use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};

use rmcp::model::{
    ClientNotification, ClientRequest, ErrorData, ProtocolVersion, RequestId, ServerInfo,
    ServerResult,
};
use rmcp::service::{NotificationContext, RequestContext, RoleServer, Service};
use tokio_util::sync::CancellationToken;

use remap_protocol::{ControlClient, Diagnostic};

use crate::resources;
use crate::server::{RemapMcp, SUPPORTED_PROTOCOL_VERSIONS};

/// MCP service wrapper that keeps the stateless and legacy lifecycle families disjoint.
#[derive(Debug, Clone)]
pub struct RemapService {
    inner: RemapMcp,
    admission: RequestAdmission,
    family: Arc<Mutex<SessionFamily>>,
}

pub(crate) const MAX_IN_FLIGHT_REQUESTS: usize = 32;
pub(crate) const MAX_SESSION_REQUEST_IDS: usize = 8_192;
const MAX_REQUEST_ID_BYTES: usize = 128;

impl RemapService {
    /// Creates a lifecycle-safe MCP service using an explicit daemon client.
    #[must_use]
    pub fn new(client: ControlClient) -> Self {
        Self::with_admission(client, RequestAdmission::new())
    }

    pub(crate) fn with_admission(client: ControlClient, admission: RequestAdmission) -> Self {
        Self {
            inner: RemapMcp::new(client),
            admission,
            family: Arc::new(Mutex::new(SessionFamily::Unopened)),
        }
    }

    /// Creates a lifecycle-safe MCP service using the native daemon path.
    ///
    /// # Errors
    ///
    /// Returns a stable diagnostic if the operating system has no application-data path.
    pub fn discover() -> Result<Self, Diagnostic> {
        Ok(Self::new(resources::discover_client()?))
    }
}

impl Service<RoleServer> for RemapService {
    async fn handle_request(
        &self,
        request: ClientRequest,
        context: RequestContext<RoleServer>,
    ) -> Result<ServerResult, ErrorData> {
        validate_request_lifecycle(&request, &context, &self.family, &self.admission)?;
        let request_guard = self.admission.claim(context.id.clone())?;
        let sdk_cancellation = context.ct.clone();
        tokio::select! {
            result = Service::<RoleServer>::handle_request(&self.inner, request, context) => result,
            () = request_guard.cancelled() => Err(request_cancelled_error()),
            () = sdk_cancellation.cancelled() => Err(request_cancelled_error()),
        }
    }

    fn handle_notification(
        &self,
        notification: ClientNotification,
        context: NotificationContext<RoleServer>,
    ) -> impl Future<Output = Result<(), ErrorData>> + Send + '_ {
        Service::<RoleServer>::handle_notification(&self.inner, notification, context)
    }

    fn get_info(&self) -> ServerInfo {
        Service::<RoleServer>::get_info(&self.inner)
    }

    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Borrowed(&SUPPORTED_PROTOCOL_VERSIONS)
    }
}

pub(crate) fn request_capacity_error() -> ErrorData {
    ErrorData::new(
        rmcp::model::ErrorCode(-30_001),
        "MCP request capacity reached",
        Some(serde_json::json!({"limit": MAX_IN_FLIGHT_REQUESTS})),
    )
}

pub(crate) fn duplicate_request_error() -> ErrorData {
    ErrorData::invalid_request("JSON-RPC request id was already used in this session", None)
}

fn request_id_limit_error() -> ErrorData {
    ErrorData::new(
        rmcp::model::ErrorCode(-30_003),
        "MCP session request-id capacity reached",
        Some(serde_json::json!({"limit": MAX_SESSION_REQUEST_IDS})),
    )
}

fn request_id_length_error() -> ErrorData {
    ErrorData::invalid_request(
        format!("String request ids may contain at most {MAX_REQUEST_ID_BYTES} UTF-8 bytes"),
        None,
    )
}

fn request_cancelled_error() -> ErrorData {
    ErrorData::new(rmcp::model::ErrorCode(-30_002), "Request cancelled", None)
}

#[derive(Debug, Clone)]
pub(crate) struct RequestAdmission {
    state: Arc<Mutex<AdmissionState>>,
}

#[derive(Debug, Default)]
struct AdmissionState {
    requests: HashMap<RequestId, RequestState>,
    seen: HashSet<RequestId>,
    legacy: bool,
    max_observed: usize,
}

#[derive(Debug)]
struct RequestState {
    phase: RequestPhase,
    transport_owned: bool,
    cancelled: bool,
    cancellation: CancellationToken,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum RequestPhase {
    Reserved,
    Running,
    HandlerDone,
    ResponseStarted,
}

impl Default for RequestState {
    fn default() -> Self {
        Self {
            phase: RequestPhase::Reserved,
            transport_owned: true,
            cancelled: false,
            cancellation: CancellationToken::new(),
        }
    }
}

impl RequestAdmission {
    pub(crate) fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(AdmissionState::default())),
        }
    }

    pub(crate) fn reserve(&self, id: RequestId) -> Result<(), AdmissionFailure> {
        let mut state = self.lock();
        validate_request_id(&id).map_err(|()| AdmissionFailure::IdTooLong)?;
        if state.requests.contains_key(&id) || (state.legacy && state.seen.contains(&id)) {
            return Err(AdmissionFailure::Duplicate);
        }
        if state.legacy && state.seen.len() >= MAX_SESSION_REQUEST_IDS {
            return Err(AdmissionFailure::SessionLimit);
        }
        if state.legacy {
            state.seen.insert(id.clone());
        }
        if state.requests.len() >= MAX_IN_FLIGHT_REQUESTS {
            return Err(AdmissionFailure::Capacity);
        }
        state.requests.insert(id, RequestState::default());
        state.max_observed = state.max_observed.max(state.requests.len());
        Ok(())
    }

    fn claim(&self, id: RequestId) -> Result<RequestGuard, ErrorData> {
        let mut state = self.lock();
        let cancellation = if let Some(request) = state.requests.get_mut(&id) {
            if request.phase != RequestPhase::Reserved {
                return Err(duplicate_request_error());
            }
            request.phase = RequestPhase::Running;
            request.cancellation.clone()
        } else {
            validate_request_id(&id).map_err(|()| request_id_length_error())?;
            if state.legacy && state.seen.contains(&id) {
                return Err(duplicate_request_error());
            }
            if state.legacy && state.seen.len() >= MAX_SESSION_REQUEST_IDS {
                return Err(request_id_limit_error());
            }
            let cancellation = CancellationToken::new();
            if state.legacy {
                state.seen.insert(id.clone());
            }
            if state.requests.len() >= MAX_IN_FLIGHT_REQUESTS {
                return Err(request_capacity_error());
            }
            state.requests.insert(
                id.clone(),
                RequestState {
                    phase: RequestPhase::Running,
                    transport_owned: false,
                    cancelled: false,
                    cancellation: cancellation.clone(),
                },
            );
            state.max_observed = state.max_observed.max(state.requests.len());
            cancellation
        };
        Ok(RequestGuard {
            admission: self.clone(),
            cancellation,
            id: Some(id),
        })
    }

    pub(crate) fn start_response(&self, id: &RequestId) {
        if let Some(request) = self.lock().requests.get_mut(id) {
            request.phase = RequestPhase::ResponseStarted;
        }
    }

    pub(crate) fn finish_response(&self, id: &RequestId) {
        self.lock().requests.remove(id);
    }

    pub(crate) fn close(&self) {
        let mut state = self.lock();
        state.requests.clear();
        state.seen.clear();
        state.legacy = false;
    }

    pub(crate) fn is_legacy(&self) -> bool {
        self.lock().legacy
    }

    pub(crate) fn cancel(&self, id: &RequestId) {
        let mut state = self.lock();
        let handler_done = state.requests.get_mut(id).is_some_and(|request| {
            request.cancelled = true;
            request.cancellation.cancel();
            request.phase == RequestPhase::HandlerDone
        });
        if handler_done {
            state.requests.remove(id);
        }
    }

    fn enter_legacy(&self) -> Result<(), ErrorData> {
        let mut state = self.lock();
        if state.requests.len() > MAX_IN_FLIGHT_REQUESTS
            || state.requests.len() > MAX_SESSION_REQUEST_IDS
        {
            return Err(request_id_limit_error());
        }
        state.legacy = true;
        let active = state.requests.keys().cloned().collect::<Vec<_>>();
        state.seen.extend(active);
        Ok(())
    }

    fn finish_handler(&self, id: &RequestId) {
        let mut state = self.lock();
        let remove = state.requests.get_mut(id).is_some_and(|request| {
            let response_started = request.phase == RequestPhase::ResponseStarted;
            if !response_started {
                request.phase = RequestPhase::HandlerDone;
            }
            !request.transport_owned || (request.cancelled && !response_started)
        });
        if remove {
            state.requests.remove(id);
        }
    }

    #[cfg(test)]
    pub(crate) fn active(&self) -> usize {
        self.lock().requests.len()
    }

    #[cfg(test)]
    pub(crate) fn max_observed(&self) -> usize {
        self.lock().max_observed
    }

    fn lock(&self) -> MutexGuard<'_, AdmissionState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum AdmissionFailure {
    Duplicate,
    Capacity,
    SessionLimit,
    IdTooLong,
}

impl AdmissionFailure {
    pub(crate) fn error(self) -> ErrorData {
        match self {
            Self::Duplicate => duplicate_request_error(),
            Self::Capacity => request_capacity_error(),
            Self::SessionLimit => request_id_limit_error(),
            Self::IdTooLong => request_id_length_error(),
        }
    }
}

fn validate_request_id(id: &RequestId) -> Result<(), ()> {
    match id {
        RequestId::String(value) if value.len() > MAX_REQUEST_ID_BYTES => Err(()),
        _ => Ok(()),
    }
}

#[derive(Debug)]
struct RequestGuard {
    admission: RequestAdmission,
    cancellation: CancellationToken,
    id: Option<RequestId>,
}

impl RequestGuard {
    async fn cancelled(&self) {
        self.cancellation.cancelled().await;
    }
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        if let Some(id) = self.id.take() {
            self.admission.finish_handler(&id);
        }
    }
}

fn validate_request_lifecycle(
    request: &ClientRequest,
    context: &RequestContext<RoleServer>,
    family: &Mutex<SessionFamily>,
    admission: &RequestAdmission,
) -> Result<(), ErrorData> {
    let mut family = family
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let opening_legacy = matches!(
        request,
        ClientRequest::InitializeRequest(initialize)
            if initialize.params.protocol_version == ProtocolVersion::V_2025_11_25
    );
    let expected = match *family {
        SessionFamily::Unopened if opening_legacy => ProtocolVersion::V_2025_11_25,
        SessionFamily::Unopened | SessionFamily::Modern => ProtocolVersion::V_2026_07_28,
        SessionFamily::Legacy => ProtocolVersion::V_2025_11_25,
    };
    if *family != SessionFamily::Unopened && matches!(request, ClientRequest::InitializeRequest(_))
    {
        return Err(method_not_found(&expected));
    }
    if let Some(requested) = context.meta.protocol_version()
        && requested != expected
    {
        return Err(ErrorData::unsupported_protocol_version(
            requested,
            std::slice::from_ref(&expected),
        ));
    }
    let cross_family = if expected == ProtocolVersion::V_2025_11_25 {
        matches!(
            request,
            ClientRequest::DiscoverRequest(_)
                | ClientRequest::SubscriptionsListenRequest(_)
                | ClientRequest::GetTaskRequest(_)
                | ClientRequest::UpdateTaskRequest(_)
                | ClientRequest::CancelTaskRequest(_)
        )
    } else {
        matches!(
            request,
            ClientRequest::SubscribeRequest(_) | ClientRequest::UnsubscribeRequest(_)
        )
    };
    if cross_family {
        return Err(method_not_found(&expected));
    }
    if *family == SessionFamily::Unopened && opening_legacy {
        admission.enter_legacy()?;
        *family = SessionFamily::Legacy;
    } else if *family == SessionFamily::Unopened {
        *family = SessionFamily::Modern;
    }
    Ok(())
}

fn method_not_found(expected: &ProtocolVersion) -> ErrorData {
    ErrorData::new(
        rmcp::model::ErrorCode::METHOD_NOT_FOUND,
        "Request method belongs to a different MCP lifecycle family",
        Some(serde_json::json!({"protocolVersion": expected})),
    )
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum SessionFamily {
    Unopened,
    Modern,
    Legacy,
}

#[cfg(test)]
mod tests {
    use rmcp::model::RequestId;

    use super::{AdmissionFailure, MAX_IN_FLIGHT_REQUESTS, RequestAdmission};

    #[test]
    fn cancellation_releases_running_and_handler_done_requests()
    -> Result<(), Box<dyn std::error::Error>> {
        let admission = RequestAdmission::new();
        let running_id = RequestId::Number(1);
        admission
            .reserve(running_id.clone())
            .map_err(|failure| format!("reserve failed: {failure:?}"))?;
        let running = admission.claim(running_id.clone())?;
        admission.cancel(&running_id);
        assert_eq!(admission.active(), 1);
        drop(running);
        assert_eq!(admission.active(), 0);

        let done_id = RequestId::Number(2);
        admission
            .reserve(done_id.clone())
            .map_err(|failure| format!("reserve failed: {failure:?}"))?;
        let done = admission.claim(done_id.clone())?;
        drop(done);
        assert_eq!(admission.active(), 1);
        admission.cancel(&done_id);
        assert_eq!(admission.active(), 0);
        Ok(())
    }

    #[test]
    fn response_started_holds_capacity_until_transport_completion()
    -> Result<(), Box<dyn std::error::Error>> {
        let admission = RequestAdmission::new();
        let id = RequestId::Number(3);
        admission
            .reserve(id.clone())
            .map_err(|failure| format!("reserve failed: {failure:?}"))?;
        let request = admission.claim(id.clone())?;
        admission.start_response(&id);
        drop(request);
        admission.cancel(&id);
        assert_eq!(admission.active(), 1);
        admission.finish_response(&id);
        assert_eq!(admission.active(), 0);
        Ok(())
    }

    #[test]
    fn modern_ids_can_be_reused_only_after_completion() -> Result<(), Box<dyn std::error::Error>> {
        let admission = RequestAdmission::new();
        let id = RequestId::String("reusable".into());
        let first = admission.claim(id.clone())?;
        assert!(admission.claim(id.clone()).is_err());
        drop(first);
        assert!(admission.claim(id).is_ok());
        Ok(())
    }

    #[test]
    fn legacy_capacity_rejection_still_consumes_the_request_id()
    -> Result<(), Box<dyn std::error::Error>> {
        let admission = RequestAdmission::new();
        admission.enter_legacy()?;
        for number in 0..MAX_IN_FLIGHT_REQUESTS {
            let request_id = i64::try_from(number)?;
            admission
                .reserve(RequestId::Number(request_id))
                .map_err(|failure| format!("reserve failed: {failure:?}"))?;
        }
        let rejected = RequestId::String("rejected-at-capacity".into());
        assert_eq!(
            admission.reserve(rejected.clone()),
            Err(AdmissionFailure::Capacity)
        );
        admission.finish_response(&RequestId::Number(0));
        assert_eq!(
            admission.reserve(rejected),
            Err(AdmissionFailure::Duplicate)
        );
        Ok(())
    }
}
