use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use remap_protocol::{
    ApplyResult, Change, Command, CommandResult, ControlClient, Diagnostic, ListResult,
    MAX_REVISION_WAIT_MS, MappingView, PreviewResult, RegistryStatus, ResolutionResult,
    RevisionNotice, ValidationResult,
};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CacheScope, CallToolResult, ClientCapabilities, DiscoverResult, ExtensionCapabilities,
    Implementation, InitializeRequestParams, InitializeResult, ListResourceTemplatesResult,
    ListResourcesResult, ListToolsResult, PaginatedRequestParams, ProtocolVersion,
    ReadResourceRequestParams, ReadResourceResponse, ServerCapabilities, ServerInfo,
    SubscribeRequestParams, SubscriptionFilter, UnsubscribeRequestParams,
};
use rmcp::service::{RequestContext, SubscriptionContext};
use rmcp::{ErrorData, ServerHandler, tool, tool_handler, tool_router};
use serde_json::{Map, Value};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, oneshot};
use uuid::Uuid;

use crate::output::{ToolSuccess, failure, success, unexpected_result};
use crate::params::{
    ApplyParams, EmptyParams, ListParams, MutationParams, PatternParams, PreviewParams,
    ResolveParams, SetParams, ValidateParams, validate_change_count, validate_limit,
};
use crate::{resources, ui};

/// MCP protocol revisions that Remap intentionally implements and tests.
pub const SUPPORTED_PROTOCOL_VERSIONS: [ProtocolVersion; 2] =
    [ProtocolVersion::V_2026_07_28, ProtocolVersion::V_2025_11_25];

const MAX_ACTIVE_SUBSCRIPTIONS: usize = 4;
const WATCH_RETRY_INITIAL: Duration = Duration::from_millis(50);
const WATCH_RETRY_MAX: Duration = Duration::from_secs(2);

/// Agent-native adapter over the authoritative per-user Remap daemon.
#[derive(Debug, Clone)]
pub(crate) struct RemapMcp {
    client: ControlClient,
    tool_router: ToolRouter<Self>,
    legacy_watchers: LegacyWatchers,
    subscription_slots: Arc<Semaphore>,
}

type LegacyWatcher = (Uuid, oneshot::Sender<()>, OwnedSemaphorePermit);
type LegacyWatchers = Arc<Mutex<BTreeMap<String, LegacyWatcher>>>;

#[derive(Debug, Clone, Eq, PartialEq)]
struct WatchState {
    revision: u64,
    maintenance: Option<Diagnostic>,
}

impl RemapMcp {
    /// Creates a server using an explicit daemon client.
    #[must_use]
    pub(crate) fn new(client: ControlClient) -> Self {
        Self {
            client,
            tool_router: Self::tool_router(),
            legacy_watchers: Arc::default(),
            subscription_slots: Arc::new(Semaphore::new(MAX_ACTIVE_SUBSCRIPTIONS)),
        }
    }

    async fn execute(&self, command: Command) -> Result<CommandResult, CallToolResult> {
        self.client.execute(command).await.map_err(failure)
    }

    async fn apply_one(
        &self,
        expected_revision: u64,
        operation_id: String,
        change: Change,
    ) -> Result<ToolSuccess<ApplyResult>, CallToolResult> {
        self.apply_batch(expected_revision, operation_id, vec![change])
            .await
    }

    async fn apply_batch(
        &self,
        expected_revision: u64,
        operation_id: String,
        changes: Vec<Change>,
    ) -> Result<ToolSuccess<ApplyResult>, CallToolResult> {
        let command = Command::Apply {
            expected_revision,
            operation_id,
            changes,
        };
        match self.execute(command).await? {
            CommandResult::Apply(result) => {
                let summary = if result.changed {
                    format!("Committed revision {}.", result.revision)
                } else {
                    format!("No state change; revision remains {}.", result.revision)
                };
                Ok(success(summary, result))
            }
            _ => Err(unexpected_result("an apply receipt")),
        }
    }
}

fn status_summary(status: &RegistryStatus) -> String {
    let base = format!(
        "Revision {} contains {} mappings; {} are active.",
        status.revision, status.mapping_count, status.enabled_count
    );
    if let Some(error) = &status.maintenance {
        format!(
            "{base} Mutations are blocked by maintenance ({}).",
            error.code
        )
    } else {
        base
    }
}

#[tool_router]
impl RemapMcp {
    /// Read the authoritative revision and mapping counts. Call this before mutations.
    #[tool(
        name = "remap_status",
        output_schema = rmcp::handler::server::tool::schema_for_output::<ToolSuccess<RegistryStatus>>(),
        annotations(title = "Remap status", read_only_hint = true, destructive_hint = false, idempotent_hint = true, open_world_hint = false),
        meta = ui::app_tool_meta()
    )]
    async fn status(
        &self,
        Parameters(_params): Parameters<EmptyParams>,
    ) -> Result<ToolSuccess<RegistryStatus>, CallToolResult> {
        match self.execute(Command::Status).await? {
            CommandResult::Status(status) => Ok(success(status_summary(&status), status)),
            _ => Err(unexpected_result("registry status")),
        }
    }

    /// List a bounded deterministic page of mappings from the authoritative registry.
    #[tool(
        name = "remap_list",
        output_schema = rmcp::handler::server::tool::schema_for_output::<ToolSuccess<ListResult>>(),
        annotations(title = "List Remap mappings", read_only_hint = true, destructive_hint = false, idempotent_hint = true, open_world_hint = false),
        meta = ui::app_tool_meta()
    )]
    async fn list(
        &self,
        Parameters(params): Parameters<ListParams>,
    ) -> Result<ToolSuccess<ListResult>, CallToolResult> {
        validate_limit(params.limit).map_err(failure)?;
        let command = Command::List {
            after: params.after,
            limit: params.limit,
            include_disabled: params.include_disabled,
        };
        match self.execute(command).await? {
            CommandResult::List(result) => Ok(success(
                format!(
                    "Read {} mappings at revision {}.",
                    result.mappings.len(),
                    result.revision
                ),
                result,
            )),
            _ => Err(unexpected_result("a mapping page")),
        }
    }

    /// Read one exact mapping pattern. This does not run wildcard resolution.
    #[tool(
        name = "remap_get",
        output_schema = rmcp::handler::server::tool::schema_for_output::<ToolSuccess<Option<MappingView>>>(),
        annotations(title = "Get a Remap mapping", read_only_hint = true, destructive_hint = false, idempotent_hint = true, open_world_hint = false),
        meta = ui::model_tool_meta()
    )]
    async fn get(
        &self,
        Parameters(params): Parameters<PatternParams>,
    ) -> Result<ToolSuccess<Option<MappingView>>, CallToolResult> {
        match self
            .execute(Command::Get {
                pattern: params.pattern,
            })
            .await?
        {
            CommandResult::Mapping(Some(mapping)) => Ok(success(
                format!("Found mapping '{}'.", mapping.pattern),
                Some(mapping),
            )),
            CommandResult::Mapping(None) => {
                Ok(success("No mapping matched that exact pattern.", None))
            }
            _ => Err(unexpected_result("an exact mapping lookup")),
        }
    }

    /// Explain which exact or wildcard mapping wins for a hostname without network I/O.
    #[tool(
        name = "remap_resolve",
        output_schema = rmcp::handler::server::tool::schema_for_output::<ToolSuccess<ResolutionResult>>(),
        annotations(
            title = "Explain Remap resolution",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        ),
        meta = ui::model_tool_meta()
    )]
    async fn resolve(
        &self,
        Parameters(params): Parameters<ResolveParams>,
    ) -> Result<ToolSuccess<ResolutionResult>, CallToolResult> {
        match self.execute(Command::Resolve { name: params.name }).await? {
            CommandResult::Resolution(result) => {
                let summary = result.mapping.as_ref().map_or_else(
                    || format!("No enabled mapping resolves '{}'.", result.name),
                    |mapping| format!("'{}' resolves through '{}'.", result.name, mapping.pattern),
                );
                Ok(success(summary, result))
            }
            _ => Err(unexpected_result("a resolution explanation")),
        }
    }

    /// Validate and canonicalize a mapping without reading or changing registry state.
    #[tool(
        name = "remap_validate",
        output_schema = rmcp::handler::server::tool::schema_for_output::<ToolSuccess<ValidationResult>>(),
        annotations(
            title = "Validate a Remap mapping",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        ),
        meta = ui::model_tool_meta()
    )]
    async fn validate(
        &self,
        Parameters(params): Parameters<ValidateParams>,
    ) -> Result<ToolSuccess<ValidationResult>, CallToolResult> {
        let command = Command::Validate {
            pattern: params.pattern,
            target: params.target,
            host_policy: params.host_policy,
        };
        match self.execute(command).await? {
            CommandResult::Validation(result) => Ok(success(
                format!("'{}' is a valid mapping.", result.pattern),
                result,
            )),
            _ => Err(unexpected_result("a validation result")),
        }
    }

    /// Project an ordered atomic change set. Always preview unfamiliar or multi-change work.
    #[tool(
        name = "remap_preview",
        output_schema = rmcp::handler::server::tool::schema_for_output::<ToolSuccess<PreviewResult>>(),
        annotations(title = "Preview Remap changes", read_only_hint = true, destructive_hint = false, idempotent_hint = true, open_world_hint = false),
        meta = ui::model_tool_meta()
    )]
    async fn preview(
        &self,
        Parameters(params): Parameters<PreviewParams>,
    ) -> Result<ToolSuccess<PreviewResult>, CallToolResult> {
        validate_change_count(params.changes.len()).map_err(failure)?;
        let changes = params.changes.into_iter().map(Change::from).collect();
        match self.execute(Command::Preview { changes }).await? {
            CommandResult::Preview(result) => Ok(success(
                format!(
                    "Previewed {} effects at revision {}; state {} change.",
                    result.effects.len(),
                    result.base_revision,
                    if result.will_change {
                        "would"
                    } else {
                        "would not"
                    }
                ),
                result,
            )),
            _ => Err(unexpected_result("a change preview")),
        }
    }

    /// Create or retarget one mapping using optimistic concurrency and idempotent retry.
    #[tool(
        name = "remap_set",
        output_schema = rmcp::handler::server::tool::schema_for_output::<ToolSuccess<ApplyResult>>(),
        annotations(title = "Set a Remap mapping", read_only_hint = false, destructive_hint = true, idempotent_hint = true, open_world_hint = false),
        meta = ui::model_tool_meta()
    )]
    async fn set(
        &self,
        Parameters(params): Parameters<SetParams>,
    ) -> Result<ToolSuccess<ApplyResult>, CallToolResult> {
        let change = Change::Set {
            pattern: params.pattern,
            target: params.target,
            host_policy: params.host_policy,
            enabled: params.enabled,
        };
        self.apply_one(params.expected_revision, params.operation_id, change)
            .await
    }

    /// Enable one existing mapping using optimistic concurrency and idempotent retry.
    #[tool(
        name = "remap_enable",
        output_schema = rmcp::handler::server::tool::schema_for_output::<ToolSuccess<ApplyResult>>(),
        annotations(title = "Enable a Remap mapping", read_only_hint = false, destructive_hint = true, idempotent_hint = true, open_world_hint = false),
        meta = ui::model_tool_meta()
    )]
    async fn enable(
        &self,
        Parameters(params): Parameters<MutationParams>,
    ) -> Result<ToolSuccess<ApplyResult>, CallToolResult> {
        let change = Change::Enable {
            pattern: params.pattern,
        };
        self.apply_one(params.expected_revision, params.operation_id, change)
            .await
    }

    /// Disable one mapping without deleting it, using revision and idempotency guards.
    #[tool(
        name = "remap_disable",
        output_schema = rmcp::handler::server::tool::schema_for_output::<ToolSuccess<ApplyResult>>(),
        annotations(title = "Disable a Remap mapping", read_only_hint = false, destructive_hint = true, idempotent_hint = true, open_world_hint = false),
        meta = ui::model_tool_meta()
    )]
    async fn disable(
        &self,
        Parameters(params): Parameters<MutationParams>,
    ) -> Result<ToolSuccess<ApplyResult>, CallToolResult> {
        let change = Change::Disable {
            pattern: params.pattern,
        };
        self.apply_one(params.expected_revision, params.operation_id, change)
            .await
    }

    /// Delete one mapping using optimistic concurrency and idempotent retry.
    #[tool(
        name = "remap_remove",
        output_schema = rmcp::handler::server::tool::schema_for_output::<ToolSuccess<ApplyResult>>(),
        annotations(title = "Remove a Remap mapping", read_only_hint = false, destructive_hint = true, idempotent_hint = true, open_world_hint = false),
        meta = ui::model_tool_meta()
    )]
    async fn remove(
        &self,
        Parameters(params): Parameters<MutationParams>,
    ) -> Result<ToolSuccess<ApplyResult>, CallToolResult> {
        let change = Change::Remove {
            pattern: params.pattern,
        };
        self.apply_one(params.expected_revision, params.operation_id, change)
            .await
    }

    /// Commit an ordered change set atomically using revision and idempotency guards.
    #[tool(
        name = "remap_apply",
        output_schema = rmcp::handler::server::tool::schema_for_output::<ToolSuccess<ApplyResult>>(),
        annotations(title = "Apply Remap changes", read_only_hint = false, destructive_hint = true, idempotent_hint = true, open_world_hint = false),
        meta = ui::model_tool_meta()
    )]
    async fn apply(
        &self,
        Parameters(params): Parameters<ApplyParams>,
    ) -> Result<ToolSuccess<ApplyResult>, CallToolResult> {
        validate_change_count(params.changes.len()).map_err(failure)?;
        let changes = params.changes.into_iter().map(Change::from).collect();
        self.apply_batch(params.expected_revision, params.operation_id, changes)
            .await
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for RemapMcp {
    fn discover(
        &self,
        context: RequestContext<rmcp::RoleServer>,
    ) -> impl Future<Output = Result<DiscoverResult, ErrorData>> + Send + '_ {
        let mut info = self.get_info();
        if !context_supports_apps(&context) {
            info.capabilities.extensions = None;
        }
        std::future::ready(Ok(DiscoverResult::from_server_info(
            vec![ProtocolVersion::V_2026_07_28],
            info,
        )))
    }

    fn initialize(
        &self,
        request: InitializeRequestParams,
        _context: RequestContext<rmcp::RoleServer>,
    ) -> impl Future<Output = Result<InitializeResult, ErrorData>> + Send + '_ {
        let result = if request.protocol_version == ProtocolVersion::V_2025_11_25 {
            let mut info = self.get_info();
            info.protocol_version = ProtocolVersion::V_2025_11_25;
            if !supports_apps(&request.capabilities) {
                info.capabilities.extensions = None;
            }
            Ok(info)
        } else {
            Err(ErrorData::unsupported_protocol_version(
                request.protocol_version,
                &[ProtocolVersion::V_2025_11_25],
            ))
        };
        std::future::ready(result)
    }

    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Borrowed(&SUPPORTED_PROTOCOL_VERSIONS)
    }

    fn get_info(&self) -> ServerInfo {
        let mut extensions = ExtensionCapabilities::new();
        let mut app_settings = Map::new();
        app_settings.insert(
            "mimeTypes".to_owned(),
            Value::Array(vec![Value::String(ui::APP_MIME_TYPE.to_owned())]),
        );
        extensions.insert("io.modelcontextprotocol/ui".to_owned(), app_settings);
        let capabilities = ServerCapabilities::builder()
            .enable_extensions_with(extensions)
            .enable_resources()
            .enable_resources_subscribe()
            .enable_tools()
            .build();
        ServerInfo::new(capabilities)
            .with_server_info(server_implementation())
            .with_instructions(
                "Read remap://help first. Observe remap_status, preview changes, then mutate with the observed expected_revision and a fresh UUIDv4 operation_id. Reuse an operation ID only to retry the identical request.",
            )
    }

    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<rmcp::RoleServer>,
    ) -> impl Future<Output = Result<ListToolsResult, ErrorData>> + Send + '_ {
        let include_app = context_supports_apps(&context);
        let mut tools = self.tool_router.list_all();
        if !include_app {
            for tool in &mut tools {
                tool.meta = None;
            }
        }
        let result = ListToolsResult::with_all_items(tools);
        let result = if supports_cache_hints(&context) {
            Ok(result
                .with_ttl_ms(3_600_000)
                .with_cache_scope(CacheScope::Private))
        } else {
            Ok(result)
        };
        std::future::ready(result)
    }

    fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<rmcp::RoleServer>,
    ) -> impl Future<Output = Result<ListResourcesResult, ErrorData>> + Send + '_ {
        std::future::ready(Ok(resources::list(
            supports_cache_hints(&context),
            context_supports_apps(&context),
        )))
    }

    fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<rmcp::RoleServer>,
    ) -> impl Future<Output = Result<ListResourceTemplatesResult, ErrorData>> + Send + '_ {
        std::future::ready(Ok(ListResourceTemplatesResult::default()))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        context: RequestContext<rmcp::RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        resources::read(
            &request.uri,
            &self.client,
            supports_cache_hints(&context),
            context_supports_apps(&context),
        )
        .await
    }

    fn accepted_subscription_filter(
        &self,
        requested: &SubscriptionFilter,
    ) -> Option<SubscriptionFilter> {
        let mut accepted = SubscriptionFilter::new();
        accepted.resource_subscriptions =
            requested.resource_subscriptions.as_ref().and_then(|uris| {
                let allowed = uris
                    .iter()
                    .filter(|uri| is_dynamic_resource(uri))
                    .cloned()
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                (!allowed.is_empty()).then_some(allowed)
            });
        accepted.resource_subscriptions.as_ref()?;
        Some(accepted)
    }

    async fn listen(&self, context: SubscriptionContext) -> Result<(), ErrorData> {
        let _permit = self
            .subscription_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| subscription_capacity_error())?;
        let uris = context
            .accepted()
            .resource_subscriptions
            .clone()
            .unwrap_or_default();
        watch_modern(self.client.clone(), context, uris).await
    }

    #[allow(deprecated)]
    async fn subscribe(
        &self,
        request: SubscribeRequestParams,
        context: RequestContext<rmcp::RoleServer>,
    ) -> Result<(), ErrorData> {
        if !is_dynamic_resource(&request.uri) {
            return Err(ErrorData::invalid_params(
                "only remap://status and remap://mappings are subscribable",
                None,
            ));
        }
        let permit = self
            .subscription_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| subscription_capacity_error())?;
        let baseline = current_watch_state(&self.client).await?;
        let identifier = Uuid::new_v4();
        let (stop_sender, stop_receiver) = oneshot::channel();
        {
            let mut watchers = self.legacy_watchers.lock().await;
            if watchers.contains_key(&request.uri) {
                return Err(ErrorData::invalid_params(
                    "this resource is already subscribed",
                    None,
                ));
            }
            watchers.insert(request.uri.clone(), (identifier, stop_sender, permit));
        }
        spawn_legacy_watch(
            self.client.clone(),
            self.legacy_watchers.clone(),
            context,
            request.uri,
            identifier,
            baseline,
            stop_receiver,
        );
        Ok(())
    }

    #[allow(deprecated)]
    async fn unsubscribe(
        &self,
        request: UnsubscribeRequestParams,
        _context: RequestContext<rmcp::RoleServer>,
    ) -> Result<(), ErrorData> {
        let sender = self
            .legacy_watchers
            .lock()
            .await
            .remove(&request.uri)
            .map(|(_, sender, _permit)| sender)
            .ok_or_else(|| ErrorData::invalid_params("resource is not subscribed", None))?;
        let _result = sender.send(());
        Ok(())
    }
}

pub(crate) fn server_implementation() -> Implementation {
    Implementation::new("remap", env!("CARGO_PKG_VERSION"))
        .with_title("Remap")
        .with_description("Local authority for arbitrary name-to-service mappings")
        .with_website_url("https://github.com/agenxy/remap")
}

fn supports_cache_hints(context: &RequestContext<rmcp::RoleServer>) -> bool {
    context
        .protocol_version()
        .is_some_and(|version| version >= ProtocolVersion::V_2026_07_28)
}

fn context_supports_apps(context: &RequestContext<rmcp::RoleServer>) -> bool {
    context
        .client_capabilities()
        .as_ref()
        .is_some_and(supports_apps)
}

fn supports_apps(capabilities: &ClientCapabilities) -> bool {
    capabilities
        .extensions
        .as_ref()
        .and_then(|extensions| extensions.get("io.modelcontextprotocol/ui"))
        .and_then(|settings| settings.get("mimeTypes"))
        .and_then(Value::as_array)
        .is_some_and(|mime_types| {
            mime_types
                .iter()
                .any(|mime| mime.as_str() == Some(ui::APP_MIME_TYPE))
        })
}

fn is_dynamic_resource(uri: &str) -> bool {
    matches!(uri, resources::STATUS_URI | resources::MAPPINGS_URI)
}

async fn current_watch_state(client: &ControlClient) -> Result<WatchState, ErrorData> {
    match client
        .execute(Command::Status)
        .await
        .map_err(resource_watch_error)?
    {
        CommandResult::Status(status) => Ok(WatchState {
            revision: status.revision,
            maintenance: status.maintenance,
        }),
        _ => Err(ErrorData::internal_error(
            "the daemon returned a non-status result to a resource watcher",
            None,
        )),
    }
}

async fn watch_modern(
    client: ControlClient,
    context: SubscriptionContext,
    uris: Vec<String>,
) -> Result<(), ErrorData> {
    let Some(mut state) = resilient_current_watch_state(&client, &context).await? else {
        return Ok(());
    };
    let mut retry_delay = WATCH_RETRY_INITIAL;
    loop {
        tokio::select! {
            () = context.cancelled() => return Ok(()),
            result = next_watch_state(&client, &state) => {
                match result {
                    Ok(next) => {
                        retry_delay = WATCH_RETRY_INITIAL;
                        for uri in uris.iter().filter(|uri| resource_changed(uri, &state, &next)) {
                            tokio::select! {
                                () = context.cancelled() => return Ok(()),
                                result = context.sink().notify_resource_updated((*uri).clone()) => {
                                    if result.is_err() {
                                        return Ok(());
                                    }
                                }
                            }
                        }
                        state = next;
                    }
                    Err(error) if retryable_watch_error(&error) => {
                        tokio::select! {
                            () = context.cancelled() => return Ok(()),
                            () = tokio::time::sleep(retry_delay) => {}
                        }
                        retry_delay = next_watch_retry(retry_delay);
                    }
                    Err(error) => return Err(error),
                }
            }
        }
    }
}

async fn resilient_current_watch_state(
    client: &ControlClient,
    context: &SubscriptionContext,
) -> Result<Option<WatchState>, ErrorData> {
    let mut retry_delay = WATCH_RETRY_INITIAL;
    loop {
        tokio::select! {
            () = context.cancelled() => return Ok(None),
            result = current_watch_state(client) => match result {
                Ok(state) => return Ok(Some(state)),
                Err(error) if retryable_watch_error(&error) => {
                    tokio::select! {
                        () = context.cancelled() => return Ok(None),
                        () = tokio::time::sleep(retry_delay) => {}
                    }
                    retry_delay = next_watch_retry(retry_delay);
                }
                Err(error) => return Err(error),
            }
        }
    }
}

fn spawn_legacy_watch(
    client: ControlClient,
    watchers: LegacyWatchers,
    context: RequestContext<rmcp::RoleServer>,
    uri: String,
    identifier: Uuid,
    mut state: WatchState,
    mut stop: oneshot::Receiver<()>,
) {
    let _task = tokio::spawn(async move {
        let mut retry_delay = WATCH_RETRY_INITIAL;
        loop {
            tokio::select! {
                _result = &mut stop => break,
                result = next_watch_state(&client, &state) => {
                    match result {
                        Ok(next) => {
                            retry_delay = WATCH_RETRY_INITIAL;
                            if resource_changed(&uri, &state, &next) {
                                let notification = rmcp::model::ResourceUpdatedNotificationParam::new(
                                    uri.clone()
                                );
                                tokio::select! {
                                    _result = &mut stop => break,
                                    result = context.peer.notify_resource_updated(notification) => {
                                        if result.is_err() {
                                            break;
                                        }
                                    }
                                }
                            }
                            state = next;
                        }
                        Err(error) if retryable_watch_error(&error) => {
                            tokio::select! {
                                _result = &mut stop => break,
                                () = tokio::time::sleep(retry_delay) => {}
                            }
                            retry_delay = next_watch_retry(retry_delay);
                        }
                        Err(_error) => break,
                    }
                }
            }
        }
        let mut active = watchers.lock().await;
        if active
            .get(&uri)
            .is_some_and(|(current, _, _)| *current == identifier)
        {
            active.remove(&uri);
        }
    });
}

async fn next_watch_state(
    client: &ControlClient,
    current: &WatchState,
) -> Result<WatchState, ErrorData> {
    let _notice = wait_for_revision(client, current.revision).await?;
    current_watch_state(client).await
}

fn resource_changed(uri: &str, previous: &WatchState, current: &WatchState) -> bool {
    previous.revision != current.revision
        || (uri == resources::STATUS_URI && previous.maintenance != current.maintenance)
}

fn retryable_watch_error(error: &ErrorData) -> bool {
    error
        .data
        .as_ref()
        .and_then(|data| data.get("retryable"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn next_watch_retry(current: Duration) -> Duration {
    current.saturating_mul(2).min(WATCH_RETRY_MAX)
}

async fn wait_for_revision(
    client: &ControlClient,
    after: u64,
) -> Result<RevisionNotice, ErrorData> {
    match client
        .execute(Command::WaitForRevision {
            after,
            timeout_ms: MAX_REVISION_WAIT_MS,
        })
        .await
        .map_err(resource_watch_error)?
    {
        CommandResult::Revision(notice) => Ok(notice),
        _ => Err(ErrorData::internal_error(
            "the daemon returned a non-revision result to a resource watcher",
            None,
        )),
    }
}

fn resource_watch_error(diagnostic: Diagnostic) -> ErrorData {
    let message = diagnostic.to_string();
    let data = serde_json::to_value(diagnostic).ok();
    ErrorData::internal_error(message, data)
}

fn subscription_capacity_error() -> ErrorData {
    ErrorData::internal_error(
        "Remap's bounded subscription capacity is full",
        Some(serde_json::json!({
            "code": "E_SUBSCRIPTION_CAPACITY",
            "limit": MAX_ACTIVE_SUBSCRIPTIONS,
            "retryable": true
        })),
    )
}

#[cfg(test)]
mod status_tests {
    use remap_protocol::{Diagnostic, RegistryStatus};

    use super::{WatchState, resource_changed, status_summary};
    use crate::resources;

    #[test]
    fn status_summary_identifies_mutation_blocking_maintenance() {
        let status = RegistryStatus {
            revision: 8,
            mapping_count: 2,
            enabled_count: 1,
            schema_version: 1,
            daemon_version: "0.1.0".to_owned(),
            maintenance: Some(Diagnostic::new(
                "E_REGISTRY_CHECKPOINT",
                "checkpoint blocked",
                None,
                true,
            )),
        };

        let summary = status_summary(&status);
        assert!(summary.contains("Mutations are blocked by maintenance"));
        assert!(summary.contains("E_REGISTRY_CHECKPOINT"));
    }

    #[test]
    fn maintenance_only_changes_notify_status_but_not_mappings() {
        let healthy = WatchState {
            revision: 8,
            maintenance: None,
        };
        let degraded = WatchState {
            revision: 8,
            maintenance: Some(Diagnostic::new(
                "E_REGISTRY_CHECKPOINT",
                "checkpoint blocked",
                None,
                true,
            )),
        };

        assert!(resource_changed(resources::STATUS_URI, &healthy, &degraded));
        assert!(!resource_changed(
            resources::MAPPINGS_URI,
            &healthy,
            &degraded
        ));
        let advanced = WatchState {
            revision: 9,
            maintenance: None,
        };
        assert!(resource_changed(
            resources::MAPPINGS_URI,
            &healthy,
            &advanced
        ));
    }
}
