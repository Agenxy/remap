use std::io;
use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use rmcp::RoleServer;
use rmcp::model::{
    ClientJsonRpcMessage, ClientRequest, ErrorData, GetMeta, ProtocolVersion, ServerJsonRpcMessage,
};
use rmcp::transport::Transport;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;
use tokio_util::bytes::BytesMut;
use tokio_util::codec::{Decoder, Encoder, FramedRead, FramedWrite, LinesCodec, LinesCodecError};

use crate::lifecycle::{AdmissionFailure, RequestAdmission};

/// Maximum size of one newline-delimited MCP message.
pub(crate) const MAX_MCP_MESSAGE_BYTES: usize = 1024 * 1024;

const CLIENT_INFO_META_KEY: &str = "io.modelcontextprotocol/clientInfo";
const LOG_LEVEL_META_KEY: &str = "io.modelcontextprotocol/logLevel";

/// Bounded newline-delimited JSON-RPC transport for an MCP stdio server.
pub(crate) struct BoundedStdioTransport<R, W> {
    reader: FramedRead<R, BoundedJsonRpcDecoder>,
    writer: Arc<Mutex<FramedWrite<W, BoundedJsonRpcEncoder>>>,
    admission: RequestAdmission,
}

impl<R, W> BoundedStdioTransport<R, W>
where
    R: AsyncRead,
    W: AsyncWrite,
{
    pub(crate) fn new(reader: R, writer: W, admission: RequestAdmission) -> Self {
        Self {
            reader: FramedRead::new(reader, BoundedJsonRpcDecoder::new()),
            writer: Arc::new(Mutex::new(FramedWrite::new(
                writer,
                BoundedJsonRpcEncoder::new(admission.clone()),
            ))),
            admission,
        }
    }
}

impl<R, W> Drop for BoundedStdioTransport<R, W> {
    fn drop(&mut self) {
        self.admission.close();
    }
}

impl<R, W> Transport<RoleServer> for BoundedStdioTransport<R, W>
where
    R: AsyncRead + Send + Unpin,
    W: AsyncWrite + Send + Unpin + 'static,
{
    type Error = io::Error;

    fn send(
        &mut self,
        message: ServerJsonRpcMessage,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send + 'static {
        let writer = self.writer.clone();
        let admission = self.admission.clone();
        let response_id = response_id(&message).cloned();
        if let Some(id) = response_id.as_ref() {
            admission.start_response(id);
        }
        async move {
            let result = writer.lock().await.send(message).await;
            if let Some(id) = response_id.as_ref() {
                admission.finish_response(id);
            }
            result
        }
    }

    async fn receive(&mut self) -> Option<ClientJsonRpcMessage> {
        loop {
            match self.reader.next().await? {
                Ok(InboundFrame::Message(message)) => {
                    match prepare_message(self.writer.clone(), &self.admission, message).await {
                        Ok(Some(message)) => return Some(message),
                        Ok(None) => {}
                        Err(_) => return None,
                    }
                }
                Ok(InboundFrame::ParseError) => {
                    let error = ErrorData::parse_error("Parse error", None);
                    if send_error(self.writer.clone(), error, None).await.is_err() {
                        return None;
                    }
                }
                Ok(InboundFrame::Oversized) | Err(_) => return None,
            }
        }
    }

    async fn close(&mut self) -> Result<(), Self::Error> {
        self.writer.lock().await.close().await
    }
}

async fn prepare_message<W>(
    writer: Arc<Mutex<FramedWrite<W, BoundedJsonRpcEncoder>>>,
    admission: &RequestAdmission,
    message: Box<ClientJsonRpcMessage>,
) -> Result<Option<ClientJsonRpcMessage>, io::Error>
where
    W: AsyncWrite + Send + Unpin + 'static,
{
    if let Some((id, error)) = modern_metadata_error(&message, admission) {
        send_error(writer, error, Some(id)).await?;
        return Ok(None);
    }
    if let Some(id) = request_id(&message).cloned()
        && let Err(failure) = admission.reserve(id.clone())
    {
        if failure == AdmissionFailure::Duplicate {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "duplicate live request id",
            ));
        }
        let terminal = failure != AdmissionFailure::Capacity;
        send_error(writer, failure.error(), Some(id)).await?;
        if terminal {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "terminal request rejection",
            ));
        }
        return Ok(None);
    }
    if let Some(id) = cancellation_id(&message) {
        admission.cancel(id);
    }
    Ok(Some(*message))
}

#[derive(Debug)]
enum InboundFrame {
    Message(Box<ClientJsonRpcMessage>),
    ParseError,
    Oversized,
}

#[derive(Debug)]
struct BoundedJsonRpcDecoder {
    lines: LinesCodec,
}

impl BoundedJsonRpcDecoder {
    fn new() -> Self {
        Self {
            lines: LinesCodec::new_with_max_length(MAX_MCP_MESSAGE_BYTES - 1),
        }
    }

    fn parse(line: Result<Option<String>, LinesCodecError>) -> Option<InboundFrame> {
        match line {
            Ok(Some(line)) => {
                let without_bom = line.strip_prefix('\u{feff}').unwrap_or(&line);
                Some(
                    serde_json::from_str(without_bom).map_or(InboundFrame::ParseError, |message| {
                        InboundFrame::Message(Box::new(message))
                    }),
                )
            }
            Ok(None) => None,
            Err(LinesCodecError::MaxLineLengthExceeded) => Some(InboundFrame::Oversized),
            Err(LinesCodecError::Io(_error)) => Some(InboundFrame::ParseError),
        }
    }
}

impl Decoder for BoundedJsonRpcDecoder {
    type Item = InboundFrame;
    type Error = io::Error;

    fn decode(&mut self, input: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        Ok(Self::parse(self.lines.decode(input)))
    }

    fn decode_eof(&mut self, input: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        Ok(Self::parse(self.lines.decode_eof(input)))
    }
}

async fn send_error<W>(
    writer: Arc<Mutex<FramedWrite<W, BoundedJsonRpcEncoder>>>,
    error: ErrorData,
    id: Option<rmcp::model::RequestId>,
) -> Result<(), io::Error>
where
    W: AsyncWrite + Unpin,
{
    tokio::time::timeout(std::time::Duration::from_millis(250), async move {
        writer
            .lock()
            .await
            .send(ServerJsonRpcMessage::error(error, id))
            .await
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "MCP output stopped draining"))?
}

fn request_id(message: &ClientJsonRpcMessage) -> Option<&rmcp::model::RequestId> {
    match message {
        ClientJsonRpcMessage::Request(request) => Some(&request.id),
        _ => None,
    }
}

fn modern_metadata_error(
    message: &ClientJsonRpcMessage,
    admission: &RequestAdmission,
) -> Option<(rmcp::model::RequestId, ErrorData)> {
    let ClientJsonRpcMessage::Request(request) = message else {
        return None;
    };
    if admission.is_legacy()
        || matches!(
            request.request,
            ClientRequest::InitializeRequest(_) | ClientRequest::PingRequest(_)
        )
    {
        return None;
    }
    let meta = request.request.get_meta();
    let mut missing = meta.missing_required_keys(&ProtocolVersion::V_2026_07_28);
    if meta.contains_key(CLIENT_INFO_META_KEY) && meta.client_info().is_none() {
        missing.push(CLIENT_INFO_META_KEY);
    }
    if meta.contains_key(LOG_LEVEL_META_KEY) && meta.log_level().is_none() {
        missing.push(LOG_LEVEL_META_KEY);
    }
    (!missing.is_empty()).then(|| {
        (
            request.id.clone(),
            ErrorData::invalid_params(
                format!(
                    "request _meta is missing or malformed: {}",
                    missing.join(", ")
                ),
                None,
            ),
        )
    })
}

fn cancellation_id(message: &ClientJsonRpcMessage) -> Option<&rmcp::model::RequestId> {
    match message {
        ClientJsonRpcMessage::Notification(notification) => match &notification.notification {
            rmcp::model::ClientNotification::CancelledNotification(cancelled) => {
                cancelled.params.request_id.as_ref()
            }
            _ => None,
        },
        _ => None,
    }
}

fn response_id(message: &ServerJsonRpcMessage) -> Option<&rmcp::model::RequestId> {
    match message {
        ServerJsonRpcMessage::Response(response) => Some(&response.id),
        ServerJsonRpcMessage::Error(error) => error.id.as_ref(),
        _ => None,
    }
}

#[derive(Debug, Clone)]
struct BoundedJsonRpcEncoder {
    admission: RequestAdmission,
}

impl BoundedJsonRpcEncoder {
    fn new(admission: RequestAdmission) -> Self {
        Self { admission }
    }
}

impl Encoder<ServerJsonRpcMessage> for BoundedJsonRpcEncoder {
    type Error = io::Error;

    fn encode(
        &mut self,
        message: ServerJsonRpcMessage,
        output: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        let mut value = serde_json::to_value(&message)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        ensure_error_id(&message, &mut value)?;
        if !self.admission.is_legacy() {
            stamp_server_info(&mut value)?;
        }
        let encoded = serde_json::to_vec(&value)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let framed_length = encoded.len().checked_add(1).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "MCP output length overflowed")
        })?;
        if framed_length > MAX_MCP_MESSAGE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "MCP output exceeded the one-MiB frame limit",
            ));
        }
        output.reserve(framed_length);
        output.extend_from_slice(&encoded);
        output.extend_from_slice(b"\n");
        Ok(())
    }
}

fn ensure_error_id(
    message: &ServerJsonRpcMessage,
    value: &mut serde_json::Value,
) -> Result<(), io::Error> {
    let ServerJsonRpcMessage::Error(error) = message else {
        return Ok(());
    };
    if error.id.is_some() {
        return Ok(());
    }
    value
        .as_object_mut()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "JSON-RPC error was not an object",
            )
        })?
        .insert("id".to_owned(), serde_json::Value::Null);
    Ok(())
}

fn stamp_server_info(value: &mut serde_json::Value) -> Result<(), io::Error> {
    let Some(result) = value
        .get_mut("result")
        .and_then(serde_json::Value::as_object_mut)
    else {
        return Ok(());
    };
    let meta = result
        .entry("_meta")
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()))
        .as_object_mut()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "MCP result _meta was not an object",
            )
        })?;
    let implementation = serde_json::to_value(crate::server::server_implementation())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    meta.insert(
        "io.modelcontextprotocol/serverInfo".to_owned(),
        implementation,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use remap_protocol::{ControlClient, ControlPaths, Surface};
    use rmcp::ServiceExt;
    use rmcp::model::{ClientJsonRpcMessage, ErrorData, RequestId, ServerJsonRpcMessage};
    use rmcp::transport::Transport;
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use crate::RemapService;
    use crate::lifecycle::{MAX_IN_FLIGHT_REQUESTS, RequestAdmission};

    use super::{BoundedStdioTransport, MAX_MCP_MESSAGE_BYTES};

    #[tokio::test]
    async fn oversized_input_closes_without_unbounded_growth()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut input, reader) = duplex(MAX_MCP_MESSAGE_BYTES + 2);
        let (_output, writer) = duplex(1024);
        let task = tokio::spawn(async move {
            input
                .write_all(&vec![b'x'; MAX_MCP_MESSAGE_BYTES + 1])
                .await?;
            input.write_all(b"\n").await
        });
        let mut transport = BoundedStdioTransport::new(reader, writer, RequestAdmission::new());
        assert!(transport.receive().await.is_none());
        task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn oversized_output_is_rejected_before_any_bytes_are_written()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_input, reader) = duplex(1024);
        let (mut output, writer) = duplex(1024);
        let mut transport = BoundedStdioTransport::new(reader, writer, RequestAdmission::new());
        let message = ServerJsonRpcMessage::error(
            ErrorData::internal_error("x".repeat(MAX_MCP_MESSAGE_BYTES), None),
            Some(RequestId::Number(1)),
        );
        let error = match transport.send(message).await {
            Ok(()) => return Err("oversized output was accepted".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        drop(transport);
        let mut bytes = Vec::new();
        output.read_to_end(&mut bytes).await?;
        assert!(bytes.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn malformed_json_returns_a_bounded_parse_error_and_recovers()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut input, reader) = duplex(4096);
        let (mut output, writer) = duplex(4096);
        let mut transport = BoundedStdioTransport::new(reader, writer, RequestAdmission::new());
        input
            .write_all(b"{\"jsonrpc\":\"2.0\",\"secret\":\"do-not-echo\",\n")
            .await?;
        input
            .write_all(
                b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\",\"params\":{}}\n",
            )
            .await?;
        let received = transport.receive().await.ok_or("transport closed")?;
        assert!(matches!(received, ClientJsonRpcMessage::Notification(_)));
        let mut response = Vec::new();
        loop {
            let byte = output.read_u8().await?;
            response.push(byte);
            if byte == b'\n' {
                break;
            }
        }
        let raw: serde_json::Value = serde_json::from_slice(&response)?;
        assert_eq!(raw.get("id"), Some(&serde_json::Value::Null));
        let message: ServerJsonRpcMessage = serde_json::from_value(raw)?;
        let ServerJsonRpcMessage::Error(error) = message else {
            return Err("malformed JSON did not return an error".into());
        };
        assert_eq!(error.error.code, rmcp::model::ErrorCode::PARSE_ERROR);
        assert_eq!(error.error.message, "Parse error");
        assert_eq!(error.error.data, None);
        assert!(
            !serde_json::to_value(error)?
                .to_string()
                .contains("do-not-echo")
        );
        Ok(())
    }

    #[tokio::test]
    async fn duplicate_live_ids_are_rejected_before_sdk_dispatch()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut input, reader) = duplex(4096);
        let (mut output, writer) = duplex(4096);
        let admission = RequestAdmission::new();
        let mut transport = BoundedStdioTransport::new(reader, writer, admission.clone());
        let request = json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "server/discover",
            "params": modern_params()
        });
        let mut bytes = serde_json::to_vec(&request)?;
        bytes.push(b'\n');
        input.write_all(&bytes).await?;
        input.write_all(&bytes).await?;
        let first = transport.receive().await.ok_or("first request missing")?;
        assert!(matches!(first, ClientJsonRpcMessage::Request(_)));
        let receive = tokio::spawn(async move { transport.receive().await });
        let duplicate = tokio::time::timeout(std::time::Duration::from_secs(1), receive).await??;
        assert!(duplicate.is_none());
        let mut response = Vec::new();
        output.read_to_end(&mut response).await?;
        assert!(response.is_empty());
        assert_eq!(admission.active(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn live_service_remains_bounded_when_output_stops_draining()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let paths = ControlPaths::under(directory.path());
        let admission = RequestAdmission::new();
        let service = RemapService::with_admission(
            ControlClient::new(paths.socket(), Surface::Mcp, env!("CARGO_PKG_VERSION")),
            admission.clone(),
        );
        let (mut input, reader) = duplex(128 * 1024);
        let (mut output, writer) = duplex(64 * 1024);
        let transport = BoundedStdioTransport::new(reader, writer, admission.clone());
        let server_task = tokio::spawn(async move { service.serve(transport).await });
        write_json_line(
            &mut input,
            &json!({
                "jsonrpc": "2.0",
                "id": 0,
                "method": "server/discover",
                "params": modern_params()
            }),
        )
        .await?;
        read_json_line(&mut output).await?;
        let running =
            tokio::time::timeout(std::time::Duration::from_secs(2), server_task).await???;
        for id in 1..=MAX_IN_FLIGHT_REQUESTS * 3 {
            write_json_line(
                &mut input,
                &json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "method": "tools/list",
                    "params": modern_params()
                }),
            )
            .await?;
        }
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while admission.active() < MAX_IN_FLIGHT_REQUESTS {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert_eq!(admission.active(), MAX_IN_FLIGHT_REQUESTS);
        assert_eq!(admission.max_observed(), MAX_IN_FLIGHT_REQUESTS);
        drop(input);
        drop(output);
        running.cancel().await?;
        Ok(())
    }

    #[tokio::test]
    async fn cancelled_requests_release_capacity_and_the_session_remains_usable()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let paths = ControlPaths::under(directory.path());
        let admission = RequestAdmission::new();
        let service = RemapService::with_admission(
            ControlClient::new(paths.socket(), Surface::Mcp, env!("CARGO_PKG_VERSION")),
            admission.clone(),
        );
        let (mut input, reader) = duplex(128 * 1024);
        let (mut output, writer) = duplex(128 * 1024);
        let transport = BoundedStdioTransport::new(reader, writer, admission.clone());
        let server_task = tokio::spawn(async move { service.serve(transport).await });
        write_json_line(
            &mut input,
            &json!({
                "jsonrpc": "2.0",
                "id": 0,
                "method": "server/discover",
                "params": modern_params()
            }),
        )
        .await?;
        read_json_line(&mut output).await?;
        let running =
            tokio::time::timeout(std::time::Duration::from_secs(2), server_task).await???;

        for id in 1..=40 {
            write_json_line(
                &mut input,
                &json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "method": "subscriptions/listen",
                    "params": modern_subscription_params()
                }),
            )
            .await?;
            wait_for_active(&admission, 1).await?;
            write_json_line(
                &mut input,
                &json!({
                    "jsonrpc": "2.0",
                    "method": "notifications/cancelled",
                    "params": {"requestId": id, "reason": "test cancellation"}
                }),
            )
            .await?;
            wait_for_active(&admission, 0).await?;
        }
        write_json_line(
            &mut input,
            &json!({
                "jsonrpc": "2.0",
                "id": 41,
                "method": "ping",
                "params": modern_params()
            }),
        )
        .await?;
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            read_response_for(&mut output, 41),
        )
        .await??;
        assert_eq!(response["id"], 41);
        assert_eq!(admission.max_observed(), 1);
        running.cancel().await?;
        Ok(())
    }

    #[tokio::test]
    async fn saturated_output_closes_instead_of_blocking_input_forever()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut input, reader) = duplex(4096);
        let (_output, writer) = duplex(64);
        let admission = RequestAdmission::new();
        for id in 0..MAX_IN_FLIGHT_REQUESTS {
            let request_id = i64::try_from(id)?;
            admission
                .reserve(RequestId::Number(request_id))
                .map_err(|failure| format!("reserve failed: {failure:?}"))?;
        }
        let mut transport = BoundedStdioTransport::new(reader, writer, admission);
        let stalled = transport.send(ServerJsonRpcMessage::error(
            ErrorData::internal_error("x".repeat(4096), None),
            None,
        ));
        let stalled_task = tokio::spawn(stalled);
        tokio::task::yield_now().await;
        write_json_line(
            &mut input,
            &json!({
                "jsonrpc": "2.0",
                "id": 99,
                "method": "ping",
                "params": modern_params()
            }),
        )
        .await?;
        let received =
            tokio::time::timeout(std::time::Duration::from_secs(1), transport.receive()).await?;
        assert!(received.is_none());
        stalled_task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn invalid_modern_opener_metadata_returns_invalid_params_and_recovers()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let paths = ControlPaths::under(directory.path());
        let admission = RequestAdmission::new();
        let service = RemapService::with_admission(
            ControlClient::new(paths.socket(), Surface::Mcp, env!("CARGO_PKG_VERSION")),
            admission.clone(),
        );
        let (mut input, reader) = duplex(32 * 1024);
        let (mut output, writer) = duplex(32 * 1024);
        let transport = BoundedStdioTransport::new(reader, writer, admission);
        let server_task = tokio::spawn(async move { service.serve(transport).await });
        for request in invalid_modern_openers() {
            write_json_line(&mut input, &request).await?;
        }
        write_json_line(
            &mut input,
            &json!({
                "jsonrpc": "2.0",
                "id": 5,
                "method": "server/discover",
                "params": minimal_modern_params()
            }),
        )
        .await?;
        for expected in [1, 2, 3, 4] {
            let error = read_json_line(&mut output).await?;
            assert_eq!(error["id"], expected);
            assert_eq!(error["error"]["code"], -32602);
        }
        let discovery = read_json_line(&mut output).await?;
        assert_eq!(discovery["id"], 5);
        assert!(discovery.get("result").is_some());
        let running =
            tokio::time::timeout(std::time::Duration::from_secs(2), server_task).await???;
        write_json_line(
            &mut input,
            &json!({
                "jsonrpc": "2.0",
                "id": 6,
                "method": "tools/list",
                "params": minimal_modern_params()
            }),
        )
        .await?;
        let listed = read_json_line(&mut output).await?;
        assert_eq!(listed["id"], 6);
        assert_eq!(
            listed["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
            "remap"
        );
        running.cancel().await?;
        Ok(())
    }

    fn invalid_modern_openers() -> [serde_json::Value; 4] {
        [
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "server/discover",
                "params": {}
            }),
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "server/discover",
                "params": {
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": 20_260_728,
                        "io.modelcontextprotocol/clientInfo": {
                            "name": "bad-meta-test",
                            "version": "1"
                        },
                        "io.modelcontextprotocol/clientCapabilities": null
                    }
                }
            }),
            json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "server/discover",
                "params": {
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                        "io.modelcontextprotocol/clientInfo": "not-an-implementation",
                        "io.modelcontextprotocol/clientCapabilities": {}
                    }
                }
            }),
            json!({
                "jsonrpc": "2.0",
                "id": 4,
                "method": "server/discover",
                "params": {
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                        "io.modelcontextprotocol/clientCapabilities": {},
                        "io.modelcontextprotocol/logLevel": 7
                    }
                }
            }),
        ]
    }

    fn minimal_modern_params() -> serde_json::Value {
        json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {}
            }
        })
    }

    fn modern_params() -> serde_json::Value {
        json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientInfo": {
                    "name": "bounded-transport-test",
                    "version": "1"
                },
                "io.modelcontextprotocol/clientCapabilities": {}
            }
        })
    }

    fn modern_subscription_params() -> serde_json::Value {
        let mut params = modern_params();
        params["notifications"] = json!({
            "resourceSubscriptions": ["remap://status"]
        });
        params
    }

    async fn wait_for_active(
        admission: &RequestAdmission,
        expected: usize,
    ) -> Result<(), tokio::time::error::Elapsed> {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while admission.active() != expected {
                tokio::task::yield_now().await;
            }
        })
        .await
    }

    async fn write_json_line(
        writer: &mut tokio::io::DuplexStream,
        value: &serde_json::Value,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut bytes = serde_json::to_vec(value)?;
        bytes.push(b'\n');
        writer.write_all(&bytes).await?;
        Ok(())
    }

    async fn read_json_line(
        reader: &mut tokio::io::DuplexStream,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let mut bytes = Vec::new();
        loop {
            let byte = reader.read_u8().await?;
            bytes.push(byte);
            if byte == b'\n' {
                return Ok(serde_json::from_slice(&bytes)?);
            }
        }
    }

    async fn read_response_for(
        reader: &mut tokio::io::DuplexStream,
        expected: i64,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        loop {
            let message = read_json_line(reader).await?;
            if message["id"] == expected {
                return Ok(message);
            }
            if !message["id"].is_null() {
                return Err(format!("cancelled request returned a response: {message}").into());
            }
        }
    }
}
