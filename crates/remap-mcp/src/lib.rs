//! MCP tools, resources, and compatibility policy for Remap.

mod lifecycle;
mod output;
mod params;
mod resources;
mod server;
mod transport;
mod ui;

pub use lifecycle::RemapService;
pub use server::SUPPORTED_PROTOCOL_VERSIONS;

use remap_protocol::{ControlClient, Diagnostic};
use rmcp::ServiceExt;
use rmcp::service::{QuitReason, ServerInitializeError};

/// Serves MCP over the process's native standard input and output streams.
///
/// Standard output is reserved exclusively for MCP frames. Runtime failures are
/// returned to the caller so it can report them on standard error.
///
/// # Errors
///
/// Returns a stable diagnostic for handshake, transport, or service-task failure.
pub async fn serve_stdio(client: ControlClient) -> Result<(), Diagnostic> {
    let admission = lifecycle::RequestAdmission::new();
    let transport = transport::BoundedStdioTransport::new(
        tokio::io::stdin(),
        tokio::io::stdout(),
        admission.clone(),
    );
    let service = RemapService::with_admission(client, admission)
        .serve(transport)
        .await
        .map_err(|error| mcp_start_error(&error))?;
    let reason = service.waiting().await.map_err(|_error| {
        mcp_runtime_error(
            "the MCP service task ended unexpectedly",
            "restart the MCP host; run 'remap doctor' if the failure repeats",
            true,
        )
    })?;
    match reason {
        QuitReason::Cancelled | QuitReason::Closed => Ok(()),
        QuitReason::JoinError(_error) => Err(mcp_runtime_error(
            "the MCP service task ended unexpectedly",
            "restart the MCP host; run 'remap doctor' if the failure repeats",
            true,
        )),
        _ => Err(mcp_runtime_error(
            "the MCP service stopped for an unsupported reason",
            "restart the MCP host; run 'remap doctor' if the failure repeats",
            false,
        )),
    }
}

fn mcp_start_error(error: &ServerInitializeError) -> Diagnostic {
    let retryable = matches!(
        error,
        ServerInitializeError::ConnectionClosed(_)
            | ServerInitializeError::TransportError { .. }
            | ServerInitializeError::Cancelled
    );
    mcp_runtime_error(
        "the MCP host did not complete a supported Remap lifecycle",
        "configure the host for MCP 2026-07-28 discovery or 2025-11-25 initialization",
        retryable,
    )
}

fn mcp_runtime_error(message: &str, hint: &str, retryable: bool) -> Diagnostic {
    Diagnostic::new("E_MCP_RUNTIME", message, Some(hint.to_owned()), retryable)
}

#[cfg(test)]
mod tests {
    use rmcp::model::ClientJsonRpcMessage;
    use rmcp::service::ServerInitializeError;
    use serde_json::json;

    use super::mcp_start_error;

    #[test]
    fn startup_diagnostics_never_echo_client_request_bodies()
    -> Result<(), Box<dyn std::error::Error>> {
        let request: ClientJsonRpcMessage = serde_json::from_value(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "remap_set",
                "arguments": {
                    "pattern": "secret-internal-host.corp",
                    "target": "https://private.example"
                }
            }
        }))?;
        let diagnostic = mcp_start_error(&ServerInitializeError::ExpectedInitializeRequest(Some(
            request,
        )));
        let encoded = serde_json::to_string(&diagnostic)?;
        assert!(!encoded.contains("secret-internal-host"));
        assert!(!encoded.contains("private.example"));
        assert!(!diagnostic.retryable);
        Ok(())
    }
}
