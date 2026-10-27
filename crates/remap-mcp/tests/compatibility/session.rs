//! Session setup shared by the compatibility proofs.

use std::error::Error;
use std::io;
use std::path::Path;
use std::time::Duration;

use remap_mcp::RemapService;
use remap_protocol::{ControlClient, ControlPaths, Surface};
use rmcp::service::ServerInitializeError;
use serde_json::{Value, json};

pub(super) fn mcp_for(paths: &ControlPaths) -> RemapService {
    RemapService::new(ControlClient::new(
        paths.socket(),
        Surface::Mcp,
        env!("CARGO_PKG_VERSION"),
    ))
}

pub(super) fn modern_meta() -> Value {
    json!({
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientInfo": {
                "name": "modern-compatibility-test",
                "version": "1"
            },
            "io.modelcontextprotocol/clientCapabilities": {}
        }
    })
}

/// Awaits a server task whose client has already sent a non-discover request.
///
/// The SDK answers `server/discover` during bootstrap and returns the running
/// service only once a later request opens the lifecycle.
pub(super) async fn opened<T>(
    task: tokio::task::JoinHandle<Result<T, ServerInitializeError>>,
) -> Result<T, Box<dyn Error>> {
    Ok(tokio::time::timeout(Duration::from_secs(1), task).await???)
}

pub(super) async fn wait_for_socket(path: &Path) -> Result<(), Box<dyn Error>> {
    for _attempt in 0..100 {
        if path.exists() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err(io::Error::other("daemon socket did not appear within one second").into())
}
