use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::net::UnixStream;
use tokio::time::timeout;
use uuid::Uuid;

use crate::wire::{ControlRequest, ControlResponse, read_frame, write_frame};
use crate::{CONTROL_PROTOCOL_VERSION, Command, CommandResult, ControlPaths, Diagnostic, Surface};

const CONTROL_TIMEOUT: Duration = Duration::from_secs(15);

/// Stateless client for the authenticated per-user `remapd` control socket.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ControlClient {
    socket: PathBuf,
    surface: Surface,
    client_version: String,
}

impl ControlClient {
    /// Creates a client for the native default socket.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the native application-data path is missing.
    pub fn discover(
        surface: Surface,
        client_version: impl Into<String>,
    ) -> Result<Self, Diagnostic> {
        let paths = ControlPaths::discover()?;
        Ok(Self::new(paths.socket(), surface, client_version))
    }

    /// Creates a client for an explicit socket path.
    #[must_use]
    pub fn new(
        socket: impl AsRef<Path>,
        surface: Surface,
        client_version: impl Into<String>,
    ) -> Self {
        Self {
            socket: socket.as_ref().to_path_buf(),
            surface,
            client_version: client_version.into(),
        }
    }

    /// Sends one command over a fresh authenticated local connection.
    ///
    /// # Errors
    ///
    /// Returns the daemon's stable diagnostic or a bounded transport failure.
    pub async fn execute(&self, command: Command) -> Result<CommandResult, Diagnostic> {
        let request_id = Uuid::new_v4().to_string();
        let request = ControlRequest {
            protocol: CONTROL_PROTOCOL_VERSION.to_owned(),
            request_id: request_id.clone(),
            surface: self.surface,
            client_version: self.client_version.clone(),
            command,
        };
        let response = timeout(CONTROL_TIMEOUT, self.exchange(&request))
            .await
            .map_err(|_| {
                Diagnostic::new(
                    "E_DAEMON_TIMEOUT",
                    "the Remap daemon did not answer within 15 seconds",
                    Some(
                        "the request may have completed; verify authoritative state before retrying"
                            .to_owned(),
                    ),
                    true,
                )
                .with_context("outcome", "unknown")
            })??;
        Self::validate_response(response, &request_id)
    }

    async fn exchange(&self, request: &ControlRequest) -> Result<ControlResponse, Diagnostic> {
        let mut stream = UnixStream::connect(&self.socket)
            .await
            .map_err(|_| Diagnostic::daemon_unavailable())?;
        write_frame(&mut stream, request)
            .await
            .map_err(|error| control_io_error("send", &error))?;
        read_frame(&mut stream)
            .await
            .map_err(|error| control_io_error("receive", &error))
    }

    fn validate_response(
        response: ControlResponse,
        request_id: &str,
    ) -> Result<CommandResult, Diagnostic> {
        if response.protocol != CONTROL_PROTOCOL_VERSION {
            return Err(Diagnostic::protocol(format!(
                "daemon answered with unsupported protocol '{}'",
                response.protocol
            )));
        }
        if response.request_id != request_id {
            return Err(Diagnostic::protocol(
                "daemon response correlation identifier did not match the request",
            ));
        }
        match (response.result, response.error) {
            (Some(result), None) => Ok(result),
            (None, Some(error)) => Err(error),
            _ => Err(Diagnostic::protocol(
                "daemon response must contain exactly one result or error",
            )),
        }
    }
}

fn control_io_error(phase: &str, error: &io::Error) -> Diagnostic {
    if error.kind() == io::ErrorKind::InvalidData {
        return Diagnostic::protocol(format!("could not {phase} a valid control frame: {error}"));
    }
    Diagnostic::new(
        "E_CONTROL_TRANSPORT",
        format!("the daemon connection closed during control {phase}"),
        Some(
            "the request may have completed; verify authoritative state before retrying".to_owned(),
        ),
        true,
    )
    .with_context("outcome", "unknown")
    .with_context("phase", phase)
}
