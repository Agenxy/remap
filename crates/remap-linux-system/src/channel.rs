use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use remap_protocol::{
    SYSTEM_PROTOCOL_VERSION, SystemCommand, SystemRequest, SystemResponse, SystemResult,
    read_system_frame, write_system_frame,
};
use tokio::net::UnixStream;
use tokio::time::timeout;
use uuid::Uuid;

const IO_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
pub(crate) struct SystemChannel {
    path: PathBuf,
    daemon_uid: u32,
}

impl SystemChannel {
    pub(crate) fn new(path: PathBuf, daemon_uid: u32) -> Self {
        Self { path, daemon_uid }
    }

    pub(crate) async fn exchange(&self, command: SystemCommand) -> io::Result<SystemResult> {
        validate_socket(&self.path, self.daemon_uid)?;
        let mut stream = timeout(IO_TIMEOUT, UnixStream::connect(&self.path))
            .await
            .map_err(|_| timed_out("system-control connection timed out"))??;
        let credentials = stream.peer_cred()?;
        if credentials.uid() != self.daemon_uid {
            return Err(permission_denied("system-control peer identity changed"));
        }
        let request_id = Uuid::new_v4();
        let request = SystemRequest {
            protocol: SYSTEM_PROTOCOL_VERSION.to_owned(),
            request_id,
            command,
        };
        timeout(IO_TIMEOUT, write_system_frame(&mut stream, &request))
            .await
            .map_err(|_| timed_out("system-control write timed out"))??;
        let response: SystemResponse =
            timeout(IO_TIMEOUT, read_system_frame(&mut stream))
                .await
                .map_err(|_| timed_out("system-control response timed out"))??;
        if response.protocol != SYSTEM_PROTOCOL_VERSION || response.request_id != request_id {
            return Err(invalid_data("system-control response identity is invalid"));
        }
        match (response.result, response.error) {
            (Some(result), None) => Ok(result),
            (None, Some(_error)) => Err(invalid_data("system-control request was rejected")),
            (Some(_), Some(_)) | (None, None) => {
                Err(invalid_data("system-control response shape is invalid"))
            }
        }
    }
}

fn validate_socket(path: &Path, daemon_uid: u32) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_socket()
        || metadata.uid() != daemon_uid
        || metadata.mode() & 0o777 != 0o600
    {
        return Err(permission_denied(
            "system-control socket metadata is unsafe",
        ));
    }
    Ok(())
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn permission_denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

fn timed_out(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, message)
}
