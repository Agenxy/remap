//! Byte streams to a Supgang peer's exposed service, through Supgang's local
//! stream endpoint (Supgang ADR 0006, "Local stream endpoint, version 1";
//! Remap ADR-0026).
//!
//! The endpoint is Supgang's owner-only control socket. One framed request
//! names the target node and service; after a `connected` reply the socket
//! carries the service's raw bytes. The endpoint authorizes on the target
//! owner's exposure and confers nothing beyond what this user can already do
//! with `supgang connect`, so arrival here proves no service identity: a
//! pinned service is still verified by TLS inside the stream.

use std::fmt;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use remap_core::MAX_SERVICE_NAME_BYTES as MAX_SERVICE_BYTES;

/// The request tag version 1 of the endpoint reads.
const REQUEST_MAGIC: &[u8; 8] = b"SUPGIPC1";
/// The version-1 operation that opens a service stream.
const OPEN_STREAM: u8 = 0x07;
/// The largest reply this client reads before the stream begins.
const MAX_REPLY_BYTES: u32 = 4096;

/// Why a stream to a peer's service could not be opened.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum StreamError {
    /// The control socket is missing or would not accept a connection.
    Unavailable,
    /// The socket is not owned by, or not answered by, this user.
    WrongOwner,
    /// Supgang refused the stream: no live session, no exposure, or a limit.
    Refused,
    /// The reply was not the shape version 1 defines.
    Malformed,
}

impl fmt::Display for StreamError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "Supgang's stream endpoint is not available",
            Self::WrongOwner => "Supgang's stream endpoint is not this user's",
            Self::Refused => "Supgang refused a stream to that service",
            Self::Malformed => "Supgang's stream reply could not be read",
        })
    }
}

impl std::error::Error for StreamError {}

/// Where this user's Supgang stream endpoint lives.
#[derive(Debug, Clone)]
pub struct SupgangStreams {
    socket: PathBuf,
}

#[derive(Deserialize)]
struct Reply {
    response: String,
}

impl SupgangStreams {
    /// The endpoint at Supgang's default macOS state directory, when it
    /// exists. `None` elsewhere: a stream is then never attempted.
    #[must_use]
    pub fn discover() -> Option<Self> {
        let home = PathBuf::from(std::env::var_os("HOME")?);
        let socket = home
            .join("Library")
            .join("Application Support")
            .join("org.agenxy.supgang")
            .join("control.sock");
        socket.exists().then(|| Self::at(socket))
    }

    /// An endpoint at an explicit socket path.
    #[must_use]
    pub const fn at(socket: PathBuf) -> Self {
        Self { socket }
    }

    /// Opens a byte stream to `service` on the node whose identity is `node`.
    ///
    /// # Errors
    ///
    /// Returns why no stream exists; never an address or the reply text.
    pub async fn open(&self, node: &[u8; 32], service: &str) -> Result<UnixStream, StreamError> {
        let owner = owner_of(&self.socket).map_err(|_| StreamError::Unavailable)?;
        let mut stream = UnixStream::connect(&self.socket)
            .await
            .map_err(|_| StreamError::Unavailable)?;
        let peer = stream.peer_cred().map_err(|_| StreamError::WrongOwner)?;
        if peer.uid() != owner || !owned_by_home_user(owner) {
            return Err(StreamError::WrongOwner);
        }
        let frame = request_frame(node, service).ok_or(StreamError::Malformed)?;
        stream
            .write_all(&frame)
            .await
            .map_err(|_| StreamError::Unavailable)?;
        let reply = read_reply(&mut stream).await?;
        match reply.response.as_str() {
            "connected" => Ok(stream),
            "error" => Err(StreamError::Refused),
            _ => Err(StreamError::Malformed),
        }
    }
}

/// The version-1 request: length, tag, operation, node, padded service.
fn request_frame(node: &[u8; 32], service: &str) -> Option<Vec<u8>> {
    let name = service.as_bytes();
    if name.is_empty() || name.len() > MAX_SERVICE_BYTES || !name.is_ascii() {
        return None;
    }
    let mut body = Vec::with_capacity(REQUEST_MAGIC.len() + 1 + 32 + MAX_SERVICE_BYTES);
    body.extend_from_slice(REQUEST_MAGIC);
    body.push(OPEN_STREAM);
    body.extend_from_slice(node);
    body.extend_from_slice(name);
    body.resize(REQUEST_MAGIC.len() + 1 + 32 + MAX_SERVICE_BYTES, 0);
    let length = u32::try_from(body.len()).ok()?;
    let mut frame = length.to_be_bytes().to_vec();
    frame.extend_from_slice(&body);
    Some(frame)
}

async fn read_reply(stream: &mut UnixStream) -> Result<Reply, StreamError> {
    let mut length = [0_u8; 4];
    stream
        .read_exact(&mut length)
        .await
        .map_err(|_| StreamError::Malformed)?;
    let length = u32::from_be_bytes(length);
    if length == 0 || length > MAX_REPLY_BYTES {
        return Err(StreamError::Malformed);
    }
    let mut body = vec![0_u8; usize::try_from(length).map_err(|_| StreamError::Malformed)?];
    stream
        .read_exact(&mut body)
        .await
        .map_err(|_| StreamError::Malformed)?;
    serde_json::from_slice(&body).map_err(|_| StreamError::Malformed)
}

fn owner_of(path: &Path) -> io::Result<u32> {
    std::fs::symlink_metadata(path).map(|metadata| metadata.uid())
}

/// The socket's owner must be the user whose home this process runs in, so a
/// socket planted by someone else is refused before any byte is sent.
fn owned_by_home_user(owner: u32) -> bool {
    std::env::var_os("HOME")
        .and_then(|home| owner_of(Path::new(&home)).ok())
        .is_some_and(|home_owner| home_owner == owner)
}

#[cfg(test)]
mod tests {
    use super::request_frame;

    #[test]
    fn the_request_frame_is_exactly_version_one() {
        let node = [0xab; 32];
        let frame = request_frame(&node, "preview").unwrap_or_default();
        assert_eq!(frame.len(), 4 + 57);
        assert_eq!(&frame[..4], &57_u32.to_be_bytes());
        assert_eq!(&frame[4..12], b"SUPGIPC1");
        assert_eq!(frame[12], 0x07);
        assert_eq!(&frame[13..45], &node);
        assert_eq!(&frame[45..52], b"preview");
        assert!(frame[52..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn a_service_name_past_the_bound_is_never_sent() {
        assert!(request_frame(&[0; 32], "").is_none());
        assert!(request_frame(&[0; 32], "seventeen-letters").is_none());
    }
}
