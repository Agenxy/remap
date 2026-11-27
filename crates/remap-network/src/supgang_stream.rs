// SPDX-License-Identifier: GPL-3.0-or-later
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
//!
//! A peer allows only so many tunnels at once. A refusal that frees itself
//! (the peer at its limit, or its session being re-established) is waited
//! out briefly with [`SupgangStreams::open_patiently`] instead of failing
//! the request at once (ADR-0040).

use std::fmt;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::{Instant, sleep};

use remap_core::MAX_SERVICE_NAME_BYTES as MAX_SERVICE_BYTES;

/// The request tag version 1 of the endpoint reads.
const REQUEST_MAGIC: &[u8; 8] = b"SUPGIPC1";
/// The version-1 operation that opens a service stream.
const OPEN_STREAM: u8 = 0x07;
/// The largest reply this client reads before the stream begins.
const MAX_REPLY_BYTES: u32 = 4096;
/// The longest a caller waits on a peer whose tunnels are all in use.
pub(crate) const BUSY_PATIENCE: Duration = Duration::from_secs(3);
/// The first pause before asking a busy peer again; it doubles each time.
const FIRST_BACKOFF: Duration = Duration::from_millis(20);
/// The longest pause between two asks of a busy peer.
const MAX_BACKOFF: Duration = Duration::from_millis(250);
/// How long a plain `refused` is asked again. Peers before Supgang's
/// `upstream_unavailable` reply send `refused` both for a service that is
/// not exposed and for one whose own listener briefly turned a connection
/// away, so it gets a short grace, not the full patience.
const REFUSED_GRACE: Duration = Duration::from_millis(300);
/// Refusal codes Supgang sends for a condition that ends on its own: a
/// tunnel slot frees, or the session to the peer is re-established.
const TRANSIENT_CODES: [&str; 7] = [
    "peer_at_capacity",
    "upstream_unavailable",
    "peer_full",
    "runtime_full",
    "session_failed",
    "not_connected",
    "authorization_lapsed",
];

/// Why a stream to a peer's service could not be opened.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum StreamError {
    /// The control socket is missing or would not accept a connection.
    Unavailable,
    /// The socket is not owned by, or not answered by, this user.
    WrongOwner,
    /// Supgang refused the stream for good: revoked, not exposed, or a
    /// refusal this client does not know to be transient.
    Refused,
    /// Supgang declined for now: the peer's tunnels are all in use or its
    /// session is being re-established. Asking again shortly may succeed.
    Busy,
    /// Supgang sent `refused`, which an older peer also sends when the
    /// service's own listener turned a connection away. Asked again only
    /// briefly; reported as [`StreamError::Refused`].
    Declined,
    /// The reply was not the shape version 1 defines.
    Malformed,
}

impl fmt::Display for StreamError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "Supgang's stream endpoint is not available",
            Self::WrongOwner => "Supgang's stream endpoint is not this user's",
            Self::Refused | Self::Declined => "Supgang refused a stream to that service",
            Self::Busy => "the peer has no free stream right now",
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
    /// The stable refusal code, from Supgang releases that send one.
    #[serde(default)]
    code: Option<String>,
}

impl Reply {
    /// A coded refusal is transient only when its code says so. A refusal
    /// without a code comes from a Supgang that cannot say why, and that
    /// sends the same reply for a peer at its limit as for a dead session,
    /// so it is treated as transient and waited out briefly.
    fn refusal(&self) -> StreamError {
        match self.code.as_deref() {
            None => StreamError::Busy,
            Some(code) if TRANSIENT_CODES.contains(&code) => StreamError::Busy,
            Some("refused") => StreamError::Declined,
            Some(_) => StreamError::Refused,
        }
    }
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
        Self::existing(socket)
    }

    /// The endpoint at `socket` if that socket exists now.
    #[must_use]
    pub fn existing(socket: PathBuf) -> Option<Self> {
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
            "error" => Err(reply.refusal()),
            _ => Err(StreamError::Malformed),
        }
    }

    /// Opens a stream like [`Self::open`], asking again with a growing
    /// pause while the peer is [`StreamError::Busy`], for at most
    /// `patience`, and while it is [`StreamError::Declined`], for at most
    /// the shorter refusal grace. Every other answer is returned at once.
    ///
    /// # Errors
    ///
    /// Returns why no stream exists; `Busy` when the peer stayed busy.
    pub async fn open_patiently(
        &self,
        node: &[u8; 32],
        service: &str,
        patience: Duration,
    ) -> Result<UnixStream, StreamError> {
        let started = Instant::now();
        let mut pause = FIRST_BACKOFF;
        loop {
            let answered = self.open(node, service).await;
            let budget = match answered {
                Err(StreamError::Busy) => patience,
                Err(StreamError::Declined) => REFUSED_GRACE.min(patience),
                _ => return answered,
            };
            if started.elapsed() + pause >= budget {
                return answered.map_err(|error| match error {
                    StreamError::Declined => StreamError::Refused,
                    other => other,
                });
            }
            sleep(pause).await;
            pause = (pause * 2).min(MAX_BACKOFF);
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
    // Supgang before its explicit capacity refusal (Supgang #64) closed an
    // over-limit stream without a reply, so a close before the first byte is a busy peer, not a fault.
    stream.read_exact(&mut length).await.map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            StreamError::Busy
        } else {
            StreamError::Malformed
        }
    })?;
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
    use super::{Reply, StreamError, request_frame};

    fn refusal(json: &str) -> Option<StreamError> {
        serde_json::from_str::<Reply>(json)
            .ok()
            .map(|reply| reply.refusal())
    }

    #[test]
    fn only_a_transient_code_or_no_code_is_waited_out() {
        for code in [
            "peer_at_capacity",
            "upstream_unavailable",
            "peer_full",
            "session_failed",
            "not_connected",
        ] {
            let json = format!(r#"{{"response":"error","code":"{code}","message":"m"}}"#);
            assert_eq!(refusal(&json), Some(StreamError::Busy), "{code}");
        }
        assert_eq!(
            refusal(r#"{"response":"error","code":"refused","message":"m"}"#),
            Some(StreamError::Declined)
        );
        for code in ["revoked", "invalid_name", "unknown", "a-future-code"] {
            let json = format!(r#"{{"response":"error","code":"{code}","message":"m"}}"#);
            assert_eq!(refusal(&json), Some(StreamError::Refused), "{code}");
        }
        assert_eq!(
            refusal(r#"{"response":"error","message":"m"}"#),
            Some(StreamError::Busy)
        );
    }

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
