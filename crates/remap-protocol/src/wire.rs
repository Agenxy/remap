use std::io;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{Command, CommandResult, Diagnostic, Surface};

/// Current local-control wire contract.
pub const CONTROL_PROTOCOL_VERSION: &str = "remap.control/v1";

/// Maximum encoded request or response accepted by the local-control channel.
pub const MAX_CONTROL_FRAME_BYTES: usize = 1024 * 1024;

/// Maximum encoded domain result before control-envelope overhead.
///
/// The reserved 64 KiB keeps correlation metadata, diagnostics, and future
/// envelope fields from turning a valid domain result into an unwritable frame.
pub const MAX_CONTROL_RESULT_BYTES: usize = MAX_CONTROL_FRAME_BYTES - (64 * 1024);

/// One request submitted to `remapd`.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlRequest {
    /// Wire contract requested by the client.
    pub protocol: String,
    /// Unique request correlation identifier.
    pub request_id: String,
    /// Calling product surface.
    pub surface: Surface,
    /// Calling Remap release.
    pub client_version: String,
    /// Domain command.
    pub command: Command,
}

/// One response returned by `remapd`.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlResponse {
    /// Wire contract used by the daemon.
    pub protocol: String,
    /// Correlation identifier copied from the request.
    pub request_id: String,
    /// Successful result, mutually exclusive with `error`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<CommandResult>,
    /// Stable failure, mutually exclusive with `result`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Diagnostic>,
}

impl ControlResponse {
    /// Creates a successful response.
    #[must_use]
    pub fn success(request_id: impl Into<String>, result: CommandResult) -> Self {
        Self {
            protocol: CONTROL_PROTOCOL_VERSION.to_owned(),
            request_id: request_id.into(),
            result: Some(result),
            error: None,
        }
    }

    /// Creates a failed response.
    #[must_use]
    pub fn failure(request_id: impl Into<String>, error: Diagnostic) -> Self {
        Self {
            protocol: CONTROL_PROTOCOL_VERSION.to_owned(),
            request_id: request_id.into(),
            result: None,
            error: Some(error),
        }
    }
}

/// Writes one length-prefixed JSON frame.
///
/// # Errors
///
/// Returns an I/O error for serialization, oversized output, or transport
/// failure.
pub async fn write_frame<T, W>(writer: &mut W, value: &T) -> io::Result<()>
where
    T: Serialize,
    W: AsyncWrite + Unpin,
{
    write_bounded_frame(writer, value, MAX_CONTROL_FRAME_BYTES).await
}

pub(crate) async fn write_bounded_frame<T, W>(
    writer: &mut W,
    value: &T,
    maximum: usize,
) -> io::Result<()>
where
    T: Serialize,
    W: AsyncWrite + Unpin,
{
    let encoded = serde_json::to_vec(value).map_err(io::Error::other)?;
    if encoded.len() > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "local-control frame exceeds its configured limit",
        ));
    }
    let length = u32::try_from(encoded.len())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    writer.write_u32(length).await?;
    writer.write_all(&encoded).await?;
    writer.flush().await
}

/// Reads one bounded length-prefixed JSON frame.
///
/// # Errors
///
/// Returns an I/O error for malformed lengths, invalid JSON, or transport
/// failure. The payload is never allocated before its declared size is checked.
pub async fn read_frame<T, R>(reader: &mut R) -> io::Result<T>
where
    T: DeserializeOwned,
    R: AsyncRead + Unpin,
{
    read_bounded_frame(reader, MAX_CONTROL_FRAME_BYTES).await
}

pub(crate) async fn read_bounded_frame<T, R>(reader: &mut R, maximum: usize) -> io::Result<T>
where
    T: DeserializeOwned,
    R: AsyncRead + Unpin,
{
    let length = reader.read_u32().await?;
    let length = usize::try_from(length)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if length > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "local-control frame exceeds its configured limit",
        ));
    }
    let mut encoded = vec![0_u8; length];
    reader.read_exact(&mut encoded).await?;
    serde_json::from_slice(&encoded).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid local-control JSON: {error}"),
        )
    })
}
