// SPDX-License-Identifier: GPL-3.0-or-later
use std::io;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use uuid::Uuid;

use crate::Diagnostic;
use crate::wire::{read_bounded_frame, write_bounded_frame};

/// Root-supervisor wire contract used only for resolver-plan lifecycle.
pub const SYSTEM_PROTOCOL_VERSION: &str = "remap.system/v1";

const MAX_SYSTEM_FRAME_BYTES: usize = 16 * 1024;

/// One narrowly scoped request from the native resolver supervisor.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemRequest {
    /// Wire contract requested by the native supervisor.
    pub protocol: String,
    /// Unique correlation identifier.
    pub request_id: Uuid,
    /// Resolver-only command.
    pub command: SystemCommand,
}

/// Resolver-plan operations available to the privileged supervisor.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SystemCommand {
    /// Publishes a complete, ordered resolver generation.
    PublishResolverPlan {
        /// Integrity-bound native activation identity.
        activation_id: Uuid,
        /// Strictly increasing generation number.
        generation: u64,
        /// Ordered upstream DNS endpoints.
        upstreams: Vec<SocketAddr>,
    },
    /// Stops forwarding through one exact generation.
    InvalidateResolverPlan {
        /// Integrity-bound native activation identity.
        activation_id: Uuid,
        /// Exact active generation to invalidate.
        generation: u64,
    },
    /// Reads non-sensitive resolver generation state.
    ResolverHealth,
}

/// One bounded response from `remapd` to the native supervisor.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemResponse {
    /// Wire contract used by the daemon.
    pub protocol: String,
    /// Correlation identifier copied from the request.
    pub request_id: Uuid,
    /// Successful result, mutually exclusive with `error`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<SystemResult>,
    /// Stable failure, mutually exclusive with `result`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Diagnostic>,
}

/// Resolver state intentionally excludes endpoint addresses and user data.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemResult {
    /// Bound activation identity after the first valid publication.
    pub activation_id: Option<Uuid>,
    /// Active resolver generation, absent while forwarding is invalidated.
    pub active_generation: Option<u64>,
    /// Highest generation the daemon has accepted since it started, sent only
    /// when it exceeds `active_generation` (for example after invalidation).
    ///
    /// Absent means the daemon is older than this field, has accepted
    /// nothing, or its high-water equals the active generation. In every one
    /// of those cases a supervisor that publishes above
    /// `max(active_generation, highest_accepted_generation, its own memory)`
    /// chooses a generation the daemon accepts. Omitting the equal case keeps
    /// steady-state responses byte-identical to the original v1 contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub highest_accepted_generation: Option<u64>,
    /// Present only while every upstream of the daemon's current set has
    /// stopped answering over its bounded window (ADR-0036).
    ///
    /// Absent means the upstreams answer, too little evidence exists yet, or
    /// the daemon is older than this field. Omitting it while healthy keeps
    /// steady-state responses byte-identical to the original v1 contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_failure: Option<UpstreamFailure>,
}

/// Why the daemon judges that its upstream resolvers stopped answering. It
/// carries counts and a duration, never an address.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamFailure {
    /// The most frequent failure among the unanswered queries.
    pub cause: UpstreamFailureCause,
    /// Queries that went unanswered since the last answer.
    pub unanswered_queries: u32,
    /// Milliseconds since the first of those queries failed.
    pub unanswered_for_ms: u64,
}

/// How the unanswered queries failed.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamFailureCause {
    /// No upstream replied before the deadline, as when a VPN's DNS leak
    /// protection drops the packets.
    TimedOut,
    /// Upstreams refused the query or the connection.
    Refused,
    /// The network reported the upstreams unreachable.
    Unreachable,
}

impl UpstreamFailure {
    /// The status diagnostic `remap status`, `remap doctor`, and MCP show.
    #[must_use]
    pub fn diagnostic(&self) -> Diagnostic {
        let seconds = self.unanswered_for_ms.saturating_add(500) / 1_000;
        let span = if seconds == 1 {
            "1 second".to_owned()
        } else {
            format!("{seconds} seconds")
        };
        Diagnostic::new(
            UPSTREAM_UNANSWERED_CODE,
            format!(
                "upstream DNS not answering: every upstream resolver {} for the last {} queries over {span}",
                self.cause.describe(),
                self.unanswered_queries
            ),
            Some(
                "names Remap does not own fall back to ordinary DNS; a VPN's DNS leak protection \
                 can block the resolvers Remap forwards to; 'remap-system status' on macOS and \
                 the remap-resolver.service journal on Linux show the fallback"
                    .to_owned(),
            ),
            true,
        )
        .with_context("cause", self.cause.as_str())
        .with_context("unanswered_queries", self.unanswered_queries.to_string())
        .with_context("unanswered_for_ms", self.unanswered_for_ms.to_string())
    }
}

/// Stable code for upstream resolvers that stopped answering (ADR-0036).
pub const UPSTREAM_UNANSWERED_CODE: &str = "E_DNS_UPSTREAM_UNANSWERED";

impl UpstreamFailureCause {
    /// Plain words for status output.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::TimedOut => "timed out",
            Self::Refused => "refused the queries",
            Self::Unreachable => "were unreachable",
        }
    }

    /// Stable lowercase name, as on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TimedOut => "timed_out",
            Self::Refused => "refused",
            Self::Unreachable => "unreachable",
        }
    }
}

impl SystemResult {
    /// Builds a result, reporting the high-water only when it adds information.
    #[must_use]
    pub fn new(
        activation_id: Option<Uuid>,
        active_generation: Option<u64>,
        highest_accepted_generation: Option<u64>,
    ) -> Self {
        let highest_accepted_generation = highest_accepted_generation
            .filter(|highest| active_generation.is_none_or(|active| *highest > active));
        Self {
            activation_id,
            active_generation,
            highest_accepted_generation,
            upstream_failure: None,
        }
    }

    /// Adds the daemon's verdict that its upstreams stopped answering.
    #[must_use]
    pub const fn with_upstream_failure(mut self, failure: Option<UpstreamFailure>) -> Self {
        self.upstream_failure = failure;
        self
    }
}

impl SystemResponse {
    /// Creates a successful resolver-only response.
    #[must_use]
    pub fn success(request_id: Uuid, result: SystemResult) -> Self {
        Self {
            protocol: SYSTEM_PROTOCOL_VERSION.to_owned(),
            request_id,
            result: Some(result),
            error: None,
        }
    }

    /// Creates a failed resolver-only response.
    #[must_use]
    pub fn failure(request_id: Uuid, error: Diagnostic) -> Self {
        Self {
            protocol: SYSTEM_PROTOCOL_VERSION.to_owned(),
            request_id,
            result: None,
            error: Some(error),
        }
    }
}

/// Reads one frame without allocating beyond the 16 KiB system limit.
///
/// # Errors
///
/// Returns an I/O error for malformed, oversized, or incomplete input.
pub async fn read_system_frame<T, R>(reader: &mut R) -> io::Result<T>
where
    T: serde::de::DeserializeOwned,
    R: AsyncRead + Unpin,
{
    read_bounded_frame(reader, MAX_SYSTEM_FRAME_BYTES).await
}

/// Writes one frame within the 16 KiB system limit.
///
/// # Errors
///
/// Returns an I/O error for serialization, oversized output, or transport failure.
pub async fn write_system_frame<T, W>(writer: &mut W, value: &T) -> io::Result<()>
where
    T: Serialize,
    W: AsyncWrite + Unpin,
{
    write_bounded_frame(writer, value, MAX_SYSTEM_FRAME_BYTES).await
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::net::{Ipv4Addr, SocketAddr};

    use tokio::io::duplex;
    use uuid::Uuid;

    use super::{
        SYSTEM_PROTOCOL_VERSION, SystemCommand, SystemRequest, SystemResult, UpstreamFailure,
        UpstreamFailureCause, read_system_frame, write_system_frame,
    };

    #[tokio::test]
    async fn resolver_plan_round_trip_preserves_order_and_identity() -> Result<(), Box<dyn Error>> {
        let activation_id = Uuid::new_v4();
        let request = SystemRequest {
            protocol: SYSTEM_PROTOCOL_VERSION.to_owned(),
            request_id: Uuid::new_v4(),
            command: SystemCommand::PublishResolverPlan {
                activation_id,
                generation: 7,
                upstreams: vec![
                    SocketAddr::from((Ipv4Addr::new(192, 0, 2, 2), 53)),
                    SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 53)),
                ],
            },
        };
        let (mut writer, mut reader) = duplex(32 * 1024);
        write_system_frame(&mut writer, &request).await?;
        let decoded: SystemRequest = read_system_frame(&mut reader).await?;
        assert_eq!(decoded, request);
        Ok(())
    }

    #[test]
    fn high_water_is_sent_only_when_it_exceeds_the_active_generation() -> Result<(), Box<dyn Error>>
    {
        let activation_id = Uuid::new_v4();
        let steady = SystemResult::new(Some(activation_id), Some(5), Some(5));
        assert_eq!(steady.highest_accepted_generation, None);
        let steady_json = serde_json::to_value(&steady)?;
        assert_eq!(
            steady_json,
            serde_json::json!({
                "activation_id": activation_id,
                "active_generation": 5,
            })
        );
        let dormant = SystemResult::new(None, None, None);
        assert_eq!(
            serde_json::to_value(&dormant)?,
            serde_json::json!({"activation_id": null, "active_generation": null})
        );
        let invalidated = SystemResult::new(None, None, Some(9));
        assert_eq!(
            serde_json::to_value(&invalidated)?,
            serde_json::json!({
                "activation_id": null,
                "active_generation": null,
                "highest_accepted_generation": 9,
            })
        );
        Ok(())
    }

    #[test]
    fn a_result_from_a_daemon_without_the_high_water_still_decodes() -> Result<(), Box<dyn Error>> {
        let decoded: SystemResult =
            serde_json::from_str(r#"{"activation_id":null,"active_generation":3}"#)?;
        assert_eq!(decoded, SystemResult::new(None, Some(3), None));
        let current: SystemResult = serde_json::from_str(
            r#"{"activation_id":null,"active_generation":null,"highest_accepted_generation":3}"#,
        )?;
        assert_eq!(current.highest_accepted_generation, Some(3));
        Ok(())
    }

    #[test]
    fn upstream_failure_is_additive_and_carries_no_address() -> Result<(), Box<dyn Error>> {
        let healthy = SystemResult::new(None, Some(4), None).with_upstream_failure(None);
        assert_eq!(
            serde_json::to_value(&healthy)?,
            serde_json::json!({"activation_id": null, "active_generation": 4})
        );
        let failing =
            SystemResult::new(None, Some(4), None).with_upstream_failure(Some(UpstreamFailure {
                cause: UpstreamFailureCause::TimedOut,
                unanswered_queries: 12,
                unanswered_for_ms: 9_000,
            }));
        let encoded = serde_json::to_value(&failing)?;
        assert_eq!(
            encoded["upstream_failure"],
            serde_json::json!({
                "cause": "timed_out",
                "unanswered_queries": 12,
                "unanswered_for_ms": 9_000,
            })
        );
        let decoded: SystemResult = serde_json::from_value(encoded)?;
        assert_eq!(decoded, failing);
        let diagnostic = failing
            .upstream_failure
            .ok_or_else(|| std::io::Error::other("the failure disappeared"))?
            .diagnostic();
        assert_eq!(diagnostic.code, "E_DNS_UPSTREAM_UNANSWERED");
        assert!(diagnostic.message.starts_with("upstream DNS not answering"));
        assert!(
            diagnostic
                .message
                .contains("timed out for the last 12 queries over 9 seconds")
        );
        assert_eq!(
            diagnostic.context.get("cause").map(String::as_str),
            Some("timed_out")
        );
        let older: SystemResult =
            serde_json::from_str(r#"{"activation_id":null,"active_generation":4}"#)?;
        assert_eq!(older.upstream_failure, None);
        Ok(())
    }

    #[tokio::test]
    async fn declared_system_frame_above_sixteen_kibibytes_is_rejected()
    -> Result<(), Box<dyn Error>> {
        let (mut writer, mut reader) = duplex(8);
        tokio::io::AsyncWriteExt::write_u32(&mut writer, 16_385).await?;
        let result = read_system_frame::<SystemRequest, _>(&mut reader).await;
        assert!(result.is_err());
        Ok(())
    }
}
