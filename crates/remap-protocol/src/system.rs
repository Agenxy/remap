// SPDX-License-Identifier: GPL-3.0-or-later
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::num::NonZeroU16;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use uuid::Uuid;

use crate::Diagnostic;
use crate::wire::{read_bounded_frame, write_bounded_frame};

/// Root-supervisor wire contract used only for resolver-plan lifecycle.
pub const SYSTEM_PROTOCOL_VERSION: &str = "remap.system/v1";

/// The largest system frame either side accepts.
pub const MAX_SYSTEM_FRAME_BYTES: usize = 16 * 1024;

/// The most listeners one exchange names, and so the most descriptors one
/// adoption carries. Root pages through the rest in later exchanges.
pub const MAX_LISTENERS_PER_EXCHANGE: usize = 64;

/// One reserved address and port a peer-machine name listens on (ADR-0033).
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerAddress {
    /// The reserved loopback address.
    pub address: Ipv4Addr,
    /// The port the owner listed for one service.
    pub port: NonZeroU16,
}

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
    /// Reads the loopback addresses that enabled peer-machine names answer
    /// with (ADR-0033), so the root supervisor can hold them on `lo0`. Only
    /// addresses cross: never a name, a peer, or a service.
    LoopbackReservations,
    /// Hands `remapd` listening sockets the root supervisor created on
    /// reserved addresses, because only root may bind a port below 1024 on
    /// one (ADR-0033 amendment). The descriptors travel as `SCM_RIGHTS` with
    /// this frame, one per listener, in this order.
    AdoptPeerMachineListeners {
        /// At most [`MAX_LISTENERS_PER_EXCHANGE`] listeners, one per descriptor.
        listeners: Vec<ListenerAddress>,
    },
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
    /// Present only in the answer to [`SystemCommand::LoopbackReservations`],
    /// so every other response stays byte-identical to the original v1
    /// contract. The root side validates each address before acting on any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loopback_reservations: Option<Vec<Ipv4Addr>>,
    /// Present with `loopback_reservations`: listeners of enabled
    /// peer-machine names that `remapd` does not yet hold, at most
    /// [`MAX_LISTENERS_PER_EXCHANGE`] of them in ascending order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unheld_listeners: Option<Vec<ListenerAddress>>,
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
            loopback_reservations: None,
            unheld_listeners: None,
        }
    }

    /// Adds the answer to [`SystemCommand::LoopbackReservations`], in
    /// ascending order.
    #[must_use]
    pub fn with_loopback_reservations(
        mut self,
        reservations: impl IntoIterator<Item = Ipv4Addr>,
    ) -> Self {
        let mut reservations: Vec<Ipv4Addr> = reservations.into_iter().collect();
        reservations.sort_unstable();
        self.loopback_reservations = Some(reservations);
        self
    }

    /// Adds the first [`MAX_LISTENERS_PER_EXCHANGE`] unheld listeners, in
    /// ascending order. Root asks again for the rest.
    #[must_use]
    pub fn with_unheld_listeners(
        mut self,
        listeners: impl IntoIterator<Item = ListenerAddress>,
    ) -> Self {
        let mut listeners: Vec<ListenerAddress> = listeners.into_iter().collect();
        listeners.sort_unstable();
        listeners.truncate(MAX_LISTENERS_PER_EXCHANGE);
        self.unheld_listeners = Some(listeners);
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

/// Decodes one system request from a frame's payload, for a reader that
/// receives the frame itself because descriptors may travel with it.
///
/// # Errors
///
/// Returns `InvalidData` when the payload is not exactly one system request.
pub fn decode_system_request(payload: &[u8]) -> io::Result<SystemRequest> {
    serde_json::from_slice(payload).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid system request JSON: {error}"),
        )
    })
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
        SYSTEM_PROTOCOL_VERSION, SystemCommand, SystemRequest, SystemResult, read_system_frame,
        write_system_frame,
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
    fn loopback_reservations_have_their_own_kind_and_field() -> Result<(), Box<dyn Error>> {
        let request: SystemRequest = serde_json::from_value(serde_json::json!({
            "protocol": SYSTEM_PROTOCOL_VERSION,
            "request_id": Uuid::nil(),
            "command": {"kind": "loopback_reservations"},
        }))?;
        assert_eq!(request.command, SystemCommand::LoopbackReservations);
        let result = SystemResult::new(None, None, None).with_loopback_reservations([
            Ipv4Addr::new(127, 77, 0, 2),
            Ipv4Addr::new(127, 77, 0, 1),
        ]);
        assert_eq!(
            serde_json::to_value(&result)?,
            serde_json::json!({
                "activation_id": null,
                "active_generation": null,
                "loopback_reservations": ["127.77.0.1", "127.77.0.2"],
            })
        );
        Ok(())
    }

    #[tokio::test]
    async fn the_largest_reservation_answer_fits_one_frame() -> Result<(), Box<dyn Error>> {
        let result = SystemResult::new(Some(Uuid::new_v4()), Some(u64::MAX), Some(u64::MAX))
            .with_loopback_reservations((0..256u16).map(|index| {
                let [high, low] = (0xFF00 + index).to_be_bytes();
                Ipv4Addr::new(127, 77, high, low)
            }));
        let (mut writer, mut reader) = duplex(32 * 1024);
        write_system_frame(
            &mut writer,
            &super::SystemResponse::success(Uuid::new_v4(), result),
        )
        .await?;
        let decoded: super::SystemResponse = read_system_frame(&mut reader).await?;
        assert_eq!(
            decoded
                .result
                .and_then(|result| result.loopback_reservations)
                .map(|list| list.len()),
            Some(256)
        );
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
