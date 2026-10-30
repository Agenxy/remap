// SPDX-License-Identifier: GPL-3.0-or-later
//! Carrying one accepted TCP connection to a peer machine's exposed service
//! through Supgang's local stream endpoint (ADR-0033, as ADR-0026 does for
//! HTTP). Supgang authorizes every stream against the peer owner's
//! exposure; Remap adds no authority and never dials the peer itself.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::peer::{PeerResolveError, PeerResolver};
use crate::supgang_stream::{StreamError, SupgangStreams};

/// Receives one line per connection that could not be carried. The daemon
/// writes it to its log; a test collects it.
pub type ConnectionLog = Arc<dyn Fn(&str) + Send + Sync>;

/// How a peer machine is reached: Supgang's stream endpoint, and its
/// resolver for a peer selected by fingerprint. Either may be absent on a
/// machine without Supgang.
#[derive(Clone)]
pub(crate) struct Carrier {
    pub(crate) streams: Option<Arc<SupgangStreams>>,
    pub(crate) resolver: Option<Arc<dyn PeerResolver>>,
    pub(crate) open_timeout: Duration,
    pub(crate) log: ConnectionLog,
}

impl fmt::Debug for Carrier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Carrier")
            .field("streams", &self.streams.is_some())
            .field("resolver", &self.resolver.is_some())
            .finish_non_exhaustive()
    }
}

/// The mapping and service one listener carries connections for.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub(crate) struct Route {
    pub(crate) pattern: String,
    pub(crate) selector: String,
    pub(crate) service: String,
}

/// Why a connection was closed without a stream, as a stable token and a
/// sentence. Neither carries an address.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum CarryFailure {
    /// No stream endpoint, or no Supgang to resolve a fingerprint.
    NoSupgang,
    /// The endpoint is not this user's.
    WrongOwner,
    /// The endpoint answered outside version 1.
    Malformed,
    /// Supgang refused the stream.
    Refused,
    /// Supgang could not say which node a fingerprint selects now.
    UnknownPeer,
    /// No stream opened before the deadline.
    Timeout,
}

impl CarryFailure {
    const fn cause(self) -> &'static str {
        match self {
            Self::NoSupgang => "no-supgang",
            Self::WrongOwner | Self::Malformed => "endpoint",
            Self::Refused => "refused",
            Self::UnknownPeer => "unknown-peer",
            Self::Timeout => "timeout",
        }
    }

    const fn reason(self) -> &'static str {
        match self {
            Self::NoSupgang => "Supgang is not available on this machine",
            Self::WrongOwner => "Supgang's stream endpoint is not this user's",
            Self::Malformed => "Supgang's stream endpoint answered outside version 1",
            Self::Refused => {
                "Supgang refused the stream: the peer may be offline, unknown, or not exposing this service"
            }
            Self::UnknownPeer => "Supgang could not resolve this fingerprint to a current peer",
            Self::Timeout => "no stream opened before the deadline",
        }
    }
}

/// The log line for a connection that could not be carried, in ADR-0028's
/// key style: the mapping's pattern, the service, and the cause.
pub(crate) fn failure_line(route: &Route, failure: CarryFailure) -> String {
    format!(
        "remap gateway: peer machine connection closed. Mapping: {} Service: {} Cause: {} ({})",
        route.pattern,
        route.service,
        failure.cause(),
        failure.reason()
    )
}

impl Carrier {
    /// Opens a stream for `client` and copies bytes both ways until each
    /// side has closed; logs and closes `client` when no stream opens.
    pub(crate) async fn carry(&self, mut client: TcpStream, route: &Route) {
        let mut upstream = match timeout(self.open_timeout, self.open(route)).await {
            Ok(Ok(upstream)) => upstream,
            Ok(Err(failure)) => return (self.log)(&failure_line(route, failure)),
            Err(_elapsed) => return (self.log)(&failure_line(route, CarryFailure::Timeout)),
        };
        let _copied = copy_bidirectional(&mut client, &mut upstream).await;
    }

    async fn open(&self, route: &Route) -> Result<tokio::net::UnixStream, CarryFailure> {
        let streams = self.streams.as_ref().ok_or(CarryFailure::NoSupgang)?;
        let node = self.node(&route.selector).await?;
        streams
            .open(&node, &route.service)
            .await
            .map_err(|error| match error {
                StreamError::Unavailable => CarryFailure::NoSupgang,
                StreamError::Refused => CarryFailure::Refused,
                StreamError::WrongOwner => CarryFailure::WrongOwner,
                StreamError::Malformed => CarryFailure::Malformed,
            })
    }

    /// A node ID is the node. A fingerprint is resolved through Supgang for
    /// every connection, so the answer follows the fleet as it changes.
    async fn node(&self, selector: &str) -> Result<[u8; 32], CarryFailure> {
        if let Some(node) = decode_node_id(selector) {
            return Ok(node);
        }
        let resolver = self.resolver.as_ref().ok_or(CarryFailure::NoSupgang)?;
        resolver
            .resolve_node(selector)
            .await
            .map_err(|error| match error {
                PeerResolveError::NotInstalled | PeerResolveError::Unavailable(_) => {
                    CarryFailure::NoSupgang
                }
                _ => CarryFailure::UnknownPeer,
            })
    }
}

/// Decodes a 64-character lowercase hexadecimal node ID.
fn decode_node_id(selector: &str) -> Option<[u8; 32]> {
    if selector.len() != 64 {
        return None;
    }
    let mut node = [0_u8; 32];
    for (index, byte) in node.iter_mut().enumerate() {
        *byte = u8::from_str_radix(selector.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(node)
}

#[cfg(test)]
mod tests {
    use super::{CarryFailure, Route, decode_node_id, failure_line};

    #[test]
    fn a_node_id_decodes_and_a_fingerprint_does_not() {
        let node = "0f".repeat(32);
        assert_eq!(decode_node_id(&node), Some([0x0f; 32]));
        assert_eq!(decode_node_id("a8a37e32"), None);
        assert_eq!(decode_node_id(&"zz".repeat(32)), None);
    }

    #[test]
    fn the_log_line_names_the_mapping_service_and_cause_only() {
        let route = Route {
            pattern: "pro.agenxy.internal".to_owned(),
            selector: "a8a37e32".to_owned(),
            service: "ssh".to_owned(),
        };
        let line = failure_line(&route, CarryFailure::Refused);
        assert!(line.contains("Mapping: pro.agenxy.internal"));
        assert!(line.contains("Service: ssh"));
        assert!(line.contains("Cause: refused"));
        assert!(!line.contains("a8a37e32"), "the selector stays out: {line}");
        assert!(!line.contains("127."), "no address: {line}");
    }
}
