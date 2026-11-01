// SPDX-License-Identifier: GPL-3.0-or-later
//! Carrying one accepted TCP connection to a peer machine's exposed service
//! through Supgang's local stream endpoint (ADR-0033, as ADR-0026 does for
//! HTTP). Supgang authorizes every stream against the peer owner's
//! exposure; Remap adds no authority and never dials the peer itself.

use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::machine_idle::carry_until_idle;
use crate::peer::{PeerResolveError, PeerResolver, SupgangResolver};
use crate::supgang_stream::{StreamError, SupgangStreams};

/// The longest a carried connection may pass no byte in either direction.
///
/// Two hours outlasts an ssh session left open over a long break, and
/// matches the TCP keepalive default, so an idle session is no worse off
/// than on a direct socket. It still reclaims a connection whose peer
/// vanished without closing, so dead carriage cannot hold the connection
/// budget for longer than that.
pub const PEER_MACHINE_IDLE_TIMEOUT: Duration = Duration::from_hours(2);
/// At most one refusal line per cause in this interval; the counters keep
/// the totals.
const REFUSAL_LOG_INTERVAL: Duration = Duration::from_secs(10);

/// Receives one line per connection that could not be carried. The daemon
/// writes it to its log; a test collects it.
pub type ConnectionLog = Arc<dyn Fn(&str) + Send + Sync>;

/// How a peer machine is reached: Supgang's stream endpoint, and its
/// resolver for a peer selected by fingerprint. Either may be absent on a
/// machine without Supgang.
#[derive(Clone)]
pub(crate) struct Carrier {
    pub(crate) streams: Lookup<SupgangStreams>,
    pub(crate) resolver: Lookup<dyn PeerResolver>,
    pub(crate) open_timeout: Duration,
    pub(crate) idle_timeout: Duration,
    pub(crate) log: ConnectionLog,
    pub(crate) refusals: RefusalCounts,
}

/// Where a Supgang component comes from: looked up again for every
/// connection, so a Supgang installed or started after `remapd` is found
/// without a restart, or fixed by a test.
pub(crate) enum Lookup<T: ?Sized> {
    Discover,
    /// Looked for at one path for every connection, as `Discover` looks at
    /// Supgang's default one; for a test.
    At(PathBuf),
    Fixed(Option<Arc<T>>),
}

impl<T: ?Sized> Clone for Lookup<T> {
    fn clone(&self) -> Self {
        match self {
            Self::Discover => Self::Discover,
            Self::At(path) => Self::At(path.clone()),
            Self::Fixed(value) => Self::Fixed(value.clone()),
        }
    }
}

const CAUSE_COUNT: usize = CarryFailure::CAUSES.len();

/// For each cause: when its line was last written, and how many were held
/// back since.
type Pacing = [(Option<Instant>, u64); CAUSE_COUNT];

/// How many connections were closed without a stream since the daemon
/// started, one counter per cause token: bounded by the five causes,
/// whatever the traffic. It also paces the log to one line per cause per
/// [`REFUSAL_LOG_INTERVAL`].
#[derive(Debug, Clone, Default)]
pub(crate) struct RefusalCounts {
    counts: Arc<[AtomicU64; CAUSE_COUNT]>,
    pacing: Arc<Mutex<Pacing>>,
}

impl RefusalCounts {
    /// Counts one refusal. When a line is due, returns how many were held
    /// back for this cause since the last one; `None` inside the interval.
    fn record(&self, failure: CarryFailure, now: Instant) -> Option<u64> {
        let index = CarryFailure::CAUSES
            .iter()
            .position(|cause| *cause == failure.cause())?;
        self.counts[index].fetch_add(1, Ordering::Relaxed);
        let mut pacing = self.pacing.lock().ok()?;
        let (last, held) = &mut pacing[index];
        if last.is_some_and(|logged| now.duration_since(logged) < REFUSAL_LOG_INTERVAL) {
            *held += 1;
            return None;
        }
        *last = Some(now);
        Some(std::mem::take(held))
    }

    /// The causes seen so far and their counts, in token order.
    pub(crate) fn snapshot(&self) -> Vec<(&'static str, u64)> {
        CarryFailure::CAUSES
            .iter()
            .zip(self.counts.iter())
            .map(|(cause, count)| (*cause, count.load(Ordering::Relaxed)))
            .filter(|(_, count)| *count > 0)
            .collect()
    }
}

impl fmt::Debug for Carrier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Carrier")
            .field(
                "streams_discovered",
                &matches!(self.streams, Lookup::Discover),
            )
            .field(
                "resolver_discovered",
                &matches!(self.resolver, Lookup::Discover),
            )
            .finish_non_exhaustive()
    }
}

/// The mapping and service one listener carries connections for. The
/// pattern stays inside the runtime: no log line carries it.
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
    /// Every cause token, in the order status reports them.
    pub(crate) const CAUSES: [&'static str; 5] = [
        "endpoint",
        "no-supgang",
        "refused",
        "timeout",
        "unknown-peer",
    ];

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
/// key style: the service and the cause. Routine logs name no mapping
/// (PRIVACY.md); `remap status` shows the owner which mapping's listener
/// it was and counts each cause.
pub(crate) fn failure_line(route: &Route, failure: CarryFailure, held: u64) -> String {
    let line = format!(
        "remap gateway: peer machine connection closed. Service: {} Cause: {} ({})",
        route.service,
        failure.cause(),
        failure.reason()
    );
    if held == 0 {
        return line;
    }
    format!("{line} [{held} more with this cause not logged]")
}

impl Carrier {
    /// Opens a stream for `client` and copies bytes both ways until each
    /// side has closed; logs and closes `client` when no stream opens.
    pub(crate) async fn carry(&self, mut client: TcpStream, route: &Route) {
        let mut upstream = match timeout(self.open_timeout, self.open(route)).await {
            Ok(Ok(upstream)) => upstream,
            Ok(Err(failure)) => return self.refuse(route, failure),
            Err(_elapsed) => return self.refuse(route, CarryFailure::Timeout),
        };
        carry_until_idle(&mut client, &mut upstream, self.idle_timeout).await;
    }

    fn refuse(&self, route: &Route, failure: CarryFailure) {
        if let Some(held) = self.refusals.record(failure, Instant::now()) {
            (self.log)(&failure_line(route, failure, held));
        }
    }

    fn current_streams(&self) -> Option<Arc<SupgangStreams>> {
        match &self.streams {
            Lookup::Discover => SupgangStreams::discover().map(Arc::new),
            Lookup::At(socket) => SupgangStreams::existing(socket.clone()).map(Arc::new),
            Lookup::Fixed(streams) => streams.clone(),
        }
    }

    fn current_resolver(&self) -> Option<Arc<dyn PeerResolver>> {
        match &self.resolver {
            Lookup::Discover => SupgangResolver::discover()
                .map(|resolver| Arc::new(resolver) as Arc<dyn PeerResolver>),
            Lookup::At(command) => command
                .is_file()
                .then(|| Arc::new(SupgangResolver::at(command.clone())) as Arc<dyn PeerResolver>),
            Lookup::Fixed(resolver) => resolver.clone(),
        }
    }

    async fn open(&self, route: &Route) -> Result<tokio::net::UnixStream, CarryFailure> {
        let streams = self.current_streams().ok_or(CarryFailure::NoSupgang)?;
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
        let resolver = self.current_resolver().ok_or(CarryFailure::NoSupgang)?;
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
    use std::time::{Duration, Instant};

    use super::{CarryFailure, RefusalCounts, Route, decode_node_id, failure_line};

    #[test]
    fn a_node_id_decodes_and_a_fingerprint_does_not() {
        let node = "0f".repeat(32);
        assert_eq!(decode_node_id(&node), Some([0x0f; 32]));
        assert_eq!(decode_node_id("a8a37e32"), None);
        assert_eq!(decode_node_id(&"zz".repeat(32)), None);
    }

    #[test]
    fn the_log_line_names_the_service_and_cause_only() {
        let route = Route {
            pattern: "pro.agenxy.internal".to_owned(),
            selector: "a8a37e32".to_owned(),
            service: "ssh".to_owned(),
        };
        let line = failure_line(&route, CarryFailure::Refused, 0);
        assert!(
            !line.contains("pro.agenxy.internal"),
            "no mapped name: {line}"
        );
        assert!(line.contains("Service: ssh"));
        assert!(line.contains("Cause: refused"));
        assert!(!line.contains("a8a37e32"), "the selector stays out: {line}");
        assert!(!line.contains("127."), "no address: {line}");
    }

    #[test]
    fn every_cause_has_a_counter() {
        let counts = RefusalCounts::default();
        let now = Instant::now();
        for failure in [
            CarryFailure::NoSupgang,
            CarryFailure::WrongOwner,
            CarryFailure::Malformed,
            CarryFailure::Refused,
            CarryFailure::UnknownPeer,
            CarryFailure::Timeout,
            CarryFailure::Refused,
        ] {
            let _due = counts.record(failure, now);
        }
        assert_eq!(
            counts.snapshot(),
            vec![
                ("endpoint", 2),
                ("no-supgang", 1),
                ("refused", 2),
                ("timeout", 1),
                ("unknown-peer", 1)
            ]
        );
    }

    #[test]
    fn the_log_is_paced_per_cause_and_says_what_it_held_back() {
        let counts = RefusalCounts::default();
        let start = Instant::now();
        assert_eq!(counts.record(CarryFailure::Refused, start), Some(0));
        assert_eq!(counts.record(CarryFailure::Refused, start), None);
        assert_eq!(counts.record(CarryFailure::Refused, start), None);
        // Another cause has its own interval.
        assert_eq!(counts.record(CarryFailure::Timeout, start), Some(0));
        let later = start + Duration::from_secs(10);
        assert_eq!(counts.record(CarryFailure::Refused, later), Some(2));
        assert_eq!(counts.snapshot(), vec![("refused", 4), ("timeout", 1)]);
        let route = Route {
            pattern: "pro.test".to_owned(),
            selector: "a8a37e32".to_owned(),
            service: "ssh".to_owned(),
        };
        assert!(
            failure_line(&route, CarryFailure::Refused, 2)
                .ends_with("[2 more with this cause not logged]")
        );
    }
}
