// SPDX-License-Identifier: GPL-3.0-or-later
//! Loopback TCP listeners for peer-machine mappings (ADR-0033).
//!
//! Each enabled peer-machine mapping holds one address in 127.77.0.0/16.
//! For each of its services, this runtime holds a listener on that address
//! at the service's port, and only there: never on another loopback
//! address, never on 127.0.0.1, never on the wildcard address, and never off
//! loopback. On macOS every listener is a socket root created and handed
//! over ([`PeerMachineListeners::adopt`]); on Linux `remapd` binds its own.
//! The listeners follow every published snapshot without a restart, and the
//! ports held are published for DNS, which answers a name only while all of
//! its ports are held. A listener that is not held is reported with a named
//! cause; nothing ever falls back to another address.

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use remap_core::{
    MAX_PEER_MACHINE_MAPPINGS, MAX_PEER_MACHINE_SERVICES, MappingTarget, RegistrySnapshot,
    is_peer_machine_address,
};
use tokio::net::TcpListener;
use tokio::sync::{Notify, Semaphore, watch};
use tokio::time::{MissedTickBehavior, interval};

use crate::machine_carry::{
    Carrier, ConnectionLog, Lookup, PEER_MACHINE_IDLE_TIMEOUT, RefusalCounts, Route,
};
use crate::machine_listen::{Active, PeerMachineAdoptError, bind, validate_adopted};
use crate::peer::PeerResolver;
use crate::supgang_stream::SupgangStreams;
use crate::{NetworkError, SnapshotStore};

/// The most connections carried at once across every peer-machine listener.
pub const PEER_MACHINE_CONNECTION_LIMIT: usize = 256;
/// The longest an accepted connection waits for its stream to open.
pub const PEER_MACHINE_OPEN_TIMEOUT: Duration = Duration::from_secs(10);
/// How often a listener that is not held is tried again.
pub const PEER_MACHINE_RETRY_INTERVAL: Duration = Duration::from_secs(5);
/// How long an adopted socket waits for a mapping that wants it before it is
/// closed. Root hands a socket over as soon as it reserves the alias, which
/// can be a moment before this runtime sees the snapshot that wants it.
const ADOPTED_GRACE: Duration = Duration::from_secs(30);
/// The most adopted sockets waiting at once: every port of every mapping.
const MAX_WAITING_SOCKETS: usize = MAX_PEER_MACHINE_MAPPINGS * MAX_PEER_MACHINE_SERVICES;

/// Why a peer-machine listener is not listening.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ListenerCause {
    /// The address is not an interface address here: the installed helper
    /// has not reserved it on this machine yet.
    AddressNotReserved,
    /// Something else on this machine already listens on that port at this
    /// address or at every address.
    PortInUse,
    /// The operating system does not let `remapd` listen on that port.
    PermissionDenied,
    /// Any other bind failure.
    Other,
    /// The installed Remap helper has not handed over this port's listening
    /// socket yet (macOS, where only root can create it).
    AwaitingSocket,
}

impl ListenerCause {
    /// The stable token, in ADR-0028's style.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::AddressNotReserved => "address-not-reserved",
            Self::PortInUse => "port-in-use",
            Self::PermissionDenied => "permission-denied",
            Self::Other => "other",
            Self::AwaitingSocket => "awaiting-socket",
        }
    }

    /// What it means and what to do.
    #[must_use]
    pub const fn explanation(self) -> &'static str {
        match self {
            Self::AddressNotReserved => {
                "this address is not reserved on this machine yet; the installed Remap helper reserves it"
            }
            Self::PortInUse => {
                "another listener on this machine holds this port; connections may reach it instead of the peer"
            }
            Self::PermissionDenied => {
                "the operating system does not let remapd listen on this port"
            }
            Self::Other => "the listener could not bind",
            Self::AwaitingSocket => {
                "the installed Remap helper has not handed over this port's listening socket yet"
            }
        }
    }

    fn classify(error: &io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::AddrNotAvailable => Self::AddressNotReserved,
            io::ErrorKind::AddrInUse => Self::PortInUse,
            io::ErrorKind::PermissionDenied => Self::PermissionDenied,
            _ => Self::Other,
        }
    }
}

/// Whether one service's listener is accepting connections.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ListenerState {
    /// Bound and accepting at this local address.
    Listening(SocketAddr),
    /// Not held, and why; retried every [`PEER_MACHINE_RETRY_INTERVAL`].
    /// The name does not answer while any of its ports is not held.
    NotListening(ListenerCause),
}

/// One service of one enabled peer-machine mapping, and its listener.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ListenerReport {
    /// The mapping's canonical pattern.
    pub pattern: String,
    /// The exposed service's name.
    pub service: String,
    /// The mapping's allocated address.
    pub address: Ipv4Addr,
    /// The port this machine listens on for the service.
    pub port: u16,
    /// Whether the listener is accepting.
    pub state: ListenerState,
}

/// A shared, current view of every peer-machine listener, read by status.
#[derive(Debug, Clone, Default)]
pub struct PeerMachineStatus {
    reports: Arc<Mutex<Vec<ListenerReport>>>,
    refusals: RefusalCounts,
}

impl PeerMachineStatus {
    /// How many connections closed without a stream since the daemon
    /// started, by cause token, omitting causes not seen. At most five.
    #[must_use]
    pub fn refusals(&self) -> Vec<(&'static str, u64)> {
        self.refusals.snapshot()
    }

    /// Returns the listeners in pattern then port order.
    #[must_use]
    pub fn reports(&self) -> Vec<ListenerReport> {
        self.reports
            .lock()
            .map(|reports| reports.clone())
            .unwrap_or_default()
    }

    fn replace(&self, reports: Vec<ListenerReport>) {
        if let Ok(mut current) = self.reports.lock() {
            *current = reports;
        }
    }
}

/// Where listeners come from.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ListenerSource {
    /// `remapd` binds each listener itself (Linux).
    Bind,
    /// Only sockets handed over through [`PeerMachineListeners::adopt`]
    /// (macOS, where root creates them).
    Adopt,
}

impl ListenerSource {
    /// Adoption on macOS, binding elsewhere.
    #[must_use]
    pub const fn platform_default() -> Self {
        if cfg!(target_os = "macos") {
            Self::Adopt
        } else {
            Self::Bind
        }
    }
}

type Waiting = BTreeMap<SocketAddrV4, (std::net::TcpListener, Instant)>;

/// The peer-machine listener runtime: one per daemon, beside the gateway.
///
/// Cloning gives another handle to the same runtime, so the system control
/// channel can hand sockets to [`Self::adopt`] while [`Self::serve`] runs.
#[derive(Clone)]
pub struct PeerMachineListeners {
    snapshots: SnapshotStore,
    status: PeerMachineStatus,
    carrier: Carrier,
    source: ListenerSource,
    substitute: Option<Ipv4Addr>,
    permits: Arc<Semaphore>,
    waiting: Arc<Mutex<Waiting>>,
    wake: Arc<Notify>,
}

impl fmt::Debug for PeerMachineListeners {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PeerMachineListeners")
            .field("carrier", &self.carrier)
            .field("source", &self.source)
            .field("substitute", &self.substitute)
            .finish_non_exhaustive()
    }
}

impl PeerMachineListeners {
    /// A runtime over `snapshots` that reports into `status`, finds this
    /// user's Supgang for each connection, logs to standard error, and takes
    /// its listeners from [`ListenerSource::platform_default`].
    #[must_use]
    pub fn new(snapshots: SnapshotStore, status: PeerMachineStatus) -> Self {
        let refusals = status.refusals.clone();
        Self {
            snapshots,
            status,
            carrier: Carrier {
                streams: Lookup::Discover,
                resolver: Lookup::Discover,
                open_timeout: PEER_MACHINE_OPEN_TIMEOUT,
                idle_timeout: PEER_MACHINE_IDLE_TIMEOUT,
                log: Arc::new(|line| eprintln!("{line}")),
                refusals,
            },
            source: ListenerSource::platform_default(),
            substitute: None,
            permits: Arc::new(Semaphore::new(PEER_MACHINE_CONNECTION_LIMIT)),
            waiting: Arc::default(),
            wake: Arc::new(Notify::new()),
        }
    }

    /// Fixes where Supgang's stream endpoint is, or that there is none, for
    /// a test.
    #[must_use]
    pub fn with_supgang_streams(mut self, streams: Option<SupgangStreams>) -> Self {
        self.carrier.streams = Lookup::Fixed(streams.map(Arc::new));
        self
    }

    /// Looks for Supgang's stream endpoint at `socket` for every
    /// connection, as production looks at Supgang's default path, for a
    /// test that starts Supgang after the runtime.
    #[must_use]
    pub fn with_supgang_socket(mut self, socket: std::path::PathBuf) -> Self {
        self.carrier.streams = Lookup::At(socket);
        self
    }

    /// Fixes how a fingerprint is resolved, or that it cannot be, for a test.
    #[must_use]
    pub fn with_peer_resolver(mut self, resolver: Option<Arc<dyn PeerResolver>>) -> Self {
        self.carrier.resolver = Lookup::Fixed(resolver);
        self
    }

    /// Replaces where refusals are logged, for a test.
    #[must_use]
    pub fn with_log(mut self, log: ConnectionLog) -> Self {
        self.carrier.log = log;
        self
    }

    /// Replaces how long a carried connection may stay silent, for a test.
    #[must_use]
    pub const fn with_idle_timeout(mut self, idle: Duration) -> Self {
        self.carrier.idle_timeout = idle;
        self
    }

    /// Chooses where listeners come from instead of the platform default.
    #[must_use]
    pub const fn with_listener_source(mut self, source: ListenerSource) -> Self {
        self.source = source;
        self
    }

    /// Stands `address` in for every reserved address, for a test on a
    /// machine where the alias cannot exist: a bound listener takes an
    /// ephemeral port there, and an adopted socket on it is accepted for
    /// any reserved endpoint.
    ///
    /// # Errors
    ///
    /// Refuses an address that is not loopback.
    pub fn with_substitute_address(mut self, address: Ipv4Addr) -> Result<Self, NetworkError> {
        if !address.is_loopback() {
            return Err(NetworkError::Configuration(
                "a peer-machine listener must bind a loopback address",
            ));
        }
        self.substitute = Some(address);
        Ok(self)
    }

    /// Adopts a listening socket root created for `address`:`port`. It
    /// replaces any listener held for that endpoint once a mapping wants it,
    /// and counts as held from then on.
    ///
    /// # Errors
    ///
    /// Refuses a socket that is not bound to exactly that address and port,
    /// or is not listening, or an endpoint outside the peer-machine range.
    pub fn adopt(
        &self,
        address: Ipv4Addr,
        port: u16,
        listener: std::net::TcpListener,
    ) -> Result<(), PeerMachineAdoptError> {
        let endpoint = SocketAddrV4::new(address, port);
        validate_adopted(endpoint, &listener, self.substitute)?;
        {
            let mut waiting = self
                .waiting
                .lock()
                .map_err(|_| PeerMachineAdoptError::Socket(io::ErrorKind::Other))?;
            if waiting.len() >= MAX_WAITING_SOCKETS && !waiting.contains_key(&endpoint) {
                return Err(PeerMachineAdoptError::TooManyWaiting);
            }
            waiting.insert(endpoint, (listener, Instant::now()));
        }
        self.wake.notify_one();
        Ok(())
    }

    /// Returns whether a live listener holds exactly `address`:`port` now.
    /// It reads the published held set without locking.
    #[must_use]
    pub fn is_held(&self, address: Ipv4Addr, port: u16) -> bool {
        self.snapshots.holds(SocketAddrV4::new(address, port))
    }

    /// Follows the published snapshots and adopted sockets until shutdown,
    /// then closes every listener and the connections it carries.
    ///
    /// # Errors
    ///
    /// Currently never fails; the result keeps the runtime's shape.
    pub async fn serve(self, mut shutdown: watch::Receiver<bool>) -> Result<(), NetworkError> {
        let mut published = self.snapshots.subscribe();
        let mut retry = interval(PEER_MACHINE_RETRY_INTERVAL);
        retry.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut active: BTreeMap<SocketAddrV4, Active> = BTreeMap::new();
        loop {
            if *shutdown.borrow() {
                break;
            }
            let snapshot = self.snapshots.load();
            self.reconcile(&snapshot, &mut active).await;
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                changed = published.changed() => {
                    if changed.is_err() {
                        break;
                    }
                }
                () = self.wake.notified() => {}
                _tick = retry.tick() => {}
            }
        }
        self.snapshots
            .publish_held(std::collections::BTreeSet::new());
        for (_endpoint, listener) in std::mem::take(&mut active) {
            listener.close().await;
        }
        self.status.replace(Vec::new());
        Ok(())
    }

    async fn reconcile(
        &self,
        snapshot: &RegistrySnapshot,
        active: &mut BTreeMap<SocketAddrV4, Active>,
    ) {
        let wanted = endpoints(snapshot);
        let retired: Vec<SocketAddrV4> = active
            .iter()
            .filter(|(endpoint, listener)| !wanted.contains_key(*endpoint) || !listener.is_live())
            .map(|(endpoint, _)| *endpoint)
            .collect();
        for endpoint in retired {
            if let Some(listener) = active.remove(&endpoint) {
                listener.close().await;
            }
        }
        let mut handed = self.take_handed(&wanted);
        let mut reports = Vec::with_capacity(wanted.len());
        for (endpoint, route) in wanted {
            let state = self
                .hold(endpoint, &route, handed.remove(&endpoint), active)
                .await;
            reports.push(ListenerReport {
                pattern: route.pattern,
                service: route.service,
                address: *endpoint.ip(),
                port: endpoint.port(),
                state,
            });
        }
        reports
            .sort_by(|left, right| (&left.pattern, left.port).cmp(&(&right.pattern, right.port)));
        self.snapshots
            .publish_held(active.keys().copied().collect());
        self.status.replace(reports);
    }

    /// Makes sure `endpoint` is held: by a newly handed socket, which
    /// replaces any current listener, by the current listener, or, when
    /// this runtime binds, by a new bind.
    async fn hold(
        &self,
        endpoint: SocketAddrV4,
        route: &Route,
        handed: Option<std::net::TcpListener>,
        active: &mut BTreeMap<SocketAddrV4, Active>,
    ) -> ListenerState {
        if let Some(socket) = handed {
            if let Some(previous) = active.remove(&endpoint) {
                previous.close().await;
            }
            return match TcpListener::from_std(socket) {
                Ok(listener) => self.start(endpoint, listener, route, active),
                Err(error) => ListenerState::NotListening(ListenerCause::classify(&error)),
            };
        }
        if let Some(listener) = active.get(&endpoint) {
            listener.retarget(route);
            return ListenerState::Listening(listener.local);
        }
        match self.source {
            ListenerSource::Adopt => ListenerState::NotListening(ListenerCause::AwaitingSocket),
            ListenerSource::Bind => {
                let address = match self.substitute {
                    Some(substitute) => SocketAddr::new(IpAddr::V4(substitute), 0),
                    None if is_peer_machine_address(*endpoint.ip()) => SocketAddr::V4(endpoint),
                    None => return ListenerState::NotListening(ListenerCause::Other),
                };
                match bind(address) {
                    Ok(listener) => self.start(endpoint, listener, route, active),
                    Err(error) => ListenerState::NotListening(ListenerCause::classify(&error)),
                }
            }
        }
    }

    fn start(
        &self,
        endpoint: SocketAddrV4,
        listener: TcpListener,
        route: &Route,
        active: &mut BTreeMap<SocketAddrV4, Active>,
    ) -> ListenerState {
        match Active::start(
            listener,
            route.clone(),
            self.carrier.clone(),
            Arc::clone(&self.permits),
        ) {
            Ok(started) => {
                let local = started.local;
                active.insert(endpoint, started);
                ListenerState::Listening(local)
            }
            Err(error) => ListenerState::NotListening(ListenerCause::classify(&error)),
        }
    }

    /// Takes the handed sockets a mapping wants now, and closes those no
    /// mapping has wanted within [`ADOPTED_GRACE`].
    fn take_handed(
        &self,
        wanted: &BTreeMap<SocketAddrV4, Route>,
    ) -> BTreeMap<SocketAddrV4, std::net::TcpListener> {
        let Ok(mut waiting) = self.waiting.lock() else {
            return BTreeMap::new();
        };
        waiting.retain(|endpoint, (_, handed_at)| {
            wanted.contains_key(endpoint) || handed_at.elapsed() < ADOPTED_GRACE
        });
        let ready: Vec<SocketAddrV4> = waiting
            .keys()
            .filter(|endpoint| wanted.contains_key(*endpoint))
            .copied()
            .collect();
        ready
            .into_iter()
            .filter_map(|endpoint| {
                waiting
                    .remove(&endpoint)
                    .map(|(socket, _)| (endpoint, socket))
            })
            .collect()
    }
}

/// Every enabled peer-machine mapping's services, by address and port.
fn endpoints(snapshot: &RegistrySnapshot) -> BTreeMap<SocketAddrV4, Route> {
    let mut wanted = BTreeMap::new();
    for mapping in snapshot.mappings() {
        let (MappingTarget::PeerMachine(machine), Some(address), true) = (
            mapping.target(),
            mapping.peer_address(),
            mapping.is_enabled(),
        ) else {
            continue;
        };
        for service in machine.services() {
            wanted.insert(
                SocketAddrV4::new(address, service.port().get()),
                Route {
                    pattern: mapping.pattern().to_string(),
                    selector: machine.selector().to_owned(),
                    service: service.name().to_owned(),
                },
            );
        }
    }
    wanted
}
