// SPDX-License-Identifier: GPL-3.0-or-later
//! Loopback TCP listeners for peer-machine mappings (ADR-0033).
//!
//! Each enabled peer-machine mapping holds one address in 127.77.0.0/16.
//! For each of its services, this runtime listens on that address at the
//! service's port, and only there: never on another loopback address, never
//! on 127.0.0.1, never on the wildcard address, and never off loopback. The
//! listeners follow every published snapshot without a restart. A listener
//! that cannot bind, typically because the address is not reserved on this
//! machine yet, is reported with a named cause and retried; it never falls
//! back to another address.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use remap_core::{MappingTarget, RegistrySnapshot, is_peer_machine_address};
use tokio::net::{TcpListener, TcpSocket};
use tokio::sync::{Semaphore, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{MissedTickBehavior, interval};

use crate::machine_carry::{Carrier, ConnectionLog, RefusalCounts, Route};
use crate::peer::{PeerResolver, SupgangResolver};
use crate::supgang_stream::SupgangStreams;
use crate::{NetworkError, SnapshotStore};

/// The most connections carried at once across every peer-machine listener.
pub const PEER_MACHINE_CONNECTION_LIMIT: usize = 256;
/// The longest an accepted connection waits for its stream to open.
pub const PEER_MACHINE_OPEN_TIMEOUT: Duration = Duration::from_secs(10);
/// How often a listener that could not bind is tried again.
pub const PEER_MACHINE_RETRY_INTERVAL: Duration = Duration::from_secs(5);
const LISTEN_BACKLOG: u32 = 128;

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
    /// Not bound, and why; retried every [`PEER_MACHINE_RETRY_INTERVAL`].
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

/// Where a listener binds: its reserved address, or for a test on a machine
/// where that alias cannot exist, a loopback address with an ephemeral port.
#[derive(Debug, Clone, Copy)]
enum Binding {
    Reserved,
    Substitute(Ipv4Addr),
}

/// The identity of one listener: what it is bound to and what it carries.
/// A change to any field closes the old listener and binds a new one.
#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
struct Endpoint {
    pattern: String,
    port: u16,
    address: Ipv4Addr,
    selector: String,
    service: String,
}

struct Active {
    task: JoinHandle<()>,
    local: SocketAddr,
}

/// The peer-machine listener runtime: one per daemon, beside the gateway.
pub struct PeerMachineListeners {
    snapshots: SnapshotStore,
    status: PeerMachineStatus,
    carrier: Carrier,
    binding: Binding,
    permits: Arc<Semaphore>,
}

impl fmt::Debug for PeerMachineListeners {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PeerMachineListeners")
            .field("carrier", &self.carrier)
            .field("binding", &self.binding)
            .finish_non_exhaustive()
    }
}

impl PeerMachineListeners {
    /// A runtime over `snapshots` that reports into `status`, using this
    /// user's Supgang when it is installed and logging to standard error.
    #[must_use]
    pub fn new(snapshots: SnapshotStore, status: PeerMachineStatus) -> Self {
        let resolver =
            SupgangResolver::discover().map(|resolver| Arc::new(resolver) as Arc<dyn PeerResolver>);
        let refusals = status.refusals.clone();
        Self {
            snapshots,
            status,
            carrier: Carrier {
                streams: SupgangStreams::discover().map(Arc::new),
                resolver,
                open_timeout: PEER_MACHINE_OPEN_TIMEOUT,
                log: Arc::new(|line| eprintln!("{line}")),
                refusals,
            },
            binding: Binding::Reserved,
            permits: Arc::new(Semaphore::new(PEER_MACHINE_CONNECTION_LIMIT)),
        }
    }

    /// Replaces where Supgang's stream endpoint is, for a test.
    #[must_use]
    pub fn with_supgang_streams(mut self, streams: Option<SupgangStreams>) -> Self {
        self.carrier.streams = streams.map(Arc::new);
        self
    }

    /// Replaces how a fingerprint is resolved, for a test.
    #[must_use]
    pub fn with_peer_resolver(mut self, resolver: Option<Arc<dyn PeerResolver>>) -> Self {
        self.carrier.resolver = resolver;
        self
    }

    /// Replaces where refusals are logged, for a test.
    #[must_use]
    pub fn with_log(mut self, log: ConnectionLog) -> Self {
        self.carrier.log = log;
        self
    }

    /// Binds every listener to `address` on an ephemeral port instead of
    /// its reserved address, for a test on a machine where the reserved
    /// alias cannot exist.
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
        self.binding = Binding::Substitute(address);
        Ok(self)
    }

    /// Follows the published snapshots until shutdown, then closes every
    /// listener and the connections it carries.
    ///
    /// # Errors
    ///
    /// Returns a configuration failure if the snapshot publisher is gone.
    pub async fn serve(self, mut shutdown: watch::Receiver<bool>) -> Result<(), NetworkError> {
        let mut published = self.snapshots.subscribe();
        let mut retry = interval(PEER_MACHINE_RETRY_INTERVAL);
        retry.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut active: BTreeMap<Endpoint, Active> = BTreeMap::new();
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
                _tick = retry.tick() => {}
            }
        }
        for (_endpoint, listener) in std::mem::take(&mut active) {
            close(listener).await;
        }
        self.status.replace(Vec::new());
        Ok(())
    }

    async fn reconcile(
        &self,
        snapshot: &RegistrySnapshot,
        active: &mut BTreeMap<Endpoint, Active>,
    ) {
        let wanted = endpoints(snapshot);
        let retired: Vec<Endpoint> = active
            .keys()
            .filter(|endpoint| !wanted.contains(*endpoint))
            .cloned()
            .collect();
        for endpoint in retired {
            if let Some(listener) = active.remove(&endpoint) {
                close(listener).await;
            }
        }
        let mut reports = Vec::with_capacity(wanted.len());
        for endpoint in wanted {
            let state = match active.get(&endpoint) {
                Some(listener) => ListenerState::Listening(listener.local),
                None => match self.listen(&endpoint) {
                    Ok(listener) => {
                        let state = ListenerState::Listening(listener.local);
                        active.insert(endpoint.clone(), listener);
                        state
                    }
                    Err(cause) => ListenerState::NotListening(cause),
                },
            };
            reports.push(ListenerReport {
                pattern: endpoint.pattern,
                service: endpoint.service,
                address: endpoint.address,
                port: endpoint.port,
                state,
            });
        }
        self.status.replace(reports);
    }

    fn listen(&self, endpoint: &Endpoint) -> Result<Active, ListenerCause> {
        let address = match self.binding {
            Binding::Reserved if is_peer_machine_address(endpoint.address) => {
                SocketAddr::new(IpAddr::V4(endpoint.address), endpoint.port)
            }
            Binding::Reserved => return Err(ListenerCause::Other),
            Binding::Substitute(address) => SocketAddr::new(IpAddr::V4(address), 0),
        };
        let listener = bind(address).map_err(|error| ListenerCause::classify(&error))?;
        let local = listener.local_addr().map_err(|_| ListenerCause::Other)?;
        let route = Arc::new(Route {
            pattern: endpoint.pattern.clone(),
            selector: endpoint.selector.clone(),
            service: endpoint.service.clone(),
        });
        let task = tokio::spawn(accept_loop(
            listener,
            route,
            self.carrier.clone(),
            Arc::clone(&self.permits),
        ));
        Ok(Active { task, local })
    }
}

/// Binds one listening socket. Address reuse lets a listener on a reserved
/// address coexist with a service listening on every address at that port,
/// as an `sshd` on port 22 does, where the platform allows it.
fn bind(address: SocketAddr) -> io::Result<TcpListener> {
    let socket = TcpSocket::new_v4()?;
    socket.set_reuseaddr(true)?;
    socket.bind(address)?;
    socket.listen(LISTEN_BACKLOG)
}

/// Every enabled peer-machine mapping's services, in pattern then port order.
fn endpoints(snapshot: &RegistrySnapshot) -> BTreeSet<Endpoint> {
    let mut wanted = BTreeSet::new();
    for mapping in snapshot.mappings() {
        let (MappingTarget::PeerMachine(machine), Some(address), true) = (
            mapping.target(),
            mapping.peer_address(),
            mapping.is_enabled(),
        ) else {
            continue;
        };
        for service in machine.services() {
            wanted.insert(Endpoint {
                pattern: mapping.pattern().to_string(),
                port: service.port().get(),
                address,
                selector: machine.selector().to_owned(),
                service: service.name().to_owned(),
            });
        }
    }
    wanted
}

/// Aborts a listener and waits until its socket and connections are dropped,
/// so the same address and port can be bound again at once.
async fn close(listener: Active) {
    listener.task.abort();
    let _ended = listener.task.await;
}

async fn accept_loop(
    listener: TcpListener,
    route: Arc<Route>,
    carrier: Carrier,
    permits: Arc<Semaphore>,
) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            completed = connections.join_next(), if !connections.is_empty() => {
                let _completed = completed;
            }
            accepted = listener.accept() => {
                let Ok((client, _peer)) = accepted else {
                    // A transient failure such as a full descriptor table is
                    // waited out instead of retried in a tight loop.
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                };
                // Past the bound, a connection is closed at once rather than
                // queued behind carried ones.
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                    continue;
                };
                let route = Arc::clone(&route);
                let carrier = carrier.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    carrier.carry(client, &route).await;
                });
            }
        }
    }
}
