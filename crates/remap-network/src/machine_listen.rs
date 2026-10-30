// SPDX-License-Identifier: GPL-3.0-or-later
//! One peer-machine listener: where its socket comes from, and the loop
//! that accepts connections on it (ADR-0033).
//!
//! On macOS a user process cannot bind a port below 1024 on a specific
//! address, so root binds every listed port on the reserved alias and hands
//! the listening descriptor to `remapd`, which adopts it only after checking
//! that it is bound to exactly that address and port and is listening. On
//! Linux `remapd` binds its own listeners.

use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use remap_core::is_peer_machine_address;
use tokio::net::{TcpListener, TcpSocket};
use tokio::sync::Semaphore;
use tokio::task::{JoinHandle, JoinSet};

use crate::machine_carry::{Carrier, Route};

const LISTEN_BACKLOG: u32 = 128;
/// The most connections one listener carries at once.
///
/// Supgang admits about 40 streams per peer across all its services, so one
/// port gets fewer than that, leaving room for the peer's other services. It
/// also keeps one busy port from taking the whole
/// [`crate::PEER_MACHINE_CONNECTION_LIMIT`].
pub const PEER_MACHINE_LISTENER_CONNECTION_LIMIT: usize = 32;

/// Why a socket handed to [`crate::PeerMachineListeners::adopt`] was refused.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PeerMachineAdoptError {
    /// The address is outside 127.77.0.0/16, is its first or last address,
    /// or the port is zero.
    NotPeerMachineEndpoint,
    /// The socket is not bound to exactly that address and port.
    WrongEndpoint,
    /// The socket is bound but not listening.
    NotListening,
    /// The socket could not be inspected or prepared.
    Socket(io::ErrorKind),
    /// More sockets are waiting to be used than any registry can need.
    TooManyWaiting,
}

impl fmt::Display for PeerMachineAdoptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotPeerMachineEndpoint => {
                formatter.write_str("the endpoint is not a peer-machine address and nonzero port")
            }
            Self::WrongEndpoint => {
                formatter.write_str("the socket is not bound to exactly that address and port")
            }
            Self::NotListening => formatter.write_str("the socket is not listening"),
            Self::Socket(kind) => write!(formatter, "the socket could not be inspected: {kind}"),
            Self::TooManyWaiting => {
                formatter.write_str("too many adopted sockets are waiting for a mapping")
            }
        }
    }
}

impl std::error::Error for PeerMachineAdoptError {}

/// Checks a handed-over socket before it is used. `substitute` is the test
/// seam: on a machine where the alias cannot exist, a socket on that
/// loopback address, at any port, stands for the reserved endpoint.
pub(crate) fn validate_adopted(
    endpoint: SocketAddrV4,
    listener: &std::net::TcpListener,
    substitute: Option<Ipv4Addr>,
) -> Result<(), PeerMachineAdoptError> {
    if !is_peer_machine_address(*endpoint.ip()) || endpoint.port() == 0 {
        return Err(PeerMachineAdoptError::NotPeerMachineEndpoint);
    }
    let local = listener
        .local_addr()
        .map_err(|error| PeerMachineAdoptError::Socket(error.kind()))?;
    let matches = match substitute {
        Some(address) => local.ip() == IpAddr::V4(address),
        None => local == SocketAddr::V4(endpoint),
    };
    if !matches {
        return Err(PeerMachineAdoptError::WrongEndpoint);
    }
    listener
        .set_nonblocking(true)
        .map_err(|error| PeerMachineAdoptError::Socket(error.kind()))?;
    // Accepting is the portable, safe test for a listening socket: one that
    // is not listening refuses with EINVAL, and one with no connection
    // pending would block. A connection already pending is closed, and its
    // client may retry.
    match listener.accept() {
        Ok(_pending) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(()),
        Err(_not_listening) => Err(PeerMachineAdoptError::NotListening),
    }
}

/// Binds one listening socket. Address reuse lets a listener on a reserved
/// address coexist with a service listening on every address at that port,
/// where the platform allows it.
pub(crate) fn bind(address: SocketAddr) -> io::Result<TcpListener> {
    let socket = TcpSocket::new_v4()?;
    socket.set_reuseaddr(true)?;
    socket.bind(address)?;
    socket.listen(LISTEN_BACKLOG)
}

/// A live listener and the route its connections take now.
pub(crate) struct Active {
    task: JoinHandle<()>,
    pub(crate) local: SocketAddr,
    route: Arc<ArcSwap<Route>>,
}

impl Active {
    /// Starts accepting on `listener` for `route`.
    pub(crate) fn start(
        listener: TcpListener,
        route: Route,
        carrier: Carrier,
        global: Arc<Semaphore>,
    ) -> io::Result<Self> {
        let local = listener.local_addr()?;
        let route = Arc::new(ArcSwap::from_pointee(route));
        let task = tokio::spawn(accept_loop(listener, Arc::clone(&route), carrier, global));
        Ok(Self { task, local, route })
    }

    /// Carries new connections for `route`; established ones keep theirs.
    pub(crate) fn retarget(&self, route: &Route) {
        if **self.route.load() != *route {
            self.route.store(Arc::new(route.clone()));
        }
    }

    /// Whether the accept loop is still running.
    pub(crate) fn is_live(&self) -> bool {
        !self.task.is_finished()
    }

    /// Aborts the listener and waits until its socket and connections are
    /// dropped, so the same address and port can be bound again at once.
    pub(crate) async fn close(self) {
        self.task.abort();
        let _ended = self.task.await;
    }
}

async fn accept_loop(
    listener: TcpListener,
    route: Arc<ArcSwap<Route>>,
    carrier: Carrier,
    global: Arc<Semaphore>,
) {
    let local = Arc::new(Semaphore::new(PEER_MACHINE_LISTENER_CONNECTION_LIMIT));
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
                // Past either bound, a connection is closed at once rather
                // than queued behind carried ones.
                let (Ok(own), Ok(shared)) = (
                    Arc::clone(&local).try_acquire_owned(),
                    Arc::clone(&global).try_acquire_owned(),
                ) else {
                    continue;
                };
                let route = route.load_full();
                let carrier = carrier.clone();
                connections.spawn(async move {
                    let _permits = (own, shared);
                    carrier.carry(client, &route).await;
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4};

    use super::{PeerMachineAdoptError, validate_adopted};

    #[test]
    fn only_a_listening_socket_on_the_endpoint_is_adopted() -> Result<(), Box<dyn std::error::Error>>
    {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let endpoint = SocketAddrV4::new(Ipv4Addr::new(127, 77, 0, 1), 22);
        // Without the test substitute, 127.0.0.1 is never the reserved address.
        assert_eq!(
            validate_adopted(endpoint, &listener, None),
            Err(PeerMachineAdoptError::WrongEndpoint)
        );
        assert_eq!(
            validate_adopted(endpoint, &listener, Some(Ipv4Addr::LOCALHOST)),
            Ok(())
        );
        for outside in [
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 22),
            SocketAddrV4::new(Ipv4Addr::new(127, 77, 0, 0), 22),
            SocketAddrV4::new(Ipv4Addr::new(127, 77, 0, 1), 0),
        ] {
            assert_eq!(
                validate_adopted(outside, &listener, Some(Ipv4Addr::LOCALHOST)),
                Err(PeerMachineAdoptError::NotPeerMachineEndpoint)
            );
        }
        Ok(())
    }

    #[test]
    fn a_bound_socket_that_is_not_listening_is_refused() -> Result<(), Box<dyn std::error::Error>> {
        // A connected stream is bound to a loopback address but listens for
        // nothing, which is what a mistaken hand-over would look like.
        let server = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let stream = std::net::TcpStream::connect(server.local_addr()?)?;
        let std_socket = std::net::TcpListener::from(std::os::fd::OwnedFd::from(stream));
        let endpoint = SocketAddrV4::new(Ipv4Addr::new(127, 77, 0, 1), 22);
        assert_eq!(
            validate_adopted(endpoint, &std_socket, Some(Ipv4Addr::LOCALHOST)),
            Err(PeerMachineAdoptError::NotListening)
        );
        Ok(())
    }
}
