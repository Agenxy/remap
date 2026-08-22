use std::io;
use std::net::SocketAddr;
use std::net::{TcpListener as StdTcpListener, UdpSocket as StdUdpSocket};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tokio::time::{timeout, timeout_at};

use crate::dns::encoded_error;
use crate::forward::{Forwarder, eof};
use crate::resolver::ResolverPlanStore;
use crate::{DnsDecision, DnsEngine, DnsPolicy, NetworkError, RuntimeIdentity, SnapshotStore};

const MAX_DNS_MESSAGE_BYTES: usize = 65_535;
const MAX_TCP_REQUESTS_PER_CONNECTION: usize = 64;
const MAX_TCP_CONNECTION_LIFETIME: Duration = Duration::from_secs(30);

/// Bounded listener, forwarding, and shutdown configuration for DNS runtime.
#[derive(Debug, Clone)]
pub struct DnsRuntimeConfig {
    /// Loopback address shared by UDP and TCP DNS listeners.
    pub listen: SocketAddr,
    /// Ordered upstream resolvers captured before local activation.
    pub upstreams: Vec<SocketAddr>,
    /// Maximum concurrent DNS request jobs.
    pub request_limit: usize,
    /// Deadline for each upstream and client I/O operation.
    pub io_timeout: Duration,
    /// Maximum time to drain accepted jobs during shutdown.
    pub shutdown_grace: Duration,
    /// Local mapped-answer synthesis policy.
    pub policy: DnsPolicy,
}

impl DnsRuntimeConfig {
    /// Creates production-shaped defaults for one listener and upstream set.
    #[must_use]
    pub fn new(listen: SocketAddr, upstreams: Vec<SocketAddr>) -> Self {
        Self {
            listen,
            upstreams,
            request_limit: 256,
            io_timeout: Duration::from_secs(3),
            shutdown_grace: Duration::from_secs(5),
            policy: DnsPolicy::default(),
        }
    }

    fn validate(&self) -> Result<(), NetworkError> {
        self.validate_common()?;
        if self.upstreams.is_empty() {
            return Err(NetworkError::Configuration(
                "configure between one and four DNS upstreams",
            ));
        }
        Ok(())
    }

    fn validate_dormant(&self) -> Result<(), NetworkError> {
        self.validate_common()?;
        if !self.upstreams.is_empty() {
            return Err(NetworkError::Configuration(
                "a dormant DNS runtime cannot receive command-line upstreams",
            ));
        }
        Ok(())
    }

    fn validate_common(&self) -> Result<(), NetworkError> {
        if !self.listen.ip().is_loopback() {
            return Err(NetworkError::Configuration(
                "the DNS listener must use a loopback address",
            ));
        }
        if self.upstreams.len() > 4 {
            return Err(NetworkError::Configuration(
                "configure between one and four DNS upstreams",
            ));
        }
        if self.upstreams.contains(&self.listen) {
            return Err(NetworkError::Configuration(
                "the DNS listener cannot forward to itself",
            ));
        }
        if !(1..=4_096).contains(&self.request_limit) {
            return Err(NetworkError::Configuration(
                "the DNS request limit must be between 1 and 4096",
            ));
        }
        if self.io_timeout.is_zero()
            || self.io_timeout > Duration::from_secs(30)
            || self.shutdown_grace.is_zero()
            || self.shutdown_grace > Duration::from_secs(30)
        {
            return Err(NetworkError::Configuration(
                "DNS I/O and shutdown deadlines must be from 1 nanosecond through 30 seconds",
            ));
        }
        Ok(())
    }
}

/// Bound UDP/TCP DNS runtime ready to serve one immutable snapshot stream.
#[derive(Debug)]
pub struct DnsRuntime {
    udp: Arc<UdpSocket>,
    tcp: TcpListener,
    engine: DnsEngine,
    forwarder: Forwarder,
    resolver_plans: ResolverPlanStore,
    udp_permits: Arc<Semaphore>,
    tcp_permits: Arc<Semaphore>,
    tcp_connections: Arc<Semaphore>,
    io_timeout: Duration,
    shutdown_grace: Duration,
    local_addr: SocketAddr,
}

#[derive(Clone)]
struct TcpRuntimeContext {
    engine: DnsEngine,
    forwarder: Forwarder,
    request_permits: Arc<Semaphore>,
    connection_permits: Arc<Semaphore>,
    io_timeout: Duration,
    shutdown_grace: Duration,
}

/// Privileged UDP/TCP DNS sockets before attachment to an async runtime.
#[derive(Debug)]
pub struct DnsBindings {
    udp: StdUdpSocket,
    tcp: StdTcpListener,
    local_addr: SocketAddr,
}

impl DnsBindings {
    /// Validates and synchronously binds matching nonblocking DNS sockets.
    ///
    /// This is intentionally runtime-independent so a native bootstrap can
    /// bind a privileged port and discard privilege before starting threads.
    ///
    /// # Errors
    ///
    /// Returns a sanitized configuration or native socket failure.
    pub fn bind(config: &DnsRuntimeConfig) -> Result<Self, NetworkError> {
        config.validate()?;
        let udp = StdUdpSocket::bind(config.listen)
            .map_err(|error| NetworkError::io("UDP listener bind", error))?;
        let local_addr = udp
            .local_addr()
            .map_err(|error| NetworkError::io("UDP listener inspection", error))?;
        let tcp = StdTcpListener::bind(local_addr)
            .map_err(|error| NetworkError::io("TCP listener bind", error))?;
        Self::from_sockets(config, udp, tcp)
    }

    /// Validates native or supervisor-activated DNS sockets.
    ///
    /// # Errors
    ///
    /// Returns a sanitized mismatch or nonblocking-configuration failure.
    pub fn from_sockets(
        config: &DnsRuntimeConfig,
        udp: StdUdpSocket,
        tcp: StdTcpListener,
    ) -> Result<Self, NetworkError> {
        config.validate()?;
        Self::validate_sockets(config, udp, tcp)
    }

    /// Validates native sockets for a runtime awaiting its first private plan.
    ///
    /// # Errors
    ///
    /// Returns a sanitized failure unless command-line upstreams are absent and
    /// the sockets satisfy the ordinary loopback listener contract.
    pub fn from_dormant_sockets(
        config: &DnsRuntimeConfig,
        udp: StdUdpSocket,
        tcp: StdTcpListener,
    ) -> Result<Self, NetworkError> {
        config.validate_dormant()?;
        Self::validate_sockets(config, udp, tcp)
    }

    fn validate_sockets(
        config: &DnsRuntimeConfig,
        udp: StdUdpSocket,
        tcp: StdTcpListener,
    ) -> Result<Self, NetworkError> {
        let udp_address = udp
            .local_addr()
            .map_err(|error| NetworkError::io("UDP listener inspection", error))?;
        let tcp_address = tcp
            .local_addr()
            .map_err(|error| NetworkError::io("TCP listener inspection", error))?;
        if udp_address != tcp_address
            || udp_address.ip() != config.listen.ip()
            || (config.listen.port() != 0 && udp_address.port() != config.listen.port())
        {
            return Err(NetworkError::Configuration(
                "activated DNS sockets do not match the declared loopback listener",
            ));
        }
        udp.set_nonblocking(true)
            .map_err(|error| NetworkError::io("UDP nonblocking configuration", error))?;
        tcp.set_nonblocking(true)
            .map_err(|error| NetworkError::io("TCP nonblocking configuration", error))?;
        Ok(Self {
            udp,
            tcp,
            local_addr: udp_address,
        })
    }
}

impl DnsRuntime {
    /// Validates configuration and binds matching UDP and TCP listeners.
    ///
    /// # Errors
    ///
    /// Returns a sanitized configuration or native listener failure.
    pub fn bind(config: &DnsRuntimeConfig, snapshots: SnapshotStore) -> Result<Self, NetworkError> {
        let bindings = DnsBindings::bind(config)?;
        Self::from_bindings(config, snapshots, bindings)
    }

    /// Binds matching listeners with authenticated runtime-health responses.
    ///
    /// # Errors
    ///
    /// Returns a sanitized configuration or native listener failure.
    pub fn bind_with_identity(
        config: &DnsRuntimeConfig,
        snapshots: SnapshotStore,
        identity: RuntimeIdentity,
    ) -> Result<Self, NetworkError> {
        let bindings = DnsBindings::bind(config)?;
        Self::from_bindings_with_identity(config, snapshots, bindings, identity)
    }

    /// Attaches pre-bound sockets after a native privilege transition.
    ///
    /// # Errors
    ///
    /// Returns a sanitized configuration or async-runtime attachment failure.
    pub fn from_bindings(
        config: &DnsRuntimeConfig,
        snapshots: SnapshotStore,
        bindings: DnsBindings,
    ) -> Result<Self, NetworkError> {
        Self::from_optional_identity(config, snapshots, bindings, None)
    }

    /// Attaches pre-bound sockets with authenticated runtime-health responses.
    ///
    /// # Errors
    ///
    /// Returns a sanitized configuration or async-runtime attachment failure.
    pub fn from_bindings_with_identity(
        config: &DnsRuntimeConfig,
        snapshots: SnapshotStore,
        bindings: DnsBindings,
        identity: RuntimeIdentity,
    ) -> Result<Self, NetworkError> {
        Self::from_optional_identity(config, snapshots, bindings, Some(identity))
    }

    /// Attaches native sockets while awaiting the first root-published plan.
    ///
    /// # Errors
    ///
    /// Returns a sanitized failure unless the configuration has no upstreams
    /// and every other DNS runtime bound remains valid.
    pub fn from_dormant_bindings_with_identity(
        config: &DnsRuntimeConfig,
        snapshots: SnapshotStore,
        bindings: DnsBindings,
        identity: RuntimeIdentity,
    ) -> Result<Self, NetworkError> {
        config.validate_dormant()?;
        Self::from_validated_parts(
            config,
            snapshots,
            bindings,
            Some(identity),
            ResolverPlanStore::dormant(),
        )
    }

    fn from_optional_identity(
        config: &DnsRuntimeConfig,
        snapshots: SnapshotStore,
        bindings: DnsBindings,
        identity: Option<RuntimeIdentity>,
    ) -> Result<Self, NetworkError> {
        config.validate()?;
        let resolver_plans = ResolverPlanStore::initial(config.upstreams.clone())?;
        Self::from_validated_parts(config, snapshots, bindings, identity, resolver_plans)
    }

    fn from_validated_parts(
        config: &DnsRuntimeConfig,
        snapshots: SnapshotStore,
        bindings: DnsBindings,
        identity: Option<RuntimeIdentity>,
        resolver_plans: ResolverPlanStore,
    ) -> Result<Self, NetworkError> {
        let udp = UdpSocket::from_std(bindings.udp)
            .map_err(|error| NetworkError::io("UDP runtime attachment", error))?;
        let tcp = TcpListener::from_std(bindings.tcp)
            .map_err(|error| NetworkError::io("TCP runtime attachment", error))?;
        let engine = match identity {
            Some(identity) => DnsEngine::with_identity(snapshots, config.policy, identity),
            None => DnsEngine::new(snapshots, config.policy),
        };
        Ok(Self {
            udp: Arc::new(udp),
            tcp,
            engine,
            forwarder: Forwarder::new(resolver_plans.clone(), config.io_timeout),
            resolver_plans,
            udp_permits: Arc::new(Semaphore::new(config.request_limit)),
            tcp_permits: Arc::new(Semaphore::new(config.request_limit)),
            tcp_connections: Arc::new(Semaphore::new(config.request_limit)),
            io_timeout: config.io_timeout,
            shutdown_grace: config.shutdown_grace,
            local_addr: bindings.local_addr,
        })
    }

    /// Returns the address shared by both bound transports.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Returns the lock-free resolver publication handle used by this runtime.
    #[must_use]
    pub fn resolver_plans(&self) -> ResolverPlanStore {
        self.resolver_plans.clone()
    }

    /// Serves until shutdown is requested or either listener fails.
    ///
    /// # Errors
    ///
    /// Returns a sanitized listener or connection lifecycle failure.
    pub async fn serve(self, shutdown: watch::Receiver<bool>) -> Result<(), NetworkError> {
        let udp_shutdown = shutdown.clone();
        let udp = run_udp(
            self.udp,
            self.engine.clone(),
            self.forwarder.clone(),
            self.udp_permits,
            self.shutdown_grace,
            udp_shutdown,
        );
        let tcp_context = TcpRuntimeContext {
            engine: self.engine,
            forwarder: self.forwarder,
            request_permits: self.tcp_permits,
            connection_permits: self.tcp_connections,
            io_timeout: self.io_timeout,
            shutdown_grace: self.shutdown_grace,
        };
        let tcp = run_tcp(self.tcp, tcp_context, shutdown);
        tokio::try_join!(udp, tcp).map(|_| ())
    }
}

async fn run_udp(
    socket: Arc<UdpSocket>,
    engine: DnsEngine,
    forwarder: Forwarder,
    permits: Arc<Semaphore>,
    shutdown_grace: Duration,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), NetworkError> {
    let mut jobs = JoinSet::new();
    let mut buffer = vec![0_u8; MAX_DNS_MESSAGE_BYTES];
    loop {
        tokio::select! {
            () = shutdown_requested(&mut shutdown) => break,
            completed = jobs.join_next(), if !jobs.is_empty() => {
                let _completed = completed;
            }
            received = socket.recv_from(&mut buffer) => {
                let (size, peer) = received
                    .map_err(|error| NetworkError::io("UDP listener read", error))?;
                let packet = buffer[..size].to_vec();
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                    let response = encoded_error(&packet, hickory_proto::op::ResponseCode::ServFail)?;
                    socket.send_to(&response, peer).await
                        .map_err(|error| NetworkError::io("UDP overload response", error))?;
                    continue;
                };
                let socket = Arc::clone(&socket);
                let engine = engine.clone();
                let forwarder = forwarder.clone();
                jobs.spawn(async move {
                    let _permit = permit;
                    let response = process_packet(&engine, &forwarder, &packet).await?;
                    socket.send_to(&response, peer).await
                        .map_err(|error| NetworkError::io("UDP response write", error))?;
                    Ok::<(), NetworkError>(())
                });
            }
        }
    }
    drain_jobs(&mut jobs, shutdown_grace).await
}

async fn run_tcp(
    listener: TcpListener,
    context: TcpRuntimeContext,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), NetworkError> {
    let mut jobs = JoinSet::new();
    loop {
        tokio::select! {
            () = shutdown_requested(&mut shutdown) => break,
            completed = jobs.join_next(), if !jobs.is_empty() => {
                let _completed = completed;
            }
            accepted = listener.accept() => {
                let (stream, _peer) = accepted
                    .map_err(|error| NetworkError::io("TCP listener accept", error))?;
                let Ok(permit) = Arc::clone(&context.connection_permits).try_acquire_owned() else {
                    continue;
                };
                let job_context = context.clone();
                jobs.spawn(async move {
                    let _permit = permit;
                    timeout(
                        tcp_connection_lifetime(job_context.io_timeout),
                        serve_tcp_connection(
                            stream,
                            &job_context.engine,
                            &job_context.forwarder,
                            job_context.request_permits,
                            job_context.io_timeout,
                        ),
                    )
                    .await
                    .unwrap_or(Ok(()))
                });
            }
        }
    }
    drain_jobs(&mut jobs, context.shutdown_grace).await
}

async fn serve_tcp_connection(
    mut stream: TcpStream,
    engine: &DnsEngine,
    forwarder: &Forwarder,
    permits: Arc<Semaphore>,
    io_timeout: Duration,
) -> Result<(), NetworkError> {
    for _request in 0..MAX_TCP_REQUESTS_PER_CONNECTION {
        let mut length = [0_u8; 2];
        match timeout(io_timeout, stream.read_exact(&mut length)).await {
            Ok(Ok(_read)) => {}
            Ok(Err(error)) if eof(&error) => return Ok(()),
            Ok(Err(error)) => return Err(NetworkError::io("TCP request read", error)),
            Err(_) => return Ok(()),
        }
        let mut packet = vec![0_u8; usize::from(u16::from_be_bytes(length))];
        timeout(io_timeout, stream.read_exact(&mut packet))
            .await
            .map_err(|_| {
                NetworkError::io("TCP request read", io::Error::from(io::ErrorKind::TimedOut))
            })?
            .map_err(|error| NetworkError::io("TCP request read", error))?;
        let _permit = Arc::clone(&permits).acquire_owned().await.map_err(|_| {
            NetworkError::Configuration("the DNS request limiter closed unexpectedly")
        })?;
        let response = process_packet(engine, forwarder, &packet).await?;
        let response_size = u16::try_from(response.len()).map_err(|_| {
            NetworkError::Configuration("a DNS response exceeds the TCP framing limit")
        })?;
        timeout(io_timeout, stream.write_all(&response_size.to_be_bytes()))
            .await
            .map_err(|_| {
                NetworkError::io(
                    "TCP response write",
                    io::Error::from(io::ErrorKind::TimedOut),
                )
            })?
            .map_err(|error| NetworkError::io("TCP response write", error))?;
        timeout(io_timeout, stream.write_all(&response))
            .await
            .map_err(|_| {
                NetworkError::io(
                    "TCP response write",
                    io::Error::from(io::ErrorKind::TimedOut),
                )
            })?
            .map_err(|error| NetworkError::io("TCP response write", error))?;
    }
    Ok(())
}

fn tcp_connection_lifetime(io_timeout: Duration) -> Duration {
    io_timeout
        .saturating_mul(4)
        .min(MAX_TCP_CONNECTION_LIFETIME)
}

async fn process_packet(
    engine: &DnsEngine,
    forwarder: &Forwarder,
    packet: &[u8],
) -> Result<Vec<u8>, NetworkError> {
    match engine.decide(packet)? {
        DnsDecision::Respond(response) => Ok(response),
        DnsDecision::Forward => forwarder
            .exchange(packet)
            .await
            .or_else(|_| encoded_error(packet, hickory_proto::op::ResponseCode::ServFail)),
    }
}

async fn shutdown_requested(shutdown: &mut watch::Receiver<bool>) {
    if *shutdown.borrow() {
        return;
    }
    let _changed = shutdown.changed().await;
}

async fn drain_jobs(
    jobs: &mut JoinSet<Result<(), NetworkError>>,
    grace: Duration,
) -> Result<(), NetworkError> {
    let deadline = tokio::time::Instant::now() + grace;
    while !jobs.is_empty() {
        match timeout_at(deadline, jobs.join_next()).await {
            Ok(Some(Ok(Ok(())))) => {}
            Ok(Some(Ok(Err(error)))) => return Err(error),
            Ok(Some(Err(_join_error))) => {
                return Err(NetworkError::Configuration("a DNS request task failed"));
            }
            Ok(None) => break,
            Err(_) => {
                jobs.abort_all();
                while jobs.join_next().await.is_some() {}
                return Err(NetworkError::Configuration(
                    "DNS requests did not drain before the shutdown deadline",
                ));
            }
        }
    }
    Ok(())
}
