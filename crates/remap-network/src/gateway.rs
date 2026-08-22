use std::fmt;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::net::TcpListener as StdTcpListener;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use hyper::Uri;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout, timeout_at};
use tower_service::Service;

use crate::proxy::{ProxyClient, route};
use crate::{NetworkError, RuntimeIdentity, SnapshotStore};

/// Bounded listener, upstream, and shutdown configuration for the HTTP gateway.
#[derive(Debug, Clone)]
pub struct GatewayRuntimeConfig {
    /// Loopback address for cleartext client-facing HTTP.
    pub listen: SocketAddr,
    /// Maximum concurrent accepted browser connections.
    pub connection_limit: usize,
    /// Deadline for receiving one complete client request header.
    pub header_timeout: Duration,
    /// Deadline for connecting and receiving upstream response headers.
    pub upstream_timeout: Duration,
    /// Maximum idle lifetime for a pooled upstream connection.
    pub pool_idle_timeout: Duration,
    /// Maximum total lifetime for one client connection, including bodies.
    pub connection_timeout: Duration,
    /// Maximum time to drain accepted connections during shutdown.
    pub shutdown_grace: Duration,
}

impl GatewayRuntimeConfig {
    /// Creates production-shaped defaults for one HTTP listener.
    #[must_use]
    pub fn new(listen: SocketAddr) -> Self {
        Self {
            listen,
            connection_limit: 512,
            header_timeout: Duration::from_secs(5),
            upstream_timeout: Duration::from_secs(15),
            pool_idle_timeout: Duration::from_secs(90),
            connection_timeout: Duration::from_secs(60),
            shutdown_grace: Duration::from_secs(5),
        }
    }

    fn validate(&self) -> Result<(), NetworkError> {
        if !self.listen.ip().is_loopback() {
            return Err(NetworkError::Configuration(
                "the HTTP gateway listener must use a loopback address",
            ));
        }
        if !(1..=4_096).contains(&self.connection_limit) {
            return Err(NetworkError::Configuration(
                "the HTTP gateway connection limit must be between 1 and 4096",
            ));
        }
        for deadline in [
            self.header_timeout,
            self.upstream_timeout,
            self.pool_idle_timeout,
            self.connection_timeout,
            self.shutdown_grace,
        ] {
            if deadline.is_zero() || deadline > Duration::from_mins(5) {
                return Err(NetworkError::Configuration(
                    "HTTP gateway deadlines must be from 1 nanosecond through 300 seconds",
                ));
            }
        }
        Ok(())
    }
}

/// Bound cleartext HTTP gateway backed by one atomic registry snapshot stream.
#[derive(Debug)]
pub struct GatewayRuntime {
    listener: TcpListener,
    client: ProxyClient,
    snapshots: SnapshotStore,
    permits: Arc<Semaphore>,
    config: GatewayRuntimeConfig,
    local_addr: SocketAddr,
    identity: Option<RuntimeIdentity>,
}

/// Privileged cleartext HTTP socket before async-runtime attachment.
#[derive(Debug)]
pub struct GatewayBindings {
    listener: StdTcpListener,
    local_addr: SocketAddr,
}

impl GatewayBindings {
    /// Validates and synchronously binds one nonblocking gateway socket.
    ///
    /// # Errors
    ///
    /// Returns a sanitized configuration or native listener failure.
    pub fn bind(config: &GatewayRuntimeConfig) -> Result<Self, NetworkError> {
        config.validate()?;
        let listener = StdTcpListener::bind(config.listen)
            .map_err(|error| NetworkError::io("HTTP listener bind", error))?;
        Self::from_listener(config, listener)
    }

    /// Validates a native or supervisor-activated gateway listener.
    ///
    /// # Errors
    ///
    /// Returns a sanitized mismatch or nonblocking-configuration failure.
    pub fn from_listener(
        config: &GatewayRuntimeConfig,
        listener: StdTcpListener,
    ) -> Result<Self, NetworkError> {
        config.validate()?;
        let local_addr = listener
            .local_addr()
            .map_err(|error| NetworkError::io("HTTP listener inspection", error))?;
        if local_addr.ip() != config.listen.ip()
            || (config.listen.port() != 0 && local_addr.port() != config.listen.port())
        {
            return Err(NetworkError::Configuration(
                "the activated HTTP socket does not match the declared loopback listener",
            ));
        }
        listener
            .set_nonblocking(true)
            .map_err(|error| NetworkError::io("HTTP nonblocking configuration", error))?;
        Ok(Self {
            listener,
            local_addr,
        })
    }
}

impl GatewayRuntime {
    /// Validates configuration, loads native trust, and binds the gateway.
    ///
    /// # Errors
    ///
    /// Returns a sanitized trust-store, configuration, or listener failure.
    pub fn bind(
        config: GatewayRuntimeConfig,
        snapshots: SnapshotStore,
    ) -> Result<Self, NetworkError> {
        let bindings = GatewayBindings::bind(&config)?;
        Self::from_bindings(config, snapshots, bindings)
    }

    /// Binds a gateway with authenticated runtime-health responses.
    ///
    /// # Errors
    ///
    /// Returns a sanitized trust-store, configuration, or listener failure.
    pub fn bind_with_identity(
        config: GatewayRuntimeConfig,
        snapshots: SnapshotStore,
        identity: RuntimeIdentity,
    ) -> Result<Self, NetworkError> {
        let bindings = GatewayBindings::bind(&config)?;
        Self::from_bindings_with_identity(config, snapshots, bindings, identity)
    }

    /// Attaches a pre-bound socket and loads native trust after privilege drop.
    ///
    /// # Errors
    ///
    /// Returns a sanitized configuration, trust-store, or runtime failure.
    pub fn from_bindings(
        config: GatewayRuntimeConfig,
        snapshots: SnapshotStore,
        bindings: GatewayBindings,
    ) -> Result<Self, NetworkError> {
        Self::from_optional_identity(config, snapshots, bindings, None)
    }

    /// Attaches a pre-bound gateway with authenticated runtime-health responses.
    ///
    /// # Errors
    ///
    /// Returns a sanitized trust-store, configuration, or listener failure.
    pub fn from_bindings_with_identity(
        config: GatewayRuntimeConfig,
        snapshots: SnapshotStore,
        bindings: GatewayBindings,
        identity: RuntimeIdentity,
    ) -> Result<Self, NetworkError> {
        Self::from_optional_identity(config, snapshots, bindings, Some(identity))
    }

    fn from_optional_identity(
        config: GatewayRuntimeConfig,
        snapshots: SnapshotStore,
        bindings: GatewayBindings,
        identity: Option<RuntimeIdentity>,
    ) -> Result<Self, NetworkError> {
        config.validate()?;
        let listener = TcpListener::from_std(bindings.listener)
            .map_err(|error| NetworkError::io("HTTP runtime attachment", error))?;
        let client = build_client(&config, bindings.local_addr)?;
        Ok(Self {
            listener,
            client,
            snapshots,
            permits: Arc::new(Semaphore::new(config.connection_limit)),
            config,
            local_addr: bindings.local_addr,
            identity,
        })
    }

    /// Returns the bound cleartext HTTP address.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Serves routed HTTP until shutdown and drains accepted connections.
    ///
    /// # Errors
    ///
    /// Returns a sanitized listener or bounded-shutdown failure.
    pub async fn serve(self, mut shutdown: watch::Receiver<bool>) -> Result<(), NetworkError> {
        let mut connections = JoinSet::new();
        loop {
            let permit = tokio::select! {
                () = shutdown_requested(&mut shutdown) => break,
                completed = connections.join_next(), if !connections.is_empty() => {
                    let _completed = completed;
                    continue;
                }
                permit = Arc::clone(&self.permits).acquire_owned() => {
                    permit.map_err(|_| NetworkError::Configuration(
                        "the HTTP connection limiter closed unexpectedly",
                    ))?
                }
            };
            let accepted = tokio::select! {
                () = shutdown_requested(&mut shutdown) => {
                    drop(permit);
                    break;
                }
                accepted = self.listener.accept() => accepted,
            };
            let (stream, _peer) =
                accepted.map_err(|error| NetworkError::io("HTTP listener accept", error))?;
            let client = self.client.clone();
            let snapshots = self.snapshots.clone();
            let connection_shutdown = shutdown.clone();
            let config = self.config.clone();
            let identity = self.identity.clone();
            connections.spawn(async move {
                let _permit = permit;
                serve_connection(
                    stream,
                    client,
                    snapshots,
                    config,
                    identity,
                    connection_shutdown,
                )
                .await;
            });
        }
        drain_connections(&mut connections, self.config.shutdown_grace).await
    }
}

fn build_client(
    config: &GatewayRuntimeConfig,
    local_addr: SocketAddr,
) -> Result<ProxyClient, NetworkError> {
    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    connector.set_connect_timeout(Some(config.upstream_timeout));
    connector.set_nodelay(true);
    let guarded = SelfRejectingConnector::new(connector, local_addr);
    let https = HttpsConnectorBuilder::new()
        .with_native_roots()
        .map_err(|error| NetworkError::io("native TLS trust loading", error))?
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(guarded);
    Ok(Client::builder(TokioExecutor::new())
        .pool_idle_timeout(config.pool_idle_timeout)
        .pool_max_idle_per_host(8)
        .build(https))
}

async fn serve_connection(
    stream: TcpStream,
    client: ProxyClient,
    snapshots: SnapshotStore,
    config: GatewayRuntimeConfig,
    identity: Option<RuntimeIdentity>,
    mut shutdown: watch::Receiver<bool>,
) {
    let service = service_fn(move |request| {
        route(
            request,
            client.clone(),
            snapshots.clone(),
            config.upstream_timeout,
            identity.clone(),
        )
    });
    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(Some(config.header_timeout))
        .max_headers(128)
        .keep_alive(true);
    let connection = builder.serve_connection(TokioIo::new(stream), service);
    tokio::pin!(connection);
    tokio::select! {
        _result = &mut connection => {}
        () = sleep(config.connection_timeout) => {}
        () = shutdown_requested(&mut shutdown) => {
            connection.as_mut().graceful_shutdown();
            let _result = timeout(config.shutdown_grace, &mut connection).await;
        }
    }
}

/// Connector boundary that rejects the gateway's exact listener after native
/// name resolution but before HTTP or TLS bytes can be sent.
#[derive(Clone)]
pub(crate) struct SelfRejectingConnector {
    inner: HttpConnector,
    listener: SocketAddr,
}

impl SelfRejectingConnector {
    const fn new(inner: HttpConnector, listener: SocketAddr) -> Self {
        Self { inner, listener }
    }
}

impl Service<Uri> for SelfRejectingConnector {
    type Response = TokioIo<TcpStream>;
    type Error = GuardedConnectError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner
            .poll_ready(context)
            .map_err(|error| GuardedConnectError::Upstream(Box::new(error)))
    }

    fn call(&mut self, destination: Uri) -> Self::Future {
        let future = self.inner.call(destination);
        let listener = self.listener;
        Box::pin(async move {
            let stream = future
                .await
                .map_err(|error| GuardedConnectError::Upstream(Box::new(error)))?;
            let peer = stream
                .inner()
                .peer_addr()
                .map_err(GuardedConnectError::Inspection)?;
            if peer == listener {
                return Err(GuardedConnectError::SelfRoute);
            }
            Ok(stream)
        })
    }
}

/// Sanitized connector failure; addresses never cross the gateway boundary.
#[derive(Debug)]
pub(crate) enum GuardedConnectError {
    Inspection(io::Error),
    SelfRoute,
    Upstream(Box<dyn std::error::Error + Send + Sync>),
}

impl fmt::Display for GuardedConnectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inspection(_) => formatter.write_str("upstream peer inspection failed"),
            Self::SelfRoute => formatter.write_str("the route resolves to the Remap gateway"),
            Self::Upstream(_) => formatter.write_str("upstream connection failed"),
        }
    }
}

impl std::error::Error for GuardedConnectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Inspection(error) => Some(error),
            Self::Upstream(error) => Some(error.as_ref()),
            Self::SelfRoute => None,
        }
    }
}

async fn shutdown_requested(shutdown: &mut watch::Receiver<bool>) {
    if *shutdown.borrow() {
        return;
    }
    let _changed = shutdown.changed().await;
}

async fn drain_connections(
    connections: &mut JoinSet<()>,
    grace: Duration,
) -> Result<(), NetworkError> {
    let deadline = tokio::time::Instant::now() + grace;
    while !connections.is_empty() {
        match timeout_at(deadline, connections.join_next()).await {
            Ok(Some(_completed)) => {}
            Ok(None) => break,
            Err(_elapsed) => {
                connections.abort_all();
                while connections.join_next().await.is_some() {}
                return Err(NetworkError::Configuration(
                    "HTTP connections did not drain before the shutdown deadline",
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::net::Ipv4Addr;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use bytes::Bytes;
    use http_body_util::Full;
    use hyper::body::Incoming;
    use hyper::header::HOST;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use hyper_util::rt::TokioIo;
    use remap_core::{HostHeaderPolicy, Mapping, MappingTarget, NamePattern, RegistrySnapshot};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::watch;
    use tokio::time::timeout;

    use super::{GatewayRuntime, GatewayRuntimeConfig};
    use crate::SnapshotStore;

    #[tokio::test]
    async fn routes_host_and_path_through_streaming_hyper_gateway()
    -> Result<(), Box<dyn std::error::Error>> {
        let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let upstream_address = upstream.local_addr()?;
        let (observed_sender, observed_receiver) = tokio::sync::oneshot::channel();
        let observed_sender = Arc::new(Mutex::new(Some(observed_sender)));
        let upstream_task = tokio::spawn(async move {
            let Ok((stream, _peer)) = upstream.accept().await else {
                return;
            };
            let service_sender = Arc::clone(&observed_sender);
            let service = service_fn(move |request: Request<Incoming>| {
                let observation = (
                    request.uri().to_string(),
                    request
                        .headers()
                        .get(HOST)
                        .and_then(|value| value.to_str().ok())
                        .map(str::to_owned),
                );
                if let Ok(mut sender) = service_sender.lock()
                    && let Some(sender) = sender.take()
                {
                    let _sent = sender.send(observation);
                }
                async {
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                        b"upstream response",
                    ))))
                }
            });
            let _result = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });

        let store = SnapshotStore::empty();
        let target = MappingTarget::parse_with_http_policy(
            &format!("http://{upstream_address}/base"),
            HostHeaderPolicy::UseUpstream,
        )?;
        let mapping = Mapping::new(NamePattern::parse("safari.test")?, target);
        assert!(store.publish(RegistrySnapshot::new(1, vec![mapping])?));
        let runtime = GatewayRuntime::bind(
            GatewayRuntimeConfig::new((Ipv4Addr::LOCALHOST, 0).into()),
            store,
        )?;
        let gateway_address = runtime.local_addr();
        let (shutdown_sender, shutdown_receiver) = watch::channel(false);
        let gateway_task = tokio::spawn(runtime.serve(shutdown_receiver));

        let mut browser = TcpStream::connect(gateway_address).await?;
        browser
            .write_all(
                b"GET /hello?source=safari HTTP/1.1\r\nHost: safari.test\r\nConnection: close\r\n\r\n",
            )
            .await?;
        let mut response = Vec::new();
        timeout(Duration::from_secs(2), browser.read_to_end(&mut response)).await??;
        let response = String::from_utf8(response)?;
        assert!(response.starts_with("HTTP/1.1 200"));
        assert!(response.ends_with("upstream response"));
        let (path, host) = timeout(Duration::from_secs(2), observed_receiver).await??;
        assert_eq!(path, "/base/hello?source=safari");
        assert_eq!(host.as_deref(), Some(upstream_address.to_string().as_str()));

        shutdown_sender.send_replace(true);
        gateway_task.await??;
        upstream_task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn rejects_non_loopback_gateway_configuration() {
        let result = GatewayRuntime::bind(
            GatewayRuntimeConfig::new(([0, 0, 0, 0], 0).into()),
            SnapshotStore::empty(),
        );
        assert!(matches!(result, Err(crate::NetworkError::Configuration(_))));
    }

    #[tokio::test]
    async fn rejects_a_route_to_its_own_listener_before_recursing()
    -> Result<(), Box<dyn std::error::Error>> {
        let reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = reservation.local_addr()?;
        drop(reservation);
        let store = SnapshotStore::empty();
        let target = MappingTarget::parse_with_http_policy(
            &format!("http://{address}"),
            HostHeaderPolicy::UseUpstream,
        )?;
        let mapping = Mapping::new(NamePattern::parse("cycle.test")?, target);
        assert!(store.publish(RegistrySnapshot::new(1, vec![mapping])?));
        let runtime = GatewayRuntime::bind(GatewayRuntimeConfig::new(address), store)?;
        let (shutdown_sender, shutdown_receiver) = watch::channel(false);
        let gateway_task = tokio::spawn(runtime.serve(shutdown_receiver));

        let mut browser = TcpStream::connect(address).await?;
        browser
            .write_all(b"GET / HTTP/1.1\r\nHost: cycle.test\r\nConnection: close\r\n\r\n")
            .await?;
        let mut response = Vec::new();
        timeout(Duration::from_secs(2), browser.read_to_end(&mut response)).await??;
        assert!(String::from_utf8(response)?.starts_with("HTTP/1.1 502"));

        shutdown_sender.send_replace(true);
        gateway_task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn total_connection_deadline_releases_saturated_capacity()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut config = GatewayRuntimeConfig::new((Ipv4Addr::LOCALHOST, 0).into());
        config.connection_limit = 1;
        config.connection_timeout = Duration::from_millis(100);
        let runtime = GatewayRuntime::bind(config, SnapshotStore::empty())?;
        let address = runtime.local_addr();
        let (shutdown_sender, shutdown_receiver) = watch::channel(false);
        let gateway_task = tokio::spawn(runtime.serve(shutdown_receiver));
        let mut stalled = TcpStream::connect(address).await?;

        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut browser = TcpStream::connect(address).await?;
        browser
            .write_all(b"GET / HTTP/1.1\r\nHost: unmapped.test\r\nConnection: close\r\n\r\n")
            .await?;
        let mut response = Vec::new();
        timeout(Duration::from_secs(2), browser.read_to_end(&mut response)).await??;
        assert!(String::from_utf8(response)?.starts_with("HTTP/1.1 404"));
        let mut closed = [0_u8; 1];
        assert_eq!(stalled.read(&mut closed).await?, 0);

        shutdown_sender.send_replace(true);
        gateway_task.await??;
        Ok(())
    }
}
