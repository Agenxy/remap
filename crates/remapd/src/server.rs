use std::fs::{File, OpenOptions};
use std::future::Future;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixListener as StdUnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use nix::fcntl::{Flock, FlockArg};
use remap_network::{
    DnsBindings, DnsRuntime, DnsRuntimeConfig, GatewayBindings, GatewayRuntime,
    GatewayRuntimeConfig, NetworkError, SnapshotStore,
};
use remap_protocol::{
    ControlPaths, ControlRequest, ControlResponse, DEFAULT_DAEMON_DRAIN_GRACE, Diagnostic,
    SYSTEM_DAEMON_SHUTDOWN_BUDGET, read_frame, write_frame,
};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tokio::time::{MissedTickBehavior, interval, timeout, timeout_at};

use crate::Engine;
use crate::network_bootstrap::{bind_network, prepare_network};
use crate::peer;
use crate::privilege;
use crate::system_control::SystemControlRuntime;

const DEFAULT_CONNECTION_LIMIT: usize = 64;
const DEFAULT_IO_TIMEOUT: Duration = Duration::from_secs(15);
const WRITER_SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
const DEFAULT_MAINTENANCE_INTERVAL: Duration = Duration::from_mins(1);
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(25);
const SNAPSHOT_RETRY_DELAY: Duration = Duration::from_millis(25);
#[cfg(target_os = "macos")]
const UNIX_SOCKET_PATH_CAPACITY: usize = 104;
#[cfg(target_os = "linux")]
const UNIX_SOCKET_PATH_CAPACITY: usize = 108;

/// Runtime configuration for one per-user `remapd` instance.
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    /// Native registry and socket locations.
    pub paths: ControlPaths,
    /// Maximum concurrently accepted local clients.
    pub connection_limit: usize,
    /// Deadline for reading one complete request frame.
    pub read_timeout: Duration,
    /// Deadline for writing one complete response frame.
    pub write_timeout: Duration,
    /// Maximum time allowed for accepted requests to finish during shutdown.
    pub shutdown_grace: Duration,
    /// Maximum delay between private-journal retention passes.
    pub maintenance_interval: Duration,
    /// Optional portable DNS runtime; native installers configure this.
    pub dns: Option<DnsRuntimeConfig>,
    /// Optional portable cleartext HTTP gateway; native installers configure this.
    pub gateway: Option<GatewayRuntimeConfig>,
    /// Optional non-root account selected by a privileged native bootstrap.
    pub run_as: Option<RunAsUser>,
    /// Consume low-port sockets activated by a macOS launchd service.
    pub launchd_sockets: bool,
    /// Consume exact low-port sockets activated by a Linux systemd service.
    pub systemd_sockets: bool,
    /// Root-supervisor channel, overridden only by a native service contract.
    pub system_socket: PathBuf,
}

impl DaemonConfig {
    /// Creates a production configuration at native per-user locations.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the platform has no application-data path.
    pub fn discover() -> Result<Self, Diagnostic> {
        Ok(Self::new(ControlPaths::discover()?))
    }

    /// Creates a production-shaped configuration for explicit paths.
    #[must_use]
    pub fn new(paths: ControlPaths) -> Self {
        let system_socket = paths.system_socket().to_path_buf();
        Self {
            paths,
            connection_limit: DEFAULT_CONNECTION_LIMIT,
            read_timeout: DEFAULT_IO_TIMEOUT,
            write_timeout: DEFAULT_IO_TIMEOUT,
            shutdown_grace: DEFAULT_DAEMON_DRAIN_GRACE,
            maintenance_interval: DEFAULT_MAINTENANCE_INTERVAL,
            dns: None,
            gateway: None,
            run_as: None,
            launchd_sockets: false,
            systemd_sockets: false,
            system_socket,
        }
    }
}

/// Non-root account selected by a root-owned native service definition.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RunAsUser {
    name: String,
}

impl RunAsUser {
    /// Declares the operating-system account that will own the runtime.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

/// Runtime-independent daemon state prepared before worker threads start.
#[derive(Debug)]
pub struct DaemonBootstrap {
    config: DaemonConfig,
    network: Option<PreboundNetwork>,
}

#[derive(Debug, Default)]
pub(crate) struct PreboundNetwork {
    pub(crate) dns: Option<DnsBindings>,
    pub(crate) gateway: Option<GatewayBindings>,
    pub(crate) system_control: Option<StdUnixListener>,
}

#[derive(Debug)]
pub(crate) struct PreparedNetwork {
    pub(crate) dns: Option<DnsRuntime>,
    pub(crate) gateway: Option<GatewayRuntime>,
    pub(crate) system_control: Option<SystemControlRuntime>,
    pub(crate) snapshots: SnapshotStore,
}

/// Binds privileged sockets and irrevocably selects the configured user.
///
/// Native service entry points must call this before creating an async runtime
/// or any other worker thread. Ordinary per-user launches perform no privilege
/// transition and return an empty pre-bound socket set.
///
/// # Errors
///
/// Returns a stable diagnostic for invalid configuration, listener failure,
/// account lookup failure, or incomplete privilege discard.
pub fn bootstrap(mut config: DaemonConfig) -> Result<DaemonBootstrap, Diagnostic> {
    validate_config(&config)?;
    #[cfg(target_os = "linux")]
    if !config.systemd_sockets {
        crate::systemd::reject_unrequested()?;
    }
    let network = if config.systemd_sockets {
        Some(crate::systemd::activate(&config)?)
    } else if config.launchd_sockets {
        Some(crate::launchd::activate(&config)?)
    } else if let Some(run_as) = &config.run_as {
        let user = privilege::resolve(&run_as.name)?;
        let network = bind_network(&config)?;
        privilege::discard(&user)?;
        Some(network)
    } else {
        None
    };
    config.run_as = None;
    config.launchd_sockets = false;
    config.systemd_sockets = false;
    Ok(DaemonBootstrap { config, network })
}

impl DaemonBootstrap {
    /// Runs a prepared daemon until `SIGINT` or `SIGTERM`.
    ///
    /// # Errors
    ///
    /// Returns a stable startup, service, or shutdown diagnostic.
    pub async fn run(self) -> Result<(), Diagnostic> {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(signal_error)?;
        serve_prepared_until(self.config, self.network, async {
            tokio::select! {
                _result = tokio::signal::ctrl_c() => {},
                _signal = terminate.recv() => {},
            }
        })
        .await
    }
}

/// Runs until the operating system delivers `SIGINT` or `SIGTERM`.
///
/// # Errors
///
/// Returns a stable startup or listener diagnostic.
pub async fn run(config: DaemonConfig) -> Result<(), Diagnostic> {
    if config.run_as.is_some() || config.launchd_sockets || config.systemd_sockets {
        return Err(bootstrap_order_error());
    }
    DaemonBootstrap {
        config,
        network: None,
    }
    .run()
    .await
}

/// Runs until an explicit shutdown future completes.
///
/// # Errors
///
/// Returns a stable diagnostic for insecure paths, peer setup, registry
/// initialization, or listener failure.
pub async fn serve_until<F>(config: DaemonConfig, shutdown: F) -> Result<(), Diagnostic>
where
    F: Future<Output = ()>,
{
    if config.run_as.is_some() || config.launchd_sockets || config.systemd_sockets {
        return Err(bootstrap_order_error());
    }
    serve_prepared_until(config, None, shutdown).await
}

async fn serve_prepared_until<F>(
    config: DaemonConfig,
    prebound: Option<PreboundNetwork>,
    shutdown: F,
) -> Result<(), Diagnostic>
where
    F: Future<Output = ()>,
{
    validate_config(&config)?;
    prepare_data_directory(config.paths.data_dir())?;
    let _authority_lock = acquire_authority_lock(config.paths.lock())?;
    prepare_socket_target(config.paths.socket()).await?;
    validate_database_family(config.paths.database())?;
    let listener = UnixListener::bind(config.paths.socket()).map_err(listener_error)?;
    std::fs::set_permissions(
        config.paths.socket(),
        std::fs::Permissions::from_mode(0o600),
    )
    .map_err(path_error)?;
    let guard = SocketGuard::capture(config.paths.socket())?;
    let engine = match Engine::spawn(config.paths.database()) {
        Ok(engine) => engine,
        Err(error) => return cleanup_start_failure(listener, guard, error),
    };
    if let Err(error) = secure_database_family(config.paths.database()) {
        let shutdown_result = engine.shutdown().await;
        let cleanup_result = cleanup_start_failure(listener, guard, error);
        return cleanup_result.and(shutdown_result);
    }
    let network = match prepare_network(&config, &engine, prebound).await {
        Ok(network) => network,
        Err(error) => {
            let shutdown_result = engine.shutdown().await;
            let cleanup_result = cleanup_start_failure(listener, guard, error);
            return cleanup_result.and(shutdown_result);
        }
    };
    let result = accept_loop(&listener, &config, engine, network, shutdown).await;
    drop(listener);
    let cleanup = guard.remove_if_unchanged();
    result.and(cleanup)
}

#[derive(Debug)]
struct AuthorityLock {
    _file: Flock<File>,
}

fn acquire_authority_lock(path: &Path) -> Result<AuthorityLock, Diagnostic> {
    validate_lock_target(path)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .map_err(path_error)?;
    set_private_file(path)?;
    let locked = Flock::lock(file, FlockArg::LockExclusiveNonblock).map_err(|(_file, error)| {
        if error == nix::errno::Errno::EWOULDBLOCK {
            Diagnostic::new(
                "E_DAEMON_ALREADY_RUNNING",
                "another Remap authority already owns this data directory",
                Some("use the running daemon instead of starting a second authority".to_owned()),
                false,
            )
        } else {
            Diagnostic::new(
                "E_AUTHORITY_LOCK",
                "the Remap authority lock could not be acquired",
                Some("check ownership and permissions on the Remap data directory".to_owned()),
                false,
            )
        }
    })?;
    Ok(AuthorityLock { _file: locked })
}

fn validate_lock_target(path: &Path) -> Result<(), Diagnostic> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(path_error(error)),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(insecure_path(
            "the authority lock path is not a regular, non-symlink file",
        ));
    }
    if metadata.uid() != nix::unistd::Uid::effective().as_raw() {
        return Err(insecure_path(
            "the authority lock is not owned by the daemon user",
        ));
    }
    Ok(())
}

async fn accept_loop<F>(
    listener: &UnixListener,
    config: &DaemonConfig,
    engine: Engine,
    network: Option<PreparedNetwork>,
    shutdown: F,
) -> Result<(), Diagnostic>
where
    F: Future<Output = ()>,
{
    let semaphore = Arc::new(Semaphore::new(config.connection_limit));
    let (shutdown_sender, _shutdown_receiver) = watch::channel(false);
    let mut connections = JoinSet::new();
    let mut services = JoinSet::new();
    if let Some(network) = network {
        spawn_network_services(&mut services, &engine, network, &shutdown_sender);
    }
    let mut maintenance = interval(config.maintenance_interval);
    maintenance.set_missed_tick_behavior(MissedTickBehavior::Delay);
    maintenance.tick().await;
    tokio::pin!(shutdown);
    let listener_result = loop {
        tokio::select! {
            () = &mut shutdown => {
                shutdown_sender.send_replace(true);
                break Ok(());
            },
            _ = maintenance.tick() => {
                if let Err(error) = engine.prune().await
                    && maintenance_failure_is_terminal(&error)
                {
                    shutdown_sender.send_replace(true);
                    break Err(error);
                }
            },
            completed = connections.join_next(), if !connections.is_empty() => {
                let _completed = completed;
            },
            completed = services.join_next(), if !services.is_empty() => {
                shutdown_sender.send_replace(true);
                break service_completion(completed);
            },
            accepted = listener.accept() => {
                let stream = match accepted {
                    Ok((stream, _address)) => stream,
                    Err(error) if transient_accept_error(&error) => {
                        tokio::time::sleep(ACCEPT_RETRY_DELAY).await;
                        continue;
                    }
                    Err(error) => {
                        shutdown_sender.send_replace(true);
                        break Err(listener_error(error));
                    }
                };
                if peer::authorize(&stream).is_err() {
                    continue;
                }
                let Ok(permit) = semaphore.clone().try_acquire_owned() else {
                    continue;
                };
                let engine = engine.clone();
                let read_timeout = config.read_timeout;
                let write_timeout = config.write_timeout;
                let connection_shutdown = shutdown_sender.subscribe();
                connections.spawn(async move {
                    let _permit = permit;
                    serve_connection(
                        stream,
                        engine,
                        read_timeout,
                        write_timeout,
                        connection_shutdown,
                    ).await
                });
            }
        }
    };
    let shutdown_deadline = tokio::time::Instant::now() + shutdown_budget(config.shutdown_grace);
    let drain_result = drain_connections(&mut connections, config.shutdown_grace).await;
    let service_result = drain_services(&mut services, config.shutdown_grace).await;
    let writer_result = timeout_at(shutdown_deadline, engine.shutdown())
        .await
        .unwrap_or_else(|_elapsed| Err(shutdown_timeout_error()));
    listener_result
        .and(drain_result)
        .and(service_result)
        .and(writer_result)
}

fn shutdown_budget(drain_grace: Duration) -> Duration {
    if drain_grace == DEFAULT_DAEMON_DRAIN_GRACE {
        SYSTEM_DAEMON_SHUTDOWN_BUDGET
    } else {
        drain_grace
            .saturating_mul(2)
            .saturating_add(WRITER_SHUTDOWN_GRACE)
    }
}

fn shutdown_timeout_error() -> Diagnostic {
    Diagnostic::new(
        "E_DAEMON_SHUTDOWN_TIMEOUT",
        "the daemon writer did not stop within the bounded shutdown budget",
        Some("inspect storage health before restarting Remap".to_owned()),
        false,
    )
}

fn spawn_network_services(
    services: &mut JoinSet<Result<(), Diagnostic>>,
    engine: &Engine,
    network: PreparedNetwork,
    shutdown: &watch::Sender<bool>,
) {
    if let Some(dns) = network.dns {
        let runtime_shutdown = shutdown.subscribe();
        services.spawn(async move {
            dns.serve(runtime_shutdown)
                .await
                .map_err(network_diagnostic)
        });
    }
    if let Some(gateway) = network.gateway {
        let runtime_shutdown = shutdown.subscribe();
        services.spawn(async move {
            gateway
                .serve(runtime_shutdown)
                .await
                .map_err(network_diagnostic)
        });
    }
    if let Some(system_control) = network.system_control {
        let runtime_shutdown = shutdown.subscribe();
        services.spawn(system_control.serve(runtime_shutdown));
    }
    let refresh_shutdown = shutdown.subscribe();
    let refresh_engine = engine.clone();
    services.spawn(refresh_snapshots(
        refresh_engine,
        network.snapshots,
        refresh_shutdown,
    ));
}

async fn refresh_snapshots(
    engine: Engine,
    snapshots: SnapshotStore,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), Diagnostic> {
    let mut revisions = engine.subscribe_revision();
    loop {
        tokio::select! {
            () = shutdown_requested(&mut shutdown) => return Ok(()),
            changed = revisions.changed() => {
                changed.map_err(|_closed| runtime_snapshot_unavailable())?;
            }
        }
        while *revisions.borrow() > snapshots.load().revision() {
            match engine.snapshot().await {
                Ok(snapshot) => {
                    let _published = snapshots.publish(snapshot);
                }
                Err(error) if error.code == "E_SNAPSHOT_BUSY" => {
                    tokio::select! {
                        () = shutdown_requested(&mut shutdown) => return Ok(()),
                        () = tokio::time::sleep(SNAPSHOT_RETRY_DELAY) => {}
                    }
                }
                Err(error) => return Err(error),
            }
        }
    }
}

fn service_completion(
    completed: Option<Result<Result<(), Diagnostic>, tokio::task::JoinError>>,
) -> Result<(), Diagnostic> {
    match completed {
        Some(Ok(Err(error))) => Err(error),
        Some(Ok(Ok(()))) | None => Err(Diagnostic::new(
            "E_NETWORK_RUNTIME_STOPPED",
            "a network runtime stopped before daemon shutdown",
            Some("restart Remap; run 'remap doctor' if the runtime stops again".to_owned()),
            true,
        )),
        Some(Err(_join_error)) => Err(Diagnostic::new(
            "E_NETWORK_RUNTIME_TASK",
            "a network runtime task terminated unexpectedly",
            Some("restart Remap; report the failure if it repeats".to_owned()),
            true,
        )),
    }
}

async fn drain_services(
    services: &mut JoinSet<Result<(), Diagnostic>>,
    grace: Duration,
) -> Result<(), Diagnostic> {
    let drain = async {
        while let Some(completed) = services.join_next().await {
            match completed {
                Ok(Ok(())) => {}
                Ok(Err(error)) => return Err(error),
                Err(_join_error) => return Err(runtime_snapshot_unavailable()),
            }
        }
        Ok(())
    };
    match timeout(grace, drain).await {
        Ok(result) => result,
        Err(_elapsed) => {
            services.abort_all();
            while services.join_next().await.is_some() {}
            Err(Diagnostic::new(
                "E_NETWORK_SHUTDOWN_TIMEOUT",
                "a network runtime did not stop before the shutdown deadline",
                Some("restart Remap and inspect local network health".to_owned()),
                false,
            ))
        }
    }
}

pub(crate) fn network_diagnostic(error: NetworkError) -> Diagnostic {
    match error {
        NetworkError::Configuration(detail) => {
            let gateway = detail.starts_with("HTTP");
            Diagnostic::new(
                if gateway {
                    "E_GATEWAY_CONFIG"
                } else {
                    "E_DNS_CONFIG"
                },
                if gateway {
                    "the HTTP gateway configuration is invalid"
                } else {
                    "the DNS runtime configuration is invalid"
                },
                Some("run 'remap doctor' and correct the reported runtime setting".to_owned()),
                false,
            )
            .with_context("detail", detail)
        }
        NetworkError::Io { operation, source } => {
            let gateway = operation.starts_with("HTTP") || operation.starts_with("native TLS");
            Diagnostic::new(
                if gateway { "E_GATEWAY_IO" } else { "E_DNS_IO" },
                if gateway {
                    "the HTTP gateway could not complete a native network operation"
                } else {
                    "the DNS runtime could not complete a native network operation"
                },
                Some(
                    "check listener ownership and local network availability, then retry"
                        .to_owned(),
                ),
                source.kind() != io::ErrorKind::PermissionDenied,
            )
            .with_context("operation", operation)
        }
        NetworkError::Encoding => Diagnostic::new(
            "E_DNS_ENCODING",
            "the DNS runtime could not encode a validated response",
            Some("restart Remap; report the request type if the failure repeats".to_owned()),
            false,
        ),
        NetworkError::UpstreamUnavailable => Diagnostic::new(
            "E_DNS_UPSTREAM",
            "no configured DNS upstream returned a related response",
            Some("check upstream resolver availability; mapped names remain local".to_owned()),
            true,
        ),
    }
}

fn runtime_snapshot_unavailable() -> Diagnostic {
    Diagnostic::new(
        "E_RUNTIME_SNAPSHOT_UNAVAILABLE",
        "the DNS snapshot publisher stopped unexpectedly",
        Some("restart Remap; run 'remap doctor' if the failure repeats".to_owned()),
        true,
    )
}

fn signal_error(_error: io::Error) -> Diagnostic {
    Diagnostic::new(
        "E_DAEMON_SIGNAL",
        "the daemon could not register its termination handler",
        Some("restart Remap; if the failure repeats, report the operating-system error".to_owned()),
        true,
    )
}

fn bootstrap_order_error() -> Diagnostic {
    Diagnostic::new(
        "E_PRIVILEGE_BOOTSTRAP_ORDER",
        "the privileged network bootstrap was requested after runtime threads started",
        Some("start the installed remapd service entry point instead".to_owned()),
        false,
    )
}

fn maintenance_failure_is_terminal(error: &Diagnostic) -> bool {
    !(error.retryable && matches!(error.code.as_str(), "E_REGISTRY" | "E_REGISTRY_CHECKPOINT"))
}

async fn serve_connection(
    mut stream: UnixStream,
    engine: Engine,
    read_deadline: Duration,
    write_deadline: Duration,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<()> {
    let request: ControlRequest = tokio::select! {
        () = shutdown_requested(&mut shutdown) => return Ok(()),
        read = timeout(read_deadline, read_frame(&mut stream)) => {
            read.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "request read timed out"))??
        }
    };
    let request_id = request.request_id.clone();
    let response = tokio::select! {
        () = shutdown_requested(&mut shutdown) => return Ok(()),
        result = engine.execute(request) => {
            result.unwrap_or_else(|error| ControlResponse::failure(request_id, error))
        }
    };
    timeout(write_deadline, write_frame(&mut stream, &response))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "response write timed out"))??;
    Ok(())
}

async fn shutdown_requested(shutdown: &mut watch::Receiver<bool>) {
    if *shutdown.borrow() {
        return;
    }
    let _changed = shutdown.changed().await;
}

async fn drain_connections(
    connections: &mut JoinSet<io::Result<()>>,
    grace: Duration,
) -> Result<(), Diagnostic> {
    let drain = async { while let Some(_result) = connections.join_next().await {} };
    if timeout(grace, drain).await.is_ok() {
        return Ok(());
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    Err(Diagnostic::new(
        "E_DAEMON_SHUTDOWN_TIMEOUT",
        "accepted local-control work did not finish before the shutdown deadline",
        Some(
            "restart Remap and inspect local storage health before retrying a mutation".to_owned(),
        ),
        false,
    ))
}

fn validate_config(config: &DaemonConfig) -> Result<(), Diagnostic> {
    validate_listener_configuration(config)?;
    validate_runtime_bounds(config)?;
    validate_socket_paths(config)
}

fn validate_listener_configuration(config: &DaemonConfig) -> Result<(), Diagnostic> {
    crate::systemd::validate_config(config)?;
    if config.launchd_sockets && config.run_as.is_some() {
        return Err(Diagnostic::new(
            "E_DAEMON_CONFIG",
            "launchd socket activation cannot be combined with a root privilege transition",
            Some("use launchd UserName and socket activation on macOS".to_owned()),
            false,
        ));
    }
    if config.launchd_sockets && config.dns.is_none() && config.gateway.is_none() {
        return Err(Diagnostic::new(
            "E_DAEMON_CONFIG",
            "launchd socket activation requires at least one network listener",
            Some("repair the native Remap service configuration".to_owned()),
            false,
        ));
    }
    if config.run_as.is_some() && config.dns.is_none() && config.gateway.is_none() {
        return Err(Diagnostic::new(
            "E_DAEMON_CONFIG",
            "a privilege transition requires at least one pre-bound network listener",
            Some("remove --run-as-user or configure the native DNS or HTTP listener".to_owned()),
            false,
        ));
    }
    Ok(())
}

fn validate_runtime_bounds(config: &DaemonConfig) -> Result<(), Diagnostic> {
    if config.connection_limit == 0 || config.connection_limit > 4096 {
        return Err(Diagnostic::new(
            "E_DAEMON_CONFIG",
            "connection_limit must be between 1 and 4096",
            Some("use the default unless a measured workload requires another bound".to_owned()),
            false,
        ));
    }
    if config.read_timeout.is_zero()
        || config.write_timeout.is_zero()
        || config.shutdown_grace.is_zero()
        || config.maintenance_interval.is_zero()
    {
        return Err(Diagnostic::new(
            "E_DAEMON_CONFIG",
            "local-control I/O timeouts must be greater than zero",
            Some("use the default 15-second deadlines".to_owned()),
            false,
        ));
    }
    Ok(())
}

fn validate_socket_paths(config: &DaemonConfig) -> Result<(), Diagnostic> {
    if config.paths.socket().as_os_str().as_bytes().len() >= UNIX_SOCKET_PATH_CAPACITY {
        return Err(Diagnostic::new(
            "E_CONTROL_SOCKET_PATH",
            "the local-control socket path is too long for this operating system",
            Some("use a shorter Remap data-directory path".to_owned()),
            false,
        ));
    }
    if config.system_socket.as_os_str().as_bytes().len() >= UNIX_SOCKET_PATH_CAPACITY {
        return Err(Diagnostic::new(
            "E_SYSTEM_CONTROL_SOCKET_PATH",
            "the resolver-supervisor socket path is too long for this operating system",
            Some("use a shorter Remap data-directory path".to_owned()),
            false,
        ));
    }
    Ok(())
}

fn prepare_data_directory(path: &Path) -> Result<(), Diagnostic> {
    if path.exists() {
        let metadata = std::fs::symlink_metadata(path).map_err(path_error)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(insecure_path("the Remap data path is not a real directory"));
        }
        if metadata.uid() != nix::unistd::Uid::effective().as_raw() {
            return Err(insecure_path(
                "the Remap data directory is not owned by the daemon user",
            ));
        }
    } else {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder.create(path).map_err(path_error)?;
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(path_error)
}

fn validate_database_target(path: &Path) -> Result<(), Diagnostic> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(path_error(error)),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(insecure_path(
            "the registry path is not a regular, non-symlink file",
        ));
    }
    if metadata.uid() != nix::unistd::Uid::effective().as_raw() {
        return Err(insecure_path(
            "the registry file is not owned by the daemon user",
        ));
    }
    Ok(())
}

fn set_private_file(path: &Path) -> Result<(), Diagnostic> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(path_error)
}

fn validate_database_family(database: &Path) -> Result<(), Diagnostic> {
    for path in database_family(database) {
        validate_database_target(&path)?;
    }
    Ok(())
}

fn secure_database_family(database: &Path) -> Result<(), Diagnostic> {
    validate_database_family(database)?;
    for path in database_family(database) {
        if path.exists() {
            set_private_file(&path)?;
        }
    }
    Ok(())
}

fn database_family(database: &Path) -> [PathBuf; 4] {
    [
        database.to_path_buf(),
        with_suffix(database, "-wal"),
        with_suffix(database, "-shm"),
        with_suffix(database, "-journal"),
    ]
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

async fn prepare_socket_target(path: &Path) -> Result<(), Diagnostic> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(path_error(error)),
    };
    if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
        return Err(insecure_path(
            "the control socket path exists but is not a real Unix socket",
        ));
    }
    if metadata.uid() != nix::unistd::Uid::effective().as_raw() {
        return Err(insecure_path(
            "the existing control socket is not owned by the daemon user",
        ));
    }
    if UnixStream::connect(path).await.is_ok() {
        return Err(Diagnostic::new(
            "E_DAEMON_ALREADY_RUNNING",
            "another Remap daemon is already listening",
            Some("use the running daemon instead of starting a second authority".to_owned()),
            false,
        ));
    }
    std::fs::remove_file(path).map_err(path_error)
}

struct SocketGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl SocketGuard {
    fn capture(path: &Path) -> Result<Self, Diagnostic> {
        let metadata = std::fs::symlink_metadata(path).map_err(path_error)?;
        Ok(Self {
            path: path.to_path_buf(),
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    fn remove_if_unchanged(self) -> Result<(), Diagnostic> {
        let metadata = match std::fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(path_error(error)),
        };
        if metadata.dev() != self.device
            || metadata.ino() != self.inode
            || !metadata.file_type().is_socket()
        {
            return Err(insecure_path(
                "the control socket path changed while the daemon was running",
            ));
        }
        std::fs::remove_file(&self.path).map_err(path_error)
    }
}

fn cleanup_start_failure(
    listener: UnixListener,
    guard: SocketGuard,
    error: Diagnostic,
) -> Result<(), Diagnostic> {
    drop(listener);
    guard.remove_if_unchanged()?;
    Err(error)
}

fn transient_accept_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock | io::ErrorKind::ConnectionAborted
    ) || matches!(
        error.raw_os_error(),
        Some(nix::libc::EMFILE | nix::libc::ENFILE)
    )
}

fn listener_error(_error: io::Error) -> Diagnostic {
    Diagnostic::new(
        "E_CONTROL_LISTENER",
        "the local-control socket could not be served",
        Some("check data-directory ownership and whether another remapd is running".to_owned()),
        false,
    )
}

fn path_error(_error: io::Error) -> Diagnostic {
    Diagnostic::new(
        "E_DATA_PATH",
        "Remap could not secure its private data path",
        Some("check that the current user owns the Remap data directory".to_owned()),
        false,
    )
}

fn insecure_path(message: &str) -> Diagnostic {
    Diagnostic::new(
        "E_INSECURE_DATA_PATH",
        message,
        Some(
            "move the unexpected path aside and restore a user-owned private directory".to_owned(),
        ),
        false,
    )
}

#[cfg(test)]
mod tests {
    use remap_protocol::{
        DEFAULT_DAEMON_DRAIN_GRACE, Diagnostic, NATIVE_DAEMON_TERMINATION_GRACE,
        SYSTEM_DAEMON_SHUTDOWN_BUDGET,
    };

    use super::{maintenance_failure_is_terminal, shutdown_budget};

    #[test]
    fn production_shutdown_budget_is_shared_with_native_lifecycle() {
        assert_eq!(
            shutdown_budget(DEFAULT_DAEMON_DRAIN_GRACE),
            SYSTEM_DAEMON_SHUTDOWN_BUDGET
        );
        assert!(NATIVE_DAEMON_TERMINATION_GRACE > SYSTEM_DAEMON_SHUTDOWN_BUDGET);
    }

    #[test]
    fn only_retryable_retention_failures_keep_the_authority_available() {
        let locked_registry = Diagnostic::new("E_REGISTRY", "locked", None, true);
        let blocked_checkpoint = Diagnostic::new("E_REGISTRY_CHECKPOINT", "blocked", None, true);
        let unavailable_writer =
            Diagnostic::new("E_DAEMON_WRITER_UNAVAILABLE", "closed", None, true);
        let permanent_registry = Diagnostic::new("E_REGISTRY", "corrupt", None, false);

        assert!(!maintenance_failure_is_terminal(&locked_registry));
        assert!(!maintenance_failure_is_terminal(&blocked_checkpoint));
        assert!(maintenance_failure_is_terminal(&unavailable_writer));
        assert!(maintenance_failure_is_terminal(&permanent_registry));
    }
}
