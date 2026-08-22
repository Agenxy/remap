use std::fs::Permissions;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener as StdUnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use remap_network::{NetworkError, ResolverPlanStore};
use remap_protocol::{
    DEFAULT_DAEMON_DRAIN_GRACE, Diagnostic, SYSTEM_PROTOCOL_VERSION, SystemCommand, SystemRequest,
    SystemResponse, SystemResult, read_system_frame, write_system_frame,
};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, Semaphore, watch};
use tokio::task::JoinSet;
use tokio::time::{timeout, timeout_at};
use uuid::Uuid;

use crate::peer;

const CONNECTION_LIMIT: usize = 8;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const SHUTDOWN_GRACE: Duration = DEFAULT_DAEMON_DRAIN_GRACE;
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(25);

#[derive(Debug)]
pub(crate) struct SystemControlRuntime {
    listener: UnixListener,
    guard: Option<SystemSocketGuard>,
    controller: SystemController,
}

#[derive(Debug, Clone)]
struct SystemController {
    plans: ResolverPlanStore,
    state: Arc<Mutex<ControllerState>>,
}

#[derive(Debug, Default)]
struct ControllerState {
    activation_id: Option<Uuid>,
}

#[derive(Debug)]
struct SystemSocketGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl SystemControlRuntime {
    pub(crate) async fn bind(path: &Path, plans: ResolverPlanStore) -> Result<Self, Diagnostic> {
        prepare_socket_target(path).await?;
        let listener = UnixListener::bind(path).map_err(listener_error)?;
        std::fs::set_permissions(path, Permissions::from_mode(0o600)).map_err(path_error)?;
        let guard = SystemSocketGuard::capture(path)?;
        Ok(Self {
            listener,
            guard: Some(guard),
            controller: SystemController::new(plans),
        })
    }

    pub(crate) fn adopt(
        listener: StdUnixListener,
        plans: ResolverPlanStore,
    ) -> Result<Self, Diagnostic> {
        listener.set_nonblocking(true).map_err(listener_error)?;
        let listener = UnixListener::from_std(listener).map_err(listener_error)?;
        Ok(Self {
            listener,
            guard: None,
            controller: SystemController::new(plans),
        })
    }

    pub(crate) async fn serve(self, mut shutdown: watch::Receiver<bool>) -> Result<(), Diagnostic> {
        let permits = Arc::new(Semaphore::new(CONNECTION_LIMIT));
        let mut jobs = JoinSet::new();
        loop {
            tokio::select! {
                () = shutdown_requested(&mut shutdown) => break,
                completed = jobs.join_next(), if !jobs.is_empty() => {
                    let _completed = completed;
                }
                accepted = self.listener.accept() => {
                    let stream = match accepted {
                        Ok((stream, _address)) => stream,
                        Err(error) if transient_accept_error(&error) => {
                            tokio::time::sleep(ACCEPT_RETRY_DELAY).await;
                            continue;
                        }
                        Err(error) => return Err(listener_error(error)),
                    };
                    if peer::authorize_root(&stream).is_err() {
                        continue;
                    }
                    let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                        continue;
                    };
                    let controller = self.controller.clone();
                    let connection_shutdown = shutdown.clone();
                    jobs.spawn(async move {
                        let _permit = permit;
                        serve_connection(stream, controller, connection_shutdown).await
                    });
                }
            }
        }
        drain_jobs(&mut jobs).await?;
        drop(self.listener);
        if let Some(guard) = self.guard {
            guard.remove_if_unchanged()?;
        }
        Ok(())
    }
}

impl SystemController {
    fn new(plans: ResolverPlanStore) -> Self {
        Self {
            plans,
            state: Arc::new(Mutex::new(ControllerState::default())),
        }
    }

    async fn execute(&self, request: SystemRequest) -> SystemResponse {
        let request_id = request.request_id;
        if request.protocol != SYSTEM_PROTOCOL_VERSION {
            return SystemResponse::failure(request_id, protocol_error());
        }
        let mut state = self.state.lock().await;
        let result = self.execute_command(&mut state, request.command);
        match result {
            Ok(result) => SystemResponse::success(request_id, result),
            Err(error) => SystemResponse::failure(request_id, error),
        }
    }

    fn execute_command(
        &self,
        state: &mut ControllerState,
        command: SystemCommand,
    ) -> Result<SystemResult, Diagnostic> {
        match command {
            SystemCommand::PublishResolverPlan {
                activation_id,
                generation,
                upstreams,
            } => self.publish(state, activation_id, generation, upstreams),
            SystemCommand::InvalidateResolverPlan {
                activation_id,
                generation,
            } => self.invalidate(state, activation_id, generation),
            SystemCommand::ResolverHealth => Ok(system_result(state, &self.plans)),
        }
    }

    fn publish(
        &self,
        state: &mut ControllerState,
        activation_id: Uuid,
        generation: u64,
        upstreams: Vec<std::net::SocketAddr>,
    ) -> Result<SystemResult, Diagnostic> {
        if !activation_matches(state.activation_id, activation_id) {
            return Err(activation_error());
        }
        self.plans
            .publish(generation, upstreams)
            .map_err(plan_error)?;
        state.activation_id = Some(activation_id);
        Ok(system_result(state, &self.plans))
    }

    fn invalidate(
        &self,
        state: &mut ControllerState,
        activation_id: Uuid,
        generation: u64,
    ) -> Result<SystemResult, Diagnostic> {
        if state.activation_id.is_none() && self.plans.active_generation().is_none() {
            return Ok(system_result(state, &self.plans));
        }
        if state.activation_id != Some(activation_id) {
            return Err(activation_error());
        }
        if !self.plans.invalidate(generation).map_err(plan_error)? {
            return Err(generation_error());
        }
        state.activation_id = None;
        Ok(system_result(state, &self.plans))
    }
}

fn activation_matches(current: Option<Uuid>, requested: Uuid) -> bool {
    current.is_none_or(|activation_id| activation_id == requested)
}

fn system_result(state: &ControllerState, plans: &ResolverPlanStore) -> SystemResult {
    SystemResult {
        activation_id: state.activation_id,
        active_generation: plans.active_generation(),
    }
}

async fn serve_connection(
    mut stream: UnixStream,
    controller: SystemController,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<()> {
    let request = tokio::select! {
        () = shutdown_requested(&mut shutdown) => return Ok(()),
        result = timeout(IO_TIMEOUT, read_system_frame::<SystemRequest, _>(&mut stream)) => {
            result.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "system request timed out"))??
        }
    };
    let response = controller.execute(request).await;
    timeout(IO_TIMEOUT, write_system_frame(&mut stream, &response))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "system response timed out"))??;
    Ok(())
}

async fn drain_jobs(jobs: &mut JoinSet<io::Result<()>>) -> Result<(), Diagnostic> {
    let deadline = tokio::time::Instant::now() + SHUTDOWN_GRACE;
    while !jobs.is_empty() {
        if timeout_at(deadline, jobs.join_next()).await.is_err() {
            jobs.abort_all();
            while jobs.join_next().await.is_some() {}
            return Err(Diagnostic::new(
                "E_SYSTEM_CONTROL_SHUTDOWN",
                "resolver-supervisor connections did not stop before shutdown",
                Some("restart Remap before changing native resolver state".to_owned()),
                false,
            ));
        }
    }
    Ok(())
}

async fn prepare_socket_target(path: &Path) -> Result<(), Diagnostic> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(path_error(error)),
    };
    if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
        return Err(insecure_path());
    }
    if metadata.uid() != nix::unistd::Uid::effective().as_raw() {
        return Err(insecure_path());
    }
    if UnixStream::connect(path).await.is_ok() {
        return Err(Diagnostic::new(
            "E_SYSTEM_CONTROL_ACTIVE",
            "another resolver-supervisor channel is already listening",
            Some("use the running Remap authority".to_owned()),
            false,
        ));
    }
    std::fs::remove_file(path).map_err(path_error)
}

impl SystemSocketGuard {
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
            return Err(insecure_path());
        }
        std::fs::remove_file(&self.path).map_err(path_error)
    }
}

fn plan_error(_error: NetworkError) -> Diagnostic {
    Diagnostic::new(
        "E_RESOLVER_PLAN",
        "the proposed resolver generation is invalid",
        Some("recompute complete native resolver state and publish a newer generation".to_owned()),
        false,
    )
}

fn protocol_error() -> Diagnostic {
    Diagnostic::new(
        "E_SYSTEM_PROTOCOL",
        "the resolver supervisor requested an unsupported protocol",
        Some("update the Remap app, service, and native supervisor together".to_owned()),
        false,
    )
}

fn activation_error() -> Diagnostic {
    Diagnostic::new(
        "E_RESOLVER_ACTIVATION",
        "the resolver plan belongs to a different native activation",
        Some("restart the installed service before publishing the new activation".to_owned()),
        false,
    )
}

fn generation_error() -> Diagnostic {
    Diagnostic::new(
        "E_RESOLVER_GENERATION",
        "the requested resolver generation is not active",
        Some("read resolver health and reconcile from complete native state".to_owned()),
        false,
    )
}

fn transient_accept_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock | io::ErrorKind::ConnectionAborted
    )
}

fn listener_error(_error: io::Error) -> Diagnostic {
    Diagnostic::new(
        "E_SYSTEM_CONTROL_LISTENER",
        "the root-only resolver-supervisor channel could not be served",
        Some("restart the native Remap service".to_owned()),
        true,
    )
}

fn path_error(_error: io::Error) -> Diagnostic {
    Diagnostic::new(
        "E_SYSTEM_CONTROL_PATH",
        "Remap could not secure the resolver-supervisor socket",
        Some("repair ownership of the private Remap data directory".to_owned()),
        false,
    )
}

fn insecure_path() -> Diagnostic {
    Diagnostic::new(
        "E_INSECURE_SYSTEM_CONTROL_PATH",
        "the resolver-supervisor socket path is not a user-owned Unix socket",
        Some("move the unexpected path aside and restart Remap".to_owned()),
        false,
    )
}

async fn shutdown_requested(shutdown: &mut watch::Receiver<bool>) {
    if *shutdown.borrow() {
        return;
    }
    let _changed = shutdown.changed().await;
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::io;
    use std::net::{Ipv4Addr, SocketAddr};

    use remap_network::ResolverPlanStore;
    use remap_protocol::{SYSTEM_PROTOCOL_VERSION, SystemCommand, SystemRequest};
    use uuid::Uuid;

    use super::SystemController;

    fn endpoint(octet: u8) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::new(192, 0, 2, octet), 53))
    }

    #[tokio::test]
    async fn controller_binds_one_activation_and_never_exposes_addresses()
    -> Result<(), Box<dyn Error>> {
        let plans = ResolverPlanStore::initial(vec![endpoint(1)])?;
        let controller = SystemController::new(plans);
        let activation_id = Uuid::new_v4();
        let response = controller
            .execute(SystemRequest {
                protocol: SYSTEM_PROTOCOL_VERSION.to_owned(),
                request_id: Uuid::new_v4(),
                command: SystemCommand::PublishResolverPlan {
                    activation_id,
                    generation: 2,
                    upstreams: vec![endpoint(2)],
                },
            })
            .await;
        let result = response
            .result
            .as_ref()
            .ok_or_else(|| io::Error::other("publication returned no result"))?;
        assert_eq!(result.activation_id, Some(activation_id));
        assert_eq!(result.active_generation, Some(2));
        let encoded = serde_json::to_string(&response)?;
        assert!(!encoded.contains("192.0.2"));
        Ok(())
    }

    #[tokio::test]
    async fn controller_rejects_activation_and_generation_confusion() -> Result<(), Box<dyn Error>>
    {
        let controller = SystemController::new(ResolverPlanStore::initial(vec![endpoint(1)])?);
        let activation_id = Uuid::new_v4();
        let publish = SystemRequest {
            protocol: SYSTEM_PROTOCOL_VERSION.to_owned(),
            request_id: Uuid::new_v4(),
            command: SystemCommand::PublishResolverPlan {
                activation_id,
                generation: 4,
                upstreams: vec![endpoint(4)],
            },
        };
        assert!(controller.execute(publish).await.error.is_none());
        let invalidation = SystemRequest {
            protocol: SYSTEM_PROTOCOL_VERSION.to_owned(),
            request_id: Uuid::new_v4(),
            command: SystemCommand::InvalidateResolverPlan {
                activation_id: Uuid::new_v4(),
                generation: 4,
            },
        };
        assert!(controller.execute(invalidation).await.error.is_some());
        Ok(())
    }

    #[tokio::test]
    async fn dormant_controller_supports_first_publish_update_and_daemon_restart()
    -> Result<(), Box<dyn Error>> {
        let activation_id = Uuid::new_v4();
        let controller = SystemController::new(ResolverPlanStore::dormant());
        let health = controller
            .execute(SystemRequest {
                protocol: SYSTEM_PROTOCOL_VERSION.to_owned(),
                request_id: Uuid::new_v4(),
                command: SystemCommand::ResolverHealth,
            })
            .await;
        assert_eq!(
            health.result.and_then(|result| result.active_generation),
            None
        );
        for generation in [7, 8] {
            let response = controller
                .execute(SystemRequest {
                    protocol: SYSTEM_PROTOCOL_VERSION.to_owned(),
                    request_id: Uuid::new_v4(),
                    command: SystemCommand::PublishResolverPlan {
                        activation_id,
                        generation,
                        upstreams: vec![endpoint(u8::try_from(generation)?)],
                    },
                })
                .await;
            assert_eq!(
                response.result.and_then(|result| result.active_generation),
                Some(generation)
            );
        }
        let invalidated = controller
            .execute(SystemRequest {
                protocol: SYSTEM_PROTOCOL_VERSION.to_owned(),
                request_id: Uuid::new_v4(),
                command: SystemCommand::InvalidateResolverPlan {
                    activation_id,
                    generation: 8,
                },
            })
            .await;
        assert_eq!(
            invalidated
                .result
                .map(|result| (result.activation_id, result.active_generation)),
            Some((None, None))
        );
        let replayed = controller
            .execute(SystemRequest {
                protocol: SYSTEM_PROTOCOL_VERSION.to_owned(),
                request_id: Uuid::new_v4(),
                command: SystemCommand::InvalidateResolverPlan {
                    activation_id: Uuid::new_v4(),
                    generation: 99,
                },
            })
            .await;
        assert_eq!(
            replayed
                .result
                .map(|result| (result.activation_id, result.active_generation)),
            Some((None, None))
        );
        let restarted = SystemController::new(ResolverPlanStore::dormant());
        let response = restarted
            .execute(SystemRequest {
                protocol: SYSTEM_PROTOCOL_VERSION.to_owned(),
                request_id: Uuid::new_v4(),
                command: SystemCommand::PublishResolverPlan {
                    activation_id,
                    generation: 8,
                    upstreams: vec![endpoint(8)],
                },
            })
            .await;
        assert_eq!(
            response.result.and_then(|result| result.active_generation),
            Some(8)
        );
        Ok(())
    }
}
