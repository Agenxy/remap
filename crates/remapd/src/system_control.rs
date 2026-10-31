// SPDX-License-Identifier: GPL-3.0-or-later
use std::fs::Permissions;
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener as StdUnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use remap_core::MappingTarget;
use remap_network::{NetworkError, PeerMachineListeners, ResolverPlanStore, SnapshotStore};
use remap_protocol::{
    DEFAULT_DAEMON_DRAIN_GRACE, Diagnostic, ListenerAddress, MAX_LISTENERS_PER_EXCHANGE,
    SYSTEM_PROTOCOL_VERSION, SystemCommand, SystemRequest, SystemResponse, SystemResult,
    decode_system_request, write_system_frame,
};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, Semaphore, watch};
use tokio::task::JoinSet;
use tokio::time::{timeout, timeout_at};
use uuid::Uuid;

use crate::descriptor_handoff;
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
    snapshots: SnapshotStore,
    peer_machines: Option<PeerMachineListeners>,
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
    pub(crate) async fn bind(
        path: &Path,
        plans: ResolverPlanStore,
        snapshots: SnapshotStore,
        peer_machines: Option<PeerMachineListeners>,
    ) -> Result<Self, Diagnostic> {
        prepare_socket_target(path).await?;
        let listener = UnixListener::bind(path).map_err(listener_error)?;
        std::fs::set_permissions(path, Permissions::from_mode(0o600)).map_err(path_error)?;
        let guard = SystemSocketGuard::capture(path)?;
        Ok(Self {
            listener,
            guard: Some(guard),
            controller: SystemController::new(plans, snapshots, peer_machines),
        })
    }

    pub(crate) fn adopt(
        listener: StdUnixListener,
        plans: ResolverPlanStore,
        snapshots: SnapshotStore,
        peer_machines: Option<PeerMachineListeners>,
    ) -> Result<Self, Diagnostic> {
        listener.set_nonblocking(true).map_err(listener_error)?;
        let listener = UnixListener::from_std(listener).map_err(listener_error)?;
        Ok(Self {
            listener,
            guard: None,
            controller: SystemController::new(plans, snapshots, peer_machines),
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
    fn new(
        plans: ResolverPlanStore,
        snapshots: SnapshotStore,
        peer_machines: Option<PeerMachineListeners>,
    ) -> Self {
        Self {
            plans,
            snapshots,
            peer_machines,
            state: Arc::new(Mutex::new(ControllerState::default())),
        }
    }

    #[cfg(test)]
    async fn execute(&self, request: SystemRequest) -> SystemResponse {
        self.execute_with(request, Vec::new()).await
    }

    /// Runs one request. Descriptors are accepted only with the one request
    /// that carries them; anything else that arrives with descriptors is
    /// refused, and dropping them closes them.
    async fn execute_with(
        &self,
        request: SystemRequest,
        descriptors: Vec<OwnedFd>,
    ) -> SystemResponse {
        let request_id = request.request_id;
        if request.protocol != SYSTEM_PROTOCOL_VERSION {
            return SystemResponse::failure(request_id, protocol_error());
        }
        let mut state = self.state.lock().await;
        let result = match request.command {
            SystemCommand::AdoptPeerMachineListeners { listeners } => {
                self.adopt_listeners(&state, &listeners, descriptors)
            }
            command if descriptors.is_empty() => self.execute_command(&mut state, command),
            _ => Err(descriptor_error(
                "only a listener hand-off may carry descriptors",
            )),
        };
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
            // The root supervisor learns addresses only, never which name or
            // peer each one serves (ADR-0033).
            SystemCommand::LoopbackReservations => Ok(self.reservations(state)),
            SystemCommand::AdoptPeerMachineListeners { .. } => Err(descriptor_error(
                "a listener hand-off must carry its descriptors",
            )),
        }
    }

    /// Addresses, and the listed ports `remapd` does not yet hold on them.
    fn reservations(&self, state: &ControllerState) -> SystemResult {
        let snapshot = self.snapshots.load();
        let unheld = self
            .peer_machines
            .as_ref()
            .map_or_else(Vec::new, |listeners| {
                snapshot
                    .mappings()
                    .iter()
                    .filter(|mapping| mapping.is_enabled())
                    .filter_map(|mapping| match (mapping.target(), mapping.peer_address()) {
                        (MappingTarget::PeerMachine(machine), Some(address)) => {
                            Some((machine, address))
                        }
                        _ => None,
                    })
                    .flat_map(|(machine, address)| {
                        machine
                            .services()
                            .iter()
                            .map(move |service| ListenerAddress {
                                address,
                                port: service.port(),
                            })
                    })
                    .filter(|listener| !listeners.is_held(listener.address, listener.port.get()))
                    .collect()
            });
        system_result(state, &self.plans)
            .with_loopback_reservations(snapshot.peer_machine_addresses())
            .with_unheld_listeners(unheld)
    }

    /// Adopts root-created listening sockets, one per named listener. The
    /// count must match exactly; each socket is checked against the endpoint
    /// it is named for before it is used.
    fn adopt_listeners(
        &self,
        state: &ControllerState,
        listeners: &[ListenerAddress],
        descriptors: Vec<OwnedFd>,
    ) -> Result<SystemResult, Diagnostic> {
        let Some(machines) = self.peer_machines.as_ref() else {
            return Err(descriptor_error(
                "this daemon carries no peer-machine listeners",
            ));
        };
        if listeners.len() != descriptors.len() || listeners.len() > MAX_LISTENERS_PER_EXCHANGE {
            return Err(descriptor_error(
                "a listener hand-off must carry one descriptor per listener",
            ));
        }
        for (listener, descriptor) in listeners.iter().zip(descriptors) {
            // A refused socket is closed here and stays unheld, so its name
            // keeps failing closed; the next exchange reports it again.
            let _refused = machines.adopt(
                listener.address,
                listener.port.get(),
                std::net::TcpListener::from(descriptor),
            );
        }
        Ok(self.reservations(state))
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
    SystemResult::new(
        state.activation_id,
        plans.active_generation(),
        plans.highest_accepted_generation(),
    )
}

async fn serve_connection(
    mut stream: UnixStream,
    controller: SystemController,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<()> {
    let frame = tokio::select! {
        () = shutdown_requested(&mut shutdown) => return Ok(()),
        result = timeout(IO_TIMEOUT, descriptor_handoff::read_frame(&stream)) => {
            result.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "system request timed out"))??
        }
    };
    let request = decode_system_request(&frame.payload)?;
    let response = controller.execute_with(request, frame.descriptors).await;
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

fn descriptor_error(message: &'static str) -> Diagnostic {
    Diagnostic::new(
        "E_SYSTEM_DESCRIPTORS",
        message,
        Some("update the Remap app, service, and native supervisor together".to_owned()),
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

    use remap_core::{Mapping, RegistrySnapshot};
    use remap_network::{ResolverPlanStore, SnapshotStore};
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
        let controller = SystemController::new(plans, SnapshotStore::empty(), None);
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
        let controller = SystemController::new(
            ResolverPlanStore::initial(vec![endpoint(1)])?,
            SnapshotStore::empty(),
            None,
        );
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
        let controller =
            SystemController::new(ResolverPlanStore::dormant(), SnapshotStore::empty(), None);
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
        assert_eq!(
            controller
                .execute(SystemRequest {
                    protocol: SYSTEM_PROTOCOL_VERSION.to_owned(),
                    request_id: Uuid::new_v4(),
                    command: SystemCommand::ResolverHealth,
                })
                .await
                .result
                .and_then(|result| result.highest_accepted_generation),
            Some(8)
        );
        let restarted =
            SystemController::new(ResolverPlanStore::dormant(), SnapshotStore::empty(), None);
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

    #[tokio::test]
    async fn health_after_invalidation_reports_the_generation_a_new_supervisor_must_exceed()
    -> Result<(), Box<dyn Error>> {
        let controller =
            SystemController::new(ResolverPlanStore::dormant(), SnapshotStore::empty(), None);
        let first = Uuid::new_v4();
        for generation in 1..=3 {
            let published = controller.execute(publish(first, generation)).await;
            assert!(published.error.is_none());
        }
        let steady = controller.execute(health()).await;
        let steady = steady
            .result
            .ok_or_else(|| io::Error::other("health returned no result"))?;
        assert_eq!(steady.active_generation, Some(3));
        assert_eq!(steady.highest_accepted_generation, None);
        let invalidated = controller
            .execute(SystemRequest {
                protocol: SYSTEM_PROTOCOL_VERSION.to_owned(),
                request_id: Uuid::new_v4(),
                command: SystemCommand::InvalidateResolverPlan {
                    activation_id: first,
                    generation: 3,
                },
            })
            .await;
        assert!(invalidated.error.is_none());
        let after = controller
            .execute(health())
            .await
            .result
            .ok_or_else(|| io::Error::other("health returned no result"))?;
        assert_eq!(
            (
                after.activation_id,
                after.active_generation,
                after.highest_accepted_generation
            ),
            (None, None, Some(3))
        );
        let second = Uuid::new_v4();
        let stale = controller.execute(publish(second, 1)).await;
        assert_eq!(
            stale.error.map(|error| error.code),
            Some("E_RESOLVER_PLAN".to_owned())
        );
        let next = after.highest_accepted_generation.unwrap_or_default() + 1;
        let rearmed = controller
            .execute(publish(second, next))
            .await
            .result
            .ok_or_else(|| io::Error::other("publication returned no result"))?;
        assert_eq!(rearmed.activation_id, Some(second));
        assert_eq!(rearmed.active_generation, Some(4));
        Ok(())
    }

    #[tokio::test]
    async fn loopback_reservations_carry_only_enabled_peer_machine_addresses()
    -> Result<(), Box<dyn Error>> {
        let node = "a8a37e32c37cdf4fb7634de622bc3f84ccb4636580d1ea26af3fe8ac31d1f152";
        let peer =
            |pattern: &str, address: [u8; 4], enabled: bool| -> Result<Mapping, Box<dyn Error>> {
                Ok(Mapping::new(
                    pattern.parse()?,
                    format!("supgang://{node}?ssh=22").parse()?,
                )
                .with_enabled(enabled)
                .with_peer_address(Some(Ipv4Addr::from(address))))
            };
        let snapshots = SnapshotStore::empty();
        let _published = snapshots.publish(RegistrySnapshot::new(
            1,
            vec![
                peer("pro.agenxy.internal", [127, 77, 0, 2], true)?,
                peer("solis.agenxy.internal", [127, 77, 0, 1], true)?,
                peer("old.agenxy.internal", [127, 77, 0, 3], false)?,
                Mapping::new("app.test".parse()?, "http://127.0.0.1:5173".parse()?),
            ],
        )?);
        let controller = SystemController::new(ResolverPlanStore::dormant(), snapshots, None);
        let response = controller
            .execute(SystemRequest {
                protocol: SYSTEM_PROTOCOL_VERSION.to_owned(),
                request_id: Uuid::new_v4(),
                command: SystemCommand::LoopbackReservations,
            })
            .await;
        let result = response
            .result
            .ok_or_else(|| io::Error::other("the request returned no result"))?;
        assert_eq!(
            result.loopback_reservations,
            Some(vec![
                Ipv4Addr::new(127, 77, 0, 1),
                Ipv4Addr::new(127, 77, 0, 2)
            ])
        );
        // Health answers stay byte-identical to v1: no reservations field.
        let health = controller.execute(health()).await;
        assert_eq!(
            health
                .result
                .and_then(|result| result.loopback_reservations),
            None
        );
        Ok(())
    }

    #[tokio::test]
    async fn descriptors_are_accepted_only_with_a_matching_hand_off() -> Result<(), Box<dyn Error>>
    {
        let controller =
            SystemController::new(ResolverPlanStore::dormant(), SnapshotStore::empty(), None);
        let (read, _write) = nix::unistd::pipe()?;
        let stray = controller.execute_with(health(), vec![read]).await;
        assert_eq!(
            stray.error.map(|error| error.code),
            Some("E_SYSTEM_DESCRIPTORS".to_owned())
        );
        let listener = remap_protocol::ListenerAddress {
            address: Ipv4Addr::new(127, 77, 0, 1),
            port: std::num::NonZeroU16::new(22).ok_or_else(|| io::Error::other("zero port"))?,
        };
        let missing = controller
            .execute_with(
                SystemRequest {
                    protocol: SYSTEM_PROTOCOL_VERSION.to_owned(),
                    request_id: Uuid::new_v4(),
                    command: SystemCommand::AdoptPeerMachineListeners {
                        listeners: vec![listener],
                    },
                },
                Vec::new(),
            )
            .await;
        assert_eq!(
            missing.error.map(|error| error.code),
            Some("E_SYSTEM_DESCRIPTORS".to_owned())
        );
        Ok(())
    }

    fn publish(activation_id: Uuid, generation: u64) -> SystemRequest {
        SystemRequest {
            protocol: SYSTEM_PROTOCOL_VERSION.to_owned(),
            request_id: Uuid::new_v4(),
            command: SystemCommand::PublishResolverPlan {
                activation_id,
                generation,
                upstreams: vec![endpoint(1)],
            },
        }
    }

    fn health() -> SystemRequest {
        SystemRequest {
            protocol: SYSTEM_PROTOCOL_VERSION.to_owned(),
            request_id: Uuid::new_v4(),
            command: SystemCommand::ResolverHealth,
        }
    }
}
