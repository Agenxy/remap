use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use remap_core::{HostHeaderPolicy, Mapping, MappingTarget, NamePattern, RegistrySnapshot};
use remap_network::RuntimeIdentity;
use remap_protocol::{
    CONTROL_PROTOCOL_VERSION, Command, CommandResult, ControlRequest, ControlResponse, Diagnostic,
    HealthChallengeResult, HostPolicy, MAX_MAPPING_COUNT, MAX_MAPPING_PAGE_SIZE,
    MAX_REVISION_WAIT_MS, MappingView, RevisionNotice, Surface,
};
use remap_registry::Registry;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::{Duration, timeout};

const ENGINE_QUEUE_CAPACITY: usize = 256;
const SNAPSHOT_RETRY_LIMIT: usize = 4;

enum Job {
    Request {
        request: ControlRequest,
        response: oneshot::Sender<ControlResponse>,
    },
    Prune {
        response: oneshot::Sender<Result<(), Diagnostic>>,
    },
}

/// Bounded handle to the daemon's one registry-owning writer thread.
#[derive(Debug, Clone)]
pub struct Engine {
    state: Arc<EngineState>,
    revision: watch::Receiver<u64>,
    identity: RuntimeIdentity,
}

#[derive(Debug)]
struct EngineState {
    sender: Mutex<Option<mpsc::Sender<Job>>>,
    writer: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl Engine {
    /// Starts one registry-owning thread after validating the registry.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the registry cannot open or the operating
    /// system cannot start the dedicated writer thread.
    pub fn spawn(database: impl AsRef<Path>) -> Result<Self, Diagnostic> {
        let identity = RuntimeIdentity::generate(
            uuid::Uuid::new_v4().to_string(),
            env!("CARGO_PKG_VERSION").to_owned(),
        )
        .map_err(runtime_identity_error)?;
        let registry = Registry::open(database)?;
        let initial_revision = registry.revision();
        let (sender, receiver) = mpsc::channel(ENGINE_QUEUE_CAPACITY);
        let (revision_sender, revision) = watch::channel(initial_revision);
        let writer = std::thread::Builder::new()
            .name("remap-registry-writer".to_owned())
            .spawn(move || writer_loop(registry, receiver, &revision_sender))
            .map_err(|_| {
                Diagnostic::new(
                    "E_DAEMON_THREAD",
                    "the registry writer thread could not start",
                    Some("check system resource limits, then retry remapd".to_owned()),
                    true,
                )
            })?;
        Ok(Self {
            state: Arc::new(EngineState {
                sender: Mutex::new(Some(sender)),
                writer: Mutex::new(Some(writer)),
            }),
            revision,
            identity,
        })
    }

    /// Executes one request through the single writer.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the bounded queue is closed or the writer
    /// exits before answering.
    pub async fn execute(&self, request: ControlRequest) -> Result<ControlResponse, Diagnostic> {
        if let Err(error) = validate_request(&request) {
            return Ok(ControlResponse::failure(request.request_id, error));
        }
        if let Command::HealthChallenge { nonce } = &request.command {
            return Ok(self.health_challenge(request.request_id.clone(), nonce));
        }
        if let Command::WaitForRevision { after, timeout_ms } = &request.command {
            return self
                .wait_for_revision(request.request_id.clone(), *after, *timeout_ms)
                .await;
        }
        let (response_sender, response_receiver) = oneshot::channel();
        self.sender()?
            .send(Job::Request {
                request,
                response: response_sender,
            })
            .await
            .map_err(|_| writer_unavailable())?;
        response_receiver.await.map_err(|_| writer_unavailable())
    }

    /// Runs retention maintenance on the registry writer.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the writer is unavailable or pruning fails.
    pub async fn prune(&self) -> Result<(), Diagnostic> {
        let (response_sender, response_receiver) = oneshot::channel();
        self.sender()?
            .send(Job::Prune {
                response: response_sender,
            })
            .await
            .map_err(|_| writer_unavailable())?;
        response_receiver.await.map_err(|_| writer_unavailable())?
    }

    /// Reads and validates one complete immutable registry snapshot.
    ///
    /// A concurrent mutation restarts pagination so readers never publish pages
    /// from different revisions.
    ///
    /// # Errors
    ///
    /// Returns a stable diagnostic when the writer is unavailable, stored data
    /// fails validation, or the registry changes during every bounded attempt.
    pub async fn snapshot(&self) -> Result<RegistrySnapshot, Diagnostic> {
        for _attempt in 0..SNAPSHOT_RETRY_LIMIT {
            match self.snapshot_once().await {
                Ok(snapshot) => return Ok(snapshot),
                Err(error) if error.code == "E_SNAPSHOT_CHANGED" => {}
                Err(error) => return Err(error),
            }
        }
        Err(Diagnostic::new(
            "E_SNAPSHOT_BUSY",
            "the registry changed throughout the bounded snapshot attempt",
            Some(
                "keep the last complete snapshot and retry after the next revision notice"
                    .to_owned(),
            ),
            true,
        ))
    }

    /// Subscribes to coalesced monotonic authoritative revision changes.
    #[must_use]
    pub fn subscribe_revision(&self) -> watch::Receiver<u64> {
        self.revision.clone()
    }

    /// Returns the shared identity for this daemon's DNS and HTTP runtimes.
    #[must_use]
    pub(crate) fn runtime_identity(&self) -> RuntimeIdentity {
        self.identity.clone()
    }

    /// Closes writer intake, drains every accepted job, and joins the writer.
    ///
    /// # Errors
    ///
    /// Returns a stable diagnostic if the writer panics or the join task fails.
    pub async fn shutdown(&self) -> Result<(), Diagnostic> {
        self.lock_sender().take();
        let writer = self.lock_writer().take();
        let Some(writer) = writer else {
            return Ok(());
        };
        tokio::task::spawn_blocking(move || writer.join())
            .await
            .map_err(|_| writer_shutdown_error())?
            .map_err(|_panic| writer_shutdown_error())
    }

    fn sender(&self) -> Result<mpsc::Sender<Job>, Diagnostic> {
        self.lock_sender().clone().ok_or_else(writer_unavailable)
    }

    fn lock_sender(&self) -> MutexGuard<'_, Option<mpsc::Sender<Job>>> {
        self.state
            .sender
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn lock_writer(&self) -> MutexGuard<'_, Option<std::thread::JoinHandle<()>>> {
        self.state
            .writer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    async fn snapshot_once(&self) -> Result<RegistrySnapshot, Diagnostic> {
        let mut revision = None;
        let mut cursor = None;
        let mut mappings = Vec::new();
        loop {
            let result = self
                .internal_command(Command::List {
                    after: cursor.clone(),
                    limit: MAX_MAPPING_PAGE_SIZE,
                    include_disabled: true,
                })
                .await?;
            let CommandResult::List(page) = result else {
                return Err(snapshot_error(
                    "the registry returned a non-list snapshot page",
                ));
            };
            if revision.is_some_and(|expected| expected != page.revision) {
                return Err(Diagnostic::new(
                    "E_SNAPSHOT_CHANGED",
                    "the registry changed while an immutable snapshot was being read",
                    None,
                    true,
                ));
            }
            revision = Some(page.revision);
            for view in &page.mappings {
                mappings.push(mapping_from_view(view)?);
                if mappings.len() > MAX_MAPPING_COUNT {
                    return Err(snapshot_error(
                        "a runtime snapshot exceeds the mapping limit",
                    ));
                }
            }
            let Some(next) = page.next_cursor else {
                return RegistrySnapshot::new(page.revision, mappings)
                    .map_err(|error| snapshot_error(&error.to_string()));
            };
            cursor = Some(next);
        }
    }

    async fn internal_command(&self, command: Command) -> Result<CommandResult, Diagnostic> {
        let response = self
            .execute(ControlRequest {
                protocol: CONTROL_PROTOCOL_VERSION.to_owned(),
                request_id: "internal-runtime-snapshot".to_owned(),
                surface: Surface::Probe,
                client_version: env!("CARGO_PKG_VERSION").to_owned(),
                command,
            })
            .await?;
        match (response.result, response.error) {
            (Some(result), None) => Ok(result),
            (None, Some(error)) => Err(error),
            _ => Err(snapshot_error(
                "the registry returned an invalid control envelope",
            )),
        }
    }

    async fn wait_for_revision(
        &self,
        request_id: String,
        after: u64,
        timeout_ms: u32,
    ) -> Result<ControlResponse, Diagnostic> {
        if !(1..=MAX_REVISION_WAIT_MS).contains(&timeout_ms) {
            return Ok(ControlResponse::failure(
                request_id,
                Diagnostic::new(
                    "E_REVISION_WAIT",
                    format!(
                        "revision wait must be between 1 and {MAX_REVISION_WAIT_MS} milliseconds"
                    ),
                    Some("use a bounded wait and retry after it returns".to_owned()),
                    false,
                ),
            ));
        }
        let mut revisions = self.revision.clone();
        let observed = *revisions.borrow_and_update();
        let revision = if observed > after {
            observed
        } else {
            match timeout(
                Duration::from_millis(u64::from(timeout_ms)),
                revisions.changed(),
            )
            .await
            {
                Ok(Ok(())) => *revisions.borrow_and_update(),
                Ok(Err(_closed)) => return Err(writer_unavailable()),
                Err(_elapsed) => *revisions.borrow(),
            }
        };
        Ok(ControlResponse::success(
            request_id,
            CommandResult::Revision(RevisionNotice {
                revision,
                changed: revision > after,
            }),
        ))
    }

    fn health_challenge(&self, request_id: String, nonce: &str) -> ControlResponse {
        let Some(proofs) = self.identity.proofs(nonce) else {
            return ControlResponse::failure(
                request_id,
                Diagnostic::new(
                    "E_HEALTH_CHALLENGE",
                    "the runtime health challenge nonce is malformed",
                    Some("use exactly 32 lowercase hexadecimal characters".to_owned()),
                    false,
                ),
            );
        };
        ControlResponse::success(
            request_id,
            CommandResult::HealthChallenge(HealthChallengeResult {
                instance_id: self.identity.instance_id().to_owned(),
                daemon_version: self.identity.version().to_owned(),
                dns_proof: proofs.dns().to_owned(),
                http_proof: proofs.http().to_owned(),
            }),
        )
    }
}

fn mapping_from_view(view: &MappingView) -> Result<Mapping, Diagnostic> {
    let pattern =
        NamePattern::parse(&view.pattern).map_err(|error| snapshot_error(&error.to_string()))?;
    let policy = match view.host_policy {
        HostPolicy::PreserveClient => HostHeaderPolicy::PreserveClient,
        HostPolicy::UseUpstream => HostHeaderPolicy::UseUpstream,
    };
    let target = MappingTarget::parse_with_http_policy(&view.target, policy)
        .map_err(|error| snapshot_error(&error.to_string()))?;
    Ok(Mapping::new(pattern, target).with_enabled(view.enabled))
}

fn snapshot_error(detail: &str) -> Diagnostic {
    Diagnostic::new(
        "E_RUNTIME_SNAPSHOT",
        "the network runtime could not validate an authoritative snapshot",
        Some("run 'remap doctor'; repair or restore the registry before enabling DNS".to_owned()),
        false,
    )
    .with_context("detail", detail.to_owned())
}

fn writer_loop(
    mut registry: Registry,
    mut receiver: mpsc::Receiver<Job>,
    revision_sender: &watch::Sender<u64>,
) {
    while let Some(job) = receiver.blocking_recv() {
        match job {
            Job::Request { request, response } => {
                let before = registry.revision();
                let control_response = dispatch(&mut registry, request);
                if registry.revision() != before {
                    revision_sender.send_replace(registry.revision());
                }
                let _result = response.send(control_response);
            }
            Job::Prune { response } => {
                let _result = response.send(registry.prune_expired());
            }
        }
    }
}

fn dispatch(registry: &mut Registry, request: ControlRequest) -> ControlResponse {
    let request_id = request.request_id.clone();
    match registry.execute(request.command, request.surface) {
        Ok(result) => ControlResponse::success(request_id, result),
        Err(error) => ControlResponse::failure(request_id, error),
    }
}

fn validate_request(request: &ControlRequest) -> Result<(), Diagnostic> {
    if request.protocol != CONTROL_PROTOCOL_VERSION {
        return Err(Diagnostic::new(
            "E_CONTROL_VERSION",
            format!("control protocol '{}' is unsupported", request.protocol),
            Some(format!("use {CONTROL_PROTOCOL_VERSION}")),
            false,
        ));
    }
    if request.request_id.len() > 128 || request.client_version.len() > 64 {
        return Err(Diagnostic::new(
            "E_CONTROL_METADATA",
            "control request metadata exceeds its size limit",
            Some("use a UUID request id and a normal release version".to_owned()),
            false,
        ));
    }
    Ok(())
}

fn writer_unavailable() -> Diagnostic {
    Diagnostic::new(
        "E_DAEMON_WRITER_UNAVAILABLE",
        "the authoritative registry writer is unavailable",
        Some("restart remapd and run remap doctor before retrying mutations".to_owned()),
        true,
    )
}

fn writer_shutdown_error() -> Diagnostic {
    Diagnostic::new(
        "E_DAEMON_WRITER_SHUTDOWN",
        "the authoritative registry writer did not stop cleanly",
        Some("run remap doctor before restarting remapd".to_owned()),
        false,
    )
}

fn runtime_identity_error(_error: remap_network::NetworkError) -> Diagnostic {
    Diagnostic::new(
        "E_RUNTIME_IDENTITY",
        "the daemon could not create its private runtime identity",
        Some("verify operating-system random generation, then restart Remap".to_owned()),
        false,
    )
}

#[cfg(test)]
mod tests {
    use remap_protocol::{
        CONTROL_PROTOCOL_VERSION, Change, Command, CommandResult, ControlRequest, HostPolicy,
        Surface,
    };
    use remap_registry::Registry;

    use super::{Engine, Job};

    #[tokio::test]
    async fn snapshot_reads_every_page_at_one_revision() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let engine = Engine::spawn(directory.path().join("registry.sqlite3"))?;
        let operation_ids = [
            "e6077e18-863b-49cb-ac87-c62682f2e92f",
            "1f530894-e58c-4ce9-a460-2c4419b949bc",
            "bd0e8054-6356-4f6b-9150-57a851e55c08",
        ];
        for (batch, operation_id) in (0..129_usize)
            .collect::<Vec<_>>()
            .chunks(remap_protocol::MAX_ATOMIC_CHANGE_COUNT)
            .zip(operation_ids)
        {
            let revision = *engine.subscribe_revision().borrow();
            let changes = batch
                .iter()
                .map(|index| Change::Set {
                    pattern: format!("n{index:03}.test"),
                    target: format!("10.0.0.{}", index % 254 + 1),
                    host_policy: HostPolicy::PreserveClient,
                    enabled: Some(*index != 128),
                })
                .collect();
            let response = engine
                .execute(ControlRequest {
                    protocol: CONTROL_PROTOCOL_VERSION.to_owned(),
                    request_id: format!("seed-{revision}"),
                    surface: Surface::Probe,
                    client_version: env!("CARGO_PKG_VERSION").to_owned(),
                    command: Command::Apply {
                        expected_revision: revision,
                        operation_id: operation_id.to_owned(),
                        changes,
                    },
                })
                .await?;
            assert!(response.error.is_none());
        }

        let snapshot = engine.snapshot().await?;
        assert_eq!(snapshot.revision(), 3);
        assert_eq!(snapshot.mappings().len(), 129);
        assert!(
            !snapshot
                .mappings()
                .iter()
                .all(remap_core::Mapping::is_enabled)
        );
        engine.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn shutdown_drains_an_accepted_job_after_its_caller_leaves()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("registry.sqlite3");
        let engine = Engine::spawn(&database)?;
        let sender = engine.sender()?;
        let (response, abandoned) = tokio::sync::oneshot::channel();
        sender
            .send(Job::Request {
                request: ControlRequest {
                    protocol: CONTROL_PROTOCOL_VERSION.to_owned(),
                    request_id: "accepted-before-shutdown".to_owned(),
                    surface: Surface::Cli,
                    client_version: env!("CARGO_PKG_VERSION").to_owned(),
                    command: Command::Apply {
                        expected_revision: 0,
                        operation_id: "6f6df502-764b-4333-9145-84a324ac3f6b".to_owned(),
                        changes: vec![Change::Set {
                            pattern: "atlas".to_owned(),
                            target: "10.0.0.8".to_owned(),
                            host_policy: HostPolicy::PreserveClient,
                            enabled: None,
                        }],
                    },
                },
                response,
            })
            .await?;
        drop(abandoned);
        drop(sender);
        engine.shutdown().await?;

        let mut registry = Registry::open(&database)?;
        let status = registry.execute(Command::Status, Surface::Probe)?;
        let CommandResult::Status(status) = status else {
            return Err("status returned the wrong result kind".into());
        };
        assert_eq!(status.revision, 1);
        assert_eq!(status.mapping_count, 1);
        Ok(())
    }

    #[tokio::test]
    async fn daemon_instances_never_reuse_runtime_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let first = Engine::spawn(directory.path().join("first.sqlite3"))?;
        let second = Engine::spawn(directory.path().join("second.sqlite3"))?;
        let nonce = "00112233445566778899aabbccddeeff";
        let first_response = first.execute(health_request("first", nonce)).await?;
        let second_response = second.execute(health_request("second", nonce)).await?;
        let Some(CommandResult::HealthChallenge(first_health)) = first_response.result else {
            return Err("first health challenge failed".into());
        };
        let Some(CommandResult::HealthChallenge(second_health)) = second_response.result else {
            return Err("second health challenge failed".into());
        };
        assert_ne!(first_health.instance_id, second_health.instance_id);
        assert_ne!(first_health.dns_proof, second_health.dns_proof);
        assert_ne!(first_health.http_proof, second_health.http_proof);
        first.shutdown().await?;
        second.shutdown().await?;
        Ok(())
    }

    fn health_request(request_id: &str, nonce: &str) -> ControlRequest {
        ControlRequest {
            protocol: CONTROL_PROTOCOL_VERSION.to_owned(),
            request_id: request_id.to_owned(),
            surface: Surface::Probe,
            client_version: env!("CARGO_PKG_VERSION").to_owned(),
            command: Command::HealthChallenge {
                nonce: nonce.to_owned(),
            },
        }
    }
}
