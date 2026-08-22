use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use crate::channel::SystemChannel;
use crate::resolver_events::{ResolverEvent, connect_monitor, next_event};
use crate::resolver_generation::timestamp_after;
use crate::resolver_stability::{
    ObservationStability, SteadyObservation, deadline_reached as steady_deadline_reached,
    evaluate_steady_observation, seeded as seeded_steady_stability,
};
use crate::resolver_upstreams::upstreams;
use crate::resolver_worker::{
    BoundedWorker, EffectCall, SettledCall, call_effect_with_shutdown, call_with_shutdown_settled,
    connect_when_ready, load as worker_load, platform_error,
    rebase_comparison as worker_rebase_comparison, shutdown_receiver,
    startup_observation as worker_startup_observation, startup_stopped,
};
use nix::unistd::Uid;
use remap_linux::{
    ActivationPhase, ActivationRecord, LinkIndex, LinkState, NetworkManagerStartupObservation,
    NetworkManagerTransaction, RecordMetadata, ResolverStartupObservation, ResolverTransaction,
    RootRecordStore, SystemdResolved,
};
use remap_protocol::{SystemCommand, SystemResult};
use tokio::time::MissedTickBehavior;
use uuid::Uuid;

const RECONCILE_INTERVAL: Duration = Duration::from_secs(1);
const EVENT_MONITOR_RECONNECT_INTERVAL: Duration = Duration::from_secs(30);
const STARTUP_TIMEOUT: Duration = Duration::from_secs(15);
const STARTUP_RETRY: Duration = Duration::from_millis(50);
const STABILITY_INTERVAL: Duration = Duration::from_millis(500);
const STEADY_STABILITY_INTERVAL: Duration = Duration::from_millis(25);
const STEADY_STABILITY_TIMEOUT: Duration = Duration::from_millis(150);
const NATIVE_EFFECT_CALL_TIMEOUT: Duration = Duration::from_secs(2);
pub(crate) const NATIVE_MANAGER_STABILITY_TIMEOUT: &str =
    "the native resolver manager did not reach stable configured state";
#[derive(Debug, Clone)]
pub(crate) struct SupervisorConfig {
    pub(crate) link: LinkIndex,
    pub(crate) interface_name: Option<String>,
    pub(crate) manager: Option<remap_linux::ResolverLinkManager>,
    pub(crate) owner_uid: u32,
    pub(crate) daemon_uid: u32,
    pub(crate) record_directory: PathBuf,
    pub(crate) system_socket: PathBuf,
}

pub(crate) fn activation_manager(
    manager: &remap_linux::ResolverManagerRecord,
) -> Option<remap_linux::ResolverLinkManager> {
    match manager {
        remap_linux::ResolverManagerRecord::Systemd => None,
        remap_linux::ResolverManagerRecord::SystemdResolved(_) => {
            Some(remap_linux::ResolverLinkManager::SystemdResolved)
        }
        remap_linux::ResolverManagerRecord::SystemdNetworkd(_) => {
            Some(remap_linux::ResolverLinkManager::SystemdNetworkd)
        }
        remap_linux::ResolverManagerRecord::NetworkManager(_) => {
            Some(remap_linux::ResolverLinkManager::NetworkManager)
        }
    }
}

pub(crate) async fn serve(config: SupervisorConfig) -> io::Result<()> {
    require_root()?;
    let mut shutdown = shutdown_receiver()?;
    let activation_creation_allowed = crate::runtime_authority::activation_creation_allowed()?;
    let startup_worker = BoundedWorker::new(config.clone())?;
    let initialized =
        match initialize_with_worker(&startup_worker, activation_creation_allowed, &mut shutdown)
            .await
        {
            Ok(SupervisorStartup::Running(initialized)) => initialized,
            Ok(SupervisorStartup::Stopped(initialized)) => {
                drop(initialized);
                return Ok(());
            }
            Err(error) => return Err(error),
        };
    drop(startup_worker);
    let channel = SystemChannel::new(config.system_socket.clone(), config.daemon_uid);
    let mut record = initialized.record;
    let mut resolver_upstreams = initialized.resolver_upstreams;
    let transaction = BoundedWorker::new(initialized.transaction)?;
    let mut events = connect_monitor(config.link, config.manager).await;
    let mut ticker = tokio::time::interval(RECONCILE_INTERVAL);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut event_reconnect = tokio::time::interval_at(
        tokio::time::Instant::now() + EVENT_MONITOR_RECONNECT_INTERVAL,
        EVENT_MONITOR_RECONNECT_INTERVAL,
    );
    event_reconnect.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        let reconcile = tokio::select! {
            _instant = ticker.tick() => true,
            event = next_event(&mut events) => {
                match event {
                    Ok(ResolverEvent::Changed) => true,
                    Ok(ResolverEvent::StreamUnavailable) => {
                        eprintln!("the native resolver event stream is unavailable; periodic reconciliation remains active");
                        events = None;
                        false
                    }
                    Err(_error) => {
                        eprintln!("the native resolver event monitor stopped; periodic reconciliation remains active");
                        events = None;
                        false
                    }
                }
            }
            _instant = event_reconnect.tick() => {
                if events.is_none() {
                    events = connect_monitor(config.link, config.manager).await;
                }
                false
            }
            result = shutdown.changed() => {
                result.map_err(|_error| io::Error::other("the supervisor shutdown monitor stopped"))?;
                return Ok(());
            }
        };
        if !reconcile {
            continue;
        }
        match reconcile_active(
            &transaction,
            &channel,
            &mut record,
            &mut resolver_upstreams,
            &mut shutdown,
        )
        .await
        {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => return Ok(()),
            Err(error) => return Err(error),
        }
    }
}

async fn initialize_with_worker(
    worker: &BoundedWorker<SupervisorConfig>,
    activation_creation_allowed: bool,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> io::Result<SupervisorStartup> {
    let worker_shutdown = shutdown.clone();
    match call_with_shutdown_settled(
        worker.call_settled(move |config| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            runtime.block_on(initialize_supervisor(
                config,
                activation_creation_allowed,
                worker_shutdown,
            ))
        }),
        shutdown,
    )
    .await?
    {
        SettledCall::Completed(result) => result.map(SupervisorStartup::Running),
        SettledCall::Stopped(Ok(initialized)) => Ok(SupervisorStartup::Stopped(Some(initialized))),
        SettledCall::Stopped(Err(error)) if error.kind() == io::ErrorKind::Interrupted => {
            Ok(SupervisorStartup::Stopped(None))
        }
        SettledCall::Stopped(Err(error)) => Err(error),
    }
}

async fn initialize_supervisor(
    config: &SupervisorConfig,
    activation_creation_allowed: bool,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> io::Result<InitializedSupervisor> {
    let channel = SystemChannel::new(config.system_socket.clone(), config.daemon_uid);
    tokio::select! {
        biased;
        result = shutdown.changed() => {
            result.map_err(|_error| io::Error::other("the supervisor shutdown monitor stopped"))?;
            return Err(startup_stopped());
        }
        result = wait_for_channel(&channel) => result?,
    }
    let session = activate_or_recover(config, activation_creation_allowed, &mut shutdown).await?;
    let resolver_upstreams = match upstreams(&session.record) {
        Ok(upstreams) => upstreams,
        Err(error) => {
            return startup_failure(session.transaction, session.provenance, true, error).await;
        }
    };
    if let Err(failure) =
        publish_if_needed(&channel, &session.record, resolver_upstreams.clone()).await
    {
        return startup_failure(
            session.transaction,
            session.provenance,
            failure.rollback_safe,
            failure.error,
        )
        .await;
    }
    Ok(InitializedSupervisor {
        record: session.record,
        transaction: session.transaction,
        resolver_upstreams,
    })
}

async fn reconcile_active(
    transaction: &BoundedWorker<NativeResolverTransaction>,
    channel: &SystemChannel,
    record: &mut ActivationRecord,
    resolver_upstreams: &mut Vec<SocketAddr>,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> io::Result<()> {
    let mut stopped_after_rebase = false;
    if let Some(observed) =
        worker_startup_observation(transaction, record.owned().link(), shutdown).await?
    {
        let requires_rebase =
            worker_rebase_comparison(transaction, record, &observed, shutdown).await?;
        if requires_rebase == Some(true)
            && let Some(observed) =
                wait_for_steady_rebase_observation(transaction, record, observed, shutdown).await?
        {
            let rebased = worker_rebase_after_observation(transaction, &observed, shutdown).await?;
            stopped_after_rebase = matches!(rebased, SettledCall::Stopped(_));
            *record = match rebased {
                SettledCall::Completed(record) | SettledCall::Stopped(record) => record,
            };
            *resolver_upstreams = upstreams(record)?;
        }
    }
    if let Err(failure) = publish_if_needed(channel, record, resolver_upstreams.clone()).await {
        return Err(failure.error);
    }
    if stopped_after_rebase {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "resolver supervision was stopped after rebase settlement",
        ));
    }
    let Some(loaded) = worker_load(transaction, shutdown).await? else {
        return Ok(());
    };
    if loaded.as_ref() != Some(record) {
        return Err(conflict(
            "resolver activation record changed while supervised",
        ));
    }
    Ok(())
}

async fn wait_for_steady_rebase_observation(
    transaction: &BoundedWorker<NativeResolverTransaction>,
    record: &ActivationRecord,
    initial: NativeStartupObservation,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> io::Result<Option<NativeStartupObservation>> {
    let deadline = tokio::time::Instant::now() + STEADY_STABILITY_TIMEOUT;
    let mut stability = seeded_steady_stability(initial);
    loop {
        if steady_deadline_reached(tokio::time::Instant::now(), deadline) {
            return Ok(None);
        }
        tokio::time::sleep(STEADY_STABILITY_INTERVAL).await;
        let observed =
            worker_startup_observation(transaction, record.owned().link(), shutdown).await?;
        let requires_rebase = match observed.as_ref() {
            Some(observed) => {
                worker_rebase_comparison(transaction, record, observed, shutdown).await?
            }
            None => None,
        };
        if steady_deadline_reached(tokio::time::Instant::now(), deadline) {
            return Ok(None);
        }
        let Some(requires_rebase) = requires_rebase else {
            stability.reset();
            continue;
        };
        match evaluate_steady_observation(&mut stability, observed, requires_rebase) {
            SteadyObservation::Cancelled => return Ok(None),
            SteadyObservation::Pending => {}
            SteadyObservation::Stable(observed) => return Ok(Some(observed)),
        }
    }
}

async fn startup_failure<T>(
    mut transaction: NativeResolverTransaction,
    provenance: ActivationProvenance,
    rollback_safe: bool,
    error: io::Error,
) -> io::Result<T> {
    if provenance == ActivationProvenance::New && rollback_safe {
        let record = transaction
            .load()
            .map_err(platform_error)?
            .ok_or_else(|| conflict("new resolver activation disappeared before rollback"))?;
        deactivate_transaction(&mut transaction, record.owned().link()).await?;
    }
    Err(error)
}

async fn wait_for_channel(channel: &SystemChannel) -> io::Result<()> {
    let deadline = tokio::time::Instant::now() + STARTUP_TIMEOUT;
    loop {
        if channel
            .exchange(SystemCommand::ResolverHealth)
            .await
            .is_ok()
        {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the private daemon resolver channel did not become ready",
            ));
        }
        tokio::time::sleep(STARTUP_RETRY).await;
    }
}

pub(crate) async fn deactivate(config: &SupervisorConfig) -> io::Result<()> {
    require_root()?;
    let mut transaction = NativeResolverTransaction::connect(config)?;
    deactivate_transaction(&mut transaction, config.link).await
}

pub(crate) async fn deactivate_with_store(
    config: &SupervisorConfig,
    store: RootRecordStore,
) -> io::Result<()> {
    require_root()?;
    let mut transaction = NativeResolverTransaction::connect_with_store(config, store)?;
    deactivate_transaction(&mut transaction, config.link).await
}

pub(crate) async fn converge_owned_with_store(
    config: &SupervisorConfig,
    store: RootRecordStore,
) -> io::Result<RootRecordStore> {
    require_root()?;
    let mut transaction = NativeResolverTransaction::connect_with_store(config, store)?;
    let Some((record, observation)) = stabilize_active(&mut transaction, config.link).await? else {
        return Err(conflict(
            "the update rollback has no resolver activation to converge",
        ));
    };
    if record.phase() != ActivationPhase::Active
        || record.owned().link() != config.link
        || transaction
            .observation_requires_rebase(&record, &observation)
            .map_err(platform_error)?
    {
        return Err(conflict(
            "the update rollback could not converge exact resolver ownership",
        ));
    }
    Ok(transaction.into_store())
}

async fn deactivate_transaction(
    transaction: &mut NativeResolverTransaction,
    link: LinkIndex,
) -> io::Result<()> {
    let Some((_record, observation)) = stabilize_active(transaction, link).await? else {
        return Ok(());
    };
    transaction
        .deactivate_observed(&observation)
        .map_err(platform_error)?;
    Ok(())
}

async fn stabilize_active(
    transaction: &mut NativeResolverTransaction,
    link: LinkIndex,
) -> io::Result<Option<(ActivationRecord, NativeStartupObservation)>> {
    let deadline = tokio::time::Instant::now() + STARTUP_TIMEOUT;
    loop {
        let Some(record) = transaction.load().map_err(platform_error)? else {
            return Ok(None);
        };
        if record.phase() != ActivationPhase::Active {
            match transaction.recover().map_err(platform_error)? {
                Some(_record) => continue,
                None => return Ok(None),
            }
        }
        let observation = wait_for_stable_observation_until(transaction, link, deadline).await?;
        if transaction
            .observation_requires_rebase(&record, &observation)
            .map_err(platform_error)?
        {
            rebase_after_observation(transaction, &observation)?;
            continue;
        }
        return Ok(Some((record, observation)));
    }
}

async fn activate_or_recover(
    config: &SupervisorConfig,
    activation_creation_allowed: bool,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> io::Result<ActivationSession> {
    let mut transaction = tokio::select! {
        biased;
        result = shutdown.changed() => {
            result.map_err(|_error| io::Error::other("the supervisor shutdown monitor stopped"))?;
            return Err(startup_stopped());
        }
        result = connect_when_ready(
            config,
            STARTUP_TIMEOUT,
            STARTUP_RETRY,
            NATIVE_MANAGER_STABILITY_TIMEOUT,
        ) => result?,
    };
    let loaded = transaction.load().map_err(platform_error)?;
    let needs_stable_observation = loaded
        .as_ref()
        .is_some_and(|record| record.phase() == ActivationPhase::Active)
        || loaded.is_none() && activation_creation_allowed;
    let stable_observation = if needs_stable_observation {
        Some(tokio::select! {
            biased;
            result = shutdown.changed() => {
                result.map_err(|_error| io::Error::other("the supervisor shutdown monitor stopped"))?;
                return Err(startup_stopped());
            }
            result = wait_for_stable_observation(&mut transaction, config.link) => result?,
        })
    } else {
        None
    };
    require_startup_running(shutdown)?;
    if let (Some(record), Some(observed)) = (loaded.as_ref(), stable_observation.as_ref())
        && record.phase() == ActivationPhase::Active
        && transaction
            .observation_requires_rebase(record, observed)
            .map_err(platform_error)?
    {
        return Ok(ActivationSession {
            record: rebase_after_observation(&mut transaction, observed)?,
            transaction,
            provenance: ActivationProvenance::Recovered,
        });
    }
    let recovered = transaction.recover();
    let (record, provenance) = match recovered {
        Ok(Some(record)) => (record, ActivationProvenance::Recovered),
        Ok(None) if activation_creation_allowed => {
            require_startup_running(shutdown)?;
            let observed = stable_observation.as_ref().ok_or_else(|| {
                conflict("new resolver ownership has no stable native-manager observation")
            })?;
            match transaction.activate_observed(
                metadata(config.owner_uid)?,
                LinkState::remap_loopback(config.link).map_err(platform_error)?,
                observed,
            ) {
                Ok(record) => (record, ActivationProvenance::New),
                Err(error) => return abort_failed_activation(transaction, error),
            }
        }
        Ok(None) => {
            return Err(conflict(
                "the durable lifecycle phase does not authorize new resolver ownership",
            ));
        }
        Err(error) => return abort_failed_activation(transaction, error),
    };
    if record.phase() != ActivationPhase::Active || record.owned().link() != config.link {
        return Err(conflict(
            "resolver activation does not match the configured link",
        ));
    }
    Ok(ActivationSession {
        record,
        transaction,
        provenance,
    })
}

async fn wait_for_stable_observation(
    transaction: &mut NativeResolverTransaction,
    link: LinkIndex,
) -> io::Result<NativeStartupObservation> {
    let deadline = tokio::time::Instant::now() + STARTUP_TIMEOUT;
    wait_for_stable_observation_until(transaction, link, deadline).await
}

async fn wait_for_stable_observation_until(
    transaction: &mut NativeResolverTransaction,
    link: LinkIndex,
    deadline: tokio::time::Instant,
) -> io::Result<NativeStartupObservation> {
    let mut stability = ObservationStability::default();
    loop {
        match transaction.startup_observation(link) {
            Err(error) if error.kind() == remap_linux::LinuxErrorKind::ResolverUnavailable => {
                stability.reset();
            }
            Err(error) => return Err(platform_error(error)),
            Ok(Some(observed)) if stability.observe(observed.clone()) => return Ok(observed),
            Ok(Some(_observed)) => {}
            Ok(None) => stability.reset(),
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                NATIVE_MANAGER_STABILITY_TIMEOUT,
            ));
        }
        tokio::time::sleep(STABILITY_INTERVAL).await;
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ActivationProvenance {
    New,
    Recovered,
}

#[derive(Debug)]
struct ActivationSession {
    record: ActivationRecord,
    transaction: NativeResolverTransaction,
    provenance: ActivationProvenance,
}

#[derive(Debug)]
struct InitializedSupervisor {
    record: ActivationRecord,
    transaction: NativeResolverTransaction,
    resolver_upstreams: Vec<SocketAddr>,
}

#[derive(Debug)]
enum SupervisorStartup {
    Running(InitializedSupervisor),
    Stopped(Option<InitializedSupervisor>),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum NativeStartupObservation {
    Systemd(ResolverStartupObservation),
    NetworkManager(NetworkManagerStartupObservation),
}

fn abort_failed_activation(
    mut transaction: NativeResolverTransaction,
    activation_error: remap_linux::LinuxError,
) -> io::Result<ActivationSession> {
    transaction.abort_activation().map_err(platform_error)?;
    Err(platform_error(activation_error))
}

#[derive(Debug)]
pub(crate) enum NativeResolverTransaction {
    Systemd {
        transaction: ResolverTransaction<SystemdResolved, RootRecordStore>,
        migrate_legacy_manager: bool,
    },
    NetworkManager(NetworkManagerTransaction<RootRecordStore>),
}

impl NativeResolverTransaction {
    pub(crate) fn connect(config: &SupervisorConfig) -> io::Result<Self> {
        let lock_directory = crate::authority::resolver_lock_directory()?;
        let store =
            RootRecordStore::open_with_lock_directory(&config.record_directory, &lock_directory)
                .map_err(platform_error)?;
        Self::connect_with_store(config, store)
    }

    fn connect_with_store(config: &SupervisorConfig, store: RootRecordStore) -> io::Result<Self> {
        if let (Some(manager), Some(interface_name)) =
            (config.manager, config.interface_name.as_deref())
            && !SystemdResolved::expected_manager_ready(config.link, interface_name, manager)
                .map_err(platform_error)?
        {
            return Err(platform_error(remap_linux::LinuxError::new(
                remap_linux::LinuxErrorKind::ResolverUnavailable,
                "the selected native resolver manager is temporarily unavailable",
            )));
        }
        let inspection = SystemdResolved::inspect(config.link).map_err(platform_error)?;
        if config
            .manager
            .is_some_and(|expected| expected != inspection.manager())
            || config
                .interface_name
                .as_deref()
                .is_some_and(|expected| expected != inspection.interface_name())
        {
            return Err(conflict(
                "the selected resolver link changed its approved native identity",
            ));
        }
        match SystemdResolved::connect(config.link) {
            Ok(backend)
                if config
                    .manager
                    .is_none_or(|expected| expected == backend.manager())
                    && config
                        .interface_name
                        .as_deref()
                        .is_none_or(|expected| expected == backend.interface_name()) =>
            {
                Ok(Self::Systemd {
                    transaction: ResolverTransaction::new(backend, store),
                    migrate_legacy_manager: config.manager.is_some()
                        && config.interface_name.is_some(),
                })
            }
            Ok(_backend) => Err(conflict(
                "the selected resolver link changed its approved native manager",
            )),
            Err(error)
                if error.kind() == remap_linux::LinuxErrorKind::UnsupportedResolverManager =>
            {
                if config.manager.is_some_and(|manager| {
                    manager != remap_linux::ResolverLinkManager::NetworkManager
                }) {
                    return Err(conflict(
                        "the selected resolver link changed its approved native manager",
                    ));
                }
                let transaction = match config.interface_name.as_deref() {
                    Some(expected) => {
                        NetworkManagerTransaction::connect_expected(config.link, expected, store)
                    }
                    None => NetworkManagerTransaction::connect(config.link, store),
                }
                .map_err(platform_error)?;
                Ok(Self::NetworkManager(transaction))
            }
            Err(error) => Err(platform_error(error)),
        }
    }

    fn activate_observed(
        &mut self,
        metadata: RecordMetadata,
        owned: LinkState,
        observed: &NativeStartupObservation,
    ) -> remap_linux::LinuxResult<ActivationRecord> {
        match (self, observed) {
            (Self::Systemd { transaction, .. }, NativeStartupObservation::Systemd(observed)) => {
                transaction.activate_observed(metadata, owned, observed)
            }
            (
                Self::NetworkManager(transaction),
                NativeStartupObservation::NetworkManager(observed),
            ) => transaction.activate_observed(metadata, owned, observed),
            (Self::Systemd { .. }, NativeStartupObservation::NetworkManager(_))
            | (Self::NetworkManager(_), NativeStartupObservation::Systemd(_)) => {
                Err(remap_linux::LinuxError::new(
                    remap_linux::LinuxErrorKind::OwnershipConflict,
                    "the native resolver manager changed after stabilization",
                ))
            }
        }
    }

    fn recover(&mut self) -> remap_linux::LinuxResult<Option<ActivationRecord>> {
        match self {
            Self::Systemd { transaction, .. } => transaction.recover(),
            Self::NetworkManager(transaction) => transaction.recover(),
        }
    }

    fn abort_activation(&mut self) -> remap_linux::LinuxResult<()> {
        match self {
            Self::Systemd { transaction, .. } => transaction.abort_activation(),
            Self::NetworkManager(transaction) => transaction.abort_activation(),
        }
    }

    fn deactivate_observed(
        &mut self,
        observed: &NativeStartupObservation,
    ) -> remap_linux::LinuxResult<()> {
        match (self, observed) {
            (
                Self::Systemd {
                    transaction,
                    migrate_legacy_manager,
                },
                NativeStartupObservation::Systemd(observed),
            ) => {
                if *migrate_legacy_manager {
                    transaction.deactivate_observed(observed)
                } else {
                    transaction.deactivate_observed_preserving_legacy_manager(observed)
                }
            }
            (
                Self::NetworkManager(transaction),
                NativeStartupObservation::NetworkManager(observed),
            ) => transaction.deactivate_observed(observed),
            (Self::Systemd { .. }, NativeStartupObservation::NetworkManager(_))
            | (Self::NetworkManager(_), NativeStartupObservation::Systemd(_)) => {
                Err(remap_linux::LinuxError::new(
                    remap_linux::LinuxErrorKind::OwnershipConflict,
                    "the native resolver manager changed after stabilization",
                ))
            }
        }
    }

    fn rebase_observed(
        &mut self,
        generation: u64,
        created: u64,
        observed: &NativeStartupObservation,
    ) -> remap_linux::LinuxResult<ActivationRecord> {
        match (self, observed) {
            (
                Self::Systemd {
                    transaction,
                    migrate_legacy_manager,
                },
                NativeStartupObservation::Systemd(observed),
            ) => {
                if *migrate_legacy_manager {
                    transaction.rebase_observed(generation, created, observed)
                } else {
                    transaction
                        .rebase_observed_preserving_legacy_manager(generation, created, observed)
                }
            }
            (
                Self::NetworkManager(transaction),
                NativeStartupObservation::NetworkManager(observed),
            ) => transaction.rebase_observed(generation, created, observed),
            (Self::Systemd { .. }, NativeStartupObservation::NetworkManager(_))
            | (Self::NetworkManager(_), NativeStartupObservation::Systemd(_)) => {
                Err(remap_linux::LinuxError::new(
                    remap_linux::LinuxErrorKind::OwnershipConflict,
                    "the native resolver manager changed after stabilization",
                ))
            }
        }
    }

    pub(crate) fn startup_observation(
        &mut self,
        link: LinkIndex,
    ) -> remap_linux::LinuxResult<Option<NativeStartupObservation>> {
        match self {
            Self::Systemd { transaction, .. } => transaction
                .startup_observation(link)
                .map(|state| state.map(NativeStartupObservation::Systemd)),
            Self::NetworkManager(transaction) => transaction
                .startup_observation()
                .map(|state| state.map(NativeStartupObservation::NetworkManager)),
        }
    }

    pub(crate) fn observation_requires_rebase(
        &mut self,
        record: &ActivationRecord,
        observed: &NativeStartupObservation,
    ) -> remap_linux::LinuxResult<bool> {
        match (self, observed) {
            (
                Self::Systemd {
                    transaction,
                    migrate_legacy_manager,
                },
                NativeStartupObservation::Systemd(observed),
            ) => {
                if *migrate_legacy_manager {
                    transaction.observation_requires_rebase(record, observed)
                } else {
                    transaction
                        .observation_requires_rebase_preserving_legacy_manager(record, observed)
                }
            }
            (
                Self::NetworkManager(transaction),
                NativeStartupObservation::NetworkManager(observed),
            ) => transaction.observation_requires_rebase(record, observed),
            (Self::Systemd { .. }, NativeStartupObservation::NetworkManager(_))
            | (Self::NetworkManager(_), NativeStartupObservation::Systemd(_)) => {
                Err(remap_linux::LinuxError::new(
                    remap_linux::LinuxErrorKind::OwnershipConflict,
                    "the native resolver manager changed after stabilization",
                ))
            }
        }
    }

    pub(crate) fn load(&mut self) -> remap_linux::LinuxResult<Option<ActivationRecord>> {
        match self {
            Self::Systemd { transaction, .. } => transaction.load_record(),
            Self::NetworkManager(transaction) => transaction.load(),
        }
    }

    fn into_store(self) -> RootRecordStore {
        match self {
            Self::Systemd { transaction, .. } => transaction.into_parts().1,
            Self::NetworkManager(transaction) => transaction.into_store(),
        }
    }
}

async fn publish_if_needed(
    channel: &SystemChannel,
    record: &ActivationRecord,
    upstreams: Vec<SocketAddr>,
) -> Result<(), PublishFailure> {
    let health = channel
        .exchange(SystemCommand::ResolverHealth)
        .await
        .map_err(PublishFailure::safe)?;
    let activation_id = record.metadata().activation_id();
    let generation = record.metadata().generation();
    let publish = match &health {
        SystemResult {
            activation_id: None,
            active_generation: None,
        } => true,
        SystemResult {
            activation_id: Some(active),
            active_generation: Some(current),
        } => *active == activation_id && *current < generation,
        _ => false,
    };
    match health {
        SystemResult {
            activation_id: Some(active),
            active_generation: Some(current),
        } if active == activation_id && current == generation => Ok(()),
        _ if publish => {
            let published = match channel
                .exchange(SystemCommand::PublishResolverPlan {
                    activation_id,
                    generation,
                    upstreams,
                })
                .await
            {
                Ok(published) => published,
                Err(error) => {
                    return resolve_ambiguous_publish(channel, activation_id, generation, error)
                        .await;
                }
            };
            match plan_state(&published, activation_id, generation) {
                PlanState::Exact => Ok(()),
                PlanState::Empty => Err(PublishFailure::safe(invalid_data(
                    "daemon did not commit the resolver plan",
                ))),
                PlanState::Other => Err(PublishFailure::ambiguous(conflict(
                    "daemon resolver ownership changed during publication",
                ))),
            }
        }
        _ => Err(PublishFailure::ambiguous(conflict(
            "daemon resolver ownership differs from the activation record",
        ))),
    }
}

async fn resolve_ambiguous_publish(
    channel: &SystemChannel,
    activation_id: Uuid,
    generation: u64,
    exchange_error: io::Error,
) -> Result<(), PublishFailure> {
    let health = match channel.exchange(SystemCommand::ResolverHealth).await {
        Ok(health) => health,
        Err(_health_error) => return Err(PublishFailure::ambiguous(exchange_error)),
    };
    match plan_state(&health, activation_id, generation) {
        PlanState::Exact => Ok(()),
        PlanState::Empty => Err(PublishFailure::safe(exchange_error)),
        PlanState::Other => Err(PublishFailure::ambiguous(conflict(
            "daemon resolver ownership is ambiguous after publication",
        ))),
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum PlanState {
    Empty,
    Exact,
    Other,
}

fn plan_state(result: &SystemResult, activation_id: Uuid, generation: u64) -> PlanState {
    match result {
        SystemResult {
            activation_id: None,
            active_generation: None,
        } => PlanState::Empty,
        SystemResult {
            activation_id: Some(active),
            active_generation: Some(current),
        } if *active == activation_id && *current == generation => PlanState::Exact,
        _ => PlanState::Other,
    }
}

#[derive(Debug)]
struct PublishFailure {
    error: io::Error,
    rollback_safe: bool,
}

impl PublishFailure {
    const fn safe(error: io::Error) -> Self {
        Self {
            error,
            rollback_safe: true,
        }
    }

    const fn ambiguous(error: io::Error) -> Self {
        Self {
            error,
            rollback_safe: false,
        }
    }
}

fn metadata(owner_uid: u32) -> io::Result<RecordMetadata> {
    let (generation, created) = timestamp_after(None)?;
    RecordMetadata::new(Uuid::new_v4(), generation, owner_uid, created).map_err(platform_error)
}

fn rebase_after_observation(
    transaction: &mut NativeResolverTransaction,
    observed: &NativeStartupObservation,
) -> io::Result<ActivationRecord> {
    let current = transaction
        .load()
        .map_err(platform_error)?
        .ok_or_else(|| conflict("resolver rebase has no durable current generation"))?;
    let (generation, created) = timestamp_after(Some(current.metadata().generation()))?;
    transaction
        .rebase_observed(generation, created, observed)
        .map_err(platform_error)
}

async fn worker_rebase_after_observation(
    transaction: &BoundedWorker<NativeResolverTransaction>,
    observed: &NativeStartupObservation,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> io::Result<SettledCall<ActivationRecord>> {
    let observed = observed.clone();
    let dispatched = transaction
        .dispatch_effect(
            move |transaction| {
                let current = transaction
                    .load()
                    .map_err(platform_error)?
                    .ok_or_else(|| conflict("resolver rebase has no durable current generation"))?;
                let (generation, created) = timestamp_after(Some(current.metadata().generation()))?;
                transaction
                    .rebase_observed(generation, created, &observed)
                    .map_err(platform_error)
            },
            shutdown,
        )
        .await?;
    match call_effect_with_shutdown(dispatched.settle(), NATIVE_EFFECT_CALL_TIMEOUT, shutdown)
        .await?
    {
        EffectCall::Completed(result) => result.map(SettledCall::Completed),
        EffectCall::Stopped(result) => result.map(SettledCall::Stopped),
        EffectCall::TimedOut => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "the native resolver rebase has an unknown bounded outcome",
        )),
    }
}

fn require_root() -> io::Result<()> {
    if Uid::effective().is_root() {
        Ok(())
    } else {
        Err(permission_denied(
            "the Linux resolver supervisor requires root",
        ))
    }
}

fn conflict(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::AlreadyExists, message)
}

fn require_startup_running(shutdown: &tokio::sync::watch::Receiver<bool>) -> io::Result<()> {
    if *shutdown.borrow() {
        Err(startup_stopped())
    } else {
        Ok(())
    }
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn permission_denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

#[cfg(test)]
#[path = "supervisor_tests.rs"]
mod tests;
