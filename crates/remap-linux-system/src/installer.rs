use std::fs::{File, OpenOptions, Permissions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use nix::fcntl::Flock;
use nix::unistd::Uid;
use remap_linux::LinkIndex;
use uuid::Uuid;

use crate::cleanup;
use crate::generation_storage::{
    GENERATION_ROOT, PRODUCT_ROOT, remove_generation_partial, stage_generation, verify_generation,
    verify_generation_root,
};
use crate::install_model::{
    Generation, InstallPhase, InstallRecord, MAX_INSTALL_RECORD_BYTES, UninstallStep, decode,
    encode,
};
use crate::manager::SystemdManager;
use crate::publications;
use crate::resolver_acceptance::{
    current_plan_identity, invalidate_plan_identity, require_activation_digest, wait_for_daemon,
    wait_for_health,
};
use crate::service_health::{
    ensure_daemon_channel, ensure_service_health, ensure_service_health_with_plan,
    stop_owned_units, stop_resolver_if_active,
};
use crate::source_io::installed_xattrs_safe;
use crate::supervisor::{self, SupervisorConfig};
use crate::system_publication::{
    install_unit_links, publish_current, remove_owned_current_link, remove_owned_unit_links,
    verify_current_link, verify_unit_links,
};

pub(crate) const STATE_DIRECTORY: &str = "/var/lib/remap-system";
const DATA_DIRECTORY: &str = "/var/lib/remap";
const INSTALL_RECORD: &str = "installation.json";
const INSTALL_TEMPORARY: &str = ".installation.new";
pub(crate) const REMAPD_UNIT: &str = "remapd.service";
pub(crate) const RESOLVER_UNIT: &str = "remap-resolver.service";
pub(crate) const SOCKET_UNITS: [&str; 3] = [
    "remapd-dns-udp.socket",
    "remapd-dns-tcp.socket",
    "remapd-http.socket",
];

#[derive(Debug, Clone)]
pub(crate) struct InstallRequest {
    pub(crate) remap_source: PathBuf,
    pub(crate) remapd_source: PathBuf,
    pub(crate) system_source: PathBuf,
    pub(crate) assets_source: PathBuf,
    pub(crate) source_manifest_sha256: [u8; 32],
    pub(crate) account: String,
    pub(crate) group: String,
    pub(crate) owner_uid: u32,
    pub(crate) link: LinkIndex,
}

#[derive(Debug)]
pub(crate) struct InstallStore {
    directory: PathBuf,
    created_state_directory: bool,
    _lock: Flock<File>,
}

pub(crate) async fn install(
    request: &InstallRequest,
    update: bool,
    approval_token: &str,
) -> io::Result<()> {
    require_root()?;
    let mut first = crate::lifecycle_contract::prepare_install(request, update).await?;
    first.require_token(approval_token)?;
    let manager = SystemdManager::connect()?;
    let mut store = InstallStore::open()?;
    let previous = store.load()?;
    if verify_noop_plan(&first, request, update, approval_token, &store).await? {
        return Ok(());
    }
    let resolver_quiesced = previous.is_some();
    if resolver_quiesced {
        stop_resolver_if_active(&manager)?;
    }
    let resolver_store = match acquire_resolver_store() {
        Ok(store) => store,
        Err(error) => {
            restart_previous_after_preflight(&manager, previous.as_ref(), resolver_quiesced)
                .await?;
            return Err(error);
        }
    };
    let normalization = crate::lifecycle_contract::SnapshotNormalization {
        fresh_state_created: store.created_state_directory,
        resolver_quiesced,
    };
    let first_socket_reservation = first.socket_reservation.take();
    let second = match crate::lifecycle_contract::prepare_install_locked(
        request,
        update,
        normalization,
        first_socket_reservation,
    )
    .await
    {
        Ok(plan) => plan,
        Err(error) if store.created_state_directory => {
            drop(resolver_store);
            return cleanup_fresh_state(store, error);
        }
        Err(error) => {
            drop(resolver_store);
            restart_previous_after_preflight(&manager, previous.as_ref(), resolver_quiesced)
                .await?;
            return Err(error);
        }
    };
    if let Err(error) = second.require_token(approval_token) {
        drop(resolver_store);
        restart_previous_after_preflight(&manager, previous.as_ref(), resolver_quiesced).await?;
        return if store.created_state_directory {
            cleanup_fresh_state(store, error)
        } else {
            Err(error)
        };
    }
    if !first.same_authority(&second) {
        drop(resolver_store);
        restart_previous_after_preflight(&manager, previous.as_ref(), resolver_quiesced).await?;
        let error = conflict("the Linux lifecycle plan changed while acquiring its lock");
        return if store.created_state_directory {
            cleanup_fresh_state(store, error)
        } else {
            Err(error)
        };
    }
    if !second.has_effects() {
        drop(resolver_store);
        restart_previous_after_preflight(&manager, previous.as_ref(), resolver_quiesced).await?;
        return Err(conflict(
            "an effectful Linux plan became a no-op after resolver quiescence",
        ));
    }
    execute_approved_generation(
        &manager,
        &mut store,
        previous.as_ref(),
        second,
        resolver_store,
    )
    .await
}

async fn execute_approved_generation(
    manager: &SystemdManager,
    store: &mut InstallStore,
    previous: Option<&InstallRecord>,
    mut plan: crate::lifecycle_contract::PreparedPlan,
    resolver_store: remap_linux::RootRecordStore,
) -> io::Result<()> {
    let expected_activation_digest = plan.activation_record_digest;
    let generation = plan
        .generation
        .take()
        .ok_or_else(|| invalid_data("the approved generation is unavailable"))?;
    let artifacts = plan
        .artifacts
        .take()
        .ok_or_else(|| invalid_data("the approved artifact set is unavailable"))?;
    let mut socket_reservation = plan.socket_reservation.take();
    let mut record = InstallRecord::staging(generation, previous);
    let result = async {
        store.save(&record)?;
        stage_generation(&record.current, &artifacts, previous.is_none())?;
        verify_generation(&record.current)?;
        publications::publish_created_directories(store, &mut record)?;
        record.stage()?;
        store.save(&record)?;
        publish_and_start(
            manager,
            store,
            &mut record,
            previous,
            resolver_store,
            expected_activation_digest,
            &mut socket_reservation,
        )
        .await
    }
    .await;
    if let Err(error) = result {
        if record.phase != InstallPhase::Pruning {
            crate::rollback::begin(manager, store, record, &mut None, socket_reservation.take())
                .await?;
        }
        return Err(error);
    }
    Ok(())
}

async fn verify_noop_plan(
    first: &crate::lifecycle_contract::PreparedPlan,
    request: &InstallRequest,
    update: bool,
    approval_token: &str,
    store: &InstallStore,
) -> io::Result<bool> {
    if first.has_effects() {
        return Ok(false);
    }
    let second = crate::lifecycle_contract::prepare_install_locked(
        request,
        update,
        crate::lifecycle_contract::SnapshotNormalization {
            fresh_state_created: store.created_state_directory,
            resolver_quiesced: false,
        },
        None,
    )
    .await?;
    second.require_token(approval_token)?;
    if !first.same_authority(&second) || second.has_effects() {
        return Err(conflict(
            "the Linux no-op plan changed while acquiring its lock",
        ));
    }
    Ok(true)
}

fn cleanup_fresh_state(mut store: InstallStore, error: io::Error) -> io::Result<()> {
    store.remove()?;
    drop(store);
    cleanup_state_after_record_removal()?;
    Err(error)
}

pub(crate) async fn uninstall(approval_token: &str) -> io::Result<()> {
    require_root()?;
    let first = crate::lifecycle_contract::prepare_uninstall().await?;
    first.require_token(approval_token)?;
    let manager = SystemdManager::connect()?;
    let mut store = InstallStore::open()?;
    stop_resolver_if_active(&manager)?;
    let mut resolver_authority = match acquire_resolver_store() {
        Ok(store) => Some(store),
        Err(error) => {
            let installed = store.load()?;
            restart_previous_after_preflight(&manager, installed.as_ref(), true).await?;
            return Err(error);
        }
    };
    let second = match crate::lifecycle_contract::prepare_uninstall_locked(
        crate::lifecycle_contract::SnapshotNormalization {
            fresh_state_created: false,
            resolver_quiesced: true,
        },
    )
    .await
    {
        Ok(plan) => plan,
        Err(error) => {
            drop(resolver_authority.take());
            let installed = store.load()?;
            restart_previous_after_preflight(&manager, installed.as_ref(), true).await?;
            return Err(error);
        }
    };
    if let Err(error) = second.require_token(approval_token) {
        drop(resolver_authority.take());
        let installed = store.load()?;
        restart_previous_after_preflight(&manager, installed.as_ref(), true).await?;
        return Err(error);
    }
    if !first.same_authority(&second) {
        drop(resolver_authority.take());
        let installed = store.load()?;
        restart_previous_after_preflight(&manager, installed.as_ref(), true).await?;
        return Err(conflict(
            "the Linux lifecycle plan changed while acquiring resolver authority",
        ));
    }
    let record = store
        .load()?
        .ok_or_else(|| conflict("Remap is not installed"))?;
    verify_active(&record)?;
    cleanup::preflight_state_directory(Path::new(STATE_DIRECTORY))?;
    let mut record = record;
    if !second.daemon_plan_observed {
        return Err(conflict(
            "the active daemon plan became unreachable after lifecycle authorization",
        ));
    }
    let resolver_plan = second.daemon_plan_identity.ok_or_else(|| {
        conflict("the active installation has no daemon resolver plan to invalidate")
    })?;
    record.begin_uninstall(resolver_plan)?;
    store.save(&record)?;
    resume_uninstall(&manager, &mut store, record, &mut resolver_authority).await?;
    drop(store);
    cleanup_state_after_record_removal()
}

pub(crate) async fn recover_all(approval_token: &str) -> io::Result<()> {
    require_root()?;
    let first = crate::lifecycle_contract::prepare_recovery().await?;
    first.require_token(approval_token)?;
    let manager = SystemdManager::connect()?;
    let mut store = InstallStore::open()?;
    let resolver_was_active =
        first.requires_resolver_authority() && manager.observed_state(RESOLVER_UNIT)? == "active";
    if resolver_was_active {
        stop_resolver_if_active(&manager)?;
    }
    let mut resolver_authority = if first.requires_resolver_authority() {
        match acquire_resolver_store() {
            Ok(authority) => Some(authority),
            Err(error) => {
                let installed = store.load()?;
                restart_previous_after_preflight(&manager, installed.as_ref(), resolver_was_active)
                    .await?;
                return Err(error);
            }
        }
    } else {
        None
    };
    let second = match crate::lifecycle_contract::prepare_recovery_locked(
        crate::lifecycle_contract::SnapshotNormalization {
            fresh_state_created: store.created_state_directory,
            resolver_quiesced: resolver_was_active,
        },
    )
    .await
    {
        Ok(plan) => plan,
        Err(error) => {
            drop(resolver_authority.take());
            let installed = store.load()?;
            restart_previous_after_preflight(&manager, installed.as_ref(), resolver_was_active)
                .await?;
            return Err(error);
        }
    };
    if let Err(error) = second.require_token(approval_token) {
        drop(resolver_authority.take());
        let installed = store.load()?;
        restart_previous_after_preflight(&manager, installed.as_ref(), resolver_was_active).await?;
        return Err(error);
    }
    if !first.same_authority(&second) {
        drop(resolver_authority.take());
        let installed = store.load()?;
        restart_previous_after_preflight(&manager, installed.as_ref(), resolver_was_active).await?;
        return Err(conflict(
            "the Linux recovery plan changed while acquiring its lock",
        ));
    }
    if let Some(residue) = &second.state_residue {
        if residue.requires_resolver_quiescence() {
            stop_resolver_if_active(&manager)?;
        }
        cleanup::cleanup_state_residue(residue)?;
    }
    if let Some(record) = store.load()?.as_ref() {
        publications::install_missing_public_links(&record.current, &second.publication_repairs)?;
    }
    recover_explicit(
        &manager,
        &mut store,
        &mut resolver_authority,
        second.daemon_plan_observed,
        second.daemon_plan_identity,
    )
    .await?;
    crate::bootstrap_recovery::cleanup(&second.bootstrap_residues)?;
    drop(store);
    cleanup_state_after_record_removal()
}

async fn recover_explicit(
    manager: &SystemdManager,
    store: &mut InstallStore,
    resolver_authority: &mut Option<remap_linux::RootRecordStore>,
    daemon_plan_observed: bool,
    daemon_plan_identity: Option<crate::install_model::ResolverPlanIdentity>,
) -> io::Result<()> {
    let record = store.load()?;
    match record {
        Some(record) if record.phase != InstallPhase::Active => {
            recover_interrupted(manager, store, resolver_authority).await
        }
        Some(record) => {
            let services_healthy = SOCKET_UNITS.into_iter().all(|socket| {
                manager
                    .observed_state(socket)
                    .is_ok_and(|state| state == "active")
            }) && manager
                .observed_state(REMAPD_UNIT)
                .is_ok_and(|state| state == "active")
                && manager
                    .observed_state(RESOLVER_UNIT)
                    .is_ok_and(|state| state == "active");
            let activation_healthy =
                remap_linux::RootRecordStore::inspect(Path::new(STATE_DIRECTORY))
                    .map_err(platform_error)?
                    .is_some_and(|activation| {
                        activation.phase() == remap_linux::ActivationPhase::Active
                            && daemon_plan_observed
                            && daemon_plan_identity
                                == Some(crate::install_model::ResolverPlanIdentity {
                                    activation_id: activation.metadata().activation_id(),
                                    generation: activation.metadata().generation(),
                                })
                    });
            if !services_healthy || !activation_healthy {
                ensure_service_health_with_plan(
                    manager,
                    &record.current,
                    resolver_authority,
                    daemon_plan_observed,
                    daemon_plan_identity,
                )
                .await?;
            }
            verify_active(&record)
        }
        None => recover_orphaned_resolver(resolver_authority).await,
    }
}

fn cleanup_state_after_record_removal() -> io::Result<()> {
    if let Some(residue) = cleanup::inspect_state_residue(Path::new(STATE_DIRECTORY))? {
        cleanup::cleanup_state_residue(&residue)?;
    }
    Ok(())
}

async fn resume_uninstall(
    manager: &SystemdManager,
    store: &mut InstallStore,
    mut record: InstallRecord,
    resolver_authority: &mut Option<remap_linux::RootRecordStore>,
) -> io::Result<()> {
    loop {
        let InstallPhase::Uninstalling(step) = record.phase else {
            return Err(conflict("the Linux uninstall journal is invalid"));
        };
        let next = match step {
            UninstallStep::RestoreResolver => {
                restore_resolver_for_uninstall(manager, &record, resolver_authority).await?;
                UninstallStep::StopServices
            }
            UninstallStep::StopServices => {
                stop_owned_units(manager)?;
                UninstallStep::RemoveUnitLinks
            }
            UninstallStep::RemoveUnitLinks => {
                remove_owned_unit_links()?;
                UninstallStep::RemovePublicPaths
            }
            UninstallStep::RemovePublicPaths => {
                publications::remove_owned_public_links(&record.current)?;
                UninstallStep::RemoveCurrent
            }
            UninstallStep::RemoveCurrent => {
                remove_owned_current_link(record.current.id)?;
                UninstallStep::ReloadManager
            }
            UninstallStep::ReloadManager => {
                manager.reload()?;
                UninstallStep::RemoveCurrentGeneration
            }
            UninstallStep::RemoveCurrentGeneration => {
                remove_generation_partial(&record.current)?;
                UninstallStep::RemovePreviousGeneration
            }
            UninstallStep::RemovePreviousGeneration => {
                if let Some(previous) = &record.previous {
                    remove_generation_partial(previous)?;
                }
                UninstallStep::RemoveGenerationRoots
            }
            UninstallStep::RemoveGenerationRoots => {
                cleanup::remove_empty_generation_roots(Path::new(GENERATION_ROOT))?;
                UninstallStep::Finalize
            }
            UninstallStep::Finalize => {
                store.remove()?;
                return Ok(());
            }
        };
        if step.successor() != Some(next) {
            return Err(conflict("the Linux uninstall journal order is invalid"));
        }
        record.advance_uninstall(step, next)?;
        store.save(&record)?;
    }
}

async fn restore_resolver_for_uninstall(
    manager: &SystemdManager,
    record: &InstallRecord,
    resolver_authority: &mut Option<remap_linux::RootRecordStore>,
) -> io::Result<()> {
    stop_resolver_if_active(manager)?;
    if remap_linux::RootRecordStore::inspect(Path::new(STATE_DIRECTORY))
        .map_err(platform_error)?
        .is_some()
    {
        let config = supervisor_config(&record.current)?;
        if let Some(store) = resolver_authority.take() {
            supervisor::deactivate_with_store(&config, store).await?;
        } else {
            supervisor::deactivate(&config).await?;
        }
    }
    let identity = record
        .pending_resolver_plan
        .ok_or_else(|| conflict("the uninstall journal has no resolver plan identity"))?;
    let _runtime_lease = crate::runtime_authority::acquire(record.current.id)?;
    ensure_daemon_channel(manager, &record.current).await?;
    invalidate_plan_identity(record.current.daemon_uid, identity).await?;
    if remap_linux::RootRecordStore::inspect(Path::new(STATE_DIRECTORY))
        .map_err(platform_error)?
        .is_some()
    {
        return Err(conflict(
            "the resolver activation record remains after restoration",
        ));
    }
    Ok(())
}

pub(crate) fn acquire_resolver_store() -> io::Result<remap_linux::RootRecordStore> {
    let lock_directory = crate::authority::resolver_lock_directory()?;
    remap_linux::RootRecordStore::open_with_lock_directory(
        Path::new(STATE_DIRECTORY),
        &lock_directory,
    )
    .map_err(platform_error)
}

async fn restart_previous_after_preflight(
    manager: &SystemdManager,
    previous: Option<&InstallRecord>,
    quiesced: bool,
) -> io::Result<()> {
    if quiesced
        && let Some(previous) = previous.filter(|record| record.phase == InstallPhase::Active)
    {
        ensure_service_health(manager, &previous.current).await?;
    }
    Ok(())
}

async fn recover_orphaned_resolver(
    resolver_authority: &mut Option<remap_linux::RootRecordStore>,
) -> io::Result<()> {
    let Some(record) = remap_linux::RootRecordStore::inspect(Path::new(STATE_DIRECTORY))
        .map_err(platform_error)?
    else {
        return Ok(());
    };
    let config = SupervisorConfig {
        link: record.owned().link(),
        interface_name: record.manager().interface_name().map(str::to_owned),
        manager: supervisor::activation_manager(record.manager()),
        owner_uid: record.metadata().owner_uid(),
        daemon_uid: 1,
        record_directory: PathBuf::from(STATE_DIRECTORY),
        system_socket: PathBuf::from("/run/remap-recovery-unavailable.sock"),
    };
    if let Some(store) = resolver_authority.take() {
        supervisor::deactivate_with_store(&config, store).await
    } else {
        supervisor::deactivate(&config).await
    }
}

async fn publish_and_start(
    manager: &SystemdManager,
    store: &mut InstallStore,
    record: &mut InstallRecord,
    previous: Option<&InstallRecord>,
    resolver_store: remap_linux::RootRecordStore,
    expected_activation_digest: Option<[u8; 32]>,
    socket_reservation: &mut Option<crate::socket_preflight::SocketReservation>,
) -> io::Result<()> {
    if previous.is_none() {
        install_unit_links()?;
        publications::install_public_links(&record.current)?;
    }
    if previous.is_some() {
        crate::service_health::prepare_update_cutover(manager, socket_reservation)?;
    }
    publish_current(record.current.id, previous.map(|value| value.current.id))?;
    record.publish()?;
    store.save(record)?;
    if let Some(previous) = previous {
        publications::install_public_link_changes(&previous.current, &record.current)?;
    }
    verify_unit_links()?;
    manager.reload()?;
    crate::service_health::retain_rollback_reservations(manager, socket_reservation)?;
    crate::service_health::prepare_daemon_transaction(manager)?;
    let mut runtime_lease = Some(crate::runtime_authority::acquire(record.current.id)?);
    if let Err(error) =
        crate::service_health::start_prepared_daemon_transaction(manager, socket_reservation)
    {
        drop(runtime_lease.take());
        if previous.is_some() {
            crate::service_health::retain_rollback_reservations(manager, socket_reservation)?;
        }
        return Err(error);
    }
    let result = async {
        wait_for_daemon(record.current.daemon_uid).await?;
        drop(resolver_store);
        require_activation_digest(expected_activation_digest)?;
        if current_plan_identity(record.current.daemon_uid)
            .await?
            .is_some()
        {
            return Err(conflict(
                "the restarted daemon retained an unexpected resolver plan",
            ));
        }
        start_and_accept_published_resolver(
            manager,
            record.current.daemon_uid,
            expected_activation_digest,
        )
        .await?;
        if let Some(stale) = record.previous_previous.clone() {
            record.begin_prune()?;
            store.save(record)?;
            remove_generation_partial(&stale)?;
        }
        record.activate()?;
        store.save(record)
    }
    .await;
    drop(runtime_lease.take());
    if result.is_err() && record.phase != InstallPhase::Pruning && previous.is_some() {
        crate::service_health::retain_rollback_reservations(manager, socket_reservation)?;
    }
    result
}

async fn start_and_accept_published_resolver(
    manager: &SystemdManager,
    daemon_uid: u32,
    expected_activation_digest: Option<[u8; 32]>,
) -> io::Result<()> {
    manager.start(RESOLVER_UNIT)?;
    let result = async {
        wait_for_health(daemon_uid).await?;
        if expected_activation_digest.is_some() {
            require_activation_digest(expected_activation_digest)?;
        }
        manager
            .require_settled_active(RESOLVER_UNIT)
            .map_err(|_error| conflict("the resolver supervisor exited before acceptance"))
    }
    .await;
    if result.is_err() {
        manager.quiesce_failed_start(RESOLVER_UNIT);
    }
    result
}

async fn recover_interrupted(
    manager: &SystemdManager,
    store: &mut InstallStore,
    resolver_authority: &mut Option<remap_linux::RootRecordStore>,
) -> io::Result<()> {
    let Some(record) = store.load()? else {
        return Ok(());
    };
    match record.phase {
        InstallPhase::Active => verify_active(&record),
        InstallPhase::Staging | InstallPhase::Staged | InstallPhase::Published => {
            crate::rollback::begin(manager, store, record, resolver_authority, None).await
        }
        InstallPhase::RollingBack(_) => {
            crate::rollback::resume(manager, store, record, resolver_authority).await
        }
        InstallPhase::Pruning => {
            drop(resolver_authority.take());
            complete_pruning(manager, store, record).await
        }
        InstallPhase::Uninstalling(_) => {
            resume_uninstall(manager, store, record, resolver_authority).await
        }
    }
}

async fn complete_pruning(
    manager: &SystemdManager,
    store: &mut InstallStore,
    mut record: InstallRecord,
) -> io::Result<()> {
    verify_current_link(record.current.id)?;
    verify_generation(&record.current)?;
    let stale = record
        .previous_previous
        .clone()
        .ok_or_else(|| conflict("the pruning journal has no stale generation"))?;
    let previous = record
        .previous
        .as_ref()
        .ok_or_else(|| conflict("the pruning journal has no rollback generation"))?;
    verify_generation(previous)?;
    match std::fs::symlink_metadata(generation_directory(stale.id)) {
        Ok(_) => {
            verify_generation_root([record.current.id, previous.id, stale.id])?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            sync_directory(Path::new(GENERATION_ROOT))?;
            verify_generation_root([record.current.id, previous.id])?;
        }
        Err(error) => return Err(error),
    }
    ensure_service_health(manager, &record.current).await?;
    remove_generation_partial(&stale)?;
    record.activate()?;
    store.save(&record)
}

pub(crate) fn restore_record(
    store: &mut InstallStore,
    record: Option<InstallRecord>,
) -> io::Result<()> {
    match record {
        Some(record) => store.save(&record),
        None => store.remove(),
    }
}

pub(crate) fn verify_active(record: &InstallRecord) -> io::Result<()> {
    verify_active_without_public_links(record)?;
    publications::verify_public_links(&record.current)
}

pub(crate) fn verify_active_without_public_links(record: &InstallRecord) -> io::Result<()> {
    if record.phase != InstallPhase::Active {
        return Err(conflict("the Linux installation requires recovery"));
    }
    verify_current_link(record.current.id)?;
    verify_unit_links()?;
    publications::verify_public_directories(&record.current)?;
    verify_generation(&record.current)?;
    let mut generation_ids = vec![record.current.id];
    if let Some(previous) = &record.previous {
        verify_generation(previous)?;
        generation_ids.push(previous.id);
    }
    verify_generation_root(generation_ids)
}

pub(crate) fn require_generation_roots_absent() -> io::Result<()> {
    for path in [PRODUCT_ROOT, GENERATION_ROOT] {
        match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
            Ok(_) => {
                return Err(conflict(
                    "the reserved Remap generation directory is already occupied",
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn create_private_directory(path: &Path, mode: u32) -> io::Result<()> {
    if mode != 0o700 {
        return Err(invalid_data(
            "a private installation directory mode is invalid",
        ));
    }
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = path
                .parent()
                .ok_or_else(|| invalid_data("installation directory has no parent"))?;
            validate_ancestor(parent)?;
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700).create(path)?;
        }
        Err(error) => return Err(error),
        Ok(_) => {}
    }
    validate_recoverable_private_directory(path)?;
    std::fs::set_permissions(path, Permissions::from_mode(mode))?;
    if let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
    validate_directory(path, mode)
}

fn validate_recoverable_private_directory(path: &Path) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.mode() & 0o077 != 0
    {
        return Err(conflict(
            "a private installation directory changed ownership or metadata",
        ));
    }
    let directory = File::open(path)?;
    if !installed_xattrs_safe(&directory)? {
        return Err(conflict(
            "a private installation directory has unsafe extended attributes",
        ));
    }
    Ok(())
}

fn validate_ancestor(path: &Path) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
    {
        return Err(conflict("an installation directory ancestor is unsafe"));
    }
    Ok(())
}

pub(crate) fn validate_directory(path: &Path, mode: u32) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != mode
    {
        return Err(conflict(
            "an installation directory is not root-owned with the exact mode",
        ));
    }
    let directory = File::open(path)?;
    if !installed_xattrs_safe(&directory)? {
        return Err(conflict(
            "an installation directory has unsafe extended attributes",
        ));
    }
    Ok(())
}

fn write_new_file(path: &Path, mode: u32, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(bytes)?;
    file.set_permissions(Permissions::from_mode(mode))?;
    file.sync_all()
}

pub(crate) fn unit_names() -> Vec<String> {
    SOCKET_UNITS
        .into_iter()
        .chain([REMAPD_UNIT, RESOLVER_UNIT])
        .map(str::to_owned)
        .collect()
}

pub(crate) fn supervisor_config(generation: &Generation) -> io::Result<SupervisorConfig> {
    Ok(SupervisorConfig {
        link: LinkIndex::new(generation.link).map_err(platform_error)?,
        interface_name: generation.interface_name.clone(),
        manager: generation.resolver_manager,
        owner_uid: generation.owner_uid,
        daemon_uid: generation.daemon_uid,
        record_directory: PathBuf::from(STATE_DIRECTORY),
        system_socket: PathBuf::from(format!("{DATA_DIRECTORY}/system.sock")),
    })
}

fn generation_directory(id: Uuid) -> PathBuf {
    generation_directory_at(Path::new(GENERATION_ROOT), id)
}

fn generation_directory_at(root: &Path, id: Uuid) -> PathBuf {
    root.join(id.to_string())
}

pub(crate) fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

impl InstallStore {
    pub(crate) fn open() -> io::Result<Self> {
        let lock = crate::authority::acquire_lifecycle()?;
        let created_state_directory = match std::fs::symlink_metadata(STATE_DIRECTORY) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => true,
            Err(error) => return Err(error),
            Ok(_) => false,
        };
        create_private_directory(Path::new(STATE_DIRECTORY), 0o700)?;
        Ok(Self {
            directory: PathBuf::from(STATE_DIRECTORY),
            created_state_directory,
            _lock: lock,
        })
    }

    pub(crate) fn load(&self) -> io::Result<Option<InstallRecord>> {
        load_install_record(&self.directory)
    }

    pub(crate) fn save(&mut self, record: &InstallRecord) -> io::Result<()> {
        let bytes = encode(record)?;
        let temporary = self.directory.join(INSTALL_TEMPORARY);
        match std::fs::symlink_metadata(&temporary) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
            Ok(_) => {
                return Err(conflict(
                    "an interrupted installation record publication requires recovery",
                ));
            }
        }
        write_new_file(&temporary, 0o600, &bytes)?;
        std::fs::rename(temporary, self.directory.join(INSTALL_RECORD))?;
        sync_directory(&self.directory)
    }

    fn remove(&mut self) -> io::Result<()> {
        match std::fs::remove_file(self.directory.join(INSTALL_RECORD)) {
            Ok(()) => sync_directory(&self.directory),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }
}

pub(crate) fn inspect_install_record() -> io::Result<Option<InstallRecord>> {
    let directory = Path::new(STATE_DIRECTORY);
    match std::fs::symlink_metadata(directory) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
        Ok(_metadata) => validate_directory(directory, 0o700)?,
    }
    load_install_record(directory)
}

fn load_install_record(directory: &Path) -> io::Result<Option<InstallRecord>> {
    let path = directory.join(INSTALL_RECORD);
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let length = validate_root_file(&file, Some(MAX_INSTALL_RECORD_BYTES as u64))?;
    let mut bytes =
        Vec::with_capacity(usize::try_from(length).map_err(|_error| {
            invalid_data("the installation record length cannot be represented")
        })?);
    file.take((MAX_INSTALL_RECORD_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    decode(&bytes).map(Some)
}

fn validate_root_file(file: &File, maximum: Option<u64>) -> io::Result<u64> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
        || maximum.is_some_and(|bound| metadata.len() == 0 || metadata.len() > bound)
    {
        return Err(conflict("a Linux installation state file is unsafe"));
    }
    if !installed_xattrs_safe(file)? {
        return Err(conflict(
            "a Linux installation state file has unsafe extended attributes",
        ));
    }
    Ok(metadata.len())
}

fn require_root() -> io::Result<()> {
    if Uid::effective().is_root() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the Linux installer requires root",
        ))
    }
}

pub(crate) fn platform_error(_error: remap_linux::LinuxError) -> io::Error {
    invalid_data("the native Linux platform contract is invalid")
}

pub(crate) fn conflict(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::AlreadyExists, message)
}

pub(crate) fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
#[path = "installer_tests.rs"]
mod tests;
