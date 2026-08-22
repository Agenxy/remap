use std::io;
use std::path::Path;

use crate::generation_storage::{
    GENERATION_ROOT, remove_empty_staging_roots, remove_generation_partial,
};
use crate::install_model::{InstallPhase, InstallRecord, RollbackStep};
use crate::installer::{
    InstallStore, REMAPD_UNIT, STATE_DIRECTORY, acquire_resolver_store, conflict, platform_error,
    restore_record, supervisor_config,
};
use crate::manager::SystemdManager;
use crate::publications;
use crate::resolver_acceptance::invalidate_plan_identity;
use crate::service_health::{
    ensure_active_services, ensure_daemon_channel, reserve_rollback_namespace,
    retain_rollback_namespace, retain_rollback_reservations, start_daemon_transaction,
    stop_owned_units,
};
use crate::supervisor;
use crate::system_publication::{
    remove_owned_unit_links, restore_current_for_rollback, verify_current_link,
};

pub(crate) async fn begin(
    manager: &SystemdManager,
    store: &mut InstallStore,
    mut record: InstallRecord,
    resolver_authority: &mut Option<remap_linux::RootRecordStore>,
    socket_reservation: Option<crate::socket_preflight::SocketReservation>,
) -> io::Result<()> {
    record.begin_rollback(None)?;
    store.save(&record)?;
    resume_with_reservation(
        manager,
        store,
        record,
        resolver_authority,
        socket_reservation,
    )
    .await
}

pub(crate) async fn resume(
    manager: &SystemdManager,
    store: &mut InstallStore,
    record: InstallRecord,
    resolver_authority: &mut Option<remap_linux::RootRecordStore>,
) -> io::Result<()> {
    resume_with_reservation(manager, store, record, resolver_authority, None).await
}

async fn resume_with_reservation(
    manager: &SystemdManager,
    store: &mut InstallStore,
    mut record: InstallRecord,
    resolver_authority: &mut Option<remap_linux::RootRecordStore>,
    mut socket_reservation: Option<crate::socket_preflight::SocketReservation>,
) -> io::Result<()> {
    let InstallPhase::RollingBack(_) = record.phase else {
        return Err(conflict("the Linux rollback journal is invalid"));
    };
    if record.rollback_record().is_some() {
        retain_rollback_reservations(manager, &mut socket_reservation)?;
    }
    if matches!(
        record.phase,
        InstallPhase::RollingBack(step) if step >= RollbackStep::RemoveFailedGeneration
    ) && record.rollback_record().is_some()
    {
        let generation = restored_rollback_generation(&record)?;
        retain_rollback_namespace(manager, generation, &mut socket_reservation);
    }
    loop {
        let InstallPhase::RollingBack(step) = record.phase else {
            return Err(conflict("the Linux rollback journal is invalid"));
        };
        let previous = record.rollback_record();
        let Some(next) = apply_step(
            manager,
            &record,
            previous.as_ref(),
            step,
            resolver_authority,
            &mut socket_reservation,
        )
        .await?
        else {
            restore_record(store, previous)?;
            return Ok(());
        };
        if step.successor() != Some(next) {
            return Err(conflict("the Linux rollback journal order is invalid"));
        }
        record.advance_rollback(step, next)?;
        store.save(&record)?;
    }
}

fn restored_rollback_generation(record: &InstallRecord) -> io::Result<uuid::Uuid> {
    let previous = record
        .previous
        .as_ref()
        .ok_or_else(|| conflict("the rollback has no restored listener generation"))?;
    verify_current_link(previous.id)?;
    Ok(previous.id)
}

async fn apply_step(
    manager: &SystemdManager,
    record: &InstallRecord,
    previous: Option<&InstallRecord>,
    step: RollbackStep,
    resolver_authority: &mut Option<remap_linux::RootRecordStore>,
    socket_reservation: &mut Option<crate::socket_preflight::SocketReservation>,
) -> io::Result<Option<RollbackStep>> {
    if step <= RollbackStep::RestoreCurrent {
        apply_early_step(
            manager,
            record,
            previous,
            step,
            resolver_authority,
            socket_reservation,
        )
        .await
    } else {
        apply_late_step(
            manager,
            record,
            previous,
            step,
            resolver_authority,
            socket_reservation,
        )
        .await
    }
}

async fn apply_early_step(
    manager: &SystemdManager,
    record: &InstallRecord,
    previous: Option<&InstallRecord>,
    step: RollbackStep,
    resolver_authority: &mut Option<remap_linux::RootRecordStore>,
    socket_reservation: &mut Option<crate::socket_preflight::SocketReservation>,
) -> io::Result<Option<RollbackStep>> {
    let next = match step {
        RollbackStep::StopServices => {
            if previous.is_some() {
                retain_rollback_reservations(manager, socket_reservation)?;
            } else if previous.is_none() {
                stop_owned_units(manager)?;
                *socket_reservation = None;
            }
            RollbackStep::RestoreResolver
        }
        RollbackStep::RestoreResolver => {
            restore_resolver_plan(
                manager,
                record,
                previous,
                resolver_authority,
                socket_reservation,
            )
            .await?;
            RollbackStep::RestoreCurrent
        }
        RollbackStep::RestoreCurrent => {
            restore_current_for_rollback(record)?;
            RollbackStep::RemoveUnitLinks
        }
        _ => return Err(conflict("the Linux rollback journal order is invalid")),
    };
    Ok(Some(next))
}

async fn apply_late_step(
    manager: &SystemdManager,
    record: &InstallRecord,
    previous: Option<&InstallRecord>,
    step: RollbackStep,
    resolver_authority: &mut Option<remap_linux::RootRecordStore>,
    socket_reservation: &mut Option<crate::socket_preflight::SocketReservation>,
) -> io::Result<Option<RollbackStep>> {
    let next = match step {
        RollbackStep::RemoveUnitLinks => {
            if previous.is_none() {
                remove_owned_unit_links()?;
            }
            RollbackStep::RemovePublicPaths
        }
        RollbackStep::RemovePublicPaths => {
            if previous.is_none() {
                publications::remove_owned_public_links(&record.current)?;
            } else if let Some(previous) = previous {
                publications::revert_public_link_changes(&previous.current, &record.current)?;
            }
            RollbackStep::ReloadManager
        }
        RollbackStep::ReloadManager => {
            manager.reload()?;
            if let Some(previous) = previous {
                retain_rollback_namespace(manager, previous.current.id, socket_reservation);
                invalidate_pending_after_reload(manager, record, previous, socket_reservation)
                    .await?;
            }
            RollbackStep::RemoveFailedGeneration
        }
        RollbackStep::RemoveFailedGeneration => {
            remove_generation_partial(&record.current)?;
            RollbackStep::RemoveGenerationRoots
        }
        RollbackStep::RemoveGenerationRoots => {
            if previous.is_none() {
                remove_empty_staging_roots(Path::new(GENERATION_ROOT))?;
            }
            RollbackStep::StartPrevious
        }
        RollbackStep::StartPrevious => {
            start_previous(
                manager,
                record,
                previous,
                resolver_authority,
                socket_reservation,
            )
            .await?;
            RollbackStep::Finalize
        }
        RollbackStep::Finalize => {
            finalize_previous(
                manager,
                record,
                previous,
                resolver_authority,
                socket_reservation,
            )
            .await?;
            return Ok(None);
        }
        _ => return Err(conflict("the Linux rollback journal order is invalid")),
    };
    Ok(Some(next))
}

async fn start_previous(
    manager: &SystemdManager,
    record: &InstallRecord,
    previous: Option<&InstallRecord>,
    resolver_authority: &mut Option<remap_linux::RootRecordStore>,
    socket_reservation: &mut Option<crate::socket_preflight::SocketReservation>,
) -> io::Result<()> {
    let Some(previous) = previous else {
        return Ok(());
    };
    converge_previous_handoff(record, resolver_authority).await?;
    drop(resolver_authority.take());
    start_previous_runtime(manager, previous, socket_reservation).await
}

async fn finalize_previous(
    manager: &SystemdManager,
    record: &InstallRecord,
    previous: Option<&InstallRecord>,
    resolver_authority: &mut Option<remap_linux::RootRecordStore>,
    socket_reservation: &mut Option<crate::socket_preflight::SocketReservation>,
) -> io::Result<()> {
    let Some(previous) = previous else {
        return Ok(());
    };
    if manager.observed_state(crate::installer::RESOLVER_UNIT)? != "active" {
        converge_previous_handoff(record, resolver_authority).await?;
        drop(resolver_authority.take());
    }
    start_previous_runtime(manager, previous, socket_reservation).await
}

async fn start_previous_runtime(
    manager: &SystemdManager,
    previous: &InstallRecord,
    socket_reservation: &mut Option<crate::socket_preflight::SocketReservation>,
) -> io::Result<()> {
    retain_rollback_namespace(manager, previous.current.id, socket_reservation);
    let mut runtime_lease = Some(crate::runtime_authority::acquire(previous.current.id)?);
    let result = match start_daemon_transaction(manager, socket_reservation) {
        Ok(()) => ensure_active_services(manager, previous).await,
        Err(error) => Err(error),
    };
    drop(runtime_lease.take());
    if result.is_err() {
        retain_rollback_namespace(manager, previous.current.id, socket_reservation);
    }
    result
}

async fn converge_previous_handoff(
    record: &InstallRecord,
    resolver_authority: &mut Option<remap_linux::RootRecordStore>,
) -> io::Result<()> {
    let authority = match resolver_authority.take() {
        Some(authority) => authority,
        None => acquire_resolver_store()?,
    };
    let config = supervisor_config(&record.current)?;
    *resolver_authority = Some(supervisor::converge_owned_with_store(&config, authority).await?);
    Ok(())
}

async fn restore_resolver_plan(
    manager: &SystemdManager,
    record: &InstallRecord,
    previous: Option<&InstallRecord>,
    resolver_authority: &mut Option<remap_linux::RootRecordStore>,
    socket_reservation: &mut Option<crate::socket_preflight::SocketReservation>,
) -> io::Result<()> {
    if previous.is_some() {
        converge_previous_handoff(record, resolver_authority).await?;
    }
    if previous.is_none()
        && remap_linux::RootRecordStore::inspect(Path::new(STATE_DIRECTORY))
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
    if previous.is_none() && record.pending_resolver_plan.is_some() {
        manager.quiesce_process(REMAPD_UNIT)?;
    }
    if previous.is_some() && socket_reservation.is_none() {
        *socket_reservation = reserve_rollback_namespace(manager)?;
    }
    Ok(())
}

async fn invalidate_pending_after_reload(
    manager: &SystemdManager,
    record: &InstallRecord,
    previous: &InstallRecord,
    socket_reservation: &mut Option<crate::socket_preflight::SocketReservation>,
) -> io::Result<()> {
    let Some(identity) = record.pending_resolver_plan else {
        return Ok(());
    };
    let mut runtime_lease = Some(crate::runtime_authority::acquire(previous.current.id)?);
    let result = async {
        start_daemon_transaction(manager, socket_reservation)?;
        ensure_daemon_channel(manager, &record.current).await?;
        invalidate_plan_identity(record.current.daemon_uid, identity).await
    }
    .await;
    drop(runtime_lease.take());
    retain_rollback_namespace(manager, previous.current.id, socket_reservation);
    result
}
