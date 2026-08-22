use std::io;
use std::path::Path;

use crate::install_model::{Generation, InstallRecord, ResolverPlanIdentity};
use crate::installer::{
    REMAPD_UNIT, RESOLVER_UNIT, SOCKET_UNITS, STATE_DIRECTORY, conflict, platform_error,
    unit_names, verify_active,
};
use crate::manager::SystemdManager;
use crate::resolver_acceptance::{
    current_plan_identity, invalidate_plan_identity, wait_for_daemon, wait_for_health,
};

const LISTENER_HANDOFF_RETRY: std::time::Duration = std::time::Duration::from_millis(25);

pub(crate) async fn ensure_daemon_channel(
    manager: &SystemdManager,
    generation: &Generation,
) -> io::Result<()> {
    if manager.observed_state(REMAPD_UNIT)? != "active" {
        manager.start(REMAPD_UNIT)?;
    }
    wait_for_daemon(generation.daemon_uid).await
}

pub(crate) fn stop_owned_units(manager: &SystemdManager) -> io::Result<()> {
    for unit in unit_names() {
        if !matches!(
            manager.observed_state(&unit)?.as_str(),
            "inactive" | "not_found"
        ) {
            manager.stop(&unit)?;
        }
        if !matches!(
            manager.observed_state(&unit)?.as_str(),
            "inactive" | "not_found"
        ) {
            return Err(conflict("an owned systemd unit did not stop"));
        }
    }
    Ok(())
}

pub(crate) fn prepare_update_cutover(
    manager: &SystemdManager,
    reservation: &mut Option<crate::socket_preflight::SocketReservation>,
) -> io::Result<()> {
    quiesce_runtime(manager)?;
    for socket in SOCKET_UNITS {
        if !matches!(
            manager.observed_state(socket)?.as_str(),
            "inactive" | "not_found"
        ) {
            manager.stop(socket)?;
        }
        crate::socket_preflight::ensure_unit_reserved(reservation, socket)?;
    }
    verify_rollback_namespace(manager, reservation.as_ref())
}

pub(crate) fn reserve_rollback_namespace(
    manager: &SystemdManager,
) -> io::Result<Option<crate::socket_preflight::SocketReservation>> {
    let mut reservation = None;
    retain_rollback_reservations(manager, &mut reservation)?;
    Ok(reservation)
}

pub(crate) fn retain_rollback_reservations(
    manager: &SystemdManager,
    reservation: &mut Option<crate::socket_preflight::SocketReservation>,
) -> io::Result<()> {
    quiesce_runtime(manager)?;
    for socket in SOCKET_UNITS {
        if manager.observed_state(socket)? != "active" {
            crate::socket_preflight::ensure_unit_reserved(reservation, socket)?;
        }
    }
    verify_rollback_namespace(manager, reservation.as_ref())
}

fn quiesce_runtime(manager: &SystemdManager) -> io::Result<()> {
    stop_unit_strict(manager, RESOLVER_UNIT)?;
    manager.quiesce_process(REMAPD_UNIT)
}

fn verify_rollback_namespace(
    manager: &SystemdManager,
    reservation: Option<&crate::socket_preflight::SocketReservation>,
) -> io::Result<()> {
    for socket in SOCKET_UNITS {
        let reserved = reservation
            .map(|value| value.covers_unit(socket))
            .transpose()?
            .unwrap_or(false);
        if manager.observed_state(socket)? == "active" || reserved {
            continue;
        }
        return Err(conflict(
            "an update rollback listener is neither active nor exactly reserved",
        ));
    }
    Ok(())
}

pub(crate) fn start_daemon_transaction(
    manager: &SystemdManager,
    reservation: &mut Option<crate::socket_preflight::SocketReservation>,
) -> io::Result<()> {
    prepare_daemon_transaction(manager)?;
    start_prepared_daemon_transaction(manager, reservation)
}

pub(crate) fn prepare_daemon_transaction(manager: &SystemdManager) -> io::Result<()> {
    manager.prepare_start_transaction(REMAPD_UNIT, &SOCKET_UNITS)
}

pub(crate) fn start_prepared_daemon_transaction(
    manager: &SystemdManager,
    reservation: &mut Option<crate::socket_preflight::SocketReservation>,
) -> io::Result<()> {
    drop(reservation.take());
    manager.start_prepared_transaction(REMAPD_UNIT, &SOCKET_UNITS)
}

pub(crate) fn retain_rollback_namespace(
    manager: &SystemdManager,
    generation: uuid::Uuid,
    reservation: &mut Option<crate::socket_preflight::SocketReservation>,
) {
    while activate_rollback_listeners(manager, generation, reservation).is_err() {
        std::thread::sleep(LISTENER_HANDOFF_RETRY);
    }
}

pub(crate) fn activate_rollback_listeners(
    manager: &SystemdManager,
    generation: uuid::Uuid,
    reservation: &mut Option<crate::socket_preflight::SocketReservation>,
) -> io::Result<()> {
    retain_rollback_reservations(manager, reservation)?;
    let runtime_lease = crate::runtime_authority::acquire(generation)?;
    for socket in SOCKET_UNITS {
        if manager.observed_state(socket)? == "active" {
            continue;
        }
        crate::socket_preflight::ensure_unit_reserved(reservation, socket)?;
        manager.prepare_start_transaction(socket, &[])?;
        reservation
            .as_mut()
            .ok_or_else(|| conflict("a rollback listener lost its exact reservation"))?
            .release_unit(socket)?;
        if let Err(error) = manager.start_prepared_transaction(socket, &[]) {
            loop {
                match crate::socket_preflight::reserve_units(&[socket]) {
                    Ok(replacement) => {
                        reservation
                            .as_mut()
                            .ok_or_else(|| {
                                conflict("a rollback listener lost its reservation holder")
                            })?
                            .merge(replacement)?;
                        break;
                    }
                    Err(_error) => std::thread::sleep(LISTENER_HANDOFF_RETRY),
                }
            }
            return Err(error);
        }
    }
    *reservation = None;
    drop(runtime_lease);
    quiesce_runtime(manager)?;
    for socket in SOCKET_UNITS {
        manager.require_settled_active(socket)?;
    }
    Ok(())
}

fn stop_unit_strict(manager: &SystemdManager, unit: &str) -> io::Result<()> {
    if !matches!(
        manager.observed_state(unit)?.as_str(),
        "inactive" | "not_found"
    ) {
        manager.stop(unit)?;
    }
    if matches!(
        manager.observed_state(unit)?.as_str(),
        "inactive" | "not_found"
    ) {
        Ok(())
    } else {
        Err(conflict("an owned systemd unit did not stop"))
    }
}

pub(crate) fn stop_resolver_if_active(manager: &SystemdManager) -> io::Result<()> {
    if manager.observed_state(RESOLVER_UNIT)? == "active" {
        manager.stop(RESOLVER_UNIT)?;
    }
    Ok(())
}

pub(crate) async fn ensure_active_services(
    manager: &SystemdManager,
    record: &InstallRecord,
) -> io::Result<()> {
    ensure_service_health(manager, &record.current).await?;
    verify_active(record)
}

pub(crate) async fn ensure_service_health(
    manager: &SystemdManager,
    generation: &Generation,
) -> io::Result<()> {
    let daemon_active = manager.observed_state(REMAPD_UNIT)? == "active";
    let (observed, plan) = if daemon_active {
        match current_plan_identity(generation.daemon_uid).await {
            Ok(plan) => (true, plan),
            Err(_error) => (false, None),
        }
    } else {
        (false, None)
    };
    let mut resolver_authority = None;
    ensure_service_health_with_plan(manager, generation, &mut resolver_authority, observed, plan)
        .await
}

pub(crate) async fn ensure_service_health_with_plan(
    manager: &SystemdManager,
    generation: &Generation,
    resolver_authority: &mut Option<remap_linux::RootRecordStore>,
    daemon_plan_observed: bool,
    daemon_plan_identity: Option<ResolverPlanIdentity>,
) -> io::Result<()> {
    start_sockets(manager)?;
    let activation = activation_record()?;
    let expected = activation
        .filter(|(phase, _identity)| *phase == remap_linux::ActivationPhase::Active)
        .map(|(_phase, identity)| identity);
    let daemon_active = manager.observed_state(REMAPD_UNIT)? == "active";
    if daemon_plan_observed
        && (!daemon_active
            || current_plan_identity(generation.daemon_uid).await? != daemon_plan_identity)
    {
        return Err(conflict(
            "the daemon resolver plan changed after lifecycle authorization",
        ));
    }
    if daemon_plan_observed && daemon_plan_identity == expected && expected.is_some() {
        drop(resolver_authority.take());
        if manager.observed_state(RESOLVER_UNIT)? != "active" {
            manager.start(RESOLVER_UNIT)?;
        }
        return accept_resolver_health(manager, generation.daemon_uid).await;
    }

    stop_resolver_if_active(manager)?;
    if daemon_plan_observed && let Some(identity) = daemon_plan_identity {
        invalidate_plan_identity(generation.daemon_uid, identity).await?;
    }
    if daemon_active {
        manager.stop(REMAPD_UNIT)?;
    }
    manager.start(REMAPD_UNIT)?;
    wait_for_daemon(generation.daemon_uid).await?;
    if current_plan_identity(generation.daemon_uid)
        .await?
        .is_some()
    {
        return Err(conflict(
            "the restarted daemon retained an unexpected resolver plan",
        ));
    }
    if activation.is_none() {
        return Err(conflict(
            "the active installation has no resolver transaction to recover",
        ));
    }
    drop(resolver_authority.take());
    manager.start(RESOLVER_UNIT)?;
    accept_resolver_health(manager, generation.daemon_uid).await
}

async fn accept_resolver_health(manager: &SystemdManager, daemon_uid: u32) -> io::Result<()> {
    let result = async {
        wait_for_health(daemon_uid).await?;
        manager
            .require_settled_active(RESOLVER_UNIT)
            .map_err(|_error| conflict("the resolver supervisor exited after publishing its plan"))
    }
    .await;
    if result.is_err() {
        manager.quiesce_failed_start(RESOLVER_UNIT);
    }
    result
}

fn start_sockets(manager: &SystemdManager) -> io::Result<()> {
    for socket in SOCKET_UNITS {
        if manager.observed_state(socket)? != "active" {
            manager.start(socket)?;
        }
    }
    Ok(())
}

fn activation_record() -> io::Result<Option<(remap_linux::ActivationPhase, ResolverPlanIdentity)>> {
    remap_linux::RootRecordStore::inspect(Path::new(STATE_DIRECTORY))
        .map_err(platform_error)
        .map(|record| {
            record.map(|record| {
                (
                    record.phase(),
                    ResolverPlanIdentity {
                        activation_id: record.metadata().activation_id(),
                        generation: record.metadata().generation(),
                    },
                )
            })
        })
}
