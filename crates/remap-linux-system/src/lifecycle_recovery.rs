use std::io;

use remap_linux::{ActivationPhase, ActivationRecord};

use crate::bootstrap_recovery::BootstrapResidue;
use crate::cleanup::StateResidue;
use crate::install_model::{InstallPhase, InstallRecord};
use crate::installer::{REMAPD_UNIT, RESOLVER_UNIT, SOCKET_UNITS};
use crate::lifecycle_contract::{ServiceStatus, StateSnapshot};

const MAX_INTEGRITY_DETAIL_BYTES: usize = 256;

pub(crate) fn active_integrity_conflict(record: Option<&InstallRecord>) -> io::Error {
    let detail = record
        .and_then(|value| crate::installer::verify_active(value).err())
        .map(|error| error.to_string());
    integrity_conflict_from_detail(detail.as_deref())
}

fn integrity_conflict_from_detail(detail: Option<&str>) -> io::Error {
    let message = detail
        .filter(|value| !value.is_empty() && value.len() <= MAX_INTEGRITY_DETAIL_BYTES)
        .map_or_else(
            || "the active Linux installation changed during exact integrity inspection".to_owned(),
            |value| format!("the active Linux installation failed exact integrity: {value}"),
        );
    io::Error::new(io::ErrorKind::AlreadyExists, message)
}

pub(crate) fn status_required(
    record: Option<&InstallRecord>,
    activation: Option<&ActivationRecord>,
    services: &[ServiceStatus],
    bootstrap_residues: &[BootstrapResidue],
    state_residue: Option<&StateResidue>,
) -> bool {
    record.is_some_and(|value| value.phase != InstallPhase::Active)
        || activation.is_some_and(|value| value.phase() != ActivationPhase::Active)
        || (record.is_some() && activation.is_none())
        || record.is_some_and(|_value| required_service_inactive(services))
        || (record.is_none() && activation.is_some())
        || !bootstrap_residues.is_empty()
        || state_residue.is_some()
        || (record.is_none() && services.iter().any(|service| service.state != "not_found"))
}

pub(crate) fn snapshot_required(snapshot: &StateSnapshot) -> bool {
    snapshot
        .install_record
        .as_ref()
        .is_some_and(|value| value.phase != InstallPhase::Active)
        || snapshot.active_integrity_valid == Some(false)
        || !snapshot.daemon_plan_valid
        || !snapshot.activation_state_valid
        || snapshot
            .activation_phase
            .is_some_and(|phase| phase != ActivationPhase::Active)
        || snapshot
            .install_record
            .as_ref()
            .is_some_and(|_value| required_service_inactive(&snapshot.services))
        || (snapshot.install_record.is_none() && snapshot.activation_phase.is_some())
        || (snapshot.install_record.is_some() && snapshot.activation_phase.is_none())
        || !snapshot.bootstrap_residues.is_empty()
        || snapshot.state_residue.is_some()
        || unowned_runtime_namespace(snapshot)
        || unowned_publication_namespace(snapshot)
}

pub(crate) fn needs_resolver_authority(snapshot: &StateSnapshot) -> bool {
    snapshot
        .install_record
        .as_ref()
        .is_some_and(|record| record.phase != InstallPhase::Active)
        || !snapshot.activation_state_valid
        || !snapshot.daemon_plan_valid
        || snapshot
            .activation_phase
            .is_some_and(|phase| phase != ActivationPhase::Active)
        || (snapshot.install_record.is_none() && snapshot.activation_phase.is_some())
        || (snapshot.install_record.is_some() && snapshot.activation_phase.is_none())
        || snapshot
            .state_residue
            .as_ref()
            .is_some_and(StateResidue::requires_resolver_quiescence)
        || snapshot.services.iter().any(|service| {
            matches!(service.unit.as_str(), RESOLVER_UNIT | REMAPD_UNIT)
                && service.state != "active"
        })
}

pub(crate) fn permits_missing_activation(record: &InstallRecord) -> bool {
    matches!(record.phase, InstallPhase::Uninstalling(_))
        || (record.previous.is_none()
            && matches!(
                record.phase,
                InstallPhase::Staging
                    | InstallPhase::Staged
                    | InstallPhase::Published
                    | InstallPhase::RollingBack(_)
            ))
}

pub(crate) fn missing_activation_blocks(record: &InstallRecord, activation_present: bool) -> bool {
    !activation_present && !permits_missing_activation(record)
}

pub(crate) fn required_service_inactive(services: &[ServiceStatus]) -> bool {
    services.iter().any(|service| {
        (SOCKET_UNITS.contains(&service.unit.as_str())
            || matches!(service.unit.as_str(), RESOLVER_UNIT | REMAPD_UNIT))
            && service.state != "active"
    })
}

pub(crate) fn unowned_runtime_namespace(snapshot: &StateSnapshot) -> bool {
    snapshot.install_record.is_none()
        && snapshot
            .services
            .iter()
            .any(|service| service.state != "not_found")
}

pub(crate) fn unowned_publication_namespace(snapshot: &StateSnapshot) -> bool {
    snapshot.install_record.is_none()
        && snapshot
            .publications
            .iter()
            .any(|publication| !publication.is_absent())
}

pub(crate) async fn observe_daemon_plan(
    record: Option<&InstallRecord>,
    services: &[ServiceStatus],
) -> (bool, Option<crate::install_model::ResolverPlanIdentity>) {
    let Some(record) = record else {
        return (true, None);
    };
    let daemon_active = services
        .iter()
        .any(|service| service.unit == REMAPD_UNIT && service.state == "active");
    if !daemon_active {
        return (false, None);
    }
    match crate::resolver_acceptance::current_plan_identity(record.current.daemon_uid).await {
        Ok(identity) => (true, identity),
        Err(_error) => (false, None),
    }
}

pub(crate) fn daemon_plan_matches_activation(
    record: Option<&InstallRecord>,
    activation: Option<&remap_linux::ActivationRecord>,
    observed: bool,
    daemon_plan: Option<crate::install_model::ResolverPlanIdentity>,
) -> bool {
    let Some(record) = record else {
        return true;
    };
    if record.phase != InstallPhase::Active {
        return true;
    }
    let expected = activation.map(|value| crate::install_model::ResolverPlanIdentity {
        activation_id: value.metadata().activation_id(),
        generation: value.metadata().generation(),
    });
    observed && daemon_plan == expected
}

#[cfg(test)]
mod tests {
    use crate::install_model::{InstallPhase, RollbackStep, UninstallStep};

    use super::{
        active_integrity_conflict, integrity_conflict_from_detail, missing_activation_blocks,
        permits_missing_activation,
    };

    #[test]
    fn active_integrity_diagnostic_is_specific_and_bounded() {
        let exact = integrity_conflict_from_detail(Some(
            "a Remap-created public directory has unsafe extended attributes",
        ));
        assert_eq!(exact.kind(), std::io::ErrorKind::AlreadyExists);
        assert!(exact.to_string().contains("unsafe extended attributes"));

        let oversized = "x".repeat(super::MAX_INTEGRITY_DETAIL_BYTES + 1);
        let bounded = integrity_conflict_from_detail(Some(&oversized));
        assert!(!bounded.to_string().contains(&oversized));
        assert!(bounded.to_string().len() < 128);

        let missing = active_integrity_conflict(None);
        assert_eq!(missing.kind(), std::io::ErrorKind::AlreadyExists);
        assert!(
            missing
                .to_string()
                .contains("changed during exact integrity")
        );
    }

    #[test]
    fn only_replayable_phases_permit_missing_activation() {
        let mut first = crate::install_model::tests::sample_record();
        first.previous = None;
        for phase in [
            InstallPhase::Staging,
            InstallPhase::Staged,
            InstallPhase::Published,
        ] {
            first.phase = phase;
            assert!(permits_missing_activation(&first));
            assert!(!missing_activation_blocks(&first, false));
        }
        for step in RollbackStep::ALL {
            first.phase = InstallPhase::RollingBack(step);
            assert!(permits_missing_activation(&first));
            assert!(!missing_activation_blocks(&first, false));
        }
        for step in UninstallStep::ALL {
            first.phase = InstallPhase::Uninstalling(step);
            assert!(permits_missing_activation(&first));
            assert!(!missing_activation_blocks(&first, false));
        }
        first.phase = InstallPhase::Active;
        assert!(!permits_missing_activation(&first));
        assert!(missing_activation_blocks(&first, false));
        first.phase = InstallPhase::Pruning;
        assert!(!permits_missing_activation(&first));
        assert!(missing_activation_blocks(&first, false));
        assert!(!missing_activation_blocks(&first, true));

        let mut update = crate::install_model::tests::sample_record();
        for step in RollbackStep::ALL {
            update.phase = InstallPhase::RollingBack(step);
            assert!(!permits_missing_activation(&update));
        }
        for step in UninstallStep::ALL {
            update.phase = InstallPhase::Uninstalling(step);
            assert!(permits_missing_activation(&update));
        }
    }
}
