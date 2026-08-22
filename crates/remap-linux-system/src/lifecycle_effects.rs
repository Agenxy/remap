use std::io;
use std::path::PathBuf;

use remap_linux::ActivationPhase;

use crate::install_model::{DirectoryProvenance, Generation, InstallPhase, InstallRecord};
use crate::lifecycle_contract::{Operation, PublicationEffect, StateSnapshot};
use crate::lifecycle_names::{
    phase as phase_name, rollback_step as rollback_step_name, uninstall_step as uninstall_step_name,
};
use crate::lifecycle_recovery::required_service_inactive;
use crate::publications;

pub(crate) fn install(
    operation: Operation,
    generation: &Generation,
    previous: Option<&InstallRecord>,
    publication_count: usize,
) -> Vec<String> {
    let mut effects = vec![
        format!(
            "stage {} immutable root-owned artifacts",
            generation.artifacts.len()
        ),
        format!(
            "{} {publication_count} owned publication paths",
            operation.as_str()
        ),
        runtime_effect(operation).to_owned(),
        format!(
            "activate resolver link {} with exact reversible state",
            generation.link
        ),
        "publish a root-authenticated private upstream plan to remapd".to_owned(),
    ];
    if operation == Operation::Install {
        let mut directories = generation
            .public_directories
            .iter()
            .filter(|directory| directory.provenance == DirectoryProvenance::CreatedByRemap)
            .map(|directory| PathBuf::from(&directory.path))
            .collect::<Vec<_>>();
        directories.sort_by_key(|path| (path.components().count(), path.clone()));
        effects.extend(
            directories
                .into_iter()
                .map(|path| format!("create owned public directory {}", path.display())),
        );
    }
    if previous.and_then(|value| value.previous.as_ref()).is_some() {
        effects.push("prune the oldest verified immutable generation".to_owned());
    }
    effects
}

pub(crate) fn update_publications(
    previous: &Generation,
    current: &Generation,
    previous_id: Option<&str>,
    current_id: &str,
) -> Vec<PublicationEffect> {
    let mut effects = Vec::new();
    for (action, changes) in [
        (
            "create",
            publications::public_link_additions(previous, current),
        ),
        (
            "remove",
            publications::public_link_removals(previous, current),
        ),
    ] {
        effects.extend(
            changes
                .into_iter()
                .map(|(path, _target)| PublicationEffect {
                    action,
                    path: path.to_string_lossy().into_owned(),
                    previous_generation_id: previous_id.map(str::to_owned),
                    next_generation_id: Some(current_id.to_owned()),
                }),
        );
    }
    effects.sort_by(|left, right| left.path.cmp(&right.path));
    effects
}

const fn runtime_effect(operation: Operation) -> &'static str {
    match operation {
        Operation::Install => {
            "publish and start three socket units, remapd, and the resolver supervisor"
        }
        Operation::Update => {
            "quiesce the owned runtime, stop and reserve three listeners, then start the updated socket units, remapd, and resolver supervisor"
        }
        Operation::Uninstall | Operation::Recover => {
            "reject an invalid install lifecycle effect operation"
        }
    }
}

pub(crate) fn uninstall(
    record: &InstallRecord,
    publication_count: usize,
) -> io::Result<Vec<String>> {
    let generation_count = usize::from(record.previous.is_some()) + 1;
    let mut effects = vec![
        format!(
            "restore exact prior resolver state for link {}",
            record.current.link
        ),
        "stop the owned runtime and remove five unit definitions and five target-wants links"
            .to_owned(),
        format!("remove {publication_count} exact owned publication paths"),
        format!("remove {generation_count} verified immutable generations"),
        "remove empty root-owned Remap state directories".to_owned(),
    ];
    effects.extend(
        publications::removable_public_directories(&record.current)?
            .into_iter()
            .map(|path| format!("remove owned public directory {}", path.display())),
    );
    Ok(effects)
}

pub(crate) fn recovery(record: Option<&InstallRecord>, snapshot: &StateSnapshot) -> Vec<String> {
    let mut effects = transaction_recovery(record, snapshot);
    for residue in &snapshot.bootstrap_residues {
        if let Some(helper) = &residue.helper {
            effects.push(format!("remove verified bootstrap helper {}", helper.path));
        }
        effects.push(format!(
            "remove verified bootstrap directory {}",
            residue.directory.path
        ));
    }
    if let Some(residue) = &snapshot.state_residue {
        if record.is_some() && residue.requires_resolver_quiescence() {
            effects.push("stop the owned resolver unit while removing resolver state".to_owned());
            effects.push("restart and verify the owned resolver unit".to_owned());
        }
        effects.push(format!(
            "remove verified interrupted lifecycle state from {}",
            residue.directory()
        ));
    }
    effects
}

fn transaction_recovery(record: Option<&InstallRecord>, snapshot: &StateSnapshot) -> Vec<String> {
    let Some(value) = record else {
        return if snapshot.activation_phase.is_some() {
            vec![
                "restore orphaned exact prior resolver state".to_owned(),
                "remove the verified orphaned activation record".to_owned(),
            ]
        } else {
            Vec::new()
        };
    };
    match value.phase {
        InstallPhase::Staging | InstallPhase::Staged | InstallPhase::Published => vec![format!(
            "roll back interrupted {} generation {}",
            phase_name(value.phase),
            value.current.id
        )],
        InstallPhase::RollingBack(step) => vec![format!(
            "resume verified rollback at next effect {}",
            rollback_step_name(step)
        )],
        InstallPhase::Pruning => vec![format!(
            "finish pruning and activate accepted generation {}",
            value.current.id
        )],
        InstallPhase::Uninstalling(step) => vec![format!(
            "resume verified uninstall at next effect {}",
            uninstall_step_name(step)
        )],
        InstallPhase::Active if active_runtime_requires_recovery(snapshot) => vec![
            format!(
                "recover exact resolver ownership for link {}",
                value.current.link
            ),
            "restart and verify only the owned daemon, socket, and resolver units".to_owned(),
        ],
        InstallPhase::Active => Vec::new(),
    }
}

fn active_runtime_requires_recovery(snapshot: &StateSnapshot) -> bool {
    required_service_inactive(&snapshot.services)
        || !snapshot.activation_state_valid
        || !snapshot.daemon_plan_valid
        || snapshot.activation_phase != Some(ActivationPhase::Active)
}

#[cfg(test)]
mod tests {
    use crate::lifecycle_contract::Operation;

    #[test]
    fn install_and_update_disclose_distinct_runtime_effects() {
        assert_ne!(
            super::runtime_effect(Operation::Install),
            super::runtime_effect(Operation::Update)
        );
        assert!(super::runtime_effect(Operation::Update).contains("stop and reserve three"));
    }
}
