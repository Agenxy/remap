use std::io;
use std::path::{Path, PathBuf};

use remap_linux::{
    ActivationPhase, ResolverEnvironment, ResolverLinkInspection, RootRecordStore, SystemdResolved,
};
use serde::{Deserialize, Serialize};

use crate::bootstrap_recovery::{self, BootstrapResidue};
use crate::cleanup::{self, StateResidue};
use crate::generation;
use crate::generation::PreparedArtifact;
use crate::install_model::{Generation, InstallPhase, InstallRecord};
use crate::installer::{
    InstallRequest, RESOLVER_UNIT, inspect_install_record, unit_names, verify_active,
};
use crate::lifecycle_approval::{digest, hex, plan_token, recovery_token, require_token};
use crate::lifecycle_names::{
    environment as environment_name, manager as manager_name, phase as phase_name,
    selection_state as selection_state_name,
};
use crate::lifecycle_observation::{Distribution, PathState, distribution, path_state};
use crate::lifecycle_recovery::{
    daemon_plan_matches_activation, missing_activation_blocks,
    needs_resolver_authority as recovery_needs_resolver_authority, observe_daemon_plan,
    snapshot_required as snapshot_recovery_required, status_required as recovery_required,
    unowned_publication_namespace, unowned_runtime_namespace,
};
use crate::manager::SystemdManager;
use crate::publications;

const MAX_OUTPUT_BYTES: usize = 64 * 1024;
const RESOLVER_RECORD_DIRECTORY: &str = "/var/lib/remap-system";
pub(crate) const LEGACY_UPDATE_ERROR: &str = "the installed Linux resolver generation predates safe transactional updates; uninstall and reinstall Remap";

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Operation {
    Install,
    Update,
    Uninstall,
    Recover,
}

impl Operation {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Update => "update",
            Self::Uninstall => "uninstall",
            Self::Recover => "recover",
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ServiceStatus {
    pub(crate) unit: String,
    pub(crate) state: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LinkCandidate {
    link_index: u32,
    interface_name: String,
    backend: String,
    selection_state: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StatusData {
    schema_version: u8,
    #[serde(rename = "activeGenerationID")]
    active_generation_id: Option<String>,
    #[serde(rename = "previousGenerationID")]
    previous_generation_id: Option<String>,
    link_index: Option<u32>,
    #[serde(rename = "ownerUID")]
    owner_uid: Option<u32>,
    recovery_required: bool,
    installation_state: &'static str,
    distribution: Distribution,
    resolver_environment: &'static str,
    interface_name: Option<String>,
    backend: Option<String>,
    services: Vec<ServiceStatus>,
    link_candidates: Vec<LinkCandidate>,
    state_residue: Option<StateResidue>,
    hint: Option<&'static str>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PublicationEffect {
    pub(crate) action: &'static str,
    pub(crate) path: String,
    #[serde(rename = "previousGenerationID")]
    pub(crate) previous_generation_id: Option<String>,
    #[serde(rename = "nextGenerationID")]
    pub(crate) next_generation_id: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PreviewData {
    schema_version: u8,
    operation: Operation,
    #[serde(rename = "generationID")]
    generation_id: Option<String>,
    #[serde(rename = "previousGenerationID")]
    previous_generation_id: Option<String>,
    #[serde(rename = "sourceManifestSHA256")]
    source_manifest_sha256: Option<String>,
    link_index: Option<u32>,
    interface_name: Option<String>,
    backend: Option<String>,
    resolver_environment: &'static str,
    publications: Vec<PublicationEffect>,
    effects: Vec<String>,
    has_effects: bool,
    approval_token: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RecoveryPreviewData {
    schema_version: u8,
    installation_phase: Option<&'static str>,
    #[serde(rename = "generationID")]
    generation_id: Option<String>,
    bootstrap_residues: Vec<BootstrapResidue>,
    state_residue: Option<StateResidue>,
    effects: Vec<String>,
    has_effects: bool,
    approval_token: String,
}

#[derive(Debug)]
pub(crate) struct PreparedPlan {
    pub(crate) preview: PreviewData,
    pub(crate) generation: Option<Generation>,
    pub(crate) artifacts: Option<Vec<PreparedArtifact>>,
    pub(crate) activation_record_digest: Option<[u8; 32]>,
    pub(crate) daemon_plan_identity: Option<crate::install_model::ResolverPlanIdentity>,
    pub(crate) daemon_plan_observed: bool,
    pub(crate) socket_reservation: Option<crate::socket_preflight::SocketReservation>,
    state_digest: [u8; 32],
}

#[derive(Debug)]
pub(crate) struct PreparedRecovery {
    pub(crate) preview: RecoveryPreviewData,
    pub(crate) bootstrap_residues: Vec<BootstrapResidue>,
    pub(crate) state_residue: Option<StateResidue>,
    pub(crate) daemon_plan_identity: Option<crate::install_model::ResolverPlanIdentity>,
    pub(crate) daemon_plan_observed: bool,
    pub(crate) publication_repairs: Vec<(PathBuf, PathBuf)>,
    resolver_authority_required: bool,
    state_digest: [u8; 32],
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct SnapshotNormalization {
    pub(crate) fresh_state_created: bool,
    pub(crate) resolver_quiesced: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StateSnapshot {
    pub(crate) install_record: Option<InstallRecord>,
    pub(crate) active_integrity_valid: Option<bool>,
    pub(crate) publications: Vec<PathState>,
    pub(crate) services: Vec<ServiceStatus>,
    pub(crate) resolver_environment: &'static str,
    pub(crate) selected_link: Option<ResolverLinkInspection>,
    pub(crate) effective_link_digest: Option<[u8; 32]>,
    pub(crate) activation_state_valid: bool,
    pub(crate) activation_record_digest: Option<[u8; 32]>,
    pub(crate) activation_phase: Option<ActivationPhase>,
    pub(crate) daemon_plan_observed: bool,
    pub(crate) daemon_plan_identity: Option<crate::install_model::ResolverPlanIdentity>,
    pub(crate) daemon_plan_valid: bool,
    pub(crate) bootstrap_residues: Vec<BootstrapResidue>,
    pub(crate) state_residue: Option<StateResidue>,
}

pub(crate) async fn status(
    explicit_link: Option<remap_linux::LinkIndex>,
) -> io::Result<StatusData> {
    require_root()?;
    let record = inspect_install_record()?;
    let resolver_record =
        RootRecordStore::inspect(Path::new(RESOLVER_RECORD_DIRECTORY)).map_err(platform_error)?;
    let selected = explicit_link.or_else(|| {
        record
            .as_ref()
            .and_then(|value| remap_linux::LinkIndex::new(value.current.link).ok())
            .or_else(|| resolver_record.as_ref().map(|value| value.owned().link()))
    });
    let environment = ResolverEnvironment::detect();
    let inspection = selected
        .map(SystemdResolved::inspect)
        .transpose()
        .map_err(platform_error)?;
    let candidates = if selected.is_none() {
        SystemdResolved::candidates()
            .map_err(platform_error)?
            .into_iter()
            .map(|value| candidate(&value))
            .collect()
    } else {
        Vec::new()
    };
    let manager = SystemdManager::connect()?;
    let services = service_states(&manager)?;
    let (daemon_plan_observed, daemon_plan_identity) =
        observe_daemon_plan(record.as_ref(), &services).await;
    let daemon_plan_valid = daemon_plan_matches_activation(
        record.as_ref(),
        resolver_record.as_ref(),
        daemon_plan_observed,
        daemon_plan_identity,
    );
    let bootstrap_residues = bootstrap_recovery::inspect()?;
    let state_residue = cleanup::inspect_state_residue(Path::new(RESOLVER_RECORD_DIRECTORY))?;
    let (recovery_required, recovery_hint) = classify_status(
        record.as_ref(),
        resolver_record.as_ref(),
        &services,
        &bootstrap_residues,
        state_residue.as_ref(),
        daemon_plan_valid,
    )?;
    let installation_state = match (&record, recovery_required) {
        (None, false) => "absent",
        (Some(value), false) if value.phase == InstallPhase::Active => "active",
        (None | Some(_), true) | (Some(_), false) => "recovery_required",
    };
    let link_hint = link_selection_hint(selected.is_some(), recovery_required, &candidates);
    let current_link_exact = record.as_ref().is_some_and(|value| {
        crate::system_publication::verify_current_link(value.current.id).is_ok()
    });
    let accepted = accepted_generation(record.as_ref(), current_link_exact);
    Ok(StatusData {
        schema_version: 1,
        active_generation_id: accepted.map(|value| value.id.to_string()),
        previous_generation_id: record
            .as_ref()
            .and_then(|value| value.previous.as_ref())
            .map(|value| value.id.to_string()),
        link_index: selected.map(remap_linux::LinkIndex::get),
        owner_uid: accepted.map(|value| value.owner_uid),
        recovery_required,
        installation_state,
        distribution: distribution()?,
        resolver_environment: environment_name(environment),
        interface_name: inspection
            .as_ref()
            .map(|value| value.interface_name().to_owned()),
        backend: inspection
            .as_ref()
            .map(|value| manager_name(value.manager())),
        services,
        link_candidates: candidates,
        state_residue,
        hint: recovery_hint.or(link_hint),
    })
}

fn accepted_generation(
    record: Option<&InstallRecord>,
    current_link_exact: bool,
) -> Option<&Generation> {
    record
        .filter(|value| {
            current_link_exact
                && matches!(value.phase, InstallPhase::Active | InstallPhase::Pruning)
        })
        .map(|value| &value.current)
}

fn link_selection_hint(
    selected: bool,
    recovery_required: bool,
    candidates: &[LinkCandidate],
) -> Option<&'static str> {
    if selected || recovery_required {
        return None;
    }
    let primary_count = candidates
        .iter()
        .filter(|candidate| candidate.selection_state == "supported_primary")
        .count();
    Some(match primary_count {
        0 => {
            "no supported primary interface is available; inspect link candidates and resolver ownership"
        }
        1 => "the only supported primary interface will be selected automatically",
        _ => "select one supported primary interface with REMAP_LINUX_LINK=<index> make install",
    })
}

fn classify_status(
    record: Option<&InstallRecord>,
    activation: Option<&remap_linux::ActivationRecord>,
    services: &[ServiceStatus],
    bootstrap_residues: &[BootstrapResidue],
    state_residue: Option<&StateResidue>,
    daemon_plan_valid: bool,
) -> io::Result<(bool, Option<&'static str>)> {
    let publication_residue = record.is_none() && publication_namespace_occupied()?;
    let active_integrity_invalid = record
        .is_some_and(|value| value.phase == InstallPhase::Active && verify_active(value).is_err());
    let activation_state_invalid = activation
        .map(|value| {
            SystemdResolved::observe(value.owned().link())
                .map(|observed| observed != *value.owned())
                .map_err(platform_error)
        })
        .transpose()?
        .unwrap_or(false);
    let missing_authority =
        record.is_some_and(|value| missing_activation_blocks(value, activation.is_some()));
    let orphaned_authority = record.is_none() && activation.is_some();
    let unowned_runtime =
        record.is_none() && services.iter().any(|service| service.state != "not_found");
    let other_recovery_required = recovery_required(
        record,
        activation,
        services,
        bootstrap_residues,
        state_residue,
    ) || publication_residue
        || activation_state_invalid
        || !daemon_plan_valid;
    let other_blocked =
        publication_residue || unowned_runtime || missing_authority || orphaned_authority;
    Ok(classify_status_observation(
        active_integrity_invalid,
        other_recovery_required,
        other_blocked,
    ))
}

fn classify_status_observation(
    active_integrity_invalid: bool,
    other_recovery_required: bool,
    other_blocked: bool,
) -> (bool, Option<&'static str>) {
    let required = active_integrity_invalid || other_recovery_required;
    let hint = if active_integrity_invalid {
        Some("run make recover to inspect the exact blocked integrity invariant without mutation")
    } else if other_blocked {
        Some("inspect the blocked Linux ownership state before attempting lifecycle changes")
    } else if required {
        Some("run make recover to preview and approve exact recovery effects")
    } else {
        None
    };
    (required, hint)
}

pub(crate) async fn prepare_install(
    request: &InstallRequest,
    update: bool,
) -> io::Result<PreparedPlan> {
    prepare_install_with(request, update, SnapshotNormalization::default(), None).await
}

pub(crate) async fn prepare_install_locked(
    request: &InstallRequest,
    update: bool,
    normalization: SnapshotNormalization,
    socket_reservation: Option<crate::socket_preflight::SocketReservation>,
) -> io::Result<PreparedPlan> {
    prepare_install_with(request, update, normalization, socket_reservation).await
}

async fn prepare_install_with(
    request: &InstallRequest,
    update: bool,
    normalization: SnapshotNormalization,
    existing_socket_reservation: Option<crate::socket_preflight::SocketReservation>,
) -> io::Result<PreparedPlan> {
    require_root()?;
    let operation = if update {
        Operation::Update
    } else {
        Operation::Install
    };
    let (record, socket_reservation) =
        crate::lifecycle_install::prepare_authority(operation, existing_socket_reservation)?;
    require_update_capability(operation, record.as_ref())?;
    let (approved_manager, approved_interface_name) = approved_link(request.link, record.as_ref())?;
    let (generation, artifacts) = generation::prepare(
        request,
        record.as_ref().map(|value| &value.current),
        approved_manager,
        &approved_interface_name,
    )?;
    if record
        .as_ref()
        .and_then(|value| value.previous.as_ref())
        .is_some_and(|value| value.id == generation.id)
    {
        return Err(conflict(
            "the requested generation is already retained as the rollback generation",
        ));
    }
    let snapshot = snapshot(Some(request.link), record.clone(), normalization).await?;
    require_approved_link(&snapshot, approved_manager, &approved_interface_name)?;
    require_no_recovery(&snapshot)?;
    let previous = record.as_ref().map(|value| value.current.id.to_string());
    let next = generation.id.to_string();
    let no_op = update
        && record
            .as_ref()
            .is_some_and(|value| value.current == generation);
    let (publications, publication_link_count) = install_publications(
        operation,
        no_op,
        record.as_ref(),
        &generation,
        previous.as_deref(),
        &next,
    )?;
    let effects = if no_op {
        Vec::new()
    } else {
        crate::lifecycle_effects::install(
            operation,
            &generation,
            record.as_ref(),
            publication_link_count,
        )
    };
    let state_digest = digest(&snapshot)?;
    let token = plan_token(
        operation,
        Some(generation.manifest_digest),
        Some(request.source_manifest_sha256),
        state_digest,
        &effects,
        &publications,
    )?;
    Ok(PreparedPlan {
        preview: PreviewData {
            schema_version: 1,
            operation,
            generation_id: Some(generation.id.to_string()),
            previous_generation_id: previous,
            source_manifest_sha256: Some(hex(&request.source_manifest_sha256)),
            link_index: Some(request.link.get()),
            interface_name: snapshot
                .selected_link
                .as_ref()
                .map(|value| value.interface_name().to_owned()),
            backend: snapshot
                .selected_link
                .as_ref()
                .map(|value| manager_name(value.manager())),
            resolver_environment: snapshot.resolver_environment,
            publications,
            effects,
            has_effects: !no_op,
            approval_token: token,
        },
        generation: Some(generation),
        artifacts: Some(artifacts),
        activation_record_digest: snapshot.activation_record_digest,
        daemon_plan_identity: snapshot.daemon_plan_identity,
        daemon_plan_observed: snapshot.daemon_plan_observed,
        socket_reservation,
        state_digest,
    })
}

/// The publications an install or update announces, and how many of them
/// are link publications (the directory publications an install appends are
/// sorted in after that count is taken).
fn install_publications(
    operation: Operation,
    no_op: bool,
    record: Option<&InstallRecord>,
    generation: &Generation,
    previous: Option<&str>,
    next: &str,
) -> io::Result<(Vec<PublicationEffect>, usize)> {
    let mut publications = if no_op {
        Vec::new()
    } else {
        publication_effects(operation, previous, Some(next))
    };
    if let (Operation::Update, Some(installed)) = (operation, record) {
        publications.extend(crate::lifecycle_effects::update_publications(
            &installed.current,
            generation,
            previous,
            next,
        ));
    }
    let publication_link_count = publications.len();
    if operation == Operation::Install {
        publications.extend(directory_publication_effects(
            generation,
            "create",
            None,
            Some(next),
        )?);
        sort_publications(&mut publications);
    }
    Ok((publications, publication_link_count))
}

fn approved_link(
    link: remap_linux::LinkIndex,
    record: Option<&InstallRecord>,
) -> io::Result<(remap_linux::ResolverLinkManager, String)> {
    let inspection = SystemdResolved::inspect(link).map_err(platform_error)?;
    let manager = inspection.manager();
    let interface_name = inspection.interface_name().to_owned();
    if record.is_some_and(|installed| {
        (installed.current.resolver_manager.is_some()
            && installed.current.resolver_manager != Some(manager))
            || (installed.current.interface_name.is_some()
                && installed.current.interface_name.as_deref() != Some(interface_name.as_str()))
    }) {
        return Err(conflict(
            "the installed resolver link changed its approved native identity",
        ));
    }
    Ok((manager, interface_name))
}

fn require_approved_link(
    snapshot: &StateSnapshot,
    expected: remap_linux::ResolverLinkManager,
    expected_interface_name: &str,
) -> io::Result<()> {
    if snapshot.selected_link.as_ref().is_some_and(|selected| {
        selected.manager() == expected && selected.interface_name() == expected_interface_name
    }) {
        Ok(())
    } else {
        Err(conflict(
            "the selected resolver link changed native managers during preview",
        ))
    }
}

fn require_update_capability(
    operation: Operation,
    record: Option<&InstallRecord>,
) -> io::Result<()> {
    if operation == Operation::Update
        && record.is_some_and(|value| {
            value.current.resolver_rebase_capability
                != crate::install_model::RESOLVER_REBASE_CAPABILITY
        })
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            LEGACY_UPDATE_ERROR,
        ))
    } else {
        Ok(())
    }
}

pub(crate) async fn prepare_uninstall() -> io::Result<PreparedPlan> {
    prepare_uninstall_with(SnapshotNormalization::default()).await
}

pub(crate) async fn prepare_uninstall_locked(
    normalization: SnapshotNormalization,
) -> io::Result<PreparedPlan> {
    prepare_uninstall_with(normalization).await
}

async fn prepare_uninstall_with(normalization: SnapshotNormalization) -> io::Result<PreparedPlan> {
    require_root()?;
    let record = inspect_install_record()?.ok_or_else(|| conflict("Remap is not installed"))?;
    verify_active(&record)?;
    let link = remap_linux::LinkIndex::new(record.current.link).map_err(platform_error)?;
    let snapshot = snapshot(Some(link), Some(record.clone()), normalization).await?;
    require_no_recovery(&snapshot)?;
    let previous = Some(record.current.id.to_string());
    let mut publications = publication_effects(Operation::Uninstall, previous.as_deref(), None);
    publications.extend(directory_publication_effects(
        &record.current,
        "remove",
        previous.as_deref(),
        None,
    )?);
    sort_publications(&mut publications);
    let effects = crate::lifecycle_effects::uninstall(&record, publication_paths().len())?;
    let state_digest = digest(&snapshot)?;
    let token = plan_token(
        Operation::Uninstall,
        None,
        None,
        state_digest,
        &effects,
        &publications,
    )?;
    Ok(PreparedPlan {
        preview: PreviewData {
            schema_version: 1,
            operation: Operation::Uninstall,
            generation_id: None,
            previous_generation_id: previous,
            source_manifest_sha256: None,
            link_index: Some(link.get()),
            interface_name: snapshot
                .selected_link
                .as_ref()
                .map(|value| value.interface_name().to_owned()),
            backend: snapshot
                .selected_link
                .as_ref()
                .map(|value| manager_name(value.manager())),
            resolver_environment: snapshot.resolver_environment,
            publications,
            effects,
            has_effects: true,
            approval_token: token,
        },
        generation: None,
        artifacts: None,
        activation_record_digest: snapshot.activation_record_digest,
        daemon_plan_identity: snapshot.daemon_plan_identity,
        daemon_plan_observed: snapshot.daemon_plan_observed,
        socket_reservation: None,
        state_digest,
    })
}

pub(crate) async fn prepare_recovery() -> io::Result<PreparedRecovery> {
    prepare_recovery_with(SnapshotNormalization::default()).await
}

pub(crate) async fn prepare_recovery_locked(
    normalization: SnapshotNormalization,
) -> io::Result<PreparedRecovery> {
    prepare_recovery_with(normalization).await
}

async fn prepare_recovery_with(
    normalization: SnapshotNormalization,
) -> io::Result<PreparedRecovery> {
    require_root()?;
    let record = inspect_install_record()?;
    let activation =
        RootRecordStore::inspect(Path::new(RESOLVER_RECORD_DIRECTORY)).map_err(platform_error)?;
    let link = record
        .as_ref()
        .map(|value| remap_linux::LinkIndex::new(value.current.link))
        .transpose()
        .map_err(platform_error)?
        .or_else(|| activation.as_ref().map(|value| value.owned().link()));
    let snapshot = snapshot(link, record.clone(), normalization).await?;
    if !snapshot_recovery_required(&snapshot) {
        return Err(conflict("the Linux installation does not require recovery"));
    }
    let publication_repairs = if snapshot.active_integrity_valid == Some(false) {
        let installed = record
            .as_ref()
            .ok_or_else(|| crate::lifecycle_recovery::active_integrity_conflict(record.as_ref()))?;
        crate::installer::verify_active_without_public_links(installed)?;
        let missing = publications::missing_public_links(&installed.current)?;
        if missing.is_empty() {
            return Err(crate::lifecycle_recovery::active_integrity_conflict(
                record.as_ref(),
            ));
        }
        missing
    } else {
        Vec::new()
    };
    if record
        .as_ref()
        .is_some_and(|value| missing_activation_blocks(value, activation.is_some()))
    {
        return Err(conflict(
            "the active Linux installation is missing its reversible resolver authority",
        ));
    }
    if record.is_none() && activation.is_some() {
        return Err(conflict(
            "the orphaned resolver authority lacks an authenticated installed daemon identity",
        ));
    }
    if record.is_none()
        && activation.is_none()
        && (unowned_runtime_namespace(&snapshot) || unowned_publication_namespace(&snapshot))
    {
        return Err(conflict(
            "an unowned Remap runtime or publication namespace requires administrator review",
        ));
    }
    let mut effects = crate::lifecycle_effects::recovery(record.as_ref(), &snapshot);
    effects.extend(publication_repairs.iter().map(|(path, _target)| {
        format!("create missing owned publication path {}", path.display())
    }));
    let bootstrap_residues = snapshot.bootstrap_residues.clone();
    let state_residue = snapshot.state_residue.clone();
    let state_digest = digest(&snapshot)?;
    let token = recovery_token(state_digest, &effects)?;
    let resolver_authority_required = recovery_needs_resolver_authority(&snapshot);
    Ok(PreparedRecovery {
        preview: RecoveryPreviewData {
            schema_version: 1,
            installation_phase: record.as_ref().map(|value| phase_name(value.phase)),
            generation_id: record.as_ref().map(|value| value.current.id.to_string()),
            bootstrap_residues: bootstrap_residues.clone(),
            state_residue,
            effects,
            has_effects: true,
            approval_token: token,
        },
        bootstrap_residues,
        state_residue: snapshot.state_residue,
        daemon_plan_identity: snapshot.daemon_plan_identity,
        daemon_plan_observed: snapshot.daemon_plan_observed,
        publication_repairs,
        resolver_authority_required,
        state_digest,
    })
}

impl PreparedPlan {
    pub(crate) fn require_token(&self, token: &str) -> io::Result<()> {
        require_token(&self.preview.approval_token, token)
    }

    pub(crate) fn same_authority(&self, other: &Self) -> bool {
        self.state_digest == other.state_digest
            && self.preview.approval_token == other.preview.approval_token
            && self.generation == other.generation
            && self.activation_record_digest == other.activation_record_digest
            && self.daemon_plan_identity == other.daemon_plan_identity
            && self.daemon_plan_observed == other.daemon_plan_observed
    }

    pub(crate) const fn has_effects(&self) -> bool {
        self.preview.has_effects
    }
}

impl PreparedRecovery {
    pub(crate) fn require_token(&self, token: &str) -> io::Result<()> {
        require_token(&self.preview.approval_token, token)
    }

    pub(crate) fn same_authority(&self, other: &Self) -> bool {
        self.state_digest == other.state_digest
            && self.preview.approval_token == other.preview.approval_token
            && self.daemon_plan_identity == other.daemon_plan_identity
            && self.daemon_plan_observed == other.daemon_plan_observed
            && self.resolver_authority_required == other.resolver_authority_required
            && self.publication_repairs == other.publication_repairs
    }

    pub(crate) const fn requires_resolver_authority(&self) -> bool {
        self.resolver_authority_required
    }
}

pub(crate) fn encode_json<T: Serialize>(value: &T) -> io::Result<String> {
    let encoded = serde_json::to_vec(value)
        .map_err(|_error| invalid_data("the Linux lifecycle response could not be encoded"))?;
    if encoded.len() > MAX_OUTPUT_BYTES {
        return Err(invalid_data(
            "the Linux lifecycle response exceeds its bound",
        ));
    }
    String::from_utf8(encoded)
        .map_err(|_error| invalid_data("the Linux lifecycle response is invalid UTF-8"))
}

async fn snapshot(
    selected: Option<remap_linux::LinkIndex>,
    record: Option<InstallRecord>,
    normalization: SnapshotNormalization,
) -> io::Result<StateSnapshot> {
    let manager = SystemdManager::connect()?;
    let mut services = service_states(&manager)?;
    if normalization.resolver_quiesced {
        let resolver = services
            .iter_mut()
            .find(|service| service.unit == RESOLVER_UNIT)
            .ok_or_else(|| invalid_data("the resolver service state is unavailable"))?;
        if resolver.state != "inactive" {
            return Err(conflict(
                "the resolver service changed while acquiring transaction authority",
            ));
        }
        "active".clone_into(&mut resolver.state);
    }
    let selected_link = selected
        .map(SystemdResolved::inspect)
        .transpose()
        .map_err(platform_error)?;
    let effective_link = selected
        .map(SystemdResolved::observe)
        .transpose()
        .map_err(platform_error)?;
    let effective_link_digest = effective_link.as_ref().map(digest).transpose()?;
    let activation_record =
        RootRecordStore::inspect(Path::new(RESOLVER_RECORD_DIRECTORY)).map_err(platform_error)?;
    let activation_record_digest = activation_record.as_ref().map(digest).transpose()?;
    let publication_snapshot = snapshot_publication_paths(record.as_ref())
        .into_iter()
        .map(|path| path_state(&path))
        .collect::<io::Result<Vec<_>>>()?;
    let bootstrap_residues = bootstrap_recovery::inspect()?;
    let mut state_residue = cleanup::inspect_state_residue(Path::new(RESOLVER_RECORD_DIRECTORY))?;
    if normalization.fresh_state_created
        && state_residue
            .as_ref()
            .is_some_and(StateResidue::is_empty_directory)
    {
        state_residue = None;
    }
    let (daemon_plan_observed, daemon_plan_identity) =
        observe_daemon_plan(record.as_ref(), &services).await;
    let daemon_plan_valid = daemon_plan_matches_activation(
        record.as_ref(),
        activation_record.as_ref(),
        daemon_plan_observed,
        daemon_plan_identity,
    );
    Ok(StateSnapshot {
        active_integrity_valid: record
            .as_ref()
            .filter(|value| value.phase == InstallPhase::Active)
            .map(|value| verify_active(value).is_ok()),
        install_record: record,
        publications: publication_snapshot,
        services,
        resolver_environment: environment_name(ResolverEnvironment::detect()),
        selected_link,
        effective_link_digest,
        activation_state_valid: activation_record.as_ref().is_none_or(|activation| {
            effective_link
                .as_ref()
                .is_some_and(|observed| observed == activation.owned())
        }),
        activation_record_digest,
        activation_phase: activation_record
            .as_ref()
            .map(remap_linux::ActivationRecord::phase),
        daemon_plan_observed,
        daemon_plan_identity,
        daemon_plan_valid,
        bootstrap_residues,
        state_residue,
    })
}

fn snapshot_publication_paths(record: Option<&InstallRecord>) -> Vec<PathBuf> {
    let mut paths = publication_paths();
    if let Some(record) = record {
        paths.extend(
            record
                .current
                .public_directories
                .iter()
                .map(|directory| PathBuf::from(&directory.path)),
        );
    }
    paths.sort();
    paths.dedup();
    paths
}

fn service_states(manager: &SystemdManager) -> io::Result<Vec<ServiceStatus>> {
    let mut units = unit_names();
    units.sort();
    units.dedup();
    units
        .into_iter()
        .map(|unit| {
            let state = manager.observed_state(&unit)?;
            Ok(ServiceStatus { unit, state })
        })
        .collect()
}

fn publication_namespace_occupied() -> io::Result<bool> {
    for path in publication_paths() {
        match std::fs::symlink_metadata(path) {
            Ok(_) => return Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(false)
}

fn require_no_recovery(snapshot: &StateSnapshot) -> io::Result<()> {
    if snapshot_recovery_required(snapshot) {
        Err(conflict(
            "the Linux installation requires separately approved recovery",
        ))
    } else {
        Ok(())
    }
}

fn publication_effects(
    operation: Operation,
    previous: Option<&str>,
    next: Option<&str>,
) -> Vec<PublicationEffect> {
    let action = match operation {
        Operation::Install => "create",
        Operation::Update => "repoint",
        Operation::Uninstall => "remove",
        Operation::Recover => "restore",
    };
    let paths = publication_paths();
    let paths = if operation == Operation::Update {
        paths
            .into_iter()
            .filter(|path| path == Path::new("/usr/libexec/remap/current"))
            .collect()
    } else {
        paths
    };
    paths
        .into_iter()
        .map(|path| PublicationEffect {
            action,
            path: path.to_string_lossy().into_owned(),
            previous_generation_id: previous.map(str::to_owned),
            next_generation_id: next.map(str::to_owned),
        })
        .collect()
}

fn directory_publication_effects(
    generation: &Generation,
    action: &'static str,
    previous: Option<&str>,
    next: Option<&str>,
) -> io::Result<Vec<PublicationEffect>> {
    let paths = if action == "create" {
        generation
            .public_directories
            .iter()
            .filter(|directory| {
                directory.provenance == crate::install_model::DirectoryProvenance::CreatedByRemap
            })
            .map(|directory| PathBuf::from(&directory.path))
            .collect()
    } else {
        publications::removable_public_directories(generation)?
    };
    Ok(paths
        .into_iter()
        .map(|path| PublicationEffect {
            action,
            path: path.to_string_lossy().into_owned(),
            previous_generation_id: previous.map(str::to_owned),
            next_generation_id: next.map(str::to_owned),
        })
        .collect())
}

fn sort_publications(publications: &mut Vec<PublicationEffect>) {
    publications.sort_by(|left, right| left.path.cmp(&right.path));
    publications.dedup_by(|left, right| left.path == right.path && left.action == right.action);
}

pub(crate) fn publication_paths() -> Vec<PathBuf> {
    publications::publication_paths()
}

fn candidate(value: &ResolverLinkInspection) -> LinkCandidate {
    LinkCandidate {
        link_index: value.index().get(),
        interface_name: value.interface_name().to_owned(),
        backend: manager_name(value.manager()),
        selection_state: selection_state_name(value.selection_state()),
    }
}

fn require_root() -> io::Result<()> {
    if nix::unistd::Uid::effective().is_root() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the Linux lifecycle authority requires root",
        ))
    }
}

fn platform_error(_error: remap_linux::LinuxError) -> io::Error {
    invalid_data("the native Linux resolver state could not be inspected safely")
}

fn conflict(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::AlreadyExists, message)
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
#[path = "lifecycle_contract_tests.rs"]
mod tests;
