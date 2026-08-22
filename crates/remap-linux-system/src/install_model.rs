use std::io;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use remap_linux::ResolverLinkManager;

pub(crate) const MAX_INSTALL_RECORD_BYTES: usize = 32 * 1024;
const INSTALL_SCHEMA: &str = "remap.linux-install/v5";
pub(crate) const LEGACY_EXPECTED_ARTIFACTS: usize = 31;
const EXPECTED_ARTIFACTS: usize = 35;
pub(crate) const RESOLVER_REBASE_CAPABILITY: u16 = 3;

const fn legacy_resolver_rebase_capability() -> u16 {
    1
}

// Serde's `skip_serializing_if` hook receives a reference even for `Copy` fields.
#[allow(clippy::trivially_copy_pass_by_ref)]
pub(crate) const fn is_legacy_resolver_rebase_capability(value: &u16) -> bool {
    *value == legacy_resolver_rebase_capability()
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum InstallPhase {
    Staging,
    Staged,
    Published,
    RollingBack(RollbackStep),
    Pruning,
    Active,
    Uninstalling(UninstallStep),
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RollbackStep {
    StopServices,
    RestoreResolver,
    RestoreCurrent,
    RemoveUnitLinks,
    RemovePublicPaths,
    ReloadManager,
    RemoveFailedGeneration,
    RemoveGenerationRoots,
    StartPrevious,
    Finalize,
}

impl RollbackStep {
    #[cfg(test)]
    pub(crate) const ALL: [Self; 10] = [
        Self::StopServices,
        Self::RestoreResolver,
        Self::RestoreCurrent,
        Self::RemoveUnitLinks,
        Self::RemovePublicPaths,
        Self::ReloadManager,
        Self::RemoveFailedGeneration,
        Self::RemoveGenerationRoots,
        Self::StartPrevious,
        Self::Finalize,
    ];

    pub(crate) const fn successor(self) -> Option<Self> {
        match self {
            Self::StopServices => Some(Self::RestoreResolver),
            Self::RestoreResolver => Some(Self::RestoreCurrent),
            Self::RestoreCurrent => Some(Self::RemoveUnitLinks),
            Self::RemoveUnitLinks => Some(Self::RemovePublicPaths),
            Self::RemovePublicPaths => Some(Self::ReloadManager),
            Self::ReloadManager => Some(Self::RemoveFailedGeneration),
            Self::RemoveFailedGeneration => Some(Self::RemoveGenerationRoots),
            Self::RemoveGenerationRoots => Some(Self::StartPrevious),
            Self::StartPrevious => Some(Self::Finalize),
            Self::Finalize => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum UninstallStep {
    RestoreResolver,
    StopServices,
    RemoveUnitLinks,
    RemovePublicPaths,
    RemoveCurrent,
    ReloadManager,
    RemoveCurrentGeneration,
    RemovePreviousGeneration,
    RemoveGenerationRoots,
    Finalize,
}

impl UninstallStep {
    #[cfg(test)]
    pub(crate) const ALL: [Self; 10] = [
        Self::RestoreResolver,
        Self::StopServices,
        Self::RemoveUnitLinks,
        Self::RemovePublicPaths,
        Self::RemoveCurrent,
        Self::ReloadManager,
        Self::RemoveCurrentGeneration,
        Self::RemovePreviousGeneration,
        Self::RemoveGenerationRoots,
        Self::Finalize,
    ];

    pub(crate) const fn successor(self) -> Option<Self> {
        match self {
            Self::RestoreResolver => Some(Self::StopServices),
            Self::StopServices => Some(Self::RemoveUnitLinks),
            Self::RemoveUnitLinks => Some(Self::RemovePublicPaths),
            Self::RemovePublicPaths => Some(Self::RemoveCurrent),
            Self::RemoveCurrent => Some(Self::ReloadManager),
            Self::ReloadManager => Some(Self::RemoveCurrentGeneration),
            Self::RemoveCurrentGeneration => Some(Self::RemovePreviousGeneration),
            Self::RemovePreviousGeneration => Some(Self::RemoveGenerationRoots),
            Self::RemoveGenerationRoots => Some(Self::Finalize),
            Self::Finalize => None,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Artifact {
    pub(crate) relative_path: String,
    pub(crate) mode: u32,
    pub(crate) byte_length: u64,
    pub(crate) digest: [u8; 32],
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DirectoryProvenance {
    Preexisting,
    CreatedByRemap,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectoryIdentity {
    pub(crate) inode: u64,
    pub(crate) birth_seconds: i64,
    pub(crate) birth_nanoseconds: u32,
    pub(crate) ownership_nonce: [u8; 16],
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PublicDirectory {
    pub(crate) path: String,
    pub(crate) provenance: DirectoryProvenance,
    pub(crate) identity: Option<DirectoryIdentity>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResolverPlanIdentity {
    pub(crate) activation_id: Uuid,
    pub(crate) generation: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Generation {
    pub(crate) id: Uuid,
    pub(crate) manifest_digest: [u8; 32],
    pub(crate) product_version: String,
    pub(crate) account: String,
    pub(crate) group: String,
    pub(crate) owner_uid: u32,
    pub(crate) daemon_uid: u32,
    pub(crate) link: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) interface_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) resolver_manager: Option<ResolverLinkManager>,
    #[serde(
        default = "legacy_resolver_rebase_capability",
        skip_serializing_if = "is_legacy_resolver_rebase_capability"
    )]
    pub(crate) resolver_rebase_capability: u16,
    pub(crate) artifacts: Vec<Artifact>,
    pub(crate) public_directories: Vec<PublicDirectory>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InstallRecord {
    pub(crate) phase: InstallPhase,
    pub(crate) current: Generation,
    pub(crate) previous: Option<Generation>,
    pub(crate) previous_previous: Option<Generation>,
    pub(crate) pending_resolver_plan: Option<ResolverPlanIdentity>,
}

impl InstallRecord {
    pub(crate) fn staging(current: Generation, previous: Option<&Self>) -> Self {
        Self {
            phase: InstallPhase::Staging,
            current,
            previous: previous.map(|record| record.current.clone()),
            previous_previous: previous.and_then(|record| record.previous.clone()),
            pending_resolver_plan: None,
        }
    }

    pub(crate) fn stage(&mut self) -> io::Result<()> {
        if self.phase != InstallPhase::Staging {
            return Err(invalid_record());
        }
        self.phase = InstallPhase::Staged;
        Ok(())
    }

    pub(crate) fn publish(&mut self) -> io::Result<()> {
        if self.phase != InstallPhase::Staged {
            return Err(invalid_record());
        }
        self.phase = InstallPhase::Published;
        Ok(())
    }

    pub(crate) fn activate(&mut self) -> io::Result<()> {
        if !matches!(self.phase, InstallPhase::Published | InstallPhase::Pruning)
            || (self.phase == InstallPhase::Published && self.previous_previous.is_some())
        {
            return Err(invalid_record());
        }
        self.phase = InstallPhase::Active;
        self.previous_previous = None;
        self.pending_resolver_plan = None;
        Ok(())
    }

    pub(crate) fn begin_prune(&mut self) -> io::Result<()> {
        if self.phase != InstallPhase::Published || self.previous_previous.is_none() {
            return Err(invalid_record());
        }
        self.phase = InstallPhase::Pruning;
        Ok(())
    }

    pub(crate) fn begin_rollback(
        &mut self,
        pending_resolver_plan: Option<ResolverPlanIdentity>,
    ) -> io::Result<()> {
        if !matches!(
            self.phase,
            InstallPhase::Staging | InstallPhase::Staged | InstallPhase::Published
        ) {
            return Err(invalid_record());
        }
        self.pending_resolver_plan = pending_resolver_plan;
        self.phase = InstallPhase::RollingBack(RollbackStep::StopServices);
        Ok(())
    }

    pub(crate) fn advance_rollback(
        &mut self,
        expected: RollbackStep,
        next: RollbackStep,
    ) -> io::Result<()> {
        if self.phase != InstallPhase::RollingBack(expected) {
            return Err(invalid_record());
        }
        self.phase = InstallPhase::RollingBack(next);
        Ok(())
    }

    pub(crate) fn rollback_record(&self) -> Option<Self> {
        self.previous.clone().map(|current| Self {
            phase: InstallPhase::Active,
            current,
            previous: self.previous_previous.clone(),
            previous_previous: None,
            pending_resolver_plan: None,
        })
    }

    pub(crate) fn begin_uninstall(
        &mut self,
        pending_resolver_plan: ResolverPlanIdentity,
    ) -> io::Result<()> {
        if self.phase != InstallPhase::Active {
            return Err(invalid_record());
        }
        self.pending_resolver_plan = Some(pending_resolver_plan);
        self.phase = InstallPhase::Uninstalling(UninstallStep::RestoreResolver);
        Ok(())
    }

    pub(crate) fn advance_uninstall(
        &mut self,
        expected: UninstallStep,
        next: UninstallStep,
    ) -> io::Result<()> {
        if self.phase != InstallPhase::Uninstalling(expected) {
            return Err(invalid_record());
        }
        self.phase = InstallPhase::Uninstalling(next);
        Ok(())
    }

    fn validate(&self) -> io::Result<()> {
        validate_generation(&self.current)?;
        if let Some(previous) = &self.previous {
            validate_generation(previous)?;
        }
        if let Some(previous) = &self.previous_previous {
            validate_generation(previous)?;
        }
        self.validate_transaction_state()?;
        let mut ids = [Some(self.current.id), None, None];
        ids[1] = self.previous.as_ref().map(|value| value.id);
        ids[2] = self.previous_previous.as_ref().map(|value| value.id);
        if ids
            .iter()
            .flatten()
            .enumerate()
            .any(|(index, id)| ids[..index].iter().flatten().any(|prior| prior == id))
        {
            return Err(invalid_record());
        }
        Ok(())
    }

    fn validate_transaction_state(&self) -> io::Result<()> {
        if matches!(
            self.phase,
            InstallPhase::Active | InstallPhase::Uninstalling(_)
        ) && self.previous_previous.is_some()
        {
            return Err(invalid_record());
        }
        if self.phase == InstallPhase::Pruning && self.previous_previous.is_none() {
            return Err(invalid_record());
        }
        if matches!(
            self.phase,
            InstallPhase::Staging
                | InstallPhase::Staged
                | InstallPhase::Published
                | InstallPhase::Pruning
                | InstallPhase::Active
        ) && self.pending_resolver_plan.is_some()
        {
            return Err(invalid_record());
        }
        if self
            .pending_resolver_plan
            .is_some_and(|identity| identity.activation_id.is_nil() || identity.generation == 0)
        {
            return Err(invalid_record());
        }
        if matches!(
            self.phase,
            InstallPhase::Staged
                | InstallPhase::Published
                | InstallPhase::Pruning
                | InstallPhase::Active
                | InstallPhase::Uninstalling(_)
        ) && self.current.public_directories.iter().any(|directory| {
            directory.provenance == DirectoryProvenance::CreatedByRemap
                && directory.identity.is_none()
        }) {
            return Err(invalid_record());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema: String,
    digest: [u8; 32],
    payload: InstallRecord,
}

pub(crate) fn encode(record: &InstallRecord) -> io::Result<Vec<u8>> {
    record.validate()?;
    let payload = serde_json::to_vec(record).map_err(|_error| invalid_record())?;
    let envelope = Envelope {
        schema: INSTALL_SCHEMA.to_owned(),
        digest: crate::digest::sha256(&payload),
        payload: record.clone(),
    };
    let encoded = serde_json::to_vec(&envelope).map_err(|_error| invalid_record())?;
    if encoded.len() > MAX_INSTALL_RECORD_BYTES {
        return Err(invalid_record());
    }
    Ok(encoded)
}

pub(crate) fn decode(encoded: &[u8]) -> io::Result<InstallRecord> {
    if encoded.is_empty() || encoded.len() > MAX_INSTALL_RECORD_BYTES {
        return Err(invalid_record());
    }
    let envelope: Envelope = serde_json::from_slice(encoded).map_err(|_error| invalid_record())?;
    if envelope.schema != INSTALL_SCHEMA {
        return Err(invalid_record());
    }
    envelope.payload.validate()?;
    let payload = serde_json::to_vec(&envelope.payload).map_err(|_error| invalid_record())?;
    let current_digest_matches = crate::digest::sha256(&payload) == envelope.digest;
    let legacy_digest_matches = record_uses_legacy_identity(&envelope.payload)
        && *blake3::hash(&payload).as_bytes() == envelope.digest;
    if !current_digest_matches && !legacy_digest_matches {
        return Err(invalid_record());
    }
    Ok(envelope.payload)
}

fn validate_generation(generation: &Generation) -> io::Result<()> {
    if generation_header_invalid(generation)
        || current_resolver_identity_invalid(generation)
        || !matches!(
            generation.artifacts.len(),
            LEGACY_EXPECTED_ARTIFACTS | EXPECTED_ARTIFACTS
        )
    {
        return Err(invalid_record());
    }
    let identity_is_valid = crate::generation::validate_identity(generation).is_ok()
        || (generation.artifacts.len() == LEGACY_EXPECTED_ARTIFACTS
            && crate::generation::validate_legacy_identity(generation).is_ok());
    if !identity_is_valid {
        return Err(invalid_record());
    }
    crate::generation::validate_public_directories(&generation.public_directories)
        .map_err(|_error| invalid_record())?;
    for artifact in &generation.artifacts {
        if artifact_invalid(artifact) {
            return Err(invalid_record());
        }
    }
    Ok(())
}

fn record_uses_legacy_identity(record: &InstallRecord) -> bool {
    std::iter::once(&record.current)
        .chain(record.previous.iter())
        .chain(record.previous_previous.as_ref())
        .all(|generation| {
            generation.artifacts.len() == LEGACY_EXPECTED_ARTIFACTS
                && crate::generation::validate_legacy_identity(generation).is_ok()
        })
}

fn generation_header_invalid(generation: &Generation) -> bool {
    generation.id.is_nil()
        || generation.product_version.is_empty()
        || generation.account.is_empty()
        || generation.group.is_empty()
        || generation.owner_uid == 0
        || generation.daemon_uid == 0
        || generation.link == 0
        || !matches!(
            generation.resolver_rebase_capability,
            1..=RESOLVER_REBASE_CAPABILITY
        )
}

fn current_resolver_identity_invalid(generation: &Generation) -> bool {
    generation.resolver_rebase_capability == RESOLVER_REBASE_CAPABILITY
        && (generation.resolver_manager.is_none()
            || generation
                .interface_name
                .as_deref()
                .is_none_or(interface_name_invalid))
}

fn interface_name_invalid(value: &str) -> bool {
    value.is_empty()
        || value.len() > 15
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
}

fn artifact_invalid(artifact: &Artifact) -> bool {
    artifact.relative_path.is_empty()
        || artifact.relative_path.starts_with('/')
        || artifact.relative_path.contains("..")
        || !matches!(artifact.mode, 0o644 | 0o755)
        || artifact.byte_length == 0
}

fn invalid_record() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "the Linux installation record is invalid",
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::BTreeSet;

    use super::{
        Artifact, DirectoryProvenance, Generation, InstallPhase, InstallRecord, PublicDirectory,
        ResolverPlanIdentity, RollbackStep, UninstallStep, decode, encode,
    };
    use uuid::Uuid;

    pub(crate) fn generation(id: u128) -> Generation {
        let salt = u8::try_from(id).unwrap_or_default();
        let mut generation = Generation {
            id: Uuid::from_u128(id),
            manifest_digest: [0; 32],
            product_version: "0.1.1".to_owned(),
            account: "remap".to_owned(),
            group: "remap".to_owned(),
            owner_uid: 1000,
            daemon_uid: 1001,
            link: 7,
            interface_name: Some("eth0".to_owned()),
            resolver_manager: Some(remap_linux::ResolverLinkManager::SystemdNetworkd),
            resolver_rebase_capability: super::RESOLVER_REBASE_CAPABILITY,
            artifacts: (0..super::EXPECTED_ARTIFACTS)
                .map(|index| Artifact {
                    relative_path: format!("artifact-{index}"),
                    mode: 0o644,
                    byte_length: 1,
                    digest: [u8::try_from(index).unwrap_or_default().wrapping_add(salt); 32],
                })
                .collect(),
            public_directories: super::super::generation::PUBLIC_DIRECTORY_PATHS
                .iter()
                .map(|path| PublicDirectory {
                    path: (*path).to_owned(),
                    provenance: DirectoryProvenance::Preexisting,
                    identity: None,
                })
                .collect(),
        };
        assert!(super::super::generation::seal_identity(&mut generation).is_ok());
        generation
    }

    pub(crate) fn sample_record() -> InstallRecord {
        InstallRecord {
            phase: InstallPhase::Active,
            current: generation(2),
            previous: Some(generation(1)),
            previous_previous: None,
            pending_resolver_plan: None,
        }
    }

    #[test]
    fn record_round_trip_and_rollback_preserve_exact_prior_generation() -> std::io::Result<()> {
        let active = InstallRecord {
            phase: InstallPhase::Active,
            current: generation(1),
            previous: Some(generation(2)),
            previous_previous: None,
            pending_resolver_plan: None,
        };
        let mut staged = InstallRecord::staging(generation(3), Some(&active));
        staged.stage()?;
        staged.publish()?;
        assert_eq!(staged.rollback_record(), Some(active));
        let encoded = encode(&staged)?;
        assert_eq!(decode(&encoded)?, staged);
        Ok(())
    }

    #[test]
    fn legacy_generation_omits_and_recovers_the_update_capability() -> std::io::Result<()> {
        let mut legacy = generation(1);
        legacy.interface_name = None;
        legacy.resolver_manager = None;
        legacy.resolver_rebase_capability = 1;
        super::super::generation::seal_identity(&mut legacy)?;
        let record = InstallRecord::staging(legacy, None);
        let encoded = encode(&record)?;
        assert!(
            !encoded
                .windows("resolver_rebase_capability".len())
                .any(|window| window == "resolver_rebase_capability".as_bytes())
        );
        assert!(
            !encoded
                .windows("interface_name".len())
                .any(|window| { window == "interface_name".as_bytes() })
        );
        assert!(
            !encoded
                .windows("resolver_manager".len())
                .any(|window| { window == "resolver_manager".as_bytes() })
        );
        let decoded = decode(&encoded)?;
        assert_eq!(decoded.current.resolver_rebase_capability, 1);
        Ok(())
    }

    #[test]
    fn blake3_generation_and_record_identity_remain_readable() -> std::io::Result<()> {
        let mut current = generation(2);
        current.artifacts.truncate(super::LEGACY_EXPECTED_ARTIFACTS);
        super::super::generation::seal_legacy_identity(&mut current)?;
        let mut previous = generation(1);
        previous
            .artifacts
            .truncate(super::LEGACY_EXPECTED_ARTIFACTS);
        super::super::generation::seal_legacy_identity(&mut previous)?;
        let record = InstallRecord {
            phase: InstallPhase::Active,
            current,
            previous: Some(previous),
            previous_previous: None,
            pending_resolver_plan: None,
        };
        let payload = serde_json::to_vec(&record).map_err(std::io::Error::other)?;
        let envelope = super::Envelope {
            schema: super::INSTALL_SCHEMA.to_owned(),
            digest: *blake3::hash(&payload).as_bytes(),
            payload: record.clone(),
        };
        let legacy_encoded = serde_json::to_vec(&envelope).map_err(std::io::Error::other)?;

        assert_eq!(decode(&legacy_encoded)?, record);
        assert_eq!(decode(&encode(&record)?)?, record);
        Ok(())
    }

    #[test]
    fn current_capability_requires_exact_interface_and_manager_identity() -> std::io::Result<()> {
        let mut record = sample_record();
        record.current.interface_name = None;
        super::super::generation::seal_identity(&mut record.current)?;
        assert!(encode(&record).is_err());
        record.current.interface_name = Some("eth0".to_owned());
        record.current.resolver_manager = None;
        super::super::generation::seal_identity(&mut record.current)?;
        assert!(encode(&record).is_err());
        Ok(())
    }

    #[test]
    fn literal_pre_capability_v5_fixture_remains_readable_and_migrates() -> std::io::Result<()> {
        let fixture = include_str!("../tests/fixtures/linux-install-v5-pre-capability.json")
            .strip_suffix('\n')
            .ok_or_else(|| std::io::Error::other("the golden fixture must end in one newline"))?;
        let record = decode(fixture.as_bytes())?;
        assert_eq!(record.current.resolver_rebase_capability, 1);
        super::super::generation::validate_legacy_identity(&record.current)?;
        assert_eq!(decode(&encode(&record)?)?, record);
        Ok(())
    }

    #[test]
    fn record_rejects_tampering() -> std::io::Result<()> {
        let encoded = encode(&InstallRecord::staging(generation(3), None))?;
        let mut tampered = encoded;
        let middle = tampered.len() / 2;
        tampered[middle] ^= 1;
        assert!(decode(&tampered).is_err());
        Ok(())
    }

    #[test]
    fn pruning_is_durable_before_old_generation_removal() -> std::io::Result<()> {
        let active = InstallRecord {
            phase: InstallPhase::Active,
            current: generation(2),
            previous: Some(generation(1)),
            previous_previous: None,
            pending_resolver_plan: None,
        };
        let mut update = InstallRecord::staging(generation(3), Some(&active));
        update.stage()?;
        update.publish()?;
        update.begin_prune()?;
        assert_eq!(decode(&encode(&update)?)?.phase, InstallPhase::Pruning);
        update.activate()?;
        assert_eq!(update.phase, InstallPhase::Active);
        assert_eq!(update.previous_previous, None);
        Ok(())
    }

    #[test]
    fn rollback_next_effect_journal_replays_every_crash_boundary() -> std::io::Result<()> {
        for crash_boundary in 0..(RollbackStep::ALL.len() * 2) {
            let mut record = InstallRecord::staging(
                generation(3),
                Some(&InstallRecord {
                    phase: InstallPhase::Active,
                    current: generation(2),
                    previous: Some(generation(1)),
                    previous_previous: None,
                    pending_resolver_plan: None,
                }),
            );
            record.stage()?;
            record.publish()?;
            record.begin_rollback(None)?;
            let mut applied = BTreeSet::new();
            let mut boundary = 0;
            loop {
                let InstallPhase::RollingBack(step) = record.phase else {
                    return Err(std::io::Error::other(
                        "rollback journal left its transaction phase",
                    ));
                };
                if boundary == crash_boundary {
                    record = decode(&encode(&record)?)?;
                }
                boundary += 1;
                applied.insert(step);
                if boundary == crash_boundary {
                    record = decode(&encode(&record)?)?;
                    assert_eq!(record.phase, InstallPhase::RollingBack(step));
                    applied.insert(step);
                }
                boundary += 1;
                let Some(next) = step.successor() else {
                    break;
                };
                record.advance_rollback(step, next)?;
            }
            assert_eq!(applied, BTreeSet::from(RollbackStep::ALL));
        }
        Ok(())
    }

    #[test]
    fn rollback_removes_failed_generation_before_previous_health_acceptance() {
        assert_eq!(
            RollbackStep::ReloadManager.successor(),
            Some(RollbackStep::RemoveFailedGeneration)
        );
        assert_eq!(
            RollbackStep::RemoveGenerationRoots.successor(),
            Some(RollbackStep::StartPrevious)
        );
        assert_eq!(
            RollbackStep::StartPrevious.successor(),
            Some(RollbackStep::Finalize)
        );
    }

    #[test]
    fn record_rejects_a_retained_generation_identity_collision() {
        let record = InstallRecord {
            phase: InstallPhase::Staging,
            current: generation(1),
            previous: Some(generation(2)),
            previous_previous: Some(generation(1)),
            pending_resolver_plan: None,
        };
        assert!(encode(&record).is_err());
    }

    #[test]
    fn uninstall_next_effect_journal_replays_every_crash_boundary() -> std::io::Result<()> {
        for crash_boundary in 0..(UninstallStep::ALL.len() * 2) {
            let mut record = InstallRecord {
                phase: InstallPhase::Active,
                current: generation(2),
                previous: Some(generation(1)),
                previous_previous: None,
                pending_resolver_plan: None,
            };
            record.begin_uninstall(ResolverPlanIdentity {
                activation_id: Uuid::from_u128(9),
                generation: 1,
            })?;
            let mut applied = BTreeSet::new();
            let mut boundary = 0;
            loop {
                let InstallPhase::Uninstalling(step) = record.phase else {
                    return Err(std::io::Error::other(
                        "uninstall journal left its transaction phase",
                    ));
                };
                if boundary == crash_boundary {
                    record = decode(&encode(&record)?)?;
                }
                boundary += 1;
                applied.insert(step);
                if boundary == crash_boundary {
                    record = decode(&encode(&record)?)?;
                    assert_eq!(record.phase, InstallPhase::Uninstalling(step));
                    applied.insert(step);
                }
                boundary += 1;
                let Some(next) = step.successor() else {
                    break;
                };
                record.advance_uninstall(step, next)?;
            }
            assert_eq!(applied, BTreeSet::from(UninstallStep::ALL));
        }
        Ok(())
    }
}
