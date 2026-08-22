use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{LinkState, LinuxError, LinuxErrorKind, LinuxResult, ResolverManagerRecord};

const RECORD_SCHEMA: &str = "remap.linux-resolver/v2";
/// Maximum encoded activation-record size accepted before JSON parsing.
pub const MAX_RECORD_BYTES: usize = 16 * 1024;
const TRANSITION_STEPS: u8 = 3;

/// Durable phase of a resolver ownership transition.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationPhase {
    /// Activation is applying Remap-owned fields in order.
    Applying {
        /// Number of fields durably verified in the target state.
        completed_steps: u8,
    },
    /// A failed activation is restoring only the fields it may have changed.
    Aborting {
        /// Number of activation fields known to have reached the owned state.
        applied_steps: u8,
        /// Number of those fields durably restored to the captured state.
        completed_steps: u8,
    },
    /// All Remap-owned fields were verified after activation.
    Active,
    /// Deactivation is restoring captured fields in order.
    Restoring {
        /// Number of fields durably verified in the captured state.
        completed_steps: u8,
    },
}

/// Identity and ordering metadata for one activation.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordMetadata {
    activation_id: Uuid,
    generation: u64,
    owner_uid: u32,
    created_unix_seconds: u64,
}

impl RecordMetadata {
    /// Validates non-secret activation metadata.
    ///
    /// # Errors
    ///
    /// Returns an invalid-record error when any required identity field is zero.
    pub fn new(
        activation_id: Uuid,
        generation: u64,
        owner_uid: u32,
        created_unix_seconds: u64,
    ) -> LinuxResult<Self> {
        if activation_id.is_nil() || generation == 0 || owner_uid == 0 || created_unix_seconds == 0
        {
            return Err(invalid_record(
                "the resolver activation metadata is invalid",
            ));
        }
        Ok(Self {
            activation_id,
            generation,
            owner_uid,
            created_unix_seconds,
        })
    }

    /// Returns the unique activation identifier.
    #[must_use]
    pub const fn activation_id(&self) -> Uuid {
        self.activation_id
    }

    /// Returns the monotonic installer generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the interactive user represented by this activation.
    #[must_use]
    pub const fn owner_uid(&self) -> u32 {
        self.owner_uid
    }
}

/// Integrity-covered, reversible ownership record for one resolved link.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationRecord {
    metadata: RecordMetadata,
    before: LinkState,
    owned: LinkState,
    manager: ResolverManagerRecord,
    phase: ActivationPhase,
}

impl ActivationRecord {
    /// Creates a prepared record before the first resolver mutation.
    ///
    /// # Errors
    ///
    /// Returns an error for ambiguous scopes, inconsistent links, or unowned target state.
    pub fn prepare(
        metadata: RecordMetadata,
        candidates: &[LinkState],
        owned: LinkState,
    ) -> LinuxResult<Self> {
        Self::prepare_with_manager(metadata, candidates, owned, ResolverManagerRecord::Systemd)
    }

    pub(crate) fn prepare_with_manager(
        metadata: RecordMetadata,
        candidates: &[LinkState],
        owned: LinkState,
        manager: ResolverManagerRecord,
    ) -> LinuxResult<Self> {
        let before = crate::model::validate_single_scope(candidates)?;
        if before.link() != owned.link() {
            return Err(invalid_record(
                "captured and Remap-owned resolver states refer to different links",
            ));
        }
        if before == &owned {
            return Err(LinuxError::new(
                LinuxErrorKind::OwnershipConflict,
                "the selected link already has Remap's target state without an ownership record",
            ));
        }
        let record = Self {
            metadata,
            before: before.clone(),
            owned,
            manager,
            phase: ActivationPhase::Applying { completed_steps: 0 },
        };
        record.validate()?;
        Ok(record)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn prepare_managed(
        metadata: RecordMetadata,
        before: LinkState,
        owned: LinkState,
        manager: ResolverManagerRecord,
    ) -> LinuxResult<Self> {
        if !matches!(&manager, ResolverManagerRecord::NetworkManager(_)) {
            return Err(invalid_record(
                "a managed resolver record requires manager-specific ownership",
            ));
        }
        let mut record = Self::prepare(metadata, &[before], owned)?;
        record.manager = manager;
        record.validate()?;
        Ok(record)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn prepare_managed_active_rebase(
        metadata: RecordMetadata,
        before: LinkState,
        owned: LinkState,
        manager: ResolverManagerRecord,
    ) -> LinuxResult<Self> {
        let mut record = Self::prepare_managed(metadata, before, owned, manager)?;
        record.phase = ActivationPhase::Active;
        record.validate()?;
        Ok(record)
    }

    pub(crate) fn prepare_active_rebase_with_manager(
        metadata: RecordMetadata,
        before: LinkState,
        owned: LinkState,
        manager: ResolverManagerRecord,
    ) -> LinuxResult<Self> {
        let mut record = Self::prepare_with_manager(metadata, &[before], owned, manager)?;
        record.phase = ActivationPhase::Active;
        record.validate()?;
        Ok(record)
    }

    /// Returns activation identity metadata.
    #[must_use]
    pub const fn metadata(&self) -> &RecordMetadata {
        &self.metadata
    }

    /// Returns the exact state captured before activation.
    #[must_use]
    pub const fn before(&self) -> &LinkState {
        &self.before
    }

    /// Returns the exact state Remap is allowed to replace during restore.
    #[must_use]
    pub const fn owned(&self) -> &LinkState {
        &self.owned
    }

    /// Returns native-manager ownership facts covered by this record.
    #[must_use]
    pub const fn manager(&self) -> &ResolverManagerRecord {
        &self.manager
    }

    /// Returns the durable transition phase.
    #[must_use]
    pub const fn phase(&self) -> ActivationPhase {
        self.phase
    }

    pub(crate) fn expected_state(&self) -> LinuxResult<LinkState> {
        match self.phase {
            ActivationPhase::Applying { completed_steps } => {
                transition_state(&self.before, &self.owned, completed_steps)
            }
            ActivationPhase::Aborting {
                applied_steps,
                completed_steps,
            } => {
                let partial = transition_state(&self.before, &self.owned, applied_steps)?;
                transition_state(&partial, &self.before, completed_steps)
            }
            ActivationPhase::Active => Ok(self.owned.clone()),
            ActivationPhase::Restoring { completed_steps } => {
                transition_state(&self.owned, &self.before, completed_steps)
            }
        }
    }

    pub(crate) fn set_phase(&mut self, phase: ActivationPhase) -> LinuxResult<()> {
        validate_phase(phase)?;
        self.phase = phase;
        Ok(())
    }

    fn validate(&self) -> LinuxResult<()> {
        if self.before.link() != self.owned.link() || self.before == self.owned {
            return Err(invalid_record(
                "the resolver activation record is inconsistent",
            ));
        }
        RecordMetadata::new(
            self.metadata.activation_id,
            self.metadata.generation,
            self.metadata.owner_uid,
            self.metadata.created_unix_seconds,
        )?;
        self.manager.validate()?;
        validate_phase(self.phase)
    }
}

/// Bounded, versioned activation-record encoder and decoder.
#[derive(Debug, Clone, Copy, Default)]
pub struct RecordCodec;

impl RecordCodec {
    /// Encodes one validated record with a SHA-256 corruption digest.
    ///
    /// # Errors
    ///
    /// Returns an error when validation, serialization, or the encoded bound fails.
    pub fn encode(record: &ActivationRecord) -> LinuxResult<Vec<u8>> {
        record.validate()?;
        let payload = serde_json::to_vec(record).map_err(|_error| persistence_error())?;
        let envelope = RecordEnvelope {
            schema: RECORD_SCHEMA.to_owned(),
            digest: crate::digest::sha256(&payload),
            payload: record.clone(),
        };
        let encoded = serde_json::to_vec(&envelope).map_err(|_error| persistence_error())?;
        if encoded.len() > MAX_RECORD_BYTES {
            return Err(invalid_record(
                "the resolver activation record exceeds its bound",
            ));
        }
        Ok(encoded)
    }

    /// Decodes only bounded, known-schema, integrity-valid records.
    ///
    /// # Errors
    ///
    /// Returns an invalid-record error for malformed, oversized, or altered bytes.
    pub fn decode(encoded: &[u8]) -> LinuxResult<ActivationRecord> {
        if encoded.is_empty() || encoded.len() > MAX_RECORD_BYTES {
            return Err(invalid_record(
                "the resolver activation record size is invalid",
            ));
        }
        let envelope: RecordEnvelope = serde_json::from_slice(encoded)
            .map_err(|_error| invalid_record("the resolver activation record is malformed"))?;
        if envelope.schema != RECORD_SCHEMA {
            return Err(invalid_record(
                "the resolver activation record schema is unsupported",
            ));
        }
        envelope.payload.validate()?;
        let payload =
            serde_json::to_vec(&envelope.payload).map_err(|_error| persistence_error())?;
        let digest_is_current = crate::digest::sha256(&payload) == envelope.digest;
        let digest_is_legacy = *blake3::hash(&payload).as_bytes() == envelope.digest;
        if !digest_is_current && !digest_is_legacy {
            return Err(invalid_record(
                "the resolver activation record failed its integrity check",
            ));
        }
        Ok(envelope.payload)
    }

    /// Validates file facts gathered without following symlinks by a root helper.
    ///
    /// # Errors
    ///
    /// Returns an invalid-record error unless the file is private, regular, and root-owned.
    pub fn validate_root_file(
        owner_uid: u32,
        unix_mode: u32,
        regular_file: bool,
        symlink: bool,
        byte_length: u64,
    ) -> LinuxResult<()> {
        if owner_uid != 0
            || unix_mode & 0o777 != 0o600
            || !regular_file
            || symlink
            || byte_length == 0
            || byte_length > MAX_RECORD_BYTES as u64
        {
            return Err(invalid_record(
                "the resolver activation record is not a bounded root-owned private file",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordEnvelope {
    schema: String,
    digest: [u8; 32],
    payload: ActivationRecord,
}

fn transition_state(from: &LinkState, to: &LinkState, steps: u8) -> LinuxResult<LinkState> {
    validate_steps(steps)?;
    let mut state = from.clone();
    if steps >= 1 {
        state = state.with_dns_from(to);
    }
    if steps >= 2 {
        state = state.with_domains_from(to);
    }
    if steps >= TRANSITION_STEPS {
        state = state.with_default_route_from(to);
    }
    Ok(state)
}

fn validate_phase(phase: ActivationPhase) -> LinuxResult<()> {
    match phase {
        ActivationPhase::Applying { completed_steps }
        | ActivationPhase::Restoring { completed_steps } => validate_steps(completed_steps),
        ActivationPhase::Aborting {
            applied_steps,
            completed_steps,
        } => {
            validate_steps(applied_steps)?;
            validate_steps(completed_steps)?;
            if completed_steps > applied_steps {
                return Err(invalid_record(
                    "the resolver abort progress exceeds its applied fields",
                ));
            }
            Ok(())
        }
        ActivationPhase::Active => Ok(()),
    }
}

fn validate_steps(steps: u8) -> LinuxResult<()> {
    if steps > TRANSITION_STEPS {
        return Err(invalid_record(
            "the resolver transition progress is invalid",
        ));
    }
    Ok(())
}

const fn invalid_record(message: &'static str) -> LinuxError {
    LinuxError::new(LinuxErrorKind::InvalidRecord, message)
}

const fn persistence_error() -> LinuxError {
    LinuxError::new(
        LinuxErrorKind::Persistence,
        "the resolver activation record could not be encoded",
    )
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use uuid::Uuid;

    use super::{ActivationRecord, RECORD_SCHEMA, RecordCodec, RecordEnvelope, RecordMetadata};
    use crate::{DnsServer, LinkDomain, LinkIndex, LinkState};

    #[test]
    fn blake3_envelope_remains_readable_and_reencodes_with_sha256()
    -> Result<(), Box<dyn std::error::Error>> {
        let link = LinkIndex::new(7)?;
        let before = LinkState::new(
            link,
            vec![DnsServer::new(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)),
                53,
                "",
            )?],
            vec![LinkDomain::new("example.test", false)?],
            true,
        )?;
        let owned = LinkState::remap_loopback(link)?;
        let record = ActivationRecord::prepare(
            RecordMetadata::new(Uuid::new_v4(), 7, 1000, 1)?,
            &[before],
            owned,
        )?;
        let payload = serde_json::to_vec(&record)?;
        let envelope = RecordEnvelope {
            schema: RECORD_SCHEMA.to_owned(),
            digest: *blake3::hash(&payload).as_bytes(),
            payload: record.clone(),
        };
        let encoded = serde_json::to_vec(&envelope)?;

        assert_eq!(RecordCodec::decode(&encoded)?, record);
        assert_eq!(RecordCodec::decode(&RecordCodec::encode(&record)?)?, record);
        Ok(())
    }
}
