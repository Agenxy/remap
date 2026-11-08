// SPDX-License-Identifier: GPL-3.0-or-later
//! Restoring ordinary DNS while the daemon's upstreams do not answer, and
//! returning from it (ADR-0036).
//!
//! A bypass is a restoration that keeps the record: it starts only from the
//! exact owned state, so it never writes over another agent's change, and it
//! journals each field like deactivation. While bypassed Remap owns nothing on
//! the link. Re-arming therefore captures the link afresh, exactly as a first
//! activation does, under the same activation identity.

use super::{
    LAST_STEP, ResolverStartupObservation, ResolverTransaction, manager_not_ready,
    ownership_conflict, recovery_required,
};
use crate::{
    ActivationPhase, ActivationRecord, ActivationStore, LinuxResult, RecordMetadata,
    ResolvedBackend,
};

impl<B, S> ResolverTransaction<B, S>
where
    B: ResolvedBackend,
    S: ActivationStore,
{
    /// Restores the captured fields and keeps the record, so ordinary DNS is
    /// in effect until the supervisor re-arms.
    ///
    /// # Errors
    ///
    /// Returns an ownership conflict, without any effect, unless a stable
    /// observation proves the link still holds exactly Remap's owned state.
    pub fn bypass_observed(
        &mut self,
        observed: &ResolverStartupObservation,
    ) -> LinuxResult<ActivationRecord> {
        self.bypass_observed_with_policy(observed, true)
    }

    /// Bypasses a legacy activation without upgrading its manager encoding.
    ///
    /// # Errors
    ///
    /// Returns an ownership conflict unless the owned state is exact.
    pub fn bypass_observed_preserving_legacy_manager(
        &mut self,
        observed: &ResolverStartupObservation,
    ) -> LinuxResult<ActivationRecord> {
        self.bypass_observed_with_policy(observed, false)
    }

    fn bypass_observed_with_policy(
        &mut self,
        observed: &ResolverStartupObservation,
        migrate_legacy_manager: bool,
    ) -> LinuxResult<ActivationRecord> {
        let mut record = self
            .store
            .load()?
            .ok_or_else(|| ownership_conflict("no resolver activation is available to bypass"))?;
        if self.observation_requires_rebase_with_policy(
            &record,
            observed,
            migrate_legacy_manager,
        )? {
            return Err(ownership_conflict(
                "resolver state changed outside Remap before ordinary DNS could be restored",
            ));
        }
        record.set_phase(ActivationPhase::Bypassing { completed_steps: 0 })?;
        self.store.save(&record)?;
        self.continue_bypass(record)
    }

    pub(super) fn continue_bypass(
        &mut self,
        mut record: ActivationRecord,
    ) -> LinuxResult<ActivationRecord> {
        let ActivationPhase::Bypassing {
            mut completed_steps,
        } = record.phase()
        else {
            return Err(recovery_required());
        };
        while completed_steps < LAST_STEP {
            self.apply_step(&record, completed_steps, true)?;
            completed_steps += 1;
            record.set_phase(ActivationPhase::Bypassing { completed_steps })?;
            self.require_expected(&record)?;
            self.store.save(&record)?;
        }
        record.set_phase(ActivationPhase::Bypassed)?;
        self.store.save(&record)?;
        Ok(record)
    }

    /// Captures the link afresh and applies Remap's owned state again under
    /// the bypassed record's identity, with a strictly newer generation.
    ///
    /// # Errors
    ///
    /// Returns an error unless the record is bypassed and the stable
    /// observation is still current, or for any native or durable failure.
    pub fn rearm_observed(
        &mut self,
        generation_candidate: u64,
        created_unix_seconds: u64,
        observed: &ResolverStartupObservation,
    ) -> LinuxResult<ActivationRecord> {
        self.rearm_observed_with_policy(generation_candidate, created_unix_seconds, observed, true)
    }

    /// Re-arms a legacy activation without upgrading its manager encoding.
    ///
    /// # Errors
    ///
    /// Returns an error unless the record is bypassed and the observation is
    /// still current.
    pub fn rearm_observed_preserving_legacy_manager(
        &mut self,
        generation_candidate: u64,
        created_unix_seconds: u64,
        observed: &ResolverStartupObservation,
    ) -> LinuxResult<ActivationRecord> {
        self.rearm_observed_with_policy(generation_candidate, created_unix_seconds, observed, false)
    }

    fn rearm_observed_with_policy(
        &mut self,
        generation_candidate: u64,
        created_unix_seconds: u64,
        observed: &ResolverStartupObservation,
        migrate_legacy_manager: bool,
    ) -> LinuxResult<ActivationRecord> {
        let record = self.load_bypassed()?;
        let metadata = successor_metadata(&record, generation_candidate, created_unix_seconds)?;
        let current = self
            .startup_observation(record.owned().link())?
            .ok_or_else(manager_not_ready)?;
        if observed.state.link() != record.owned().link() || current != *observed {
            return Err(ownership_conflict(
                "resolver state changed after startup stabilization",
            ));
        }
        let legacy_manager = matches!(record.manager(), crate::ResolverManagerRecord::Systemd);
        if !legacy_manager && record.manager() != &observed.manager {
            return Err(ownership_conflict(
                "the durable resolver manager identity changed",
            ));
        }
        let manager = if legacy_manager && !migrate_legacy_manager {
            record.manager().clone()
        } else {
            observed.manager.clone()
        };
        let successor = ActivationRecord::prepare_with_manager(
            metadata,
            std::slice::from_ref(&observed.state),
            record.owned().clone(),
            manager,
        )?;
        self.store.replace(&record, &successor)?;
        self.continue_transition(successor)
    }

    /// Forgets a bypassed record. Remap owns nothing on the link while
    /// bypassed, so nothing is written to it.
    ///
    /// # Errors
    ///
    /// Returns an error unless the durable record is bypassed.
    pub fn release_bypassed(&mut self) -> LinuxResult<()> {
        let record = self.load_bypassed()?;
        self.store.remove(record.metadata())
    }

    fn load_bypassed(&mut self) -> LinuxResult<ActivationRecord> {
        let record = self
            .store
            .load()?
            .ok_or_else(|| ownership_conflict("no bypassed resolver activation is available"))?;
        if record.phase() != ActivationPhase::Bypassed {
            return Err(recovery_required());
        }
        Ok(record)
    }
}

/// The identity a re-armed record carries: the same activation and owner, a
/// strictly newer generation.
pub(crate) fn successor_metadata(
    record: &ActivationRecord,
    generation_candidate: u64,
    created_unix_seconds: u64,
) -> LinuxResult<RecordMetadata> {
    let generation = generation_candidate.max(
        record
            .metadata()
            .generation()
            .checked_add(1)
            .ok_or_else(recovery_required)?,
    );
    RecordMetadata::new(
        record.metadata().activation_id(),
        generation,
        record.metadata().owner_uid(),
        created_unix_seconds,
    )
}
