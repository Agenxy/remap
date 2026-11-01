// SPDX-License-Identifier: GPL-3.0-or-later
//! Restoring ordinary DNS through `NetworkManager` while the daemon's
//! upstreams do not answer, and returning from it (ADR-0036).
//!
//! The bypass is the same compare-and-swap reapply deactivation uses, ending
//! in a kept record instead of a removed one. Re-arming prepares ownership
//! from the applied connection exactly as a first activation does.

use super::{
    NetworkManagerStartupObservation, NetworkManagerTransaction, connection_is_owned,
    external_change, manager_not_ready, network_manager, observation_changed, ownership_conflict,
    prepare_ownership, recovery_required, restore_dns,
};
use crate::{
    ActivationPhase, ActivationRecord, ActivationStore, LinuxResult, ResolverManagerRecord,
};

impl<S> NetworkManagerTransaction<S>
where
    S: ActivationStore,
{
    /// Restores the prior applied-connection DNS and keeps the record, so
    /// ordinary DNS is in effect until the supervisor re-arms.
    ///
    /// # Errors
    ///
    /// Returns an ownership conflict, without any effect, unless a stable
    /// observation proves the full owned contract is still exact.
    pub fn bypass_observed(
        &mut self,
        observed: &NetworkManagerStartupObservation,
    ) -> LinuxResult<ActivationRecord> {
        let mut record = self
            .store
            .load()?
            .ok_or_else(|| ownership_conflict("no resolver activation is available"))?;
        if self.observation_requires_rebase(&record, observed)? {
            return Err(external_change());
        }
        record.set_phase(ActivationPhase::Bypassing { completed_steps: 0 })?;
        self.store.save(&record)?;
        self.bypass(record)
    }

    pub(super) fn bypass(&mut self, record: ActivationRecord) -> LinuxResult<ActivationRecord> {
        let applied = self.backend.applied()?;
        let ownership = network_manager(&record)?;
        if applied.digest != ownership.before_connection_digest() {
            if !connection_is_owned(&applied, ownership)? {
                return Err(external_change());
            }
            let restored = restore_dns(&applied.settings, ownership)?;
            self.backend.reapply(restored, applied.version)?;
        }
        self.require_before_connection(&record)?;
        self.finish_bypass(record)
    }

    fn finish_bypass(&mut self, mut record: ActivationRecord) -> LinuxResult<ActivationRecord> {
        let ActivationPhase::Bypassing { completed_steps } = record.phase() else {
            return Err(recovery_required());
        };
        for completed_steps in (completed_steps + 1)..=3 {
            record.set_phase(ActivationPhase::Bypassing { completed_steps })?;
            self.store.save(&record)?;
        }
        record.set_phase(ActivationPhase::Bypassed)?;
        self.store.save(&record)?;
        Ok(record)
    }

    /// Prepares ownership from the current applied connection and reapplies
    /// Remap DNS under the bypassed record's identity, with a strictly newer
    /// generation.
    ///
    /// # Errors
    ///
    /// Returns an error unless the record is bypassed and the stable
    /// observation is still current, or for any native or durable failure.
    pub fn rearm_observed(
        &mut self,
        generation_candidate: u64,
        created_unix_seconds: u64,
        observed: &NetworkManagerStartupObservation,
    ) -> LinuxResult<ActivationRecord> {
        let record = self.load_bypassed()?;
        let metadata = crate::transaction::successor_metadata(
            &record,
            generation_candidate,
            created_unix_seconds,
        )?;
        let (current, applied) = self
            .backend
            .startup_observation()?
            .ok_or_else(manager_not_ready)?;
        if current != *observed {
            return Err(observation_changed());
        }
        let (ownership, prepared) = prepare_ownership(&self.backend, &applied)?;
        let successor = ActivationRecord::prepare_managed(
            metadata,
            current.resolved,
            record.owned().clone(),
            ResolverManagerRecord::NetworkManager(Box::new(ownership)),
        )?;
        self.store.replace(&record, &successor)?;
        self.apply_owned(successor, &applied, prepared)
    }

    /// Forgets a bypassed record. Remap owns nothing on the connection while
    /// bypassed, so nothing is reapplied.
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
