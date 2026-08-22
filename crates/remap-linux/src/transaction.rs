use crate::{
    ActivationPhase, ActivationRecord, LinuxError, LinuxErrorKind, LinuxResult, RecordMetadata,
    ResolvedBackend,
};

const LAST_STEP: u8 = 3;

/// Complete stable systemd resolver input paired with exact manager identity.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ResolverStartupObservation {
    manager: crate::ResolverManagerRecord,
    state: crate::LinkState,
}

/// Durable root-owned activation-record storage boundary.
///
/// Implementations must use a root-owned directory, reject symlinks, durably
/// replace records, and call [`crate::RecordCodec::validate_root_file`] before
/// decoding an existing file.
pub trait ActivationStore {
    /// Loads the one host-wide resolver activation, if present.
    ///
    /// # Errors
    ///
    /// Returns an error when the root-owned record cannot be safely loaded.
    fn load(&mut self) -> LinuxResult<Option<ActivationRecord>>;
    /// Durably replaces the activation record before the next side effect.
    ///
    /// # Errors
    ///
    /// Returns an error unless the replacement is durably committed.
    fn save(&mut self, record: &ActivationRecord) -> LinuxResult<()>;
    /// Atomically replaces an exact active record with one prepared successor.
    ///
    /// # Errors
    ///
    /// Returns an error unless the persisted record still exactly matches
    /// `expected` and the successor preserves ownership identity.
    fn replace(
        &mut self,
        expected: &ActivationRecord,
        successor: &ActivationRecord,
    ) -> LinuxResult<()>;
    /// Durably removes the record matching the supplied identity.
    ///
    /// # Errors
    ///
    /// Returns an error for an identity mismatch or failed durable removal.
    fn remove(&mut self, metadata: &RecordMetadata) -> LinuxResult<()>;
}

/// Crash-recoverable systemd-resolved ownership transaction.
#[derive(Debug)]
pub struct ResolverTransaction<B, S> {
    backend: B,
    store: S,
}

impl<B, S> ResolverTransaction<B, S>
where
    B: ResolvedBackend,
    S: ActivationStore,
{
    /// Creates a resolver transaction over typed native boundaries.
    #[must_use]
    pub const fn new(backend: B, store: S) -> Self {
        Self { backend, store }
    }

    /// Captures and activates one explicit link.
    ///
    /// The prepared record is durable before the first D-Bus mutation.
    ///
    /// # Errors
    ///
    /// Returns an error for existing ownership, native failure, or incomplete recovery.
    pub fn activate(
        &mut self,
        metadata: RecordMetadata,
        owned: crate::LinkState,
    ) -> LinuxResult<ActivationRecord> {
        let before = self.backend.snapshot(owned.link())?;
        let observation = ResolverStartupObservation {
            manager: self.backend.manager_record(),
            state: before,
        };
        self.activate_observed(metadata, owned, &observation)
    }

    /// Activates from a previously stabilized native snapshot after proving it
    /// is still current before the durable record is created.
    ///
    /// # Errors
    ///
    /// Returns an error if ownership appeared or native state changed after
    /// stabilization.
    pub fn activate_observed(
        &mut self,
        metadata: RecordMetadata,
        owned: crate::LinkState,
        observed: &ResolverStartupObservation,
    ) -> LinuxResult<ActivationRecord> {
        if self.store.load()?.is_some() {
            return Err(ownership_conflict(
                "a resolver activation record already owns the host scope",
            ));
        }
        let current = self
            .startup_observation(owned.link())?
            .ok_or_else(manager_not_ready)?;
        if observed.state.link() != owned.link() || current != *observed {
            return Err(ownership_conflict(
                "resolver state changed after startup stabilization",
            ));
        }
        let record = ActivationRecord::prepare_with_manager(
            metadata,
            std::slice::from_ref(&observed.state),
            owned,
            observed.manager.clone(),
        )?;
        self.store.save(&record)?;
        self.continue_transition(record)
    }

    /// Restores a currently active record only when its owned state is intact.
    ///
    /// # Errors
    ///
    /// Returns an error for missing ownership, external drift, or incomplete recovery.
    pub fn deactivate(&mut self) -> LinuxResult<()> {
        let mut record = self
            .store
            .load()?
            .ok_or_else(|| ownership_conflict("no resolver activation is available to restore"))?;
        if record.phase() != ActivationPhase::Active {
            return Err(recovery_required());
        }
        self.require_expected(&record)?;
        record.set_phase(ActivationPhase::Restoring { completed_steps: 0 })?;
        self.store.save(&record)?;
        self.continue_restore(record)
    }

    /// Starts restoration only after a stable manager-aware observation proves
    /// the complete active ownership contract is still exact.
    ///
    /// # Errors
    ///
    /// Returns an error if manager readiness, identity, or resolver state
    /// changed after stabilization.
    pub fn deactivate_observed(
        &mut self,
        observed: &ResolverStartupObservation,
    ) -> LinuxResult<()> {
        self.deactivate_observed_with_policy(observed, true)
    }

    /// Restores a stable legacy activation without requiring a manager-encoding
    /// upgrade that an interrupted older helper cannot decode.
    ///
    /// # Errors
    ///
    /// Returns an error if the complete manager-aware observation changed.
    pub fn deactivate_observed_preserving_legacy_manager(
        &mut self,
        observed: &ResolverStartupObservation,
    ) -> LinuxResult<()> {
        self.deactivate_observed_with_policy(observed, false)
    }

    fn deactivate_observed_with_policy(
        &mut self,
        observed: &ResolverStartupObservation,
        migrate_legacy_manager: bool,
    ) -> LinuxResult<()> {
        let mut record = self
            .store
            .load()?
            .ok_or_else(|| ownership_conflict("no resolver activation is available to restore"))?;
        if self.observation_requires_rebase_with_policy(
            &record,
            observed,
            migrate_legacy_manager,
        )? {
            return Err(ownership_conflict(
                "resolver ownership changed before stable restoration",
            ));
        }
        record.set_phase(ActivationPhase::Restoring { completed_steps: 0 })?;
        self.store.save(&record)?;
        self.continue_restore(record)
    }

    /// Safely abandons an incomplete activation and restores its captured state.
    ///
    /// An ambiguous native failure may have applied the current field before
    /// returning an error. Live state is reconciled against the two exact safe
    /// transition points before the abort phase is made durable.
    ///
    /// # Errors
    ///
    /// Returns an error for missing ownership, external drift, or failed recovery.
    pub fn abort_activation(&mut self) -> LinuxResult<()> {
        let mut record = self
            .store
            .load()?
            .ok_or_else(|| ownership_conflict("no resolver activation is available to abort"))?;
        self.reconcile_progress(&mut record)?;
        match record.phase() {
            ActivationPhase::Applying { completed_steps } => {
                if completed_steps == 0 {
                    return self.store.remove(record.metadata());
                }
                record.set_phase(ActivationPhase::Aborting {
                    applied_steps: completed_steps,
                    completed_steps: 0,
                })?;
                self.store.save(&record)?;
                self.continue_abort(record)
            }
            ActivationPhase::Aborting { .. } => self.continue_abort(record),
            ActivationPhase::Active | ActivationPhase::Restoring { .. } => Err(recovery_required()),
        }
    }

    /// Captures a native manager's new per-link state and reapplies Remap.
    ///
    /// The current record must be active, the live state must differ from the
    /// owned loopback state, and the successor must retain the same activation
    /// identity with a strictly newer generation.
    ///
    /// # Errors
    ///
    /// Returns an error for ambiguous ownership, invalid ordering, or any
    /// native/persistence failure.
    pub fn rebase(
        &mut self,
        generation_candidate: u64,
        created_unix_seconds: u64,
    ) -> LinuxResult<ActivationRecord> {
        let record = self
            .store
            .load()?
            .ok_or_else(|| ownership_conflict("no resolver activation is available to rebase"))?;
        let observed = ResolverStartupObservation {
            manager: self.backend.manager_record(),
            state: self.backend.snapshot(record.owned().link())?,
        };
        self.rebase_observed(generation_candidate, created_unix_seconds, &observed)
    }

    /// Rebases from a stable native-manager observation after comparing it
    /// again immediately before durable publication.
    ///
    /// # Errors
    ///
    /// Returns an error if the activation or native manager state changed
    /// after stabilization.
    pub fn rebase_observed(
        &mut self,
        generation_candidate: u64,
        created_unix_seconds: u64,
        observed: &ResolverStartupObservation,
    ) -> LinuxResult<ActivationRecord> {
        self.rebase_observed_with_policy(generation_candidate, created_unix_seconds, observed, true)
    }

    /// Rebases stable resolver fields while retaining a legacy manager encoding
    /// that an interrupted older rollback helper can still decode.
    ///
    /// # Errors
    ///
    /// Returns an error if manager readiness or resolver state changed after
    /// stabilization.
    pub fn rebase_observed_preserving_legacy_manager(
        &mut self,
        generation_candidate: u64,
        created_unix_seconds: u64,
        observed: &ResolverStartupObservation,
    ) -> LinuxResult<ActivationRecord> {
        self.rebase_observed_with_policy(
            generation_candidate,
            created_unix_seconds,
            observed,
            false,
        )
    }

    fn rebase_observed_with_policy(
        &mut self,
        generation_candidate: u64,
        created_unix_seconds: u64,
        observed: &ResolverStartupObservation,
        migrate_legacy_manager: bool,
    ) -> LinuxResult<ActivationRecord> {
        let record = self
            .store
            .load()?
            .ok_or_else(|| ownership_conflict("no resolver activation is available to rebase"))?;
        if record.phase() != ActivationPhase::Active {
            return Err(ownership_conflict(
                "the resolver rebase requires an active ownership record",
            ));
        }
        let generation = generation_candidate.max(
            record
                .metadata()
                .generation()
                .checked_add(1)
                .ok_or_else(recovery_required)?,
        );
        let metadata = RecordMetadata::new(
            record.metadata().activation_id(),
            generation,
            record.metadata().owner_uid(),
            created_unix_seconds,
        )?;
        let current = self
            .startup_observation(record.owned().link())?
            .ok_or_else(manager_not_ready)?;
        let legacy_manager = matches!(record.manager(), crate::ResolverManagerRecord::Systemd);
        let manager_migration = migrate_legacy_manager
            && legacy_manager
            && !matches!(&observed.manager, crate::ResolverManagerRecord::Systemd);
        if observed.state.link() != record.owned().link()
            || current != *observed
            || (!legacy_manager && record.manager() != &observed.manager)
        {
            return Err(ownership_conflict(
                "resolver state changed after startup stabilization",
            ));
        }
        if observed.state == *record.owned() && !manager_migration {
            return Ok(record);
        }
        let rebased_before = record
            .before()
            .merge_external_changes(record.owned(), &observed.state)?;
        let successor_manager = if legacy_manager && !migrate_legacy_manager {
            record.manager().clone()
        } else {
            observed.manager.clone()
        };
        let successor = ActivationRecord::prepare_active_rebase_with_manager(
            metadata,
            rebased_before,
            record.owned().clone(),
            successor_manager,
        )?;
        self.store.replace(&record, &successor)?;
        for completed_steps in 0..LAST_STEP {
            self.apply_step(&successor, completed_steps, false)?;
        }
        self.require_expected(&successor)?;
        Ok(successor)
    }
}

impl<B, S> ResolverTransaction<B, S>
where
    B: ResolvedBackend,
    S: ActivationStore,
{
    /// Continues an interrupted transition only from an exact recognized state.
    ///
    /// # Errors
    ///
    /// Returns an error when live state does not match a safe transition point.
    pub fn recover(&mut self) -> LinuxResult<Option<ActivationRecord>> {
        let Some(mut record) = self.store.load()? else {
            return Ok(None);
        };
        self.reconcile_progress(&mut record)?;
        match record.phase() {
            ActivationPhase::Applying { .. } => self.continue_transition(record).map(Some),
            ActivationPhase::Aborting { .. } => {
                self.continue_abort(record)?;
                Ok(None)
            }
            ActivationPhase::Active => Ok(Some(record)),
            ActivationPhase::Restoring { .. } => {
                self.continue_restore(record)?;
                Ok(None)
            }
        }
    }

    /// Returns the backend and store for native lifecycle integration.
    #[must_use]
    pub fn into_parts(self) -> (B, S) {
        (self.backend, self.store)
    }

    /// Returns one complete live link snapshot through the owned backend.
    ///
    /// # Errors
    ///
    /// Returns an error when the native manager cannot provide exact state.
    pub fn snapshot(&mut self, link: crate::LinkIndex) -> LinuxResult<crate::LinkState> {
        self.backend.snapshot(link)
    }

    /// Returns a complete startup observation only after the selected native
    /// manager reports that its link is configured.
    ///
    /// # Errors
    ///
    /// Returns an error for manager-identity drift or unreadable native state.
    pub fn startup_observation(
        &mut self,
        link: crate::LinkIndex,
    ) -> LinuxResult<Option<ResolverStartupObservation>> {
        let Some(state) = self.backend.startup_snapshot(link)? else {
            return Ok(None);
        };
        Ok(Some(ResolverStartupObservation {
            manager: self.backend.manager_record(),
            state,
        }))
    }

    /// Determines whether a stable observation differs from the complete
    /// active systemd resolver ownership contract.
    ///
    /// # Errors
    ///
    /// Returns an error if readiness, manager identity, or values changed
    /// after the supplied observation.
    pub fn observation_requires_rebase(
        &mut self,
        record: &ActivationRecord,
        observed: &ResolverStartupObservation,
    ) -> LinuxResult<bool> {
        self.observation_requires_rebase_with_policy(record, observed, true)
    }

    /// Compares stable state while suppressing only the serialization upgrade
    /// of a legacy manager record needed by an interrupted older rollback.
    ///
    /// # Errors
    ///
    /// Returns an error if readiness, manager identity, or values changed.
    pub fn observation_requires_rebase_preserving_legacy_manager(
        &mut self,
        record: &ActivationRecord,
        observed: &ResolverStartupObservation,
    ) -> LinuxResult<bool> {
        self.observation_requires_rebase_with_policy(record, observed, false)
    }

    fn observation_requires_rebase_with_policy(
        &mut self,
        record: &ActivationRecord,
        observed: &ResolverStartupObservation,
        migrate_legacy_manager: bool,
    ) -> LinuxResult<bool> {
        if record.phase() != ActivationPhase::Active {
            return Err(recovery_required());
        }
        let current = self
            .startup_observation(record.owned().link())?
            .ok_or_else(observation_unstable)?;
        if current.manager != observed.manager {
            return Err(ownership_conflict(
                "the native resolver manager changed during steady observation",
            ));
        }
        if current.state != observed.state {
            return Err(observation_unstable());
        }
        let legacy_manager = matches!(record.manager(), crate::ResolverManagerRecord::Systemd);
        let manager_migration = migrate_legacy_manager
            && legacy_manager
            && !matches!(&observed.manager, crate::ResolverManagerRecord::Systemd);
        if !legacy_manager && record.manager() != &observed.manager {
            return Err(ownership_conflict(
                "the durable resolver manager identity changed",
            ));
        }
        Ok(manager_migration || observed.state != *record.owned())
    }

    /// Loads the exact durable activation record without changing it.
    ///
    /// # Errors
    ///
    /// Returns an error when root-owned persistence validation fails.
    pub fn load_record(&mut self) -> LinuxResult<Option<ActivationRecord>> {
        self.store.load()
    }

    fn continue_transition(
        &mut self,
        mut record: ActivationRecord,
    ) -> LinuxResult<ActivationRecord> {
        let ActivationPhase::Applying {
            mut completed_steps,
        } = record.phase()
        else {
            return Err(recovery_required());
        };
        while completed_steps < LAST_STEP {
            self.apply_step(&record, completed_steps, false)?;
            completed_steps += 1;
            record.set_phase(ActivationPhase::Applying { completed_steps })?;
            self.require_expected(&record)?;
            self.store.save(&record)?;
        }
        record.set_phase(ActivationPhase::Active)?;
        self.store.save(&record)?;
        Ok(record)
    }

    fn continue_restore(&mut self, mut record: ActivationRecord) -> LinuxResult<()> {
        let ActivationPhase::Restoring {
            mut completed_steps,
        } = record.phase()
        else {
            return Err(recovery_required());
        };
        while completed_steps < LAST_STEP {
            self.apply_step(&record, completed_steps, true)?;
            completed_steps += 1;
            record.set_phase(ActivationPhase::Restoring { completed_steps })?;
            self.require_expected(&record)?;
            self.store.save(&record)?;
        }
        self.store.remove(record.metadata())
    }

    fn continue_abort(&mut self, mut record: ActivationRecord) -> LinuxResult<()> {
        let ActivationPhase::Aborting {
            applied_steps,
            mut completed_steps,
        } = record.phase()
        else {
            return Err(recovery_required());
        };
        while completed_steps < applied_steps {
            self.apply_step(&record, completed_steps, true)?;
            completed_steps += 1;
            record.set_phase(ActivationPhase::Aborting {
                applied_steps,
                completed_steps,
            })?;
            self.require_expected(&record)?;
            self.store.save(&record)?;
        }
        self.store.remove(record.metadata())
    }

    fn apply_step(
        &mut self,
        record: &ActivationRecord,
        completed_steps: u8,
        restoring: bool,
    ) -> LinuxResult<()> {
        let target = if restoring {
            record.before()
        } else {
            record.owned()
        };
        match completed_steps {
            0 => self.backend.set_dns(target.link(), target.dns_servers()),
            1 => self.backend.set_domains(target.link(), target.domains()),
            2 => self
                .backend
                .set_default_route(target.link(), target.default_route()),
            _ => Err(recovery_required()),
        }
    }

    fn reconcile_progress(&mut self, record: &mut ActivationRecord) -> LinuxResult<()> {
        let current = self.backend.snapshot(record.owned().link())?;
        if current == record.expected_state()? {
            return Ok(());
        }
        let next_phase = match record.phase() {
            ActivationPhase::Applying { completed_steps } if completed_steps < LAST_STEP => {
                ActivationPhase::Applying {
                    completed_steps: completed_steps + 1,
                }
            }
            ActivationPhase::Restoring { completed_steps } if completed_steps < LAST_STEP => {
                ActivationPhase::Restoring {
                    completed_steps: completed_steps + 1,
                }
            }
            ActivationPhase::Aborting {
                applied_steps,
                completed_steps,
            } if completed_steps < applied_steps => ActivationPhase::Aborting {
                applied_steps,
                completed_steps: completed_steps + 1,
            },
            ActivationPhase::Applying { .. }
            | ActivationPhase::Active
            | ActivationPhase::Restoring { .. }
            | ActivationPhase::Aborting { .. } => {
                return Err(ownership_conflict(external_change()));
            }
        };
        record.set_phase(next_phase)?;
        if current != record.expected_state()? {
            return Err(ownership_conflict(external_change()));
        }
        self.store.save(record)
    }

    fn require_expected(&mut self, record: &ActivationRecord) -> LinuxResult<()> {
        let current = self.backend.snapshot(record.owned().link())?;
        if current != record.expected_state()? {
            return Err(ownership_conflict(external_change()));
        }
        Ok(())
    }
}

const fn external_change() -> &'static str {
    "resolver state changed outside the recorded Remap transition"
}

const fn ownership_conflict(message: &'static str) -> LinuxError {
    LinuxError::new(LinuxErrorKind::OwnershipConflict, message)
}

const fn recovery_required() -> LinuxError {
    LinuxError::new(
        LinuxErrorKind::RecoveryRequired,
        "the resolver transition stopped with a durable recovery record",
    )
}

const fn manager_not_ready() -> LinuxError {
    LinuxError::new(
        LinuxErrorKind::ResolverUnavailable,
        "the selected resolver manager is not fully configured",
    )
}

const fn observation_unstable() -> LinuxError {
    LinuxError::new(
        LinuxErrorKind::UnstableObservation,
        "resolver state changed during steady observation",
    )
}

#[cfg(test)]
#[path = "transaction_tests.rs"]
mod tests;
