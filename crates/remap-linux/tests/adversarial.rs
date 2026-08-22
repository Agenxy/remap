//! Adversarial resolver-ownership and systemd contract tests.

use std::error::Error;
use std::net::{IpAddr, Ipv4Addr};

use remap_linux::{
    ActivationEnvironment, ActivationPhase, ActivationRecord, ActivationStore, DnsServer,
    LinkDomain, LinkIndex, LinkLifecycleEvent, LinkScopeMonitor, LinkState, LinuxError,
    LinuxErrorKind, LinuxResult, MAX_DNS_SERVERS, MAX_RECORD_BYTES, RecordCodec, RecordMetadata,
    ResolvedBackend, ResolverManagerRecord, ResolverSupervisorIdentity, ResolverSupervisorLink,
    ResolverTransaction, ServiceIdentity, SocketContract, SystemdUnitSet,
};
use uuid::Uuid;

#[derive(Debug, Clone)]
struct MemoryBackend {
    state: LinkState,
    calls: usize,
    fail_call: Option<usize>,
    apply_before_failure: bool,
    manager: Option<ResolverManagerRecord>,
}

impl MemoryBackend {
    fn stable(state: LinkState) -> Self {
        Self {
            state,
            calls: 0,
            fail_call: None,
            apply_before_failure: false,
            manager: None,
        }
    }

    fn finish_call(&mut self) -> LinuxResult<()> {
        self.calls += 1;
        if self.fail_call == Some(self.calls) {
            self.fail_call = None;
            return Err(LinuxError::new(
                LinuxErrorKind::ResolverUnavailable,
                "synthetic resolver failure",
            ));
        }
        Ok(())
    }
}

impl ResolvedBackend for MemoryBackend {
    fn manager_record(&self) -> ResolverManagerRecord {
        self.manager.clone().unwrap_or_default()
    }

    fn snapshot(&mut self, _link: LinkIndex) -> LinuxResult<LinkState> {
        Ok(self.state.clone())
    }

    fn set_dns(&mut self, _link: LinkIndex, servers: &[DnsServer]) -> LinuxResult<()> {
        let result = self.finish_call();
        if result.is_ok() || self.apply_before_failure {
            self.state = LinkState::new(
                self.state.link(),
                servers.to_vec(),
                self.state.domains().to_vec(),
                self.state.default_route(),
            )?;
        }
        result
    }

    fn set_domains(&mut self, _link: LinkIndex, domains: &[LinkDomain]) -> LinuxResult<()> {
        let result = self.finish_call();
        if result.is_ok() || self.apply_before_failure {
            self.state = LinkState::new(
                self.state.link(),
                self.state.dns_servers().to_vec(),
                domains.to_vec(),
                self.state.default_route(),
            )?;
        }
        result
    }

    fn set_default_route(&mut self, _link: LinkIndex, enabled: bool) -> LinuxResult<()> {
        let result = self.finish_call();
        if result.is_ok() || self.apply_before_failure {
            self.state = LinkState::new(
                self.state.link(),
                self.state.dns_servers().to_vec(),
                self.state.domains().to_vec(),
                enabled,
            )?;
        }
        result
    }
}

#[derive(Debug, Clone, Default)]
struct MemoryStore {
    record: Option<ActivationRecord>,
    saves: usize,
    fail_save: Option<usize>,
}

impl ActivationStore for MemoryStore {
    fn load(&mut self) -> LinuxResult<Option<ActivationRecord>> {
        Ok(self.record.clone())
    }

    fn save(&mut self, record: &ActivationRecord) -> LinuxResult<()> {
        self.saves += 1;
        if self.fail_save == Some(self.saves) {
            self.fail_save = None;
            return Err(LinuxError::new(
                LinuxErrorKind::Persistence,
                "synthetic persistence failure",
            ));
        }
        self.record = Some(record.clone());
        Ok(())
    }

    fn replace(
        &mut self,
        expected: &ActivationRecord,
        successor: &ActivationRecord,
    ) -> LinuxResult<()> {
        if self.record.as_ref() != Some(expected) {
            return Err(LinuxError::new(
                LinuxErrorKind::OwnershipConflict,
                "synthetic activation identity mismatch",
            ));
        }
        self.record = Some(successor.clone());
        Ok(())
    }

    fn remove(&mut self, metadata: &RecordMetadata) -> LinuxResult<()> {
        if self.record.as_ref().map(ActivationRecord::metadata) != Some(metadata) {
            return Err(LinuxError::new(
                LinuxErrorKind::OwnershipConflict,
                "synthetic activation identity mismatch",
            ));
        }
        self.record = None;
        Ok(())
    }
}

#[test]
fn activation_and_deactivation_restore_every_exact_field() -> LinuxResult<()> {
    let before = prior_state()?;
    let owned = LinkState::remap_loopback(before.link())?;
    let mut transaction = ResolverTransaction::new(
        MemoryBackend::stable(before.clone()),
        MemoryStore::default(),
    );
    let active = transaction.activate(metadata()?, owned.clone())?;
    assert_eq!(active.phase(), ActivationPhase::Active);
    transaction.deactivate()?;
    let (backend, store) = transaction.into_parts();
    assert_eq!(backend.state, before);
    assert_eq!(store.record, None);
    assert_eq!(owned.dns_servers()[0].port(), 0);
    Ok(())
}

#[test]
fn failed_record_save_after_effect_is_recovered_from_live_state() -> LinuxResult<()> {
    let before = prior_state()?;
    let owned = LinkState::remap_loopback(before.link())?;
    let store = MemoryStore {
        fail_save: Some(2),
        ..MemoryStore::default()
    };
    let mut transaction = ResolverTransaction::new(MemoryBackend::stable(before), store);
    let error = transaction.activate(metadata()?, owned.clone());
    assert_eq!(
        error.err().map(|value| value.kind()),
        Some(LinuxErrorKind::Persistence)
    );
    let (backend, store) = transaction.into_parts();
    assert_eq!(
        store.record.as_ref().map(ActivationRecord::phase),
        Some(ActivationPhase::Applying { completed_steps: 0 })
    );
    let mut recovery = ResolverTransaction::new(backend, store);
    let recovered = recovery.recover()?;
    assert_eq!(
        recovered.as_ref().map(ActivationRecord::phase),
        Some(ActivationPhase::Active)
    );
    let (backend, _store) = recovery.into_parts();
    assert_eq!(backend.state, owned);
    Ok(())
}

#[test]
fn ambiguous_dbus_error_keeps_recoverable_record() -> LinuxResult<()> {
    let before = prior_state()?;
    let owned = LinkState::remap_loopback(before.link())?;
    let mut backend = MemoryBackend::stable(before);
    backend.fail_call = Some(1);
    backend.apply_before_failure = true;
    let mut transaction = ResolverTransaction::new(backend, MemoryStore::default());
    let error = transaction.activate(metadata()?, owned.clone());
    assert_eq!(
        error.err().map(|value| value.kind()),
        Some(LinuxErrorKind::ResolverUnavailable)
    );
    let (backend, store) = transaction.into_parts();
    assert!(store.record.is_some());
    let mut recovery = ResolverTransaction::new(backend, store);
    assert!(recovery.recover()?.is_some());
    let (backend, _store) = recovery.into_parts();
    assert_eq!(backend.state, owned);
    Ok(())
}

#[test]
fn failed_activation_without_effect_aborts_without_native_writes() -> LinuxResult<()> {
    let before = prior_state()?;
    let owned = LinkState::remap_loopback(before.link())?;
    let mut backend = MemoryBackend::stable(before.clone());
    backend.fail_call = Some(1);
    let mut transaction = ResolverTransaction::new(backend, MemoryStore::default());
    assert!(transaction.activate(metadata()?, owned).is_err());
    transaction.abort_activation()?;
    let (backend, store) = transaction.into_parts();
    assert_eq!(backend.state, before);
    assert_eq!(backend.calls, 1);
    assert_eq!(store.record, None);
    Ok(())
}

#[test]
fn ambiguous_failed_activation_aborts_every_applied_field() -> LinuxResult<()> {
    let before = prior_state()?;
    let owned = LinkState::remap_loopback(before.link())?;
    let mut backend = MemoryBackend::stable(before.clone());
    backend.fail_call = Some(2);
    backend.apply_before_failure = true;
    let mut transaction = ResolverTransaction::new(backend, MemoryStore::default());
    assert!(transaction.activate(metadata()?, owned).is_err());
    transaction.abort_activation()?;
    let (backend, store) = transaction.into_parts();
    assert_eq!(backend.state, before);
    assert_eq!(store.record, None);
    Ok(())
}

#[test]
fn failed_record_save_during_restore_resumes_without_guessing() -> LinuxResult<()> {
    let before = prior_state()?;
    let owned = LinkState::remap_loopback(before.link())?;
    let mut activation = ResolverTransaction::new(
        MemoryBackend::stable(before.clone()),
        MemoryStore::default(),
    );
    activation.activate(metadata()?, owned)?;
    let (backend, mut store) = activation.into_parts();
    store.fail_save = Some(store.saves + 2);
    let mut deactivation = ResolverTransaction::new(backend, store);
    let failure = deactivation.deactivate();
    assert_eq!(
        failure.err().map(|error| error.kind()),
        Some(LinuxErrorKind::Persistence)
    );
    let (backend, store) = deactivation.into_parts();
    let mut recovery = ResolverTransaction::new(backend, store);
    assert_eq!(recovery.recover()?, None);
    let (backend, store) = recovery.into_parts();
    assert_eq!(backend.state, before);
    assert_eq!(store.record, None);
    Ok(())
}

#[test]
fn external_change_blocks_restore_without_overwrite() -> LinuxResult<()> {
    let before = prior_state()?;
    let owned = LinkState::remap_loopback(before.link())?;
    let mut transaction = ResolverTransaction::new(
        MemoryBackend::stable(before.clone()),
        MemoryStore::default(),
    );
    transaction.activate(metadata()?, owned.clone())?;
    let (mut backend, store) = transaction.into_parts();
    let foreign_domains = vec![LinkDomain::new("operator.example", false)?];
    backend.state = LinkState::new(
        owned.link(),
        owned.dns_servers().to_vec(),
        foreign_domains,
        owned.default_route(),
    )?;
    let foreign_state = backend.state.clone();
    let mut deactivation = ResolverTransaction::new(backend, store);
    let result = deactivation.deactivate();
    assert_eq!(
        result.err().map(|value| value.kind()),
        Some(LinuxErrorKind::OwnershipConflict)
    );
    let (backend, store) = deactivation.into_parts();
    assert_eq!(backend.state, foreign_state);
    assert!(store.record.is_some());
    Ok(())
}

#[test]
fn managed_link_rebase_captures_new_upstream_and_reapplies_owned_state() -> LinuxResult<()> {
    let before = prior_state()?;
    let owned = LinkState::remap_loopback(before.link())?;
    let mut transaction = ResolverTransaction::new(
        MemoryBackend::stable(before.clone()),
        MemoryStore::default(),
    );
    let active = transaction.activate(metadata()?, owned.clone())?;
    let (mut backend, store) = transaction.into_parts();
    let changed = LinkState::new(
        owned.link(),
        vec![DnsServer::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99)),
            0,
            "",
        )?],
        vec![LinkDomain::new("transition.example", false)?],
        true,
    )?;
    backend.state = changed.clone();
    let mut rebase = ResolverTransaction::new(backend, store);
    let rebased = rebase.rebase(active.metadata().generation() + 1, 2)?;
    let (backend, store) = rebase.into_parts();
    let expected_before = LinkState::new(
        before.link(),
        changed.dns_servers().to_vec(),
        changed.domains().to_vec(),
        before.default_route(),
    )?;
    assert_eq!(rebased.before(), &expected_before);
    assert_eq!(backend.state, owned);
    assert_eq!(store.record, Some(rebased));
    Ok(())
}

#[test]
fn stable_rebase_input_is_rechecked_before_any_durable_effect() -> LinuxResult<()> {
    let before = prior_state()?;
    let owned = LinkState::remap_loopback(before.link())?;
    let mut transaction = ResolverTransaction::new(
        MemoryBackend::stable(before.clone()),
        MemoryStore::default(),
    );
    let active = transaction.activate(metadata()?, owned.clone())?;
    let (mut backend, store) = transaction.into_parts();
    let observed = LinkState::new(
        owned.link(),
        vec![DnsServer::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99)),
            0,
            "",
        )?],
        before.domains().to_vec(),
        before.default_route(),
    )?;
    let later = LinkState::new(
        owned.link(),
        observed.dns_servers().to_vec(),
        vec![LinkDomain::new("later.example", false)?],
        before.default_route(),
    )?;
    backend.state = observed;
    let mut stabilized = ResolverTransaction::new(backend, store);
    let observation = stabilized
        .startup_observation(owned.link())?
        .ok_or_else(|| LinuxError::new(LinuxErrorKind::InvalidState, "missing observation"))?;
    let (mut backend, store) = stabilized.into_parts();
    backend.state = later.clone();
    let mut rebase = ResolverTransaction::new(backend, store);

    let result = rebase.rebase_observed(active.metadata().generation() + 1, 2, &observation);
    assert_eq!(
        result.err().map(|error| error.kind()),
        Some(LinuxErrorKind::OwnershipConflict)
    );
    let (backend, store) = rebase.into_parts();
    assert_eq!(backend.state, later);
    assert_eq!(store.record, Some(active));
    Ok(())
}

#[test]
fn stable_rebase_rechecks_exact_manager_identity_before_any_effect() -> LinuxResult<()> {
    let before = prior_state()?;
    let owned = LinkState::remap_loopback(before.link())?;
    let mut backend = MemoryBackend::stable(before.clone());
    backend.manager = Some(ResolverManagerRecord::SystemdNetworkd("eth0".to_owned()));
    let mut transaction = ResolverTransaction::new(backend, MemoryStore::default());
    let active = transaction.activate(metadata()?, owned.clone())?;
    let (mut backend, store) = transaction.into_parts();
    backend.state = LinkState::new(
        owned.link(),
        vec![DnsServer::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99)),
            0,
            "",
        )?],
        before.domains().to_vec(),
        before.default_route(),
    )?;
    let mut stabilized = ResolverTransaction::new(backend, store);
    let observation = stabilized
        .startup_observation(owned.link())?
        .ok_or_else(|| LinuxError::new(LinuxErrorKind::InvalidState, "missing observation"))?;
    let (mut backend, store) = stabilized.into_parts();
    backend.manager = Some(ResolverManagerRecord::SystemdResolved("eth0".to_owned()));
    let mut rebase = ResolverTransaction::new(backend, store);

    let result = rebase.rebase_observed(active.metadata().generation() + 1, 2, &observation);
    assert_eq!(
        result.err().map(|error| error.kind()),
        Some(LinuxErrorKind::OwnershipConflict)
    );
    let (backend, store) = rebase.into_parts();
    assert_eq!(
        backend.state.dns_servers()[0].address(),
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99))
    );
    assert_eq!(store.record, Some(active));
    Ok(())
}

#[test]
fn stabilized_legacy_handoff_and_deactivation_preserve_old_encoding() -> LinuxResult<()> {
    let before = prior_state()?;
    let owned = LinkState::remap_loopback(before.link())?;
    let mut legacy = ResolverTransaction::new(
        MemoryBackend::stable(before.clone()),
        MemoryStore::default(),
    );
    let active = legacy.activate(metadata()?, owned.clone())?;
    let (mut backend, store) = legacy.into_parts();
    let changed = LinkState::new(
        owned.link(),
        vec![DnsServer::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99)),
            0,
            "",
        )?],
        before.domains().to_vec(),
        before.default_route(),
    )?;
    backend.state = changed.clone();
    backend.manager = Some(ResolverManagerRecord::SystemdNetworkd("eth0".to_owned()));
    let mut current_helper = ResolverTransaction::new(backend, store);
    let observation = current_helper
        .startup_observation(owned.link())?
        .ok_or_else(|| LinuxError::new(LinuxErrorKind::InvalidState, "missing observation"))?;
    assert!(
        current_helper
            .observation_requires_rebase_preserving_legacy_manager(&active, &observation)?
    );
    let converged = current_helper.rebase_observed_preserving_legacy_manager(
        active.metadata().generation() + 1,
        2,
        &observation,
    )?;
    assert_eq!(converged.manager(), &ResolverManagerRecord::Systemd);
    let encoded = RecordCodec::encode(&converged)?;
    assert!(
        encoded
            .windows(b"\"manager\":\"systemd\"".len())
            .any(|window| { window == b"\"manager\":\"systemd\"" })
    );
    assert_eq!(RecordCodec::decode(&encoded)?, converged);

    let restored_observation = current_helper
        .startup_observation(owned.link())?
        .ok_or_else(|| LinuxError::new(LinuxErrorKind::InvalidState, "missing observation"))?;
    current_helper.deactivate_observed_preserving_legacy_manager(&restored_observation)?;
    let (backend, store) = current_helper.into_parts();
    assert_eq!(backend.state, changed);
    assert_eq!(store.record, None);
    Ok(())
}

#[test]
fn managed_link_rebase_preserves_fields_that_remain_owned() -> LinuxResult<()> {
    let before = prior_state()?;
    let owned = LinkState::remap_loopback(before.link())?;
    let mut transaction = ResolverTransaction::new(
        MemoryBackend::stable(before.clone()),
        MemoryStore::default(),
    );
    let active = transaction.activate(metadata()?, owned.clone())?;
    let (mut backend, store) = transaction.into_parts();
    let changed_dns = vec![DnsServer::new(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99)),
        0,
        "",
    )?];
    backend.state = LinkState::new(
        owned.link(),
        changed_dns.clone(),
        owned.domains().to_vec(),
        owned.default_route(),
    )?;

    let mut rebase = ResolverTransaction::new(backend, store);
    let rebased = rebase.rebase(active.metadata().generation() + 1, 2)?;
    let expected_before = LinkState::new(
        before.link(),
        changed_dns,
        before.domains().to_vec(),
        before.default_route(),
    )?;
    let (backend, store) = rebase.into_parts();
    assert_eq!(rebased.before(), &expected_before);
    assert_eq!(backend.state, owned);
    assert_eq!(store.record, Some(rebased));
    Ok(())
}

#[test]
fn managed_link_rebase_composes_separate_external_fields() -> LinuxResult<()> {
    let before = prior_state()?;
    let owned = LinkState::remap_loopback(before.link())?;
    let mut transaction = ResolverTransaction::new(
        MemoryBackend::stable(before.clone()),
        MemoryStore::default(),
    );
    let active = transaction.activate(metadata()?, owned.clone())?;
    let (mut backend, store) = transaction.into_parts();
    let changed_dns = vec![DnsServer::new(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99)),
        0,
        "",
    )?];
    backend.state = LinkState::new(
        owned.link(),
        changed_dns.clone(),
        owned.domains().to_vec(),
        owned.default_route(),
    )?;
    let mut first = ResolverTransaction::new(backend, store);
    let dns_rebased = first.rebase(active.metadata().generation() + 1, 2)?;
    let (mut backend, store) = first.into_parts();

    let changed_domains = vec![LinkDomain::new("transition.example", false)?];
    backend.state = LinkState::new(
        owned.link(),
        owned.dns_servers().to_vec(),
        changed_domains.clone(),
        owned.default_route(),
    )?;
    let mut second = ResolverTransaction::new(backend, store);
    let domains_rebased = second.rebase(dns_rebased.metadata().generation() + 1, 3)?;
    let expected_before = LinkState::new(
        before.link(),
        changed_dns,
        changed_domains,
        before.default_route(),
    )?;
    let (backend, store) = second.into_parts();
    assert_eq!(domains_rebased.before(), &expected_before);
    assert_eq!(backend.state, owned);
    assert_eq!(store.record, Some(domains_rebased));
    Ok(())
}

#[test]
fn failed_rebase_keeps_the_merged_active_record_replayable() -> LinuxResult<()> {
    let before = prior_state()?;
    let owned = LinkState::remap_loopback(before.link())?;
    let mut transaction = ResolverTransaction::new(
        MemoryBackend::stable(before.clone()),
        MemoryStore::default(),
    );
    let active = transaction.activate(metadata()?, owned.clone())?;
    let (mut backend, store) = transaction.into_parts();
    let changed_dns = vec![DnsServer::new(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99)),
        0,
        "",
    )?];
    backend.state = LinkState::new(
        owned.link(),
        changed_dns.clone(),
        owned.domains().to_vec(),
        owned.default_route(),
    )?;
    backend.fail_call = Some(backend.calls + 1);

    let mut failed = ResolverTransaction::new(backend, store);
    let error = failed.rebase(active.metadata().generation() + 1, 2);
    assert_eq!(
        error.err().map(|value| value.kind()),
        Some(LinuxErrorKind::ResolverUnavailable)
    );
    let (backend, store) = failed.into_parts();
    let Some(persisted) = store.record.as_ref() else {
        return Err(LinuxError::new(
            LinuxErrorKind::InvalidRecord,
            "the active rebase record was not retained",
        ));
    };
    assert_eq!(persisted.phase(), ActivationPhase::Active);
    assert_eq!(persisted.before().dns_servers(), changed_dns);
    assert_eq!(persisted.before().domains(), before.domains());
    let persisted_generation = persisted.metadata().generation();

    let mut replay = ResolverTransaction::new(backend, store);
    let replayed = replay.rebase(persisted_generation + 1, 3)?;
    let (backend, store) = replay.into_parts();
    assert_eq!(replayed.before().dns_servers(), changed_dns);
    assert_eq!(replayed.before().domains(), before.domains());
    assert_eq!(backend.state, owned);
    assert_eq!(store.record, Some(replayed));
    Ok(())
}

#[test]
fn ambiguous_rebase_effect_retains_the_captured_upstream() -> LinuxResult<()> {
    let before = prior_state()?;
    let owned = LinkState::remap_loopback(before.link())?;
    let mut transaction = ResolverTransaction::new(
        MemoryBackend::stable(before.clone()),
        MemoryStore::default(),
    );
    let active = transaction.activate(metadata()?, owned.clone())?;
    let (mut backend, store) = transaction.into_parts();
    let changed_dns = vec![DnsServer::new(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99)),
        0,
        "",
    )?];
    backend.state = LinkState::new(
        owned.link(),
        changed_dns.clone(),
        owned.domains().to_vec(),
        owned.default_route(),
    )?;
    backend.fail_call = Some(backend.calls + 1);
    backend.apply_before_failure = true;

    let mut failed = ResolverTransaction::new(backend, store);
    assert!(
        failed
            .rebase(active.metadata().generation() + 1, 2)
            .is_err()
    );
    let (backend, store) = failed.into_parts();
    let mut recovery = ResolverTransaction::new(backend, store);
    let Some(recovered) = recovery.recover()? else {
        return Err(LinuxError::new(
            LinuxErrorKind::InvalidRecord,
            "the active rebase record was not recovered",
        ));
    };
    let (backend, store) = recovery.into_parts();
    assert_eq!(recovered.before().dns_servers(), changed_dns);
    assert_eq!(recovered.before().domains(), before.domains());
    assert_eq!(backend.state, owned);
    assert_eq!(store.record, Some(recovered));
    Ok(())
}

#[test]
fn current_helper_converges_every_rebase_fault_before_old_generation_handoff() -> LinuxResult<()> {
    for failed_effect in 1..=3 {
        let before = prior_state()?;
        let owned = LinkState::remap_loopback(before.link())?;
        let mut transaction = ResolverTransaction::new(
            MemoryBackend::stable(before.clone()),
            MemoryStore::default(),
        );
        let active = transaction.activate(metadata()?, owned.clone())?;
        let (mut backend, store) = transaction.into_parts();
        let changed_dns = vec![DnsServer::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99)),
            0,
            "",
        )?];
        let changed_domains = vec![LinkDomain::new("transition.example", false)?];
        backend.state = LinkState::new(
            owned.link(),
            changed_dns.clone(),
            changed_domains.clone(),
            owned.default_route(),
        )?;
        backend.fail_call = Some(backend.calls + failed_effect);
        backend.apply_before_failure = true;

        let mut failed = ResolverTransaction::new(backend, store);
        assert!(
            failed
                .rebase(active.metadata().generation() + 1, 2)
                .is_err()
        );
        let (backend, store) = failed.into_parts();
        let mut current_helper = ResolverTransaction::new(backend, store);
        let converged = match current_helper.recover() {
            Ok(Some(record)) => record,
            Err(error) if error.kind() == LinuxErrorKind::OwnershipConflict => {
                current_helper.rebase(active.metadata().generation() + 2, 3)?
            }
            Ok(None) | Err(_) => {
                return Err(LinuxError::new(
                    LinuxErrorKind::InvalidRecord,
                    "the current helper could not converge resolver ownership",
                ));
            }
        };
        let expected_before = LinkState::new(
            before.link(),
            changed_dns,
            changed_domains,
            before.default_route(),
        )?;
        let (mut backend, store) = current_helper.into_parts();
        assert_eq!(backend.state, owned);
        assert_eq!(converged.before(), &expected_before);

        let final_dns = vec![DnsServer::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 100)),
            0,
            "",
        )?];
        backend.state = LinkState::new(
            owned.link(),
            final_dns.clone(),
            owned.domains().to_vec(),
            owned.default_route(),
        )?;
        let mut final_convergence = ResolverTransaction::new(backend, store);
        let final_record = final_convergence.rebase(converged.metadata().generation() + 1, 4)?;
        let expected_before = LinkState::new(
            before.link(),
            final_dns,
            expected_before.domains().to_vec(),
            expected_before.default_route(),
        )?;
        let (backend, store) = final_convergence.into_parts();
        assert_eq!(backend.state, owned);
        assert_eq!(final_record.before(), &expected_before);

        let mut previous_generation = ResolverTransaction::new(backend, store);
        let unchanged = previous_generation.rebase(final_record.metadata().generation() + 1, 5)?;
        assert_eq!(unchanged, final_record);
        previous_generation.deactivate()?;
        let (backend, store) = previous_generation.into_parts();
        assert_eq!(backend.state, expected_before);
        assert_eq!(store.record, None);
    }
    Ok(())
}

#[test]
fn multiple_links_and_preowned_state_fail_closed() -> LinuxResult<()> {
    let prior = prior_state()?;
    let owned = LinkState::remap_loopback(prior.link())?;
    let duplicate = prior.clone();
    let multiple = ActivationRecord::prepare(metadata()?, &[prior, duplicate], owned.clone());
    assert_eq!(
        multiple.err().map(|value| value.kind()),
        Some(LinuxErrorKind::InvalidScope)
    );
    let preowned =
        ActivationRecord::prepare(metadata()?, std::slice::from_ref(&owned), owned.clone());
    assert_eq!(
        preowned.err().map(|value| value.kind()),
        Some(LinuxErrorKind::OwnershipConflict)
    );
    Ok(())
}

#[test]
fn codec_rejects_tampering_unknown_fields_and_oversize() -> Result<(), Box<dyn Error>> {
    let prior = prior_state()?;
    let owned = LinkState::remap_loopback(prior.link())?;
    let record = ActivationRecord::prepare(metadata()?, &[prior], owned)?;
    let encoded = RecordCodec::encode(&record)?;
    assert_eq!(RecordCodec::decode(&encoded)?, record);

    let mut value: serde_json::Value = serde_json::from_slice(&encoded)?;
    value["payload"]["metadata"]["generation"] = serde_json::Value::from(9_u64);
    let tampered = serde_json::to_vec(&value)?;
    assert_eq!(
        RecordCodec::decode(&tampered)
            .err()
            .map(|error| error.kind()),
        Some(LinuxErrorKind::InvalidRecord)
    );

    value["unexpected"] = serde_json::Value::Bool(true);
    let unknown = serde_json::to_vec(&value)?;
    assert_eq!(
        RecordCodec::decode(&unknown)
            .err()
            .map(|error| error.kind()),
        Some(LinuxErrorKind::InvalidRecord)
    );
    assert_eq!(
        RecordCodec::decode(&vec![b'x'; MAX_RECORD_BYTES + 1])
            .err()
            .map(|error| error.kind()),
        Some(LinuxErrorKind::InvalidRecord)
    );
    Ok(())
}

#[test]
fn root_record_contract_rejects_permissions_links_and_non_root_owner() {
    assert!(RecordCodec::validate_root_file(0, 0o600, true, false, 512).is_ok());
    for invalid in [
        RecordCodec::validate_root_file(1000, 0o600, true, false, 512),
        RecordCodec::validate_root_file(0, 0o644, true, false, 512),
        RecordCodec::validate_root_file(0, 0o400, true, false, 512),
        RecordCodec::validate_root_file(0, 0o600, true, true, 512),
        RecordCodec::validate_root_file(0, 0o600, false, false, 512),
        RecordCodec::validate_root_file(0, 0o600, true, false, 0),
    ] {
        assert_eq!(
            invalid.err().map(|error| error.kind()),
            Some(LinuxErrorKind::InvalidRecord)
        );
    }
}

#[test]
fn state_collections_are_bounded_before_platform_effects() -> LinuxResult<()> {
    let link = LinkIndex::new(7)?;
    let server = DnsServer::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53, "")?;
    let result = LinkState::new(link, vec![server; MAX_DNS_SERVERS + 1], Vec::new(), false);
    assert_eq!(
        result.err().map(|error| error.kind()),
        Some(LinuxErrorKind::InvalidState)
    );
    Ok(())
}

#[test]
fn activation_environment_requires_exact_named_descriptor_set() {
    let contract = SocketContract::remap();
    let environment =
        ActivationEnvironment::parse(4242, "4242", "3", "http:dns-udp:dns-tcp", &contract);
    assert!(environment.is_ok());
    if let Ok(environment) = environment {
        assert_eq!(environment.descriptor_number("http"), Some(3));
        assert_eq!(environment.descriptor_number("dns-tcp"), Some(5));
    }
    for invalid in [
        ActivationEnvironment::parse(4242, "4243", "3", "dns-udp:dns-tcp:http", &contract),
        ActivationEnvironment::parse(4242, "4242", "2", "dns-udp:dns-tcp", &contract),
        ActivationEnvironment::parse(4242, "4242", "3", "dns-udp:dns-udp:http", &contract),
        ActivationEnvironment::parse(4242, "4242", "3", "dns-udp:dns-tcp:other", &contract),
    ] {
        assert_eq!(
            invalid.err().map(|error| error.kind()),
            Some(LinuxErrorKind::InvalidServiceContract)
        );
    }
}

#[test]
fn generated_units_are_loopback_only_and_drop_process_privilege() -> LinuxResult<()> {
    let identity = ServiceIdentity::new("remap", "remap", "/usr/libexec/remap/remapd")?;
    let units = SystemdUnitSet::generate(&identity, &SocketContract::remap())?;
    assert!(units.service().contains("User=remap\nGroup=remap"));
    assert!(units.service().contains("CapabilityBoundingSet=\n"));
    assert!(units.service().contains("NoNewPrivileges=yes"));
    assert!(units.service().contains("ProtectSystem=strict"));
    assert!(!units.service().contains("User=root"));
    assert_eq!(units.sockets().len(), 3);
    assert!(
        units
            .sockets()
            .values()
            .all(|unit| unit.contains("127.0.0.1:"))
    );
    assert!(
        units
            .sockets()
            .values()
            .all(|unit| unit.contains("FreeBind=no\n")
                && !unit.contains("NonBlocking=")
                && !unit.contains("PartOf=remapd.service"))
    );
    assert!(
        units
            .sockets()
            .values()
            .all(|unit| !unit.contains("0.0.0.0"))
    );
    assert!(ServiceIdentity::new("root", "remap", "/usr/libexec/remap/remapd").is_err());
    assert!(ServiceIdentity::new("remap", "remap", "/tmp/remap daemon").is_err());
    let supervisor = ResolverSupervisorIdentity::new(
        "/usr/libexec/remap/remap-linux-system",
        ResolverSupervisorLink::new(
            LinkIndex::new(7)?,
            "eth0",
            remap_linux::ResolverLinkManager::SystemdNetworkd,
        )?,
        1000,
        1001,
        "/var/lib/remap-system",
        "/var/lib/remap/system.sock",
    )?;
    let installable =
        SystemdUnitSet::generate_installable(&identity, &supervisor, &SocketContract::remap())?;
    let resolver = installable
        .resolver_service()
        .ok_or_else(|| LinuxError::new(LinuxErrorKind::InvalidState, "missing resolver unit"))?;
    assert!(resolver.contains("User=root\nGroup=root"));
    assert!(resolver.contains("CapabilityBoundingSet=CAP_DAC_OVERRIDE"));
    assert!(resolver.contains("RestrictAddressFamilies=AF_UNIX"));
    assert!(
        resolver.contains("ExecCondition=/usr/libexec/remap/remap-linux-system authorize-runtime")
    );
    assert!(
        resolver.contains(
            "--link 7 --interface-name eth0 --manager systemd-networkd --owner-uid 1000 --daemon-uid 1001"
        )
    );
    assert!(!resolver.contains("dns-upstream"));
    assert!(
        installable
            .service()
            .contains("ExecCondition=+/usr/libexec/remap/remap-linux-system authorize-runtime")
    );
    assert!(!installable.service().contains("Restart="));
    assert!(installable.sockets().values().all(|unit| {
        unit.contains("ExecStartPre=/usr/libexec/remap/remap-linux-system authorize-runtime")
            && !unit.contains("Restart=")
    }));
    assert!(resolver.contains("Restart=on-failure"));
    assert!(resolver.contains("Wants=network-online.target\n"));
    assert!(resolver.contains("After=network-online.target"));
    assert!(!resolver.contains("ExecStartPre="));
    Ok(())
}

#[test]
fn link_monitor_retains_scope_on_ambiguity_and_reports_exact_lifecycle() -> LinuxResult<()> {
    let first = prior_state()?;
    let mut monitor = LinkScopeMonitor::new();
    assert_eq!(monitor.reconcile(&[]), LinkLifecycleEvent::NoSelection);
    assert_eq!(
        monitor.reconcile(std::slice::from_ref(&first)),
        LinkLifecycleEvent::Selected(first.clone())
    );
    assert_eq!(
        monitor.reconcile(std::slice::from_ref(&first)),
        LinkLifecycleEvent::Stable
    );
    let changed = LinkState::new(
        first.link(),
        first.dns_servers().to_vec(),
        first.domains().to_vec(),
        true,
    )?;
    assert_eq!(
        monitor.reconcile(std::slice::from_ref(&changed)),
        LinkLifecycleEvent::Changed {
            previous: first,
            current: changed.clone(),
        }
    );
    let second = LinkState::remap_loopback(LinkIndex::new(8)?)?;
    assert_eq!(
        monitor.reconcile(&[changed.clone(), second]),
        LinkLifecycleEvent::Ambiguous {
            previous: Some(changed.clone()),
            candidate_count: 2,
        }
    );
    assert_eq!(monitor.selected(), Some(&changed));
    assert_eq!(
        monitor.reconcile(&[]),
        LinkLifecycleEvent::Removed { previous: changed }
    );
    assert_eq!(monitor.selected(), None);
    Ok(())
}

fn prior_state() -> LinuxResult<LinkState> {
    let link = LinkIndex::new(7)?;
    LinkState::new(
        link,
        vec![DnsServer::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53)),
            853,
            "private-dns.example",
        )?],
        vec![
            LinkDomain::new("corp.example", true)?,
            LinkDomain::new("lan.example", false)?,
        ],
        false,
    )
}

fn metadata() -> LinuxResult<RecordMetadata> {
    RecordMetadata::new(Uuid::from_u128(0x1234), 7, 1000, 1_786_400_000)
}
