// SPDX-License-Identifier: GPL-3.0-or-later
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr};

use uuid::Uuid;

use crate::{
    ActivationPhase, ActivationRecord, ActivationStore, DnsServer, LinkDomain, LinkIndex,
    LinkState, LinuxError, LinuxErrorKind, LinuxResult, RecordMetadata, ResolvedBackend,
    ResolverTransaction,
};

#[derive(Debug)]
struct SequenceBackend {
    state: LinkState,
    observations: VecDeque<Option<LinkState>>,
}

impl ResolvedBackend for SequenceBackend {
    fn startup_snapshot(&mut self, _link: LinkIndex) -> LinuxResult<Option<LinkState>> {
        Ok(self
            .observations
            .pop_front()
            .unwrap_or_else(|| Some(self.state.clone())))
    }

    fn snapshot(&mut self, _link: LinkIndex) -> LinuxResult<LinkState> {
        Ok(self.state.clone())
    }

    fn set_dns(&mut self, _link: LinkIndex, servers: &[DnsServer]) -> LinuxResult<()> {
        self.state = LinkState::new(
            self.state.link(),
            servers.to_vec(),
            self.state.domains().to_vec(),
            self.state.default_route(),
        )?;
        Ok(())
    }

    fn set_domains(&mut self, _link: LinkIndex, domains: &[LinkDomain]) -> LinuxResult<()> {
        self.state = LinkState::new(
            self.state.link(),
            self.state.dns_servers().to_vec(),
            domains.to_vec(),
            self.state.default_route(),
        )?;
        Ok(())
    }

    fn set_default_route(&mut self, _link: LinkIndex, enabled: bool) -> LinuxResult<()> {
        self.state = LinkState::new(
            self.state.link(),
            self.state.dns_servers().to_vec(),
            self.state.domains().to_vec(),
            enabled,
        )?;
        Ok(())
    }
}

#[derive(Debug, Default)]
struct MemoryStore {
    record: Option<ActivationRecord>,
    saves: usize,
}

impl ActivationStore for MemoryStore {
    fn load(&mut self) -> LinuxResult<Option<ActivationRecord>> {
        Ok(self.record.clone())
    }

    fn save(&mut self, record: &ActivationRecord) -> LinuxResult<()> {
        self.saves += 1;
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
                "synthetic record changed",
            ));
        }
        self.save(successor)
    }

    fn remove(&mut self, metadata: &RecordMetadata) -> LinuxResult<()> {
        if self.record.as_ref().map(ActivationRecord::metadata) != Some(metadata) {
            return Err(LinuxError::new(
                LinuxErrorKind::OwnershipConflict,
                "synthetic record changed",
            ));
        }
        self.record = None;
        Ok(())
    }
}

#[test]
fn transitional_observations_retry_without_durable_or_native_effects() -> LinuxResult<()> {
    let link = LinkIndex::new(7)?;
    let before = LinkState::new(
        link,
        vec![DnsServer::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53)),
            0,
            "",
        )?],
        vec![LinkDomain::new("before.example", false)?],
        false,
    )?;
    let owned = LinkState::remap_loopback(link)?;
    let backend = SequenceBackend {
        state: before,
        observations: VecDeque::new(),
    };
    let mut activation = ResolverTransaction::new(backend, MemoryStore::default());
    let metadata = RecordMetadata::new(Uuid::from_u128(7), 7, 1000, 7)?;
    let active = activation.activate(metadata, owned.clone())?;
    let (mut backend, store) = activation.into_parts();
    let first = LinkState::new(
        link,
        vec![DnsServer::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)),
            0,
            "",
        )?],
        owned.domains().to_vec(),
        owned.default_route(),
    )?;
    let second = LinkState::new(
        link,
        first.dns_servers().to_vec(),
        vec![LinkDomain::new("ready.example", false)?],
        owned.default_route(),
    )?;
    backend
        .observations
        .extend([Some(first), None, Some(second.clone()), Some(second)]);
    let expected_saves = store.saves;
    let mut transaction = ResolverTransaction::new(backend, store);

    let first = transaction
        .startup_observation(link)?
        .ok_or_else(|| LinuxError::new(LinuxErrorKind::InvalidState, "missing observation"))?;
    assert_eq!(
        transaction
            .observation_requires_rebase(&active, &first)
            .err()
            .map(|error| error.kind()),
        Some(LinuxErrorKind::UnstableObservation)
    );
    let second = transaction
        .startup_observation(link)?
        .ok_or_else(|| LinuxError::new(LinuxErrorKind::InvalidState, "missing observation"))?;
    assert!(transaction.observation_requires_rebase(&active, &second)?);

    let (backend, store) = transaction.into_parts();
    assert_eq!(backend.state, owned);
    assert_eq!(store.record, Some(active));
    assert_eq!(store.saves, expected_saves);
    Ok(())
}

type MemoryTransaction = ResolverTransaction<SequenceBackend, MemoryStore>;

fn upstream(octet: u8) -> LinuxResult<LinkState> {
    LinkState::new(
        LinkIndex::new(7)?,
        vec![DnsServer::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, octet)),
            0,
            "",
        )?],
        vec![LinkDomain::new("before.example", false)?],
        false,
    )
}

fn active_transaction(before: LinkState) -> LinuxResult<(MemoryTransaction, ActivationRecord)> {
    let owned = LinkState::remap_loopback(before.link())?;
    let backend = SequenceBackend {
        state: before,
        observations: VecDeque::new(),
    };
    let mut transaction = ResolverTransaction::new(backend, MemoryStore::default());
    let metadata = RecordMetadata::new(Uuid::from_u128(7), 7, 1000, 7)?;
    let active = transaction.activate(metadata, owned)?;
    Ok((transaction, active))
}

fn observe(transaction: &mut MemoryTransaction) -> LinuxResult<crate::ResolverStartupObservation> {
    transaction
        .startup_observation(LinkIndex::new(7)?)?
        .ok_or_else(|| LinuxError::new(LinuxErrorKind::InvalidState, "missing observation"))
}

#[test]
fn bypass_restores_the_capture_and_keeps_the_activation() -> LinuxResult<()> {
    let before = upstream(53)?;
    let (mut transaction, active) = active_transaction(before.clone())?;
    let observed = observe(&mut transaction)?;

    let bypassed = transaction.bypass_observed(&observed)?;

    assert_eq!(bypassed.phase(), ActivationPhase::Bypassed);
    assert_eq!(bypassed.metadata(), active.metadata());
    assert_eq!(bypassed.before(), active.before());
    let (backend, store) = transaction.into_parts();
    assert_eq!(backend.state, before);
    assert_eq!(store.record, Some(bypassed));
    Ok(())
}

#[test]
fn bypass_never_writes_over_a_foreign_change() -> LinuxResult<()> {
    let (transaction, active) = active_transaction(upstream(53)?)?;
    let (mut backend, store) = transaction.into_parts();
    let foreign = LinkState::new(
        active.owned().link(),
        upstream(99)?.dns_servers().to_vec(),
        active.owned().domains().to_vec(),
        active.owned().default_route(),
    )?;
    backend.state = foreign.clone();
    let saves = store.saves;
    let mut transaction = ResolverTransaction::new(backend, store);
    let observed = observe(&mut transaction)?;

    let refused = transaction.bypass_observed(&observed);

    assert_eq!(
        refused.err().map(|error| error.kind()),
        Some(LinuxErrorKind::OwnershipConflict)
    );
    let (backend, store) = transaction.into_parts();
    assert_eq!(backend.state, foreign);
    assert_eq!(store.record, Some(active));
    assert_eq!(store.saves, saves);
    Ok(())
}

#[test]
fn an_interrupted_bypass_finishes_as_a_bypass_not_a_deactivation() -> LinuxResult<()> {
    let before = upstream(53)?;
    let (transaction, active) = active_transaction(before.clone())?;
    let (mut backend, mut store) = transaction.into_parts();
    let mut interrupted = active.clone();
    interrupted.set_phase(ActivationPhase::Bypassing { completed_steps: 1 })?;
    store.save(&interrupted)?;
    backend.state = LinkState::new(
        before.link(),
        before.dns_servers().to_vec(),
        active.owned().domains().to_vec(),
        active.owned().default_route(),
    )?;
    let mut transaction = ResolverTransaction::new(backend, store);

    let recovered = transaction.recover()?;

    assert_eq!(
        recovered.as_ref().map(ActivationRecord::phase),
        Some(ActivationPhase::Bypassed)
    );
    let (backend, store) = transaction.into_parts();
    assert_eq!(backend.state, before);
    assert_eq!(store.record, recovered);
    Ok(())
}

#[test]
fn a_bypassed_record_survives_recovery_after_the_network_changed() -> LinuxResult<()> {
    let (mut transaction, _active) = active_transaction(upstream(53)?)?;
    let observed = observe(&mut transaction)?;
    let bypassed = transaction.bypass_observed(&observed)?;
    let (mut backend, store) = transaction.into_parts();
    backend.state = upstream(54)?;
    let mut transaction = ResolverTransaction::new(backend, store);

    assert_eq!(transaction.recover()?, Some(bypassed));
    Ok(())
}

#[test]
fn rearm_captures_the_network_afresh_under_the_same_activation() -> LinuxResult<()> {
    let (mut transaction, active) = active_transaction(upstream(53)?)?;
    let observed = observe(&mut transaction)?;
    let bypassed = transaction.bypass_observed(&observed)?;
    let (mut backend, store) = transaction.into_parts();
    let offered = upstream(54)?;
    backend.state = offered.clone();
    let mut transaction = ResolverTransaction::new(backend, store);
    let observed = observe(&mut transaction)?;

    let rearmed = transaction.rearm_observed(3, 9, &observed)?;

    assert_eq!(rearmed.phase(), ActivationPhase::Active);
    assert_eq!(
        rearmed.metadata().activation_id(),
        active.metadata().activation_id()
    );
    assert_eq!(
        rearmed.metadata().owner_uid(),
        active.metadata().owner_uid()
    );
    assert!(rearmed.metadata().generation() > bypassed.metadata().generation());
    assert_eq!(rearmed.before(), &offered);
    let (backend, store) = transaction.into_parts();
    assert_eq!(&backend.state, active.owned());
    assert_eq!(store.record, Some(rearmed));
    Ok(())
}

#[test]
fn rearm_and_release_refuse_a_record_that_is_not_bypassed() -> LinuxResult<()> {
    let (mut transaction, active) = active_transaction(upstream(53)?)?;
    let observed = observe(&mut transaction)?;

    assert_eq!(
        transaction
            .rearm_observed(9, 9, &observed)
            .err()
            .map(|error| error.kind()),
        Some(LinuxErrorKind::RecoveryRequired)
    );
    assert_eq!(
        transaction
            .release_bypassed()
            .err()
            .map(|error| error.kind()),
        Some(LinuxErrorKind::RecoveryRequired)
    );
    let (backend, store) = transaction.into_parts();
    assert_eq!(&backend.state, active.owned());
    assert_eq!(store.record, Some(active));
    Ok(())
}

#[test]
fn release_forgets_a_bypass_without_touching_the_link() -> LinuxResult<()> {
    let (mut transaction, _active) = active_transaction(upstream(53)?)?;
    let observed = observe(&mut transaction)?;
    transaction.bypass_observed(&observed)?;
    let (mut backend, store) = transaction.into_parts();
    let offered = upstream(54)?;
    backend.state = offered.clone();
    let mut transaction = ResolverTransaction::new(backend, store);

    transaction.release_bypassed()?;

    let (backend, store) = transaction.into_parts();
    assert_eq!(backend.state, offered);
    assert_eq!(store.record, None);
    Ok(())
}
