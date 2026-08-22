use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr};

use uuid::Uuid;

use crate::{
    ActivationRecord, ActivationStore, DnsServer, LinkDomain, LinkIndex, LinkState, LinuxError,
    LinuxErrorKind, LinuxResult, RecordMetadata, ResolvedBackend, ResolverTransaction,
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
