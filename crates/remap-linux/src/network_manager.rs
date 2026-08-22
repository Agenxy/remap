use std::collections::BTreeMap;

use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

use crate::resolved::{SystemdResolved, name_has_owner, snapshot_resolved, system_connection};
use crate::{
    ActivationPhase, ActivationRecord, ActivationStore, LinkIndex, LinkState, LinuxResult,
    NetworkManagerIpDns, NetworkManagerLegacyDns, NetworkManagerOwnership, RecordMetadata,
    ResolverManagerRecord,
};

#[path = "network_manager_errors.rs"]
mod errors;
use errors::{
    bus_error, external_change, invalid_scope, invalid_state, manager_identity_ready,
    manager_not_ready, method_error, observation_changed, observation_unstable, ownership_conflict,
    recovery_required, unsupported,
};

type Settings = BTreeMap<String, BTreeMap<String, OwnedValue>>;

const IPV4: &str = "ipv4";
const IPV6: &str = "ipv6";
const DNS_DATA: &str = "dns-data";
const DNS_SEARCH: &str = "dns-search";
const IGNORE_AUTO_DNS: &str = "ignore-auto-dns";
const DNS_PRIORITY: &str = "dns-priority";
const LEGACY_DNS: &str = "dns";
const METHOD: &str = "method";
const EXCLUSIVE_PRIORITY: i32 = i32::MIN;
const REAPPLY_PRESERVE_EXTERNAL_IP: u32 = 1;
const DEVICE_STATE_ACTIVATED: u32 = 100;
const NETWORK_MANAGER_SERVICE: &str = "org.freedesktop.NetworkManager";

#[derive(Debug)]
struct AppliedConnection {
    settings: Settings,
    version: u64,
    digest: [u8; 32],
}

/// Complete stable `NetworkManager` input used to guard activation or rebase.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NetworkManagerStartupObservation {
    resolved: LinkState,
    applied_version: u64,
    applied_digest: [u8; 32],
}

#[derive(Debug)]
struct NetworkManagerBackend {
    connection: zbus::blocking::Connection,
    device_path: OwnedObjectPath,
    interface_name: String,
    link: LinkIndex,
}

/// Crash-safe `NetworkManager` applied-connection resolver transaction.
#[derive(Debug)]
pub struct NetworkManagerTransaction<S> {
    backend: NetworkManagerBackend,
    store: S,
}

impl<S> NetworkManagerTransaction<S>
where
    S: ActivationStore,
{
    /// Connects to the exact `NetworkManager` device for one explicit link.
    ///
    /// # Errors
    ///
    /// Returns an error unless `NetworkManager` owns the selected interface and
    /// exposes its versioned applied-connection contract.
    pub fn connect(link: LinkIndex, store: S) -> LinuxResult<Self> {
        Ok(Self {
            backend: NetworkManagerBackend::connect(link)?,
            store,
        })
    }

    /// Connects only when the selected device retains an approved interface
    /// identity across manager arbitration and backend construction.
    ///
    /// # Errors
    ///
    /// Returns an ownership conflict if the interface was renamed or replaced.
    pub fn connect_expected(
        link: LinkIndex,
        expected_interface_name: &str,
        store: S,
    ) -> LinuxResult<Self> {
        let backend = NetworkManagerBackend::connect(link)?;
        require_interface_identity(expected_interface_name, &backend.interface_name)?;
        Ok(Self { backend, store })
    }

    /// Captures and atomically applies Remap DNS through `NetworkManager`.
    ///
    /// # Errors
    ///
    /// Returns an error for existing ownership, concurrent reapply, unsupported
    /// IP settings, or any state that cannot be restored exactly.
    pub fn activate(
        &mut self,
        metadata: RecordMetadata,
        owned: LinkState,
    ) -> LinuxResult<ActivationRecord> {
        let observation = self.startup_observation()?.ok_or_else(manager_not_ready)?;
        self.activate_observed(metadata, owned, &observation)
    }

    /// Activates from a stable `NetworkManager` observation after comparing the
    /// complete applied connection and resolved view again.
    ///
    /// # Errors
    ///
    /// Returns an error if manager state changed after stabilization.
    pub fn activate_observed(
        &mut self,
        metadata: RecordMetadata,
        owned: LinkState,
        observed: &NetworkManagerStartupObservation,
    ) -> LinuxResult<ActivationRecord> {
        if self.store.load()?.is_some() {
            return Err(ownership_conflict(
                "a resolver activation already owns the host",
            ));
        }
        let (current, applied) = self
            .backend
            .startup_observation()?
            .ok_or_else(manager_not_ready)?;
        if current != *observed {
            return Err(observation_changed());
        }
        let before = current.resolved;
        let (ownership, prepared) = prepare_ownership(&self.backend, &applied)?;
        let record = ActivationRecord::prepare_managed(
            metadata,
            before,
            owned,
            ResolverManagerRecord::NetworkManager(Box::new(ownership)),
        )?;
        self.store.save(&record)?;
        self.apply_owned(record, &applied, prepared)
    }

    /// Recovers an interrupted atomic reapply from exact full-connection digests.
    ///
    /// # Errors
    ///
    /// Returns an ownership conflict for any state other than the recorded
    /// before or owned connection.
    pub fn recover(&mut self) -> LinuxResult<Option<ActivationRecord>> {
        let Some(record) = self.store.load()? else {
            return Ok(None);
        };
        match record.phase() {
            ActivationPhase::Applying { .. } => self.recover_apply(record).map(Some),
            ActivationPhase::Active => {
                self.require_owned(&record)?;
                Ok(Some(record))
            }
            ActivationPhase::Restoring { .. } => {
                self.recover_restore(record)?;
                Ok(None)
            }
            ActivationPhase::Aborting { .. } => Err(recovery_required()),
        }
    }

    /// Restores the exact prior applied-connection DNS properties with CAS.
    ///
    /// # Errors
    ///
    /// Returns an ownership conflict unless both the full applied connection and
    /// resolved link still equal Remap's recorded owned state.
    pub fn deactivate(&mut self) -> LinuxResult<()> {
        let mut record = self
            .store
            .load()?
            .ok_or_else(|| ownership_conflict("no resolver activation is available"))?;
        if record.phase() != ActivationPhase::Active {
            return Err(recovery_required());
        }
        self.require_owned(&record)?;
        record.set_phase(ActivationPhase::Restoring { completed_steps: 0 })?;
        self.store.save(&record)?;
        self.restore(record)
    }

    /// Starts restoration only after a stable, manager-aware observation
    /// proves the complete active ownership contract is still exact.
    ///
    /// # Errors
    ///
    /// Returns an error if manager readiness, applied identity, or resolved
    /// state changed after stabilization.
    pub fn deactivate_observed(
        &mut self,
        observed: &NetworkManagerStartupObservation,
    ) -> LinuxResult<()> {
        let mut record = self
            .store
            .load()?
            .ok_or_else(|| ownership_conflict("no resolver activation is available"))?;
        if self.observation_requires_rebase(&record, observed)? {
            return Err(external_change());
        }
        record.set_phase(ActivationPhase::Restoring { completed_steps: 0 })?;
        self.store.save(&record)?;
        self.restore(record)
    }

    /// Restores or discards an incomplete first activation without guessing.
    ///
    /// # Errors
    ///
    /// Returns an ownership conflict when the applied connection matches neither
    /// exact safe transition point.
    pub fn abort_activation(&mut self) -> LinuxResult<()> {
        let Some(record) = self.store.load()? else {
            return Ok(());
        };
        let applied = self.backend.applied()?;
        let ownership = network_manager(&record)?;
        if applied.digest == ownership.before_connection_digest() {
            return self.store.remove(record.metadata());
        }
        if !connection_is_owned(&applied, ownership)? {
            return Err(external_change());
        }
        let active = self.finish_apply(record)?;
        self.require_owned(&active)?;
        let mut restoring = active;
        restoring.set_phase(ActivationPhase::Restoring { completed_steps: 0 })?;
        self.store.save(&restoring)?;
        self.restore(restoring)
    }

    /// Rebases a replaced applied connection and republishes Remap with one CAS.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-active record, unchanged connection, invalid
    /// ordering, or an unsupported new applied connection.
    pub fn rebase(
        &mut self,
        generation_candidate: u64,
        created_unix_seconds: u64,
    ) -> LinuxResult<ActivationRecord> {
        let observation = self.startup_observation()?.ok_or_else(manager_not_ready)?;
        self.rebase_observed(generation_candidate, created_unix_seconds, &observation)
    }

    /// Rebases from a stable `NetworkManager` observation after comparing the
    /// full applied connection and resolved view immediately before CAS.
    ///
    /// # Errors
    ///
    /// Returns an error if manager or activation state changed after
    /// stabilization.
    pub fn rebase_observed(
        &mut self,
        generation_candidate: u64,
        created_unix_seconds: u64,
        observed: &NetworkManagerStartupObservation,
    ) -> LinuxResult<ActivationRecord> {
        let record = self
            .store
            .load()?
            .ok_or_else(|| ownership_conflict("no resolver activation is available"))?;
        if record.phase() != ActivationPhase::Active {
            return Err(recovery_required());
        }
        let (current, applied) = self
            .backend
            .startup_observation()?
            .ok_or_else(manager_not_ready)?;
        if current != *observed {
            return Err(observation_changed());
        }
        let before = current.resolved;
        let prior_ownership = network_manager(&record)?;
        if connection_is_owned(&applied, prior_ownership)? {
            self.require_owned(&record)?;
            return Ok(record);
        }
        let direct_active_rebase = active_rebase_mode(
            before == *record.owned(),
            dns_sections_are_owned(&applied, prior_ownership)?,
        )?;
        let (ownership, prepared) = prepare_ownership(&self.backend, &applied)?;
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
        if direct_active_rebase {
            let ownership = prepare_owned_connection_rebase(
                &self.backend.interface_name,
                &applied,
                prior_ownership,
            )?;
            let successor = ActivationRecord::prepare_managed_active_rebase(
                metadata,
                record.before().clone(),
                record.owned().clone(),
                ResolverManagerRecord::NetworkManager(Box::new(ownership)),
            )?;
            self.store.replace(&record, &successor)?;
            self.require_owned(&successor)?;
            return Ok(successor);
        }
        let successor = ActivationRecord::prepare_managed(
            metadata,
            before,
            record.owned().clone(),
            ResolverManagerRecord::NetworkManager(Box::new(ownership)),
        )?;
        self.store.replace(&record, &successor)?;
        self.apply_owned(successor, &applied, prepared)
    }

    /// Returns the current resolved view for lifecycle reconciliation.
    ///
    /// # Errors
    ///
    /// Returns an error when resolved cannot provide a complete link snapshot.
    pub fn snapshot(&self) -> LinuxResult<LinkState> {
        self.backend.snapshot()
    }

    /// Returns a complete observation only while `NetworkManager` reports the
    /// exact managed device as activated.
    ///
    /// # Errors
    ///
    /// Returns an error when the device or applied connection cannot be read.
    pub fn startup_observation(&self) -> LinuxResult<Option<NetworkManagerStartupObservation>> {
        self.backend
            .startup_observation()
            .map(|value| value.map(|(observation, _applied)| observation))
    }

    /// Determines whether one exact stable observation differs from the full
    /// active `NetworkManager` ownership contract.
    ///
    /// # Errors
    ///
    /// Returns an error if the observation is stale, the record is not active,
    /// or applied and resolved ownership drift incoherently.
    pub fn observation_requires_rebase(
        &self,
        record: &ActivationRecord,
        observed: &NetworkManagerStartupObservation,
    ) -> LinuxResult<bool> {
        if record.phase() != ActivationPhase::Active {
            return Err(recovery_required());
        }
        let (current, applied) = self
            .backend
            .startup_observation()?
            .ok_or_else(observation_unstable)?;
        if current != *observed {
            return Err(observation_unstable());
        }
        let resolved = current.resolved;
        let ownership = network_manager(record)?;
        let connection_owned = connection_is_owned(&applied, ownership)?;
        let resolved_owned = resolved == *record.owned();
        if connection_owned && resolved_owned {
            return Ok(false);
        }
        active_rebase_mode(resolved_owned, dns_sections_are_owned(&applied, ownership)?)?;
        Ok(true)
    }

    /// Loads the exact durable ownership record.
    ///
    /// # Errors
    ///
    /// Returns an error when root-owned storage validation fails.
    pub fn load(&mut self) -> LinuxResult<Option<ActivationRecord>> {
        self.store.load()
    }

    /// Returns the locked activation store after native lifecycle reconciliation.
    #[must_use]
    pub fn into_store(self) -> S {
        self.store
    }

    fn apply_owned(
        &mut self,
        record: ActivationRecord,
        applied: &AppliedConnection,
        prepared: Settings,
    ) -> LinuxResult<ActivationRecord> {
        let ownership = network_manager(&record)?;
        if applied.digest != ownership.before_connection_digest()
            || protected_digest(&prepared)? != ownership.protected_connection_digest()
        {
            return Err(external_change());
        }
        self.backend.reapply(prepared, applied.version)?;
        self.require_owned(&record)?;
        self.finish_apply(record)
    }

    fn recover_apply(&mut self, record: ActivationRecord) -> LinuxResult<ActivationRecord> {
        let applied = self.backend.applied()?;
        let ownership = network_manager(&record)?;
        if connection_is_owned(&applied, ownership)? {
            self.require_owned(&record)?;
            return self.finish_apply(record);
        }
        if applied.digest != ownership.before_connection_digest() {
            return Err(external_change());
        }
        let prepared = apply_owned_dns(&applied.settings)?;
        self.apply_owned(record, &applied, prepared)
    }

    fn finish_apply(&mut self, mut record: ActivationRecord) -> LinuxResult<ActivationRecord> {
        let completed = match record.phase() {
            ActivationPhase::Applying { completed_steps } => completed_steps,
            ActivationPhase::Active => return Ok(record),
            ActivationPhase::Aborting { .. } | ActivationPhase::Restoring { .. } => {
                return Err(recovery_required());
            }
        };
        for completed_steps in (completed + 1)..=3 {
            record.set_phase(ActivationPhase::Applying { completed_steps })?;
            self.store.save(&record)?;
        }
        record.set_phase(ActivationPhase::Active)?;
        self.store.save(&record)?;
        Ok(record)
    }

    fn restore(&mut self, record: ActivationRecord) -> LinuxResult<()> {
        let applied = self.backend.applied()?;
        let ownership = network_manager(&record)?;
        if applied.digest == ownership.before_connection_digest() {
            self.require_before_connection(&record)?;
            return self.finish_restore(record);
        }
        if !connection_is_owned(&applied, ownership)? {
            return Err(external_change());
        }
        let restored = restore_dns(&applied.settings, ownership)?;
        self.backend.reapply(restored, applied.version)?;
        self.require_before_connection(&record)?;
        self.finish_restore(record)
    }

    fn recover_restore(&mut self, record: ActivationRecord) -> LinuxResult<()> {
        self.restore(record)
    }

    fn finish_restore(&mut self, mut record: ActivationRecord) -> LinuxResult<()> {
        let completed = match record.phase() {
            ActivationPhase::Restoring { completed_steps } => completed_steps,
            ActivationPhase::Applying { .. }
            | ActivationPhase::Aborting { .. }
            | ActivationPhase::Active => return Err(recovery_required()),
        };
        for completed_steps in (completed + 1)..=3 {
            record.set_phase(ActivationPhase::Restoring { completed_steps })?;
            self.store.save(&record)?;
        }
        self.store.remove(record.metadata())
    }

    fn require_owned(&self, record: &ActivationRecord) -> LinuxResult<()> {
        self.require_owned_connection(record)?;
        if self.backend.snapshot()? != *record.owned() {
            return Err(external_change());
        }
        Ok(())
    }

    fn require_owned_connection(&self, record: &ActivationRecord) -> LinuxResult<()> {
        let applied = self.backend.applied()?;
        if !connection_is_owned(&applied, network_manager(record)?)? {
            return Err(external_change());
        }
        Ok(())
    }

    fn require_before_connection(&self, record: &ActivationRecord) -> LinuxResult<()> {
        if self.backend.applied()?.digest != network_manager(record)?.before_connection_digest()
            || self.backend.snapshot()? != *record.before()
        {
            return Err(external_change());
        }
        Ok(())
    }
}

impl NetworkManagerBackend {
    fn connect(link: LinkIndex) -> LinuxResult<Self> {
        let connection = system_connection()?;
        let interface_name = nix::net::if_::if_indextoname(link.get())
            .map_err(|_error| invalid_scope())?
            .into_string()
            .map_err(|_error| invalid_scope())?;
        let manager = NetworkManagerProxy::new(&connection).map_err(|_error| bus_error())?;
        let device_path = manager
            .get_device_by_ip_iface(&interface_name)
            .map_err(|_error| invalid_scope())?;
        let backend = Self {
            connection,
            device_path,
            interface_name,
            link,
        };
        if !backend
            .device_proxy()?
            .managed()
            .map_err(|_error| bus_error())?
        {
            return Err(invalid_scope());
        }
        Ok(backend)
    }

    fn snapshot(&self) -> LinuxResult<LinkState> {
        snapshot_resolved(&self.connection, self.link)
    }

    fn ready(&self) -> LinuxResult<bool> {
        if !name_has_owner(&self.connection, NETWORK_MANAGER_SERVICE)? {
            return Ok(false);
        }
        let inspection = SystemdResolved::inspect(self.link)?;
        if !manager_identity_ready(
            name_has_owner(&self.connection, NETWORK_MANAGER_SERVICE)?,
            inspection.manager(),
            inspection.interface_name(),
            &self.interface_name,
        )? {
            return Ok(false);
        }
        let proxy = self.device_proxy()?;
        Ok(proxy.managed().map_err(|_error| bus_error())?
            && proxy.state().map_err(|_error| bus_error())? == DEVICE_STATE_ACTIVATED)
    }

    fn startup_observation(
        &self,
    ) -> LinuxResult<Option<(NetworkManagerStartupObservation, AppliedConnection)>> {
        if !self.ready()? {
            return Ok(None);
        }
        let applied = self.applied()?;
        let resolved = self.snapshot()?;
        if !self.ready()? {
            return Ok(None);
        }
        Ok(Some((
            NetworkManagerStartupObservation {
                resolved,
                applied_version: applied.version,
                applied_digest: applied.digest,
            },
            applied,
        )))
    }

    fn applied(&self) -> LinuxResult<AppliedConnection> {
        let proxy = self.device_proxy()?;
        let (settings, version) = proxy
            .get_applied_connection(0)
            .map_err(|error| method_error(&error))?;
        let digest = digest(&settings)?;
        Ok(AppliedConnection {
            settings,
            version,
            digest,
        })
    }

    fn reapply(&self, settings: Settings, version: u64) -> LinuxResult<()> {
        self.device_proxy()?
            .reapply(settings, version, REAPPLY_PRESERVE_EXTERNAL_IP)
            .map_err(|error| method_error(&error))
    }

    fn device_proxy(&self) -> LinuxResult<NetworkManagerDeviceProxy<'_>> {
        NetworkManagerDeviceProxy::builder(&self.connection)
            .path(self.device_path.clone())
            .map_err(|_error| bus_error())?
            .build()
            .map_err(|_error| bus_error())
    }
}

fn prepare_ownership(
    backend: &NetworkManagerBackend,
    applied: &AppliedConnection,
) -> LinuxResult<(NetworkManagerOwnership, Settings)> {
    require_ipv4(&applied.settings)?;
    let ipv4 = snapshot_ip_dns(&applied.settings, IPV4)?;
    let ipv6 = snapshot_ip_dns(&applied.settings, IPV6)?;
    let prepared = apply_owned_dns(&applied.settings)?;
    let protected_digest = protected_digest(&prepared)?;
    let ownership = NetworkManagerOwnership::new(
        backend.interface_name.clone(),
        applied.digest,
        protected_digest,
        ipv4,
        ipv6,
    )?;
    Ok((ownership, prepared))
}

fn prepare_owned_connection_rebase(
    interface_name: &str,
    applied: &AppliedConnection,
    prior: &NetworkManagerOwnership,
) -> LinuxResult<NetworkManagerOwnership> {
    if !dns_sections_are_owned(applied, prior)? {
        return Err(external_change());
    }
    let restored = restore_dns(&applied.settings, prior)?;
    NetworkManagerOwnership::new(
        interface_name.to_owned(),
        digest(&restored)?,
        protected_digest(&applied.settings)?,
        prior.ipv4().cloned(),
        prior.ipv6().cloned(),
    )
}

fn active_rebase_mode(resolved_owned: bool, connection_dns_owned: bool) -> LinuxResult<bool> {
    match (resolved_owned, connection_dns_owned) {
        (true, true) => Ok(true),
        (false, false) => Ok(false),
        (true, false) | (false, true) => Err(external_change()),
    }
}

fn require_ipv4(settings: &Settings) -> LinuxResult<()> {
    let section = settings.get(IPV4).ok_or_else(unsupported)?;
    let method = section
        .get(METHOD)
        .ok_or_else(unsupported)
        .and_then(value_string)?;
    if matches!(method.as_str(), "disabled" | "shared" | "link-local") {
        return Err(unsupported());
    }
    Ok(())
}

fn snapshot_ip_dns(settings: &Settings, section: &str) -> LinuxResult<Option<NetworkManagerIpDns>> {
    let Some(values) = settings.get(section) else {
        return Ok(None);
    };
    NetworkManagerIpDns::new(
        optional_strings(values.get(DNS_DATA))?,
        optional_strings(values.get(DNS_SEARCH))?,
        optional_bool(values.get(IGNORE_AUTO_DNS))?,
        optional_i32(values.get(DNS_PRIORITY))?,
        optional_legacy_dns(values.get(LEGACY_DNS), section == IPV4)?,
    )
    .map(Some)
}

fn apply_owned_dns(settings: &Settings) -> LinuxResult<Settings> {
    let mut owned = clone_settings(settings)?;
    let ipv4 = owned.get_mut(IPV4).ok_or_else(unsupported)?;
    insert_strings(ipv4, DNS_DATA, &["127.0.0.1"])?;
    insert_strings(ipv4, DNS_SEARCH, &["~."])?;
    ipv4.insert(IGNORE_AUTO_DNS.to_owned(), OwnedValue::from(true));
    ipv4.insert(
        DNS_PRIORITY.to_owned(),
        OwnedValue::from(EXCLUSIVE_PRIORITY),
    );
    insert_legacy_ipv4(ipv4, &[u32::from_ne_bytes([127, 0, 0, 1])])?;
    if let Some(ipv6) = owned.get_mut(IPV6) {
        insert_strings(ipv6, DNS_DATA, &[])?;
        insert_strings(ipv6, DNS_SEARCH, &[])?;
        ipv6.insert(IGNORE_AUTO_DNS.to_owned(), OwnedValue::from(true));
        ipv6.insert(
            DNS_PRIORITY.to_owned(),
            OwnedValue::from(EXCLUSIVE_PRIORITY),
        );
        insert_legacy_ipv6(ipv6, &[])?;
    }
    Ok(owned)
}

fn restore_dns(settings: &Settings, ownership: &NetworkManagerOwnership) -> LinuxResult<Settings> {
    let mut restored = clone_settings(settings)?;
    restore_section(&mut restored, IPV4, ownership.ipv4())?;
    restore_section(&mut restored, IPV6, ownership.ipv6())?;
    Ok(restored)
}

fn restore_section(
    settings: &mut Settings,
    name: &str,
    prior: Option<&NetworkManagerIpDns>,
) -> LinuxResult<()> {
    match (settings.get_mut(name), prior) {
        (Some(section), Some(prior)) => {
            restore_strings(section, DNS_DATA, prior.dns_data())?;
            restore_strings(section, DNS_SEARCH, prior.dns_search())?;
            restore_bool(section, IGNORE_AUTO_DNS, prior.ignore_auto_dns());
            restore_i32(section, DNS_PRIORITY, prior.dns_priority());
            restore_legacy(section, prior.legacy_dns())?;
            Ok(())
        }
        (None, None) => Ok(()),
        (Some(_), None) | (None, Some(_)) => Err(external_change()),
    }
}

fn clone_settings(settings: &Settings) -> LinuxResult<Settings> {
    settings
        .iter()
        .map(|(section, values)| {
            let values = values
                .iter()
                .map(|(name, value)| {
                    value
                        .try_clone()
                        .map(|value| (name.clone(), value))
                        .map_err(|_error| invalid_state())
                })
                .collect::<LinuxResult<BTreeMap<_, _>>>()?;
            Ok((section.clone(), values))
        })
        .collect()
}

fn digest(settings: &Settings) -> LinuxResult<[u8; 32]> {
    let context = zbus::zvariant::serialized::Context::new_dbus(zbus::zvariant::LE, 0);
    let encoded = zbus::zvariant::to_bytes(context, settings).map_err(|_error| invalid_state())?;
    Ok(crate::digest::sha256(encoded.bytes()))
}

fn protected_digest(settings: &Settings) -> LinuxResult<[u8; 32]> {
    let mut protected = clone_settings(settings)?;
    for section_name in [IPV4, IPV6] {
        if let Some(section) = protected.get_mut(section_name) {
            for property in [
                DNS_DATA,
                DNS_SEARCH,
                IGNORE_AUTO_DNS,
                DNS_PRIORITY,
                LEGACY_DNS,
            ] {
                section.remove(property);
            }
        }
    }
    digest(&protected)
}

fn connection_is_owned(
    applied: &AppliedConnection,
    ownership: &NetworkManagerOwnership,
) -> LinuxResult<bool> {
    if protected_digest(&applied.settings)? != ownership.protected_connection_digest() {
        return Ok(false);
    }
    if !dns_sections_are_owned(applied, ownership)? {
        return Ok(false);
    }
    Ok(true)
}

fn dns_sections_are_owned(
    applied: &AppliedConnection,
    ownership: &NetworkManagerOwnership,
) -> LinuxResult<bool> {
    if !section_is_owned(&applied.settings, IPV4, true)? {
        return Ok(false);
    }
    match ownership.ipv6() {
        Some(_) => section_is_owned(&applied.settings, IPV6, false),
        None => Ok(!applied.settings.contains_key(IPV6)),
    }
}

fn section_is_owned(settings: &Settings, name: &str, ipv4: bool) -> LinuxResult<bool> {
    let Some(section) = settings.get(name) else {
        return Ok(false);
    };
    let dns_owned = if ipv4 {
        optional_strings(section.get(DNS_DATA))? == Some(vec!["127.0.0.1".to_owned()])
            && optional_strings(section.get(DNS_SEARCH))? == Some(vec!["~.".to_owned()])
            && optional_legacy_dns(section.get(LEGACY_DNS), true)?
                == Some(NetworkManagerLegacyDns::Ipv4(vec![u32::from_ne_bytes([
                    127, 0, 0, 1,
                ])]))
    } else {
        optional_strings(section.get(DNS_DATA))?.is_none()
            && optional_strings(section.get(DNS_SEARCH))?.is_none()
            && optional_legacy_dns(section.get(LEGACY_DNS), false)?.is_none()
    };
    Ok(dns_owned
        && optional_bool(section.get(IGNORE_AUTO_DNS))? == Some(true)
        && optional_i32(section.get(DNS_PRIORITY))? == Some(EXCLUSIVE_PRIORITY))
}

fn optional_strings(value: Option<&OwnedValue>) -> LinuxResult<Option<Vec<String>>> {
    value
        .map(|value| {
            value
                .try_clone()
                .map_err(|_error| invalid_state())
                .and_then(|value| Vec::<String>::try_from(value).map_err(|_error| invalid_state()))
        })
        .transpose()
}

fn optional_bool(value: Option<&OwnedValue>) -> LinuxResult<Option<bool>> {
    value.map(value_bool).transpose()
}

fn optional_i32(value: Option<&OwnedValue>) -> LinuxResult<Option<i32>> {
    value.map(value_i32).transpose()
}

fn optional_legacy_dns(
    value: Option<&OwnedValue>,
    ipv4: bool,
) -> LinuxResult<Option<NetworkManagerLegacyDns>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.try_clone().map_err(|_error| invalid_state())?;
    if ipv4 {
        Vec::<u32>::try_from(value)
            .map(NetworkManagerLegacyDns::Ipv4)
            .map(Some)
            .map_err(|_error| invalid_state())
    } else {
        Vec::<Vec<u8>>::try_from(value)
            .map(NetworkManagerLegacyDns::Ipv6)
            .map(Some)
            .map_err(|_error| invalid_state())
    }
}

fn value_string(value: &OwnedValue) -> LinuxResult<String> {
    value
        .try_clone()
        .map_err(|_error| invalid_state())
        .and_then(|value| String::try_from(value).map_err(|_error| invalid_state()))
}

fn value_bool(value: &OwnedValue) -> LinuxResult<bool> {
    bool::try_from(value).map_err(|_error| invalid_state())
}

fn value_i32(value: &OwnedValue) -> LinuxResult<i32> {
    i32::try_from(value).map_err(|_error| invalid_state())
}

fn insert_strings(
    section: &mut BTreeMap<String, OwnedValue>,
    name: &str,
    values: &[&str],
) -> LinuxResult<()> {
    let values = values
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    let value = OwnedValue::try_from(Value::new(values)).map_err(|_error| invalid_state())?;
    section.insert(name.to_owned(), value);
    Ok(())
}

fn insert_legacy_ipv4(
    section: &mut BTreeMap<String, OwnedValue>,
    values: &[u32],
) -> LinuxResult<()> {
    let value =
        OwnedValue::try_from(Value::new(values.to_vec())).map_err(|_error| invalid_state())?;
    section.insert(LEGACY_DNS.to_owned(), value);
    Ok(())
}

fn insert_legacy_ipv6(
    section: &mut BTreeMap<String, OwnedValue>,
    values: &[Vec<u8>],
) -> LinuxResult<()> {
    let value =
        OwnedValue::try_from(Value::new(values.to_vec())).map_err(|_error| invalid_state())?;
    section.insert(LEGACY_DNS.to_owned(), value);
    Ok(())
}

fn restore_strings(
    section: &mut BTreeMap<String, OwnedValue>,
    name: &str,
    value: Option<&Vec<String>>,
) -> LinuxResult<()> {
    match value {
        Some(values) => {
            let value = OwnedValue::try_from(Value::new(values.clone()))
                .map_err(|_error| invalid_state())?;
            section.insert(name.to_owned(), value);
        }
        None => {
            section.remove(name);
        }
    }
    Ok(())
}

fn restore_bool(section: &mut BTreeMap<String, OwnedValue>, name: &str, value: Option<bool>) {
    match value {
        Some(value) => {
            section.insert(name.to_owned(), OwnedValue::from(value));
        }
        None => {
            section.remove(name);
        }
    }
}

fn restore_i32(section: &mut BTreeMap<String, OwnedValue>, name: &str, value: Option<i32>) {
    match value {
        Some(value) => {
            section.insert(name.to_owned(), OwnedValue::from(value));
        }
        None => {
            section.remove(name);
        }
    }
}

fn restore_legacy(
    section: &mut BTreeMap<String, OwnedValue>,
    value: Option<&NetworkManagerLegacyDns>,
) -> LinuxResult<()> {
    match value {
        Some(NetworkManagerLegacyDns::Ipv4(values)) => insert_legacy_ipv4(section, values),
        Some(NetworkManagerLegacyDns::Ipv6(values)) => insert_legacy_ipv6(section, values),
        None => {
            section.remove(LEGACY_DNS);
            Ok(())
        }
    }
}

fn network_manager(record: &ActivationRecord) -> LinuxResult<&NetworkManagerOwnership> {
    match record.manager() {
        ResolverManagerRecord::NetworkManager(ownership) => Ok(ownership),
        ResolverManagerRecord::Systemd
        | ResolverManagerRecord::SystemdResolved(_)
        | ResolverManagerRecord::SystemdNetworkd(_) => Err(recovery_required()),
    }
}

fn require_interface_identity(expected: &str, observed: &str) -> LinuxResult<()> {
    if expected == observed {
        Ok(())
    } else {
        Err(ownership_conflict(
            "the NetworkManager interface changed after approved inspection",
        ))
    }
}

#[zbus::proxy(
    interface = "org.freedesktop.NetworkManager",
    default_service = "org.freedesktop.NetworkManager",
    default_path = "/org/freedesktop/NetworkManager",
    gen_async = false
)]
trait NetworkManager {
    #[zbus(name = "GetDeviceByIpIface")]
    fn get_device_by_ip_iface(&self, interface_name: &str) -> zbus::Result<OwnedObjectPath>;
}

#[zbus::proxy(
    interface = "org.freedesktop.NetworkManager.Device",
    default_service = "org.freedesktop.NetworkManager",
    gen_async = false
)]
trait NetworkManagerDevice {
    #[zbus(property, name = "Managed")]
    fn managed(&self) -> zbus::Result<bool>;

    #[zbus(property, name = "State")]
    fn state(&self) -> zbus::Result<u32>;

    #[zbus(name = "GetAppliedConnection")]
    fn get_applied_connection(&self, flags: u32) -> zbus::Result<(Settings, u64)>;

    #[zbus(name = "Reapply")]
    fn reapply(&self, connection: Settings, version: u64, flags: u32) -> zbus::Result<()>;
}

#[cfg(test)]
#[path = "network_manager_tests.rs"]
mod tests;
