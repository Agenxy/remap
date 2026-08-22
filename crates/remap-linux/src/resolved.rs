use crate::{
    DnsServer, LinkDomain, LinkIndex, LinkState, LinuxError, LinuxErrorKind, LinuxResult,
    ResolverManagerRecord,
};

#[cfg(target_os = "linux")]
const NATIVE_METHOD_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(100);

/// Native owner of the selected resolver link.
#[derive(Debug, Clone, Copy, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolverLinkManager {
    /// systemd-resolved transient per-link configuration.
    SystemdResolved,
    /// systemd-networkd persistent link configuration.
    SystemdNetworkd,
    /// `NetworkManager` applied-connection configuration.
    NetworkManager,
}

/// Read-only suitability of one resolver link for explicit selection.
#[derive(Debug, Clone, Copy, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolverLinkSelectionState {
    /// Has usable non-loopback DNS and is the native default DNS route.
    SupportedPrimary,
    /// Has usable non-loopback DNS but is not the native default DNS route.
    SupportedSecondary,
    /// Has no usable non-loopback DNS upstream.
    Inactive,
    /// Effective resolved state could not be captured exactly.
    Unsupported,
}

/// Bounded, privacy-safe resolver-link candidate.
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolverLinkInspection {
    index: LinkIndex,
    interface_name: String,
    manager: ResolverLinkManager,
    selection_state: ResolverLinkSelectionState,
}

impl ResolverLinkInspection {
    /// Returns the stable kernel link index.
    #[must_use]
    pub const fn index(&self) -> LinkIndex {
        self.index
    }

    /// Returns the kernel interface name.
    #[must_use]
    pub fn interface_name(&self) -> &str {
        &self.interface_name
    }

    /// Returns the exact manager Remap would use.
    #[must_use]
    pub const fn manager(&self) -> ResolverLinkManager {
        self.manager
    }

    /// Returns privacy-safe native selection suitability.
    #[must_use]
    pub const fn selection_state(&self) -> ResolverLinkSelectionState {
        self.selection_state
    }
}

#[cfg(target_os = "linux")]
type RawDnsEx = (i32, Vec<u8>, u16, String);

#[cfg(target_os = "linux")]
#[derive(Debug)]
enum MutationAdapter {
    Resolved,
    SystemdNetworkd(zbus::zvariant::OwnedObjectPath),
}

/// Typed operations Remap uses from one systemd-resolved manager.
pub trait ResolvedBackend {
    /// Returns the integrity-covered native manager identity represented by
    /// this backend instance.
    fn manager_record(&self) -> ResolverManagerRecord {
        ResolverManagerRecord::Systemd
    }

    /// Reads one complete startup snapshot only after the selected native
    /// manager reports that the link is ready for resolver ownership.
    ///
    /// Backends without a separate manager-readiness contract return their
    /// ordinary complete snapshot. A managed backend returns `None` while its
    /// link is still being configured.
    ///
    /// # Errors
    ///
    /// Returns an error when manager identity changed or exact state cannot be
    /// read safely.
    fn startup_snapshot(&mut self, link: LinkIndex) -> LinuxResult<Option<LinkState>> {
        self.snapshot(link).map(Some)
    }

    /// Reads one complete per-link ownership snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error when resolved is unavailable or returns invalid state.
    fn snapshot(&mut self, link: LinkIndex) -> LinuxResult<LinkState>;
    /// Replaces the link's complete ordered DNS server list.
    ///
    /// # Errors
    ///
    /// Returns an error when the native resolver rejects the replacement.
    fn set_dns(&mut self, link: LinkIndex, servers: &[DnsServer]) -> LinuxResult<()>;
    /// Replaces the link's complete ordered search and route domain list.
    ///
    /// # Errors
    ///
    /// Returns an error when the native resolver rejects the replacement.
    fn set_domains(&mut self, link: LinkIndex, domains: &[LinkDomain]) -> LinuxResult<()>;
    /// Replaces the link's explicit default-route decision.
    ///
    /// # Errors
    ///
    /// Returns an error when the native resolver rejects the replacement.
    fn set_default_route(&mut self, link: LinkIndex, enabled: bool) -> LinuxResult<()>;
}

/// Native system-bus client for `org.freedesktop.resolve1`.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct SystemdResolved {
    connection: zbus::blocking::Connection,
    adapter: MutationAdapter,
    interface_name: String,
}

/// Unavailable marker on non-Linux build hosts.
#[cfg(not(target_os = "linux"))]
#[derive(Debug, Default)]
pub struct SystemdResolved;

impl SystemdResolved {
    /// Returns the exact native manager selected for mutation.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub const fn manager(&self) -> ResolverLinkManager {
        match &self.adapter {
            MutationAdapter::Resolved => ResolverLinkManager::SystemdResolved,
            MutationAdapter::SystemdNetworkd(_) => ResolverLinkManager::SystemdNetworkd,
        }
    }

    /// Returns the exact kernel interface name selected with this backend.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn interface_name(&self) -> &str {
        &self.interface_name
    }

    /// Connects to the system bus without invoking an external utility.
    ///
    /// # Errors
    ///
    /// Returns a resolver-unavailable error when the system bus cannot be opened.
    #[cfg(target_os = "linux")]
    pub fn connect(link: LinkIndex) -> LinuxResult<Self> {
        let connection = system_connection()?;
        let interface_name = nix::net::if_::if_indextoname(link.get())
            .map_err(|_error| invalid_scope())?
            .into_string()
            .map_err(|_error| invalid_scope())?;
        let network_manager = network_manager_owns(&connection, &interface_name)?;
        let networkd_link = networkd_link(&connection, link)?;
        if network_manager && networkd_link.is_some() {
            return Err(LinuxError::new(
                LinuxErrorKind::InvalidScope,
                "multiple native managers claim the selected resolver link",
            ));
        }
        let adapter = match (network_manager, networkd_link) {
            (true, None) => return Err(network_manager_unsupported()),
            (false, Some(path)) => MutationAdapter::SystemdNetworkd(path),
            (false, None) => MutationAdapter::Resolved,
            (true, Some(_)) => unreachable!("multiple-manager scope returned above"),
        };
        Ok(Self {
            connection,
            adapter,
            interface_name,
        })
    }

    /// Inspects one link without changing resolver state.
    ///
    /// # Errors
    ///
    /// Returns an error when the link is absent, ambiguously owned, or its
    /// native manager cannot be established through typed APIs.
    #[cfg(target_os = "linux")]
    pub fn inspect(link: LinkIndex) -> LinuxResult<ResolverLinkInspection> {
        let connection = system_connection()?;
        inspect_with_connection(&connection, link)
    }

    /// Reports whether the integrity-bound native manager is presently
    /// available for the exact selected interface.
    ///
    /// # Errors
    ///
    /// Returns an ownership conflict when another manager positively claims
    /// the link, or when the kernel interface identity changed.
    #[cfg(target_os = "linux")]
    pub fn expected_manager_ready(
        link: LinkIndex,
        interface_name: &str,
        manager: ResolverLinkManager,
    ) -> LinuxResult<bool> {
        let connection = system_connection()?;
        let current_interface = nix::net::if_::if_indextoname(link.get())
            .map_err(|_error| invalid_scope())?
            .into_string()
            .map_err(|_error| invalid_scope())?;
        if current_interface != interface_name {
            return Err(invalid_scope());
        }
        expected_manager_ready(
            manager,
            network_manager_owns(&connection, interface_name)?,
            networkd_link(&connection, link)?.is_some(),
        )
    }

    /// Enumerates a bounded set of non-loopback resolver-link candidates.
    ///
    /// # Errors
    ///
    /// Returns an error if the system bus, kernel interface list, or any
    /// candidate ownership decision cannot be inspected exactly.
    #[cfg(target_os = "linux")]
    pub fn candidates() -> LinuxResult<Vec<ResolverLinkInspection>> {
        const MAX_LINKS: usize = 64;
        let connection = system_connection()?;
        let interfaces = nix::net::if_::if_nameindex().map_err(|_error| invalid_scope())?;
        let mut candidates = Vec::new();
        for interface in &interfaces {
            let name = interface
                .name()
                .to_str()
                .map_err(|_error| invalid_scope())?;
            if name == "lo" {
                continue;
            }
            if candidates.len() == MAX_LINKS {
                return Err(invalid_scope());
            }
            candidates.push(inspect_with_connection(
                &connection,
                LinkIndex::new(interface.index())?,
            )?);
        }
        candidates.sort_by_key(|candidate| candidate.index.get());
        Ok(candidates)
    }

    /// Captures one exact effective systemd-resolved link state read-only.
    ///
    /// # Errors
    ///
    /// Returns an error when resolved is unavailable or the link state is invalid.
    #[cfg(target_os = "linux")]
    pub fn observe(link: LinkIndex) -> LinuxResult<LinkState> {
        let connection = system_connection()?;
        snapshot_resolved(&connection, link)
    }

    #[cfg(target_os = "linux")]
    fn startup_ready(&self, link: LinkIndex) -> LinuxResult<bool> {
        let interface_name = nix::net::if_::if_indextoname(link.get())
            .map_err(|_error| invalid_scope())?
            .into_string()
            .map_err(|_error| invalid_scope())?;
        if interface_name != self.interface_name {
            return Err(LinuxError::new(
                LinuxErrorKind::InvalidScope,
                "the selected resolver link changed interface identity",
            ));
        }
        if network_manager_owns(&self.connection, &interface_name)? {
            return Err(LinuxError::new(
                LinuxErrorKind::InvalidScope,
                "the selected resolver link changed native managers",
            ));
        }
        systemd_startup_ready(&self.adapter, networkd_link_state(&self.connection, link)?)
    }

    /// Reports that the native adapter cannot run on a non-Linux build host.
    ///
    /// # Errors
    ///
    /// Always returns a resolver-unavailable error on non-Linux hosts.
    #[cfg(not(target_os = "linux"))]
    pub fn connect(_link: LinkIndex) -> LinuxResult<Self> {
        Err(bus_error())
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn system_connection() -> LinuxResult<zbus::blocking::Connection> {
    zbus::blocking::connection::Builder::system()
        .map_err(|_error| bus_error())?
        .method_timeout(NATIVE_METHOD_TIMEOUT)
        .build()
        .map_err(|_error| bus_error())
}

#[cfg(target_os = "linux")]
fn systemd_startup_ready(
    adapter: &MutationAdapter,
    networkd: Option<(zbus::zvariant::OwnedObjectPath, String)>,
) -> LinuxResult<bool> {
    match (adapter, networkd) {
        (MutationAdapter::Resolved, None) => Ok(true),
        (MutationAdapter::SystemdNetworkd(expected), Some((path, state))) if *expected == path => {
            Ok(state == "configured")
        }
        (MutationAdapter::SystemdNetworkd(_expected), None) => Err(bus_error()),
        _ => Err(LinuxError::new(
            LinuxErrorKind::InvalidScope,
            "the selected resolver link changed native managers",
        )),
    }
}

#[cfg(target_os = "linux")]
fn expected_manager_ready(
    expected: ResolverLinkManager,
    network_manager: bool,
    networkd: bool,
) -> LinuxResult<bool> {
    if network_manager && networkd {
        return Err(invalid_scope());
    }
    match expected {
        ResolverLinkManager::SystemdResolved if network_manager || networkd => Err(invalid_scope()),
        ResolverLinkManager::SystemdResolved => Ok(true),
        ResolverLinkManager::SystemdNetworkd if network_manager => Err(invalid_scope()),
        ResolverLinkManager::SystemdNetworkd => Ok(networkd),
        ResolverLinkManager::NetworkManager if networkd => Err(invalid_scope()),
        ResolverLinkManager::NetworkManager => Ok(network_manager),
    }
}

#[cfg(target_os = "linux")]
fn inspect_with_connection(
    connection: &zbus::blocking::Connection,
    link: LinkIndex,
) -> LinuxResult<ResolverLinkInspection> {
    let interface_name = nix::net::if_::if_indextoname(link.get())
        .map_err(|_error| invalid_scope())?
        .into_string()
        .map_err(|_error| invalid_scope())?;
    let network_manager = network_manager_owns(connection, &interface_name)?;
    let networkd = networkd_link(connection, link)?.is_some();
    if network_manager && networkd {
        return Err(LinuxError::new(
            LinuxErrorKind::InvalidScope,
            "multiple native managers claim the selected resolver link",
        ));
    }
    let manager = if network_manager {
        ResolverLinkManager::NetworkManager
    } else if networkd {
        ResolverLinkManager::SystemdNetworkd
    } else {
        ResolverLinkManager::SystemdResolved
    };
    let selection_state = snapshot_resolved(connection, link).map_or(
        ResolverLinkSelectionState::Unsupported,
        |state| {
            let usable_dns = state.dns_servers().iter().any(|server| {
                let address = server.address();
                !address.is_unspecified() && !address.is_multicast() && !address.is_loopback()
            });
            match (usable_dns, state.default_route()) {
                (true, true) => ResolverLinkSelectionState::SupportedPrimary,
                (true, false) => ResolverLinkSelectionState::SupportedSecondary,
                (false, _) => ResolverLinkSelectionState::Inactive,
            }
        },
    );
    Ok(ResolverLinkInspection {
        index: link,
        interface_name,
        manager,
        selection_state,
    })
}

#[cfg(target_os = "linux")]
impl ResolvedBackend for SystemdResolved {
    fn manager_record(&self) -> ResolverManagerRecord {
        match &self.adapter {
            MutationAdapter::Resolved => {
                ResolverManagerRecord::SystemdResolved(self.interface_name.clone())
            }
            MutationAdapter::SystemdNetworkd(_) => {
                ResolverManagerRecord::SystemdNetworkd(self.interface_name.clone())
            }
        }
    }

    fn startup_snapshot(&mut self, link: LinkIndex) -> LinuxResult<Option<LinkState>> {
        if !self.startup_ready(link)? {
            return Ok(None);
        }
        let state = self.snapshot(link)?;
        if !self.startup_ready(link)? {
            return Ok(None);
        }
        Ok(Some(state))
    }

    fn snapshot(&mut self, link: LinkIndex) -> LinuxResult<LinkState> {
        snapshot_resolved(&self.connection, link)
    }

    fn set_dns(&mut self, link: LinkIndex, servers: &[DnsServer]) -> LinuxResult<()> {
        let entries = servers
            .iter()
            .map(DnsServer::to_resolved)
            .collect::<Vec<_>>();
        match &self.adapter {
            MutationAdapter::Resolved => {
                let proxy =
                    ResolveManagerProxy::new(&self.connection).map_err(|_error| bus_error())?;
                proxy
                    .set_link_dns_ex(link.as_i32(), entries)
                    .map_err(|error| method_error(&error))
            }
            MutationAdapter::SystemdNetworkd(path) => networkd_proxy(&self.connection, path)?
                .set_dns_ex(entries)
                .map_err(|error| method_error(&error)),
        }
    }

    fn set_domains(&mut self, link: LinkIndex, domains: &[LinkDomain]) -> LinuxResult<()> {
        let entries = domains
            .iter()
            .map(|domain| (domain.name().to_owned(), domain.route_only()))
            .collect::<Vec<_>>();
        match &self.adapter {
            MutationAdapter::Resolved => {
                let proxy =
                    ResolveManagerProxy::new(&self.connection).map_err(|_error| bus_error())?;
                proxy
                    .set_link_domains(link.as_i32(), entries)
                    .map_err(|error| method_error(&error))
            }
            MutationAdapter::SystemdNetworkd(path) => networkd_proxy(&self.connection, path)?
                .set_domains(entries)
                .map_err(|error| method_error(&error)),
        }
    }

    fn set_default_route(&mut self, link: LinkIndex, enabled: bool) -> LinuxResult<()> {
        match &self.adapter {
            MutationAdapter::Resolved => {
                let proxy =
                    ResolveManagerProxy::new(&self.connection).map_err(|_error| bus_error())?;
                proxy
                    .set_link_default_route(link.as_i32(), enabled)
                    .map_err(|error| method_error(&error))
            }
            MutationAdapter::SystemdNetworkd(path) => networkd_proxy(&self.connection, path)?
                .set_default_route(enabled)
                .map_err(|error| method_error(&error)),
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn snapshot_resolved(
    connection: &zbus::blocking::Connection,
    link: LinkIndex,
) -> LinuxResult<LinkState> {
    let manager = ResolveManagerProxy::new(connection).map_err(|_error| bus_error())?;
    let path = manager
        .get_link(link.as_i32())
        .map_err(|_error| bus_error())?;
    let proxy = ResolveLinkProxy::builder(connection)
        .path(path)
        .map_err(|_error| bus_error())?
        .build()
        .map_err(|_error| bus_error())?;
    let raw_dns = proxy.dns_ex().map_err(|_error| bus_error())?;
    let raw_domains = proxy.domains().map_err(|_error| bus_error())?;
    let default_route = proxy.default_route().map_err(|_error| bus_error())?;
    let dns_servers = raw_dns
        .into_iter()
        .map(|(family, bytes, port, name)| DnsServer::from_resolved(family, &bytes, port, name))
        .collect::<LinuxResult<Vec<_>>>()?;
    let domains = raw_domains
        .into_iter()
        .map(|(name, route_only)| LinkDomain::new(name, route_only))
        .collect::<LinuxResult<Vec<_>>>()?;
    LinkState::new(link, dns_servers, domains, default_route)
}

#[cfg(target_os = "linux")]
fn network_manager_owns(
    connection: &zbus::blocking::Connection,
    interface_name: &str,
) -> LinuxResult<bool> {
    if !name_has_owner(connection, "org.freedesktop.NetworkManager")? {
        return Ok(false);
    }
    let proxy = NetworkManagerProxy::new(connection).map_err(|_error| bus_error())?;
    match proxy.get_device_by_ip_iface(interface_name) {
        Ok(path) => NetworkManagerDeviceOwnerProxy::builder(connection)
            .path(path)
            .map_err(|_error| bus_error())?
            .build()
            .map_err(|_error| bus_error())?
            .managed()
            .map_err(|_error| bus_error()),
        Err(zbus::Error::MethodError(name, _detail, _reply))
            if name.as_str() == "org.freedesktop.NetworkManager.UnknownDevice" =>
        {
            Ok(false)
        }
        Err(_error) => Err(bus_error()),
    }
}

#[cfg(target_os = "linux")]
fn networkd_link(
    connection: &zbus::blocking::Connection,
    link: LinkIndex,
) -> LinuxResult<Option<zbus::zvariant::OwnedObjectPath>> {
    Ok(networkd_link_state(connection, link)?.map(|(path, _state)| path))
}

#[cfg(target_os = "linux")]
fn networkd_link_state(
    connection: &zbus::blocking::Connection,
    link: LinkIndex,
) -> LinuxResult<Option<(zbus::zvariant::OwnedObjectPath, String)>> {
    if !name_has_owner(connection, "org.freedesktop.network1")? {
        return Ok(None);
    }
    let manager = NetworkdManagerProxy::new(connection).map_err(|_error| bus_error())?;
    let (_name, path) = manager
        .get_link_by_index(link.as_i32())
        .map_err(|_error| bus_error())?;
    let state = networkd_proxy(connection, &path)?
        .administrative_state()
        .map_err(|_error| bus_error())?;
    Ok((state != "unmanaged").then_some((path, state)))
}

#[cfg(target_os = "linux")]
pub(crate) fn name_has_owner(
    connection: &zbus::blocking::Connection,
    name: &str,
) -> LinuxResult<bool> {
    let proxy = zbus::blocking::fdo::DBusProxy::new(connection).map_err(|_error| bus_error())?;
    let name = zbus::names::BusName::try_from(name).map_err(|_error| bus_error())?;
    proxy.name_has_owner(name).map_err(|_error| bus_error())
}

#[cfg(target_os = "linux")]
fn networkd_proxy<'a>(
    connection: &'a zbus::blocking::Connection,
    path: &zbus::zvariant::OwnedObjectPath,
) -> LinuxResult<NetworkdLinkProxy<'a>> {
    NetworkdLinkProxy::builder(connection)
        .path(path.clone())
        .map_err(|_error| bus_error())?
        .build()
        .map_err(|_error| bus_error())
}

#[cfg(target_os = "linux")]
#[zbus::proxy(
    interface = "org.freedesktop.resolve1.Manager",
    default_service = "org.freedesktop.resolve1",
    default_path = "/org/freedesktop/resolve1",
    gen_async = false
)]
trait ResolveManager {
    #[zbus(name = "GetLink")]
    fn get_link(&self, interface_index: i32) -> zbus::Result<zbus::zvariant::OwnedObjectPath>;

    #[zbus(name = "SetLinkDNSEx")]
    fn set_link_dns_ex(&self, interface_index: i32, addresses: Vec<RawDnsEx>) -> zbus::Result<()>;

    #[zbus(name = "SetLinkDomains")]
    fn set_link_domains(
        &self,
        interface_index: i32,
        domains: Vec<(String, bool)>,
    ) -> zbus::Result<()>;

    #[zbus(name = "SetLinkDefaultRoute")]
    fn set_link_default_route(&self, interface_index: i32, enabled: bool) -> zbus::Result<()>;
}

#[cfg(target_os = "linux")]
#[zbus::proxy(
    interface = "org.freedesktop.resolve1.Link",
    default_service = "org.freedesktop.resolve1",
    gen_async = false
)]
trait ResolveLink {
    #[zbus(property, name = "DNSEx")]
    fn dns_ex(&self) -> zbus::Result<Vec<RawDnsEx>>;

    #[zbus(property, name = "Domains")]
    fn domains(&self) -> zbus::Result<Vec<(String, bool)>>;

    #[zbus(property, name = "DefaultRoute")]
    fn default_route(&self) -> zbus::Result<bool>;
}

#[cfg(target_os = "linux")]
#[zbus::proxy(
    interface = "org.freedesktop.network1.Manager",
    default_service = "org.freedesktop.network1",
    default_path = "/org/freedesktop/network1",
    gen_async = false
)]
trait NetworkdManager {
    #[zbus(name = "GetLinkByIndex")]
    fn get_link_by_index(
        &self,
        interface_index: i32,
    ) -> zbus::Result<(String, zbus::zvariant::OwnedObjectPath)>;
}

#[cfg(target_os = "linux")]
#[zbus::proxy(
    interface = "org.freedesktop.network1.Link",
    default_service = "org.freedesktop.network1",
    gen_async = false
)]
trait NetworkdLink {
    #[zbus(property, name = "AdministrativeState")]
    fn administrative_state(&self) -> zbus::Result<String>;

    #[zbus(name = "SetDNSEx")]
    fn set_dns_ex(&self, addresses: Vec<RawDnsEx>) -> zbus::Result<()>;

    #[zbus(name = "SetDomains")]
    fn set_domains(&self, domains: Vec<(String, bool)>) -> zbus::Result<()>;

    #[zbus(name = "SetDefaultRoute")]
    fn set_default_route(&self, enabled: bool) -> zbus::Result<()>;
}

#[cfg(target_os = "linux")]
#[zbus::proxy(
    interface = "org.freedesktop.NetworkManager",
    default_service = "org.freedesktop.NetworkManager",
    default_path = "/org/freedesktop/NetworkManager",
    gen_async = false
)]
trait NetworkManager {
    #[zbus(name = "GetDeviceByIpIface")]
    fn get_device_by_ip_iface(
        &self,
        interface_name: &str,
    ) -> zbus::Result<zbus::zvariant::OwnedObjectPath>;
}

#[cfg(target_os = "linux")]
#[zbus::proxy(
    interface = "org.freedesktop.NetworkManager.Device",
    default_service = "org.freedesktop.NetworkManager",
    gen_async = false
)]
trait NetworkManagerDeviceOwner {
    #[zbus(property, name = "Managed")]
    fn managed(&self) -> zbus::Result<bool>;
}

const fn bus_error() -> LinuxError {
    LinuxError::new(
        LinuxErrorKind::ResolverUnavailable,
        "the native systemd-resolved system-bus operation failed",
    )
}

#[cfg(target_os = "linux")]
fn method_error(error: &zbus::Error) -> LinuxError {
    let zbus::Error::MethodError(name, _detail, _reply) = error else {
        return bus_error();
    };
    match name.as_str() {
        "org.freedesktop.DBus.Error.AccessDenied"
        | "org.freedesktop.DBus.Error.AuthFailed"
        | "org.freedesktop.DBus.Error.InteractiveAuthorizationRequired" => LinuxError::new(
            LinuxErrorKind::ResolverUnavailable,
            "systemd-resolved denied the native resolver mutation",
        ),
        "org.freedesktop.DBus.Error.InvalidArgs"
        | "org.freedesktop.DBus.Error.InvalidSignature" => LinuxError::new(
            LinuxErrorKind::InvalidState,
            "systemd-resolved rejected the typed resolver argument contract",
        ),
        "org.freedesktop.DBus.Error.UnknownMethod"
        | "org.freedesktop.DBus.Error.UnknownInterface" => LinuxError::new(
            LinuxErrorKind::ResolverUnavailable,
            "systemd-resolved does not expose the required native resolver API",
        ),
        _ => bus_error(),
    }
}

#[cfg(target_os = "linux")]
const fn invalid_scope() -> LinuxError {
    LinuxError::new(
        LinuxErrorKind::InvalidScope,
        "the selected resolver link is unavailable",
    )
}

#[cfg(target_os = "linux")]
const fn network_manager_unsupported() -> LinuxError {
    LinuxError::new(
        LinuxErrorKind::UnsupportedResolverManager,
        "the selected link requires the native NetworkManager adapter",
    )
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::{MutationAdapter, expected_manager_ready, systemd_startup_ready};
    use crate::{LinuxErrorKind, ResolverLinkManager};

    #[test]
    fn expected_manager_absence_retries_but_positive_other_ownership_conflicts() {
        assert_eq!(
            expected_manager_ready(ResolverLinkManager::SystemdNetworkd, false, false),
            Ok(false)
        );
        assert!(expected_manager_ready(ResolverLinkManager::SystemdNetworkd, true, false).is_err());
        assert!(expected_manager_ready(ResolverLinkManager::NetworkManager, false, true).is_err());
    }

    #[test]
    fn selected_networkd_outage_retries_but_positive_manager_drift_conflicts()
    -> Result<(), crate::LinuxError> {
        let selected = zbus::zvariant::OwnedObjectPath::try_from(
            "/org/freedesktop/network1/link/_2".to_owned(),
        )
        .map_err(|_error| {
            crate::LinuxError::new(LinuxErrorKind::InvalidState, "invalid fixture")
        })?;
        let replacement = zbus::zvariant::OwnedObjectPath::try_from(
            "/org/freedesktop/network1/link/_3".to_owned(),
        )
        .map_err(|_error| {
            crate::LinuxError::new(LinuxErrorKind::InvalidState, "invalid fixture")
        })?;
        let adapter = MutationAdapter::SystemdNetworkd(selected.clone());
        let Err(outage) = systemd_startup_ready(&adapter, None) else {
            return Err(crate::LinuxError::new(
                LinuxErrorKind::InvalidState,
                "outage did not retry",
            ));
        };
        assert_eq!(outage.kind(), LinuxErrorKind::ResolverUnavailable);
        assert!(systemd_startup_ready(
            &adapter,
            Some((selected, "configured".to_owned()))
        )?);
        let Err(drift) =
            systemd_startup_ready(&adapter, Some((replacement, "configured".to_owned())))
        else {
            return Err(crate::LinuxError::new(
                LinuxErrorKind::InvalidState,
                "replacement manager path did not conflict",
            ));
        };
        assert_eq!(drift.kind(), LinuxErrorKind::InvalidScope);
        Ok(())
    }
}
