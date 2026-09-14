#[cfg(target_os = "linux")]
use std::path::Path;

/// Native resolver manager observed on the host.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ResolverBackendKind {
    /// systemd-resolved owns the documented resolver D-Bus API.
    SystemdResolved,
    /// `NetworkManager` is active without an active systemd-resolved owner.
    NetworkManager,
    /// `/etc/resolv.conf` is a regular or externally managed file.
    ResolvConf,
    /// No supported manager could be established without guessing.
    Unknown,
}

/// Why the observed resolver path is not safe to mutate yet.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum UnsupportedResolverReason {
    /// A `NetworkManager` adapter must preserve its connection-scoped settings.
    NetworkManagerAdapterRequired,
    /// Rewriting `resolv.conf` would bypass its unknown owner.
    ResolvConfOwnerUnknown,
    /// resolved-looking files exist, but its D-Bus owner is unavailable.
    SystemdResolvedUnavailable,
    /// The system bus or resolver owner could not be established.
    ManagerUnavailable,
}

/// Mutation support for an observed resolver environment.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ResolverSupport {
    /// The typed systemd-resolved adapter may be considered after link selection.
    Supported,
    /// Detection is read-only and mutation must stop for the stated reason.
    Unsupported(UnsupportedResolverReason),
}

/// Privacy-safe result of native resolver-manager detection.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ResolverEnvironment {
    backend: ResolverBackendKind,
    support: ResolverSupport,
}

impl ResolverEnvironment {
    /// Detects the active resolver owner without invoking commands or mutating state.
    #[must_use]
    pub fn detect() -> Self {
        detect_platform()
    }

    /// Returns the observed native backend category.
    #[must_use]
    pub const fn backend(self) -> ResolverBackendKind {
        self.backend
    }

    /// Returns whether the current adapter may proceed to explicit link selection.
    #[must_use]
    pub const fn support(self) -> ResolverSupport {
        self.support
    }
}

#[cfg(target_os = "linux")]
fn detect_platform() -> ResolverEnvironment {
    let owners = bus_owners();
    if owners.is_some_and(|(resolved, _network_manager)| resolved) {
        return environment(
            ResolverBackendKind::SystemdResolved,
            ResolverSupport::Supported,
        );
    }
    if owners.is_some_and(|(_resolved, network_manager)| network_manager) {
        return environment(
            ResolverBackendKind::NetworkManager,
            ResolverSupport::Unsupported(UnsupportedResolverReason::NetworkManagerAdapterRequired),
        );
    }
    classify_resolv_conf(owners.is_some())
}

#[cfg(not(target_os = "linux"))]
const fn detect_platform() -> ResolverEnvironment {
    environment(
        ResolverBackendKind::Unknown,
        ResolverSupport::Unsupported(UnsupportedResolverReason::ManagerUnavailable),
    )
}

#[cfg(target_os = "linux")]
fn bus_owners() -> Option<(bool, bool)> {
    let connection = zbus::blocking::Connection::system().ok()?;
    let proxy = zbus::blocking::Proxy::new(
        &connection,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
    )
    .ok()?;
    let resolved = proxy
        .call::<_, _, bool>("NameHasOwner", &("org.freedesktop.resolve1",))
        .ok()?;
    let network_manager = proxy
        .call::<_, _, bool>("NameHasOwner", &("org.freedesktop.NetworkManager",))
        .ok()?;
    Some((resolved, network_manager))
}

#[cfg(target_os = "linux")]
fn classify_resolv_conf(system_bus_available: bool) -> ResolverEnvironment {
    let path = Path::new("/etc/resolv.conf");
    let metadata = std::fs::symlink_metadata(path);
    if metadata
        .as_ref()
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        let resolved_target = std::fs::read_link(path)
            .is_ok_and(|target| target.to_string_lossy().contains("systemd/resolve"));
        if resolved_target {
            return environment(
                ResolverBackendKind::SystemdResolved,
                ResolverSupport::Unsupported(UnsupportedResolverReason::SystemdResolvedUnavailable),
            );
        }
    }
    if metadata.as_ref().is_ok_and(std::fs::Metadata::is_file) {
        return environment(
            ResolverBackendKind::ResolvConf,
            ResolverSupport::Unsupported(UnsupportedResolverReason::ResolvConfOwnerUnknown),
        );
    }
    environment(
        ResolverBackendKind::Unknown,
        ResolverSupport::Unsupported(if system_bus_available {
            UnsupportedResolverReason::ResolvConfOwnerUnknown
        } else {
            UnsupportedResolverReason::ManagerUnavailable
        }),
    )
}

const fn environment(
    backend: ResolverBackendKind,
    support: ResolverSupport,
) -> ResolverEnvironment {
    ResolverEnvironment { backend, support }
}
