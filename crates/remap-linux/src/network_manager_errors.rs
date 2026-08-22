use crate::{LinuxError, LinuxErrorKind, LinuxResult, ResolverLinkManager};

pub(super) fn manager_identity_ready(
    service_owned: bool,
    manager: ResolverLinkManager,
    observed_interface: &str,
    expected_interface: &str,
) -> LinuxResult<bool> {
    if !service_owned {
        return Ok(false);
    }
    if manager != ResolverLinkManager::NetworkManager || observed_interface != expected_interface {
        return Err(invalid_scope());
    }
    Ok(true)
}

pub(super) fn method_error(error: &zbus::Error) -> LinuxError {
    let zbus::Error::MethodError(name, _detail, _reply) = error else {
        return bus_error();
    };
    match name.as_str() {
        "org.freedesktop.DBus.Error.AccessDenied"
        | "org.freedesktop.DBus.Error.AuthFailed"
        | "org.freedesktop.DBus.Error.InteractiveAuthorizationRequired"
        | "org.freedesktop.NetworkManager.PermissionDenied" => LinuxError::new(
            LinuxErrorKind::ResolverUnavailable,
            "NetworkManager denied the native resolver mutation",
        ),
        "org.freedesktop.NetworkManager.Device.VersionIdMismatch" => ownership_conflict(
            "the NetworkManager applied connection changed before compare-and-swap",
        ),
        "org.freedesktop.DBus.Error.InvalidArgs"
        | "org.freedesktop.DBus.Error.InvalidSignature"
        | "org.freedesktop.NetworkManager.Device.IncompatibleConnection" => invalid_state(),
        _ => bus_error(),
    }
}

pub(super) const fn bus_error() -> LinuxError {
    LinuxError::new(
        LinuxErrorKind::ResolverUnavailable,
        "the native NetworkManager system-bus operation failed",
    )
}

pub(super) const fn invalid_scope() -> LinuxError {
    LinuxError::new(
        LinuxErrorKind::InvalidScope,
        "the selected NetworkManager interface is unavailable",
    )
}

pub(super) const fn manager_not_ready() -> LinuxError {
    LinuxError::new(
        LinuxErrorKind::ResolverUnavailable,
        "the selected NetworkManager interface is not fully activated",
    )
}

pub(super) const fn observation_changed() -> LinuxError {
    ownership_conflict("NetworkManager state changed after startup stabilization")
}

pub(super) const fn observation_unstable() -> LinuxError {
    LinuxError::new(
        LinuxErrorKind::UnstableObservation,
        "NetworkManager state changed during steady observation",
    )
}

pub(super) const fn invalid_state() -> LinuxError {
    LinuxError::new(
        LinuxErrorKind::InvalidState,
        "the NetworkManager applied connection has an unsupported typed value",
    )
}

pub(super) const fn unsupported() -> LinuxError {
    LinuxError::new(
        LinuxErrorKind::UnsupportedResolverManager,
        "the NetworkManager applied connection cannot be redirected reversibly",
    )
}

pub(super) const fn ownership_conflict(message: &'static str) -> LinuxError {
    LinuxError::new(LinuxErrorKind::OwnershipConflict, message)
}

pub(super) const fn external_change() -> LinuxError {
    ownership_conflict("the NetworkManager applied connection changed outside Remap ownership")
}

pub(super) const fn recovery_required() -> LinuxError {
    LinuxError::new(
        LinuxErrorKind::RecoveryRequired,
        "the NetworkManager resolver transition requires exact recovery",
    )
}
