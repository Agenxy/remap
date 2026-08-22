use std::error::Error;
use std::fmt::{Display, Formatter};

/// Stable failure categories for the Linux platform boundary.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum LinuxErrorKind {
    /// A caller supplied an invalid or unsupported link scope.
    InvalidScope,
    /// Resolver state exceeded a documented bound or was malformed.
    InvalidState,
    /// A persisted activation record was malformed, stale, or untrusted.
    InvalidRecord,
    /// Resolver state changed outside Remap after activation.
    OwnershipConflict,
    /// A manager-aware observation changed while the caller was sampling it.
    UnstableObservation,
    /// The systemd-resolved D-Bus operation failed.
    ResolverUnavailable,
    /// The selected link is owned by a resolver manager without a reversible adapter.
    UnsupportedResolverManager,
    /// A durable state transition failed.
    Persistence,
    /// A partial transition needs explicit recovery.
    RecoveryRequired,
    /// A systemd unit or descriptor contract was invalid.
    InvalidServiceContract,
}

/// Privacy-safe Linux platform error.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LinuxError {
    kind: LinuxErrorKind,
    message: &'static str,
}

impl LinuxError {
    /// Creates an error without embedding interface names, addresses, or paths.
    #[must_use]
    pub const fn new(kind: LinuxErrorKind, message: &'static str) -> Self {
        Self { kind, message }
    }

    /// Returns the stable failure category.
    #[must_use]
    pub const fn kind(&self) -> LinuxErrorKind {
        self.kind
    }
}

impl Display for LinuxError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.message)
    }
}

impl Error for LinuxError {}

/// Result type for Linux platform operations.
pub type LinuxResult<T> = Result<T, LinuxError>;
