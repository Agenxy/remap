//! Versioned, bounded messages shared by Remap control surfaces and `remapd`.

use std::time::Duration;

mod client;
mod diagnostic;
mod model;
mod paths;
mod system;
mod wire;

pub use client::ControlClient;
pub use diagnostic::Diagnostic;
pub use model::{
    ApplyResult, Change, ChangeEffect, Command, CommandResult, HealthChallengeResult, HostPolicy,
    ListResult, MAX_ATOMIC_CHANGE_COUNT, MAX_MAPPING_COUNT, MAX_MAPPING_PAGE_SIZE,
    MAX_REVISION_WAIT_MS, MAX_TARGET_BYTES, MappingView, PreviewResult, RegistryStatus,
    ResolutionResult, RevisionNotice, Surface, ValidationResult,
};
pub use paths::ControlPaths;
pub use system::{
    SYSTEM_PROTOCOL_VERSION, SystemCommand, SystemRequest, SystemResponse, SystemResult,
    read_system_frame, write_system_frame,
};
pub use wire::{
    CONTROL_PROTOCOL_VERSION, ControlRequest, ControlResponse, MAX_CONTROL_FRAME_BYTES,
    MAX_CONTROL_RESULT_BYTES, read_frame, write_frame,
};

/// Per-stage grace used by the production daemon for connection and service drain.
pub const DEFAULT_DAEMON_DRAIN_GRACE: Duration = Duration::from_secs(5);

/// Maximum production daemon shutdown time honored before native lifecycle escalation.
pub const SYSTEM_DAEMON_SHUTDOWN_BUDGET: Duration = Duration::from_secs(15);

/// Native lifecycle grace for signal delivery plus the complete daemon shutdown budget.
pub const NATIVE_DAEMON_TERMINATION_GRACE: Duration = Duration::from_secs(20);
