//! Portable, side-effect-free Portal domain and policy primitives.

mod mapping;
mod name;
mod target;

pub use mapping::{Mapping, RegistrySnapshot, SnapshotError};
pub use name::{NamePattern, PortalName, PortalNameError};
pub use target::{
    HostHeaderPolicy, HttpScheme, HttpUpstream, HttpUpstreamError, MappingTarget,
    MappingTargetError, MappingTargetKind, UpstreamHost,
};
