//! Portable, side-effect-free Remap domain and policy primitives.

mod mapping;
mod name;
mod target;

pub use mapping::{Mapping, RegistrySnapshot, SnapshotError};
pub use name::{NamePattern, RemapName, RemapNameError};
pub use target::{
    HostHeaderPolicy, HttpScheme, HttpUpstream, HttpUpstreamError, MappingTarget,
    MappingTargetError, MappingTargetKind, UpstreamHost,
};
