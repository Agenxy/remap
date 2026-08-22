//! Native Linux resolver and service-manager contracts for Remap.
//!
//! This crate deliberately separates reversible resolver policy from the
//! privileged installer and from the portable data plane. It does not install
//! units, select a user's active network link, or claim a live Linux path.

mod digest;
mod environment;
mod error;
mod lifecycle;
mod manager_record;
mod model;
#[cfg(target_os = "linux")]
mod network_manager;
mod record;
#[cfg(target_os = "linux")]
mod record_store;
mod resolved;
#[cfg(target_os = "linux")]
mod socket_adoption;
mod systemd;
mod transaction;

pub use environment::{
    ResolverBackendKind, ResolverEnvironment, ResolverSupport, UnsupportedResolverReason,
};
pub use error::{LinuxError, LinuxErrorKind, LinuxResult};
pub use lifecycle::{LinkLifecycleEvent, LinkScopeMonitor};
pub use manager_record::{
    NetworkManagerIpDns, NetworkManagerLegacyDns, NetworkManagerOwnership, ResolverManagerRecord,
};
pub use model::{DnsServer, LinkDomain, LinkIndex, LinkState, MAX_DNS_SERVERS, MAX_DOMAINS};
#[cfg(target_os = "linux")]
pub use network_manager::{NetworkManagerStartupObservation, NetworkManagerTransaction};
pub use record::{
    ActivationPhase, ActivationRecord, MAX_RECORD_BYTES, RecordCodec, RecordMetadata,
};
#[cfg(target_os = "linux")]
pub use record_store::RootRecordStore;
pub use resolved::{
    ResolvedBackend, ResolverLinkInspection, ResolverLinkManager, ResolverLinkSelectionState,
    SystemdResolved,
};
#[cfg(target_os = "linux")]
pub use socket_adoption::{
    AdoptedSystemdSockets, adopt_systemd_sockets, reject_unrequested_activation,
};
pub use systemd::{
    ActivationEnvironment, DescriptorKind, DescriptorSpec, ResolverSupervisorIdentity,
    ResolverSupervisorLink, ServiceIdentity, SocketContract, SystemdUnitSet,
};
pub use transaction::{ActivationStore, ResolverStartupObservation, ResolverTransaction};
