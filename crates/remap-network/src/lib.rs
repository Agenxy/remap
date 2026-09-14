//! Portable, bounded network runtime for Remap.

mod dns;
mod error;
mod forward;
mod gateway;
mod health;
mod peer;
mod proxy;
mod resolver;
mod server;
mod snapshot;

pub use dns::{DnsDecision, DnsEngine, DnsPolicy};
pub use error::NetworkError;
pub use gateway::{GatewayBindings, GatewayRuntime, GatewayRuntimeConfig};
pub use health::{
    HEALTH_NONCE_BYTES, HEALTH_PROOF_BYTES, MAX_INSTANCE_ID_BYTES, MAX_RUNTIME_VERSION_BYTES,
    RuntimeIdentity, RuntimeProofs,
};
pub use peer::{
    PEER_CACHE_LIMIT, PeerResolveError, PeerResolver, PinnedVerifier, RESOLVE_TIMEOUT,
    ResolvedPeerService, SupgangResolver, parse_resolution, subject_public_key_info,
};
pub use resolver::ResolverPlanStore;
pub use server::{DnsBindings, DnsRuntime, DnsRuntimeConfig};
pub use snapshot::SnapshotStore;
