//! Portable, bounded network runtime for Remap.

mod dns;
mod error;
mod forward;
mod gateway;
mod health;
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
pub use resolver::ResolverPlanStore;
pub use server::{DnsBindings, DnsRuntime, DnsRuntimeConfig};
pub use snapshot::SnapshotStore;
