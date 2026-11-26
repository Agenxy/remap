// SPDX-License-Identifier: GPL-3.0-or-later
//! Portable, bounded network runtime for Remap.

mod dns;
mod error;
mod failure;
mod forward;
mod gateway;
mod health;
mod liveness;
mod machine;
mod machine_carry;
mod machine_idle;
mod machine_listen;
mod peer;
mod proxy;
mod reachability;
mod resolver;
mod server;
mod snapshot;
mod stream_route;
mod supgang_stream;
mod tunnel;

pub use dns::{DnsDecision, DnsEngine, DnsPolicy};
pub use error::NetworkError;
pub use gateway::{GatewayBindings, GatewayRuntime, GatewayRuntimeConfig};
pub use health::{
    HEALTH_NONCE_BYTES, HEALTH_PROOF_BYTES, MAX_INSTANCE_ID_BYTES, MAX_RUNTIME_VERSION_BYTES,
    RuntimeIdentity, RuntimeProofs,
};
pub use liveness::{UpstreamFailureCause, UpstreamLivenessPolicy, UpstreamsUnanswered};
pub use machine::{
    ListenerCause, ListenerReport, ListenerSource, ListenerState, PEER_MACHINE_CONNECTION_LIMIT,
    PEER_MACHINE_OPEN_TIMEOUT, PEER_MACHINE_RETRY_INTERVAL, PeerMachineListeners,
    PeerMachineStatus,
};
pub use machine_carry::{ConnectionLog, PEER_MACHINE_IDLE_TIMEOUT};
pub use machine_listen::{PEER_MACHINE_LISTENER_CONNECTION_LIMIT, PeerMachineAdoptError};
pub use peer::{
    PEER_CACHE_LIMIT, PeerResolveError, PeerResolver, PinnedVerifier, RESOLVE_TIMEOUT,
    ResolvedPeerService, SupgangResolver, parse_node, parse_resolution, subject_public_key_info,
};
pub use reachability::{PROBE_DEADLINE, Reachability, loopback_addresses, probe};
pub use resolver::ResolverPlanStore;
pub use server::{DnsBindings, DnsRuntime, DnsRuntimeConfig};
pub use snapshot::SnapshotStore;
pub use supgang_stream::{StreamError, SupgangStreams};
