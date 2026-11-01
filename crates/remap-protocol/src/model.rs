// SPDX-License-Identifier: GPL-3.0-or-later
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::Diagnostic;

/// Maximum mappings returned by one bounded registry page.
pub const MAX_MAPPING_PAGE_SIZE: u16 = 128;

/// Maximum mappings retained by one authoritative registry and runtime snapshot.
pub const MAX_MAPPING_COUNT: usize = 16_384;

/// Maximum changes committed in one atomic registry operation.
pub const MAX_ATOMIC_CHANGE_COUNT: usize = 64;

/// Maximum encoded destination length accepted by the registry.
pub const MAX_TARGET_BYTES: usize = 4_096;

/// Maximum not-listening peer-machine listeners one status names.
pub const MAX_LISTENER_FAILURES: usize = 64;

/// Maximum duration of one daemon-backed revision wait.
pub const MAX_REVISION_WAIT_MS: u32 = 5_000;

/// The control surface responsible for a command.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Surface {
    /// The terminal command-line interface.
    Cli,
    /// The Model Context Protocol server.
    Mcp,
    /// A native management application.
    NativeApp,
    /// A test or diagnostic probe.
    Probe,
}

/// HTTP host and SNI behavior for a routed target.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum HostPolicy {
    /// Preserve the client-facing name upstream.
    PreserveClient,
    /// Use the configured upstream host.
    UseUpstream,
}

impl HostPolicy {
    /// Returns the stable wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PreserveClient => "preserve-client",
            Self::UseUpstream => "use-upstream",
        }
    }
}

/// One atomic registry change.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Change {
    /// Create a mapping or replace its target.
    Set {
        /// Exact name or suffix wildcard.
        pattern: String,
        /// IP address, DNS alias, or HTTP(S) upstream.
        target: String,
        /// HTTP host and SNI behavior.
        host_policy: HostPolicy,
        /// Explicit enabled state, or preserve the current state when omitted.
        enabled: Option<bool>,
        /// Optional same-origin landing path for root GET and HEAD requests.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        landing: Option<String>,
    },
    /// Enable an existing mapping.
    Enable {
        /// Exact canonical mapping pattern.
        pattern: String,
    },
    /// Disable an existing mapping without deleting it.
    Disable {
        /// Exact canonical mapping pattern.
        pattern: String,
    },
    /// Remove an existing mapping.
    Remove {
        /// Exact canonical mapping pattern.
        pattern: String,
    },
}

/// A command accepted by the authoritative daemon.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    /// Report daemon and registry state.
    Status,
    /// Return per-instance proofs for authenticated runtime listeners.
    HealthChallenge {
        /// Exactly 128 bits encoded as 32 lowercase hexadecimal characters.
        nonce: String,
    },
    /// Return a bounded, deterministic page of mappings.
    List {
        /// Return patterns lexically after this opaque cursor.
        after: Option<String>,
        /// Maximum records to return.
        limit: u16,
        /// Include disabled records.
        include_disabled: bool,
    },
    /// Read one exact registry key.
    Get {
        /// Exact name or wildcard key.
        pattern: String,
    },
    /// Explain the mapping selected for one lookup name.
    Resolve {
        /// Client-facing name to resolve.
        name: String,
    },
    /// Validate and canonicalize a mapping without daemon state changes.
    Validate {
        /// Exact name or wildcard key.
        pattern: String,
        /// Proposed destination.
        target: String,
        /// HTTP host and SNI behavior.
        host_policy: HostPolicy,
        /// Optional same-origin landing path.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        landing: Option<String>,
    },
    /// Evaluate an atomic change set without committing it.
    Preview {
        /// Changes evaluated in order.
        changes: Vec<Change>,
    },
    /// Commit an atomic change set against an observed revision.
    Apply {
        /// Revision on which the decision was based.
        expected_revision: u64,
        /// Caller-generated UUID used to make retries idempotent.
        operation_id: String,
        /// Changes applied in order or not at all.
        changes: Vec<Change>,
    },
    /// Wait for a later authoritative revision or a bounded timeout.
    WaitForRevision {
        /// Revision already observed by the caller.
        after: u64,
        /// Maximum wait in milliseconds, from 1 through 5,000.
        timeout_ms: u32,
    },
}

/// Result of one bounded wait for a later registry revision.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RevisionNotice {
    /// Latest authoritative revision at return time.
    pub revision: u64,
    /// Whether the revision advanced beyond the caller's observation.
    pub changed: bool,
}

/// Authenticated runtime-listener expectations for one fresh challenge.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct HealthChallengeResult {
    /// Opaque identifier regenerated for each daemon runtime.
    pub instance_id: String,
    /// Running daemon release that produced the proofs.
    pub daemon_version: String,
    /// Expected DNS TXT value for the challenge.
    pub dns_proof: String,
    /// Expected HTTP response body for the challenge.
    pub http_proof: String,
}

/// Current authoritative registry status.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RegistryStatus {
    /// Monotonic registry revision.
    pub revision: u64,
    /// Number of stored mappings.
    pub mapping_count: u64,
    /// Number of mappings participating in resolution.
    pub enabled_count: u64,
    /// On-disk schema revision.
    pub schema_version: u32,
    /// Running daemon release.
    pub daemon_version: String,
    /// Retryable retention failure currently blocking new mutations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maintenance: Option<Diagnostic>,
    /// Present while every upstream DNS resolver has stopped answering the
    /// names this daemon forwards (ADR-0036).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_upstream: Option<Diagnostic>,
    /// Present while the owner has turned Remap's system DNS off on purpose
    /// (ADR-0036); absent while it is on, falling back on its own, or was
    /// never activated. Boxed, as `peer_machine_listeners` is, because both
    /// are usually absent and would otherwise size every command result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_turned_off: Option<Box<DnsTurnedOff>>,
    /// The gateway's peer-machine listeners (ADR-0033), when it runs any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_machine_listeners: Option<Box<PeerMachineListeners>>,
}

/// The owner turned Remap's system DNS off on purpose. It carries a time and
/// commands, never a name or an address.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DnsTurnedOff {
    /// UTC time to the minute, such as `2026-10-31T01:20Z`.
    pub turned_off_at: String,
    /// The same time in Unix milliseconds.
    pub turned_off_at_ms: u64,
    /// The command that turned DNS off, such as `remap-system deactivate`.
    pub command: String,
    /// The exact root command that turns DNS back on.
    pub turn_on: String,
}

impl DnsTurnedOff {
    /// One line for status output, such as "turned off by the owner at
    /// 2026-10-31T01:20Z (`remap-system deactivate`)".
    #[must_use]
    pub fn status_line(&self) -> String {
        format!(
            "turned off by the owner at {} (`{}`)",
            self.turned_off_at, self.command
        )
    }
}

/// How many peer-machine service listeners accept connections, and why the
/// others do not.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PeerMachineListeners {
    /// Listeners bound to their mapping's address and accepting.
    pub listening: u64,
    /// Listeners that could not bind.
    pub not_listening: u64,
    /// The first not-listening listeners, by pattern then port, at most 64.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failures: Vec<PeerMachineListenerFailure>,
    /// Connections closed without a stream since the daemon started, by
    /// cause: `endpoint`, `no-supgang`, `refused`, `timeout` or
    /// `unknown-peer`. Causes not seen are omitted.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub refusals: BTreeMap<String, u64>,
}

/// One peer-machine service listener that could not bind.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PeerMachineListenerFailure {
    /// Canonical pattern of the mapping.
    pub pattern: String,
    /// The exposed service.
    pub service: String,
    /// The mapping's allocated address.
    pub address: String,
    /// The port listened on for the service.
    pub port: u16,
    /// Stable cause: `address-not-reserved`, `port-in-use`,
    /// `permission-denied` or `other`.
    pub cause: String,
    /// What the cause means and what to do.
    pub detail: String,
}

/// Stable presentation of one mapping.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MappingView {
    /// Optional same-origin landing path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub landing: Option<String>,
    /// Canonical exact name or wildcard.
    pub pattern: String,
    /// Canonical destination.
    pub target: String,
    /// Destination category.
    pub target_kind: String,
    /// HTTP host behavior, including for direct targets for stable shape.
    pub host_policy: HostPolicy,
    /// Whether the record participates in resolution.
    pub enabled: bool,
    /// Revision that most recently changed this record.
    pub updated_revision: u64,
    /// Loopback address the registry allocated to a peer-machine mapping
    /// (ADR-0033); its DNS answer while enabled. Absent for other kinds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_address: Option<String>,
}

/// One bounded page from the registry.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ListResult {
    /// Registry revision observed by this page.
    pub revision: u64,
    /// Deterministically ordered mappings.
    pub mappings: Vec<MappingView>,
    /// Cursor for the next page, if more records remain.
    pub next_cursor: Option<String>,
}

/// Resolution explanation for one lookup name.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ResolutionResult {
    /// Canonical lookup name.
    pub name: String,
    /// Registry revision used for the decision.
    pub revision: u64,
    /// Selected exact or wildcard mapping.
    pub mapping: Option<MappingView>,
}

/// Canonical result of side-effect-free mapping validation.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ValidationResult {
    /// Advisory guidance that never changes validation or mutation success.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// Optional same-origin landing path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub landing: Option<String>,
    /// Canonical exact name or wildcard.
    pub pattern: String,
    /// Canonical destination.
    pub target: String,
    /// Destination category.
    pub target_kind: String,
    /// Canonical host policy.
    pub host_policy: HostPolicy,
}

/// One projected effect in an ordered change set.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ChangeEffect {
    /// Canonical mapping pattern.
    pub pattern: String,
    /// Stable effect category.
    pub action: String,
    /// Mapping before this effect, when present.
    pub before: Option<MappingView>,
    /// Mapping after this effect, when present.
    pub after: Option<MappingView>,
}

/// Side-effect-free projection of proposed changes.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PreviewResult {
    /// Advisory guidance that never blocks the owner's explicit target,
    /// including reachability of loopback HTTP targets observed now.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// Registry revision against which the projection ran.
    pub base_revision: u64,
    /// Whether committing this projection would advance the revision.
    pub will_change: bool,
    /// Ordered effects, including explicit no-ops.
    pub effects: Vec<ChangeEffect>,
}

/// Receipt for an idempotent committed change set.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ApplyResult {
    /// Advisory guidance retained in the exact idempotent receipt, followed
    /// by reachability of loopback HTTP targets observed when answering.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// Caller-generated idempotency identifier.
    pub operation_id: String,
    /// Revision observed before the operation.
    pub previous_revision: u64,
    /// Revision after the operation.
    pub revision: u64,
    /// Whether authoritative state changed.
    pub changed: bool,
    /// Ordered effects committed by the operation.
    pub effects: Vec<ChangeEffect>,
}

/// Successful response payload for a control command.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum CommandResult {
    /// Status response.
    Status(RegistryStatus),
    /// Runtime-listener proof expectations.
    HealthChallenge(HealthChallengeResult),
    /// Mapping page response.
    List(ListResult),
    /// Exact mapping lookup response.
    Mapping(Option<MappingView>),
    /// Resolution explanation response.
    Resolution(ResolutionResult),
    /// Offline validation response.
    Validation(ValidationResult),
    /// Preview response.
    Preview(PreviewResult),
    /// Mutation receipt.
    Apply(ApplyResult),
    /// Bounded revision wait result.
    Revision(RevisionNotice),
}
