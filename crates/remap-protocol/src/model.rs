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
#[serde(deny_unknown_fields)]
pub struct RevisionNotice {
    /// Latest authoritative revision at return time.
    pub revision: u64,
    /// Whether the revision advanced beyond the caller's observation.
    pub changed: bool,
}

/// Authenticated runtime-listener expectations for one fresh challenge.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
}

/// Stable presentation of one mapping.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MappingView {
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
}

/// One bounded page from the registry.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct ValidationResult {
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct PreviewResult {
    /// Registry revision against which the projection ran.
    pub base_revision: u64,
    /// Whether committing this projection would advance the revision.
    pub will_change: bool,
    /// Ordered effects, including explicit no-ops.
    pub effects: Vec<ChangeEffect>,
}

/// Receipt for an idempotent committed change set.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApplyResult {
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
