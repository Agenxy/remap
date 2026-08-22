use remap_protocol::{Change, HostPolicy};
use schemars::JsonSchema;
use serde::Deserialize;

/// Maximum records returned by one MCP list operation.
pub(crate) const MAX_MCP_MAPPING_PAGE_SIZE: u16 = 64;

/// Maximum effects returned by one MCP preview or apply operation.
pub(crate) const MAX_MCP_ATOMIC_CHANGE_COUNT: usize = 32;

const fn default_limit() -> u16 {
    MAX_MCP_MAPPING_PAGE_SIZE
}

const fn default_host_policy() -> HostPolicy {
    HostPolicy::UseUpstream
}

/// Explicit empty input that rejects unknown status arguments.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct EmptyParams {}

/// Parameters for a bounded registry listing.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ListParams {
    /// Return patterns lexically after this cursor.
    #[serde(default)]
    #[schemars(length(max = 255))]
    pub after: Option<String>,
    /// Maximum mappings to return, from 1 through 64.
    #[serde(default = "default_limit")]
    #[schemars(range(min = 1, max = 64))]
    pub limit: u16,
    /// Include disabled mappings in the result.
    #[serde(default)]
    pub include_disabled: bool,
}

/// Parameters identifying one canonical mapping pattern.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct PatternParams {
    /// Exact hostname or leading-label wildcard such as `*.internal`.
    #[schemars(length(min = 1, max = 255))]
    pub pattern: String,
}

/// Parameters identifying one name to resolve.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResolveParams {
    /// Hostname whose winning exact or wildcard mapping should be explained.
    #[schemars(length(min = 1, max = 253))]
    pub name: String,
}

/// Parameters for side-effect-free mapping validation.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ValidateParams {
    /// Exact hostname or leading-label wildcard.
    #[schemars(length(min = 1, max = 255))]
    pub pattern: String,
    /// IP address, DNS name, or absolute HTTP(S) upstream URL.
    #[schemars(length(min = 1, max = 4_096))]
    pub target: String,
    /// Whether routed HTTP(S) traffic preserves the client-facing host.
    #[serde(default = "default_host_policy")]
    pub host_policy: HostPolicy,
}

/// One machine-readable change in an ordered atomic batch.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ChangeInput {
    /// Create a mapping or replace its destination.
    Set {
        /// Exact hostname or leading-label wildcard.
        #[schemars(length(min = 1, max = 255))]
        pattern: String,
        /// IP address, DNS name, or absolute HTTP(S) upstream URL.
        #[schemars(length(min = 1, max = 4_096))]
        target: String,
        /// Whether routed HTTP(S) traffic preserves the client-facing host.
        #[serde(default = "default_host_policy")]
        host_policy: HostPolicy,
        /// Explicit enabled state; omission preserves an existing state.
        #[serde(default)]
        enabled: Option<bool>,
    },
    /// Enable an existing mapping.
    Enable {
        /// Exact canonical mapping pattern.
        #[schemars(length(min = 1, max = 255))]
        pattern: String,
    },
    /// Disable an existing mapping without deleting it.
    Disable {
        /// Exact canonical mapping pattern.
        #[schemars(length(min = 1, max = 255))]
        pattern: String,
    },
    /// Delete an existing mapping.
    Remove {
        /// Exact canonical mapping pattern.
        #[schemars(length(min = 1, max = 255))]
        pattern: String,
    },
}

impl From<ChangeInput> for Change {
    fn from(value: ChangeInput) -> Self {
        match value {
            ChangeInput::Set {
                pattern,
                target,
                host_policy,
                enabled,
            } => Self::Set {
                pattern,
                target,
                host_policy,
                enabled,
            },
            ChangeInput::Enable { pattern } => Self::Enable { pattern },
            ChangeInput::Disable { pattern } => Self::Disable { pattern },
            ChangeInput::Remove { pattern } => Self::Remove { pattern },
        }
    }
}

/// Parameters for projecting an ordered batch without committing it.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct PreviewParams {
    /// Changes evaluated in order and, if later applied, committed atomically.
    #[schemars(length(min = 1, max = 32))]
    pub changes: Vec<ChangeInput>,
}

/// Parameters required by enable, disable, and remove operations.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct MutationParams {
    /// Registry revision observed before deciding to mutate.
    pub expected_revision: u64,
    /// Fresh `UUIDv4` for this logical operation; reuse it only to retry the same request.
    #[schemars(
        length(equal = 36),
        regex(
            pattern = "^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-4[0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}$"
        )
    )]
    pub operation_id: String,
    /// Exact canonical mapping pattern.
    #[schemars(length(min = 1, max = 255))]
    pub pattern: String,
}

/// Parameters for creating or retargeting one mapping.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct SetParams {
    /// Registry revision observed before deciding to mutate.
    pub expected_revision: u64,
    /// Fresh `UUIDv4` for this logical operation; reuse it only to retry the same request.
    #[schemars(
        length(equal = 36),
        regex(
            pattern = "^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-4[0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}$"
        )
    )]
    pub operation_id: String,
    /// Exact hostname or leading-label wildcard.
    #[schemars(length(min = 1, max = 255))]
    pub pattern: String,
    /// IP address, DNS name, or absolute HTTP(S) upstream URL.
    #[schemars(length(min = 1, max = 4_096))]
    pub target: String,
    /// Whether routed HTTP(S) traffic preserves the client-facing host.
    #[serde(default = "default_host_policy")]
    pub host_policy: HostPolicy,
    /// Explicit enabled state; omission preserves an existing state.
    #[serde(default)]
    pub enabled: Option<bool>,
}

/// Parameters for an atomic multi-change commit.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ApplyParams {
    /// Registry revision observed before deciding to mutate.
    pub expected_revision: u64,
    /// Fresh `UUIDv4` for this logical operation; reuse it only to retry the same request.
    #[schemars(
        length(equal = 36),
        regex(
            pattern = "^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-4[0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}$"
        )
    )]
    pub operation_id: String,
    /// Ordered changes committed together or not at all.
    #[schemars(length(min = 1, max = 32))]
    pub changes: Vec<ChangeInput>,
}

/// Returns a diagnostic if a requested page size is unsafe or nonsensical.
pub(crate) fn validate_limit(limit: u16) -> Result<(), remap_protocol::Diagnostic> {
    if (1..=MAX_MCP_MAPPING_PAGE_SIZE).contains(&limit) {
        return Ok(());
    }
    Err(remap_protocol::Diagnostic::new(
        "E_LIST_LIMIT",
        format!("list limit must be between 1 and {MAX_MCP_MAPPING_PAGE_SIZE}"),
        Some(format!(
            "choose a limit from 1 through {MAX_MCP_MAPPING_PAGE_SIZE}, then retry"
        )),
        false,
    ))
}

/// Returns a diagnostic when an MCP batch could exceed the bounded result envelope.
pub(crate) fn validate_change_count(count: usize) -> Result<(), remap_protocol::Diagnostic> {
    if count <= MAX_MCP_ATOMIC_CHANGE_COUNT {
        return Ok(());
    }
    Err(remap_protocol::Diagnostic::new(
        "E_CHANGE_LIMIT",
        format!(
            "MCP preview and apply operations accept at most {MAX_MCP_ATOMIC_CHANGE_COUNT} changes"
        ),
        Some("split the operation into smaller revision-guarded batches, previewing each batch before applying it".to_owned()),
        false,
    ))
}

#[cfg(test)]
mod tests {
    use remap_protocol::HostPolicy;

    use super::SetParams;

    #[test]
    fn omitted_http_host_policy_uses_the_destination() -> Result<(), serde_json::Error> {
        let parameters: SetParams = serde_json::from_value(serde_json::json!({
            "expected_revision": 0,
            "operation_id": "4df4bb55-93bb-4f99-9707-9761f6a69364",
            "pattern": "remap.test",
            "target": "http://127.0.0.1:4270"
        }))?;

        assert_eq!(parameters.host_policy, HostPolicy::UseUpstream);
        Ok(())
    }
}
