// SPDX-License-Identifier: GPL-3.0-or-later
//! The receipt a mutation tool returns, with the registry counts at the
//! committed revision when they can be read at exactly that revision.
//!
//! An MCP Apps host renders a fresh dashboard for every tool result. A host
//! that does not let the dashboard call tools would otherwise show the new
//! revision beside counts it never learned. So the receipt carries them, but
//! only when a status read lands on the receipt's own revision: counts from
//! any other revision would be a different registry.

use remap_protocol::{ApplyResult, RegistryStatus};
use schemars::JsonSchema;
use serde::Serialize;

/// A committed change set's receipt, as the MCP tools return it.
#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct CommitReceipt {
    /// The daemon's exact, idempotent receipt.
    #[serde(flatten)]
    pub receipt: ApplyResult,
    /// Registry status at `revision`, absent when it could not be read at
    /// exactly that revision.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry: Option<RegistryStatus>,
}

impl CommitReceipt {
    /// Pairs `receipt` with `status` only when both describe one revision.
    pub(crate) fn new(receipt: ApplyResult, status: Option<RegistryStatus>) -> Self {
        let registry = status.filter(|status| status.revision == receipt.revision);
        Self { receipt, registry }
    }
}

#[cfg(test)]
mod tests {
    use remap_protocol::{ApplyResult, RegistryStatus};

    use super::CommitReceipt;

    fn receipt(revision: u64) -> ApplyResult {
        ApplyResult {
            warnings: Vec::new(),
            operation_id: "7c2e9a41-3b5d-4f8e-9a17-2d6c4b8e1f03".to_owned(),
            previous_revision: revision - 1,
            revision,
            changed: true,
            effects: Vec::new(),
        }
    }

    fn status(revision: u64) -> RegistryStatus {
        RegistryStatus {
            revision,
            mapping_count: 8,
            enabled_count: 7,
            schema_version: 2,
            daemon_version: "0.2.0".to_owned(),
            maintenance: None,
            dns_upstream: None,
            dns_turned_off: None,
            peer_machine_listeners: None,
        }
    }

    #[test]
    fn counts_at_the_committed_revision_ride_with_the_receipt()
    -> Result<(), Box<dyn std::error::Error>> {
        let value = serde_json::to_value(CommitReceipt::new(receipt(37), Some(status(37))))?;
        assert_eq!(value["revision"], 37);
        assert_eq!(
            value["operation_id"],
            "7c2e9a41-3b5d-4f8e-9a17-2d6c4b8e1f03"
        );
        assert_eq!(value["registry"]["revision"], 37);
        assert_eq!(value["registry"]["mapping_count"], 8);
        assert_eq!(value["registry"]["enabled_count"], 7);
        Ok(())
    }

    #[test]
    fn counts_from_another_revision_are_left_out() -> Result<(), Box<dyn std::error::Error>> {
        for other in [36, 38] {
            let value = serde_json::to_value(CommitReceipt::new(receipt(37), Some(status(other))))?;
            assert!(value.get("registry").is_none(), "revision {other}");
            assert_eq!(value["revision"], 37);
        }
        let value = serde_json::to_value(CommitReceipt::new(receipt(37), None))?;
        assert!(value.get("registry").is_none());
        Ok(())
    }
}
