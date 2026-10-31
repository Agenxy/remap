// SPDX-License-Identifier: GPL-3.0-or-later
//! The one-sentence summary the MCP status tool gives beside its data.

use remap_protocol::RegistryStatus;

pub(crate) fn status_summary(status: &RegistryStatus) -> String {
    let base = format!(
        "Revision {} contains {} mappings; {} are active.",
        status.revision, status.mapping_count, status.enabled_count
    );
    let base = match &status.dns_upstream {
        Some(upstream) => format!(
            "{base} Upstream DNS {}.",
            upstream
                .message
                .strip_prefix("upstream DNS ")
                .unwrap_or(&upstream.message)
        ),
        None => base,
    };
    let base = match &status.dns_turned_off {
        Some(turned_off) => format!(
            "{base} Remap DNS was {}; turn it on with: {}.",
            turned_off.status_line(),
            turned_off.turn_on
        ),
        None => base,
    };
    if let Some(error) = &status.maintenance {
        format!(
            "{base} Mutations are blocked by maintenance ({}).",
            error.code
        )
    } else {
        base
    }
}

#[cfg(test)]
mod tests {
    use remap_protocol::{Diagnostic, RegistryStatus};

    use super::status_summary;

    #[test]
    fn status_summary_identifies_mutation_blocking_maintenance() {
        let status = RegistryStatus {
            revision: 8,
            mapping_count: 2,
            enabled_count: 1,
            schema_version: 1,
            daemon_version: "0.1.0".to_owned(),
            maintenance: Some(Diagnostic::new(
                "E_REGISTRY_CHECKPOINT",
                "checkpoint blocked",
                None,
                true,
            )),
            dns_upstream: None,
            dns_turned_off: None,
        };

        let summary = status_summary(&status);
        assert!(summary.contains("Mutations are blocked by maintenance"));
        assert!(summary.contains("E_REGISTRY_CHECKPOINT"));
    }

    #[test]
    fn status_summary_says_upstream_dns_is_not_answering() {
        let failure = remap_protocol::UpstreamFailure {
            cause: remap_protocol::UpstreamFailureCause::Refused,
            unanswered_queries: 5,
            unanswered_for_ms: 4_000,
        };
        let status = RegistryStatus {
            revision: 8,
            mapping_count: 2,
            enabled_count: 1,
            schema_version: 1,
            daemon_version: "0.2.0".to_owned(),
            maintenance: None,
            dns_upstream: Some(failure.diagnostic()),
            dns_turned_off: None,
        };

        let summary = status_summary(&status);
        assert!(summary.contains("Upstream DNS not answering: every upstream resolver"));
        let turned_off = RegistryStatus {
            dns_upstream: None,
            dns_turned_off: Some(remap_protocol::DnsTurnedOff {
                turned_off_at: "2026-10-31T01:20Z".to_owned(),
                turned_off_at_ms: 1_793_409_600_000,
                command: "remap-system deactivate".to_owned(),
                turn_on: "sudo remap-system activate".to_owned(),
            }),
            ..status.clone()
        };
        assert!(status_summary(&turned_off).contains(
            "Remap DNS was turned off by the owner at 2026-10-31T01:20Z (`remap-system deactivate`)"
        ));
        assert!(summary.contains("refused the queries"));
    }
}
