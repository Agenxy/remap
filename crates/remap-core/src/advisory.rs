// SPDX-License-Identifier: GPL-3.0-or-later
use crate::MappingTarget;

/// Returns non-blocking guidance without changing the owner's target or policy.
#[must_use]
pub fn target_advisories(target: &MappingTarget) -> Vec<String> {
    if let MappingTarget::Http(upstream) = target
        && upstream.base_path() != "/"
    {
        let path = upstream.base_path().chars().take(128).collect::<String>();
        return vec![format!(
            "requests are prefixed with {path}; root-absolute assets may 404; to alias one page, map the origin root and use --landing for the page path",
        )];
    }
    Vec::new()
}
