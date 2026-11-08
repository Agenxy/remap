// SPDX-License-Identifier: GPL-3.0-or-later
//! What the native lifecycle status tells a person to do next.

use remap_linux::ActivationPhase;

use crate::lifecycle_contract::LinkCandidate;

pub(crate) fn link_selection_hint(
    selected: bool,
    recovery_required: bool,
    candidates: &[LinkCandidate],
) -> Option<&'static str> {
    if selected || recovery_required {
        return None;
    }
    let primary_count = candidates
        .iter()
        .filter(|candidate| candidate.selection_state == "supported_primary")
        .count();
    Some(match primary_count {
        0 => {
            "no supported primary interface is available; inspect link candidates and resolver ownership"
        }
        1 => "the only supported primary interface will be selected automatically",
        _ => "select one supported primary interface with REMAP_LINUX_LINK=<index> make install",
    })
}

/// Explains a fallback to ordinary DNS (ADR-0036); it needs no action.
pub(crate) fn bypass_hint(
    activation: Option<&remap_linux::ActivationRecord>,
    recovery_required: bool,
) -> Option<&'static str> {
    (!recovery_required
        && activation.is_some_and(|value| value.phase() == ActivationPhase::Bypassed))
    .then_some(UPSTREAM_BYPASS_HINT)
}

pub(crate) const UPSTREAM_BYPASS_HINT: &str = "upstream DNS stopped answering, so ordinary DNS is in effect; Remap DNS returns by itself once those resolvers answer again or the network offers others";
