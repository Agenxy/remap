//! Advisory reachability in previews and apply receipts (ADR-0028).
//!
//! After the registry answers a preview or an apply, each loopback HTTP
//! target the change set leaves enabled is probed once, concurrently, with
//! a bounded TCP connect. A target nothing accepts adds an advisory warning
//! to the result. The registry has already decided by then: a warning never
//! blocks a change, and it is never stored in the idempotent receipt, so a
//! retried apply reports what is listening at the time of the retry.

use std::collections::BTreeMap;
use std::net::SocketAddr;

use remap_core::{HostHeaderPolicy, MappingTarget};
use remap_network::{PROBE_DEADLINE, Reachability, loopback_addresses, probe};
use remap_protocol::{ChangeEffect, CommandResult, HostPolicy};
use tokio::task::JoinSet;

/// Adds reachability advice to a preview or apply result; any other result
/// is left alone. Waits at most [`PROBE_DEADLINE`], however many targets.
pub(crate) async fn advise(result: &mut CommandResult) {
    let (effects, warnings) = match result {
        CommandResult::Preview(preview) => (&preview.effects, &mut preview.warnings),
        CommandResult::Apply(receipt) => (&receipt.effects, &mut receipt.warnings),
        _ => return,
    };
    let mut probes = JoinSet::new();
    for (pattern, addresses) in probed_targets(effects) {
        probes.spawn(async move {
            let observed = probe(&addresses, PROBE_DEADLINE).await;
            (pattern, observed)
        });
    }
    let mut observed = BTreeMap::new();
    while let Some(joined) = probes.join_next().await {
        if let Ok((pattern, reachability)) = joined {
            observed.insert(pattern, reachability);
        }
    }
    warnings.extend(
        observed
            .iter()
            .filter_map(|(pattern, reachability)| advice(pattern, *reachability)),
    );
}

/// The loopback addresses of each pattern's final state in the change set,
/// for the patterns that end enabled with a loopback HTTP target.
fn probed_targets(effects: &[ChangeEffect]) -> BTreeMap<String, Vec<SocketAddr>> {
    let mut latest = BTreeMap::new();
    for effect in effects {
        let addresses = effect
            .after
            .as_ref()
            .filter(|mapping| mapping.enabled)
            .and_then(|mapping| {
                let policy = match mapping.host_policy {
                    HostPolicy::PreserveClient => HostHeaderPolicy::PreserveClient,
                    HostPolicy::UseUpstream => HostHeaderPolicy::UseUpstream,
                };
                MappingTarget::parse_with_http_policy(&mapping.target, policy).ok()
            })
            .and_then(|target| loopback_addresses(&target));
        latest.insert(effect.pattern.clone(), addresses);
    }
    latest
        .into_iter()
        .filter_map(|(pattern, addresses)| addresses.map(|addresses| (pattern, addresses)))
        .collect()
}

fn advice(pattern: &str, reachability: Reachability) -> Option<String> {
    let consequence = match reachability {
        Reachability::Accepted => return None,
        Reachability::Refused => {
            "target refused connection; nothing is listening there, so requests will fail with 502 E_GATEWAY_UPSTREAM (cause refused) until a service starts"
        }
        Reachability::TimedOut => {
            "target did not accept a connection within 1 second; requests may fail with 502 or 504 until it does"
        }
        Reachability::Failed => {
            "target could not be connected to on this machine; requests may fail with 502 E_GATEWAY_UPSTREAM"
        }
    };
    Some(format!("{pattern}: {consequence}"))
}
