use std::collections::{BTreeMap, BTreeSet};

use remap_core::{HttpScheme, MappingTarget, target_advisories};
use remap_protocol::{ChangeEffect, HostPolicy};

use crate::project::{StoredMapping, core_host_policy};

fn origin(target: &MappingTarget) -> Option<String> {
    let MappingTarget::Http(upstream) = target else {
        return None;
    };
    let port = upstream.port().map_or_else(
        || match upstream.scheme() {
            HttpScheme::Http => 80,
            HttpScheme::Https => 443,
        },
        std::num::NonZeroU16::get,
    );
    Some(format!(
        "{}://{}:{port}",
        upstream.scheme(),
        upstream.host()
    ))
}

pub(crate) fn warnings(
    effects: &[ChangeEffect],
    mappings: &BTreeMap<String, StoredMapping>,
) -> Vec<String> {
    let mut warnings = BTreeSet::new();
    for effect in effects {
        let Some(mapping) = effect.after.as_ref() else {
            continue;
        };
        let Ok(target) = MappingTarget::parse_with_http_policy(
            &mapping.target,
            core_host_policy(mapping.host_policy),
        ) else {
            continue;
        };
        warnings.extend(target_advisories(&target));
        if mapping.host_policy != HostPolicy::UseUpstream {
            continue;
        }
        let Some(key) = origin(&target) else {
            continue;
        };
        let count = mappings
            .values()
            .filter(|other| other.enabled && other.host_policy == HostPolicy::UseUpstream)
            .filter_map(|other| {
                MappingTarget::parse_with_http_policy(
                    &other.target,
                    core_host_policy(other.host_policy),
                )
                .ok()
            })
            .filter(|other| origin(other).as_ref() == Some(&key))
            .take(2)
            .count();
        if count >= 2 {
            warnings.insert("multiple names share this origin under use-upstream; use --host-header preserve-client if the origin selects sites by their client-facing name; the default remains use-upstream".to_owned());
        }
    }
    warnings.into_iter().collect()
}
