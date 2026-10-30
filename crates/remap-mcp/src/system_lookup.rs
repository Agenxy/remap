// SPDX-License-Identifier: GPL-3.0-or-later
//! Whether the operating system's own resolver returns Remap's answer.
//!
//! The DNS and forwarding probes ask Remap's listener directly, so they stay
//! green while the system has silently stopped using it: a resolver fallback,
//! another DNS service taking over, or a cached answer hiding a live failure.
//! This probe resolves one mapped name through `getaddrinfo`, the path a
//! browser or `curl` takes, and compares the result with what the registry
//! says that name must answer.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use remap_protocol::MappingView;
use tokio::time::timeout;

/// Longest the system resolver may take before the lookup counts as failed.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(3);

/// What the system resolver said about one mapped name.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum SystemLookup {
    /// It returned exactly the addresses Remap answers.
    Matched {
        /// The probed name.
        name: String,
        /// The first address returned.
        answer: IpAddr,
    },
    /// It returned other addresses: the system is not asking Remap.
    Bypassed {
        /// The probed name.
        name: String,
        /// The first address Remap would not have given.
        answer: IpAddr,
    },
    /// It returned nothing, or gave up.
    Unresolved {
        /// The probed name.
        name: String,
    },
    /// No enabled, exact mapping has an answer this probe can predict.
    NotChecked,
}

impl SystemLookup {
    /// A stable token for structured output.
    #[must_use]
    pub const fn state(&self) -> &'static str {
        match self {
            Self::Matched { .. } => "ready",
            Self::Bypassed { .. } => "bypassed",
            Self::Unresolved { .. } => "unresolved",
            Self::NotChecked => "not_checked",
        }
    }

    /// The name that was probed, if any.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Matched { name, .. }
            | Self::Bypassed { name, .. }
            | Self::Unresolved { name } => Some(name),
            Self::NotChecked => None,
        }
    }

    /// The first address the system returned, if any.
    #[must_use]
    pub const fn answer(&self) -> Option<IpAddr> {
        match self {
            Self::Matched { answer, .. } | Self::Bypassed { answer, .. } => Some(*answer),
            Self::Unresolved { .. } | Self::NotChecked => None,
        }
    }
}

/// The first enabled exact mapping and the addresses Remap must answer for
/// it: loopback for a routed name, the literal address for a direct one. A
/// wildcard or an alias has no single predictable answer and is skipped.
#[must_use]
pub fn candidate(mappings: &[MappingView]) -> Option<(String, Vec<IpAddr>)> {
    mappings
        .iter()
        .filter(|mapping| mapping.enabled && !mapping.pattern.starts_with("*."))
        .find_map(|mapping| {
            let expected = match mapping.target_kind.as_str() {
                "http" | "peer" => vec![
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    IpAddr::V6(Ipv6Addr::LOCALHOST),
                ],
                "dns-address" => vec![mapping.target.parse().ok()?],
                _ => return None,
            };
            Some((mapping.pattern.clone(), expected))
        })
}

/// Resolves `name` through the operating system and classifies the answer.
pub async fn probe(name: String, expected: &[IpAddr]) -> SystemLookup {
    let answers = timeout(LOOKUP_TIMEOUT, tokio::net::lookup_host((name.as_str(), 0)))
        .await
        .ok()
        .and_then(Result::ok)
        .map(|addresses| addresses.map(|address| address.ip()).collect::<Vec<_>>())
        .unwrap_or_default();
    classify(name, &answers, expected)
}

/// Every address returned must be one Remap answers. One stray address means
/// the system asked another resolver for at least one family.
#[must_use]
pub fn classify(name: String, answers: &[IpAddr], expected: &[IpAddr]) -> SystemLookup {
    let Some(&first) = answers.first() else {
        return SystemLookup::Unresolved { name };
    };
    if let Some(&stray) = answers.iter().find(|answer| !expected.contains(answer)) {
        return SystemLookup::Bypassed {
            name,
            answer: stray,
        };
    }
    SystemLookup::Matched {
        name,
        answer: first,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use remap_protocol::{HostPolicy, MappingView};

    use super::{SystemLookup, candidate, classify, probe};

    fn view(pattern: &str, target: &str, kind: &str, enabled: bool) -> MappingView {
        MappingView {
            pattern: pattern.to_owned(),
            target: target.to_owned(),
            target_kind: kind.to_owned(),
            host_policy: HostPolicy::UseUpstream,
            enabled,
            updated_revision: 1,
            landing: None,
            peer_address: None,
        }
    }

    const LOOPBACK: [IpAddr; 2] = [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ];

    #[test]
    fn a_routed_name_must_resolve_to_loopback_and_a_direct_name_to_its_address() {
        let mappings = [
            view("*.lab", "http://127.0.0.1:1/", "http", true),
            view("off.test", "http://127.0.0.1:2/", "http", false),
            view("alias.test", "example.com", "dns-alias", true),
            view("agenxy.internal", "http://127.0.0.1:8792/", "http", true),
        ];
        assert_eq!(
            candidate(&mappings),
            Some(("agenxy.internal".to_owned(), LOOPBACK.to_vec()))
        );
        let direct = [view("nas", "192.0.2.7", "dns-address", true)];
        assert_eq!(
            candidate(&direct),
            Some((
                "nas".to_owned(),
                vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7))]
            ))
        );
        assert_eq!(
            candidate(&[view("*.lab", "10.0.0.1", "dns-address", true)]),
            None
        );
    }

    #[test]
    fn any_answer_remap_did_not_give_is_a_bypass() {
        let router = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 254));
        assert!(matches!(
            classify("a.test".into(), &[LOOPBACK[0], LOOPBACK[1]], &LOOPBACK),
            SystemLookup::Matched { .. }
        ));
        assert_eq!(
            classify("a.test".into(), &[LOOPBACK[0], router], &LOOPBACK).state(),
            "bypassed"
        );
        assert_eq!(
            classify("a.test".into(), &[], &LOOPBACK).state(),
            "unresolved"
        );
    }

    // The probe goes through the system resolver (getaddrinfo), not a DNS
    // socket: `localhost` resolves to loopback on every supported platform
    // without Remap, so this exercises the real path in CI.
    #[tokio::test]
    async fn the_probe_asks_the_operating_system_resolver() {
        let lookup = probe("localhost".to_owned(), &LOOPBACK).await;
        assert_eq!(lookup.state(), "ready", "{lookup:?}");
        let unknown = probe("remap-probe.invalid".to_owned(), &LOOPBACK).await;
        assert_eq!(unknown.state(), "unresolved", "{unknown:?}");
    }
}
