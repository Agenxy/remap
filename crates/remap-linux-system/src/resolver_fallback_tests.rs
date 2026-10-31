// SPDX-License-Identifier: GPL-3.0-or-later
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use remap_linux::{
    ActivationRecord, DnsServer, LinkIndex, LinkState, LinuxErrorKind, RecordMetadata,
};
use remap_protocol::{SystemResult, UpstreamFailure, UpstreamFailureCause};
use uuid::Uuid;

use super::{
    Supervised, rearm_permitted, refusal_kind, seconds_phrase, stopped_result, unanswered_summary,
};
use crate::lifecycle_hints::{UPSTREAM_BYPASS_HINT, bypass_hint};
use crate::lifecycle_recovery::expected_daemon_plan;

fn link_with(octet: u8) -> io::Result<LinkState> {
    let link = LinkIndex::new(2).map_err(io::Error::other)?;
    let server = DnsServer::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, octet)), 0, "")
        .map_err(io::Error::other)?;
    LinkState::new(link, vec![server], Vec::new(), true).map_err(io::Error::other)
}

fn upstream(octet: u8) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, octet)), 53)
}

/// A record in `phase`, built through the public serialized form because only
/// the native transactions move a record between phases.
fn record_in(phase: &str) -> io::Result<ActivationRecord> {
    let before = link_with(53)?;
    let owned = LinkState::remap_loopback(before.link()).map_err(io::Error::other)?;
    let metadata =
        RecordMetadata::new(Uuid::from_u128(7), 11, 1000, 1).map_err(io::Error::other)?;
    let prepared =
        ActivationRecord::prepare(metadata, &[before], owned).map_err(io::Error::other)?;
    let mut encoded = serde_json::to_value(prepared).map_err(io::Error::other)?;
    encoded["phase"] = serde_json::Value::String(phase.to_owned());
    serde_json::from_value(encoded).map_err(io::Error::other)
}

fn health(unanswered: bool) -> SystemResult {
    SystemResult::new(None, None, Some(11)).with_upstream_failure(unanswered.then_some(
        UpstreamFailure {
            cause: UpstreamFailureCause::TimedOut,
            unanswered_queries: 4,
            unanswered_for_ms: 2_600,
        },
    ))
}

#[test]
fn the_verdict_holds_back_a_re_arm_only_onto_the_same_set() -> io::Result<()> {
    let unanswered = [upstream(53)];
    assert!(!rearm_permitted(
        &health(true),
        &link_with(53)?,
        &unanswered
    ));
    assert!(rearm_permitted(&health(true), &link_with(54)?, &unanswered));
    assert!(rearm_permitted(
        &health(false),
        &link_with(53)?,
        &unanswered
    ));
    Ok(())
}

#[test]
fn a_link_without_forwardable_dns_never_re_arms() -> io::Result<()> {
    let loopback = LinkState::remap_loopback(LinkIndex::new(2).map_err(io::Error::other)?)
        .map_err(io::Error::other)?;
    assert!(!rearm_permitted(&health(false), &loopback, &[upstream(53)]));
    Ok(())
}

#[test]
fn the_journal_line_names_the_cause_and_never_an_address() {
    let line = unanswered_summary(UpstreamFailure {
        cause: UpstreamFailureCause::TimedOut,
        unanswered_queries: 4,
        unanswered_for_ms: 2_600,
    });
    assert_eq!(
        line,
        "upstream DNS not answering: every upstream resolver timed out for the last 4 queries over 3 seconds"
    );
    assert!(!line.contains("192.0.2"));
    assert_eq!(seconds_phrase(Duration::from_secs(1)), "1 second");
    assert_eq!(seconds_phrase(Duration::from_secs(300)), "300 seconds");
}

#[test]
fn only_refusals_that_precede_any_effect_are_tolerated() {
    assert!(refusal_kind(LinuxErrorKind::OwnershipConflict));
    assert!(refusal_kind(LinuxErrorKind::UnstableObservation));
    assert!(refusal_kind(LinuxErrorKind::ResolverUnavailable));
    assert!(!refusal_kind(LinuxErrorKind::RecoveryRequired));
    assert!(!refusal_kind(LinuxErrorKind::Persistence));
    assert!(stopped_result(false).is_ok());
    assert_eq!(
        stopped_result(true).err().map(|error| error.kind()),
        Some(io::ErrorKind::Interrupted)
    );
}

#[test]
fn a_supervisor_restarted_while_bypassed_resumes_bypassed() -> io::Result<()> {
    let active = Supervised::new(record_in("active")?, vec![upstream(53)]);
    let bypassed = Supervised::new(record_in("bypassed")?, vec![upstream(53)]);
    assert!(!active.is_bypassed());
    assert!(!active.fallback.is_bypassed());
    assert!(bypassed.is_bypassed());
    assert!(bypassed.fallback.is_bypassed());
    Ok(())
}

#[test]
fn a_bypassed_activation_expects_no_daemon_plan() -> io::Result<()> {
    let active = record_in("active")?;
    let bypassed = record_in("bypassed")?;
    assert_eq!(
        expected_daemon_plan(Some(&active)),
        Some(crate::install_model::ResolverPlanIdentity {
            activation_id: Uuid::from_u128(7),
            generation: 11,
        })
    );
    assert_eq!(expected_daemon_plan(Some(&bypassed)), None);
    assert_eq!(expected_daemon_plan(None), None);
    assert!(bypassed.phase().is_settled());
    Ok(())
}

#[test]
fn status_explains_a_bypass_only_when_nothing_needs_recovery() -> io::Result<()> {
    let bypassed = record_in("bypassed")?;
    let active = record_in("active")?;
    assert_eq!(
        bypass_hint(Some(&bypassed), false),
        Some(UPSTREAM_BYPASS_HINT)
    );
    assert_eq!(bypass_hint(Some(&bypassed), true), None);
    assert_eq!(bypass_hint(Some(&active), false), None);
    assert!(UPSTREAM_BYPASS_HINT.len() <= 512);
    Ok(())
}
