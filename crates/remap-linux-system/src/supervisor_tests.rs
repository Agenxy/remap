use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use remap_linux::{DnsServer, LinkDomain, LinkIndex, LinkState};
use remap_protocol::SystemResult;
use uuid::Uuid;

use crate::resolver_generation::monotonic_generation;
use crate::resolver_stability::REQUIRED_STABLE_OBSERVATIONS;
use crate::resolver_stability::deadline_reached as steady_deadline_reached;
use crate::resolver_stability::seeded as seeded_steady_stability;

use super::{
    ObservationStability, PlanState, RECONCILE_INTERVAL, STABILITY_INTERVAL,
    STEADY_STABILITY_TIMEOUT, plan_state,
};

#[test]
fn only_typed_manager_unavailability_enters_the_startup_retry_path() {
    let unavailable = crate::resolver_worker::platform_error(remap_linux::LinuxError::new(
        remap_linux::LinuxErrorKind::ResolverUnavailable,
        "synthetic manager outage",
    ));
    let conflict = crate::resolver_worker::platform_error(remap_linux::LinuxError::new(
        remap_linux::LinuxErrorKind::OwnershipConflict,
        "synthetic manager conflict",
    ));
    assert!(crate::resolver_worker::platform_error_is_unavailable(
        &unavailable
    ));
    assert!(!crate::resolver_worker::platform_error_is_unavailable(
        &conflict
    ));
}

#[test]
fn steady_reconciliation_is_bounded_without_weakening_startup_stability() {
    assert_eq!(REQUIRED_STABLE_OBSERVATIONS, 3);
    assert!(
        STABILITY_INTERVAL * u32::from(REQUIRED_STABLE_OBSERVATIONS - 1) >= Duration::from_secs(1)
    );
    assert_eq!(RECONCILE_INTERVAL, Duration::from_secs(1));
    assert!(STEADY_STABILITY_TIMEOUT <= Duration::from_millis(150));
}

#[test]
fn steady_reconciliation_counts_the_seed_in_debug_and_release() {
    let mut stability = seeded_steady_stability(42_u8);
    assert!(!stability.observe(42));
    assert!(stability.observe(42));
}

#[test]
fn steady_reconciliation_timeout_boundary_is_exact() {
    let deadline = tokio::time::Instant::now() + STEADY_STABILITY_TIMEOUT;
    assert!(!steady_deadline_reached(
        deadline - Duration::from_nanos(1),
        deadline
    ));
    assert!(steady_deadline_reached(deadline, deadline));
}

#[test]
fn resolver_generation_survives_a_backward_clock() {
    assert_eq!(monotonic_generation(41, Some(900)), Some(901));
    assert_eq!(monotonic_generation(901, Some(900)), Some(901));
    assert_eq!(monotonic_generation(902, Some(900)), Some(902));
    assert_eq!(monotonic_generation(41, Some(u64::MAX)), None);
}

#[test]
fn ambiguous_publication_state_is_never_treated_as_empty() {
    let activation_id = Uuid::new_v4();
    let exact = SystemResult {
        activation_id: Some(activation_id),
        active_generation: Some(42),
    };
    let empty = SystemResult {
        activation_id: None,
        active_generation: None,
    };
    let partial = SystemResult {
        activation_id: Some(activation_id),
        active_generation: None,
    };
    assert_eq!(plan_state(&exact, activation_id, 42), PlanState::Exact);
    assert_eq!(plan_state(&empty, activation_id, 42), PlanState::Empty);
    assert_eq!(plan_state(&partial, activation_id, 42), PlanState::Other);
    assert_eq!(plan_state(&exact, activation_id, 43), PlanState::Other);
}

#[test]
fn staggered_manager_fields_never_become_a_stable_rebase_input() -> std::io::Result<()> {
    let link = LinkIndex::new(2).map_err(std::io::Error::other)?;
    let dns = DnsServer::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)), 0, "")
        .map_err(std::io::Error::other)?;
    let domain = LinkDomain::new("example.test", false).map_err(std::io::Error::other)?;
    let dns_only = LinkState::new(link, vec![dns.clone()], Vec::new(), false)
        .map_err(std::io::Error::other)?;
    let dns_and_domain = LinkState::new(link, vec![dns.clone()], vec![domain.clone()], false)
        .map_err(std::io::Error::other)?;
    let configured =
        LinkState::new(link, vec![dns], vec![domain], true).map_err(std::io::Error::other)?;
    let mut stability = ObservationStability::default();

    assert!(!stability.observe(dns_only));
    assert!(!stability.observe(dns_and_domain));
    assert!(!stability.observe(configured.clone()));
    assert!(!stability.observe(configured.clone()));
    assert!(stability.observe(configured));
    Ok(())
}
