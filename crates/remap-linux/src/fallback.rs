// SPDX-License-Identifier: GPL-3.0-or-later
//! When the resolver supervisor returns to Remap DNS after it restored
//! ordinary DNS (ADR-0030, ADR-0036).
//!
//! This is the same policy the macOS supervisor applies, in awake time since
//! the supervisor started. A fault restores ordinary DNS at once. Re-arming
//! waits until the daemon has answered every probe for `base` of awake time.
//! A bypass that follows a re-arm within `reset_after` doubles the wait, up
//! to `cap`; an armed run of at least `reset_after` forgets earlier bypasses.

use std::net::SocketAddr;
use std::time::Duration;

/// How eagerly the supervisor returns to Remap DNS after a bypass.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct RearmDamping {
    base: Duration,
    cap: Duration,
    reset_after: Duration,
}

impl RearmDamping {
    /// The ADR-0030 policy: 5 seconds, doubling to 5 minutes, forgotten after
    /// 5 minutes armed.
    pub const STANDARD: Self = Self {
        base: Duration::from_secs(5),
        cap: Duration::from_secs(300),
        reset_after: Duration::from_secs(300),
    };
}

/// The supervisor's memory of recent bypasses.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ResolverFallback {
    policy: RearmDamping,
    required: Duration,
    armed_since: Option<Duration>,
    healthy_since: Option<Duration>,
    bypassed: bool,
}

impl ResolverFallback {
    /// A supervisor whose record is armed.
    #[must_use]
    pub const fn armed(policy: RearmDamping) -> Self {
        Self {
            policy,
            required: policy.base,
            armed_since: None,
            healthy_since: None,
            bypassed: false,
        }
    }

    /// A supervisor that started with a bypassed record. It remembers no
    /// earlier bypass, so it owes the base period. Unlike a restarted macOS
    /// supervisor it does not try at once: a lifecycle start accepts the
    /// bypassed record as it is, and must not see it rewritten meanwhile.
    #[must_use]
    pub const fn resumed_bypassed(policy: RearmDamping) -> Self {
        Self {
            bypassed: true,
            ..Self::armed(policy)
        }
    }

    /// Records a bypass that restored ordinary DNS at `now`.
    pub fn note_bypass(&mut self, now: Duration) {
        if self.bypassed {
            return;
        }
        self.bypassed = true;
        self.required = match self.armed_since {
            Some(since) if now.saturating_sub(since) < self.policy.reset_after => {
                self.required.saturating_mul(2).min(self.policy.cap)
            }
            Some(_) | None => self.policy.base,
        };
        self.armed_since = None;
        self.healthy_since = None;
    }

    /// Records that Remap DNS was re-armed at `now`; only the first call
    /// after a bypass starts the armed run.
    pub fn note_armed(&mut self, now: Duration) {
        if !self.bypassed {
            return;
        }
        self.bypassed = false;
        self.armed_since = Some(now);
        self.healthy_since = None;
    }

    /// Records one health probe of the daemon while bypassed. A failed probe
    /// starts the period again.
    pub fn note_probe(&mut self, now: Duration, answered: bool) {
        if !self.bypassed {
            return;
        }
        if answered {
            self.healthy_since.get_or_insert(now);
        } else {
            self.healthy_since = None;
        }
    }

    /// A re-arm attempt at the end of the period that did not re-arm, as when
    /// the same upstreams still do not answer, starts the period again.
    pub const fn restart_period(&mut self) {
        self.healthy_since = None;
    }

    /// Whether the daemon has been healthy for long enough to try re-arming.
    #[must_use]
    pub fn rearm_due(&self, now: Duration) -> bool {
        self.bypassed
            && self
                .healthy_since
                .is_some_and(|since| now.saturating_sub(since) >= self.required)
    }

    /// Whether ordinary DNS is in effect.
    #[must_use]
    pub const fn is_bypassed(&self) -> bool {
        self.bypassed
    }

    /// Continuous daemon health the current bypass requires before re-arming.
    #[must_use]
    pub const fn required(&self) -> Duration {
        self.required
    }
}

/// Whether two upstream lists are the set the daemon's verdict is about. The
/// daemon keys its verdict by the set, so order and repetition do not count.
#[must_use]
pub fn same_upstream_set(left: &[SocketAddr], right: &[SocketAddr]) -> bool {
    let key = |upstreams: &[SocketAddr]| {
        let mut key = upstreams.to_vec();
        key.sort_unstable();
        key.dedup();
        key
    };
    key(left) == key(right)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::time::Duration;

    use super::{RearmDamping, ResolverFallback, same_upstream_set};

    const fn seconds(value: u64) -> Duration {
        Duration::from_secs(value)
    }

    fn healthy_for(fallback: &mut ResolverFallback, from: u64, to: u64) {
        for now in from..=to {
            fallback.note_probe(seconds(now), true);
        }
    }

    #[test]
    fn one_answered_probe_after_a_bypass_does_not_re_arm() {
        let mut fallback = ResolverFallback::armed(RearmDamping::STANDARD);
        fallback.note_bypass(seconds(10));
        fallback.note_probe(seconds(11), true);
        assert!(!fallback.rearm_due(seconds(11)));
        healthy_for(&mut fallback, 12, 15);
        assert!(!fallback.rearm_due(seconds(15)));
        fallback.note_probe(seconds(16), true);
        assert!(fallback.rearm_due(seconds(16)));
    }

    #[test]
    fn a_failed_probe_or_a_blocked_attempt_starts_the_period_again() {
        let mut fallback = ResolverFallback::armed(RearmDamping::STANDARD);
        fallback.note_bypass(seconds(0));
        healthy_for(&mut fallback, 1, 4);
        fallback.note_probe(seconds(5), false);
        healthy_for(&mut fallback, 6, 10);
        assert!(!fallback.rearm_due(seconds(10)));
        fallback.note_probe(seconds(11), true);
        assert!(fallback.rearm_due(seconds(11)));
        fallback.restart_period();
        assert!(!fallback.rearm_due(seconds(11)));
        healthy_for(&mut fallback, 12, 17);
        assert!(fallback.rearm_due(seconds(17)));
    }

    #[test]
    fn repeated_bypasses_double_the_period_to_the_cap() {
        let mut fallback = ResolverFallback::armed(RearmDamping::STANDARD);
        let mut now = 0;
        let mut periods = Vec::new();
        for _ in 0..8 {
            fallback.note_bypass(seconds(now));
            periods.push(fallback.required().as_secs());
            now += fallback.required().as_secs();
            fallback.note_armed(seconds(now));
            now += 10;
        }
        assert_eq!(periods, [5, 10, 20, 40, 80, 160, 300, 300]);
    }

    #[test]
    fn five_minutes_armed_forgets_earlier_bypasses() {
        let mut fallback = ResolverFallback::armed(RearmDamping::STANDARD);
        fallback.note_bypass(seconds(0));
        fallback.note_armed(seconds(5));
        fallback.note_bypass(seconds(6));
        assert_eq!(fallback.required(), seconds(10));
        fallback.note_armed(seconds(16));
        fallback.note_bypass(seconds(316));
        assert_eq!(fallback.required(), seconds(5));
    }

    #[test]
    fn a_retried_bypass_is_the_same_fault() {
        let mut fallback = ResolverFallback::armed(RearmDamping::STANDARD);
        fallback.note_bypass(seconds(0));
        fallback.note_armed(seconds(5));
        fallback.note_bypass(seconds(6));
        fallback.note_bypass(seconds(7));
        assert_eq!(fallback.required(), seconds(10));
    }

    #[test]
    fn a_restarted_supervisor_owes_the_base_period() {
        let mut fallback = ResolverFallback::resumed_bypassed(RearmDamping::STANDARD);
        assert!(fallback.is_bypassed());
        assert_eq!(fallback.required(), seconds(5));
        healthy_for(&mut fallback, 1, 5);
        assert!(!fallback.rearm_due(seconds(5)));
        fallback.note_probe(seconds(6), true);
        assert!(fallback.rearm_due(seconds(6)));
        fallback.note_armed(seconds(6));
        fallback.note_bypass(seconds(7));
        assert_eq!(fallback.required(), seconds(10));
    }

    #[test]
    fn probes_mean_nothing_while_armed() {
        let mut fallback = ResolverFallback::armed(RearmDamping::STANDARD);
        healthy_for(&mut fallback, 0, 600);
        assert!(!fallback.rearm_due(seconds(600)));
    }

    #[test]
    fn the_verdict_follows_the_set_in_any_order() {
        let first = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 53);
        let second = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            53,
        );
        let other = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 243)), 53);
        assert!(same_upstream_set(&[first, second], &[second, first]));
        assert!(same_upstream_set(&[first, first], &[first]));
        assert!(!same_upstream_set(&[first, second], &[first]));
        assert!(!same_upstream_set(&[first], &[other]));
    }
}
