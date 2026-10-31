// SPDX-License-Identifier: GPL-3.0-or-later
//! Whether the active plan's upstream resolvers still answer (ADR-0036).
//!
//! Every forwarded exchange ends answered or unanswered. An exchange is
//! answered when any upstream returned a related response other than
//! REFUSED, including a truncated one. It is unanswered when every upstream
//! timed out, refused, or could not be reached. Lost packets, one slow
//! upstream, and one burst of parallel queries never trip the verdict: it
//! needs a minimum number of unanswered exchanges with no answer between
//! them, spread over a minimum span, inside a bounded evidence window.
//!
//! The verdict belongs to an upstream set, not a generation. Republishing
//! the same set, as a supervisor does when it re-arms, keeps it; a different
//! set starts from nothing. Only an answered exchange clears it, which the
//! runtime's bounded probe provides while no client traffic arrives.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::time::Instant;

use crate::NetworkError;

/// Thresholds for deciding that every upstream has stopped answering.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct UpstreamLivenessPolicy {
    /// Unanswered exchanges, with no answer between them, before the verdict trips.
    pub min_unanswered: u32,
    /// Minimum time between the first and the last of those exchanges.
    pub min_span: Duration,
    /// Unanswered evidence older than this, before the verdict trips, is discarded.
    pub evidence_window: Duration,
    /// Interval between bounded probes while the verdict holds.
    pub probe_interval: Duration,
}

impl Default for UpstreamLivenessPolicy {
    fn default() -> Self {
        Self {
            min_unanswered: 4,
            min_span: Duration::from_secs(2),
            evidence_window: Duration::from_secs(30),
            probe_interval: Duration::from_secs(5),
        }
    }
}

impl UpstreamLivenessPolicy {
    pub(crate) fn validate(&self) -> Result<(), NetworkError> {
        let bounded = |value: Duration| !value.is_zero() && value <= Duration::from_secs(600);
        if !(1..=1_024).contains(&self.min_unanswered)
            || self.min_span > Duration::from_secs(600)
            || !bounded(self.evidence_window)
            || !bounded(self.probe_interval)
            || self.min_span > self.evidence_window
        {
            return Err(NetworkError::Configuration(
                "upstream liveness thresholds are outside their supported bounds",
            ));
        }
        Ok(())
    }
}

/// Why the last unanswered exchanges went unanswered.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum UpstreamFailureCause {
    /// No upstream replied before the I/O deadline.
    TimedOut,
    /// Upstreams refused the query or the connection.
    Refused,
    /// The network reported the upstreams unreachable.
    Unreachable,
}

/// The verdict that every upstream of the active set has stopped answering.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct UpstreamsUnanswered {
    /// The most frequent cause among the unanswered exchanges.
    pub cause: UpstreamFailureCause,
    /// Unanswered exchanges since the last answer.
    pub unanswered_queries: u32,
    /// Time since the first of those exchanges completed.
    pub unanswered_for: Duration,
}

/// How one complete forwarded exchange ended.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum ExchangeOutcome {
    Answered,
    Unanswered(UpstreamFailureCause),
}

/// Shared, bounded liveness evidence for the plan store's upstream set.
#[derive(Debug, Clone)]
pub(crate) struct UpstreamLiveness {
    policy: UpstreamLivenessPolicy,
    state: Arc<Mutex<LivenessState>>,
}

#[derive(Debug, Default)]
struct LivenessState {
    upstreams: Vec<SocketAddr>,
    streak: Option<Streak>,
    tripped: bool,
}

#[derive(Debug, Clone, Copy)]
struct Streak {
    first: Instant,
    last: Instant,
    count: u32,
    causes: [u32; 3],
}

impl UpstreamLiveness {
    pub(crate) fn new(policy: UpstreamLivenessPolicy) -> Self {
        Self {
            policy,
            state: Arc::new(Mutex::new(LivenessState::default())),
        }
    }

    pub(crate) const fn policy(&self) -> UpstreamLivenessPolicy {
        self.policy
    }

    /// Adopts a newly published upstream set. The same set keeps its
    /// evidence and verdict; any other set starts without either.
    pub(crate) fn observe_plan(&self, upstreams: &[SocketAddr]) {
        let key = upstream_key(upstreams);
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if state.upstreams != key {
            *state = LivenessState {
                upstreams: key,
                streak: None,
                tripped: false,
            };
        }
    }

    /// Records one complete exchange made through `upstreams`. Evidence
    /// from a set that is no longer current is ignored.
    pub(crate) fn record(&self, upstreams: &[SocketAddr], outcome: ExchangeOutcome, now: Instant) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if state.upstreams != upstream_key(upstreams) {
            return;
        }
        let cause = match outcome {
            ExchangeOutcome::Answered => {
                state.streak = None;
                state.tripped = false;
                return;
            }
            ExchangeOutcome::Unanswered(cause) => cause,
        };
        let expired = state.streak.is_some_and(|streak| {
            !state.tripped
                && now.saturating_duration_since(streak.last) > self.policy.evidence_window
        });
        let mut streak = match state.streak {
            Some(streak) if !expired => streak,
            _ => Streak {
                first: now,
                last: now,
                count: 0,
                causes: [0; 3],
            },
        };
        streak.last = now;
        streak.count = streak.count.saturating_add(1);
        let slot = &mut streak.causes[cause_index(cause)];
        *slot = slot.saturating_add(1);
        state.streak = Some(streak);
        if streak.count >= self.policy.min_unanswered
            && streak.last.saturating_duration_since(streak.first) >= self.policy.min_span
        {
            state.tripped = true;
        }
    }

    /// The verdict, present only while every upstream has stopped answering.
    pub(crate) fn verdict(&self, now: Instant) -> Option<UpstreamsUnanswered> {
        let state = self.state.lock().ok()?;
        if !state.tripped {
            return None;
        }
        let streak = state.streak?;
        Some(UpstreamsUnanswered {
            cause: dominant_cause(streak.causes),
            unanswered_queries: streak.count,
            unanswered_for: now.saturating_duration_since(streak.first),
        })
    }

    pub(crate) fn tripped(&self) -> bool {
        self.state.lock().is_ok_and(|state| state.tripped)
    }
}

fn upstream_key(upstreams: &[SocketAddr]) -> Vec<SocketAddr> {
    let mut key = upstreams.to_vec();
    key.sort_unstable();
    key.dedup();
    key
}

const fn cause_index(cause: UpstreamFailureCause) -> usize {
    match cause {
        UpstreamFailureCause::TimedOut => 0,
        UpstreamFailureCause::Refused => 1,
        UpstreamFailureCause::Unreachable => 2,
    }
}

/// Ties favour a timeout, the cause a filtering firewall produces.
fn dominant_cause(causes: [u32; 3]) -> UpstreamFailureCause {
    let [timed_out, refused, unreachable] = causes;
    if timed_out >= refused && timed_out >= unreachable {
        UpstreamFailureCause::TimedOut
    } else if refused >= unreachable {
        UpstreamFailureCause::Refused
    } else {
        UpstreamFailureCause::Unreachable
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use tokio::time::Instant;

    use super::{ExchangeOutcome, UpstreamFailureCause, UpstreamLiveness, UpstreamLivenessPolicy};

    fn endpoint(octet: u8) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::new(192, 0, 2, octet), 53))
    }

    const TIMED_OUT: ExchangeOutcome = ExchangeOutcome::Unanswered(UpstreamFailureCause::TimedOut);

    fn liveness(upstreams: &[SocketAddr]) -> UpstreamLiveness {
        let liveness = UpstreamLiveness::new(UpstreamLivenessPolicy::default());
        liveness.observe_plan(upstreams);
        liveness
    }

    #[test]
    fn one_lost_packet_and_one_burst_never_trip() {
        let set = [endpoint(1)];
        let liveness = liveness(&set);
        let start = Instant::now();
        liveness.record(&set, TIMED_OUT, start);
        liveness.record(&set, ExchangeOutcome::Answered, start);
        assert_eq!(liveness.verdict(start), None);
        // Eight parallel queries lost together in the same instant.
        for _ in 0..8 {
            liveness.record(&set, TIMED_OUT, start + Duration::from_secs(5));
        }
        assert_eq!(liveness.verdict(start + Duration::from_secs(5)), None);
    }

    #[test]
    fn sustained_silence_trips_and_one_answer_clears() {
        let set = [endpoint(1), endpoint(2)];
        let liveness = liveness(&set);
        let start = Instant::now();
        for second in 0..4 {
            liveness.record(&set, TIMED_OUT, start + Duration::from_secs(second));
        }
        let verdict = liveness.verdict(start + Duration::from_secs(9));
        assert_eq!(
            verdict.map(|verdict| (verdict.cause, verdict.unanswered_queries)),
            Some((UpstreamFailureCause::TimedOut, 4))
        );
        assert_eq!(
            verdict.map(|verdict| verdict.unanswered_for),
            Some(Duration::from_secs(9))
        );
        liveness.record(
            &set,
            ExchangeOutcome::Answered,
            start + Duration::from_secs(10),
        );
        assert_eq!(liveness.verdict(start + Duration::from_secs(10)), None);
    }

    #[test]
    fn evidence_outside_the_window_is_discarded() {
        let set = [endpoint(1)];
        let liveness = liveness(&set);
        let start = Instant::now();
        for second in [0, 1, 2] {
            liveness.record(&set, TIMED_OUT, start + Duration::from_secs(second));
        }
        liveness.record(&set, TIMED_OUT, start + Duration::from_secs(60));
        assert_eq!(liveness.verdict(start + Duration::from_secs(60)), None);
    }

    #[test]
    fn the_verdict_follows_the_upstream_set_not_the_generation() {
        let dead = [endpoint(2), endpoint(1)];
        let liveness = liveness(&dead);
        let start = Instant::now();
        for second in 0..4 {
            liveness.record(&dead, TIMED_OUT, start + Duration::from_secs(second));
        }
        // The same set in another order, as a re-arm republishes it.
        liveness.observe_plan(&[endpoint(1), endpoint(2)]);
        assert!(liveness.tripped());
        // A different set, such as a VPN's resolver, starts clean, and late
        // results from the old set no longer count.
        liveness.observe_plan(&[endpoint(3)]);
        assert!(!liveness.tripped());
        for second in 4..9 {
            liveness.record(&dead, TIMED_OUT, start + Duration::from_secs(second));
        }
        assert!(!liveness.tripped());
    }

    #[test]
    fn the_dominant_cause_is_reported() {
        let set = [endpoint(1)];
        let liveness = liveness(&set);
        let start = Instant::now();
        let refused = ExchangeOutcome::Unanswered(UpstreamFailureCause::Refused);
        for second in 0..3 {
            liveness.record(&set, refused, start + Duration::from_secs(second));
        }
        liveness.record(&set, TIMED_OUT, start + Duration::from_secs(3));
        assert_eq!(
            liveness
                .verdict(start + Duration::from_secs(3))
                .map(|verdict| verdict.cause),
            Some(UpstreamFailureCause::Refused)
        );
    }

    #[test]
    fn unsupported_thresholds_are_rejected() {
        let mut policy = UpstreamLivenessPolicy::default();
        assert!(policy.validate().is_ok());
        policy.min_unanswered = 0;
        assert!(policy.validate().is_err());
        policy = UpstreamLivenessPolicy {
            min_span: Duration::from_secs(60),
            ..UpstreamLivenessPolicy::default()
        };
        assert!(policy.validate().is_err());
    }
}
