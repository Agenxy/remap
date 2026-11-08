// SPDX-License-Identifier: GPL-3.0-or-later
//! Ordinary DNS while the daemon or its upstreams do not answer (ADR-0036),
//! and the damped return to Remap DNS (ADR-0030).
//!
//! When the daemon reports that every upstream stopped answering, or does not
//! answer its resolver channel at all, the supervisor restores the link's
//! captured state through the same journaled, compare-first restoration
//! deactivation uses, keeps the activation record with the period the next
//! re-arm owes, and invalidates the daemon's plan. It writes nothing when the
//! link no longer holds exactly Remap's state. While bypassed it only probes
//! the daemon; once the daemon has answered for the damped period, it re-arms
//! from a fresh capture of the link, unless the network still offers the
//! same upstreams the daemon still judges unanswered.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use remap_linux::{
    ActivationPhase, ActivationRecord, LinkIndex, LinuxErrorKind, LinuxResult, RearmDamping,
    ResolverFallback, same_upstream_set,
};
use remap_protocol::{SystemCommand, SystemResult, UpstreamFailure};

use crate::channel::SystemChannel;
use crate::native_transaction::{NativeResolverTransaction, NativeStartupObservation};
use crate::resolver_generation::timestamp_after;
use crate::resolver_stability::{deadline_reached, seeded};
use crate::resolver_upstreams::{state_upstreams, upstreams};
use crate::resolver_worker::{
    BoundedWorker, EffectCall, SettledCall, call_effect_with_shutdown, load as worker_load,
    platform_error, startup_observation as worker_startup_observation,
};
use crate::supervisor::{
    NATIVE_EFFECT_CALL_TIMEOUT, STEADY_STABILITY_INTERVAL, STEADY_STABILITY_TIMEOUT,
    publish_if_needed,
};

/// The record the supervisor owns, the upstreams its plan forwards to, and
/// its memory of recent bypasses in awake time.
#[derive(Debug)]
pub(crate) struct Supervised {
    pub(crate) record: ActivationRecord,
    pub(crate) upstreams: Vec<SocketAddr>,
    fallback: ResolverFallback,
    origin: tokio::time::Instant,
}

impl Supervised {
    pub(crate) fn new(record: ActivationRecord, upstreams: Vec<SocketAddr>) -> Self {
        let fallback = ResolverFallback::resumed(
            RearmDamping::STANDARD,
            record.phase() == ActivationPhase::Bypassed,
            record.rearm_after_healthy(),
        );
        Self {
            record,
            upstreams,
            fallback,
            origin: tokio::time::Instant::now(),
        }
    }

    pub(crate) fn is_bypassed(&self) -> bool {
        self.record.phase() == ActivationPhase::Bypassed
    }

    /// Awake time since the supervisor started: Linux's monotonic clock does
    /// not advance while the host is suspended.
    fn now(&self) -> Duration {
        self.origin.elapsed()
    }
}

/// Why the supervisor restored ordinary DNS.
#[derive(Debug, Clone, Copy)]
pub(crate) enum BypassCause {
    /// The daemon's verdict: every upstream of the active plan stopped
    /// answering.
    Unanswered(UpstreamFailure),
    /// The daemon did not answer its resolver channel.
    DaemonUnreachable,
}

/// Restores ordinary DNS when `latest` carries the daemon's verdict that
/// every upstream of the active plan stopped answering.
pub(crate) async fn bypass_if_unanswered(
    transaction: &BoundedWorker<NativeResolverTransaction>,
    channel: &SystemChannel,
    supervised: &mut Supervised,
    latest: &SystemResult,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> io::Result<()> {
    let Some(failure) = latest.upstream_failure else {
        return Ok(());
    };
    bypass(
        transaction,
        channel,
        supervised,
        BypassCause::Unanswered(failure),
        shutdown,
    )
    .await
    .map(|_bypassed| ())
}

/// Restores ordinary DNS when the daemon stopped answering its channel, then
/// ends the supervisor so systemd restarts it, which starts the daemon again
/// if it stopped: nothing else would once DNS no longer reaches its sockets.
/// The restarted supervisor resumes the bypass and its period from the
/// record. When ordinary DNS could not be restored it returns `unreachable`,
/// as before.
pub(crate) async fn bypass_unreachable(
    transaction: &BoundedWorker<NativeResolverTransaction>,
    channel: &SystemChannel,
    supervised: &mut Supervised,
    unreachable: io::Error,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> io::Result<()> {
    let cause = BypassCause::DaemonUnreachable;
    if !bypass(transaction, channel, supervised, cause, shutdown).await? {
        return Err(unreachable);
    }
    Err(io::Error::other(DAEMON_RESTART))
}

/// The supervisor's exit after a channel bypass, which systemd restarts.
pub(crate) const DAEMON_RESTART: &str = "restarting the resolver supervisor so systemd starts the Remap daemon again; ordinary DNS stays in effect meanwhile";

/// Restores ordinary DNS for `cause`, and reports whether it did. A link that
/// changed outside Remap is left as it is.
async fn bypass(
    transaction: &BoundedWorker<NativeResolverTransaction>,
    channel: &SystemChannel,
    supervised: &mut Supervised,
    cause: BypassCause,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> io::Result<bool> {
    if supervised.record.phase() != ActivationPhase::Active {
        return Ok(false);
    }
    let link = supervised.record.owned().link();
    let Some(observed) = worker_startup_observation(transaction, link, shutdown).await? else {
        return Ok(false);
    };
    let now = supervised.now();
    let period = supervised.fallback.bypass_period(now);
    let settled = native_effect(
        transaction,
        move |transaction| transaction.bypass_observed(&observed, period),
        shutdown,
        "restoring ordinary DNS has an unknown bounded outcome",
    )
    .await?;
    let (stopped, outcome) = settled_parts(settled);
    let record = match outcome {
        Ok(record) => record,
        Err(error) => {
            refused_without_effect(transaction, &supervised.record, error, shutdown).await?;
            eprintln!(
                "{}; ordinary DNS was not restored because the resolver link changed outside Remap, and nothing was written",
                cause_summary(cause)
            );
            return stopped_result(stopped).map(|()| false);
        }
    };
    let identity = (
        record.metadata().activation_id(),
        record.metadata().generation(),
    );
    supervised.record = record;
    supervised.fallback.note_bypass(now);
    invalidate_plan(channel, identity).await;
    eprintln!("{}", bypass_line(cause, supervised.fallback.required()));
    stopped_result(stopped).map(|()| true)
}

/// Restores ordinary DNS at startup for a recovered active record whose
/// daemon does not answer, from a stable observation of the link. A
/// restarted supervisor remembers only the period the record carries, so it
/// counts as just re-armed and owes the doubled period.
pub(crate) fn startup_bypass(
    transaction: &mut NativeResolverTransaction,
    record: &ActivationRecord,
    observed: &NativeStartupObservation,
) -> LinuxResult<ActivationRecord> {
    let period =
        ResolverFallback::resumed(RearmDamping::STANDARD, false, record.rearm_after_healthy())
            .bypass_period(Duration::ZERO);
    let bypassed = transaction.bypass_observed(observed, period)?;
    eprintln!("{}", bypass_line(BypassCause::DaemonUnreachable, period));
    Ok(bypassed)
}

/// The journal line for a bypass: the cause and the period the next re-arm
/// owes, never an address.
pub(crate) fn bypass_line(cause: BypassCause, period: Duration) -> String {
    let returns = match cause {
        BypassCause::Unanswered(_) => "once they answer or the network offers other resolvers",
        BypassCause::DaemonUnreachable => "once the daemon answers again",
    };
    format!(
        "{}; ordinary DNS restored; Remap DNS returns after {} of continuous daemon health {returns}",
        cause_summary(cause),
        seconds_phrase(period),
    )
}

fn cause_summary(cause: BypassCause) -> String {
    match cause {
        BypassCause::Unanswered(failure) => unanswered_summary(failure),
        BypassCause::DaemonUnreachable => {
            "the Remap daemon is not answering its resolver channel".to_owned()
        }
    }
}

/// One reconciliation while ordinary DNS is in effect: probe the daemon and,
/// once the damped period has passed, re-arm.
pub(crate) async fn reconcile_bypassed(
    transaction: &BoundedWorker<NativeResolverTransaction>,
    channel: &SystemChannel,
    supervised: &mut Supervised,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> io::Result<()> {
    let health = channel.exchange(SystemCommand::ResolverHealth).await;
    let now = supervised.now();
    supervised.fallback.note_probe(now, health.is_ok());
    let Ok(health) = health else {
        return Ok(());
    };
    // A daemon that hung through the bypass may still hold the plan; while
    // bypassed it is expected to hold none.
    let identity = (
        supervised.record.metadata().activation_id(),
        supervised.record.metadata().generation(),
    );
    if health.activation_id == Some(identity.0) {
        invalidate_plan(channel, identity).await;
    }
    if !supervised.fallback.rearm_due(now) {
        return Ok(());
    }
    let link = supervised.record.owned().link();
    let Some(observed) = steady_observation(transaction, link, shutdown).await? else {
        return Ok(());
    };
    if !rearm_permitted(&health, observed.resolved_state(), &supervised.upstreams) {
        supervised.fallback.restart_period();
        return Ok(());
    }
    let (generation, created) = timestamp_after(Some(supervised.record.metadata().generation()))?;
    let settled = native_effect(
        transaction,
        move |transaction| transaction.rearm_observed(generation, created, &observed),
        shutdown,
        "re-arming Remap DNS has an unknown bounded outcome",
    )
    .await?;
    let (stopped, outcome) = settled_parts(settled);
    let record = match outcome {
        Ok(record) => record,
        Err(error) => {
            refused_without_effect(transaction, &supervised.record, error, shutdown).await?;
            supervised.fallback.restart_period();
            return stopped_result(stopped);
        }
    };
    supervised.upstreams = upstreams(&record)?;
    supervised.record = record;
    let published =
        publish_if_needed(channel, &supervised.record, supervised.upstreams.clone()).await;
    supervised.fallback.note_armed(supervised.now());
    match published {
        Ok(_latest) => {}
        // The link is on loopback again; a daemon gone since the probe must
        // not leave it there.
        Err(failure) if failure.unreachable && !stopped => {
            return bypass_unreachable(transaction, channel, supervised, failure.error, shutdown)
                .await;
        }
        Err(failure) => return Err(failure.error),
    }
    eprintln!("Remap DNS re-armed after sustained daemon health");
    stopped_result(stopped)
}

/// Whether re-arming would forward to upstreams other than the set the
/// daemon still judges unanswered. The verdict belongs to that set, so any
/// other set the network offers starts clean (ADR-0036).
fn rearm_permitted(
    health: &SystemResult,
    offered: &remap_linux::LinkState,
    unanswered: &[SocketAddr],
) -> bool {
    let Ok(offered) = state_upstreams(offered) else {
        return false;
    };
    health.upstream_failure.is_none() || !same_upstream_set(&offered, unanswered)
}

async fn steady_observation(
    transaction: &BoundedWorker<NativeResolverTransaction>,
    link: LinkIndex,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> io::Result<Option<NativeStartupObservation>> {
    let Some(initial) = worker_startup_observation(transaction, link, shutdown).await? else {
        return Ok(None);
    };
    let deadline = tokio::time::Instant::now() + STEADY_STABILITY_TIMEOUT;
    let mut stability = seeded(initial);
    loop {
        if deadline_reached(tokio::time::Instant::now(), deadline) {
            return Ok(None);
        }
        tokio::time::sleep(STEADY_STABILITY_INTERVAL).await;
        let observed = worker_startup_observation(transaction, link, shutdown).await?;
        if deadline_reached(tokio::time::Instant::now(), deadline) {
            return Ok(None);
        }
        match observed {
            Some(observed) if stability.observe(observed.clone()) => return Ok(Some(observed)),
            Some(_observed) => {}
            None => stability.reset(),
        }
    }
}

async fn native_effect<R, F>(
    transaction: &BoundedWorker<NativeResolverTransaction>,
    operation: F,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
    unknown_outcome: &'static str,
) -> io::Result<SettledCall<LinuxResult<R>>>
where
    R: Send + 'static,
    F: FnOnce(&mut NativeResolverTransaction) -> LinuxResult<R> + Send + 'static,
{
    let dispatched = transaction.dispatch_effect(operation, shutdown).await?;
    match call_effect_with_shutdown(dispatched.settle(), NATIVE_EFFECT_CALL_TIMEOUT, shutdown)
        .await?
    {
        EffectCall::Completed(outcome) => Ok(SettledCall::Completed(outcome)),
        EffectCall::Stopped(outcome) => Ok(SettledCall::Stopped(outcome)),
        EffectCall::TimedOut => Err(io::Error::new(io::ErrorKind::TimedOut, unknown_outcome)),
    }
}

fn settled_parts<T>(settled: SettledCall<T>) -> (bool, T) {
    match settled {
        SettledCall::Completed(outcome) => (false, outcome),
        SettledCall::Stopped(outcome) => (true, outcome),
    }
}

/// Accepts a native refusal only when the durable record proves it had no
/// effect: a changed or settling link refuses before the first write. Any
/// other outcome is surfaced so the restarted supervisor recovers from the
/// journal.
async fn refused_without_effect(
    transaction: &BoundedWorker<NativeResolverTransaction>,
    expected: &ActivationRecord,
    error: remap_linux::LinuxError,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> io::Result<()> {
    if !refusal_kind(error.kind()) {
        return Err(platform_error(error));
    }
    match worker_load(transaction, shutdown).await? {
        Some(Some(loaded)) if loaded == *expected => Ok(()),
        Some(_) | None => Err(platform_error(error)),
    }
}

const fn refusal_kind(kind: LinuxErrorKind) -> bool {
    matches!(
        kind,
        LinuxErrorKind::OwnershipConflict
            | LinuxErrorKind::UnstableObservation
            | LinuxErrorKind::ResolverUnavailable
    )
}

async fn invalidate_plan(channel: &SystemChannel, (activation_id, generation): (uuid::Uuid, u64)) {
    let invalidated = channel
        .exchange(SystemCommand::InvalidateResolverPlan {
            activation_id,
            generation,
        })
        .await;
    if invalidated.is_err() {
        // The link no longer points at the daemon, so a plan it keeps serves
        // no lookup; the re-armed generation supersedes it.
        eprintln!(
            "the daemon resolver plan could not be invalidated after ordinary DNS was restored"
        );
    }
}

fn stopped_result(stopped: bool) -> io::Result<()> {
    if stopped {
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "resolver supervision was stopped after a settled fallback effect",
        ))
    } else {
        Ok(())
    }
}

/// The journal line for the verdict: a cause, a count, and a span, never an
/// address.
fn unanswered_summary(failure: UpstreamFailure) -> String {
    let span = Duration::from_millis(failure.unanswered_for_ms.saturating_add(500));
    format!(
        "upstream DNS not answering: every upstream resolver {} for the last {} queries over {}",
        failure.cause.describe(),
        failure.unanswered_queries,
        seconds_phrase(span),
    )
}

fn seconds_phrase(duration: Duration) -> String {
    match duration.as_secs() {
        1 => "1 second".to_owned(),
        seconds => format!("{seconds} seconds"),
    }
}

#[cfg(test)]
#[path = "resolver_fallback_tests.rs"]
mod tests;
