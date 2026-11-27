// SPDX-License-Identifier: GPL-3.0-or-later
//! Background work: effect tasks, the revision watcher, and the debounce
//! that keeps validation from running on every keystroke.

use std::sync::Arc;
use std::time::Duration;

use remap_protocol::{Command, CommandResult, Diagnostic, MAX_REVISION_WAIT_MS};
use tokio::sync::mpsc::Sender;
use tokio::time::Instant;

use crate::authority::{self, Authority};
use crate::update::{Effect, Event, Watch};

/// How long typing must pause before the form is validated.
pub(crate) const VALIDATION_DEBOUNCE: Duration = Duration::from_millis(200);

/// Runs one effect on its own task and sends its outcome back.
pub(crate) fn spawn_effect<A: Authority>(authority: Arc<A>, effect: Effect, events: Sender<Event>) {
    tokio::spawn(async move {
        let outcome = authority::execute(&*authority, effect).await;
        // The loop has stopped when the receiver is gone; nothing to report.
        let _closed = events.send(Event::Outcome(Box::new(outcome))).await;
    });
}

/// Doubling retry delay for an unreachable daemon.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct Backoff {
    first: Duration,
    next: Duration,
    most: Duration,
}

impl Backoff {
    pub(crate) const fn new(first: Duration, most: Duration) -> Self {
        Self {
            first,
            next: first,
            most,
        }
    }

    pub(crate) const fn standard() -> Self {
        Self::new(Duration::from_millis(250), Duration::from_secs(5))
    }

    pub(crate) fn delay(&mut self) -> Duration {
        let delay = self.next;
        self.next = (self.next * 2).min(self.most);
        delay
    }

    pub(crate) const fn reset(&mut self) {
        self.next = self.first;
    }
}

/// Long-polls the daemon for revisions and reports each change, and each
/// failure, until the receiver goes away. It never gives up on the daemon.
pub(crate) async fn watch<A: Authority>(
    authority: Arc<A>,
    events: Sender<Event>,
    mut backoff: Backoff,
) {
    let mut after = 0;
    let mut healthy = false;
    loop {
        let command = Command::WaitForRevision {
            after,
            timeout_ms: MAX_REVISION_WAIT_MS,
        };
        let watch = match authority.execute(command).await {
            Ok(CommandResult::Revision(notice)) => {
                let report = !healthy || notice.revision != after;
                after = notice.revision;
                healthy = true;
                backoff.reset();
                report.then_some(Watch::Revision(notice.revision))
            }
            Ok(_) => Some(Watch::Unreachable(Diagnostic::protocol(
                "the daemon answered a revision wait with a different kind of result",
            ))),
            Err(diagnostic) => Some(Watch::Unreachable(diagnostic)),
        };
        let failed = matches!(watch, Some(Watch::Unreachable(_)));
        if let Some(watch) = watch
            && events.send(Event::Watch(watch)).await.is_err()
        {
            return;
        }
        if failed {
            healthy = false;
            tokio::time::sleep(backoff.delay()).await;
        }
    }
}

/// Holds the latest validation until typing pauses.
#[derive(Debug, Default)]
pub(crate) struct Debouncer {
    pending: Option<(Instant, Effect)>,
}

impl Debouncer {
    /// Replaces any held effect and restarts the wait.
    pub(crate) fn hold(&mut self, effect: Effect, delay: Duration) {
        self.pending = Some((Instant::now() + delay, effect));
    }

    /// Resolves with the held effect once its wait is over. Cancel-safe: the
    /// effect is taken only after the wait completes.
    pub(crate) async fn ready(&mut self) -> Effect {
        loop {
            match &self.pending {
                Some((deadline, _)) => tokio::time::sleep_until(*deadline).await,
                None => std::future::pending::<()>().await,
            }
            if let Some((_, effect)) = self.pending.take() {
                return effect;
            }
        }
    }
}
