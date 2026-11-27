// SPDX-License-Identifier: GPL-3.0-or-later
//! The executor, the revision watcher, the debounce, and the terminal checks.

use std::ffi::OsString;
use std::sync::Arc;
use std::time::Duration;

use remap_protocol::{
    Command, CommandResult, Diagnostic, ListResult, MAX_MAPPING_PAGE_SIZE, MAX_REVISION_WAIT_MS,
    RevisionNotice,
};

use super::support::{Scripted, TestResult, mapping, status};
use crate::authority::{REGISTRY_BUSY, execute};
use crate::update::{Effect, Event, Outcome, Watch};
use crate::worker::{Backoff, Debouncer, watch};

fn page(revision: u64, patterns: &[&str], next: Option<&str>) -> CommandResult {
    CommandResult::List(ListResult {
        revision,
        mappings: patterns
            .iter()
            .map(|pattern| mapping(pattern, "127.0.0.1", true))
            .collect(),
        next_cursor: next.map(ToOwned::to_owned),
    })
}

fn status_answer(revision: u64) -> CommandResult {
    CommandResult::Status(status(revision, &[]))
}

#[tokio::test]
async fn a_refresh_reads_every_page_including_disabled_mappings() -> TestResult {
    let authority = Scripted::answering(vec![
        status_answer(7),
        page(7, &["a.test", "b.test"], Some("b.test")),
        page(7, &["c.test"], None),
    ]);
    let Outcome::Refreshed(Ok(snapshot)) = execute(&authority, Effect::Refresh).await else {
        return Err("the refresh succeeds".into());
    };
    let patterns: Vec<_> = snapshot
        .mappings
        .iter()
        .map(|m| m.pattern.as_str())
        .collect();
    assert_eq!(patterns, ["a.test", "b.test", "c.test"]);
    assert_eq!(snapshot.status.revision, 7);
    assert_eq!(
        authority.commands(),
        vec![
            Command::Status,
            Command::List {
                after: None,
                limit: MAX_MAPPING_PAGE_SIZE,
                include_disabled: true
            },
            Command::List {
                after: Some("b.test".to_owned()),
                limit: MAX_MAPPING_PAGE_SIZE,
                include_disabled: true
            },
        ]
    );
    Ok(())
}

#[tokio::test]
async fn a_refresh_rereads_when_the_registry_moves_mid_read() -> TestResult {
    let authority = Scripted::answering(vec![
        status_answer(7),
        page(7, &["a.test"], Some("a.test")),
        page(8, &["b.test"], None),
        status_answer(8),
        page(8, &["a.test", "b.test"], None),
    ]);
    let Outcome::Refreshed(Ok(snapshot)) = execute(&authority, Effect::Refresh).await else {
        return Err("the second read succeeds".into());
    };
    assert_eq!(snapshot.status.revision, 8);
    assert_eq!(snapshot.mappings.len(), 2);
    Ok(())
}

#[tokio::test]
async fn a_registry_that_never_settles_is_reported_not_spun_on() -> TestResult {
    let mut answers = Vec::new();
    for revision in 1..=3 {
        answers.push(status_answer(revision));
        answers.push(page(revision, &["a.test"], Some("a.test")));
        answers.push(page(revision + 10, &["b.test"], None));
    }
    let authority = Scripted::answering(answers);
    let Outcome::Refreshed(Err(diagnostic)) = execute(&authority, Effect::Refresh).await else {
        return Err("the refresh gives up".into());
    };
    assert_eq!(diagnostic.code, REGISTRY_BUSY);
    assert!(diagnostic.retryable);
    Ok(())
}

#[tokio::test]
async fn a_list_that_does_not_advance_is_a_protocol_error() -> TestResult {
    let authority = Scripted::answering(vec![status_answer(1), page(1, &[], Some("a.test"))]);
    let Outcome::Refreshed(Err(diagnostic)) = execute(&authority, Effect::Refresh).await else {
        return Err("the refresh fails".into());
    };
    assert_eq!(diagnostic.code, "E_CONTROL_PROTOCOL");
    Ok(())
}

#[tokio::test]
async fn unexpected_results_and_failures_become_outcomes() -> TestResult {
    let authority = Scripted::answering(vec![status_answer(1)]);
    let outcome = execute(
        &authority,
        Effect::Preview {
            seq: 1,
            changes: Vec::new(),
        },
    )
    .await;
    assert!(
        matches!(&outcome, Outcome::Previewed { seq: 1, result: Err(d) } if d.code == "E_CONTROL_PROTOCOL"),
        "{outcome:?}"
    );
    let outcome = execute(
        &authority,
        Effect::Apply {
            expected_revision: 1,
            operation_id: "op".to_owned(),
            changes: Vec::new(),
        },
    )
    .await;
    assert!(
        matches!(&outcome, Outcome::Applied { operation_id, result: Err(d) } if operation_id == "op" && d.code == "E_DAEMON_UNAVAILABLE"),
        "{outcome:?}"
    );
    Ok(())
}

#[tokio::test]
async fn the_watcher_reports_outages_and_revisions_with_backoff() -> TestResult {
    let notice = |revision, changed| {
        Ok(CommandResult::Revision(RevisionNotice {
            revision,
            changed,
        }))
    };
    let authority = Arc::new(Scripted::new(vec![
        Err(Diagnostic::daemon_unavailable()),
        notice(3, true),
        notice(3, false),
        notice(4, true),
    ]));
    let (sender, mut receiver) = tokio::sync::mpsc::channel(8);
    let backoff = Backoff::new(Duration::from_millis(1), Duration::from_millis(4));
    let task = tokio::spawn(watch(Arc::clone(&authority), sender, backoff));
    let mut seen = Vec::new();
    for _ in 0..3 {
        let event = tokio::time::timeout(Duration::from_secs(5), receiver.recv()).await?;
        match event {
            Some(Event::Watch(Watch::Revision(revision))) => seen.push(Some(revision)),
            Some(Event::Watch(Watch::Unreachable(_))) => seen.push(None),
            other => return Err(format!("unexpected {other:?}").into()),
        }
    }
    assert_eq!(
        seen,
        [None, Some(3), Some(4)],
        "an unchanged revision is not reported"
    );
    drop(receiver);
    tokio::time::timeout(Duration::from_secs(5), task).await??;
    let waits: Vec<_> = authority
        .commands()
        .into_iter()
        .take(4)
        .map(|command| match command {
            Command::WaitForRevision { after, timeout_ms } => Some((after, timeout_ms)),
            _ => None,
        })
        .collect();
    let wait = MAX_REVISION_WAIT_MS;
    assert_eq!(
        waits,
        [
            Some((0, wait)),
            Some((0, wait)),
            Some((3, wait)),
            Some((3, wait))
        ]
    );
    Ok(())
}

#[test]
fn backoff_doubles_to_a_ceiling_and_resets() {
    let mut backoff = Backoff::standard();
    let delays: Vec<_> = (0..7).map(|_| backoff.delay().as_millis()).collect();
    assert_eq!(delays, [250, 500, 1_000, 2_000, 4_000, 5_000, 5_000]);
    backoff.reset();
    assert_eq!(backoff.delay(), Duration::from_millis(250));
}

#[tokio::test]
async fn the_debounce_keeps_only_the_latest_validation() -> TestResult {
    let validate = |seq| Effect::Validate {
        seq,
        pattern: "a.test".to_owned(),
        target: "127.0.0.1".to_owned(),
        host_policy: remap_protocol::HostPolicy::PreserveClient,
        landing: None,
    };
    let mut debounce = Debouncer::default();
    debounce.hold(validate(1), Duration::from_millis(5));
    debounce.hold(validate(2), Duration::from_millis(5));
    let ready = tokio::time::timeout(Duration::from_secs(5), debounce.ready()).await?;
    assert_eq!(ready, validate(2));
    let idle = tokio::time::timeout(Duration::from_millis(20), debounce.ready()).await;
    assert!(idle.is_err(), "nothing else is pending");
    Ok(())
}

#[test]
fn the_console_refuses_without_a_terminal() -> TestResult {
    assert!(crate::require_terminals(true, true).is_ok());
    for (stdin, stdout, missing) in [
        (false, true, "standard input"),
        (true, false, "standard output"),
        (false, false, "standard input and output"),
    ] {
        let Err(diagnostic) = crate::require_terminals(stdin, stdout) else {
            return Err(format!("{missing} is not a terminal, yet the console started").into());
        };
        assert_eq!(diagnostic.code, crate::NEEDS_TERMINAL);
        assert_eq!(diagnostic.code, "console-needs-terminal");
        assert!(!diagnostic.retryable);
        let hint = diagnostic.hint.unwrap_or_default();
        assert!(
            hint.contains("remap list") && hint.contains("remap status"),
            "{hint}"
        );
        assert_eq!(
            diagnostic.context.get("not_a_terminal").map(String::as_str),
            Some(missing)
        );
    }
    Ok(())
}

#[tokio::test]
async fn run_refuses_when_the_streams_are_not_both_terminals() {
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
        return;
    }
    let client = remap_protocol::ControlClient::new(
        "/nonexistent/remap.sock",
        remap_protocol::Surface::Cli,
        "test",
    );
    let refusal = crate::run(client).await.err().map(|d| d.code);
    assert_eq!(refusal.as_deref(), Some("console-needs-terminal"));
}

#[test]
fn no_color_turns_colour_off_unless_empty() {
    use crate::terminal::color_enabled;
    assert!(color_enabled(None));
    assert!(color_enabled(Some(OsString::new())));
    assert!(!color_enabled(Some(OsString::from("1"))));
}

#[test]
fn text_wraps_by_words_and_keeps_short_lines_exact() {
    use crate::text::{sentence, truncate, wrap};
    assert_eq!(wrap("  a  b", 10), ["  a  b"]);
    assert_eq!(wrap("one two three four", 9), ["one two", "three", "four"]);
    assert_eq!(
        wrap("  before: abcdefghij", 10),
        ["  before:", "  abcdefgh", "  ij"]
    );
    assert_eq!(truncate("abcdef", 4), "abc…");
    assert_eq!(sentence("run it"), "Run it.");
    assert_eq!(sentence("done!"), "Done!");
}
