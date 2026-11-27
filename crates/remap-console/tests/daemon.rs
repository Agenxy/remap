// SPDX-License-Identifier: GPL-3.0-or-later
//! The console's model and executor against a real `remapd`, without a
//! terminal: every write is previewed, confirmed and revision-checked
//! (ADR-0041).

use std::collections::VecDeque;
use std::error::Error;
use std::io;
use std::path::Path;
use std::time::Duration;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use remap_console::authority::execute;
use remap_console::model::Model;
use remap_console::update::{Effect, Event, start, update};
use remap_protocol::{Change, Command, CommandResult, ControlClient, ControlPaths, Surface};
use remapd::DaemonConfig;

type TestResult = Result<(), Box<dyn Error>>;

/// More effects than one owner action can cause; a loop would exceed it.
const MAX_EFFECTS_PER_ACTION: usize = 64;

async fn wait_for_socket(path: &Path) -> TestResult {
    for _attempt in 0..200 {
        if path.exists() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err(io::Error::other("daemon socket did not appear").into())
}

/// Runs effects, and every effect their outcomes cause, to completion.
async fn settle(client: &ControlClient, model: &mut Model, effects: Vec<Effect>) -> TestResult {
    let mut queue = VecDeque::from(effects);
    let mut ran = 0;
    while let Some(effect) = queue.pop_front() {
        ran += 1;
        if ran > MAX_EFFECTS_PER_ACTION {
            return Err(io::Error::other("effects did not settle").into());
        }
        let outcome = execute(client, effect).await;
        queue.extend(update(model, Event::Outcome(Box::new(outcome))));
    }
    Ok(())
}

fn key(code: KeyCode) -> Event {
    Event::Key(KeyEvent::new(code, KeyModifiers::NONE))
}

/// Presses keys in order, then settles everything they asked for.
async fn keys(client: &ControlClient, model: &mut Model, codes: &[KeyCode]) -> TestResult {
    let mut effects = Vec::new();
    for code in codes {
        effects.extend(update(model, key(*code)));
    }
    settle(client, model, effects).await
}

async fn type_text(client: &ControlClient, model: &mut Model, text: &str) -> TestResult {
    let codes: Vec<KeyCode> = text.chars().map(KeyCode::Char).collect();
    keys(client, model, &codes).await
}

/// Opens the form and fills pattern and target, leaving it open.
async fn fill_form(
    client: &ControlClient,
    model: &mut Model,
    pattern: &str,
    target: &str,
) -> TestResult {
    keys(client, model, &[KeyCode::Char('n')]).await?;
    type_text(client, model, pattern).await?;
    keys(client, model, &[KeyCode::Tab]).await?;
    type_text(client, model, target).await
}

fn enabled(model: &Model, pattern: &str) -> Option<bool> {
    model
        .mappings()
        .iter()
        .find(|mapping| mapping.pattern == pattern)
        .map(|mapping| mapping.enabled)
}

/// Another client sets other.test, moving the registry past `revision`.
async fn write_elsewhere(client: &ControlClient, revision: u64) -> TestResult {
    let elsewhere = client
        .execute(Command::Apply {
            expected_revision: revision,
            operation_id: uuid::Uuid::new_v4().to_string(),
            changes: vec![Change::Set {
                pattern: "other.test".to_owned(),
                target: "127.0.0.3".to_owned(),
                host_policy: remap_protocol::HostPolicy::PreserveClient,
                enabled: None,
                landing: None,
            }],
        })
        .await?;
    assert!(matches!(elsewhere, CommandResult::Apply(receipt) if receipt.revision == revision + 1));
    Ok(())
}

#[tokio::test]
async fn the_console_sets_lists_disables_removes_and_surfaces_conflicts() -> TestResult {
    let directory = tempfile::tempdir()?;
    let paths = ControlPaths::under(directory.path().join("data"));
    let mut config = DaemonConfig::new(paths.clone());
    config.dns_turned_off_record = None;
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let daemon = tokio::spawn(remapd::serve_until(config, async {
        let _done = stopped.await;
    }));
    wait_for_socket(paths.socket()).await?;
    let client = ControlClient::new(paths.socket(), Surface::Cli, env!("CARGO_PKG_VERSION"));

    let mut model = Model::new(false);
    let effects = start(&mut model);
    settle(&client, &mut model, effects).await?;
    assert!(model.is_live());
    assert_eq!(model.revision(), Some(0));

    // Set: the form previews; nothing is written until the owner confirms.
    fill_form(&client, &mut model, "api.test", "127.0.0.1").await?;
    keys(&client, &mut model, &[KeyCode::Enter]).await?;
    let preview = model.awaiting_confirmation().cloned();
    assert_eq!(preview.as_ref().map(|p| p.base_revision), Some(0));
    assert_eq!(preview.as_ref().map(|p| p.will_change), Some(true));
    keys(&client, &mut model, &[KeyCode::Char('x')]).await?;
    assert_eq!(model.mappings().len(), 0, "no write before confirmation");
    keys(&client, &mut model, &[KeyCode::Char('y')]).await?;
    assert_eq!(
        enabled(&model, "api.test"),
        Some(true),
        "{:?}",
        model.notice()
    );
    assert_eq!(model.revision(), Some(1));
    let notice = model.notice().unwrap_or_default();
    assert!(
        notice.contains("changed, now revision 1 (was 0)"),
        "{notice}"
    );
    assert_eq!(
        model.selected().map(|m| m.pattern.as_str()),
        Some("api.test")
    );

    // Disable with space. Enter does not confirm; only y does.
    keys(&client, &mut model, &[KeyCode::Char(' ')]).await?;
    assert!(model.awaiting_confirmation().is_some());
    keys(&client, &mut model, &[KeyCode::Enter]).await?;
    assert_eq!(
        enabled(&model, "api.test"),
        Some(true),
        "Enter applied nothing"
    );
    keys(&client, &mut model, &[KeyCode::Char('y')]).await?;
    assert_eq!(enabled(&model, "api.test"), Some(false));
    assert_eq!(model.revision(), Some(2));

    // Cancelling a removal changes nothing.
    keys(&client, &mut model, &[KeyCode::Char('d'), KeyCode::Esc]).await?;
    assert_eq!(enabled(&model, "api.test"), Some(false));
    // Confirming it removes the mapping.
    keys(&client, &mut model, &[KeyCode::Char('d')]).await?;
    keys(&client, &mut model, &[KeyCode::Char('y')]).await?;
    assert_eq!(enabled(&model, "api.test"), None);
    assert_eq!(model.revision(), Some(3));

    // A write elsewhere between preview and confirmation is refused, shown,
    // and previewed again; the console never applies against the new
    // revision on its own.
    fill_form(&client, &mut model, "web.test", "127.0.0.2").await?;
    keys(&client, &mut model, &[KeyCode::Enter]).await?;
    assert_eq!(
        model.awaiting_confirmation().map(|p| p.base_revision),
        Some(3)
    );
    write_elsewhere(&client, 3).await?;
    keys(&client, &mut model, &[KeyCode::Char('y')]).await?;
    let note = model.write_note().unwrap_or_default().to_owned();
    assert!(
        note.contains("The registry changed elsewhere (now revision 4)"),
        "{note}"
    );
    assert_eq!(
        model.awaiting_confirmation().map(|p| p.base_revision),
        Some(4)
    );
    assert_eq!(
        enabled(&model, "other.test"),
        Some(true),
        "the new state was reread"
    );
    assert_eq!(
        enabled(&model, "web.test"),
        None,
        "the refused write was not applied"
    );
    keys(&client, &mut model, &[KeyCode::Char('y')]).await?;
    assert_eq!(enabled(&model, "web.test"), Some(true));
    assert_eq!(model.revision(), Some(5));

    let _sent = stop.send(());
    daemon.await??;
    Ok(())
}
