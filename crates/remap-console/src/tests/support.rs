// SPDX-License-Identifier: GPL-3.0-or-later
//! Builders and drivers shared by the unit and render tests.

use std::collections::VecDeque;
use std::error::Error;
use std::sync::Mutex;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use remap_protocol::{
    ApplyResult, ChangeEffect, Command, CommandResult, Diagnostic, HostPolicy, MappingView,
    PreviewResult, RegistryStatus,
};

use crate::authority::Authority;
use crate::model::Model;
use crate::update::{Effect, Event, Outcome, Snapshot, update};
use crate::view::view;

pub(crate) type TestResult = Result<(), Box<dyn Error>>;

/// No effects, for comparing against.
pub(crate) const fn none() -> Vec<Effect> {
    Vec::new()
}

pub(crate) fn mapping(pattern: &str, target: &str, enabled: bool) -> MappingView {
    MappingView {
        landing: None,
        pattern: pattern.to_owned(),
        target: target.to_owned(),
        target_kind: "ip".to_owned(),
        host_policy: HostPolicy::PreserveClient,
        enabled,
        updated_revision: 1,
        peer_address: None,
    }
}

pub(crate) fn status(revision: u64, mappings: &[MappingView]) -> RegistryStatus {
    let count = |enabled_only: bool| {
        let selected = mappings
            .iter()
            .filter(|m| !enabled_only || m.enabled)
            .count();
        u64::try_from(selected).unwrap_or(u64::MAX)
    };
    RegistryStatus {
        revision,
        mapping_count: count(false),
        enabled_count: count(true),
        schema_version: 1,
        daemon_version: "0.2.0".to_owned(),
        maintenance: None,
        dns_upstream: None,
        dns_turned_off: None,
        peer_machine_listeners: None,
    }
}

pub(crate) fn snapshot(revision: u64, mappings: Vec<MappingView>) -> Event {
    let status = status(revision, &mappings);
    Event::Outcome(Box::new(Outcome::Refreshed(Ok(Snapshot {
        status,
        mappings,
    }))))
}

/// A live model showing three mappings at revision 4, one of them off.
pub(crate) fn loaded() -> Model {
    let mut model = Model::new(false);
    let effects = crate::update::start(&mut model);
    assert_eq!(effects, vec![Effect::Refresh]);
    let effects = update(
        &mut model,
        snapshot(
            4,
            vec![
                mapping("api.test", "127.0.0.1", true),
                mapping("db.test", "10.0.0.5", false),
                mapping("web.test", "192.168.1.9", true),
            ],
        ),
    );
    assert_eq!(effects, none());
    model
}

pub(crate) fn key(code: KeyCode) -> Event {
    Event::Key(KeyEvent::new(code, KeyModifiers::NONE))
}

pub(crate) fn press(model: &mut Model, character: char) -> Vec<Effect> {
    update(model, key(KeyCode::Char(character)))
}

pub(crate) fn type_text(model: &mut Model, text: &str) -> Vec<Effect> {
    let mut effects = Vec::new();
    for character in text.chars() {
        effects.extend(press(model, character));
    }
    effects
}

pub(crate) fn diagnostic(code: &str, retryable: bool) -> Diagnostic {
    Diagnostic::new(code, "it failed", Some("try again".to_owned()), retryable)
}

pub(crate) fn preview(
    base_revision: u64,
    before: Option<MappingView>,
    after: Option<MappingView>,
) -> PreviewResult {
    let pattern = after
        .as_ref()
        .or(before.as_ref())
        .map_or_else(String::new, |m| m.pattern.clone());
    PreviewResult {
        warnings: vec!["target refused connection".to_owned()],
        base_revision,
        will_change: true,
        effects: vec![ChangeEffect {
            pattern,
            action: "updated".to_owned(),
            before,
            after,
        }],
    }
}

pub(crate) fn receipt(operation_id: &str, previous: u64) -> ApplyResult {
    ApplyResult {
        warnings: Vec::new(),
        operation_id: operation_id.to_owned(),
        previous_revision: previous,
        revision: previous + 1,
        changed: true,
        effects: Vec::new(),
    }
}

/// The screen as text, one string per row.
pub(crate) fn render(
    model: &Model,
    width: u16,
    height: u16,
) -> Result<Vec<String>, Box<dyn Error>> {
    let mut terminal = Terminal::new(TestBackend::new(width, height))?;
    terminal.draw(|frame| view(model, frame))?;
    let buffer = terminal.backend().buffer();
    let rows = (0..height)
        .map(|y| {
            (0..width)
                .map(|x| buffer[(x, y)].symbol().to_owned())
                .collect::<String>()
        })
        .collect();
    Ok(rows)
}

pub(crate) fn screen_contains(rows: &[String], needle: &str) -> bool {
    rows.iter().any(|row| row.contains(needle))
}

/// An authority that answers from a script and records what it was asked.
#[derive(Debug, Default)]
pub(crate) struct Scripted {
    answers: Mutex<VecDeque<Result<CommandResult, Diagnostic>>>,
    commands: Mutex<Vec<Command>>,
}

impl Scripted {
    pub(crate) fn new(answers: Vec<Result<CommandResult, Diagnostic>>) -> Self {
        Self {
            answers: Mutex::new(answers.into()),
            commands: Mutex::new(Vec::new()),
        }
    }

    /// An authority whose every scripted answer succeeds.
    pub(crate) fn answering(answers: Vec<CommandResult>) -> Self {
        Self::new(answers.into_iter().map(Ok).collect())
    }

    pub(crate) fn commands(&self) -> Vec<Command> {
        self.commands
            .lock()
            .map(|commands| commands.clone())
            .unwrap_or_default()
    }
}

impl Authority for Scripted {
    fn execute(
        &self,
        command: Command,
    ) -> impl std::future::Future<Output = Result<CommandResult, Diagnostic>> + Send {
        if let Ok(mut commands) = self.commands.lock() {
            commands.push(command);
        }
        let answer = self
            .answers
            .lock()
            .ok()
            .and_then(|mut answers| answers.pop_front())
            .unwrap_or_else(|| Err(Diagnostic::daemon_unavailable()));
        std::future::ready(answer)
    }
}
