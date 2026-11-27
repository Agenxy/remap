// SPDX-License-Identifier: GPL-3.0-or-later
//! The pure state transition: one event in, the daemon commands to run out.

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use remap_protocol::{
    ApplyResult, Change, Diagnostic, HostPolicy, MappingView, PreviewResult, RegistryStatus,
    ResolutionResult, ValidationResult,
};

use crate::browse;
use crate::form::{Form, FormAction};
use crate::model::{Connection, Mode, Model, Notice};
use crate::resolve::{self, ResolveAction};
use crate::write;

/// Something that happened: a key, a paste, a resize, a daemon answer, or
/// news from the revision watcher.
#[derive(Debug, Clone)]
pub enum Event {
    /// A key press. Releases and repeats of non-press kinds are ignored.
    Key(KeyEvent),
    /// Text pasted into the terminal (bracketed paste).
    Paste(String),
    /// The terminal changed size.
    Resize {
        /// Columns.
        width: u16,
        /// Rows.
        height: u16,
    },
    /// A daemon command finished.
    Outcome(Box<Outcome>),
    /// The revision watcher reported.
    Watch(Watch),
    /// The process was asked to stop (SIGTERM or SIGHUP). The console quits
    /// through its normal path, so the terminal is restored.
    Stop,
}

/// News from the long-polling revision watcher.
#[derive(Debug, Clone)]
pub enum Watch {
    /// The daemon answered and is at this revision.
    Revision(u64),
    /// The daemon could not be reached; the watcher keeps retrying.
    Unreachable(Diagnostic),
}

/// A daemon command the console wants run. [`crate::authority::execute`]
/// turns each into exactly one [`Outcome`].
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Effect {
    /// Read status and every page of mappings, disabled ones included.
    Refresh,
    /// Validate the form as it stands. `seq` orders answers.
    Validate {
        /// Monotonic request number; stale answers are ignored.
        seq: u64,
        /// Pattern as typed.
        pattern: String,
        /// Target as typed.
        target: String,
        /// Chosen host policy.
        host_policy: HostPolicy,
        /// Landing path, when given.
        landing: Option<String>,
    },
    /// Preview a change set without committing it.
    Preview {
        /// Identifies the write flow that asked; other flows ignore the answer.
        seq: u64,
        /// Changes evaluated in order.
        changes: Vec<Change>,
    },
    /// Commit a previewed change set.
    Apply {
        /// The preview's base revision.
        expected_revision: u64,
        /// A UUID (version 4), reused only to retry this exact request.
        operation_id: String,
        /// The previewed changes.
        changes: Vec<Change>,
    },
    /// Explain which mapping answers a name.
    Resolve {
        /// Client-facing name.
        name: String,
    },
}

/// The answer to one [`Effect`].
#[derive(Debug, Clone)]
pub enum Outcome {
    /// Answer to [`Effect::Refresh`].
    Refreshed(Result<Snapshot, Diagnostic>),
    /// Answer to [`Effect::Validate`].
    Validated {
        /// The request number it answers.
        seq: u64,
        /// The daemon's canonical form, or its refusal.
        result: Result<ValidationResult, Diagnostic>,
    },
    /// Answer to [`Effect::Preview`].
    Previewed {
        /// The preview request it answers.
        seq: u64,
        /// The projection, or the refusal.
        result: Result<PreviewResult, Diagnostic>,
    },
    /// Answer to [`Effect::Apply`].
    Applied {
        /// The operation it answers.
        operation_id: String,
        /// The receipt, or the refusal.
        result: Result<ApplyResult, Diagnostic>,
    },
    /// Answer to [`Effect::Resolve`].
    Resolved(Result<ResolutionResult, Diagnostic>),
}

/// Status and the full mapping list, read together.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Snapshot {
    /// Daemon and registry status.
    pub status: RegistryStatus,
    /// Every mapping, disabled ones included, in registry order.
    pub mappings: Vec<MappingView>,
}

/// The effects to run when the console opens.
pub fn start(model: &mut Model) -> Vec<Effect> {
    model.request_refresh()
}

/// Applies one event to the model and returns the daemon commands to run.
pub fn update(model: &mut Model, event: Event) -> Vec<Effect> {
    match event {
        Event::Key(key) => on_key(model, key),
        Event::Paste(text) => on_paste(model, &text),
        Event::Resize { width, height } => {
            model.width = width;
            model.height = height;
            model.reselect();
            Vec::new()
        }
        Event::Outcome(outcome) => on_outcome(model, *outcome),
        Event::Watch(watch) => on_watch(model, watch),
        Event::Stop => {
            model.quit = true;
            Vec::new()
        }
    }
}

fn on_key(model: &mut Model, key: KeyEvent) -> Vec<Effect> {
    if key.kind == KeyEventKind::Release {
        return Vec::new();
    }
    if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
        model.quit = true;
        return Vec::new();
    }
    match std::mem::replace(&mut model.mode, Mode::Browse) {
        Mode::Browse => browse::on_key(model, key),
        Mode::Filter => browse::on_filter_key(model, key),
        Mode::Help => Vec::new(),
        Mode::Form(form) => on_form_key(model, form, key),
        Mode::Resolve(prompt) => on_resolve_key(model, prompt, key),
        Mode::Write(flow) => write::on_key(model, flow, key),
    }
}

fn on_form_key(model: &mut Model, mut form: Box<Form>, key: KeyEvent) -> Vec<Effect> {
    match form.on_key(key) {
        FormAction::Stay => {
            model.mode = Mode::Form(form);
            Vec::new()
        }
        FormAction::Changed => {
            let effects = model.check_form(&mut form);
            model.mode = Mode::Form(form);
            effects
        }
        FormAction::Cancel => {
            model.notice = Some(Notice::info("Closed the form. Nothing was changed."));
            Vec::new()
        }
        FormAction::Submit => submit_form(model, form),
    }
}

fn submit_form(model: &mut Model, form: Box<Form>) -> Vec<Effect> {
    match form.changes() {
        Ok(changes) => {
            let title = form.change_title();
            let focus = form.focus_pattern();
            write::begin(model, title, changes, Some(form), Some(focus))
        }
        Err(message) => {
            model.notice = Some(Notice::warning(message));
            model.mode = Mode::Form(form);
            Vec::new()
        }
    }
}

fn on_resolve_key(
    model: &mut Model,
    mut prompt: Box<resolve::ResolvePrompt>,
    key: KeyEvent,
) -> Vec<Effect> {
    match prompt.on_key(key) {
        ResolveAction::Close => Vec::new(),
        ResolveAction::Stay => {
            model.mode = Mode::Resolve(prompt);
            Vec::new()
        }
        ResolveAction::Lookup(name) => {
            model.mode = Mode::Resolve(prompt);
            vec![Effect::Resolve { name }]
        }
    }
}

fn on_paste(model: &mut Model, text: &str) -> Vec<Effect> {
    match std::mem::replace(&mut model.mode, Mode::Browse) {
        Mode::Form(mut form) => {
            let effects = if form.paste(text) {
                model.check_form(&mut form)
            } else {
                Vec::new()
            };
            model.mode = Mode::Form(form);
            effects
        }
        Mode::Resolve(mut prompt) => {
            prompt.input.insert_str(text);
            model.mode = Mode::Resolve(prompt);
            Vec::new()
        }
        Mode::Filter => {
            let room = browse::MAX_FILTER_CHARS.saturating_sub(model.filter.chars().count());
            model
                .filter
                .extend(text.chars().filter(|c| !c.is_control()).take(room));
            model.mode = Mode::Filter;
            model.reselect();
            Vec::new()
        }
        other => {
            model.mode = other;
            Vec::new()
        }
    }
}

fn on_outcome(model: &mut Model, outcome: Outcome) -> Vec<Effect> {
    match outcome {
        Outcome::Refreshed(result) => on_refreshed(model, result),
        Outcome::Validated { seq, result } => {
            if let Mode::Form(form) = &mut model.mode {
                form.accept_check(seq, result);
            }
            Vec::new()
        }
        Outcome::Previewed { seq, result } => write::on_previewed(model, seq, result),
        Outcome::Applied {
            operation_id,
            result,
        } => write::on_applied(model, &operation_id, result),
        Outcome::Resolved(result) => {
            if let Mode::Resolve(prompt) = &mut model.mode {
                prompt.accept(result);
            }
            Vec::new()
        }
    }
}

fn on_refreshed(model: &mut Model, result: Result<Snapshot, Diagnostic>) -> Vec<Effect> {
    match result {
        Ok(snapshot) => {
            let current = model.revision().unwrap_or(0);
            if snapshot.status.revision >= current || model.connection != Connection::Live {
                model.status = Some(snapshot.status);
                model.mappings = snapshot.mappings;
                model.reselect();
            }
            model.connection = Connection::Live;
            if model.notice() == Some(browse::REFRESHING) {
                let revision = model.revision().unwrap_or(0);
                model.notice = Some(Notice::info(format!(
                    "Read revision {revision} from the daemon."
                )));
            }
        }
        Err(diagnostic) => model.connection = Connection::Unreachable(diagnostic),
    }
    model.refresh_finished()
}

fn on_watch(model: &mut Model, watch: Watch) -> Vec<Effect> {
    match watch {
        Watch::Revision(revision) => {
            if model.connection == Connection::Live && model.revision() == Some(revision) {
                Vec::new()
            } else {
                model.request_refresh()
            }
        }
        Watch::Unreachable(diagnostic) => {
            model.connection = Connection::Unreachable(diagnostic);
            Vec::new()
        }
    }
}
