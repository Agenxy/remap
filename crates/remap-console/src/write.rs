// SPDX-License-Identifier: GPL-3.0-or-later
//! The flow every write follows (ADR-0041): preview, explicit confirmation,
//! then apply against the preview's base revision with a fresh operation ID.

use crossterm::event::{KeyCode, KeyEvent};
use remap_protocol::{ApplyResult, Change, Diagnostic, PreviewResult};

use crate::form::Form;
use crate::model::{Mode, Model, Notice};
use crate::text;
use crate::update::Effect;

/// The daemon's code for an apply whose expected revision is stale.
pub(crate) const REVISION_CONFLICT: &str = "E_REVISION_CONFLICT";

#[derive(Debug, Clone)]
pub(crate) struct WriteFlow {
    pub(crate) title: String,
    pub(crate) changes: Vec<Change>,
    pub(crate) stage: Stage,
    pub(crate) note: Option<String>,
    /// The preview this flow waits for; answers to any other are dropped.
    pub(crate) preview_seq: u64,
    form: Option<Box<Form>>,
    focus: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) enum Stage {
    Previewing,
    Confirm(PreviewResult),
    Applying {
        preview: PreviewResult,
        operation_id: String,
    },
    /// The apply may or may not have committed; a retry reuses the request.
    Uncertain {
        preview: PreviewResult,
        operation_id: String,
        diagnostic: Diagnostic,
    },
    Refused(Diagnostic),
}

/// Only `y` confirms. Enter also submits the form, so a doubled Enter must
/// never apply a preview the owner has not read.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum Answer {
    Yes,
    No,
    Enter,
    Other,
}

impl Answer {
    fn of(key: KeyEvent) -> Self {
        match key.code {
            KeyCode::Char('y' | 'Y') => Self::Yes,
            KeyCode::Char('n' | 'N') | KeyCode::Esc => Self::No,
            KeyCode::Enter => Self::Enter,
            _ => Self::Other,
        }
    }
}

/// The hint Enter shows where only `y` confirms.
pub(crate) const PRESS_Y_TO_APPLY: &str = "Press y to apply, n to cancel.";
const PRESS_Y_TO_RETRY: &str = "Press y to retry the same request, n to stop.";

/// Asks the daemon for a preview on behalf of the flow, under a new ID.
fn request_preview(model: &mut Model, flow: &mut WriteFlow) -> Effect {
    model.next_preview += 1;
    flow.preview_seq = model.next_preview;
    Effect::Preview {
        seq: flow.preview_seq,
        changes: flow.changes.clone(),
    }
}

/// Starts a write by asking the daemon for a preview.
pub(crate) fn begin(
    model: &mut Model,
    title: String,
    changes: Vec<Change>,
    form: Option<Box<Form>>,
    focus: Option<String>,
) -> Vec<Effect> {
    let mut flow = Box::new(WriteFlow {
        title,
        changes,
        stage: Stage::Previewing,
        note: None,
        preview_seq: 0,
        form,
        focus,
    });
    let effect = request_preview(model, &mut flow);
    model.mode = Mode::Write(flow);
    vec![effect]
}

/// Keys in the write dialog. The mode has already been reset to browsing.
pub(crate) fn on_key(model: &mut Model, mut flow: Box<WriteFlow>, key: KeyEvent) -> Vec<Effect> {
    let answer = Answer::of(key);
    let stage = std::mem::replace(&mut flow.stage, Stage::Previewing);
    match (stage, answer) {
        (Stage::Confirm(preview), Answer::Yes) => {
            let operation_id = uuid::Uuid::new_v4().to_string();
            apply(model, flow, preview, operation_id)
        }
        (
            Stage::Uncertain {
                preview,
                operation_id,
                ..
            },
            Answer::Yes,
        ) => apply(model, flow, preview, operation_id),
        (Stage::Uncertain { .. }, Answer::No) => {
            model.notice = Some(Notice::warning(
                "Stopped. The write may have been committed; the table shows the daemon's current state.",
            ));
            model.request_refresh()
        }
        (Stage::Refused(diagnostic), Answer::Yes | Answer::No | Answer::Enter) => {
            model.notice = Some(Notice::error(format!(
                "Refused: {}",
                text::diagnostic(&diagnostic)
            )));
            close(model, flow);
            Vec::new()
        }
        (Stage::Confirm(_) | Stage::Previewing, Answer::No) => {
            model.notice = Some(Notice::info("Cancelled. Nothing was changed."));
            close(model, flow);
            Vec::new()
        }
        (stage, answer) => {
            let hint = match &stage {
                Stage::Confirm(_) => Some(PRESS_Y_TO_APPLY),
                Stage::Uncertain { .. } => Some(PRESS_Y_TO_RETRY),
                _ => None,
            };
            if answer == Answer::Enter
                && let Some(hint) = hint
            {
                model.notice = Some(Notice::info(hint));
            }
            flow.stage = stage;
            model.mode = Mode::Write(flow);
            Vec::new()
        }
    }
}

fn apply(
    model: &mut Model,
    mut flow: Box<WriteFlow>,
    preview: PreviewResult,
    operation_id: String,
) -> Vec<Effect> {
    let effect = Effect::Apply {
        expected_revision: preview.base_revision,
        operation_id: operation_id.clone(),
        changes: flow.changes.clone(),
    };
    flow.stage = Stage::Applying {
        preview,
        operation_id,
    };
    model.mode = Mode::Write(flow);
    vec![effect]
}

/// Returns to the form the write came from, or to the table.
fn close(model: &mut Model, flow: Box<WriteFlow>) {
    model.mode = flow.form.map_or(Mode::Browse, Mode::Form);
}

/// Records a preview for the write waiting on exactly that preview. An
/// answer for a cancelled flow, or for an earlier request, is dropped.
pub(crate) fn on_previewed(
    model: &mut Model,
    seq: u64,
    result: Result<PreviewResult, Diagnostic>,
) -> Vec<Effect> {
    if let Mode::Write(flow) = &mut model.mode
        && flow.preview_seq == seq
        && matches!(flow.stage, Stage::Previewing)
    {
        flow.stage = match result {
            Ok(preview) => Stage::Confirm(preview),
            Err(diagnostic) => Stage::Refused(diagnostic),
        };
    }
    Vec::new()
}

/// Records an apply's answer. A conflict re-reads and previews again; a
/// transport failure waits for the owner to retry the identical request.
pub(crate) fn on_applied(
    model: &mut Model,
    operation_id: &str,
    result: Result<ApplyResult, Diagnostic>,
) -> Vec<Effect> {
    let mode = std::mem::replace(&mut model.mode, Mode::Browse);
    let Mode::Write(mut flow) = mode else {
        model.mode = mode;
        return model.request_refresh();
    };
    let stage = std::mem::replace(&mut flow.stage, Stage::Previewing);
    let Stage::Applying {
        preview,
        operation_id: pending,
    } = stage
    else {
        flow.stage = stage;
        model.mode = Mode::Write(flow);
        return model.request_refresh();
    };
    if pending != operation_id {
        flow.stage = Stage::Applying {
            preview,
            operation_id: pending,
        };
        model.mode = Mode::Write(flow);
        return model.request_refresh();
    }
    match result {
        Ok(receipt) => applied(model, &flow, &receipt),
        Err(diagnostic) => refused(model, flow, preview, pending, diagnostic),
    }
}

fn applied(model: &mut Model, flow: &WriteFlow, receipt: &ApplyResult) -> Vec<Effect> {
    model.notice = Some(Notice::success(text::receipt(&flow.title, receipt)));
    if let Some(focus) = &flow.focus {
        model.anchor = Some(focus.clone());
    }
    model.request_refresh()
}

fn refused(
    model: &mut Model,
    mut flow: Box<WriteFlow>,
    preview: PreviewResult,
    operation_id: String,
    diagnostic: Diagnostic,
) -> Vec<Effect> {
    if diagnostic.code == REVISION_CONFLICT {
        let now = diagnostic
            .context
            .get("current_revision")
            .map_or_else(String::new, |revision| {
                format!(" (now revision {revision})")
            });
        flow.note = Some(format!(
            "The registry changed elsewhere{now}. Nothing was applied. Review this new preview, then confirm again."
        ));
        let mut effects = model.request_refresh();
        effects.push(request_preview(model, &mut flow));
        model.mode = Mode::Write(flow);
        return effects;
    }
    flow.stage = if diagnostic.retryable {
        Stage::Uncertain {
            preview,
            operation_id,
            diagnostic,
        }
    } else {
        Stage::Refused(diagnostic)
    };
    model.mode = Mode::Write(flow);
    model.request_refresh()
}
