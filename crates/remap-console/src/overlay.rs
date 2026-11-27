// SPDX-License-Identifier: GPL-3.0-or-later
//! Dialogs drawn over the table: help, the form, resolve, and the write flow.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Padding, Paragraph};
use remap_protocol::{ChangeEffect, HostPolicy, PreviewResult};

use crate::form::{Check, Field, Form};
use crate::input::LineInput;
use crate::model::{Mode, Model};
use crate::resolve::{Lookup, ResolvePrompt};
use crate::text;
use crate::view::Palette;
use crate::write::{Stage, WriteFlow};

const LABEL_WIDTH: usize = 14;
const DIALOG_WIDTH: u16 = 76;

const HELP: [&str; 16] = [
    "Up Down  j k    Move the selection",
    "PgUp PgDn       Move a page",
    "Home End        First or last mapping",
    "/               Filter by pattern or target as you type",
    "a               Show or hide mappings that are off",
    "n               New mapping",
    "e               Edit the selected mapping",
    "Space           Turn the selected mapping on or off",
    "d               Remove the selected mapping",
    "r               Resolve a name",
    "g               Refresh from the daemon",
    "?               This help",
    "q  Esc          Quit (Esc clears a filter first)",
    "Ctrl-C          Quit from anywhere",
    "",
    "Every change is previewed. Only y applies it; n or Esc cancels.",
];

/// One dialog line and its style.
type Styled = (String, Style);

pub(crate) fn draw(model: &Model, palette: Palette, frame: &mut Frame<'_>, area: Rect) {
    match &model.mode {
        Mode::Help => {
            let lines = HELP
                .iter()
                .map(|line| ((*line).to_owned(), Style::new()))
                .collect();
            dialog(frame, area, " Keys ", lines);
        }
        Mode::Form(form) => draw_form(form, palette, frame, area),
        Mode::Resolve(prompt) => draw_resolve(prompt, palette, frame, area),
        Mode::Write(flow) => {
            let lines = write_lines(flow, palette);
            let title = format!(" {} ", flow.title);
            dialog(frame, area, &title, lines);
        }
        Mode::Browse | Mode::Filter => {}
    }
}

/// Text columns inside a dialog drawn over `area`: borders and padding off.
fn inner_width(area: Rect) -> usize {
    usize::from(area.width.min(DIALOG_WIDTH).saturating_sub(4))
}

/// Draws a centred box of pre-wrapped lines and returns its inner area.
fn dialog(frame: &mut Frame<'_>, area: Rect, title: &str, lines: Vec<Styled>) -> Rect {
    let width = area.width.min(DIALOG_WIDTH);
    let inner_width = inner_width(area);
    let wrapped: Vec<Line<'_>> = lines
        .into_iter()
        .flat_map(|(line, style)| {
            text::wrap(&line, inner_width)
                .into_iter()
                .map(move |part| Line::styled(part, style))
        })
        .collect();
    let wanted = u16::try_from(wrapped.len())
        .unwrap_or(u16::MAX)
        .saturating_add(2);
    let height = wanted.min(area.height);
    let x = area.x + (area.width - width) / 2;
    let y = area.y + (area.height - height) / 2;
    let rect = Rect::new(x, y, width, height);
    let block = Block::new()
        .borders(Borders::ALL)
        .padding(Padding::horizontal(1))
        .title(Span::styled(title.to_owned(), Palette::title()));
    let inner = block.inner(rect);
    frame.render_widget(Clear, rect);
    frame.render_widget(Paragraph::new(wrapped).block(block), rect);
    inner
}

fn input_line(label: &str, input: &LineInput, focused: bool, width: usize) -> (String, usize) {
    let marker = if focused { "> " } else { "  " };
    let prefix = format!("{marker}{label:<LABEL_WIDTH$}");
    let room = width.saturating_sub(prefix.chars().count()).max(1);
    let (shown, cursor) = input.window(room);
    let column = prefix.chars().count() + cursor;
    (format!("{prefix}{shown}"), column)
}

fn policy_line(form: &Form) -> String {
    let marker = if form.focus == Field::HostPolicy {
        "> "
    } else {
        "  "
    };
    let choice = |policy: HostPolicy| {
        let mark = if form.host_policy == policy {
            "(x)"
        } else {
            "( )"
        };
        format!("{mark} {}", policy.as_str())
    };
    format!(
        "{marker}{:<LABEL_WIDTH$}{}  {}",
        "Host policy",
        choice(HostPolicy::PreserveClient),
        choice(HostPolicy::UseUpstream)
    )
}

fn check_lines(check: &Check, palette: Palette) -> Vec<Styled> {
    match check {
        Check::Incomplete => vec![("Enter a pattern and a target.".to_owned(), palette.muted())],
        Check::Waiting => vec![("Checking with the daemon.".to_owned(), palette.muted())],
        Check::Valid(validation) => {
            let mut lines = vec![
                (
                    format!("Valid: {} to {}", validation.pattern, validation.target),
                    palette.tone(crate::model::Tone::Success),
                ),
                (
                    format!(
                        "Target kind: {}   Host policy: {}",
                        validation.target_kind,
                        validation.host_policy.as_str()
                    ),
                    Style::new(),
                ),
            ];
            if let Some(landing) = &validation.landing {
                lines.push((format!("Landing: {landing}"), Style::new()));
            }
            lines.extend(advisories(&validation.warnings, palette));
            lines
        }
        Check::Invalid(diagnostic) => vec![(
            format!("Invalid: {}", text::diagnostic(diagnostic)),
            palette.tone(crate::model::Tone::Error),
        )],
    }
}

fn advisories(warnings: &[String], palette: Palette) -> Vec<Styled> {
    warnings
        .iter()
        .map(|warning| (format!("Advisory: {warning}"), palette.problem()))
        .collect()
}

fn draw_form(form: &Form, palette: Palette, frame: &mut Frame<'_>, area: Rect) {
    let inner_width = inner_width(area);
    let fields = [
        ("Pattern", &form.pattern, Field::Pattern),
        ("Target", &form.target, Field::Target),
    ];
    let mut lines = Vec::new();
    let mut cursor = None;
    for (row, (label, input, field)) in fields.into_iter().enumerate() {
        let (line, column) = input_line(label, input, form.focus == field, inner_width);
        if form.focus == field {
            cursor = Some((row, column));
        }
        lines.push((line, Style::new()));
    }
    lines.push((
        text::truncate(&policy_line(form), inner_width),
        Style::new(),
    ));
    let landing_focused = form.focus == Field::Landing;
    let (mut landing, column) = input_line("Landing", &form.landing, landing_focused, inner_width);
    if landing_focused {
        cursor = Some((3, column));
    } else if form.landing.is_blank() {
        landing.push_str("(optional)");
    }
    lines.push((landing, Style::new()));
    lines.push((String::new(), Style::new()));
    lines.extend(check_lines(&form.check, palette));
    lines.push((String::new(), Style::new()));
    lines.push((
        "Tab next field   Enter preview   Esc cancel".to_owned(),
        palette.muted(),
    ));
    let title = format!(" {} ", form.title());
    let inner = dialog(frame, area, &title, lines);
    if let Some((row, column)) = cursor {
        place_cursor(frame, inner, row, column);
    }
}

fn place_cursor(frame: &mut Frame<'_>, inner: Rect, row: usize, column: usize) {
    let row = u16::try_from(row).unwrap_or(u16::MAX);
    let column = u16::try_from(column).unwrap_or(u16::MAX);
    if row < inner.height && column < inner.width {
        frame.set_cursor_position((inner.x + column, inner.y + row));
    }
}

fn draw_resolve(prompt: &ResolvePrompt, palette: Palette, frame: &mut Frame<'_>, area: Rect) {
    let inner_width = inner_width(area);
    let (line, column) = input_line("Name", &prompt.input, true, inner_width);
    let mut lines = vec![(line, Style::new()), (String::new(), Style::new())];
    lines.extend(lookup_lines(&prompt.lookup, palette));
    lines.push((String::new(), Style::new()));
    lines.push(("Enter resolve   Esc close".to_owned(), palette.muted()));
    let inner = dialog(frame, area, " Resolve a name ", lines);
    place_cursor(frame, inner, 0, column);
}

fn lookup_lines(lookup: &Lookup, palette: Palette) -> Vec<Styled> {
    match lookup {
        Lookup::Idle => vec![(
            "Type a name to see which mapping answers it.".to_owned(),
            palette.muted(),
        )],
        Lookup::Pending(name) => vec![(format!("Resolving {name}."), palette.muted())],
        Lookup::Found(resolution) => match &resolution.mapping {
            Some(mapping) => vec![
                (
                    format!("{} is answered by {}", resolution.name, mapping.pattern),
                    palette.tone(crate::model::Tone::Success),
                ),
                (text::mapping_summary(mapping), Style::new()),
                (
                    format!("At revision {}.", resolution.revision),
                    palette.muted(),
                ),
            ],
            None => vec![(
                format!(
                    "No mapping answers {}. Remap leaves it to the normal resolver.",
                    resolution.name
                ),
                Style::new(),
            )],
        },
        Lookup::Failed(diagnostic) => vec![(
            format!("Could not resolve: {}", text::diagnostic(diagnostic)),
            palette.tone(crate::model::Tone::Error),
        )],
    }
}

fn effect_lines(effect: &ChangeEffect) -> Vec<Styled> {
    let side = |label: &str, mapping: Option<&remap_protocol::MappingView>| {
        let shown = mapping.map_or_else(|| "none".to_owned(), text::mapping_summary);
        (format!("  {label} {shown}"), Style::new())
    };
    vec![
        (
            format!("{} {}", effect.action, effect.pattern),
            Style::new().add_modifier(ratatui::style::Modifier::BOLD),
        ),
        side("before:", effect.before.as_ref()),
        side("after: ", effect.after.as_ref()),
    ]
}

fn preview_lines(preview: &PreviewResult, palette: Palette) -> Vec<Styled> {
    let change = if preview.will_change {
        "This changes the registry."
    } else {
        "This would leave the registry unchanged."
    };
    let mut lines = vec![(
        format!(
            "Preview against revision {}. {change}",
            preview.base_revision
        ),
        Style::new(),
    )];
    for effect in &preview.effects {
        lines.extend(effect_lines(effect));
    }
    lines.extend(advisories(&preview.warnings, palette));
    lines
}

fn write_lines(flow: &WriteFlow, palette: Palette) -> Vec<Styled> {
    let mut lines = Vec::new();
    if let Some(note) = &flow.note {
        lines.push((note.clone(), palette.problem()));
    }
    let (body, prompt) = match &flow.stage {
        Stage::Previewing => (
            vec![(
                "Asking the daemon for a preview.".to_owned(),
                palette.muted(),
            )],
            "n or Esc cancel".to_owned(),
        ),
        Stage::Confirm(preview) => (
            preview_lines(preview, palette),
            "y apply   n or Esc cancel".to_owned(),
        ),
        Stage::Applying { preview, .. } => (
            preview_lines(preview, palette),
            "Applying. Waiting for the daemon.".to_owned(),
        ),
        Stage::Uncertain {
            preview,
            operation_id,
            diagnostic,
        } => {
            let mut body = preview_lines(preview, palette);
            body.push((
                format!(
                    "The daemon did not confirm the write: {} It may already be committed.",
                    text::diagnostic(diagnostic)
                ),
                palette.tone(crate::model::Tone::Error),
            ));
            let prompt =
                format!("y retry the same request (operation {operation_id})   n or Esc stop");
            (body, prompt)
        }
        Stage::Refused(diagnostic) => (
            vec![(
                format!("Refused: {}", text::diagnostic(diagnostic)),
                palette.tone(crate::model::Tone::Error),
            )],
            "Enter or Esc back".to_owned(),
        ),
    };
    lines.extend(body);
    lines.push((String::new(), Style::new()));
    lines.push((prompt, Palette::title()));
    lines
}
