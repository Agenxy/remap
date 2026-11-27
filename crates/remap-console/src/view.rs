// SPDX-License-Identifier: GPL-3.0-or-later
//! The pure view: draws a [`Model`] into a frame and changes nothing.

use ratatui::Frame;
use ratatui::layout::{Constraint, Flex, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, HighlightSpacing, Paragraph, Row, Table, TableState, Wrap,
};
use remap_protocol::MappingView;

use crate::layout::{self, Regions};
use crate::model::{Connection, Mode, Model, Tone};
use crate::overlay;
use crate::text;

/// Draws the whole console for `model`.
pub fn view(model: &Model, frame: &mut Frame<'_>) {
    let area = frame.area();
    let regions = layout::regions(model, area);
    let palette = Palette::new(model.color);
    let header = text::header(model.status.as_ref(), area.width);
    frame.render_widget(
        Paragraph::new(header).style(palette.header()),
        regions.header,
    );
    let problems: Vec<Line<'_>> = regions
        .problem_lines
        .iter()
        .map(|line| Line::from(line.as_str()))
        .collect();
    frame.render_widget(
        Paragraph::new(problems).style(palette.problem()),
        regions.problems,
    );
    table(model, palette, frame, regions.table);
    if let Some(area) = regions.detail {
        detail(model, frame, area, &regions);
    }
    notice(model, palette, frame, regions.notice);
    footer(model, palette, frame, regions.footer);
    overlay::draw(model, palette, frame, area);
}

/// Styles that fall back to plain modifiers when colour is off.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Palette {
    color: bool,
}

impl Palette {
    pub(crate) const fn new(color: bool) -> Self {
        Self { color }
    }

    fn tint(self, color: Color) -> Style {
        if self.color {
            Style::new().fg(color)
        } else {
            Style::new()
        }
    }

    pub(crate) fn header(self) -> Style {
        self.tint(Color::Cyan).add_modifier(Modifier::BOLD)
    }

    pub(crate) fn problem(self) -> Style {
        self.tint(Color::Yellow)
    }

    pub(crate) fn muted(self) -> Style {
        self.tint(Color::DarkGray)
    }

    pub(crate) fn selected() -> Style {
        Style::new().add_modifier(Modifier::REVERSED)
    }

    pub(crate) fn title() -> Style {
        Style::new().add_modifier(Modifier::BOLD)
    }

    pub(crate) fn tone(self, tone: Tone) -> Style {
        match tone {
            Tone::Info => Style::new(),
            Tone::Success => self.tint(Color::Green),
            Tone::Warning => self.tint(Color::Yellow),
            Tone::Error => self.tint(Color::Red).add_modifier(Modifier::BOLD),
        }
    }
}

/// Which columns fit the width.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum Columns {
    Full,
    Medium,
    Narrow,
}

impl Columns {
    const fn for_width(width: u16) -> Self {
        if width >= 72 {
            Self::Full
        } else if width >= 46 {
            Self::Medium
        } else {
            Self::Narrow
        }
    }

    fn titles(self) -> Vec<&'static str> {
        match self {
            Self::Full => vec!["Pattern", "Target", "Kind", "State", "Host policy"],
            Self::Medium => vec!["Pattern", "Target", "State"],
            Self::Narrow => vec!["Pattern", "State"],
        }
    }

    fn widths(self) -> Vec<Constraint> {
        let state = Constraint::Length(5);
        match self {
            Self::Full => vec![
                Constraint::Fill(3),
                Constraint::Fill(4),
                Constraint::Length(12),
                state,
                Constraint::Length(15),
            ],
            Self::Medium => vec![Constraint::Fill(1), Constraint::Fill(1), state],
            Self::Narrow => vec![Constraint::Fill(1), state],
        }
    }

    fn cells(self, mapping: &MappingView) -> Vec<String> {
        let state = text::state_word(mapping.enabled).to_owned();
        match self {
            Self::Full => vec![
                mapping.pattern.clone(),
                mapping.target.clone(),
                mapping.target_kind.clone(),
                state,
                mapping.host_policy.as_str().to_owned(),
            ],
            Self::Medium => vec![mapping.pattern.clone(), mapping.target.clone(), state],
            Self::Narrow => vec![mapping.pattern.clone(), state],
        }
    }
}

/// The width each column gets, as the table lays them out: the room left after
/// the two-character selection marker, split with one space between columns.
/// Cells are cut to it with a visible "…" so a long target never looks complete.
fn column_limits(columns: Columns, width: u16) -> Vec<usize> {
    let room = Rect::new(0, 0, width.saturating_sub(SELECTION_MARKER_WIDTH), 1);
    Layout::horizontal(columns.widths())
        .flex(Flex::Start)
        .spacing(1)
        .split(room)
        .iter()
        .map(|column| usize::from(column.width))
        .collect()
}

const SELECTION_MARKER_WIDTH: u16 = 2;

fn table_title(model: &Model, shown: usize) -> String {
    let mut title = format!(" Mappings: {shown} shown");
    if !model.filter.is_empty() {
        title.push_str(", filter \"");
        title.push_str(&model.filter);
        title.push('"');
    }
    if !model.show_disabled {
        title.push_str(", only on");
    }
    title.push(' ');
    title
}

fn empty_message(model: &Model) -> &'static str {
    if model.connection == Connection::Connecting {
        "Reading mappings from the daemon."
    } else if model.mappings.is_empty() {
        "No mappings yet. Press n to create one."
    } else if !model.filter.is_empty() {
        "No mapping matches the filter. Press / then Esc to clear it."
    } else {
        "Every mapping is off and hidden. Press a to show them."
    }
}

fn table(model: &Model, palette: Palette, frame: &mut Frame<'_>, area: Rect) {
    let visible = model.visible();
    let block = Block::new().borders(Borders::TOP).title(Span::styled(
        table_title(model, visible.len()),
        Palette::title(),
    ));
    if visible.is_empty() {
        let message = Paragraph::new(empty_message(model))
            .block(block)
            .wrap(Wrap { trim: true });
        frame.render_widget(message, area);
        return;
    }
    let columns = Columns::for_width(area.width);
    let limits = column_limits(columns, area.width);
    let rows = visible.iter().map(|mapping| {
        let style = if mapping.enabled {
            Style::new()
        } else {
            palette.muted()
        };
        let cells = columns.cells(mapping).into_iter().zip(&limits);
        Row::new(cells.map(|(cell, limit)| Cell::from(text::truncate(&cell, *limit)))).style(style)
    });
    let header = Row::new(columns.titles()).style(Palette::title());
    let widget = Table::new(rows, columns.widths())
        .header(header)
        .block(block)
        .row_highlight_style(Palette::selected())
        .highlight_symbol("> ")
        .highlight_spacing(HighlightSpacing::Always);
    let mut state = TableState::new()
        .with_offset(model.offset)
        .with_selected(Some(model.cursor));
    frame.render_stateful_widget(widget, area, &mut state);
}

fn detail_lines(mapping: &MappingView, beside: bool) -> Vec<String> {
    let landing = mapping.landing.as_deref().unwrap_or("none");
    let state = text::state_word(mapping.enabled);
    let mut lines = vec![format!("Target: {}", mapping.target)];
    if beside {
        lines.push(format!("Target kind: {}", mapping.target_kind));
        lines.push(format!("Host policy: {}", mapping.host_policy.as_str()));
        lines.push(format!("State: {state}"));
        lines.push(format!("Landing: {landing}"));
        lines.push(format!("Updated: revision {}", mapping.updated_revision));
        if let Some(address) = &mapping.peer_address {
            lines.push(format!("Peer address: {address}"));
        }
        return lines;
    }
    lines.push(format!(
        "Target kind: {}   Host policy: {}   State: {state}",
        mapping.target_kind,
        mapping.host_policy.as_str()
    ));
    lines.push(format!("Landing: {landing}"));
    let mut updated = format!("Updated: revision {}", mapping.updated_revision);
    if let Some(address) = &mapping.peer_address {
        updated.push_str("   Peer address: ");
        updated.push_str(address);
    }
    lines.push(updated);
    lines
}

fn detail(model: &Model, frame: &mut Frame<'_>, area: Rect, regions: &Regions) {
    let borders = if regions.beside {
        Borders::TOP | Borders::LEFT
    } else {
        Borders::TOP
    };
    let Some(mapping) = model.selected() else {
        frame.render_widget(Block::new().borders(borders).title(" Detail "), area);
        return;
    };
    let block = Block::new().borders(borders).title(Span::styled(
        format!(" {} ", mapping.pattern),
        Palette::title(),
    ));
    let lines: Vec<Line<'_>> = detail_lines(mapping, regions.beside)
        .into_iter()
        .map(Line::from)
        .collect();
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn notice(model: &Model, palette: Palette, frame: &mut Frame<'_>, area: Rect) {
    let Some(notice) = &model.notice else {
        return;
    };
    let line = text::truncate(&notice.text, usize::from(area.width));
    frame.render_widget(Paragraph::new(line).style(palette.tone(notice.tone)), area);
}

/// Key hints for the current mode, in priority order.
fn hints(model: &Model) -> &'static [(&'static str, &'static str)] {
    match &model.mode {
        Mode::Browse => &[
            ("?", "help"),
            ("q", "quit"),
            ("n", "new"),
            ("e", "edit"),
            ("space", "on/off"),
            ("d", "remove"),
            ("/", "filter"),
            ("r", "resolve"),
            ("a", "all/on"),
            ("g", "refresh"),
            ("↑↓", "move"),
        ],
        Mode::Filter => &[("Enter", "keep filter"), ("Esc", "clear")],
        Mode::Help => &[("any key", "close help")],
        Mode::Form(_) => &[
            ("Enter", "preview"),
            ("Esc", "cancel"),
            ("Tab", "next field"),
            ("←→", "host policy"),
        ],
        Mode::Resolve(_) => &[("Enter", "resolve"), ("Esc", "close")],
        Mode::Write(_) => &[("y", "apply"), ("n/Esc", "cancel")],
    }
}

fn hint_line(model: &Model, width: usize) -> String {
    let mut line = String::new();
    for (key, label) in hints(model) {
        let item = format!("{key} {label}");
        let needed = if line.is_empty() { 0 } else { 2 } + item.chars().count();
        if line.chars().count() + needed > width {
            break;
        }
        if !line.is_empty() {
            line.push_str("  ");
        }
        line.push_str(&item);
    }
    line
}

fn footer(model: &Model, palette: Palette, frame: &mut Frame<'_>, area: Rect) {
    if matches!(model.mode, Mode::Filter) {
        let label = "Filter: ";
        let hint = "   Enter keep  Esc clear";
        let room = usize::from(area.width).saturating_sub(label.len() + hint.len());
        let shown = text::truncate(&model.filter, room.max(1));
        let cursor = u16::try_from(label.len() + shown.chars().count()).unwrap_or(area.width);
        frame.render_widget(
            Paragraph::new(format!("{label}{shown}{hint}")).style(Palette::title()),
            area,
        );
        frame.set_cursor_position((area.x + cursor.min(area.width.saturating_sub(1)), area.y));
        return;
    }
    let line = hint_line(model, usize::from(area.width));
    frame.render_widget(Paragraph::new(line).style(palette.muted()), area);
}
