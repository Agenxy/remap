// SPDX-License-Identifier: GPL-3.0-or-later
//! Console state: what the daemon last reported and what the owner is doing.

use ratatui::layout::Rect;
use remap_protocol::{Diagnostic, MappingView, RegistryStatus};

use crate::form::Form;
use crate::layout;
use crate::resolve::ResolvePrompt;
use crate::update::Effect;
use crate::write::{Stage, WriteFlow};

/// Everything the console shows, as plain data.
#[derive(Debug, Clone)]
pub struct Model {
    pub(crate) status: Option<RegistryStatus>,
    pub(crate) mappings: Vec<MappingView>,
    pub(crate) connection: Connection,
    pub(crate) refresh: Refresh,
    pub(crate) show_disabled: bool,
    pub(crate) filter: String,
    pub(crate) cursor: usize,
    pub(crate) anchor: Option<String>,
    pub(crate) offset: usize,
    pub(crate) mode: Mode,
    pub(crate) notice: Option<Notice>,
    pub(crate) width: u16,
    pub(crate) height: u16,
    pub(crate) color: bool,
    pub(crate) quit: bool,
    pub(crate) next_check: u64,
    pub(crate) next_preview: u64,
}

/// Whether the console can currently read the daemon.
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum Connection {
    Connecting,
    Live,
    Unreachable(Diagnostic),
}

/// Coalesces refresh requests so at most one read runs at a time.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum Refresh {
    Idle,
    Running,
    RunningStale,
}

/// What the owner is doing.
#[derive(Debug, Clone)]
pub(crate) enum Mode {
    Browse,
    Filter,
    Help,
    Form(Box<Form>),
    Resolve(Box<ResolvePrompt>),
    Write(Box<WriteFlow>),
}

/// The one-line status message under the table.
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct Notice {
    pub(crate) tone: Tone,
    pub(crate) text: String,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum Tone {
    Info,
    Success,
    Warning,
    Error,
}

impl Notice {
    pub(crate) fn info(text: impl Into<String>) -> Self {
        Self {
            tone: Tone::Info,
            text: text.into(),
        }
    }

    pub(crate) fn success(text: impl Into<String>) -> Self {
        Self {
            tone: Tone::Success,
            text: text.into(),
        }
    }

    pub(crate) fn warning(text: impl Into<String>) -> Self {
        Self {
            tone: Tone::Warning,
            text: text.into(),
        }
    }

    pub(crate) fn error(text: impl Into<String>) -> Self {
        Self {
            tone: Tone::Error,
            text: text.into(),
        }
    }
}

impl Model {
    /// Creates an empty model for an 80 by 24 terminal. `color` is false
    /// when `NO_COLOR` asks for plain output.
    #[must_use]
    pub fn new(color: bool) -> Self {
        Self {
            status: None,
            mappings: Vec::new(),
            connection: Connection::Connecting,
            refresh: Refresh::Idle,
            show_disabled: true,
            filter: String::new(),
            cursor: 0,
            anchor: None,
            offset: 0,
            mode: Mode::Browse,
            notice: None,
            width: 80,
            height: 24,
            color,
            quit: false,
            next_check: 0,
            next_preview: 0,
        }
    }

    /// Every mapping last read, disabled ones included.
    #[must_use]
    pub fn mappings(&self) -> &[MappingView] {
        &self.mappings
    }

    /// The mappings the table shows after the filter and the disabled toggle.
    #[must_use]
    pub fn visible(&self) -> Vec<&MappingView> {
        self.mappings.iter().filter(|m| self.shows(m)).collect()
    }

    /// The selected mapping, if the table shows any.
    #[must_use]
    pub fn selected(&self) -> Option<&MappingView> {
        self.visible().get(self.cursor).copied()
    }

    /// The registry status last read.
    #[must_use]
    pub fn status(&self) -> Option<&RegistryStatus> {
        self.status.as_ref()
    }

    /// The registry revision last read.
    #[must_use]
    pub fn revision(&self) -> Option<u64> {
        self.status.as_ref().map(|status| status.revision)
    }

    /// The status-line message, if any.
    #[must_use]
    pub fn notice(&self) -> Option<&str> {
        self.notice.as_ref().map(|notice| notice.text.as_str())
    }

    /// Whether the owner asked to quit.
    #[must_use]
    pub fn should_quit(&self) -> bool {
        self.quit
    }

    /// Whether the daemon is currently reachable.
    #[must_use]
    pub fn is_live(&self) -> bool {
        self.connection == Connection::Live
    }

    /// The preview awaiting the owner's explicit confirmation, if any.
    #[must_use]
    pub fn awaiting_confirmation(&self) -> Option<&remap_protocol::PreviewResult> {
        match &self.mode {
            Mode::Write(flow) => match &flow.stage {
                Stage::Confirm(preview) | Stage::Uncertain { preview, .. } => Some(preview),
                _ => None,
            },
            _ => None,
        }
    }

    /// The note a write dialog carries, such as a revision conflict.
    #[must_use]
    pub fn write_note(&self) -> Option<&str> {
        match &self.mode {
            Mode::Write(flow) => flow.note.as_deref(),
            _ => None,
        }
    }

    pub(crate) fn shows(&self, mapping: &MappingView) -> bool {
        (self.show_disabled || mapping.enabled) && matches_filter(mapping, &self.filter)
    }

    /// Keeps the selection on the same pattern when the list changes, or on
    /// the nearest row when that pattern is gone.
    pub(crate) fn reselect(&mut self) {
        let (count, found) = {
            let visible = self.visible();
            let found = self.anchor.as_ref().and_then(|anchor| {
                visible
                    .iter()
                    .position(|mapping| &mapping.pattern == anchor)
            });
            (visible.len(), found)
        };
        if let Some(index) = found {
            self.cursor = index;
        }
        self.cursor = self.cursor.min(count.saturating_sub(1));
        self.anchor = self.selected().map(|mapping| mapping.pattern.clone());
        self.ensure_visible();
    }

    /// Moves the selection by `delta` rows, clamped to the table.
    pub(crate) fn move_by(&mut self, delta: isize) {
        let count = self.visible().len();
        if count == 0 {
            return;
        }
        let target = self.cursor.saturating_add_signed(delta);
        self.cursor = target.min(count - 1);
        self.anchor = self.selected().map(|mapping| mapping.pattern.clone());
        self.ensure_visible();
    }

    /// Mapping rows the table can show at the current size.
    pub(crate) fn table_rows(&self) -> usize {
        let area = Rect::new(0, 0, self.width, self.height);
        layout::regions(self, area).table_rows()
    }

    fn ensure_visible(&mut self) {
        let rows = self.table_rows().max(1);
        if self.cursor < self.offset {
            self.offset = self.cursor;
        } else if self.cursor >= self.offset + rows {
            self.offset = self.cursor + 1 - rows;
        }
        let count = self.visible().len();
        self.offset = self.offset.min(count.saturating_sub(rows));
    }

    /// Asks for a refresh, coalescing with one already running.
    pub(crate) fn request_refresh(&mut self) -> Vec<Effect> {
        match self.refresh {
            Refresh::Idle => {
                self.refresh = Refresh::Running;
                vec![Effect::Refresh]
            }
            Refresh::Running | Refresh::RunningStale => {
                self.refresh = Refresh::RunningStale;
                Vec::new()
            }
        }
    }

    /// Records a finished refresh, starting another if one was asked for meanwhile.
    pub(crate) fn refresh_finished(&mut self) -> Vec<Effect> {
        if self.refresh == Refresh::RunningStale {
            self.refresh = Refresh::Running;
            vec![Effect::Refresh]
        } else {
            self.refresh = Refresh::Idle;
            Vec::new()
        }
    }

    /// Starts a debounced validation of the form as it stands.
    pub(crate) fn check_form(&mut self, form: &mut Form) -> Vec<Effect> {
        self.next_check += 1;
        form.request_check(self.next_check).into_iter().collect()
    }
}

fn matches_filter(mapping: &MappingView, filter: &str) -> bool {
    if filter.is_empty() {
        return true;
    }
    let needle = filter.to_lowercase();
    mapping.pattern.to_lowercase().contains(&needle)
        || mapping.target.to_lowercase().contains(&needle)
}
