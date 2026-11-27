// SPDX-License-Identifier: GPL-3.0-or-later
//! The resolve prompt: which mapping, if any, answers a name.

use crossterm::event::{KeyCode, KeyEvent};
use remap_protocol::{Diagnostic, ResolutionResult};

use crate::input::LineInput;

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum Lookup {
    Idle,
    Pending(String),
    Found(ResolutionResult),
    Failed(Diagnostic),
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvePrompt {
    pub(crate) input: LineInput,
    pub(crate) lookup: Lookup,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum ResolveAction {
    Stay,
    Close,
    Lookup(String),
}

impl ResolvePrompt {
    pub(crate) fn new() -> Self {
        Self {
            input: LineInput::default(),
            lookup: Lookup::Idle,
        }
    }

    pub(crate) fn on_key(&mut self, key: KeyEvent) -> ResolveAction {
        match key.code {
            KeyCode::Esc => ResolveAction::Close,
            KeyCode::Enter if !self.input.is_blank() => {
                let name = self.input.trimmed();
                self.lookup = Lookup::Pending(name.clone());
                ResolveAction::Lookup(name)
            }
            _ => {
                self.input.edit(key);
                ResolveAction::Stay
            }
        }
    }

    pub(crate) fn accept(&mut self, result: Result<ResolutionResult, Diagnostic>) {
        if matches!(self.lookup, Lookup::Pending(_)) {
            self.lookup = match result {
                Ok(resolution) => Lookup::Found(resolution),
                Err(diagnostic) => Lookup::Failed(diagnostic),
            };
        }
    }
}
