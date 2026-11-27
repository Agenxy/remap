// SPDX-License-Identifier: GPL-3.0-or-later
//! The new and edit mapping form, validated by the daemon as the owner types.

use crossterm::event::{KeyCode, KeyEvent};
use remap_protocol::{Change, Diagnostic, HostPolicy, MappingView, ValidationResult};

use crate::input::LineInput;
use crate::update::Effect;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum Field {
    Pattern,
    Target,
    HostPolicy,
    Landing,
}

impl Field {
    const ORDER: [Self; 4] = [Self::Pattern, Self::Target, Self::HostPolicy, Self::Landing];

    fn step(self, forward: bool) -> Self {
        let index = Self::ORDER
            .iter()
            .position(|field| *field == self)
            .unwrap_or(0);
        let next = if forward { index + 1 } else { index + 3 };
        Self::ORDER[next % Self::ORDER.len()]
    }
}

/// The daemon's latest judgement of the form.
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum Check {
    Incomplete,
    Waiting,
    Valid(ValidationResult),
    Invalid(Diagnostic),
}

#[derive(Debug, Clone)]
pub(crate) struct Form {
    pub(crate) original: Option<MappingView>,
    pub(crate) pattern: LineInput,
    pub(crate) target: LineInput,
    pub(crate) landing: LineInput,
    pub(crate) host_policy: HostPolicy,
    pub(crate) focus: Field,
    pub(crate) check: Check,
    check_seq: u64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum FormAction {
    Stay,
    Changed,
    Submit,
    Cancel,
}

impl Form {
    pub(crate) fn create() -> Self {
        Self {
            original: None,
            pattern: LineInput::default(),
            target: LineInput::default(),
            landing: LineInput::default(),
            // The same default as `remap set` and the MCP tools.
            host_policy: HostPolicy::UseUpstream,
            focus: Field::Pattern,
            check: Check::Incomplete,
            check_seq: 0,
        }
    }

    pub(crate) fn edit(mapping: &MappingView) -> Self {
        Self {
            original: Some(mapping.clone()),
            pattern: LineInput::with(&mapping.pattern),
            target: LineInput::with(&mapping.target),
            landing: LineInput::with(mapping.landing.as_deref().unwrap_or_default()),
            host_policy: mapping.host_policy,
            focus: Field::Target,
            check: Check::Incomplete,
            check_seq: 0,
        }
    }

    pub(crate) fn title(&self) -> String {
        match &self.original {
            Some(mapping) => format!("Edit {}", mapping.pattern),
            None => "New mapping".to_owned(),
        }
    }

    pub(crate) fn on_key(&mut self, key: KeyEvent) -> FormAction {
        match key.code {
            KeyCode::Esc => FormAction::Cancel,
            KeyCode::Enter => FormAction::Submit,
            KeyCode::Tab | KeyCode::Down => self.move_focus(true),
            KeyCode::BackTab | KeyCode::Up => self.move_focus(false),
            _ if self.focus == Field::HostPolicy => self.policy_key(key),
            _ => match self.focused_input().and_then(|input| input.edit(key)) {
                Some(true) => FormAction::Changed,
                _ => FormAction::Stay,
            },
        }
    }

    fn move_focus(&mut self, forward: bool) -> FormAction {
        self.focus = self.focus.step(forward);
        FormAction::Stay
    }

    fn policy_key(&mut self, key: KeyEvent) -> FormAction {
        match key.code {
            KeyCode::Left | KeyCode::Right | KeyCode::Char(' ') => {
                self.host_policy = match self.host_policy {
                    HostPolicy::PreserveClient => HostPolicy::UseUpstream,
                    HostPolicy::UseUpstream => HostPolicy::PreserveClient,
                };
                FormAction::Changed
            }
            _ => FormAction::Stay,
        }
    }

    fn focused_input(&mut self) -> Option<&mut LineInput> {
        match self.focus {
            Field::Pattern => Some(&mut self.pattern),
            Field::Target => Some(&mut self.target),
            Field::Landing => Some(&mut self.landing),
            Field::HostPolicy => None,
        }
    }

    /// Inserts pasted text into the focused field and reports whether it changed.
    pub(crate) fn paste(&mut self, text: &str) -> bool {
        self.focused_input()
            .is_some_and(|input| input.insert_str(text))
    }

    /// The validation to run for the form as it stands, if it is complete.
    pub(crate) fn request_check(&mut self, seq: u64) -> Option<Effect> {
        self.check_seq = seq;
        if self.pattern.is_blank() || self.target.is_blank() {
            self.check = Check::Incomplete;
            return None;
        }
        self.check = Check::Waiting;
        Some(Effect::Validate {
            seq,
            pattern: self.pattern.trimmed(),
            target: self.target.trimmed(),
            host_policy: self.host_policy,
            landing: self.landing_value(),
        })
    }

    /// Records the daemon's judgement unless a newer check is pending.
    pub(crate) fn accept_check(&mut self, seq: u64, result: Result<ValidationResult, Diagnostic>) {
        if seq != self.check_seq {
            return;
        }
        self.check = match result {
            Ok(validation) => Check::Valid(validation),
            Err(diagnostic) => Check::Invalid(diagnostic),
        };
    }

    fn landing_value(&self) -> Option<String> {
        (!self.landing.is_blank()).then(|| self.landing.trimmed())
    }

    /// The pattern the daemon will store: its canonical form once validated.
    pub(crate) fn focus_pattern(&self) -> String {
        match &self.check {
            Check::Valid(validation) => validation.pattern.clone(),
            _ => self.pattern.trimmed().to_lowercase(),
        }
    }

    fn renames(&self) -> Option<&MappingView> {
        let original = self.original.as_ref()?;
        let pattern = self.focus_pattern();
        let same = original.pattern.trim_end_matches('.') == pattern.trim_end_matches('.');
        (!same).then_some(original)
    }

    pub(crate) fn change_title(&self) -> String {
        match self.renames() {
            Some(original) => format!("Rename {} to {}", original.pattern, self.focus_pattern()),
            None => format!("Set {}", self.focus_pattern()),
        }
    }

    /// The change set the form describes. Renaming an existing mapping
    /// removes the old pattern and sets the new one, keeping its state.
    pub(crate) fn changes(&self) -> Result<Vec<Change>, &'static str> {
        if self.pattern.is_blank() || self.target.is_blank() {
            return Err("A pattern and a target are both required.");
        }
        let set = |enabled| Change::Set {
            pattern: self.pattern.trimmed(),
            target: self.target.trimmed(),
            host_policy: self.host_policy,
            enabled,
            landing: self.landing_value(),
        };
        Ok(match self.renames() {
            Some(original) => vec![
                Change::Remove {
                    pattern: original.pattern.clone(),
                },
                set(Some(original.enabled)),
            ],
            None => vec![set(None)],
        })
    }
}
