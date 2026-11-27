// SPDX-License-Identifier: GPL-3.0-or-later
//! Keys while browsing the mapping table or typing a filter.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use remap_protocol::Change;

use crate::form::Form;
use crate::model::{Mode, Model, Notice};
use crate::resolve::ResolvePrompt;
use crate::update::Effect;
use crate::write;

const NOTHING_SELECTED: &str = "Nothing is selected. Press n to create a mapping.";

/// The status line while an owner-requested refresh runs.
pub(crate) const REFRESHING: &str = "Refreshing from the daemon.";

/// The longest filter kept.
pub(crate) const MAX_FILTER_CHARS: usize = 256;

/// Keys in the table. The mode has already been reset to browsing.
pub(crate) fn on_key(model: &mut Model, key: KeyEvent) -> Vec<Effect> {
    let page = isize::try_from(model.table_rows().max(1)).unwrap_or(isize::MAX);
    match key.code {
        KeyCode::Up => model.move_by(-1),
        KeyCode::Down => model.move_by(1),
        KeyCode::PageUp => model.move_by(-page),
        KeyCode::PageDown => model.move_by(page),
        KeyCode::Home => model.move_by(isize::MIN),
        KeyCode::End => model.move_by(isize::MAX),
        KeyCode::Esc => escape(model),
        KeyCode::Char(character) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
            return on_character(model, character);
        }
        _ => {}
    }
    Vec::new()
}

fn escape(model: &mut Model) {
    if model.filter.is_empty() {
        model.quit = true;
    } else {
        model.filter.clear();
        model.reselect();
    }
}

fn on_character(model: &mut Model, character: char) -> Vec<Effect> {
    match character {
        'k' => model.move_by(-1),
        'j' => model.move_by(1),
        'q' => model.quit = true,
        '/' => model.mode = Mode::Filter,
        '?' => model.mode = Mode::Help,
        'a' => toggle_disabled(model),
        'n' => return open_form(model, Form::create()),
        'e' => return edit_selected(model),
        ' ' => return toggle_selected(model),
        'd' => return remove_selected(model),
        'r' => model.mode = Mode::Resolve(Box::new(ResolvePrompt::new())),
        'g' => {
            model.notice = Some(Notice::info(REFRESHING));
            return model.request_refresh();
        }
        _ => {}
    }
    Vec::new()
}

fn toggle_disabled(model: &mut Model) {
    model.show_disabled = !model.show_disabled;
    model.notice = Some(Notice::info(if model.show_disabled {
        "Showing every mapping, on and off."
    } else {
        "Showing only mappings that are on. Press a to show all."
    }));
    model.reselect();
}

fn open_form(model: &mut Model, mut form: Form) -> Vec<Effect> {
    let effects = model.check_form(&mut form);
    model.mode = Mode::Form(Box::new(form));
    effects
}

fn edit_selected(model: &mut Model) -> Vec<Effect> {
    let Some(mapping) = model.selected().cloned() else {
        model.notice = Some(Notice::warning(NOTHING_SELECTED));
        return Vec::new();
    };
    open_form(model, Form::edit(&mapping))
}

fn toggle_selected(model: &mut Model) -> Vec<Effect> {
    let Some(mapping) = model.selected().cloned() else {
        model.notice = Some(Notice::warning(NOTHING_SELECTED));
        return Vec::new();
    };
    let pattern = mapping.pattern.clone();
    let (title, change) = if mapping.enabled {
        (
            format!("Turn off {pattern}"),
            Change::Disable {
                pattern: pattern.clone(),
            },
        )
    } else {
        (
            format!("Turn on {pattern}"),
            Change::Enable {
                pattern: pattern.clone(),
            },
        )
    };
    write::begin(model, title, vec![change], None, Some(pattern))
}

fn remove_selected(model: &mut Model) -> Vec<Effect> {
    let Some(mapping) = model.selected().cloned() else {
        model.notice = Some(Notice::warning(NOTHING_SELECTED));
        return Vec::new();
    };
    let title = format!("Remove {}", mapping.pattern);
    let change = Change::Remove {
        pattern: mapping.pattern,
    };
    write::begin(model, title, vec![change], None, None)
}

/// Keys while typing a filter. The mode has already been reset to browsing.
pub(crate) fn on_filter_key(model: &mut Model, key: KeyEvent) -> Vec<Effect> {
    let control = key.modifiers.contains(KeyModifiers::CONTROL);
    match key.code {
        KeyCode::Enter => return Vec::new(),
        KeyCode::Esc => model.filter.clear(),
        KeyCode::Backspace => {
            model.filter.pop();
        }
        KeyCode::Char('u') if control => model.filter.clear(),
        KeyCode::Char(character) if !control && model.filter.chars().count() < MAX_FILTER_CHARS => {
            model.filter.push(character);
        }
        KeyCode::Up => model.move_by(-1),
        KeyCode::Down => model.move_by(1),
        _ => {}
    }
    if key.code != KeyCode::Esc {
        model.mode = Mode::Filter;
    }
    model.reselect();
    Vec::new()
}
