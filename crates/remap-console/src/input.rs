// SPDX-License-Identifier: GPL-3.0-or-later
//! One line of editable text.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use remap_protocol::MAX_TARGET_BYTES;

/// The longest input kept; the daemon refuses longer targets anyway.
const MAX_INPUT_CHARS: usize = MAX_TARGET_BYTES;

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub(crate) struct LineInput {
    chars: Vec<char>,
    cursor: usize,
}

impl LineInput {
    pub(crate) fn with(text: &str) -> Self {
        let mut input = Self::default();
        input.insert_str(text);
        input
    }

    pub(crate) fn value(&self) -> String {
        self.chars.iter().collect()
    }

    /// The value without surrounding whitespace.
    pub(crate) fn trimmed(&self) -> String {
        self.value().trim().to_owned()
    }

    pub(crate) fn is_blank(&self) -> bool {
        self.chars.iter().all(|c| c.is_whitespace())
    }

    /// Inserts printable text at the cursor and reports whether it changed.
    pub(crate) fn insert_str(&mut self, text: &str) -> bool {
        let mut changed = false;
        for character in text.chars().filter(|c| !c.is_control()) {
            changed |= self.insert(character);
        }
        changed
    }

    fn insert(&mut self, character: char) -> bool {
        if self.chars.len() >= MAX_INPUT_CHARS {
            return false;
        }
        self.chars.insert(self.cursor, character);
        self.cursor += 1;
        true
    }

    /// Applies an editing key. `None` means the key is not an editing key;
    /// `Some(changed)` says whether the text changed.
    pub(crate) fn edit(&mut self, key: KeyEvent) -> Option<bool> {
        let control = key.modifiers.contains(KeyModifiers::CONTROL);
        let changed = match key.code {
            KeyCode::Char('u') if control => {
                let had_text = !self.chars.is_empty();
                self.chars.clear();
                self.cursor = 0;
                had_text
            }
            KeyCode::Char(character) if !control => self.insert(character),
            KeyCode::Backspace => self.backspace(),
            KeyCode::Delete => self.delete(),
            KeyCode::Left => self.place(self.cursor.saturating_sub(1)),
            KeyCode::Right => self.place(self.cursor + 1),
            KeyCode::Home => self.place(0),
            KeyCode::End => self.place(self.chars.len()),
            _ => return None,
        };
        Some(changed)
    }

    fn place(&mut self, cursor: usize) -> bool {
        self.cursor = cursor.min(self.chars.len());
        false
    }

    fn backspace(&mut self) -> bool {
        if self.cursor == 0 {
            return false;
        }
        self.cursor -= 1;
        self.chars.remove(self.cursor);
        true
    }

    fn delete(&mut self) -> bool {
        if self.cursor >= self.chars.len() {
            return false;
        }
        self.chars.remove(self.cursor);
        true
    }

    /// The part of the text that fits `width` columns with the cursor in
    /// view, and the cursor's column within it.
    pub(crate) fn window(&self, width: usize) -> (String, usize) {
        let width = width.max(1);
        let start = (self.cursor + 1).saturating_sub(width);
        let shown = self.chars.iter().skip(start).take(width).collect();
        (shown, self.cursor - start)
    }
}

#[cfg(test)]
mod tests {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    use super::LineInput;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn edits_at_the_cursor() {
        let mut input = LineInput::with("api.test");
        assert_eq!(input.edit(key(KeyCode::Home)), Some(false));
        assert_eq!(input.edit(key(KeyCode::Char('x'))), Some(true));
        assert_eq!(input.edit(key(KeyCode::Delete)), Some(true));
        assert_eq!(input.value(), "xpi.test");
        assert_eq!(input.edit(key(KeyCode::End)), Some(false));
        assert_eq!(input.edit(key(KeyCode::Backspace)), Some(true));
        assert_eq!(input.value(), "xpi.tes");
        let clear = KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL);
        assert_eq!(input.edit(clear), Some(true));
        assert!(input.is_blank());
        assert_eq!(input.edit(key(KeyCode::Tab)), None);
    }

    #[test]
    fn paste_drops_control_characters_and_windows_follow_the_cursor() {
        let mut input = LineInput::default();
        assert!(input.insert_str("abc\ndef\t"));
        assert_eq!(input.value(), "abcdef");
        assert_eq!(input.window(4), ("def".to_owned(), 3));
        assert_eq!(input.window(10), ("abcdef".to_owned(), 6));
    }
}
