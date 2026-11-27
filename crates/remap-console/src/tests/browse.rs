// SPDX-License-Identifier: GPL-3.0-or-later
//! Navigation, filtering, the disabled toggle, refresh and quitting.

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use remap_protocol::Change;

use super::support::{key, loaded, mapping, none, press, snapshot, type_text};
use crate::model::{Connection, Model};
use crate::update::{Effect, Event, Watch, update};

fn selected(model: &Model) -> Option<&str> {
    model.selected().map(|mapping| mapping.pattern.as_str())
}

#[test]
fn arrows_and_vi_keys_move_within_the_table() {
    let mut model = loaded();
    assert_eq!(selected(&model), Some("api.test"));
    update(&mut model, key(KeyCode::Down));
    assert_eq!(selected(&model), Some("db.test"));
    press(&mut model, 'j');
    assert_eq!(selected(&model), Some("web.test"));
    press(&mut model, 'j');
    assert_eq!(selected(&model), Some("web.test"), "stops at the end");
    press(&mut model, 'k');
    update(&mut model, key(KeyCode::Up));
    update(&mut model, key(KeyCode::Up));
    assert_eq!(selected(&model), Some("api.test"), "stops at the start");
    update(&mut model, key(KeyCode::End));
    assert_eq!(selected(&model), Some("web.test"));
    update(&mut model, key(KeyCode::Home));
    assert_eq!(selected(&model), Some("api.test"));
}

#[test]
fn page_keys_move_by_the_visible_rows_and_scroll() {
    let mut model = Model::new(false);
    let many: Vec<_> = (0..40)
        .map(|index| mapping(&format!("host{index:02}.test"), "127.0.0.1", true))
        .collect();
    update(&mut model, snapshot(1, many));
    let rows = model.table_rows();
    assert!(rows > 3, "an 80x24 screen shows several rows, got {rows}");
    update(&mut model, key(KeyCode::PageDown));
    assert_eq!(model.cursor, rows);
    assert!(
        model.offset > 0,
        "the table scrolled to keep the selection visible"
    );
    update(&mut model, key(KeyCode::PageUp));
    assert_eq!(model.cursor, 0);
    assert_eq!(model.offset, 0);
}

#[test]
fn filter_matches_pattern_or_target_as_you_type() {
    let mut model = loaded();
    press(&mut model, '/');
    type_text(&mut model, "10.0");
    let shown: Vec<_> = model.visible().iter().map(|m| m.pattern.clone()).collect();
    assert_eq!(shown, ["db.test"], "matches the target");
    update(&mut model, key(KeyCode::Backspace));
    update(&mut model, key(KeyCode::Backspace));
    update(&mut model, key(KeyCode::Backspace));
    update(&mut model, key(KeyCode::Backspace));
    type_text(&mut model, "WEB");
    assert_eq!(
        selected(&model),
        Some("web.test"),
        "case-insensitive pattern match"
    );
    update(&mut model, key(KeyCode::Enter));
    assert_eq!(model.filter, "WEB", "Enter keeps the filter");
    press(&mut model, 'q');
    assert!(
        model.should_quit(),
        "q quits once the filter is no longer being typed"
    );
}

#[test]
fn escape_clears_a_filter_before_it_quits() {
    let mut model = loaded();
    press(&mut model, '/');
    type_text(&mut model, "api");
    update(&mut model, key(KeyCode::Enter));
    update(&mut model, key(KeyCode::Esc));
    assert_eq!(model.filter, "");
    assert!(!model.should_quit());
    update(&mut model, key(KeyCode::Esc));
    assert!(model.should_quit());
}

#[test]
fn typing_q_into_a_filter_does_not_quit_but_ctrl_c_always_does() {
    let mut model = loaded();
    press(&mut model, '/');
    press(&mut model, 'q');
    assert!(!model.should_quit());
    assert_eq!(model.filter, "q");
    let ctrl_c = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
    update(&mut model, Event::Key(ctrl_c));
    assert!(model.should_quit());
}

#[test]
fn key_releases_are_ignored() {
    let mut model = loaded();
    let release = KeyEvent::new_with_kind(KeyCode::Down, KeyModifiers::NONE, KeyEventKind::Release);
    update(&mut model, Event::Key(release));
    assert_eq!(selected(&model), Some("api.test"));
}

#[test]
fn a_toggles_mappings_that_are_off() {
    let mut model = loaded();
    assert_eq!(model.visible().len(), 3, "every mapping shows by default");
    press(&mut model, 'j');
    assert_eq!(selected(&model), Some("db.test"));
    press(&mut model, 'a');
    let shown: Vec<_> = model.visible().iter().map(|m| m.pattern.clone()).collect();
    assert_eq!(shown, ["api.test", "web.test"]);
    assert_eq!(
        selected(&model),
        Some("web.test"),
        "the nearest row stays selected"
    );
    press(&mut model, 'a');
    assert_eq!(model.visible().len(), 3);
}

#[test]
fn selection_follows_its_pattern_across_refresh() {
    let mut model = loaded();
    press(&mut model, 'j');
    press(&mut model, 'j');
    assert_eq!(selected(&model), Some("web.test"));
    update(
        &mut model,
        snapshot(
            5,
            vec![
                mapping("aaa.test", "127.0.0.2", true),
                mapping("api.test", "127.0.0.1", true),
                mapping("db.test", "10.0.0.5", false),
                mapping("web.test", "192.168.1.9", true),
            ],
        ),
    );
    assert_eq!(selected(&model), Some("web.test"));
    assert_eq!(model.cursor, 3);
    update(
        &mut model,
        snapshot(6, vec![mapping("aaa.test", "127.0.0.2", true)]),
    );
    assert_eq!(
        selected(&model),
        Some("aaa.test"),
        "a vanished pattern falls back"
    );
}

#[test]
fn older_snapshots_never_replace_newer_ones() {
    let mut model = loaded();
    update(&mut model, snapshot(2, Vec::new()));
    assert_eq!(model.mappings().len(), 3);
    assert_eq!(model.revision(), Some(4));
}

#[test]
fn refreshes_coalesce_and_follow_the_watcher() {
    let mut model = loaded();
    assert_eq!(update(&mut model, Event::Watch(Watch::Revision(4))), none());
    assert_eq!(
        update(&mut model, Event::Watch(Watch::Revision(5))),
        vec![Effect::Refresh]
    );
    assert_eq!(press(&mut model, 'g'), none(), "one refresh at a time");
    assert_eq!(
        update(&mut model, snapshot(5, Vec::new())),
        vec![Effect::Refresh],
        "the refresh asked for meanwhile runs next"
    );
    assert_eq!(update(&mut model, snapshot(5, Vec::new())), none());
}

#[test]
fn an_unreachable_daemon_is_shown_and_a_recovery_rereads() {
    let mut model = loaded();
    let down = remap_protocol::Diagnostic::daemon_unavailable();
    update(&mut model, Event::Watch(Watch::Unreachable(down.clone())));
    assert_eq!(model.connection, Connection::Unreachable(down));
    assert!(!model.should_quit());
    assert_eq!(
        update(&mut model, Event::Watch(Watch::Revision(4))),
        vec![Effect::Refresh],
        "the same revision is reread after an outage"
    );
    update(&mut model, snapshot(4, Vec::new()));
    assert!(model.is_live());
}

#[test]
fn space_and_d_preview_the_selected_mapping() {
    let mut model = loaded();
    assert_eq!(
        press(&mut model, ' '),
        vec![Effect::Preview {
            seq: 1,
            changes: vec![Change::Disable {
                pattern: "api.test".to_owned()
            }]
        }]
    );
    update(&mut model, key(KeyCode::Esc));
    press(&mut model, 'j');
    assert_eq!(
        press(&mut model, ' '),
        vec![Effect::Preview {
            seq: 2,
            changes: vec![Change::Enable {
                pattern: "db.test".to_owned()
            }]
        }]
    );
    update(&mut model, key(KeyCode::Esc));
    assert_eq!(
        press(&mut model, 'd'),
        vec![Effect::Preview {
            seq: 3,
            changes: vec![Change::Remove {
                pattern: "db.test".to_owned()
            }]
        }]
    );
}

#[test]
fn actions_on_an_empty_table_explain_themselves() {
    let mut model = Model::new(false);
    for character in ['e', ' ', 'd'] {
        assert_eq!(press(&mut model, character), none());
        assert!(
            model
                .notice()
                .is_some_and(|notice| notice.contains("Nothing is selected"))
        );
    }
}

#[test]
fn help_opens_and_any_key_closes_it() {
    let mut model = loaded();
    press(&mut model, '?');
    assert!(matches!(model.mode, crate::model::Mode::Help));
    press(&mut model, 'x');
    assert!(matches!(model.mode, crate::model::Mode::Browse));
    assert!(!model.should_quit());
}

#[test]
fn resolve_looks_up_a_typed_name() {
    let mut model = loaded();
    press(&mut model, 'r');
    assert_eq!(
        update(&mut model, key(KeyCode::Enter)),
        none(),
        "a blank name is not sent"
    );
    type_text(&mut model, "api.test");
    assert_eq!(
        update(&mut model, key(KeyCode::Enter)),
        vec![Effect::Resolve {
            name: "api.test".to_owned()
        }]
    );
    update(&mut model, key(KeyCode::Esc));
    assert!(matches!(model.mode, crate::model::Mode::Browse));
}

#[test]
fn a_stop_signal_quits_from_any_mode() {
    let mut model = loaded();
    update(&mut model, Event::Stop);
    assert!(model.should_quit());
    let mut model = loaded();
    press(&mut model, 'n');
    type_text(&mut model, "q");
    assert!(!model.should_quit());
    update(&mut model, Event::Stop);
    assert!(model.should_quit(), "quits from the form");
    let mut model = loaded();
    press(&mut model, ' ');
    update(&mut model, Event::Stop);
    assert!(model.should_quit(), "quits while a preview is in flight");
}
