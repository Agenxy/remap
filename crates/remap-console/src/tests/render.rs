// SPDX-License-Identifier: GPL-3.0-or-later
//! The view at 80x24 and narrower, rendered with ratatui's test backend.

use std::collections::BTreeMap;

use crossterm::event::KeyCode;
use remap_protocol::{Diagnostic, DnsTurnedOff, PeerMachineListenerFailure, PeerMachineListeners};

use super::support::{
    TestResult, key, loaded, mapping, press, preview, render, screen_contains, type_text,
};
use crate::model::Model;
use crate::update::{Event, Outcome, Watch, update};

fn assert_screen(rows: &[String], needle: &str) {
    assert!(
        screen_contains(rows, needle),
        "expected {needle:?} on screen:\n{}",
        rows.join("\n")
    );
}

fn with_problems() -> Model {
    let mut model = loaded();
    if let Some(status) = model.status.as_mut() {
        status.maintenance = Some(Diagnostic::new(
            "E_RETENTION",
            "journal retention is blocked",
            Some("free disk space".to_owned()),
            true,
        ));
        status.dns_turned_off = Some(Box::new(DnsTurnedOff {
            turned_off_at: "2026-10-31T01:20Z".to_owned(),
            turned_off_at_ms: 0,
            command: "remap-system deactivate".to_owned(),
            turn_on: "sudo remap-system activate".to_owned(),
        }));
        status.peer_machine_listeners = Some(Box::new(PeerMachineListeners {
            listening: 1,
            not_listening: 1,
            failures: vec![PeerMachineListenerFailure {
                pattern: "box.test".to_owned(),
                service: "ssh".to_owned(),
                address: "127.77.0.2".to_owned(),
                port: 22,
                cause: "port-in-use".to_owned(),
                detail: "another program holds the port".to_owned(),
            }],
            refusals: BTreeMap::new(),
        }));
    }
    model
}

#[test]
fn the_main_screen_fits_80_by_24() -> TestResult {
    let rows = render(&loaded(), 80, 24)?;
    assert_eq!(rows.len(), 24);
    assert_screen(
        &rows,
        "Remap console  revision 4  3 mappings, 2 on  daemon 0.2.0",
    );
    for needle in ["Pattern", "Target", "Kind", "State", "Host policy"] {
        assert_screen(&rows, needle);
    }
    assert_screen(&rows, "> api.test");
    assert_screen(&rows, "preserve-client");
    let db = rows
        .iter()
        .find(|row| row.contains("db.test"))
        .cloned()
        .unwrap_or_default();
    assert!(db.contains(" off "), "{db}");
    let web = rows
        .iter()
        .find(|row| row.contains("web.test"))
        .cloned()
        .unwrap_or_default();
    assert!(web.contains(" on "), "{web}");
    assert_screen(&rows, "Target: 127.0.0.1");
    assert_screen(&rows, "Landing: none");
    assert_screen(&rows, "Updated: revision 1");
    assert_screen(&rows, "? help  q quit  n new");
    Ok(())
}

#[test]
fn status_problems_are_spelled_out() -> TestResult {
    let rows = render(&with_problems(), 80, 24)?;
    assert_screen(&rows, "Maintenance: Journal retention is blocked.");
    assert_screen(&rows, "New changes are blocked.");
    assert_screen(&rows, "DNS turned off by the owner at 2026-10-31T01:20Z");
    assert_screen(&rows, "sudo remap-system activate");
    assert_screen(&rows, "Peer listeners: 1 not listening");
    assert_screen(&rows, "> api.test");
    Ok(())
}

#[test]
fn upstream_dns_and_an_unreachable_daemon_are_spelled_out() -> TestResult {
    let mut model = loaded();
    if let Some(status) = model.status.as_mut() {
        status.dns_upstream = Some(Diagnostic::new(
            "E_DNS_UPSTREAM",
            "no upstream resolver answered",
            None,
            true,
        ));
    }
    let down = Diagnostic::daemon_unavailable();
    update(&mut model, Event::Watch(Watch::Unreachable(down)));
    let rows = render(&model, 80, 24)?;
    assert_screen(
        &rows,
        "Daemon unreachable: The Remap daemon is not reachable.",
    );
    assert_screen(&rows, "Retrying in the background.");
    assert_screen(
        &rows,
        "Upstream DNS not answering: No upstream resolver answered.",
    );
    Ok(())
}

#[test]
fn narrow_screens_drop_columns_but_keep_state_words() -> TestResult {
    let mut model = loaded();
    update(
        &mut model,
        Event::Resize {
            width: 40,
            height: 16,
        },
    );
    let rows = render(&model, 40, 16)?;
    assert_screen(&rows, "revision 4  3 mappings, 2 on");
    assert!(!screen_contains(&rows, "Host policy"));
    let db = rows
        .iter()
        .find(|row| row.contains("db.test"))
        .cloned()
        .unwrap_or_default();
    assert!(db.contains("off"), "{db}");
    assert_screen(&rows, "? help  q quit");
    let rows = render(&model, 60, 12)?;
    assert_screen(&rows, "Target");
    assert!(!screen_contains(&rows, "Kind"));
    Ok(())
}

#[test]
fn wide_screens_put_the_detail_beside_the_table() -> TestResult {
    let mut model = loaded();
    if let Some(first) = model.mappings.first_mut() {
        first.peer_address = Some("127.77.0.9".to_owned());
        first.landing = Some("/app".to_owned());
    }
    update(
        &mut model,
        Event::Resize {
            width: 120,
            height: 30,
        },
    );
    let rows = render(&model, 120, 30)?;
    assert_screen(&rows, "Peer address: 127.77.0.9");
    assert_screen(&rows, "Landing: /app");
    assert_screen(&rows, "Host policy: preserve-client");
    Ok(())
}

#[test]
fn tiny_screens_render_without_panicking() -> TestResult {
    let model = with_problems();
    for (width, height) in [(1, 1), (10, 3), (20, 5), (30, 8)] {
        let rows = render(&model, width, height)?;
        assert_eq!(rows.len(), usize::from(height));
    }
    Ok(())
}

#[test]
fn the_confirm_dialog_shows_before_after_and_advisories() -> TestResult {
    let mut model = loaded();
    press(&mut model, ' ');
    let rows = render(&model, 80, 24)?;
    assert_screen(&rows, "Asking the daemon for a preview.");
    let preview = preview(
        4,
        Some(mapping("api.test", "127.0.0.1", true)),
        Some(mapping("api.test", "127.0.0.1", false)),
    );
    let seq = match &model.mode {
        crate::model::Mode::Write(flow) => flow.preview_seq,
        _ => 0,
    };
    update(
        &mut model,
        Event::Outcome(Box::new(Outcome::Previewed {
            seq,
            result: Ok(preview),
        })),
    );
    let rows = render(&model, 80, 24)?;
    assert_screen(&rows, "Turn off api.test");
    assert_screen(
        &rows,
        "Preview against revision 4. This changes the registry.",
    );
    assert_screen(&rows, "updated api.test");
    assert_screen(&rows, "before: 127.0.0.1 (ip, preserve-client, on)");
    assert_screen(&rows, "after:  127.0.0.1 (ip, preserve-client, off)");
    assert_screen(&rows, "Advisory: target refused connection");
    assert_screen(&rows, "y apply   n or Esc cancel");
    Ok(())
}

#[test]
fn the_form_help_and_resolve_dialogs_render() -> TestResult {
    let mut model = loaded();
    press(&mut model, 'n');
    type_text(&mut model, "app.test");
    let rows = render(&model, 80, 24)?;
    assert_screen(&rows, "New mapping");
    assert_screen(&rows, "> Pattern       app.test");
    assert_screen(&rows, "( ) preserve-client  (x) use-upstream");
    assert_screen(&rows, "Landing       (optional)");
    assert_screen(&rows, "Enter a pattern and a target.");
    update(&mut model, key(KeyCode::Esc));
    press(&mut model, '?');
    let rows = render(&model, 80, 24)?;
    assert_screen(&rows, "Turn the selected mapping on or off");
    assert_screen(&rows, "Ctrl-C");
    press(&mut model, 'x');
    press(&mut model, 'r');
    type_text(&mut model, "api.test");
    let rows = render(&model, 80, 24)?;
    assert_screen(&rows, "Resolve a name");
    assert_screen(&rows, "> Name          api.test");
    Ok(())
}

#[test]
fn the_filter_line_replaces_the_footer() -> TestResult {
    let mut model = loaded();
    press(&mut model, '/');
    type_text(&mut model, "web");
    let rows = render(&model, 80, 24)?;
    assert_screen(&rows, "Filter: web");
    assert_screen(&rows, "Mappings: 1 shown, filter \"web\"");
    Ok(())
}

#[test]
fn empty_registries_say_what_to_do() -> TestResult {
    let mut model = Model::new(false);
    let rows = render(&model, 80, 24)?;
    assert_screen(&rows, "Reading mappings from the daemon.");
    update(&mut model, super::support::snapshot(0, Vec::new()));
    let rows = render(&model, 80, 24)?;
    assert_screen(&rows, "No mappings yet. Press n to create one.");
    Ok(())
}

#[test]
fn a_target_wider_than_its_column_ends_in_an_ellipsis() -> TestResult {
    let mut model = Model::new(false);
    crate::update::start(&mut model);
    let long = "https://builds.internal.example:9443/very/long/path/";
    update(
        &mut model,
        super::support::snapshot(2, vec![mapping("builds.lab", long, true)]),
    );
    let rows = render(&model, 80, 24)?;
    let row = rows
        .iter()
        .find(|row| row.contains("> builds.lab"))
        .ok_or("the mapping's table row is on screen")?;
    assert!(
        row.contains("https://builds.internal…") && !row.contains(long),
        "the table cuts the target visibly: {row}"
    );
    assert_screen(&rows, long);
    Ok(())
}
