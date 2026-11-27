// SPDX-License-Identifier: GPL-3.0-or-later
//! Preview, confirm, apply: cancel, conflict, transport failure and receipts.

use crossterm::event::KeyCode;
use remap_protocol::{Change, Diagnostic};

use super::support::{
    TestResult, diagnostic, key, loaded, mapping, none, press, preview, receipt, snapshot,
    type_text,
};
use crate::model::{Mode, Model};
use crate::update::{Effect, Event, Outcome, update};
use crate::write::REVISION_CONFLICT;

fn previewed(seq: u64, base: u64) -> Event {
    Event::Outcome(Box::new(Outcome::Previewed {
        seq,
        result: Ok(preview(
            base,
            Some(mapping("api.test", "127.0.0.1", true)),
            Some(mapping("api.test", "127.0.0.1", false)),
        )),
    }))
}

/// The preview the current write flow waits for.
fn preview_seq(model: &Model) -> u64 {
    match &model.mode {
        Mode::Write(flow) => flow.preview_seq,
        _ => 0,
    }
}

/// Answers the current flow's preview with one at `base`.
fn answer_preview(model: &mut Model, base: u64) -> Vec<Effect> {
    let seq = preview_seq(model);
    update(model, previewed(seq, base))
}

fn preview_ids(effects: &[Effect]) -> Vec<u64> {
    effects
        .iter()
        .filter_map(|effect| match effect {
            Effect::Preview { seq, .. } => Some(*seq),
            _ => None,
        })
        .collect()
}

fn applied(operation_id: &str, result: Result<remap_protocol::ApplyResult, Diagnostic>) -> Event {
    Event::Outcome(Box::new(Outcome::Applied {
        operation_id: operation_id.to_owned(),
        result,
    }))
}

fn disable_api() -> Vec<Change> {
    vec![Change::Disable {
        pattern: "api.test".to_owned(),
    }]
}

/// Starts turning api.test off and confirms its preview at `base`.
fn confirm(model: &mut Model, base: u64) -> Result<(u64, String), Box<dyn std::error::Error>> {
    press(model, ' ');
    answer_preview(model, base);
    assert!(model.awaiting_confirmation().is_some());
    match press(model, 'y').as_slice() {
        [
            Effect::Apply {
                expected_revision,
                operation_id,
                changes,
            },
        ] => {
            assert_eq!(changes, &disable_api());
            Ok((*expected_revision, operation_id.clone()))
        }
        other => Err(format!("confirming applies once: {other:?}").into()),
    }
}

#[test]
fn confirmed_previews_apply_against_the_base_revision_with_a_fresh_uuid() -> TestResult {
    let mut model = loaded();
    let (expected, operation_id) = confirm(&mut model, 4)?;
    assert_eq!(expected, 4);
    let parsed = uuid::Uuid::parse_str(&operation_id)?;
    assert_eq!(parsed.get_version_num(), 4);
    let effects = update(
        &mut model,
        applied(&operation_id, Ok(receipt(&operation_id, 4))),
    );
    assert_eq!(effects, vec![Effect::Refresh]);
    assert!(matches!(model.mode, Mode::Browse));
    let notice = model.notice().unwrap_or_default();
    assert!(
        notice.contains("Applied Turn off api.test: changed, now revision 5 (was 4)"),
        "{notice}"
    );

    press(&mut model, ' ');
    answer_preview(&mut model, 5);
    let effects = press(&mut model, 'y');
    let second = match effects.as_slice() {
        [Effect::Apply { operation_id, .. }] => operation_id.clone(),
        other => return Err(format!("y applies too: {other:?}").into()),
    };
    assert_ne!(
        second, operation_id,
        "every confirmed write gets its own operation ID"
    );
    Ok(())
}

#[test]
fn n_or_escape_cancels_without_writing() {
    for cancel in [KeyCode::Char('n'), KeyCode::Esc] {
        let mut model = loaded();
        press(&mut model, ' ');
        answer_preview(&mut model, 4);
        assert_eq!(update(&mut model, key(cancel)), none());
        assert!(matches!(model.mode, Mode::Browse));
        assert!(
            model
                .notice()
                .is_some_and(|notice| notice.contains("Nothing was changed"))
        );
    }
}

#[test]
fn other_keys_leave_the_confirmation_waiting() {
    let mut model = loaded();
    press(&mut model, ' ');
    answer_preview(&mut model, 4);
    assert_eq!(press(&mut model, 'x'), none());
    assert_eq!(press(&mut model, 'q'), none());
    assert!(!model.should_quit());
    assert!(model.awaiting_confirmation().is_some());
}

#[test]
fn cancelling_a_form_write_returns_to_the_form() {
    let mut model = loaded();
    press(&mut model, 'e');
    update(&mut model, key(KeyCode::Enter));
    answer_preview(&mut model, 4);
    update(&mut model, key(KeyCode::Esc));
    assert!(matches!(model.mode, Mode::Form(_)));
}

#[test]
fn a_revision_conflict_rereads_and_previews_again_without_applying() -> TestResult {
    let mut model = loaded();
    let (_, operation_id) = confirm(&mut model, 4)?;
    let conflict = Diagnostic::new(
        REVISION_CONFLICT,
        "the registry is at revision 6",
        None,
        false,
    )
    .with_context("current_revision", "6");
    let effects = update(&mut model, applied(&operation_id, Err(conflict)));
    assert_eq!(
        effects,
        vec![
            Effect::Refresh,
            Effect::Preview {
                seq: 2,
                changes: disable_api()
            }
        ],
        "a conflict never retries the apply on its own"
    );
    let note = model.write_note().unwrap_or_default().to_owned();
    assert!(
        note.contains("changed elsewhere (now revision 6)"),
        "{note}"
    );
    assert!(
        model.awaiting_confirmation().is_none(),
        "waiting for the new preview"
    );
    answer_preview(&mut model, 6);
    assert_eq!(
        model.awaiting_confirmation().map(|p| p.base_revision),
        Some(6)
    );
    match press(&mut model, 'y').as_slice() {
        [
            Effect::Apply {
                expected_revision,
                operation_id: retry,
                ..
            },
        ] => {
            assert_eq!(*expected_revision, 6);
            assert_ne!(retry, &operation_id, "the new decision is a new operation");
        }
        other => return Err(format!("the owner confirms again: {other:?}").into()),
    }
    Ok(())
}

#[test]
fn a_transport_failure_retries_the_identical_request() -> TestResult {
    let mut model = loaded();
    let (expected, operation_id) = confirm(&mut model, 4)?;
    let lost = diagnostic("E_CONTROL_TRANSPORT", true);
    let effects = update(&mut model, applied(&operation_id, Err(lost)));
    assert_eq!(effects, vec![Effect::Refresh]);
    assert!(
        model.awaiting_confirmation().is_some(),
        "the owner decides whether to retry"
    );
    assert_eq!(
        update(&mut model, key(KeyCode::Enter)),
        none(),
        "Enter never retries"
    );
    assert_eq!(
        model.notice(),
        Some("Press y to retry the same request, n to stop.")
    );
    let retry = press(&mut model, 'y');
    assert_eq!(
        retry,
        vec![Effect::Apply {
            expected_revision: expected,
            operation_id: operation_id.clone(),
            changes: disable_api(),
        }]
    );
    update(
        &mut model,
        applied(&operation_id, Err(diagnostic("E_DAEMON_TIMEOUT", true))),
    );
    assert!(
        model.awaiting_confirmation().is_some(),
        "still uncertain after a second loss"
    );
    update(&mut model, key(KeyCode::Esc));
    assert!(matches!(model.mode, Mode::Browse));
    assert!(
        model
            .notice()
            .is_some_and(|notice| notice.contains("may have been committed"))
    );
    Ok(())
}

#[test]
fn a_refused_apply_is_shown_and_closes() -> TestResult {
    let mut model = loaded();
    let (_, operation_id) = confirm(&mut model, 4)?;
    update(
        &mut model,
        applied(&operation_id, Err(diagnostic("E_MAINTENANCE", false))),
    );
    assert!(model.awaiting_confirmation().is_none());
    update(&mut model, key(KeyCode::Enter));
    assert!(matches!(model.mode, Mode::Browse));
    let notice = model.notice().unwrap_or_default();
    assert!(
        notice.starts_with("Refused: It failed. Try again."),
        "{notice}"
    );
    Ok(())
}

#[test]
fn a_refused_preview_is_shown() {
    let mut model = loaded();
    press(&mut model, 'd');
    let refusal = Outcome::Previewed {
        seq: preview_seq(&model),
        result: Err(diagnostic("E_INVALID_PATTERN", false)),
    };
    update(&mut model, Event::Outcome(Box::new(refusal)));
    assert!(
        matches!(&model.mode, Mode::Write(flow) if matches!(flow.stage, crate::write::Stage::Refused(_)))
    );
}

#[test]
fn stale_answers_are_ignored_but_still_reread() -> TestResult {
    let mut model = loaded();
    let (_, operation_id) = confirm(&mut model, 4)?;
    let effects = update(&mut model, applied("another", Ok(receipt("another", 4))));
    assert_eq!(effects, vec![Effect::Refresh]);
    assert!(
        matches!(&model.mode, Mode::Write(flow) if matches!(flow.stage, crate::write::Stage::Applying { .. }))
    );
    update(
        &mut model,
        applied(&operation_id, Ok(receipt(&operation_id, 4))),
    );
    assert!(matches!(model.mode, Mode::Browse));
    Ok(())
}

#[test]
fn a_successful_set_selects_the_written_pattern_after_refresh() -> TestResult {
    let mut model = loaded();
    press(&mut model, 'n');
    type_text(&mut model, "Zed.Test");
    update(&mut model, key(KeyCode::Tab));
    type_text(&mut model, "10.1.1.1");
    update(&mut model, key(KeyCode::Enter));
    answer_preview(&mut model, 4);
    let effects = press(&mut model, 'y');
    let Some(Effect::Apply { operation_id, .. }) = effects.first() else {
        return Err(format!("confirming applies: {effects:?}").into());
    };
    let operation_id = operation_id.clone();
    assert_eq!(press(&mut model, 'x'), none(), "keys wait while applying");
    update(
        &mut model,
        applied(&operation_id, Ok(receipt(&operation_id, 4))),
    );
    let mut mappings = model.mappings().to_vec();
    mappings.push(mapping("zed.test", "10.1.1.1", true));
    update(&mut model, snapshot(5, mappings));
    assert_eq!(
        model.selected().map(|m| m.pattern.as_str()),
        Some("zed.test")
    );
    Ok(())
}

#[test]
fn enter_never_confirms_a_preview() {
    let mut model = loaded();
    press(&mut model, 'e');
    update(&mut model, key(KeyCode::Enter));
    answer_preview(&mut model, 4);
    assert_eq!(
        update(&mut model, key(KeyCode::Enter)),
        none(),
        "a doubled Enter from the form must not apply"
    );
    assert!(model.awaiting_confirmation().is_some());
    assert_eq!(model.notice(), Some(crate::write::PRESS_Y_TO_APPLY));
}

#[test]
fn a_late_preview_from_a_cancelled_flow_never_reaches_the_next_one() -> TestResult {
    let mut model = loaded();
    let first = preview_ids(&press(&mut model, 'd'));
    update(&mut model, key(KeyCode::Esc));
    press(&mut model, 'j');
    let second = preview_ids(&press(&mut model, 'd'));
    assert_eq!((first.len(), second.len()), (1, 1));
    assert_ne!(first, second);
    update(&mut model, previewed(first[0], 4));
    assert!(
        model.awaiting_confirmation().is_none(),
        "api.test's preview is not shown for the db.test removal"
    );
    assert_eq!(press(&mut model, 'y'), none(), "nothing to confirm yet");
    let removal = preview(4, Some(mapping("db.test", "10.0.0.5", false)), None);
    let answer = Outcome::Previewed {
        seq: second[0],
        result: Ok(removal),
    };
    update(&mut model, Event::Outcome(Box::new(answer)));
    assert_eq!(
        model
            .awaiting_confirmation()
            .map(|p| p.effects[0].pattern.clone()),
        Some("db.test".to_owned())
    );
    match press(&mut model, 'y').as_slice() {
        [Effect::Apply { changes, .. }] => assert_eq!(
            changes,
            &vec![Change::Remove {
                pattern: "db.test".to_owned()
            }]
        ),
        other => return Err(format!("y applies the db.test removal: {other:?}").into()),
    }
    Ok(())
}

#[test]
fn an_out_of_order_conflict_re_preview_is_ignored() -> TestResult {
    let mut model = loaded();
    let (_, first) = confirm(&mut model, 4)?;
    let conflict = || Err(Diagnostic::new(REVISION_CONFLICT, "moved", None, false));
    let again = preview_ids(&update(&mut model, applied(&first, conflict())));
    answer_preview(&mut model, 5);
    let second = match press(&mut model, 'y').as_slice() {
        [Effect::Apply { operation_id, .. }] => operation_id.clone(),
        other => return Err(format!("the owner confirms again: {other:?}").into()),
    };
    let latest = preview_ids(&update(&mut model, applied(&second, conflict())));
    assert_eq!((again.len(), latest.len()), (1, 1));
    update(&mut model, previewed(latest[0], 7));
    update(&mut model, previewed(again[0], 5));
    assert_eq!(
        model.awaiting_confirmation().map(|p| p.base_revision),
        Some(7),
        "the earlier re-preview arriving late changes nothing"
    );
    let mut model = loaded();
    let (_, operation_id) = confirm(&mut model, 4)?;
    let pending = preview_ids(&update(&mut model, applied(&operation_id, conflict())));
    update(&mut model, previewed(pending[0] - 1, 4));
    assert!(
        model.awaiting_confirmation().is_none(),
        "the original preview's ID does not satisfy the re-preview"
    );
    Ok(())
}
