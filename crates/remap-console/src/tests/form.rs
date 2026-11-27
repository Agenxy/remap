// SPDX-License-Identifier: GPL-3.0-or-later
//! The mapping form and its live validation.

use crossterm::event::KeyCode;
use remap_protocol::{Change, HostPolicy, ValidationResult};

use super::support::{TestResult, diagnostic, key, loaded, none, press, type_text};
use crate::form::Check;
use crate::model::{Mode, Model};
use crate::update::{Effect, Event, Outcome, update};

fn form(model: &Model) -> Option<&crate::form::Form> {
    match &model.mode {
        Mode::Form(form) => Some(form),
        _ => None,
    }
}

fn last_seq(effects: &[Effect]) -> Option<u64> {
    effects.iter().rev().find_map(|effect| match effect {
        Effect::Validate { seq, .. } => Some(*seq),
        _ => None,
    })
}

fn validated(seq: u64, result: Result<ValidationResult, remap_protocol::Diagnostic>) -> Event {
    Event::Outcome(Box::new(Outcome::Validated { seq, result }))
}

fn canonical(pattern: &str, target: &str, warnings: Vec<String>) -> ValidationResult {
    ValidationResult {
        warnings,
        landing: None,
        pattern: pattern.to_owned(),
        target: target.to_owned(),
        target_kind: "http".to_owned(),
        host_policy: HostPolicy::UseUpstream,
    }
}

#[test]
fn a_new_form_validates_once_complete_and_previews_on_enter() -> TestResult {
    let mut model = loaded();
    assert_eq!(
        press(&mut model, 'n'),
        none(),
        "an empty form is not validated"
    );
    assert_eq!(type_text(&mut model, "App.Test"), none(), "no target yet");
    update(&mut model, key(KeyCode::Tab));
    let effects = type_text(&mut model, "http://127.0.0.1:3000/");
    assert!(
        effects.iter().all(|e| matches!(e, Effect::Validate { .. })),
        "{effects:?}"
    );
    update(&mut model, key(KeyCode::Tab));
    let effects = update(&mut model, key(KeyCode::Right));
    let Some(Effect::Validate {
        seq,
        pattern,
        target,
        host_policy,
        landing,
    }) = effects.last().cloned()
    else {
        return Err(
            format!("toggling the default use-upstream policy revalidates: {effects:?}").into(),
        );
    };
    assert_eq!(pattern, "App.Test");
    assert_eq!(target, "http://127.0.0.1:3000/");
    assert_eq!(host_policy, HostPolicy::PreserveClient);
    assert_eq!(landing, None);
    update(&mut model, key(KeyCode::Tab));
    type_text(&mut model, "/app");
    update(
        &mut model,
        validated(
            seq,
            Ok(canonical("app.test", "http://127.0.0.1:3000/", Vec::new())),
        ),
    );
    assert!(
        form(&model).is_some_and(|form| form.check == Check::Waiting),
        "an answer to an older check is ignored"
    );
    let effects = update(&mut model, key(KeyCode::Enter));
    assert_eq!(
        effects,
        vec![Effect::Preview {
            seq: 1,
            changes: vec![Change::Set {
                pattern: "App.Test".to_owned(),
                target: "http://127.0.0.1:3000/".to_owned(),
                host_policy: HostPolicy::PreserveClient,
                enabled: None,
                landing: Some("/app".to_owned()),
            }]
        }]
    );
    Ok(())
}

#[test]
fn validation_shows_the_canonical_form_or_the_daemons_refusal() {
    let mut model = loaded();
    press(&mut model, 'n');
    type_text(&mut model, "app.test");
    update(&mut model, key(KeyCode::Tab));
    let effects = type_text(&mut model, "http://x/");
    let seq = last_seq(&effects).unwrap_or_default();
    let valid = canonical(
        "app.test",
        "http://x/",
        vec!["target refused connection".to_owned()],
    );
    update(&mut model, validated(seq, Ok(valid.clone())));
    assert_eq!(
        form(&model).map(|form| form.check.clone()),
        Some(Check::Valid(valid))
    );
    let effects = type_text(&mut model, "!");
    let seq = last_seq(&effects).unwrap_or_default();
    let refusal = diagnostic("E_INVALID_TARGET", false);
    update(&mut model, validated(seq, Err(refusal.clone())));
    assert_eq!(
        form(&model).map(|form| form.check.clone()),
        Some(Check::Invalid(refusal))
    );
}

#[test]
fn an_incomplete_form_is_not_submitted() {
    let mut model = loaded();
    press(&mut model, 'n');
    type_text(&mut model, "app.test");
    assert_eq!(update(&mut model, key(KeyCode::Enter)), none());
    assert!(form(&model).is_some(), "the form stays open");
    assert!(
        model
            .notice()
            .is_some_and(|notice| notice.contains("required"))
    );
    update(&mut model, key(KeyCode::Esc));
    assert!(matches!(model.mode, Mode::Browse));
}

#[test]
fn editing_keeps_the_pattern_and_preserves_the_state() {
    let mut model = loaded();
    let effects = press(&mut model, 'e');
    assert!(
        matches!(effects.as_slice(), [Effect::Validate { .. }]),
        "{effects:?}"
    );
    type_text(&mut model, ":8080");
    let effects = update(&mut model, key(KeyCode::Enter));
    assert_eq!(
        effects,
        vec![Effect::Preview {
            seq: 1,
            changes: vec![Change::Set {
                pattern: "api.test".to_owned(),
                target: "127.0.0.1:8080".to_owned(),
                host_policy: HostPolicy::PreserveClient,
                enabled: None,
                landing: None,
            }]
        }]
    );
}

#[test]
fn renaming_removes_the_old_pattern_and_keeps_its_state() {
    let mut model = loaded();
    press(&mut model, 'j');
    press(&mut model, 'e');
    update(&mut model, key(KeyCode::BackTab));
    update(&mut model, key(KeyCode::Home));
    type_text(&mut model, "new");
    let effects = update(&mut model, key(KeyCode::Enter));
    assert_eq!(
        effects,
        vec![Effect::Preview {
            seq: 1,
            changes: vec![
                Change::Remove {
                    pattern: "db.test".to_owned()
                },
                Change::Set {
                    pattern: "newdb.test".to_owned(),
                    target: "10.0.0.5".to_owned(),
                    host_policy: HostPolicy::PreserveClient,
                    enabled: Some(false),
                    landing: None,
                },
            ]
        }]
    );
}

#[test]
fn paste_fills_the_focused_field() {
    let mut model = loaded();
    press(&mut model, 'n');
    update(&mut model, Event::Paste("paste.test\n".to_owned()));
    assert_eq!(
        form(&model).map(|form| form.pattern.value()),
        Some("paste.test".to_owned())
    );
}
