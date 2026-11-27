// SPDX-License-Identifier: GPL-3.0-or-later
use std::ffi::OsString;

use super::interfaces::WebAction;
use super::{Action, Invocation, ParseOutcome, parse};

fn arguments(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

fn action(values: &[&str]) -> Option<Action> {
    match parse(arguments(values)) {
        ParseOutcome::Run(Invocation { action, .. }) => Some(action),
        ParseOutcome::Display(_) | ParseOutcome::Failure { .. } => None,
    }
}

#[test]
fn console_parses_and_takes_the_global_data_directory() {
    assert_eq!(action(&["remap", "console"]), Some(Action::Console));
    let outcome = parse(arguments(&["remap", "console", "--data-dir", "/tmp/remap"]));
    assert!(matches!(
        outcome,
        ParseOutcome::Run(Invocation { action: Action::Console, data_dir: Some(directory), .. })
            if directory.as_os_str() == "/tmp/remap"
    ));
}

#[test]
fn web_defaults_to_an_ephemeral_port_and_no_extra_name() {
    assert_eq!(
        action(&["remap", "web"]),
        Some(Action::Web(WebAction {
            port: 0,
            name: None
        }))
    );
    assert_eq!(
        action(&["remap", "web", "--port", "7341", "--name", "remap.lab"]),
        Some(Action::Web(WebAction {
            port: 7341,
            name: Some("remap.lab".to_owned()),
        }))
    );
}

#[test]
fn web_refuses_port_zero_and_out_of_range_ports() {
    assert_eq!(action(&["remap", "web", "--port", "0"]), None);
    assert_eq!(action(&["remap", "web", "--port", "65536"]), None);
}

#[test]
fn interactive_interfaces_refuse_json_output() {
    for command in ["console", "web"] {
        let outcome = parse(arguments(&["remap", "--json", command]));
        assert!(matches!(
            outcome,
            ParseOutcome::Failure { diagnostic, json: true }
                if diagnostic.detail().contains("interactive")
        ));
    }
}

#[test]
fn help_explains_keys_confirmation_and_the_capability_address() {
    let console = parse(arguments(&["remap", "console", "--help"]));
    let web = parse(arguments(&["remap", "web", "--help"]));
    assert!(matches!(console, ParseOutcome::Display(text)
        if text.contains("previewed first") && text.contains("remap list")));
    assert!(matches!(web, ParseOutcome::Display(text)
        if text.contains("127.0.0.1 only")
            && text.contains("can change your mappings")
            && text.contains("DNS rebinding")));
}
