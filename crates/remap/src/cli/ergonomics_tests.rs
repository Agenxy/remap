use std::ffi::OsString;

use super::{Action, ParseOutcome, parse};

fn action(arguments: &[&str]) -> Result<Action, Box<dyn std::error::Error>> {
    let ParseOutcome::Run(invocation) = parse(arguments.iter().map(OsString::from).collect())
    else {
        return Err("command refused".into());
    };
    Ok(invocation.action)
}

#[test]
fn tutorial_commands_match_the_cli_contract() -> Result<(), Box<dyn std::error::Error>> {
    let recipe = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/tutorials/name-a-local-site.md"),
    )?;
    for line in recipe.lines().filter(|line| line.starts_with("remap ")) {
        // The only quoted token is the wildcard pattern in these examples.
        let tokens = line
            .split_whitespace()
            .map(|token| token.trim_matches('\''))
            .collect::<Vec<_>>();
        let _action = action(&tokens)?;
    }
    Ok(())
}

#[test]
fn moved_cli_validates_the_new_name_expiry_and_conflicts() -> Result<(), Box<dyn std::error::Error>>
{
    let Action::Set {
        target,
        host_header_policy,
        ..
    } = action(&[
        "remap",
        "set",
        "old.test",
        "--moved-to",
        "NEW.test",
        "--until",
        "2030-01-01T00:00:00Z",
    ])?
    else {
        return Err("wrong action".into());
    };
    assert_eq!(target, "moved://new.test?until=2030-01-01T00:00:00Z");
    assert_eq!(
        host_header_policy,
        remap_core::HostHeaderPolicy::UseUpstream
    );
    for arguments in [
        vec!["remap", "set", "old.test", "--moved-to", "//evil"],
        vec![
            "remap",
            "set",
            "old.test",
            "http://127.0.0.1/",
            "--moved-to",
            "new.test",
        ],
        vec![
            "remap",
            "set",
            "old.test",
            "--moved-to",
            "new.test",
            "--landing",
            "/page",
        ],
        vec![
            "remap",
            "set",
            "old.test",
            "http://127.0.0.1/",
            "--until",
            "2030-01-01T00:00:00Z",
        ],
    ] {
        assert!(action(&arguments).is_err(), "accepted {arguments:?}");
    }
    Ok(())
}

#[test]
fn landing_cli_output_and_path_warning_are_visible() -> Result<(), Box<dyn std::error::Error>> {
    for (target, landing, warning) in [
        ("http://127.0.0.1/", true, false),
        ("http://127.0.0.1/page/", false, true),
    ] {
        let mut args = vec!["remap", "validate", "site.test", target];
        if landing {
            args.extend(["--landing", "/page"]);
        }
        let report = crate::app::execute(action(&args)?)?;
        let mut human = Vec::new();
        crate::output::write_report(&mut human, &report, false)?;
        let human = String::from_utf8(human)?;
        assert_eq!(human.contains("Landing"), landing);
        assert_eq!(human.contains("Advisory"), warning);
        let mut encoded = Vec::new();
        crate::output::write_report(&mut encoded, &report, true)?;
        let result: serde_json::Value = serde_json::from_slice(&encoded)?;
        assert_eq!(result["result"]["host_header_policy"], "use-upstream");
        assert_eq!(
            !result["result"]["warnings"]
                .as_array()
                .ok_or("warnings missing")?
                .is_empty(),
            warning
        );
    }
    Ok(())
}
