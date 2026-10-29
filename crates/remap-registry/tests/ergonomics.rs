// SPDX-License-Identifier: GPL-3.0-or-later
//! Registry guidance remains advisory and moved-name graph changes are atomic.

use remap_protocol::{Command, CommandResult, Surface};
use remap_registry::Registry;
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn set(name: &str, target: &str) -> serde_json::Value {
    json!({"kind":"set", "pattern":name, "target":target, "host_policy":"use-upstream", "enabled":null})
}

#[test]
fn path_advice_is_present_only_for_pathful_targets_and_never_blocks_set() -> TestResult {
    let mut registry = Registry::open_in_memory()?;
    for (target, expected) in [
        ("http://127.0.0.1/", false),
        ("http://127.0.0.1/ops/scorecard/", true),
    ] {
        let command = serde_json::from_value(
            json!({"kind":"preview", "changes":[set("site.test", target)]}),
        )?;
        let CommandResult::Preview(result) = registry.execute(command, Surface::Mcp)? else {
            return Err("wrong result".into());
        };
        assert_eq!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("prefixed")),
            expected
        );
    }
    let command = serde_json::from_value(json!({"kind":"apply", "expected_revision":0,
        "operation_id":"c4d1f8c7-bd38-4a5a-a8ee-bb1f36cd2851", "changes":[set("site.test", "http://127.0.0.1/page/")]}))?;
    let CommandResult::Apply(result) = registry.execute(command, Surface::Mcp)? else {
        return Err("wrong result".into());
    };
    assert!(result.changed && !result.warnings.is_empty());
    Ok(())
}

#[test]
fn shared_origin_hint_does_not_change_the_host_policy() -> TestResult {
    let mut registry = Registry::open_in_memory()?;
    let command = serde_json::from_value(json!({"kind":"preview", "changes":[
        set("one.test", "http://127.0.0.1/"), set("two.test", "http://127.0.0.1:80/")]}))?;
    let CommandResult::Preview(result) = registry.execute(command, Surface::Probe)? else {
        return Err("wrong result".into());
    };
    assert!(
        result
            .warnings
            .iter()
            .any(|warning| warning.contains("preserve-client"))
    );
    assert!(result.effects.iter().all(|effect| {
        effect
            .after
            .as_ref()
            .is_some_and(|mapping| mapping.host_policy == remap_protocol::HostPolicy::UseUpstream)
    }));
    Ok(())
}

#[test]
fn moved_round_trip_expiry_and_reverse_chain_refusal() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("registry.sqlite");
    let mut registry = Registry::open(&path)?;
    let command = serde_json::from_value(json!({"kind":"apply", "expected_revision":0,
        "operation_id":"c4d1f8c7-bd38-4a5a-a8ee-bb1f36cd2851",
        "changes":[set("old.test", "moved://new.test?until=2000-01-01T00:00:00Z")]}))?;
    registry.execute(command, Surface::Probe)?;
    drop(registry);
    let mut registry = Registry::open(&path)?;
    let CommandResult::Resolution(result) = registry.execute(
        Command::Resolve {
            name: "old.test".to_owned(),
        },
        Surface::Probe,
    )?
    else {
        return Err("wrong result".into());
    };
    assert!(result.mapping.is_none());
    let CommandResult::Mapping(Some(mapping)) = registry.execute(
        Command::Get {
            pattern: "old.test".to_owned(),
        },
        Surface::Probe,
    )?
    else {
        return Err("expired record was removed".into());
    };
    assert_eq!(mapping.target_kind, "moved");
    assert_eq!(
        mapping.target,
        "moved://new.test?until=2000-01-01T00:00:00Z"
    );
    for changes in [
        vec![set("new.test", "moved://third.test")],
        vec![set("self.test", "moved://self.test")],
    ] {
        let command = serde_json::from_value(json!({"kind":"preview", "changes":changes}))?;
        assert_eq!(
            registry
                .execute(command, Surface::Probe)
                .err()
                .ok_or("chain accepted")?
                .code,
            "E_MOVED_CHAIN"
        );
    }
    assert_eq!(registry.revision(), 1);
    Ok(())
}
