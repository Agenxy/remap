// SPDX-License-Identifier: GPL-3.0-or-later
//! Landing validation and durable round trips use the authority's wire surface.

use remap_protocol::{Command, CommandResult, Surface};
use remap_registry::Registry;
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn landing_registry_round_trip_and_replay() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("registry.sqlite");
    let command: Command = serde_json::from_value(json!({
        "kind": "apply", "expected_revision": 0,
        "operation_id": "c4d1f8c7-bd38-4a5a-a8ee-bb1f36cd2851",
        "changes": [{"kind": "set", "pattern": "landing.test", "target": "http://127.0.0.1:8792/",
            "host_policy": "use-upstream", "enabled": null, "landing": "/ops/scorecard/"}]
    }))?;
    let mut registry = Registry::open(&path)?;
    let receipt = registry.execute(command.clone(), Surface::Mcp)?;
    drop(registry);
    let mut registry = Registry::open(&path)?;
    assert_eq!(registry.execute(command, Surface::Mcp)?, receipt);
    let result = registry.execute(
        Command::Get {
            pattern: "landing.test".to_owned(),
        },
        Surface::Probe,
    )?;
    let CommandResult::Mapping(Some(mapping)) = result else {
        return Err("mapping missing".into());
    };
    assert_eq!(serde_json::to_value(mapping)?["landing"], "/ops/scorecard/");
    Ok(())
}

#[test]
fn landing_validation_refuses_unsafe_paths_and_non_root_or_dns_targets() -> TestResult {
    let mut registry = Registry::open_in_memory()?;
    for (target, landing) in [
        ("http://127.0.0.1/sub/", "/page"),
        ("127.0.0.1", "/page"),
        ("http://127.0.0.1/", "/"),
        ("http://127.0.0.1/", "/../page"),
        ("http://127.0.0.1/", "//host"),
        ("http://127.0.0.1/", "https://host/page"),
        ("http://127.0.0.1/", "/page\r\nheader"),
    ] {
        let command: Command = serde_json::from_value(json!({"kind": "validate",
            "pattern": "landing.test", "target": target, "host_policy": "use-upstream", "landing": landing}))?;
        let error = registry
            .execute(command, Surface::Probe)
            .err()
            .ok_or("unsafe landing accepted")?;
        assert_eq!(error.code, "E_INVALID_LANDING");
    }
    Ok(())
}

#[test]
fn landing_schema_migrates_v1_without_changing_old_receipts() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("registry.sqlite");
    let mut original = Registry::open(&path)?;
    let old_command: Command = serde_json::from_value(json!({
        "kind": "apply", "expected_revision": 0,
        "operation_id": "c4d1f8c7-bd38-4a5a-a8ee-bb1f36cd2851",
        "changes": [{"kind": "set", "pattern": "old.test", "target": "127.0.0.1",
            "host_policy": "use-upstream", "enabled": null}]
    }))?;
    let old_receipt = original.execute(old_command.clone(), Surface::Probe)?;
    drop(original);
    let connection = rusqlite::Connection::open(&path)?;
    connection
        .execute_batch("ALTER TABLE mappings DROP COLUMN landing; PRAGMA user_version = 1;")?;
    drop(connection);
    let mut registry = Registry::open(&path)?;
    assert_eq!(registry.execute(old_command, Surface::Probe)?, old_receipt);
    let CommandResult::Status(status) = registry.execute(Command::Status, Surface::Probe)? else {
        return Err("wrong status result".into());
    };
    assert_eq!(status.schema_version, 2);
    let connection = rusqlite::Connection::open(&path)?;
    let version: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    assert_eq!(
        version, 2,
        "older daemons must see a newer schema before reading records"
    );
    drop(registry);
    connection.pragma_update(None, "user_version", 3)?;
    assert_eq!(
        Registry::open(&path)
            .err()
            .ok_or("newer schema accepted")?
            .code,
        "E_REGISTRY_SCHEMA_NEWER"
    );
    Ok(())
}
