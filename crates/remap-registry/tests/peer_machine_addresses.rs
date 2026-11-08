// SPDX-License-Identifier: GPL-3.0-or-later
//! Each peer-machine mapping holds one stable loopback address while it
//! exists (ADR-0033): allocated lowest-first, kept across restarts, edits and
//! disable, and freed when the mapping goes.

use std::path::Path;

use remap_protocol::{ApplyResult, Command, CommandResult, Diagnostic, MappingView, Surface};
use remap_registry::Registry;
use serde_json::{Value, json};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const MACHINE: &str = "supgang://a8a37e32?ssh=22";

fn set(pattern: &str, target: &str) -> Value {
    json!({"kind": "set", "pattern": pattern, "target": target,
        "host_policy": "use-upstream", "enabled": null})
}

fn change(kind: &str, pattern: &str) -> Value {
    json!({"kind": kind, "pattern": pattern})
}

struct Owner {
    registry: Registry,
    operations: u64,
}

impl Owner {
    fn new(registry: Registry) -> Self {
        Self {
            registry,
            operations: 0,
        }
    }

    fn try_apply(&mut self, changes: &[Value]) -> Result<ApplyResult, Diagnostic> {
        self.operations += 1;
        let revision = match self.registry.execute(Command::Status, Surface::Probe)? {
            CommandResult::Status(status) => status.revision,
            _ => 0,
        };
        let command: Command = serde_json::from_value(json!({
            "kind": "apply", "expected_revision": revision,
            "operation_id": format!("00000000-0000-4000-8000-{:012x}", self.operations),
            "changes": changes,
        }))
        .map_err(|_| Diagnostic::new("E_TEST", "bad command", None, false))?;
        match self.registry.execute(command, Surface::Probe)? {
            CommandResult::Apply(receipt) => Ok(receipt),
            _ => Err(Diagnostic::new("E_TEST", "wrong result", None, false)),
        }
    }

    fn apply(&mut self, changes: &[Value]) -> Result<ApplyResult, Box<dyn std::error::Error>> {
        Ok(self.try_apply(changes)?)
    }

    fn get(&mut self, pattern: &str) -> Result<MappingView, Box<dyn std::error::Error>> {
        let command = Command::Get {
            pattern: pattern.to_owned(),
        };
        match self.registry.execute(command, Surface::Probe)? {
            CommandResult::Mapping(Some(view)) => Ok(view),
            other => Err(format!("{pattern}: {other:?}").into()),
        }
    }

    fn address(&mut self, pattern: &str) -> Result<String, Box<dyn std::error::Error>> {
        self.get(pattern)?
            .peer_address
            .ok_or_else(|| format!("{pattern} has no address").into())
    }
}

fn open(path: &Path) -> Result<Owner, Box<dyn std::error::Error>> {
    Ok(Owner::new(Registry::open(path)?))
}

#[test]
fn addresses_are_lowest_first_unique_and_survive_a_restart() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("registry.sqlite3");
    let mut owner = open(&path)?;
    owner.apply(&[
        set("pro.test", MACHINE),
        set("web.test", "http://127.0.0.1:8080"),
        set("air.test", "supgang://0b1c2d3e?ssh=22"),
    ])?;
    assert_eq!(owner.address("air.test")?, "127.77.0.2");
    assert_eq!(owner.address("pro.test")?, "127.77.0.1");
    assert_eq!(owner.get("web.test")?.peer_address, None);
    drop(owner);

    let mut reopened = open(&path)?;
    assert_eq!(reopened.address("pro.test")?, "127.77.0.1");
    assert_eq!(reopened.address("air.test")?, "127.77.0.2");
    let list: Command = serde_json::from_value(
        json!({"kind": "list", "after": null, "limit": 10, "include_disabled": true}),
    )?;
    let CommandResult::List(page) = reopened.registry.execute(list, Surface::Probe)? else {
        return Err("wrong list result".into());
    };
    assert_eq!(
        page.mappings
            .iter()
            .filter_map(|view| view.peer_address.as_deref())
            .collect::<Vec<_>>(),
        vec!["127.77.0.2", "127.77.0.1"]
    );
    Ok(())
}

#[test]
fn edits_disable_and_enable_keep_the_address() -> TestResult {
    let mut owner = Owner::new(Registry::open_in_memory()?);
    owner.apply(&[set("first.test", MACHINE), set("pro.test", MACHINE)])?;
    assert_eq!(owner.address("pro.test")?, "127.77.0.2");

    let other_peer = format!("supgang://{}?ssh=2222,k7=7443", "c".repeat(64));
    owner.apply(&[set("pro.test", &other_peer)])?;
    assert_eq!(owner.address("pro.test")?, "127.77.0.2");
    owner.apply(&[change("disable", "pro.test")])?;
    assert!(!owner.get("pro.test")?.enabled);
    assert_eq!(owner.address("pro.test")?, "127.77.0.2");
    // A disabled mapping's address is still its own.
    owner.apply(&[set("new.test", MACHINE)])?;
    assert_eq!(owner.address("new.test")?, "127.77.0.3");
    owner.apply(&[change("enable", "pro.test")])?;
    assert_eq!(owner.address("pro.test")?, "127.77.0.2");
    Ok(())
}

#[test]
fn removal_frees_the_address_for_the_next_mapping() -> TestResult {
    let mut owner = Owner::new(Registry::open_in_memory()?);
    owner.apply(&[
        set("one.test", MACHINE),
        set("two.test", MACHINE),
        set("three.test", MACHINE),
    ])?;
    owner.apply(&[change("remove", "two.test")])?;
    owner.apply(&[set("four.test", MACHINE)])?;
    assert_eq!(owner.address("four.test")?, "127.77.0.2");

    // Freed and taken again inside one atomic change set.
    let receipt = owner.apply(&[change("remove", "one.test"), set("five.test", MACHINE)])?;
    assert!(receipt.changed);
    assert_eq!(owner.address("five.test")?, "127.77.0.1");

    // A mapping that stops being a peer machine releases its address.
    owner.apply(&[set("three.test", "http://127.0.0.1:8080")])?;
    assert_eq!(owner.get("three.test")?.peer_address, None);
    owner.apply(&[set("six.test", MACHINE)])?;
    assert_eq!(owner.address("six.test")?, "127.77.0.3");
    Ok(())
}

#[test]
fn preview_shows_the_address_an_apply_would_allocate() -> TestResult {
    let mut owner = Owner::new(Registry::open_in_memory()?);
    owner.apply(&[set("one.test", MACHINE)])?;
    let preview: Command =
        serde_json::from_value(json!({"kind": "preview", "changes": [set("pro.test", MACHINE)]}))?;
    let CommandResult::Preview(result) = owner.registry.execute(preview, Surface::Probe)? else {
        return Err("wrong preview result".into());
    };
    let after = result.effects[0].after.as_ref().ok_or("no after")?;
    assert_eq!(after.peer_address.as_deref(), Some("127.77.0.2"));
    assert_eq!(after.target_kind, "peer-machine");
    Ok(())
}

#[test]
fn the_registry_holds_at_most_256_peer_machine_mappings() -> TestResult {
    let mut owner = Owner::new(Registry::open_in_memory()?);
    for batch in 0..4 {
        let changes: Vec<Value> = (0..64)
            .map(|index| set(&format!("m{batch}-{index}.test"), MACHINE))
            .collect();
        owner.apply(&changes)?;
    }
    assert_eq!(owner.address("m3-63.test")?, "127.77.1.0");
    let error = owner
        .try_apply(&[set("one-more.test", MACHINE)])
        .err()
        .ok_or("the 257th peer machine was accepted")?;
    assert_eq!(error.code, "E_PEER_MACHINE_CAPACITY");
    assert_eq!(error.context.get("limit").map(String::as_str), Some("256"));
    // Other kinds are not counted, and a removal makes room again.
    owner.apply(&[set("web.test", "http://127.0.0.1:8080")])?;
    owner.apply(&[change("remove", "m0-0.test"), set("one-more.test", MACHINE)])?;
    assert_eq!(owner.address("one-more.test")?, "127.77.0.1");
    Ok(())
}

#[test]
fn a_stored_address_that_breaks_the_rules_is_corrupt() -> TestResult {
    for tampered in ["127.0.0.1", "127.77.0.0", "not-an-address"] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("registry.sqlite3");
        let mut owner = open(&path)?;
        owner.apply(&[set("pro.test", MACHINE)])?;
        drop(owner);
        rusqlite::Connection::open(&path)?.execute(
            "UPDATE mappings SET peer_address = ?1 WHERE pattern = 'pro.test'",
            [tampered],
        )?;
        let error = Registry::open(&path)
            .err()
            .ok_or("a tampered address was accepted")?;
        assert_eq!(error.code, "E_REGISTRY_CORRUPT", "{tampered}");
    }
    Ok(())
}
