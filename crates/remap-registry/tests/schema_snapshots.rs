// SPDX-License-Identifier: GPL-3.0-or-later
//! Migrating an existing registry keeps a copy at its old schema, and putting
//! that copy back is a complete rollback (ADR-0032).

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use remap_protocol::{Command, CommandResult, Surface};
use remap_registry::Registry;
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn set(registry: &mut Registry, revision: u64, operation: &str, name: &str) -> TestResult {
    let command: Command = serde_json::from_value(json!({
        "kind": "apply", "expected_revision": revision, "operation_id": operation,
        "changes": [{"kind": "set", "pattern": name, "target": "127.0.0.1",
            "host_policy": "use-upstream", "enabled": null}]
    }))?;
    registry.execute(command, Surface::Probe)?;
    Ok(())
}

fn names(registry: &mut Registry) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let command: Command = serde_json::from_value(
        json!({"kind": "list", "after": null, "limit": 100, "include_disabled": true}),
    )?;
    let CommandResult::List(list) = registry.execute(command, Surface::Probe)? else {
        return Err("wrong list result".into());
    };
    Ok(list
        .mappings
        .into_iter()
        .map(|mapping| mapping.pattern)
        .collect())
}

fn user_version(path: &Path) -> Result<u32, Box<dyn std::error::Error>> {
    let connection = rusqlite::Connection::open(path)?;
    Ok(connection.pragma_query_value(None, "user_version", |row| row.get(0))?)
}

fn snapshots(directory: &Path) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(directory)? {
        let path = entry?.path();
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("registry.schema-"))
        {
            found.push(path);
        }
    }
    Ok(found)
}

/// Writes a registry as a schema-2 daemon left it.
fn schema_two_registry(path: &Path) -> TestResult {
    let mut registry = Registry::open(path)?;
    set(
        &mut registry,
        0,
        "c4d1f8c7-bd38-4a5a-a8ee-bb1f36cd2851",
        "old.test",
    )?;
    drop(registry);
    rusqlite::Connection::open(path)?.pragma_update(None, "user_version", 2)?;
    Ok(())
}

#[test]
fn migrating_keeps_a_private_copy_at_the_old_schema() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("registry.sqlite3");
    schema_two_registry(&path)?;
    assert_eq!(snapshots(directory.path())?, Vec::<PathBuf>::new());

    let mut registry = Registry::open(&path)?;
    assert_eq!(user_version(&path)?, 3);
    let copies = snapshots(directory.path())?;
    let [copy] = copies.as_slice() else {
        return Err(format!("expected one copy, found {copies:?}").into());
    };
    assert!(
        copy.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("registry.schema-2.")),
        "{copy:?}"
    );
    assert_eq!(
        user_version(copy)?,
        2,
        "the copy is the registry before migration"
    );
    assert_eq!(std::fs::metadata(copy)?.permissions().mode() & 0o777, 0o600);
    let check: String =
        rusqlite::Connection::open(copy)?
            .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
    assert_eq!(check, "ok");

    // A registry already at the current schema is opened without a copy.
    set(
        &mut registry,
        1,
        "7f0c1c55-0a64-4d39-9d1e-0fd5b4c58e2b",
        "new.test",
    )?;
    drop(registry);
    drop(Registry::open(&path)?);
    assert_eq!(snapshots(directory.path())?.len(), 1);
    Ok(())
}

#[test]
fn restoring_the_copy_returns_exactly_the_old_registry() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("registry.sqlite3");
    schema_two_registry(&path)?;
    let mut registry = Registry::open(&path)?;
    set(
        &mut registry,
        1,
        "7f0c1c55-0a64-4d39-9d1e-0fd5b4c58e2b",
        "after.test",
    )?;
    drop(registry);
    let copies = snapshots(directory.path())?;
    let [copy] = copies.as_slice() else {
        return Err("expected one copy".into());
    };

    // The documented restore: with remapd stopped, the copy replaces the
    // registry and its write-ahead files.
    for suffix in ["-wal", "-shm"] {
        let sidecar = directory.path().join(format!("registry.sqlite3{suffix}"));
        if sidecar.exists() {
            std::fs::remove_file(sidecar)?;
        }
    }
    std::fs::rename(copy, &path)?;
    assert_eq!(
        user_version(&path)?,
        2,
        "a schema-2 daemon reads this registry"
    );

    let mut restored = Registry::open(&path)?;
    assert_eq!(names(&mut restored)?, vec!["old.test".to_owned()]);
    Ok(())
}

#[test]
fn a_copy_that_cannot_be_made_refuses_the_migration() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("registry.sqlite3");
    schema_two_registry(&path)?;
    // An open reader keeps the write-ahead files, so the registry itself
    // still opens once its directory takes no new file.
    let reader = rusqlite::Connection::open(&path)?;
    reader.pragma_update(None, "journal_mode", "WAL")?;
    let mut permissions = std::fs::metadata(directory.path())?.permissions();
    permissions.set_mode(0o500);
    std::fs::set_permissions(directory.path(), permissions.clone())?;
    let outcome = Registry::open(&path);
    permissions.set_mode(0o700);
    std::fs::set_permissions(directory.path(), permissions)?;

    assert_eq!(
        outcome.err().ok_or("migrated without a copy")?.code,
        "E_REGISTRY_SNAPSHOT"
    );
    assert_eq!(user_version(&path)?, 2, "the registry was not changed");
    assert_eq!(snapshots(directory.path())?, Vec::<PathBuf>::new());
    drop(reader);
    Ok(())
}
