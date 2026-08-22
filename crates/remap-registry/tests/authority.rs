//! Executable specifications for one authoritative registry and revision order.

use remap_protocol::{Change, Command, CommandResult, HostPolicy, Surface};
use remap_registry::Registry;

const OP_ONE: &str = "c4d1f8c7-bd38-4a5a-a8ee-bb1f36cd2851";
const OP_TWO: &str = "86bd7f59-9fce-4c87-a86d-a19de6e4cc6d";
const OP_THREE: &str = "8adae9eb-ad38-43da-b012-c92b6a3ca407";

fn set(pattern: &str, target: &str) -> Change {
    Change::Set {
        pattern: pattern.to_owned(),
        target: target.to_owned(),
        host_policy: HostPolicy::PreserveClient,
        enabled: None,
    }
}

#[test]
fn mutation_advances_revision_and_is_visible_to_resolution()
-> Result<(), Box<dyn std::error::Error>> {
    let mut registry = Registry::open_in_memory()?;
    let applied = registry.execute(
        Command::Apply {
            expected_revision: 0,
            operation_id: OP_ONE.to_owned(),
            changes: vec![set("Atlas.", "http://127.0.0.1:5173")],
        },
        Surface::Mcp,
    )?;
    let CommandResult::Apply(receipt) = applied else {
        return Err("apply returned the wrong result kind".into());
    };
    assert!(receipt.changed);
    assert_eq!(receipt.revision, 1);

    let resolved = registry.execute(
        Command::Resolve {
            name: "ATLAS".to_owned(),
        },
        Surface::Probe,
    )?;
    let CommandResult::Resolution(resolution) = resolved else {
        return Err("resolve returned the wrong result kind".into());
    };
    assert_eq!(resolution.revision, 1);
    assert_eq!(
        resolution.mapping.map(|mapping| mapping.pattern),
        Some("atlas".to_owned())
    );
    Ok(())
}

#[test]
fn stale_and_invalid_batches_leave_every_mapping_unchanged()
-> Result<(), Box<dyn std::error::Error>> {
    let mut registry = Registry::open_in_memory()?;
    registry.execute(
        Command::Apply {
            expected_revision: 0,
            operation_id: OP_ONE.to_owned(),
            changes: vec![set("atlas", "10.0.0.1")],
        },
        Surface::Cli,
    )?;
    let stale = registry.execute(
        Command::Apply {
            expected_revision: 0,
            operation_id: OP_TWO.to_owned(),
            changes: vec![set("second", "10.0.0.2")],
        },
        Surface::Mcp,
    );
    assert_eq!(
        stale.as_ref().map_err(|error| error.code.as_str()),
        Err("E_REVISION_CONFLICT")
    );

    let invalid = registry.execute(
        Command::Preview {
            changes: vec![set("second", "10.0.0.2"), set("bad..name", "10.0.0.3")],
        },
        Surface::Mcp,
    );
    assert_eq!(
        invalid.as_ref().map_err(|error| error.code.as_str()),
        Err("E_INVALID_PATTERN")
    );

    let status = registry.execute(Command::Status, Surface::Probe)?;
    let CommandResult::Status(status) = status else {
        return Err("status returned the wrong result kind".into());
    };
    assert_eq!(status.revision, 1);
    assert_eq!(status.mapping_count, 1);
    Ok(())
}

#[test]
fn exact_retry_returns_receipt_and_conflicting_reuse_is_rejected()
-> Result<(), Box<dyn std::error::Error>> {
    let mut registry = Registry::open_in_memory()?;
    let command = Command::Apply {
        expected_revision: 0,
        operation_id: OP_ONE.to_owned(),
        changes: vec![set("atlas", "10.0.0.1")],
    };
    let first = registry.execute(command.clone(), Surface::Mcp)?;
    let retry = registry.execute(command, Surface::Mcp)?;
    assert_eq!(first, retry);

    let conflict = registry.execute(
        Command::Apply {
            expected_revision: 0,
            operation_id: OP_ONE.to_owned(),
            changes: vec![set("atlas", "10.0.0.2")],
        },
        Surface::Mcp,
    );
    assert_eq!(
        conflict.as_ref().map_err(|error| error.code.as_str()),
        Err("E_IDEMPOTENCY_CONFLICT")
    );
    Ok(())
}

#[test]
fn persisted_registry_reopens_with_same_revision_and_mapping()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("registry.sqlite3");
    {
        let mut registry = Registry::open(&path)?;
        registry.execute(
            Command::Apply {
                expected_revision: 0,
                operation_id: OP_ONE.to_owned(),
                changes: vec![set("*.lab", "10.0.0.8")],
            },
            Surface::Cli,
        )?;
    }
    let mut reopened = Registry::open(&path)?;
    let status = reopened.execute(Command::Status, Surface::Probe)?;
    let CommandResult::Status(status) = status else {
        return Err("status returned the wrong result kind".into());
    };
    assert_eq!(status.revision, 1);
    assert_eq!(status.mapping_count, 1);
    Ok(())
}

#[test]
fn reopening_prunes_expired_private_journal_rows() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("registry.sqlite3");
    {
        let mut registry = Registry::open(&path)?;
        registry.execute(
            Command::Apply {
                expected_revision: 0,
                operation_id: OP_ONE.to_owned(),
                changes: vec![set("atlas", "10.0.0.1")],
            },
            Surface::Cli,
        )?;
    }
    {
        let connection = rusqlite::Connection::open(&path)?;
        connection.execute("UPDATE requests SET recorded_unix_ms = 0", [])?;
        connection.execute("UPDATE events SET recorded_unix_ms = 0", [])?;
    }
    let _registry = Registry::open(&path)?;
    let connection = rusqlite::Connection::open(&path)?;
    let requests: u32 =
        connection.query_row("SELECT COUNT(*) FROM requests", [], |row| row.get(0))?;
    let events: u32 = connection.query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))?;
    assert_eq!(requests, 0);
    assert_eq!(events, 0);
    Ok(())
}

#[test]
fn reopening_enforces_private_journal_byte_ceilings_and_truncates_wal()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("registry.sqlite3");
    drop(Registry::open(&path)?);
    let now_ms = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis(),
    )?;
    let payload = vec![b'x'; 600 * 1024];
    {
        let mut connection = rusqlite::Connection::open(&path)?;
        let transaction = connection.transaction()?;
        for index in 1..=60_i64 {
            transaction.execute(
                "INSERT INTO requests(operation_id, payload, receipt, recorded_unix_ms)
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![format!("operation-{index}"), payload, b"{}", now_ms],
            )?;
            transaction.execute(
                "INSERT INTO events(revision, operation_id, surface, effects, recorded_unix_ms)
                 VALUES (?1, ?2, 'probe', ?3, ?4)",
                rusqlite::params![index, format!("event-{index}"), payload, now_ms],
            )?;
        }
        transaction.commit()?;
    }

    drop(Registry::open(&path)?);
    let connection = rusqlite::Connection::open(&path)?;
    let request_bytes: i64 = connection.query_row(
        "SELECT COALESCE(SUM(length(payload) + length(receipt)), 0) FROM requests",
        [],
        |row| row.get(0),
    )?;
    let event_bytes: i64 = connection.query_row(
        "SELECT COALESCE(SUM(length(effects)), 0) FROM events",
        [],
        |row| row.get(0),
    )?;
    assert!(request_bytes <= 32 * 1024 * 1024);
    assert!(event_bytes <= 32 * 1024 * 1024);
    drop(connection);
    let wal = std::path::PathBuf::from(format!("{}-wal", path.display()));
    match std::fs::metadata(wal) {
        Ok(metadata) => assert_eq!(metadata.len(), 0),
        Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::NotFound),
    }
    Ok(())
}

#[test]
fn checkpoint_contention_never_hides_a_committed_revision() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("registry.sqlite3");
    let mut registry = Registry::open(&path)?;
    registry.execute(apply(0, OP_ONE, "atlas"), Surface::Cli)?;
    let updater = rusqlite::Connection::open(&path)?;
    updater.execute("UPDATE requests SET recorded_unix_ms = 0", [])?;
    let reader = rusqlite::Connection::open(&path)?;
    reader.execute_batch("BEGIN")?;
    let _count: i64 = reader.query_row("SELECT COUNT(*) FROM requests", [], |row| row.get(0))?;

    let started = std::time::Instant::now();
    let result = registry.execute(apply(1, OP_THREE, "second"), Surface::Cli)?;
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
    let CommandResult::Apply(receipt) = result else {
        return Err("apply returned the wrong result kind".into());
    };
    assert_eq!(receipt.revision, 2);
    assert_eq!(registry.revision(), 2);
    let readable = registry.execute(Command::Status, Surface::Probe)?;
    assert!(matches!(
        readable,
        CommandResult::Status(status)
            if status.revision == 2
                && status.maintenance.as_ref().is_some_and(|error| {
                    error.code == "E_REGISTRY_CHECKPOINT"
                })
    ));
    let blocked = registry.execute(apply(2, OP_TWO, "third"), Surface::Cli);
    assert_eq!(
        blocked.as_ref().map_err(|error| error.code.as_str()),
        Err("E_REGISTRY_CHECKPOINT")
    );
    let replay = registry.execute(apply(1, OP_THREE, "second"), Surface::Cli)?;
    assert!(matches!(replay, CommandResult::Apply(receipt) if receipt.revision == 2));

    drop(registry);
    reader.execute_batch("ROLLBACK")?;
    drop(reader);
    let started = std::time::Instant::now();
    let mut reopened = Registry::open(&path)?;
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
    let status = reopened.execute(Command::Status, Surface::Probe)?;
    assert!(matches!(
        status,
        CommandResult::Status(status) if status.revision == 2 && status.maintenance.is_none()
    ));
    let applied = reopened.execute(apply(2, OP_TWO, "third"), Surface::Cli)?;
    assert!(matches!(applied, CommandResult::Apply(receipt) if receipt.revision == 3));
    let checkpoint_owed: i64 = updater.query_row(
        "SELECT value FROM metadata WHERE key = 'retention_checkpoint_owed'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(checkpoint_owed, 0);
    Ok(())
}

#[test]
fn checkpoint_contention_at_startup_preserves_reads_and_blocks_mutation()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("registry.sqlite3");
    let mut registry = Registry::open(&path)?;
    registry.execute(apply(0, OP_ONE, "atlas"), Surface::Cli)?;
    drop(registry);

    let updater = rusqlite::Connection::open(&path)?;
    updater.execute("UPDATE requests SET recorded_unix_ms = 0", [])?;
    let reader = rusqlite::Connection::open(&path)?;
    reader.execute_batch("BEGIN")?;
    let _count: i64 = reader.query_row("SELECT COUNT(*) FROM requests", [], |row| row.get(0))?;

    let started = std::time::Instant::now();
    let mut reopened = Registry::open(&path)?;
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
    let status = reopened.execute(Command::Status, Surface::Probe)?;
    assert!(matches!(
        status,
        CommandResult::Status(status)
            if status.revision == 1
                && status.maintenance.as_ref().is_some_and(|error| {
                    error.code == "E_REGISTRY_CHECKPOINT"
                })
    ));
    let blocked = reopened.execute(apply(1, OP_TWO, "second"), Surface::Cli);
    assert_eq!(
        blocked.as_ref().map_err(|error| error.code.as_str()),
        Err("E_REGISTRY_CHECKPOINT")
    );

    reader.execute_batch("ROLLBACK")?;
    let applied = reopened.execute(apply(1, OP_TWO, "second"), Surface::Cli)?;
    assert!(matches!(applied, CommandResult::Apply(receipt) if receipt.revision == 2));
    let status = reopened.execute(Command::Status, Surface::Probe)?;
    assert!(matches!(
        status,
        CommandResult::Status(status) if status.maintenance.is_none()
    ));
    Ok(())
}

fn apply(expected_revision: u64, operation_id: &str, pattern: &str) -> Command {
    Command::Apply {
        expected_revision,
        operation_id: operation_id.to_owned(),
        changes: vec![set(pattern, "10.0.0.1")],
    }
}
