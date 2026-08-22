use std::time::Duration;

use rusqlite::Connection;

use remap_protocol::Diagnostic;

pub(crate) const SCHEMA_VERSION: u32 = 1;
pub(crate) const DATABASE_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) fn configure(connection: &Connection) -> Result<(), Diagnostic> {
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .map_err(database_error)?;
    connection
        .pragma_update(None, "journal_mode", "WAL")
        .map_err(database_error)?;
    connection
        .pragma_update(None, "synchronous", "FULL")
        .map_err(database_error)?;
    connection
        .pragma_update(None, "trusted_schema", "OFF")
        .map_err(database_error)?;
    connection
        .pragma_update(None, "secure_delete", "ON")
        .map_err(database_error)?;
    connection
        .busy_timeout(DATABASE_BUSY_TIMEOUT)
        .map_err(database_error)?;
    connection
        .set_limit(rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH, 1024 * 1024)
        .map_err(database_error)?;
    Ok(())
}

pub(crate) fn migrate(connection: &mut Connection) -> Result<(), Diagnostic> {
    with_immediate_busy_failure(connection, migrate_without_wait)
}

pub(crate) fn with_immediate_busy_failure<T>(
    connection: &mut Connection,
    operation: impl FnOnce(&mut Connection) -> Result<T, Diagnostic>,
) -> Result<T, Diagnostic> {
    connection
        .busy_timeout(Duration::ZERO)
        .map_err(database_error)?;
    let outcome = operation(connection);
    let restoration = connection
        .busy_timeout(DATABASE_BUSY_TIMEOUT)
        .map_err(database_error);
    match (outcome, restoration) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (outcome, Err(restoration_error)) => {
            let operation_outcome = match outcome {
                Ok(_) => "completed".to_owned(),
                Err(error) => format!("failed:{}", error.code),
            };
            Err(Diagnostic::new(
                "E_REGISTRY_CONFIGURATION",
                "the registry could not restore its normal contention policy",
                Some("stop remapd and inspect the local SQLite installation".to_owned()),
                false,
            )
            .with_context("maintenance_outcome", operation_outcome)
            .with_context("restoration_error", restoration_error.code))
        }
    }
}

fn migrate_without_wait(connection: &mut Connection) -> Result<(), Diagnostic> {
    let found: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(database_error)?;
    if found > SCHEMA_VERSION {
        return Err(Diagnostic::new(
            "E_REGISTRY_SCHEMA_NEWER",
            format!(
                "registry schema {found} is newer than this daemon supports ({SCHEMA_VERSION})"
            ),
            Some("update Remap before starting this registry".to_owned()),
            false,
        ));
    }
    if found == 0 {
        connection
            .execute_batch(
                "BEGIN IMMEDIATE;
                 CREATE TABLE metadata (
                     key TEXT PRIMARY KEY NOT NULL,
                     value INTEGER NOT NULL
                 ) STRICT;
                 INSERT INTO metadata(key, value) VALUES ('revision', 0);
                 INSERT INTO metadata(key, value)
                     VALUES ('retention_checkpoint_owed', 0);
                 CREATE TABLE mappings (
                     pattern TEXT PRIMARY KEY NOT NULL,
                     target TEXT NOT NULL,
                     host_policy TEXT NOT NULL,
                     enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
                     updated_revision INTEGER NOT NULL CHECK (updated_revision >= 0)
                 ) STRICT;
                 CREATE TABLE requests (
                     operation_id TEXT PRIMARY KEY NOT NULL,
                     payload BLOB NOT NULL,
                     receipt BLOB NOT NULL,
                     recorded_unix_ms INTEGER NOT NULL
                 ) STRICT;
                 CREATE TABLE events (
                     revision INTEGER PRIMARY KEY NOT NULL CHECK (revision > 0),
                     operation_id TEXT UNIQUE NOT NULL,
                     surface TEXT NOT NULL,
                     effects BLOB NOT NULL,
                     recorded_unix_ms INTEGER NOT NULL
                 ) STRICT;
                 PRAGMA user_version = 1;
                 COMMIT;",
            )
            .map_err(database_error)?;
    }
    connection
        .execute(
            "INSERT OR IGNORE INTO metadata(key, value)
             VALUES ('retention_checkpoint_owed', 1)",
            [],
        )
        .map_err(database_error)?;
    let quick_check: String = connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(database_error)?;
    if quick_check != "ok" {
        return Err(Diagnostic::new(
            "E_REGISTRY_CORRUPT",
            "the Remap registry failed SQLite's integrity check",
            Some(
                "preserve the registry and run remap doctor before attempting recovery".to_owned(),
            ),
            false,
        ));
    }
    Ok(())
}

pub(crate) fn database_error(error: rusqlite::Error) -> Diagnostic {
    let retryable = matches!(
        error,
        rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error {
                code: rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked,
                ..
            },
            _
        )
    );
    drop(error);
    Diagnostic::new(
        "E_REGISTRY",
        "the authoritative registry operation failed",
        Some("run remap doctor; preserve the registry if the failure repeats".to_owned()),
        retryable,
    )
}

#[cfg(test)]
mod tests {
    use super::database_error;

    #[test]
    fn only_lock_contention_is_retryable() {
        let busy = rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY);
        let corrupt = rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CORRUPT);
        assert!(database_error(rusqlite::Error::SqliteFailure(busy, None)).retryable);
        assert!(!database_error(rusqlite::Error::SqliteFailure(corrupt, None)).retryable);
    }
}
