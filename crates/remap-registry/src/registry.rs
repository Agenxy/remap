use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use remap_core::{Mapping, MappingTarget, NamePattern, RegistrySnapshot, RemapName};
use remap_protocol::{
    ApplyResult, Command, CommandResult, Diagnostic, HostPolicy, ListResult,
    MAX_CONTROL_RESULT_BYTES, MAX_MAPPING_COUNT, MAX_MAPPING_PAGE_SIZE, MappingView,
    RegistryStatus, ResolutionResult, Surface, ValidationResult,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use uuid::Uuid;

use crate::project::{Projection, StoredMapping, core_host_policy, project};
use crate::schema::{
    SCHEMA_VERSION, configure, database_error, migrate, with_immediate_busy_failure,
};

const DEFAULT_LIST_LIMIT: u16 = 50;
const REQUEST_RETENTION_MS: u64 = 24 * 60 * 60 * 1_000;
const EVENT_RETENTION_MS: u64 = 7 * 24 * 60 * 60 * 1_000;
const MAX_REQUEST_JOURNAL_ROWS: i64 = 4_096;
const MAX_EVENT_JOURNAL_ROWS: i64 = 4_096;
const MAX_REQUEST_JOURNAL_BYTES: i64 = 32 * 1024 * 1024;
const MAX_EVENT_JOURNAL_BYTES: i64 = 32 * 1024 * 1024;

/// Single-threaded authoritative registry and operation journal.
pub struct Registry {
    connection: Connection,
    revision: u64,
    mappings: BTreeMap<String, StoredMapping>,
    snapshot: RegistrySnapshot,
    maintenance_error: Option<Diagnostic>,
}

impl Registry {
    /// Returns the current monotonic registry revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Opens or creates a registry at an explicit native path.
    ///
    /// # Errors
    ///
    /// Returns a stable diagnostic for schema, integrity, permission, or data
    /// validation failures. A retryable retention failure opens the authority
    /// in an observable read-only maintenance state.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Diagnostic> {
        let mut connection = Connection::open(path).map_err(database_error)?;
        configure(&connection)?;
        migrate(&mut connection)?;
        let maintenance_error = match prune_on_connection(&mut connection) {
            Ok(()) => None,
            Err(error) if recoverable_maintenance_failure(&error) => Some(error),
            Err(error) => return Err(error),
        };
        let revision = load_revision(&connection)?;
        let mappings = load_mappings(&connection, revision)?;
        let snapshot = build_snapshot(revision, &mappings)?;
        Ok(Self {
            connection,
            revision,
            mappings,
            snapshot,
            maintenance_error,
        })
    }

    /// Opens a private in-memory registry for executable specifications.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when `SQLite` initialization fails.
    pub fn open_in_memory() -> Result<Self, Diagnostic> {
        let mut connection = Connection::open_in_memory().map_err(database_error)?;
        configure(&connection)?;
        migrate(&mut connection)?;
        Ok(Self {
            connection,
            revision: 0,
            mappings: BTreeMap::new(),
            snapshot: RegistrySnapshot::new(0, Vec::new()).map_err(corrupt_record)?,
            maintenance_error: None,
        })
    }

    /// Applies the documented age, row, and byte retention ceilings now.
    ///
    /// Deleted content is securely cleared by `SQLite` and the `WAL` is truncated
    /// before this method reports success.
    ///
    /// # Errors
    ///
    /// Returns a stable persistence diagnostic if pruning or checkpointing fails.
    pub fn prune_expired(&mut self) -> Result<(), Diagnostic> {
        let result = prune_on_connection(&mut self.connection);
        match result {
            Ok(()) => {
                self.maintenance_error = None;
                Ok(())
            }
            Err(error) => {
                self.maintenance_error = Some(error.clone());
                Err(error)
            }
        }
    }

    /// Executes one validated command on the registry's owning thread.
    ///
    /// # Errors
    ///
    /// Returns a stable domain or persistence diagnostic. Rejected mutations
    /// never advance the revision or partially change mappings.
    pub fn execute(
        &mut self,
        command: Command,
        surface: Surface,
    ) -> Result<CommandResult, Diagnostic> {
        let result = match command {
            Command::Status => Ok(CommandResult::Status(self.status())),
            Command::HealthChallenge { .. } => Err(Diagnostic::new(
                "E_CONTROL_COMMAND",
                "runtime health challenges are handled by the daemon",
                Some("update the Remap daemon and client together".to_owned()),
                false,
            )),
            Command::List {
                after,
                limit,
                include_disabled,
            } => self.list(after.as_deref(), limit, include_disabled),
            Command::Get { pattern } => self.get(&pattern),
            Command::Resolve { name } => self.resolve(&name),
            Command::Validate {
                pattern,
                target,
                host_policy,
            } => Self::validate(&pattern, &target, host_policy),
            Command::Preview { changes } => {
                let projection = project(&self.mappings, self.revision, &changes)?;
                ensure_mapping_capacity(projection.mappings.len())?;
                Ok(CommandResult::Preview(projection.result))
            }
            Command::Apply {
                expected_revision,
                operation_id,
                changes,
            } => self.apply(expected_revision, &operation_id, &changes, surface),
            Command::WaitForRevision { .. } => Err(Diagnostic::new(
                "E_CONTROL_COMMAND",
                "revision waits are handled by the daemon, not the registry writer",
                Some("update the Remap daemon and client together".to_owned()),
                false,
            )),
        }?;
        ensure_result_budget(&result)?;
        Ok(result)
    }

    fn status(&self) -> RegistryStatus {
        RegistryStatus {
            revision: self.revision,
            mapping_count: u64::try_from(self.mappings.len()).unwrap_or(u64::MAX),
            enabled_count: u64::try_from(
                self.mappings
                    .values()
                    .filter(|mapping| mapping.enabled)
                    .count(),
            )
            .unwrap_or(u64::MAX),
            schema_version: SCHEMA_VERSION,
            daemon_version: env!("CARGO_PKG_VERSION").to_owned(),
            maintenance: self.maintenance_error.clone(),
        }
    }

    fn list(
        &self,
        after: Option<&str>,
        requested_limit: u16,
        include_disabled: bool,
    ) -> Result<CommandResult, Diagnostic> {
        let limit = if requested_limit == 0 {
            DEFAULT_LIST_LIMIT
        } else if requested_limit > MAX_MAPPING_PAGE_SIZE {
            return Err(Diagnostic::new(
                "E_PAGE_LIMIT",
                format!("the mapping page limit cannot exceed {MAX_MAPPING_PAGE_SIZE}"),
                Some(format!(
                    "request a limit from 1 through {MAX_MAPPING_PAGE_SIZE}"
                )),
                false,
            ));
        } else {
            requested_limit
        };
        let canonical_after = after.map(canonical_pattern).transpose()?;
        let mut records = self
            .mappings
            .values()
            .filter(|mapping| include_disabled || mapping.enabled)
            .filter(|mapping| {
                canonical_after
                    .as_ref()
                    .is_none_or(|cursor| mapping.pattern > *cursor)
            });
        let take = usize::from(limit).saturating_add(1);
        let mut page: Vec<MappingView> = records
            .by_ref()
            .take(take)
            .map(StoredMapping::view)
            .collect();
        let has_more = page.len() > usize::from(limit);
        if has_more {
            page.truncate(usize::from(limit));
        }
        let next_cursor = has_more
            .then(|| page.last().map(|mapping| mapping.pattern.clone()))
            .flatten();
        Ok(CommandResult::List(ListResult {
            revision: self.revision,
            mappings: page,
            next_cursor,
        }))
    }

    fn get(&self, pattern: &str) -> Result<CommandResult, Diagnostic> {
        let canonical = canonical_pattern(pattern)?;
        Ok(CommandResult::Mapping(
            self.mappings.get(&canonical).map(StoredMapping::view),
        ))
    }

    fn resolve(&self, name: &str) -> Result<CommandResult, Diagnostic> {
        let canonical = RemapName::parse(name).map_err(|error| {
            Diagnostic::new(
                "E_INVALID_NAME",
                error.to_string(),
                Some("use a hostname rather than an address literal".to_owned()),
                false,
            )
        })?;
        let mapping = self
            .snapshot
            .resolve(&canonical)
            .and_then(|selected| self.mappings.get(&selected.pattern().to_string()))
            .map(StoredMapping::view);
        Ok(CommandResult::Resolution(ResolutionResult {
            name: canonical.to_string(),
            revision: self.revision,
            mapping,
        }))
    }

    fn validate(
        pattern: &str,
        target: &str,
        host_policy: HostPolicy,
    ) -> Result<CommandResult, Diagnostic> {
        let record = StoredMapping::validate(pattern, target, host_policy, true, 0)?;
        Ok(CommandResult::Validation(ValidationResult {
            pattern: record.pattern,
            target: record.target,
            target_kind: record.target_kind,
            host_policy: record.host_policy,
        }))
    }

    fn apply(
        &mut self,
        expected_revision: u64,
        operation_id: &str,
        changes: &[remap_protocol::Change],
        surface: Surface,
    ) -> Result<CommandResult, Diagnostic> {
        validate_operation_id(operation_id)?;
        let payload = serde_json::to_vec(&(expected_revision, changes)).map_err(json_error)?;
        if let Some(receipt) = self.replayed_receipt(operation_id, &payload)? {
            return Ok(CommandResult::Apply(receipt));
        }
        if self.maintenance_error.is_some() {
            self.prune_expired()?;
        }
        if expected_revision != self.revision {
            return Err(Diagnostic::new(
                "E_REVISION_CONFLICT",
                format!(
                    "the registry is at revision {}, not the expected revision {expected_revision}",
                    self.revision
                ),
                Some(
                    "read current mappings, reconsider the change, and use the new revision"
                        .to_owned(),
                ),
                false,
            )
            .with_context("expected_revision", expected_revision.to_string())
            .with_context("current_revision", self.revision.to_string()));
        }
        let projection = project(&self.mappings, self.revision, changes)?;
        ensure_mapping_capacity(projection.mappings.len())?;
        self.commit_projection(operation_id, &payload, projection, surface)
    }

    fn replayed_receipt(
        &self,
        operation_id: &str,
        payload: &[u8],
    ) -> Result<Option<ApplyResult>, Diagnostic> {
        let stored: Option<(Vec<u8>, Vec<u8>)> = self
            .connection
            .query_row(
                "SELECT payload, receipt FROM requests WHERE operation_id = ?1",
                [operation_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(database_error)?;
        let Some((stored_payload, receipt)) = stored else {
            return Ok(None);
        };
        if stored_payload != payload {
            return Err(Diagnostic::new(
                "E_IDEMPOTENCY_CONFLICT",
                "the operation identifier was already used for a different request",
                Some("reuse an operation identifier only for an exact retry; generate a new UUID otherwise".to_owned()),
                false,
            ));
        }
        serde_json::from_slice(&receipt)
            .map(Some)
            .map_err(json_error)
    }

    fn commit_projection(
        &mut self,
        operation_id: &str,
        payload: &[u8],
        projection: Projection,
        surface: Surface,
    ) -> Result<CommandResult, Diagnostic> {
        let previous_revision = self.revision;
        let revision = if projection.result.will_change {
            previous_revision
                .checked_add(1)
                .ok_or_else(revision_exhausted)?
        } else {
            previous_revision
        };
        let receipt = ApplyResult {
            operation_id: operation_id.to_owned(),
            previous_revision,
            revision,
            changed: projection.result.will_change,
            effects: projection.result.effects,
        };
        let next_snapshot = build_snapshot(revision, &projection.mappings)?;
        ensure_result_budget(&CommandResult::Apply(receipt.clone()))?;
        let receipt_bytes = serde_json::to_vec(&receipt).map_err(json_error)?;
        let effects_bytes = serde_json::to_vec(&receipt.effects).map_err(json_error)?;
        let recorded_unix_ms = unix_milliseconds()?;
        let database_revision = database_integer(revision)?;
        let database_time = database_integer(recorded_unix_ms)?;
        let touched: BTreeSet<String> = receipt
            .effects
            .iter()
            .map(|effect| effect.pattern.clone())
            .collect();
        let transaction = self.connection.transaction().map_err(database_error)?;
        persist_touched(&transaction, &projection.mappings, &touched)?;
        if receipt.changed {
            transaction
                .execute(
                    "UPDATE metadata SET value = ?1 WHERE key = 'revision'",
                    [database_revision],
                )
                .map_err(database_error)?;
            transaction
                .execute(
                    "INSERT INTO events(revision, operation_id, surface, effects, recorded_unix_ms)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        database_revision,
                        operation_id,
                        surface_name(surface),
                        effects_bytes,
                        database_time
                    ],
                )
                .map_err(database_error)?;
        }
        transaction
            .execute(
                "INSERT INTO requests(operation_id, payload, receipt, recorded_unix_ms)
                 VALUES (?1, ?2, ?3, ?4)",
                params![operation_id, payload, receipt_bytes, database_time],
            )
            .map_err(database_error)?;
        let pruned = prune_journals(&transaction, recorded_unix_ms)?;
        if pruned > 0 {
            mark_retention_checkpoint_owed(&transaction)?;
        }
        transaction.commit().map_err(database_error)?;
        self.mappings = projection.mappings;
        self.revision = revision;
        self.snapshot = next_snapshot;
        if pruned > 0
            && let Err(error) = complete_retention_checkpoint(&mut self.connection)
        {
            self.maintenance_error = Some(error);
        }
        Ok(CommandResult::Apply(receipt))
    }
}

fn build_snapshot(
    revision: u64,
    records: &BTreeMap<String, StoredMapping>,
) -> Result<RegistrySnapshot, Diagnostic> {
    let mappings = records
        .values()
        .map(|record| {
            let pattern = NamePattern::parse(&record.pattern).map_err(corrupt_record)?;
            let target = MappingTarget::parse_with_http_policy(
                &record.target,
                core_host_policy(record.host_policy),
            )
            .map_err(corrupt_record)?;
            Ok(Mapping::new(pattern, target).with_enabled(record.enabled))
        })
        .collect::<Result<Vec<_>, Diagnostic>>()?;
    RegistrySnapshot::new(revision, mappings).map_err(corrupt_record)
}

fn prune_on_connection(connection: &mut Connection) -> Result<(), Diagnostic> {
    with_immediate_busy_failure(connection, prune_without_wait)
}

fn prune_without_wait(connection: &mut Connection) -> Result<(), Diagnostic> {
    let now_ms = unix_milliseconds()?;
    let transaction = connection.transaction().map_err(database_error)?;
    let pruned = prune_journals(&transaction, now_ms)?;
    if pruned > 0 {
        mark_retention_checkpoint_owed(&transaction)?;
    }
    transaction.commit().map_err(database_error)?;
    complete_retention_checkpoint_without_wait(connection)
}

fn recoverable_maintenance_failure(error: &Diagnostic) -> bool {
    error.retryable && matches!(error.code.as_str(), "E_REGISTRY" | "E_REGISTRY_CHECKPOINT")
}

fn prune_journals(transaction: &Transaction<'_>, now_ms: u64) -> Result<usize, Diagnostic> {
    let request_cutoff = database_integer(now_ms.saturating_sub(REQUEST_RETENTION_MS))?;
    let event_cutoff = database_integer(now_ms.saturating_sub(EVENT_RETENTION_MS))?;
    let requests = transaction
        .execute(
            "DELETE FROM requests WHERE recorded_unix_ms <= ?1 OR rowid IN (
                 SELECT rowid FROM requests ORDER BY recorded_unix_ms DESC, rowid DESC
                 LIMIT -1 OFFSET ?2
             ) OR rowid IN (
                 SELECT rowid FROM (
                     SELECT rowid,
                            SUM(length(payload) + length(receipt)) OVER (
                                ORDER BY recorded_unix_ms DESC, rowid DESC
                                ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
                            ) AS cumulative_bytes
                     FROM requests
                 ) WHERE cumulative_bytes > ?3
             )",
            params![
                request_cutoff,
                MAX_REQUEST_JOURNAL_ROWS,
                MAX_REQUEST_JOURNAL_BYTES
            ],
        )
        .map_err(database_error)?;
    let events = transaction
        .execute(
            "DELETE FROM events WHERE recorded_unix_ms <= ?1 OR revision IN (
                 SELECT revision FROM events ORDER BY revision DESC LIMIT -1 OFFSET ?2
             ) OR revision IN (
                 SELECT revision FROM (
                     SELECT revision,
                            SUM(length(effects)) OVER (
                                ORDER BY revision DESC
                                ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
                            ) AS cumulative_bytes
                     FROM events
                 ) WHERE cumulative_bytes > ?3
             )",
            params![
                event_cutoff,
                MAX_EVENT_JOURNAL_ROWS,
                MAX_EVENT_JOURNAL_BYTES
            ],
        )
        .map_err(database_error)?;
    Ok(requests.saturating_add(events))
}

fn truncate_wal(connection: &Connection) -> Result<(), Diagnostic> {
    let busy: i64 = connection
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))
        .map_err(database_error)?;
    if busy != 0 {
        return Err(Diagnostic::new(
            "E_REGISTRY_CHECKPOINT",
            "the private registry journal could not be cleared after retention pruning",
            Some("stop other registry readers and retry remapd".to_owned()),
            true,
        ));
    }
    Ok(())
}

fn mark_retention_checkpoint_owed(transaction: &Transaction<'_>) -> Result<(), Diagnostic> {
    let changed = transaction
        .execute(
            "UPDATE metadata SET value = 1 WHERE key = 'retention_checkpoint_owed'",
            [],
        )
        .map_err(database_error)?;
    if changed == 1 {
        Ok(())
    } else {
        Err(corrupt_record("the retention checkpoint marker is missing"))
    }
}

fn complete_retention_checkpoint(connection: &mut Connection) -> Result<(), Diagnostic> {
    with_immediate_busy_failure(connection, complete_retention_checkpoint_without_wait)
}

fn complete_retention_checkpoint_without_wait(
    connection: &mut Connection,
) -> Result<(), Diagnostic> {
    let owed: i64 = connection
        .query_row(
            "SELECT value FROM metadata WHERE key = 'retention_checkpoint_owed'",
            [],
            |row| row.get(0),
        )
        .map_err(database_error)?;
    match owed {
        0 => Ok(()),
        1 => {
            truncate_wal(connection)?;
            connection
                .execute(
                    "UPDATE metadata SET value = 0 WHERE key = 'retention_checkpoint_owed'",
                    [],
                )
                .map_err(database_error)?;
            Ok(())
        }
        _ => Err(corrupt_record(
            "the retention checkpoint marker is outside its supported range",
        )),
    }
}

fn load_revision(connection: &Connection) -> Result<u64, Diagnostic> {
    let stored: i64 = connection
        .query_row(
            "SELECT value FROM metadata WHERE key = 'revision'",
            [],
            |row| row.get(0),
        )
        .map_err(database_error)?;
    stored.try_into().map_err(|_| {
        corrupt_record("the registry revision is negative or outside the supported range")
    })
}

fn load_mappings(
    connection: &Connection,
    revision: u64,
) -> Result<BTreeMap<String, StoredMapping>, Diagnostic> {
    let mut statement = connection
        .prepare(
            "SELECT pattern, target, host_policy, enabled, updated_revision
             FROM mappings ORDER BY pattern",
        )
        .map_err(database_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, bool>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })
        .map_err(database_error)?;
    let mut mappings = BTreeMap::new();
    for row in rows {
        let (pattern, target, policy, enabled, stored_revision) = row.map_err(database_error)?;
        let updated_revision = u64::try_from(stored_revision)
            .map_err(|_| corrupt_record("a mapping revision is negative"))?;
        if updated_revision > revision {
            return Err(corrupt_record(
                "a mapping revision exceeds the registry revision",
            ));
        }
        let host_policy = parse_host_policy(&policy)?;
        let record =
            StoredMapping::validate(&pattern, &target, host_policy, enabled, updated_revision)?;
        if mappings.insert(record.pattern.clone(), record).is_some() {
            return Err(corrupt_record("the registry contains a duplicate pattern"));
        }
        ensure_mapping_capacity(mappings.len())?;
    }
    Ok(mappings)
}

fn ensure_mapping_capacity(count: usize) -> Result<(), Diagnostic> {
    if count <= MAX_MAPPING_COUNT {
        return Ok(());
    }
    Err(Diagnostic::new(
        "E_MAPPING_CAPACITY",
        format!("the registry cannot contain more than {MAX_MAPPING_COUNT} mappings"),
        Some("remove unused mappings before adding another".to_owned()),
        false,
    )
    .with_context("limit", MAX_MAPPING_COUNT.to_string()))
}

fn persist_touched(
    transaction: &Transaction<'_>,
    mappings: &BTreeMap<String, StoredMapping>,
    touched: &BTreeSet<String>,
) -> Result<(), Diagnostic> {
    for pattern in touched {
        if let Some(record) = mappings.get(pattern) {
            let updated_revision = database_integer(record.updated_revision)?;
            transaction
                .execute(
                    "INSERT INTO mappings(pattern, target, host_policy, enabled, updated_revision)
                     VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT(pattern) DO UPDATE SET
                       target = excluded.target,
                       host_policy = excluded.host_policy,
                       enabled = excluded.enabled,
                       updated_revision = excluded.updated_revision",
                    params![
                        record.pattern,
                        record.target,
                        record.host_policy.as_str(),
                        record.enabled,
                        updated_revision
                    ],
                )
                .map_err(database_error)?;
        } else {
            transaction
                .execute("DELETE FROM mappings WHERE pattern = ?1", [pattern])
                .map_err(database_error)?;
        }
    }
    Ok(())
}

fn canonical_pattern(pattern: &str) -> Result<String, Diagnostic> {
    NamePattern::parse(pattern)
        .map(|value| value.to_string())
        .map_err(|error| {
            Diagnostic::new(
                "E_INVALID_PATTERN",
                error.to_string(),
                Some("use an exact hostname or a suffix wildcard such as '*.lab'".to_owned()),
                false,
            )
        })
}

fn parse_host_policy(value: &str) -> Result<HostPolicy, Diagnostic> {
    match value {
        "preserve-client" => Ok(HostPolicy::PreserveClient),
        "use-upstream" => Ok(HostPolicy::UseUpstream),
        _ => Err(corrupt_record("a mapping contains an unknown host policy")),
    }
}

fn validate_operation_id(operation_id: &str) -> Result<(), Diagnostic> {
    let parsed = Uuid::parse_str(operation_id).map_err(|_| {
        Diagnostic::new(
            "E_OPERATION_ID",
            "operation_id must be a UUID",
            Some("generate one UUID and reuse it only when retrying this exact request".to_owned()),
            false,
        )
    })?;
    if parsed.get_version_num() != 4 {
        return Err(Diagnostic::new(
            "E_OPERATION_ID",
            "operation_id must be a random UUID version 4",
            Some("generate a UUIDv4 for this mutation".to_owned()),
            false,
        ));
    }
    Ok(())
}

fn unix_milliseconds() -> Result<u64, Diagnostic> {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| {
        Diagnostic::new(
            "E_CLOCK",
            "the system clock is earlier than the Unix epoch",
            Some("correct the system clock before changing the registry".to_owned()),
            false,
        )
    })?;
    u64::try_from(duration.as_millis()).map_err(|_| revision_exhausted())
}

fn database_integer(value: u64) -> Result<i64, Diagnostic> {
    i64::try_from(value).map_err(|_| revision_exhausted())
}

fn surface_name(surface: Surface) -> &'static str {
    match surface {
        Surface::Cli => "cli",
        Surface::Mcp => "mcp",
        Surface::NativeApp => "native-app",
        Surface::Probe => "probe",
    }
}

fn corrupt_record(error: impl std::fmt::Display) -> Diagnostic {
    Diagnostic::new(
        "E_REGISTRY_CORRUPT",
        format!("the registry contains invalid authoritative data: {error}"),
        Some("preserve the registry and run remap doctor before recovery".to_owned()),
        false,
    )
}

fn json_error(_error: serde_json::Error) -> Diagnostic {
    Diagnostic::new(
        "E_INTERNAL_SERIALIZATION",
        "Remap could not encode an internal registry receipt",
        Some("preserve the registry and report this invariant failure".to_owned()),
        false,
    )
}

fn ensure_result_budget(result: &CommandResult) -> Result<(), Diagnostic> {
    let encoded = serde_json::to_vec(result).map_err(json_error)?;
    if encoded.len() <= MAX_CONTROL_RESULT_BYTES {
        return Ok(());
    }
    Err(Diagnostic::new(
        "E_CONTROL_RESULT_TOO_LARGE",
        "the requested result exceeds the local-control response budget",
        Some("request a smaller page or split the atomic change set".to_owned()),
        false,
    ))
}

fn revision_exhausted() -> Diagnostic {
    Diagnostic::new(
        "E_REVISION_EXHAUSTED",
        "the registry revision or timestamp counter is exhausted",
        Some("preserve the registry and contact the Remap maintainers".to_owned()),
        false,
    )
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_MAPPING_COUNT, MAX_REQUEST_JOURNAL_ROWS, configure, ensure_mapping_capacity, migrate,
        prune_journals,
    };

    #[test]
    fn mapping_capacity_accepts_the_limit_and_rejects_the_next_record()
    -> Result<(), Box<dyn std::error::Error>> {
        assert!(ensure_mapping_capacity(MAX_MAPPING_COUNT).is_ok());
        let diagnostic = ensure_mapping_capacity(MAX_MAPPING_COUNT + 1)
            .err()
            .ok_or_else(|| std::io::Error::other("capacity did not reject the next mapping"))?;
        assert_eq!(diagnostic.code, "E_MAPPING_CAPACITY");
        assert_eq!(
            diagnostic.context.get("limit"),
            Some(&MAX_MAPPING_COUNT.to_string())
        );
        Ok(())
    }

    #[test]
    fn equal_timestamp_pruning_retains_the_newest_request() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut connection = rusqlite::Connection::open_in_memory()?;
        configure(&connection)?;
        migrate(&mut connection)?;
        let transaction = connection.transaction()?;
        for index in 0..=MAX_REQUEST_JOURNAL_ROWS {
            transaction.execute(
                "INSERT INTO requests(operation_id, payload, receipt, recorded_unix_ms)
                 VALUES (?1, ?2, ?3, 100)",
                rusqlite::params![format!("operation-{index}"), [1_u8], [2_u8]],
            )?;
        }
        prune_journals(&transaction, 100)?;
        let total: i64 =
            transaction.query_row("SELECT COUNT(*) FROM requests", [], |row| row.get(0))?;
        let newest: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM requests WHERE operation_id = ?1",
            [format!("operation-{MAX_REQUEST_JOURNAL_ROWS}")],
            |row| row.get(0),
        )?;
        assert_eq!(total, MAX_REQUEST_JOURNAL_ROWS);
        assert_eq!(newest, 1);
        Ok(())
    }
}
