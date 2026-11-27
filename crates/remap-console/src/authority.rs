// SPDX-License-Identifier: GPL-3.0-or-later
//! Runs [`Effect`]s against the daemon. The console never writes anything
//! itself; every change goes through these commands.

use std::future::Future;

use remap_protocol::{
    Command, CommandResult, ControlClient, Diagnostic, ListResult, MAX_MAPPING_COUNT,
    MAX_MAPPING_PAGE_SIZE, MappingView, RegistryStatus,
};

use crate::update::{Effect, Outcome, Snapshot};

/// How many times a refresh rereads when the registry moves under it.
const SNAPSHOT_ATTEMPTS: usize = 3;

/// Stable code for a registry that changed on every read attempt.
pub const REGISTRY_BUSY: &str = "console-registry-busy";

/// The daemon, as far as the console is concerned: something that answers
/// control commands. [`ControlClient`] is the real one.
pub trait Authority: Send + Sync + 'static {
    /// Sends one command and returns the daemon's result or diagnostic.
    fn execute(
        &self,
        command: Command,
    ) -> impl Future<Output = Result<CommandResult, Diagnostic>> + Send;
}

impl Authority for ControlClient {
    fn execute(
        &self,
        command: Command,
    ) -> impl Future<Output = Result<CommandResult, Diagnostic>> + Send {
        ControlClient::execute(self, command)
    }
}

/// Runs one effect and returns its outcome. Every effect produces exactly
/// one outcome, including on failure.
pub async fn execute<A: Authority + ?Sized>(authority: &A, effect: Effect) -> Outcome {
    match effect {
        Effect::Refresh => Outcome::Refreshed(snapshot(authority).await),
        Effect::Validate {
            seq,
            pattern,
            target,
            host_policy,
            landing,
        } => {
            let command = Command::Validate {
                pattern,
                target,
                host_policy,
                landing,
            };
            let result = authority
                .execute(command)
                .await
                .and_then(|result| match result {
                    CommandResult::Validation(validation) => Ok(validation),
                    _ => Err(unexpected("validate")),
                });
            Outcome::Validated { seq, result }
        }
        Effect::Preview { seq, changes } => {
            let result = authority
                .execute(Command::Preview { changes })
                .await
                .and_then(|result| match result {
                    CommandResult::Preview(preview) => Ok(preview),
                    _ => Err(unexpected("preview")),
                });
            Outcome::Previewed { seq, result }
        }
        Effect::Apply {
            expected_revision,
            operation_id,
            changes,
        } => apply(authority, expected_revision, operation_id, changes).await,
        Effect::Resolve { name } => {
            let result = authority
                .execute(Command::Resolve { name })
                .await
                .and_then(|result| match result {
                    CommandResult::Resolution(resolution) => Ok(resolution),
                    _ => Err(unexpected("resolve")),
                });
            Outcome::Resolved(result)
        }
    }
}

async fn apply<A: Authority + ?Sized>(
    authority: &A,
    expected_revision: u64,
    operation_id: String,
    changes: Vec<remap_protocol::Change>,
) -> Outcome {
    let command = Command::Apply {
        expected_revision,
        operation_id: operation_id.clone(),
        changes,
    };
    let result = authority
        .execute(command)
        .await
        .and_then(|result| match result {
            CommandResult::Apply(receipt) => Ok(receipt),
            _ => Err(unexpected("apply")),
        });
    Outcome::Applied {
        operation_id,
        result,
    }
}

fn unexpected(command: &str) -> Diagnostic {
    Diagnostic::protocol(format!(
        "the daemon answered {command} with a different kind of result"
    ))
    .with_context("command", command)
}

/// Reads status and every mapping page at one revision, rereading when the
/// registry moves mid-read.
async fn snapshot<A: Authority + ?Sized>(authority: &A) -> Result<Snapshot, Diagnostic> {
    for attempt in 1..=SNAPSHOT_ATTEMPTS {
        let status = status(authority).await?;
        let Some((revision, mappings)) = list_all(authority).await? else {
            continue;
        };
        // On the last attempt a listing from a later revision is still the
        // best view; the status keeps its older revision, so the revision
        // watcher asks for another read.
        if revision == status.revision || attempt == SNAPSHOT_ATTEMPTS {
            return Ok(Snapshot { status, mappings });
        }
    }
    Err(Diagnostic::new(
        REGISTRY_BUSY,
        "the registry kept changing while the console read it",
        Some("the console reads it again after the next change".to_owned()),
        true,
    ))
}

async fn status<A: Authority + ?Sized>(authority: &A) -> Result<RegistryStatus, Diagnostic> {
    match authority.execute(Command::Status).await? {
        CommandResult::Status(status) => Ok(status),
        _ => Err(unexpected("status")),
    }
}

/// Every page of the list at one revision, or `None` when the revision
/// changed between pages.
async fn list_all<A: Authority + ?Sized>(
    authority: &A,
) -> Result<Option<(u64, Vec<MappingView>)>, Diagnostic> {
    let mut mappings = Vec::new();
    let mut after = None;
    let mut revision = None;
    loop {
        let page = page(authority, after.clone()).await?;
        if revision.is_some_and(|seen| seen != page.revision) {
            return Ok(None);
        }
        revision = Some(page.revision);
        let advanced = !page.mappings.is_empty();
        mappings.extend(page.mappings);
        if mappings.len() > MAX_MAPPING_COUNT {
            return Err(Diagnostic::protocol(format!(
                "the daemon listed more than {MAX_MAPPING_COUNT} mappings"
            )));
        }
        match page.next_cursor {
            Some(cursor) if advanced && after.as_ref() != Some(&cursor) => after = Some(cursor),
            Some(_) => {
                return Err(Diagnostic::protocol(
                    "the daemon's mapping list did not advance between pages",
                ));
            }
            None => return Ok(Some((page.revision, mappings))),
        }
    }
}

async fn page<A: Authority + ?Sized>(
    authority: &A,
    after: Option<String>,
) -> Result<ListResult, Diagnostic> {
    let command = Command::List {
        after,
        limit: MAX_MAPPING_PAGE_SIZE,
        include_disabled: true,
    };
    match authority.execute(command).await? {
        CommandResult::List(page) => Ok(page),
        _ => Err(unexpected("list")),
    }
}
