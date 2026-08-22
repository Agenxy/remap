use remap_protocol::{
    Command, CommandResult, ControlClient, Diagnostic, MAX_MAPPING_PAGE_SIZE, Surface,
};
use rmcp::ErrorData;
use rmcp::model::{
    CacheScope, ListResourcesResult, ReadResourceResponse, ReadResourceResult, Resource,
    ResourceContents,
};
use serde::Serialize;

use crate::ui::{APP_MIME_TYPE, dashboard_html, dashboard_uri, resource_meta};

pub(crate) const HELP_URI: &str = "remap://help";
pub(crate) const PRIVACY_URI: &str = "remap://privacy";
pub(crate) const STATUS_URI: &str = "remap://status";
pub(crate) const MAPPINGS_URI: &str = "remap://mappings";

const STATIC_TTL_MS: u64 = 3_600_000;
const STATE_TTL_MS: u64 = 1_000;
const PRIVACY: &str = include_str!("privacy.md");
const HELP: &str = r"# Remap MCP

Remap maps arbitrary names to network destinations through one per-user authority.

Read before write: call `remap_status`, then `remap_preview`. Every mutation requires
the observed `expected_revision` and a fresh UUIDv4 `operation_id`. Reuse an operation
ID only when retrying the exact same request. A stale revision fails instead of
overwriting somebody else's work.

Prefer `remap_set` for one create or retarget operation and `remap_apply` for a batch.
The batch is atomic. `remap_resolve` explains exact and wildcard precedence without
performing network I/O. Read `remap://privacy` for the data boundary.
";

/// Lists the fixed, bounded resource catalog.
pub(crate) fn list(cache_hints: bool, include_app: bool) -> ListResourcesResult {
    let mut resources = vec![
        resource(
            HELP_URI,
            "help",
            "Agent workflow and mutation discipline",
            "text/markdown",
        ),
        resource(
            PRIVACY_URI,
            "privacy",
            "Remap's local-first privacy contract",
            "text/markdown",
        ),
        resource(
            STATUS_URI,
            "status",
            "Current authoritative registry status",
            "application/json",
        ),
        resource(
            MAPPINGS_URI,
            "mappings",
            "First bounded page of authoritative mappings",
            "application/json",
        ),
    ];
    if include_app {
        resources.push(
            Resource::new(dashboard_uri(), "dashboard")
                .with_title("Remap dashboard")
                .with_description("Accessible human view of registry status and mappings")
                .with_mime_type(APP_MIME_TYPE)
                .with_size(size_of(dashboard_html()))
                .with_meta(resource_meta()),
        );
    }
    let result = ListResourcesResult::with_all_items(resources);
    if cache_hints {
        result
            .with_ttl_ms(STATIC_TTL_MS)
            .with_cache_scope(CacheScope::Private)
    } else {
        result
    }
}

/// Reads one fixed resource, consulting the daemon only for private state.
pub(crate) async fn read(
    uri: &str,
    client: &ControlClient,
    cache_hints: bool,
    include_app: bool,
) -> Result<ReadResourceResponse, ErrorData> {
    if uri == dashboard_uri() && include_app {
        return Ok(app_resource(cache_hints));
    }
    match uri {
        HELP_URI => Ok(static_text(HELP_URI, HELP, "text/markdown", cache_hints)),
        PRIVACY_URI => Ok(static_text(
            PRIVACY_URI,
            PRIVACY,
            "text/markdown",
            cache_hints,
        )),
        STATUS_URI => read_status(client, cache_hints).await,
        MAPPINGS_URI => read_mappings(client, cache_hints).await,
        _ => Err(ErrorData::resource_not_found(
            format!("unknown Remap resource: {uri}"),
            None,
        )),
    }
}

fn resource(uri: &str, name: &str, description: &str, mime: &str) -> Resource {
    Resource::new(uri, name)
        .with_title(format!("Remap {name}"))
        .with_description(description)
        .with_mime_type(mime)
}

fn static_text(uri: &str, text: &str, mime: &str, cache_hints: bool) -> ReadResourceResponse {
    let result =
        ReadResourceResult::new(vec![ResourceContents::text(text, uri).with_mime_type(mime)]);
    with_cache(result, cache_hints, STATIC_TTL_MS, CacheScope::Public).into()
}

fn app_resource(cache_hints: bool) -> ReadResourceResponse {
    let result = ReadResourceResult::new(vec![
        ResourceContents::text(dashboard_html(), dashboard_uri())
            .with_mime_type(APP_MIME_TYPE)
            .with_meta(resource_meta()),
    ]);
    with_cache(result, cache_hints, STATIC_TTL_MS, CacheScope::Public).into()
}

async fn read_status(
    client: &ControlClient,
    cache_hints: bool,
) -> Result<ReadResourceResponse, ErrorData> {
    match client
        .execute(Command::Status)
        .await
        .map_err(daemon_error)?
    {
        CommandResult::Status(status) => private_json(STATUS_URI, &status, cache_hints),
        _ => Err(internal_variant("status")),
    }
}

async fn read_mappings(
    client: &ControlClient,
    cache_hints: bool,
) -> Result<ReadResourceResponse, ErrorData> {
    let command = Command::List {
        after: None,
        limit: MAX_MAPPING_PAGE_SIZE,
        include_disabled: true,
    };
    match client.execute(command).await.map_err(daemon_error)? {
        CommandResult::List(mappings) => private_json(MAPPINGS_URI, &mappings, cache_hints),
        _ => Err(internal_variant("mapping list")),
    }
}

fn private_json<T: Serialize>(
    uri: &str,
    value: &T,
    cache_hints: bool,
) -> Result<ReadResourceResponse, ErrorData> {
    let text = serde_json::to_string_pretty(value).map_err(|error| {
        ErrorData::internal_error(format!("could not encode Remap resource: {error}"), None)
    })?;
    let result = ReadResourceResult::new(vec![
        ResourceContents::text(text, uri).with_mime_type("application/json"),
    ]);
    Ok(with_cache(result, cache_hints, STATE_TTL_MS, CacheScope::Private).into())
}

fn with_cache(
    result: ReadResourceResult,
    cache_hints: bool,
    ttl_ms: u64,
    scope: CacheScope,
) -> ReadResourceResult {
    if cache_hints {
        result.with_ttl_ms(ttl_ms).with_cache_scope(scope)
    } else {
        result
    }
}

fn daemon_error(diagnostic: Diagnostic) -> ErrorData {
    let message = diagnostic.to_string();
    let data = serde_json::to_value(diagnostic).ok();
    ErrorData::internal_error(message, data)
}

fn internal_variant(expected: &str) -> ErrorData {
    ErrorData::internal_error(
        format!("the daemon returned a result other than {expected}"),
        None,
    )
}

fn size_of(text: &str) -> u64 {
    u64::try_from(text.len()).unwrap_or(u64::MAX)
}

/// Creates the MCP-surface daemon client for the native default path.
pub(crate) fn discover_client() -> Result<ControlClient, Diagnostic> {
    ControlClient::discover(Surface::Mcp, env!("CARGO_PKG_VERSION"))
}
