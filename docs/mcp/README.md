# Remap MCP server

Remap is agent-native: MCP and the human CLI are peer adapters over one
authoritative per-user daemon. The MCP process owns no registry, performs no
privileged installation, and cannot grant authority the daemon denied.

## Start and connect

An installed Remap service starts the authority automatically. For an isolated
development checkout, run the foreground authority before the agent host:

```text
remap daemon
```

Codex can register the installed server without editing configuration by hand:

```text
codex mcp add remap -- /usr/local/bin/remap mcp
codex mcp get remap
```

Claude Code uses the same stdio command. Choose `user` scope to make it
available outside this checkout:

```text
claude mcp add --scope user remap -- /usr/local/bin/remap mcp
claude mcp get remap
```

Hosts that accept the familiar JSON form can use:

```json
{
  "mcpServers": {
    "remap": {
      "command": "/usr/local/bin/remap",
      "args": ["mcp"]
    }
  }
}
```

Use the same explicit `--data-dir PATH` on the foreground daemon and MCP command
only for an isolated development authority. Standard output from `remap mcp` is
protocol-only. Remove the registration with `codex mcp remove remap` or
`claude mcp remove --scope user remap`.

## Compatibility contract

Remap implements exactly two MCP revisions:

- `2026-07-28`: `server/discover`, self-contained request metadata, result
  discriminators, scoped cache hints, MRTR-compatible results, and
  `subscriptions/listen`.
- `2025-11-25`: legacy `initialize`, the older result shape, and
  `resources/subscribe` / `resources/unsubscribe`.

The official Rust SDK drives both executable compatibility tests. The modern
client can commit a mapping and the previous client observes its revision from
the same daemon. Revision-specific cache and result fields are not emitted on
the previous wire contract. In particular, `initialize` cannot negotiate the
stateless revision. A previous-version client receives the stable Apps
extension only when it explicitly advertises the compatible MCP Apps MIME
type; non-negotiating clients receive no extension or App surface.

## Agent workflow

1. Call `remap_status` and retain its revision.
2. Use `remap_validate` and `remap_preview` before unfamiliar or multi-change
   work.
3. Commit with the observed `expected_revision` and a fresh UUIDv4
   `operation_id`.
4. Reuse that identifier only to retry the exact same call.
5. Verify the receipt or read the affected mapping.

A conflict is a request to reconsider, not an invitation to blind retry.

## Tools

| Tool | Effect |
|---|---|
| `remap_status` | Read revision, schema, and mapping counts |
| `remap_list` | Read a bounded deterministic page |
| `remap_get` | Read one exact mapping key |
| `remap_resolve` | Explain exact and wildcard selection without network I/O |
| `remap_validate` | Canonicalize one proposed mapping without state changes |
| `remap_preview` | Project an ordered atomic batch |
| `remap_set` | Create or retarget one mapping |
| `remap_enable` | Enable one existing mapping |
| `remap_disable` | Disable without deleting |
| `remap_remove` | Delete one mapping |
| `remap_apply` | Commit an ordered batch atomically |

Successful calls return matching text and typed structured content. Domain and
authority failures are structured tool errors with a stable code, message,
hint, retryability, and safe context. Each advertised output schema accepts
both its typed success envelope and this common diagnostic shape. Unknown input
fields are rejected, including for tools with no required arguments.

## Resources and UI

- `remap://help`
- `remap://privacy`
- `remap://status`
- `remap://mappings`
- `ui://remap/dashboard/<build>`

Static resources are public-cacheable in the modern protocol. Machine state is
private-cacheable and never shareable across users. Status and mappings can be
subscribed to in both supported revisions. Each subscription holds a bounded
long-poll against the daemon's in-memory revision watch; it does not poll the
database. After each bounded wait, status subscriptions also compare the
maintenance diagnostic, so blocked and recovered retention states notify both
protocol eras without pretending the mapping revision changed. Mapping
subscriptions remain revision-driven. The dashboard URI includes a digest of
its bytes so public host caches cannot serve an older panel after an upgrade.

The dashboard uses the stable MCP Apps `2026-01-26` extension and is exposed
only after the host negotiates `text/html;profile=mcp-app`. It is a bundled,
self-contained HTML document with no external network, script, font, image, or
stylesheet origin. It renders status, mapping pages, validation, resolution,
previews, receipts, exact lookups, errors, and cancellations; follows host
theme, style variables, fixed or flexible container dimensions, safe-area
insets, locale, and display mode; and honors reduced-motion preferences. Hosts
without an App renderer receive the same complete text and typed result.

## Security boundary

The initial transport is local stdio. MCP reaches `remapd` through a private
Unix socket with operating-system peer credential checks, bounded frames, I/O
deadlines, a bounded connection count, optimistic concurrency, and idempotent
receipts. Loopback is not treated as authentication, so remote Streamable HTTP
is intentionally absent until scoped credentials, revocation, issuer binding,
origin validation, and rate limiting are designed and proven together.

The stdio transport rejects messages over 1 MiB and admits at most 32 in-flight
requests. It releases cancelled work without leaking capacity; duplicate live
request identifiers fail closed. If standard output stops draining, error
delivery and the session close are bounded to 250 milliseconds rather than
allowing an unbounded task queue. The process admits at most four live
subscriptions.

MCP mapping pages contain at most 64 records and MCP preview/apply batches at
most 32 changes so text plus structured results remain inside the 1 MiB MCP
envelope. The daemon's local-control contract independently supports 128-record
pages and 64-change batches inside its 1 MiB frame. The registry accepts at
most 16,384 mappings. Shutdown cancels idle readers, drains every accepted
mutation, and joins the writer before removing the socket or releasing the
authority lock.

If a same-user SQLite reader temporarily prevents secure WAL truncation, Remap
keeps reads available, blocks further mutations, and retries retention
maintenance before the next mutation and on the next bounded interval. Status
exposes the maintenance diagnostic, while exact retries of already committed
operations continue to return their stored receipts. A durable database marker
carries an owed checkpoint across restarts. Checkpoint attempts fail fast
instead of inheriting the database's ordinary five-second contention wait, so
privacy maintenance cannot stall the single authority writer or status reads.
A permanent maintenance failure stops the authority rather than silently
weakening the privacy contract.
