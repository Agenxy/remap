# `remap` command reference

The CLI is human-readable by default and emits a stable JSON envelope when
`--json` is present. Stateful commands reach the same authoritative daemon as
MCP; they never edit the registry directly.

## Start the local authority

```text
remap daemon
remap status
```

The daemon runs in the foreground until interrupted. Its private data directory,
database, and Unix control socket are user-owned and permission restricted. Use
`--data-dir PATH` for an explicit test or development authority.

## Work with mappings

```text
remap set atlas http://127.0.0.1:5173
remap set database 192.168.1.40
remap set '*.lab' https://example.com:9443 --host-header use-upstream
remap list --all
remap get atlas
remap resolve service.lab
remap disable atlas
remap enable atlas
remap remove atlas
```

Interactive mutations read the current registry revision and generate a UUIDv4
operation identifier. Automation can make both guards explicit:

```text
remap set atlas 127.0.0.1 \
  --expect 12 \
  --operation-id 4df4bb55-93bb-4f99-9707-9761f6a69364
```

Reuse an operation identifier only for an exact retry. A stale revision or a
conflicting reuse fails without partial effects. Supplying `--operation-id` on
a single-mapping command therefore also requires `--expect`; both values must
remain identical on a retry.

Humans and agents share the same atomic preview/apply model. The document is a
JSON array of tagged changes and is limited to 512 KiB:

```json
[
  {
    "kind": "set",
    "pattern": "atlas",
    "target": "http://127.0.0.1:5173",
    "host_policy": "preserve-client"
  },
  { "kind": "disable", "pattern": "old-atlas" }
]
```

```text
remap preview changes.json
remap apply changes.json --expect 12 \
  --operation-id 4df4bb55-93bb-4f99-9707-9761f6a69364
```

Omit the file or use `-` to read the document from standard input. `apply`
requires both guards so a lost response can be retried exactly.

Listings are deterministically ordered and bounded. `--limit` accepts 1 through
128; a returned cursor can be supplied with `--after`.

## Validate without the daemon

```text
remap validate atlas http://127.0.0.1:5173
remap validate google.com 127.0.0.1
remap validate '*.lab' https://example.com:9443/base
```

Validation canonicalizes the name, destination, inferred destination type, and
HTTP host policy without reading or changing authority state.

## Agent host

```text
remap mcp
```

This command serves MCP on standard input and output. It emits no banners or
human results on standard output. See [the MCP guide](../mcp/README.md) for host
configuration, versions, tools, resources, and security boundaries.

## Manage the installed service

```text
remap system status
remap system recover
remap system uninstall
```

These commands hand off directly to the locally signed lifecycle client in the
active immutable generation. They do not use a shell, accept a helper path, or
run a binary from the working directory. The privileged service accepts the
client only when its user, code identifier, certificate, and exact code hash
match the root-owned lifecycle configuration.

`status` is read-only. `recover` and `uninstall` first print the exact native
effects. At a terminal, type the displayed `approve <token-prefix>` phrase.
Piped use must return the complete 64-character token on standard input. Empty
input, `yes`, stale state, and token mismatches make no change. There is no
`--yes` flag or environment-variable bypass.

With `--json`, a mutation writes one canonical response per line: the preview
before approval, followed by the mutation result. This lets a controller read
the state-bound token before it writes the complete token to standard input.
Errors are one bounded JSON object on standard output.

## JSON contract

Every structured response includes schema identity and success state:

```json
{
  "schema": "remap.cli/v1",
  "ok": true,
  "command": "status",
  "result": {
    "kind": "status",
    "value": {
      "revision": 12,
      "mapping_count": 4,
      "enabled_count": 3,
      "schema_version": 1,
      "daemon_version": "0.2.0"
    }
  }
}
```

When retryable retention maintenance is blocking new mutations, status adds a
`maintenance` diagnostic with its stable code, explanation, recovery hint, and
retryability. Reads and previews remain available; an exact retry of an already
committed operation still returns its stored receipt.

Errors retain the daemon's stable identity, retry guidance, and safe context:

```json
{
  "schema": "remap.cli/v1",
  "ok": false,
  "error": {
    "code": "E_REVISION_CONFLICT",
    "message": "the registry is at revision 13, not the expected revision 12",
    "detail": "current_revision=13, expected_revision=12",
    "hint": "read current mappings, reconsider the change, and use the new revision",
    "retryable": false,
    "context": {
      "current_revision": "13",
      "expected_revision": "12"
    }
  }
}
```

Structured results are written only to standard output. Human diagnostics and
service lifecycle messages use standard error. Broken pipes terminate cleanly.

## Exit status

| Status | Meaning |
|---:|---|
| `0` | Command completed successfully, including help and a closed downstream pipe |
| `1` | A non-retryable authority or service operation failed |
| `2` | Usage or supplied offline mapping input is invalid |
| `64` | Native lifecycle command usage is invalid |
| `65` | Native lifecycle data or integrity validation failed |
| `69` | The native lifecycle client or requested operation is unavailable |
| `70` | Internal command state violated an invariant |
| `73` | Native lifecycle state is busy or conflicts with the reviewed state |
| `75` | A retryable authority or local transport condition prevented completion |
| `77` | Native lifecycle authority or approval was rejected |
