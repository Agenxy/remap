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
remap set hub supgang://MacSolis/dibs --host-header preserve-client
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

### Open a page while preserving root-absolute assets

```text
remap set process.YOUR-SUFFIX http://127.0.0.1:8792/ --landing /ops/scorecard/
```

Root GET and HEAD requests redirect to the landing page and retain their query.
Other requests, including `/bar.css` and POST `/`, reach the origin unchanged.
Landing requires an origin-root HTTP target or a Supgang service. It cannot be
`/`, leave the same origin, contain traversal, fragments or control characters,
or exceed 2048 encoded bytes. Percent-encode non-ASCII text.

Set changes in preview/apply documents accept an optional `landing` field.
`apply --landing PATH` sets it on every set change in that batch. Get, list,
validate and before/after previews show the landing path. Set without landing
removes an existing landing. `validate` accepts the same `--landing` flag.

### Name a Supgang peer machine

```text
remap set pro.agenxy.internal 'supgang://<node-id>?ssh=22,k7=7443'
ssh pro.agenxy.internal
```

A `supgang://` target with a `?` list and no path names a Supgang peer
machine and the TCP services its name reaches, on any network (ADR-0033).

- The peer is selected by its Supgang node ID (64 lowercase hex) or shown
  fingerprint (8 lowercase hex). A name is refused, because Supgang names may
  repeat and change; `supgang resolve <name>` shows the node ID and
  fingerprint.
- Each pair is a service the peer's owner exposes with
  `supgang expose <name> <port>`, and the port this Mac listens on for it.
  A target lists 1 through 16 pairs, with unique service names and unique
  ports. Templates are not accepted here.
- The daemon allocates the mapping one address in `127.77.0.0/16`, the
  lowest free one from `127.77.0.1`. It keeps that address across restarts,
  edits, disable and enable, and frees it when the mapping is removed or
  retargeted to another kind. A registry holds at most 256 peer-machine
  mappings (`E_PEER_MACHINE_CAPACITY`).
- Remap holds a listener on that address at each listed port and carries
  each connection through Supgang's local stream endpoint to the named
  service on the peer, resolving the peer for every connection. TCP only:
  UDP and services the owner has not exposed are not reachable. Supgang
  decides whether a stream opens; a refused or failed stream closes the
  connection, and the daemon's log names the service and the cause, never the
  mapped name, at most once per cause every ten seconds. `remap status`
  counts every connection not carried since the daemon started, by cause.
  A connection silent in both directions for two hours is closed.
- The name answers A with that address, and no AAAA, only while Remap holds
  every listed port. Otherwise it fails with SERVFAIL, and `remap status`
  and `remap doctor` name each port that is not held and why, so a
  connection never reaches another service on this machine in its place.
- **Every listed port is reachable from anything on this Mac that can open
  a loopback TCP connection**, including other accounts and web pages whose
  browser resolves names itself, and it is carried with your Supgang
  identity. List only services the peer protects itself, such as ssh.
- On macOS the installed helper reserves the address and creates each
  listening socket as root, so ports below 1024 such as `ssh=22` work even
  beside Remote Login's sshd; until it has, the cause is `awaiting-socket`.
  On Linux `remapd` binds the ports itself: a port below 1024 needs
  `CAP_NET_BIND_SERVICE`, and a port that a service already listens on at
  every address cannot be held, so the name fails rather than reach that
  service. Choose a free port above 1023 there, such as `ssh=2222`.

`get`, `list`, `preview` and the receipt show the address (`peer_address` in
JSON), the peer and each service's local endpoint.

### Rename a name

```text
remap set old.YOUR-SUFFIX --moved-to new.YOUR-SUFFIX --until 2030-01-01T00:00:00Z
```

Every HTTP request receives a 301 to the new name, retaining its path and query.
The optional RFC3339 deadline stops the mapping from matching; the record stays
listed. Self redirects and chains are refused. Atomic documents use the target
`moved://new.YOUR-SUFFIX?until=2030-01-01T00:00:00Z`.

Set, preview and validate give advisory warnings for pathful HTTP targets.
Set and preview also give a host-policy hint when multiple names share one
origin under use-upstream. The default remains use-upstream; choose preserve-client
explicitly when an origin serves several names or selects virtual hosts by name.
See [Name a local site](../tutorials/name-a-local-site.md) for the complete recipe.

### Reachability advice

Preview, apply, set and enable try one TCP connection, for at most a second, to
each loopback HTTP target they leave enabled: an address on `127.0.0.0/8` or
`::1`, or `localhost`. When nothing accepts it, the result carries an advisory:

```text
  Advisory   api.test: target refused connection; nothing is listening there, so requests will fail with 502 E_GATEWAY_UPSTREAM (cause refused) until a service starts
```

The change is still previewed or committed; start the service whenever you
like. Peer targets, other names and addresses off loopback are never probed,
and the probe sends no bytes. An exact retry of an apply returns its stored
receipt with advice about what is listening at the time of the retry.

### When the gateway cannot reach a target

A request that matched a mapping but could not be completed receives a plain-text
error naming the code, the matched mapping and a stable cause:

```text
Remap could not route this request.

E_GATEWAY_UPSTREAM: The mapping's target refused the connection.

Mapping: api.test
Cause: refused
Next: start the service; `remap get api.test` shows the target.
```

The causes are `refused`, `timeout`, `tls`, `reset`, `unreachable` and `other`.
`504 E_GATEWAY_TIMEOUT` always has cause `timeout`. The response never shows the
target's address or port; `remap get` shows it to you.

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
effects, then require macOS device-owner authentication in an interactive
terminal. Text input, a pseudo-terminal, and a disclosed state token cannot
substitute for Touch ID or the account-password fallback. There is no `--yes`
flag or environment-variable bypass.

With `--json`, a mutation writes one canonical response per line: the preview
before macOS authentication, followed by the mutation result. JSON does not
make lifecycle mutation noninteractive. Errors are one bounded JSON object on
standard output.

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
      "schema_version": 4,
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
