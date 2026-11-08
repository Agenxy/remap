# ADR-0005: Agent-native MCP control surface

Status: accepted for implementation, August 2026.

## Context

Remap is infrastructure operated by people and by software agents. Treating the
CLI as the product contract and adding MCP later as a translation shim would
create two classes of operator: humans with complete control and agents with a
partial, lossy surface. Giving an MCP process its own registry would be worse;
it would violate the single-writer authority boundary and partition state by
client.

The current MCP revision, `2026-07-28`, replaced the session handshake with a
stateless request model. The immediately previous revision, `2025-11-25`, is
still used by deployed hosts and retains `initialize` and session-oriented
behavior. Both revisions must operate against the same Remap authority.

## Decision

### MCP is a first-class adapter, not an authority

Remap ships one domain command model and one authoritative daemon. The native
app, CLI, and MCP server translate their inputs into that model and return the
same receipts and diagnostics. Only `remapd` validates authority state, commits
mutations, advances the registry revision, and publishes snapshots.

The dependency direction is:

```text
MCP transport -> MCP presentation -> control client -> remapd -> registry
CLI parsing   -> CLI presentation -> control client -----^
native app    -> platform adapter -> control client -----^
```

An MCP server never opens the registry database, edits snapshots, holds CA
private keys, or reimplements mapping policy.

### Exactly two protocol revisions

Remap supports:

- `2026-07-28` as the primary, stateless MCP contract. It uses
  `server/discover`, per-request protocol/client metadata, deterministic list
  results, result types, cache hints, and the revision's subscription model.
- `2025-11-25` as the immediate compatibility contract. It uses the legacy
  initialization lifecycle and only fields valid for that revision.

The lists are explicit and tested. A modern revision is never negotiated by the
legacy `initialize` path. Fields required by one revision are not leaked onto
the other. Both paths reach one control client and therefore one registry,
revision order, authorization policy, and error taxonomy.

Remap uses the official Rust MCP SDK rather than maintaining private JSON-RPC
machinery. The SDK is pinned exactly and upgraded only after its wire behavior
passes Remap's compatibility suite.

The SDK's current tracing macro edge retains `syn` 2 while its own macros and
Remap use `syn` 3. The dependency gate carries one exact-version exception for
that upstream edge; duplicate denial remains active for every other crate, and
the exception must be removed when `tracing-attributes` converges.

### Local transport first

The initial server uses MCP stdio, the standard local subprocess transport. It
connects to `remapd` through Remap's authenticated local-control protocol. This
preserves the same operating-system identity boundary as the CLI and does not
open a listening network service.

Streamable HTTP is deferred until Remap has a complete remote authorization
design with scoped credentials, revocation, issuer binding, origin validation,
rate limits, and an explicit enablement flow. Loopback alone is not treated as
authentication. The absence of HTTP does not reduce the stdio tool or resource
surface.

### Agent workflow

The MCP surface is designed around an observe, preview, commit, verify loop:

1. Read status, mappings, or a resolution explanation and its registry
   revision.
2. Preview a proposed change when its consequence is not already obvious.
3. Commit against `expected_revision`; stale decisions fail without effects.
4. Read the returned receipt or current resource to verify the resulting state.

Mutations support idempotency keys and atomic batches at the domain-command
boundary. A retry either returns the original receipt or fails as a conflicting
reuse; it never applies the same intended operation twice.

Tool descriptions state effects, authority, preconditions, and the useful next
step. Destructive and read-only annotations are accurate. Required and unknown
parameters are enforced, not merely documented. Validation failures are normal
tool results so hosts show their full explanation; JSON-RPC errors are reserved
for malformed or unroutable protocol messages.

### Tools and resources

The M1 surface covers the same authority as the CLI:

- Inspect: status, list, get, resolve, and offline validation.
- Change: create or retarget, enable, disable, remove, and atomically apply a
  batch.
- Safety: preview, expected-revision checks, idempotency, and exact receipts.

Canonical resources are server guidance, current status, the bounded mapping
collection, the privacy policy, and an MCP Apps status and outcome view. Status and
mapping resources support change notifications through modern
`subscriptions/listen` and legacy `resources/subscribe`.

Mapping and diagnostic resources are private-cache data. Static documentation
may be public-cache data only when its bytes are identical for every caller and
contain no machine state. A cache scope is an authorization decision, not only
a performance hint.

### Human and model presentation

Every successful tool result has concise text and a stable structured result.
The two carriers answer the same domain question; a host choosing one must not
silently receive less information than a host choosing the other.

The MCP Apps view is an in-conversation status and operation-outcome surface,
not the only human UI. It is static, content-addressed, self-contained, usable
without external origins, and draws a useful shell before any host handshake
completes. It receives live data through tool results and can refresh through
host-authorized tool calls. Hosts without MCP Apps retain complete text and
structured behavior.

Large mapping collections are paginated and bounded before allocation. Default
responses are compact enough for model context; full detail is explicit.

### Security and privacy

- `remapd` authenticates the local control peer. The MCP layer cannot grant
  authority that the daemon denied.
- Mutations use optimistic concurrency and produce audit receipts.
- Stdio messages and daemon frames are limited to 1 MiB. At most 32 MCP
  requests and four subscriptions are active per process. MCP results use
  64-record pages and 32-change batches; the daemon's separate local-control
  envelope supports 128-record pages and 64-change batches. The authority holds
  at most 16,384 mappings.
- Unknown fields are rejected with the offending names when the protocol shape
  permits it; a misspelled parameter never becomes a silent no-op.
- Any future operational logs may contain only operation categories, durations,
  revisions, and opaque correlation identifiers, never mapping names, targets,
  tool arguments, or result bodies. M1 emits no routine structured log stream.
- MCP instructions and schemas contain no machine-specific state.
- The Apps document has no external network, script, font, image, or stylesheet
  dependency and declares a restrictive content security policy.

## Verification requirements

The MCP gate must prove:

- discovery and initialization negotiate only their valid revision families;
- the latest and previous revisions observe and mutate one shared authority;
- revision-specific required fields appear only where valid;
- official SDK clients can list, call, read, and subscribe;
- every declared tool parameter reaches shipped code and affects its documented
  behavior;
- missing, null, unknown, and near-miss parameters produce useful failures;
- all mutation tools enforce authorization, expected revisions, idempotency,
  preview semantics, and annotations;
- mapping resources are never marked shareable across authorization contexts;
- malformed frames, oversized inputs, cancellation, slow readers, and daemon
  loss remain bounded and fail closed for mutations;
- rendered Apps behavior is checked at desktop and mobile sizes with every tool
  result shape, host-context changes, cancellation, and hostile text. A real
  supporting host is required before claiming host-specific interoperability.

## Consequences

Agent support advances the authoritative daemon and local protocol rather than
creating an M0-only side channel. This is more work than exposing the offline
validator, but it produces one durable product boundary.

The MCP server remains useful without a graphical host, and the native app
remains useful without an agent. Neither is a degraded wrapper around the other.

Remote MCP access is intentionally unavailable until it can be authenticated
and authorized without relying on network location. Users can still compose
the stdio server through an agent host on their own machine.
