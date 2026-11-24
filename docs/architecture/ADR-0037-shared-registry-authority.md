# ADR-0037: One Mac can be the registry every member follows, over Supgang

## Status

Proposed, 2026-11-24. It amends ADR-0003 (authority boundaries) and ADR-0016
(peers are Supgangs) and begins M7. Peer-to-peer replication, the second mode,
is a later ADR.

## Context

On 24 November the owner asked that Remap run on every computer and keep the
same names on all of them. They also said: "We should be able to have a remap
server on pro, or have various remaps be able to sync across devices - we
should eventually support both, but for now I think the server might be
simpler." They want devices (a KVM, a USB hub, Spark analyzers, internal sites)
reached by descriptive names from anywhere, with no addresses to remember and
no extra logins.

Today every Mac keeps its own registry. A name added on MacMarine does not
exist on Solis or pro, and the same name can point to different places on
different machines.

ADR-0016 gave node identity, enrollment, authentication and revocation to
Supgang, and redefined M7 as replicating signed operations over Supgang's
transport and identity. Supgang's opt-in service tunnels (Supgang ADR 0003) let
an owner expose a loopback port by name to every member of the hive. Supgang
admits each stream against that exposure, and it never resolves addresses on
the target.

## Decision

### Roles

A Remap installation is in one of two roles. The default is unchanged.

- **Standalone**: the daemon's own registry is the only registry.
- **Follower of `<authority>`**: the daemon keeps two layers.
  - The **shared** layer is a read-only copy of the authority's registry, at
    the authority's revision.
  - The **local** layer holds this Mac's own mappings, exactly as today.

The authority is an ordinary Remap installation that has turned on serving.
Nothing else changes on it: its registry is the shared registry, and its
`remapd` stays the sole writer (ADR-0003).

`remapd` remains the sole writer of each Mac's registry. A follower applies
each shared revision through its own daemon, as one atomic commit. The DNS
listener and the gateway keep reading the same immutable snapshot they read
today.

### Resolution on a follower

- A local mapping wins over a shared mapping with the same pattern. Exact user
  intent on this Mac wins. `remap list`, `remap resolve` and the MCP tools say
  which layer answered. Status counts shadowed names as conflicts, so a
  shadowed name is visible and never silent.
- Wildcard precedence is unchanged (ADR-0002). It is evaluated over the merged
  view.

### What a shared mapping may point to

A target is interpreted on the machine that resolves it. Shared mappings must
therefore mean the same thing on every member:

- **Allowed**:
  - peer targets: `supgang://`, `supgang+http://`, and the peer-machine target
    of ADR-0033;
  - DNS address and alias targets;
  - `moved://`;
  - HTTP(S) URLs whose host is not loopback.
- **Refused at the authority**: a shared mapping whose HTTP target is loopback
  (`127.0.0.0/8`, `::1`, `localhost`). The refusal says to expose the service
  through Supgang and use the peer form. Such a mapping belongs in a Mac's
  local layer.

A peer target that names the Mac resolving it is routed to the Supgang
exposure's own loopback port. It is not sent through a tunnel to itself. That
way pro reaches its own services through the same shared names as everyone
else.

### Transport and authentication

There are no new credentials. Membership is Supgang's.

1. The authority's `remapd` listens on one loopback TCP port, the **registry
   service**. It speaks the `remap.registry/v1` protocol described below. It
   never listens on a non-loopback address.
2. The owner exposes that port through Supgang under the service name `remap`,
   with `supgang expose remap <port>`. Turning serving on prints this exact
   command; Remap never runs it.
3. A follower opens the stream through Supgang's local stream endpoint, the
   one ADR-0026 already uses. Supgang admits the stream only from an enrolled
   member, against the owner's exposure. The stream is end-to-end
   authenticated to the authority's node key.
4. The follower is configured with the authority's Supgang node ID, not a
   name or address. A revoked or unenrolled machine gets no stream.

**Reads.** Any admitted member may read.

**Writes.** In v1, a member's writes travel over the same stream as ordinary
`remap.control` commands: `set`, `remove`, `enable` and `disable`, each with
`expected_revision` and `operation_id`, exactly as locally. The authority
commits them through its own daemon. Admission is the authorization, because
every admitted member is one of the owner's own machines. This matches what
the exposure already grants: a member that can reach `remap` can already reach
every service the owner exposed. The authority records every write in its
operation log with the revision and operation ID. The author is recorded as
"a hive member" until Supgang can attest the caller (see Dependencies).

Writing to the shared layer is explicit. `remap set --shared …` writes there.
Plain `remap set` on a follower still writes the local layer, so that no
existing command changes meaning. The MCP tools take a `layer` argument, and
it defaults to `local`.

### `remap.registry/v1`

The protocol is a framed request–response, with one long-poll:

- `hello {protocol, follower_revision}` →
  `{authority_node, revision, schema_version}`.
- `changes {since}` returns either `{revision, operations[]}` or, when
  `since` is older than the authority's retained log, `{revision, snapshot}`.
  The snapshot is the canonical mapping list plus its SHA-256. The call waits
  up to 60 seconds for a revision newer than `since`.
- Writes are the existing `remap.control` mutation messages, unchanged.

Every frame is bounded. The registry service rejects:

- an unknown version;
- a frame larger than 1 MiB;
- more than 8 concurrent streams.

Each of these is rejected before any registry access.

### Offline behaviour

A follower stores the shared layer in its own SQLite registry, together with:

- the authority's node ID;
- the revision;
- the snapshot hash;
- `synced_at`.

When the authority is unreachable, the last-known shared layer keeps
resolving indefinitely. It does not expire, because names that disappear when
pro sleeps would be worse than names that are stale. While it cannot sync, the
follower:

- retries with backoff, starting at 5 s and capped at 5 min;
- says in `remap system status` and the menu-bar app "following pro, last
  synced <time> ago (revision N), pro unreachable since <time>";
- refuses `--shared` writes with an error that names the authority and says
  it is unreachable. It never queues writes silently.

A change to the authority's node ID, or a lower revision than the one held, is
refused and surfaced. The follower never rolls back silently.

### Commands

- On the authority: `remap registry serve` (turn on), `remap registry stop`.
- On a member: `remap registry follow <node-id>` and `remap registry unfollow`.
  Unfollowing keeps the last shared layer as local mappings only if
  `--keep-mappings` is given; otherwise it removes them in one revision.
- `remap registry status` shows the role, authority, revisions, last sync and
  shadowed names.

Each of these changes daemon configuration through the existing authenticated
control path. None needs administrator approval or a new install.

## Dependencies

- **Supgang**: an exposure named `remap` on the authority. That is an owner
  action, done once.
- **Supgang, wanted but not blocking**: the caller's attested node ID on an
  exposed stream. With it, the operation log names the author, and the
  authority can limit `--shared` writes to members the owner chooses. This is
  requested from Supgang's lead and recorded here as v1.1.

## Consequences

- One `remap set --shared` makes a name resolve on every member, wherever it
  is. A member that is offline at the time picks the name up on its next
  sync.
- An HTTP mapping that is loopback on the authority, such as today's
  `agenxy.internal → http://127.0.0.1:8792/` on MacMarine, cannot be shared.
  It is rewritten to the peer form first.
- A compromised member can rewrite shared names until Supgang attests callers.
  That member can already reach every exposed service. The operation log on
  the authority and the follower's change notices make a rewrite visible, and
  one revision reverts it.
- Peer-to-peer replication (signed operations between equals, with conflicts
  surfaced) remains the M7 exit criterion. It reuses this ADR's layers,
  storage and status, and replaces the single authority with a set of
  replicas.
- Installing Remap is unchanged. Follower mode arrives in an ordinary update.
