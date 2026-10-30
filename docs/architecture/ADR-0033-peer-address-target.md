# ADR-0033: A peer's name reaches it on any network

## Status

Proposed, 2026-10-30. The owner asked on 30 October for this as a capability,
not a document: the fleet travels, and its machines are spread across networks.
The shape was settled with Supgang the same day. It extends ADR-0016 and
ADR-0026, which route a peer's advertised HTTP services, to a peer's exposed
TCP services. It adds one privileged operation, a loopback address
reservation, so it is recorded here before that lands.

Steps 1 and 3 are implemented for review on `feature/peer-machine-names`, as
recorded under "Implementation of steps 1 and 3". Step 2, the reservation, is
built separately. Installing and choosing mappings stay with the owner.

## Context

On 30 October a new MacBook Pro joined the fleet. The owner asked for a stable
name for it that keeps working wherever the machines are.

Remap cannot provide one today:

- `supgang://<peer>/<service>` follows the peer, because the gateway resolves
  it on every request. But it carries only HTTP, to services the peer
  *advertises*, through the loopback gateway.
- A name for the machine itself, for ssh, K7 or any other TCP service, can
  only be an `address` mapping. That is one fixed IP, which goes stale when the
  machine changes network and never worked off the LAN.

What reaches another member depends on where both machines are, and Supgang
already chooses the path. Its authenticated stream uses the on-link route when
one exists and its forwarded QUIC port otherwise. A peer's own services are
usually reachable only through that stream: an owner *exposes* a loopback
service with `supgang expose <name> <port>`, and Supgang admits a stream to it
against that exposure. A direct LAN connection to an exposed service fails,
because it listens on the peer's loopback.

Answering a peer's LAN address would therefore be wrong for exposed services,
and it would change the answer every time either machine moved. The name
should be one stable local endpoint, and Supgang should carry what reaches it.

## Decision

### The mapping

`supgang://<node-id>?<service>=<port>[,<service>=<port>…]` names a machine and
the exposed services that name reaches. An example:

`pro.agenxy.internal → supgang://<node-id>?ssh=22,k7=7443`

- The peer is selected by its Supgang node ID or shown fingerprint, never its
  name. Supgang names are labels that may repeat and change. A name in this
  position is refused, and the refusal shows the matching fingerprint.
  `remap get` shows the peer's current signed name for display.
- Each pair is a service the peer's owner exposes and the port this Mac
  listens on for it. Ports are unique within a mapping. Names follow Supgang's
  restriction: 1 to 16 ASCII bytes.
- When Supgang's signed record carries exposures (a proposed ADR 0002
  amendment), they replace the explicit pairs, so K7 and Supgang can change
  ports without anyone editing a mapping. Until then the owner writes the
  pairs.
- The owner writes every mapping. Remap imposes no name or suffix, and a
  Supgang record never creates one.

### What the name answers

Each enabled peer mapping is given a stable address in `127.77.0.0/16`,
recorded with the mapping. DNS answers A with that address and no AAAA, from
the immutable snapshot as for every other mapping. The answer never changes
while the mapping exists, however the peer moves. Supgang alone follows the
peer's address.

### What reaches the peer

- **A reserved loopback address.** On macOS the root resolver supervisor makes
  the mapping's address an `lo0` alias. Linux already routes all of
  `127.0.0.0/8` to loopback, so nothing is reserved there. The reservation is
  the one new privileged operation, held as follows:
  - It runs as its own task in the root process, beside the resolver
    supervisor. Nothing it does can bypass, suspend or restore DNS.
  - Every 5 seconds it asks `remapd` over the existing `remap.system/v1`
    socket with one additive request, `loopback_reservations`. The answer
    carries addresses only, never a name, peer or service, and every other
    response is unchanged byte for byte.
  - Root refuses the whole answer if any address is outside
    `127.77.0.0/16`, duplicated, or beyond 256. It acts only inside that
    range, and removes only aliases it recorded in the root-owned
    `loopback-reservations-v1.json` beside the activation record.
  - An address is recorded before it is added and forgotten only after it
    is removed, so a crash never leaves an alias nobody owns.
  - Aliases are held while a DNS activation exists, including while DNS is
    suspended, so a flap never drops connections. An unreachable daemon
    leaves them as they are. Deactivation and uninstall release them all,
    and boot restores them through the same reconciliation.
- **Listeners bound only to that address.** The gateway listens on the
  mapping's address at each pair's port, never on a non-loopback address and
  never on `127.0.0.1`. Each accepted TCP connection is carried through
  Supgang's local stream endpoint (Supgang ADR 0006, as ADR-0026 does for HTTP)
  to the named service on that peer. The peer is resolved per connection.
- **Supgang authorizes.** Whether a stream opens is the peer's owner's
  exposure, judged by Supgang. Remap adds no authority. A refused or failed
  stream closes the connection. The gateway's log names only the service and
  the cause, never a mapped name or address (PRIVACY.md). `remap status` and
  `remap doctor` show the owner which mapping it was, with a per-cause count.
- **TCP only.** UDP and unexposed services are not reachable. The help text,
  `remap://help` and the CLI manual say so.

### Direct LAN access to advertised services

A service the peer *advertises* is a signed claim that it listens on the
peer's addresses with a pinned TLS key. Those stay with the existing
`supgang://<peer>/<service>` target, which verifies the pin. This ADR does not
change them.

## Building order

1. **The target and DNS.** The target's grammar, the selector rule, address
   allocation recorded with the mapping, and the A answer. Preview and
   `remap get` show the address, the pairs and the peer's display name.
2. **The loopback reservation.** It goes through the platform adapters, with
   install, boot, disable, removal and uninstall.
3. **The stream listeners.** These go in the gateway, through Supgang's local
   stream endpoint.

Each step ships with tests:

- the grammar, covering a name selector, duplicate ports, an oversized name
  and an empty pair list;
- allocation that is stable across restarts and unique across mappings;
- the reservation's full lifecycle;
- a stream round trip against a real local stream endpoint fixture;
- named refusals.

The onboarding acceptance runs from MacMarine and Solis:

- `ssh` through the MBP's name connects at home;
- it connects again after the MBP takes a new address;
- with the MBP on a phone hotspot, it still connects through the same name.

## Implementation of steps 1 and 3

### The target

`supgang://<selector>?<service>=<port>[,<service>=<port>...]`, target kind
`peer-machine`, is told apart from `supgang://<peer>/<service>` by having no
path segment. The selector is exactly 64 or 8 lowercase hex characters. Any
other selector is refused, and the error tells the owner to use the node ID
or fingerprint and that `supgang resolve <name>` shows both. Uppercase hex is
refused separately.

Two points differ from the decision above. Registry validation is pure and
never runs Supgang, so the refusal cannot show the matching fingerprint.
`remap get` does not show the peer's signed name either, because only a
Supgang subprocess could supply it. Both can be added when Supgang offers a
cheap local lookup.

The target holds 1 to 16 pairs. Each pair is a Supgang service name and a
decimal port from 1 to 65535, with unique names and unique ports. Templates
(`{1}`, `{2}`) are refused. The pairs keep the owner's order, and the target
displays canonically: `ssh=022` is stored as `ssh=22`.

### Allocation and the registry

- **Schema 4** adds the column `mappings.peer_address TEXT`, NULL for every
  other kind, and the partial unique index `mappings_peer_address` on it
  `WHERE peer_address IS NOT NULL`. Migration from 3 runs behind ADR-0032's
  pre-migration copy. No schema-3 registry can hold a peer-machine mapping,
  so no row is backfilled, and a schema-3 daemon refuses a schema-4 registry
  with `E_REGISTRY_SCHEMA_NEWER`.
- **Allocation.** The registry writer allocates an address when a set creates
  a peer-machine mapping, or retargets another kind to one. It takes the
  lowest address from `127.77.0.1` that no other mapping holds, disabled
  mappings included. The address is kept across restarts, target edits,
  disable and enable. It is freed when the mapping is removed or retargeted
  to another kind. 127.77.0.0 and 127.77.255.255 are never allocated
  (`remap_core::PEER_MACHINE_LOOPBACK`, `is_peer_machine_address`). An
  address freed by one change in an atomic set may be taken by a later one.
- **Bounds.** A registry holds at most 256 peer-machine mappings, enabled or
  not (`MAX_PEER_MACHINE_MAPPINGS`); the 257th is `E_PEER_MACHINE_CAPACITY`.
  A full range would be `E_PEER_ADDRESS_EXHAUSTED`, which the cap keeps out
  of reach.
- **Loading.** A stored address that is missing, out of range, not canonical,
  duplicated, or on another kind makes the registry `E_REGISTRY_CORRUPT`.

### Wire

- `MappingView.peer_address`: the allocated address, omitted for every other
  kind. Get, list, resolve, preview, apply receipts and the MCP tools carry
  it, and older receipts are unchanged.
- `RegistryStatus.peer_machine_listeners`: `{listening, not_listening,
  failures, refusals}`, present while the daemon runs a peer-machine
  listener or has counted a refusal. `failures` lists at most 64 entries,
  each `{pattern, service, address, port, cause, detail}`. `refusals` maps
  each carriage cause seen since the daemon started to its count, so it
  holds at most five entries.

### DNS

DNS answers A for an enabled peer-machine mapping with its address, at the
TTL every synthesized answer uses. AAAA, like any type with no address, is
NOERROR with no answer. A disabled mapping is not resolved, so its name is
forwarded like any unmapped name. Through the HTTP gateway the kind is
`421 E_GATEWAY_DIRECT_TARGET`.

### Listeners

The listener runtime runs beside the HTTP gateway whenever the gateway is
configured. It follows every published snapshot, plus a five-second retry of
listeners that could not bind. For each service of each enabled mapping it
binds `<address>:<port>` with address reuse, and nothing else.

- An address outside the range is never bound.
- A listener that cannot bind is reported with a cause and never moved to
  another address. The causes are `address-not-reserved` (the alias does not
  exist yet), `port-in-use`, `permission-denied` and `other`.
- Changing any field of a listener, or disabling or removing its mapping,
  closes it and the connections it carries before a new one binds.

Each accepted connection is carried as follows:

- A node ID selector is used as it is. A fingerprint is resolved through
  `supgang resolve` for every connection.
- One version-1 stream is opened through this user's endpoint, with
  ADR-0026's ownership checks, and bytes are copied both ways until each side
  closes.
- At most 256 connections are carried at once.
- A stream must open within 10 seconds.

A connection that is not carried is closed, and the daemon logs:

```text
remap gateway: peer machine connection closed. Service: NAME Cause: TOKEN (reason)
```

The tokens are `no-supgang`, `refused`, `unknown-peer`, `endpoint` and
`timeout`. This narrows the decision above, which had the log name the
mapping: PRIVACY.md's rule that routine logs carry no mapped name stands, so
the line carries no pattern, address, port or selector. The owner learns
which mapping is affected from `remap status` and `remap doctor`, which only
the owner can read. They name each listener that cannot bind, and they count
the connections not carried since the daemon started, by cause.

### What step 2 provides

The listeners need each enabled mapping's address to be an interface address
on macOS. Linux already routes all of `127.0.0.0/8`. The reservation reads
the addresses from the same snapshot that DNS and the listeners read:
`RegistrySnapshot::peer_machine_addresses()`, the set of enabled mappings'
addresses. Every one of them lies inside `PEER_MACHINE_LOOPBACK`, and there
are at most 256.

The listener runtime reads no reservation state of its own. It retries a
listener that could not bind every five seconds, so an alias reserved later
starts listening within that interval, without a restart and without telling
the gateway.

### Acceptance

- `crates/remap-core/tests/peer_machine_targets.rs`: the grammar. It covers a
  name selector, 8 and 64 hex characters, uppercase, duplicate ports and
  names, an oversized name, empty and overlong lists, placeholders,
  canonical round trip, and the snapshot's address rules.
- `crates/remap-registry/tests/peer_machine_addresses.rs`: allocation. It is
  lowest-first and unique, survives a restart, is kept on edit and disable,
  is freed on removal and on retargeting, shows in preview, and has the cap
  and tampered rows. A unit test proves exhaustion.
- `crates/remap-registry/tests/schema_snapshots.rs`: 3 to 4 with its copy.
- `crates/remap-network/src/dns.rs`: the A, AAAA and disabled answers.
- `crates/remap-network/tests/peer_machine_listeners.rs`: these run against
  a stand-in version-1 endpoint. They cover a round trip in both directions
  by node ID and by fingerprint, and refusal for an unexposed service, an
  unknown fingerprint and a missing Supgang. Each logs the service and cause
  with no mapped name or address, and each is counted by cause in status. They also cover following add, disable,
  enable and remove, binding the reserved address or reporting
  `address-not-reserved` without falling back, and refusing a substitute
  address off loopback.
- `crates/remapd/tests/peer_machines.rs`: through a live daemon, the DNS
  answer and the listener in status.

## Consequences

- A machine's name works at home and away, and its DNS answer never changes.
- A Mac without Supgang behaves exactly as today. Supgang stays an optional
  provider, and a connection without it fails with Supgang named as missing.
- The gateway gains loopback TCP listeners beside its HTTP ones, each bound
  to one reserved address.
- The privileged helper gains one operation, loopback address reservation,
  and its removal.
- Traffic between machines on the same LAN also rides Supgang's stream. That
  costs user-space carriage instead of a direct socket, in exchange for one
  name with one meaning everywhere.
- Wildcard templates (`*.agenxy.internal → supgang://{1}`, after ADR-0032)
  remain a separate decision, because they would turn any label into a
  Supgang lookup.
