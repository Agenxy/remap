# ADR-0033: A peer's name reaches it on any network

## Status

Proposed, 2026-10-30. The owner asked on 30 October for this as a capability,
not a document: the fleet travels, and its machines are spread across networks.
The shape was settled with Supgang the same day. It extends ADR-0016 and
ADR-0026, which route a peer's advertised HTTP services, to a peer's exposed
TCP services. It adds one privileged operation, a loopback address
reservation, so it is recorded here before that lands.

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
  stream closes the connection, and the gateway's log names the mapping, the
  service and why.
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
