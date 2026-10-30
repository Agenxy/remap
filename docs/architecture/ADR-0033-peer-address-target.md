# ADR-0033: A name may answer with a Supgang peer's current address

## Status

Proposed, 2026-10-30, for the owner's go-ahead. Nothing here is implemented,
and nothing may be until the owner approves. It extends ADR-0016 and ADR-0026,
which route a peer's advertised services, to the peer's own address. It is
independent of ADR-0031 and ADR-0032; templates for this target are a
follow-up.

## Context

On 30 October a new MacBook Pro joined the fleet. The owner asked for a stable
name that follows the machine's Supgang-tracked address, resolvable from
MacMarine and Solis, so that keeping track of its address is automatic.

Remap cannot say that today:

- `supgang://<peer>/<service>` follows the peer, because the gateway resolves
  it through `supgang resolve` on every routed request. But DNS answers it with
  the loopback gateway, and it carries only HTTP services the peer advertises.
- A name for the machine itself, for ssh, K7 node traffic or any other port,
  can only be an `address` mapping. That is one fixed IP, and it goes stale
  the next time the machine changes network.

Supgang already holds what the name needs: a device-signed, expiring record of
the peer's address candidates, one of which it marks `preferred`. Remap
already has a client for it, which `remap-network`'s peer resolver uses.

## Decision

### The target

`supgang://<peer>`, a peer selector with no service, is a DNS target. A
mapping such as `pro.agenxy.internal → supgang://<node-id>` answers A or AAAA queries
with the peer's current address. The owner writes every such mapping, so Remap
still imposes no name, suffix or namespace, and a Supgang record never creates
one.

The peer is selected by its Supgang node ID or the fingerprint Supgang shows
for it, never by its name. Supgang names are labels: they may repeat, and they
change with `supgang name set`. The node ID is stable and cryptographic. A name
in this position is refused, and the refusal shows the matching peer's
fingerprint so the owner can write it instead. `remap get` and `remap list` show
the peer's current signed name beside the selector, for display only.

### Who resolves, and when

`remapd` stays the sole writer, and DNS keeps answering only from immutable
snapshots:

- `remapd` resolves each enabled peer-address mapping through the existing
  `supgang --json resolve` client when it is created or enabled, every
  10 seconds, and when the record it holds expires.
- When the selected address changes, `remapd` publishes a new versioned
  snapshot. An unchanged answer publishes nothing.
- The DNS path never runs Supgang, waits on it, or reads its files.

### What a name answers

- **The address** is the IP of the candidate Supgang marks `preferred`, with
  its port removed. It is published only when that candidate's scope is
  `local` and its address lies on one of this Mac's own interface networks.
  It is returned as A for IPv4 or AAAA for IPv6, with a TTL of 10 seconds, and
  NOERROR with no answers for the other family.
- **Off the shared network, no address.** Supgang computes `preferred` from
  this Mac's viewpoint, as a dial preference. Off the LAN it can be a public,
  `mapped` or gateway-reported address, and only Supgang's own QUIC port is
  reachable there. A preferred candidate that is not local and on-link answers
  NOERROR with no data, never a WAN address. Off-network reach is a Supgang
  tunnel to loopback (`expose` on the peer, `forward` here), named with an
  ordinary loopback mapping. That is not this target.
- **Never the whole candidate list.** It includes link-local and VM-bridge
  addresses, and a client that picks one at random would fail.
- **No fresh record.** If the record has expired, the peer is unknown or
  ambiguous, or Supgang is not installed, the name answers SERVFAIL. It never
  answers a stale address, and it never falls through to public DNS for a
  name it owns. `remap resolve` and `remap get` say which case applies.

### What it does not promise

Supgang signs that its own QUIC port is reachable at a candidate address.
Whether ssh, K7 or any other service answers on that IP is up to the peer's
firewall and network. The help text, `remap://help` and the CLI manual say so.
The gateway is not involved. The target is never routed over HTTP, and the
gateway stays loopback-only.

## Before anything is built

- The owner approves this ADR.
- Supgang confirmed the selection rule above on 30 October: `preferred` only
  when local and on-link, and nothing otherwise. It has no change notice
  today, so polling `supgang --json resolve` every 10 seconds is the
  contract. A future bounded wait is not designed around.
- Tests:
  - address selection and expiry against real `supgang resolve` JSON
    fixtures, including preferred-public, `mapped`-only, link-local-only,
    off-link-local, expired and ambiguous records, and a name in the selector
    position;
  - `remapd` republishing a snapshot when the preferred address changes, and
    not republishing when it stays the same;
  - SERVFAIL with no Supgang binary;
  - the onboarding acceptance: from MacMarine and Solis, the name resolves to
    the new MacBook Pro. When that machine takes a new address on the same
    network, for example by moving between Wi-Fi and Ethernet, the new address
    resolves within 20 seconds. When it leaves the network, the name answers
    no data rather than a stale or WAN address.

## Consequences

- On a shared network, a machine's name follows its address with no edit, as
  long as Supgang tracks it. Away from that network the name deliberately
  answers nothing. Names for remote services stay on the tunnel path.
- `remapd` reads this Mac's interface networks to decide what is on-link,
  through a portable interface list, behind the platform adapters.
- A Mac without Supgang behaves exactly as today. Supgang stays an optional
  provider, and the target says plainly when it is missing.
- `remapd` gains a small periodic resolver, bounded to one `supgang resolve`
  per enabled peer-address mapping every 10 seconds.
- Wildcard templates (`*.agenxy.internal → supgang://{1}`, after ADR-0032) are
  a natural follow-up and need their own decision, because they would turn
  any label into a Supgang lookup.
