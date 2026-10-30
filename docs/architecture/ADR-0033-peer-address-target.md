# ADR-0033: A peer's name reaches it on any network

## Status

Proposed, 2026-10-30. The owner asked on 30 October for this as a capability,
not a document: the fleet travels, and its machines are spread across networks.
The design is settled with Supgang where marked, and building starts with the
on-network path. It extends ADR-0016 and ADR-0026, which route a peer's HTTP
services, to the peer itself. It adds one privileged operation, a loopback
address reservation, so it is recorded here before that lands.

## Context

On 30 October a new MacBook Pro joined the fleet. The owner asked for a stable
name for it that keeps working wherever the machines are.

Remap cannot provide one today:

- `supgang://<peer>/<service>` follows the peer, because the gateway resolves
  it on every request. But it carries only HTTP, to services the peer
  advertises, through the loopback gateway.
- A name for the machine itself, for ssh, K7 node traffic or any other TCP
  service, can only be an `address` mapping. That is one fixed IP, which goes
  stale when the machine changes network and never worked off the LAN.

Off a shared network the only thing that reaches another member is Supgang's
authenticated stream. A peer's public or NAT address reaches Supgang's own
QUIC port and nothing else. A name that works everywhere must therefore be
able to ride that stream, and should go direct only when the machines share a
network.

## Decision

### One target, two paths

`supgang://<peer>`, with no service, names a machine. A mapping such as
`pro.agenxy.internal → supgang://<node-id>` resolves to whichever path reaches
that peer from this Mac now:

| This Mac and the peer | The name answers | Traffic |
| --- | --- | --- |
| Share a network | The peer's on-link local address | Direct, every protocol |
| Do not | The peer's reserved loopback address on this Mac | TCP, through Supgang's stream, to the services the peer's owner exposes |
| No fresh record, or no Supgang | SERVFAIL | None |

The answer has a TTL of 10 seconds, so it follows either machine between
networks. The owner writes every mapping, so Remap imposes no name or suffix,
and a Supgang record never creates one.

### Selecting the peer

The peer is selected by its Supgang node ID or shown fingerprint, never its
name. Supgang names are labels that may repeat and can be changed with
`supgang name set`. A name in this position is refused, and the refusal shows
the matching fingerprint. `remap get` shows the peer's current signed name for
display.

### The on-network path (agreed with Supgang, 30 October)

`remapd`, the sole writer, resolves each enabled peer mapping through the
existing `supgang --json resolve` client every 10 seconds and when the record
expires. It publishes a new immutable DNS snapshot only when the answer
changes, and DNS never runs or waits on Supgang.

The direct answer is the candidate Supgang marks `preferred`, with its port
removed, and only when that candidate's scope is `local` and its address is
on one of this Mac's interface networks. Supgang computes `preferred` from this
Mac's viewpoint as a dial preference. A public, `mapped` or gateway-reported
preference is never published. Remap also never publishes the whole candidate
list, which includes link-local and VM-bridge addresses.

### The off-network path

- **A reserved loopback address per peer mapping.** Remap allocates each
  enabled peer mapping a stable address in `127.77.0.0/16`, recorded with the
  mapping. The privileged helper makes it an `lo0` alias on macOS, and Linux
  routes all of `127.0.0.0/8` to loopback already. The reservation is the one
  new privileged operation, and it lives behind the platform adapter, like
  every other lifecycle effect, with exact uninstall.
- **Listeners on the peer's service ports.** On that address the gateway
  listens on the port of each service the peer's owner exposes, and carries
  each accepted TCP connection through Supgang's local stream endpoint
  (Supgang ADR 0006, as ADR-0026 does for HTTP) to that service. It never
  listens on a non-loopback address.
- **Supgang authorizes.** The peer's owner decides what is reachable with
  `supgang expose`. Remap adds no authority, and a connection to a port the
  peer does not expose is refused with a named reason.
- **TCP only.** UDP and unexposed ports are not reachable off the network. The
  help text says so.
- **Open with Supgang:** whether the signed record lists every exposed service
  with its port, or the mapping must name the port-to-service pairs. Remap
  prefers the signed record, so K7 and Supgang can change ports without anyone
  editing a mapping.

## Building order

1. The target, the selector, the on-network answer, and the polling and
   republishing in `remapd`. This is useful at once on a shared network and
   needs no privilege.
2. The loopback reservation, through the platform adapters, with its tests
   and uninstall.
3. The stream listeners, once Supgang answers the open question.

Each step ships with tests:

- selection and expiry against real `supgang resolve` JSON fixtures, covering
  preferred-public, `mapped`-only, link-local-only, off-link-local, expired and
  ambiguous records, and a name in the selector position;
- snapshot republishing on change only;
- SERVFAIL with no Supgang;
- the reservation's install and uninstall;
- a stream round trip.

The onboarding acceptance runs from MacMarine and Solis:

- the name reaches the new MacBook Pro on the shared network;
- it follows the machine to a new address within 20 seconds;
- with the machine on another network, such as a phone hotspot, ssh through
  the same name still connects.

## Consequences

- A machine's name works at home and away, with no edit, as long as Supgang
  tracks it.
- A Mac without Supgang behaves exactly as today. Supgang stays an optional
  provider, and a missing provider is named.
- `remapd` gains a bounded poller, and the gateway gains loopback TCP listeners
  beside its HTTP ones.
- The privileged helper gains one operation, loopback address reservation, and
  its uninstall.
- Wildcard templates (`*.agenxy.internal → supgang://{1}`, after ADR-0032)
  remain a separate decision, because they would turn any label into a
  Supgang lookup.
