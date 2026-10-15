# ADR-0026: Peer routes ride the Supgang stream

## Status

Accepted, 2026-10-15. Amends ADR-0016 (peers are Supgang's). Depends on Supgang
ADR 0006, "Local stream endpoint, version 1", which is shipped.

## Context

ADR-0016 routes `supgang://<peer>/<service>` by dialling the address in the
peer's signed record directly, over TLS pinned to the advertised key. That
works on a shared network. It fails when the owner is away: the advertised
address is the home network's, and only Supgang's own UDP port is forwarded.
The owner asked on 2026-10-15 that names for services on his other machines
work "as if local" during a trip, with no workarounds.

Supgang already carries authenticated byte streams between its members, and
its local stream endpoint is shipped: an owner-only control socket where one
framed request names a node and a service, and a `connected` reply turns the
socket into that service's bytes. It authorizes on the target owner's
*exposure* (`supgang expose <name> <port>`), not on an advertisement. Supgang
will not make the advertisement's `key_pin` optional the night before the
trip, because that would change a signed record format both machines must
agree on.

Two concerns are kept with one owner each, consistent with the 2026-10-15
split: K7 owns ports and service names for K7 services, Supgang owns
carriage, and Remap owns only the human names. Supgang remains an optional
provider. Remap works without it, and a missing provider produces a named
error.

## Decision

**A peer mapping's bytes travel inside Supgang's stream whenever this
machine has the endpoint.** What protects them inside the stream is the
owner's explicit choice, never an inference.

| Target | Inside the stream | When no stream opens |
| --- | --- | --- |
| `supgang://<peer>/<service>` | TLS to the advertised key, verified as in ADR-0016 | The direct pinned dial of ADR-0016 |
| `supgang+http://<peer>/<service>` | Plain HTTP, labelled as such | Refused, `502 E_GATEWAY_PEER_NO_TUNNEL` or `E_GATEWAY_UPSTREAM` |

- **Plaintext is never inferred.** A missing or stripped advertisement never
  downgrades a `supgang://` target to plaintext. It fails as
  `E_GATEWAY_PEER_NO_SERVICE`. Only the distinct `supgang+http://` form,
  written by the owner, carries plain HTTP. When Supgang later supports
  pinless advertisements, it will mark them explicitly, and that marker will
  not be an absent field.
- **Plaintext never leaves the tunnel.** A `supgang+http://` route has no
  direct-dial fallback. If the endpoint is missing or Supgang refuses the
  stream, the request fails.
- **What a stream proves.** The endpoint confers nothing beyond what this
  user can already do with `supgang connect`. Supgang authenticates the
  member device and admits the stream against the owner's exposure and
  tunnel limits. For `supgang://`, Remap additionally verifies the
  service's TLS key end to end inside the stream. For `supgang+http://`, the
  tunnel's device authentication is the only protection, which is why that
  form must be chosen explicitly.
- **Addressing.** A plaintext route's request is origin-form, with `Host:
  localhost` under the default `use-upstream` policy, because the target
  connects only to its own loopback. A pinned route keeps ADR-0016's
  addressing, using the advertised host for the TLS server name.
- **Endpoint use.** Remap opens one stream per upstream connection. Before
  sending a byte, it refuses a socket that this user does not own, or that
  this user's process does not answer, by checking the peer credentials. It
  reads at most 4 KiB of reply. WebSocket switches ride the stream under
  ADR-0021's tunnel bounds.
- **Discovery.** On macOS the endpoint is Supgang's default
  `~/Library/Application Support/org.agenxy.supgang/control.sock`. Where it
  is absent, the gateway behaves exactly as before this ADR.

## Consequences

- A name such as `preview.agenxy.test → supgang+http://solis/preview` works
  from any network where Supgang can reach the peer, including off the home
  LAN, and the browser sees an ordinary local origin.
- `supgang://` routes gain off-LAN reach without losing their key pinning.
  On the home LAN they keep working through the fallback even when Supgang
  refuses a stream, for example to the machine itself.
- Streams are not pooled: each upstream connection is a new stream, counted
  against Supgang's per-peer tunnel limit. Browser concurrency stays well
  under the current limit of 40. If it ever doesn't, pooling is a later
  change.
- A Remap build older than this ADR cannot parse a `supgang+http://` target
  that a newer one stored. Downgrading Remap while such a mapping exists
  makes that mapping fail validation until it is removed.

Acceptance: `crates/remap-network/tests/supgang_stream_gateway.rs` runs
against a stand-in version-1 endpoint and covers five cases:

- plaintext reached only through the stream, origin-form with `Host:
  localhost`;
- a WebSocket switch over the stream;
- plaintext refused without a tunnel;
- a refused stream never falling back to the network;
- a pinned service verified inside the stream, with a wrong key refused and
  no fallback.

Live check on 2026-10-15: a version-1 stream from MacMarine to Solis's
exposed `ssh` service answered `connected` and carried the `SSH-2.0` banner.
