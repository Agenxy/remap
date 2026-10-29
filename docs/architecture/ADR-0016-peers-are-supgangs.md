# ADR-0016: Peers are Supgang's; a mapping may name a Supgang peer's service

## Status

Proposed for Remap 0.3.0. This revises the M7 milestone and extends ADR-0002
and ADR-0003.

## Context

M7 planned node identity, enrollment, discovery, mutual authentication,
revocation, and transports for Remap itself. Supgang, the Agenxy address
plane, already is that: a self-certifying Ed25519 identity per computer,
root-signed and expiring membership, permanent revocation, device-signed
endpoint records exchanged between members as their addresses change, and
since its ADR 0002, signed service advertisements: a member states in its own
record that it runs a named service on a port behind a TLS key, as the SHA-256
of that key's SubjectPublicKeyInfo. On 2026-09-13 Agenxy decided its tools use
each other as dependencies rather than each growing a copy of the others'
work.

Dibs is the first consumer. A Dibs hub on a member is reached by a name that
Remap routes (`http://hub/`), but the target of that mapping is an address,
and the hub's address is what Supgang exists to keep current. Today the
mapping breaks when the hub moves networks, and the gateway cannot verify the
hub's self-issued certificate at all.

## Decision

Remap does not build node identity, enrollment, discovery, authentication, or
revocation. Those are Supgang's, and M7 is redefined as: replication of signed
operations between members over the transport and identity Supgang provides.

Remap gains a fourth mapping target, `peer`, written
`supgang://<peer>/<service>`. `<peer>` is anything `supgang resolve` accepts
(a computer name, a local tag, a fingerprint, or a node id) and `<service>` is
a service name as Supgang bounds it (1 to 16 lowercase ASCII letters, digits
and hyphens, not starting with a hyphen). The target is validated as text and
stored as text, like every other target; nothing is resolved at `remap set`.

- DNS answers a peer mapping exactly as it answers an HTTP mapping: the
  loopback gateway address, so the browser reaches the gateway.
- The gateway resolves the peer at route time through Supgang's own versioned
  contract, `supgang --json resolve <peer>` (`supgang.resolve/v5`, whose
  `services` rows carry `{name, port, key_pin}`), caches the answer until the
  signed record's `expires_at` or five minutes, whichever is sooner, and
  dials the peer's preferred route-compatible candidate host on the
  advertised port over HTTPS.
- The upstream TLS session is verified against the advertised pin, not the
  system roots: the certificate at the top of the chain the peer presents
  must carry the pinned key, and the leaf must be issued under it for the
  host dialled. The gateway keeps one TLS client per advertised key, so
  every connection it holds, pooled or new, was verified against that key
  and none can serve another peer; a key that goes unused is dropped with
  its connections. A record that has expired, or carries no expiry, names
  nothing. A peer that does not advertise the service, or presents another
  key, is a gateway error naming which, never a plaintext or unverified
  fallback.
- A machine without Supgang, or one whose Supgang cannot answer, routes a
  peer mapping to a gateway error that says so. The mapping stays valid:
  Remap's registry does not depend on Supgang, only the route does.
- The host header policy is the mapping's, as for HTTP targets. Dibs checks
  the `Host` it is given against the name its board is configured with, so
  `preserve-client` is the policy a Dibs hub is mapped with.

The Supgang binary is found where the Agenxy installers put it when it is not
on the daemon's PATH, which under launchd or systemd it is not. This is a
subprocess with a versioned JSON contract, the same seam Dibs uses; Supgang
exposes no library or socket API to a second process today, and when it does
this resolver is the one place to change.

## Consequences

- `remap set hub supgang://MacSolis/dibs --host-header preserve-client` makes
  `http://hub/` reach the Dibs on MacSolis wherever MacSolis is, verified
  against the key MacSolis signed, with nothing pinned by hand.
- `MappingView.target_kind` gains the value `peer`; `remap validate`, `set`,
  `list`, `resolve`, the MCP tools and the dashboard carry it as text and need
  no other change.
- Replication (the rest of M7) is designed later, on Supgang's identity and
  transport, and this ADR is amended then.
- A peer mapping is only as current as the peer's record and as reachable as
  the candidate Supgang prefers from this machine; the gateway says which
  step failed.
