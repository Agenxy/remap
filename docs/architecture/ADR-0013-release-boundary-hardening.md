# ADR-0013: Release-boundary hardening for native DNS, routing, and local signing

## Status

Accepted for Remap 0.2.0.

## Context

The 0.2.0 release review found six boundary assumptions that were individually
bounded but unsafe in combination:

- the macOS root resolver authenticated a user-owned Unix-socket server only by
  UID, even though another process with that UID could replace the pathname;
- an activation snapshot could be reused after a network handoff when macOS no
  longer exposed current non-loopback DNS state;
- connection-scoped DNS and HTTP permits allowed idle or indefinitely streaming
  clients to retain all capacity;
- an HTTP target could resolve to the gateway's own active listener and recurse;
- and the public-forwarding health query omitted the DNS recursion-desired bit, so
  a conforming recursive resolver could refuse the probe while serving ordinary
  recursive traffic.

The local self-signing bootstrap also wrote exportable private-key material to
user-owned temporary files and passed a generated archive password in process
arguments. Administrator trust consumed a user-owned certificate pathname
after authorization, leaving a same-UID replacement window.

These are authority, wire, privilege, and trust changes, so they require one
coherent architecture decision rather than isolated checks.

## Decision

### launchd owns the macOS system-control endpoint

The native daemon launchd definition now declares the resolver system-control
socket alongside the DNS and HTTP sockets. Its pathname is fixed at
`/var/run/org.agenxy.Remap.system.sock`, outside the configured user's writable
data directory. `remapd` adopts the descriptor supplied by launchd and never
creates, removes, or replaces that pathname. The root resolver connects only to
that manifest-validated endpoint. UID checks remain defense in depth, but UID
alone is no longer the endpoint authority.

### captured resolvers require a stable native network signature

Each new macOS activation record stores the SystemConfiguration
`NetworkSignatureHash` observed with the captured resolver set. Live dynamic DNS
and DHCP option 6 still take precedence. A captured set is reused only when the
current signature exactly matches; a missing signature, an older record, a
missing service, or a changed signature yields no plan and triggers safe bypass.
This preserves manually configured resolvers on an unchanged attachment without
treating a persistent service ID as network identity.

### request work and connection lifetime are independently bounded

UDP DNS and TCP DNS have separate request capacity. TCP connection admission is
bounded separately, permits are acquired per framed request, and every TCP
connection has an aggregate deadline. HTTP retains bounded connection admission
and now has an aggregate deadline covering request bodies, upstream response
bodies, client backpressure, and keep-alive reuse. Expiry cancels the complete
connection future and releases its permit.

### the connector rejects the exact gateway destination

Private and loopback mappings remain valid. The outbound connector inspects the
actual peer after native resolution and TCP connection but before HTTP or TLS
bytes are sent. If that peer is the gateway's active listener, the route fails
closed. This targets recursion without adding a generic SSRF policy.

### the public-forwarding probe is an ordinary recursive DNS query

The UDP and TCP public-forwarding probes set the DNS recursion-desired bit and
still require an exact nonce-bound question with an `NXDOMAIN` response. This
tests the same recursive service ordinary forwarded queries require. A resolver
that correctly refuses non-recursive cache misses can no longer make a healthy
installation appear incomplete, while local listener health remains
insufficient on its own.

### self-signing bootstrap material never enters a filesystem path

The compatibility bootstrap keeps generated private-key and PKCS#12 bytes only
in process memory and anonymous pipes, imports the key as non-extractable, and
uses a fixed non-secret transport password because the archive itself never has
a pathname. No private key, archive, or generated secret appears in a file or
process argument. Administrator trust hashes the captured certificate bytes and
passes those exact bytes to the fixed system `security` tool through
`/dev/stdin`; the privileged operation never reopens a user-owned pathname.

The durable identities remain separate for code signing and Installer signing.
This is local self-signing, not Apple notarization or public Apple trust.

### package inputs are metadata-neutral

The portable package builder normalizes timestamps and then removes every
inherited extended attribute from its already-verified staging tree, native
scripts, and component metadata immediately before invoking `pkgbuild`. The
order is security-relevant because another metadata mutation can restore the
protected provenance attribute. Verification independently lists the unexpanded
payload and rejects noncanonical paths and every AppleDouble `._` member.
Expanded-package inspection alone is insufficient because macOS can restore
those sidecars as extended attributes and hide their archive identity.

## Consequences

The next macOS package must replace both launchd jobs together because the old
daemon does not adopt the new system socket. Older activation records remain
decodable and restorable, but they cannot authorize captured-upstream reuse
without fresh network provenance. Long-lived HTTP streams are intentionally
bounded by the configured connection lifetime; future SSE or upgrade support
requires an explicit separately bounded policy.

Acceptance must include same-service network signature changes, an idle TCP DNS
population with working UDP DNS, a stalled HTTP body followed by recovered
capacity, a direct self-route, launchd socket-path substitution, and exact
certificate/trust identity verification. Public-forwarding acceptance must use
at least one resolver that refuses non-recursive cache misses.
Release distribution inspection must also prove that the package contains no
AppleDouble members, regardless of the build host's Finder or provenance
metadata.
