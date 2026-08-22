# ADR-0007: Authenticated local runtime health

Status: accepted for implementation, August 2026.

## Context

An open loopback port does not identify Remap. Another process can occupy a
configured port, a launchd definition can outlive its process, and an old
installation record says nothing about the code currently answering. Treating
any of those signals as readiness would let the CLI and native app present an
unrelated or partial runtime as healthy.

The authority, DNS listener, and HTTP gateway are separate local interfaces of
one daemon process. A health decision must establish that all required
interfaces possess the same fresh process identity without persisting another
machine secret or exposing user mappings, destinations, traffic, or resolver
state.

## Decision

### One ephemeral process identity

At startup, `remapd` obtains a 256-bit secret from the operating-system random
generator. The secret exists only in zeroizing process memory, is never
persisted, and is shared by reference with the control, DNS, and HTTP runtimes.
The daemon also creates an opaque, bounded process instance identifier and
reports its bounded build version. A restart always creates a new secret and
instance identifier.

The authority accepts a health challenge only when its nonce is exactly 16
bytes encoded as 32 lowercase hexadecimal characters. Clients generate all 128
nonce bits from the operating-system random generator for every check. A
challenge result contains the process instance identifier, daemon version, and
two 32-byte HMAC-SHA-256 outputs encoded as 64 lowercase hexadecimal
characters.

The proof inputs are:

```text
DNS proof  = HMAC-SHA-256(process_secret,
                          "remap.runtime-health/v1\0dns\0" || nonce_bytes)

HTTP proof = HMAC-SHA-256(process_secret,
                          "remap.runtime-health/v1\0http\0" || nonce_bytes)
```

The exact NUL-terminated domain strings are part of the versioned contract.
DNS and HTTP proofs must differ. The instance identifier and version are
validated control metadata, not additional proof inputs; possession of the
fresh per-process secret binds the listeners to the challenged authority. A
client rejects a daemon version that differs from its own version.

### Exact listener challenges

The DNS listener recognizes only an IN `TXT` or `ANY` query for:

```text
r<nonce>._health.remap.invalid.
```

It returns one zero-TTL TXT answer containing the DNS proof. Native and CLI
readiness requires the same proof over both UDP and TCP. The transaction ID,
question, response envelope, owner, type, class, TTL, TXT segment, and absence
of unrelated sections are validated before acceptance. Other names, malformed
nonces, and other record types do not receive a health proof and continue
through ordinary mapped or unmapped DNS policy.

The HTTP gateway recognizes only an HTTP/1.1 `GET` with no query, exactly one
`Host: _health.remap.invalid`, and this path:

```text
/.well-known/remap/health/<nonce>
```

It returns status 200, exactly one `Cache-Control: no-store`, exactly one
`Content-Type: text/plain; charset=utf-8`, and the HTTP proof as the complete
body. Health clients reject transfer encoding, duplicate required headers,
extra body bytes, malformed framing, and responses beyond the byte limit.
Requests that do not match the complete health route remain ordinary gateway
requests.

### Readiness is conjunctive and point-in-time

The CLI and native app obtain one fresh challenge and compare its expected
proofs with all listener responses. Runtime readiness is true only when:

```text
validated control authority
AND authenticated UDP DNS
AND authenticated TCP DNS
AND authenticated HTTP
```

Property-list existence, installation receipts, resolver state, and generic
TCP acceptance are never substitutes for runtime identity. Resolver activation
and maintenance state remain separate readiness conditions. A successful
health result is a point-in-time observation, not a lease; consumers refresh it
after lifecycle changes and on their normal bounded observation cadence.

## Local trust model

The per-user control socket is the root of this check. Operating-system identity
and socket permissions decide which local principals can request a challenge.
The proof establishes that loopback listeners possess the same ephemeral
secret as that authority. It does not create a new authorization boundary
around callers already authorized to use the control socket.

The health host uses the permanently non-public `.invalid` namespace and the
listeners bind loopback in this deployment. Proofs are safe to expose on these
challenge-specific local responses because they are nonce-bound, short-lived,
and useless for a different nonce or proof domain. They are authentication
values, not bearer credentials for mutation.

## Bounds and cancellation

- Nonce, proof, instance identifier, and version lengths are fixed or capped
  before further processing.
- DNS and HTTP responses are capped at 4,096 bytes.
- The CLI gives the complete DNS operation and the complete HTTP operation one
  750-millisecond deadline each; sub-operations cannot multiply that budget.
- The native client gives the control challenge, DNS verification, and HTTP
  verification one second each. DNS UDP and TCP verification runs concurrently.
- Timeout or cancellation closes the active local connection, cancels sibling
  work, and returns a fail-closed health value. A late callback cannot turn a
  completed or canceled check into readiness.

These are local-health budgets, not ordinary control-command or routed-traffic
budgets.

## Privacy properties

The process secret never crosses an interface and is zeroized when the final
runtime reference is released. Health checks do not read or disclose mappings,
destinations, resolver upstreams, request content, traffic metadata, user paths,
or peer addresses. Routine logs and diagnostics contain neither the secret,
nonce, proof, socket path, nor listener address. Failures use stable categories
and bounded state descriptions.

## Explicit non-goals

This mechanism does not:

- attest the daemon binary, code signature, launchd definition, installer, or
  host to a remote party;
- defend against code running as a principal already authorized to use the
  control socket and capable of relaying current challenge responses;
- prove that resolver configuration currently directs applications to Remap;
- prove that mapped upstreams, public DNS forwarding, TLS trust, certificates,
  or application requests work;
- reserve `.invalid` as a product namespace for ordinary user mappings;
- guarantee liveness after the point at which the probes completed; or
- replace lifecycle, privilege, resolver, routing, and end-to-end browser tests.

## Consequences

Readiness now requires a small amount of local cryptographic work and one
bounded exchange on each required transport. In return, stale metadata and
unrelated listeners fail closed without adding persistent key management or
collecting user activity. Any future listener, remote health surface, protocol
version, proof algorithm, domain string, timeout, or trust-root change requires
a new architecture decision and adversarial boundary tests.
