# Remap threat model

Status: normative design input for privileged and network-facing work.

## Overview

Remap lets a local operator map an arbitrary hostname to an IP address or an
HTTP service. A mapping may deliberately shadow a public name. The product is
intended for technical users, but technical intent does not reduce the need for
strict authority, isolation, lifecycle, and recovery guarantees.

The portable Rust authority consists of the `remap` CLI and MCP server,
`remapd`, the bounded local-control protocol, and the SQLite registry. The
planned runtime adds DNS interception, a loopback HTTP and HTTPS gateway,
certificate issuance, peer synchronization, and native platform lifecycle
adapters. Swift owns Apple entitlement-bearing entry points and native macOS
management surfaces. Linux uses native Rust integrations for its resolver and
service manager.

Remap does not promise that an arbitrary web application remains valid under a
new origin. Browser certificate, cookie, redirect, origin, CSP, and application
errors remain visible. This is a deliberate correctness boundary, not a failure
to provide security.

The repository security invariants are defined in `SECURITY.md`. The authority
model is recorded in `docs/architecture/ADR-0003-authority-boundaries.md`, and
the exact-name behavior is recorded in
`docs/architecture/ADR-0002-arbitrary-name-semantics.md`.

## Threat Model, Trust Boundaries, and Assumptions

### Actors

- The local operator controls mappings, installation, trust changes, ingress,
  peer enrollment, updates, and removal.
- A local unprivileged process may call public CLI or MCP surfaces, connect to
  local sockets, race lifecycle events, send malformed frames, and attempt to
  observe another user's state.
- A local privileged process is outside Remap's containment boundary. Remap
  still avoids giving it durable secrets or unnecessary plaintext data.
- A network peer may be authenticated, revoked, compromised, replaying old
  operations, or sending validly framed but hostile input.
- An upstream DNS resolver or HTTP service may be malicious, slow, inconsistent,
  compromised, or unreachable.
- A remote network client is untrusted whenever the operator explicitly enables
  non-loopback ingress.
- A developer or dependency can affect build inputs. Release provenance and
  dependency policy reduce, but cannot eliminate, this supply-chain boundary.
- Apple and the host operating system enforce code signing, Network Extension,
  Keychain, Service Management, resolver, and trust-store policies.

### Authority boundaries

`remapd` is the only writer of authoritative mappings, routes, peer state, and
certificate metadata. CLI, MCP, native UI, DNS providers, gateways, and peers
must submit versioned operations rather than editing storage directly.

The registry publishes complete immutable snapshots with a monotonic revision.
DNS and gateway consumers may read a snapshot but cannot mutate authority. DNS
and gateway decisions for one request must come from compatible revisions so a
name cannot resolve to a listener whose route policy is from another state.

The local-control socket crosses a user-process to authority boundary. The
server verifies peer credentials and socket ownership before parsing or
executing a mutation. File permissions alone are defense in depth, not the
complete authorization decision.

MCP hosts are local clients, not administrators by definition. Tool annotations,
preview, revision guards, operation identifiers, cancellation semantics, and
bounded output protect both people and agents from ambiguous or repeated
effects. MCP cancellation never means that an accepted mutation rolled back.

### macOS privilege boundaries

The preferred macOS resolver uses a DNS Proxy Network Extension packaged as a
System Extension. The host app requests activation through SystemExtensions,
and the operating system verifies the app, embedded extension, entitlements,
provisioning profile, team identity, and bundle relationship. Remap never
invents or injects an entitlement that the signing team was not granted.

An entitlement-free source-build backend may run a minimal privileged service
that binds the local DNS listener and updates DNS configuration using documented
SystemConfiguration and ServiceManagement APIs. That service must not parse MCP,
render UI, own registry policy, hold CA or peer private keys, or accept arbitrary
filesystem paths. Its command vocabulary, callers, inputs, and rollback state
are narrowly bounded.

DNS configuration changes are explicit and reversible. Installation records
the exact prior configuration needed for rollback, detects external changes,
and refuses to restore stale state over a newer operator or VPN decision.
Crashes must leave a repair path that does not require the product to start.

Apple signing identity, HTTPS CA identity, and peer identity are separate. A
grant or compromise in one domain must not authorize another.

### Linux privilege boundaries

Linux resolver integration uses documented systemd-resolved or distribution
native interfaces. A privileged installer or service owns only the operations
that require privilege. Per-user authority state remains inaccessible to other
users. The implementation must define behavior on multi-user systems rather
than assuming the desktop has one operator.

Package installation, service enablement, resolver activation, CA trust,
non-loopback ingress, and peer enrollment remain separate operations. A package
manager transaction must not silently opt the user into traffic interception or
trust mutation.

### DNS boundary

DNS packets, flow metadata, upstream replies, and names are untrusted. Input is
bounded before allocation and parsed without recursion controlled by the wire.
Compression-pointer loops, truncated messages, duplicate sections, oversized
labels, unexpected classes, unsupported opcodes, TCP framing, and response
correlation require explicit handling.

Exact names take precedence over wildcard suffixes. An unmatched name fails
open to the system's upstream resolver. A matched mapping whose target fails
must fail closed for that mapping; it must never fall through to public DNS and
silently reach a different service.

The resolver must avoid forwarding to itself. Upstream configuration is captured
before activation and updated atomically when network state changes. A captured
macOS resolver set is reusable only with the exact current native network
signature; a service identifier alone is not network identity. Forwarding has
bounded transport-specific concurrency, request size, retry count, connection
lifetime, and time.

### HTTP and TLS boundary

The gateway binds loopback unless the operator separately enables ingress. It
routes HTTP by a validated Host header and TLS by validated SNI. Ambiguous,
missing, duplicated, malformed, or conflicting authority is rejected before an
upstream connection is made.

Request and response headers, bodies, upgrades, trailers, and timing are
untrusted. Limits, streaming backpressure, cancellation, idle timeouts, header
normalization, and hop-by-hop header handling are correctness and security
properties. WebSocket and SSE paths retain the same policy and resource bounds
as ordinary requests.

Targets can intentionally point to loopback, LAN, VPN, private, link-local, or
public addresses. Generic SSRF blocking would violate the product contract.
Instead, the operator receives exact preview and route information, non-loopback
ingress is opt-in, redirects are not rewritten silently, and agent callers must
provide explicit mutation guards. The connector still rejects the gateway's
exact active listener after resolution so a valid private target cannot recurse
through Remap itself.

A peer target (`supgang://<peer>/<service>`, ADR-0016) is resolved at route
time from the peer's device-signed Supgang record, and the upstream TLS session
is verified against the key that record advertises rather than the system
roots: the top of the presented chain must carry the pinned key and the leaf
must be issued under it for the host dialled. The gateway keeps one TLS client
per advertised key, so a pooled connection can never serve a peer with another
key; an expired or unbounded record names nothing. No peer mapping is ever
dialled unverified or in plaintext, and a peer that cannot be resolved is a
gateway error that names the step, not a fallback.

### Certificate and key boundary

Creating, trusting, untrusting, rotating, exporting, or destroying a local CA is
an explicit trust operation. Trust is never implied by creating a service
mapping. The UI and CLI display certificate identity, scope, custody, and trust
state without claiming that a certificate makes an upstream trustworthy.

Local self-signing bootstrap material is transferred only through process memory
and anonymous pipes before a non-extractable Keychain import. Administrator
trust receives fingerprint-checked certificate bytes on standard input; it does
not reopen a user-owned staging pathname after authorization.

Private keys use native protected storage where its lifecycle meets the product
contract. Key material never appears in command arguments, routine logs,
telemetry, crash reports, MCP cacheable output, or world-readable files. Export,
when supported, requires a separate explicit workflow and cannot be performed
for a non-exportable key.

Issued certificates have bounded validity and atomic replacement. A failed
rotation cannot strand the gateway between a new key and an old certificate.
Uninstall offers an exact preview of trust entries and keys to remove while
preserving unrelated user state.

### Peer and replication boundary

Peer identity, enrollment, discovery, and revocation are Supgang's (ADR-0016);
Remap consumes them and builds none of its own. Replicated operations
are signed, bounded, ordered, idempotent, revision-aware, and attributable to a
peer without logging the user's mapped names or targets.

Revocation stops new authorization even when a peer retains old transport
credentials. Replays, clock skew, partition healing, simultaneous edits, and
conflicts are protocol states rather than last-writer-wins accidents. Relay or
discovery infrastructure, if later introduced, must not learn registry content
or private keys.

### Build, update, and uninstall boundary

Toolchains and dependencies are pinned and verified against authoritative
release sources. Warnings are fatal. Release artifacts include hashes,
signatures, an SBOM, provenance, embedded license text, version metadata, and a
documented relationship to the source revision.

Update cannot weaken signing identity, entitlements, trust, or rollback state.
The app and every embedded privileged component are verified as a bundle graph,
not as isolated executables. An update is not complete until the running
services have transitioned to the new version or report why they did not.

Uninstall deactivates interception before deleting code. It distinguishes
program files, resolver state, trust state, peer identity, CA material, and user
mappings, and lets the operator choose what to preserve. Failure must leave a
repairable, accurately reported state.

The source installer does not treat printing a preview as consent. It hashes
the complete observed lifecycle state and exact classified effects into an
approval token, then revalidates the token while holding the native transaction
lock before any mutation. macOS additionally requires device-owner presence in
the exact signed lifecycle client and privileged source-install helper; text
input, direct root invocation, and cached sudo cannot substitute for it. Linux
uses the displayed phrase for an interactive operator and accepts the complete
token only through its explicit automation boundary. Authentication failure,
state drift, and stale tokens fail closed. Crash recovery has a distinct
preview and token, and is never folded silently into install, update, or
uninstall.

### Privacy assumptions

Remap has no telemetry, analytics, account, remote control plane, forced update,
or usage-reporting channel. Routine logs never contain mapped hostnames, targets,
peer addresses, traffic metadata, request bodies, certificate subjects, or
private keys. Local diagnostics disclose only the minimum needed and are
inspectable before export.

Authoritative mappings necessarily exist on enrolled devices. Zero knowledge
therefore means no third-party or Agenxy visibility, least retention, separated
key custody, and no unnecessary duplication. It does not mean the local
authority can route without knowing its own configuration.

## Attack Surface, Mitigations, and Attacker Stories

### Local control and persistence

A hostile local process may connect to the control socket, spoof a client,
reuse an operation identifier, race daemon shutdown, submit a stale revision,
grow the registry, or exploit malformed JSON. Existing mitigations include Unix
peer credentials, a single writer, bounded framing, strict schemas, atomic
projection, revision guards, idempotent receipts, mapping ceilings, and an
authority lifetime lock. Tests must cover credential rejection, stale writes,
shutdown drain, restart handoff, retention, WAL checkpoint behavior, and
post-send uncertain outcomes.

SQLite files, sockets, locks, snapshots, and exported diagnostics must resist
symlink replacement, path traversal, permission drift, partial writes, rollback,
and opening a different user's state. Backup and migration operate on coherent
snapshots and validate schema and resource limits before becoming authoritative.

### DNS interception

A network attacker may return malformed, oversized, delayed, mismatched, or
poisoned DNS responses. A local application may flood unique queries or attempt
compression bombs. The resolver uses bounded parser state, outstanding-query
tables, randomized upstream identifiers where relevant, source and question
correlation, timeouts, backpressure, and negative outcomes that preserve mapped
name ownership.

A crash or stale upstream snapshot can cause an outage or loop. Activation
probes the listener before changing system DNS. Deactivation restores only the
configuration Remap still owns. The source backend starts the daemon without an
install-time resolver fallback, retains the last complete generation across a
transient handoff, and republishes after daemon replacement. After a bounded
series of reconciliation failures, its native root watchdog restores ordinary
system DNS before invalidating Remap forwarding and preserves an explicit
diagnostic for the operator.

### Gateway and upstream services

A client may smuggle requests through conflicting length or transfer semantics,
inject terminal or log control bytes, exhaust connections, abuse upgrades, or
coerce a public listener to reach a private target. The gateway uses maintained
HTTP protocol implementations, one normalized authority decision, bounded
headers and queues, streaming backpressure, idle and total deadlines, and no
sensitive access log.

The default listener is loopback. Enabling ingress previews the interfaces,
ports, mappings, and trust implications. Ingress authorization is a separate
policy layer; it is never inferred from the existence of a local mapping.

### Native app, extension, and FFI

The native app may receive hostile registry text, stale XPC replies, forged
distributed notifications, or extension lifecycle races. UI content is escaped,
state is revision-labeled, and success is not displayed until the platform
reports the corresponding state. Accessibility labels and non-color status are
part of this correctness boundary.

The Rust and Swift boundary uses a versioned C ABI with explicit ownership,
length, thread, cancellation, and panic contracts. Unsafe Rust is isolated to a
small interop crate, reviewed separately, and tested with sanitizers where
available. Swift never retains borrowed Rust memory beyond the documented call.

### MCP and embedded App

A host may send malformed or oversized JSON-RPC, duplicate identifiers,
unsupported protocol families, cancellation races, hostile tool arguments, or
backpressured output. A tool result may arrive through text, structured content,
or the embedded App. All carriers preserve the same authoritative meaning within
their wire budget.

Transport admission, request lifetime, response backpressure, subscriptions,
and cancellation are bounded together. Apps capabilities are negotiated by
protocol revision and MIME type. The App validates bridge messages, escapes
content, renders every result and error shape, reports size only after
initialization, supports keyboard and assistive technology, and remains useful
without permission to call server tools.

### Out-of-scope stories

A fully privileged local attacker can replace binaries, inspect process memory,
alter trust, and modify resolver state. Preventing that is outside Remap's local
containment promise. Remap still avoids persistent secrets and recovery designs
that amplify such compromise.

An operator deliberately mapping a public name to a different service is not an
attack on Remap. Hiding browser warnings or silently preserving the public
destination would violate the product contract. Unauthorized mutation of that
mapping, misleading preview, stale application, or failure to remove it is in
scope.

An upstream application rejecting a new Host, origin, cookie domain, redirect,
or certificate is not by itself a Remap vulnerability. Rewriting those controls
without explicit policy, concealing the failure, or routing to the wrong
upstream is in scope.

## Severity Calibration (Critical, High, Medium, Low)

### Critical

- Remote code execution in a privileged helper, system extension, gateway, or
  automatically reachable daemon with practical default preconditions.
- Unauthorized remote mutation of mappings, trust, peer identity, or update
  state across enrolled devices.
- Release-signing, update, CA, or peer-key compromise that enables silent code
  or traffic impersonation at scale.
- A default-on non-loopback gateway that exposes private services without an
  explicit operator decision.

### High

- A local unprivileged process can modify another user's or system-wide mapping,
  resolver, CA trust, ingress, or peer state.
- A mapped-name failure silently falls through to public DNS and sends traffic
  to an unintended real domain.
- DNS or gateway parsing yields memory corruption, sandbox escape, privilege
  escalation, request smuggling, or cross-route confusion.
- Uninstall or update leaves traffic intercepted by unowned or unverifiable code
  without an independent recovery path.
- Private CA or peer keys are persisted or exported in plaintext without an
  explicit, accurately described operation.

### Medium

- A same-user hostile process can cause a persistent denial of service, exhaust
  bounded authority resources, reuse an ambiguous operation, or read mappings it
  was not authorized to inspect under the chosen local policy.
- Resolver lifecycle races lose the prior DNS configuration but retain a manual,
  documented repair path.
- Host or SNI normalization routes a request to the wrong local mapping without
  crossing a user or privilege boundary.
- MCP or native UI presents stale or incomplete mutation scope that can induce a
  user or agent to approve the wrong operation.
- Routine diagnostics disclose mapped names, targets, peer addresses, or traffic
  metadata beyond the local operator's explicit request.

### Low

- A local client can trigger a bounded transient error, misleading non-security
  wording, or low-impact terminal presentation issue without changing authority.
- An authenticated operator can create an intentionally dangerous mapping after
  receiving exact scope and normal platform warnings.
- Public, non-sensitive build metadata or aggregate local health information is
  exposed without user content.
- A defense-in-depth recommendation is absent while the primary authorization,
  isolation, and recovery controls remain effective.
