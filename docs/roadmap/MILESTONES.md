# Implementation milestones

Status: M0 complete; M1 next.

Every platform milestone ends with observable system evidence. Unit tests are
necessary but never sufficient for resolver, privilege, routing, or packaging
claims.

## M0 — Rust foundation

- Accepted product, language, name, and authority decisions.
- Exact Rust toolchain pin and edition 2024 workspace.
- Canonical exact/wildcard names and typed destinations.
- Immutable snapshot validation and deterministic precedence.
- Offline validation CLI and focused executable specifications.

Exit: formatting, Clippy with warnings denied, tests, and representative CLI
validation pass from a clean checkout.

## M1 — Authoritative daemon and local protocol

- Versioned local-control and snapshot schemas.
- SQLite WAL materialized registry behind one writer.
- Create, retarget, disable, remove, list, resolve, status, and diagnostics.
- Permissioned Unix-domain transport with peer credentials on Linux.
- Audit events and monotonic revision publication.

Exit: multiple clients observe one authority; unauthorized local clients and
stale snapshot schemas are rejected.

## M2 — Linux DNS vertical slice

- Loopback UDP and TCP DNS service.
- Bounded query parsing and exact-name A/AAAA synthesis.
- Unmatched forwarding without recursion.
- systemd-resolved adapter and explicit lifecycle installation.
- Wildcard precedence after exact behavior is proven live.

Exit: `dig`, browsers, SSH, and another non-browser client prove mapped and
unmapped behavior across daemon and network restarts.

## M3 — Native macOS product graph

- Choose bundle namespace and Apple Developer team.
- Add Swift app, DNS System Extension, daemon host prototype, and Rust FFI.
- Add only proven entitlements and profiles.
- Compare native daemon-hosting alternatives with real code-signing identity,
  crash, update, and extension snapshot evidence.
- Add one shell-first build, install, launch, and diagnostics workflow.

Exit: every bundle is embedded and signed correctly; the app reports inactive
service state without pretending to perform privileged work.

## M4 — macOS DNS vertical slice

- Activate `NEDNSProxyProvider` through a System Extension.
- Handle bounded UDP and TCP DNS flows.
- Forward unmatched queries without recursion.
- Atomically deliver versioned Rust snapshots to the provider.
- Survive daemon and provider restarts with defined fail-open behavior.

Exit: Safari, `dig`, SSH, and another native client prove the real installed
path for exact, wildcard, and unmapped names.

## M5 — HTTP gateway

- Supervise loopback listeners on ports 80 and 443.
- Route by Host and TLS SNI.
- Implement explicit preserve-client/use-upstream host policy.
- Support streaming, cancellation, backpressure, SSE, and WebSocket upgrades.
- Add HTTP/2 after HTTP/1.1 lifecycle behavior is stable.

Exit: local, LAN, VPN, and remote upstreams pass browser and command-line tests
under connection churn on macOS and Linux.

## M6 — Local HTTPS and platform key custody

- Create, inspect, export, trust, untrust, and rotate a local CA.
- Use Keychain/Secure Enclave where their execution contracts are proven on
  macOS; use a protected native keystore adapter on Linux.
- Issue and atomically replace gateway certificates.
- Surface certificate mismatch and trust state without blocking user intent.

Exit: trusted and deliberately untrusted flows behave predictably in browsers
and command-line clients on both platforms.

## M7 — Peers and replication

- Hardware-backed node identity where viable.
- Explicit enrollment, discovery, mutual authentication, and revocation.
- Signed operation replication and explicit conflict resolution.
- LAN, existing VPN, and routed IPv6 transports before native relay work.

Exit: macOS and Linux nodes converge independent mappings, surface a same-name
conflict, and enforce revocation.

## M8 — Distribution and lifecycle

- Deterministic artifacts, manifests, SBOM, and provenance.
- Developer ID signing, notarization, stapling, and update signing on macOS.
- Native Linux packages and service integration.
- Homebrew Cask and source-build instructions.
- Clean update, rollback, disable, and complete uninstall behavior.

Exit: clean machines on both platforms can install, approve, operate, update,
disable, and completely remove Portal without orphaned state.
