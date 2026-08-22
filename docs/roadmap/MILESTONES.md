# Implementation milestones

Status: M0 and the M1 authority foundation are complete. The portable M2 data
plane and native macOS product path are in active implementation; no production
readiness claim is made before the installed Safari and Linux exits pass.

Every platform milestone ends with observable system evidence. Unit tests are
necessary but never sufficient for resolver, privilege, routing, or packaging
claims.

## M0: Rust foundation

- Accepted product, language, name, and authority decisions.
- Exact Rust toolchain pin and edition 2024 workspace.
- Canonical exact/wildcard names and typed destinations.
- Immutable snapshot validation and deterministic precedence.
- Offline validation CLI and focused executable specifications.

Exit: formatting, Clippy with warnings denied, tests, and representative CLI
validation pass from a clean checkout.

## M1: Authoritative daemon and local protocol

- Versioned local-control and snapshot schemas.
- SQLite WAL materialized registry behind one writer.
- Create, retarget, disable, remove, list, resolve, status, and diagnostics.
- Permissioned Unix-domain transport with peer credentials on Linux.
- Audit events and monotonic revision publication.
- Agent-native MCP tools and resources over the same local-control client as
  the CLI.
- MCP `2026-07-28` plus immediate-previous `2025-11-25` interoperability,
  including mixed-version access to one authority.
- Revision preconditions, idempotency, preview, stable structured errors, and
  private cache policy for mapping state.

Exit: CLI and both MCP revisions observe and mutate one authority; unauthorized
local clients, stale mutation decisions, and stale snapshot schemas are
rejected. Official SDK clients pass list, call, read, and subscription probes.

## M2: Portable DNS and HTTP data plane

- Loopback UDP and TCP DNS service.
- Bounded query parsing and exact-name A/AAAA synthesis.
- Unmatched forwarding without recursion.
- Atomic daemon snapshot publication without mixed revisions.
- Streaming HTTP/HTTPS upstream routing by Host with bounded backpressure.
- Explicit preserve-client/use-upstream host policy and base-path routing.
- Wildcard precedence and live revision changes.

Exit: real UDP/TCP and HTTP clients prove mapped, forwarded, revised, overload,
and shutdown behavior through one daemon. Security, latency, memory, throughput,
and tail budgets are measured rather than inferred.

## M3: Native macOS product and source-build activation

- Choose bundle namespace and Apple Developer team.
- Add Swift app, DNS System Extension, native SystemConfiguration adapter, and
  least-privilege launchd service.
- Add only proven entitlements and profiles.
- Compare native daemon-hosting alternatives with real code-signing identity,
  crash, update, and extension snapshot evidence.
- Add typed build, install, activate, diagnose, deactivate, rollback, and
  complete-uninstall workflows.

Exit: every bundle is embedded and signed correctly; a source build can bind
normal ports, discard root, activate native DNS reversibly, and the app reports
inactive or blocked states without pretending to perform privileged work.

## M4: macOS DNS vertical slice

- Activate `NEDNSProxyProvider` through a System Extension.
- Handle bounded UDP and TCP DNS flows.
- Forward unmatched queries without recursion.
- Atomically deliver versioned Rust snapshots to the provider.
- Survive daemon and provider restarts with defined fail-open behavior.

Exit: Safari, `dig`, SSH, and another native client prove the real installed
path for exact, wildcard, and unmapped names.

## M4L: Native Linux vertical slice

- Integrate with systemd-resolved through its native D-Bus contract.
- Ship a hardened systemd user/system service arrangement with explicit
  privilege and socket ownership.
- Support NetworkManager/resolv.conf environments through detected, reversible
  adapters rather than one blind configuration path.
- Package, update, rollback, disable, and uninstall without stale resolver
  state.

Exit: `dig`, browsers, SSH, and another non-browser client prove mapped and
unmapped behavior across daemon, resolver, interface, and system restarts on
supported distributions.

## M5: HTTP gateway

- Supervise loopback listeners on ports 80 and 443.
- Route by Host and TLS SNI.
- Implement explicit preserve-client/use-upstream host policy.
- Support streaming, cancellation, backpressure, SSE, and WebSocket upgrades.
- Add HTTP/2 after HTTP/1.1 lifecycle behavior is stable.

Exit: local, LAN, VPN, and remote upstreams pass browser and command-line tests
under connection churn on macOS and Linux.

## M6: Local HTTPS and platform key custody

- Create, inspect, export, trust, untrust, and rotate a local CA.
- Use Keychain/Secure Enclave where their execution contracts are proven on
  macOS; use a protected native keystore adapter on Linux.
- Issue and atomically replace gateway certificates.
- Surface certificate mismatch and trust state without blocking user intent.

Exit: trusted and deliberately untrusted flows behave predictably in browsers
and command-line clients on both platforms.

## M7: Peers and replication

- Hardware-backed node identity where viable.
- Explicit enrollment, discovery, mutual authentication, and revocation.
- Signed operation replication and explicit conflict resolution.
- LAN, existing VPN, and routed IPv6 transports before native relay work.

Exit: macOS and Linux nodes converge independent mappings, surface a same-name
conflict, and enforce revocation.

## M8: Distribution and lifecycle

- Deterministic artifacts, manifests, SBOM, and provenance.
- Detached release signing plus durable target-Mac local signing on macOS,
  without requiring a paid Apple account. Developer ID and notarization remain
  optional future channels rather than release prerequisites.
- Native Linux packages and service integration.
- Homebrew Cask and source-build instructions.
- Clean update, rollback, disable, and complete uninstall behavior.

Exit: clean machines on both platforms can install, approve, operate, update,
disable, and completely remove Remap without orphaned state.
