# Changelog

Remap follows semantic versioning while the public interfaces are still young.
Every release keeps source installation, signed distribution, and supported
platform claims separate.

## Unreleased

- Fixed the native macOS lifecycle on a Mac that has restarted or that runs a
  launchd-owned system socket, found by driving `make recover` and `make update`
  end to end: the source orchestrator's privileged sink is spawned in the
  caller's session, so `sudo -n` keeps its ticket (a new session dropped it,
  and a root-owned tree that refused a signal then hid the real error); a root
  helper under sudo puts the presence prompt to the invoking user, not to
  "System Administrator" (`remap-install presence` is the user-side half), and
  a refusal names why the dialog ended; a job launchd reloaded from its
  published `LaunchDaemons` plist after a restart is that generation's, not a
  collision; `launchctl print` is read for the service's own `path` and
  `program`, not a nested socket's; a generation image carries the socket
  contract it was validated under, so activation dials the socket its resolver
  serves; remapd accepts the launchd-owned system socket, whose remembered
  address is launchd's private path, NUL-padded, not the declared one; the
  resolver supervisor accepts launchd (root) as the listener of that socket;
  the runtime readiness ceiling is five minutes (macOS assesses a newly signed
  daemon before it starts), the orchestrator waits for the helper's bounded
  work, and the post-install doctor check settles for a minute; an internal
  installer error says what it was.
- After review (astra): a job loaded from the published plist is the
  generation's only when the published bytes are the generation's plist; the
  presence child is bounded to five minutes and must end of its own accord;
  the post-install doctor check keeps its deadline and reports the last
  answer; `remap system` on a source install says the lifecycle is the
  repository's make targets. ADR-0017 records the two contracts.
- Added the `peer` mapping target, `supgang://<peer>/<service>` (ADR-0016). The
  gateway resolves the peer through Supgang when a request is routed, dials the
  address Supgang prefers on the port the peer's signed record advertises, and
  verifies the upstream TLS key against the advertised pin rather than the
  system roots; a chain that merely appends the peer's public CA is refused.
  DNS answers a peer mapping as it answers an HTTP one. A machine without
  Supgang, a peer with no route, or a service the peer does not advertise is a
  gateway error that says which. M7 is redefined on Supgang's identity: Remap
  builds no enrollment, discovery, or revocation of its own.

## 0.2.0 - 2026-08-19

- Added the authoritative daemon, private registry, revision-safe preview and
  atomic apply, exact retry receipts, and complete CLI mapping lifecycle.
- Added bounded UDP and TCP DNS, fail-open public resolution, loopback HTTP
  routing, authenticated runtime health, and automatic resolver recovery.
- Added dual-version MCP tools, resources, subscriptions, and the optional MCP
  Apps dashboard over the same authority as the CLI.
- Added a native macOS Apple Installer package with detached Remap release
  signing, durable target-Mac local signing, immutable generations, update
  rollback, crash recovery, exact uninstall, manuals, completions, and license
  notices. The source installation retains its exact preview and state-bound
  approval flow.
- Added the Linux systemd-resolved, systemd-networkd, and NetworkManager
  vertical slices with non-root socket activation and transactional recovery.
- Added strict multi-language quality, adversarial lifecycle, dependency,
  packaging, browser, SBOM, and release-evidence gates.

The macOS package is signed by Remap's dedicated release key. After verifying
that signature and its internal manifest, the installer signs the executables
with a durable identity created on the target Mac. It is not notarized or
presented as a Developer ID distribution. Linux support remains limited to the
exact documented native backends and acceptance environments.

## 0.1.0 - 2026-08-11

- Published the portable mapping model and offline validation CLI.
