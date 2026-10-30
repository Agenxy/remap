# Changelog

Remap follows semantic versioning while the public interfaces are still young.
Every release keeps source installation, signed distribution, and supported
platform claims separate.

## Unreleased

- Login Items and Background Items list Remap's services under the developer
  "Remap" instead of "Agenxy Local". macOS takes that name from the
  organisation of the self-signed certificate that signed them, and the
  identities Remap creates (`Remap Local Codesign` on a receiving Mac,
  `Remap Build Signing` and `Remap Local Installer` on a building one) now
  carry it. An identity that already exists keeps the name it was created
  with until it is recreated, so a Mac set up before this release goes on
  showing "Agenxy Local" until then.

- Fixed a failed macOS DNS activation that could leave the Mac pointed at
  Remap under a record marked prepared, which deactivation then removed
  without restoring anything. The activation record is now written active
  before any service is pointed at loopback; a failed commit restores every
  service and returns the record to prepared, and a restore that also fails
  is reported instead of ignored, leaving the record active so deactivation,
  safe bypass, and the supervisor still restore it (ADR-0025).
- Fixed a macOS safe bypass taken with no network connected reporting
  `E_RESOLVER_SAFE_BYPASS_FAILED` until the network returned, although
  ordinary DNS had been restored. With nothing connected macOS publishes no
  global resolver, so restoration now accepts an empty one once every service
  Remap changed holds its captured configuration again; any other global
  resolver is checked exactly as before.
- A failed routed request says which mapping failed and why (ADR-0028). The
  `502 E_GATEWAY_UPSTREAM` and `504 E_GATEWAY_TIMEOUT` bodies, reported from
  agenxy-supply, said neither. They keep their codes and now carry the matched
  pattern (`Mapping: *.api.test`), a stable cause (`refused`, `timeout`,
  `tls`, `reset`, `unreachable` or `other`) and a next step; every other error
  after a match names the mapping too. The upstream's address and port still
  never leave the gateway, and `remap get` shows the owner the target.
- A mapping to a port with nothing listening no longer looks healthy until the
  first request. Preview, apply, set and enable, on the CLI, over MCP and in
  the native app, try one TCP connection, for at most a second, to each
  loopback HTTP target the change leaves enabled, and advise
  `target refused connection` when nothing accepts it. The change still
  succeeds. Peer targets, other names and addresses off loopback are never
  probed, and the probe sends no bytes, so the MCP tools keep their read-only
  and closed-world annotations; their descriptions now say they probe.
- Fixed a source build that stopped at macOS's trust dialog for the
  `Remap Build Signing` identity refusing every later build, saying the
  identity had no private key. Trust is creation's last step, so the key and
  certificate were already imported. The build now finishes that exact
  identity's trust setting when it is refused only as untrusted, after
  checking the exported certificate is the one in the keychain, and still
  refuses any other damaged state.
- Fixed macOS asking whether `codesign` may use key "stdin". The build and
  installer signing identities were imported through a pipe, and macOS names
  a key's access prompt after the file it was read from, and labels the key
  "Imported Private Key" in Keychain Access. Each identity is now imported
  from a file named for it, in a directory only the owner can enter, under a
  random per-run password, and removed straight after. Its key is labelled
  and prompts as `Remap Build Signing`, `Remap Local Installer` or
  `Remap Release Installer`. The signing key a package creates on each Mac
  it installs on was described as "codesign" and labelled the same way; it
  is now `Remap Local Codesign`. An identity created before this fix keeps
  its old name until it is recreated.
- `remap://help` explains the trade-offs between single-label names and a
  suffix of the owner's choosing, without recommending one.
- The release signing key lives in the Secure Enclave (ADR-0029). The new build-only
  `remap-release-key` helper creates a P-256 key that the release-building Mac's Secure
  Enclave will not export, writes only the Enclave's device-bound blob and never
  overwrites one, and makes an OpenSSH SSHSIG signature that `ssh-keygen -Y verify`
  accepts unchanged; every signature asks for Touch ID or the login password. A release
  package (`REMAP_RELEASE_SE_KEY`) signs its manifest and package only with that key,
  after proving the blob's public key is the release pin, and refuses a file key or a pin
  marked `remap-release-development-only`. A development package
  (`REMAP_DEVELOPMENT_PACKAGE=1`) keeps its file key and now has its own pin,
  `docs/release/remap-development-signing-key.pub`; each package's installer compiles in
  only its own kind's key, and `make install-package-macos` checks each kind against its
  own pin. The `Remap Release Installer` identity stays RSA in the login keychain, because
  the Enclave cannot hold RSA. The release pin is now that Enclave key,
  `remap-release-v2`, fingerprint `SHA256:UNkUo9rEtVK+N92onnYn1C9d6U2cCkuTOYFvZIW/dgQ`,
  created on the owner's release-building Mac. The README and release evidence also
  quoted the lost August key's fingerprint; they now quote the release pin's.
- Fixed Remap DNS flipping on and off every few seconds on a heavily loaded
  Mac (ADR-0030). `remapd` and the resolver supervisor ran in launchd's
  Background band, so under contention the supervisor's 250 ms exchange with
  the daemon failed, ordinary DNS was restored, and one lucky exchange put
  Remap back moments later. Both jobs are now `Interactive`, as macOS's own
  resolver is; a new generation must declare it, while an installed one may
  still carry the old value so rollback keeps working. A fault still restores
  ordinary DNS at once, but Remap returns only after the daemon has answered
  continuously for 5 seconds, doubling with each further fallback up to 5
  minutes and resetting after 5 minutes armed; `remap-system status` says how
  long the next return waits. Linux units set no lower priority and are
  unchanged.
- Fixed the macOS resolver supervisor falling back to ordinary DNS and never
  re-arming until `remapd` restarted (ADR-0025). The daemon reports the
  highest generation it has accepted, so a fresh reconciler publishes above
  it; a bypass that cannot release the daemon's plan remembers that one
  activation, durably, and a later reconciliation releases exactly it instead
  of reporting an activation mismatch forever; an unobserved network (sleep,
  Wi-Fi rejoining) keeps the last complete plan for up to 20 awake seconds,
  while a channel failure, daemon refusal, or conflict still bypasses at once;
  and every fallback records its reason, time, and re-arm in a root-owned
  `resolver-bypass-v1.json` that `remap-system status` shows.
- The macOS resolver follows the network service that carries DNS
  (ADR-0024). When Wi-Fi turns off and a tethered phone or Ethernet takes
  over, or the reverse, the supervisor captures the new service's prior DNS
  configuration, publishes its plan, restores the service it leaves, and
  points the new one at Remap, as the same activation. Two services with DNS
  at once are refused as split DNS, during supervision as at activation, so a
  second network or a VPN with its own resolver now restores ordinary DNS
  until one service remains. Deactivation restores every service Remap
  changed, including both during an interrupted move.
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
