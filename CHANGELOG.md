# Changelog

Remap follows semantic versioning while the public interfaces are still young.
Every release keeps source installation, signed distribution, and supported
platform claims separate.

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
