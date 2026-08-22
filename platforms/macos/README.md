# macOS platform

This directory contains the native macOS resolver, lifecycle, package, and app
targets. `RemapSystemKit`
reads active resolver services through SystemConfiguration, records their exact
prior DNS dictionaries in a root-owned integrity-covered activation record,
and applies or conditionally restores loopback DNS without invoking
`networksetup`, `scutil`, `/etc/hosts`, or a shell script.

The source backend deliberately refuses multiple active DNS service scopes. It
will not flatten split-DNS or VPN resolvers and risk leaking private queries.
Launchd owns the privileged loopback sockets; `remapd` consumes them through
socket activation and runs as the signed-in non-root account.

The current product does not require an Apple-provisioned Network Extension.
The root resolver helper uses the reviewed SystemConfiguration contract, while
launchd owns the loopback sockets. Restricted entitlements, Team IDs, App
Groups, and provisioning profiles are not guessed or claimed.

## Prebuilt package

`make package-macos` builds `dist/Remap-0.2.0-arm64.pkg` and its detached SSH
signature. The package uses native Mach-O `preinstall` and `postinstall`
executables; there is no installer shell script. The package itself is unsigned
by Apple and is not notarized. Remap instead signs the complete package bytes
with its dedicated Ed25519 release key under the `remap-package-v1` namespace.
The pinned public key is
[`docs/release/remap-release-signing-key.pub`](../../docs/release/remap-release-signing-key.pub).

The package carries a signed, canonical release manifest. On the target Mac,
the native installer verifies that manifest and every payload entry before
creating or reusing a root-managed `Remap Local Codesign` identity in the System
keychain. That identity is a 3072-bit RSA code-signing certificate, is trusted
only on that Mac, and grants private-key use to `/usr/bin/codesign`. It signs the
verified app, CLI, daemon, resolver, installer, and lifecycle executables before
publication. The identity is retained across uninstall so reinstall and update
do not repeatedly ask for key access.

This model deliberately separates two questions:

- Remap's detached release signature proves which package bytes Agenxy
  published.
- The Mac's durable local identity gives macOS stable code identity for those
  verified bytes without a paid Apple account.

It does not claim Apple review, Developer ID identity, or notarization. A user
must make one explicit Gatekeeper exception for the downloaded package in
System Settings > Privacy & Security. Remap never asks the user to disable
Gatekeeper globally.

The package builds and tests with `xcrun swift`; the Xcode IDE is optional.
The exact full Xcode version and build in [`XCODE_VERSION`](XCODE_VERSION) must
be selected. Apple's command-line-tools-only package is not sufficient for the
native source installation.
The repository's `make install` task builds and locally signs the source product,
installs, activates, probes, and can transactionally roll back this source path.
Install, update, uninstall, and crash recovery each require a native
state-bound preview token. Interactive use confirms a short token prefix;
automation returns the complete token over standard input after reading the
preview. Recovery is never performed implicitly before another operation.
Before the product preview, source orchestration copies descriptor-pinned bytes
into a root-private directory under `/Library/PrivilegedHelperTools`, verifies
the exact SHA-256 and code identity, then publishes and leases only that inode.
It discloses this bootstrap boundary and removes only that exact helper on
normal exit. A crash can leave a published helper or a root-private, possibly
partial stage. Recovery reports and token-binds their exact metadata and digest;
invalid or partial bytes are never executed, and normal lifecycle work never
silently deletes a possibly active helper from another process.

The pinned Xcode 27 beta currently passes the macOS 27 SDK to Swift while its
Swift driver stamps `LC_BUILD_VERSION sdk 15.0`. The package builder repairs
that Apple-toolchain defect with Apple's own `vtool`, then revalidates every
Mach-O as macOS 15 minimum / SDK 27.0 before signing or packaging. It never
changes executable instructions or claims a different minimum operating
system. This normalization remains covered by byte-level release tests and is
required only while the pinned Apple beta emits the incorrect load command.
