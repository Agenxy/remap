# ADR-0034: Every Remap release is rehearsed on its own channel first

## Status

Accepted, 2026-10-30. The owner approved the product-neutral contract, K7
ADR 0167 (kassettes/kassette#2334), for every Agenxy tool. He also approved a
K7 deck on Solis, reachable over Supgang, as the rehearsal host. This ADR is
how Remap adopts that contract without weakening ADR-0014, ADR-0029 or
ADR-0031.

## Context

No Remap release since 0.1.0 has been installed the way an outside user would
install it. On 30 October a new MacBook Pro was onboarded from the public
sources only. It found that every public channel still served 0.1.0, an
offline validator, and that the 0.2.0 package the README documents had never
been published.

The owner wants every release and install path exercised before any public
rollout, through the same pipeline, the same documented commands, and a
signer that no production installer can be made to accept.

Remap already builds two kinds of package from one pipeline, `make
package-macos`, and keeps them apart at compile time (ADR-0029):

- A **release package** signs its manifest only with the Secure Enclave key.
  Its installer compiles in only the release pin, and Apple Installer checks
  its signature from the `Remap Release Installer` identity.
- A **development package** signs its manifest with an Ed25519 file key. Its
  public half is pinned in `docs/release/remap-development-signing-key.pub`,
  and its installer compiles in only that pin. It touches no keychain on the
  build machine and carries no Apple Installer signature.

## Decision

### The rehearsal kind is the development kind, published

A rehearsal of release *N* is a development package of *N*, built by the same
`make package-macos` from the same commit, with the release's version. It is
the only kind of artifact published to a rehearsal root.

- **Mixed cases cannot be expressed.** Each installer compiles in exactly
  one pin, so a production installer has no code path that accepts a
  rehearsal manifest, and a rehearsal installer has none that accepts a
  release one. Nothing at runtime chooses between them.
- **The production verification code is not modified.**
- **A rehearsal says what it is.**
  - The package file is named `Remap-<version>-<arch>-rehearsal.pkg`.
  - The installer prints that it is installing a rehearsal, not a release,
    signed by a key held in a file.
  - The installed release manifest records the kind.
  - `remap doctor` and `remap system status` report a rehearsal install as
    one.
  - People only ever see the word *rehearsal*. *Development* stays a word
    inside the build.

### The rehearsal root has the production layout

`make rehearsal-publish REMAP_REHEARSAL_ROOT=<directory>` runs the package
build, then writes:

- `releases/Agenxy/remap/download/v<version>/`, holding the rehearsal
  package, its detached signature, `remap-development-signing-key.pub` and a
  `SHA256SUMS` file. This is the GitHub release asset layout.
- `api/repos/Agenxy/remap/releases/`: `latest` and `tags/v<version>` JSON in
  GitHub's shape, naming those assets.
- `homebrew/`: the tap formula for the `<version>` CLI, rendered from the
  same template as the production tap, against a source archive the root also
  serves.

The root is static files. Remap's channel lives on the Solis rehearsal deck,
beside K7's, as its own `remap/` root with its own signer.

### One documented override

The README keeps its commands and names one override: replace
`https://github.com/Agenxy/remap/releases/download` with the rehearsal root's
`releases/Agenxy/remap/download`, and verify against the development pin
instead of the release pin. The tap is tapped from the rehearsal root's
`homebrew/`. With no override, every command is the production command.

`cargo install remap` is withdrawn from the README rather than rehearsed. The
0.2.0 product is a native package, not a crate, and crates.io keeps the 0.1.0
validator only.

### Custody of the rehearsal signer

The Ed25519 key is a file today, in `~/.ssh` on the release-building Mac
(docs/security/SECRETS.md). On the rehearsal deck it moves into that deck's
K7 keystore (K7 ADR 0099) and is used only inside the clean build guest. It is
never the owner's key, never the Enclave key, and never a release identity.

### The gate

A rehearsal passes only when a clean macOS guest on the deck completes all of
the following, using the documented commands with the one override:

1. Download and verify the four files.
2. Install the package.
3. Run `remap doctor`, which must report a rehearsal install.
4. Map a name and resolve it through the operating system's resolver.
5. Uninstall, then check that ordinary DNS is restored, no Remap launchd job
   or loopback alias is left, and the System-keychain trust entry is gone.
6. Reinstall and resolve again.

It runs before every production release, and on a schedule. The guest also
answers a question this ADR does not assume: whether root can record the
per-Mac codesign trust without a dialog. The onboarding log records that
answer in place of the current "macOS-impossible" entry.

### What a rehearsal cannot prove

- the Secure Enclave signature and the release pin;
- the Apple Installer signature from `Remap Release Installer`.

Both stay proven at production time: by `make release-check`, by the package
step's check that the Enclave blob's public key is the release pin, and by
`make install-package-macos` against the release pin. The rehearsal records
these as known gaps and never claims them.

## Consequences

- A release reaches the public channels only after its rehearsal passed and
  the owner gave his per-release OK.
- Rehearsal builds need no person at all: no Touch ID, no keychain item, no
  trust dialog. The owner's sitting is needed only for production signing.
- A Mac may run a rehearsal install, for example during onboarding. The
  production release then replaces it as an ordinary update, verified by the
  new package's own compiled-in pin.
- The README gains one documented override. Its production commands are
  unchanged.
