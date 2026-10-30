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

### A third kind: rehearsal

A rehearsal of release *N* is a **rehearsal package** of *N*. It is built by
the same `make package-macos`, from the same commit, with the release's
version. It is the only kind of artifact published to a rehearsal root.

The development kind is not reused. Its key is an unprotected file, and its
package is meant only for the machine that built it ("Do not distribute
it"). A distributed package whose key anyone with that file could use would
let them sign what every rehearsal-installed Mac accepts. So:

- **The rehearsal kind has its own key.** It is a dedicated Ed25519 rehearsal
  signer, never the development key, the owner's key or the Enclave key.
  Its public half is pinned at `docs/release/remap-rehearsal-signing-key.pub`
  and marked `remap-release-rehearsal-only`. A release pin carrying either
  non-release marker is refused, as the development marker already is.
- **Mixed cases cannot be expressed.** Each installer compiles in exactly one
  of the three pins (`-D REMAP_REHEARSAL_PACKAGE` selects this one). A
  production installer has no code path that accepts a rehearsal manifest,
  and none of the three accepts another kind's. Nothing at runtime chooses
  between them.
- **The production verification code is not modified.**
- **A rehearsal says what it is.**
  - The package file is named `Remap-<version>-<arch>-rehearsal.pkg`.
  - The installer prints that it is installing a rehearsal, not a release.
  - The installed release manifest records the kind.
  - `remap doctor` and `remap system status` report a rehearsal install as
    one.
- **Like a development package, it touches no keychain on the build machine**
  and carries no Apple Installer signature, so building it needs no person.

### The rehearsal root has the production layout

`make rehearsal-publish REMAP_REHEARSAL_ROOT=<directory>` runs the package
build, then writes:

- `releases/Agenxy/remap/download/v<version>/`, holding the rehearsal
  package, its detached signature, `remap-rehearsal-signing-key.pub` and a
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
`releases/Agenxy/remap/download`, and verify against the rehearsal pin
instead of the release pin. The tap is tapped from the rehearsal root's
`homebrew/`. With no override, every command is the production command.

`cargo install remap` is withdrawn from the README rather than rehearsed. The
0.2.0 product is a native package, not a crate, and crates.io keeps the 0.1.0
validator only.

### Custody of the rehearsal signer

The rehearsal key is created in, and stays in, the rehearsal deck's K7
keystore (K7 ADR 0099). It is used only inside the clean build guest and is
short-lived: it is rotated by a new pin commit, and a rotation makes every
older rehearsal install refuse the newer rehearsal until it is reinstalled.

A Mac installed from a rehearsal trusts that key for its updates until a
production release replaces it. That is the exposure the owner accepts by
onboarding a fleet machine from a rehearsal. It is bounded by the deck
keystore's custody, and it ends at the first production update.

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

- the Secure Enclave signature and the release pin, because the rehearsal
  installer compiles in the rehearsal pin instead, the one difference in its
  bytes;
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
