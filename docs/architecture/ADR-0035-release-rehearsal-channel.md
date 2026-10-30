# ADR-0035: Every Remap release is rehearsed on its own channel first

## Status

Accepted, 2026-10-30. The owner approved the product-neutral contract, K7
ADR 0167 (kassettes/kassette#2334), for every Agenxy tool. He also approved a
K7 deck on Solis, reachable over Supgang, as the rehearsal host. This ADR is
how Remap adopts that contract without weakening ADR-0014, ADR-0029 or
ADR-0031.

Amended 2026-10-30: the interim rehearsal signer, its custody and rotation,
and the interim hosting below. The pipeline is built; the key is not. The
interim signer is proposed and waits for the owner's approval, and until then
no rehearsal pin is committed and every rehearsal build refuses, saying so.

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

- **The rehearsal kind has its own key.** It is a dedicated rehearsal signer,
  never the development key, the owner's key or the release key. Its public
  half is pinned at `docs/release/remap-rehearsal-signing-key.pub` and marked
  `remap-release-rehearsal-only`. A release pin carrying either non-release
  marker is refused, as the development marker already is, and so is a
  rehearsal pin without its marker or with the development one. The key is
  P-256 for now and may become Ed25519 at rotation, so the pipeline accepts
  either type for this pin and verifies by the pin file's own type.
- **Mixed cases cannot be expressed.** Each installer compiles in exactly one
  of the three pins (`-D REMAP_REHEARSAL_PACKAGE` selects this one). A
  production installer has no code path that accepts a rehearsal manifest,
  and none of the three accepts another kind's. Nothing at runtime chooses
  between them. Selecting two kinds at once is refused before anything
  builds.
- **The rehearsal literal is generated, never committed.** The pin exists
  only once the owner approves the signer, so the installer's rehearsal
  branch names `RehearsalSigningPin.publicKey`, which the package build
  generates from the committed pin into
  `platforms/macos/Sources/RemapPortableInstaller/Generated/RehearsalSigningPin.swift`
  for the length of the rehearsal Swift build and then removes. The path is
  ignored, the file states its provenance, and it compiles to nothing outside
  a rehearsal build, so release and development builds neither read nor need
  it. This is the one generated source inside a first-party path; it is there
  because a Swift target compiles only files under its own directory, and it
  never exists at rest. A test proves the generated literal equals a fixture
  pin byte for byte, as the committed literals equal theirs.
- **The production verification code is not modified.**
- **A rehearsal says what it is.**
  - The package file is named `Remap-<version>-<arch>-rehearsal.pkg`, and
    `make package-macos` says it is a rehearsal and not to install it as a
    release.
  - The installer prints that it is installing a rehearsal, not a release.
  - The installed generation records the kind as `packageKind` in its
    install manifest, `.remap-install-manifest.json`. The installer knows the
    kind because it was compiled for it. The signed release manifest is not
    touched, and its format is unchanged. A release and a source build record
    nothing, so their install manifests and generation IDs are byte-identical
    to before. A rehearsal's kind joins its generation seed, so a release of
    the same version replaces it as an update instead of finding it current.
  - `remap doctor` and `remap system status` report a rehearsal install as
    one: `rehearsal install, not a release`.
  - `make install-package-macos` takes a `-rehearsal.pkg` only with
    `REMAP_REHEARSAL_PACKAGE=1`, verifies it against the rehearsal pin, and
    never as a release.
- **Like a development package, it touches no keychain on the build machine**
  and carries no Apple Installer signature, so building it needs no person.
  Its Enclave key is a CryptoKit blob, not a keychain item, and it signs
  without Touch ID.

### The rehearsal root has the production layout

`make rehearsal-publish REMAP_REHEARSAL_ROOT=<directory>
REMAP_REHEARSAL_URL=<url>` checks the root, the URL, that the version is not
yet published there, and that the working tree has nothing HEAD lacks. It then
runs the rehearsal package build, archives HEAD with `git archive`, and
writes:

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

#### The interim signer: a Secure Enclave key without user presence

Until the deck keystore can hold it, the rehearsal key is a P-256 key in the
Secure Enclave of the release-building Mac, created by `remap-release-key
create --kind rehearsal`:

- Its access control is `.privateKeyUsage` alone, accessible only while that
  Mac is unlocked. There is no `.userPresence`, so signing a rehearsal asks
  for no Touch ID and a rehearsal builds unattended. The release key keeps
  `.userPresence` (ADR-0029); only the kind differs.
- It never leaves the Enclave. The file the helper writes is the Enclave's
  device-bound blob, mode 0600, usable only on that Mac.
- It cannot be mistaken for the release key. CryptoKit Enclave keys carry no
  keychain application tag, so the label lives in the blob: a rehearsal blob
  begins with `remap-release-rehearsal-key-v1`, and a release blob is the bare
  representation ADR-0029 wrote. The helper refuses to load either blob as the
  other kind, and to create, read or sign with a rehearsal key at a path whose
  file name lacks `rehearsal`, or a release key at one that has it. Its prompt
  reason and creation notice name the kind. The Python build checks the label
  again before it signs.
- It is selected by `REMAP_REHEARSAL_PACKAGE=1` with `REMAP_REHEARSAL_SE_KEY`
  naming the blob. Once the helper is built, and before anything is signed,
  the build requires the blob's public key to equal the rehearsal pin.

The exposure is the one a missing presence requirement implies: **any process
running as the owner on that Mac, while it is unlocked, can sign a
rehearsal.** That signature is accepted only by rehearsal installers, never by
a release installer, and only by Macs that installed a rehearsal. A Mac
installed from a rehearsal trusts that key for its updates until a production
release replaces it. That is the exposure the owner accepts by onboarding a
fleet machine from a rehearsal, and it ends at the first production update.

The creation itself is one command and one commit, written out in
[`docs/release/REHEARSAL.md`](../release/REHEARSAL.md). It is run only after
the owner approves this signer.

#### Rotation to the deck keystore

The rehearsal key moves to the rehearsal deck's K7 keystore (K7 ADR 0099,
kassettes/kassette#2359) once that keystore can sign for Remap. That key may
be Ed25519. The rotation is:

1. Create the new key in the deck keystore and export only its public line,
   with the comment `remap-release-rehearsal-only`.
2. In one commit, replace `docs/release/remap-rehearsal-signing-key.pub` with
   that line. Nothing else in the pipeline changes for the key type: the pin
   decides it, and the build refuses any signer whose public key is not the
   pin.
3. Build and publish the next rehearsal with the deck's signer.
4. Every Mac installed from an older rehearsal refuses the new one, because
   its installer compiled in the old pin. Each reinstalls once, from the new
   rehearsal or from a production release.
5. Delete the interim Enclave blob on the release-building Mac. The old pin
   stays in history beside the rehearsals it signed.

Any rotation, including one forced by losing the release-building Mac, takes
the same steps.

### Interim hosting

K7 ADR 0167 §6 allows an interim host while the deck is not ready. Until it
is, the rehearsal root is staged on a LAN host, Solis, as static files served
over HTTP to the LAN, and the first clean target is a stock Mac rather than a
deck macOS guest. Each substitution is recorded in that rehearsal's evidence:
which host served the root, which Mac was the target and how it was made
clean, and that the guest gate below ran on that Mac instead. A rehearsal run
this way proves the same six steps; it does not prove anything about the
deck, and does not say it does.

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

- the release key's signature, its presence requirement and the release pin,
  because the rehearsal installer compiles in the rehearsal pin instead, the
  one difference in its bytes. The interim rehearsal key does exercise the
  same Enclave signing path, `remap-release-key sign`, without Touch ID;
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
