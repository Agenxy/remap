# ADR-0035: Every Remap release is rehearsed on its own channel first

## Status

Accepted, 2026-10-30. The owner approved the product-neutral contract, K7
ADR 0167 (kassettes/kassette#2334), for every Agenxy tool. He also approved a
K7 deck on Solis, reachable over Supgang, as the rehearsal host. This ADR is
how Remap adopts that contract without weakening ADR-0014, ADR-0029 or
ADR-0031.

Amended 2026-10-30: where trust comes from, the interim rehearsal signer, its
custody, rotation and revocation, the rehearsal's own install sequence, and
the interim hosting below. The pipeline is built; the key is not. The
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
let them sign what passes every rehearsal check. So:

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
  builds. This keeps the kinds apart inside the pipeline; it is not where
  trust comes from (see "Where trust comes from").
- **The rehearsal literal is committed with its pin.** Until the owner
  approves the signer there is no pin, and the installer's rehearsal branch is
  `#error("The rehearsal signing pin is not committed yet (ADR-0035).")`, so a
  rehearsal cannot even compile. `make rehearsal-key` replaces that branch with
  the literal, written exactly as the release and development literals are, in
  the same commit as the pin and its published fingerprint. The existing
  pin-consistency test then keeps the literal equal to the pin file, and a
  rehearsal build refuses if they differ.
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
    nothing, so their install manifests stay schema version 1 and, with their
    generation IDs, byte-identical to before. A manifest that records a kind
    is schema version 2, so an installer from before this change refuses it at
    its schema check instead of misreading it, and this installer names any
    version it does not know. In practice that means installing an older
    package over a rehearsal install is refused until the rehearsal is
    uninstalled or replaced by a current release. A rehearsal's kind joins its
    generation seed, so a release of the same version replaces it as an update
    instead of finding it current.
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

The root is served only over HTTPS, or over plain HTTP to a loopback address
(`127.0.0.0/8` or `[::1]`), which is how a Supgang `forward` or `connect`
delivers it after authenticating the peer. `make rehearsal-publish` refuses
any other URL. Nothing in the root is a trust anchor, and the publisher never
writes through a symbolic link in it.

### The rehearsal's own install sequence

A rehearsal cannot use the README's release commands unchanged: its package
has no Apple Installer signature, the root serves no installer certificate,
and the pin it serves is not trusted. `docs/release/REHEARSAL.md` writes the
sequence out, and the README links to it:

1. download the package, its `.sig`, the served pin and `SHA256SUMS`, and
   check `SHA256SUMS`;
2. fetch the committed pin and the revoked list from GitHub over HTTPS; the
   committed pin must have the published fingerprint, the fingerprint must not
   be revoked, and the served pin must equal the committed pin;
3. verify the `.sig` against the committed pin only;
4. copy the package root-owned, verify that copy again, and run Apple
   Installer on it.

The tap is tapped from the rehearsal root's `homebrew/`.

`cargo install remap` is withdrawn from the README rather than rehearsed. The
0.2.0 product is a native package, not a crate, and crates.io keeps the 0.1.0
validator only.

### Where trust comes from

Every package carries its own installer, and that installer checks the
package against the pin compiled into it. Whoever builds a package chooses
that pin, so the check proves the package is self-consistent and nothing about
who built it. An installed generation pins nothing that a later package's
installer reads: each package brings its own. So no installed Remap, release
or rehearsal, constrains what a later package may be signed by.

Trust comes only from verification outside the package: the published
fingerprint of the pin. For a release that is the release pin's fingerprint in
the README, the macOS tutorial and `docs/release/EVIDENCE.md`. For a
rehearsal it is the rehearsal pin's fingerprint in the README and
`docs/release/REHEARSAL.md`, read over HTTPS from GitHub, checked against the
committed pin, and checked against
`docs/release/remap-rehearsal-revoked-fingerprints.txt`. `make
install-package-macos` checks against the committed pin in the checkout it
runs from.

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

The exposure is the one a missing presence requirement implies, stated
against where trust actually comes from. **Any process running as the owner on
the release-building Mac, while it is unlocked, can sign a package that passes
every rehearsal check**: the published fingerprint, the committed pin and the
revoked list all accept it. A Mac that installs that package runs it as root.
This lasts for as long as the key's fingerprint is published and not revoked.
It is not bounded by any production update, because an installed Remap pins
nothing a later package's installer reads, and a production release on a Mac
does not stop a rehearsal signed by this key from installing there later. A
release installer never accepts a rehearsal manifest, and a release is checked
against the release fingerprint, so the key cannot pass as a release.

Because a package signed by this key keeps verifying against its fingerprint
until that fingerprint is revoked, the key without presence is kept where its
reach is smallest. It is device-bound: it never leaves the Enclave, it exists
only on the release-building Mac, and copying its blob elsewhere yields
nothing that can sign. Its reach is exactly the owner's account on that one
Mac, and revocation is how that reach ends.

The creation itself is one command and one commit, written out in
[`docs/release/REHEARSAL.md`](../release/REHEARSAL.md). It is run only after
the owner approves this signer.

#### Rotation and revocation

The rehearsal key moves to the rehearsal deck's K7 keystore (K7 ADR 0099,
kassettes/kassette#2359) once that keystore can sign for Remap. That key may
be Ed25519. A rotation publishes the new fingerprint and marks the old one
revoked. It changes nothing on a Mac that already installed a rehearsal, and a
package signed by the old key still passes its own installer's check and still
verifies against the old fingerprint. A rotation works only because the
documented steps refuse a revoked fingerprint, and because `make
install-package-macos` checks against whatever pin is committed now. In one
commit:

1. Add the old fingerprint, the date and the reason to
   `docs/release/remap-rehearsal-revoked-fingerprints.txt`.
2. Replace `docs/release/remap-rehearsal-signing-key.pub` with the new key's
   line, comment `remap-release-rehearsal-only`; replace the verifier's
   rehearsal literal with it; and publish its fingerprint in the README and
   `docs/release/REHEARSAL.md`. `make rehearsal-key` does all three for a new
   Enclave key once the old pin is removed. Nothing else changes for the key
   type: the pin decides it, and the build refuses any signer whose public key
   is not the pin.

Then build and publish the next rehearsal with the new signer, and delete the
interim Enclave blob on the release-building Mac. A Mac that installed an
older rehearsal needs nothing done to it: the next package, rehearsal or
release, brings its own installer. A rehearsal build refuses a committed pin
that is in the revoked list.

Any rotation, including one forced by losing the release-building Mac or by a
suspected compromise of the owner's account on it, takes the same steps, and
the revocation is the part that matters.

### Interim hosting

K7 ADR 0167 §6 allows an interim host while the deck is not ready. Until it
is, the rehearsal root is staged on a LAN host, Solis, as static files on its
loopback address, exposed to the hive with `supgang expose` and read by each
consumer through `supgang forward` to `http://127.0.0.1:<port>/`, never as
plain HTTP across the LAN. The first clean target is a stock Mac rather than a
deck macOS guest. Each substitution is recorded in that rehearsal's evidence:
which host served the root and how it was reached, which Mac was the target
and how it was made clean, and that the gate below ran on that Mac instead. A
rehearsal run this way proves the same six steps; it does not prove anything
about the deck, and does not say it does.

### The gate

A rehearsal passes only when a clean macOS guest on the deck completes all of
the following, using the documented rehearsal sequence:

1. Download the package, its `.sig`, the served pin and `SHA256SUMS`; check
   `SHA256SUMS`; check that the committed pin has the published fingerprint,
   is not revoked and equals the served pin; and verify the `.sig` against the
   committed pin.
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
  production release then replaces it as an ordinary update, trusted because
  its signature verifies against the published release fingerprint, not
  because of anything the rehearsal install recorded.
- The README gains a rehearsal section that publishes the rehearsal
  fingerprint and links to the written-out rehearsal sequence. Its production
  commands are unchanged.
