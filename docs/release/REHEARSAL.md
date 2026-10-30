# Rehearsing a release

Every Remap release is first published to a rehearsal root and installed on a
clean Mac ([ADR-0035](../architecture/ADR-0035-release-rehearsal-channel.md)).
This page is the procedure. The pipeline is in place. The one thing it lacks
is the rehearsal signer, which waits for the owner's approval.

## Until the owner approves the signer

There is no `docs/release/remap-rehearsal-signing-key.pub`, so no rehearsal can
be built. `make package-macos REMAP_REHEARSAL_PACKAGE=1` and
`make rehearsal-publish` both stop before building anything:

```text
task failed: the rehearsal pin docs/release/remap-rehearsal-signing-key.pub
has not been committed. That is expected until the owner approves the interim
rehearsal signer; ...
```

Release and development packages are unaffected.

## Creating the signer, once, after approval

The interim signer is a P-256 key in the Secure Enclave of the release-building
Mac, created without a user-presence requirement, so a rehearsal signs without
Touch ID. Any process running as the owner on that Mac can then sign a
rehearsal, and no release installer accepts one. That is the exposure being
approved.

On the release-building Mac, in a clean checkout of the branch the rehearsal is
built from, run one command:

```sh
make rehearsal-key REMAP_REHEARSAL_SE_KEY="$HOME/.ssh/remap_rehearsal.enclave-key"
```

It builds `remap-release-key`, asks the Enclave for the key, keeps only the
device-bound blob at that path (mode 0600, never overwritten), and writes the
public line to `docs/release/remap-rehearsal-signing-key.pub`. The line is
`ecdsa-sha2-nistp256 <key> remap-release-rehearsal-only`. It refuses if the pin
already exists, if the blob path exists, or if the blob's file name lacks
`rehearsal`, before the Enclave is asked for anything.

Then make one commit:

```sh
git add docs/release/remap-rehearsal-signing-key.pub
git commit -m "Pin the interim rehearsal signer (ADR-0035)"
```

Record the pin's fingerprint in the rehearsal evidence:

```sh
ssh-keygen -l -E sha256 -f docs/release/remap-rehearsal-signing-key.pub
```

## Building and publishing a rehearsal

With the pin committed and the working tree clean:

```sh
make rehearsal-publish \
  REMAP_REHEARSAL_SE_KEY="$HOME/.ssh/remap_rehearsal.enclave-key" \
  REMAP_REHEARSAL_ROOT=/absolute/path/to/rehearsal/root \
  REMAP_REHEARSAL_URL=http://solis.local:8080/remap
```

This builds `dist/Remap-<version>-<arch>-rehearsal.pkg` and its `.sig`, signed
by the rehearsal key with no Touch ID and no Apple Installer signature, then
publishes the package, the signature, the rehearsal pin, and a `git archive`
of HEAD into the root with the production layout. A version already in the
root is never rewritten. To build the package alone, use
`make package-macos REMAP_REHEARSAL_PACKAGE=1 REMAP_REHEARSAL_SE_KEY=...`.

Until the deck is ready the root is staged on Solis on the LAN, and the first
clean target is a stock Mac. Record both as substitutions in the rehearsal
evidence (ADR-0035, "Interim hosting").

## Installing it on the clean Mac

Use the README's commands with the one override in
[Installing a rehearsal](../../README.md#installing-a-rehearsal). From a
checkout, `make install-package-macos` takes the package only as a rehearsal:

```sh
make install-package-macos REMAP_REHEARSAL_PACKAGE=1 \
  REMAP_MACOS_PACKAGE=dist/Remap-0.2.0-arm64-rehearsal.pkg
```

The installer says it is installing a rehearsal, not a release, and
`remap doctor` and `remap system status` then report a rehearsal install.

## Rotating the signer

The interim key moves to the rehearsal deck's K7 keystore later
(kassettes/kassette#2359), and may become Ed25519. A rotation is a new pin
commit: `git rm` the old pin and commit the new line in its place. Every Mac
installed from an older rehearsal then refuses the newer one and reinstalls
once. ADR-0035 lists the steps.
