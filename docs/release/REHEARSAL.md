# Rehearsing a release

Every Remap release is first published to a rehearsal root and installed on a
clean Mac ([ADR-0035](../architecture/ADR-0035-release-rehearsal-channel.md)).
This page is the procedure. The pipeline is in place. The one thing it lacks
is the rehearsal signer, which waits for the owner's approval.

## What an installing Mac trusts

Every package carries its own installer, and that installer checks the package
only against the pin compiled into it. Whoever builds a package chooses that
pin, so it proves nothing about who built the package. Neither does anything
the rehearsal root serves, the pin beside the package included: anyone who can
write the root, or change what it serves on the way, can replace the package,
its signature and that pin together.

Trust therefore comes only from outside the package and outside the root:

- the rehearsal pin's SHA-256 fingerprint, published below and in the README,
  read on GitHub over HTTPS;
- the pin committed in the repository, fetched from GitHub over HTTPS, which
  must have that fingerprint, must not be in the
  [revoked list](remap-rehearsal-revoked-fingerprints.txt), and is the only
  pin the package's signature is checked against.

The rehearsal pin's fingerprint is not published yet, so no rehearsal can run.

## Until the owner approves the signer

There is no `docs/release/remap-rehearsal-signing-key.pub`, and the rehearsal
branch of the installer's verifier is a compile-time error, so no rehearsal can
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
Touch ID. The exposure being approved is in ADR-0035: any process running as
the owner on that Mac, while it is unlocked, can sign a package that passes
the rehearsal checks below, for as long as the key's fingerprint is published
and not revoked.

On the release-building Mac, in a clean checkout of the branch the rehearsal is
built from, run one command:

```sh
make rehearsal-key REMAP_REHEARSAL_SE_KEY="$HOME/.ssh/remap_rehearsal.enclave-key"
```

It builds `remap-release-key`, asks the Enclave for the key, keeps only the
device-bound blob at that path (mode 0600, never overwritten), and writes:

- `docs/release/remap-rehearsal-signing-key.pub`, the line
  `ecdsa-sha2-nistp256 <key> remap-release-rehearsal-only`;
- the rehearsal branch of
  `platforms/macos/Sources/RemapPortableInstaller/PortableReleaseManifest.swift`,
  as a literal written exactly like the release and development pins;
- the pin's fingerprint, in place of the "not published yet" line, in the
  README and on this page.

It refuses if the pin already exists, if the blob path exists, or if the blob's
file name lacks `rehearsal`, before the Enclave is asked for anything. Then
make one commit of exactly those four files:

```sh
git add docs/release/remap-rehearsal-signing-key.pub \
  platforms/macos/Sources/RemapPortableInstaller/PortableReleaseManifest.swift \
  README.md docs/release/REHEARSAL.md
git commit -m "Pin the interim rehearsal signer (ADR-0035)"
```

The pin-consistency test keeps the literal equal to the pin file, and the
documentation test keeps the published fingerprint equal to the pin's. Once
the commit is pushed to GitHub, the fingerprint is published.

## Building and publishing a rehearsal

The rehearsal root is served over HTTPS, or over plain HTTP only to a loopback
address, `127.0.0.0/8` or `[::1]`. Loopback is how a Supgang `forward` or
`connect` delivers the root after authenticating the peer (K7 ADR 0167 §6).
`make rehearsal-publish` refuses any other URL, because what it writes names
that URL as the place every asset is downloaded from.

Until the deck is ready, the root is staged on Solis and the first clean target
is a stock Mac. Record both as substitutions in the rehearsal evidence
(ADR-0035, "Interim hosting"). On Solis, serve the root directory as static
files on its loopback address only, for example port 8080, and expose that
port to the hive:

```sh
supgang expose remap-rehearsal 8080
```

On each Mac that reads the root, forward the same local port to it:

```sh
supgang forward 127.0.0.1:14331 solis remap-rehearsal
```

Every reader must use the same local port, because the published API answers
and Homebrew formula name `REMAP_REHEARSAL_URL`. With the pin committed and the
working tree clean, on the release-building Mac:

```sh
make rehearsal-publish \
  REMAP_REHEARSAL_SE_KEY="$HOME/.ssh/remap_rehearsal.enclave-key" \
  REMAP_REHEARSAL_ROOT=/absolute/path/to/rehearsal/root \
  REMAP_REHEARSAL_URL=http://127.0.0.1:14331/remap
```

This builds `dist/Remap-<version>-<arch>-rehearsal.pkg` and its `.sig`, signed
by the rehearsal key with no Touch ID and no Apple Installer signature, then
publishes the package, the signature, the rehearsal pin, `SHA256SUMS`, and a
`git archive` of HEAD into the root with the production layout. A version
already in the root is never rewritten, and nothing is written through a
symbolic link. Copy the root to Solis's served directory. To build the package
alone, use `make package-macos REMAP_REHEARSAL_PACKAGE=1
REMAP_REHEARSAL_SE_KEY=...`.

## Installing a rehearsal on the clean Mac

This replaces the README's install commands for a rehearsal. Each check must
succeed; stop at the first that fails, and install nothing.

Set the inputs. `FINGERPRINT` is the one published above, as GitHub shows this
page over HTTPS; `REF` is the branch that carries the pin commit.

```sh
FINGERPRINT='SHA256:<the published fingerprint>'
REF=main
ROOT_URL=http://127.0.0.1:14331/remap
VERSION=0.2.0
PACKAGE="Remap-$VERSION-arm64-rehearsal.pkg"
GITHUB="https://raw.githubusercontent.com/Agenxy/remap/$REF/docs/release"
```

Download the four served files into a new directory, and check them against
the root's own `SHA256SUMS`. This catches a damaged download, not a hostile
root:

```sh
mkdir remap-rehearsal && cd remap-rehearsal
for file in "$PACKAGE" "$PACKAGE.sig" remap-rehearsal-signing-key.pub SHA256SUMS; do
  curl -fsSLO "$ROOT_URL/releases/Agenxy/remap/download/v$VERSION/$file"
done
shasum -a 256 -c SHA256SUMS
```

Fetch the committed pin and the revoked list from GitHub over HTTPS. The
committed pin must have the published fingerprint, that fingerprint must not
be revoked, and the served pin must be the committed pin byte for byte:

```sh
curl -fsSL "$GITHUB/remap-rehearsal-signing-key.pub" -o committed-rehearsal-key.pub
curl -fsSL "$GITHUB/remap-rehearsal-revoked-fingerprints.txt" -o revoked-fingerprints.txt
test "$(ssh-keygen -lf committed-rehearsal-key.pub -E sha256 | awk '{print $2}')" = "$FINGERPRINT"
! awk '!/^#/ {print $1}' revoked-fingerprints.txt | grep -qxF "$FINGERPRINT"
cmp committed-rehearsal-key.pub remap-rehearsal-signing-key.pub
```

Verify the package signature against the committed pin, never the served copy:

```sh
printf 'remap-release %s\n' "$(cat committed-rehearsal-key.pub)" > remap-allowed-signers
ssh-keygen -Y verify \
  -f remap-allowed-signers \
  -I remap-release \
  -n remap-package-v1 \
  -s "$PACKAGE.sig" \
  < "$PACKAGE"
```

Copy the package to a new root-owned directory, verify that exact copy again,
and run Apple Installer on it:

```sh
install_dir="$(sudo mktemp -d /private/var/tmp/org.agenxy.Remap.install.XXXXXX)"
sudo chmod 0755 "$install_dir"
sudo install -o root -g wheel -m 0444 "$PACKAGE" "$install_dir/Remap.pkg"
ssh-keygen -Y verify \
  -f remap-allowed-signers \
  -I remap-release \
  -n remap-package-v1 \
  -s "$PACKAGE.sig" \
  < "$install_dir/Remap.pkg" && \
sudo installer -pkg "$install_dir/Remap.pkg" -target /
sudo /bin/unlink "$install_dir/Remap.pkg"
sudo rmdir "$install_dir"
```

The installer says it is installing a rehearsal, not a release. Then run
`remap doctor`, which must report `rehearsal install, not a release`, and
continue with the gate in ADR-0035.

From a checkout of the repository, `make install-package-macos` does the
signature, staging and installer steps against the committed pin, and takes
the package only as a rehearsal:

```sh
make install-package-macos REMAP_REHEARSAL_PACKAGE=1 \
  REMAP_MACOS_PACKAGE=dist/Remap-0.2.0-arm64-rehearsal.pkg
```

## Rotating and revoking the signer

The interim key moves to the rehearsal deck's K7 keystore later
(kassettes/kassette#2359), and may become Ed25519. A rotation publishes the new
fingerprint and revokes the old one. It cannot reach into Macs that already
installed a rehearsal, and it does not stop a package signed by the old key
from passing its own installer's check. It works only because the steps above
refuse a revoked fingerprint. In one commit:

1. Add the old fingerprint to
   [`remap-rehearsal-revoked-fingerprints.txt`](remap-rehearsal-revoked-fingerprints.txt),
   with the date and the reason.
2. `git rm docs/release/remap-rehearsal-signing-key.pub`.
3. Pin the new key: `make rehearsal-key` for another Enclave key, or for the
   deck's key write its public line to the pin file, its literal into the
   verifier's rehearsal branch, and its fingerprint into the README and this
   page.

Then delete the old Enclave blob on the release-building Mac. ADR-0035 says
what a rotation does and does not change.
