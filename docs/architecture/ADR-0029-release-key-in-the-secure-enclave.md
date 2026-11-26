# ADR-0029: The release key lives in the Secure Enclave

## Status

Accepted, 2026-10-27. This changes the publisher key of ADR-0014 and ADR-0015; the
Installer identity those records describe is unchanged.

## Context

A Remap package carries two signatures from one publisher key: the detached `.pkg.sig`
over the final package bytes (namespace `remap-package-v1`), and `release-manifest.json.sig`
inside the package (namespace `remap-release`), which the portable installer verifies on
the target Mac with a public key compiled into it.

That key has never been held to the owner's standard. The August key was an Ed25519 file
with a passphrase that is now lost. Its replacement is a passphrase-less Ed25519 file,
`~/.ssh/remap_release_dev_ed25519`, marked `remap-release-development-only`, which anyone
who can read the file can use. `docs/security/SECRETS.md` states the standard: a signing key
is generated inside hardware that will not surrender it. On 2026-10-27 the owner decided the
public 0.2.0 release must be signed by a Secure Enclave key before it ships.

The key, pin, and verifier for a development package and for a release were also one and
the same, distinguished only by a comment in the pin. Nothing stopped a file key from
signing a package that a release verifier would accept.

## Decision

### The release key is a P-256 key generated in the Secure Enclave

A build-only Swift executable, `remap-release-key`, owns the key. It is not copied into any
package.

- `create --key <path>` creates `SecureEnclave.P256.Signing.PrivateKey` with access
  control `.privateKeyUsage` and `.userPresence`, accessible only while this Mac is
  unlocked. It writes the key's `dataRepresentation` with `O_CREAT | O_EXCL | O_NOFOLLOW`
  and mode 0600, refuses to overwrite an existing file, and prints the OpenSSH public key.
  The file is opened before the key is made, so an existing file is refused without asking
  the Enclave for a key that would be discarded.
- `public-key --key <path> [--comment <c>]` prints `ecdsa-sha2-nistp256 <base64> <comment>`,
  by default `remap-release-v2`.
- `sign --key <path> -n <namespace>` streams at most 256 MiB from standard input into
  SHA-512, the same bound the package verifier puts on a package, and writes an armoured
  SSHSIG signature to standard output.

P-256 is the curve because the Secure Enclave holds nothing else. It cannot hold Ed25519,
and it cannot hold RSA.

### The format stays SSHSIG

The signature is byte-compatible with `ssh-keygen -Y sign` for an `ecdsa-sha2-nistp256`
key: magic `SSHSIG`, version 1, the public key, the namespace, an empty reserved field,
hash `sha512`, and an `ecdsa-sha2-nistp256` signature of `mpint r` and `mpint s` over the
SSHSIG signed-data blob, armoured in 70-column base64. A test takes a signature that
`ssh-keygen` produced, re-encodes its key and scalars with this encoder, and requires the
same bytes.

Every verifier is therefore unchanged: `/usr/bin/ssh-keygen -Y verify` in the Swift
installer, in the Python tools, and in the tutorial's commands. Only the pinned key type
changes. The encoder is written against a small signing-key protocol so tests drive it with
a software P-256 key, because hosted CI has no Secure Enclave.

### Every signature needs the owner present

`.userPresence` makes every signature ask for Touch ID or the login password. A release
build signs twice, the inner manifest and then the package, so it asks twice. That is the
point: no process running as the owner, and no copy of the blob, can sign a release by
itself.

### Two kinds of package, two pins, never mixed

- `docs/release/remap-release-signing-key.pub` is the release pin.
  `docs/release/remap-development-signing-key.pub` is the development pin, and must carry
  `remap-release-development-only`.
- `PortableReleaseManifest.swift` compiles in exactly one of them. The package builder
  passes `-D REMAP_DEVELOPMENT_PACKAGE` when, and only when, it builds a development
  package, and afterwards requires the built installer to contain its own kind's key and,
  where the pins differ, not the other's.
- A development package (`REMAP_DEVELOPMENT_PACKAGE=1`) is signed with the development file
  key named by `REMAP_RELEASE_SIGNING_KEY`, through `ssh-keygen`, as before.
- A release package is signed only by `remap-release-key sign`, with the blob named by
  `REMAP_RELEASE_SE_KEY`. The build refuses a release if it is handed an exportable private
  key file, if the release pin is marked `remap-release-development-only`, is not
  `ecdsa-sha2-nistp256`, or equals the development pin, and if both kinds' variables are
  set at once. Once the helper is built, and before anything is signed, it requires the
  blob's public key to equal the release pin.
- `make install-package-macos` verifies a development package against the development pin
  only when `REMAP_DEVELOPMENT_PACKAGE=1` is set, and anything else against the release pin,
  which it refuses while that pin is still marked as the development key.

A test keeps each doc pin byte-identical to its Swift constant, and the release pin's
fingerprint quoted in the tutorial, the README, and `docs/release/EVIDENCE.md`.

The release pin keeps its current content until the owner creates the Secure Enclave key
and pins its public line. Until then no release can be built or verified, which is the
intended state.

### The blob is bound to this Mac

The file `create` writes is not the private key. It is the key wrapped by this Mac's Secure
Enclave, usable only there. Copying it elsewhere yields nothing that can sign, and there is
nothing to back up.

The consequence is accepted deliberately. If the release-building Mac is lost, replaced, or
its Enclave is erased, the release key is gone. The recovery is rotation: create a new key on
another Mac, pin it, and rebuild. Every package built before the rotation embeds the old pin
in its installer and was signed by the old key, so it can only ever be verified against the
old pin; a rotation does not make an older package installable under the new one. The old
pin should be published beside the releases it signed.

### The Installer identity stays in the login keychain

`Remap Release Installer` remains a 3072-bit RSA identity in the release-building Mac's login
keychain (ADR-0014, ADR-0015). Apple's installer requires an RSA signature in the XAR, and the
Secure Enclave cannot hold an RSA key. This ADR therefore makes only the detached signatures
hardware backed; the Installer signature is not, and must not be described as such.

## Consequences

The release publisher key can no longer be read, copied, or used without the owner, and a
lost passphrase can no longer strand it. Building a release now needs the owner at the
release-building Mac for two Touch ID or password prompts, and that Mac becomes the only
place a release can be signed until a rotation.

A development package works as before, needs no person, and is now verifiable only by a
development installer and by `make install-package-macos` with `REMAP_DEVELOPMENT_PACKAGE=1`.

Not addressed here: a TPM-backed key for machines without a Secure Enclave, and moving the
other keychain identities in `docs/security/SECRETS.md` into hardware.
