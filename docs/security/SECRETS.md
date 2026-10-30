# Where Remap's secrets live

Every private key Remap uses or creates, what actually protects it, and how far that is
from where it should be. Measured on macOS 27 on 2026-09-24, not inferred from design;
the release key row was changed on 2026-10-27 (ADR-0029), and what of it was measured is
said below.

## The inventory

| Secret | Where it lives | What protects it | Used for |
| --- | --- | --- | --- |
| Release package signing key (P-256) | The release-building Mac's **Secure Enclave**. The owner keeps a blob file, mode 0600, that only that Enclave can use | The Enclave, which will not export it, and **user presence on every signature**: Touch ID or the login password | The detached `.pkg.sig` of a release package and its inner `release-manifest.json.sig` |
| Rehearsal package signing key (P-256), interim | The release-building Mac's **Secure Enclave**, once the owner approves it. The owner keeps a blob file, mode 0600, labelled as the rehearsal key, that only that Enclave can use | The Enclave, which will not export it. **No user presence**: any process running as the owner on that Mac, while it is unlocked, can sign a rehearsal | The detached `.pkg.sig` of a rehearsal package and its inner `release-manifest.json.sig`, accepted only by rehearsal installers (ADR-0035) |
| Development package signing key (Ed25519) | `~/.ssh/remap_release_dev_ed25519`, an ordinary file, mode 0600 | File permissions and whole-disk encryption. **No passphrase.** | The same two signatures on a development package, and nothing else |
| `Remap Release Installer` (RSA and certificate) | The building Mac's **login keychain** | The login keychain, plus a per-key access list naming which programs may use it | `productsign`, which is what lets another Mac's Installer accept the package |
| `Remap Build Signing` | The building Mac's **login keychain** | The login keychain | Signing products on a release build |
| `Remap Local Codesign` | The installing Mac's **System keychain** | Root ownership | Signing the shipped products on the machine that receives them |
| `Remap Local Installer` | The building Mac's **login keychain** | The login keychain | Locally built installer packages |

Two things in the package are not secrets and deserve saying so. The products inside a
portable package are **ad hoc signed**, which involves no key at all; the installing Mac
gives them a real identity. And the public half of each signing key is pinned, and the
pins are never mixed. The release key is pinned in
`docs/release/remap-release-signing-key.pub`, in the release branch of the Swift verifier
in `PortableReleaseManifest.swift`, and by fingerprint in the macOS tutorial, the README,
and `docs/release/EVIDENCE.md`. The development key is pinned in
`docs/release/remap-development-signing-key.pub` and in the verifier's development branch.
The rehearsal key, once created, is pinned in `docs/release/remap-rehearsal-signing-key.pub`,
marked `remap-release-rehearsal-only`, and compiled into a rehearsal installer from a source
generated from that pin for each rehearsal build.

The verifier copy ships **inside** every package, because the portable installer that
runs on the target verifies the release manifest with its own embedded copy, and exactly
one copy is compiled in: a development package's installer knows only the development
key, and a release package's only the release key. So rotating the release key
invalidates every package built before the rotation, and the symptom is a refusal from
the package's own postinstall rather than anything a signature check on the outside would
catch:

```text
Installation stopped safely: Installer integrity validation failed:
the portable Remap release signature is invalid.
```

Rotate the key, then rebuild. A test keeps the source copies in step with each other;
nothing can keep an artifact that has already been built in step with them.

## What a development package needs

A development package touches **no keychain on the machine that builds it**. It skips the
Apple installer signature, because it is installed on the machine that built it, and the
products are ad hoc signed. The only secret it uses is the development Ed25519 file
above, and a release build refuses that file, or any other exportable private key, outright.

That is worth stating precisely, because it is easy to misread as an improvement. The
keychain was not removed by protecting the key better. It was removed by using a key that
is protected **less**: an unencrypted file guarded by nothing but its mode bits. What that
buys is that no person is asked to approve anything during development, which is the rule
a development gate has to meet. What it costs is that anyone who can read the file can
sign a package that this repository's own verifier accepts. That is why the key is marked
`remap-release-development-only`, why packaging refuses to run without being told the
result is for local use, and why the artifact is named `-development`.

## Where this should be

The standard is that a signing key is generated inside hardware that will not surrender
it: the Secure Enclave on Apple silicon, a TPM elsewhere, behind one boundary with a
per-platform implementation. Remap mints and holds its own identity, in that hardware
where the machine has it, and that path must work on a machine that has never heard of
any other Agenxy tool.

The release package signing key now meets it on the Mac that builds releases.
`remap-release-key create` asks that Mac's Secure Enclave for a P-256 key whose every use
needs the owner present, and writes only the Enclave's device-bound blob, refusing to
overwrite one. The private key never exists outside the Enclave, so there is nothing to
copy, back up, or lose a passphrase for. On 2026-10-27 a key was created this way on
macOS 27 and its public key read back from the blob; a signature from it, which needs a
person to answer Touch ID, was not exercised in that change, and is the first thing the
owner's first release build proves.

The interim rehearsal key, once the owner approves it, is held in the same hardware by the
same helper, `remap-release-key create --kind rehearsal`, but without the presence
requirement, so that a rehearsal builds with no one at the Mac. It cannot be copied, but any
process running as the owner on that Mac can use it while the Mac is unlocked. That is
accepted because only rehearsal installers accept its signatures, and it is bounded by
rotation to the rehearsal deck's keystore (ADR-0035).

The release key is the only row that meets the standard in full, and only the detached
signatures may be described as hardware backed. The rest of the table does not:

- `Remap Release Installer` stays an RSA identity in the login keychain. The Secure
  Enclave holds only P-256 keys, and Apple's installer signature requires RSA, so this
  key cannot move there. A login keychain still holds exportable key material and asks a
  human at exactly the moment a human cannot evaluate the question.
- The development key is a file, on purpose, and is accepted only by a development
  package's installer.
- The other keychain identities are where they were.
- Nothing yet covers a machine without a Secure Enclave. A TPM path is still owed.

The device-bound blob has a cost the owner accepts: if the release-building Mac is lost or
its Enclave is reset, the release key is gone. The recovery is rotation, a new key on
another Mac and a new pin, and every package built before it keeps needing the old pin.

## What Supgang is, and is not

Supgang is a **convenience, not a dependency**. Remap must install and sign without it.
What Supgang adds, when it is there, is that the owner does not have to be standing at
the machine: it can supply the trust and identity that installation would otherwise ask a
person for, which is the difference between administering a gang of computers and
visiting each one.

That places real requirements on Supgang rather than on Remap. It is reachable over a
network, so it has to establish that the requester is the same owner before it vouches
for anything, and it has to hold what it vouches with in hardware that will not give it
up. A convenience that can be hijacked is worse than no convenience, because it converts
a task the owner would have done in person into one an attacker can do remotely. Remap
asking Supgang for an identity is therefore never a reason for Remap to hold its own key
less carefully, and never a path Remap may require.
