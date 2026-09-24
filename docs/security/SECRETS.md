# Where Remap's secrets live

Every private key Remap uses or creates, what actually protects it, and how far that is
from where it should be. Measured on macOS 27 on 2026-09-24, not inferred from design.

## The inventory

| Secret | Where it lives | What protects it | Used for |
| --- | --- | --- | --- |
| Release package signing key (Ed25519) | `~/.ssh/remap_release_dev_ed25519`, an ordinary file, mode 0600 | File permissions and whole-disk encryption. **No passphrase.** | The detached `.pkg.sig` that proves the package bytes are the ones that were built |
| `Remap Release Installer` (RSA and certificate) | The building Mac's **login keychain** | The login keychain, plus a per-key access list naming which programs may use it | `productsign`, which is what lets another Mac's Installer accept the package |
| `Remap Local Codesign` | The building Mac's **login keychain** | The login keychain | Signing products on a release build |
| `Remap Local Installer` | The building Mac's **login keychain** | The login keychain | Locally built installer packages |
| Target code signing identity | The installing Mac's **System keychain** | Root ownership, which is why installation needs no login password | The portable installer re-signs the shipped products on the machine that receives them |

Two things in the package are not secrets and deserve saying so. The products inside a
portable package are **ad hoc signed**, which involves no key at all; the installing Mac
gives them a real identity. And the public half of the release key is pinned in three
places that must move together: `docs/release/remap-release-signing-key.pub`, the Swift
verifier in `PortableReleaseManifest.swift`, and the fingerprint in the macOS tutorial.

## What a development package needs

A development package touches **no keychain on the machine that builds it**. It skips the
Apple installer signature, because it is installed on the machine that built it, and the
products are ad hoc signed. The only secret it uses is the Ed25519 file above.

That is worth stating precisely, because it is easy to misread as an improvement. The
keychain was not removed by protecting the key better. It was removed by using a key that
is protected **less**: an unencrypted file guarded by nothing but its mode bits. What that
buys is that no person is asked to approve anything during development, which is the rule
a development gate has to meet. What it costs is that anyone who can read the file can
sign a package that this repository's own verifier accepts. That is why the key is marked
`remap-release-development-only`, why packaging refuses to run without being told the
result is for local use, and why the artifact is named `-development`.

## Where this should be

None of the rows above meet the standard. A file is readable by anything running as the
owner. A login keychain is better, and it still holds exportable key material and asks a
human at exactly the moment a human cannot evaluate the question.

The standard is that a signing key is generated inside hardware that will not surrender
it: the Secure Enclave on Apple silicon, a TPM elsewhere, behind one boundary with a
per-platform implementation. Remap should not be minting and storing its own identities at
all; it should be asking Supgang for one, as the owner of identity across these products.
Until that exists, no Remap release may describe its signing as hardware backed, and this
page is the statement of what it is instead.
