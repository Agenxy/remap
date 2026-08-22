# Your first macOS mapping

This tutorial installs the native package, verifies the running system, maps
`agenxy.remap` to a local service, and removes the mapping again. The Remap CLI
is the primary interface; the app is an optional status surface.

## Before you start

You need:

- an Apple silicon Mac running macOS 15 or later;
- an administrator account on that Mac; and
- a local HTTP service you control.

The example expects that service at `http://localhost:4399/`. The prebuilt
package does not require Xcode, Homebrew, `mise`, Rust, Python, an Apple
Developer account, or a paid Apple service.

## Download and verify Remap

Download these files from the same Remap release into one directory:

- `Remap-0.2.0-arm64.pkg`
- `Remap-0.2.0-arm64.pkg.sig`
- `remap-release-signing-key.pub`

The public-key fingerprint must be exactly:

```text
256 SHA256:bG9pik9VV1jT2rZrsC7sYJCZOfc0tiuSrL05/v6FmtI remap-release-v1 (ED25519)
```

From that download directory, check it:

```sh
ssh-keygen -lf remap-release-signing-key.pub -E sha256
```

Create the small `ssh-keygen` allow-list and verify the complete package bytes:

```sh
printf 'remap-release %s\n' "$(cat remap-release-signing-key.pub)" > remap-allowed-signers
ssh-keygen -Y verify \
  -f remap-allowed-signers \
  -I remap-release \
  -n remap-package-v1 \
  -s Remap-0.2.0-arm64.pkg.sig \
  < Remap-0.2.0-arm64.pkg
```

Continue only if the final command says the signature is good for
`remap-release`. A missing, changed, or mismatched package must fail this check.
The allow-list file is only verification input; it does not install anything or
change system trust.

## Install

Open `Remap-0.2.0-arm64.pkg` in Finder. The package is signed by Remap but is not
signed or notarized through Apple's paid Developer Program. macOS may therefore
block the first attempt.

If it does:

1. Open **System Settings**.
2. Choose **Privacy & Security**.
3. Scroll to **Security**.
4. Confirm that the blocked item is the Remap package you just verified.
5. Choose **Open Anyway**, then open the package again.

Do not disable Gatekeeper globally. Apple documents this per-item exception in
[Open an app by overriding security settings](https://support.apple.com/guide/mac-help/open-an-app-by-overriding-security-settings-mh40617/mac).

Apple Installer asks for administrator approval. Remap then verifies its signed
release manifest and every payload entry. It creates or reuses a durable local
code-signing identity named `Remap Local Codesign`, signs the verified
executables on this Mac, installs the product transactionally, and proves the
running authority, DNS listeners, and HTTP gateway belong to the same Remap
instance.

The local identity stays in the System keychain across updates and uninstall.
It is not an Agenxy private key and cannot authenticate a release. Its only job
is to give successive verified Remap builds the same local macOS code identity
without repeated Touch ID prompts.

## Verify the installed system

Open Terminal and run:

```sh
remap --version
remap doctor
remap system status
```

Do not continue unless `remap doctor` reports the local authority, native
resolver, UDP DNS, TCP DNS, and HTTP gateway ready. An installed file or an open
port alone is not enough.

If an earlier install or update was interrupted, run:

```sh
remap system recover
```

Recovery prints its exact effects before asking for approval. A stale or
incorrect approval leaves the reviewed state untouched.

## Create the mapping

First make sure your local service answers directly:

```sh
curl --fail --show-error http://localhost:4399/
```

Then validate and create the mapping:

```sh
remap validate agenxy.remap http://localhost:4399/
remap set agenxy.remap http://localhost:4399/
remap resolve agenxy.remap
curl --fail --show-error http://agenxy.remap/
```

`validate` changes nothing. `set` commits one mapping against the current
registry revision. `resolve` reports the selected mapping and destination. The
last command must return the same service through Remap's DNS and HTTP path.

To test in Safari, enter the complete URL:

```text
http://agenxy.remap/
```

Using the explicit `http://` scheme prevents Safari from treating the name as a
search. Remap provides routing; it does not hide an upstream application's
redirect, cookie, origin, certificate, or content-security-policy behavior.

## Update

Download and verify the newer package and signature exactly as above, then open
the newer package. It reuses `Remap Local Codesign`, keeps the previous immutable
generation until the new runtime proves ready, and removes the superseded
generation only after a successful cutover. A failed update restores the prior
generation and resolver state.

## Remove the mapping or product

Remove only the example mapping:

```sh
remap remove agenxy.remap
remap resolve agenxy.remap
```

Remove the installed native product:

```sh
remap system uninstall
```

Uninstall restores the reviewed resolver state before removing services and
public files. It removes Remap's package receipt and portable source material,
but preserves the private mapping database and the durable local signing
identity. The signing identity contains no mapping data or Agenxy release
secret; retaining it prevents another key-access prompt if Remap is installed
again.

## Build from source instead

Contributors can use the source lifecycle, which requires GNU Make, `mise`
2026.8.10, and the exact full Xcode build in
[`platforms/macos/XCODE_VERSION`](../../platforms/macos/XCODE_VERSION):

```sh
make setup-install
make install
```

The source path presents an exact state-bound preview before every install,
update, recovery, or uninstall mutation. It is not required for users of the
prebuilt package.
