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
- `remap-release-installer.pem`

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

Also inspect the complete Apple Installer signature:

```sh
pkgutil --check-signature Remap-0.2.0-arm64.pkg
```

The signer must be `Remap Release Installer` with SHA-256 fingerprint
`44C5C1BFEE4479F03AFF134F1A8E7971EA55C981698CFC6E0E7A100CE4239618`.
The certificate is self-signed and is therefore not publicly Apple-trusted;
the exact fingerprint and detached Ed25519 signature provide the release
identity without a paid Apple account.

## Install

Do not open the mutable download directly in Finder. Copy it to a new
root-owned directory, re-verify the exact copy, and invoke Apple Installer on
that copy:

```sh
install_dir="$(sudo mktemp -d /private/var/tmp/org.agenxy.Remap.install.XXXXXX)"
sudo chmod 0755 "$install_dir"
sudo install -o root -g wheel -m 0444 \
  Remap-0.2.0-arm64.pkg "$install_dir/Remap.pkg"
ssh-keygen -Y verify \
  -f remap-allowed-signers \
  -I remap-release \
  -n remap-package-v1 \
  -s Remap-0.2.0-arm64.pkg.sig \
  < "$install_dir/Remap.pkg" && \
sudo installer -pkg "$install_dir/Remap.pkg" -target /
sudo /bin/unlink "$install_dir/Remap.pkg"
sudo rmdir "$install_dir"
```

Stop if the second signature check fails. The root-owned copy cannot be
replaced by another process running as your account between that check and
Installer. Remap is not signed or notarized through Apple's paid Developer
Program, and this workflow does not claim Apple review or public Apple trust.

Apple Installer asks for administrator approval. Remap then verifies its signed
release manifest and every payload entry. It creates or reuses a durable local
code-signing identity named `Remap Local Codesign`, signs the verified
executables on this Mac, installs the product transactionally, and proves the
running authority, DNS listeners, and HTTP gateway belong to the same Remap
instance.

The local identity stays in the System keychain across updates, then uninstall
removes its exact private key, certificate, and trust setting. It is not an
Agenxy release key and cannot authenticate a release. User mappings are
preserved separately.

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
public files. It removes Remap's package receipt, portable source material,
local signing identity, and matching System-keychain trust, while preserving
the private mapping database.

## Build from source instead

Contributors can use the source lifecycle, which requires GNU Make, `mise`
2026.9.8, and the full Xcode version at one of the reviewed builds listed in
[`platforms/macos/XCODE_VERSION`](../../platforms/macos/XCODE_VERSION):

```sh
make setup-install
make install
```

The source path presents an exact state-bound preview before every install,
update, recovery, or uninstall mutation. It is not required for users of the
prebuilt package.
