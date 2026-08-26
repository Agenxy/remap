# Remap

Remap is a serious, cross-platform name override and service-routing utility
for technical users.

Its contract is direct:

> Map any valid hostname you choose to a network-accessible address or service,
> and apply that mapping on enrolled devices.

Remap does not reserve a suffix or prevent users from shadowing public names:

```sh
remap set atlas http://127.0.0.1:5173
remap set builds.lab https://10.0.0.12:9443
remap set database 192.168.1.40
remap set google.com http://127.0.0.1:9000
```

If a browser rejects the resulting certificate, origin, redirect, cookie, or
content-security policy, that failure remains visible. Remap provides routing;
it does not pretend arbitrary web applications are relocatable.

## Status

Remap has completed its portable authority, DNS, and cleartext HTTP-routing
foundation. The repository contains a private SQLite registry behind one
writer, authenticated local control, revision-safe preview and atomic apply,
bounded UDP/TCP DNS, unmatched forwarding, a streaming HTTP gateway, and a
dual-version MCP server with an MCP Apps dashboard.

The macOS and Linux native backends are in active verification. macOS uses
launchd socket activation and a reversible Swift SystemConfiguration adapter.
Linux uses systemd socket activation, runs the data plane as the selected
non-root account, and changes resolver state through the native owner over
D-Bus. Remap now builds a native Apple Installer package whose release bytes
are signed with Remap's public release key and whose executables are signed on
the target Mac with a durable local identity. This is still a release candidate:
privileged clean-machine acceptance, public artifact publication,
client-facing HTTPS/CA lifecycle, wider platform acceptance, peers, and the
remaining native-app proof gates are still open.

## Install on macOS

The prebuilt installer is the normal macOS path. It requires macOS 15 or later
and an administrator account. It does not require Xcode, Homebrew, `mise`, Rust,
Python, an Apple Developer account, or a paid Apple service.

Download these four files from the same Remap release:

- `Remap-0.2.0-arm64.pkg`
- `Remap-0.2.0-arm64.pkg.sig`
- `remap-release-signing-key.pub`
- `remap-release-installer.pem`

Verify the public-key fingerprint is
`SHA256:bG9pik9VV1jT2rZrsC7sYJCZOfc0tiuSrL05/v6FmtI`, then verify the detached
package signature under the `remap-package-v1` namespace. The complete commands
are in [the macOS tutorial](docs/tutorials/first-map-macos.md). This signature
authenticates the downloaded package without relying on Apple or another paid
certificate authority. The complete XAR also carries the pinned self-signed
`Remap Release Installer` certificate so Apple Installer validates every
package action before root execution.

Do not open the mutable download directly in Finder. The tutorial copies it to
a root-owned staging directory, re-verifies those exact bytes, and invokes
Apple Installer on that immutable path. This closes the gap between signature
verification and root execution without a paid Apple identity or notarization.

The Apple Installer asks for administrator approval once. It then:

1. verifies the signed Remap release manifest and every packaged byte;
2. creates or reuses `Remap Local Codesign` in the System keychain;
3. signs the verified executables on this Mac;
4. installs and starts the native services transactionally; and
5. proves the authority, UDP DNS, TCP DNS, and HTTP gateway belong to the same
   running Remap instance.

The local signing identity is intentionally kept across updates and removed by
uninstall together with its System-keychain trust setting. It contains no
Agenxy release secret and is allowed to sign only through macOS's `codesign`
tool. User mappings remain preserved.

After installation, use the CLI:

```sh
remap doctor
remap set agenxy.remap http://localhost:4399/
curl http://agenxy.remap/
remap system status
```

Use `remap system recover` after an interrupted lifecycle operation, and
`remap system uninstall` to remove the native product. The private mapping
database is preserved so reinstalling does not lose mappings.

## Build and install from source

The same lifecycle commands are used on each supported host:

```sh
make setup-install
make install
make update
make recover
make uninstall
```

Every lifecycle mutation is preceded by an exact preview from the privileged
native authority. macOS requires device-owner authentication inside the signed
privileged boundary after that preview; text input, a copied token, and cached
administrator authority cannot authorize the lifecycle client or source helper.
Linux uses the displayed state-bound approval phrase, with the full token for
explicit automation. There is no environment or `--yes` bypass.

An interrupted operation never recovers as a side effect of another request.
Run `make recover`, review and approve its separate recovery preview, then
request a fresh install, update, or uninstall preview.

### macOS source build

The native macOS source installation requires macOS 15 or later, GNU Make,
`mise` 2026.8.13, and the exact full Xcode build recorded in
[`platforms/macos/XCODE_VERSION`](platforms/macos/XCODE_VERSION). Xcode's
command-line-tools-only package is insufficient because Remap builds and signs
native Swift products. The Xcode IDE does not need to be opened.

Verify the selected build before installing:

```sh
xcodebuild -version
```

If the pinned Xcode is installed but another build is selected, select its
developer directory with `sudo xcode-select --switch` and the app's exact
`Contents/Developer` path. Remap checks the version and build again before any
privileged installation or update effect.

Build and install the current native macOS source product:

```sh
make setup-install
make install
remap --version
```

`make setup-install` installs only the pinned Rust, Python, and `uv` tools used
to build the native source product, then checks the exact selected Xcode. It
does not download the browser test runtimes or contributor linters. Use
`make setup` when preparing the full contributor environment.

`make install` requests administrator approval once. It installs the CLI,
daemon, native resolver adapter, complete generated manual-page family, Bash,
Fish, and Zsh completions, and exact Apache license notices under `/usr/local`;
launchd owns the low ports while the daemon runs as the active non-root
account. Before mutation, the preview enumerates every public path and any
previous immutable generation that a successful update will purge. Activation
first records and then conditionally restores the prior DNS configuration. A
failed update restores the preceding installed files, service generation, and
resolver state.

Before that preview, macOS copies descriptor-pinned source bytes into a
root-private stage, verifies their SHA-256 and code identity there, and publishes
only that exact helper. This bootstrap does not install or change the Remap
product. Crash residue may be either a published helper or a root-private,
possibly partial stage; both are disclosed and retained for a separate explicit
recovery preview. Recovery binds exact metadata and SHA-256, never executes
invalid or partial residue, and a later lifecycle request never deletes it
implicitly. If macOS authentication is unavailable, cancelled, or denied, the
workflow stops before sending the mutation.

The preview identifies every public path, service, resolver change, and
immutable generation covered by the approval token.

### Linux

The native Linux source installation requires a systemd host with
systemd-resolved, Linux memfd seals, an accessible procfs descriptor view, and a
supported native link owner. `make setup-install` proves those bootstrap
properties before a product build or administrator request. Remap never hides an
`/etc/hosts`, `/etc/resolv.conf`, `resolvectl`, or `nmcli` fallback behind this
workflow. When the native preflight proves exactly one supported primary DNS
link, Remap selects it. When several links could own DNS, select the exact
numeric interface index whose resolver scope Remap should own:

On a minimal Ubuntu 24.04 host, install the operating-system build and resolver
prerequisites first. `build-essential` provides `make`, the compiler, and
linker; Remap does not download or replace these host tools:

```sh
sudo apt-get update
sudo apt-get install build-essential cmake pkg-config systemd-resolved
sudo systemctl enable --now systemd-resolved
```

Other supported distributions need the equivalent native packages. Then run
the pinned source bootstrap and installation:

```sh
make setup-install
REMAP_LINUX_LINK=2 make install
remap --version
```

The native preflight and preview report the distribution, selected link,
resolver environment, native manager backend, captured state classification,
systemd units, public paths, and immutable generation before asking for
approval. Update reuses the installed link and owner identity:

```sh
make update
```

Before native inspection, Linux descriptor-pins the reviewed lifecycle helper,
copies those bytes into a sealed anonymous Linux file, and verifies its complete
seal, digest, metadata, and exact `/proc/<pid>/fd/<fd>` identity. The operating
system's absolute `install` program receives only that immutable descriptor
path; the mutable build pathname never crosses the administrator boundary. A
shared lease on `/run` closes staging and cleanup races, while a shared lease on
the staged helper excludes the active command from residue recovery. The
root-owned copy, its non-writable ancestry, link count, mode, extended
attributes, and digest are rechecked around every privileged execution.

Normal exit removes only that exact helper and directory. After a crash,
`make recover` renders every eligible residue directory identity and helper
SHA-256, binds the typed list and exact removal effects into a separate token,
revalidates it under the native lock, and removes only an approved unchanged
candidate. An active leased helper is excluded. A normal lifecycle request
never implicitly executes or deletes prior residue. Interrupted lifecycle state
files are also rendered with exact paths, byte lengths, and full SHA-256
identities before cleanup approval. This bootstrap cannot approve product
mutation: the native helper still requires and recomputes the separately
reviewed state-bound token under its lifecycle lock.

Install and update also keep every binary, manual, completion, and license
input descriptor-pinned through preview and commit. Their complete
canonical SHA-256 manifest is printed in full and independently bound by the
approval token before the native helper rereads it under the transaction lock.
The helper recomputes the preview and requires macOS device-owner presence
before any privileged source-install effect.

The data plane runs as the selected non-root account. The narrow root helper is
the only installation and resolver-lifecycle authority; the Python task runner
builds inputs, displays bounded native output, and carries the approved token,
but cannot authorize or perform a privileged effect itself.

Install only the optimized CLI for development or for an unsupported platform:

```sh
make install-cli
```

The CLI-only default is `~/.local`; use `PREFIX=/some/root` when needed. Remove
the complete native source installation with `make uninstall`. It restores DNS
before stopping or deleting the service and preserves the private mapping
registry. Two empty root-owned lock files remain under the volatile
`/run/remap-lifecycle-authority` directory so concurrent and future lifecycle
commands continue to synchronize on stable inodes; they contain no mappings,
credentials, executable code, or product configuration and disappear when the
host clears `/run`. `make uninstall-cli` removes only a CLI-only installation.

## Architecture

Rust 1.98.0 and edition 2024 own the portable engine, daemon, CLI, DNS protocol,
gateway, persistence, and synchronization. Swift remains deliberately present
for the macOS app, Network Extension entry point, Service Management, XPC,
Keychain, Secure Enclave, signing, and packaging.

See [the architecture](docs/architecture/ARCHITECTURE.md) and
[implementation milestones](docs/roadmap/MILESTONES.md).

The [macOS tutorial](docs/tutorials/first-map-macos.md) follows the complete
installed path from activation through Safari and cleanup. The
[Linux tutorial](docs/tutorials/first-map-linux.md) covers native owner
selection, lifecycle approval, system resolution, recovery, and removal.

Remap's [values](VALUES.md), [privacy contract](PRIVACY.md),
[security policy](SECURITY.md), and
[engineering standard](docs/engineering/STANDARDS.md) are product requirements,
not aspirational marketing.

## Development

Remap follows K7's exact toolchain-pin convention without coupling Remap's
build to the K7 repository. The Make targets are a thin, discoverable front end
over pinned native tools:

```sh
make setup
make check
mise exec -- cargo run -p remap -- validate atlas http://127.0.0.1:5173
mise exec -- cargo run -p remap -- daemon
```

With the daemon running in one terminal:

```sh
mise exec -- cargo run -p remap -- status
mise exec -- cargo run -p remap -- set atlas http://127.0.0.1:5173
mise exec -- cargo run -p remap -- list --all
mise exec -- cargo run -p remap -- resolve atlas
mise exec -- cargo run -p remap -- preview changes.json
mise exec -- cargo run -p remap -- mcp
```

`remap mcp` reserves standard output for MCP frames and is intended to be
launched by an MCP host. See [the MCP guide](docs/mcp/README.md).

## Repository layout

```text
crates/remap-core       portable domain and policy primitives
crates/remap            portable command-line client and published `remap` crate
crates/remap-mcp        dual-version MCP tools, resources, subscriptions, and App
crates/remap-network    bounded DNS, forwarding, snapshots, and HTTP data plane
crates/remap-protocol   bounded local-control wire contract and native paths
crates/remap-quality    native structural quality analyzer
crates/remap-registry   authoritative SQLite registry and idempotency journal
crates/remapd           authenticated single-writer per-user daemon
docs/architecture        system design and accepted decisions
docs/cli                 command and structured-output reference
docs/engineering         enforced engineering standards
docs/mcp                 agent-host setup and MCP contract
docs/roadmap             proof-gated implementation sequence
platforms/macos          native Apple products and adapters
platforms/linux          Linux lifecycle and resolver adapters
```

Remap is licensed under the [Apache License 2.0](LICENSE). The name has passed a
preliminary open-source ecosystem collision review; that is not a legal
trademark opinion.
