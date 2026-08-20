# Remap

A cross-platform name override and service-routing utility for technical users.

**0.1.0 validates mappings offline. It does not yet resolve them.** Milestone
M0 is complete: the Rust domain model, deterministic exact and wildcard
matching, immutable registry snapshots, executable specifications and a stable
CLI contract. It does not alter DNS, bind privileged ports, install a daemon,
or modify trust. M1, the authoritative daemon and local protocol, is next.

What the released binary does today:

```sh
remap doctor                                   # build, platform, capabilities
remap validate atlas http://127.0.0.1:5173
remap validate google.com 127.0.0.1
remap validate '*.lab' https://example.com:9443/base
```

`doctor` reports the build, platform, current capabilities, DNS impact and
telemetry posture without making a network request. Nothing above changes
system state. Full reference: [docs/cli/remap.md](docs/cli/remap.md).

## Install

```sh
brew install agenxy/tap/remap        # macOS, Linux
cargo install remap                  # from crates.io
```

## The contract, once M1 lands

> Map any valid hostname you choose to a network-accessible address or service,
> and apply that mapping on enrolled devices.

Remap will not reserve a suffix or prevent users from shadowing public names,
so `google.com` is a mapping you are allowed to make. If a browser then rejects
the resulting certificate, origin, redirect, cookie or content-security policy,
that failure stays visible: Remap provides routing, and does not pretend
arbitrary web applications are relocatable.

This section describes intent, not shipped behaviour. `remap set` does not
exist yet.

## Architecture

Rust 1.97.1 and edition 2024 own the portable engine, daemon, CLI, DNS protocol,
gateway, persistence, and synchronization. Swift remains deliberately present
for the macOS app, Network Extension entry point, Service Management, XPC,
Keychain, Secure Enclave, signing, and packaging.

See [the architecture](docs/architecture/ARCHITECTURE.md) and
[implementation milestones](docs/roadmap/MILESTONES.md).

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
mise exec -- cargo run -p remap -- --json doctor
```

The validation command is intentionally offline. `remap set` will not be
introduced until it can call the authoritative daemon rather than editing a
convenient but incorrect local file.

## Repository layout

```text
crates/remap-core       portable domain and policy primitives
crates/remap            portable command-line client and published `remap` crate
crates/remap-quality    native structural quality analyzer
docs/architecture        system design and accepted decisions
docs/cli                 command and structured-output reference
docs/engineering         enforced engineering standards
docs/roadmap             proof-gated implementation sequence
platforms/macos          native Apple products and adapters
platforms/linux          Linux lifecycle and resolver adapters
```

Remap is licensed under the [Apache License 2.0](LICENSE). The name has passed a
preliminary open-source ecosystem collision review; that is not a legal
trademark opinion.
