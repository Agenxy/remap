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

Remap has completed foundation milestone M0. The repository contains the first
safe Rust domain model, deterministic exact/wildcard matching, an immutable
registry snapshot, executable specifications, a stable offline CLI contract,
and enforced engineering and dependency gates. M1—the authoritative daemon and
local protocol—is next. Remap does not yet alter DNS, bind privileged ports,
install services, or mutate trust.

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
