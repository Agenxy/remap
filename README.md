# Portal

Portal is a serious, cross-platform name override and service-routing utility
for technical users.

Its contract is direct:

> Map any valid hostname you choose to a network-accessible address or service,
> and apply that mapping on enrolled devices.

Portal does not reserve a suffix or prevent users from shadowing public names:

```sh
portal map atlas http://127.0.0.1:5173
portal map builds.lab https://10.0.0.12:9443
portal map database 192.168.1.40
portal map google.com http://127.0.0.1:9000
```

If a browser rejects the resulting certificate, origin, redirect, cookie, or
content-security policy, that failure remains visible. Portal provides routing;
it does not pretend arbitrary web applications are relocatable.

## Status

Portal is at architecture milestone M0. The repository contains the first safe
Rust domain model, deterministic exact/wildcard matching, an immutable registry
snapshot, executable specifications, and an offline validation command. It does
not yet alter DNS, bind privileged ports, install services, or mutate trust.

## Architecture

Rust 1.97.1 and edition 2024 own the portable engine, daemon, CLI, DNS protocol,
gateway, persistence, and synchronization. Swift remains deliberately present
for the macOS app, Network Extension entry point, Service Management, XPC,
Keychain, Secure Enclave, signing, and packaging.

See [the architecture](docs/architecture/ARCHITECTURE.md) and
[implementation milestones](docs/roadmap/MILESTONES.md).

## Development

Portal follows K7's exact toolchain-pin convention without coupling Portal's
build to the K7 repository:

```sh
mise install
mise exec -- cargo fmt --all --check
mise exec -- cargo clippy --workspace --all-targets --all-features -- -D warnings
mise exec -- cargo test --workspace --all-targets
mise exec -- cargo run -p portal-cli -- validate atlas http://127.0.0.1:5173
```

The validation command is intentionally offline. `portal map` will not be
introduced until it can call the authoritative daemon rather than editing a
convenient but incorrect local file.

## Repository layout

```text
crates/portal-core       portable domain and policy primitives
crates/portal-cli        portable command-line client
docs/architecture        system design and accepted decisions
docs/roadmap             proof-gated implementation sequence
platforms/macos          native Apple products and adapters
platforms/linux          Linux lifecycle and resolver adapters
```

The working product name has not undergone a trademark or naming-clearance
review. Licensing and public distribution terms remain to be selected.

