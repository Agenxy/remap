# Portal agent briefing

Portal is a power-user name override and service-routing utility for macOS and
Linux. It maps arbitrary user-selected hostnames to DNS addresses or routed
services. It never imposes a product namespace and does not hide normal TLS,
origin, cookie, redirect, or content-security failures.

## Invariants

- Exact user intent wins. Single-label names, arbitrary suffixes, wildcard
  suffixes, and deliberate public-domain shadowing are valid.
- `portald` is the sole writer of authoritative registry, route, peer, and
  certificate state.
- DNS consumers receive immutable, versioned snapshots and fail open for names
  they do not own.
- The HTTP gateway binds loopback only unless the user explicitly configures
  an ingress listener.
- Platform privileges stay behind platform adapters. Do not make the portable
  core depend on Apple or Linux lifecycle APIs.
- Swift owns entitlement-bearing Apple entry points. Rust owns portable policy,
  protocol, routing, storage, synchronization, daemon, and CLI behavior.
- Do not add guessed entitlements or fake privileged behavior in unit tests.

## Toolchain and workflow

Rust is pinned in `mise.toml`; it is the toolchain source of truth. Use:

```sh
mise install
mise exec -- cargo fmt --all --check
mise exec -- cargo clippy --workspace --all-targets --all-features -- -D warnings
mise exec -- cargo test --workspace --all-targets
```

Keep the core safe Rust. Any future FFI `unsafe` must live in a narrowly scoped
interop crate, state its safety invariants, and have boundary tests. Add tests
and an ADR with any change to a wire format, authority boundary, privilege,
trust operation, or platform contract.

