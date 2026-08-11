# Remap agent briefing

Remap is a power-user name override and service-routing utility for macOS and
Linux. It maps arbitrary user-selected hostnames to DNS addresses or routed
services. It never imposes a product namespace and does not hide normal TLS,
origin, cookie, redirect, or content-security failures.

## Invariants

- Exact user intent wins. Single-label names, arbitrary suffixes, wildcard
  suffixes, and deliberate public-domain shadowing are valid.
- `remapd` is the sole writer of authoritative registry, route, peer, and
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

Read `VALUES.md`, `PRIVACY.md`, `SECURITY.md`, and
`docs/engineering/STANDARDS.md` before changing architecture, trust, data, or
user-facing behavior. Rust and quality tools are pinned in `mise.toml`; it is
the toolchain source of truth. Use the thin Make front end:

```sh
make setup
make check
```

Every warning is an error. `remap-quality` enforces the K7 ceilings for files,
functions, type bodies, parameters, complexity, and nesting. Never weaken or
suppress a gate to land code. Keep the core safe Rust. Any future FFI `unsafe`
must live in a narrowly scoped interop crate, state its safety invariants, and
have boundary tests. Add tests and an ADR with any change to a wire format,
authority boundary, privilege, trust operation, or platform contract.

Make and shell are acceptable for thin orchestration and bootstrap. Substantive
logic belongs in native typed tools; product platform behavior never shells out
when a maintained native API or binding exists.
