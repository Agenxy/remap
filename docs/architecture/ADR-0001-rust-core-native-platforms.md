# ADR-0001: Rust core with native platform adapters

Status: accepted.

## Context

Portal must support macOS and Linux without weakening either implementation.
Its shared code parses untrusted network input, routes long-lived connections,
maintains security-sensitive state, and may execute inside a constrained macOS
Network Extension. C++26 offers control but not memory safety; Go offers an
excellent daemon experience but is less suitable for a small embedded core.
Swift is the correct language for Apple entitlement-bearing entry points but is
not the intended portable systems foundation.

The maintainer also uses C++ natively, is deliberately building Rust fluency,
and uses Rust within K7.

## Decision

- Rust 1.97.1, edition 2024, is the portable implementation language.
- Swift owns Apple-native UI, extension entry points, lifecycle, security, XPC,
  signing, and packaging.
- Linux receives native Rust platform adapters for its resolver and service
  managers.
- Cross-language reuse uses a narrow, versioned C ABI rather than Rust ABI.
- The embedded DNS path is synchronous and bounded; async runtimes stay in the
  daemon.
- Go and C++ are not initial implementation languages.
- Tool versions are pinned exactly through `mise.toml`, following the useful
  reproducibility convention in K7 without coupling Portal to K7's build.

## Consequences

Portal gains memory safety without garbage collection, deterministic resource
control, one portable engine, Cargo-native testing and fuzzing, and a practical
embedding story. The project accepts Rust's steeper learning curve and compile
times. Apple SDK changes remain isolated in Swift rather than depending on
third-party Rust bindings to expose every new framework surface immediately.

FFI is security-sensitive code. It is introduced only with explicit ownership,
panic, threading, and lifetime contracts plus tests on both sides.

