# ADR-0004: Adopt Remap as the product and command name

Status: accepted.

## Context

The original working name, Portal, expressed movement between destinations but
collided with an existing Homebrew formula and executable. Ionic also ships a
developer CLI named `portals`. Those are operational installation conflicts,
not merely unrelated uses of a common word.

Remap directly describes the product's operation: associate a user-selected
name with an address or routed service, and change that association without
reconfiguring clients. A live namespace review on 2026-08-11 found the exact
`remap` Homebrew formula, Homebrew cask, crates.io crate, and `agenxy/remap`
repository paths unclaimed. Unrelated legacy packages already use `remap` on
npm and PyPI; Remap does not depend on either namespace.

## Decision

- The product, repository, and executable are named Remap and `remap`.
- The authoritative daemon is named `remapd`.
- The published CLI crate is `remap`; portable policy primitives are published
  as `remap-core`; repository-only quality tooling remains `remap-quality`.
- The structured CLI schema is `remap.cli/v1` and stable diagnostic identifiers
  use the `R` prefix.
- The first mutation verb will be `set`, producing `remap set NAME TARGET`.
  `remap map` is rejected as redundant wording.
- Homebrew distribution will use the `remap` formula through the Agenxy tap
  until the project qualifies for Homebrew core.

## Consequences

This pre-release rename intentionally changes crate names, Rust type names,
documentation paths, examples, diagnostic identifiers, and the JSON schema.
There is no compatibility alias for the unreleased Portal working name.

The npm and PyPI names are not release dependencies and will not be disputed or
imitated with misleading placeholder packages. If bindings later justify those
registries, they will use an explicit scoped or descriptive package name unless
the registries approve a normal abandoned-project transfer.
