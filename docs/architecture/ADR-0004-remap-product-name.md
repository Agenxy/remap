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
repository paths unclaimed. Unrelated legacy projects already use the unscoped
`remap` names on npm and PyPI. The npm package remains active but does not
conflict with Agenxy's organization scope. The PyPI project has no downloadable
files and has had no release activity since 2011.

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
- Agenxy owns the npm `@agenxy` organization scope. Any future JavaScript or
  TypeScript integration will use `@agenxy/remap`; no placeholder package will
  be published merely to occupy that scoped name.
- Agenxy will pursue the inactive PyPI `remap` project through respectful
  owner contact and the normal PEP 541 process. A transfer will not erase the
  former project's history or justify an empty placeholder release.

## Consequences

This pre-release rename intentionally changes crate names, Rust type names,
documentation paths, examples, diagnostic identifiers, and the JSON schema.
There is no compatibility alias for the unreleased Portal working name.

The npm and PyPI names are not release dependencies. The npm organization scope
provides an unambiguous identity without disputing the unrelated unscoped
package. If PyPI approves a transfer, Remap will publish only a maintained
Python integration with accurate historical attribution and a clear account of
the change in project identity.
