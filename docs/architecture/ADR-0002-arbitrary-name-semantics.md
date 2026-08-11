# ADR-0002: Arbitrary name semantics

Status: accepted.

## Context

Remap is a user-directed name override layer, not a manager for a branded
private namespace.

## Decision

Remap accepts valid single-label and multi-label hostnames without imposing a
suffix. It permits invented suffixes, wildcard suffixes, and existing public
domains:

```text
atlas
atlas.local
api.whatever
google.com
*.lab
```

Exact user intent is not blocked by product policy. Shadowing a public name
affects enrolled devices and ordinary certificate and origin behavior remains
visible. Address literals are destinations rather than source mapping keys.

The initial parser accepts ASCII hostname labels. Unicode input is added only
with one explicit IDNA conversion and safe-display policy shared by every
component.

## Consequences

- There is no mandatory `.remap` namespace.
- Exact matches outrank wildcards; the most specific wildcard wins.
- Unmapped names follow the normal forwarding path.
- Mapping a public name intentionally shadows its public result.
- HTTPS success depends on trust and upstream origin behavior; Remap does not
  conceal failures or claim arbitrary applications are relocatable.

