# ADR-0009: Recover detached portable installer sources

Status: accepted for implementation, August 2026.

## Context

The macOS portable package retains the active, root-owned source package so the
installed lifecycle service can verify later update, recovery, and uninstall
requests. A successful authority update removes the immediately previous
source package. An interrupted or previously defective update can nevertheless
leave an older source package beside the active one. The product then correctly
refuses uninstall because its cleanup plan cannot prove that the unexpected
directory is Remap-owned, but the existing recovery surface cannot classify or
remove it. This leaves system DNS active with no complete product-owned removal
path.

## Decision

While holding the portable lifecycle authority lock, package installation
enumerates at most 32 entries in the canonical root-owned `Installer/Sources`
directory. It retains the active and incoming manifest digests. Every other
entry must have a canonical lowercase SHA-256 name and must pass the complete
manifest, payload, ownership, mode, link, size, and digest validation already
required by `MacOSPortableSourcePurge`.

Validation is all-or-nothing: every detached candidate is validated before any
candidate is removed. A foreign name, invalid manifest, unsafe metadata, or
entry-count overflow stops installation without deleting anything. Validated
detached packages are then removed through the descriptor-rooted exact-file
purge; recursive deletion and shell commands remain prohibited. The incoming
and active sources are never candidates.

## Consequences

Repeated installation can converge authenticated residue from an interrupted
older update and restore the normal uninstall path. A root-created object that
does not prove it is a canonical Remap source still blocks mutation for manual
inspection. User mappings, the durable local signing identity, installed
product state, and resolver state are outside this cleanup operation.

Tests cover retaining the active source, removing a fully verified detached
source, and preserving a foreign entry when validation fails.
