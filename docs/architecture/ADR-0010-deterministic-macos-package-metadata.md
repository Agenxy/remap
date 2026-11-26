# ADR-0010: Normalize macOS package metadata timestamps

Status: accepted for implementation, August 2026.

## Context

The portable macOS package already produces identical payload bytes and a
canonical signed release manifest from unchanged source. Apple's `pkgbuild`
also records each payload node's modification time in the Bill of Materials.
Files copied into a fresh private staging tree therefore gave otherwise
identical package builds different Bill of Materials bytes. `pkgbuild` also
records its fresh archive files' creation time, inode, device, ownership, and
access/change times in the outer XAR table. Those fields made the outer package
and detached signature vary even after the payload metadata was normalized.

The payload manifest intentionally binds content, paths, modes, and sizes. A
staging-time modification date is not a product identity field and has no
runtime or recovery meaning.

## Decision

Immediately before invoking `pkgbuild`, the builder sets every node in the
verified package root, native script tree, and component property list to the
fixed Unix timestamp `946684800` (2000-01-01T00:00:00Z). The normalizer accepts
only unique regular files and directories and rejects symbolic links or other
node types. Content, ownership, permissions, and release-manifest identity are
unchanged.

After `pkgbuild`, the builder validates the XAR header, compressed table,
uncompressed-size bounds, SHA-1 compressed-table checksum, XML root, and exact metadata
shape. It replaces only the volatile outer metadata with fixed values, assigns
archive-entry inodes from their stable XAR IDs, recompresses the table, updates
its checksum, and atomically replaces the temporary package. The package heap,
including its Bill of Materials, payload, native scripts, and package metadata,
is not rewritten.

The fixed timestamp is a package-format input, not a claim about source commit
time. Release provenance continues to come from the clean committed revision,
checksums, evidence manifest, and platform acceptance records.

## Consequences

Independent package builds from the same source and pinned toolchain can
produce the same Bill of Materials, package bytes, and deterministic Ed25519
signature. A future package format change must preserve this normalization or
replace it with an equally explicit reproducibility contract.

Tests cover timestamp normalization for files and directories, rejection of
symbolic links, and identical canonical XAR bytes from different volatile
build metadata.
