# ADR-0019: Development app signing requires no trusted identity

## Status

Accepted on 2026-09-23.

## Context

The development gate built its test bundle with `Remap Local Codesign`.
Creating that identity on a fresh Mac records a trust setting, which can require
interactive approval even through noninteractive sudo. A development gate must
never require a person. Trust for installed or distributed artifacts belongs to
the release and installation paths.

## Decision

An app build with `release=False` and no explicit signing identity signs ad hoc,
using `org.agenxy.Remap`, the hardened runtime, and no timestamp service. Verification
requires strict codesign validation, that exact signing identifier, an ad-hoc
signature, and the runtime flag. It never resolves or creates a keychain identity.

Release builds retain durable identity selection and exact certificate verification.
An explicitly supplied identity retains the existing signing behavior. Unsigned
release staging with `sign=False` and no identity still checks structure only;
the existing downstream signing and release verification remain required.
The shared app task supplies the durable identity explicitly when called by
`release-check`, preserving that gate's existing build configuration and checks.

The development `check` and `test` tasks do not build certificate-backed native
installation images. The generated-package contract check belongs to `release-check`,
where it runs before the release metadata checks that consume its native binaries.
The isolated CLI install/uninstall check also belongs to `release-check` and remains
available separately as `make install-check`. Neither check performs a system-wide
native installation. Deliberate native installs and setup packages retain their
certificate requirements, manifests, and Swift signature verification unchanged.

## Consequences and verification

Development bundles establish local code integrity without signer provenance.
They must not satisfy durable-identity release verification. This changes no
installer authority, entitlement, release inventory, or distribution policy.

Cross-platform contract tests assert that development builds never request identity
creation or trust recording, reject unexpected subprocesses, and distinguish the
release signer and certificate requirement. A macOS-only test signs and strictly
verifies a real Mach-O bundle, checks its identifier and runtime flag, and executes
it without keychain access. Its fixture substitutes compilation, icon generation,
and SDK normalization; it does not claim a full application build or release
keychain acceptance.

Gate orchestration tests also run the development call graph with identity acquisition
set to fail, and require the release gate to reach native identity acquisition and
propagate its failure. These tests prove dispatch and failure behavior, not successful
execution of the complete gate on a fresh Mac with a locked keychain.
