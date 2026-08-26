# ADR-0015: Deterministic self-signed macOS XAR envelopes

## Status

Accepted for Remap 0.2.0. This extends ADR-0010 and ADR-0014.

## Context

The unsigned package is byte-reproducible, but Apple's `productsign` writes the
current wall-clock second into the signed XAR table. Disabling network
timestamping does not suppress that field. Two otherwise identical signed
packages therefore have different table checksums, RSA signatures, package
hashes, and detached Ed25519 signatures.

The release Installer private key is nonexportable in the login keychain. It
must not be copied into the repository, a temporary file, an environment
variable, a command argument, or Python process memory to work around Apple's
volatile metadata.

## Decision

Remap continues to let `productsign` construct the complete Installer envelope
and certificate chain with the exact pinned `Remap Release Installer`
identity. Before the detached Ed25519 signature is created, the builder parses
that signed XAR using the same bounded header, compressed-table, checksum, XML,
and heap checks used for unsigned packages. It requires one 3072-bit RSA
signature at heap offset 20. If `productsign` also emitted its extended CMS
record immediately after that signature, the builder removes the record,
compacts the heap, and adjusts every later heap offset. The primary signature's
embedded certificate remains in the XAR table. The builder then normalizes the
XAR metadata and recompresses the canonical table deterministically.

A narrow Swift executable selects exactly one login-keychain identity by the
committed certificate's SHA-256 fingerprint. It accepts at most 16 MiB of
canonical compressed-table bytes on standard input, requires a 3072-bit RSA
private key, and returns only the 384-byte PKCS#1 v1.5 SHA-1 signature on
standard output. Security.framework performs the signature. The helper cannot
export the key, select an identity by name alone, sign an unbounded message, or
alter package bytes.

The builder replaces only the old primary signature bytes, preserves its
certificate chain and the package payload heap, then revalidates the complete
XAR with `pkgutil`, the pinned certificate fingerprint, full package expansion,
the internal release manifest, native scripts, executable signatures, and the
exact payload tree. The detached Ed25519 signature is applied after this final
verification. The optional CMS record is not retained because its signature
covers the volatile pre-normalization table and would correctly invalidate the
canonical envelope.

The self-signed certificate requires one explicit administrator-domain trust
decision on the release-building Mac because `productsign` does not accept
user-domain trust for an Installer identity. That builder trust is not bundled,
does not make the certificate an Apple identity, and is removed after release
construction. Target Macs rely on Remap's pinned-certificate and detached-key
verification rather than inheriting the builder's trust settings.

## Consequences

Final signed package bytes and detached signatures can be compared across
independent builds rather than treating an unsigned inner package as a proxy.
Changing the canonical XAR table, certificate, signature layout, key size, or
payload fails closed. An extended signature is accepted only at the exact
post-primary heap position with a bounded, nonzero size; overlaps and malformed
offsets fail closed. The release helper is build-only and is not copied into the
installed product.

This intentionally retains SHA-1 only where the XAR format's table checksum and
Installer RSA signature contract require it. Artifact identity and publisher
authentication also require SHA-256 fingerprints, SHA-256 artifact hashes, and
the detached Ed25519 signature. A future package format or Apple signing path
that supports deterministic modern digests should replace this compatibility
boundary.
