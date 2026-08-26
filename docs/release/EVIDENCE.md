# Release evidence

Status: implemented source-artifact evidence layer and a separately verified
portable macOS package. The evidence directory itself is not a notarization or
authenticated-builder claim.

Remap creates a deterministic evidence directory beside final artifact files.
The directory binds artifact bytes, source dependency authorities, a
multi-language CycloneDX 1.7 SBOM, and an explicitly unsigned in-toto
statement. Re-running the generator with identical artifact bytes, repository
state, dependency authorities, and toolchain produces identical evidence
bytes. Absolute paths, user names, host names, timestamps, and random SBOM
serial numbers are excluded.

## Evidence files

| File | Meaning |
|---|---|
| `artifacts.sha256` | Portable SHA-256 lines for every final artifact. |
| `manifest.json` | Artifact sizes and digests, material digests, coverage, repository observation, and release-readiness limits. |
| `sbom.cdx.json` | Canonical CycloneDX 1.7 component and dependency inventory. |
| `provenance.intoto.json` | Unsigned local observation using an in-toto Statement v1 envelope and a Remap-specific predicate. |
| `evidence.sha256` | SHA-256 coverage for every other evidence file. |

The in-toto file is not a SLSA provenance claim. It records that the evidence
tool did not observe the build invocation, verify a builder or CI identity,
verify an artifact signature, or assess notarization. It has no signature.
Changing its file extension or uploading it beside a release does not
authenticate it.

`manifest.json` keeps readiness states explicit:

- `sourceTree` is `clean` or `dirty` at the observation immediately before
  evidence generation. It does not claim the artifact was built from that
  tree.
- CI is `unverified` with `verified: false`. A future authenticated builder may
  distinguish `passed`, `failed`, and `unverified`, but local environment
  variables are not identity evidence.
- macOS code-signature status is `not-assessed`. A future native artifact
  verifier must distinguish `unsigned`, `ad-hoc`, and `developer-id`, and must
  keep signature integrity separate from trust and notarization.
- macOS linked-SDK status is `not-assessed`. The native release gate separately
  fails when a Mach-O artifact declares an SDK other than the exact selected
  Xcode SDK. A future artifact evidence adapter must record `passed` or `failed`
  from that same byte-level check.
- notarization is `absent`, meaning the evidence set contains no verified
  notarization proof. It is not a claim about Apple's service state.
- the evidence manifest's distribution field remains `source-install-only`
  because this generator currently covers crate archives. The portable macOS
  package has its own release-manifest and detached-signature verifier; those
  claims are not silently projected into the source evidence set.

## Portable macOS package

`make package-macos` creates the Apple silicon package and a detached SSH
signature:

```text
dist/Remap-0.2.0-arm64.pkg
dist/Remap-0.2.0-arm64.pkg.sig
```

The signature uses Remap's dedicated Ed25519 release key, identity
`remap-release`, and namespace `remap-package-v1`. The corresponding public key
is committed at `docs/release/remap-release-signing-key.pub`; its SHA-256
fingerprint is `SHA256:bG9pik9VV1jT2rZrsC7sYJCZOfc0tiuSrL05/v6FmtI`.

The builder refuses to overwrite an existing artifact, verifies the complete
detached signature after publication, rejects noncanonical and AppleDouble
members from the unexpanded payload listing, expands the package, checks the
exact identifier and version, requires native Mach-O installer actions,
compares the canonical internal release manifest byte for byte, and revalidates
every expanded payload node. It then signs the complete XAR with the pinned
self-signed `Remap Release Installer` identity before applying the detached
Ed25519 signature to those final bytes. The package is intentionally not
Developer ID signed or notarized. On the target Mac, a root native installer
verifies the signed internal manifest and signs the verified executables with a
durable local System-keychain identity before native publication.

Apple's `productsign` accepts this self-signed Installer identity only while its
pinned public certificate has explicit administrator-domain trust on the
release-building Mac. That one-time builder decision is separate from target
installation and is removed after the reproducibility runs. `productsign` also
inserts its wall-clock signing second even when network timestamping is
disabled. Remap therefore normalizes the completed XAR table and uses a narrow
Swift helper to ask Keychain to re-sign those canonical bytes with the exact
nonexportable identity. The helper is build-only, accepts a bounded table on
standard input, selects by the pinned SHA-256 certificate fingerprint, and is
not copied into the package. Final signed package bytes, not only the unsigned
payload, must match across two clean builds.

## SBOM coverage and evidence classes

[Syft 1.51.0](https://github.com/anchore/syft/releases/tag/v1.51.0) is the exact
current stable release and is pinned in `mise.toml`. Syft scans the final
artifact set and the copied dependency authorities. Remap removes Syft's random
serial number and timestamp, assigns the stable product identity, canonicalizes
unordered content, then applies Remap's strict structural and cross-reference
validator. Syft's `convert` command is not used because version 1.51.0 labels it
experimental with a warning, and release warnings are fatal.

Every component has exactly one `org.agenxy.remap:evidence-class` property:

- `artifact-observed` means Syft found the component in the final artifact
  scan tree.
- `lock-declared` means Syft found the component only in a copied dependency
  authority such as `Cargo.lock`.
- `artifact-observed-and-lock-declared` means both sources support it.
- `scanner-observed` is retained for a Syft result without either recognized
  location and remains weaker than artifact observation.
- `manually-declared-swiftpm` identifies first-party shipped targets from the
  exact SwiftPM package graph.
- `manually-declared-esbuild` identifies the embedded MCP App and the exact
  first-party inputs reported by esbuild.

Syft 1.51.0 catalogs the locked Cargo graph, but it does not catalog Bun's
lockfile or a Swift package with no external resolution file. Remap does not
hide those gaps. SwiftPM must report zero external packages until an approved
Swift advisory scanner is integrated. The esbuild input graph must remain
inside `crates/remap-mcp/app`; an external bundled package fails evidence
generation until it has explicit package identity and lock coverage. The Bun
lock is still hashed as a build material and `bun audit --audit-level=low` must
pass.

## Security and integrity checks

Artifact arguments use a portable public name and a lexical path. Symlinks,
hardlinks, directories, and special files are rejected. Hashing uses a
no-follow descriptor and compares device, inode, mode, owner, group, link
count, size, modification time, and change time before and after reading. The
exact number of bytes read must equal the original file size. Each artifact is
copied into the isolated Syft scan root and hashed again before evidence is
written.

Generation runs the complete `cargo deny` policy with warnings denied and the
Bun low-severity advisory gate. Syft diagnostics are fatal. Verification
recomputes live artifact digests, both checksum files, canonical JSON, manifest
and in-toto subjects, language coverage, component evidence classes, and a
strict CycloneDX structure and dependency cross-check.

## Current command surface

Build and verify every workspace crate archive, then create the deterministic
unsigned source-artifact evidence set:

```sh
DEVELOPER_DIR=/Applications/Xcode-27.0.0-Beta.5.app/Contents/Developer \
  make release-evidence
```

The fixed local output is `dist/remap-0.2.0-source-evidence`. Generation fails
instead of replacing an existing evidence directory. Verify the same archive
and evidence bytes later:

```sh
DEVELOPER_DIR=/Applications/Xcode-27.0.0-Beta.5.app/Contents/Developer \
  make release-evidence-verify
```

On macOS, `make check` also creates and verifies the full evidence set in an
isolated temporary directory after package verification. That gate exercises
the real Syft, SwiftPM, and embedded App inventory path without publishing or
overwriting a persistent evidence directory.

The isolated module remains available for a deliberately different final
artifact set:

```sh
mise install
DEVELOPER_DIR=/Applications/Xcode-27.0.0-Beta.5.app/Contents/Developer \
  mise exec -- uv run python -m tools.remap_release_evidence create \
  --artifact remap-0.2.0.crate=target/package/remap-0.2.0.crate \
  --evidence dist/remap-0.2.0-evidence
```

Verify the same bytes later:

```sh
DEVELOPER_DIR=/Applications/Xcode-27.0.0-Beta.5.app/Contents/Developer \
  mise exec -- uv run python -m tools.remap_release_evidence verify \
  --artifact remap-0.2.0.crate=target/package/remap-0.2.0.crate \
  --evidence dist/remap-0.2.0-evidence
```

The exact selected Xcode build is checked before SwiftPM inventory. Supplying
`DEVELOPER_DIR` does not weaken that check; the version and build must match
`platforms/macos/XCODE_VERSION`.

## Rust-specific generator assessment

[`cargo-auditable` 0.7.5](https://github.com/rust-secure-code/cargo-auditable/releases/tag/v0.7.5)
is suitable future hardening because it embeds the exact Rust dependency graph
in each final executable without timestamps, and Syft can read that section.
It is not added unused: adoption must change every owned Rust release build
invocation together and add a regression that extracts the section from each
binary.

[`cargo-cyclonedx` 0.5.9](https://github.com/CycloneDX/cyclonedx-rust-cargo/releases/tag/cargo-cyclonedx-0.5.9)
is not added. It would create a second Rust-only SBOM authority while leaving
Swift, the embedded App, final artifact observation, and cross-language
composition unresolved.

## Public release order

The local evidence targets never publish, sign, or claim CI identity. A future
public release must preserve this order:

1. Build final source or signed distribution artifacts from a committed
   revision.
2. Run the native linked-SDK, signature-classification, notarization, and
   platform acceptance gates appropriate to those artifact bytes.
3. Generate and verify evidence against the final, immutable artifact paths.
4. Require a clean tree and authenticated successful CI before a public
   release workflow changes `source-install-only` readiness.
5. Sign the checksum, SBOM, and in-toto statement set in the release workflow,
   then verify those signatures independently before upload.

No current command publishes, signs, notarizes, tags, pushes, or changes a
repository setting.
