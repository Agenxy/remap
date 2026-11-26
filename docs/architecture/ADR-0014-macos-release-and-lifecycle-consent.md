# ADR-0014: macOS package execution, lifecycle consent, and uninstall trust cleanup

## Status

Accepted for Remap 0.2.0. This supersedes the uninstall-identity retention and
text-token consent portions of ADR-0006 and ADR-0009.

## Context

The 0.2.0 security review found four connected privileged-boundary failures.
The detached Ed25519 signature authenticated a downloaded package pathname,
but Apple Installer later reopened that mutable pathname and executed package
scripts as root. The installed, correctly signed lifecycle CLI accepted a
deterministic preview token from its own caller, so a same-UID process could use
the trusted CLI as a deputy. The macOS manifest validator required known
publications but did not reject surplus system-root publications on every
recovery path. Finally, uninstall left the machine-local code-signing private
key and administrator trust root behind.

These are release trust, privilege, recovery, and cleanup-contract changes.

## Decision

### Apple Installer authenticates the complete XAR

The canonical unsigned package is fully expanded and inspected first. Remap
then signs the complete XAR, including `PackageInfo`, `Scripts`, and payload,
with the dedicated self-signed `Remap Release Installer` identity. The builder
requires the exact committed certificate fingerprint and disables network
timestamping. The detached Ed25519 signature is applied only to those final
signed bytes. No later step mutates the XAR.

The Installer certificate is separate from the Ed25519 publisher key, the
target Mac's `Remap Local Installer` bootstrap identity, and `Remap Local
Codesign`. It is not Developer ID and provides no Apple review or notarization.
The supported install workflow copies the verified download into a new
root-owned directory, re-verifies the detached signature against that exact
copy, and invokes Apple Installer only on that immutable pathname.

Each native package script also requires its exact script name, package
identifier, system-root destination, bounded arguments, and a lexically
canonical absolute package path. Lexical normalization is intentional:
Foundation's `standardizedFileURL` rewrites an existing `/private/var/tmp` or
`/private/tmp` path through macOS's `/var` or `/tmp` aliases. Treating that
filesystem alias as lexical traversal rejects Apple's own root-owned staging
path. Dot components, duplicate separators, relative paths, and embedded nulls
remain invalid.

Package preparation also distinguishes active resolver ownership from a
prepared safe-bypass record. An active record remains the authority for
network reconciliation. A prepared record means macOS is already using its
ordinary resolver, so an update captures the live effective service instead.
This permits recovery after macOS replaces a service identifier during a
network transition without reviving DNS data bound to the departed service.

An update may also need to inspect or restore an immutable generation produced
before the launchd-owned system socket became mandatory. The loader accepts the
complete earlier daemon-and-resolver socket contract only for an already
installed, manifest-owned generation. Portable and source package inputs never
receive that compatibility allowance and must use the hardened system socket.

### A state token is freshness evidence, not consent

The signed lifecycle CLI still obtains and internally carries the exact
state-bound token so the root service can revalidate the operation while
holding its lock. It no longer reads token text or an approval phrase.
Mutating recovery and uninstall require an interactive terminal and macOS
device-owner authentication through LocalAuthentication after the preview is
rendered. Authentication failure, cancellation, or unavailability sends no
mutation. Each distinct recovery mutation requires a separate authentication.
Read-only status and no-op recovery remain noninteractive.

The source-build root helper retains the token argument as freshness evidence
for its split preview and mutation calls. It recomputes that preview first, then
requires device-owner authentication inside the privileged executable before
every install, update, uninstall, or recovery effect. A disclosed token, direct
root invocation, or cached sudo session therefore cannot authorize a mutation.
The Python orchestrator acquires root access once for inspection and does not
force a second sudo prompt after preview; the root helper owns fresh consent.

Apple Installer's administrator authorization remains the separate consent
boundary for its package bootstrap. Linux retains its own explicit preview
token workflow and is not coupled to LocalAuthentication.

### Publication manifests are exact at every mutation boundary

The product validator reconstructs the complete canonical publication array
from the immutable generation entries and requires array equality. Production
injects that validator into both transaction coordination and crash recovery.
The publication reconciler revalidates current and previous manifests before
install, removal, ownership checks, or rollback restoration. Surplus paths,
wrong kinds, targets, sources, digests, ownership, or modes fail before a
system-root publication is touched.

### Uninstall removes the exact local code-signing authority

The portable uninstall state now binds the SHA-256 fingerprint from the
root-owned lifecycle configuration. Its preview explicitly includes removal of
the matching `Remap Local Codesign` private key, certificate, and administrator
trust. Native Security APIs classify the exact label and fingerprint, preserve
foreign or ambiguous items, independently enumerate administrator-domain trust,
remove trust and identity idempotently, and verify absence. Certificate and
identity queries are restricted to `/Library/Keychains/System.keychain`.

Security provides no nondeprecated API that creates the `SecKeychain` reference
required by `kSecMatchSearchList` for a legacy file keychain. Remap therefore
uses one narrowly declared Swift ABI binding to the public `SecKeychainOpen`
symbol. Its signature exactly matches the framework declaration; the returned
Core Foundation object remains ARC-managed; the path is a fixed product
constant; and the reference is used only as a read/delete query scope. This
exception ends when Apple provides a supported replacement or Remap moves the
local identity out of the legacy System keychain.

The cleanup plan and signed helper remain until keychain absence is verified.
The helper is booted out before key removal but its file and canonical plan are
retained, so a failure or crash can be retried. The already signed helper embeds
its certificate chain; its static code identity does not depend on the deleted
private key. Only after trust cleanup succeeds are the helper, plan, package
receipt, and empty installer directories removed. The private mapping database
is outside this cleanup and remains untouched.

## Consequences

Release packaging now requires custody of two distinct publisher authorities:
the existing Ed25519 key and the nonextractable self-signed Installer identity.
Reproducibility must be demonstrated on final signed XAR bytes rather than
assumed from the unsigned package. Distribution verification must check both
the exact Installer certificate fingerprint and the detached Ed25519 signature.

macOS lifecycle automation can inspect status and previews but cannot perform a
mutation, including direct root-helper invocation, without visible OS
authentication. Reinstall after a complete
uninstall creates a fresh machine-local code-signing identity. Updates reuse the
existing identity. Acceptance must prove malicious XAR mutation invalidates the
Installer signature, denial sends no lifecycle mutation, crash recovery rejects
surplus publications before effects, uninstall removes exact keychain trust,
and mappings remain byte-identical.
