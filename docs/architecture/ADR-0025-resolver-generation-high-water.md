# ADR-0025: A resolver fallback re-arms without restarting the daemon

## Status

Accepted, 2026-10-15. It amends the `remap.system/v1` result (ADR-0006,
ADR-0007) with one optional field and records how the macOS resolver
supervisor holds, releases, and records a fallback.

## Context

On 13 October the root resolver supervisor on the owner's Mac restored
ordinary DNS and never put Remap back. Nothing in the unified log said why.
Reading the code found three causes, each enough on its own.

The daemon's plan store refuses every generation at or below the highest it
has ever accepted, and invalidation does not lower that mark. Health reported
only the active generation, which is absent after invalidation. A
reconciler that starts without memory, such as the one `remap-system activate`
builds or a restarted supervisor, therefore proposed generation one, and the
daemon answered `E_RESOLVER_PLAN` until `remapd` itself restarted.

`enterSafeBypass` restored ordinary DNS and then released the daemon's plan
with `try?`. When the health or invalidation exchange failed, nothing was
released and nothing was remembered. The daemon stayed bound to the old
activation, and once the activation record changed, every later
reconciliation stopped at `activationMismatch`. That check is correct: it is
what keeps two controllers from fighting over one daemon. The supervisor had
simply lost track of a binding it had created itself.

The supervisor bypassed after one failed reconciliation. ADR-0006 already
says that "a transient incomplete network observation preserves the last
complete generation", but a Wi-Fi association after sleep or a DHCP renewal
produced exactly one such observation and was treated as a sustained failure.

## Decision

### The daemon reports its high-water

`SystemResult` gains `highest_accepted_generation`, the highest generation
the daemon has accepted since it started. The daemon sends it only when it
exceeds `active_generation`, which in practice means after invalidation, so
steady-state responses stay byte-identical to the original contract. A
supervisor publishes above the greatest of the active generation, this
high-water, and every generation it has itself seen.

Compatibility runs both ways. A current supervisor talking to an older daemon
decodes the missing field as absent and falls back to its own memory, which
is today's behaviour; only a supervisor that starts without memory still needs
that older daemon restarted. An older Swift supervisor ignores the unknown key,
because `JSONDecoder` does. The Rust decoder (`serde(default)`) accepts a
missing field. An older Rust Linux helper rejects unknown fields, so it would
refuse a result carrying the high-water; that combination is not produced,
because the Linux lifecycle replaces and restarts the daemon and resolver
units together, and the field is absent in every steady-state response.

### A bypass remembers the binding it failed to release

`enterSafeBypass` throws only when ordinary DNS could not be restored. If the
daemon's plan then cannot be released, it returns `pending` with the activation
the daemon may still hold, and the reconciler remembers that identity. On a
later mismatch the reconciler invalidates the bound plan only when the bound
identity is exactly that orphan, then publishes the current activation. Any
other bound activation is still `activationMismatch`. The orphan is also
written to the durable bypass record, so a restarted supervisor or a separate
`remap-system activate` can release it; a record that has since been re-armed
names no orphan.

### Only an unobserved network is held

A reconciliation that fails because the recorded service exposes no usable
resolver (`noUsableUpstream` or `noEnabledDNSService`, reported as
`E_RESOLVER_NETWORK_UNOBSERVED`) leaves the daemon's last complete plan in
place. The supervisor re-observes every 250 ms for up to 20 seconds of awake
time, measured on the suspending clock so that hours of sleep never exhaust
the window, and ordinary DNS is restored only if the network is still
unobserved when the window ends. Nothing has been refused in that state: the
daemon holds a complete plan, and the question is only whether the network
has come back yet.

Every other failure is a fault and restores ordinary DNS at once: a channel
that cannot reach the daemon, a daemon refusal (its own stable code is
reported, such as `E_RESOLVER_ACTIVATION` or `E_RESOLVER_PLAN`), an activation
mismatch, a configuration conflict, or a damaged activation record. A failed
bypass keeps the expired window, so the next failed reconciliation retries
the bypass without waiting again.

### Every fallback leaves durable evidence

The supervisor writes `resolver-bypass-v1.json` beside the activation record:
a root-owned 0600 regular file, replaced by exclusive temporary file and
atomic rename, covered by a SHA-256 digest of its canonical payload, and
refused if it is a symlink, has other permissions, or sits in a writable
directory. It holds the reason code, the outcome, the start of the failure
window, the bypass time, whether the release is pending and for which
activation, and when a later generation re-armed Remap. It holds no name,
address, or traffic. `remap-system status` shows it, and its JSON adds a
`lastResolverBypass` key beside the unchanged activation keys. The supervisor
also logs each bypass and re-arm to the unified log. Writing the record never
changes resolver behaviour; a write that fails is logged.

## Consequences

A fallback is followed by a re-arm as soon as a complete generation can be
published, whether the supervisor, a restarted supervisor, or an activation
performs it, and none of them needs `remapd` restarted. The cost is one
optional wire field and one more root-owned file.

A network that is genuinely gone for more than 20 awake seconds still falls
back to ordinary DNS, which ADR-0006 requires. A move to a different network
service, such as USB tethering after Wi-Fi turns off, is not an unobserved
network: ADR-0024 hands the activation over to the one service that now
carries DNS.

The durable record keeps only the last bypass. It is evidence for diagnosis,
not a history.

Acceptance: `crates/remap-network/src/resolver.rs`,
`crates/remap-protocol/src/system.rs`, and `crates/remapd/src/system_control.rs`
test the high-water through invalidation and on the wire. The Swift tests in
`ResolverSelfHealingTests.swift` fail against the sources before this change
and pass after it: release of an orphan after a bypass that could not reach
the daemon or whose invalidation failed, publication above the high-water by a
fresh reconciler, and an unobserved network shorter than the default window.
`ResolverRecoveryTests.swift` covers the window expiring, a daemon refusal
bypassing at once under a one-hour window, the pending release and its
durable record, the store's integrity and permission checks, and the status
output.

## Amendment, 2026-10-27: a prepared record never covers loopback

Re-arming after a bypass, like activation, commits a prepared record: it
points the recorded services at loopback, verifies the result, and rewrites
the record active. The record was rewritten only after verification, and a
failure restored the services with `try?`. A restore that failed was
discarded and the record stayed prepared over a service that still pointed
at loopback. Deactivation removes a prepared record without restoring
anything, because prepared means ordinary DNS, so that service was left on
Remap with no record of what to restore.

The record is now rewritten active before any service is pointed at
loopback, the order an ADR-0024 handoff already uses, so it lists every
service that may hold Remap's configuration whenever one can. The format and
the activation identity are unchanged: `activationIdentifier()` binds both
phases to the same identity. A failed commit is restored by the same
compare-and-restore deactivation uses, and the record returns to prepared
only when no owned service can still hold Remap's configuration, because the
commit never reached one or the restore has been verified. When the restore
fails, its error is thrown and the record stays active, which deactivation,
safe bypass, and reconciliation all restore. A crash between the write and
the commit leaves an active record over prior configurations: deactivation
and safe bypass find nothing to restore, and the supervisor's reconciliation
sees Remap is not the effective resolver and commits again.

This keeps the integrity-covered record a description of what may be
installed rather than of what was intended, which is the property
ADR-0006's compare-and-restore depends on. Rolling the record back to
prepared after a failed restore instead would hide the installed
configuration from deactivation, which is the defect itself.

Acceptance: `ResolverCommitRollbackTests.swift` fails against the sources
before this amendment and passes after it: a restore that fails after a
failed commit is reported and leaves the record active, deactivation then
restores the service, and the record is active before any commit is made.

## Amendment, 2026-10-31: a commit another agent's DNS outranks is kept

ADR-0036 keeps one failed verification active instead of restoring it: when
every owned service holds Remap's configuration and another agent's resolver,
for one of those services or for a service outside the preferences, is the
one macOS uses anyway. The record still lists every service that may hold
Remap's configuration, which is the property this amendment protects, and a
restore would be a write against that agent at every re-arm. Every other
failed commit restores exactly as above.
