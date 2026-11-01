# ADR-0030: The DNS path runs Interactive, and a fallback returns only after sustained health

## Status

Accepted, 2026-10-27. It amends ADR-0025 on how soon the macOS resolver
supervisor re-arms Remap after a fallback, and ADR-0014 on which launchd
scheduling class an installed generation may declare.

## Context

On 27 October the owner's Mac ran Remap 0.2.0 (generation 3788724…) under a
load average of 114 to 130 from parallel builds. Remap DNS had worked at
08:18, before the load started. Under the load:

- The root supervisor's exchange with `remapd` over the system socket
  (`ResolverChannel.swift`, a 250 ms deadline) failed again and again with a
  transport error, reported as `E_RESOLVER_CHANNEL`.
- Each failure restored ordinary DNS at once, as ADR-0025 requires. The
  supervisor then retried every 250 ms and re-armed on the first exchange that
  succeeded, about 0.3 to 2 seconds later. The next failure came 5 to 15
  seconds after that. The unified log shows the cycle every 10 to 20 seconds
  for many minutes.
- While Remap DNS was armed, `dig @127.0.0.1` timed out even for mapped names.
  The Mac's resolver kept flipping between Remap and the ordinary resolvers.

Both installed launchd jobs, `org.agenxy.Remap.daemon` (`remapd`: DNS on
127.0.0.1:53, the HTTP gateway, and the system socket) and
`org.agenxy.Remap.resolver` (the root supervisor), declare
`ProcessType = Background`; launchd reports `spawn type = background (5)`.
launchd gives Background jobs the resource policy meant for work nobody is
waiting on, and under contention that is the work that waits. macOS's own
resolver, `com.apple.mDNSResponder`, declares `POSIXSpawnType = Interactive`.

Two defects compounded. The processes every name lookup waits on were in the
band that yields first. And one successful exchange was taken as recovery, so
a channel that answered intermittently turned into DNS that changed every few
seconds, which is worse for the owner than either state held steadily.

## Decision

### The daemon and the supervisor are Interactive

Every generator of the daemon and resolver launchd definitions writes
`ProcessType = Interactive`: `MacOSPortableLaunchd.swift`,
`tools/remap_native_package.py`, and the older single-job model in
`tools/remap_native_model.py`. The lifecycle service was already Interactive.

`Interactive` is the class the system resolver itself uses, and Remap's daemon
answers the same lookups from the same position in the path. `Adaptive` was
not chosen: it follows XPC activity, and `remapd` serves DNS over UDP and TCP
sockets, not XPC, so it would stay in the Background band. `Standard`, what
an absent key means, was not chosen either: the measured precedent is
Interactive, and Remap has no evidence for a weaker class on this path.

The class changes scheduling and resource policy only. The daemon still runs
as the selected user after launchd binds its sockets, and nothing gains
privilege.

### New definitions must be Interactive; installed ones may still be Background

`MacOSLaunchdPropertyList.validate` is applied both to new packages and to
generations that are already installed. Package inputs reach it through
`validateSource` and `validateProductionSource`; installed, manifest-owned
generations reach it through `MacOSGenerationImageStore.load`, which status,
reconciliation, update, rollback, and recovery all use, including for the
previous generation an update rolls back to. Every generation on owners' Macs
today declares Background, and its bytes are fixed by its manifest.

So the validator takes a scheduling admission beside the existing socket
contract, following the same rule ADR-0014 set for the legacy socket:

- `generated`, for every package input: exactly `Interactive`.
- `installed`, only for an already-installed, manifest-owned generation:
  `Interactive`, or `Background` as the legacy value.

No other value is accepted under either admission, including `Standard`,
`Adaptive`, a missing key, or a different spelling. A source package that
declares Background is refused, so no new generation can reintroduce it, and
an installed Background generation keeps loading until it is replaced.

### Linux has no equivalent setting

The systemd units `remapd.service` and the resolver supervisor set no
`Nice=`, `CPUSchedulingPolicy=`, `IOSchedulingClass=`, `CPUWeight=`, or
`IOWeight=`, so they run at systemd's defaults like any ordinary service.
Nothing there lowers their priority, and nothing changes.

### A fallback returns only after sustained health

A channel failure, a daemon refusal, or a conflict still restores ordinary DNS
at once, and an unobserved network is still held for up to 20 awake seconds
(ADR-0025). What changes is how eagerly the supervisor comes back.

While bypassed, the supervisor probes the daemon every 250 ms with a health
exchange that publishes nothing, invalidates nothing, and leaves
SystemConfiguration alone. It re-arms only after the daemon has answered every
probe for the required period of awake time, measured on the suspending clock
like the grace window. It then reconciles as before, publishing and verifying
a complete generation before the prepared activation is committed. A failed
probe, or a reconciliation that fails at the end of the period, starts the
period again; neither counts as a further bypass.

The required period starts at 5 seconds. A bypass that follows a re-arm by
less than 5 minutes of awake time doubles it, up to a cap of 5 minutes. Once
Remap has stayed armed for 5 minutes, the next bypass starts again at 5
seconds. A bypass that could not restore ordinary DNS is retried as the same
fault and does not double the period. Under the measured cycle, a fault 5 to
15 seconds after each re-arm, Remap waits 5, 10, 20, 40, 80, 160, then 300
seconds, so after about seven minutes of an unhealthy channel the Mac changes
resolvers at most once every five minutes, and stays on ordinary DNS, which
keeps public names working (ADR-0006), in between.

### The bypass record says how long the next re-arm waits

`resolver-bypass-v1.json` gains one optional field,
`rearmAfterHealthyMilliseconds`, written with every bypass and kept when the
bypass is re-armed. `remap-system status` adds a line while a fallback is in
effect, `Next try    after 20 seconds of continuous daemon health`, and its
JSON carries the field inside `lastResolverBypass`. The supervisor also logs
the period with each bypass. It is a duration, not a time: when the next try
happens depends on when the daemon starts answering steadily.

A record written by an earlier build has no field, decodes, and verifies
exactly as before. An earlier build cannot verify a record that has the field
and reports it as unreadable until its own next bypass replaces it. Only a
rollback produces that combination, and a rollback restarts `remapd` from the
previous generation, so the one fact a lost record could matter for, an
unreleased daemon binding, is gone with the old process.

The damping memory itself lives in the running supervisor. A restarted
supervisor starts at 5 seconds, and its first reconciliation re-arms as it did
before this change.

## Consequences

On an owner's Mac the scheduling class changes only when a generation built
from this change is installed; the installed 0.2.0 generation stays Background
until it is updated. The damping arrives with the same update.

After any fault Remap now stays on ordinary DNS for at least 5 seconds of
steady daemon health, where it used to return within a probe interval. That
also applies when a fault was not the channel, such as a second network
service with DNS: the supervisor reconciles once per period rather than every
250 ms, and re-arms within one period of the conflict ending. The channel's
250 ms deadline is unchanged.

Acceptance: the Swift tests in `MacOSLaunchdSchedulingClassTests.swift` check
that both generated definitions are Interactive and pass the validator, that
a new generation is refused anything but Interactive, and that an installed
one accepts only Interactive and Background. `tests/python/test_native_package.py`
checks the Python generators, the assembled package's published plists, and
the older model. `ResolverRearmDampingTests.swift` drives the supervisor on a
stepped clock: one successful exchange after a channel bypass does not re-arm,
a sustained healthy period does, repeated bypasses double the period to the
cap, and a five-minute armed run resets it. Each of the tests named so far
failed against the behaviour before this change. The same file also checks
the backoff's arithmetic directly, that status names the period, and that a
bypass record written before the field existed still verifies.
