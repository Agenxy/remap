# ADR-0024: The macOS resolver follows the active network service

## Status

Proposed, 2026-10-15. Not implemented. The owner asked for this on the
`fix/resolver-self-healing` branch; it was stopped at this record because the
change rewrites the privileged SystemConfiguration path and could not be
exercised on a real Mac in that session. The remaining work is listed at the
end so that it can be finished as one change rather than shipped in part.

## Context

Activation records exactly one network service, its prior DNS configuration,
and the configuration Remap installed. `reconciliationPlan` derives upstreams
only for the services in that record, and `dynamicResolverUpstreams` requires
the recorded service's effective entry to exist. Every later network is judged
against the service that happened to be active at activation.

That is correct while the Mac stays on one service, and wrong as soon as it
moves. When Wi-Fi turns off and USB tethering or Ethernet carries the traffic,
the recorded service has no effective entry, reconciliation reports an
unobserved network, and after the ADR-0025 window the supervisor restores
ordinary DNS. Recovery then retries forever and never succeeds, because it is
still waiting for Wi-Fi. When both services are up and the new one sorts first,
the global resolver leaves loopback without any service changing,
`systemDNSNeedsReactivation` asks to recommit the recorded service, and
verification cannot pass because the effective resolver is the other
service's.
Either way Remap stays bypassed until the original service returns.

## Decision

The supervisor follows the single service that currently carries DNS, under
the rules that already govern activation.

- **One scope.** Observation counts the enabled services that expose a usable,
  non-loopback resolver, including the recorded service when its own resolver
  is Remap's loopback but its DHCP or captured provenance still yields one.
  None is an unobserved network (ADR-0025). Exactly one is the target. More
  than one is refused as `unsupportedResolverScope`, a fault that restores
  ordinary DNS at once and records its reason.
- **Capture before change.** Before Remap touches a newly active service, its
  exact prior DNS configuration, enabled state, upstreams, and network
  signature are captured into the integrity-covered activation record, which
  then lists both the retiring and the new service. That record is written and
  synchronized before any SystemConfiguration change.
- **Publish before loopback.** The daemon accepts the complete plan for the new
  service's upstreams before that service points at loopback, as ADR-0006
  requires for every upstream change.
- **Compare-and-restore.** In one authorized preferences session the retiring
  service is restored to its captured prior state only where it still holds
  Remap's installed configuration, the new service receives the installed
  configuration, and the change is committed and verified. A retiring service
  the user has changed is reported as a conflict and never overwritten.
- **Converge the record.** Only after verification does the record shrink to
  the new service and return to the active phase. Because restore already
  skips a service that still holds its prior configuration, the two-service
  record is recoverable at every intermediate point: deactivation restores
  every service Remap changed, and an interrupted handoff is undone by the same
  path as a failed activation.

## Consequences

Tethering, Ethernet, and a return to Wi-Fi re-arm Remap without user action,
and the single-scope refusal keeps split DNS and VPN scopes from being
flattened. The activation record becomes a small state machine across two
services, which is the main cost and the reason this needs its own review.

## Open question

The activation identity is derived from the record's digest, so a record that
names a different service has a different identity, and the daemon refuses it
while it is bound to the previous one. A handoff therefore either invalidates
its own previous binding first, which leaves a short interval with no plan
while the retiring service still points at loopback, or keeps the identity
stable across a handoff by deriving it from a field that survives service
changes. The second avoids the gap but changes what the identity commits to,
and must be decided before implementation.

## Remaining work

1. Observation of usable services as described, as a pure function over the
   SystemConfiguration snapshot so that it can be tested without root.
2. The handoff transaction in `SystemResolver`: capture, record write,
   publication, compare-and-restore, commit, verification, record
   convergence, and failure restoration, with the identity question settled.
3. The reconciler and supervisor driving that transaction instead of reporting
   an unobserved network when exactly one different service is usable.
4. Tests: Wi-Fi to a tethered service, the tethered service back to Wi-Fi, two
   usable services refused, a user change to the retiring service reported as
   a conflict, deactivation after a handoff restoring both services, and an
   interruption at each step converging on recovery.
5. Evidence on a real Mac with the installed privileged supervisor, since none
   of the SystemConfiguration effects can be shown by unit tests alone.
