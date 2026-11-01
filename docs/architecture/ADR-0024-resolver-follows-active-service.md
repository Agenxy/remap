# ADR-0024: The macOS resolver follows the active network service

## Status

Accepted pending owner review, 2026-10-15. Proposed earlier the same day and
implemented on `fix/resolver-self-healing` at the owner's request. The
SystemConfiguration effects are proven against a model in the Swift tests,
not yet on a Mac with the installed privileged supervisor.

Amended 2026-10-31 by ADR-0036: several services with DNS are refused as
split DNS only when the global resolver does not say which one macOS uses,
and another agent's DNS ahead of Remap's is deferred to without any write.

## Context

Activation records exactly one network service, its prior DNS configuration,
and the configuration Remap installed. Reconciliation derived upstreams only
for the services in that record, and required the recorded service's
effective DNS entry to exist. Every later network was judged against the
service that happened to be active at activation.

That is correct while the Mac stays on one service, and wrong as soon as it
moves. When Wi-Fi turns off and USB tethering or Ethernet carries the traffic,
the recorded service has no effective entry, reconciliation reports an
unobserved network, and after the ADR-0025 window the supervisor restores
ordinary DNS. Recovery then retries forever and never succeeds, because it is
still waiting for Wi-Fi.

The activation identity was also derived from the record's digest. A record
that named a different service would therefore have been a different
activation, which the daemon refuses while it is bound to the previous one,
and which `activationMismatch` would report as another controller.

## Decision

### Identity is fixed at the first handoff and is not the digest after it

The integrity-covered payload gains an optional `activationID`. When present
it is the activation's identity whatever its phase or services, so a handoff
is the same activation with a new service set, and `activationMismatch` keeps
meaning a different controller. The SHA-256 digest remains integrity only.

A record that has never moved omits the field, so its canonical encoding and
digest are exactly what older builds produce and verify, and its identity is
still the one derived from that digest. The first handoff writes the derived
identity into `activationID`; every later record carries it, so the daemon's
binding is unchanged across every move.

A new activation deliberately does not choose a random identity, although that
was the first design. An update that fails after re-enabling DNS rolls back by
re-activating with the running, newer installer and then handing the record to
the previous generation's supervisor. A record that older supervisor cannot
verify would leave it unable to reconcile or restore DNS. Deferring the field
to the first handoff keeps every record that has not moved readable by older
builds.

### The supervisor follows one usable service

On every reconciliation the root supervisor counts the enabled services that
expose a usable, non-loopback resolver. A recorded service counts when its own
resolver is Remap's loopback but its DHCP lease or matching captured network
provenance still yields one, exactly as reconciliation already derived it.

- None is an unobserved network (ADR-0025).
- More than one is refused as `unsupportedResolverScope`, the single-scope
  rule activation already applies. It is a fault, so ordinary DNS is restored
  at once and the reason recorded.
- The recorded service alone is reconciled as before.
- Exactly one other service is the target of a handoff.

Only the root supervisor hands off. `remap-system activate` captures the
current service itself and never changes a service after activation.

### A handoff is a sequence of durable, repeatable steps

1. Every service the record owns other than the target must hold either
   Remap's installed configuration or its captured prior configuration. A
   user change, or an owned service that can no longer be seen, is reported
   as `configurationConflict` before anything changes, and nothing is
   overwritten.
2. The target's exact current DNS configuration and enabled state are
   captured, unless it already holds Remap's configuration, whose captured
   prior state is then kept. A configuration that already points at loopback
   is refused rather than recorded as a prior state. The record is rewritten,
   still active, listing the service being left and the target, with a
   `handoffTargetServiceID` marker.
3. The daemon accepts the target's complete plan under the same activation.
   An orphan from ADR-0025 is released only at this point.
4. The owner must be the console user and the loopback listener must answer.
5. In one authorized preferences session, every expected configuration is
   compared again, the service being left returns to its captured prior state
   where it still holds Remap's configuration, the target receives Remap's
   configuration, and the change is committed once.
6. The global resolver must be loopback, the target must hold Remap's
   configuration, and every service being left must no longer hold it.
7. The record converges to the target alone and the marker is removed.

Each step can be repeated, so an interruption anywhere is finished by the
next reconciliation. Before step 5 commits, only the service being left can
point at loopback, and the daemon holds a plan for it or already for the
target; after it, only the target can, and its plan was published first. No
service ever points at loopback without a published plan, and the record
lists every service that may hold Remap's configuration.

### Restoration covers every owned service

Deactivation and safe bypass use the same compare-and-restore over every
service the record owns, which during an interrupted handoff can be two. A
service still holding Remap's configuration returns to its captured prior
state; a service at its prior state is left alone; any other state is a
conflict and nothing is restored. Verification expects the global resolver to
match the prior configuration only of services that are connected, since a
disconnected service cannot contribute to it. With no service connected at
all, macOS publishes no global resolver, so an empty one is the restored
state; the per-service comparison is then the whole proof (amended
2026-10-27, `ResolverOfflineRestoreTests.swift`).

## Consequences

Tethering, Ethernet, and a return to Wi-Fi re-arm Remap without user action,
and the activation keeps its identity, generation history, and daemon binding
across the move.

The single-scope rule now holds during supervision as well as at activation.
A second service with DNS appearing while Remap is active, such as Ethernet
plugged in beside Wi-Fi, a tethered phone beside Wi-Fi, or a VPN that installs
its own resolver, restores ordinary DNS promptly with the reason
`E_RESOLVER_PLAN`, and Remap re-arms when one service remains. Before, the
second service was ignored, and Remap kept working only while macOS happened
to prefer the recorded service.

A record that has been handed off carries fields an older build does not
decode into its digest, so an older build reading it fails closed with an
integrity error rather than changing DNS. The installer's own update and
rollback deactivate with the running installer first, so they are unaffected;
installing an older build by hand over a handed-off activation requires
deactivating first.

Acceptance: `ResolverHandoffTests.swift` drives the reconciler against a
model of SystemConfiguration that persists and applies DNS protocols per
service, derives effective and global resolvers from connection state and
DHCP, and enforces compare-and-set: Wi-Fi to a tethered service, the tethered
service back to Wi-Fi, two usable services refused and then bypassed, a user
change to the service being left reported and not overwritten, deactivation
after and during a handoff restoring both services, an interruption at each
of seven steps leaving one armed service with its plan published and
completing on the next reconciliation, and an older record keeping its
derived identity across a handoff.
