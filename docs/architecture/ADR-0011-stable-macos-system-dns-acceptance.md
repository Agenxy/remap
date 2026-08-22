# ADR-0011: Require stable macOS system DNS at package acceptance

Status: accepted for implementation, August 2026.

## Context

Remap's authenticated health protocol proves that the intended daemon owns the
control, UDP DNS, TCP DNS, and HTTP listeners. It deliberately does not prove
that macOS is directing system DNS through those listeners.

SystemConfiguration preferences and the effective dynamic-store view settle
independently. A package installation observed the authenticated runtime ready
while one immediate effective-resolver observation still reported ordinary
router DNS. macOS applied the intended loopback resolver moments later, after
the package had already failed safely. Treating listener health as acceptance
would have hidden the opposite and more dangerous failure mode.

## Decision

The final macOS installation-acceptance step retains the authenticated runtime
gate and separately polls the native effective resolver observation for up to
15 seconds. Acceptance requires two consecutive observations, 250 milliseconds
apart, that all active configured service identifiers exactly match the active
Remap record, owner, and product generation. Any mismatch resets the consecutive
count. Observation errors remain immediate failures.

The earlier transactional activation checks remain unchanged. This final wait
exists only at the package commit boundary, where macOS may still be converging
after the listeners have become ready.

## Consequences

- A healthy loopback listener cannot make an installation ready while macOS is
  using an ordinary router, a partial service set, or a different generation.
- A transient macOS propagation delay no longer rejects an otherwise correct
  installation.
- Persistent resolver drift still fails closed within a bounded time and leaves
  the install transaction available for authenticated recovery.
- Platform acceptance must exercise a clean install and inspect the system
  resolver, UDP and TCP DNS, public forwarding, and mapped routing separately.
