# ADR-0018: Publication verifies completeness; teardown preserves owner decisions

## Status

Accepted for the source changes on 2026-09-22. Privileged machine acceptance is pending.
Extends ADR-0017 and implements the Agenxy installation discipline.

## Context

The September 18 source generation contains every executable it declares, but does not
declare the prebuilt distribution's `libexec/remap-lifecycle`. Its older CLI reports a
missing file and suggests a recovery command that needs that same file. Commit
`7218c4d` names the source lifecycle but retains the generic circular recovery hint and
infers source provenance solely from absence.

Daemon and resolver reconciliation already waits for asynchronous launchd teardown.
The separate lifecycle-service adapter returned directly from bootout. Reconciliation
also enabled the daemon and resolver implicitly, overriding persistent owner state.

## Decision

- Keep the source and prebuilt payload contracts unchanged. Absence alone cannot prove
  installation provenance. The CLI names the missing component, explains both
  distributions, and provides an external, owner-approved remedy for each.
- Reverify the complete generation at `GenerationStore.publish`, including manifest
  bytes, payload bytes, modes, ownership and directory membership. The transaction's
  earlier staging verification remains in force. Neither check replaces the other.
- Python executable staging opens destinations exclusively. Existing files and symlinks
  are collisions, including inside a directory a caller believes is fresh.
- The native launchctl adapter's bootout returns only after the exact job disappears.
  It receives the caller's admitted plist/program identity and rechecks it before
  issuing bootout, rather than adopting whichever job it finds at the label.
  Each launchctl call remains bounded to five seconds; the post-bootout polling deadline
  is five seconds, with at most one in-flight bounded observation beyond that deadline.
  A different program or plist at the label is a collision. These observations do not
  make launchctl's label-based operations atomic against an external privileged actor.
  The portable lifecycle
  service delegates teardown to this same adapter.
- Remove implicit `launchctl enable` from reconciliation and from the typed command
  interface. Installation approval does not authorize changing an owner's persistent
  disabled state. Failed startup follows the existing rollback/recovery transaction.
- A plist naming a program outside its exact generation is refused with the offending
  path and admitted destination. Fixed production roots remain non-configurable.

## Consequences

No wire format, entitlement, approval token or privilege scope changes. An owner-disabled
job remains disabled. Status still needs a versioned extension to report that state and
the manager PID separately from the authenticated socket responder; this change does
not claim that observability work is complete.

The diagnostic does not repair an existing installation. Deploying these changes or
switching a source installation to the prebuilt lifecycle remains a separately approved
owner action. Synthetic process-runner and isolated filesystem tests exercise these
contracts without pretending to perform privileged installation.

The shared specification now records immutable generations, exact teardown identity,
ownership-preserving publication, revalidated approval and distribution-specific
lifecycle contracts. The Compass and Supgang copies need the same amendment.
