# ADR-0012: macOS install failures roll back before returning

- Status: Accepted
- Date: 2026-08-21

## Context

The macOS installer already recorded every privileged install and update phase
in a durable journal. An interrupted process could use that journal to restore
the exact prior generation, publications, and DNS state. A normal error from a
pre-commit system effect, however, returned to Installer with the transaction
still awaiting crash recovery. That left a failed update's launchd definitions
pointing at the rejected generation until another approved installer operation
explicitly recovered it.

Installer failure is an observed transaction outcome, not a process crash. A
failed package must leave ordinary networking safe and must also restore the
previous working Remap generation before Installer reports the failure.

## Decision

The native install coordinator now treats every error after the initial durable
`prepared` record and before the durable `committed` record as an immediate
rollback boundary.

- A failure while only `prepared` disposes the candidate generation.
- A later update failure first restores ordinary DNS, then restores and
  authenticates the exact previous service generation, reactivates that
  generation's DNS ownership, verifies stable effective system DNS, and
  disposes the candidate generation.
- Failed fresh installs and uninstall continue to restore ordinary DNS because
  they have no previous owned generation to reactivate.
- A successful rollback is durably completed and its terminal journal is
  collected before the original install error is returned.
- If immediate rollback also fails, the coordinator returns a combined error
  and retains the nonterminal journal so authenticated crash recovery can
  resume idempotently.
- Failures after the durable `committed` record do not roll back a committed
  update; existing purge recovery resumes those cleanup phases.

The system-effect adapter remains the macOS privilege boundary. The portable
transaction coordinator chooses recovery state but does not call launchd or
SystemConfiguration APIs directly.

## Consequences

Installer can still report a package failure, but a successfully recovered
failure returns with the prior Remap service and its prior DNS ownership
restored. Durable crash recovery remains necessary for process termination and
for failures inside the immediate rollback itself. Fault-injection tests cover
every pre-commit effect boundary and the combined-failure recovery path, while
live package acceptance must verify both system DNS and the restored prior
generation.
