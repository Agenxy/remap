# ADR-0017: Presence is the invoking user's; a launchd-owned socket is launchd's to listen on

## Status

Accepted for Remap 0.2.x, 2026-09-18. Amends ADR-0014 (lifecycle consent) on
two contracts the native macOS lifecycle relies on.

## Context

Driving `make recover` and `make update` end to end on a Mac that had restarted
since its package install, and whose update had been left in rollback, showed
that the source lifecycle never completed on a real machine:

- `remap-install`, root under `sudo`, evaluated the device-owner
  authentication as root. macOS asked for the password of "System
  Administrator" and never offered Touch ID; no owner could approve.
- A generation using the launchd-owned system socket never started: `remapd`
  compared the address the activated socket remembers with the declared path,
  and launchd reports its own private bind path there, NUL-padded.
- The root resolver supervisor refused that socket: `getpeereid` reports
  whoever called `listen`, and for a launchd-owned socket that is launchd.
- After a restart, launchd loads the plist copy the manifest publishes under
  `/Library/LaunchDaemons`, and every later reconcile called the running job a
  collision.

## Decision

1. **Presence is proved as the invoking user.** A root helper started by
   `sudo` (`SUDO_UID` set by sudo itself, after its environment reset) puts
   the device-owner authentication to that user by running its own executable
   as that user for the `presence` command alone, which does nothing but ask.
   The executable is the published bootstrap helper: root-owned, code-verified
   before publication, so the user it runs as cannot have altered it. Only a
   child this process started and awaited, ending of its own accord with
   status zero within five minutes, counts as approval. A refusal names why
   the dialog ended. Without `SUDO_UID`, or not as root, the process asks as
   itself, as before.
2. **A launchd-owned system socket is launchd's to listen on.** The client
   accepts a listener credential of the daemon's user or of root: a
   root-listened socket at a root-only path in `/var/run` is launchd's by
   construction, and nobody but root can listen as root. `remapd` accepts the
   activated descriptor when its remembered address is the declared path or
   the declared socket key under launchd's private directory with a socket at
   the declared path; the descriptor's provenance is `launch_activate_socket`,
   and this is a consistency check of the contract, not a proof of identity.
3. **A generation image carries its socket contract**, and activation dials
   the socket that contract names, so an installed generation with the
   data-directory socket is reached where its resolver listens.
4. **A job loaded from the published plist is the generation's service**
   when its program is the generation's and the published bytes are the
   generation's plist, byte for byte. Otherwise it is a collision, as before.

## Consequences

- The threat model is unchanged: an attacker with root, or with a sudo ticket
  that runs arbitrary commands, is outside it; a user without root cannot forge
  the child's exit status, replace the root-owned helper, listen as root, or
  write under `/Library/LaunchDaemons`.
- Readiness is given five minutes: macOS assesses a newly signed daemon before
  it starts. The orchestrator waits for the helper's own bounded work.
- Not decided here: the source installation ships no `remap-lifecycle`
  client, so `remap system` says so and points at the repository's targets. A
  source install that carries the lifecycle client and its launchd service is
  a separate decision.
