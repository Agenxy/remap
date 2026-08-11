# ADR-0003: Authority and process boundaries

Status: accepted at architecture level; platform transports require prototypes.

## Context

Remap combines a privileged system service, a DNS interception component,
user-facing clients, and eventually mutually authenticated peers. Multiple
writers or policy implementations would make authorization and recovery
ambiguous.

## Decision

- `remapd` is the sole writer for registry, route, peer, and CA state.
- Apps and CLIs submit authenticated commands; they do not edit databases or
  snapshots directly.
- DNS components consume immutable snapshots and cannot write authority state.
- Peer replication submits signed operations to the daemon.
- Conflicting operations on the same mapping are recorded and surfaced.
- The gateway reads the same registry revision identified by DNS snapshots.
- macOS uses XPC where it materially supplies the correct native identity or
  lifecycle boundary. Portable control messages remain transport-independent.
- Linux uses a permissioned Unix-domain control socket with peer credentials.

## Consequences

The M0 CLI offers offline validation only. A fake `remap set` that edits a JSON
file would establish the wrong ownership and concurrency contract, so mutation
commands wait for the daemon milestone.

The exact macOS daemon hosting choice—Rust executable with a native adapter or a
Swift host embedding the Rust engine—must be decided by an entitlement-bearing
prototype measuring XPC authentication, extension snapshot delivery, crash
isolation, update behavior, and FFI lifecycle. It is not decided by aesthetic
language purity.
