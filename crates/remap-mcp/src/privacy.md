# Privacy

Remap is designed for local control and minimal knowledge.

## Baseline

- No analytics, advertising identifiers, crash-upload service, or usage
  telemetry.
- No central account, activation, entitlement, or license server.
- No request or response bodies in logs.
- No mapped hostnames, upstream addresses, peer addresses, certificate names,
  or traffic metadata in routine logs.
- No secret keys, credentials, tokens, cookies, authorization headers, or
  private configuration in logs or diagnostic bundles.
- No network communication except traffic required by mappings, user-configured
  DNS forwarding, explicit peer synchronization, and an explicit update check
  if that feature is later accepted.

## Diagnostics

Diagnostics are local and inspectable before export. They use counts, states,
versions, opaque correlation identifiers, and redacted error categories where
possible. A future support bundle must show its complete manifest before it is
written and must never upload itself.

Debug logging is not permission to record user traffic. Any exceptional trace
surface must be narrow, temporary, visibly enabled, and documented with its
exact data fields and deletion behavior.

## Local registry retention

The private SQLite registry stores current mappings. To make mutation retries
safe, it also keeps the request payload and receipt for at most 24 hours and
4,096 operations, with a 32 MiB encoded-byte ceiling. A bounded event journal
keeps change effects for at most seven days and 4,096 revisions, also capped at
32 MiB, for local recovery and future peer-sync work. Both journals live only
in the user-owned data directory. Startup, every mutation, and periodic idle
maintenance prune them; secure deletion is enabled and maintenance truncates
the SQLite write-ahead log after pruning. A durable non-payload marker preserves
an owed checkpoint across crashes and restarts; until it clears, status reports
the degraded state and new mutations remain blocked. Removing the Remap data directory
while the daemon is stopped clears the registry and both journals.

## Synchronization

Peer synchronization is explicit and mutually authenticated. Registry data is
shared only with enrolled peers selected by the user. The architecture does not
require a Remap-operated coordination service.

This policy is an implementation contract. Changes require an architecture
decision, threat analysis, documentation, and an explicit user-visible reason.
