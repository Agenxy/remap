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

## Synchronization

Peer synchronization is explicit and mutually authenticated. Registry data is
shared only with enrolled peers selected by the user. The architecture does not
require a Remap-operated coordination service.

This policy is an implementation contract. Changes require an architecture
decision, threat analysis, documentation, and an explicit user-visible reason.

