# ADR-0028: Gateway upstream diagnostics

## Status

Proposed, 2026-10-27, for the owner's review. Implemented for review on
`feat/gateway-upstream-diagnostics`; installation and live acceptance remain
separate owner actions. Extends ADR-0027's advisory warnings and keeps
ADR-0016's rule that upstream addresses stay inside the gateway.

## Context

The agenxy-supply field report of 2026-10-22 found two gaps.

A mapping to a port with nothing listening looks healthy everywhere before it
is used. `status`, `list`, `resolve` and `preview` all describe the registry,
and the registry is correct: the owner asked for that target. The mapping fails
only when a request reaches the gateway.

The failure then says too little. Every failed upstream exchange answered
`502 E_GATEWAY_UPSTREAM: The selected service did not accept the routed
request.` That names neither the mapping that matched nor what went wrong, so
a refused port, an untrusted certificate and a crashed service look the same.
A browser tab showing that page gives the owner nothing to act on.

The obvious repair, printing the upstream address, is ruled out. ADR-0016 and
the threat model keep addresses, including peer candidates, inside the
gateway's boundary, and the owner can already read a mapping's target from
the registry.

## Decision

### The error body names the mapping and the cause

A gateway error for a request that matched a mapping carries that mapping's
canonical pattern. An error for a failed upstream exchange also carries a
stable cause and a next step. The body is plain text:

```text
Remap could not route this request.

E_GATEWAY_UPSTREAM: The mapping's target refused the connection.

Mapping: *.api.test
Cause: refused
Next: start the service; `remap get *.api.test` shows the target.
```

The contract is:

- The first line and the `CODE: message` line keep their existing shape.
  Error codes and statuses are unchanged: `502 E_GATEWAY_UPSTREAM` and
  `504 E_GATEWAY_TIMEOUT` remain the upstream failures, and every other code
  keeps its meaning.
- `Mapping: PATTERN` appears on every error after a mapping matched, including
  peer, upgrade, landing and direct-target errors. It is the pattern that
  matched, so a wildcard mapping is named as `*.suffix`, not as the requested
  host. Errors before a match (`E_GATEWAY_HOST`, `E_GATEWAY_UNMAPPED`) have no
  mapping line.
- `Cause: TOKEN` and `Next: TEXT` appear on `E_GATEWAY_UPSTREAM` and
  `E_GATEWAY_TIMEOUT`. `E_GATEWAY_TIMEOUT` is always `timeout`.
- The line keys and cause tokens are stable. The message and next-step wording
  may improve; scripts should read the code, `Mapping:` and `Cause:`.
- Error responses carry `Cache-Control: no-store`, as redirects already do.

| Token | Meaning | Classified from |
| --- | --- | --- |
| `refused` | The target refused the connection; nothing listens there | `ConnectionRefused`, or a Supgang stream refusal |
| `timeout` | No connection or answer before a deadline | `TimedOut`, a hyper timeout, or the routing deadline |
| `tls` | The TLS handshake failed: an untrusted or wrong certificate, a pin mismatch, or a plain-HTTP service on an `https` target | a `rustls::Error`, alone or inside an `io::Error` |
| `reset` | The target closed or reset the connection before answering | `ConnectionReset`, `ConnectionAborted`, `BrokenPipe`, `UnexpectedEof`, or an incomplete or cancelled hyper message |
| `unreachable` | The target's network cannot be reached | `HostUnreachable`, `NetworkUnreachable`, `NetworkDown`, `AddrNotAvailable` |
| `other` | Anything else, including a route to the gateway's own listener and a DNS failure for a named target | no recognised link |

The classifier walks the error's source chain, at most 16 links, and the
first link that says what happened decides. It steps into the error an
`io::Error` wraps, because `io::Error::source` skips it and that is where
rustls puts a handshake failure.

The body never contains the upstream address, port, peer node, requested
host, certificate subject or the native error text, which can carry any of
those. The pattern is the owner's own configuration. The client receiving it
has just reached the gateway with a name that pattern matched; on the default
loopback listener that client is a local process, and with ingress the owner
has chosen to expose the mapping.

### Preview and apply advise on loopback reachability

When `remapd` answers a preview or an apply, it probes each loopback HTTP
target the change set leaves enabled and adds an advisory warning when nothing
accepts a connection. This reaches every surface through the warnings channel
ADR-0027 added: `remap preview`, `remap apply`, `remap set`, `remap enable`,
the MCP `remap_preview`, `remap_set`, `remap_enable` and `remap_apply`, and the
native app's preview and receipt views.

```text
api.test: target refused connection; nothing is listening there, so requests
will fail with 502 E_GATEWAY_UPSTREAM (cause refused) until a service starts
```

- **Advice, never a refusal.** The registry has already projected or committed
  the change before the probe runs. Mapping a port before its service starts
  is ordinary owner intent.
- **What is probed.** The final state of each pattern in the change set, when
  that state is enabled and is an HTTP or HTTPS target whose host is a
  loopback address literal (`127.0.0.0/8`, `::1`, or an IPv4-mapped loopback
  address) or exactly `localhost`, which is tried at `127.0.0.1` and `::1`.
  The port is the target's, or the scheme's default.
- **What is never probed.** Peer targets (`supgang://`, `supgang+http://`),
  addresses off the loopback interface, any other name (including names under
  `.localhost`), DNS targets and moved names. A name would need a DNS lookup,
  and an address off loopback can be another machine; a preview never sends
  traffic off the machine.
- **How.** One TCP connect per address, closed at once without sending a byte,
  each bounded by one second, all concurrently, so a preview or apply waits at
  most about one second longer. A change set holds at most 64 changes, so a
  probe makes at most 128 connections. Any accepted address counts as
  reachable.
- **Where.** In the daemon's engine, after the single registry writer has
  answered and outside its thread, so the writer is never held for network
  I/O. The registry and its projection stay free of I/O.
- **Receipts.** Probe advice is appended after the registry's own advisories,
  ordered by pattern. It is not stored in the idempotent receipt: a retried
  apply returns the stored receipt with fresh advice about what listens now.
  The longest advice is about 420 bytes and there are at most 64, well inside
  the 64 KiB the control frame reserves beyond the result budget.
- **Validate is not probed.** It remains a side-effect-free canonicalization
  that also runs without the daemon.

A local service sees an accepted connection close with no request; some
development servers log one line for it, and a listener that accepts exactly
one connection, such as `nc -l`, is spent by the probe. The daemon's own
gateway test upstream was such a listener and now waits for the connection
that carries a request. A target that is the gateway's own
listener accepts the probe, so it is not advised; the gateway still refuses to
route to itself, reported as `other`.

### MCP annotations stay as they are

`remap_preview` keeps `read_only_hint = true`: the probe writes nothing and
changes no state any tool owns. All four tools keep `open_world_hint = false`:
the probe is confined to the loopback interface, to ports the owner named,
and sends no bytes, so the tools' domain remains this machine. `remap_health`
stays the only open-world tool, because the system resolver it asks may
forward to network DNS. Each probing tool's description now says that it
probes and how far, and the catalog test pins that disclosure.

### Naming guidance

`remap://help` gains a short section on choosing names: single-label names
against a chosen suffix such as `.test`, `.internal` or the owner's own, the
`.local` and HSTS-preloaded-suffix pitfalls, and deliberate shadowing. It
prescribes no suffix and names no product namespace.

## Alternatives considered

- **Print the address in the 502.** Rejected by ADR-0016 and the threat model;
  `remap get` already shows the owner the target.
- **Probe in the CLI and MCP adapters.** Duplicates policy in two places and
  misses the native app. The authority answers every surface.
- **Probe inside the registry writer.** Holds the single writer for up to a
  second per request.
- **Refuse a mapping to a closed port.** Contradicts "exact user intent wins".
- **Probe in `status`, `list` and `resolve`.** Those stay pure reads of the
  registry. A future `remap doctor` check may probe the enabled loopback
  mappings on request.
- **A response header for the cause.** Not added; the body lines are the
  contract. A header can be added later without changing them.

## Security and privacy

No authority, privilege, service, subprocess or remote dependency is added.
The probe cannot be aimed off the machine: only loopback addresses are
dialled, after the target has passed the registry's validation, and the
connect sends nothing. Routine logs gain nothing. Error bodies gain the
matched pattern and a token, never an address. The threat model records both.

## Validation and acceptance

Each test below failed on the parent revision `1972445`:

- `crates/remap-network/tests/upstream_diagnostics.rs`:
  `refused_names_the_wildcard_mapping_and_the_refusal`,
  `timeout_names_the_mapping_and_the_deadline`,
  `tls_names_the_mapping_when_the_certificate_is_not_trusted`,
  `tls_names_an_https_target_that_speaks_plain_http`,
  `reset_names_the_mapping_when_the_upstream_hangs_up`. Each asserts the code,
  the `Mapping:` and `Cause:` lines, and that neither the upstream's address
  nor its port appears in the body.
- `crates/remapd/tests/reachability.rs`:
  `apply_advises_on_a_refused_target_and_still_commits`,
  `preview_advises_only_where_nothing_listens` (a listening target, a LAN
  address and a peer target are not advised, and the preview finishes before
  any probe could have timed out), and
  `preview_advice_clears_once_the_service_starts`.
- `crates/remap-mcp/tests/reachability.rs`:
  `preview_set_and_apply_advise_on_a_refused_loopback_target`, through the
  official MCP client against a real daemon.
- The MCP catalog contract (`modern_discover_exposes_bounded_agent_contract`)
  pins each probing tool's disclosure and unchanged annotations, and
  `remap-mcp` unit tests pin the help sections.

Unit tests cover the cause classifier, including a rustls error wrapped in an
`io::Error`, and which targets are probed. Full `make check` is required
before handoff. A green local gate is not installation or live acceptance.
