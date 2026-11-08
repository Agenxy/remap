# ADR-0027: Mapping ergonomics

## Status

Proposed, 2026-10-24. Implemented for review; installation and live acceptance
remain separate owner actions.

## Context

A mapping whose upstream base URL names a page also prefixes root-absolute
assets with that page. An application requesting `/bar.css` therefore reaches
the wrong origin path. Rewriting response bodies would obscure origin behavior
and cannot reliably repair scripts, redirects or application state.

## Decision

Mappings may carry an optional validated `landing` path. The target remains an
HTTP origin with base path `/`, or a Supgang service. DNS targets refuse landing.
Only exact-root GET and HEAD requests receive a 302 with a same-origin relative
Location. Their query bytes are preserved, appended with `&` when the landing
already has a query. Other requests retain their method, path, query and body.
Health requests and WebSocket upgrades follow their existing paths.

The portable core owns validation. Landing paths are at most 2048 encoded bytes,
start with a single slash, and cannot resolve to the root. Schemes, authorities,
parent traversal, fragments, backslashes, whitespace and controls are refused.
Percent escapes must be valid UTF-8 and cannot conceal traversal, controls or
an authority. Non-ASCII text must be percent-encoded. The gateway builds an
empty redirect response; it never rewrites an upstream response body.

The sole registry writer persists a nullable `landing` column and atomically
migrates SQLite schema version 1 to version 2. Existing records become null.
Older daemons already refuse a greater `user_version` before reading records,
so rollback cannot silently discard the field. A downgrade requires restoring
a compatible registry backup; no destructive down-migration is provided.
New daemons retain old journal payloads and receipts. Absent landing fields are
defaulted and omitted when serializing, preserving old idempotency payloads.

The control protocol, mapping views, validation and MCP schemas include the
optional field. Older peers reject a present unknown field. CLI set and validate
accept `--landing`. Apply accepts per-change landing fields in its JSON document;
an explicit `--landing` flag replaces the landing on every set change in that
batch. Omission on set removes an existing landing, just as set replaces a target.
The before/after preview, get, list and validate outputs expose the value.

## Moved names and advisory guidance (expanded scope)

A moved mapping redirects every HTTP request with 301 to a validated new Remap
name, retaining the request path and query and the gateway's HTTP scheme.
Its optional RFC3339 expiry removes it from runtime matching without deleting
the listed record. DNS treats an active moved mapping as gateway-routed.
Self redirects and chains are refused across the complete projected registry,
including changes that would turn an existing destination into a moved mapping.
Persistence retains the validated moved target and expiry in its canonical target
representation. The same schema version 2 compatibility boundary applies.
`moved://NAME?until=RFC3339` is the canonical control/persistence representation;
CLI `--moved-to` and `--until` construct it without changing HTTP host policy.
Chrono 0.4.45, already present transitively in the lockfile, becomes a direct
standard-library-only core dependency for maintained RFC3339 parsing; the
dependency graph gains no package. Snapshot `resolve` observes native Unix
nanoseconds; the pure `resolve_at` accepts an explicit observation. Both preserve
fractional RFC3339 deadlines at the clock's available precision. A missing
observation cannot prolong an expiry. Moved `OPTIONS *` requests use `/` as the
redirect path so the destination remains a valid URL.

The native app decodes landing fields, retains them in editing drafts and sends
them with set/validate commands. Clearing the optional field deliberately removes
it. Details and before/after effects expose landing changes; previews and receipts
also display the authority's advisory warnings. Only actual WebSocket requests
bypass root landing redirects; other Upgrade values retain ordinary HTTP behavior.
The read-only MCP Apps dashboard also shows landing paths in lists, direct facts
and before/after effects, including an explicit absence when a landing is removed.
Advisories render as inert text and are cleared when the displayed result changes.

Pathful HTTP targets remain valid explicit owner intent. Set, validate and preview
add advisory warnings about path prefixing and recommend origin-root landing for
page aliases. Set and preview also hint when multiple names share one origin with
use-upstream. These hints never reject or silently change a mapping. Use-upstream
remains the default because development servers commonly validate Host. Preserve-
client is an explicit choice for origins that serve multiple names or virtual
hosts. A tutorial covers root targets, landing pages, wildcard names, host policy
and safe renames using placeholders for the owner's chosen suffix.

## Security and privacy

Landing introduces no authority, privilege, service, subprocess or remote
dependency. Validation prevents open redirects, header injection and redirect
loops, including encoded disguises. Existing host selection, peer authentication,
TLS failures and gateway resource bounds remain authoritative. Routine logs gain
no mapping, path, query or traffic data. Redirects use `Cache-Control: no-store`.

## Validation and acceptance

Retained baseline controls fail on the prior code in all five requested groups:
root-absolute assets; root GET/HEAD versus other methods; query carriage; unsafe
or incompatible inputs; and registry/MCP/CLI plumbing. The authority currently
rejects the new field before gateway setup on that baseline. The same controls
then exercise the daemon gateway with the implemented field. Additional tests
cover encoded attacks, byte limits, migration, replay, peer routing and upgrades.
Full `make check` and independent reviewer approval are required before handoff.
A green local source gate is not installation or live DNS acceptance.
