# ADR-0032: A wildcard's peer target may read its peer and service from the name

## Status

Proposed, 2026-10-29. Implemented for review; installing it and choosing
mappings stay with the owner. It extends ADR-0016 and ADR-0026 (peer targets)
and ADR-0002 (arbitrary names).

## Context

K7 is growing a fleet of build machines, and each runs deck services that
Supgang can carry. A mapping per service, such as
`preview.solis.k7.internal → supgang+http://solis/preview`, has to be written
and kept up to date by hand for every machine and service. The 15 October
split anticipated an owner-set wildcard template for this, and said it needed
an ADR and the owner's choice of suffix. On 29 October the owner left the
suffix to K7's lead ("make the technically best ... choice ... and go
ahead"), who chose `k7.internal`. ICANN reserved `.internal` in 2024 for
private use, so it can never shadow a public name.

Remap must not invent names, reserve a namespace, or derive names from
Supgang's advertisements. The owner writes every mapping, and the suffix is
part of the owner's mapping, not part of Remap.

## Decision

A peer target (`supgang://` or `supgang+http://`) on a **wildcard** pattern
may use `{1}` or `{2}` as its whole peer or whole service:

```text
*.k7.internal → supgang://{1}/{2}
preview.solis.k7.internal  routes to  supgang://solis/preview
```

- `{1}` is the label nearest the wildcard's suffix, and `{2}` the next one out.
  This reads outward from the suffix, as DNS delegation does, so the machine
  sits next to the suffix and the service in front of it.
- A placeholder is a whole field. `so{1}` and `{1}x` are refused, as is any
  field that starts with `{` and is not exactly `{1}` or `{2}`. A literal peer
  selector can no longer contain a brace, so a template is never ambiguous.
- The placeholders used must be `{1}`, or both `{1}` and `{2}`. `{2}` without
  `{1}` is refused, because every label a template reads must be used.
- A template on an exact name is refused, at set time as
  `E_TEMPLATE_NEEDS_WILDCARD`, and in a stored revision as corrupt.

**Matching does not change.** A wildcard owns every descendant of its suffix,
templated or not, and exact names and more specific wildcards keep their
precedence. DNS answers every matched name with the gateway, exactly as for a
literal peer mapping. Only routing reads the template. At routing time the
gateway fills it from the name's labels and validates the result exactly as
it would a literal peer and service. A name with a different number of labels
before the suffix, or a label that is not valid in its field (a service is at
most 16 characters, for example), is answered with
`404 E_GATEWAY_TEMPLATE_NAME` naming the mapping. It is never shortened,
padded, or routed to any other service. The response body is static text, so
nothing from the request is echoed back.

**Stored as written.** The target keeps its template text in the registry,
the control protocol, MCP and the CLI, so `remap get` shows the owner exactly
what they wrote. No wire field is added.

**Registry schema 3.** A daemon from before this ADR would read
`supgang://{1}/{2}` as a corrupt record, or worse, `supgang://{1}/dibs` as a
peer literally named `{1}`. Schema version 3 adds no column. It only raises
`user_version`, so an older daemon refuses the registry with
`E_REGISTRY_SCHEMA_NEWER` before reading any record.

**The way back is kept.** ADR-0027 said a rollback needs "a compatible
registry backup", but Remap made none. From now on, before the registry
migrates an existing database to a newer schema, it writes a coherent copy
beside it with SQLite's `VACUUM INTO`:
`registry.schema-<old>.<unix-ms>.sqlite3`, mode 0600.

- `VACUUM INTO` refuses a destination that already holds data, so no copy is
  ever overwritten.
- If the copy cannot be made, the migration is refused with
  `E_REGISTRY_SNAPSHOT` and the registry is left unchanged.
- To roll back, stop `remapd`, remove `registry.sqlite3-wal` and
  `registry.sqlite3-shm`, and move the copy over `registry.sqlite3`. A daemon
  that reads the old schema then opens exactly the registry it left.
- Changes made after the migration are not in the copy.
- Copies are kept until the owner deletes them.

**Not decided here.** A `k7://<node>/<deck>/<service>` target would take a
third capture. It waits on K7's local stream endpoint contract and will extend
`MAX_TEMPLATE_CAPTURES` in its own ADR. Templates for HTTP, DNS and moved
targets are not offered: a template that writes a hostname or an address would
let a name choose where the gateway dials, and no owner has asked for that.

## Consequences

- One mapping, `*.k7.internal → supgang+http://{1}/{2}`, reaches every service
  that every fleet machine exposes through Supgang, with no Remap change as
  machines and services come and go. Authorization stays Supgang's: a stream
  opens only for services the target's owner exposed, and `supgang://` keeps
  its end-to-end pinned TLS.
- A name can only choose among what the owner's template allows: the peer and
  service fields, each checked against Supgang's own bounds. A request cannot
  reach a scheme, a host, a port, or a path that the owner did not write.
- Rolling back to an older daemon means putting the pre-migration copy back,
  even if no template was ever written. The copy holds nothing written after
  the upgrade.
