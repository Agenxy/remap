# `portal` command reference

Status: M0 command contract.

The CLI is human-readable by default and emits a stable JSON envelope when
`--json` is present. In M0 it performs only local validation and diagnostics. It
does not install a daemon, alter DNS, bind listeners, change trust, or write a
registry.

## Discover the build

```text
portal --help
portal doctor
portal --json doctor
```

`doctor` is deliberately useful before privileged installation exists. It
reports the build, platform, current capabilities, DNS impact, and telemetry
posture without making a network request.

## Validate a mapping

```text
portal validate atlas http://127.0.0.1:5173
portal validate google.com 127.0.0.1
portal validate '*.lab' https://example.com:9443/base
portal validate atlas https://upstream.example --host-header use-upstream
```

The result shows the canonical name, destination, inferred destination type,
and HTTP host policy. Validation never persists the result.

## JSON contract

Every structured response includes schema identity and success state:

```json
{
  "schema": "portal.cli/v1",
  "ok": true,
  "command": "validate",
  "result": {
    "name_pattern": "atlas",
    "target": "http://127.0.0.1:5173/",
    "target_kind": "http",
    "host_header_policy": "preserve-client",
    "system_state_changed": false
  }
}
```

Errors use the same envelope and stable codes:

```json
{
  "schema": "portal.cli/v1",
  "ok": false,
  "error": {
    "code": "P101",
    "message": "the mapping name is not valid",
    "detail": "'127.0.0.1' is an address literal, not a DNS name that Portal can override",
    "hint": "Use a hostname such as 'atlas', 'api.lab', or '*.lab'; addresses belong on the target side."
  }
}
```

Structured results are written only to standard output. Human diagnostics and
progress use standard error. Broken pipes terminate cleanly. JSON never includes
credentials or hidden environment data.

## Exit status

| Status | Meaning |
|---:|---|
| `0` | Command completed successfully, including help and a downstream closed pipe |
| `2` | Usage or supplied mapping input is invalid |
| `70` | Internal command state violated an invariant |

Mutation commands will be added only when they can call the authoritative
daemon. They will support structured preview before any destructive, trust, or
system-wide action.

