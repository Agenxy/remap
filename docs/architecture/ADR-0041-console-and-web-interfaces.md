# ADR-0041: A console and a web interface, both clients of remapd

- Status: Accepted
- Date: 2026-11-27
- Deciders: Remap owner, Remap lead

## Context

Remap has four owner surfaces today: the `remap` command line, the MCP server
with its MCP Apps panel, the macOS menu-bar app, and the Linux system
commands. The command line is complete but one command at a time. The MCP
panel lives inside an agent host. The menu-bar app exists only on macOS, so a
Linux owner, including one on the riscv64 reference machine, has no
interactive way to see and change their names.

The owner asked for a console interface and a web interface to the Agenxy
standard: clear, fast, accessible, honest about failure, and first-class on
Linux and riscv64.

Both must respect the invariants in `AGENTS.md`. `remapd` stays the sole
writer of the registry. Nothing listens beyond loopback unless the owner asks.
Exact owner intent wins, so neither interface invents or rewrites a name.

## Decision

### Two new commands, both control-socket clients

`remap console` opens a full-screen terminal interface. `remap web` serves a
browser interface on loopback for as long as the command runs. Both live in
the `remap` binary and talk to `remapd` through the same `ControlClient` and
commands the CLI uses (`status`, `list`, `get`, `resolve`, `validate`,
`preview`, `apply`, `wait_for_revision`). Neither touches the registry, the
resolver, or any privileged path directly, and neither needs root.

Both record their writes under the existing `cli` surface. They are modes of
the `remap` command, and a new `Surface` value would be a wire change that an
older daemon rejects. Telling them apart in the event history is not needed
by any current reader. If one appears, it is a deliberate protocol change
with its own ADR.

The code lives in two crates so each has a narrow public surface and its own
tests: `remap-console` and `remap-web`. The `remap` crate only parses the
commands and hands each a client.

### Every write is previewed, confirmed, and revision-checked

Both interfaces change the registry the same way:

1. Build the change set (set, enable, disable or remove).
2. Run `preview`. Show every effect, before and after, and every warning.
3. The owner confirms explicitly: `y` in the console, or the Apply button in
   the browser, whose dialog opens with focus on Cancel. The key or click that
   asked for the preview can never also confirm it.
4. Run `apply` with `expected_revision` set to the preview's
   `base_revision` and a fresh UUIDv4 `operation_id`.
5. If the registry moved in between, the daemon refuses with a revision
   conflict. The interface re-reads, shows the new state, and asks again. It
   never retries against a newer revision on its own.

A retry after a transport failure reuses the same operation ID and changes,
so a write the daemon already committed is reported, not repeated.

Forms validate as the owner types, with the daemon's `validate` command, so
the canonical pattern, target kind and warnings shown are the daemon's own.

### Live state

Both interfaces follow the registry with `wait_for_revision` (at most five
seconds per call) and re-read status and the full mapping list when the
revision advances. The full list is read in pages of at most 128, bounded by
the registry's 16,384-mapping ceiling. Status problems the daemon reports
(maintenance, upstream DNS not answering, DNS turned off, peer listeners that
could not bind) are shown in words, never by colour alone.

### The console

The console uses `ratatui` with the `crossterm` backend: pure Rust,
maintained, and portable to macOS, Linux and riscv64.

- It refuses to start unless standard input and output are terminals, and
  points to `remap list` and `remap status` for scripts.
- It restores the terminal on every exit path: quitting, an error, a panic,
  SIGTERM and SIGHUP.
- It works at 80×24 and adapts to resizing. `NO_COLOR` turns colour off.
- Every action has a key, shown in the footer and in `?` help.
- Every preview carries a sequence number, and an answer for a preview the
  owner has since cancelled or replaced is dropped, so a dialog only ever
  shows the change it will apply.
- State is a pure model with an `update` function. Rendering is a pure view
  of that model. Daemon calls run on a worker task and report back as
  events. Tests drive the model and render with `ratatui`'s test backend.

### The web interface

`remap web` serves HTTP/1.1 with `hyper`, from the `remap` process, never
from `remapd`.

**Listening.** It binds `127.0.0.1` only. The port is ephemeral unless the
owner passes `--port`, which gives a stable address the owner can name with
Remap, for example `remap set remap.lab http://127.0.0.1:7341/
--host-header use-upstream`. There is no option to bind another address. It
stops on Ctrl-C or SIGTERM and is never installed as a service.

**Capability token.** Each run generates a 256-bit token from the operating
system's random source. The command prints one URL,
`http://127.0.0.1:<port>/#token=<token>`. The fragment never reaches the
server, logs, or a `Referer`. The page moves the token into session storage
and removes it from the address bar. The browser's history may still hold the
first address, fragment included; the token is worthless once the command
stops, and the next run makes a new one. Every `/api` request must carry
`Authorization: Bearer <token>`, compared in constant time. Static assets
carry no data and need no token.

**DNS rebinding and cross-site requests.** Remap itself can point any name at
`127.0.0.1`, so the server trusts no name it was not given:

- The `Host` header must be exactly `127.0.0.1:<port>`, `localhost:<port>`,
  or the name passed with `--name`. Anything else gets `421`.
- A request that carries `Origin` must name one of those same origins.
- Writes are `POST` with `Content-Type: application/json`, which no
  cross-site form can send without a preflight the server never answers.
- No response carries CORS headers.

**Response headers.** Every response the interface writes sets a strict
Content Security Policy (`default-src 'none'`, with script, style, image and
connect limited to `'self'`, `base-uri` and `form-action` set to `'none'`, and
`frame-ancestors 'none'`), plus `X-Content-Type-Options:
nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`,
`Cross-Origin-Opener-Policy: same-origin` and
`Cross-Origin-Resource-Policy: same-origin`. The exceptions are the empty
replies `hyper` writes itself before a request reaches the interface (a
malformed request line, oversized headers, a header timeout). They carry no
body, so they have nothing to protect.

**Bounds.** Request bodies are at most 64 KiB, connections at most 32 at a
time. Headers and bodies must arrive within ten seconds, and a connection is
closed after five minutes. A long-poll answers when the daemon does, which is
within its five-second wait bound.

**Privacy.** The server logs nothing about requests. It prints its URL and
when it stops, and nothing else.

**API.** The API relays one control command per request. Bodies and results
use the protocol's own JSON forms, so the web interface and the CLI's
`--json` output agree. Daemon diagnostics pass through unchanged, with an
HTTP status chosen by their code.

| Method and path | Command |
| --- | --- |
| `GET /api/status` | `status` |
| `GET /api/mappings` | `list`, every page, with disabled mappings |
| `GET /api/mapping?pattern=` | `get` |
| `GET /api/resolve?name=` | `resolve` |
| `GET /api/wait?after=` | `wait_for_revision`, five seconds |
| `POST /api/validate` | `validate` |
| `POST /api/preview` | `preview` |
| `POST /api/apply` | `apply` |

**Front end.** The page is TypeScript, bundled with esbuild into one script
and one stylesheet. Both are committed, checked for staleness like the MCP
panel's, and embedded in the binary. It loads nothing from the network: no
fonts, no CDN. It follows the system light or dark setting, works at phone
width, and is fully usable from the keyboard. Status changes are announced
through an ARIA live region. It is tested in Chromium and WebKit with
Playwright.

## Threat model

| Asset | Threat | Mitigation |
| --- | --- | --- |
| Registry integrity | Another local web page writes mappings | Capability token required. Origin and Host checked. JSON content type forces a preflight that is never answered. |
| Registry integrity | DNS rebinding of a name to the loopback port | Exact `Host` allow-list, plus the token. |
| Registry contents | Another origin reads the mapping list | No CORS headers. Token required on every API read. CORP `same-origin`. |
| Token | Leaks through logs or `Referer` | Kept in the URL fragment, then session storage. `no-referrer`. Never logged. |
| Token | Read back from browser history later | Valid only while that run of `remap web` lasts. |
| Token | Brute force | 256 bits. Constant-time comparison. |
| Availability | Connection or body floods from local processes | 32 connections, 64 KiB bodies, header and request time limits. |
| Terminal | Console exits and leaves the terminal raw | Restore on drop and in the panic hook. |
| Network exposure | Interface reachable from the LAN | Binds 127.0.0.1 only, with no flag to change it. |

Local processes running as the same user can already read the control socket.
The web interface grants them nothing new. It is no defence against them, and
it does not claim to be.

## Consequences

- Linux and riscv64 owners get an interactive interface. The macOS menu-bar
  app stays the macOS-native surface.
- Two new direct dependencies, `ratatui` and `crossterm`, pass the licence
  and advisory gates. The HTTP server reuses `hyper`, which the gateway
  already depends on.
- `remap web` prints a capability URL. Anyone the owner shares it with can
  change mappings until the command stops. The help text says so.
- A permanently running web interface, or one served over HTTPS, needs a
  service owner and certificates. HTTPS for remapped names is ADR-0038's
  subject. Neither is part of this decision.

## Alternatives considered

- **Serve the web interface from `remapd`.** Rejected. It widens the
  daemon's attack surface and makes a long-lived listener of what should be
  a session the owner starts and stops.
- **Bind beyond loopback for remote administration.** Rejected. Reaching
  another computer's Remap belongs to Supgang and ADR-0037's shared
  registry, which authenticate the peer.
- **A front-end framework.** Rejected. A few hundred lines of typed DOM code
  serve the need without a runtime dependency to audit and update.
- **Reuse the MCP panel as the web page.** Rejected. Its host bridge,
  sizing and read-only stance are specific to MCP Apps. The web page reuses
  its visual tokens and colours, so the two look like one product.
