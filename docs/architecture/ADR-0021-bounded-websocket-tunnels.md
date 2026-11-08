# ADR-0021: WebSocket switches are carried as separately bounded tunnels

## Status

Accepted, 2026-10-10. This is the "explicit separately bounded policy" that
ADR-0013 requires before the gateway carries upgrades, and it delivers the
WebSocket half of the M5 streaming item.

## Context

The gateway removed `Connection` and `Upgrade` along with every other
hop-by-hop header and never took over a switched connection. A WebSocket
request therefore reached the upstream as an ordinary `GET`, and the client
received whatever that returned. A Vite dev server mapped as `agenxy.test`
answered with its HTML page, the browser reported "Unexpected response code:
200", and hot reload fell back to polling. Nothing in the mapping was wrong,
and nothing in the error said the gateway was the cause.

Carrying the switch is not just a matter of forwarding two headers. Once a
connection switches it stops being HTTP, so the HTTP bounds no longer apply
to it. The 60-second connection lifetime would close a hot-reload socket every
minute. The connection limit would let open tabs exhaust browser capacity.
ADR-0013 therefore deferred upgrades until they had bounds of their own.

## Decision

The gateway carries exactly one upgrade protocol, WebSocket, over HTTP/1.1.

- A request is a WebSocket switch when `Connection` names the `upgrade` token
  and there is exactly one `Upgrade` header, naming `websocket` (any case).
  Every other `Upgrade` value, `h2c` included, is forwarded as today: an
  ordinary request with its hop-by-hop headers removed.
- After the hop-by-hop headers are removed, the gateway writes back
  `Connection: upgrade` and `Upgrade: websocket` and nothing else.
  `Sec-WebSocket-*`, `Origin`, and the client's query are end-to-end and pass
  unchanged, and the mapping's host policy applies as for any request.
- A tunnel slot is taken before the upstream is contacted. If none is free,
  the client receives `503 E_GATEWAY_TUNNEL_LIMIT` and the upstream sees
  nothing.
- If the upstream answers with anything other than `101`, that answer is
  relayed like any other response and the slot is released. If it answers
  `101` with an `Upgrade` other than `websocket`, the client receives
  `502 E_GATEWAY_UPGRADE`. A `101` to a request that did not ask for one is
  also `502 E_GATEWAY_UPGRADE`.
- Once both sides have switched, the HTTP connection's future completes and
  its connection permit is returned. The tunnel then runs under its own
  bounds, and the first one reached closes it:

  | Bound | Field | Default | Valid range |
  | --- | --- | --- | --- |
  | Concurrent tunnels | `tunnel_limit` | 256 | 1 to 4096 |
  | No byte in either direction | `tunnel_idle_timeout` | 5 minutes | up to 1 hour |
  | Total lifetime | `tunnel_lifetime` | 12 hours | idle deadline to 24 hours |
  | Gateway shutdown | n/a | immediate | n/a |

  Bytes are copied with backpressure in both directions, and a half-close on
  one side is passed to the other. The gateway does not parse WebSocket
  frames, so it neither answers pings nor produces them.

## Consequences

Dev servers, dashboards, and other WebSocket services behind a Remap name work
the same as they do on their own ports. A five-minute idle limit does not
close the common clients: Vite's HMR client pings every 30 seconds, and most
WebSocket libraries send a heartbeat well within five minutes. A client that
sends nothing for longer is disconnected and has to reconnect, which is the
same behavior a typical reverse proxy shows.

The upgrade is HTTP/1.1 only. An HTTPS upstream that negotiates HTTP/2 through
ALPN cannot accept a `Connection` header, so that request fails with the
existing `502 E_GATEWAY_UPSTREAM`. Carrying WebSocket over HTTP/2 (RFC 8441
extended CONNECT) needs a separate decision. Server-sent events are ordinary
streamed responses and are still bounded by the HTTP connection lifetime, as
ADR-0013 records. They need their own policy too.

Acceptance: `crates/remap-network/tests/websocket_gateway.rs` shows the switch
reaching the upstream with its headers and outliving the HTTP connection
deadline, an idle tunnel being closed, a switch past the limit being refused
before the upstream, and a non-WebSocket upgrade being forwarded as an
ordinary request. On 2026-10-10 a Vite 8 dev server routed through a branch
`remapd` logged `[vite] connected.` in a browser.
