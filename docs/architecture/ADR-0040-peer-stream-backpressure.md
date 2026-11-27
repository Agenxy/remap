# ADR-0040: A busy peer is waited out, then answered as busy

## Status

Accepted, 2026-11-26. Amends ADR-0026 (peer routes ride the Supgang stream)
and ADR-0028 (gateway upstream diagnostics) with one new error code.

## Context

On 26 Nov, `agenxy.internal`, a `supgang+http` mapping to pro, failed about
half of all parallel requests. Eight parallel requests gave four `200`s and
four `502 E_GATEWAY_UPSTREAM` responses with cause `other`. Every page load
rendered half-styled.

The gateway opens one Supgang stream per request (ADR-0026). Supgang admits
at most four tunnels per peer by default, sixteen in total. Opening eight
streams directly on the control socket, with Remap not involved, gave four
connected and four refused. The limit is Supgang's, and a reasonable one.
What was wrong was how Remap answered it:

- A refusal at the limit is temporary: a slot frees as soon as an earlier
  request finishes, often within milliseconds. Remap failed the request at
  once.
- It reported the refusal as a failed upstream. Supgang 0.2.0-alpha.21 sends
  a reply without a code, and before Supgang #64 a peer at its limit closed
  the stream with no reply at all. Remap read that close as a malformed
  reply, which is cause `other`. The owner was told the service was broken
  when it was busy.

## Decision

1. **Classify the refusal.** Supgang's local control reply may carry a stable
   `code` next to its `message`.
   - These codes are transient and are waited out: `peer_at_capacity`,
     `upstream_unavailable`, `peer_full`, `runtime_full`, `session_failed`,
     `not_connected` and `authorization_lapsed`.
   - `refused` is asked again for at most 300 ms. Peers older than
     Supgang's `upstream_unavailable` reply send `refused` both for a service
     that is not exposed and for one whose own listener briefly turned a
     connection away under a burst. A short grace covers the second case
     without making the first one slow.
   - Every other code, including codes this client does not know, is a final
     refusal and fails at once, as before.
   - A refusal without a code, and a close before the first reply byte, come
     from Supgang releases that cannot say why. They are treated as
     transient, because those releases send the same reply for a full peer
     as for a dead session. Remap never branches on the message text.
2. **Wait, bounded.**
   - **Tunnel-only service** (`supgang+http`): the gateway asks again with
     a pause that starts at 20 ms and doubles up to 250 ms. It keeps asking
     for at most three seconds, or half the routing deadline if that is
     shorter, so the exchange still has time to run.
   - **Pinned service with a direct fallback** (ADR-0016): the gateway asks
     once and takes the fallback.
   - **Peer machine listener:** waits the same way, for at most half its open
     deadline.
3. **Answer busy as busy.** A peer that stays full gets `503
   E_GATEWAY_PEER_BUSY` with `Retry-After: 1` and the matched mapping. It
   carries no `Cause:` line, because nothing failed. The peer machine
   listener's log keeps cause `refused`, so the cause set that `remap status`
   reports is unchanged.

## Consequences

- With the default limit of four, a browser's six to eight parallel requests
  are served in full. The surplus waits a few milliseconds for a slot.
- A peer that is truly unreachable, against a Supgang without refusal codes,
  now costs up to three seconds before it fails, and the answer is `503 busy`
  rather than `502`. Supgang releases that send codes fail fast with the
  exact reason. Supgang sends a code on every op 0x07 refusal from the release after #64 (agreed in Dibs #557592); a code it cannot place decodes as `unknown`, which Remap treats as final.
- Each request still opens its own stream. Reusing keep-alive connections over
  a stream would mean fewer streams; it is left for later, because waiting
  alone already fixes the failures.

## Verification

`crates/remap-network/tests/supgang_stream_gateway.rs`:

- `parallel_requests_past_the_peer_limit_all_succeed` sends eight parallel
  requests to a stand-in endpoint that allows four tunnels. It covers each
  over-limit reply in turn: coded, uncoded, and a silent close.
- `a_peer_that_stays_full_is_busy_not_failed` checks the `503`,
  `Retry-After` and body.

Unit tests in `supgang_stream.rs` pin the code classification.
