# MCP and App verification record

## 2026-08-15: M1 adversarial pass

The official Rust MCP SDK drives both supported core revisions against one live
daemon. Twelve compatibility tests cover modern discovery, previous-version
initialization, shared revision order, cache-field separation, complete text
plus typed structured results, mutation idempotency, subscription updates, the
four-subscription capacity limit, recovery across a daemon restart,
maintenance-only status updates in both eras, and exact MCP Apps MIME
negotiation in both protocol eras. Every listed tool's input
bounds, safety annotations, App visibility, and success/diagnostic output schema
are executable assertions.

Seventeen MCP unit tests cover the 1 MiB decoder and encoder,
bounded parse errors, malformed modern metadata, required response identity,
duplicate live identifiers, the 32-request admission ceiling, saturated output,
and repeated cancellation followed by a successful request on the same session.
Raw family probes prove that legacy `initialize` rejects `2026-07-28`, modern
discovery rejects `2025-11-25`, cross-family methods are unavailable, and an
opened modern stdio process cannot become a hybrid legacy session.

The wire budgets are deliberately distinct. Registry tests prove 128-record
pages and 64-change before/after receipts fit the 1 MiB local-control frame. MCP
tests prove 64-record pages and 32-change receipts fit a complete MCP tool result
after both the text and structured carriers are encoded. Registry boundary
tests cover the 16,384-mapping authority ceiling, request/event
row and byte retention, same-timestamp receipt retention, WAL truncation,
checkpoint contention during startup and runtime, and writer drain before
authority handoff. Contention tests also prove visible degraded status,
receipt replay, mutation-path recovery, and durable checkpoint debt across a
restart. Both contended checkpoint paths complete in under one second, proving
that maintenance does not inherit the ordinary five-second SQLite busy wait.

The embedded App is exercised in Chromium by Playwright 1.62.1 at 520 by 900
and 320 by 800 CSS pixels. Eighteen browser cases cover every success shape,
all five mutation receipts, errors, cancellation uncertainty, hostile text,
coherent refresh retries, out-of-order updates, server-tool presence and
absence, host layout changes, ResizeObserver lifecycle, initialization message
order, teardown, and malformed Apps initialization results. The suite also
fails on browser console errors and verifies that the checked-in JavaScript is
the deterministic build of the reviewed TypeScript source. A degraded
maintenance diagnostic remains in a persistent alert after unrelated tool
results and states both the mutation block and the recovery action. The
initial-size/teardown lifecycle case runs 20 times in each
viewport on every complete App gate to expose animation-frame races.

This is browser and protocol-bridge verification, not a claim about a
particular agent host. Each host-specific integration remains gated on a live
render in that host before Remap documents it as supported.
