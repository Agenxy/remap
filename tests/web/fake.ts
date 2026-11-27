// SPDX-License-Identifier: GPL-3.0-or-later
// A scripted `remap web` for the page tests. `page.route` serves the real
// committed page, with the real security headers, and answers the API from
// an in-memory registry the test controls.
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import type { Page, Request, Route } from "@playwright/test";

export const ORIGIN = "http://127.0.0.1:7341";
export const TOKEN = "ab".repeat(32);

export const CONTENT_SECURITY_POLICY =
  "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; " +
  "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

const SECURITY_HEADERS = {
  "content-security-policy": CONTENT_SECURITY_POLICY,
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "cache-control": "no-store",
  "cross-origin-opener-policy": "same-origin",
  "cross-origin-resource-policy": "same-origin",
};

const app = resolve(import.meta.dirname, "../../crates/remap-web/app");
const ASSETS: Record<string, [string, string]> = {
  "/": ["index.html", "text/html; charset=utf-8"],
  "/app.js": ["app.js", "text/javascript; charset=utf-8"],
  "/app.css": ["app.css", "text/css; charset=utf-8"],
  "/remap-mark.svg": ["remap-mark.svg", "image/svg+xml"],
};

export type Json = Record<string, unknown>;

export interface Mapping extends Json {
  pattern: string;
  target: string;
  target_kind: string;
  host_policy: string;
  enabled: boolean;
  updated_revision: number;
  landing?: string;
  peer_address?: string;
}

export const mapping = (pattern: string, extra: Partial<Mapping> = {}): Mapping => ({
  pattern,
  target: "127.0.0.1",
  target_kind: "dns-address",
  host_policy: "preserve-client",
  enabled: true,
  updated_revision: 1,
  ...extra,
});

export interface Recorded {
  method: string;
  path: string;
  body: Json | null;
  authorization: string | null;
}

/** What the next request should meet instead of a normal answer. */
export interface Faults {
  daemonDown: boolean;
  /** Commit the next apply, then drop the connection before answering. */
  loseNextApplyAnswer: boolean;
}

export class FakeRemap {
  revision = 0;
  mappings: Mapping[] = [];
  status: Json = {};
  readonly faults: Faults = { daemonDown: false, loseNextApplyAnswer: false };
  readonly requests: Recorded[] = [];
  readonly #receipts = new Map<string, Json>();
  #waiters: (() => void)[] = [];

  constructor(mappings: Mapping[] = [], revision = 3) {
    this.mappings = mappings;
    this.revision = revision;
  }

  /** Another surface changes the registry. */
  externalChange(next?: Mapping): void {
    this.revision += 1;
    if (next !== undefined) this.mappings.push(next);
    this.#notify();
  }

  applies(): Recorded[] {
    return this.requests.filter((request) => request.path === "/api/apply");
  }

  async install(page: Page): Promise<void> {
    await page.route(`${ORIGIN}/**`, (route, request) => this.#handle(route, request));
  }

  async #handle(route: Route, request: Request): Promise<void> {
    const url = new URL(request.url());
    if (!url.pathname.startsWith("/api/")) return this.#asset(route, url.pathname);
    const body = request.postData();
    const recorded: Recorded = {
      method: request.method(),
      path: url.pathname,
      body: body === null ? null : (JSON.parse(body) as Json),
      authorization: request.headers().authorization ?? null,
    };
    this.requests.push(recorded);
    if (recorded.authorization !== `Bearer ${TOKEN}`) {
      return json(
        route,
        401,
        diagnostic("web-unauthorized", "this request needs the capability token"),
      );
    }
    if (this.faults.daemonDown) return json(route, 503, unavailable());
    return this.#api(route, recorded, url.searchParams);
  }

  async #asset(route: Route, path: string): Promise<void> {
    const asset = ASSETS[path];
    if (asset === undefined) return route.fulfill({ status: 404, headers: SECURITY_HEADERS });
    const [file, contentType] = asset;
    await route.fulfill({
      status: 200,
      headers: { ...SECURITY_HEADERS, "content-type": contentType },
      body: await readFile(resolve(app, file)),
    });
  }

  async #api(route: Route, request: Recorded, query: URLSearchParams): Promise<void> {
    switch (request.path) {
      case "/api/status":
        return json(route, 200, this.#statusBody());
      case "/api/mappings":
        return json(route, 200, {
          revision: this.revision,
          mappings: this.mappings,
          next_cursor: null,
        });
      case "/api/wait":
        return this.#wait(route, Number(query.get("after")));
      case "/api/resolve":
        return json(route, 200, this.#resolve(query.get("name") ?? ""));
      case "/api/validate":
        return this.#validate(route, request.body ?? {});
      case "/api/preview":
        return json(route, 200, this.#preview(request.body ?? {}));
      default:
        return this.#apply(route, request.body ?? {});
    }
  }

  #statusBody(): Json {
    return {
      revision: this.revision,
      mapping_count: this.mappings.length,
      enabled_count: this.mappings.filter((entry) => entry.enabled).length,
      schema_version: 1,
      daemon_version: "0.2.0",
      ...this.status,
    };
  }

  async #wait(route: Route, after: number): Promise<void> {
    if (this.revision === after) {
      await new Promise<void>((done) => {
        const timer = setTimeout(done, 400);
        this.#waiters.push(() => {
          clearTimeout(timer);
          done();
        });
      });
    }
    await json(route, 200, { revision: this.revision, changed: this.revision !== after });
  }

  #notify(): void {
    const waiters = this.#waiters;
    this.#waiters = [];
    for (const waiter of waiters) waiter();
  }

  #resolve(name: string): Json {
    const lookup = name.toLowerCase();
    const found = this.mappings.find((entry) => entry.enabled && entry.pattern === lookup);
    return { name: lookup, revision: this.revision, mapping: found ?? null };
  }

  async #validate(route: Route, body: Json): Promise<void> {
    const target = String(body.target);
    if (target === "bad") {
      return json(route, 422, {
        ...diagnostic("E_INVALID_TARGET", "the target is not an address, name or URL"),
        hint: "use an IP address, DNS alias, http(s) upstream URL, or supgang://<peer>/<service>",
      });
    }
    const canonical = this.#project(body);
    const warnings = target.startsWith("http://127.0.0.1:9/")
      ? ["api.test: target refused connection at 127.0.0.1:9"]
      : [];
    await json(route, 200, { ...canonical, warnings });
  }

  #project(body: Json): Mapping {
    const target = String(body.target);
    const kind = /^\d+\.\d+\.\d+\.\d+$/.test(target)
      ? "dns-address"
      : target.startsWith("http")
        ? "http"
        : "dns-alias";
    const projected = mapping(String(body.pattern).toLowerCase(), {
      target,
      target_kind: kind,
      host_policy: String(body.host_policy),
      updated_revision: this.revision + 1,
    });
    if (typeof body.landing === "string") projected.landing = body.landing;
    if (typeof body.enabled === "boolean") projected.enabled = body.enabled;
    return projected;
  }

  #preview(body: Json): Json {
    const changes = (body.changes as Json[]) ?? [];
    const effects = changes.map((change) => this.#effect(change));
    const warnings = changes.some((change) =>
      String(change.target).startsWith("http://127.0.0.1:9/"),
    )
      ? ["api.test: target refused connection at 127.0.0.1:9"]
      : [];
    return { base_revision: this.revision, will_change: true, effects, warnings };
  }

  #effect(change: Json): Json {
    const pattern = String(change.pattern).toLowerCase();
    const before = this.mappings.find((entry) => entry.pattern === pattern) ?? null;
    if (change.kind === "set") {
      return {
        pattern,
        action: before === null ? "created" : "updated",
        before,
        after: this.#project(change),
      };
    }
    if (change.kind === "remove") return { pattern, action: "removed", before, after: null };
    const enabled = change.kind === "enable";
    const after =
      before === null ? null : { ...before, enabled, updated_revision: this.revision + 1 };
    return { pattern, action: enabled ? "enabled" : "disabled", before, after };
  }

  async #apply(route: Route, body: Json): Promise<void> {
    const operation = String(body.operation_id);
    const stored = this.#receipts.get(operation);
    if (stored !== undefined) return json(route, 200, stored);
    if (body.expected_revision !== this.revision)
      return json(route, 409, conflict(this.revision, body));
    const receipt = this.#commit(operation, (body.changes as Json[]) ?? []);
    if (this.faults.loseNextApplyAnswer) {
      this.faults.loseNextApplyAnswer = false;
      return route.abort("connectionreset");
    }
    await json(route, 200, receipt);
  }

  #commit(operation: string, changes: Json[]): Json {
    const previous = this.revision;
    const effects = changes.map((change) => this.#effect(change));
    for (const effect of effects) {
      this.mappings = this.mappings.filter((entry) => entry.pattern !== effect.pattern);
      if (effect.after !== null) this.mappings.push(effect.after as Mapping);
    }
    this.mappings.sort((left, right) => left.pattern.localeCompare(right.pattern));
    this.revision += 1;
    const receipt = {
      operation_id: operation,
      previous_revision: previous,
      revision: this.revision,
      changed: true,
      effects,
    };
    this.#receipts.set(operation, receipt);
    this.#notify();
    return receipt;
  }
}

const json = (route: Route, status: number, body: unknown): Promise<void> =>
  route.fulfill({
    status,
    headers: { ...SECURITY_HEADERS, "content-type": "application/json" },
    body: JSON.stringify(body),
  });

const diagnostic = (code: string, message: string): Json => ({ code, message, retryable: false });

const unavailable = (): Json => ({
  code: "E_DAEMON_UNAVAILABLE",
  message: "the Remap daemon is not reachable",
  hint: "run 'remap doctor' for the exact service recovery path, then retry",
  retryable: true,
});

const conflict = (revision: number, body: Json): Json => ({
  code: "E_REVISION_CONFLICT",
  message: `the registry is at revision ${revision}, not the expected revision ${String(body.expected_revision)}`,
  hint: "read current mappings, reconsider the change, and use the new revision",
  retryable: false,
});

/** Opens the page as `remap web` printed it, and records page failures. */
export const open = async (
  page: Page,
  fake: FakeRemap,
  hash = `#token=${TOKEN}`,
): Promise<string[]> => {
  const problems: string[] = [];
  page.on("pageerror", (error) => problems.push(`page error: ${error.message}`));
  page.on("console", (message) => {
    if (message.type() === "error" && !message.text().includes("Failed to load resource")) {
      problems.push(`console: ${message.text()}`);
    }
  });
  await fake.install(page);
  await page.goto(`${ORIGIN}/${hash}`);
  return problems;
};
