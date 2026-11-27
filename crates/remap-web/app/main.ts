// SPDX-License-Identifier: GPL-3.0-or-later
// The page: reads the token, follows the registry, and wires the controls.

import { Api, forgetToken, type Outcome, takeToken } from "./api.ts";
import { announce, byId, sleep } from "./dom.ts";
import { Editor } from "./editor.ts";
import type {
  ApplyResult,
  ListResult,
  MappingView,
  RegistryStatus,
  ResolutionResult,
  RevisionNotice,
} from "./model.ts";
import { statusProblems } from "./model.ts";
import {
  type Connection,
  renderConnection,
  renderMappings,
  renderProblems,
  renderReceipt,
  renderResolution,
  renderResolveFailure,
  renderStats,
} from "./render.ts";
import { WriteFlow } from "./writes.ts";

type Failed = Exclude<Outcome<unknown>, { ok: true }>;

const FIRST_RETRY_MS = 1_000;
const LONGEST_RETRY_MS = 30_000;

class App {
  readonly #api: Api;
  readonly #writes: WriteFlow;
  readonly #editor: Editor;
  #status: RegistryStatus | null = null;
  #list: ListResult | null = null;
  #retry = FIRST_RETRY_MS;
  #stopped = false;
  #wasDown = false;

  constructor(api: Api) {
    this.#api = api;
    this.#writes = new WriteFlow(api, {
      reload: async () => {
        await this.load();
      },
      applied: (receipt) => this.#applied(receipt),
    });
    this.#editor = new Editor(api, (label, changes) => this.#writes.start(label, changes));
    this.#wire();
  }

  #wire(): void {
    byId("search").addEventListener("input", () => this.#renderList());
    byId("show-disabled").addEventListener("change", () => this.#renderList());
    byId("add").addEventListener("click", () => this.#editor.open(null));
    byId("resolve-form").addEventListener("submit", (event) => {
      event.preventDefault();
      void this.#resolve();
    });
  }

  /** Reads status and every mapping; false when either could not be read. */
  async load(): Promise<boolean> {
    const [status, list] = await Promise.all([
      this.#api.get<RegistryStatus>("/api/status"),
      this.#api.get<ListResult>("/api/mappings"),
    ]);
    if (!status.ok) {
      this.#down(status);
      return false;
    }
    if (!list.ok) {
      this.#down(list);
      return false;
    }
    this.#status = status.value;
    this.#list = list.value;
    this.#up();
    renderStats(this.#status);
    renderProblems(statusProblems(this.#status));
    this.#renderList();
    return true;
  }

  #up(): void {
    this.#retry = FIRST_RETRY_MS;
    renderConnection({ kind: "current", revision: this.#status?.revision ?? 0 });
    if (this.#wasDown) announce("Connected again. The registry is current.");
    this.#wasDown = false;
  }

  #down(failure: Failed): void {
    const connection = this.#connectionFor(failure);
    renderConnection(connection);
    if (connection.kind === "token") {
      this.#stopped = true;
      forgetToken();
    }
    if (!this.#wasDown) announce(byId("connection").textContent ?? "");
    this.#wasDown = true;
  }

  #connectionFor(failure: Failed): Connection {
    if (failure.status === 401) return { kind: "token" };
    if (failure.diagnostic === null) return { kind: "server", retryIn: this.#retry };
    return { kind: "daemon", diagnostic: failure.diagnostic, retryIn: this.#retry };
  }

  /** Follows the registry with bounded waits, retrying with backoff. */
  async follow(): Promise<void> {
    let current = await this.load();
    while (!this.#stopped) {
      if (!current) {
        await sleep(this.#retry);
        this.#retry = Math.min(this.#retry * 2, LONGEST_RETRY_MS);
        current = await this.load();
        continue;
      }
      current = await this.#wait();
    }
  }

  async #wait(): Promise<boolean> {
    const after = String(this.#list?.revision ?? 0);
    const notice = await this.#api.get<RevisionNotice>("/api/wait", { after });
    if (!notice.ok) {
      this.#down(notice);
      return false;
    }
    return notice.value.changed || notice.value.revision !== this.#list?.revision
      ? this.load()
      : true;
  }

  #renderList(): void {
    renderMappings(
      {
        list: this.#list,
        search: byId<HTMLInputElement>("search").value,
        showOff: byId<HTMLInputElement>("show-disabled").checked,
      },
      {
        edit: (mapping) => this.#editor.open(mapping),
        toggle: (mapping) => void this.#toggle(mapping),
        remove: (mapping) =>
          void this.#writes.start(`Remove ${mapping.pattern}`, [
            { kind: "remove", pattern: mapping.pattern },
          ]),
      },
    );
  }

  async #toggle(mapping: MappingView): Promise<void> {
    const kind = mapping.enabled ? "disable" : "enable";
    const label = `${mapping.enabled ? "Turn off" : "Turn on"} ${mapping.pattern}`;
    await this.#writes.start(label, [{ kind, pattern: mapping.pattern }]);
  }

  #applied(receipt: ApplyResult): void {
    this.#editor.close();
    renderReceipt(receipt);
    const heading = byId("receipt-title");
    heading.focus();
    announce(
      receipt.changed
        ? `Applied. The registry is at revision ${receipt.revision}.`
        : "Nothing changed. The registry already matched.",
    );
  }

  async #resolve(): Promise<void> {
    const name = byId<HTMLInputElement>("resolve-name").value.trim();
    if (name === "") return;
    const outcome = await this.#api.get<ResolutionResult>("/api/resolve", { name });
    if (outcome.ok) renderResolution(outcome.value);
    else renderResolveFailure(outcome.diagnostic);
  }
}

const start = (): void => {
  const token = takeToken();
  if (token === null) {
    byId("no-token").hidden = false;
    return;
  }
  byId("app").hidden = false;
  void new App(new Api(token)).follow();
};

start();
