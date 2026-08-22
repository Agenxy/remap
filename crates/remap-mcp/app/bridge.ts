import { asRecord, asString, type JsonRecord } from "./model.ts";

interface PendingCall {
  resolve: (value: unknown) => void;
  reject: (reason: Error) => void;
  timer: number;
}

export type NotificationHandler = (method: string, params: unknown) => void;

export class AppBridge {
  readonly #pending = new Map<number, PendingCall>();
  readonly #handler: NotificationHandler;
  readonly #listener: (event: MessageEvent<unknown>) => void;
  #nextId = 1;
  #tornDown = false;

  constructor(handler: NotificationHandler) {
    this.#handler = handler;
    this.#listener = (event) => this.#receive(event);
    addEventListener("message", this.#listener);
  }

  notify(method: string, params: JsonRecord = {}): void {
    if (!this.#tornDown) parent.postMessage({ jsonrpc: "2.0", method, params }, "*");
  }

  call(method: string, params: JsonRecord = {}): Promise<unknown> {
    if (this.#tornDown) return Promise.reject(new Error("The host closed this panel"));
    const id = this.#nextId++;
    return new Promise((resolve, reject) => {
      const timer = window.setTimeout(() => {
        this.#pending.delete(id);
        reject(new Error("The host did not answer in time"));
      }, 6_000);
      this.#pending.set(id, { resolve, reject, timer });
      parent.postMessage({ jsonrpc: "2.0", id, method, params }, "*");
    });
  }

  #receive(event: MessageEvent<unknown>): void {
    if (event.source !== parent) return;
    const message = asRecord(event.data);
    if (message?.jsonrpc !== "2.0") return;
    if (message.method === "ui/resource-teardown") {
      this.#teardown(message);
      return;
    }
    const id = typeof message.id === "number" ? message.id : null;
    if (id !== null && typeof message.method !== "string") {
      this.#settle(id, message);
      return;
    }
    const method = asString(message.method);
    if (method !== null) this.#handler(method, message.params);
  }

  #settle(id: number, message: JsonRecord): void {
    const pending = this.#pending.get(id);
    if (pending === undefined) return;
    this.#pending.delete(id);
    clearTimeout(pending.timer);
    const error = asRecord(message.error);
    if (error !== null) {
      pending.reject(new Error(asString(error.message) ?? "Host request failed"));
    } else {
      pending.resolve(message.result);
    }
  }

  #teardown(message: JsonRecord): void {
    this.#handler("ui/resource-teardown", message.params);
    this.#tornDown = true;
    removeEventListener("message", this.#listener);
    for (const pending of this.#pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(new Error("The host closed this panel"));
    }
    this.#pending.clear();
    if (message.id !== undefined) {
      parent.postMessage({ jsonrpc: "2.0", id: message.id, result: {} }, "*");
    }
  }
}
