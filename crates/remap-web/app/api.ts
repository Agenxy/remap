// SPDX-License-Identifier: GPL-3.0-or-later
// The capability token and the one way this page talks to `remap web`.

import { type Diagnostic, isDiagnostic } from "./model.ts";

const TOKEN_KEY = "remap-web-token";
const TOKEN_PATTERN = /^[0-9a-f]{64}$/;

/**
 * Moves `#token=` from the address bar into session storage, so it is not
 * left in history or on screen, and returns the token this tab holds.
 */
export const takeToken = (): string | null => {
  const match = /^#token=([0-9a-f]{64})$/.exec(location.hash);
  if (match?.[1] !== undefined) {
    storeToken(match[1]);
    history.replaceState(null, "", `${location.pathname}${location.search}`);
  }
  const stored = readToken();
  return stored !== null && TOKEN_PATTERN.test(stored) ? stored : null;
};

const storeToken = (token: string): void => {
  try {
    sessionStorage.setItem(TOKEN_KEY, token);
  } catch {
    // Storage can be refused; the token then lives only in this page's memory.
    memoryToken = token;
  }
};

let memoryToken: string | null = null;

const readToken = (): string | null => {
  try {
    return sessionStorage.getItem(TOKEN_KEY) ?? memoryToken;
  } catch {
    return memoryToken;
  }
};

export const forgetToken = (): void => {
  memoryToken = null;
  try {
    sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    // Nothing stored.
  }
};

/**
 * A fresh UUIDv4 for one write. `crypto.randomUUID` exists only in a secure
 * context; a page opened as `http://<name>` builds the same form from
 * `crypto.getRandomValues`.
 */
export const operationId = (): string => {
  if (typeof crypto.randomUUID === "function") return crypto.randomUUID();
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = ((bytes[6] ?? 0) & 0x0f) | 0x40;
  bytes[8] = ((bytes[8] ?? 0) & 0x3f) | 0x80;
  const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
};

/** What one request came to: a value, a diagnostic, or no answer at all. */
export type Outcome<T> =
  | { ok: true; value: T }
  | { ok: false; status: number; diagnostic: Diagnostic }
  | { ok: false; status: 0; diagnostic: null };

export class Api {
  readonly #token: string;

  constructor(token: string) {
    this.#token = token;
  }

  get<T>(path: string, query: Record<string, string> = {}): Promise<Outcome<T>> {
    const search = new URLSearchParams(query).toString();
    return this.#send<T>(search === "" ? path : `${path}?${search}`, { method: "GET" });
  }

  post<T>(path: string, body: unknown): Promise<Outcome<T>> {
    return this.#send<T>(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  }

  async #send<T>(path: string, init: RequestInit): Promise<Outcome<T>> {
    const headers = new Headers(init.headers);
    headers.set("Authorization", `Bearer ${this.#token}`);
    let response: Response;
    try {
      response = await fetch(path, {
        ...init,
        headers,
        cache: "no-store",
        credentials: "omit",
        redirect: "error",
      });
    } catch {
      return { ok: false, status: 0, diagnostic: null };
    }
    return parse<T>(response);
  }
}

const parse = async <T>(response: Response): Promise<Outcome<T>> => {
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    body = null;
  }
  if (response.ok) return { ok: true, value: body as T };
  const diagnostic = isDiagnostic(body)
    ? body
    : {
        code: "web-unreadable-answer",
        message: `remap web answered ${response.status} without a diagnostic`,
        retryable: response.status >= 500,
      };
  return { ok: false, status: response.status, diagnostic };
};
