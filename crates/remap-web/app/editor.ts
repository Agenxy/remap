// SPDX-License-Identifier: GPL-3.0-or-later
// The add and edit form, validated by the daemon as the owner types.

import type { Api, Outcome } from "./api.ts";
import { byId } from "./dom.ts";
import {
  type Change,
  type Draft,
  isHostPolicy,
  type MappingView,
  setChange,
  type ValidationResult,
} from "./model.ts";
import { renderValidation, type Validation } from "./render.ts";

/** Quiet time after the last keystroke before asking the daemon. */
export const VALIDATE_DELAY_MS = 300;

type Review = (label: string, changes: Change[]) => Promise<void>;

export class Editor {
  readonly #api: Api;
  readonly #review: Review;
  readonly #form = byId<HTMLFormElement>("mapping-form");
  readonly #pattern = byId<HTMLInputElement>("pattern");
  readonly #target = byId<HTMLInputElement>("target");
  readonly #policies = Array.from(
    document.querySelectorAll<HTMLInputElement>('input[name="host-policy"]'),
  );
  readonly #landing = byId<HTMLInputElement>("landing");
  readonly #enabled = byId<HTMLInputElement>("enabled");
  #editing: string | null = null;
  #timer: ReturnType<typeof setTimeout> | null = null;
  #sequence = 0;

  constructor(api: Api, review: Review) {
    this.#api = api;
    this.#review = review;
    for (const field of [this.#pattern, this.#target, this.#landing]) {
      field.addEventListener("input", () => this.#schedule());
    }
    for (const policy of this.#policies) {
      policy.addEventListener("change", () => this.#schedule());
    }
    this.#form.addEventListener("submit", (event) => {
      event.preventDefault();
      void this.#submit();
    });
    byId("cancel-edit").addEventListener("click", () => this.close());
  }

  /** Opens the form empty, or filled with one mapping to edit. */
  open(mapping: MappingView | null): void {
    this.#editing = mapping?.pattern ?? null;
    byId("editor-title").textContent = mapping === null ? "Add mapping" : `Edit ${mapping.pattern}`;
    this.#pattern.value = mapping?.pattern ?? "";
    this.#pattern.readOnly = mapping !== null;
    this.#target.value = mapping?.target ?? "";
    const policy = mapping?.host_policy ?? "use-upstream";
    for (const choice of this.#policies) choice.checked = choice.value === policy;
    this.#landing.value = mapping?.landing ?? "";
    this.#enabled.checked = mapping?.enabled ?? true;
    byId("editor").hidden = false;
    (mapping === null ? this.#pattern : this.#target).focus();
    if (mapping === null) renderValidation({ kind: "idle" });
    else void this.#validate();
  }

  close(): void {
    this.#cancelTimer();
    this.#sequence += 1;
    byId("editor").hidden = true;
    this.#editing = null;
  }

  #draft(): Draft {
    const policy = this.#policies.find((choice) => choice.checked)?.value ?? "";
    return {
      pattern: this.#pattern.value,
      target: this.#target.value,
      host_policy: isHostPolicy(policy) ? policy : "use-upstream",
      landing: this.#landing.value,
      enabled: this.#enabled.checked,
    };
  }

  #schedule(): void {
    this.#cancelTimer();
    this.#timer = setTimeout(() => void this.#validate(), VALIDATE_DELAY_MS);
  }

  #cancelTimer(): void {
    if (this.#timer !== null) clearTimeout(this.#timer);
    this.#timer = null;
  }

  async #validate(): Promise<void> {
    const change = setChange(this.#draft());
    const sequence = ++this.#sequence;
    if (change.pattern === "" || change.target === "") {
      renderValidation({ kind: "idle" });
      return;
    }
    renderValidation({ kind: "checking" });
    const body = {
      pattern: change.pattern,
      target: change.target,
      host_policy: change.host_policy,
      ...(change.landing === undefined ? {} : { landing: change.landing }),
    };
    const outcome = await this.#api.post<ValidationResult>("/api/validate", body);
    // A later keystroke has already asked again.
    if (sequence !== this.#sequence) return;
    renderValidation(validationOf(outcome));
  }

  async #submit(): Promise<void> {
    const change = setChange(this.#draft());
    const missing =
      change.pattern === "" ? this.#pattern : change.target === "" ? this.#target : null;
    if (missing !== null) {
      renderValidation({ kind: "idle" });
      missing.focus();
      return;
    }
    this.#cancelTimer();
    const label = this.#editing === null ? `Add ${change.pattern}` : `Edit ${change.pattern}`;
    await this.#review(label, [change]);
  }
}

const validationOf = (outcome: Outcome<ValidationResult>): Validation => {
  if (outcome.ok) return { kind: "valid", result: outcome.value };
  if (outcome.diagnostic === null) return { kind: "unreachable" };
  return { kind: "invalid", diagnostic: outcome.diagnostic };
};
