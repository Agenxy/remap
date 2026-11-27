// SPDX-License-Identifier: GPL-3.0-or-later
// Every write: preview, an explicit confirmation listing each effect, then
// apply against the previewed revision (ADR-0041, "Every write is
// previewed").

import { type Api, type Outcome, operationId } from "./api.ts";
import { announce, byId, el } from "./dom.ts";
import {
  type ApplyResult,
  type Change,
  type Diagnostic,
  diagnosticText,
  type PreviewResult,
  plural,
} from "./model.ts";
import { effectItem, warningNodes } from "./render.ts";

/** Codes whose request may or may not have been committed. */
const OUTCOME_UNKNOWN = new Set(["E_DAEMON_TIMEOUT", "E_CONTROL_TRANSPORT"]);

type Next = "apply" | "retry" | "review" | "none";

interface Pending {
  label: string;
  changes: Change[];
  preview: PreviewResult | null;
  /** Generated at the first apply; a retry after no answer reuses it. */
  operationId: string | null;
}

export interface WriteHooks {
  /** Re-reads status and mappings. */
  reload(): Promise<void>;
  /** Shows a committed receipt. */
  applied(receipt: ApplyResult): void;
}

export class WriteFlow {
  readonly #api: Api;
  readonly #hooks: WriteHooks;
  readonly #dialog = byId<HTMLDialogElement>("confirm");
  readonly #apply = byId<HTMLButtonElement>("confirm-apply");
  readonly #cancel = byId<HTMLButtonElement>("confirm-cancel");
  #pending: Pending | null = null;
  #next: Next = "none";
  #busy = false;

  constructor(api: Api, hooks: WriteHooks) {
    this.#api = api;
    this.#hooks = hooks;
    this.#apply.addEventListener("click", () => void this.#proceed());
    this.#cancel.addEventListener("click", () => this.#close());
    // Escape closes the dialog, except while a request is in flight.
    this.#dialog.addEventListener("cancel", (event) => {
      if (this.#busy) event.preventDefault();
    });
  }

  /** Previews `changes` and opens the confirmation for them. */
  async start(label: string, changes: Change[]): Promise<void> {
    this.#pending = { label, changes, preview: null, operationId: null };
    byId("confirm-title").textContent = label;
    this.#showError(null, null);
    this.#fill(null);
    this.#setNext("none");
    if (!this.#dialog.open) this.#dialog.showModal();
    await this.#review();
  }

  async #review(): Promise<void> {
    const pending = this.#pending;
    if (pending === null) return;
    this.#working("Previewing");
    const outcome = await this.#api.post<PreviewResult>("/api/preview", {
      changes: pending.changes,
    });
    this.#busy = false;
    if (this.#pending !== pending) return;
    if (!outcome.ok) {
      this.#fill(null);
      this.#showError("The preview failed. Nothing was changed.", outcome.diagnostic);
      this.#setNext(outcome.diagnostic?.retryable === false ? "none" : "review");
      return;
    }
    pending.preview = outcome.value;
    pending.operationId = null;
    this.#showError(null, null);
    this.#fill(outcome.value);
    this.#setNext("apply");
  }

  async #proceed(): Promise<void> {
    if (this.#busy) return;
    if (this.#next === "review") await this.#review();
    else if (this.#next === "apply" || this.#next === "retry") await this.#commit();
  }

  async #commit(): Promise<void> {
    const pending = this.#pending;
    if (pending?.preview == null) return;
    pending.operationId ??= operationId();
    this.#working("Applying");
    const outcome = await this.#api.post<ApplyResult>("/api/apply", {
      expected_revision: pending.preview.base_revision,
      operation_id: pending.operationId,
      changes: pending.changes,
    });
    this.#busy = false;
    if (outcome.ok) {
      this.#dialog.close();
      this.#hooks.applied(outcome.value);
      await this.#hooks.reload();
      return;
    }
    await this.#refused(outcome);
  }

  async #refused(outcome: Exclude<Outcome<ApplyResult>, { ok: true }>): Promise<void> {
    const diagnostic = outcome.diagnostic;
    if (diagnostic?.code === "E_REVISION_CONFLICT") {
      await this.#hooks.reload();
      this.#showError(
        "The registry changed while you were reviewing, so nothing was applied. Review again to see this change against the current mappings.",
        diagnostic,
      );
      announce("Nothing was applied: the registry changed. Review again.");
      this.#setNext("review");
      return;
    }
    if (diagnostic === null || OUTCOME_UNKNOWN.has(diagnostic.code)) {
      this.#showError(
        "No answer arrived, so the change may or may not have been made. Retry sends the same request with the same operation ID: a change already made is reported, not made twice.",
        diagnostic,
      );
      this.#setNext("retry");
      return;
    }
    this.#showError("The daemon refused the change. Nothing was applied.", diagnostic);
    this.#setNext(diagnostic.retryable ? "retry" : "none");
  }

  #fill(preview: PreviewResult | null): void {
    const summary = byId("confirm-summary");
    const effects = byId("confirm-effects");
    const warnings = byId("confirm-warnings");
    if (preview === null) {
      summary.textContent = "Asking the daemon what this would change.";
      effects.replaceChildren();
      warnings.replaceChildren();
      return;
    }
    summary.textContent = preview.will_change
      ? `Against revision ${preview.base_revision}, this makes ${plural(preview.effects.length, "change", "changes")}:`
      : `Against revision ${preview.base_revision}, this changes nothing:`;
    effects.replaceChildren(...preview.effects.map(effectItem));
    warnings.replaceChildren(...warningNodes(preview.warnings));
  }

  #showError(summary: string | null, diagnostic: Diagnostic | null): void {
    const box = byId("confirm-error");
    box.hidden = summary === null;
    if (summary === null) {
      box.replaceChildren();
      return;
    }
    const detail = diagnostic === null ? "remap web did not answer." : diagnosticText(diagnostic);
    box.replaceChildren(el("strong", null, summary), el("span", null, detail));
  }

  #working(label: string): void {
    this.#busy = true;
    this.#apply.disabled = true;
    this.#cancel.disabled = true;
    this.#apply.textContent = label;
  }

  #setNext(next: Next): void {
    this.#next = next;
    this.#cancel.disabled = false;
    this.#apply.hidden = next === "none";
    this.#apply.disabled = false;
    this.#apply.textContent = { apply: "Apply", retry: "Retry", review: "Review again", none: "" }[
      next
    ];
    this.#cancel.textContent = next === "none" ? "Close" : "Cancel";
    // Focus starts on Cancel, so confirming is always a deliberate second
    // step; a retry or a fresh review is offered on the action button.
    const focusApply = next === "retry" || next === "review";
    (focusApply ? this.#apply : this.#cancel).focus();
  }

  #close(): void {
    if (!this.#busy) this.#dialog.close();
  }
}
