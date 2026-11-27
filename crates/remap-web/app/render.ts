// SPDX-License-Identifier: GPL-3.0-or-later
// Views of daemon state. Each function replaces what it owns.

import { button, byId, code, el } from "./dom.ts";
import {
  type ApplyResult,
  actionWord,
  type ChangeEffect,
  type Diagnostic,
  diagnosticText,
  type ListResult,
  type MappingView,
  mappingLine,
  type Problem,
  plural,
  type RegistryStatus,
  type ResolutionResult,
  sentence,
  stateWord,
  type ValidationResult,
  visibleMappings,
} from "./model.ts";

export const renderStats = (status: RegistryStatus | null): void => {
  byId("stats").hidden = status === null;
  if (status === null) return;
  byId("stat-revision").textContent = String(status.revision);
  byId("stat-total").textContent = String(status.mapping_count);
  byId("stat-on").textContent = String(status.enabled_count);
};

export type Connection =
  | { kind: "reading" }
  | { kind: "current"; revision: number }
  | { kind: "daemon"; diagnostic: Diagnostic; retryIn: number }
  | { kind: "server"; retryIn: number }
  | { kind: "token" };

export const connectionText = (connection: Connection): [string, string] => {
  switch (connection.kind) {
    case "reading":
      return ["", "Reading the registry."];
    case "current":
      return [
        "",
        `Current at revision ${connection.revision}. Changes made anywhere appear here as they happen.`,
      ];
    case "daemon":
      return [
        "The Remap daemon is not answering.",
        `${diagnosticText(connection.diagnostic)} Trying again in ${seconds(connection.retryIn)}.`,
      ];
    case "server":
      return [
        "remap web is not answering.",
        `If it stopped, run remap web again and open the new address. Trying again in ${seconds(connection.retryIn)}.`,
      ];
    case "token":
      return [
        "This page's token was not accepted.",
        "remap web makes a new address each time it starts. Open the address it printed most recently.",
      ];
  }
};

const seconds = (milliseconds: number): string =>
  plural(Math.round(milliseconds / 1000), "second", "seconds");

export const renderConnection = (connection: Connection): void => {
  const notice = byId("connection");
  const [problem, detail] = connectionText(connection);
  notice.classList.toggle("bad", problem !== "");
  notice.replaceChildren();
  if (problem !== "") notice.append(el("strong", null, problem), " ");
  notice.append(detail);
};

export const renderProblems = (problems: readonly Problem[]): void => {
  byId("problems-section").hidden = problems.length === 0;
  byId("problems").replaceChildren(...problems.map(problemItem));
};

const problemItem = (problem: Problem): HTMLElement => {
  const item = el(
    "li",
    "problem",
    el("strong", null, problem.title),
    " ",
    el("span", null, problem.detail),
  );
  if (problem.command !== undefined) item.append(" ", code(problem.command));
  if (problem.items !== undefined && problem.items.length > 0) {
    item.append(el("ul", null, ...problem.items.map((line) => el("li", null, line))));
  }
  return item;
};

export interface RowActions {
  edit(mapping: MappingView): void;
  toggle(mapping: MappingView): void;
  remove(mapping: MappingView): void;
}

export interface ListView {
  list: ListResult | null;
  search: string;
  showOff: boolean;
}

export const renderMappings = (view: ListView, actions: RowActions): void => {
  const all = view.list?.mappings ?? [];
  const shown = visibleMappings(all, view.search, view.showOff);
  byId("mapping-rows").replaceChildren(...shown.map((mapping) => mappingRow(mapping, actions)));
  byId("mapping-table").hidden = shown.length === 0;
  const empty = byId("empty");
  empty.hidden = shown.length > 0;
  empty.textContent = emptyText(view.list, all.length);
  byId("count").textContent =
    view.list === null
      ? ""
      : `Showing ${shown.length} of ${plural(all.length, "mapping", "mappings")}`;
};

const emptyText = (list: ListResult | null, total: number): string => {
  if (list === null) return "Not read yet.";
  if (total === 0) return "No mappings yet. Add one to point a name somewhere you choose.";
  return "No mapping matches. Clear the search or show mappings that are off.";
};

const cell = (label: string, className: string | null, ...children: (Node | string)[]) => {
  const element = el("td", className, ...children);
  element.dataset.label = label;
  element.setAttribute("role", "cell");
  return element;
};

const optional = (value: string | undefined): Node | string =>
  value === undefined ? el("span", "none", "none") : value;

const mappingRow = (mapping: MappingView, actions: RowActions): HTMLTableRowElement => {
  const row = el("tr", null);
  row.setAttribute("role", "row");
  row.dataset.pattern = mapping.pattern;
  const state = el("span", `state ${stateWord(mapping.enabled)}`, stateWord(mapping.enabled));
  const toggleLabel = mapping.enabled ? "Turn off" : "Turn on";
  const controls = el(
    "div",
    "row-actions",
    labelled(
      button("Edit", "small", () => actions.edit(mapping)),
      `Edit ${mapping.pattern}`,
    ),
    labelled(
      button(toggleLabel, "small", () => actions.toggle(mapping)),
      `${toggleLabel} ${mapping.pattern}`,
    ),
    labelled(
      button("Remove", "small danger", () => actions.remove(mapping)),
      `Remove ${mapping.pattern}`,
    ),
  );
  row.append(
    cell("Name", "name", mapping.pattern),
    cell("State", null, state),
    cell("Target", "target", mapping.target),
    cell("Kind", null, mapping.target_kind),
    cell("Host header", null, mapping.host_policy),
    cell("Landing", null, optional(mapping.landing)),
    cell("Peer address", null, optional(mapping.peer_address)),
    cell("Actions", null, controls),
  );
  return row;
};

const labelled = (element: HTMLElement, label: string): HTMLElement => {
  element.setAttribute("aria-label", label);
  return element;
};

export type Validation =
  | { kind: "idle" }
  | { kind: "checking" }
  | { kind: "valid"; result: ValidationResult }
  | { kind: "invalid"; diagnostic: Diagnostic }
  | { kind: "unreachable" };

export const renderValidation = (validation: Validation): void => {
  const root = byId("validation");
  root.classList.toggle("bad", validation.kind === "invalid");
  root.replaceChildren(...validationContent(validation));
};

const validationContent = (validation: Validation): (Node | string)[] => {
  switch (validation.kind) {
    case "idle":
      return ["Type a name and a target to check them."];
    case "checking":
      return ["Checking with the daemon."];
    case "unreachable":
      return ["Could not check: remap web is not answering."];
    case "invalid":
      return [
        el("strong", null, sentence(validation.diagnostic.message)),
        el("span", null, sentence(validation.diagnostic.hint ?? "")),
      ];
    case "valid":
      return validContent(validation.result);
  }
};

const validContent = (result: ValidationResult): (Node | string)[] => {
  const facts = [result.target_kind, result.host_policy];
  if (result.landing !== undefined) facts.push(`landing ${result.landing}`);
  return [
    el(
      "span",
      null,
      el("strong", null, "Valid. "),
      "Saved as ",
      code(result.pattern),
      " to ",
      code(result.target),
      ` · ${facts.join(" · ")}`,
    ),
    ...warningNodes(result.warnings),
  ];
};

export const warningNodes = (warnings: readonly string[] | undefined): HTMLElement[] =>
  (warnings ?? []).map((warning) => el("p", "warning", el("strong", null, "Warning: "), warning));

export const effectItem = (effect: ChangeEffect): HTMLElement => {
  const compare = el(
    "dl",
    "compare",
    el("dt", null, "Before"),
    el("dd", null, mappingLine(effect.before)),
    el("dt", null, "After"),
    el("dd", null, mappingLine(effect.after)),
  );
  const head = el("div", "effect-head", `${actionWord(effect.action)} `, code(effect.pattern));
  return el("li", "effect", head, compare);
};

export const renderReceipt = (receipt: ApplyResult): void => {
  const summary = receipt.changed
    ? `Applied. The registry moved from revision ${receipt.previous_revision} to ${receipt.revision}.`
    : `Nothing changed. The registry already matched at revision ${receipt.revision}.`;
  byId("receipt-body").replaceChildren(
    el("p", null, summary),
    el("ul", "effects", ...receipt.effects.map(effectItem)),
    ...warningNodes(receipt.warnings),
    el("p", "muted", "Operation ", code(receipt.operation_id)),
  );
  byId("receipt").hidden = false;
};

export const renderResolution = (result: ResolutionResult): void => {
  const mapping = result.mapping;
  const line =
    mapping === null
      ? [code(result.name), " matches no mapping, so it resolves through normal DNS."]
      : [code(result.name), " uses ", code(mapping.pattern), `: ${mappingLine(mapping)}.`];
  byId("resolve-result").replaceChildren(
    el("p", null, ...line),
    el("p", "muted", `At revision ${result.revision}.`),
  );
};

export const renderResolveFailure = (diagnostic: Diagnostic | null): void => {
  const text = diagnostic === null ? "remap web is not answering." : diagnosticText(diagnostic);
  byId("resolve-result").replaceChildren(el("p", "validation bad", text));
};
