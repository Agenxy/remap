// SPDX-License-Identifier: GPL-3.0-or-later
// The protocol's JSON forms, as `remap web` relays them, and pure views of
// them. Nothing here touches the DOM.

export type HostPolicy = "preserve-client" | "use-upstream";

export interface Diagnostic {
  code: string;
  message: string;
  hint?: string;
  retryable: boolean;
  context?: Record<string, string>;
}

export interface MappingView {
  pattern: string;
  target: string;
  target_kind: string;
  host_policy: HostPolicy;
  enabled: boolean;
  updated_revision: number;
  landing?: string;
  peer_address?: string;
}

export interface ListenerFailure {
  pattern: string;
  service: string;
  address: string;
  port: number;
  cause: string;
  detail: string;
}

export interface RegistryStatus {
  revision: number;
  mapping_count: number;
  enabled_count: number;
  schema_version: number;
  daemon_version: string;
  maintenance?: Diagnostic;
  dns_upstream?: Diagnostic;
  dns_turned_off?: { turned_off_at: string; command: string; turn_on: string };
  peer_machine_listeners?: {
    listening: number;
    not_listening: number;
    failures?: ListenerFailure[];
  };
}

export interface ListResult {
  revision: number;
  mappings: MappingView[];
}

export interface ValidationResult {
  pattern: string;
  target: string;
  target_kind: string;
  host_policy: HostPolicy;
  landing?: string;
  warnings?: string[];
}

export interface ChangeEffect {
  pattern: string;
  action: string;
  before: MappingView | null;
  after: MappingView | null;
}

export interface PreviewResult {
  base_revision: number;
  will_change: boolean;
  effects: ChangeEffect[];
  warnings?: string[];
}

export interface ApplyResult {
  operation_id: string;
  previous_revision: number;
  revision: number;
  changed: boolean;
  effects: ChangeEffect[];
  warnings?: string[];
}

export interface ResolutionResult {
  name: string;
  revision: number;
  mapping: MappingView | null;
}

export interface RevisionNotice {
  revision: number;
  changed: boolean;
}

export type Change =
  | {
      kind: "set";
      pattern: string;
      target: string;
      host_policy: HostPolicy;
      enabled: boolean;
      landing?: string;
    }
  | { kind: "enable" | "disable" | "remove"; pattern: string };

export type SetChange = Extract<Change, { kind: "set" }>;

export interface Draft {
  pattern: string;
  target: string;
  host_policy: HostPolicy;
  landing: string;
  enabled: boolean;
}

export const isDiagnostic = (value: unknown): value is Diagnostic => {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Record<string, unknown>;
  return (
    typeof record.code === "string" &&
    typeof record.message === "string" &&
    typeof record.retryable === "boolean"
  );
};

export const isHostPolicy = (value: string): value is HostPolicy =>
  value === "preserve-client" || value === "use-upstream";

/** The mappings a search and the show-off toggle leave visible. */
export const visibleMappings = (
  mappings: readonly MappingView[],
  search: string,
  showOff: boolean,
): MappingView[] => {
  const needle = search.trim().toLowerCase();
  return mappings.filter((mapping) => {
    if (!showOff && !mapping.enabled) return false;
    if (needle === "") return true;
    return [mapping.pattern, mapping.target, mapping.target_kind, mapping.peer_address ?? ""].some(
      (field) => field.toLowerCase().includes(needle),
    );
  });
};

export const stateWord = (enabled: boolean): string => (enabled ? "on" : "off");

/** One problem the daemon reports, in words. */
export interface Problem {
  title: string;
  detail: string;
  command?: string;
  items?: string[];
}

export const statusProblems = (status: RegistryStatus): Problem[] => {
  const problems: Problem[] = [];
  if (status.maintenance !== undefined) {
    problems.push({
      title: "Changes are paused for maintenance.",
      detail: diagnosticText(status.maintenance),
    });
  }
  if (status.dns_upstream !== undefined) {
    problems.push({
      title: "Upstream DNS is not answering.",
      detail: diagnosticText(status.dns_upstream),
    });
  }
  const off = status.dns_turned_off;
  if (off !== undefined) {
    problems.push({
      title: "System DNS is off.",
      detail: `Turned off by the owner at ${off.turned_off_at} with ${off.command}. Mapped names do not resolve until it is on again. To turn it on, run:`,
      command: off.turn_on,
    });
  }
  const listeners = listenerProblem(status);
  if (listeners !== null) problems.push(listeners);
  return problems;
};

const listenerProblem = (status: RegistryStatus): Problem | null => {
  const listeners = status.peer_machine_listeners;
  if (listeners === undefined || listeners.not_listening === 0) return null;
  const count = listeners.not_listening;
  const failures = listeners.failures ?? [];
  const shown = failures.length < count ? ` The first ${failures.length} are listed.` : "";
  return {
    title: `${count} peer ${count === 1 ? "listener is" : "listeners are"} not listening.`,
    detail: `${listeners.listening} listening.${shown}`,
    items: failures.map(
      (failure) =>
        `${failure.pattern} ${failure.service} on ${failure.address}:${failure.port}: ${failure.detail} (${failure.cause})`,
    ),
  };
};

/** Daemon text starts lower case and has no final stop; show it as a sentence. */
export const sentence = (text: string): string => {
  const trimmed = text.trim();
  if (trimmed === "") return trimmed;
  const capital = `${trimmed.charAt(0).toUpperCase()}${trimmed.slice(1)}`;
  return /[.!?]$/.test(capital) ? capital : `${capital}.`;
};

export const diagnosticText = (diagnostic: Diagnostic): string =>
  diagnostic.hint === undefined
    ? sentence(diagnostic.message)
    : `${sentence(diagnostic.message)} ${sentence(diagnostic.hint)}`;

/** The change set a draft makes; an empty landing is left out. */
export const setChange = (draft: Draft): SetChange => {
  const change: SetChange = {
    kind: "set",
    pattern: draft.pattern.trim(),
    target: draft.target.trim(),
    host_policy: draft.host_policy,
    enabled: draft.enabled,
  };
  const landing = draft.landing.trim();
  if (landing !== "") change.landing = landing;
  return change;
};

const ACTIONS: Record<string, string> = {
  created: "Create",
  updated: "Update",
  enabled: "Turn on",
  disabled: "Turn off",
  removed: "Remove",
  unchanged: "No change to",
};

export const actionWord = (action: string): string => ACTIONS[action] ?? action;

/** A mapping on one line, for before-and-after comparisons. */
export const mappingLine = (mapping: MappingView | null): string => {
  if (mapping === null) return "none";
  const parts = [
    stateWord(mapping.enabled),
    mapping.target,
    mapping.target_kind,
    mapping.host_policy,
  ];
  if (mapping.landing !== undefined) parts.push(`landing ${mapping.landing}`);
  if (mapping.peer_address !== undefined) parts.push(`address ${mapping.peer_address}`);
  return parts.join(" · ");
};

export const plural = (count: number, one: string, many: string): string =>
  `${count} ${count === 1 ? one : many}`;
