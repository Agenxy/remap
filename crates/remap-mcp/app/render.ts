import {
  asMappings,
  asNumber,
  asRecord,
  asString,
  type DashboardState,
  type JsonRecord,
  type MappingView,
  mappingSummary,
  type Outcome,
} from "./model.ts";

const byId = <T extends HTMLElement>(id: string): T => {
  const element = document.getElementById(id);
  if (element === null) throw new Error(`Missing dashboard element: ${id}`);
  return element as T;
};

const text = (tag: string, value: string, className?: string): HTMLElement => {
  const element = document.createElement(tag);
  element.textContent = value;
  if (className !== undefined) element.className = className;
  return element;
};

export class SizeReporter {
  readonly #send: (width: number, height: number) => void;
  readonly #resize: () => void;
  #observer: ResizeObserver | null = null;
  #frame: number | null = null;
  #last = "";
  #started = false;

  constructor(send: (width: number, height: number) => void) {
    this.#send = send;
    this.#resize = () => this.schedule();
  }

  start(): void {
    if (this.#started) return;
    this.#started = true;
    this.#observer = new ResizeObserver(() => this.schedule());
    this.#observer.observe(document.documentElement);
    addEventListener("resize", this.#resize);
    this.schedule();
  }

  schedule(): void {
    if (!this.#started || this.#frame !== null) return;
    this.#frame = requestAnimationFrame(() => {
      this.#frame = null;
      const width = Math.ceil(innerWidth);
      const height = Math.ceil(document.documentElement.getBoundingClientRect().height);
      const identity = `${width}:${height}`;
      if (identity === this.#last) return;
      this.#last = identity;
      this.#send(width, height);
    });
  }

  stop(): void {
    this.#started = false;
    this.#observer?.disconnect();
    this.#observer = null;
    removeEventListener("resize", this.#resize);
    if (this.#frame !== null) cancelAnimationFrame(this.#frame);
    this.#frame = null;
  }
}

export const setNotice = (message: string, bad: boolean): void => {
  const notice = byId("notice");
  notice.textContent = message;
  notice.classList.toggle("bad", bad);
};

export const announce = (message: string): void => {
  byId("announcer").textContent = message;
};

export const render = (state: DashboardState, sizes: SizeReporter): void => {
  const status = state.status;
  const list = state.list;
  const outcome = state.outcome;
  const mappings = asMappings(list?.mappings);
  const partial = asString(list?.next_cursor) !== null;
  const revision = status?.revision ?? list?.revision ?? asRecord(outcome?.data)?.revision;
  byId("revision").textContent = String(revision ?? "Not available");
  byId("total").textContent = String(
    status?.mapping_count ??
      (list === null ? "Not available" : `${partial ? "≥" : ""}${mappings.length}`),
  );
  const active = mappings.filter((mapping) => mapping.enabled).length;
  const activeFallback = list === null ? "Not available" : `${partial ? "≥" : ""}${active}`;
  byId("enabled").textContent = String(status?.enabled_count ?? activeFallback);
  renderMaintenance(state.maintenance);
  renderOutcome(outcome);
  renderMappings(list, mappings);
  sizes.schedule();
};

const renderMaintenance = (maintenance: JsonRecord | null): void => {
  const banner = byId("maintenance");
  banner.hidden = maintenance === null;
  if (maintenance === null) {
    banner.textContent = "";
    return;
  }
  const message = asString(maintenance.message) ?? "Retention maintenance is blocked.";
  const hint = asString(maintenance.hint);
  const recovery = hint === null ? "" : ` ${hint}`;
  banner.textContent = `${message} New mutations are blocked.${recovery}`;
};

const renderMappings = (list: JsonRecord | null, mappings: MappingView[]): void => {
  const root = byId("mappings");
  root.replaceChildren();
  const more = asString(list?.next_cursor) === null ? "" : " · more available";
  byId("count").textContent = list === null ? "" : `${mappings.length} shown${more}`;
  if (list === null || mappings.length === 0) {
    const message =
      list === null
        ? "Awaiting registry state."
        : "No mappings yet. Ask your agent to create one, or use remap set.";
    root.append(text("div", message, "empty"));
    return;
  }
  for (const mapping of mappings) root.append(mappingRow(mapping));
};

const mappingRow = (mapping: MappingView): HTMLElement => {
  const row = document.createElement("div");
  row.className = "mapping";
  const name = text("span", mapping.pattern, "name");
  name.title = mapping.pattern;
  const target = text("span", mapping.target, "target");
  target.title = mapping.target;
  const destination = document.createElement("span");
  destination.className = "destination";
  const updated =
    mapping.updated_revision === undefined ? "" : ` · revision ${mapping.updated_revision}`;
  destination.append(
    target,
    text("span", `${mapping.target_kind} · ${mapping.host_policy}${updated}`, "mapping-meta"),
  );
  row.append(name, text("span", "→", "arrow"), destination);
  const pill = text("span", mapping.enabled ? "active" : "disabled", "pill");
  pill.classList.toggle("off", !mapping.enabled);
  row.append(pill);
  return row;
};

const renderOutcome = (outcome: Outcome | null): void => {
  const panel = byId("outcome");
  panel.hidden = outcome === null;
  if (outcome === null) return;
  byId("outcome-kind").textContent = outcome.kind;
  const body = byId("outcome-body");
  body.replaceChildren(text("strong", outcome.summary, "outcome-summary"));
  const data = asRecord(outcome.data);
  const facts = outcomeFacts(data);
  if (facts.length > 0) {
    const factRoot = document.createElement("div");
    factRoot.className = "facts";
    for (const fact of facts) factRoot.append(text("span", fact));
    body.append(factRoot);
  }
  const effects = Array.isArray(data?.effects) ? data.effects : [];
  for (const effect of effects) body.append(effectRow(effect));
  const hint = asString(data?.hint);
  if (hint !== null) body.append(text("div", hint, "effect"));
};

const outcomeFacts = (data: JsonRecord | null): string[] => {
  if (data === null) return [];
  const facts = [...revisionFacts(data), ...namedFacts(data)];
  facts.push(...booleanFacts(data), ...contextFacts(asRecord(data.context)));
  const selected = mappingSummary(data.mapping);
  if (selected !== "∅") facts.push(selected);
  return facts;
};

const revisionFacts = (data: JsonRecord): string[] => {
  const facts: string[] = [];
  const revision = asNumber(data.revision);
  const previous = asNumber(data.previous_revision);
  const base = asNumber(data.base_revision);
  if (revision !== null) facts.push(`revision ${revision}`);
  if (previous !== null) facts.push(`previous ${previous}`);
  if (base !== null) facts.push(`base ${base}`);
  return facts;
};

const namedFacts = (data: JsonRecord): string[] => {
  const facts: string[] = [];
  for (const key of [
    "operation_id",
    "name",
    "pattern",
    "target",
    "target_kind",
    "host_policy",
    "code",
  ] as const) {
    const value = asString(data[key]);
    if (value !== null) facts.push(value);
  }
  return facts;
};

const booleanFacts = (data: JsonRecord): string[] => {
  const facts: string[] = [];
  if (typeof data.enabled === "boolean") facts.push(data.enabled ? "active" : "disabled");
  if (typeof data.retryable === "boolean") {
    facts.push(data.retryable ? "retryable" : "not retryable");
  }
  return facts;
};

const contextFacts = (context: JsonRecord | null): string[] => {
  if (context === null) return [];
  return Object.entries(context)
    .slice(0, 8)
    .map(([key, value]) => `${key}: ${boundedFact(value)}`);
};

const boundedFact = (value: unknown): string => {
  const encoded =
    typeof value === "string" || typeof value === "number" || typeof value === "boolean"
      ? String(value)
      : (JSON.stringify(value) ?? "unknown");
  return encoded.length <= 128 ? encoded : `${encoded.slice(0, 125)}…`;
};

const effectRow = (value: unknown): HTMLElement => {
  const effect = asRecord(value);
  const row = document.createElement("div");
  row.className = "effect";
  const action = asString(effect?.action) ?? "change";
  const pattern = asString(effect?.pattern) ?? "unknown mapping";
  row.append(text("strong", `${action} · ${pattern}`));
  row.append(
    text(
      "span",
      `${mappingSummary(effect?.before)}  →  ${mappingSummary(effect?.after)}`,
      "effect-change",
    ),
  );
  return row;
};

const boundedPixels = (value: unknown, fallback = 0): number => {
  const number = asNumber(value);
  return number === null ? fallback : Math.min(4_096, Math.max(0, number));
};

export const applyHostContext = (context: JsonRecord): void => {
  const root = document.documentElement;
  const theme = asString(context.theme);
  if (theme === "light" || theme === "dark") root.dataset.theme = theme;
  else delete root.dataset.theme;
  root.dataset.displayMode = asString(context.displayMode) ?? "inline";
  const locale = asString(context.locale);
  if (locale !== null && /^[A-Za-z0-9-]{2,35}$/.test(locale)) root.lang = locale;
  applyInsets(root, asRecord(context.safeAreaInsets));
  applyDimensions(root, asRecord(context.containerDimensions));
  applyVariables(root, asRecord(asRecord(context.styles)?.variables));
};

const applyInsets = (root: HTMLElement, area: JsonRecord | null): void => {
  for (const side of ["top", "right", "bottom", "left"] as const) {
    root.style.setProperty(`--safe-${side}`, `${boundedPixels(area?.[side])}px`);
  }
};

const applyDimensions = (root: HTMLElement, dimensions: JsonRecord | null): void => {
  applyAxis(root, "width", {
    fixed: dimensions?.width,
    maximum: dimensions?.maxWidth,
    ceiling: 920,
  });
  applyAxis(root, "height", {
    fixed: dimensions?.height,
    maximum: dimensions?.maxHeight,
  });
};

interface AxisDimensions {
  readonly fixed: unknown;
  readonly maximum: unknown;
  readonly ceiling?: number;
}

const applyAxis = (
  root: HTMLElement,
  axis: "width" | "height",
  dimensions: AxisDimensions,
): void => {
  const fixedPixels = asNumber(dimensions.fixed);
  const viewportUnit = axis === "width" ? "100vw" : "100vh";
  root.style.setProperty(`--container-${axis}`, fixedPixels === null ? "auto" : viewportUnit);
  const maxPixels = asNumber(dimensions.maximum);
  const bounded = boundedPixels(maxPixels);
  const capped = Math.min(dimensions.ceiling ?? bounded, bounded);
  root.style.setProperty(`--container-max-${axis}`, maxPixels === null ? "none" : `${capped}px`);
};

const appliedVariables = new Set<string>();

const applyVariables = (root: HTMLElement, variables: JsonRecord | null): void => {
  for (const key of appliedVariables) {
    if (variables?.[key] === undefined) root.style.removeProperty(key);
  }
  appliedVariables.clear();
  for (const [key, value] of Object.entries(variables ?? {})) {
    const safeKey = /^--(?:color|font|border|shadow)-[a-z0-9-]+$/.test(key);
    if (!safeKey || typeof value !== "string" || value.length > 256) continue;
    root.style.setProperty(key, value);
    appliedVariables.add(key);
  }
};
