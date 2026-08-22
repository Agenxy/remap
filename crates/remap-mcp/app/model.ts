export type JsonRecord = Record<string, unknown>;

export interface MappingView extends JsonRecord {
  pattern: string;
  target: string;
  target_kind: string;
  host_policy: string;
  enabled: boolean;
  updated_revision?: number;
}

export interface DashboardState {
  status: JsonRecord | null;
  list: JsonRecord | null;
  maintenance: JsonRecord | null;
  outcome: Outcome | null;
  hostContext: JsonRecord;
}

export interface Outcome {
  kind: string;
  summary: string;
  data: unknown;
}

export const asRecord = (value: unknown): JsonRecord | null =>
  typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as JsonRecord)
    : null;

export const asNumber = (value: unknown): number | null =>
  typeof value === "number" && Number.isFinite(value) ? value : null;

export const asString = (value: unknown): string | null =>
  typeof value === "string" ? value : null;

export const asMappings = (value: unknown): MappingView[] =>
  Array.isArray(value) ? value.filter(isMapping) : [];

export const isMapping = (value: unknown): value is MappingView => {
  const item = asRecord(value);
  return (
    item !== null &&
    typeof item.pattern === "string" &&
    typeof item.target === "string" &&
    typeof item.target_kind === "string" &&
    typeof item.host_policy === "string" &&
    typeof item.enabled === "boolean"
  );
};

export const envelopeOf = (result: unknown): JsonRecord | null => {
  const record = asRecord(result);
  return asRecord(record?.structuredContent) ?? record;
};

export const classifyOutcome = (data: unknown): string => {
  const record = asRecord(data);
  if (data === null) return "lookup";
  if (typeof record?.operation_id === "string") return record.changed ? "committed" : "no change";
  if (typeof record?.base_revision === "number") return "preview";
  if (typeof record?.name === "string" && "mapping" in record) return "resolution";
  if (typeof record?.pattern === "string" && typeof record.target === "string") return "mapping";
  return "result";
};

export const mappingSummary = (value: unknown): string => {
  const mapping = isMapping(value) ? value : null;
  if (mapping === null) return "∅";
  const state = mapping.enabled ? "active" : "disabled";
  return `${mapping.pattern} → ${mapping.target} · ${mapping.target_kind} · ${mapping.host_policy} · ${state}`;
};

export const isErrorResult = (result: unknown, data: JsonRecord | null): boolean => {
  const record = asRecord(result);
  return record?.isError === true || typeof data?.code === "string";
};
