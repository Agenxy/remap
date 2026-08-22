import { AppBridge } from "./bridge.ts";
import {
  asMappings,
  asRecord,
  asString,
  classifyOutcome,
  type DashboardState,
  envelopeOf,
  isErrorResult,
  type JsonRecord,
} from "./model.ts";
import { announce, applyHostContext, render, SizeReporter, setNotice } from "./render.ts";

const state: DashboardState = {
  status: null,
  list: null,
  maintenance: null,
  outcome: null,
  hostContext: {},
};
let hostCanCall = false;
let tornDown = false;
let bridge: AppBridge;
const sizes = new SizeReporter((width, height) => {
  bridge?.notify("ui/notifications/size-changed", { width, height });
});

const accept = (result: unknown): void => {
  const envelope = envelopeOf(result);
  if (envelope === null) return;
  const data = asRecord(envelope.data);
  if (isErrorResult(result, data)) {
    const error = data ?? envelope;
    const summary = asString(error.message) ?? "The Remap operation failed.";
    state.outcome = { kind: "error", summary, data: error };
    setNotice(summary, true);
    draw();
    return;
  }
  if (isStatus(data) || isList(data)) {
    acceptRegistryState(envelope, data);
  } else {
    const summary = asString(envelope.summary) ?? "Remap returned a result.";
    state.outcome = { kind: classifyOutcome(envelope.data), summary, data: envelope.data };
    setNotice(summary, false);
  }
  draw();
};

const isStatus = (data: JsonRecord | null): data is JsonRecord =>
  typeof data?.mapping_count === "number" && typeof data.enabled_count === "number";

const isList = (data: JsonRecord | null): data is JsonRecord =>
  data !== null && Array.isArray(data.mappings);

const acceptRegistryState = (envelope: JsonRecord, data: JsonRecord): void => {
  const revision = resultDataRevision(data);
  const status = isStatus(data);
  const other = status ? state.list : state.status;
  const otherRevision = resultDataRevision(other);
  if (revision !== null && otherRevision !== null && revision < otherRevision) {
    setNotice("Ignored an older registry snapshot.", false);
    return;
  }
  if (status) {
    state.status = data;
    state.maintenance = asRecord(data.maintenance);
  }
  if (isList(data)) state.list = { ...data, mappings: asMappings(data.mappings) };
  if (revision !== otherRevision) {
    if (status) state.list = null;
    else state.status = null;
  }
  state.outcome = null;
  setRegistryStateNotice(asString(envelope.summary) ?? "Registry state is current.");
};

const setRegistryStateNotice = (fallback: string): void => {
  const maintenance = state.maintenance;
  if (maintenance === null) {
    setNotice(fallback, false);
    return;
  }
  const message = asString(maintenance.message) ?? "Retention maintenance is blocked.";
  const hint = asString(maintenance.hint);
  setNotice(
    hint === null
      ? `${message} New mutations are blocked.`
      : `${message} New mutations are blocked. ${hint}`,
    true,
  );
};

const draw = (): void => render(state, sizes);

const mergeHostContext = (update: unknown): void => {
  const incoming = asRecord(update) ?? {};
  const oldStyles = asRecord(state.hostContext.styles) ?? {};
  const newStyles = asRecord(incoming.styles) ?? {};
  const variables = {
    ...(asRecord(oldStyles.variables) ?? {}),
    ...(asRecord(newStyles.variables) ?? {}),
  };
  state.hostContext = {
    ...state.hostContext,
    ...incoming,
    styles: { ...oldStyles, ...newStyles, variables },
  };
  applyHostContext(state.hostContext);
  sizes.schedule();
};

const handleNotification = (method: string, params: unknown): void => {
  if (method === "ui/notifications/tool-result") accept(params);
  if (method === "ui/notifications/tool-cancelled") {
    const reason = asString(asRecord(params)?.reason);
    const summary =
      reason === null
        ? "The request was cancelled. Authoritative state may have changed; refresh before retrying."
        : `The request was cancelled (${reason}). Authoritative state may have changed; refresh before retrying.`;
    state.outcome = { kind: "cancelled", summary, data: null };
    setNotice(summary, false);
    draw();
  }
  if (method === "ui/notifications/host-context-changed") mergeHostContext(params);
  if (method === "ui/resource-teardown") {
    tornDown = true;
    hostCanCall = false;
    sizes.stop();
    refreshButton().disabled = true;
  }
};

bridge = new AppBridge(handleNotification);

const refresh = async (): Promise<void> => {
  if (tornDown) return;
  if (!hostCanCall) {
    setNotice(
      "This host does not allow app-to-tool calls. Invoke remap_status or remap_list to refresh the panel.",
      false,
    );
    return;
  }
  const button = refreshButton();
  button.disabled = true;
  setNotice("Reading authoritative state…", false);
  try {
    await refreshCoherentSnapshot();
  } catch (error) {
    setNotice(error instanceof Error ? error.message : "The registry could not be read.", true);
  } finally {
    button.disabled = tornDown;
  }
};

const refreshCoherentSnapshot = async (): Promise<void> => {
  let last: [unknown, unknown] = [null, null];
  for (let attempt = 0; attempt < 3; attempt += 1) {
    last = await readSnapshot();
    const failed = last.find(toolFailed);
    if (failed !== undefined) {
      accept(failed);
      return;
    }
    const revisions = last.map(resultRevision);
    if (revisions[0] !== null && revisions[0] === revisions[1]) {
      accept(last[0]);
      accept(last[1]);
      setRegistryStateNotice("Registry state is current.");
      announce("Remap registry refreshed");
      return;
    }
    if (revisions.includes(null)) break;
  }
  const statusRevision = resultRevision(last[0]);
  const listRevision = resultRevision(last[1]);
  const newest =
    statusRevision !== null && statusRevision > (listRevision ?? -1) ? last[0] : last[1];
  accept(newest);
  setRegistryStateNotice(
    "The registry changed during refresh. Showing the latest coherent mapping page.",
  );
};

const readSnapshot = async (): Promise<[unknown, unknown]> => {
  const status = await bridge.call("tools/call", { name: "remap_status", arguments: {} });
  const list = await bridge.call("tools/call", {
    name: "remap_list",
    arguments: { limit: 64, include_disabled: true },
  });
  return [status, list];
};

const resultRevision = (result: unknown): number | null => {
  return resultDataRevision(asRecord(envelopeOf(result)?.data));
};

const resultDataRevision = (data: JsonRecord | null): number | null => {
  const revision = data?.revision;
  return typeof revision === "number" && Number.isSafeInteger(revision) ? revision : null;
};

const toolFailed = (result: unknown): boolean => {
  const data = asRecord(envelopeOf(result)?.data);
  return isErrorResult(result, data);
};

const refreshButton = (): HTMLButtonElement =>
  document.getElementById("refresh") as HTMLButtonElement;

const validateInitializeResult = (value: unknown): JsonRecord => {
  const result = asRecord(value);
  if (result === null) {
    throw new Error("The host returned an incompatible MCP Apps initialization result.");
  }
  const hostInfo = asRecord(result?.hostInfo);
  const valid =
    asString(result?.protocolVersion) === "2026-01-26" &&
    asString(hostInfo?.name) !== null &&
    asString(hostInfo?.version) !== null &&
    asRecord(result?.hostCapabilities) !== null &&
    asRecord(result?.hostContext) !== null;
  if (!valid) throw new Error("The host returned an incompatible MCP Apps initialization result.");
  return result;
};

refreshButton().addEventListener("click", () => void refresh());
draw();

const initialize = async (): Promise<void> => {
  try {
    const response = await bridge.call("ui/initialize", {
      appInfo: { name: "remap-dashboard", version: "1" },
      appCapabilities: { availableDisplayModes: ["inline", "fullscreen"] },
      protocolVersion: "2026-01-26",
    });
    const initialized = validateInitializeResult(response);
    hostCanCall = asRecord(asRecord(initialized?.hostCapabilities)?.serverTools) !== null;
    mergeHostContext(initialized?.hostContext);
    bridge.notify("ui/notifications/initialized");
    sizes.start();
    setNotice(
      hostCanCall
        ? "Connected. Reading authoritative state…"
        : "Connected. Invoke a Remap tool to populate this view.",
      false,
    );
    if (hostCanCall) await refresh();
  } catch (error) {
    const message =
      error instanceof Error
        ? error.message
        : "The host could not complete MCP Apps initialization.";
    setNotice(message, true);
  }
};

void initialize();
