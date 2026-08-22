import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { expect, type Page, test } from "@playwright/test";

type JsonRecord = Record<string, unknown>;
type RevisionPair = [number, number];

const root = resolve(import.meta.dirname, "../..");

const dashboardDocument = async (): Promise<string> => {
  const app = resolve(root, "crates/remap-mcp/app");
  const [template, style, script, manifest] = await Promise.all([
    readFile(resolve(app, "dashboard.html"), "utf8"),
    readFile(resolve(app, "dashboard.css"), "utf8"),
    readFile(resolve(app, "dashboard.js"), "utf8"),
    readFile(resolve(root, "Cargo.toml"), "utf8"),
  ]);
  const version = manifest.match(/^version = "([^"]+)"/m)?.[1];
  if (version === undefined) throw new Error("workspace version is missing");
  return template
    .replace("__REMAP_STYLE__", style)
    .replace("__REMAP_SCRIPT__", script.replaceAll("</script", "<\\/script"))
    .replace("__REMAP_VERSION__", version);
};

const installHost = async (
  page: Page,
  app: string,
  serverTools: unknown,
  revisions: RevisionPair[],
): Promise<void> => {
  const responses = hostResponses(revisions);
  await page.evaluate(
    ({ documentText, tools, toolResponses, initialContext }) => {
      const iframe = document.getElementById("app") as HTMLIFrameElement;
      const host = window as typeof window & { hostMessages: JsonRecord[] };
      let responseIndex = 0;
      host.hostMessages = [];
      addEventListener("message", (event: MessageEvent<unknown>) => {
        const message = event.data as JsonRecord;
        host.hostMessages.push(message);
        if (message.method === "ui/initialize") {
          const result = {
            protocolVersion: "2026-01-26",
            hostInfo: { name: "remap-test-host", version: "1" },
            hostCapabilities: { serverTools: tools },
            hostContext: initialContext,
          };
          setTimeout(
            () =>
              iframe.contentWindow?.postMessage({ jsonrpc: "2.0", id: message.id, result }, "*"),
            30,
          );
          return;
        }
        if (message.method !== "tools/call") return;
        const result = toolResponses[Math.min(responseIndex, toolResponses.length - 1)];
        responseIndex += 1;
        iframe.contentWindow?.postMessage({ jsonrpc: "2.0", id: message.id, result }, "*");
      });
      iframe.srcdoc = documentText;
    },
    {
      documentText: app,
      tools: serverTools,
      toolResponses: responses,
      initialContext: initialHostContext(),
    },
  );
};

const hostResponses = (revisions: RevisionPair[]): JsonRecord[] => {
  return revisions.flatMap(([statusRevision, listRevision]) => [
    hostResult(statusRevision, statusData(statusRevision)),
    hostResult(listRevision, { revision: listRevision, mappings: [mapping()] }),
  ]);
};

const hostResult = (revision: number, data: JsonRecord): JsonRecord => {
  if (revision >= 0) {
    return { structuredContent: { summary: "Current.", data }, isError: false };
  }
  const error = {
    code: "E_REFRESH",
    message: "Refresh failed.",
    retryable: true,
    context: { outcome: "unknown" },
  };
  return { structuredContent: { summary: "Refresh failed.", data: error }, isError: true };
};

const mount = async (
  page: Page,
  serverTools: unknown = null,
  revisions: RevisionPair[] = [[1, 1]],
): Promise<void> => {
  await page.setContent('<iframe id="app" title="Remap dashboard"></iframe>');
  await installHost(page, await dashboardDocument(), serverTools, revisions);
  const notice = page.frameLocator("#app").locator("#notice");
  const expected =
    serverTools === null ? "Connected." : /Connected|Registry state is current|Refresh failed/;
  await expect(notice).toContainText(expected);
};

const mountWithInitialization = async (page: Page, result: JsonRecord): Promise<void> => {
  await page.setContent('<iframe id="app" title="Remap dashboard"></iframe>');
  await page.evaluate(
    ({ documentText, initializeResult }) => {
      const iframe = document.getElementById("app") as HTMLIFrameElement;
      const host = window as typeof window & { hostMessages: JsonRecord[] };
      host.hostMessages = [];
      addEventListener("message", (event: MessageEvent<unknown>) => {
        const message = event.data as JsonRecord;
        host.hostMessages.push(message);
        if (message.method !== "ui/initialize") return;
        iframe.contentWindow?.postMessage(
          { jsonrpc: "2.0", id: message.id, result: initializeResult },
          "*",
        );
      });
      iframe.srcdoc = documentText;
    },
    { documentText: await dashboardDocument(), initializeResult: result },
  );
};

const send = async (page: Page, method: string, params: unknown, id?: number): Promise<void> => {
  await page.evaluate(
    ({ sentMethod, sentParams, sentId }) => {
      const iframe = document.getElementById("app") as HTMLIFrameElement;
      iframe.contentWindow?.postMessage(
        { jsonrpc: "2.0", method: sentMethod, params: sentParams, id: sentId },
        "*",
      );
    },
    { sentMethod: method, sentParams: params, sentId: id },
  );
};

const toolResult = (summary: string, data: unknown, isError = false): JsonRecord => ({
  isError,
  structuredContent: { summary, data },
});

const mapping = (pattern = "atlas", target = "127.0.0.1:5173"): JsonRecord => ({
  pattern,
  target,
  target_kind: "socket",
  host_policy: "preserve-client",
  enabled: true,
  updated_revision: 1,
});

const runtimeErrors = (page: Page): string[] => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("console", (message) => {
    if (["error", "warning"].includes(message.type())) errors.push(message.text());
  });
  return errors;
};

test("renders status and paginated lists without stale outcomes", async ({ page }) => {
  const errors = runtimeErrors(page);
  await mount(page);
  const frame = page.frameLocator("#app");
  await send(page, "ui/notifications/tool-result", toolResult("Failed.", errorData(), true));
  await expect(frame.locator("#outcome")).toContainText("E_TEST");
  await send(page, "ui/notifications/tool-result", toolResult("Status.", statusData(3)));
  await expect(frame.locator("#outcome")).toBeHidden();
  await expect(frame.locator("#revision")).toHaveText("3");
  await send(page, "ui/notifications/tool-result", toolResult("List.", listData(3)));
  await expect(frame.locator("#mappings")).toContainText("atlas");
  await expect(frame.locator("#mappings")).toContainText("preserve-client");
  await expect(frame.locator("#mappings")).toContainText("revision 1");
  await expect(frame.locator("#count")).toContainText("more available");
  const maintenance = {
    ...statusData(4),
    maintenance: {
      code: "E_REGISTRY_CHECKPOINT",
      message: "The private journal is awaiting retention maintenance.",
      hint: "Release the other registry reader.",
      retryable: true,
    },
  };
  await send(page, "ui/notifications/tool-result", toolResult("Status.", maintenance));
  await send(page, "ui/notifications/tool-result", toolResult("List.", listData(4)));
  await expect(frame.locator("#notice")).toContainText("New mutations are blocked");
  await expect(frame.locator("#notice")).toContainText("Release the other registry reader");
  await expect(frame.locator("#notice")).toHaveClass(/bad/);
  await send(page, "ui/notifications/tool-result", toolResult("Newer list.", listData(5)));
  await expect(frame.locator("#revision")).toHaveText("5");
  await expect(frame.locator("#maintenance")).toContainText("New mutations are blocked");
  await send(page, "ui/notifications/tool-result", toolResult("Found atlas.", mapping()));
  await expect(frame.locator("#notice")).toContainText("Found atlas");
  await expect(frame.locator("#maintenance")).toContainText("New mutations are blocked");
  await expect(frame.locator("#maintenance")).toContainText("Release the other registry reader");
  await expect(frame.locator("#maintenance")).toBeVisible();
  expect(errors).toEqual([]);
});

test("renders exact lookup, resolution, and validation facts", async ({ page }) => {
  const errors = runtimeErrors(page);
  await mount(page);
  const outcome = page.frameLocator("#app").locator("#outcome");
  await send(page, "ui/notifications/tool-result", toolResult("Found atlas.", mapping()));
  await expect(outcome).toContainText("socket");
  await expect(outcome).toContainText("preserve-client");
  await send(page, "ui/notifications/tool-result", toolResult("No exact mapping.", null));
  await expect(outcome).toContainText("No exact mapping");
  await send(page, "ui/notifications/tool-result", toolResult("Resolved.", resolutionData()));
  await expect(outcome).toContainText("atlas → 127.0.0.1:5173");
  await send(page, "ui/notifications/tool-result", toolResult("Unresolved.", unresolvedData()));
  await expect(outcome).toContainText("missing");
  await send(page, "ui/notifications/tool-result", toolResult("Valid.", validationData()));
  await expect(outcome).toContainText("https");
  expect(errors).toEqual([]);
});

test("renders preview diffs and all five mutation receipts", async ({ page }) => {
  const errors = runtimeErrors(page);
  await mount(page);
  const outcome = page.frameLocator("#app").locator("#outcome");
  const preview = previewData();
  await send(page, "ui/notifications/tool-result", toolResult("Previewed.", preview));
  await expect(outcome).toContainText("127.0.0.1:5173");
  await expect(outcome).toContainText("127.0.0.1:6173");
  for (const tool of ["set", "enable", "disable", "remove", "apply"]) {
    await send(page, "ui/notifications/tool-result", toolResult("Committed.", receipt(tool)));
    await expect(outcome).toContainText(`${tool}-operation`);
    await expect(outcome).toContainText("previous 3");
    await expect(outcome).toContainText("revision 4");
  }
  expect(errors).toEqual([]);
});

test("keeps hostile text inert and describes cancelled outcomes safely", async ({ page }) => {
  const errors = runtimeErrors(page);
  await mount(page);
  const frame = page.frameLocator("#app");
  const hostile = '<img src=x onerror="window.hostile=true">';
  await send(page, "ui/notifications/tool-result", toolResult("List.", listData(1, hostile)));
  await expect(frame.locator("#mappings")).toContainText(hostile);
  expect(await frame.locator("img").count()).toBe(0);
  await send(page, "ui/notifications/tool-result", toolResult("Failed.", errorData(), true));
  await expect(frame.locator("#outcome")).toContainText("not retryable");
  await expect(frame.locator("#outcome")).toContainText("scope: test");
  await send(page, "ui/notifications/tool-cancelled", { reason: "user changed direction" });
  await expect(frame.locator("#outcome")).toContainText("state may have changed");
  await expect(frame.locator("#outcome")).toContainText("user changed direction");
  expect(errors).toEqual([]);
});

test("applies host layout changes and releases lifecycle resources", async ({ page }) => {
  const errors = runtimeErrors(page);
  await mount(page);
  const frame = page.frameLocator("#app");
  await send(page, "ui/notifications/host-context-changed", hostContextUpdate());
  await expect(frame.locator("html")).toHaveAttribute("data-theme", "light");
  await expect(frame.locator("html")).toHaveAttribute("data-display-mode", "fullscreen");
  await expect(frame.locator("html")).toHaveCSS("--container-width", "100vw");
  await expect(frame.locator("html")).toHaveCSS("--container-max-height", "480px");
  await expect(frame.locator("html")).toHaveCSS("--color-text-primary", "rgb(1, 2, 3)");
  await expect
    .poll(
      async () =>
        (await hostMethods(page)).filter((method) => method === "ui/notifications/size-changed")
          .length,
    )
    .toBeGreaterThan(0);
  await send(page, "ui/resource-teardown", {}, 91);
  await expect(frame.locator("#refresh")).toBeDisabled();
  const sizeNotifications = (await hostMethods(page)).filter(
    (method) => method === "ui/notifications/size-changed",
  ).length;
  await send(page, "ui/notifications/host-context-changed", { theme: "dark" });
  await expect(frame.locator("html")).toHaveAttribute("data-theme", "light");
  await page.evaluate(
    () =>
      new Promise<void>((resolve) =>
        requestAnimationFrame(() => requestAnimationFrame(() => resolve())),
      ),
  );
  const methods = await hostMethods(page);
  expect(methods.filter((method) => method === "ui/notifications/size-changed").length).toBe(
    sizeNotifications,
  );
  expect(methods.indexOf("ui/notifications/initialized")).toBeLessThan(
    methods.indexOf("ui/notifications/size-changed"),
  );
  expect(errors).toEqual([]);
});

test("keeps out-of-order registry notifications revision coherent", async ({ page }) => {
  const errors = runtimeErrors(page);
  await mount(page);
  const frame = page.frameLocator("#app");
  await send(page, "ui/notifications/tool-result", toolResult("Status.", statusData(3)));
  await send(page, "ui/notifications/tool-result", toolResult("List.", listData(4)));
  await expect(frame.locator("#revision")).toHaveText("4");
  await expect(frame.locator("#mappings")).toContainText("atlas");
  await send(page, "ui/notifications/tool-result", toolResult("Old status.", statusData(3)));
  await expect(frame.locator("#revision")).toHaveText("4");
  await expect(frame.locator("#notice")).toHaveText("Ignored an older registry snapshot.");
  expect(errors).toEqual([]);
});

test("refreshes through serverTools and retries incoherent snapshots", async ({ page }) => {
  const errors = runtimeErrors(page);
  await mount(page, {}, [
    [1, 2],
    [2, 3],
    [3, 3],
  ]);
  const frame = page.frameLocator("#app");
  await expect(frame.locator("#notice")).toHaveText("Registry state is current.");
  await expect(frame.locator("#revision")).toHaveText("3");
  const calls = await hostCalls(page);
  expect(calls.filter((name) => name === "remap_status")).toHaveLength(3);
  expect(calls.filter((name) => name === "remap_list")).toHaveLength(3);
  expect(errors).toEqual([]);
});

test("preserves a tool-level refresh failure", async ({ page }) => {
  const errors = runtimeErrors(page);
  await mount(page, {}, [[-1, 1]]);
  const frame = page.frameLocator("#app");
  await expect(frame.locator("#notice")).toHaveText("Refresh failed.");
  await expect(frame.locator("#outcome")).toContainText("E_REFRESH");
  await expect(frame.locator("#outcome")).toContainText("outcome: unknown");
  expect(errors).toEqual([]);
});

test("rejects malformed MCP Apps initialization results", async ({ page }) => {
  const errors = runtimeErrors(page);
  for (const result of [
    {
      protocolVersion: "2025-11-25",
      hostInfo: { name: "bad", version: "1" },
      hostCapabilities: {},
      hostContext: {},
    },
    { protocolVersion: "2026-01-26", hostCapabilities: {}, hostContext: {} },
  ]) {
    await mountWithInitialization(page, result);
    const frame = page.frameLocator("#app");
    await expect(frame.locator("#notice")).toContainText("incompatible MCP Apps");
    const methods = await hostMethods(page);
    expect(methods).not.toContain("ui/notifications/initialized");
  }
  expect(errors).toEqual([]);
});

const errorData = (): JsonRecord => ({
  code: "E_TEST",
  message: "Failed.",
  retryable: false,
  context: { scope: "test" },
});
const statusData = (revision: number): JsonRecord => ({
  revision,
  mapping_count: 1,
  enabled_count: 1,
});
const listData = (revision: number, pattern = "atlas"): JsonRecord => ({
  revision,
  mappings: [mapping(pattern)],
  next_cursor: "next-page",
});
const resolutionData = (): JsonRecord => ({ name: "atlas", revision: 3, mapping: mapping() });
const unresolvedData = (): JsonRecord => ({ name: "missing", revision: 3, mapping: null });
const validationData = (): JsonRecord => ({
  pattern: "atlas",
  target: "https://127.0.0.1:9443/",
  target_kind: "https",
  host_policy: "use-upstream",
});

const previewData = (): JsonRecord => ({
  base_revision: 3,
  will_change: true,
  effects: [
    {
      action: "update",
      pattern: "atlas",
      before: mapping("atlas", "127.0.0.1:5173"),
      after: mapping("atlas", "127.0.0.1:6173"),
    },
  ],
});

const receipt = (tool: string): JsonRecord => ({
  operation_id: `${tool}-operation`,
  previous_revision: 3,
  revision: 4,
  changed: true,
  effects: previewData().effects,
});

const hostContextUpdate = (): JsonRecord => ({
  theme: "light",
  displayMode: "fullscreen",
  containerDimensions: { width: 320, maxHeight: 480 },
  styles: { variables: { "--color-text-primary": "rgb(1, 2, 3)" } },
});

const initialHostContext = (): JsonRecord => ({
  theme: "dark",
  locale: "en-US",
  displayMode: "inline",
  safeAreaInsets: { top: 4, right: 3, bottom: 2, left: 1 },
});

const hostCalls = async (page: Page): Promise<unknown[]> =>
  page.evaluate(() => {
    const host = window as typeof window & { hostMessages: JsonRecord[] };
    return host.hostMessages
      .filter((message) => message.method === "tools/call")
      .map((message) => (message.params as JsonRecord).name);
  });

const hostMethods = async (page: Page): Promise<string[]> =>
  page.evaluate(() => {
    const host = window as typeof window & { hostMessages: JsonRecord[] };
    return host.hostMessages
      .map((message) => message.method)
      .filter((method): method is string => typeof method === "string");
  });
