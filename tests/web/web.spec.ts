// SPDX-License-Identifier: GPL-3.0-or-later
import { expect, type Page, test } from "@playwright/test";
import { FakeRemap, mapping, ORIGIN, open, TOKEN } from "./fake.ts";

const seeded = (): FakeRemap =>
  new FakeRemap([
    mapping("api.test"),
    mapping("old.test", { enabled: false, target: "10.0.0.9" }),
    mapping("app.lab", {
      target: "http://127.0.0.1:5173/",
      target_kind: "http",
      host_policy: "use-upstream",
      landing: "/dashboard",
    }),
    mapping("nas.home", {
      target: "supgang://nas/files",
      target_kind: "peer-machine",
      peer_address: "127.77.0.2",
    }),
  ]);

const rows = (page: Page) => page.locator("#mapping-rows tr");
const dialog = (page: Page) => page.locator("#confirm");

const expectCurrent = async (page: Page, revision: number): Promise<void> => {
  await expect(page.locator("#connection")).toHaveText(
    new RegExp(`Current at revision ${revision}\\.`),
  );
};

const fillDraft = async (page: Page, pattern: string, target: string): Promise<void> => {
  await page.getByRole("button", { name: "Add mapping" }).click();
  await page.getByLabel("Name", { exact: true }).fill(pattern);
  await page.getByLabel("Target", { exact: true }).fill(target);
};

let problems: string[] = [];

test.afterEach(() => {
  expect(problems, "the page logged errors or broke its Content Security Policy").toEqual([]);
});

test("moves the token from the address into session storage", async ({ page }) => {
  const fake = seeded();
  problems = await open(page, fake);
  await expectCurrent(page, 3);
  expect(page.url()).toBe(`${ORIGIN}/`);
  expect(await page.evaluate(() => sessionStorage.getItem("remap-web-token"))).toBe(TOKEN);
  expect(fake.requests.every((request) => request.authorization === `Bearer ${TOKEN}`)).toBe(true);
  await page.reload();
  await expectCurrent(page, 3);
  expect(page.url()).toBe(`${ORIGIN}/`);
});

test("without a token it says which address to open", async ({ page }) => {
  const fake = seeded();
  problems = await open(page, fake, "");
  await expect(
    page.getByRole("heading", { name: "Open the address remap web printed" }),
  ).toBeVisible();
  await expect(page.locator("#no-token")).toContainText("#token=");
  await expect(page.locator("#app")).toBeHidden();
  expect(fake.requests).toEqual([]);
});

test("a token the server does not accept is explained", async ({ page }) => {
  const fake = seeded();
  problems = await open(page, fake, `#token=${"cd".repeat(32)}`);
  await expect(page.locator("#connection")).toContainText("This page's token was not accepted.");
  await expect(page.locator("#connection")).toContainText("printed most recently");
  expect(await page.evaluate(() => sessionStorage.getItem("remap-web-token"))).toBeNull();
});

test("lists every mapping with its state in words", async ({ page }) => {
  problems = await open(page, seeded());
  await expect(rows(page)).toHaveCount(4);
  await expect(page.locator("#stat-revision")).toHaveText("3");
  await expect(page.locator("#stat-total")).toHaveText("4");
  await expect(page.locator("#stat-on")).toHaveText("3");
  const old = page.locator('tr[data-pattern="old.test"]');
  await expect(old.locator("td").nth(1)).toHaveText("off");
  await expect(page.locator('tr[data-pattern="api.test"] td').nth(1)).toHaveText("on");
  const app = page.locator('tr[data-pattern="app.lab"] td');
  await expect(app.nth(2)).toHaveText("http://127.0.0.1:5173/");
  await expect(app.nth(3)).toHaveText("http");
  await expect(app.nth(4)).toHaveText("use-upstream");
  await expect(app.nth(5)).toHaveText("/dashboard");
  await expect(app.nth(6)).toHaveText("none");
  await expect(page.locator('tr[data-pattern="nas.home"] td').nth(6)).toHaveText("127.77.0.2");
  await expect(page.getByRole("columnheader", { name: "Host header" })).toBeAttached();
  await expect(page.locator("#count")).toHaveText("Showing 4 of 4 mappings");
});

test("search and the show-off toggle narrow the list", async ({ page }) => {
  problems = await open(page, seeded());
  await page.getByLabel("Search").fill("PEER");
  await expect(rows(page)).toHaveCount(1);
  await expect(rows(page).first()).toHaveAttribute("data-pattern", "nas.home");
  await page.getByLabel("Search").fill("nothing-matches");
  await expect(page.locator("#empty")).toHaveText(/No mapping matches/);
  await page.getByLabel("Search").fill("");
  await page.getByLabel("Show mappings that are off").uncheck();
  await expect(rows(page)).toHaveCount(3);
  await expect(page.locator('tr[data-pattern="old.test"]')).toHaveCount(0);
  await expect(page.locator("#count")).toHaveText("Showing 3 of 4 mappings");
});

test("hostile names are shown as text", async ({ page }) => {
  const name = '<img src=x onerror="document.body.dataset.owned=1">';
  problems = await open(page, new FakeRemap([mapping(name)]));
  await expect(page.locator("#mapping-rows td.name")).toHaveText(name);
  expect(await page.evaluate(() => document.body.dataset.owned)).toBeUndefined();
  expect(await page.locator("#mapping-rows img").count()).toBe(0);
});

test("the form validates with the daemon as the owner types", async ({ page }) => {
  problems = await open(page, seeded());
  await fillDraft(page, "API2.Test", "bad");
  const validation = page.locator("#validation");
  await expect(validation).toContainText("The target is not an address, name or URL.");
  await expect(validation).toContainText("Use an IP address, DNS alias");
  await expect(validation).toHaveClass(/bad/);
  await page.getByLabel("Target", { exact: true }).fill("http://127.0.0.1:9/");
  await expect(validation).toContainText("Valid. Saved as api2.test to http://127.0.0.1:9/ · http");
  await expect(validation).toContainText("Warning: api.test: target refused connection");
});

test("adding previews, confirms, applies and shows the receipt", async ({ page }) => {
  const fake = seeded();
  problems = await open(page, fake);
  await fillDraft(page, "New.Test", "192.0.2.7");
  await page.getByRole("button", { name: "Review change" }).click();
  await expect(dialog(page)).toBeVisible();
  await expect(dialog(page)).toContainText("Against revision 3, this makes 1 change:");
  await expect(dialog(page)).toContainText("Create new.test");
  await expect(dialog(page).locator(".compare dd").first()).toHaveText("none");
  await expect(dialog(page).locator(".compare dd").nth(1)).toHaveText(
    "on · 192.0.2.7 · dns-address · use-upstream",
  );
  await dialog(page).getByRole("button", { name: "Apply" }).click();
  await expect(dialog(page)).toBeHidden();
  await expect(page.locator("#receipt")).toContainText(
    "Applied. The registry moved from revision 3 to 4.",
  );
  await expect(page.locator('tr[data-pattern="new.test"]')).toHaveCount(1);
  await expect(page.locator("#editor")).toBeHidden();
  const [apply] = fake.applies();
  expect(apply?.body?.expected_revision).toBe(3);
  expect(String(apply?.body?.operation_id)).toMatch(
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
  );
  await expect(page.locator("#announcer")).toHaveText("Applied. The registry is at revision 4.");
});

test("a conflict re-reads, explains, and reviews again", async ({ page }) => {
  const fake = seeded();
  problems = await open(page, fake);
  await fillDraft(page, "new.test", "192.0.2.7");
  await page.getByRole("button", { name: "Review change" }).click();
  await expect(dialog(page)).toContainText("Against revision 3");
  fake.externalChange(mapping("other.test"));
  await dialog(page).getByRole("button", { name: "Apply" }).click();
  const error = page.locator("#confirm-error");
  await expect(error).toContainText("The registry changed while you were reviewing");
  await expect(error).toContainText("The registry is at revision 4, not the expected revision 3.");
  await expect(page.locator('tr[data-pattern="other.test"]')).toHaveCount(1);
  await dialog(page).getByRole("button", { name: "Review again" }).click();
  await expect(dialog(page)).toContainText("Against revision 4");
  await expect(error).toBeHidden();
  await dialog(page).getByRole("button", { name: "Apply" }).click();
  await expect(page.locator("#receipt")).toContainText("from revision 4 to 5");
  const [first, second] = fake.applies();
  expect(second?.body?.expected_revision).toBe(4);
  expect(second?.body?.operation_id).not.toBe(first?.body?.operation_id);
});

test("a lost answer is retried with the same operation ID", async ({ page }) => {
  const fake = seeded();
  problems = await open(page, fake);
  fake.faults.loseNextApplyAnswer = true;
  await page
    .locator('tr[data-pattern="api.test"]')
    .getByRole("button", { name: "Remove api.test" })
    .click();
  await expect(dialog(page)).toContainText("Remove api.test");
  await dialog(page).getByRole("button", { name: "Apply" }).click();
  await expect(page.locator("#confirm-error")).toContainText("No answer arrived");
  await expect(page.locator("#confirm-error")).toContainText("same operation ID");
  await dialog(page).getByRole("button", { name: "Retry" }).click();
  await expect(page.locator("#receipt")).toContainText("from revision 3 to 4");
  const [first, second] = fake.applies();
  expect(second?.body?.operation_id).toBe(first?.body?.operation_id);
  expect(fake.revision).toBe(4);
  await expect(page.locator('tr[data-pattern="api.test"]')).toHaveCount(0);
});

test("an unreachable daemon is said plainly and retried", async ({ page }) => {
  const fake = seeded();
  fake.faults.daemonDown = true;
  problems = await open(page, fake);
  const connection = page.locator("#connection");
  await expect(connection).toContainText("The Remap daemon is not answering.");
  await expect(connection).toContainText("Run 'remap doctor' for the exact service recovery path");
  await expect(connection).toContainText("Trying again in 1 second.");
  await expect(connection).toHaveClass(/bad/);
  fake.faults.daemonDown = false;
  await expectCurrent(page, 3);
  await expect(rows(page)).toHaveCount(4);
  await expect(page.locator("#announcer")).toHaveText("Connected again. The registry is current.");
});

test("changes made elsewhere appear without a reload", async ({ page }) => {
  const fake = seeded();
  problems = await open(page, fake);
  await expect(rows(page)).toHaveCount(4);
  fake.externalChange(mapping("live.test"));
  await expect(page.locator('tr[data-pattern="live.test"]')).toHaveCount(1);
  await expectCurrent(page, 4);
});

test("status problems are described in words", async ({ page }) => {
  const fake = seeded();
  fake.status = {
    maintenance: {
      code: "E_REGISTRY_CHECKPOINT",
      message: "checkpoint is blocked",
      retryable: true,
    },
    dns_upstream: {
      code: "E_DNS_UPSTREAM_UNANSWERED",
      message: "no upstream answered",
      retryable: true,
    },
    dns_turned_off: {
      turned_off_at: "2026-10-31T01:20Z",
      turned_off_at_ms: 0,
      command: "remap-system deactivate",
      turn_on: "sudo remap-system activate",
    },
    peer_machine_listeners: {
      listening: 1,
      not_listening: 1,
      failures: [failure()],
    },
  };
  problems = await open(page, fake);
  const list = page.locator("#problems");
  await expect(list).toContainText("Changes are paused for maintenance. Checkpoint is blocked.");
  await expect(list).toContainText("Upstream DNS is not answering. No upstream answered.");
  await expect(list).toContainText("System DNS is off.");
  await expect(list.locator("code")).toHaveText("sudo remap-system activate");
  await expect(list).toContainText("1 peer listener is not listening.");
  await expect(list).toContainText(
    "nas.home files on 127.77.0.2:445: Another program has it. (port-in-use)",
  );
});

const failure = () => ({
  pattern: "nas.home",
  service: "files",
  address: "127.77.0.2",
  port: 445,
  cause: "port-in-use",
  detail: "Another program has it.",
});

test("the resolve tester names the mapping a lookup uses", async ({ page }) => {
  problems = await open(page, seeded());
  await page.getByLabel("Name to resolve").fill("API.test");
  await page.getByRole("button", { name: "Resolve" }).click();
  await expect(page.locator("#resolve-result")).toContainText(
    "api.test uses api.test: on · 127.0.0.1",
  );
  await page.getByLabel("Name to resolve").fill("old.test");
  await page.keyboard.press("Enter");
  await expect(page.locator("#resolve-result")).toContainText("matches no mapping");
});

test("the confirm dialog works from the keyboard alone", async ({ page, browserName }) => {
  const fake = seeded();
  problems = await open(page, fake);
  const toggle = page.getByRole("button", { name: "Turn off api.test" });
  await toggle.focus();
  await page.keyboard.press("Enter");
  await expect(dialog(page)).toContainText("Turn off api.test");
  await expect(dialog(page).getByRole("button", { name: "Cancel" })).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(dialog(page)).toBeHidden();
  await expect(toggle).toBeFocused();
  expect(fake.applies()).toEqual([]);
  await page.keyboard.press("Enter");
  await expect(dialog(page)).toContainText("Against revision 3");
  // Safari moves focus to buttons with Option-Tab unless the owner turns on
  // "Press Tab to highlight each item"; WebKit here behaves the same.
  await page.keyboard.press(browserName === "webkit" ? "Alt+Tab" : "Tab");
  const apply = dialog(page).getByRole("button", { name: "Apply" });
  await expect(apply).toBeFocused();
  expect(await apply.evaluate((element) => getComputedStyle(element).outlineStyle)).toBe("solid");
  await page.keyboard.press("Enter");
  await expect(page.locator("#receipt")).toContainText("from revision 3 to 4");
  await expect(page.locator('tr[data-pattern="api.test"] td').nth(1)).toHaveText("off");
  await expect(page.locator("#receipt-title")).toBeFocused();
});

test("light and dark follow the system setting", async ({ page }) => {
  problems = await open(page, seeded());
  const background = () => page.evaluate(() => getComputedStyle(document.body).backgroundColor);
  await page.emulateMedia({ colorScheme: "light" });
  expect(await background()).toBe("rgb(244, 244, 239)");
  await page.emulateMedia({ colorScheme: "dark" });
  expect(await background()).toBe("rgb(17, 20, 17)");
  const state = page.locator('tr[data-pattern="api.test"] .state');
  expect(await state.evaluate((element) => getComputedStyle(element).color)).toBe(
    "rgb(114, 197, 164)",
  );
});

test("phone width has a 16px gutter and no horizontal scroll", async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 800 });
  const long = `${"very-long-label-".repeat(6)}name.test`;
  problems = await open(page, new FakeRemap([mapping(long, { target: `http://${long}/a/b/c` })]));
  await expect(rows(page)).toHaveCount(1);
  const overflow = () =>
    page.evaluate(
      () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
    );
  expect(await overflow()).toBe(0);
  const gutter = await page
    .locator(".shell")
    .evaluate((element) => getComputedStyle(element).paddingLeft);
  expect(gutter).toBe("16px");
  await fillDraft(page, long, "192.0.2.1");
  await page.getByRole("button", { name: "Review change" }).click();
  await expect(dialog(page)).toContainText("Against revision 3");
  expect(await overflow()).toBe(0);
});
