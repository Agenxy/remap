import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "tests/app",
  fullyParallel: true,
  forbidOnly: true,
  retries: 0,
  reporter: "line",
  timeout: 10_000,
  projects: [
    {
      name: "desktop-chromium",
      use: { browserName: "chromium", viewport: { width: 520, height: 900 } },
    },
    {
      name: "compact-chromium",
      use: { browserName: "chromium", viewport: { width: 320, height: 800 } },
    },
    {
      name: "desktop-webkit",
      use: { browserName: "webkit", viewport: { width: 520, height: 900 } },
    },
    {
      name: "compact-webkit",
      use: { browserName: "webkit", viewport: { width: 320, height: 800 } },
    },
  ],
  use: {
    headless: true,
  },
});
