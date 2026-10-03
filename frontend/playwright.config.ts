import { defineConfig, devices } from "@playwright/test";

/**
 * End-to-end tests against the production build (`next build` with ANGEL_DEV_API_ORIGIN, then `next start`, so the
 * real nonce CSP applies) and a disposable backend seeded with the offline demo (scripts/e2e-backend.sh).
 *
 *   ANGEL_DEV_API_ORIGIN=http://127.0.0.1:8000 pnpm build && pnpm e2e
 *
 * E2E_REUSE_SERVERS=1 reuses an API and web server that are already running (for iterating on one spec; the data
 * is then not reset). E2E_SCREENSHOTS=1 saves a screenshot of every page the accessibility scan visits.
 */
const BASE_URL = process.env.E2E_BASE_URL ?? "http://localhost:3000";
const reuse = process.env.E2E_REUSE_SERVERS === "1";
const desktop = { ...devices["Desktop Chrome"], viewport: { width: 1440, height: 900 } };

export default defineConfig<{ theme: "dark" | "light" }>({
  testDir: "./e2e",
  outputDir: "./test-results",
  fullyParallel: false,
  workers: 1, // one shared, stateful backend
  retries: 0,
  forbidOnly: Boolean(process.env.CI),
  timeout: 120_000,
  expect: { timeout: 15_000 },
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }], ["github"]] : [["list"]],
  use: {
    baseURL: BASE_URL,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    acceptDownloads: true,
    locale: "en-GB",
    timezoneId: "UTC",
    colorScheme: "dark",
  },
  projects: [
    { name: "setup", testMatch: /auth\.setup\.ts/, use: desktop },
    { name: "desktop-dark", testMatch: /\.spec\.ts$/, dependencies: ["setup"], use: desktop },
    {
      name: "desktop-light",
      testMatch: /a11y\.spec\.ts$/,
      dependencies: ["setup"],
      use: { ...desktop, colorScheme: "light", theme: "light" },
    },
    { name: "mobile", testMatch: /a11y\.spec\.ts$/, dependencies: ["setup"], use: { ...devices["Pixel 7"] } },
  ],
  webServer: [
    {
      command: "bash ../scripts/e2e-backend.sh",
      url: "http://127.0.0.1:8000/api/v1/health/ready",
      timeout: 300_000,
      reuseExistingServer: reuse,
      stdout: "pipe",
      stderr: "pipe",
      env: { E2E_BASE_URL: BASE_URL },
    },
    {
      command: "pnpm start",
      url: `${BASE_URL}/login`,
      timeout: 120_000,
      reuseExistingServer: reuse,
      stdout: "ignore",
      stderr: "pipe",
    },
  ],
});
