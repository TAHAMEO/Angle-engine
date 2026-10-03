import { test as base, expect, type Page } from "@playwright/test";

import { DEMO_PASSWORD, USERS, type Role } from "./users";
import { freshCode } from "./totp";

export { expect };

type Options = { theme: "dark" | "light" };

/**
 * Every test page is watched: a Content-Security-Policy violation, an uncaught page error, a console error, or a
 * request to any origin other than the app's fails the test. HTTP error statuses the app handles (401 re-auth, 409,
 * 422 refusals…) are logged by Chromium as "Failed to load resource" and are not failures by themselves.
 */
export const test = base.extend<Options>({
  theme: ["dark", { option: true }],
  page: async ({ page, theme, baseURL }, use) => {
    if (theme === "light") {
      await page.addInitScript(() => {
        try {
          window.localStorage.setItem("theme", "light");
        } catch {
          // Sandboxed frames (report previews) have no storage.
        }
      });
    }
    const origin = new URL(baseURL ?? "http://localhost:3000").origin;
    const problems: string[] = [];
    // Chromium does not log every violation to the console (a caught `new Function` probe, for example), so listen
    // for the DOM event in every document.
    await page.exposeFunction("__aeCspViolation", (detail: string) => problems.push(`CSP violation: ${detail}`));
    await page.addInitScript(() => {
      document.addEventListener("securitypolicyviolation", (event) => {
        const report = (window as unknown as { __aeCspViolation?: (detail: string) => void }).__aeCspViolation;
        report?.(`${event.violatedDirective} blocked ${event.blockedURI} (${event.sourceFile}:${event.lineNumber}:${event.columnNumber})`);
      });
    });
    page.on("console", (message) => {
      const text = message.text();
      if (/Content.Security.Policy|Refused to (load|execute|apply|frame|connect)/i.test(text)) {
        problems.push(`CSP violation: ${text.slice(0, 300)}`);
      } else if (
        message.type() === "error" &&
        !text.startsWith("Failed to load resource") &&
        // Report previews render in sandbox="" frames; Playwright's own snapshots probe them and Chromium logs the block.
        !/^Blocked script execution in .* because the document's frame is sandboxed/.test(text)
      ) {
        problems.push(`console error: ${text.slice(0, 300)}`);
      }
    });
    page.on("pageerror", (error) => problems.push(`page error: ${error.message.slice(0, 300)}`));
    page.on("request", (request) => {
      const url = request.url();
      if (url.startsWith("data:") || url.startsWith("blob:") || url === "about:blank") return;
      if (new URL(url).origin !== origin) problems.push(`cross-origin request: ${request.method()} ${url}`);
    });
    await use(page);
    expect(problems, "browser problems during the test").toEqual([]);
  },
});

/** Sign in through the login form (password, then the authenticator code). */
export async function signIn(page: Page, role: Role): Promise<void> {
  const user = USERS[role];
  await page.goto("/login");
  await page.getByLabel("Email").fill(user.email);
  await page.getByLabel("Password").fill(DEMO_PASSWORD);
  await page.getByRole("button", { name: "Continue" }).click();
  const code = page.getByLabel("Authentication code");
  await expect(code).toBeVisible();
  await code.fill(await freshCode(user.email, user.totpSecret));
  await page.getByRole("button", { name: "Verify" }).click();
  await page.waitForURL((url) => !url.pathname.startsWith("/login"));
}

/**
 * Sensitive actions need a password confirmation within the last five minutes (signing in counts), so whether the
 * "Confirm it's you" dialog appears depends on timing. Race it against the action's outcome, confirm when asked
 * (the client then retries the action), and return the outcome.
 */
export async function withStepUp<T>(page: Page, outcome: Promise<T>): Promise<T> {
  const dialog = page.getByRole("dialog", { name: "Confirm it's you" });
  const settled = outcome.then(
    () => "done" as const,
    () => "done" as const,
  );
  const asked = dialog.waitFor({ state: "visible", timeout: 60_000 }).then(
    () => "asked" as const,
    () => "done" as const,
  );
  if ((await Promise.race([settled, asked])) === "asked") {
    await dialog.getByLabel("Password").fill(DEMO_PASSWORD);
    await dialog.getByRole("button", { name: "Confirm" }).click();
  }
  return outcome;
}

/** A toast message (scoped to the notification region: screen-reader announcements repeat the text elsewhere). */
export function toast(page: Page, text: string | RegExp) {
  return page.getByRole("region", { name: /^Notifications/ }).getByText(text);
}

/** The demo investigation's id, looked up through the API with the page's session. */
export async function investigationId(page: Page, title: string): Promise<string> {
  const response = await page.request.get("/api/v1/investigations?limit=100");
  expect(response.ok()).toBeTruthy();
  const items = (await response.json()) as { id: string; title: string }[];
  const match = items.find((item) => item.title === title);
  if (!match) throw new Error(`investigation "${title}" not found`);
  return match.id;
}
