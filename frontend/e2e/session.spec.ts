import { expect, investigationId, signIn, test } from "./support/fixtures";
import { DEMO_INVESTIGATION, DEMO_PASSWORD, USERS } from "./support/users";

test("warns two minutes before the idle timeout, can extend, and signs out when it passes", async ({ page }) => {
  // Fake timers from the first page load (time keeps flowing until the test jumps ahead).
  await page.clock.install();
  await signIn(page, "viewer");
  await expect(page.getByRole("button", { name: /^Account: / })).toBeVisible();

  await page.clock.fastForward("28:30");
  const warning = page.getByRole("dialog", { name: "Are you still there?" });
  await expect(warning).toBeVisible();
  await warning.getByRole("button", { name: "Stay signed in" }).click();
  await expect(warning).toBeHidden();

  await page.clock.fastForward("30:30");
  await page.waitForURL(/\/login\?reason=idle/);
  await expect(page.getByText("You were signed out after 30 minutes of inactivity.")).toBeVisible();
  expect((await page.request.get("/api/v1/auth/session")).status()).toBe(401);
});

test("leftover cookies from an unfinished or ended sign-in do not block signing in again", async ({ page, context }) => {
  // Stop at the code step and start over: the browser still holds the unfinished sign-in's cookies.
  await page.goto("/login");
  await page.getByLabel("Email").fill(USERS.admin.email);
  await page.getByLabel("Password").fill(DEMO_PASSWORD);
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.getByLabel("Authentication code")).toBeVisible();
  await signIn(page, "admin");
  await expect(page.getByRole("button", { name: /^Account: / })).toBeVisible();

  // The session ends on the server while the browser keeps its cookies (a sleeping laptop, a recreated stack).
  const leftover = await context.cookies();
  await page.getByRole("button", { name: /^Account: / }).click();
  await page.getByRole("menuitem", { name: "Sign out" }).click();
  await page.waitForURL(/\/login/);
  await context.addCookies(leftover);
  await signIn(page, "auditor");
  await expect(page.getByRole("button", { name: /^Account: / })).toBeVisible();
});

test("signing out ends the session and Back does not reveal investigation data", async ({ page }) => {
  await signIn(page, "investigator");
  const id = await investigationId(page, DEMO_INVESTIGATION);
  await page.goto(`/investigations/${id}/evidence`);
  const findings = page.getByRole("button", { name: /Open finding F-/ });
  await expect(findings.first()).toBeVisible();

  await page.getByRole("button", { name: /^Account: / }).click();
  await page.getByRole("menuitem", { name: "Sign out" }).click();
  await page.waitForURL(/\/login/);
  expect((await page.request.get("/api/v1/auth/session")).status()).toBe(401);

  await page.goBack();
  await expect(page).toHaveURL(/\/login/);
  await expect(findings).toHaveCount(0);
});
