import { expect, investigationId, signIn, test } from "./support/fixtures";
import { DEMO_INVESTIGATION } from "./support/users";

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
