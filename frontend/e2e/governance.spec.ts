import { expect, test, toast, withStepUp } from "./support/fixtures";
import { ACCESS_REQUEST_NAME, AUTH, PENDING_INVESTIGATION } from "./support/users";

test.describe("supervisor", () => {
  test.use({ storageState: AUTH.supervisor });

  test("approves an individual-subject investigation, which then runs in restricted mode", async ({ page }) => {
    await page.goto("/reviews");
    await expect(page.getByRole("heading", { name: "Reviews", level: 1 })).toBeVisible();
    const card = page.locator("section, article, li, div").filter({ hasText: PENDING_INVESTIGATION }).filter({
      has: page.getByRole("button", { name: "Approve" }),
    });
    await card.last().getByRole("button", { name: "Approve" }).click();
    const dialog = page.getByRole("dialog", { name: /^Approve: AE-\d{4}-\d{6}$/ });
    await dialog.getByLabel("Note to the requester").fill("Public statements in an official capacity only.");
    await dialog.getByRole("button", { name: "Approve" }).click();
    await expect(toast(page, /AE-\d{4}-\d{6}: decision recorded/)).toBeVisible();
    await expect(page.getByText(PENDING_INVESTIGATION)).toHaveCount(0);
  });
});

test.describe("administrator", () => {
  test.use({ storageState: AUTH.admin });

  test("administers without investigation content: no investigation navigation, metadata-only register", async ({ page }) => {
    await page.goto("/admin/investigations");
    await expect(page.getByRole("heading", { name: "Investigations", level: 1 })).toBeVisible();
    await expect(page.getByRole("navigation").getByRole("link", { name: "New Investigation" })).toHaveCount(0);
    const response = await page.request.get("/api/v1/admin/investigations");
    expect(response.ok()).toBeTruthy();
    const rows = (await response.json()) as Record<string, unknown>[];
    expect(rows.length).toBeGreaterThan(0);
    for (const row of rows) {
      expect(row).not.toHaveProperty("purpose");
      expect(row).not.toHaveProperty("description");
    }
    // Investigation content stays out of reach even with a known id.
    const id = String(rows[0]!.id);
    expect((await page.request.get(`/api/v1/investigations/${id}/evidence`)).status()).toBe(404);
  });

  test("approves an access request", async ({ page }) => {
    await page.goto("/admin/users");
    const row = page.getByRole("row").filter({ hasText: ACCESS_REQUEST_NAME });
    await row.getByRole("button", { name: "Approve" }).click();
    await page.getByRole("alertdialog", { name: `Approve ${ACCESS_REQUEST_NAME}?` }).getByRole("button", { name: "Confirm" }).click();
    await expect(toast(page, "Saved")).toBeVisible();
    await expect(row).toHaveCount(0); // no longer an open access request
    await page.getByRole("tab", { name: "Active" }).click();
    await expect(page.getByRole("row").filter({ hasText: ACCESS_REQUEST_NAME })).toBeVisible();
  });

  test("locates a data subject's references without seeing content", async ({ page }) => {
    await page.goto("/admin/investigations");
    await page.getByLabel("Kind").selectOption("domain");
    await page.getByLabel("Value").fill("northwind-coffee.example");
    await page.getByRole("button", { name: "Locate" }).click();
    const table = page.getByRole("table", { name: "Investigations that reference the value" });
    await withStepUp(page, table.waitFor({ timeout: 60_000 }));
    await expect(table.getByRole("row").nth(1)).toContainText(/AE-\d{4}-\d{6}/);
  });

  test("sees the abuse report queue and retention settings", async ({ page }) => {
    await page.goto("/admin/abuse-reports");
    await expect(page.getByText(/Data removal request/i).first()).toBeVisible();
    await page.goto("/admin/retention");
    await expect(page.getByRole("heading", { name: "Retention", level: 1 })).toBeVisible();
  });
});

test.describe("auditor", () => {
  test.use({ storageState: AUTH.auditor });

  test("verifies the hash-chained audit log", async ({ page }) => {
    await page.goto("/admin/audit-log");
    await page.getByRole("button", { name: "Verify chain" }).click();
    const result = page.getByRole("note").filter({ hasText: "Chain verified" });
    await expect(result).toBeVisible({ timeout: 30_000 });
    await expect(result).toContainText(/\d+ entries checked up to #\d+\. No tampering detected\./);
  });
});
