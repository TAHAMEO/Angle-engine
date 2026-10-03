import AxeBuilder from "@axe-core/playwright";
import type { Page, TestInfo } from "@playwright/test";

import { expect, investigationId, test } from "./support/fixtures";
import { AUTH, DEMO_INVESTIGATION, DEMO_REPORT, type Role } from "./support/users";

/** WCAG 2.0–2.2 level A and AA rules. */
const TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"];

async function scan(page: Page, testInfo: TestInfo, name: string, path: string): Promise<void> {
  await test.step(name, async () => {
    await page.goto(path);
    await page.waitForLoadState("networkidle");
    // A modal drawer (e.g. ?finding=) hides the rest of the page from the accessibility tree.
    await expect(page.getByRole("main").or(page.getByRole("dialog")).first()).toBeVisible();
    await expect(page.locator('[aria-busy="true"]')).toHaveCount(0, { timeout: 15_000 });
    const { violations } = await new AxeBuilder({ page }).withTags(TAGS).analyze();
    const found = violations.map(
      (v) => `${v.id} [${v.impact}] ${v.help}: ${v.nodes.slice(0, 4).map((n) => n.target.join(" ")).join(" | ")}`,
    );
    if (process.env.E2E_SCREENSHOTS) {
      await page.screenshot({ path: `test-results/screens/${testInfo.project.name}/${name}.png`, fullPage: false });
    }
    expect.soft(found, `accessibility violations on ${name} (${path})`).toEqual([]);
  });
}

async function json<T>(page: Page, url: string): Promise<T> {
  const response = await page.request.get(url);
  expect(response.ok(), url).toBeTruthy();
  return (await response.json()) as T;
}

test.describe("public pages", () => {
  test("are accessible", async ({ page }, testInfo) => {
    for (const [name, path] of [
      ["login", "/login"],
      ["request-access", "/request-access"],
      ["report-abuse", "/report-abuse"],
      ["acceptable-use", "/legal/acceptable-use"],
    ] as const) {
      await scan(page, testInfo, name, path);
    }
  });
});

test.describe("investigator pages", () => {
  test.use({ storageState: AUTH.investigator });

  test("are accessible", async ({ page }, testInfo) => {
    const id = await investigationId(page, DEMO_INVESTIGATION);
    const base = `/investigations/${id}`;
    const api = `/api/v1/investigations/${id}`;
    const image = (await json<{ id: string }[]>(page, `${api}/images`))[0]!;
    const source = (await json<{ items: { id: string }[] }>(page, `${api}/sources?limit=1`)).items[0]!;
    const finding = (await json<{ items: { id: string }[] }>(page, `${api}/findings?limit=1`)).items[0]!;
    const report = (await json<{ id: string; title: string }[]>(page, `${api}/reports`)).find((r) => r.title === DEMO_REPORT)!;

    const pages: [string, string][] = [
      ["dashboard", "/dashboard"],
      ["investigations", "/investigations"],
      ["new-investigation", "/investigations/new"],
      ["overview", base],
      ["images", `${base}/images`],
      ["image-detail", `${base}/images/${image.id}`],
      ["sources", `${base}/sources`],
      ["source-detail", `${base}/sources/${source.id}`],
      ["evidence", `${base}/evidence`],
      ["finding-drawer", `${base}/evidence?finding=${finding.id}`],
      ["timeline", `${base}/timeline`],
      ["graph", `${base}/graph`],
      ["reports", `${base}/reports`],
      ["report-builder", `${base}/reports/${report.id}`],
      ["activity", `${base}/activity`],
      ["investigation-data-controls", `${base}/data-controls`],
      ["account-data-controls", "/data-controls"],
      ["settings-profile", "/settings/profile"],
      ["settings-security", "/settings/security"],
      ["settings-sessions", "/settings/sessions"],
      ["settings-appearance", "/settings/appearance"],
    ];
    for (const [name, path] of pages) await scan(page, testInfo, name, path);
  });
});

const GOVERNANCE: [Role, [string, string][]][] = [
  ["supervisor", [["reviews", "/reviews"]]],
  [
    "admin",
    [
      ["admin-users", "/admin/users"],
      ["admin-investigations", "/admin/investigations"],
      ["admin-connectors", "/admin/connectors"],
      ["admin-retention", "/admin/retention"],
      ["admin-abuse-reports", "/admin/abuse-reports"],
      ["admin-jobs", "/admin/jobs"],
    ],
  ],
  ["auditor", [["audit-log", "/admin/audit-log"]]],
];

for (const [role, pages] of GOVERNANCE) {
  test.describe(`${role} pages`, () => {
    test.use({ storageState: AUTH[role] });

    test("are accessible", async ({ page }, testInfo) => {
      for (const [name, path] of pages) await scan(page, testInfo, name, path);
    });
  });
}
