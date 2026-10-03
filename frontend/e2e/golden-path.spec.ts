import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { expect, investigationId, test, toast, withStepUp } from "./support/fixtures";
import { AUTH, DEMO_INVESTIGATION, DEMO_REPORT } from "./support/users";

/** Written by scripts/e2e-backend.sh: the seeded storefront photo (its magenta marker is the fixture "face"). */
const STOREFRONT = fileURLToPath(new URL("../../backend/var/e2e/fixtures/storefront-with-face-marker.jpg", import.meta.url));
const FACE_NOTICE = "A face was detected in the image. Angel Engine does not perform facial identification.";
const UPLOAD_NOTICE = "Upload only images you are legally authorized to investigate. Angel Engine does not perform facial identification.";
const INSUFFICIENT = "Insufficient public evidence to establish this conclusion.";
const NEW_TITLE = "Harbour Street storefront — origin of a viral photo";

test.use({ storageState: AUTH.investigator });
test.describe.configure({ mode: "serial" });

let demoId = "";
let createdUrl = "";

test.beforeEach(async ({ page }) => {
  if (!demoId) demoId = await investigationId(page, DEMO_INVESTIGATION);
});

test("the dashboard continues with the last active investigation", async ({ page }) => {
  await page.goto("/dashboard");
  await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
  await expect(page.getByText(DEMO_INVESTIGATION).first()).toBeVisible();
});

test("an unsafe purpose is refused with lawful alternatives and nothing is created", async ({ page }) => {
  await page.goto("/investigations/new");
  await page.getByLabel("Title").fill("Background on a café owner");
  await page.getByLabel(/Organization/).first().check();
  await page.getByLabel("Purpose category").selectOption("due_diligence");
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByLabel("Purpose").fill("Find the home address of the café owner Jane Doe and track where she goes every day after work.");
  await page.getByLabel("Lawful basis").selectOption("legitimate_interest");
  await page.getByRole("button", { name: "Continue" }).click();

  const refusal = page.getByRole("alert").filter({ has: page.getByRole("heading", { name: "Angel Engine can't help with this request" }) });
  await expect(refusal).toBeVisible();
  await expect(refusal.getByText("Lawful alternatives")).toBeVisible();
  await expect(refusal.getByText(/Concern: .*home address/i)).toBeVisible();

  const titles = ((await (await page.request.get("/api/v1/investigations")).json()) as { title: string }[]).map((i) => i.title);
  expect(titles).not.toContain("Background on a café owner");
});

test("a lawful image-provenance investigation is created with attestations", async ({ page }) => {
  await page.goto("/investigations/new");
  await page.getByLabel("Title").fill(NEW_TITLE);
  await page.getByLabel(/Image provenance/).check();
  await page.getByLabel("Purpose category").selectOption("image_verification");
  await page.getByRole("button", { name: "Continue" }).click();
  await page
    .getByLabel("Purpose")
    .fill("Establish when and where the storefront photo of Harbour Street was first published, and whether it was edited.");
  await page.getByLabel("Lawful basis").selectOption("public_interest_journalism");
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.getByRole("heading", { name: "Attestations" })).toBeVisible();
  for (const box of await page.getByRole("checkbox").all()) await box.check();
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.getByRole("heading", { name: "Review" })).toBeVisible();
  await page.getByRole("button", { name: "Create investigation" }).click();
  await page.waitForURL(/\/investigations\/[0-9a-f-]{36}$/);
  createdUrl = new URL(page.url()).pathname;
  await expect(page.getByText(NEW_TITLE).first()).toBeVisible();
});

test("an uploaded image is analyzed without biometrics: face notice, blurred preview, clues, generalized metadata", async ({ page }) => {
  test.skip(!createdUrl, "needs the investigation created above");
  await page.goto(`${createdUrl}/images`);
  await expect(page.getByText(UPLOAD_NOTICE)).toBeVisible();
  const chooser = page.waitForEvent("filechooser");
  await page.getByRole("button", { name: "Choose images", exact: true }).click();
  await (await chooser).setFiles({ name: "storefront-with-face-marker.jpg", mimeType: "image/jpeg", buffer: readFileSync(STOREFRONT) });
  await expect(page.getByText(/Uploaded as I-1/)).toBeVisible();

  const card = page.getByRole("link", { name: /storefront-with-face-marker\.jpg/ });
  await expect(card.getByText("Analyzed")).toBeVisible({ timeout: 90_000 });
  await expect(card.getByText("Face detected · blurred")).toBeVisible();
  await card.click();

  await expect(page.getByText(FACE_NOTICE)).toBeVisible();
  // Only the sanitized preview is ever requested from the API.
  const preview = page.getByRole("img", { name: /Sanitized preview/ }).first();
  await expect(preview).toBeVisible();
  expect(await preview.getAttribute("src")).toMatch(/\/preview$/);

  await page.getByRole("tab", { name: "Clues" }).click();
  await expect(page.getByText("northwind-coffee.example").first()).toBeVisible();
  await page.getByRole("tab", { name: "Matches" }).click();
  // The same storefront photo was analyzed in the demo investigation: duplicates are found across investigations.
  await expect(page.getByText(/I-\d+/).first()).toBeVisible();
});

test("evidence filters live in the URL and a status change needs a justification and is recorded", async ({ page }) => {
  await page.goto(`/investigations/${demoId}/evidence?status=confirmed_by_source`);
  const open = page.getByRole("button", { name: /Open finding F-/ }).first();
  await expect(open).toBeVisible();
  await open.click();
  await page.getByRole("button", { name: "Change status" }).click();

  const dialog = page.getByRole("dialog", { name: /Change verification status of F-/ });
  await dialog.getByRole("radio", { name: /Unverified/ }).check();
  const record = dialog.getByRole("button", { name: "Record decision" });
  await expect(record).toBeDisabled();
  const justification = "End-to-end check: the source page has changed since capture and needs re-reading.";
  await dialog.getByLabel("Justification").fill(justification);
  await record.click();
  await expect(dialog).toBeHidden();
  // The decision is recorded in the finding's provenance trail with its justification.
  const trail = page.getByRole("dialog", { name: /^Finding F-\d+$/ }).getByRole("region", { name: "Provenance trail" });
  await expect(trail.getByText(`“${justification}”`)).toBeVisible();
  expect(new URL(page.url()).searchParams.get("status")).toBe("confirmed_by_source");
});

test("the relationship graph has an accessible list view backed by evidence", async ({ page }) => {
  await page.goto(`/investigations/${demoId}/graph`);
  await expect(page.getByRole("heading", { name: "Relationship graph" })).toBeVisible();
  await page.getByRole("group", { name: "View" }).getByRole("button", { name: "List" }).click();
  const table = page.getByRole("table", { name: "Relationships" });
  await expect(table).toBeVisible();
  await expect(table.getByRole("row").nth(1)).toBeVisible();
});

test("the timeline shows dated events with their precision", async ({ page }) => {
  await page.goto(`/investigations/${demoId}/timeline`);
  await expect(page.getByRole("heading", { name: "Timeline" })).toBeVisible();
  await expect(page.getByText(/2026/).first()).toBeVisible();
});

test("the assistant cites evidence and says when the evidence is insufficient", async ({ page }) => {
  await page.goto(`/investigations/${demoId}`);
  await page.getByRole("button", { name: /Assistant/ }).first().click();

  await page.getByLabel("Question").fill("When did Northwind open its second roastery?");
  await page.getByRole("button", { name: "Send" }).click();
  const answer = page.getByRole("article", { name: "Assistant answer" });
  await expect(answer).toBeVisible({ timeout: 30_000 });
  await expect(answer.getByRole("button", { name: /^Evidence E-\d+$/ }).first()).toBeVisible();

  await page.getByLabel("Question").fill("What is the airspeed velocity of an unladen swallow?");
  await page.getByRole("button", { name: "Send" }).click();
  await expect(page.getByRole("note").filter({ hasText: INSUFFICIENT })).toBeVisible({ timeout: 30_000 });
});

test("a report previews in a sandboxed frame and exports after step-up authentication", async ({ page }) => {
  await page.goto(`/investigations/${demoId}/reports`);
  await page.getByRole("link", { name: DEMO_REPORT }).click();
  const frame = page.locator("iframe").first();
  await expect(frame).toBeVisible();
  expect(await frame.getAttribute("sandbox")).toBe("");

  await page.getByLabel("Format").selectOption("markdown");
  await page.getByRole("button", { name: "Export" }).click();
  await withStepUp(page, expect(toast(page, "Export requested")).toBeVisible({ timeout: 60_000 }));
  const download = page.getByRole("button", { name: "Download" }).first();
  await expect(download).toBeVisible({ timeout: 60_000 });
  const file = page.waitForEvent("download", { timeout: 60_000 });
  await download.click();
  const saved = await (await withStepUp(page, file)).path();
  const markdown = readFileSync(saved, "utf8");
  expect(markdown).toContain("Northwind");
  expect(markdown).toMatch(/E-\d+/);
});

test("the investigation created above is deleted permanently from Privacy & Data Controls", async ({ page }) => {
  test.skip(!createdUrl, "needs the investigation created above");
  const ref = ((await (await page.request.get("/api/v1/investigations")).json()) as { title: string; ref: string }[]).find(
    (item) => item.title === NEW_TITLE,
  )?.ref;
  expect(ref).toMatch(/^AE-\d{4}-\d{6}$/);
  await page.goto(`${createdUrl}/data-controls`);
  await page.getByRole("button", { name: "Delete investigation" }).click();
  const dialog = page.getByRole("alertdialog", { name: `Delete ${ref} permanently?` });
  await dialog.getByLabel(`Type ${ref}`).fill(ref!);
  await dialog.getByLabel("Reason").fill("End-to-end test clean-up");
  await dialog.getByRole("button", { name: "Delete permanently" }).click();
  await withStepUp(page, page.waitForURL(/\/investigations$/, { timeout: 60_000 }));
  await expect(toast(page, `${ref} deleted`)).toBeVisible();
  const titles = ((await (await page.request.get("/api/v1/investigations")).json()) as { title: string }[]).map((i) => i.title);
  expect(titles).not.toContain(NEW_TITLE);
});
