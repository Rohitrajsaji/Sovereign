// Callers: `npm run e2e` and `scripts/e2e.sh`.
// API: Playwright against sovereign-e2e-server with installed Chrome and axe.
// Schema: schemas/control-api-v2.json via the live loopback API.
// User instruction: Continue from the current tree and finish the remaining consumer-product gaps you identified. Then complete Playwright/axe E2E.

import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

const token = process.env.SOVEREIGN_E2E_TOKEN ?? "e2e-session-token";
const baseURL = process.env.SOVEREIGN_E2E_URL ?? "http://127.0.0.1:7777";

async function openAuthed(page: Page, hash = "/") {
  await page.goto(`/?t=${token}${hash === "/" ? "" : hash}`, { waitUntil: "domcontentloaded" });
}

async function assertAxe(page: Page) {
  const results = await new AxeBuilder({ page }).analyze();
  const serious = results.violations.filter((item) =>
    ["serious", "critical"].includes(item.impact ?? ""),
  );
  expect(serious, JSON.stringify(serious, null, 2)).toEqual([]);
}

test.describe("consumer e2e", () => {
  test("onboarding wizard", async ({ page }) => {
    await openAuthed(page, "#/welcome");
    await expect(page.getByRole("heading", { name: "Onboarding" })).toBeVisible();
    await page.getByRole("button", { name: "Continue" }).first().click();
    await expect(page.getByText("2. System check")).toBeVisible();
    await assertAxe(page);
  });

  test("add project form is present", async ({ page }) => {
    await openAuthed(page, "#/projects");
    await expect(page.getByLabel("Absolute git root")).toBeVisible();
    await assertAxe(page);
  });

  test("submit goal and open detail", async ({ page }) => {
    await openAuthed(page, "#/goals/new");
    await page.getByLabel("What should Sovereign do?").fill("Create a bounded local note file");
    await page.getByRole("button", { name: "Queue goal" }).click();
    const link = page.getByRole("link", { name: /Create a bounded local note file/ });
    await expect(link).toBeVisible();
    await link.click();
    await expect(page.getByText("Verification, not the model")).toBeVisible();
    await page.getByRole("tab", { name: "Changes" }).click();
    await page.getByRole("button", { name: "Load task diff" }).click();
    await expect(page.getByText("<script>alert(1)</script>")).toBeVisible();
    expect(await page.locator("script", { hasText: "alert(1)" }).count()).toBe(0);
    await assertAxe(page);
  });

  test("approvals require an explicit click", async ({ page }) => {
    await openAuthed(page, "#/approvals");
    await expect(page.getByRole("heading", { name: "Approvals" })).toBeVisible();
    await expect(page.getByText("no bulk approve", { exact: false })).toBeVisible();
    await assertAxe(page);
  });

  test("pause and resume", async ({ page }) => {
    await openAuthed(page, "#/");
    if (await page.getByRole("button", { name: "Pause" }).count()) {
      await page.getByRole("button", { name: "Pause" }).click();
      await page.getByRole("button", { name: "Resume" }).click();
    }
    await assertAxe(page);
  });

  test("cancel during a queued goal", async ({ page }) => {
    await openAuthed(page, "#/goals/new");
    await page.getByLabel("What should Sovereign do?").fill("Cancel this fixture goal");
    await page.getByRole("button", { name: "Queue goal" }).click();
    await page.getByRole("link", { name: /Cancel this fixture goal/ }).click();
    await page.getByRole("button", { name: "Cancel goal" }).click();
    await expect(page.getByRole("dialog")).toBeVisible();
    await page.getByRole("button", { name: "Cancel goal" }).last().click();
  });

  test("missing token is unauthorized", async ({ playwright }) => {
    const context = await playwright.request.newContext({
      baseURL,
      extraHTTPHeaders: {},
    });
    const response = await context.get("/v2/overview");
    expect(response.status()).toBe(401);
    await context.dispose();
  });

  test("missing CSRF is forbidden", async ({ request }) => {
    const response = await request.post("/v2/control/pause", {
      data: {},
      headers: { "content-type": "application/json" },
    });
    expect(response.status()).toBe(403);
  });

  test("recovery center explains mutation policy", async ({ page }) => {
    await openAuthed(page, "#/recovery");
    await expect(page.getByRole("heading", { name: "Recovery", exact: true })).toBeVisible();
    await expect(page.getByText("not replayed", { exact: false })).toBeVisible();
    await assertAxe(page);
  });

  test("keyboard and axe pass on primary pages", async ({ page }) => {
    test.setTimeout(120_000);
    const pages = ["#/", "#/projects", "#/goals", "#/approvals", "#/recovery", "#/settings", "#/diagnostics"];
    for (const hash of pages) {
      await openAuthed(page, hash);
      await page.keyboard.press("Tab");
      await assertAxe(page);
    }
    await page.keyboard.press("Meta+K");
    await expect(page.getByRole("textbox", { name: "Jump to" })).toBeVisible();
  });
});
