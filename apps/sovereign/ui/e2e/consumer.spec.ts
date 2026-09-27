// Callers: `npm run e2e` and `scripts/e2e.sh`.
// API: the consumer journey against sovereign-e2e-server (a starter project, the fixture model,
// the live preview) with axe on every main view.
// Schema: schemas/control-api-v2.json via the live loopback API.

import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

const token = process.env.SOVEREIGN_E2E_TOKEN ?? "e2e-session-token";
const baseURL = process.env.SOVEREIGN_E2E_URL ?? "http://127.0.0.1:7777";

async function open(page: Page, { onboarded }: { onboarded: boolean }) {
  if (onboarded) {
    await page.addInitScript(() => window.localStorage.setItem("sovereign.onboarding.done", "1"));
  }
  await page.goto(`/?t=${token}`, { waitUntil: "domcontentloaded" });
}

async function assertAxe(page: Page) {
  const results = await new AxeBuilder({ page }).analyze();
  const serious = results.violations.filter((item) => ["serious", "critical"].includes(item.impact ?? ""));
  expect(serious, JSON.stringify(serious, null, 2)).toEqual([]);
}

async function send(page: Page, text: string) {
  await page.getByLabel("Describe what you want").fill(text);
  await page.getByRole("button", { name: "Send" }).click();
  await expect(page.getByText(text, { exact: true }).first()).toBeVisible();
}

test.describe("consumer journey", () => {
  test("onboarding explains itself and can be finished later", async ({ page }) => {
    await open(page, { onboarded: false });
    await expect(page.getByRole("heading", { name: "Build apps by describing them." })).toBeVisible();
    await assertAxe(page);
    await page.getByRole("button", { name: "Get started" }).click();
    await expect(page.getByRole("heading", { name: "Getting ready" })).toBeVisible();
    // Exact matches: on a small runner, a problem line also mentions "This Mac".
    await expect(page.getByText("This Mac", { exact: true })).toBeVisible();
    await expect(page.getByText(/^Local AI model/)).toBeVisible();
    await assertAxe(page);
    await page.getByRole("button", { name: "Set up later" }).click();
    await expect(page.getByRole("navigation", { name: "Projects" })).toBeVisible();
  });

  test("the starter project previews in a sandboxed frame on its own origin", async ({ page }) => {
    await open(page, { onboarded: true });
    const frame = page.getByTitle("Preview of your app");
    await expect(frame).toBeVisible();
    const src = (await frame.getAttribute("src")) ?? "";
    expect(new URL(src).hostname).toBe("localhost");
    expect(new URL(src).origin).not.toBe(new URL(baseURL).origin);
    expect(await frame.getAttribute("sandbox")).not.toContain("allow-top-navigation");
    await expect(page.frameLocator('iframe[title="Preview of your app"]').getByRole("heading", { name: "Fixture" })).toBeVisible();
    await assertAxe(page);
  });

  test("a request shows up as a conversation with live progress and details", async ({ page }) => {
    await open(page, { onboarded: true });
    await send(page, "Make a page that says hello");
    await expect(page.locator(".reply").first()).toBeVisible();
    await page.getByRole("button", { name: "Details" }).first().click();
    await expect(page.getByRole("tab", { name: "Details", selected: true })).toBeVisible();
    await expect(page.getByRole("complementary").getByText("Make a page that says hello")).toBeVisible();
    await assertAxe(page);
  });

  test("request text is shown as text, never as markup", async ({ page }) => {
    await open(page, { onboarded: true });
    const hostile = '<img src=x onerror="window.pwned=1"> make it red';
    await send(page, hostile);
    expect(await page.evaluate(() => (window as unknown as { pwned?: number }).pwned)).toBeUndefined();
    expect(await page.locator(".conversation img").count()).toBe(0);
  });

  test("a request can be cancelled after a confirmation", async ({ page }) => {
    await open(page, { onboarded: true });
    await send(page, "Cancel this fixture request");
    const turn = page.getByRole("article", { name: /Cancel this fixture request/ });
    const stop = turn.getByRole("button", { name: /^(Stop|Cancel)$/ });
    await stop.click();
    await expect(page.getByRole("dialog")).toBeVisible();
    await page.getByRole("button", { name: /^(Stop|Cancel) request$/ }).click();
    await expect(turn.getByText(/Cancelled|Stopping/).first()).toBeVisible({ timeout: 15_000 });
  });

  test("files are listed and shown read-only", async ({ page }) => {
    await open(page, { onboarded: true });
    await page.getByRole("tab", { name: "Files" }).click();
    await expect(page.getByRole("button", { name: /index\.html/ })).toBeVisible();
    await expect(page.getByLabel("Contents of index.html")).toContainText("<title>Fixture</title>");
    await assertAxe(page);
  });

  test("settings and help open, explain, and close from the keyboard", async ({ page }) => {
    await open(page, { onboarded: true });
    await page.getByRole("button", { name: "Settings" }).click();
    await expect(page.getByRole("dialog", { name: "Settings" })).toBeVisible();
    // Every pinned model has a card with its size and what it needs.
    await expect(page.getByRole("heading", { name: "Qwen3 1.7B", level: 4 })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Qwen3 4B", level: 4 })).toBeVisible();
    await expect(page.getByText(/GB download · best with \d+ GB of memory/).first()).toBeVisible();
    await page.getByText("Advanced").click();
    await expect(page.getByRole("list", { name: "Diagnostics" })).toBeVisible();
    await assertAxe(page);
    await page.keyboard.press("Escape");
    await expect(page.getByRole("dialog")).toHaveCount(0);
    await page.getByRole("button", { name: "Help" }).click();
    await expect(page.getByRole("heading", { name: "Does anything leave my Mac?" })).toBeVisible();
    await page.keyboard.press("Escape");
  });

  test("a second project can be created and becomes active", async ({ page }) => {
    await open(page, { onboarded: true });
    await page.getByRole("button", { name: "New project" }).click();
    const name = page.getByLabel("Project name");
    await name.fill("Second app");
    await expect(page.getByRole("button", { name: "Create" })).toBeEnabled();
    // Enter, not a click: the dialog opens over the preview, a cross-origin frame. For a moment
    // after it opens, Chrome can still route a click at those coordinates into that frame.
    await name.press("Enter");
    await expect(page.getByRole("heading", { level: 1, name: "Second app" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Second app" })).toHaveAttribute("aria-current", "true");
  });

  test("the API refuses a missing session and a missing CSRF header", async ({ playwright, request }) => {
    const anonymous = await playwright.request.newContext({ baseURL, extraHTTPHeaders: {} });
    expect((await anonymous.get("/v2/overview")).status()).toBe(401);
    await anonymous.dispose();
    const response = await request.post("/v2/control/pause", {
      data: {},
      headers: { "content-type": "application/json" },
    });
    expect(response.status()).toBe(403);
  });
});
