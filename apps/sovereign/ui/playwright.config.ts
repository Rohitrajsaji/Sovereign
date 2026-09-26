// Callers: `npm run e2e` and `scripts/e2e.sh`.
// API: Playwright against `sovereign-e2e-server` with installed Chrome.
// Schema: `schemas/control-api-v2.json` via the live loopback API.
// User instruction: Continue from the current tree and finish the remaining consumer-product gaps you identified. Then complete Playwright/axe E2E.

import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  retries: 0,
  use: {
    baseURL: process.env.SOVEREIGN_E2E_URL ?? "http://127.0.0.1:7777",
    channel: "chrome",
    extraHTTPHeaders: process.env.SOVEREIGN_E2E_TOKEN
      ? { Cookie: `sovereign_session=${process.env.SOVEREIGN_E2E_TOKEN}` }
      : {},
  },
});
