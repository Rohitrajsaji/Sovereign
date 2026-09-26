// Callers: `npm test` and `scripts/verify-ui.sh`.
// API: Vitest + jsdom for component and axe checks.
// Schema: none.
// User instruction: Continue from the current tree and finish the remaining consumer-product gaps you identified. Prioritize turning the existing SPA into the exceptional polished Sovereign UI specified by the plan, using the intended frontend stack and replacing placeholder frontend tooling with real tests/linting.

import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.test.ts", "src/**/*.test.tsx"],
    css: true,
  },
});
