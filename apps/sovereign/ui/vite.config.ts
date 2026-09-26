// Callers: `npm run build`, `npm run dev`, and `scripts/verify-ui.sh`.
// API: Vite build to `apps/sovereign/ui-dist` with hashed filenames and no source maps.
// Schema: none. Proxies `/v1` and `/v2` to loopback during `vite` dev.
// User instruction: Continue from the current tree and finish the remaining consumer-product gaps you identified. Prioritize turning the existing SPA into the exceptional polished Sovereign UI specified by the plan, using the intended frontend stack.

import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    outDir: "../ui-dist",
    emptyOutDir: true,
    sourcemap: false,
  },
  server: {
    proxy: {
      "/v1": "http://127.0.0.1:7777",
      "/v2": "http://127.0.0.1:7777",
    },
  },
});
