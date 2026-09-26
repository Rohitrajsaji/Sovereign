// Callers: Vite entry from index.html.
// API: mounts the SPA at #root.
// Schema: none.
// User instruction: Continue from the current tree and finish the remaining consumer-product gaps you identified.

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import "./styles.css";

const root = document.getElementById("root");
if (!root) {
  throw new Error("missing root");
}
createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
