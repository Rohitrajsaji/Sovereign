// Callers: vitest.config.ts setupFiles.
// API: jest-dom and axe matchers for component tests.
// Schema: none.
// User instruction: Continue from the current tree and finish the remaining consumer-product gaps you identified. Replace placeholder frontend tooling with real tests/linting.

import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach, expect } from "vitest";
import * as matchers from "vitest-axe/matchers";

afterEach(() => {
  cleanup();
});

expect.extend(matchers);

class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}

if (!("ResizeObserver" in globalThis)) {
  Object.defineProperty(globalThis, "ResizeObserver", { value: ResizeObserverStub });
}
