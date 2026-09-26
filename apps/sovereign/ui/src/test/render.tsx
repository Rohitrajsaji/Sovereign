// Callers: component tests.
// API: `renderWithProviders` (query client plus toasts and tooltips), `mockApi` (a fetch stub
// that answers /v2 routes and records every call), and goal fixtures.
// Schema: GoalView from control-api-v2.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render } from "@testing-library/react";
import type { ReactElement } from "react";
import { vi } from "vitest";
import type { GoalView } from "../api/generated";
import { ToastProvider } from "../components/ui";

export function renderWithProviders(ui: ReactElement) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <ToastProvider>{ui}</ToastProvider>
    </QueryClientProvider>,
  );
}

export type ApiCall = { path: string; method: string; body: unknown };

/** Stubs fetch. `routes` maps "METHOD /path" (query string ignored) to a response body. */
export function mockApi(routes: Record<string, unknown>): ApiCall[] {
  const calls: ApiCall[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string, init: RequestInit = {}) => {
      const method = init.method ?? "GET";
      const path = input.split("?")[0] ?? input;
      const body = typeof init.body === "string" && init.body ? JSON.parse(init.body) : undefined;
      calls.push({ path, method, body });
      const key = `${method} ${path}`;
      if (!(key in routes)) {
        return new Response(JSON.stringify({ error: `not found: ${key}` }), { status: 404 });
      }
      return new Response(JSON.stringify(routes[key]), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }),
  );
  return calls;
}

export function goal(overrides: Partial<GoalView> & { phase?: GoalView["progress"]["phase"] } = {}): GoalView {
  const { phase = "building", ...rest } = overrides;
  const terminal = ["done", "not_applied", "undone", "failed", "cancelled"].includes(phase);
  return {
    schema_version: 1,
    goal_id: "goal-1",
    natural_language_goal: "Make a budget page",
    status: terminal ? "completed" : "active_plan",
    submitted_at_ms: 1_700_000_000_000,
    progress: {
      phase,
      headline: "Building",
      sentence: "Step 1 of 2: Create the page",
      steps_done: 0,
      steps_total: 2,
      percent: 31,
      terminal,
    },
    steps: [
      { task_id: "task.a", title: "Create the page", phase: "working" },
      { task_id: "task.b", title: "Add styles", phase: "waiting" },
    ],
    outcome: null,
    queue_position: null,
    landing: null,
    ...rest,
  };
}
