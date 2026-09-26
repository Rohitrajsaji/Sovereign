// Callers: `npm test` / scripts/verify-ui.sh.
// API: the workspace while a chosen project waits for the current step, and after it opens.
// Schema: ProjectsResponse, OverviewResponse, GoalView, PreviewResponse from control-api-v2.

import { screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { OverviewResponse, ProjectRecord, SetupStatus } from "../api/generated";
import { Workspace } from "../screens/Workspace";
import { goal, mockApi, renderWithProviders } from "./render";

function project(project_id: string, display_name: string): ProjectRecord {
  return {
    project_id,
    display_name,
    root: `/Users/ana/Sovereign Projects/${display_name}`,
    state_path: `/state/${project_id}/state.sqlite3`,
    cas_root: `/state/${project_id}/cas`,
    created_at_ms: 1_700_000_000_000,
    managed: true,
  };
}

function overview(pendingSwitch: boolean): OverviewResponse {
  return {
    schema_version: 1,
    service_phase: "running",
    active_project: "First app",
    paused: false,
    working: true,
    pending_commands: pendingSwitch ? [{ ticket: 7, kind: "switch_project", accepted_at_ms: 1 }] : [],
  };
}

const readySetup = { ready: true, model_ready: true, runtime_ready: true } as SetupStatus;

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("workspace", () => {
  it("shows a chosen project as opening until the service switches, then reloads it", async () => {
    const routes: Record<string, unknown> = {
      "GET /v2/projects": {
        schema_version: 1,
        active_project_id: "second",
        projects: [project("first", "First app"), project("second", "Second app")],
      },
      "GET /v2/overview": overview(true),
      // Until the switch applies, reads still come from the previous project.
      "GET /v2/goals": [goal({ natural_language_goal: "A request in the first app" })],
      "GET /v2/settings": { schema_version: 1, execute_on_start: true, approval_principal: "ana" },
      "GET /v2/preview": { available: true, url: "http://localhost:7778/p/abc/" },
    };
    mockApi(routes);
    renderWithProviders(<Workspace setup={readySetup} onOpenSetup={() => undefined} />);

    expect(await screen.findByRole("heading", { level: 1, name: "Second app" })).toBeInTheDocument();
    expect(
      await screen.findByText("Opening Second app. Sovereign finishes its current step first."),
    ).toBeInTheDocument();
    expect(screen.queryByText("A request in the first app")).toBeNull();
    expect(screen.queryByTitle("Preview of your app")).toBeNull();

    routes["GET /v2/overview"] = overview(false);
    routes["GET /v2/goals"] = [];
    expect(await screen.findByTitle("Preview of your app", {}, { timeout: 4000 })).toBeInTheDocument();
    await waitFor(() => expect(screen.queryByText(/^Opening Second app/)).toBeNull());
    expect(screen.queryByText("A request in the first app")).toBeNull();
  });
});
