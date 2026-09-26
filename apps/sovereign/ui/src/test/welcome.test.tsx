// Callers: `npm test`.
// API: onboarding step coverage including a doctor failure that blocks Continue.
// Schema: DoctorResponse.
// User instruction: Continue from the current tree and finish the remaining consumer-product gaps you identified. CX-T18 tests: component tests per step; a doctor failure blocks the continue button.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it } from "vitest";
import type { DoctorCheck, ProjectsResponse, SettingsV1 } from "../api/generated";
import { keys } from "../api/query";
import { WelcomeScreen } from "../screens/Welcome";

afterEach(() => {
  cleanup();
});

function renderWelcome(doctor: DoctorCheck[]) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: Infinity, refetchOnMount: false } },
  });
  const projects: ProjectsResponse = { schema_version: 1, active_project_id: null, projects: [] };
  const settings: SettingsV1 = { schema_version: 1, execute_on_start: false, approval_principal: "operator@ui" };
  client.setQueryData(keys.doctor, doctor);
  client.setQueryData(keys.projects, projects);
  client.setQueryData(keys.settings, settings);
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <WelcomeScreen ready />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("onboarding", () => {
  it("walks the welcome step", async () => {
    const user = userEvent.setup();
    renderWelcome([]);
    expect(screen.getByRole("heading", { name: "Onboarding" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Continue" }));
    expect(screen.getByText("System checks passed or only warn.")).toBeInTheDocument();
  });

  it("blocks continue when a doctor check failed", async () => {
    const user = userEvent.setup();
    renderWelcome([
      { id: "sandbox-exec", status: "fail", detail: "missing", fix_hint: "install sandbox-exec" },
    ]);
    await user.click(screen.getByRole("button", { name: "Continue" }));
    expect(screen.getByText("Fix failing doctor checks before continuing.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Continue", description: /failing doctor/i })).toBeDisabled();
  });
});
