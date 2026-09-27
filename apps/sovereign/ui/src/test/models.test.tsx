// Callers: `npm test` / scripts/verify-ui.sh.
// API: the model switcher (download, switch, remove, and the choice while a request runs) and
// "Start anyway" on a request waiting for memory.
// Schema: SetupStatus.models, GoalProgress.memory from control-api-v2.

import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { axe } from "vitest-axe";
import type { ModelOption, SetupStatus } from "../api/generated";
import { GoalTurn } from "../components/Conversation";
import { ModelSwitcher } from "../components/ModelSwitcher";
import { goal, mockApi, renderWithProviders } from "./render";

function option(overrides: Partial<ModelOption>): ModelOption {
  return {
    id: "qwen3-4b-q4_k_m",
    display_name: "Qwen3 4B",
    summary: "Best results.",
    size_bytes: 2_497_280_256,
    recommended_memory_mib: 16_384,
    installed: true,
    selected: true,
    queued: false,
    fits: false,
    recommended: false,
    ...overrides,
  };
}

function setup(models: ModelOption[]): SetupStatus {
  return {
    schema_version: 1,
    machine: { supported: true, apple_silicon: true, memory_mib: 8_192, free_disk_mib: 204_800, problems: [] },
    developer_tools: { installed: true, detail: "" },
    model: { id: "qwen3-4b-q4_k_m", display_name: "Qwen3 4B", size_bytes: 2_497_280_256 },
    models,
    runtime_ready: true,
    model_ready: true,
    download: { phase: "idle", bytes_done: 0, bytes_total: 0, percent: 0, detail: "" },
    ready: true,
  };
}

const small = option({
  id: "qwen3-1.7b",
  display_name: "Qwen3 1.7B",
  summary: "Fits 8 GB Macs.",
  size_bytes: 1_800_000_000,
  recommended_memory_mib: 8_192,
  installed: false,
  selected: false,
  fits: true,
  recommended: true,
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("model switcher", () => {
  it("downloads a model and then switches to it when nothing is running", async () => {
    const routes: Record<string, unknown> = {
      "GET /v2/setup": setup([option({}), small]),
      "GET /v2/goals": [],
      "POST /v2/setup/model/download": { download: { phase: "downloading_model", bytes_done: 0, bytes_total: 1, percent: 0, detail: "" } },
      "POST /v2/models/select": { model_id: "qwen3-1.7b", applies: "now" },
    };
    const calls = mockApi(routes);
    const { container } = renderWithProviders(<ModelSwitcher />);
    expect(await screen.findByText("In use")).toBeInTheDocument();
    expect(screen.getByText("Suggested for this Mac")).toBeInTheDocument();
    expect(screen.getByText(/requests may wait for memory/)).toBeInTheDocument();
    expect((await axe(container)).violations).toEqual([]);

    // The download finishes: the next status shows it installed.
    routes["GET /v2/setup"] = setup([option({}), { ...small, installed: true }]);
    await userEvent.click(screen.getByRole("button", { name: "Download and use" }));
    await waitFor(() =>
      expect(calls.find((call) => call.path === "/v2/setup/model/download")?.body).toEqual({ model_id: "qwen3-1.7b" }),
    );
    await waitFor(() =>
      expect(calls.find((call) => call.path === "/v2/models/select")?.body).toEqual({
        model_id: "qwen3-1.7b",
        when: "now",
      }),
    );
  });

  it("asks what to do with a running request, and can switch after it finishes", async () => {
    const calls = mockApi({
      "GET /v2/setup": setup([option({}), { ...small, installed: true }]),
      "GET /v2/goals": [goal({ natural_language_goal: "A budget page" })],
      "POST /v2/models/select": { model_id: "qwen3-1.7b", applies: "after_current" },
    });
    renderWithProviders(<ModelSwitcher />);
    await userEvent.click(await screen.findByRole("button", { name: "Use this model" }));
    const ask = screen.getByRole("group", { name: "A request is running" });
    expect(ask).toHaveTextContent("A budget page");
    expect(screen.getByRole("button", { name: "Stop it and start again" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "After it finishes" }));
    await waitFor(() =>
      expect(calls.find((call) => call.path === "/v2/models/select")?.body).toEqual({
        model_id: "qwen3-1.7b",
        when: "after_current",
      }),
    );
  });

  it("removes a downloaded model that is not in use", async () => {
    const calls = mockApi({
      "GET /v2/setup": setup([option({}), { ...small, installed: true }]),
      "GET /v2/goals": [],
      "POST /v2/models/remove": { model_id: "qwen3-1.7b", removed: true },
    });
    renderWithProviders(<ModelSwitcher />);
    await userEvent.click(await screen.findByRole("button", { name: "Remove" }));
    await waitFor(() =>
      expect(calls.find((call) => call.path === "/v2/models/remove")?.body).toEqual({ model_id: "qwen3-1.7b" }),
    );
  });
});

describe("waiting for memory", () => {
  it("offers Start anyway only when close, and asks before lending memory", async () => {
    const calls = mockApi({
      "POST /v2/goals/goal-1/start-anyway": { goal_id: "goal-1", lent_mib: 436 },
    });
    const waiting = goal({ status: "queued_for_plan_compilation", phase: "waiting" });
    waiting.progress.headline = "Waiting for memory";
    waiting.progress.memory = { short_mib: 308, can_start_anyway: true };
    const noop = () => undefined;
    renderWithProviders(
      <GoalTurn goal={waiting} approvals={[]} principal="ana" onShowPreview={noop} onDetails={noop} onRetry={noop} />,
    );
    await userEvent.click(screen.getByRole("button", { name: "Start anyway" }));
    expect(screen.getByRole("dialog", { name: "Start anyway?" })).toHaveTextContent("may slow down");
    await userEvent.click(screen.getAllByRole("button", { name: "Start anyway" }).at(-1) as HTMLElement);
    await waitFor(() => expect(calls.map((call) => call.path)).toContain("/v2/goals/goal-1/start-anyway"));
  });

  it("does not offer Start anyway when far short", () => {
    const waiting = goal({ status: "queued_for_plan_compilation", phase: "waiting" });
    waiting.progress.memory = { short_mib: 3_000, can_start_anyway: false };
    const noop = () => undefined;
    renderWithProviders(
      <GoalTurn goal={waiting} approvals={[]} principal="ana" onShowPreview={noop} onDetails={noop} onRetry={noop} />,
    );
    expect(screen.queryByRole("button", { name: "Start anyway" })).toBeNull();
  });
});
