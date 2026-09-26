// Callers: `npm test` / scripts/verify-ui.sh.
// API: the three onboarding steps, the Continue gate, the model download, and Set up later.
// Schema: SetupStatus from control-api-v2.

import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { axe } from "vitest-axe";
import type { SetupStatus } from "../api/generated";
import { Onboarding } from "../screens/Onboarding";
import { mockApi, renderWithProviders } from "./render";

function setup(overrides: Partial<SetupStatus> = {}): SetupStatus {
  return {
    schema_version: 1,
    machine: { supported: true, apple_silicon: true, memory_mib: 16384, free_disk_mib: 204800, problems: [] },
    developer_tools: { installed: true, detail: "Apple's Command Line Tools are installed." },
    model: { id: "qwen3-4b-q4_k_m", display_name: "Qwen3 4B", size_bytes: 2_497_280_256 },
    runtime_ready: false,
    model_ready: false,
    download: { phase: "idle", bytes_done: 0, bytes_total: 0, percent: 0, detail: "" },
    ready: false,
    ...overrides,
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("onboarding", () => {
  it("walks from welcome to getting ready and gates Continue on setup", async () => {
    const onDone = vi.fn();
    const { container } = renderWithProviders(
      <Onboarding setup={setup()} hasProjects={true} onRecheck={() => undefined} onDone={onDone} />,
    );
    expect(screen.getByRole("heading", { name: "Build apps by describing them." })).toBeInTheDocument();
    expect((await axe(container)).violations).toEqual([]);
    await userEvent.click(screen.getByRole("button", { name: "Get started" }));
    expect(screen.getByRole("heading", { name: "Getting ready" })).toBeInTheDocument();
    expect(screen.getByText(/16 GB memory/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Continue" })).toBeDisabled();
    expect((await axe(container)).violations).toEqual([]);
    await userEvent.click(screen.getByRole("button", { name: "Set up later" }));
    expect(onDone).toHaveBeenCalledOnce();
  });

  it("starts the one-time model download", async () => {
    const calls = mockApi({
      "POST /v2/setup/model/download": {
        download: { phase: "checking", bytes_done: 0, bytes_total: 0, percent: 0, detail: "Checking." },
      },
    });
    renderWithProviders(
      <Onboarding setup={setup()} hasProjects={false} initialStep={1} onRecheck={() => undefined} onDone={() => undefined} />,
    );
    expect(screen.getByText(/one-time download of 2.5 GB/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Download" }));
    await waitFor(() => expect(calls.map((call) => call.path)).toContain("/v2/setup/model/download"));
  });

  it("shows download progress with a pause button", () => {
    renderWithProviders(
      <Onboarding
        setup={setup({
          download: {
            phase: "downloading_model",
            bytes_done: 1_200_000_000,
            bytes_total: 2_497_280_256,
            percent: 48,
            detail: "Downloading Qwen3 4B.",
          },
        })}
        hasProjects={false}
        initialStep={1}
        onRecheck={() => undefined}
        onDone={() => undefined}
      />,
    );
    expect(screen.getByRole("progressbar", { name: "Model download" })).toHaveAttribute("aria-valuenow", "48");
    expect(screen.getByText("1.2 GB of 2.5 GB")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Pause" })).toBeInTheDocument();
  });

  it("explains an unsupported Mac instead of offering a download that cannot work", () => {
    renderWithProviders(
      <Onboarding
        setup={setup({
          machine: {
            supported: false,
            apple_silicon: false,
            memory_mib: 8192,
            free_disk_mib: 100000,
            problems: ["Sovereign runs on Macs with Apple silicon (M1 or later)."],
          },
        })}
        hasProjects={false}
        initialStep={1}
        onRecheck={() => undefined}
        onDone={() => undefined}
      />,
    );
    expect(screen.getByText(/Apple silicon \(M1 or later\)/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Download" })).toBeDisabled();
  });

  it("creates the first project", async () => {
    const calls = mockApi({
      "POST /v2/projects/create": { cancelled: false },
    });
    const onDone = vi.fn();
    renderWithProviders(
      <Onboarding setup={setup({ ready: true })} hasProjects={false} initialStep={2} onRecheck={() => undefined} onDone={onDone} />,
    );
    const name = screen.getByLabelText("Project name");
    await userEvent.clear(name);
    await userEvent.type(name, "Budget");
    await userEvent.click(screen.getByRole("button", { name: "Create" }));
    await waitFor(() => expect(onDone).toHaveBeenCalledOnce());
    expect(calls[0]?.body).toEqual({ name: "Budget" });
  });
});
