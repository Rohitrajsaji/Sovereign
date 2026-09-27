// Callers: `npm test` / scripts/verify-ui.sh.
// API: adopting an existing folder only after the person has seen what it means.
// Schema: FolderSummary, POST /v2/projects/inspect and /v2/projects/open from control-api-v2.

import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { axe } from "vitest-axe";
import type { FolderSummary } from "../api/generated";
import { ProjectChooser } from "../components/ProjectChooser";
import { mockApi, renderWithProviders } from "./render";

function summary(overrides: Partial<FolderSummary>): FolderSummary {
  return {
    cancelled: false,
    root: "/Users/ana/Documents",
    name: "Documents",
    has_history: false,
    parent_project: null,
    file_count: 12_345,
    total_bytes: 3_200_000_000,
    more_than: false,
    large: true,
    private_files: [".env", "keys/id_rsa"],
    ...overrides,
  };
}

const openResponse = { cancelled: false };

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("adopting a folder", () => {
  it("shows what would be saved, including private files, and waits for a yes", async () => {
    const calls = mockApi({
      "POST /v2/projects/inspect": summary({}),
      "POST /v2/projects/open": openResponse,
    });
    const onDone = vi.fn();
    const { container } = renderWithProviders(<ProjectChooser onDone={onDone} />);
    await userEvent.click(screen.getByRole("button", { name: /Choose a folder/ }));
    const confirm = await screen.findByRole("group", { name: "Use this folder?" });
    expect(confirm).toHaveTextContent("12,345 files, 3.2 GB");
    expect(confirm).toHaveTextContent("may be private, like .env, keys/id_rsa");
    expect(confirm).toHaveTextContent("may be slow");
    expect(calls.some((call) => call.path === "/v2/projects/open")).toBe(false);
    expect((await axe(container)).violations).toEqual([]);

    await userEvent.click(screen.getByRole("button", { name: "Use this folder" }));
    await waitFor(() =>
      expect(calls.find((call) => call.path === "/v2/projects/open")?.body).toEqual({ root: "/Users/ana/Documents" }),
    );
    await waitFor(() => expect(onDone).toHaveBeenCalled());
  });

  it("offers the bigger project a folder belongs to, or another choice", async () => {
    const calls = mockApi({
      "POST /v2/projects/inspect": summary({
        root: "/Users/ana/code/site",
        name: "site",
        has_history: true,
        parent_project: "/Users/ana/code",
        large: false,
        private_files: [],
      }),
      "POST /v2/projects/open": openResponse,
    });
    renderWithProviders(<ProjectChooser onDone={() => undefined} />);
    await userEvent.click(screen.getByRole("button", { name: /Choose a folder/ }));
    expect(await screen.findByText(/part of a bigger project at ~\/code/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Choose another" }));
    expect(screen.queryByRole("group", { name: "Use this folder?" })).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: /Choose a folder/ }));
    await userEvent.click(await screen.findByRole("button", { name: "Use ~/code" }));
    await waitFor(() =>
      expect(calls.find((call) => call.path === "/v2/projects/open")?.body).toEqual({ root: "/Users/ana/code" }),
    );
  });

  it("does nothing when the folder picker is closed", async () => {
    const calls = mockApi({ "POST /v2/projects/inspect": { ...summary({}), cancelled: true } });
    renderWithProviders(<ProjectChooser onDone={() => undefined} />);
    await userEvent.click(screen.getByRole("button", { name: /Choose a folder/ }));
    await waitFor(() => expect(calls).toHaveLength(1));
    expect(screen.queryByRole("group", { name: "Use this folder?" })).toBeNull();
  });
});
