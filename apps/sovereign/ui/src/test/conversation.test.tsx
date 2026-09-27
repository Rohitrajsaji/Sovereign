// Callers: `npm test` / scripts/verify-ui.sh.
// API: every reply card state, its actions, approvals, and text-node rendering of untrusted text.
// Schema: GoalView, ApprovalRequest from control-api-v2.

import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { axe } from "vitest-axe";
import type { ApprovalRequest } from "../api/generated";
import { GoalTurn } from "../components/Conversation";
import { goal, mockApi, renderWithProviders } from "./render";

const noop = () => undefined;

function turn(props: Partial<Parameters<typeof GoalTurn>[0]> & { goal: Parameters<typeof GoalTurn>[0]["goal"] }) {
  return renderWithProviders(
    <GoalTurn
      approvals={[]}
      principal="ana@mac"
      onShowPreview={noop}
      onDetails={noop}
      onRetry={noop}
      {...props}
    />,
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("reply cards", () => {
  it("shows live progress with the current stage and a real progress bar", async () => {
    const { container } = turn({ goal: goal() });
    expect(screen.getByRole("heading", { name: "Building" })).toBeInTheDocument();
    expect(screen.getByText("Step 1 of 2")).toBeInTheDocument();
    expect(screen.getByRole("progressbar", { name: "Request progress" })).toHaveAttribute("aria-valuenow", "31");
    const current = screen.getByText("Building", { selector: "li" });
    expect(current).toHaveAttribute("aria-current", "step");
    expect((await axe(container)).violations).toEqual([]);
  });

  it("renders the person's words and step titles as text, never as markup", () => {
    const hostile = '<img src=x onerror="alert(1)"><script>alert(2)</script>';
    const { container } = turn({
      goal: goal({
        natural_language_goal: hostile,
        steps: [{ task_id: "task.a", title: hostile, phase: "working" }],
      }),
    });
    expect(screen.getAllByText(hostile).length).toBe(2);
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
  });

  it("asks before stopping and then stops the request", async () => {
    const calls = mockApi({
      "POST /v2/goals/goal-1/cancel": { accepted: true, applied: false, ticket: 3, message: "Stopping." },
    });
    turn({ goal: goal() });
    await userEvent.click(screen.getByRole("button", { name: "Stop" }));
    expect(screen.getByRole("dialog", { name: "Stop this request?" })).toBeInTheDocument();
    expect(calls).toHaveLength(0);
    await userEvent.click(screen.getByRole("button", { name: "Stop request" }));
    await waitFor(() => expect(calls.map((call) => call.path)).toEqual(["/v2/goals/goal-1/cancel"]));
    expect(await screen.findByText("Stopping.")).toBeInTheDocument();
  });

  it("offers Open preview and Undo on a landed result", async () => {
    const calls = mockApi({
      "POST /v2/goals/goal-1/undo": {
        goal_id: "goal-1",
        status: "undone",
        commit: "abc",
        undo_commit: "def",
        changed_paths: [],
        detail: null,
        technical_detail: null,
        updated_at_ms: 2,
      },
    });
    const onShowPreview = vi.fn();
    turn({
      onShowPreview,
      goal: goal({
        phase: "done",
        progress: {
          phase: "done",
          headline: "Done",
          sentence: "Finished, checked, and saved in your project.",
          steps_done: 0,
          steps_total: 0,
          percent: 100,
          terminal: true,
        },
        landing: {
          goal_id: "goal-1",
          status: "landed",
          commit: "abc",
          undo_commit: null,
          changed_paths: ["index.html", "app.js"],
          detail: null,
          technical_detail: null,
          updated_at_ms: 1,
        },
      }),
    });
    expect(screen.getByRole("list", { name: "Changed files" })).toHaveTextContent("index.html");
    await userEvent.click(screen.getByRole("button", { name: "Open preview" }));
    expect(onShowPreview).toHaveBeenCalledOnce();
    await userEvent.click(screen.getByRole("button", { name: "Undo" }));
    await waitFor(() => expect(calls.map((call) => call.path)).toEqual(["/v2/goals/goal-1/undo"]));
  });

  it("shows an Undo waiting for the current request, without offering Undo again", () => {
    turn({
      goal: goal({
        phase: "done",
        progress: {
          phase: "done",
          headline: "Done",
          sentence: "Undo will happen as soon as the current request finishes.",
          steps_done: 0,
          steps_total: 0,
          percent: 100,
          terminal: true,
        },
        landing: {
          goal_id: "goal-1",
          status: "undo_queued",
          commit: "abc",
          undo_commit: null,
          changed_paths: ["index.html"],
          detail: "Undo will happen as soon as the current request finishes.",
          technical_detail: null,
          updated_at_ms: 2,
        },
      }),
    });
    expect(screen.getByText("Undo will happen as soon as the current request finishes.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Undo" })).toBeNull();
  });

  it("offers Apply when a result could not be applied, with the reason", async () => {
    const calls = mockApi({ "POST /v2/goals/goal-1/apply": { accepted: true, applied: false, ticket: 9, message: "Soon." } });
    turn({
      goal: goal({
        phase: "not_applied",
        progress: {
          phase: "not_applied",
          headline: "Not applied yet",
          sentence: "Your project folder has unsaved changes to files this result also changes.",
          steps_done: 0,
          steps_total: 0,
          percent: 100,
          terminal: true,
        },
      }),
    });
    expect(screen.getByText(/unsaved changes/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(calls.map((call) => call.path)).toEqual(["/v2/goals/goal-1/apply"]));
    expect(await screen.findByText("Soon.")).toBeInTheDocument();
  });

  it("lets a failed request be tried again with the same words", async () => {
    const onRetry = vi.fn();
    turn({
      onRetry,
      goal: goal({
        phase: "failed",
        progress: {
          phase: "failed",
          headline: "Didn't finish",
          sentence: "The local model couldn't make a plan for this request.",
          steps_done: 0,
          steps_total: 0,
          percent: 0,
          terminal: true,
        },
      }),
    });
    await userEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(onRetry).toHaveBeenCalledWith("Make a budget page");
  });

  it("describes an approval in plain words and needs an explicit click", async () => {
    const calls = mockApi({ "POST /v2/approvals/respond": { status: "approved" } });
    const approval: ApprovalRequest = {
      schema_version: 1,
      request_id: "approval-1",
      action_id: "action-1",
      plan_id: "plan-1",
      plan_revision: 1,
      task_id: "task.a",
      permission_class: "network_read",
      execution_epoch: 1,
      expires_at_ms: 1_700_000_600_000,
      status: "pending",
    };
    const { container } = turn({
      goal: goal({ phase: "waiting_for_you" }),
      approvals: [approval],
    });
    expect(screen.getByText(/download something from the internet/)).toBeInTheDocument();
    expect(screen.getByRole("group", { name: "Sovereign needs your OK" })).toHaveTextContent("Create the page");
    expect(calls).toHaveLength(0);
    await userEvent.click(screen.getByRole("button", { name: "Allow" }));
    await waitFor(() =>
      expect(calls[0]).toEqual({
        path: "/v2/approvals/respond",
        method: "POST",
        body: { request_id: "approval-1", decision: "approve", principal: "ana@mac" },
      }),
    );
    expect((await axe(container)).violations).toEqual([]);
  });
});

describe("waiting requests", () => {
  it("offers Cancel, not Stop, before a request has started", async () => {
    turn({
      goal: goal({
        status: "queued_for_plan_compilation",
        phase: "queued",
        steps: [],
        progress: {
          phase: "queued",
          headline: "Queued",
          sentence: "Waiting for 1 request ahead of it.",
          steps_done: 0,
          steps_total: 0,
          percent: 0,
          terminal: false,
        },
      }),
    });
    expect(screen.queryByRole("button", { name: "Stop" })).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.getByRole("dialog", { name: "Cancel this request?" })).toBeInTheDocument();
  });
});
