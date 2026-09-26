// Callers: `npm test` / `scripts/verify-ui.sh`.
// API: render + vitest-axe for each design-system component; keyboard dialog/palette.
// Schema: none. Diff fixture includes a script tag to prove text-node rendering.
// User instruction: Continue from the current tree and finish the remaining consumer-product gaps you identified. Tests: one Vitest render test per component, a vitest-axe check, and a keyboard navigation test for the dialog and command palette.

import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { axe } from "vitest-axe";
import { describe, expect, it, vi } from "vitest";
import { PlanGraph } from "../components/PlanGraph";
import {
  AppShell,
  Button,
  Card,
  CodeBlock,
  CommandPalette,
  ConfirmDialog,
  Dialog,
  DiffViewer,
  EmptyState,
  IconButton,
  KeyValue,
  ProgressRing,
  Skeleton,
  StatusPill,
  Tabs,
  Timeline,
  Toast,
  Tooltip,
} from "../components/ui";

async function noAxe(container: HTMLElement) {
  const results = await axe(container);
  expect(results.violations, JSON.stringify(results.violations, null, 2)).toEqual([]);
}

describe("design system", () => {
  it("renders Button", async () => {
    const { container } = render(<Button>Queue</Button>);
    expect(screen.getByRole("button", { name: "Queue" })).toBeInTheDocument();
    await noAxe(container);
  });

  it("renders IconButton", async () => {
    const { container } = render(<IconButton label="Refresh">R</IconButton>);
    expect(screen.getByLabelText("Refresh")).toBeInTheDocument();
    await noAxe(container);
  });

  it("renders StatusPill", async () => {
    const { container } = render(<StatusPill status="queued" />);
    expect(screen.getByText("queued")).toBeInTheDocument();
    await noAxe(container);
  });

  it("renders Card", async () => {
    const { container } = render(<Card title="Service">Ready</Card>);
    expect(screen.getByRole("heading", { name: "Service" })).toBeInTheDocument();
    await noAxe(container);
  });

  it("renders EmptyState", async () => {
    const { container } = render(<EmptyState title="Idle" detail="No goals" />);
    expect(screen.getByText("Idle")).toBeInTheDocument();
    await noAxe(container);
  });

  it("renders Skeleton", async () => {
    const { container } = render(<Skeleton label="Loading service status" />);
    expect(screen.getByText("Loading service status")).toBeInTheDocument();
    await noAxe(container);
  });

  it("renders Toast", async () => {
    const { container } = render(<Toast message="Connected" />);
    expect(screen.getByText("Connected")).toBeInTheDocument();
    await noAxe(container);
  });

  it("renders Tabs", async () => {
    const { container } = render(<Tabs tabs={["Plan", "Activity"]} active="Plan" onChange={() => undefined} />);
    expect(screen.getByRole("tab", { name: "Plan" })).toBeInTheDocument();
    await noAxe(container);
  });

  it("renders Tooltip", async () => {
    const { container } = render(
      <Tooltip text="Pause">
        <Button>Pause</Button>
      </Tooltip>,
    );
    expect(screen.getByRole("button", { name: "Pause" })).toBeInTheDocument();
    await noAxe(container);
  });

  it("renders CodeBlock tokens as text nodes", async () => {
    const { container } = render(<CodeBlock text={"fn main() { let x = 1; // c\n}"} />);
    expect(container.textContent).toContain("fn");
    await noAxe(container);
  });

  it("renders DiffViewer without interpreting HTML", async () => {
    const { container } = render(<DiffViewer diff={"-old\n+new\n<script>alert(1)</script>\n"} />);
    expect(container.querySelector("script")).toBeNull();
    expect(container.textContent).toContain("<script>alert(1)</script>");
    await noAxe(container);
  });

  it("renders KeyValue", async () => {
    const { container } = render(<KeyValue items={[["phase", "idle"]]} />);
    expect(screen.getByText("idle")).toBeInTheDocument();
    await noAxe(container);
  });

  it("renders Timeline", async () => {
    const { container } = render(<Timeline items={[{ id: "1", title: "goal queued", detail: "goal" }]} />);
    expect(screen.getByText("goal queued")).toBeInTheDocument();
    await noAxe(container);
  });

  it("renders ProgressRing", async () => {
    const { container } = render(<ProgressRing value={40} />);
    expect(screen.getByRole("meter")).toHaveAttribute("aria-valuenow", "40");
    await noAxe(container);
  });

  it("renders AppShell navigation", async () => {
    const { container } = render(
      <MemoryRouter>
        <AppShell message="Ready" onOpenPalette={() => undefined}>
          <p>body</p>
        </AppShell>
      </MemoryRouter>,
    );
    expect(screen.getByRole("navigation", { name: "Primary" })).toBeInTheDocument();
    await noAxe(container);
  });

  it("supports keyboard close on Dialog", async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    const { container } = render(
      <Dialog open title="Cancel this goal?" onClose={onClose}>
        <p>Dispatched side effects stay unknown.</p>
      </Dialog>,
    );
    expect(screen.getByRole("dialog", { name: "Cancel this goal?" })).toBeInTheDocument();
    await user.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalled();
    await noAxe(container);
  });

  it("supports keyboard close on CommandPalette", async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    const { container } = render(<CommandPalette open onClose={onClose} onNavigate={() => undefined} />);
    expect(screen.getByRole("textbox", { name: "Jump to" })).toBeInTheDocument();
    await user.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalled();
    await noAxe(container);
  });

  it("renders ConfirmDialog", async () => {
    const { container } = render(
      <ConfirmDialog
        open
        title="Confirm approval"
        confirmLabel="Approve"
        onClose={() => undefined}
        onConfirm={() => undefined}
      >
        <p>Type approve</p>
      </ConfirmDialog>,
    );
    expect(screen.getByRole("button", { name: "Approve" })).toBeInTheDocument();
    await noAxe(container);
  });

  it("renders a 16-node plan graph", async () => {
    const tasks = Array.from({ length: 16 }, (_, index) => ({
      task_id: `t${index}`,
      state: index % 2 === 0 ? "queued" : "running",
      title: `Task ${index}`,
    }));
    const { container } = render(<PlanGraph tasks={tasks} />);
    expect(screen.getByLabelText("Task graph")).toBeInTheDocument();
    await noAxe(container);
  });
});
