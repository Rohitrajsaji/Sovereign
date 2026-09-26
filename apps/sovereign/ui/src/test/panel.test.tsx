// Callers: `npm test` / scripts/verify-ui.sh.
// API: the preview frame's sandbox, the read-only file viewer, and the composer.
// Schema: PreviewResponse, ProjectFilesResponse, ProjectFileContent.

import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Composer } from "../components/Composer";
import { SidePanel } from "../components/SidePanel";
import { mockApi, renderWithProviders } from "./render";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("side panel", () => {
  it("frames the preview from its own origin in a sandbox without top navigation", async () => {
    mockApi({ "GET /v2/preview": { available: true, url: "http://localhost:7778/p/abc/" } });
    renderWithProviders(
      <SidePanel tab="preview" onTabChange={() => undefined} onClose={() => undefined} goal={undefined} reloadKey="k" />,
    );
    const frame = await screen.findByTitle("Preview of your app");
    expect(frame).toHaveAttribute("src", "http://localhost:7778/p/abc/");
    const sandbox = frame.getAttribute("sandbox") ?? "";
    expect(sandbox.split(" ")).toEqual(expect.arrayContaining(["allow-scripts"]));
    expect(sandbox).not.toContain("allow-top-navigation");
    expect(sandbox).not.toContain("allow-popups");
    expect(frame).toHaveAttribute("referrerpolicy", "no-referrer");
  });

  it("shows file contents as text", async () => {
    mockApi({
      "GET /v2/files": { files: [{ path: "index.html", size_bytes: 40 }], truncated: false },
      "GET /v2/files/content": {
        path: "index.html",
        size_bytes: 40,
        binary: false,
        truncated: false,
        text: "<script>alert(1)</script>",
      },
    });
    const { container } = renderWithProviders(
      <SidePanel tab="files" onTabChange={() => undefined} onClose={() => undefined} goal={undefined} reloadKey="k" />,
    );
    expect(await screen.findByText("<script>alert(1)</script>")).toBeInTheDocument();
    expect(container.querySelector("script")).toBeNull();
  });
});

describe("composer", () => {
  it("sends with Enter, keeps Shift+Enter for new lines, and reports a queued request", async () => {
    const calls = mockApi({
      "POST /v2/goals": { accepted: true, applied: false, ticket: 1, message: "Got it." },
    });
    const onSent = vi.fn();
    function Harness() {
      const [value, setValue] = useState("Make a tip calculator");
      return <Composer value={value} onChange={setValue} busyNote={null} onSent={onSent} />;
    }
    renderWithProviders(<Harness />);
    const box = screen.getByLabelText("Describe what you want");
    await userEvent.type(box, "{Shift>}{Enter}{/Shift}");
    expect(calls).toHaveLength(0);
    await userEvent.type(box, "{Enter}");
    await waitFor(() => expect(calls[0]?.body).toEqual({ goal: "Make a tip calculator" }));
    await waitFor(() => expect(onSent).toHaveBeenCalledWith("Got it."));
  });
});
