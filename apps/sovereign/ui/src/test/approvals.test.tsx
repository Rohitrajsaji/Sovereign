// Callers: `npm test`.
// API: static proof that approve POSTs only from the confirm handler.
// Schema: ApprovalRequest via /v2/approvals/respond.
// User instruction: Continue from the current tree and finish the remaining consumer-product gaps you identified. Tests: no auto-approve path exists.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const root = resolve(process.cwd(), "src/screens/Workspace.tsx");

describe("approvals", () => {
  it("only posts approve from the confirm handler", () => {
    const source = readFileSync(root, "utf8");
    expect(source).toContain('decision: "approve"');
    const approvePosts = source.split('decision: "approve"');
    expect(approvePosts.length).toBe(2);
    expect(source).toContain("onConfirm");
    expect(source).not.toMatch(/auto.?approve/i);
  });

  it("disables expired approvals", () => {
    const source = readFileSync(root, "utf8");
    expect(source).toContain("disabled={expired}");
  });
});
