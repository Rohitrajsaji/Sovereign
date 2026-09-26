// Callers: `npm test` / scripts/verify-ui.sh.
// API: plain-language helpers and request notices.
// Schema: GoalView, DownloadProgress.

import { describe, expect, it } from "vitest";
import { goalNotice } from "../lib/notify";
import { formatBytes, permissionPhrase, stageIndex } from "../lib/words";
import { goal } from "./render";

describe("words", () => {
  it("formats sizes the way people read them", () => {
    expect(formatBytes(2_497_280_256)).toBe("2.5 GB");
    expect(formatBytes(11_089_823)).toBe("11 MB");
    expect(formatBytes(512)).toBe("512 bytes");
  });

  it("places every phase on the stepper", () => {
    expect(stageIndex("queued")).toBe(-1);
    expect(stageIndex("planning")).toBe(0);
    expect(stageIndex("waiting_for_you")).toBe(1);
    expect(stageIndex("checking")).toBe(2);
    expect(stageIndex("applying")).toBe(3);
    expect(stageIndex("done")).toBe(4);
  });

  it("describes every permission without jargon", () => {
    for (const permission of [
      "network_read",
      "network_write",
      "package_install",
      "secret_use",
      "external_side_effect",
      "external_intelligence",
      "destructive",
      "browser_interactive",
      "process_exec",
      "repo_write",
      "something_new",
    ]) {
      expect(permissionPhrase(permission)).not.toMatch(/_/);
    }
  });
});

describe("notices", () => {
  it("is quiet on the first snapshot and speaks when a request finishes or needs you", () => {
    const running = goal();
    expect(goalNotice(undefined, [running])).toBeNull();
    expect(goalNotice([running], [running])).toBeNull();
    const done = goal({ phase: "done" });
    expect(goalNotice([running], [done])).toBe("Done: “Make a budget page”.");
    const waiting = goal({ phase: "waiting_for_you" });
    expect(goalNotice([running], [waiting])).toContain("needs your OK");
  });
});
