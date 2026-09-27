// Callers: `npm test` / scripts/verify-ui.sh.
// API: plain-language helpers and request notices.
// Schema: GoalView, DownloadProgress.

import { describe, expect, it } from "vitest";
import { goalNotice } from "../lib/notify";
import { bigFilesNotice, folderSentences, formatBytes, permissionPhrase, stageIndex } from "../lib/words";
import { goal } from "./render";

describe("words", () => {
  it("names files too big for the planner, and stays quiet otherwise", () => {
    const limit = 12 * 1024;
    expect(bigFilesNotice([{ path: "index.html", size_bytes: 4_000 }], limit)).toBeNull();
    const one = bigFilesNotice([{ path: "index.html", size_bytes: 18_000 }], limit) ?? "";
    expect(one).toMatch(/^index\.html is too big for Sovereign to read/);
    expect(one).toContain("separate files");
    const many = bigFilesNotice(
      [
        { path: "a.js", size_bytes: 20_000 },
        { path: "b.js", size_bytes: 20_000 },
        { path: "c.js", size_bytes: 20_000 },
      ],
      limit,
    );
    expect(many).toMatch(/^a\.js and b\.js and 1 more are too big/);
  });

  it("describes a folder that already keeps a history without warnings", () => {
    const sentences = folderSentences({
      cancelled: false,
      root: "/Users/ana/site",
      name: "site",
      has_history: true,
      parent_project: null,
      file_count: 10,
      total_bytes: 1_000,
      more_than: false,
      large: false,
      private_files: [],
    });
    expect(sentences).toEqual([
      "This folder already keeps a history. Sovereign works in it and never saves your own changes for you.",
    ]);
  });

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
