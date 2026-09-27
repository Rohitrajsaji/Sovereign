// Callers: onboarding, conversation cards, side panel, settings.
// API: plain-language formatting for sizes, times, approval permissions, and progress stages.
// Schema: GoalProgress.phase, ApprovalRequest.permission_class, DownloadProgress.

import type { DownloadProgress, FolderSummary, GoalProgress, ProjectFile } from "../api/generated";

export const GOAL_LIMIT = 4000;

export function formatBytes(bytes: number): string {
  if (bytes >= 1_000_000_000) {
    return `${(bytes / 1_000_000_000).toFixed(1)} GB`;
  }
  if (bytes >= 1_000_000) {
    return `${Math.round(bytes / 1_000_000)} MB`;
  }
  if (bytes >= 1_000) {
    return `${Math.round(bytes / 1_000)} KB`;
  }
  return `${bytes} bytes`;
}

export function formatMib(mib: number | null | undefined): string {
  if (mib === null || mib === undefined) {
    return "unknown";
  }
  return `${Math.round(mib / 1024)} GB`;
}

export function clockTime(ms: number): string {
  return new Date(ms).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
}

/** What an approval lets Sovereign do, in words a person can judge. */
export function permissionPhrase(permissionClass: string): string {
  switch (permissionClass) {
    case "network_read":
      return "download something from the internet";
    case "network_write":
      return "send something to the internet";
    case "package_install":
      return "install a software package";
    case "secret_use":
      return "use one of your saved secrets";
    case "external_side_effect":
      return "do something outside this project, such as publishing";
    case "external_intelligence":
      return "send part of this project to an online AI service";
    case "destructive":
      return "delete or overwrite something that can't be recovered";
    case "browser_interactive":
      return "control a web browser";
    case "process_exec":
      return "run a program on your Mac";
    case "repo_write":
      return "change files in this project";
    default:
      return "take an action that needs your OK";
  }
}

export const STAGES = ["Planning", "Building", "Checking", "Done"] as const;

/**
 * Index of the stage a request is in: -1 while it waits to start, 0-3 while it runs, and 4 once
 * everything is finished.
 */
export function stageIndex(phase: GoalProgress["phase"]): number {
  switch (phase) {
    case "received":
    case "queued":
    case "waiting":
      return -1;
    case "planning":
      return 0;
    case "building":
    case "waiting_for_you":
    case "stopping":
      return 1;
    case "checking":
      return 2;
    case "applying":
      return 3;
    default:
      return 4;
  }
}

/**
 * A notice when project files are too big for the planner to read whole, or null. Names at most
 * two files.
 */
export function bigFilesNotice(files: ProjectFile[], limitBytes: number): string | null {
  const big = files.filter((file) => file.size_bytes > limitBytes);
  if (big.length === 0) {
    return null;
  }
  const names = big.slice(0, 2).map((file) => file.path);
  const more = big.length > 2 ? ` and ${big.length - 2} more` : "";
  const subject = `${names.join(" and ")}${more}`;
  return `${subject} ${big.length === 1 ? "is" : "are"} too big for Sovereign to read (it reads files up to ${formatBytes(limitBytes)}). Changes to ${big.length === 1 ? "it" : "them"} may not work well; ask for new features in separate files.`;
}

/** `/Users/ana/Documents` reads as `~/Documents`. */
export function homeRelative(path: string): string {
  return path.replace(/^\/(Users|home)\/[^/]+(?=\/|$)/, "~");
}

/** What adopting a folder means, in sentences, shown before anything is saved. */
export function folderSentences(summary: FolderSummary): string[] {
  if (summary.parent_project) {
    return [
      `This folder is part of a bigger project at ${homeRelative(summary.parent_project)}. Sovereign would work on that whole project.`,
    ];
  }
  if (summary.has_history) {
    return ["This folder already keeps a history. Sovereign works in it and never saves your own changes for you."];
  }
  const count = summary.more_than ? `more than ${summary.file_count.toLocaleString()}` : summary.file_count.toLocaleString();
  const sentences = [
    `Sovereign will start keeping a history of this folder. Everything in it (${count} ${summary.file_count === 1 ? "file" : "files"}, ${formatBytes(summary.total_bytes)}) is saved in that history.`,
  ];
  if (summary.private_files.length > 0) {
    sentences.push(
      `It includes files that may be private, like ${summary.private_files.join(", ")}. They would be saved too.`,
    );
  }
  if (summary.large) {
    sentences.push("That's a lot, so Sovereign may be slow in this folder. A folder with just your app works best.");
  }
  return sentences;
}

export function downloadRunning(download: DownloadProgress | undefined): boolean {
  return Boolean(
    download &&
      ["checking", "downloading_runtime", "downloading_model", "verifying"].includes(download.phase),
  );
}

export function downloadLine(download: DownloadProgress): string {
  if (download.bytes_total > 0 && download.phase.startsWith("downloading")) {
    return `${formatBytes(download.bytes_done)} of ${formatBytes(download.bytes_total)}`;
  }
  return download.detail;
}

export const EXAMPLE_REQUESTS = [
  "A to-do list that remembers my tasks",
  "A tip calculator that splits a bill between friends",
  "A page that tracks my monthly budget with a simple chart",
];
