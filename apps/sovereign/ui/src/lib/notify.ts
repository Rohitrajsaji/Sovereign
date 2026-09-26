// Callers: the workspace shell.
// API: `goalNotice` turns two snapshots of requests into one notice, or null; `desktopNotify`.
// Schema: GoalView from control-api-v2. Notices quote the person's own words only, as text.

import type { GoalView } from "../api/generated";

function shortWords(text: string): string {
  const single = text.replace(/\s+/g, " ").trim();
  return single.length > 60 ? `${single.slice(0, 59)}…` : single;
}

/** The notice for the most important change between two snapshots of the same project. */
export function goalNotice(previous: GoalView[] | undefined, next: GoalView[]): string | null {
  if (!previous) {
    return null;
  }
  const before = new Map(previous.map((goal) => [goal.goal_id, goal.progress.phase]));
  for (const goal of next) {
    const was = before.get(goal.goal_id);
    const now = goal.progress.phase;
    if (was === undefined || was === now) {
      continue;
    }
    const words = shortWords(goal.natural_language_goal);
    switch (now) {
      case "waiting_for_you":
        return `Sovereign needs your OK to continue “${words}”.`;
      case "done":
        return `Done: “${words}”.`;
      case "not_applied":
        return `“${words}” is finished but needs your attention.`;
      case "failed":
        return `“${words}” didn't finish.`;
      default:
        break;
    }
  }
  return null;
}

/** Shows a desktop notification only when permission was granted and the tab is hidden. */
export function desktopNotify(message: string): void {
  if (typeof window === "undefined" || !("Notification" in window)) {
    return;
  }
  if (Notification.permission !== "granted" || !document.hidden) {
    return;
  }
  try {
    new Notification("Sovereign", { body: message });
  } catch {
    // Some browsers only allow notifications from a service worker. The in-app notice remains.
  }
}
