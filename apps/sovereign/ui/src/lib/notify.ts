// Callers: `Shell` in App.tsx.
// API: `transitionNotice` turns two overview snapshots into one user-facing notice, or null.
// Schema: OverviewResponse from control-api-v2.
// Notices are plain strings rendered as text nodes. They never include repository or model text.

import type { OverviewResponse } from "../api/generated";

type Snapshot = Pick<
  OverviewResponse,
  "service_phase" | "paused" | "approval_count" | "unknown_action_count" | "last_outcome"
>;

export function transitionNotice(previous: Snapshot | undefined, next: Snapshot): string | null {
  if (!previous) {
    return null;
  }
  const approvals = next.approval_count ?? 0;
  if (approvals > (previous.approval_count ?? 0)) {
    return approvals === 1
      ? "An action needs your approval."
      : `${approvals} actions need your approval.`;
  }
  if ((next.unknown_action_count ?? 0) > (previous.unknown_action_count ?? 0)) {
    return "An action has an unknown outcome. Open Recovery before continuing.";
  }
  const completed = (outcome: string | undefined) => (outcome ?? "").startsWith("GoalCompleted");
  if (completed(next.last_outcome) && !completed(previous.last_outcome)) {
    return "A goal completed and passed verification.";
  }
  if (next.service_phase === previous.service_phase) {
    return null;
  }
  switch (next.service_phase) {
    case "recovery_blocked":
      return "Work is blocked until recovery finishes.";
    case "error":
      return "The last step recorded an error.";
    case "deferred_resource":
      return "Work is waiting for memory or host pressure to ease.";
    default:
      return null;
  }
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
