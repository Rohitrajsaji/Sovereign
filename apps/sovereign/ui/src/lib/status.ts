// Callers: `StatusPill`, home hero, and goal list filters.
// API: maps Controller status strings to tone and label.
// Schema: TaskState, ServiceStatus, approval status from control-api-v2.
// User instruction: Continue from the current tree and finish the remaining consumer-product gaps you identified. Badge/StatusPill mapped from TaskState, ServiceStatus, and approval status.

export type Tone = "success" | "warning" | "danger" | "info";

export function statusTone(status: string): Tone {
  if (/fail|error|blocked|denied|unknown|critical/i.test(status)) {
    return "danger";
  }
  if (/warn|pause|defer|wait|expir|queued|pending/i.test(status)) {
    return "warning";
  }
  if (/pass|run|complete|success|idle|loaded|approve/i.test(status)) {
    return "success";
  }
  return "info";
}

export function phaseCopy(phase: string, paused: boolean): string {
  if (paused) {
    return "Paused. The Controller will not dispatch new work.";
  }
  switch (phase) {
    case "running":
      return "The Controller is advancing a queued goal.";
    case "waiting_for_approval":
      return "An action is waiting for an explicit Approve or Deny.";
    case "recovery_blocked":
      return "Mutation is blocked until recovery finishes.";
    case "deferred_resource":
      return "Work is deferred for memory or host pressure.";
    case "error":
      return "The last step recorded an error. Unknown outcomes are not retried.";
    default:
      return "Idle. Queue a bounded goal when you are ready.";
  }
}

export const GOAL_LIMIT = 4000;
