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
      return "Waiting for memory or host pressure to ease. Closing other apps frees memory. Sovereign retries on its own.";
    case "error":
      return "The last step recorded an error. Unknown outcomes are not retried.";
    default:
      return "Idle. Queue a bounded goal when you are ready.";
  }
}

// Readable labels for the service's last step. `last_outcome` is the Rust Debug form of
// `ProductionAdvanceOutcome`, or "none" / "error" from the execution service.
const OUTCOME_LABELS: Array<[string, string]> = [
  ["AwaitingApproval", "Waiting for your approval"],
  ["RecoveryRequired", "Recovery required"],
  ["PlanActivated", "Plan compiled and activated"],
  ["TaskVerified", "Task verified"],
  ["TaskFailed", "Task failed verification"],
  ["GoalCompleted", "Goal completed and verified"],
  ["Complete", "All work complete"],
  ["Paused", "Paused"],
  ["Idle", "Idle"],
];

const BLOCK_LABELS: Array<[string, string]> = [
  ["CompilationInputRequired", "Preparing to compile a plan"],
  ["CompilationFailed", "Plan compilation failed"],
  ["CompilationBudgetExhausted", "Plan compilation used its model budget"],
  ["ExecutionInputsRequired", "Preparing the next task"],
  ["BrowserHandoffRequired", "Waiting for the browser step"],
  ["FailedTerminal", "Stopped after a failure that cannot be repaired"],
  ["NoRunnableTask", "No task can run yet"],
  ["Readiness", "Waiting until work can start"],
];

export function outcomeLabel(lastOutcome: string | undefined): string {
  const outcome = (lastOutcome ?? "none").trim();
  if (outcome === "" || outcome === "none") {
    return "Nothing has run yet";
  }
  if (outcome === "error") {
    return "The last step recorded an error";
  }
  if (outcome.startsWith("Blocked")) {
    const match = BLOCK_LABELS.find(([key]) => outcome.includes(`reason: ${key}`));
    return match ? match[1] : "Blocked";
  }
  const match = OUTCOME_LABELS.find(([key]) => outcome === key || outcome.startsWith(`${key} `));
  return match ? match[1] : "Other outcome";
}

export const GOAL_LIMIT = 4000;
