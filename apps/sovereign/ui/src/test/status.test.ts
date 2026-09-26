// Callers: `npm test`.
// API: every ProductionAdvanceOutcome variant and block reason has readable copy.

import { describe, expect, it } from "vitest";
import { outcomeLabel, phaseCopy } from "../lib/status";
import { transitionNotice } from "../lib/notify";

describe("outcomeLabel", () => {
  it("labels every outcome variant without leaking Debug text", () => {
    const outcomes = [
      "Idle",
      "Paused",
      "RecoveryRequired",
      'AwaitingApproval { action_id: "a", request_id: "r" }',
      'PlanActivated { goal_id: "g", plan_id: "p" }',
      'TaskVerified { task_id: "t" }',
      'TaskFailed { task_id: "t" }',
      'GoalCompleted { goal_id: "g" }',
      'Complete { plan_id: "p" }',
      "none",
      "error",
    ];
    for (const outcome of outcomes) {
      const label = outcomeLabel(outcome);
      expect(label, outcome).not.toBe("Other outcome");
      expect(label).not.toMatch(/[{}]/);
    }
  });

  it("labels every block reason", () => {
    const reasons = [
      "CompilationInputRequired",
      'CompilationFailed("x")',
      "CompilationBudgetExhausted",
      "ExecutionInputsRequired",
      "BrowserHandoffRequired",
      "FailedTerminal",
      "NoRunnableTask",
      'Readiness("waiting for memory")',
    ];
    for (const reason of reasons) {
      const label = outcomeLabel(`Blocked { task_id: None, reason: ${reason} }`);
      expect(label, reason).not.toBe("Blocked");
    }
  });

  it("does not mistake Complete for GoalCompleted", () => {
    expect(outcomeLabel('GoalCompleted { goal_id: "g" }')).toBe("Goal completed and verified");
    expect(outcomeLabel('Complete { plan_id: "p" }')).toBe("All work complete");
  });

  it("explains deferral as a memory wait", () => {
    expect(phaseCopy("deferred_resource", false)).toMatch(/memory/);
  });
});

describe("transitionNotice", () => {
  const base = {
    service_phase: "idle",
    paused: false,
    approval_count: 0,
    unknown_action_count: 0,
    last_outcome: "Idle",
  };

  it("is silent on the first snapshot and when nothing changed", () => {
    expect(transitionNotice(undefined, base)).toBeNull();
    expect(transitionNotice(base, base)).toBeNull();
  });

  it("announces approvals, unknown actions, completion, and blocking phases", () => {
    expect(transitionNotice(base, { ...base, approval_count: 1 })).toMatch(/approval/);
    expect(transitionNotice(base, { ...base, unknown_action_count: 1 })).toMatch(/Recovery/);
    expect(
      transitionNotice(base, { ...base, last_outcome: 'GoalCompleted { goal_id: "g" }' }),
    ).toMatch(/completed/);
    expect(transitionNotice(base, { ...base, service_phase: "recovery_blocked" })).toMatch(
      /recovery/,
    );
    expect(transitionNotice(base, { ...base, service_phase: "deferred_resource" })).toMatch(
      /memory/,
    );
    expect(transitionNotice(base, { ...base, service_phase: "running" })).toBeNull();
  });
});
