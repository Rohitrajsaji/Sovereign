# Controller lifecycle

> Snapshot: HEAD `d266399` (2026-09-24) plus uncommitted work (+3440/−604 across 34 files, observed 2026-09-25). Symbols below were confirmed in that tree. Line numbers drift; search the symbol.

The Controller (`crates/sovereign-controller`) is the only component allowed to commit execution transitions. Models, tools, the CLI, and the dashboard submit requests or render state. They do not own it. See [02-architecture.md](02-architecture.md).

## What `Controller` owns

`Controller` holds a `StateStore`, an optional `ActivePlan`, a `CancellationTree`, a `ControllerResourceCoordinator`, and a permission context. `ActivePlan` carries the plan document, digests, `plan_id`, `goal_id`, `revision`, `PlanValidity`, and the live task and attempt views.

Public control types in `src/lib.rs`:

| Type | Role |
| --- | --- |
| `PlanValidity` | `Current`, `StaleEvidence`, `Invalidated` |
| `TaskState` | `Planned`, `Running`, `Verifying`, `RepairPending`, `DeferredResource`, `ReconcilingUnknown`, `FailedTerminal`, `Succeeded` |
| `AttemptState` | `Prepared`, `Executing`, `Verifying`, `Failed`, `Aborted`, `Interrupted`, `Succeeded` |
| `SchedulerView` | `Blocked`, `Running`, `Terminal` |
| `ExecutionControlV1` | Pause flag and reason |
| `GoalIntentV1` | Durable natural-language goal |
| `FailureClassificationKind` | `ExecutionFailure` or `PlanFailure` |
| `ReadyLease`, `IntegrationGateLeaseV1`, `NonWriteTaskLeaseV1`, `HeavyPhaseLease` | Scheduler grants for one next step |

`FailureClassifier` decides execution failure versus plan failure only from Controller-verified contract invalidation. Retry exhaustion is not an input to that decision.

## Goal statuses

`goal_runner.rs` stores intents in namespace `controller.goal_intent`:

| Status constant | Value |
| --- | --- |
| `GOAL_STATUS_QUEUED` | `queued_for_plan_compilation` |
| `GOAL_STATUS_CLAIMED` | `claimed_for_plan_compilation` |
| `GOAL_STATUS_ACTIVE` | `active_plan` |
| `GOAL_STATUS_COMPLETED` | `completed` |

## Ordered lifecycle

1. `Controller::submit_goal_intent` (or `submit_goal_intent_with_browser_grant`) writes a queued intent. The CLI `goal` command and `POST /v1/goals` call this path. They do not execute the plan.
2. `advance_production_goal` in `production_driver.rs` reconciles, then either compiles, executes one step, completes, or finalizes.
3. Compilation: `next_queued_goal_intent`, then `PlanCompiler::compile` under a reserved compilation budget (`controller.goal_compilation_budget`), then `activate_queued_goal_intent`.
4. Activation: `Controller::activate` persists the claim, the active plan pointer, and a checkpoint. A second `activate` while a plan is already active is rejected. Superseding revisions use `activate_superseding_revision`.
5. Scheduling: `scheduler_view`, then `derive_ready_lease`, `derive_integration_gate_lease`, or `derive_non_write_task_lease`. An attempt starts through the private `start_attempt` family. Authorization is epoch-bound. See [07-recovery-and-crash.md](07-recovery-and-crash.md).
6. Execution: `execute_replace`, `execute_repository_*`, `execute_non_write_task`, `execute_integration_gate`, `execute_build_heavy`, `execute_secret_process`, or browser APIs in `browser.rs`. Every side effect goes through policy and the action journal ([09-tools-sandbox-processes.md](09-tools-sandbox-processes.md)).
7. Verification: the task moves to `Verifying`. Success for repository work finalizes through `finalize_verified_repository_success` and `record_exact_evidence_satisfaction`. A passing model sentence is not this step.
8. Execution failure: `repair_replace` or `repair_repository_with_model`, still inside the same revision, bounded by the plan's retry budget.
9. Plan failure: `record_plan_failure` and `replan_input`, then `PlanCompiler::compile` with `PlanReplanInput`, then `activate_superseding_revision`. Old revision keys stay. See [05-plan-ir-and-compiler.md](05-plan-ir-and-compiler.md).
10. Completion: when required tasks have succeeded, `complete_queued_goal_intent` then `complete_goal` writes `controller.completion_record`.
11. Finalization: `finalize_completed_active_plan` clears the active pointer and keeps revision-scoped history under `controller.plan_finalization`.
12. After a crash: `RecoveryManager::recover` (or `recover_with_permission_context`), then `reconcile_queued_goal_lifecycle`, before any new advance.

`production_driver.rs` is a composition API. The caller supplies `ProductionCompilationResources`, `ProductionExecutionResources`, `ProductionBrowserResources`, and `ProductionExecutionCatalog`. The Controller chooses the task. Outcomes are `ProductionAdvanceOutcome` and blocks such as `ProductionBlockReason` (compilation budget exhausted, no runnable task, and similar). Task contracts passed through this driver are capped at `MAX_PRODUCTION_TASK_CONTRACT_BYTES` = 3000.

## Completion governance

Architecture section 26, implemented as Controller completion records rather than a model verdict:

- every required acceptance criterion has current evidence;
- required gates passed at the recorded repository revisions;
- no required task is blocked, replan-pending, or unresolved;
- no dispatched action remains `unknown`;
- artifacts match recorded digests;
- scope audit finds no unexplained changes;
- a final checkpoint and a completion record exist.

`crates/sovereign-eval/tests/completion_governance.rs` asserts that a model "done" cannot override a failed verification.

## Pause, resume, approvals

`ExecutionControlV1` is Controller state. `pause` and `resume` on the CLI, and `POST /v1/control/pause` and `/resume`, delegate to it. Approval requests live in `controller.approval_request`. Decisions are `ApprovalDecisionV1`. The dashboard cannot dispatch a tool. See [08-security-and-permissions.md](08-security-and-permissions.md) and [14-cli-runner-control-api.md](14-cli-runner-control-api.md).

## Revision-scoped record keys

Logical names such as a task id are stored under a revision prefix so revision N and N+1 never share a row:

```text
{plan_id}@r{revision}:{logical_key}
```

Implemented by `revision_scoped_key` and `active_scoped_key` in `src/lib.rs`. `revision_record_key` is `{plan_id}@r{revision}` for compilation evidence and completion records. Namespaces stay separate (`controller.task`, `controller.verification`, `controller.task_runtime`, and so on). The key inside the namespace is what is scoped.

Revision 1 may still be read from a bare key, and only under `LegacyRev1Authority`. Do not write new bare keys and then treat them as proof for a later revision. The uncommitted learning test `learning_revision_one_bare_keys_cannot_claim_scoped_controller_proof` exists to keep that boundary. Details: [06-durable-state.md](06-durable-state.md).

## Fail-closed gaps

There are no `TODO`, `FIXME`, `todo!`, or `unimplemented!` markers in this crate's `src/`. Unsupported behavior returns an error instead: unknown schema versions, Plan IR versions the recovery path does not understand, verification kinds outside the supported set, and attempts to activate a second plan. Treat a new "best effort" branch as a policy change, not a convenience.
