# Sovereign Product Delivery Amendment v1.0

Date: 2026-09-12
Status: accepted implementation amendment; additive to the frozen Sovereign core architecture and roadmap.

## Scope and ordering

This amendment does not alter the frozen core architecture. Core M1 must close first. After M1, implementation continues in dependency order while adding the following product-delivery profile as a bounded acceptance track.

## Target product profile

Sovereign's first concrete product profile is **local full-stack web application delivery plus existing-repository engineering work**.

The representative release proof is a local inventory application that demonstrates:

- persistent inventory records;
- validation;
- create, edit, delete, and search flows;
- restart durability;
- deterministic backend/frontend verification;
- real browser-flow verification;
- setup and run instructions;
- work performed through the same Controller, PlanCompiler, action journal, evidence, checkpoint, recovery, and approval mechanisms as generic core execution.

## Interfaces

Two local interfaces are required:

1. **CLI** — goal submission, status, evidence inspection, pause/resume, and approvals.
2. **Lightweight local dashboard** — goals, task progress, verification/evidence, pause/resume, and approval requests.

Neither interface owns execution authority. Both are clients of the same Controller and durable state.

## Permission boundary

Autonomous local repository work is allowed within the effective capability intersection. The following remain explicit approval boundaries:

- publication/deployment to an external destination;
- spending or payments;
- secret/credential access;
- destructive external actions.

No amendment task may weaken the frozen capability, checkpoint, unknown-outcome, isolation, or resource floors.

## Browser profile

Browser tooling is optional for generic Sovereign core. It is required for this web-product profile only for release verification of user-visible browser flows. Browser execution remains Controller-authorized and resource-admitted.

## Additive tasks

### PD-T01 — Controller-backed CLI surface

Depends on: core M1 complete.

Acceptance:
- submit a natural-language goal through the CLI;
- inspect current plan/task/attempt/action status and evidence references;
- pause and resume through Controller-owned state;
- render approval requests without bypassing policy;
- no duplicate execution state exists outside Controller/state.

### PD-T02 — Controller-backed local dashboard

Depends on: PD-T01 and the roadmap milestone that supplies the needed local API/state read model.

Acceptance:
- display goals, plan/tasks, current progress, verification/evidence, and blocked approvals;
- pause/resume delegates to the same Controller transitions as CLI;
- approval UI cannot directly execute actions;
- restart reconstructs the displayed state from durable Controller/state data.

### PD-T03 — Inventory application delivery proof

Depends on: core execution, repair, checkpoint/restart, and the browser-verification capability required by this profile.

Acceptance:
- starts from a natural-language product goal compiled by the canonical PlanCompiler;
- creates or modifies a real local full-stack application repository;
- persistent inventory records survive application restart;
- invalid inputs are rejected with deterministic validation;
- create/edit/delete/search work through the real application;
- deterministic code/test verification passes;
- real browser flows verify the required user-visible operations;
- one bounded repair path is demonstrated if the seeded proof fixture intentionally fails;
- Sovereign itself can restart/resume without chat replay;
- setup/run instructions are generated and verified locally;
- no publication, payment, secret access, or destructive external action occurs without explicit approval.

### PD-T04 — Product release acceptance

Depends on: PD-T01, PD-T02, PD-T03.

Acceptance:
- evidence bundle maps each product requirement to current verification evidence;
- no unresolved `unknown` action or recovery block remains;
- no changed-code gate relies solely on historical receipts;
- release is local-only unless the user separately authorizes publication;
- work stops when this verified release acceptance is met rather than adding unrelated scope.

