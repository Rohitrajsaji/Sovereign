# Sovereign Product Delivery Task-ID Amendment v1.1

Date: 2026-09-13
Status: accepted narrow implementation amendment; additive to `output/PRODUCT_DELIVERY_AMENDMENT_v1.0.md` and roadmap `1.4-frozen`.

## Purpose

This amendment resolves previously unnamed product-delivery dependencies without redesigning the frozen architecture, Plan IR, Controller authority, or core roadmap. It assigns explicit task IDs to the missing local engineering/action and dashboard API/read-model capabilities, and names the existing browser and release tasks promoted only by the selected local-web product profile.

The frozen roadmap remains authoritative for all existing task semantics. This file only adds the two product-profile tasks below and resolves the dependency edges of PD-T01..PD-T04.

## Profile requirement rules

- `required_for_core=false` for every PD task in this amendment. These tasks are required only when the `local-web` product profile is selected.
- Existing optional roadmap tasks remain optional for generic core. The selected `local-web` profile promotes only the minimum existing browser chain needed for browser release proof.
- No task here may create a second execution authority. CLI, API, dashboard, file mutation, command execution, browser execution, and verification all delegate through the same Controller/action-journal/policy/state machinery.
- No publication, deployment, payment, secret access, destructive external action, or security-floor weakening is authorized by this amendment.

## New explicit task IDs

### PD-T00 — General local engineering action surface

Depends on: milestone M1 complete.

Targets:
- `crates/sovereign-tools`
- `crates/sovereign-controller`
- `crates/sovereign-plan`

Objective: provide the bounded general-purpose local engineering capabilities needed by the product proof: typed file creation, structured file patch/update, and Controller-routed structured build/test command execution using the existing `AuthorizedAction`, `ActionJournal`, `CommandSpec`, `ProcessRunner`, policy, evidence, and deterministic verifier contracts.

Acceptance:
- create-file and patch/update actions have typed schemas and exact repository-relative scope;
- every mutation is durably authorized before dispatch and receives durable redacted result evidence before commit;
- structured build/test commands use pinned/approved executable resolution and the existing isolation/resource/process-tree floors;
- stale preimages, path escape, protected roots, ungranted package/network/destructive effects, and unresolved unknown outcomes fail closed;
- build/test success is evidence only; Controller-owned deterministic acceptance remains the only success authority;
- existing M1 replace-literal behavior remains compatible and no raw shell bypass is added.

Verification intent:
- file create/patch preimage and rollback fixtures;
- protected-root/path/symlink denial fixtures;
- structured build/test command fixtures including nonzero, timeout, escaped descendant, and restart reconciliation;
- current full M1 security/recovery suites remain green.

### PD-T02A — Local Controller API and durable state read model

Depends on: PD-T01 and milestone M1 complete.

Targets:
- `apps/sovereign`
- `crates/sovereign-controller`
- `crates/sovereign-state`

Objective: expose a loopback-only local API/read model for CLI/dashboard clients without creating new execution state or authority.

Acceptance:
- read model reconstructs goals/plans/tasks/attempts/actions/verification/evidence/blocked approvals from durable Controller/state truth;
- submit, pause, resume, and approval-response endpoints call the same Controller transition APIs used by the CLI rather than mutating state directly;
- API is loopback-only by default and requires no external network service;
- restart reconstructs the same displayed state from durable storage;
- UI/API clients cannot directly authorize or execute tools;
- no duplicate task/action lifecycle state is persisted outside authoritative state.

Verification intent:
- CLI/API state equivalence fixture;
- restart/read-model reconstruction fixture;
- direct-state-mutation denial fixture;
- loopback binding fixture.

## Resolved product-delivery dependency edges

The following edges supersede the unnamed dependency prose in `PRODUCT_DELIVERY_AMENDMENT_v1.0.md` while preserving that amendment's acceptance requirements:

- `PD-T01` — depends on milestone `M1`.
- `PD-T00` — depends on milestone `M1`.
- `PD-T02A` — depends on `PD-T01` and milestone `M1`.
- `PD-T02` — depends on `PD-T01`, `PD-T02A`.
- `PD-T03` — depends on `PD-T00`, `M3-T02`, `M7-T03`.
- `PD-T04` — depends on `PD-T01`, `PD-T02`, `PD-T03`, `M9-T04`.

Roadmap task dependency arrays contain task IDs only. The containing product-profile track has milestone prerequisite `M1`; references above to milestone M1 describe that track prerequisite rather than inventing a task ID for milestone closure.

## Existing roadmap tasks promoted by the selected `local-web` profile

- `M3-T02` supplies the canonical multi-module/full-stack PlanCompiler/DAG capability used by the representative product goal.
- `M7-T03` supplies the real deterministic browser verification capability.
- Because frozen `M7-T03` depends on `M7-T02`, `M7-T02` becomes transitively required for this selected profile even though generic core continues to treat both as optional.
- `M9-T04` gates final PD-T04 release acceptance so the product cannot claim ready-to-use release before the current-tree target-machine soak/crash/security matrix passes.

The selected profile does **not** promote `M7-T01`, `M7-T04`, `M8-T02`, or `M8-T03`. Their absence remains a valid local-web release configuration unless a later explicit amendment changes the profile.

## Execution order consequence

Core dependency order continues unchanged from M2 onward. Product-profile work may be implemented when its explicit prerequisites become satisfied, but final `PD-T04` cannot close until the required core release gate `M9-T04` and the complete selected-profile chain are current-tree verified.

