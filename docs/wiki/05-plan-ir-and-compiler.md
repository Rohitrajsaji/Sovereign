# Plan IR and the compiler

> Snapshot: HEAD `d266399` (2026-09-24) plus uncommitted work (+3440/−604 across 34 files, observed 2026-09-25).

## Which schema file is authoritative

| File | Status |
| --- | --- |
| `schemas/plan-ir-v1.json` | **Verified** authority. `crates/sovereign-plan/src/lib.rs` embeds it as `PLAN_SCHEMA` and exposes `PLAN_IR_VERSION` = `"1.2"`. |
| `output/plan-ir.schema.json` | Roadmap copy shipped with the frozen plan. Do not edit one and assume the other changed. If they diverge, the embedded `schemas/plan-ir-v1.json` is what `PlanValidator` enforces. **Uncertain:** this wiki did not byte-compare the two files. |

`PLAN_COMPILATION_SCHEMA_VERSION`, `CROSS_REPO_CONTRACT_SCHEMA_VERSION`, and `BROWSER_ACCEPTANCE_CONTRACT_SCHEMA_VERSION` are all `1`.

## Documents

`PlanIr` is the candidate document. Browser acceptance is `BrowserAcceptanceContractV1` and related types (`BrowserAcceptanceTemplateV1`, loopback target, semantic expectation). Cross-repository work uses `CrossRepoContract`.

Scenario narratives, not executable plans, live in [output/PLAN_IR_SCENARIOS.md](../../output/PLAN_IR_SCENARIOS.md): trivial edit, multi-module feature, cross-repo migration, crash and unknown action, bounded repair, smallest-scope replan, unsafe rejection, and M1/8 GB pressure.

## Validation

`PlanValidator::validate` checks JSON Schema, then `validate_semantics`. Stable diagnostic codes (`DiagnosticCode::as_str`):

| Code | Meaning |
| --- | --- |
| `PLAN-SCHEMA` | Schema rejection |
| `PLAN-DUPLICATE-ID` | Duplicate identifier |
| `PLAN-MISSING-REFERENCE` | Dangling reference |
| `PLAN-DEPENDENCY-CYCLE` | Cycle |
| `PLAN-DEPENDENCY-BINDING` | Dependency binding |
| `PLAN-EVIDENCE-CONTRACT` | Evidence contract |
| `PLAN-ACCEPTANCE-CONTRACT` | Acceptance contract |
| `PLAN-PERMISSION-POLICY` | Permission policy |
| `PLAN-RESOURCE-POLICY` | Resource policy |
| `PLAN-ISOLATION-UNAVAILABLE` | Isolation the host cannot prove |
| `PLAN-DEADLINE-POLICY` | Deadline policy |
| `PLAN-RECONCILIATION-POLICY` | Unknown-outcome policy |
| `PLAN-EXTERNAL-INTELLIGENCE-POLICY` | External intelligence policy |
| `PLAN-REVISION-BUDGET` | Revision budget |
| `PLAN-ROLLBACK-POLICY` | Rollback policy |
| `PLAN-FAILURE-ROUTING` | Failure routing |

A plan may add stricter completion checks. It cannot compile a weaker completion definition than the universal floors (architecture section 26). Hand-authored fixtures remain valid for unit tests. They cannot close an end-to-end goal that is supposed to pass through `PlanCompiler`.

## Compiler

Entry point: `PlanCompiler::compile` in `crates/sovereign-plan/src/compiler.rs`. Inputs are `PlanCompilationInput` and optional `M3PlanningInput`. The result is `PlanCompilationResult` plus `CompilationEvidence`.

Caps enforced in the compiler:

| Constant | Value |
| --- | --- |
| `MAX_COMPILER_MODEL_CALLS` | 2 |
| `MAX_PROPOSAL_TASKS` | 2 |
| `MAX_PROPOSAL_FILES` | 16 |
| `MAX_PROPOSAL_SYMBOLS` | 16 |
| `MAX_PROPOSAL_EVIDENCE_QUERIES` | 8 |
| `MAX_PROPOSAL_TEXT_BYTES` | 2048 |
| `MAX_M3_TASKS` | 16 |
| `MAX_M3_SUPPLIED_SOURCES` | 16 |
| `MAX_M3_ADDITIONAL_REPOSITORIES` | 8 |
| `MAX_M3_MANUAL_GATES` | 16 |
| `MAX_M3_ACCEPTANCE` | 4 |
| `MAX_M3_EVIDENCE_NEEDS` | 8 |
| `MAX_M3_ASSUMPTIONS` | 8 |

The production runner identifies the compiler as `COMPILER_VERSION` = `sovereign-local-v1` and allows at most `MAX_ADDITIONAL_REPOSITORIES` = 8. There is one compiler. M3 deepened it. Do not add a second compiler that emits Plan IR beside this path.

`local_autonomous_plan_policy` in `src/policy.rs` is the local autonomous policy helper used when compiling under the default local profile.

## Depth

`DepthClassifier::extract` then `classify` in `src/depth.rs` yields `ExecutionDepth::{D0, D1, D2, D3, D4}`. Inputs are a typed `DepthFeatureInput` (repository and language counts, expected files and symbols, security and migration flags, uncertainty percents, blast radius, prior failures, destructive and external effects, rollback availability). Percents are clamped to `0..=100` so the feature vector is stable.

Architecture intent, still reflected by worktree policy:

- D0 and D1 may edit in place only when the project profile allows it and pre-existing user changes are fingerprinted.
- D3 and D4 use Controller-owned worktrees (`M3-T04`). See [10-repository-and-worktrees.md](10-repository-and-worktrees.md).

The numeric thresholds inside `classify` are the source of truth. Do not copy a threshold into a prompt and treat the prompt as the classifier.

## Replan

`ReplanScope` is `Task`, `DependencyBranch`, or `Plan`. `smallest_replan_scope_tasks` picks the smallest scope. `PlanRevisionDiff` requires an adjacent step from revision N to N+1 inside that scope. Assumptions (`PlanAssumption`) authorize replanning only after the Controller verifies that the exact clause was invalidated.

Execution failure stays on the same revision and goes to repair. Plan failure invalidates and compiles a new revision. Resource or environment failure is a third class in the architecture (section 12) and shows up as `DeferredResource` or a governor denial, not as a silent replan. See [04-controller-lifecycle.md](04-controller-lifecycle.md).

## Tests

`crates/sovereign-plan/tests/validator.rs`, `minimal_compiler.rs`, `compiler_m3.rs`, `depth.rs`. End-to-end compile paths also live in `crates/sovereign-eval/tests/compiler_vertical_slice.rs`, `m3_scenario_gate.rs`, and `plan_failure.rs`.
