# Sovereign release audit — 2026-09-13

## Verdict and scope

Direction is broadly aligned with the accepted architecture, but the product is not ready to use. The build is at the M1 real-model qualification gate, not final release. This review covers the workspace/module inventory, frozen roadmap and amendments, durable task evidence, Git state, high-risk implementation paths and current CoS session. It is not a claim that every source line has been independently proved correct. No source changes or duplicate real-model tests were performed by the auditor.

Snapshot: HEAD `02fecec`; the real qualification harness is untracked. BUILD_STATE has 14 completed tasks and only M0 closed. The frozen roadmap contains 47 tasks, of which 41 are core-required: **14/41 = 34.1% core task-count progress**, or 29.8% of all listed tasks. These are unweighted counts, not effort, elapsed-time or product-readiness estimates. The four product amendment tasks and the promoted browser capability add release work outside that core denominator.

## What exists

- Rust workspace, SQLite state/migrations, content-addressed artifacts and destination contracts.
- Plan IR validation, Git baselines, local model backend, minimum security/action/process kernel.
- Evidence compression, bounded context and exact retrieval, minimal natural-language PlanCompiler.
- Controller execution/verification, checkpoint recovery, bounded targeted repair.
- Local Git history and exclusions for models, research, runtime/build caches and sensitive artifacts.

The latest T09 evidence records formatting, strict Clippy, full offline workspace tests, Controller 4 unit + 18 integration tests, repair 2/2 and crash/restart 20/20, plus independent review. Its three source hashes match the current files. Those recorded results are not a fresh independent execution by this auditor. Earlier task hashes may differ after legitimate downstream edits; final regression evidence must bind the final tree.

## Findings requiring action

1. **Continuation is stalled.** The live CoS UI reports `goal_context_too_large`, retrying an oversized helper request. Its task was a literal `[OBJECTIVE]` template and incorrectly framed construction as running through the unfinished Sovereign product. Replace it with a concrete implementation/release objective, bounded work cycles and short file-referenced handoffs. Recover this existing durable session rather than starting a competing build.
2. **Real-model M1 gate remains open.** The builder explicitly reports that the combined real-Qwen qualification has not passed. The compiler smoke admitted 680 input/schema tokens; that is not representative full-packet/8K qualification. Require actual compile → Controller attempt → failure → durable restart → real model repair → isolated edit → deterministic verification, with complete input/template/tool/output accounting, absolute deadlines, exact evidence IDs and resource observations.
3. **Qualification harness has an inconsistent branch.** In `crates/sovereign-eval/tests/m1_real_qualification.rs`, the initial-response handler injects a fault only when the raw proposal is exact-valid, allowing a naturally invalid proposal otherwise. The final assertion near line 989 unconditionally requires `fault_injected` and differing raw/delivered hashes. That rejects the naturally invalid branch. Review and correct the branch-specific proof requirements without weakening normal validation or hiding model failures. Distinguish controlled injection from a natural model error in evidence.
4. **The user interface is a stub.** `apps/sovereign/src/main.rs` only supports version, a fixed foundation message and an unconditional foundation `doctor` result. It cannot submit goals, inspect real state, pause/resume or approve. The dashboard remains to be implemented.
5. **Current action scope cannot deliver the requested product.** The minimal compiler and Controller implement a small bounded literal replacement slice. This is appropriate for M1 but does not establish general file creation, structured patches, build/test commands or full-stack generation. Add explicit, narrowly scoped versioned tasks/dependencies connecting the later compiler/tool capabilities to PD-T03, preserving existing security and Controller authority.
6. **Product amendment scheduling is not fully executable.** PD-T02 refers to an unnamed API milestone and PD-T03 uses broad capability dependencies. Resolve these to concrete task IDs and evidence gates. Promote only the browser capability required for local web proof; unrelated optional adapters should have an explicit deferred disposition.

## Remaining scope

M2: indexed/symbol retrieval, routing and telemetry. M3: richer planning, classification/replanning and worktrees. M4: durable memory/retrieval/projections/episodes. M5: roles, skills and capability filtering. M6: pressure governance, stronger policy, secret broker, approvals, injection boundaries, audit/rollback/budgets and policy gateway. M8: required cross-repository contracts. M9: eval corpus, completion governance, migration compatibility and target-machine soak. PD: usable CLI, lightweight dashboard, generated inventory app and final release acceptance. Optional tracks are not all mandatory, except capabilities explicitly promoted by the selected product profile.

## Refined release contract

The existing CoS prime remains sole integration owner. Resume the current M1 gate, then select dependency-ready work from durable state. For each bounded cycle: inspect the current tree, assign exclusive file ownership, implement, verify relevant behavior, address concrete review findings, record redacted evidence, commit locally and advance state only after acceptance. Do not repeatedly reopen completed work without new evidence. Keep handoffs under 1500 words with file references, task/commit IDs, active-process ownership and exact next action.

Release requires all required core and selected product gates; a working local CLI and dashboard sharing Controller state; a natural-language goal that Sovereign turns into a complete local full-stack inventory app; create/edit/delete/search; validation; database persistence across restart; actual browser verification; bounded repair and Sovereign restart/resume; reproducible setup/run instructions; and final current-tree evidence. No unresolved unknown action may remain. Retain durable redacted action receipts before commit, bounded output-reader draining, escaped-descendant cleanup or fail-closed unknown recovery, coherent migrations and runtime-proven isolation including protected roots inside repositories. Test target-machine resource behavior with one resident local model. Never substitute prose or fake-model tests for real release proof.

Stop on verified release, a user stop, or a genuine external blocker requiring a specific human action. Ordinary implementation defects require bounded diagnosis and repair. Do not publish, spend, access secrets or weaken security under this authorization.
