# Glossary

> Snapshot: HEAD `d266399` (2026-09-24). Terms as used in this tree.

| Term | Meaning |
| --- | --- |
| Controller | `crates/sovereign-controller`. Sole writer of execution transitions. |
| Plan IR | Immutable plan document, version `1.2`, schema `schemas/plan-ir-v1.json`. |
| Revision | Integer N on a plan. N+1 supersedes part of N. Old rows stay. |
| Revision-scoped key | `{plan_id}@r{revision}:{logical_key}` in `state_records`. |
| Legacy rev 1 | Bare keys without `@r`, readable only under `LegacyRev1Authority`. |
| Goal intent | Durable natural-language objective. Statuses: queued, claimed, active, completed. |
| Active plan | The `controller.plan` row keyed `active`. Cleared on finalization. |
| Task | A node in the plan DAG. `TaskState`. |
| Attempt | One execution try of a task. `AttemptState`. |
| Lease | A scheduler or resource grant for one next step (`ReadyLease`, resource lease, browser lease, worktree lease). |
| Epoch | `controller_runtime.execution_epoch`. Authorization from an older epoch is dead. |
| Action | A journaled side effect. States include committed and unknown. |
| Unknown | A dispatch that may have happened and lacks a reconciling receipt. Not a failure. |
| Receipt | `ActionReceipt`, schema `sovereign-action-receipt-v1`. |
| Checkpoint | Hash-chained manifest. Current writer schema version 3. |
| CAS | Content-addressed artifact bytes in `ArtifactStore`. SQLite stores digests. |
| Capability | One of twelve Plan IR permissions. Effective set is an intersection. |
| Approval claim | Exact, expiring, payload-bound permission to cross an approval boundary. |
| Verifier | Deterministic check that acceptance evidence matches the task. Not the model. |
| Repair | Another attempt inside the same revision after an execution failure. |
| Replan | New revision after a plan failure, smallest `ReplanScope`. |
| Depth D0–D4 | `ExecutionDepth` from `DepthClassifier`. D3/D4 mutate in controller worktrees. |
| C0–C3 | Context packet levels. C0 is the contract and is not evicted to make room. |
| Pressure band | `Green`, `Guarded`, `Constrained`, `Emergency` on the M1/8 GB governor. |
| Heavy lease | Model, embedder, browser, build, indexer, codegraph, LSP, or unknown. |
| Fake backend | `DeterministicFakeBackend`. Tests only. Not qualification. |
| Run lock | Kernel flock beside the state file. Not Controller state. |
| Read model | `LocalControl` projection for CLI and dashboard. Not a second database. |
| Product profile | `local_full_stack_v1`. Inventory app plus CLI and dashboard. |
| M0–M9, PD-T* | Roadmap task ids. Evidence in `implementation/evidence/`. |
| CoS | **Historical** name in the 2026-09-13 audit for an external coordinator UI. Not a crate. |
| Astra | **Historical** name in `NON_GOALS.md` for the architect. Not a runtime service. |
| `sovereignd` | **Historical** architecture name. The binary is `sovereign`. |
