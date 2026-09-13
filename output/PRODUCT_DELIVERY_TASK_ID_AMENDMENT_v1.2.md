# Sovereign Product Delivery Task-ID Amendment v1.2

Date: 2026-09-13
Status: accepted scheduling-only successor to `PRODUCT_DELIVERY_AMENDMENT_v1.0.md` and `PRODUCT_DELIVERY_TASK_ID_AMENDMENT_v1.1.md`; additive to roadmap `1.4-frozen`.

## Scope

This amendment resolves only the missing product-profile task IDs and dependency edges required to make the accepted local full-stack release profile executable. It does not edit `output/implementation-plan.json`, the frozen architecture, Plan IR, or stable interface manifest, and it creates no new execution authority.

All tasks defined here have `required_for_core=false` and `required_for_product_profile=true` for the selected `local_full_stack_v1` profile. Profile activation requires completed milestone M1; M1 closed at local commit `dbd4d45`.

## New task IDs

### PD-T05 — General repository engineering action surface

Depends on task IDs:
- `M3-T02` — canonical multi-module/full-stack PlanCompiler/DAG support;
- `M3-T04` — Controller-owned worktree isolation for larger engineering changes;
- `M6-T02` — hardened filesystem/process/Git/package/network policy surface.

Objective: extend the existing `ToolAdapter`, `AuthorizedAction`, Controller, action-journal, checkpoint/recovery, isolation, evidence, and Verifier contracts with the general local repository actions needed for the product proof: typed create-file, structured patch/update, and governed structured build/test execution.

Acceptance:
- create-file and patch/update proposals are typed, repository-relative, exact-scope actions with preimage/postimage evidence where applicable;
- all mutations use existing durable authorization, policy/epoch binding, receipts, checkpoint/recovery, unknown-outcome handling, and isolation floors;
- build/test proposals resolve through governed `CommandSpec`/`ProcessRunner`; no opaque shell bypass is introduced;
- protected roots, path/symlink escape, stale preimage, ungranted package/network/destructive effects, and ambiguous outcomes fail closed;
- build/test success is evidence only and never a second completion authority;
- existing M1 replace-literal behavior remains compatible.

### PD-T06 — Local control API and durable read model

Depends on task IDs:
- `M1-T08` — checkpoint/restart recovery truth;
- `M6-T04` — approval/action-receipt/reconciliation policy required by local control surfaces.

Objective: expose a loopback-local command/read-model facade for CLI and dashboard clients while keeping Controller/SQLite as the sole lifecycle authority.

Acceptance:
- durable read model reconstructs goals, plans, tasks, attempts, actions, verification/evidence, recovery state, and blocked approvals from authoritative Controller/state data;
- submit/pause/resume/approval responses delegate to Controller APIs and never mutate authoritative state directly;
- dashboard/API never dispatch tools or authorize actions directly;
- loopback-only binding is the default local release surface;
- restart reconstructs the same visible state from durable data;
- no duplicate execution-state database exists outside the authoritative state store.

## Resolved dependency overlay

The accepted product-delivery tasks retain their original acceptance semantics, with these machine-resolvable edges:

- `PD-T01` depends on `M1-T09`, with the profile-level prerequisite that milestone M1 is complete.
- `PD-T06` depends on `M1-T08`, `M6-T04`.
- `PD-T02` depends on `PD-T01`, `PD-T06`.
- `PD-T05` depends on `M3-T02`, `M3-T04`, `M6-T02`.
- `PD-T03` depends on `PD-T05`, `M7-T03`.
- The selected profile adds `PD-T03` as an overlay prerequisite to the final `M9-T04` soak/security evidence so that the soak is run against the actual product-capable current tree rather than an earlier core-only tree.
- `PD-T04` depends on `PD-T01`, `PD-T02`, `PD-T03`, `M9-T04`.

The overlay does not mutate the frozen core roadmap's task arrays. It is evaluated by the selected product profile after normal core dependencies are satisfied.

## Browser promotion

For `local_full_stack_v1` only:

- `M7-T03` is explicitly profile-required because real browser-flow verification is part of release acceptance.
- Frozen dependency closure makes `M7-T02` profile-required only as a dependency of `M7-T03`; its Scrapling fetcher/browser extras remain optional according to its own acceptance contract.
- `M7-T01` semantic retrieval and `M7-T04` adaptive browser remain optional/deferred.
- `M8-T02` CodeGraph and `M8-T03` Wiki/document graph remain optional/deferred.

This promotion does not change `required_for_core` for any M7/M8 task.

## Release-order consequence

Core implementation continues in frozen dependency order. Product-profile tasks may start only when their explicit prerequisites are complete. `PD-T04` cannot close until the current product-capable tree has passed `M9-T04` and the full selected-profile evidence bundle has no unresolved unknown action or recovery block.

