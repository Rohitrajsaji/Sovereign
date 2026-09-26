# Sovereign context wiki

> Snapshot: HEAD `d266399` (2026-09-24) plus uncommitted work (+3440/−604 across 34 files, observed 2026-09-25). **Verified** was checked in that tree. **Historical** may be superseded. **Uncertain** is not proven.

Sovereign is a local-first engineering control plane. A replaceable model proposes. The Controller in `crates/sovereign-controller` commits plans, permissions, tool effects, verification, and completion. Authoritative state is SQLite (`crates/sovereign-state`, schema 7), not the chat transcript. The target machine is a MacBook Air M1 with 8 GB of memory and one resident local model (Qwen3-4B class via `llama-server`).

Frozen design: [output/SOVEREIGN_ARCHITECTURE.md](../../output/SOVEREIGN_ARCHITECTURE.md) revision 2026-09-12.7 and [output/implementation-plan.json](../../output/implementation-plan.json) roadmap `1.4-frozen`. This wiki tells an agent how the code implements that contract today. It does not replace it.

## Ten invariants

1. Only the Controller commits execution transitions.
2. A model response is a proposal until validation commits it.
3. Plan revisions are immutable. Replan writes revision N+1.
4. The model cannot declare a task complete. Acceptance evidence must pass.
5. Repository, web, memory, skill, and tool text are untrusted and cannot grant permissions.
6. A crash after dispatch yields `unknown`, which is not replayed, until reconciliation.
7. Sovereign does not reset or overwrite pre-existing user git work to recover itself.
8. One local model invocation at a time on the M1 profile. Heavy pairs serialize when unknown.
9. Isolation is `sandbox-exec` on macOS, or execution is denied. A cleared environment is not a sandbox.
10. Normal operation stays useful offline after models and tools are already on disk.

## Current snapshot

`BUILD_STATE.json` (updated 2026-09-20) marks M0–M6, selected M7/M8 tasks, all M9 tasks, and PD-T01–PD-T06 complete. Milestone objects stop at M6. Deferred and absent from completed tasks: M7-T01 embeddings, M7-T04 adaptive browser, M8-T02 CodeGraph, M8-T03 document graph.

Commit `d266399` (2026-09-24) and the uncommitted diff are after that file. Do not revert the dirty tree. Do not treat the 2026-09-13 Codex audit as current.

On 2026-09-25 `./scripts/verify.sh` passed fmt and clippy, then failed `broker_pins_upstream_identity_rejects_startup_and_never_replays_after_loss`. A follow-up of the remaining crates passed until `controller_inflight_model_cancellation_interrupts_backend_and_keeps_call_consumed` (`Controller never entered model completion`). Details: [15-testing-and-evals.md](15-testing-and-evals.md).

## First session

1. Read this page, then [20-agent-playbook.md](20-agent-playbook.md).
2. `git status`. Expect the uncommitted diff described in [18-status-blockers-debt.md](18-status-blockers-debt.md).
3. Open the topic page for the subsystem you will change. Search symbols. Do not read all of `sovereign-controller/src/lib.rs`.
4. Run the narrow test for that subsystem, then `./scripts/verify.sh` before claiming the workspace is green.
5. Do not commit, do not edit `output/` or `BUILD_STATE.json`, and do not copy from `research/`, unless the user asked.

## Read by task

| You are about to | Read |
| --- | --- |
| Change execution flow | [04-controller-lifecycle.md](04-controller-lifecycle.md), [07-recovery-and-crash.md](07-recovery-and-crash.md) |
| Change plans | [05-plan-ir-and-compiler.md](05-plan-ir-and-compiler.md) |
| Change persistence | [06-durable-state.md](06-durable-state.md) |
| Change permissions or sandbox | [08-security-and-permissions.md](08-security-and-permissions.md), [09-tools-sandbox-processes.md](09-tools-sandbox-processes.md) |
| Change repos, browser, or Postgres | [10-repository-and-worktrees.md](10-repository-and-worktrees.md), [11-browser-and-postgres.md](11-browser-and-postgres.md) |
| Change the model or memory budget | [12-model-and-resources.md](12-model-and-resources.md), [13-context-memory-roles-skills.md](13-context-memory-roles-skills.md) |
| Change the CLI or dashboard | [14-cli-runner-control-api.md](14-cli-runner-control-api.md) |
| Change the consumer UI or `serve --execute` | [21-consumer-ui-and-service.md](21-consumer-ui-and-service.md) |

## Pages

| Page | Topic |
| --- | --- |
| [01-product-and-goals.md](01-product-and-goals.md) | Requirements, machine, product profile |
| [02-architecture.md](02-architecture.md) | Invariants, topology, crate graph |
| [03-code-map.md](03-code-map.md) | Files and where to look |
| [04-controller-lifecycle.md](04-controller-lifecycle.md) | Goal, task, attempt, completion |
| [05-plan-ir-and-compiler.md](05-plan-ir-and-compiler.md) | Plan IR 1.2, depth, replan |
| [06-durable-state.md](06-durable-state.md) | SQLite, keys, CAS, checkpoints |
| [07-recovery-and-crash.md](07-recovery-and-crash.md) | Unknown actions, epochs, kill tests |
| [08-security-and-permissions.md](08-security-and-permissions.md) | Capabilities, approvals, secrets |
| [09-tools-sandbox-processes.md](09-tools-sandbox-processes.md) | Process runner and Seatbelt |
| [10-repository-and-worktrees.md](10-repository-and-worktrees.md) | Git, leases, indexes |
| [11-browser-and-postgres.md](11-browser-and-postgres.md) | CDP and the Postgres broker |
| [12-model-and-resources.md](12-model-and-resources.md) | llama-server and the 8 GB profile |
| [13-context-memory-roles-skills.md](13-context-memory-roles-skills.md) | Packets, memory, roles |
| [14-cli-runner-control-api.md](14-cli-runner-control-api.md) | `sovereign` binary and loopback API |
| [15-testing-and-evals.md](15-testing-and-evals.md) | `verify.sh`, tests, this session's run |
| [16-environment-and-commands.md](16-environment-and-commands.md) | Toolchain, env vars, commands |
| [17-constants-and-limits.md](17-constants-and-limits.md) | Frozen numbers |
| [18-status-blockers-debt.md](18-status-blockers-debt.md) | What is done, stale, and risky |
| [19-decisions-and-history.md](19-decisions-and-history.md) | Decisions and commit timeline |
| [20-agent-playbook.md](20-agent-playbook.md) | How to change code safely |
| [21-consumer-ui-and-service.md](21-consumer-ui-and-service.md) | Loopback UI, actor, token, LaunchAgent |
| [glossary.md](glossary.md) | Short definitions |
