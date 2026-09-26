# Decisions and history

> Snapshot: HEAD `d266399` (2026-09-24) plus uncommitted work (+3440/−604 across 34 files, observed 2026-09-25). Dates are `git log --date=short`.

## Decisions that still bind

These are in the frozen architecture (revision 2026-09-12.7) and are implemented, not abandoned:

- The Controller is the only execution authority. The model proposes.
- Plan revisions are immutable. Replan is N to N+1 inside `ReplanScope`.
- One canonical `PlanCompiler`. M3 deepened it. It did not add a second compiler.
- SQLite WAL plus an append-only journal, not a full event-sourced rewrite. CAS for large blobs.
- Unknown action outcomes are not failures and are not replayed.
- Capability intersection. Skills and roles cannot grant permissions.
- One resident local model on the M1/8 GB profile. Heavy pairs serialize when uncalibrated.
- Semantic retrieval, adaptive browser, CodeGraph, and a document wiki graph stay optional.
- External intelligence is advisory and redacted.
- Secrets are references in SQLite. Values are ephemeral.
- Isolation must be provable (`sandbox-exec` on macOS) or execution is denied.
- Product delivery is an overlay (`local_full_stack_v1`), not a fork of the state model. v1.2 fixed task ids: PD-T05 engineering actions, PD-T06 control API. v1.1 is superseded by v1.2.
- Release is local. Publication, spending, secrets, and destructive external actions need an explicit approval.

Research notes in architecture section 27 (OpenHuman, OpenViking, agentmemory, TencentDB Agent Memory, ECC, OpenHands, Scrapling, browser-use, agency-agents) explain why those shapes were chosen. The license constraints there still apply: do not copy OpenHuman's GPL core or OpenViking's AGPL Python into this tree. `research/` is gitignored on purpose.

## Superseded

| Item | Why it is historical |
| --- | --- |
| Codex audit at `02fecec` (2026-09-13) | Written when M1 qualification was still open and the CLI was a stub. Later commits closed that work. |
| `NON_GOALS.md` invitation for Astra to replace the architecture | Overwritten as process by the freeze. The nine hard constraints remain. |
| Shell residue in the top-level markdown files | Authoring accident. Not a build step. |
| `completed_milestones` ending at M6 | Bookkeeping. Task evidence for M7-T02, M7-T03, M8-T01, M9, and PD exists. |
| Plan IR copy under `output/plan-ir.schema.json` | The compiler embeds `schemas/plan-ir-v1.json`. |

## Timeline

| Date | Commit | What closed or landed |
| --- | --- | --- |
| 2026-09-12 | `2ee08ef` | Local implementation baseline |
| 2026-09-12 | `1884f86` through `5de947a` | M1 kernel, evidence, context, compiler start |
| 2026-09-13 | `3a8ca1e` through `dbd4d45` | Controller slice, recovery, repair, real-model qualification |
| 2026-09-13 | `8bc73b2`, `44c94f4`, `af1fee7` | Audit acknowledgement and product-profile dependency fixes |
| 2026-09-13 | `a971346` through `e93dbfa` | CLI, lexical index, structural graph, retrieval, telemetry, depth, compiler, replan, worktrees. M2 and M3 |
| 2026-09-13 | `28a56a9` through `f671cf5` | Memory lifecycle, retrieval, projection, learning. M4 |
| 2026-09-14 | `39b2f81` through `9383fa5` | Roles, skills, capability filter, resource governor, hardening, secrets, approvals, injection, resilience, external gateway. M5 and M6 |
| 2026-09-16 | `93106ae`, `9eb58cc` | PD-T06 control API, PD-T02 dashboard |
| 2026-09-17 | `3054d40` | PD-T05 repository engineering actions |
| 2026-09-18 | `beb65d8` | M7-T02 web acquisition |
| 2026-09-19 | `0ed73ec`, `383f967` | M7-T03 browser lease, M8-T01 cross-repo contracts |
| 2026-09-20 | `9382063` through `520f9a9` | PD-T03, M9 eval, completion, upgrade, soak, PD-T04 |
| 2026-09-20 | `46948c1` through `4f8b7cd` | Qwen qualification headroom and evidence binding |
| 2026-09-24 | `d266399` | Governed execution, recovery, sandboxing, runtime integration. Not a task id |
| 2026-09-25 | uncommitted | Revision-scoped keys, kill matrix, headroom, Rust verification admission, subprocess caps. Not committed |

M1 remediation notes live in `implementation/AUDIT_REMEDIATION_2026-09-12.1.md`. They describe gates that later commits closed. Read them for the original failure modes (recovery integrity, qualification harness branches), not for current task status.

## Evidence discipline

A closure commit should point at `implementation/evidence/<task>.json` with a status, a head, and source hashes when the task required current-tree proof. PD-T04's file has `status`, `head`, `source_hashes`, and `current_tree_verification`. If you edit a file named in those hashes, the evidence no longer proves the new bytes. Say so. Do not rewrite old evidence to match a new tree without rerunning the gate.

`BUILD_STATE.json` is updated when a task is accepted. This wiki does not update it.
