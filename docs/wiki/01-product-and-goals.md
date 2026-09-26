# Product and goals

> Snapshot: HEAD `d266399` (2026-09-24) plus uncommitted work (+3440/−604 across 34 files, observed 2026-09-25).

## Purpose

Sovereign accepts a high-level software objective and carries it through planning, execution, verification, repair, and resume, on a MacBook Air M1 with 8 GB of unified memory, using a local model by default. The LLM is not the system controller. The Controller owns authoritative project and execution state. That sentence is the product requirement, not a slogan. See [04-controller-lifecycle.md](04-controller-lifecycle.md).

## Requirements

[REQUIREMENTS.md](../../REQUIREMENTS.md) lists twenty capabilities the system must eventually have: accept an objective, clone or open repositories, understand unfamiliar code, persist understanding across sessions, decompose work, select roles and skills, retrieve only the needed context, modify files safely, install dependencies under policy, run builds and tests, debug failures, verify completion deterministically, resume after restart, learn procedures, discover tools when required, run primarily on local models, stay inside the 8 GB budget, keep execution state outside chat history, preserve provenance, and keep external components replaceable through adapters.

**Historical:** the file still contains a leading `cat > REQUIREMENTS.md <<'EOF'` shell residue from the original authoring session. The requirements list itself is the contract. The same residue is in `MACHINE.md`, `NON_GOALS.md`, `SOURCES.md`, and `DEVELOPMENT.md`. Do not treat the shell lines as instructions to re-run.

## Non-goals and hard constraints

[NON_GOALS.md](../../NON_GOALS.md) is titled "Sovereign Architectural Freedom." It tells an architect (named Astra in that draft) to choose the strongest practical local design. The hard constraints that survived into the frozen architecture are:

1. Run primarily locally.
2. Target MacBook Air M1, 8 GB unified memory.
3. Do not depend on paid cloud APIs for normal operation.
4. Stay useful when external AI services are down.
5. Engineer resource use deliberately.
6. Verify autonomous work. A claim of completion is not completion.
7. Survive context exhaustion and process restart.
8. Aggressively limit context and tokens.
9. Remain able to evolve.

Everything else in that file is historical briefing, not a license to replace the frozen architecture. The frozen documents are under `output/`. See [19-decisions-and-history.md](19-decisions-and-history.md).

## Target machine

[MACHINE.md](../../MACHINE.md), planning-time snapshot:

- MacBook Air M1, Apple Silicon, 8 GB unified memory, 512 GB SSD
- macOS, Git 2.50.1, Python 3.14.7, Node.js 22.23.2
- about 107 GB free disk at planning time
- one resident LLM, shared serially by logical agents
- Docker is not assumed to run permanently
- browsers and language servers are demand-loaded
- cloud APIs are optional
- optimization target: verified useful engineering work per RAM, time, and tokens

The encoded profile is `HardwareProfileV1::m1_8gb`. Numbers: [12-model-and-resources.md](12-model-and-resources.md) and [17-constants-and-limits.md](17-constants-and-limits.md).

## Product profile

Amendment [output/PRODUCT_DELIVERY_AMENDMENT_v1.0.md](../../output/PRODUCT_DELIVERY_AMENDMENT_v1.0.md) adds profile `local_full_stack_v1` without changing core architecture. The representative proof is a local inventory application: persistent records, validation, create/edit/delete/search, restart durability, deterministic tests, real browser verification, and setup instructions, all through the same Controller.

Scheduling edges are in [output/PRODUCT_DELIVERY_TASK_ID_AMENDMENT_v1.2.md](../../output/PRODUCT_DELIVERY_TASK_ID_AMENDMENT_v1.2.md) (successor to v1.1):

| Task | Depends on | Role |
| --- | --- | --- |
| PD-T01 | M1-T09, milestone M1 | CLI |
| PD-T06 | M1-T08, M6-T04 | Loopback control API and read model |
| PD-T02 | PD-T01, PD-T06 | Dashboard |
| PD-T05 | M3-T02, M3-T04, M6-T02 | Create, patch, governed build/test |
| PD-T03 | PD-T05, M7-T03 | Inventory delivery proof |
| PD-T04 | PD-T01, PD-T02, PD-T03, M9-T04 | Release acceptance |

`BUILD_STATE.json` marks PD-T01 through PD-T06 completed. Evidence files are under `implementation/evidence/`. Whether that evidence still matches the uncommitted tree is a freshness question, not a reason to reopen the tasks without new findings. See [18-status-blockers-debt.md](18-status-blockers-debt.md).

## Release boundary

Local verified release only. Publication, spending, secret access, and destructive external actions require explicit approval. Work stops at verified release, a user stop, or a genuine external blocker. Ordinary defects get bounded repair. This boundary is in `BUILD_STATE.json` `active_steering.release_boundary` and in the product amendment.

## Research inputs

[SOURCES.md](../../SOURCES.md) lists the clones under `research/`, which git ignores. They are evidence inputs, not product source. Architecture section 27 records what was borrowed. Do not copy GPL or AGPL code into the workspace. Do not vendor `research/` into a commit.
