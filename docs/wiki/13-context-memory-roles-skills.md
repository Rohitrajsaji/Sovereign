# Context, memory, roles, and skills

> Snapshot: HEAD `d266399` (2026-09-24) plus uncommitted work (+3440/−604 across 34 files, observed 2026-09-25).

Context is a cache assembled for one attempt. Memory is durable project knowledge. Neither one is permission state.

## Context levels

`ContextLevel` in `crates/sovereign-context/src/lib.rs`: `C0`, `C1`, `C2`, `C3`. Packet sections, in order, are `PacketSection`: controller prefix, task contract, current state, direct evidence, routed expansion, tool evidence, output schema.

`EvidenceKind` includes source slices, search hits, diffs, tool synopses, failure synopses, external advisory, verification, prior transcripts, raw tool logs, and explicit exclusions such as `HiddenReasoning` and `FullRepository`. Those last two exist so the planner can refuse to put them in a packet. Do not attach the whole repository to help the model.

`TrustClass` (`Controller`, `Repository`, `Tool`, `Verification`, `Derived`, `Untrusted`) is provenance. Security ingress uses `TrustLabel` from the policy crate. Neither grants a capability.

`ContextPlanner` builds a `ContextPacket` under a `ContextBudget`. The default counter is `Utf8FourByteTokenCounter` (a deterministic stand-in, not the model's tokenizer). Real admission still goes through `ModelBackend::count_tokens`. `RepairPacket` is the bounded packet for a repair attempt.

`ExpansionHandle` records source URI, digest, offset, and retained length so a later step can read more of an already-redacted blob without rerunning the producer.

## Retrieval router

`src/routing.rs` chooses exact, lexical, and structural channels before any semantic path. Semantic retrieval (`M7-T01`) is not in `BUILD_STATE.json` as completed and is not a default dependency. If a route would need embeddings, it should fail closed or stay on lexical and symbol evidence.

`src/telemetry.rs` records token accounting. `RATIO_SCALE_PPM` = 1_000_000 so ratios are integers.

`src/memory.rs` bridges memory synopses into C3 evidence. It does not copy memory rows into the model as policy.

## Memory

`MemoryManager` in `crates/sovereign-memory`. `MEMORY_RECORD_SCHEMA_VERSION` = 1. `MEMORY_STATE_SCHEMA_VERSION` = 6 (the memory slice of the state schema, which overall is 7 after the security-audit migration).

| Enum | Variants |
| --- | --- |
| `MemoryKind` | `GovernedKnowledge`, `ValidatedProjectFact`, `Episodic`, `ProceduralCandidate`, `PreferenceContext` |
| `MemoryScopeKind` | `Project`, `Agent`, `Shared` (shared means shared inside one project, not global) |
| `MemoryTrust` | `Governed`, `Validated`, `Observed`, `Unreviewed` |
| `MemoryStatus` | `Active`, `Stale`, `Superseded`, `Deprecated`, `Expired`, `Archived` |

Conflict is orthogonal to status: two `Active` records may point at one unresolved conflict set. Records are not deleted (`memory_records_no_delete`). Invalidation uses `InvalidationPredicate`. Provenance is `MemoryProvenance` plus source fingerprints.

Retrieval caps in `retrieval.rs`: 32 results, 2048 tokens, 128 candidates, 16 graph neighbors, synopsis 192 tokens, 4 provenance handles.

Projection: `memory_fts_projection` is fed by `memory_projection_outbox`. `MAX_OUTBOX_BATCH_HARD` = 128. Repair rows live in `memory_projection_repairs`. A crash mid-projection is repaired, not ignored (`tests/projection.rs`, env `SOVEREIGN_PROJECTION_CRASH_CHILD_DB`). The FTS table is rebuildable. The memory rows are not.

Learning: `EpisodeRecorder` in `learning.rs` writes episodic and procedural-candidate memories only from Controller proof records (`controller.attempt`, `controller.task`, `controller.verification`, `controller.failure_record`, `controller.repair_packet`). Uncommitted test `learning_revision_one_bare_keys_cannot_claim_scoped_controller_proof` blocks a revision-1 bare key from being treated as a scoped later-revision proof.

Schema document: `schemas/memory-record-v1.json`.

## Roles

`crates/sovereign-controller/src/roles.rs`. `ROLE_PROFILE_VERSION` = `1.3.0`. Older versions still parsed: `1.2.0`, `1.1.0`, `1.0.0`. `ROLE_OUTPUT_TOKEN_CEILING` = 512. At most 32 findings and 64 evidence ids. A role narrows behavior and output shape. It cannot grant a capability the task does not already have. Reviewer contexts are fresh; they do not inherit the implementer transcript as authority.

## Skills

`crates/sovereign-controller/src/skills.rs`:

| Constant | Value |
| --- | --- |
| `DEFAULT_MAX_SELECTED_SKILLS` | 4 |
| `HARD_MAX_SELECTED_SKILLS` | 16 |
| `DEFAULT_MAX_SKILL_BODY_BYTES` | 32 KiB |
| `HARD_MAX_SKILL_BODY_BYTES` | 128 KiB |
| `DEFAULT_MAX_SELECTED_BODY_BYTES` | 64 KiB |
| `DEFAULT_MAX_SELECTED_BODY_TOKENS` | 1600 |
| `HARD_MAX_SELECTED_BODY_TOKENS` | 3200 |
| `DEFAULT_MAX_SELECTED_METADATA_TOKENS` | 512 |
| `HARD_MAX_SKILL_MANIFEST_BYTES` | 32 KiB |
| `DEFAULT_MAX_DISCOVERED_MANIFESTS` | 4096 |

Skill text is untrusted data. Helper scripts inside a skill are not pre-authorized tools.

## Tests

Context: `context_packet.rs`, `context_metrics.rs`, `routing.rs`, `memory_history.rs`, `external_advisory.rs`. Memory: `lifecycle.rs`, `retrieval.rs`, `projection.rs`, `learning.rs`.
