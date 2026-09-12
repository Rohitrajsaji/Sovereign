# Sovereign Research Audit

Status: **independently re-audited source audit — revision 2026-09-12.2**.

This audit records what was observed in the supplied research checkouts, what is inferred for Sovereign, and the resulting reuse decision. It is intentionally stricter than repository marketing claims. Where a capability is documented but the implementing runtime is not present in the supplied checkout, this document says so. The 2026-09-12.2 pass was performed independently from the earlier synthesis and treats prior conclusions as hypotheses rather than evidence.

## Evidence labels

- **Observed** means the behavior, configuration, dependency, or license marker was found directly in the audited checkout at the recorded revision.
- **Documented** means the repository documentation states it, but this audit did not necessarily execute the behavior.
- **Inferred for Sovereign** is an engineering conclusion about fit, safety, resource cost, or architecture; it is not a claim that the source project makes.
- **Unverified** means the checkout does not contain enough evidence to clear the claim, commonly a transitive license or target-machine runtime cost. License observations here are repository facts for engineering triage, not legal advice.

No M1/8 GB suitability statement below is a benchmark result unless explicitly labelled as measured. Dependency breadth, service topology, in-memory algorithms, pool settings, and resident data structures are source facts; their overall laptop impact is an engineering inference that Sovereign must calibrate on the target machine.

## Audit baseline

| Repository | Audited revision | License observed in checkout | Sovereign use class |
| --- | --- | --- | --- |
| `research/core/OpenViking` | `84bbf79711f3d18000beb1d16708e69627743b0e` | AGPL-3.0 main Python package; `crates/ov_cli` **and `crates/ragfs`** declare Apache-2.0 and `crates/LICENSE` is Apache-2.0; `ragfs-python` has no package license field; `examples/LICENSE`/README say Apache-2.0 but at least nine files under `examples/` carry AGPL-3.0 SPDX, so those files are license-ambiguous; Python `openviking_cli/` carries AGPL-3.0 SPDX | algorithmic concepts + optional adapter; Apache Rust components are direct-reuse candidates after dependency/fit review |
| `research/core/agentmemory` | `e04ba88819c365c9acf9d6661ea802143e728bd6` | Apache-2.0 | algorithms/select helpers; optional adapter; clean-room core persistence |
| `research/core/TencentDB-Agent-Memory` | `0468a2a5b50eaafc54758ed1e2e6609472e5b6ce` | MIT root | selected component/pattern adaptation; optional adapter |
| `research/core/openhuman` | `a655daeb7f75ac84e5b7de39b640f6199b6f4bdc` | GPL-3.0-only | clean-room architecture/policy inspiration |
| `research/core/OpenHands` | `60877198aa4b0075a47eef9a24043f21f5bf6f97` | MIT | Agent Canvas frontend/control-center + local-stack orchestration patterns; backend agent runtime is external |
| `research/core/ECC` | `8321021c54d670126ce3b2969d5deb880b4b0c2a` | MIT | selected skill content + controller-pattern inspiration |
| `research/harness/awesome-harness-engineering` | `cff9b006ef64c624a62cbb1ee36b0c4b2b3a67ad` | CC0-1.0 | research index/reference |
| `research/tools/browser-use` | `50f205533fe10ba35b553d2a3689c77b87bd5d0a` | MIT | optional heavy browser adapter/patterns |
| `research/tools/Scrapling` | `3115acab99a978026ea6c542f9dfe726c486778b` | BSD-3-Clause | optional lightweight web/parser adapter |
| `research/agents-skills/agency-agents` | `6d29a9b08785a0e49ffc9818bbdd381164c2df5f` | MIT | optional role-content catalogue |
| `research/agents-skills/Anthropic-Cybersecurity-Skills` | `54a798831d2266a3ca61ce68a7acb80b81160d57` | Apache-2.0 | optional indexed security skills |

The checkout date is 2026-09-12. No conclusion below assumes a newer upstream state.

## 1. Memory-system comparison

### Summary

| Dimension | OpenViking | agentmemory | TencentDB Agent Memory | Sovereign conclusion |
| --- | --- | --- | --- | --- |
| canonical persistence | its own context DB/files/vector infrastructure | iii-engine state primitives | MemoryCore + MemoryKnowledge services/stores | one embedded Sovereign SQLite authority |
| lexical retrieval | present around resource/context flows, but hierarchy is strongly vector-oriented | strong in-memory BM25 | SQLite FTS5 BM25 | FTS5/BM25 first |
| semantic retrieval | `find/search` retriever is embedding/vector oriented; quick-start also configures VLM/model support for semantic ingestion/generation, while exact filesystem/grep-style operations are distinct | optional local/provider vectors | optional vectors; zero-config runs without them, and current user config explicitly disables the `local` embedding provider | demand-loaded, optional |
| hybrid fusion | hierarchy/search/rerank | BM25 + vector + graph RRF | FTS + vector RRF | deterministic router + optional RRF |
| hierarchy | L0 abstract / L1 overview / L2 full | multiple memory tiers/types, less uniformly scoped | chat L0-L3 plus Wiki/CodeGraph assets | explicit context levels + typed memory |
| code intelligence | tree-sitter code parsing/summaries; no first-class impact graph found | observational code/file/session memory, not AST code graph | explicit CodeGraph service | Sovereign native symbol/dependency index; optional deeper adapter |
| wiki/document | resources + compile/wiki artifacts | summaries/observations/memories | Wiki asset service | keep docs as indexed evidence; no always-on wiki service |
| provenance/versioning | context/session/resource metadata; tool artifacts durable | strong on `Memory`; uneven across higher-tier types | asset versions/audits/status; SQLite metadata | uniform provenance/version envelope for every durable memory |
| restart recovery | persistent queues/vector snapshots; several recovery mechanisms | persisted indexes/state through iii; snapshot coverage incomplete | interrupted knowledge builds marked failed; recall checkpoint exists | first-class checkpoint/action reconciliation in Controller |
| local-only viability | exact/local storage paths exist, but semantic workflows require acquired embedding/model components | keyless BM25 works; local MiniLM works after first model download, but full runtime remains iii-coupled | SQLite FTS/no-vector read path is local; current `local` embedding provider is disabled in config, while L1-L3 generation requires a host or OpenAI-compatible LLM endpoint | no mandatory background memory service |
| M1/8 GB fit | full stack too broad/heavy as default | full daemon/index stack unnecessary and memory-heavy at scale | full services/knowledge pools too heavy without tuning | reuse algorithms, keep core embedded and sparse |
| license | AGPL-3.0 | Apache-2.0 | MIT | avoid copyleft code in core by default; permissive reuse still scoped |

### Local-runtime dependency reality

| System | Minimum/runtime facts observed in checkout | Consequence for Sovereign |
| --- | --- | --- |
| OpenViking | Python `>=3.10`; build system includes CMake + maturin; the main Python package has a broad mandatory parser/web/model/telemetry/tree-sitter dependency set; semantic quick start needs acquired embedding + VLM/model access | viable as an explicitly installed external system, but not a minimal embedded M1 control-plane dependency |
| agentmemory | Node `>=20`; full server pins `iii-sdk`/`iii-engine` `0.11.2`, normally exposes REST/streams/viewer/worker-WebSocket surfaces; local MiniLM is optional and downloaded through Hugging Face tooling; reduced standalone MCP fallback exists without the engine but has materially weaker writable/search semantics | full runtime should remain external/noncanonical; do not confuse the reduced MCP fallback with equivalent server semantics |
| TencentDB Agent Memory | MemoryCore Node `>=22.16`; MemoryKnowledge Node `>=22`; MemoryCore includes `sqlite-vec` and AI/telemetry/provider packages; MemoryKnowledge adds `better-sqlite3`, graphology, LLM SDKs, MCP, and external CodeGraph; FTS/no-vector mode works without an embedder | lexical/read paths are locally useful, but the complete memory+knowledge product is a broader Node/service runtime and advanced semantic/knowledge features must remain optional |

The checkout did not contain installed dependency trees for these systems, so exact transitive license closure and measured resident memory were **not** reconstructed from package manifests alone. Those are implementation-time audits, not facts supplied by this architecture review.

### 1.1 OpenViking

#### Observed

`README.md` describes a virtual filesystem/context database spanning resources, memories, and skills, with L0/L1/L2 hierarchical representations. The audited `HierarchicalRetriever` embeds the query and searches the vector index across L0/L1 before recursive descent; the documented quick start also requires access to an embedding model and a VLM. That does **not** mean the VLM sits in the query retriever itself: it belongs to the broader semantic ingestion/generation workflow. Exact filesystem/grep-style operations are separate and should not be described as requiring embeddings. `pyproject.toml` also pulls a broad server/web/parsing/telemetry/tree-sitter surface. This is not a tiny embedded memory library.

The concrete tool-result path is especially relevant. `openviking/session/tool_result_store.py` persists original tool results with content/hash metadata, while `tool_result_synopsis.py` creates deterministic previews for JSON, delimited data, YAML/XML, code, and text. The model can later work from a synopsis without losing the ability to retrieve the original.

The retrieval code was independently inspected. Its hierarchical retriever performs vector-oriented L0/L1 directory search, optional reranking, then recursively explores child nodes with bounded parallelism; terminal detail is L2. The local vector store uses persistent native storage and timestamped snapshots with completion markers so incomplete snapshots can be ignored during recovery.

The code parser uses tree-sitter to create file-level skeleton/import/symbol summaries and hierarchical directory summaries. The audit did **not** find a first-class callers/callees/impact graph equivalent to a dedicated code graph. Wiki/knowledge-graph outputs are generated compile artifacts such as Markdown and relations data driven by a bot/skill loop, rather than proof of a native graph query engine.

Queue infrastructure persists work and supports stale recovery. A caveat was found in semantic coalescing: a stale-version map used to fence superseded semantic jobs appears process-memory resident, and the audit did not establish startup reconstruction for that map. Treat this as an observed recovery uncertainty rather than claiming restart-safe semantic coalescing.

The main Python package is AGPL-3.0. **`crates/ov_cli`** and **`crates/ragfs`** independently declare Apache-2.0 in their Cargo manifests, and `crates/LICENSE` contains Apache-2.0. `crates/ragfs` is especially relevant because its QueueFS SQLite backend implements at-least-once semantics, WAL-backed persistence, and startup `recover_stale()` that moves abandoned `processing` messages back to `pending`. The thin `crates/ragfs-python` package does not declare a package license in its `pyproject.toml`, so this audit does not infer a blanket license for that binding solely from the Rust crate. The `examples` directory is more complicated: the README and `examples/LICENSE` state Apache-2.0, but this checkout also contains at least nine files inside `examples/` with `SPDX-License-Identifier: AGPL-3.0` (including the OpenWebUI example and graph-show Python files). That is a file-level licensing conflict/ambiguity, so Sovereign must not assume the whole examples tree is safely Apache-licensed for direct reuse without clarification. The Python `openviking_cli/` files likewise carry AGPL-3.0 SPDX. This materially affects direct embedding into Sovereign's core.

#### Inferred for Sovereign

The strongest ideas are hierarchical progressive disclosure, durable original tool results with compact synopses, URI-like evidence addressing, and resumable index snapshots. The exact OpenViking service/runtime topology is unnecessary for Sovereign and would duplicate controller, memory, and model infrastructure.

#### Decision

**Direct reuse:** no OpenViking component is yet selected for Sovereign core inclusion, but `crates/ragfs` and `crates/ov_cli` are concrete Apache-2.0 candidates. `ragfs` QueueFS recovery is particularly worth an implementation-time dependency/footprint/API-fit evaluation because Sovereign is Rust-first; direct reuse should still preserve notices and avoid importing unrelated filesystem surface without value. Do not treat the examples tree as uniformly Apache until its conflicting SPDX markers are resolved. **Adapter integration:** optional external OpenViking adapter when a user intentionally installs/accepts that runtime. **Algorithmic inspiration:** L0/L1/L2 progressive disclosure, at-least-once queue recovery, tool-result offload/synopsis, and completed-snapshot markers. **Clean-room reimplementation:** Sovereign context hierarchy, evidence access, and canonical state integration, so the AGPL runtime does not become the core authority.

### 1.2 agentmemory

#### Observed

The package identifies itself as persistent memory on iii-engine and pins `iii-sdk` (`package.json:63-70`). `src/state/kv.ts` routes canonical state operations through iii state primitives, which means adopting the complete runtime would also adopt iii-engine as a state authority.

Retrieval is the strongest subsystem. `src/state/search-index.ts` implements in-memory BM25; `src/state/vector-index.ts` stores vectors in memory and performs brute-force cosine search; `src/state/hybrid-search.ts` fuses BM25, vector, and graph streams with reciprocal-rank fusion and result diversification. Vector failure can fall back to BM25. `functions/search.ts`/smart-search support compact-first progressive disclosure and token budgets.

The repository's `benchmark/LONGMEMEVAL.md` reports retrieval-only results in which BM25 + MiniLM improves recall over BM25 alone. That supports optional semantic augmentation, but it is not evidence that the complete daemon answers coding questions at the same quality. Another internal quality result is more modest and does not show a universal aggregate gain from the graph stream; therefore Sovereign should measure semantic/graph value rather than presume it.

`src/functions/remember.ts:71-242` shows useful lifecycle patterns: candidate-based near-duplicate detection, version increments, `parentId`/`supersedes`, `sourceObservationIds`, project/agent metadata, TTL, and removal of superseded rows from search projections before inserting the replacement. `src/functions/verify.ts:17-59` traces a Memory back to source observations/session metadata. `src/functions/retention.ts` computes explicit salience/decay/reinforcement scores and records batched audit summaries. `src/functions/checkpoints.ts` models pending/pass/fail/expiry gates linked to actions.

`src/state/index-persistence.ts` persists generation-sharded BM25/vector index snapshots, writes shards before publishing a manifest, audits index changes, and can reject malformed/missing shards. This is a strong crash-consistency pattern. Its cost is also clear: a save serializes the full in-memory index; write amplification grows with corpus size.

The independent audit found lifecycle coherence gaps that prevent treating the current index as a universally consistent projection. Some consolidation/evolution/archive/eviction/snapshot-restore paths write/delete KV records without equivalent live index mutation/rebuild. The refined finding is important: TTL and old-low-value auto-forget paths do clean BM25/vector state, but other paths remain inconsistent. A derived index that can become stale must therefore never be Sovereign's canonical truth.

Scoping is also uneven. The base `Memory` type carries rich version/provenance/project/agent fields, but several semantic/procedural/core/slot structures do not share the same complete envelope. The audit found higher-tier consolidation paths that operate globally and project-labelled slots stored in a shared scope keyed by label. Branch-aware helpers compute branch information, but session persistence does not provide full branch isolation. Code memory is primarily observational (files/commits/tool events), not a source-level AST/symbol code index.

There is concrete interface drift: skill documentation instructs some project-scoped smart-search usage that the registered MCP tool schema does not expose equivalently. The standalone MCP path can, after daemon proxy failure, fall back to a separate writable in-memory/JSON store with weaker scoping/search semantics. This is a split-brain pattern Sovereign must explicitly forbid.

Local embeddings use quantized MiniLM 384-dimensional vectors when configured. Vector search is O(N) and vectors/index serialization remain resident. The audit calculated a raw Float32 lower bound around 154 MB for 100k 384d vectors before JS object/index overhead, and persistence encodes vectors in a larger textual form. This is acceptable for a bounded optional corpus but poor as an unconstrained always-resident default on 8 GB.

The package is pre-1.0 (`0.9.29`) and has substantial test source, but dependencies were absent in the supplied checkout so its tests, iii-engine/transitive installed footprint, and transitive-license set were not independently executed/audited here. Root agentmemory license is Apache-2.0; that root license must not be projected onto absent/unverified transitive packages.

#### Inferred for Sovereign

Use compact→expand retrieval, BM25-first operation, optional MiniLM semantic candidates, RRF/diversification, source-observation citations, version/supersession chains, access/retention signals, and generation-manifest persistence ideas. Uniformly apply scope/provenance to every Sovereign memory type rather than inheriting agentmemory's fragmented envelopes.

#### Decision

**Direct reuse:** no agentmemory core component is currently selected for direct inclusion. Isolated engine-independent Apache-licensed helpers or static content could be candidates after per-file/dependency review; in practice Sovereign is Rust-first, so reuse should be selective rather than importing the full TypeScript runtime. **Adapter integration:** import/read compatibility or an explicitly installed agentmemory service may be exposed, but it remains noncanonical. **Algorithmic inspiration:** BM25-first retrieval, compact→expand disclosure, optional MiniLM candidates, RRF/diversification, provenance/version chains, retention signals, and generation-manifest persistence. **Clean-room/design reimplementation:** canonical persistence, uniform scope model, transactional/outbox projections, snapshots, scheduler, consolidation, slots, audit, and bounded vector storage. This clean-room choice is architectural—not a claim that Apache-2.0 forbids reuse.

### 1.3 TencentDB Agent Memory

#### Observed

The root README describes a deployment with MemoryCore, MemoryHub, and proxy/service pieces plus multiple asset classes: Chat Memory, Skills, Wiki, and CodeGraph. Its default product deployment is therefore broader than a single embedded library.

MemoryCore can run with embedding provider `none`: vector dimensions become zero and SQLite FTS5/BM25 remains usable. When vectors are enabled, the SQLite path uses vector search and the recall/search code merges FTS and vector candidates with reciprocal-rank fusion (`k=60`). However, the **current audited config explicitly treats `embedding.provider="local"` as disabled/not user-exposed**; configured vector mode expects qclaw or another OpenAI-compatible remote-style provider. This is direct evidence for a strong local lexical baseline, not evidence that this checkout already exposes a turnkey local semantic embedder.

Chat memory is hierarchical (L0 Conversation → L1 Atom → L2 Scenario → L3 Core/Persona in the documentation and API surface). Retrieval uses lexical/vector paths and bounded result budgets. MemoryCore documentation also states that read-only queries may avoid an LLM, while extraction/aggregation for L1-L3 requires a host LLM or configured OpenAI-compatible endpoint. The exact hierarchy is product-specific; Sovereign should not copy its semantic categories blindly.

MemoryKnowledge contains separate lifecycle/state for Wiki and CodeGraph. `MemoryKnowledge/src/store/code-graph-service.ts` uses an explicit build queue, state transitions, audit events, version increments, cleanup, and worker release. `MemoryKnowledge/src/store/sqlite-store.ts` persists asset metadata and on startup marks interrupted pending/processing jobs failed because their in-memory execution queue is gone. This is honest recovery semantics and a useful pattern: never pretend an interrupted background build is still running after restart.

CodeGraph metadata is versioned and rebuilt/synced through queued workers. The implementation depends on `@colbymchenry/codegraph`; that dependency's license was not established from the supplied checkout, so direct reuse remains conditional on an explicit license audit. Its exact Apple-Silicon/8-GB runtime and memory footprint also was not measured in this audit, so no capacity claim is made for it.

The knowledge layer's per-wiki SQLite/index design is useful but its defaults are not suited unchanged to the target machine. The audited source configures a read pool up to 300 connections with a 2 MB SQLite cache per connection, an aggregate configured cache upper bound of roughly 600 MB plus file descriptors/other overhead; that is **not** a claim that 600 MB is always resident, because actual connections are demand/LRU driven. Startup behavior also eagerly opens ready CodeGraph indexes and initializes ready Wiki assets in places where a truly sparse Sovereign runtime should remain lazy.

`MemoryCore/src/offload/context-token-tracker.ts` counts context tokens with caching and can prefer provider-reported usage. `MemoryCore/src/services/worker-permit-pool.ts` implements a bounded FIFO permit pool. A durable recall checkpoint with a monotonic cursor supports restart rehydration. One source comment still describes backlog drain as TODO, but the current class implements enqueue/idle-after-drain behavior and the gateway invokes it; therefore this audit does **not** treat that stale comment as evidence of missing backlog drain. These mechanisms are evidence for explicit resource permits and cursor checkpoints, not evidence that every background flow is transparently restart-resumable.

Root license is MIT.

#### Inferred for Sovereign

The best fit is selective: FTS-first local retrieval, explicit knowledge-asset lifecycle, **queued knowledge construction with persisted asset status**, bounded worker permits, token accounting, and versioned metadata. MemoryCore checkpoint/cursor rehydration is real, and MemoryKnowledge can detect interrupted pending/processing builds after restart; however, the audited build queues themselves are in-memory, so interrupted builds are surfaced as failed and require explicit retry/rebuild rather than transparent durable queue replay. Sovereign should start with its own smaller symbol/dependency graph and only activate richer graph/wiki adapters when a task justifies them.

#### Decision

**Direct reuse:** no Tencent component is currently selected for Sovereign core inclusion. MIT-root components may be candidates only after their own dependency boundaries are audited; root MIT must not be projected onto `@colbymchenry/codegraph` or other transitive packages. **Adapter integration:** CodeGraph/Wiki or a full Tencent service can be optional external adapters, never core authority. **Algorithmic inspiration:** FTS-first/no-vector operation, RRF fusion, asset lifecycle/status, monotonic checkpoint cursors, permit pools, token accounting, and explicit interrupted-build failure semantics. **Clean-room/design reimplementation:** Sovereign's embedded canonical memory/repository intelligence, because the full multi-service topology, LLM generation pipeline, currently remote-style embedding configuration, pool defaults, and eager asset restoration conflict with runtime sparsity.

## 2. Control-plane and harness audit

### 2.1 OpenHuman

#### Observed

The checkout's architecture explicitly separates the agent/tool harness from product policy. `gitbooks/developing/architecture/agent-harness.md` describes a loop built around `tinyagents`, while OpenHuman owns approvals, security policy, sandbox/runtime controls, timeout machinery, progress, and product behavior. This supports Sovereign's most important architectural boundary: the LLM/harness cannot be the authority. This should not be read as a claim that every tool has a hard deadline: the audited shell tool is unbounded unless an explicit timeout is supplied.

The harness documentation shows a stable system/tool prefix, append-oriented turn history, context compaction, bounded tool iterations, approval/security middleware, repeated-failure handling, subagent terminal states, and durable artifacts. Its artifact-offload policy stores large results outside immediate model context and replaces them with bounded references/summaries, closely matching Sovereign's evidence-store design.

`src/core/runtime/builder.rs` exposes independent feature activation (`ServiceSet`, `DomainSet`, `ToolGroups`), strong evidence for runtime sparsity by registration/advertisement rather than pretending every capability must be active. Startup/recovery code handles orphaned runs rather than trusting stale `running` state.

Concrete source and tests establish important product-owned controls: `SecurityPolicy` canonicalizes paths, blocks symlink escapes and credential/system locations, classifies unknown commands at least as writes, and enforces command/path gates; the shell tool clears/rebuilds a safe environment allowlist and routes prompt-class actions through the approval layer. A separate generic `DefaultToolPolicy` is intentionally **allow-all**, however, so the reusable lesson is the concrete `SecurityPolicy`/ApprovalGate composition—not an assumption that every OpenHuman policy hook fails closed by default.

The crate/root license declaration is GPL-3.0-only ("only", not "or later").

#### Decision

**Clean-room architectural inspiration** for controller/harness separation, output offload/compression, capability activation, circuit breaking, and recovery. Do not copy GPL core code into Sovereign's default core.

### 2.2 ECC

#### Observed

ECC is primarily a large set of agents, skills, commands, rules, hooks, and supporting workflow content rather than a single authoritative runtime kernel.

The audited skills provide several concrete execution disciplines:

- `skills/iterative-retrieval/SKILL.md` bounds retrieval refinement rather than blindly expanding context;
- `skills/token-budget-advisor/SKILL.md` provides heuristic response-depth/token-budget guidance; it is prompt/workflow advice, not a tokenizer or deterministic runtime budget enforcer;
- `skills/plan-orchestrate/SKILL.md` turns plans into staged work with acceptance conditions;
- `skills/autonomous-loops/SKILL.md` uses execution-depth tiers, persistent state, bounded retries, and worktree/DAG patterns;
- `skills/operator-approval-loop/SKILL.md` binds approval to exact draft/claim state and distinguishes uncertain post-dispatch outcomes from a clean failure;
- `docs/design/ecc-memory-vault.md` treats remembered material as context rather than instruction and supports explicit supersession/governance rather than silent truth promotion.

Root license is MIT.

#### Decision

**Reuse selected skill content** where useful and preserve license notices. More importantly, **translate the operational invariants into deterministic Controller code**. Sovereign should not load ECC's full catalogue or use prompts as substitutes for policy/state machines.

### 2.3 OpenHands checkout

#### Critical correction

The supplied `research/core/OpenHands` repository owns the **Agent Canvas frontend/control center, backend selection, and local-stack orchestration**. Its README/`AGENTS.md` place the SDK, Agent Server, agents/tools, and runtime behavior in a separate `software-agent-sdk`. Therefore this audit does not attribute backend loop, planning, tool-execution, or checkpoint features to code that is absent here.

#### Observed useful patterns

The frontend enforces a typed client boundary for local agent-server calls, checks server-version compatibility, receives server-advertised usable tool capabilities, and has local/public authentication modes. Local launchers generate/persist a session API key; **public mode** avoids baking that key into the frontend, while ordinary local mode does inject the local session capability into the browser-side configuration. Git-provider tokens are server-side secrets rather than localStorage values. Full-stack and minimal launch modes exist, showing a useful distinction between capability-rich installation and small active topology, but `dev:minimal` is a smaller process topology—not a sandbox. The project documentation also warns that a directly connected local Agent Server can have broad/full filesystem access, so Sovereign must not inherit its trust boundary as an isolation guarantee.

#### Decision

Use these as **integration and capability-negotiation patterns**. No backend harness claim is grounded in this checkout.

## 3. Browser and acquisition audit

### Scrapling

`pyproject.toml:63-70` shows a small **parser** core (`lxml`, `cssselect`, `orjson`, `tld`, `w3lib`). Its single optional `fetchers` extra adds `curl_cffi` **and** Playwright/Patchright/browserforge plus related packages (`pyproject.toml:72-83`), so Scrapling's own Fetcher is not equivalent to the base parser-only install.

**Decision:** use Sovereign's Controller-governed HTTP client for the cheapest static acquisition tier and optionally pass returned HTML into Scrapling's base parser. Treat Scrapling's Fetcher as a broader optional adapter only when those extra dependencies are justified; do not activate Playwright/Patchright merely to parse static HTML.

### browser-use

`pyproject.toml:13-51` shows a broad default dependency/runtime surface including CDP/browser harness pieces, multiple model-provider SDKs, document/image libraries, MCP, and macOS PyObjC. The manifest proves breadth, not a measured resident-memory figure; Sovereign therefore keeps the browser process demand-loaded and measures it on the target machine.

`browser_use/browser/watchdogs/security_watchdog.py` checks navigation before dispatch, after redirects, and on new-tab creation, and includes handling for non-standard/encoded IP forms. But the audited **defaults are permissive/network-active**: `allowed_domains=None` means allow all, `block_ip_addresses=false`, downloads are accepted, clipboard/notification permissions are granted, default extensions are enabled and may be downloaded, and telemetry/version checks are enabled unless configuration disables them. Browser state is summarized into model-oriented DOM/tab/page/network structures rather than feeding raw browser internals.

**Decision:** **adapter integration only** for adaptive/visual workflows, with Sovereign overriding the permissive defaults and disabling telemetry/version checks/extension downloads in offline mode. Use browser-use as **algorithmic inspiration** for pre/post-navigation domain checks and browser-state compression; do not inherit its default permissions/network/download/extension policy. Sovereign's normal browser tier should use deterministic CDP actions first and preserve Controller-owned domain/network policy.

## 4. Agent and skill catalogue audit

### agency-agents

The README explicitly describes Markdown personalities/roles and installer/conversion scripts. It is a prompt/content catalogue, not evidence of a control plane. The catalogue is very large (hundreds of roles), which is valuable for inspiration but actively harmful if loaded into a 3B/4B context wholesale.

**Decision:** index metadata only. Curate a tiny Sovereign core role set. Import selected role material as optional versioned content under MIT terms.

### Anthropic-Cybersecurity-Skills

The project is a community project rather than an Anthropic product (`README.md:33-37`) and includes defensive, offensive, and dual-use security material. It uses structured `SKILL.md` frontmatter/body organization and **documents** progressive disclosure: metadata scanning followed by loading only a small number of full workflows (`README.md:189-212`). That is a content convention, not an enforced runtime in this checkout. The tree also contains a large helper-script surface (hundreds of scripts; for example some invoke external CLIs such as `gcloud`), so script execution has a materially different dependency/side-effect profile from loading skill text. Root license is Apache-2.0.

**Decision:** the metadata/full-body split is a good skill-registry pattern. Curate defensive and engineering-relevant skill **text/metadata** as optional content. Helper scripts require individual dependency, side-effect, license, and capability review before registration as tools. Skill text remains untrusted knowledge and cannot grant tools, network, or destructive permissions.

## 5. Maturity and maintainability cautions

These checkouts are current research inputs, not a guarantee of production fitness for Sovereign's exact constraints.

- OpenViking's package metadata marks it early-stage/alpha and carries a broad dependency graph. Its architecture is capable but too expansive for a default embedded M1/8 GB control plane.
- agentmemory is pre-1.0 and shows active hardening plus meaningful tests, but the independent audit found concrete scoping/index/fallback inconsistencies. Its strongest parts are retrieval/provenance ideas.
- TencentDB Agent Memory is broad and service-oriented. Some queues are intentionally in-memory with restart jobs marked failed; that is acceptable product behavior but not equivalent to fully resumable execution. Several default pools/eager initializations should be reduced or made lazy for M1.
- OpenHuman has mature-looking policy boundaries but is GPL-3.0-only and not a drop-in component for Sovereign's core licensing strategy.
- ECC/agency/security libraries are mostly instruction content. Their existence does not remove the need for deterministic orchestration, permissions, and verification.
- Browser frameworks are expensive primarily because the browser itself and surrounding provider/tool stacks are expensive. Keeping them optional is more important than choosing a single brand.

## 6. Reuse decision matrix

| Source | Direct reuse | Adapter | Algorithm/pattern | Clean-room reimplementation |
| --- | --- | --- | --- | --- |
| OpenViking | none selected; Apache `crates/ragfs` (including QueueFS) and `crates/ov_cli` are candidates after fit/dependency review; examples are license-conflicted | optional external adapter | L0/L1/L2 disclosure, tool-result offload, queue/snapshot recovery ideas | context hierarchy, CAS evidence access where direct Rust reuse is not justified |
| agentmemory | none selected; isolated engine-independent Apache helpers/content are candidates after review | optional import/read compatibility | BM25+optional vector/RRF, compact→expand, version chains, provenance, retention | canonical memory/state, uniform scoping, projections, scheduler, snapshots |
| TencentDB Agent Memory | none selected; MIT-root pieces are candidates only after per-dependency audit | optional service/CodeGraph/Wiki adapter | FTS-first path, RRF, checkpoint cursors, asset lifecycle, permit pools, token accounting | default embedded repo/memory intelligence where smaller |
| OpenHuman | no core copy by default | generally unnecessary | harness/policy separation, activation sets, compression, recovery | Controller policy/harness boundaries |
| ECC | selected MIT skills/templates | no runtime dependency needed | depth tiers, bounded loops, exact approval claims, memory governance | encode invariants in Controller |
| OpenHands Canvas | selected MIT UI/client ideas later | local agent-server compatibility only if desired | capability/version negotiation, secret boundary | Sovereign UI/backend contract |
| Scrapling | yes as optional adapter dependency | yes | progressive web acquisition | core HTTP/router logic |
| browser-use | avoid core dependency | yes, demand-loaded | structured browser state/errors/domain controls | core permission/browser routing |
| agency-agents | selected role content | no | role metadata/success contracts | core role set/routing |
| Cybersecurity Skills | selected skill content | no | progressive metadata/body disclosure | permission/security policy |

## 7. Impact on the frozen Sovereign architecture

The independent re-audit **does not invalidate Sovereign's core Controller/Plan IR/local-first architecture or milestone critical path**, but it does justify a narrow revision **2026-09-12.2** research-grounding amendment to the architecture/roadmap:

- OpenViking remains primarily an algorithmic/context reference and optional adapter, but the independent audit identified a stronger direct-reuse candidate than previously recorded: Apache-2.0 `crates/ragfs`, including its Rust QueueFS persistence/recovery machinery. This does **not** justify wholesale OpenViking reuse; dependency/API fit must still be measured, and the examples tree remains file-level license-conflicted.
- agentmemory remains valuable chiefly for retrieval/provenance algorithms. Its Apache root license permits more than Sovereign plans to reuse; clean-room/design reimplementation is chosen because the canonical-state/scope/runtime model does not fit Sovereign, not because its root license requires clean-room work.
- TencentDB Agent Memory strengthens the case for SQLite FTS/BM25-first retrieval, but it no longer serves as evidence for a turnkey local semantic embedder in this revision. Its CodeGraph/Wiki capabilities remain optional adapter candidates pending dependency-license and Apple-Silicon resource checks.
- OpenHuman remains a strong source for concrete security and approval patterns, while Sovereign must not copy the generic allow-all `DefaultToolPolicy` behavior or infer that every OpenHuman execution path has a hard timeout/human prompt.
- The static web tier is corrected to **Sovereign-governed HTTP + Scrapling base parsing** by default. Scrapling's own Fetcher belongs to a broader optional dependency tier because its `fetchers` extra includes curl and browser packages.
- browser-use remains useful only behind a Controller-owned wrapper because its defaults are deliberately more permissive/network-active than Sovereign's security policy; offline mode must also suppress telemetry/version checks and automatic extension acquisition.
- OpenHands minimal/local modes are topology choices, not sandbox evidence. Cybersecurity-skill helper scripts are tool candidates requiring separate dependency/side-effect review, not automatically safe consequences of loading skill text.

Accordingly, the **research-grounding amendment itself** moved `SOVEREIGN_ARCHITECTURE.md` and `implementation-plan.json` to revision 2026-09-12.2 for these optional-adapter/reuse constraints while leaving the 2026-09-12.1 Plan IR/resource/scenario semantics unchanged at that time. A later **2026-09-12.3 M1/8 GB resource stress-test amendment** updates the architecture/roadmap/resource contract and Scenario 8. The subsequent **2026-09-12.4 Plan Compiler/Plan IR/controller/recovery amendment** hardens execution-contract semantics, **2026-09-12.5** makes weak-model retrieval/memory/context telemetry explicit, **2026-09-12.6** adds Controller-owned security/autonomy/resilience policy including untrusted-code isolation, audit integrity, bounded autonomy and external-intelligence boundaries, and **2026-09-12.7** changes roadmap sequencing so the first complete M1 vertical slice proves the canonical minimal Plan Compiler before advanced capabilities. These later amendments do not change factual findings about the audited repositories. This research audit therefore remains source-audit revision 2026-09-12.2.

## 8. Corrections to avoid in future implementation

The following claims would be unsupported or misleading and should not appear in implementation prompts:

1. “OpenHands in this workspace contains the OpenHands backend agent runtime.” It does not; this checkout owns the Agent Canvas frontend/control center and local-stack orchestration, while the SDK/Agent Server/agents/tools/runtime live in the separate `software-agent-sdk`.
2. “OpenViking provides a complete native code impact/call graph.” The audit found tree-sitter summaries and hierarchy, not proof of that full graph capability.
3. “Agentmemory's entire memory hierarchy is project/agent isolated.” Several higher-tier/global structures do not meet that standard.
4. “Agentmemory snapshots are complete disaster-recovery snapshots.” The audited snapshot does not cover every memory/index scope uniformly.
5. “A vector store is required for TencentDB Agent Memory.” Its zero-embedding/FTS path exists.
6. “Tencent knowledge builds automatically resume transparently after process death.” Some interrupted builds are explicitly marked failed because execution queues are in-memory; durable cursors exist for specific flows, not every worker.
7. “All Tencent CodeGraph dependencies are already cleared for direct reuse.” The audit did not establish the license of the external codegraph package in this checkout.
8. “OpenHuman code can simply be copied because it is open source.” Its GPL-3.0-only license matters; Sovereign's default design uses clean-room architectural inspiration.
9. “Browser-use should be assumed lightweight enough to remain resident.” Its manifest shows a broad default dependency/runtime surface, but does not establish a RAM number; Sovereign therefore treats browser residency as demand-loaded and calibrates the actual footprint on the target machine.
10. “Hundreds of agent prompts equal hundreds of agents.” Sovereign logical agents are controller-selected execution profiles over one resident model; prompt catalogues are content, not autonomous runtimes.
11. “OpenViking is uniformly AGPL, or conversely all of its examples/crates are uniformly Apache-2.0.” Neither blanket statement is supported. The main Python package/openviking CLI is AGPL-3.0; `crates/ragfs` and `crates/ov_cli` explicitly declare Apache-2.0; the examples tree has conflicting directory-level Apache notices and file-level AGPL SPDX markers. Resolve reuse at the actual file/crate boundary.
12. “TencentDB Agent Memory already exposes a local embedding provider suitable for Sovereign offline semantic search.” In this audited revision, `embedding.provider="local"` is explicitly mapped to disabled; the local strength established by code is the FTS/no-vector path, while L1-L3 generation still needs a host or OpenAI-compatible LLM endpoint.
