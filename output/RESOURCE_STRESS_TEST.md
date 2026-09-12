# M1 / 8 GB Resource Stress Test

Status: **frozen M1/8GB resource contract — revision 2026-09-12.3 (resource stress-test amendment)**.

This document is the resource contract for the first Sovereign hardware profile. Values below are **initial engineering budgets and admission-control thresholds**, not universal benchmark claims. The implementation must measure actual RSS, model KV usage, browser footprint, build footprint, thermal state, and disk growth on first use and retain per-tool/model calibration data.

## 1. Observed planning-machine baseline

Fresh host observation at **2026-09-12 20:03 IST** reports:

- Apple M1, 8 GiB physical unified memory, 8 CPUs;
- macOS 26.3.1;
- roughly 104 GiB currently available on the system volume;
- `memory_pressure` reported 37% system-wide free percentage at the sample instant;
- the compressor occupied roughly 2.1 GiB of physical pages while representing a much larger compressed logical set;
- encrypted swap had roughly **9.7 GiB in use** at the sample instant;
- `pmset -g therm` reported no recorded thermal/performance warning at that instant;
- the foreground desktop was not empty: Chrome/Chat On Steroids/other GUI processes already held material memory;
- the supplied research tree itself is ~784 MB, showing that source/catalog storage is not the dominant constraint compared with model/build/browser working sets.

The important consequence is that Sovereign cannot assume "8 GB minus its own RSS" is freely available. macOS, the desktop/browser/IDE, filesystem cache, GPU allocations, compressed pages, and user applications already consume the same unified pool. The current high absolute swap usage also proves that **absolute swap-used is not an instantaneous admission signal by itself**: macOS may retain swap after pressure subsides. The Controller therefore uses current pressure plus **swap-out/compressor growth over time** and hysteresis, not a single swap-used number.

## 2. Hardware profile contract

```yaml
profile: m1-8gb
physical_memory_mb: 8192
logical_cpus: 8
normal_model_slots: 1
mutating_task_slots: 1
browser_slots: 1
embedder_slots: 1
heavy_build_slots: 1
heavy_index_slots: 1
minimum_host_free_disk_gib: 20
sovereign_disk_soft_limit_gib: 40
sovereign_disk_hard_limit_gib: 60
normal_controlled_working_set_soft_mb: 4864
normal_controlled_working_set_hard_mb: 5632
minimum_launch_headroom_soft_mb: 1536
minimum_launch_headroom_hard_mb: 1280
default_model_input_tokens: 8192
default_model_output_reserve_tokens: 1536
hard_model_input_tokens_without_profile_override: 16384
heavy_lease_recovery_green_seconds: 120
heavy_lease_reload_cooldown_seconds: 30
```

The working-set and headroom values are starting policy. Live macOS pressure/thermal/swap-growth signals can lower admission even when arithmetic says a lease would fit. `hard_model_input_tokens_without_profile_override` is a **hardware-profile safety ceiling**, not an invitation to use 16k routinely.

## 3. Memory/RSS budgets

| Capability | Provisional steady admission envelope | Provisional peak envelope | Default lifecycle |
| --- | ---: | ---: | --- |
| Controller + SQLite + CAS metadata + small caches | 150-300 MB | 400 MB | always resident; exceeding peak is a bug/calibration failure |
| Current-task FTS/symbol/dependency cache | 64-256 MB | 384 MB | bounded/mapped; rebuildable cache pages evict first |
| 3B Q4-class model at 8k input profile | 2.4-3.4 GB | 3.0-4.2 GB during load/prefill | one `MODEL` lease |
| 4B Q4-class model at 8k input profile | 3.0-4.0 GB | 3.6-4.8 GB during load/prefill | one `MODEL` lease only after target calibration |
| Small local embedder + runtime | 250-650 MB | 800 MB | semantic escalation only; zero-resident when idle |
| Deterministic Chromium/CDP, one active tab | 500 MB-1.0 GB | 1.25 GB | isolated browser lease; zero-resident when idle |
| Adaptive browser worker + Chromium, excluding LLM | 800 MB-1.5 GB | 1.8 GB | optional; strict one-tab/action budget |
| One language server | 150-800 MB | 1.0 GB | one at a time, on demand |
| FTS/tree-sitter index build | 128-384 MB | 512 MB | bounded batches; one index lease |
| Optional CodeGraph/wiki build/open | **1.0 GB reserved until calibrated** | **1.5 GB admission ceiling** | optional/noncanonical; serialized by default |
| Build/test command | 200 MB-2.5+ GB | unknown tools treated as 3.0 GB class | measured task-specific lease; first heavy run isolated |

### Admission rule

Before launching a heavyweight process, ResourceGovernor calculates:

```text
projected_controlled_rss
  = current_measured_controlled_rss
  - evictable_idle_rss
  + calibrated_p95_rss(requested_lease)
```

Admission requires all of:

1. `projected_controlled_rss <= current_profile_limit`;
2. estimated host headroom remains at least the configured reserve;
3. macOS memory pressure is not above the profile's launch threshold;
4. no mutually-exclusive heavy lease is active;
5. the action's task resource budget permits the lease.

Unknown/un-calibrated heavyweight tools get conservative admission and are measured on their first bounded run.

### 3.1 Model weight, runtime, and KV planning envelope

The resource profile must separate four contributors rather than use one "model size" number:

| Component | 3B Q4-class planning envelope | 4B Q4-class planning envelope | Notes |
| --- | ---: | ---: | --- |
| quantized weight file / mapped weight pages | ~1.7-2.1 GB | ~2.2-2.7 GB | engineering range; exact GGUF/MLX format and quant metadata vary |
| runtime/Metal/backend scratch | 0.25-0.60 GB | 0.30-0.70 GB | backend/version dependent |
| KV + attention state at 8k | 0.20-0.80 GB | 0.25-0.90 GB | architecture/GQA/cache precision dependent |
| KV + attention state at 16k | 0.40-1.60 GB | 0.50-1.80 GB | must be measured before enabling 16k |
| transient load/prefill margin | 0.3-0.8 GB | 0.4-0.9 GB | covers model load, prefill and allocator spikes |

These are **not benchmark claims** for a named model. M1 closure must record the exact backend/model/quantization and directly measure startup peak, post-load idle footprint, 4k/8k/12k/16k KV growth where supported, first-token prefill peak, decode footprint, unload residual, and reload behavior. A backend/model is rejected for the default 8 GB profile if its calibrated 8k reasoning lease cannot preserve the host reserve under an otherwise ordinary desktop workload.

Default policy is 8k input with separately reserved output. 12k is an opt-in calibrated tier. 16k is the un-overridden M1/8 GB hard ceiling. A task that cannot fit at that ceiling must refine evidence, summarize, split, or replan; the Controller does not keep increasing context until macOS swaps.

### 3.2 Memory pressure states and hysteresis

The governor samples current memory-pressure state plus controlled-process footprint and **deltas** in swap-outs/compressor use over a rolling window. Initial state bands are:

| State | Initial trigger examples | Admission behavior |
| --- | --- | --- |
| `GREEN` | OS pressure normal; swap-out growth <64 MiB/min; controlled working set <4.75 GiB; no recent pressure event | normal profile rules |
| `GUARDED` | pressure normal but swap-out growth 64-256 MiB/min, controlled set 4.75-5.25 GiB, or pressure warning occurred in last 120 s | no new overlapping heavy lease; finish/evict before another |
| `CONSTRAINED` | OS warning/serious pressure, swap-out growth >256 MiB/min, or controlled set >5.25 GiB | evict optional heavy processes, serialize to one heavyweight, reduce worker counts |
| `EMERGENCY` | critical pressure, allocation failure, repeated resource kill, or uncontrolled child growth | checkpoint, terminate optional heavy work, block new heavy admission, preserve Controller/SQLite/CAS |

The numeric rates are initial engineering thresholds to be calibrated in M6; the **policy shape is normative**. High absolute swap-used alone does not force `CONSTRAINED`, because the 2026-09-12 sample already shows ~9.7 GiB swap can coexist with a reported 37% system-wide free percentage and no `pmset` warning. Positive swap-out growth and pressure transitions are what prevent launch/reload thrash.

After `GUARDED`/`CONSTRAINED`, the system must remain `GREEN` for at least 120 s before restoring overlapping heavy concurrency. After a heavy eviction, wait at least 30 s of stable pressure before automatic reload. More than one evict→reload→evict cycle for the same capability inside five minutes causes checkpoint/defer instead of oscillation.

## 4. CPU and thermal budget

The MacBook Air is fanless, so sustained CPU saturation can reduce throughput and increase memory pressure even when RSS is acceptable.

Initial policy:

- Controller/background housekeeping: effectively one low-duty thread.
- Local model inference: default backend thread count calibrated in the 4-6 CPU range rather than blindly consuming all 8 CPUs.
- Indexing/parsing while the model is resident: at most 2 workers; with model unloaded and pressure `GREEN`: at most 4 workers. One repository batch at a time.
- Embedding: 2-4 CPU workers depending backend; it does not run concurrently with heavy build/browser/index work by default.
- Heavy builds/tests: initial Controller cap of **2 parallel jobs** for unknown/JVM/Node/link-heavy workloads. Up to 4 jobs is allowed only after calibration, with model/browser/embedder unloaded and pressure `GREEN`.
- No simultaneous CPU-heavy model inference + full index build + heavy build.
- Read macOS thermal state where available. On serious/critical thermal state, stop launching new heavy work and checkpoint; let deterministic light work proceed.

Resource telemetry stores wall time, user/system CPU, maximum RSS/physical footprint when observable, child count, swap/compressor deltas, exit reason, and thermal state before/after the lease. Later admission uses measured p50/p95 rather than static guesses. A build tool that ignores the Controller's worker cap and creates excessive children is terminated under the task process budget and classified as a resource/environment failure, not allowed to force the host into swap thrash.

## 5. Disk budget

Sovereign must preserve host free space because model runtimes, Git worktrees, package caches, compilers, and macOS swap all compete for the same SSD.

Initial managed budget:

| Store | Soft target | Hard/action rule |
| --- | ---: | --- |
| Installed local model artifacts managed by Sovereign | 12 GiB | LRU/manual eviction before additional model acquisition |
| CAS raw evidence/artifacts | 10 GiB | may grow to 20 GiB; GC only unreferenced/expired data |
| Repository/search indexes | 5 GiB | may grow to 10 GiB; rebuildable indexes evicted first |
| Controller worktrees + task temp | 10 GiB | old completed worktrees pruned after evidence/change-set preservation |
| Browser profiles/download/cache | 2 GiB | isolated task profile TTL; user-approved persistent profiles separately accounted |
| SQLite authoritative state | warn at 2 GiB | compact/archive event payload bodies to CAS before uncontrolled growth |

Global admission stops new disk-expanding work if either:

- Sovereign-managed storage reaches the hard profile limit; or
- host free space would fall below ~20 GiB.

Evidence GC never deletes an artifact still referenced by a plan revision, action, verification result, checkpoint, completion record, or governed memory provenance.

Per-task initial retained-raw spool quotas are deliberately small relative to the global CAS budget: **64 MiB** for tiny/medium tasks, **512 MiB** for build/integration-heavy tasks, and at most **1 GiB** only when the Plan IR explicitly requests it. Process output may be segmented earlier. A 10 GiB global CAS budget is not permission for one task to emit 10 GiB of logs.

Raw-output limits are intentionally split so later implementers do not conflate process safety, evidence retention, and model context:

- `CommandSpec.output_limit_bytes`: per-action process-output safety limit/segmentation threshold enforced by the runner;
- `resource_budget.max_output_bytes`: aggregate observed tool/process output ceiling for the task;
- `resource_budget.max_retained_raw_bytes`: retained **post-ingress/redacted** raw spool/CAS quota for the task;
- `context_budget`: model-facing token/evidence budget after deterministic compression.

Exceeding a retained-raw quota never becomes silent data loss. The evidence record must set `raw_complete=false` and record captured byte ranges/chunks, observed counts when knowable, and the exact segmentation/truncation/termination reason. Known secret-bearing pre-redaction bytes are not persisted merely to make the raw artifact byte-for-byte complete.

## 6. Indexing policy

### Initial repository registration

Registration is staged so large codebases become useful before full indexing completes:

1. paths, Git metadata, instructions, language/build markers;
2. FTS text chunks for relevant source/docs, excluding generated/vendor/binary files by policy;
3. tree-sitter symbols/imports for supported languages;
4. dependency edges;
5. optional semantic vectors only after a real task demonstrates a retrieval gap.

Each stage checkpoints a cursor and source snapshot. The scheduler may execute tasks using exact search while later stages continue when a resource lease is available.

### Index memory/disk control

- Parse bounded file batches; do not hold a whole repository AST in memory.
- Keep SQLite FTS and graph rows durable on disk; cache only current task neighborhoods.
- Large generated files are metadata-only unless a task explicitly references them.
- Index records carry file blob/source hashes so incremental refresh touches changed files and affected graph neighbors.
- If an index quota is reached, retain path/exact/FTS coverage first and degrade optional summaries/vectors before blocking the project.

Initial derived-index planning envelope is **0.5x-3.0x indexable source-text bytes on disk** for FTS + symbol/import/dependency metadata, depending language/chunking/tokenization. This is intentionally a broad engineering bound, not a benchmark. Repository registration records actual source bytes and actual index bytes so future admission uses measured ratios.

| Indexable text size | Scheduling rule | Peak index-memory target | Provisional derived-disk envelope |
| --- | --- | ---: | ---: |
| <=25 MiB | single staged pass | <=192 MiB | 25-100 MiB |
| 25-150 MiB | bounded batches/checkpoints | <=256 MiB | 50-450 MiB |
| 150-500 MiB | module/repository partitions | <=384 MiB | 0.3-1.5 GiB |
| >500 MiB | never whole-repo AST; staged partitions only | <=512 MiB | measured before full coverage |

The scheduler may stop after FTS/symbol coverage sufficient for the current task. "Repository indexed" is not a requirement to eagerly build every optional projection.

## 6.1 SQLite canonical-state and FTS budget

SQLite is embedded, not a server farm. Initial M1/8 GB limits:

- one writer connection and at most two read connections in the normal control plane;
- **32 MiB target / 64 MiB hard aggregate SQLite page-cache budget** across canonical state + FTS connections;
- `mmap_size` disabled or capped at **64 MiB** until measurement proves benefit without hiding large mapped working sets;
- WAL soft-checkpoint target around **64 MiB**; a WAL approaching **256 MiB** without safe checkpoint progress is a health/resource event;
- long-running readers may delay WAL truncation but may not justify unbounded WAL growth;
- FTS result materialization is bounded and paged; no query may hydrate an entire large index into Controller memory;
- full `VACUUM` is an idle maintenance action requiring adequate free disk (roughly database-size working space). Normal cleanup prefers incremental/page-reuse strategies and CAS body offload.

The Tencent 300-connection/wiki-pool pattern is explicitly **not** inherited. Canonical truth remains SQLite rows/CAS evidence; FTS and other indexes are projections that can be rebuilt.

## 6.2 Embedding/vector budget

Semantic retrieval is an optional derived projection. The default local profile assumes a small 384-dimensional embedding class only for budgeting; another dimension requires recalibration.

At 384 dimensions, float32 vectors are 1,536 bytes/vector before IDs/index overhead:

| Active corpus | Raw float32 vector bytes | Initial total in-memory planning envelope with IDs/index overhead |
| ---: | ---: | ---: |
| 50k vectors | ~73 MiB | ~100-180 MiB |
| 100k vectors | ~147 MiB | ~190-320 MiB |
| 250k vectors | ~366 MiB | ~475-750 MiB |

The **default active-corpus ceiling is 50k vectors** and the **hard M1/8 GB ceiling is 100k float32-equivalent vectors per admitted semantic corpus** unless a calibrated profile explicitly raises it. Larger historical corpora remain on disk/sharded or are rebuilt/selected by project/task; they are not all made hot. Float16/int8 backends may use less, but admission initially budgets the float32-equivalent envelope rather than assuming compression.

Embedding activation policy:

1. lexical/symbol/dependency retrieval must first record a concrete recall gap;
2. acquire `EMBEDDER`; by default `MODEL`, `BROWSER`, `BUILD_HEAVY`, and unrelated `INDEXER` are not concurrently active;
3. embed in bounded batches (initial batch <=256 chunks or <=16 MiB source text, whichever is smaller);
4. commit vectors as derived records with model/version/source hashes;
5. unload embedder after the task/short idle TTL; vector pages may remain on disk and be lazily mapped under the cache cap;
6. if memory pressure rises, discard semantic mappings before any canonical state/evidence.

Semantic capability can therefore be fully evicted without loss of truth. Rebuild source is repository/memory canonical data plus provenance/version metadata.

## 7. Mutually exclusive heavy capabilities

Default M1 admission matrix (`SAFE` = ordinary concurrency, `COND` = only after calibrated p95 + live `GREEN`, `SER` = serialize by default, `NO` = forbidden):

| Active \ Requested | MODEL | EMBEDDER | CDP_BROWSER | ADAPTIVE_BROWSER | BUILD_HEAVY | INDEXER | CODEGRAPH/WIKI | LSP |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| MODEL | **NO second model** | SER | COND | COND only with calibrated 3B/4B combined lease | SER | COND for small incremental batch only | SER | COND |
| EMBEDDER | SER | one | SER | SER | SER | COND if it is the same semantic-build phase | SER | SER |
| CDP_BROWSER | COND | SER | one | n/a | SER | SER | SER | SER |
| ADAPTIVE_BROWSER | COND | SER | n/a | one | SER | SER | SER | SER |
| BUILD_HEAVY | SER | SER | SER | SER | one | SER | SER | project-dependent/usually SER |
| INDEXER | COND small only | COND same phase | SER | SER | SER | one | SER | SER |
| CODEGRAPH/WIKI | SER | SER | SER | SER | SER | SER | one | SER |
| LSP | COND | SER | SER | SER | usually SER | SER | SER | one |

`COND` never means "if the sums look barely under 8 GB." It requires calibrated process p95, the 1.25-1.5 GiB host reserve, `GREEN` pressure, no recent swap-growth event, and a hardware-policy rule permitting the pair. Unknown capability pairs are `SER`.

Deterministic CDP browser work normally serializes with the model because the model is not needed while the browser performs a known action/verification. Adaptive browser mode is the exception: it may require the one local LLM and browser to coexist. That pair is admitted only if the **combined calibrated p95 plus core stays below 4.75 GiB** and host reserve remains >=1.5 GiB at launch. Otherwise the Controller falls back to deterministic/static evidence where possible, switches to a smaller already-supported single model after unloading the current one, or checkpoints/defers; it never adds a second resident model.

## 8. Activation and eviction policy

### Activation

Heavy capability activation requires a concrete task reason:

- `MODEL`: a semantic decision/proposal is needed.
- `EMBEDDER`: exact/lexical/structural retrieval has an identified recall gap.
- `BROWSER`: static HTTP/parser acquisition cannot establish required UI behavior.
- `LSP`: symbol/type/refactoring evidence materially exceeds tree-sitter/lexical capability.
- `INDEXER`: the current task depends on missing structural coverage or incremental background quota is available.
- `BUILD_HEAVY`: an acceptance/verification contract requires it.
- `CODEGRAPH/WIKI`: native exact/FTS/symbol/dependency retrieval has a documented structural gap and the optional adapter has passed license/resource calibration.

### Eviction order under pressure

1. stop admitting new heavy work and lower build/index worker counts;
2. drop optional query/result caches and close nonessential mapped vector/index pages;
3. unload embedder;
4. close idle browser/adaptive worker and ephemeral profile processes;
5. close idle language server;
6. terminate/release optional CodeGraph/wiki process/index lease;
7. unload local model if the next phase is deterministic/heavy and its context/evidence checkpoint is durable;
8. if pressure still fails to recover, checkpoint/defer the task instead of starting another heavyweight lease.

Canonical SQLite/CAS state is never an eviction target. Rebuildable FTS/symbol/vector/codegraph/wiki projections may be closed or deleted only under their own retention policy.

Each heavy process has an idle TTL and a health/reap policy. Initial idle TTLs are short: embedder 30 s, browser 60 s, LSP 120 s, model 120 s after a reasoning phase when no next model task is ready. Repeated unload/reload thrash is prevented by the hysteresis/cooldown rules in Section 3.2. Process death does not imply task failure until the Controller classifies whether required durable output was committed.

### Admission algorithm

For every heavy request the Controller performs, in order:

1. verify Plan IR/task permission and lease class;
2. reject any forbidden pair from the hardware-profile matrix;
3. sample pressure, controlled footprint, swap-out/compressor deltas, thermal state, free disk, and current heavy leases;
4. compute `projected_controlled_rss` using calibrated p95, but treat it as advisory telemetry rather than physical-memory truth;
5. if `GUARDED` or worse, evict/serialize before considering launch;
6. checkpoint before model/browser/build/index handoff if the current task has mutation/context state to preserve;
7. launch with CPU/child/output/disk/network ceilings;
8. sample again after warmup/prefill/first page/first compile phase; abort and classify resource failure if the lease exceeds its calibrated envelope;
9. on release, persist calibration telemetry and only restore evicted capabilities after cooldown and stable `GREEN`.

## 9. Model context, task-depth, and KV pressure

The architecture makes an 8k input profile the baseline for a 3B/4B model, reserving generation tokens separately. 12k/16k is allowed only after backend-specific memory calibration shows enough reserve.

Controller policy prevents context growth from silently increasing model memory:

- C0 contract is exact and persistent across turns.
- C1 direct evidence is refreshed/deduplicated.
- C2-C5 are demand-loaded and evictable.
- raw tool output never enters context wholesale by default.
- a task exceeding its context budget triggers evidence refinement or bounded replanning rather than an automatic context-window increase.

Initial depth-class budgets:

| Task class | Max model input per call | Output reserve | Evidence-item cap | Model-call budget | Default retrieval/capabilities |
| --- | ---: | ---: | ---: | ---: | --- |
| D0/D1 tiny | 4k tokens | 1k | 16 | 1-2 | exact/path/symbol; no semantic/browser/memory unless evidence forces it |
| D2/D3 medium | 8k | 1.5k | 32 | up to 6 per task | exact + FTS + structural; compact memory/ADR as needed |
| D4 execution task | 8k | 1.5-2k | 48 | up to 8 per bounded task | staged repo evidence, contracts, focused failure/context packets |
| D4 planning/review exception | 12k if calibrated | 2k | 64 | bounded by plan budget | multi-repo summaries/contracts only; never raw all-repo context |

16k is a profile ceiling, not a normal D4 budget. A large project can consume many bounded task packets over time, but no single call receives all repository state or complete session history. Context metrics must report injected tokens, reused tokens, duplicate ratio, raw-to-synopsis compression, evidence hit/expansion rate, and verified-task token cost.

## 10. Phase simulation: tiny request

Example: `Change the Save label to Apply.`

| Phase | Active heavy leases | Approximate Sovereign-controlled working set | Behavior |
| --- | --- | ---: | --- |
| exact discovery | none | ~0.2-0.4 GB | exact path/text/symbol; no broad index activation |
| reasoning/edit proposal | MODEL | ~2.7-4.2 GB depending calibrated 3B/4B backend | <=4k input, usually one call |
| focused test | MODEL retained only if command is calibrated light | ~3-4.5 GB typical envelope | 1-2 tool actions; output compressed |
| completion | none/model TTL | returns toward control-plane baseline | checkpoint + evidence |

No browser, embedder, LSP, persistent-memory scan, multi-agent process, or wiki/codegraph service starts. Expected disk growth is normally patch/checkpoint/test evidence in the MiB range, not a repository-wide index rebuild.

## 11. Phase simulation: medium security-sensitive feature

Example: `Add Google authentication.`

1. **Evidence phase:** Controller + FTS/symbol/dependency index. No browser/embedder by default.
2. **Planning/reasoning:** load one model; create D3/D4 plan with auth/security verification.
3. **Implementation:** same model switches logical roles serially.
4. **Package/network evidence:** network remains offline unless the Plan IR explicitly grants package registry/provider documentation access. Secrets remain `SecretRef`; no browser credential is globally injected.
5. **Build/test:** if native/JS build is unknown or calibrates above ~1 GiB, checkpoint and unload model; start at two build jobs and raise only if calibration permits.
6. **Browser E2E:** launch isolated deterministic Chromium only if acceptance requires the actual flow. Prefer model unloaded while browser is resident; store bounded DOM/screenshot/network evidence and close browser. Adaptive browser mode is a separate conditional lease and cannot coexist with embedder/build/LSP.
7. **Semantic fallback:** only after an identified lexical/structural miss; if used, embed in bounded batches and unload before browser/build.
8. **Review:** reload the same model in fresh security-review context using the diff and compressed E2E evidence.

Peak phases occur sequentially rather than additively. Sovereign therefore preserves advanced browser/review capability without needing model + embedder + Chromium + build simultaneously.

## 12. Phase simulation: large five-repository migration

Example: cross-service authentication migration.

- Register five repository baselines, but keep only metadata and bounded current-task index neighborhoods hot.
- Stage FTS/symbol indexing per repository/module; never create a single all-repository AST or giant in-memory dependency graph.
- Compile one D4 cross-repo DAG and store it in SQLite; DAG parallelism is logical, while the M1 scheduler serializes mutation/model tasks.
- Work one repo/worktree at a time where contracts allow.
- Large repository builds run under BUILD_HEAVY with model eviction as required.
- Cross-repo integration gate runs after compatible producers/consumers exist; it may execute several services/processes, but those service leases replace the model lease during the gate.
- A plan failure in one protocol branch recompiles that branch; it does not re-index/re-plan all five repositories unless shared contracts changed.
- Semantic retrieval and CodeGraph adapters remain absent until a concrete structural retrieval miss justifies them.
- If optional semantic search is justified, activate at most the current repo/task shard (default <=50k vectors); do not hot-load vectors from all five repos.
- Optional CodeGraph/wiki compilation is a separate serialized heavy phase with a provisional 1.5 GiB admission ceiling until target-machine calibration.
- Disk growth is checked before clone/worktree/index/build-cache expansion; rebuildable indexes and completed task temp are pruned before authoritative evidence.

The stress objective is not "everything stays resident". It is that every capability remains reachable through staged execution while the active working set remains sparse.

## 12.1 Worst-case pressure simulations

### Large build requested while model is resident

If `BUILD_HEAVY` is unknown or calibrated above safe co-residency, admission is denied. Controller checkpoints task/context IDs, unloads the model, waits for stable pressure, launches the build at two jobs, captures bounded evidence, reaps children, waits for cooldown, and reloads the same model only if `GREEN`. This is a normal phase transition, not a failure.

### Browser requested during a model phase

For deterministic CDP verification, checkpoint/snapshot the reasoning state and normally unload the model. For adaptive browser interaction, only the calibrated `MODEL + ADAPTIVE_BROWSER` pair may coexist; no embedder/build/LSP/CodeGraph lease is admitted. If the pair cannot preserve reserve, the task uses static/deterministic evidence where possible or defers with exact resource evidence. It never spawns a second model.

### Semantic retrieval requested while pressure is high

The `EMBEDDER` lease is denied under `GUARDED`/`CONSTRAINED`; FTS/symbol/dependency retrieval remains available. Because vectors are derived, no truth is lost. The task either proceeds lexically, waits for `GREEN`, or records that semantic escalation was unavailable and replans evidence acquisition if necessary.

### Swap is already heavily used

The observed host currently has ~9.7 GiB swap used, so absolute swap occupancy alone cannot permanently disable Sovereign. The governor samples swap-out growth. Stable/high historical swap with normal pressure may permit one calibrated model lease; increasing swap-outs or warning pressure blocks overlapping heavy leases and triggers eviction/hysteresis.

### Compiler/test tool spawns excessive workers

`max_subprocesses`, process-group ownership, child CPU time, and injected job caps are enforced by the runner. A tool that exceeds the ceiling is stopped; evidence records requested/observed child counts and memory/CPU. Retry uses lower parallelism or model eviction. The Controller never lets an unbounded native worker pool decide the machine's concurrency policy.

### Disk free space falls below reserve

No new clone/model/index/browser-download/build-cache expansion begins if projected host free space would cross 20 GiB. The Controller evicts rebuildable indexes, expired browser profiles, completed temp worktrees, and unreferenced CAS candidates in that order; referenced evidence, canonical SQLite state, active checkpoints, and user repositories are never silently removed.

## 13. Failure/resource interaction

Resource exhaustion is a first-class failure category, not an implementation failure and not automatically a plan failure.

Examples:

- Build killed by OS memory pressure: record `environment_resource_failure`, lower concurrency/unload model, then retry if budget allows.
- Browser exceeds profile after multiple pages: persist evidence, terminate browser, reopen only the required page/state if reconstructable.
- Index job exceeds disk quota: stop optional index layers, retain source/FTS baseline, record degraded capability; do not mark repository corrupt.
- Model cannot fit requested context: shrink/retrieve context first; if the task fundamentally requires broader evidence, escalate/replan rather than enter swap-thrash loop.

Repeated resource failure consumes a separate retry budget and eventually blocks with exact measured evidence.

## 14. Resource acceptance tests

A conforming M1 profile implementation must prove:

1. never more than one local LLM resident;
2. browser and embedder are zero-resident when unused;
3. real-model calibration records weight/runtime/KV/startup/prefill/unload/reload memory at the target context tiers;
4. 8k is the normal context profile; 16k cannot be enabled without calibrated fit and no task can auto-grow beyond the profile ceiling;
5. a heavy build can trigger model eviction and later clean reload;
6. every heavy child process is reaped after crash/restart;
7. build/test worker caps and subprocess ceilings prevent runaway parallelism;
8. SQLite normal topology stays within the connection/cache/WAL limits or emits a health/resource event rather than silently growing;
9. index construction is resumable, bounded in memory, and records actual source:index disk ratios on medium/large calibration repos;
10. default semantic corpus <=50k vectors and hard M1/8 GB active corpus <=100k float32-equivalent vectors unless an explicit calibrated profile overrides it;
11. semantic retrieval can be disabled/evicted with canonical truth and core scenarios intact;
12. browser adapters can be uninstalled with core scenarios still passing;
13. deterministic browser, adaptive browser, embedder, build, indexer, and optional knowledge adapters obey the concurrency matrix;
14. optional CodeGraph/wiki adapters remain noncanonical and cannot be promoted until Apple-arm64 memory/disk calibration passes;
15. storage quotas preserve authoritative state/evidence references while evicting rebuildable/expired data first;
16. resource admission uses measured footprint + live pressure + swap/compressor **deltas**, not static RSS estimates or absolute swap-used alone;
17. pressure hysteresis/cooldown prevents model/browser/build unload-reload oscillation;
18. tiny, medium, and large reference scenarios complete or checkpoint/defer cleanly without sustained resource thrashing.
