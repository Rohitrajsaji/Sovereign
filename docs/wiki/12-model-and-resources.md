# Model and resources

> Snapshot: HEAD `d266399` (2026-09-24) plus uncommitted work (+3440/−604 across 34 files, observed 2026-09-25).

One local model is resident at a time. Roles share it serially. Cloud APIs are optional and have zero tool authority ([08-security-and-permissions.md](08-security-and-permissions.md)).

## Backend

`ModelBackend` in `crates/sovereign-model/src/lib.rs`: `capabilities`, `load`, `complete`, `count_tokens`, `health`, `residency_proof`, `unload`. `MODEL_SCHEMA_VERSION` = 1. `M1_HARD_INPUT_CONTEXT_TOKENS` = 16384. `DEFAULT_MAX_HTTP_RESPONSE_BYTES` = 8 MiB.

`LocalOpenAiBackend` talks to a loopback OpenAI-compatible server. `LlamaServerLaunch` starts `llama-server` with a cleared environment plus `PATH`, arguments `-m <gguf> --host --port -c <ctx> --jinja`, then polls health. `Drop` and `unload` kill the child. Token counts come from `POST /tokenize`. Admission uses `server_context_tokens = context + output_reserve`. Usage is read from the response token fields.

`DeterministicFakeBackend` returns a FIFO of scripted responses and does not start a process. Most workspace tests use it. It is not qualification evidence.

On disk, gitignored:

- `.models/Qwen3-4B-Q4_K_M.gguf`
- `.tools/llama-b10516/llama-b10516/llama-server` (and `llama-cli`, `llama-tokenize`)

The runner reads `SOVEREIGN_MODEL_RUNTIME`, `SOVEREIGN_MODEL_PATH`, and `SOVEREIGN_MODEL_NAME`. Smoke tiers in `model-smoke.rs` are 4096, 8192, 12288, and 16384.

## What `sovereign run` loads

`apps/sovereign/src/runner.rs` sets capability `max_context_tokens` to 16384. The load call uses context 8192 and reserve 1536, so the server `-c` is 9728. Controller output cap for the M1 slice is `M1_MODEL_OUTPUT_TOKENS` = 512. Uncalibrated model admission is `M1_MODEL_UNCALIBRATED_ADMISSION_MIB` = 4096. A measured calibration replaces it (see below).

Compilation may call the model at most twice (`MAX_COMPILER_MODEL_CALLS`). A timed-out call consumes a model-call budget unit and cannot retry outside Controller counters.

## Hardware profile

`HardwareProfileV1::m1_8gb` in `crates/sovereign-policy/src/resources.rs` is the frozen M1/8 GB profile. Narrative budgets are in [output/RESOURCE_STRESS_TEST.md](../../output/RESOURCE_STRESS_TEST.md). If prose and this function disagree, the function wins.

| Field | Value |
| --- | --- |
| `profile_id` | `m1-8gb` |
| `physical_memory_mib` | 8192 |
| `logical_cpus` | 8 |
| `normal_model_slots` | 1 |
| `mutating_task_slots` | 1 |
| browser, embedder, heavy build, heavy index slots | 1 each |
| `minimum_host_free_disk_mib` | 20 GiB |
| `sovereign_disk_soft_limit_mib` | 40 GiB |
| `sovereign_disk_hard_limit_mib` | 60 GiB |
| `normal_controlled_working_set_soft_mib` | 4864 (about 59% of 8192) |
| `normal_controlled_working_set_hard_mib` | 5632 (about 69% of 8192) |
| `minimum_launch_headroom_soft_mib` | 1536 |
| `minimum_launch_headroom_hard_mib` | 1280 |
| `default_model_input_tokens` | 8192 |
| `default_model_output_reserve_tokens` | 1536 |
| `hard_model_input_tokens_without_profile_override` | 16384 |
| `constrained_controlled_working_set_mib` | 5376 |
| `heavy_lease_recovery_green_seconds` | 120 |
| `heavy_lease_reload_cooldown_seconds` | 30 |
| `heavy_lease_oscillation_window_seconds` | 300 |
| `max_completed_eviction_cycles_per_window` | 1 |
| `unknown_heavy_admission_mib` | 3072 |
| `unknown_heavy_first_run_max_jobs` | 2 |
| `calibrated_build_max_jobs` | 4 |
| `unknown_heavy_first_run_max_subprocesses` | 2 |

`HeavyLeaseClass::KNOWN` is Model, Embedder, CdpBrowser, AdaptiveBrowser, BuildHeavy, Indexer, CodegraphWiki, Lsp. `Unknown` serializes against everything and consumes `BUILD_HEAVY` task authority. Idle TTLs: embedder 30s, browsers 60s, model and LSP 120s, build, indexer, and codegraph 0.

Pressure bands are `PressureBand::{Green, Guarded, Constrained, Emergency}`. Guarded growth 64 MiB/min, constrained growth 256 MiB/min.

Uncommitted qualification tests distinguish "compiler model boundary is not reached without frozen headroom" from "admitted compiler model boundary can begin at 69 percent." Do not lower the hard working set to make a launch succeed.

`admit_rust_verification` is the narrower build admission described in [09-tools-sandbox-processes.md](09-tools-sandbox-processes.md). It does not raise the RSS ceiling.

## Calibration

Added 2026-09-26. `ModelCalibrationV1` (`crates/sovereign-policy/src/model_calibration.rs`) holds measured peak RSS samples for one key: model identity, server context (9728 on this profile), profile id, and profile digest. The estimate is the largest sample plus 15 percent, floor 1024 MiB, and needs at least 3 samples. A larger sample always raises it.

`crates/sovereign-controller/src/model_calibration.rs` stores it in namespace `controller.model_calibration` (CAS write plus a `model_calibration_sample_recorded` event). Samples come from Controller-owned loads (`startup_peak_rss_kb`, `post_load_rss_kb`) and calls (`peak_rss_kb_during_call` through `PeakRssRecorder`). A failed sample write never changes a task outcome. MODEL admission uses the estimate when one exists, otherwise 4096.

The runner sets the identity from the canonical path, size, and mtime of the runtime and weights plus the model name, so replacing a file starts uncalibrated again. Fixture backends never calibrate. State is per project database.

Before plan compilation loads the model, `Controller::compilation_model_admission` asks the governor whether a MODEL lease of the current estimate would be admitted. It holds no lease. A deferral or a failed pressure probe returns `Blocked { Readiness(reason) }` and `llama-server` is not started. Before 2026-09-26 the compile path loaded the model with no governor admission.

Arithmetic to keep in mind: 3130 MiB measured becomes a 3600 MiB estimate, which needs about 5136 MiB of headroom with the 1536 soft launch reserve. The CX-T25 host had 3686, so it still defers there.

## Residency

`crates/sovereign-controller/src/resources.rs` namespaces: `controller.resource_lease`, `controller.resource_pressure`, `controller.resource_residency`, `controller.resource_governor`. Keys: `model`, `cdp_browser`, governor key `active`. Schema version 1.

The governor evicts idle heavy leases before admitting a new one. A second model lease is not a supported configuration on this profile.

## Real-model evidence

Ignored tests, not part of `scripts/verify.sh` unless `--ignored` is passed:

- `crates/sovereign-eval/tests/local_model_smoke.rs`
- `crates/sovereign-eval/tests/compiler_real_smoke.rs`
- `crates/sovereign-eval/tests/m1_real_qualification.rs`

Recorded evidence: `implementation/evidence/M1-real-model-qualification.json` and the M1-T03 / M1-T10 smoke JSON files. Those files bind an older tree unless their source hashes are rechecked. This wiki session did not rerun them. Treat them as **Historical** until a fresh ignored run is recorded. See [15-testing-and-evals.md](15-testing-and-evals.md).
