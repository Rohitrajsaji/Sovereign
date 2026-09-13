#![cfg(target_os = "macos")]

use rusqlite::Connection;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sovereign_context::{
    ContextBudget, ContextMode, ContextPacket, ContextPacketInput, ContextPlanner, EvidenceItem,
};
use sovereign_controller::{
    Controller, ExecutionRuntime, ReadinessInputs, RecoveryManager, TaskState,
};
use sovereign_evidence::ArtifactStore;
use sovereign_model::{
    DeterministicFakeBackend, MODEL_SCHEMA_VERSION, ModelBackend, ModelCapabilities,
    ModelFinishReason, ModelLoadProfile, ModelResponse, ModelUsage,
};
use sovereign_plan::{
    PLAN_COMPILATION_SCHEMA_VERSION, PlanCompilationInput, PlanCompilationRepository, PlanCompiler,
    PlanIr, PlanRevisionDiff, PlanValidator, ReplanScope, ValidationEnvironment,
};
use sovereign_policy::{
    CommandPolicy, CommandRisk, CommandSpec, ExecutionIsolationBackend, IsolatedCommand,
    IsolationCapabilities, IsolationRequest, MacSandboxExecBackend, ModelCallBudget,
    PinnedExecutable, PolicyError,
};
use sovereign_repo::{ExactRetriever, ProjectRegistry, RepositoryIntelligence, RepositorySnapshot};
use sovereign_state::{
    ActionTransition, NewActionRecord, NewJournalEvent, StateRecordUpdate, StateStore,
};
use sovereign_tools::{PermissionClass, ToolManifest, process_group_leader_identity};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const SETTINGS_FORM: &[u8] = include_bytes!("fixtures/scenario1/src/settings/SettingsForm.tsx");
const SETTINGS_FORM_TEST: &[u8] =
    include_bytes!("fixtures/scenario1/src/settings/SettingsForm.test.tsx");
const WRITE_TOOL_DIGEST: &str =
    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const CHILD_CASE: &str = "SOVEREIGN_CRASH_CHILD_CASE";
const CHILD_BASE: &str = "SOVEREIGN_CRASH_CHILD_BASE";
const CHILD_ROOT: &str = "SOVEREIGN_CRASH_CHILD_ROOT";
const CHILD_MARKER: &str = "SOVEREIGN_CRASH_CHILD_MARKER";
static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

struct Fixture {
    base: PathBuf,
    root: PathBuf,
}

impl Fixture {
    fn create(label: &str) -> Self {
        let sequence = FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let home = std::env::var_os("HOME").map_or_else(
            || panic!("HOME must be set for macOS recovery tests"),
            PathBuf::from,
        );
        let base = home.join(format!(
            ".sovereign-eval-t08-{label}-{}-{nanos}-{sequence}",
            std::process::id()
        ));
        let root = base.join("repo");
        let settings = root.join("src/settings");
        fs::create_dir_all(&settings)
            .unwrap_or_else(|error| panic!("create crash fixture: {error}"));
        fs::write(settings.join("SettingsForm.tsx"), SETTINGS_FORM)
            .unwrap_or_else(|error| panic!("write SettingsForm: {error}"));
        fs::write(settings.join("SettingsForm.test.tsx"), SETTINGS_FORM_TEST)
            .unwrap_or_else(|error| panic!("write SettingsForm test: {error}"));
        git(&root, &["init", "-q"]);
        git(
            &root,
            &["config", "user.email", "sovereign-recovery@example.invalid"],
        );
        git(&root, &["config", "user.name", "Sovereign Recovery"]);
        git(&root, &["add", "."]);
        git(&root, &["commit", "-qm", "recovery baseline"]);
        Self { base, root }
    }

    fn state_path(&self) -> PathBuf {
        self.base.join("state.sqlite3")
    }

    fn marker(&self) -> PathBuf {
        self.base.join("crash.marker")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

struct Prepared {
    registry: ProjectRegistry,
    packet: ContextPacket,
    snapshot: RepositorySnapshot,
    form_digest: String,
}

fn git(root: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .unwrap_or_else(|error| panic!("git {args:?}: {error}"));
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn global_policy() -> Value {
    serde_json::from_str(include_str!("fixtures/scenario1/policy.json"))
        .unwrap_or_else(|error| panic!("policy fixture: {error}"))
}

fn capability(id: &str, digest: &str) -> Value {
    json!({"id": id, "version": "1.0.0", "digest": digest})
}

fn registry_for(root: &Path) -> ProjectRegistry {
    let mut registry = ProjectRegistry::new();
    registry
        .register("repo.app", root)
        .unwrap_or_else(|error| panic!("register repository: {error}"));
    registry
}

fn prepare(root: &Path) -> Prepared {
    let registry = registry_for(root);
    let snapshot = registry
        .snapshot("repo.app")
        .unwrap_or_else(|error| panic!("snapshot: {error}"));
    let retriever = ExactRetriever::new(&registry);
    let form = retriever
        .read_path("repo.app", Path::new("src/settings/SettingsForm.tsx"), None)
        .unwrap_or_else(|error| panic!("read form: {error}"));
    let focused_test = retriever
        .read_path(
            "repo.app",
            Path::new("src/settings/SettingsForm.test.tsx"),
            None,
        )
        .unwrap_or_else(|error| panic!("read focused test: {error}"));
    let packet = ContextPlanner::default()
        .build(
            ContextMode::Implementation,
            ContextBudget::m1_8k(),
            ContextPacketInput {
                controller_prefix: "Controller owns durable recovery authority.".to_owned(),
                task_contract: "Rename Save to Apply only.".to_owned(),
                current_state: format!("dirty_digest={}", snapshot.dirty_digest),
                candidates: vec![
                    EvidenceItem::from_exact_file(&form, "exact form"),
                    EvidenceItem::from_exact_file(&focused_test, "focused test"),
                ],
                output_schema: "phase-specific typed proposal".to_owned(),
            },
        )
        .unwrap_or_else(|error| panic!("context packet: {error}"));
    Prepared {
        registry,
        packet,
        snapshot,
        form_digest: form.digest,
    }
}

fn response(content: String, input_tokens: u32) -> ModelResponse {
    ModelResponse {
        schema_version: MODEL_SCHEMA_VERSION,
        request_id: "recovery.fixture".to_owned(),
        content,
        structured: None,
        tool_calls: Vec::new(),
        finish_reason: ModelFinishReason::Stop,
        usage: ModelUsage {
            input_tokens: u64::from(input_tokens),
            output_tokens: 128,
        },
        elapsed_ms: 1,
        peak_rss_kb_during_call: None,
    }
}

fn fake_backend(prepared: &Prepared, with_execution: bool) -> DeterministicFakeBackend {
    let plan = json!({
        "tasks": [{
            "title": "Rename Settings submit label",
            "objective": "Change the rendered Settings submit label from Save to Apply without altering submit behavior.",
            "rationale": "Exact current source identifies one bounded edit.",
            "files": ["src/settings/SettingsForm.tsx", "src/settings/SettingsForm.test.tsx"],
            "symbols": ["SettingsForm"],
            "evidence_queries": [],
            "expected_change": "SettingsForm renders Apply instead of Save."
        }]
    });
    let execution = json!({
        "schema_version": 1,
        "evidence_ids": ["file:repo.app:src/settings/SettingsForm.tsx"],
        "action": {
            "kind": "replace_literal",
            "repository_id": "repo.app",
            "path": "src/settings/SettingsForm.tsx",
            "expected_source_digest": prepared.form_digest,
            "old_literal": "Save",
            "new_literal": "Apply",
            "expected_occurrences": 1
        }
    });
    let mut responses = vec![response(
        plan.to_string(),
        prepared.packet.metrics.final_serialized_input_tokens,
    )];
    if with_execution {
        responses.push(response(
            execution.to_string(),
            prepared.packet.metrics.final_serialized_input_tokens,
        ));
    }
    let backend = DeterministicFakeBackend::new(
        ModelCapabilities {
            schema_version: MODEL_SCHEMA_VERSION,
            model_id: "fake-recovery-model".to_owned(),
            parameter_class: "fixture".to_owned(),
            quantization: "fixture".to_owned(),
            max_context_tokens: 16_384,
            supports_tools: false,
            supports_json_schema: true,
            local: true,
        },
        responses,
    )
    .unwrap_or_else(|error| panic!("fake backend: {error}"));
    backend
        .load(ModelLoadProfile {
            context_tokens: 8_000,
            output_reserve_tokens: 1_024,
            startup_timeout_ms: 1_000,
            provider_call_timeout_ms: 1_000,
        })
        .unwrap_or_else(|error| panic!("load fake backend: {error}"));
    backend
}

fn compile_and_activate(
    base: &Path,
    prepared: &Prepared,
    backend: &DeterministicFakeBackend,
) -> (Controller, String) {
    let input = PlanCompilationInput {
        schema_version: PLAN_COMPILATION_SCHEMA_VERSION,
        compilation_id: "compile.t08.crash".to_owned(),
        compiled_at: "2026-09-12T20:00:00Z".to_owned(),
        project_id: "project.t08".to_owned(),
        project_name: "T08 crash fixture".to_owned(),
        workspace_roots: vec![prepared.snapshot.root.display().to_string()],
        goal_id: "goal.t08".to_owned(),
        goal_statement: "Rename the Settings button from Save to Apply.".to_owned(),
        goal_invariants: vec!["Preserve submit behavior.".to_owned()],
        goal_non_goals: vec!["No redesign.".to_owned()],
        repository: PlanCompilationRepository {
            repository_id: prepared.snapshot.repository_id.clone(),
            root: prepared.snapshot.root.display().to_string(),
            head: prepared.snapshot.head.clone(),
            branch: prepared.snapshot.branch.clone(),
            dirty_digest: prepared.snapshot.dirty_digest.clone(),
            protected_changes_present: prepared.snapshot.protected_changes_present,
            languages: vec!["typescript".to_owned()],
        },
        policy: global_policy(),
        role: capability(
            "role.implementer",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        skills: vec![capability(
            "skill.focused-edit",
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )],
        tools: vec![
            capability("tool.patch", WRITE_TOOL_DIGEST),
            capability(
                "tool.read",
                "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            ),
        ],
        write_tool_id: "tool.patch".to_owned(),
        read_tool_id: "tool.read".to_owned(),
        diff_evaluator: "builtin.diff.scope_and_literal.v1".to_owned(),
        rollback_diff_evaluator: "builtin.diff.controller_patch_absent.v1".to_owned(),
        context_packet: prepared.packet.clone(),
        m3: None,
        max_model_calls: 1,
        model_input_token_ceiling: 8_000,
        max_output_tokens: 512,
        model_deadline_ms: 1_000,
    };
    let validator = PlanValidator::new(ValidationEnvironment::default())
        .unwrap_or_else(|error| panic!("validator: {error}"));
    let compiler = PlanCompiler::new(backend, &validator, "m1-t08-crash-compiler")
        .unwrap_or_else(|error| panic!("compiler: {error}"));
    let mut budget = ModelCallBudget::new(1, 1_000);
    let compilation = compiler
        .compile(&input, &mut budget)
        .unwrap_or_else(|error| panic!("compile T08 goal: {error}"));
    let state = StateStore::open(base.join("state.sqlite3"))
        .unwrap_or_else(|error| panic!("state: {error}"));
    let mut controller = Controller::new(state);
    let activation = controller
        .activate(compilation, &prepared.registry)
        .unwrap_or_else(|error| panic!("activate: {error}"));
    (controller, activation.task_ids[0].clone())
}

fn canonical_value_digest(value: &Value) -> String {
    PlanIr::from_value(value.clone())
        .canonical_digest()
        .unwrap_or_else(|error| panic!("canonical digest: {error}"))
}

fn raw_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

#[allow(clippy::too_many_lines)]
fn install_uncheckpointed_supersession(
    state: &mut StateStore,
    task_id: &str,
    tamper_task_runtime_digest: bool,
) -> String {
    let active_raw = state
        .get_state("controller.plan", "active")
        .unwrap_or_else(|error| panic!("read active plan: {error}"))
        .unwrap_or_else(|| panic!("active plan record missing"));
    let active: Value =
        serde_json::from_str(&active_raw).unwrap_or_else(|error| panic!("active json: {error}"));
    let plan_id = active["plan_id"]
        .as_str()
        .unwrap_or_else(|| panic!("active plan id"))
        .to_owned();
    let goal_id = active["goal_id"]
        .as_str()
        .unwrap_or_else(|| panic!("active goal id"))
        .to_owned();
    let previous_digest = active["plan_digest"]
        .as_str()
        .unwrap_or_else(|| panic!("active plan digest"))
        .to_owned();
    let previous_document_raw = state
        .get_state("controller.plan_document", "active")
        .unwrap_or_else(|error| panic!("read active plan document: {error}"))
        .unwrap_or_else(|| panic!("active plan document missing"));
    let previous_document: Value = serde_json::from_str(&previous_document_raw)
        .unwrap_or_else(|error| panic!("previous plan json: {error}"));
    let mut next_document = previous_document.clone();
    next_document["revision"] = json!(2);
    next_document["supersedes_revision"] = json!(1);
    next_document["tasks"][0]["title"] = json!("Replanned Settings submit label");
    let next_digest = canonical_value_digest(&next_document);
    let diff = PlanRevisionDiff::between(
        &previous_document,
        &next_document,
        ReplanScope::Task,
        &["ASSUME.fixture-invalidated".to_owned()],
        &[task_id.to_owned()],
    )
    .unwrap_or_else(|error| panic!("revision diff: {error}"));
    let diff_json =
        serde_json::to_string(&diff).unwrap_or_else(|error| panic!("diff json: {error}"));
    let diff_digest = raw_sha256(diff_json.as_bytes());

    let task = next_document["tasks"][0].clone();
    let task_contract_digest = canonical_value_digest(&task);
    let task_runtime = json!({
        "state": "planned",
        "attempts_started": 0,
        "model_calls_used": 0,
        "failure_counts": {},
        "retry_exhausted": false,
        "resource_deferrals_used": 0,
        "resource_retry_exhausted": false,
        "resource_deferred_from": Value::Null,
        "task_contract_digest": task_contract_digest,
        "task": task
    });
    let task_runtime_values = BTreeMap::from([(task_id.to_owned(), task_runtime.clone())]);
    let task_runtime_map_digest = if tamper_task_runtime_digest {
        format!("sha256:{}", "f".repeat(64))
    } else {
        canonical_value_digest(
            &serde_json::to_value(&task_runtime_values)
                .unwrap_or_else(|error| panic!("task runtime map: {error}")),
        )
    };
    let attempt_runtime_map_digest = canonical_value_digest(&json!({}));
    let carry_record_digests = BTreeMap::<String, String>::new();
    let carry_proof_digest = canonical_value_digest(
        &serde_json::to_value(&carry_record_digests)
            .unwrap_or_else(|error| panic!("carry digest map: {error}")),
    );
    let compilation_evidence = json!({
        "schema": "fixture-post-checkpoint-supersession",
        "plan_digest": next_digest,
        "validator_passed": true
    });
    let compilation_evidence_digest = canonical_value_digest(&compilation_evidence);
    let baseline_raw = state
        .get_state("controller.repository_baseline", "active")
        .unwrap_or_else(|error| panic!("read baseline: {error}"))
        .unwrap_or_else(|| panic!("baseline missing"));
    let baseline: Value = serde_json::from_str(&baseline_raw)
        .unwrap_or_else(|error| panic!("baseline json: {error}"));
    let baseline_snapshot: RepositorySnapshot =
        serde_json::from_value(baseline["snapshot"].clone())
            .unwrap_or_else(|error| panic!("baseline snapshot json: {error}"));
    let repository_snapshot_digest = raw_sha256(
        baseline_snapshot
            .manifest_json()
            .unwrap_or_else(|error| panic!("baseline snapshot manifest: {error}"))
            .as_bytes(),
    );
    let baseline_diff_digest = baseline["diff_digest"]
        .as_str()
        .unwrap_or_else(|| panic!("baseline diff digest"))
        .to_owned();
    let epoch = state
        .advance_execution_epoch()
        .unwrap_or_else(|error| panic!("advance epoch: {error}"));
    let revision_key = format!("{plan_id}@r2");
    let active_plan_json = json!({
        "plan_id": plan_id,
        "goal_id": goal_id,
        "revision": 2,
        "plan_digest": next_digest,
        "compilation_evidence_digest": compilation_evidence_digest,
        "validity": "current"
    })
    .to_string();
    let revision_record_json = json!({
        "plan_id": plan_id,
        "revision": 2,
        "plan_digest": next_digest,
        "compilation_evidence_digest": compilation_evidence_digest,
        "previous_plan_digest": previous_digest,
        "plan_document": next_document
    })
    .to_string();
    let prior_lifecycle = json!({
        "plan_id": plan_id,
        "revision": 1,
        "plan_digest": previous_digest,
        "status": "superseded",
        "superseded_by_revision": 2,
        "superseded_by_digest": next_digest
    })
    .to_string();
    let next_lifecycle = json!({
        "plan_id": plan_id,
        "revision": 2,
        "plan_digest": next_digest,
        "status": "active",
        "superseded_by_revision": Value::Null,
        "superseded_by_digest": Value::Null
    })
    .to_string();
    let task_key = format!("{plan_id}@r2:{task_id}");
    let prior_revision_key = format!("{plan_id}@r1");
    let task_runtime_json = task_runtime.to_string();
    let next_document_json = next_document.to_string();
    let compilation_json = compilation_evidence.to_string();
    let activation_payload = json!({
        "from_revision": 1,
        "to_revision": 2,
        "from_plan_digest": previous_digest,
        "to_plan_digest": next_digest,
        "plan_revision_diff_digest": diff_digest,
        "carry_proof_digest": carry_proof_digest,
        "task_runtime_map_digest": task_runtime_map_digest,
        "attempt_runtime_map_digest": attempt_runtime_map_digest,
        "execution_epoch": epoch,
        "repository_snapshot_digest": repository_snapshot_digest,
        "baseline_diff_digest": baseline_diff_digest,
        "plan_validity": "current"
    });
    let activation_json = activation_payload.to_string();
    let event_id = format!(
        "fixture.supersession.{}",
        &raw_sha256(activation_json.as_bytes())[7..27]
    );
    let records = vec![
        ("controller.plan", "active", active_plan_json.as_str()),
        (
            "controller.plan_document",
            "active",
            next_document_json.as_str(),
        ),
        (
            "controller.plan_revision",
            revision_key.as_str(),
            revision_record_json.as_str(),
        ),
        (
            "controller.plan_revision_diff",
            revision_key.as_str(),
            diff_json.as_str(),
        ),
        (
            "controller.compilation_evidence",
            revision_key.as_str(),
            compilation_json.as_str(),
        ),
        (
            "controller.plan_revision_lifecycle",
            prior_revision_key.as_str(),
            prior_lifecycle.as_str(),
        ),
        (
            "controller.plan_revision_lifecycle",
            revision_key.as_str(),
            next_lifecycle.as_str(),
        ),
        (
            "controller.task",
            task_key.as_str(),
            task_runtime_json.as_str(),
        ),
    ];
    let owned_records = records
        .iter()
        .map(|(namespace, key, value_json)| {
            (
                (*namespace).to_owned(),
                (*key).to_owned(),
                (*value_json).to_owned(),
            )
        })
        .collect::<Vec<_>>();
    let updates = owned_records
        .iter()
        .map(|(namespace, key, value_json)| StateRecordUpdate {
            namespace,
            key,
            value_json,
        })
        .collect::<Vec<_>>();
    state
        .put_state_records_with_events(
            &updates,
            &[NewJournalEvent {
                event_id: &event_id,
                entity_type: "controller",
                entity_id: &plan_id,
                event_kind: "plan_revision_activated",
                payload_json: &activation_json,
            }],
        )
        .unwrap_or_else(|error| panic!("publish supersession: {error}"));
    next_digest
}

struct RuntimeParts {
    command_policy: CommandPolicy,
    isolation_request: IsolationRequest,
    artifacts: ArtifactStore,
    manifest: ToolManifest,
}

fn runtime_parts(base: &Path, root: &Path) -> RuntimeParts {
    let python = PinnedExecutable::from_path("/usr/bin/python3", "macos-system-python")
        .unwrap_or_else(|error| panic!("pin python: {error}"));
    let toolchain = python
        .path
        .parent()
        .unwrap_or_else(|| panic!("python parent"))
        .to_path_buf();
    let home = std::env::var_os("HOME").map_or_else(|| panic!("HOME missing"), PathBuf::from);
    RuntimeParts {
        command_policy: CommandPolicy::new([python], [toolchain])
            .unwrap_or_else(|error| panic!("command policy: {error}")),
        isolation_request: IsolationRequest {
            repository_root: root.to_path_buf(),
            user_home_root: home,
            extra_protected_read_roots: Vec::new(),
            network_offline: true,
            allow_repository_write: true,
            require_full_filesystem_read_jail: false,
        },
        artifacts: ArtifactStore::open(base.join("cas"))
            .unwrap_or_else(|error| panic!("artifact store: {error}")),
        manifest: ToolManifest {
            tool_id: "tool.patch".to_owned(),
            version: "1.0.0".to_owned(),
            content_digest: WRITE_TOOL_DIGEST.to_owned(),
            permission_ceiling: BTreeSet::from([PermissionClass::RepositoryWrite]),
            declared_risk_floor: CommandRisk::RepositoryMutation,
        },
    }
}

enum CrashIsolation {
    Normal(MacSandboxExecBackend),
    BlockBefore {
        inner: MacSandboxExecBackend,
        marker: PathBuf,
    },
    Ambiguous(MacSandboxExecBackend),
    Orphan(MacSandboxExecBackend),
    PendingSpawn(MacSandboxExecBackend),
}

impl ExecutionIsolationBackend for CrashIsolation {
    fn capabilities(&self) -> IsolationCapabilities {
        match self {
            Self::Normal(inner)
            | Self::BlockBefore { inner, .. }
            | Self::Ambiguous(inner)
            | Self::Orphan(inner)
            | Self::PendingSpawn(inner) => inner.capabilities(),
        }
    }

    fn isolate(
        &self,
        spec: &CommandSpec,
        request: &IsolationRequest,
    ) -> Result<IsolatedCommand, PolicyError> {
        match self {
            Self::Normal(inner) => inner.isolate(spec, request),
            Self::BlockBefore { marker, .. } => {
                fs::write(marker, b"before_mutation")?;
                loop {
                    thread::sleep(Duration::from_secs(60));
                }
            }
            Self::Ambiguous(_) => Ok(IsolatedCommand {
                executable: PathBuf::from("/usr/bin/python3"),
                args: vec![
                    "-I".to_owned(),
                    "-c".to_owned(),
                    "import pathlib,sys,time; pathlib.Path(sys.argv[1]).write_text('ambiguous crash residue\\n'); time.sleep(60)".to_owned(),
                    request
                        .repository_root
                        .join("src/settings/SettingsForm.tsx")
                        .display()
                        .to_string(),
                ],
            }),
            Self::Orphan(_) => Ok(IsolatedCommand {
                executable: PathBuf::from("/bin/sleep"),
                args: vec!["60".to_owned()],
            }),
            Self::PendingSpawn(_) => Ok(IsolatedCommand {
                executable: PathBuf::from("/bin/sleep"),
                args: vec!["2".to_owned()],
            }),
        }
    }
}

fn run_child(case: &str, base: &Path, root: &Path, marker: &Path) {
    let prepared = prepare(root);
    let backend = fake_backend(&prepared, true);
    let (mut controller, task_id) = compile_and_activate(base, &prepared, &backend);
    let ready = controller
        .derive_ready_lease(
            &prepared.registry,
            &task_id,
            ReadinessInputs::permissive_m1("sha256:t08-resource"),
        )
        .unwrap_or_else(|error| panic!("child ready: {error}"));
    let parts = runtime_parts(base, root);
    let detected =
        MacSandboxExecBackend::detect().unwrap_or_else(|error| panic!("detect Seatbelt: {error}"));
    let isolation = match case {
        "before_mutation" => CrashIsolation::BlockBefore {
            inner: detected,
            marker: marker.to_path_buf(),
        },
        "dispatch_ambiguous" => CrashIsolation::Ambiguous(detected),
        "orphan_sleep" => CrashIsolation::Orphan(detected),
        "pending_spawn" => CrashIsolation::PendingSpawn(detected),
        _ => CrashIsolation::Normal(detected),
    };
    let runtime = ExecutionRuntime {
        registry: &prepared.registry,
        backend: &backend,
        command_policy: &parts.command_policy,
        isolation_backend: &isolation,
        isolation_request: &parts.isolation_request,
        artifacts: &parts.artifacts,
        tool_manifest: &parts.manifest,
        python_executable: Path::new("/usr/bin/python3"),
    };
    let mut budget = ModelCallBudget::new(4, 30_000);
    let _ = controller.execute_replace(ready, &runtime, &prepared.packet, &mut budget);
}

#[test]
fn crash_worker_entry() {
    let Ok(case) = std::env::var(CHILD_CASE) else {
        return;
    };
    let base = PathBuf::from(
        std::env::var(CHILD_BASE).unwrap_or_else(|error| panic!("child base env: {error}")),
    );
    let root = PathBuf::from(
        std::env::var(CHILD_ROOT).unwrap_or_else(|error| panic!("child root env: {error}")),
    );
    let marker = PathBuf::from(
        std::env::var(CHILD_MARKER).unwrap_or_else(|error| panic!("child marker env: {error}")),
    );
    run_child(&case, &base, &root, &marker);
}

fn spawn_child(fixture: &Fixture, case: &str, pause_at: Option<&str>) -> Child {
    let current =
        std::env::current_exe().unwrap_or_else(|error| panic!("current test exe: {error}"));
    let mut command = Command::new(current);
    command
        .args(["--exact", "crash_worker_entry", "--nocapture"])
        .env(CHILD_CASE, case)
        .env(CHILD_BASE, &fixture.base)
        .env(CHILD_ROOT, &fixture.root)
        .env(CHILD_MARKER, fixture.marker())
        .env("RUST_BACKTRACE", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(point) = pause_at {
        command
            .env("SOVEREIGN_RECOVERY_TEST_PAUSE_AT", point)
            .env("SOVEREIGN_RECOVERY_TEST_MARKER", fixture.marker());
    }
    command
        .spawn()
        .unwrap_or_else(|error| panic!("spawn crash child: {error}"))
}

fn kill_child(child: &mut Child) {
    child
        .kill()
        .unwrap_or_else(|error| panic!("SIGKILL child: {error}"));
    child
        .wait()
        .unwrap_or_else(|error| panic!("wait killed child: {error}"));
}

fn wait_for_marker(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if path.exists() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for crash marker {}", path.display());
}

fn wait_for_source_contains(root: &Path, needle: &str) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if fs::read_to_string(root.join("src/settings/SettingsForm.tsx"))
            .is_ok_and(|content| content.contains(needle))
        {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for source to contain {needle:?}");
}

fn wait_for_action_state(path: &Path, expected: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if let Ok(state) = StateStore::open(path)
            && let Ok(records) = state.action_records()
            && let Some(record) = records.iter().find(|record| record.state == expected)
        {
            return record.action_id.clone();
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for action state {expected}");
}

fn wait_for_active_process_lease(path: &Path) -> (u32, String) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if let Ok(state) = StateStore::open(path)
            && let Ok(records) = state.state_records("controller.process_lease")
        {
            for record in records {
                let value: Value = serde_json::from_str(&record.value_json)
                    .unwrap_or_else(|error| panic!("process lease json: {error}"));
                if value["state"] == "active"
                    && let (Some(pgid), Some(identity)) = (
                        value["process_group_id"].as_u64(),
                        value["leader_identity"].as_str(),
                    )
                {
                    return (
                        u32::try_from(pgid).unwrap_or_else(|_| panic!("pgid overflow")),
                        identity.to_owned(),
                    );
                }
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for active process lease");
}

fn wait_for_pending_process_lease(path: &Path) -> String {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if let Ok(state) = StateStore::open(path)
            && let Ok(records) = state.state_records("controller.process_lease")
        {
            for record in records {
                let value: Value = serde_json::from_str(&record.value_json)
                    .unwrap_or_else(|error| panic!("process lease json: {error}"));
                if value["state"] == "pending_spawn"
                    && value["process_group_id"].is_null()
                    && value["leader_identity"].is_null()
                {
                    return value["lease_id"]
                        .as_str()
                        .unwrap_or_else(|| panic!("pending lease id missing"))
                        .to_owned();
                }
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for pending process lease");
}

fn first_task_id(state: &StateStore) -> String {
    state
        .state_records("controller.task")
        .unwrap_or_else(|error| panic!("task records: {error}"))
        .first()
        .map_or_else(
            || panic!("task record missing"),
            |record| record.key.clone(),
        )
}

fn source(root: &Path) -> String {
    fs::read_to_string(root.join("src/settings/SettingsForm.tsx"))
        .unwrap_or_else(|error| panic!("read source: {error}"))
}

fn action_event_count(state: &StateStore, kind: &str) -> usize {
    state
        .journal()
        .unwrap_or_else(|error| panic!("journal: {error}"))
        .iter()
        .filter(|event| event.entity_type == "action" && event.event_kind == kind)
        .count()
}

fn recover(
    fixture: &Fixture,
) -> (
    Controller,
    sovereign_controller::RecoverySummary,
    ProjectRegistry,
) {
    let registry = registry_for(&fixture.root);
    let state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("open state for recovery: {error}"));
    let (controller, summary) = RecoveryManager::recover(state, &registry)
        .unwrap_or_else(|error| panic!("recover controller: {error}"));
    (controller, summary, registry)
}

fn normal_runtime<'a>(
    registry: &'a ProjectRegistry,
    backend: &'a DeterministicFakeBackend,
    parts: &'a RuntimeParts,
    isolation: &'a MacSandboxExecBackend,
) -> ExecutionRuntime<'a, MacSandboxExecBackend> {
    ExecutionRuntime {
        registry,
        backend,
        command_policy: &parts.command_policy,
        isolation_backend: isolation,
        isolation_request: &parts.isolation_request,
        artifacts: &parts.artifacts,
        tool_manifest: &parts.manifest,
        python_executable: Path::new("/usr/bin/python3"),
    }
}

#[test]
fn kill_before_mutation_resumes_persisted_intent_without_model_replay() {
    let fixture = Fixture::create("before-mutation");
    let mut child = spawn_child(&fixture, "before_mutation", None);
    wait_for_marker(&fixture.marker());
    let _old_action = wait_for_action_state(&fixture.state_path(), "authorized");
    kill_child(&mut child);
    assert!(source(&fixture.root).contains("Save"));

    let (mut controller, summary, registry) = recover(&fixture);
    assert!(!summary.mutation_blocked);
    assert_eq!(summary.pending_recovery_action_ids.len(), 1);
    let task_id = first_task_id(controller.state());
    assert_eq!(controller.task_model_calls_used(&task_id), Some(1));
    let prepared = prepare(&fixture.root);
    let backend = fake_backend(&prepared, false);
    let parts = runtime_parts(&fixture.base, &fixture.root);
    let isolation =
        MacSandboxExecBackend::detect().unwrap_or_else(|error| panic!("Seatbelt: {error}"));
    let runtime = normal_runtime(&registry, &backend, &parts, &isolation);
    controller
        .resume_recovered_replace(
            &summary.pending_recovery_action_ids[0],
            &runtime,
            ReadinessInputs::permissive_m1("sha256:t08-recovery-resource"),
        )
        .unwrap_or_else(|error| panic!("resume persisted action: {error}"));
    assert_eq!(controller.task_model_calls_used(&task_id), Some(1));
    assert_eq!(controller.task_state(&task_id), Some(TaskState::Succeeded));
    assert!(source(&fixture.root).contains("Apply"));
}

#[test]
fn tampered_persisted_intent_is_rejected_before_recovered_mutation() {
    let fixture = Fixture::create("tampered-intent");
    let mut child = spawn_child(&fixture, "before_mutation", None);
    wait_for_marker(&fixture.marker());
    let action_id = wait_for_action_state(&fixture.state_path(), "authorized");
    kill_child(&mut child);

    let (mut controller, summary, registry) = recover(&fixture);
    assert_eq!(summary.pending_recovery_action_ids, vec![action_id.clone()]);
    let dispatched_before = action_event_count(controller.state(), "dispatched");
    let task_id = first_task_id(controller.state());

    let mut external_state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("open state for intent tamper: {error}"));
    let raw = external_state
        .get_state("controller.action_intent", &action_id)
        .unwrap_or_else(|error| panic!("read action intent: {error}"))
        .unwrap_or_else(|| panic!("action intent missing"));
    let mut value: Value =
        serde_json::from_str(&raw).unwrap_or_else(|error| panic!("intent json: {error}"));
    let mode = value["expected_target_mode"]
        .as_u64()
        .unwrap_or_else(|| panic!("expected target mode missing"));
    value["expected_target_mode"] = json!(mode + 1);
    external_state
        .put_state("controller.action_intent", &action_id, &value.to_string())
        .unwrap_or_else(|error| panic!("tamper action intent: {error}"));
    drop(external_state);

    let prepared = prepare(&fixture.root);
    let backend = fake_backend(&prepared, false);
    let parts = runtime_parts(&fixture.base, &fixture.root);
    let isolation =
        MacSandboxExecBackend::detect().unwrap_or_else(|error| panic!("Seatbelt: {error}"));
    let runtime = normal_runtime(&registry, &backend, &parts, &isolation);
    let Err(error) = controller.resume_recovered_replace(
        &action_id,
        &runtime,
        ReadinessInputs::permissive_m1("sha256:t08-recovery-resource"),
    ) else {
        panic!("tampered recovery intent must not execute");
    };
    assert!(
        error
            .to_string()
            .contains("differs from its trusted recovery checkpoint binding")
    );
    assert_eq!(controller.task_model_calls_used(&task_id), Some(1));
    assert_eq!(
        action_event_count(controller.state(), "dispatched"),
        dispatched_before
    );
    assert!(source(&fixture.root).contains("Save"));
}

fn assert_verification_only_recovery(pause_at: &str, label: &str) {
    let fixture = Fixture::create(label);
    let mut child = spawn_child(&fixture, "normal", Some(pause_at));
    wait_for_marker(&fixture.marker());
    let action_id = wait_for_action_state(&fixture.state_path(), "committed");
    kill_child(&mut child);
    assert!(source(&fixture.root).contains("Apply"));
    let before = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("state before recovery: {error}"));
    let dispatched_before = action_event_count(&before, "dispatched");
    let committed_before = action_event_count(&before, "committed");
    drop(before);

    let (controller, summary, _registry) = recover(&fixture);
    let task_id = first_task_id(controller.state());
    assert!(!summary.mutation_blocked);
    assert!(summary.pending_recovery_action_ids.is_empty());
    assert_eq!(controller.task_state(&task_id), Some(TaskState::Succeeded));
    assert_eq!(controller.task_model_calls_used(&task_id), Some(1));
    assert_eq!(
        action_event_count(controller.state(), "dispatched"),
        dispatched_before
    );
    assert_eq!(
        action_event_count(controller.state(), "committed"),
        committed_before
    );
    let action = controller
        .state()
        .action_record(&action_id)
        .unwrap_or_else(|error| panic!("action after recovery: {error}"))
        .unwrap_or_else(|| panic!("committed action disappeared"));
    assert_eq!(action.state, "committed");
    assert!(action.result_digest.is_some());
    assert!(source(&fixture.root).contains("Apply"));
}

#[test]
fn kill_after_local_edit_recovers_by_deterministic_verification_only() {
    assert_verification_only_recovery("after_mutation_checkpoint", "after-edit");
}

#[test]
fn kill_during_verification_recovers_by_deterministic_verification_only() {
    assert_verification_only_recovery("verification_started", "during-verification");
}

#[test]
fn kill_after_dispatch_before_observed_blocks_ambiguous_effect_without_replay() {
    let fixture = Fixture::create("dispatch-unknown");
    let mut child = spawn_child(&fixture, "dispatch_ambiguous", None);
    let action_id = wait_for_action_state(&fixture.state_path(), "dispatched");
    let _lease = wait_for_active_process_lease(&fixture.state_path());
    wait_for_source_contains(&fixture.root, "ambiguous crash residue");
    kill_child(&mut child);
    let (controller, summary, _registry) = recover(&fixture);
    assert!(summary.mutation_blocked);
    assert_eq!(summary.unknown_action_ids, vec![action_id.clone()]);
    let task_id = first_task_id(controller.state());
    assert_eq!(
        controller.task_state(&task_id),
        Some(TaskState::ReconcilingUnknown)
    );
    assert_eq!(action_event_count(controller.state(), "dispatched"), 1);
    assert_eq!(action_event_count(controller.state(), "committed"), 0);
    assert!(source(&fixture.root).contains("ambiguous crash residue"));
}

#[test]
fn orphan_process_group_is_reaped_before_recovery_continues() {
    let fixture = Fixture::create("orphan-reap");
    let mut child = spawn_child(&fixture, "orphan_sleep", None);
    let _action_id = wait_for_action_state(&fixture.state_path(), "dispatched");
    let (pgid, identity) = wait_for_active_process_lease(&fixture.state_path());
    assert_eq!(
        process_group_leader_identity(pgid)
            .unwrap_or_else(|error| panic!("observe child identity: {error}"))
            .as_deref(),
        Some(identity.as_str())
    );
    kill_child(&mut child);
    let (controller, summary, _registry) = recover(&fixture);
    assert!(summary.unresolved_process_lease_ids.is_empty());
    assert!(
        process_group_leader_identity(pgid)
            .unwrap_or_else(|error| panic!("observe reaped group: {error}"))
            .is_none()
    );
    let leases = controller
        .state()
        .state_records("controller.process_lease")
        .unwrap_or_else(|error| panic!("process leases: {error}"));
    assert!(
        leases
            .iter()
            .any(|record| record.value_json.contains("reaped_recovery"))
    );
}

#[test]
fn kill_after_spawn_before_identity_lease_stays_recovery_blocked() {
    let fixture = Fixture::create("pending-spawn");
    let mut child = spawn_child(
        &fixture,
        "pending_spawn",
        Some("after_process_spawn_before_identity_lease"),
    );
    wait_for_marker(&fixture.marker());
    let action_id = wait_for_action_state(&fixture.state_path(), "dispatched");
    let pending_lease_id = wait_for_pending_process_lease(&fixture.state_path());
    kill_child(&mut child);

    let (controller, summary, _registry) = recover(&fixture);
    assert!(summary.mutation_blocked);
    assert!(
        summary
            .unresolved_process_lease_ids
            .contains(&pending_lease_id)
    );
    assert_eq!(summary.unknown_action_ids, vec![action_id]);
    let task_id = first_task_id(controller.state());
    assert_eq!(
        controller.task_state(&task_id),
        Some(TaskState::ReconcilingUnknown)
    );
    assert_eq!(action_event_count(controller.state(), "dispatched"), 1);
    assert_eq!(action_event_count(controller.state(), "committed"), 0);
    thread::sleep(Duration::from_millis(2_100));
}

fn run_to_success(fixture: &Fixture) -> String {
    let prepared = prepare(&fixture.root);
    let backend = fake_backend(&prepared, true);
    let (mut controller, task_id) = compile_and_activate(&fixture.base, &prepared, &backend);
    let ready = controller
        .derive_ready_lease(
            &prepared.registry,
            &task_id,
            ReadinessInputs::permissive_m1("sha256:t08-resource"),
        )
        .unwrap_or_else(|error| panic!("ready: {error}"));
    let parts = runtime_parts(&fixture.base, &fixture.root);
    let isolation =
        MacSandboxExecBackend::detect().unwrap_or_else(|error| panic!("Seatbelt: {error}"));
    let runtime = normal_runtime(&prepared.registry, &backend, &parts, &isolation);
    let mut budget = ModelCallBudget::new(4, 30_000);
    controller
        .execute_replace(ready, &runtime, &prepared.packet, &mut budget)
        .unwrap_or_else(|error| panic!("normal success: {error}"));
    task_id
}

#[test]
fn corrupt_latest_checkpoint_falls_back_and_committed_edit_is_never_replayed() {
    let fixture = Fixture::create("checkpoint-fallback");
    let task_id = run_to_success(&fixture);
    let before = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("state before corruption: {error}"));
    let dispatched_before = action_event_count(&before, "dispatched");
    let committed_before = action_event_count(&before, "committed");
    let corrupt_generation = before
        .latest_checkpoint_integrity()
        .unwrap_or_else(|error| panic!("latest checkpoint: {error}"))
        .unwrap_or_else(|| panic!("checkpoint missing"))
        .generation;
    drop(before);
    let connection = Connection::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("open sqlite for corruption: {error}"));
    connection
        .execute_batch(
            "DROP TRIGGER checkpoint_integrity_no_update;\
             UPDATE checkpoint_integrity SET checkpoint_hash='sha256:0000000000000000000000000000000000000000000000000000000000000000' \
             WHERE generation=(SELECT MAX(generation) FROM checkpoint_integrity);\
             CREATE TRIGGER checkpoint_integrity_no_update \
             BEFORE UPDATE ON checkpoint_integrity \
             BEGIN \
                 SELECT RAISE(ABORT, 'checkpoint integrity rows are immutable'); \
             END;",
        )
        .unwrap_or_else(|error| panic!("simulate immutable checkpoint disk corruption: {error}"));
    drop(connection);

    let (controller, summary, _registry) = recover(&fixture);
    assert!(summary.fallback_checkpoint_used);
    assert_eq!(controller.task_state(&task_id), Some(TaskState::Succeeded));
    assert_eq!(
        action_event_count(controller.state(), "dispatched"),
        dispatched_before
    );
    assert_eq!(
        action_event_count(controller.state(), "committed"),
        committed_before
    );
    assert!(source(&fixture.root).contains("Apply"));
    let newest = controller
        .state()
        .latest_valid_checkpoint_integrity()
        .unwrap_or_else(|error| panic!("latest valid recovery checkpoint: {error}"))
        .unwrap_or_else(|| panic!("recovery checkpoint missing"));
    assert!(newest.generation > corrupt_generation);
    assert_eq!(
        newest.action_sequence,
        controller
            .state()
            .latest_journal_sequence()
            .unwrap_or_else(|error| panic!("journal tail: {error}"))
    );
}

#[test]
fn missing_latest_manifest_cas_reanchors_to_older_trusted_checkpoint() {
    let fixture = Fixture::create("checkpoint-cas-missing");
    let task_id = run_to_success(&fixture);
    let before = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("state before CAS loss: {error}"));
    let dispatched_before = action_event_count(&before, "dispatched");
    let committed_before = action_event_count(&before, "committed");
    let latest = before
        .latest_checkpoint_integrity()
        .unwrap_or_else(|error| panic!("latest checkpoint: {error}"))
        .unwrap_or_else(|| panic!("checkpoint missing"));
    drop(before);
    let cas_path = fixture
        .state_path()
        .parent()
        .unwrap_or_else(|| panic!("state database parent missing"))
        .join("checkpoint-cas")
        .join("sha256")
        .join(&latest.payload_digest[..2])
        .join(&latest.payload_digest);
    fs::remove_file(&cas_path)
        .unwrap_or_else(|error| panic!("remove latest checkpoint manifest CAS: {error}"));

    let (controller, summary, _registry) = recover(&fixture);
    assert!(summary.fallback_checkpoint_used);
    assert_eq!(controller.task_state(&task_id), Some(TaskState::Succeeded));
    assert_eq!(
        action_event_count(controller.state(), "dispatched"),
        dispatched_before
    );
    assert_eq!(
        action_event_count(controller.state(), "committed"),
        committed_before
    );
    let reanchored = controller
        .state()
        .latest_valid_checkpoint_integrity()
        .unwrap_or_else(|error| panic!("latest valid re-anchor: {error}"))
        .unwrap_or_else(|| panic!("re-anchor checkpoint missing"));
    assert!(reanchored.generation > latest.generation);
    drop(controller);

    let (controller, summary, _registry) = recover(&fixture);
    assert!(!summary.fallback_checkpoint_used);
    assert_eq!(controller.task_state(&task_id), Some(TaskState::Succeeded));
    assert_eq!(
        action_event_count(controller.state(), "dispatched"),
        dispatched_before
    );
}

#[test]
fn corrupt_tail_then_missing_reanchor_manifest_falls_back_only_on_trusted_ancestry() {
    let fixture = Fixture::create("checkpoint-ancestry");
    let task_id = run_to_success(&fixture);
    let before = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("state before combined corruption: {error}"));
    let corrupt = before
        .latest_checkpoint_integrity()
        .unwrap_or_else(|error| panic!("latest checkpoint: {error}"))
        .unwrap_or_else(|| panic!("checkpoint missing"));
    drop(before);

    let connection = Connection::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("open sqlite for checkpoint corruption: {error}"));
    connection
        .execute_batch(
            "DROP TRIGGER checkpoint_integrity_no_update;\
             UPDATE checkpoint_integrity SET checkpoint_hash='sha256:0000000000000000000000000000000000000000000000000000000000000000' \
             WHERE generation=(SELECT MAX(generation) FROM checkpoint_integrity);\
             CREATE TRIGGER checkpoint_integrity_no_update \
             BEFORE UPDATE ON checkpoint_integrity \
             BEGIN \
                 SELECT RAISE(ABORT, 'checkpoint integrity rows are immutable'); \
             END;",
        )
        .unwrap_or_else(|error| panic!("simulate corrupt immutable checkpoint tail: {error}"));
    drop(connection);

    let (controller, first_summary, _registry) = recover(&fixture);
    assert!(first_summary.fallback_checkpoint_used);
    assert!(first_summary.checkpoint_generation < corrupt.generation);
    assert_eq!(controller.task_state(&task_id), Some(TaskState::Succeeded));
    let reanchor = controller
        .state()
        .latest_valid_checkpoint_integrity()
        .unwrap_or_else(|error| panic!("latest recovery re-anchor: {error}"))
        .unwrap_or_else(|| panic!("re-anchor missing"));
    assert!(reanchor.generation > corrupt.generation);
    drop(controller);

    let reanchor_cas = fixture
        .state_path()
        .parent()
        .unwrap_or_else(|| panic!("state database parent missing"))
        .join("checkpoint-cas")
        .join("sha256")
        .join(&reanchor.payload_digest[..2])
        .join(&reanchor.payload_digest);
    fs::remove_file(&reanchor_cas)
        .unwrap_or_else(|error| panic!("remove re-anchor manifest CAS: {error}"));

    let (controller, second_summary, _registry) = recover(&fixture);
    assert!(second_summary.fallback_checkpoint_used);
    assert!(second_summary.checkpoint_generation < corrupt.generation);
    assert_ne!(second_summary.checkpoint_generation, corrupt.generation);
    assert_eq!(controller.task_state(&task_id), Some(TaskState::Succeeded));
    assert!(source(&fixture.root).contains("Apply"));
}

#[test]
fn unjournaled_task_state_drift_is_rejected_during_recovery() {
    let fixture = Fixture::create("unjournaled-task-drift");
    let task_id = run_to_success(&fixture);
    let mut state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("state for task drift: {error}"));
    let raw = state
        .get_state("controller.task", &task_id)
        .unwrap_or_else(|error| panic!("read task state: {error}"))
        .unwrap_or_else(|| panic!("task state missing"));
    let mut value: Value =
        serde_json::from_str(&raw).unwrap_or_else(|error| panic!("task json: {error}"));
    let calls = value["model_calls_used"]
        .as_u64()
        .unwrap_or_else(|| panic!("model call counter missing"));
    value["model_calls_used"] = json!(calls + 1);
    state
        .put_state("controller.task", &task_id, &value.to_string())
        .unwrap_or_else(|error| panic!("write unjournaled task drift: {error}"));
    drop(state);

    let registry = registry_for(&fixture.root);
    let state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("reopen drifted state: {error}"));
    let Err(error) = RecoveryManager::recover(state, &registry) else {
        panic!("unjournaled current-state drift must not recover");
    };
    assert!(
        error
            .to_string()
            .contains("does not equal ordered post-checkpoint journal replay")
    );
}

#[test]
fn recovery_normalized_attempt_state_survives_second_restart() {
    let fixture = Fixture::create("recovery-second-restart");
    let mut child = spawn_child(&fixture, "before_mutation", None);
    wait_for_marker(&fixture.marker());
    let action_id = wait_for_action_state(&fixture.state_path(), "authorized");
    kill_child(&mut child);

    let (controller, first, _registry) = recover(&fixture);
    assert!(!first.mutation_blocked);
    assert_eq!(first.pending_recovery_action_ids, vec![action_id.clone()]);
    drop(controller);

    let (controller, second, _registry) = recover(&fixture);
    assert!(!second.mutation_blocked);
    assert_eq!(second.pending_recovery_action_ids, vec![action_id.clone()]);
    assert_eq!(
        controller
            .state()
            .action_record(&action_id)
            .unwrap_or_else(|error| panic!("action after second recovery: {error}"))
            .unwrap_or_else(|| panic!("recovery action missing"))
            .state,
        "authorized"
    );
}

#[test]
fn older_checkpoint_fallback_replays_model_and_attempt_transitions_exactly() {
    let fixture = Fixture::create("ordered-runtime-replay");
    let task_id = run_to_success(&fixture);
    let state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("state before replay fallback: {error}"));
    let generation_two = state
        .checkpoint_integrity_by_generation(2)
        .unwrap_or_else(|error| panic!("checkpoint generation 2: {error}"))
        .unwrap_or_else(|| panic!("checkpoint generation 2 missing"));
    assert_eq!(generation_two.generation, 2);
    drop(state);

    let connection = Connection::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("open sqlite for ordered replay corruption: {error}"));
    connection
        .execute_batch(
            "DROP TRIGGER checkpoint_integrity_no_update;\
             UPDATE checkpoint_integrity SET checkpoint_hash='sha256:0000000000000000000000000000000000000000000000000000000000000000' \
             WHERE generation=2;\
             CREATE TRIGGER checkpoint_integrity_no_update \
             BEFORE UPDATE ON checkpoint_integrity \
             BEGIN \
                 SELECT RAISE(ABORT, 'checkpoint integrity rows are immutable'); \
             END;",
        )
        .unwrap_or_else(|error| panic!("simulate early checkpoint corruption: {error}"));
    drop(connection);

    let (controller, summary, _registry) = recover(&fixture);
    assert!(summary.fallback_checkpoint_used);
    assert_eq!(summary.checkpoint_generation, 1);
    assert_eq!(controller.task_state(&task_id), Some(TaskState::Succeeded));
    assert_eq!(controller.task_model_calls_used(&task_id), Some(1));
    assert!(source(&fixture.root).contains("Apply"));
}

#[test]
fn unjournaled_repository_baseline_and_validity_drift_is_rejected_during_recovery() {
    let fixture = Fixture::create("unjournaled-baseline-drift");
    let _task_id = run_to_success(&fixture);
    let mut state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("state for baseline drift: {error}"));

    let raw_baseline = state
        .get_state("controller.repository_baseline", "active")
        .unwrap_or_else(|error| panic!("read repository baseline: {error}"))
        .unwrap_or_else(|| panic!("repository baseline missing"));
    let mut baseline: Value = serde_json::from_str(&raw_baseline)
        .unwrap_or_else(|error| panic!("baseline json: {error}"));
    baseline["diff_digest"] = Value::String(format!("sha256:{}", "b".repeat(64)));
    state
        .put_state(
            "controller.repository_baseline",
            "active",
            &baseline.to_string(),
        )
        .unwrap_or_else(|error| panic!("write unjournaled baseline drift: {error}"));

    let raw_plan = state
        .get_state("controller.plan", "active")
        .unwrap_or_else(|error| panic!("read active plan: {error}"))
        .unwrap_or_else(|| panic!("active plan missing"));
    let mut plan: Value =
        serde_json::from_str(&raw_plan).unwrap_or_else(|error| panic!("plan json: {error}"));
    plan["validity"] = Value::String("stale_evidence".to_owned());
    state
        .put_state("controller.plan", "active", &plan.to_string())
        .unwrap_or_else(|error| panic!("write unjournaled validity drift: {error}"));
    drop(state);

    let registry = registry_for(&fixture.root);
    let state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("reopen baseline-drifted state: {error}"));
    let Err(error) = RecoveryManager::recover(state, &registry) else {
        panic!("unjournaled baseline/validity drift must not recover");
    };
    assert!(
        error
            .to_string()
            .contains("durable repository baseline diff content does not match its digest")
    );
}

#[test]
fn fallback_rejects_baseline_diff_content_tamper_before_reconstruction() {
    let fixture = Fixture::create("fallback-baseline-content-tamper");
    let _task_id = run_to_success(&fixture);

    let mut state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("state for baseline-content tamper: {error}"));
    let raw_baseline = state
        .get_state("controller.repository_baseline", "active")
        .unwrap_or_else(|error| panic!("read repository baseline: {error}"))
        .unwrap_or_else(|| panic!("repository baseline missing"));
    let mut baseline: Value = serde_json::from_str(&raw_baseline)
        .unwrap_or_else(|error| panic!("baseline json: {error}"));
    let content = baseline["diff_content"]
        .as_str()
        .unwrap_or_else(|| panic!("baseline diff content missing"));
    baseline["diff_content"] =
        Value::String(format!("{content}\n# tampered without digest update\n"));
    state
        .put_state(
            "controller.repository_baseline",
            "active",
            &baseline.to_string(),
        )
        .unwrap_or_else(|error| panic!("write baseline-content tamper: {error}"));
    drop(state);

    let connection = Connection::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("open sqlite for fallback corruption: {error}"));
    connection
        .execute_batch(
            "DROP TRIGGER checkpoint_integrity_no_update;\
             UPDATE checkpoint_integrity SET checkpoint_hash='sha256:0000000000000000000000000000000000000000000000000000000000000000' \
             WHERE generation=2;\
             CREATE TRIGGER checkpoint_integrity_no_update \
             BEFORE UPDATE ON checkpoint_integrity \
             BEGIN \
                 SELECT RAISE(ABORT, 'checkpoint integrity rows are immutable'); \
             END;",
        )
        .unwrap_or_else(|error| panic!("force older checkpoint fallback: {error}"));
    drop(connection);

    let registry = registry_for(&fixture.root);
    let state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("reopen tampered fallback state: {error}"));
    let Err(error) = RecoveryManager::recover(state, &registry) else {
        panic!("fallback must reject baseline diff content tamper");
    };
    assert!(
        error
            .to_string()
            .contains("durable repository baseline diff content does not match its digest")
    );
}

#[test]
fn recovery_rejects_execution_epoch_rollback_below_trusted_manifest() {
    let fixture = Fixture::create("epoch-rollback-manifest");
    let _task_id = run_to_success(&fixture);
    let state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("state before epoch rollback: {error}"));
    let current_epoch = state
        .current_execution_epoch()
        .unwrap_or_else(|error| panic!("current epoch: {error}"));
    assert!(current_epoch > 0);
    drop(state);

    let connection = Connection::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("open sqlite for epoch rollback: {error}"));
    connection
        .execute(
            "UPDATE controller_runtime SET execution_epoch=?1 WHERE singleton=1",
            [current_epoch - 1],
        )
        .unwrap_or_else(|error| panic!("rollback execution epoch: {error}"));
    drop(connection);

    let registry = registry_for(&fixture.root);
    let state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("reopen epoch-rolled state: {error}"));
    let Err(error) = RecoveryManager::recover(state, &registry) else {
        panic!("execution epoch rollback below trusted manifest must fail closed");
    };
    assert!(error.to_string().contains("below trusted recovery floor"));
}

#[test]
fn fallback_rejects_epoch_below_later_authoritative_journal_epoch() {
    let fixture = Fixture::create("epoch-rollback-fallback");
    let _task_id = run_to_success(&fixture);
    let connection = Connection::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("open sqlite for fallback epoch rollback: {error}"));
    connection
        .execute_batch(
            "DROP TRIGGER checkpoint_integrity_no_update;\
             UPDATE checkpoint_integrity SET checkpoint_hash='sha256:0000000000000000000000000000000000000000000000000000000000000000' \
             WHERE generation=2;\
             UPDATE controller_runtime SET execution_epoch=1 WHERE singleton=1;\
             CREATE TRIGGER checkpoint_integrity_no_update \
             BEFORE UPDATE ON checkpoint_integrity \
             BEGIN \
                 SELECT RAISE(ABORT, 'checkpoint integrity rows are immutable'); \
             END;",
        )
        .unwrap_or_else(|error| panic!("force fallback and epoch rollback: {error}"));
    drop(connection);

    let registry = registry_for(&fixture.root);
    let state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("reopen fallback epoch state: {error}"));
    let Err(error) = RecoveryManager::recover(state, &registry) else {
        panic!("fallback must honor later authoritative execution epoch");
    };
    assert!(error.to_string().contains("below trusted recovery floor"));
}

#[test]
fn superseded_plan_checkpoint_is_blocked_without_explicit_carry_forward() {
    let fixture = Fixture::create("superseded");
    let prepared = prepare(&fixture.root);
    let backend = fake_backend(&prepared, false);
    let (_controller, _task_id) = compile_and_activate(&fixture.base, &prepared, &backend);
    let mut state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("state for supersede: {error}"));
    let raw = state
        .get_state("controller.plan", "active")
        .unwrap_or_else(|error| panic!("read active plan: {error}"))
        .unwrap_or_else(|| panic!("active plan missing"));
    let mut value: Value =
        serde_json::from_str(&raw).unwrap_or_else(|error| panic!("plan json: {error}"));
    value["plan_id"] = Value::String("plan.superseding-n-plus-one".to_owned());
    value["revision"] = json!(2);
    value["plan_digest"] = Value::String(format!("sha256:{}", "f".repeat(64)));
    state
        .put_state("controller.plan", "active", &value.to_string())
        .unwrap_or_else(|error| panic!("write superseding plan state: {error}"));
    drop(state);
    let registry = registry_for(&fixture.root);
    let state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("reopen state: {error}"));
    let Err(error) = RecoveryManager::recover(state, &registry) else {
        panic!("superseded checkpoint must not resume");
    };
    assert!(error.to_string().contains("superseded plan"));
    assert!(source(&fixture.root).contains("Save"));
}

#[test]
fn post_activation_pre_checkpoint_recovery_switches_to_n_plus_one_without_deleting_n_rows() {
    let fixture = Fixture::create("supersession-switch");
    let prepared = prepare(&fixture.root);
    let backend = fake_backend(&prepared, false);
    let (controller, task_id) = compile_and_activate(&fixture.base, &prepared, &backend);
    drop(controller);

    let mut state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("state for supersession: {error}"));
    assert!(
        state
            .get_state("controller.task", &task_id)
            .unwrap_or_else(|error| panic!("read N task: {error}"))
            .is_some(),
        "revision N runtime must exist before supersession"
    );
    let next_digest = install_uncheckpointed_supersession(&mut state, &task_id, false);
    drop(state);

    let registry = registry_for(&fixture.root);
    let state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("reopen supersession state: {error}"));
    let (recovered, summary) = RecoveryManager::recover(state, &registry)
        .unwrap_or_else(|error| panic!("recover N+1 activation: {error}"));
    assert_eq!(summary.plan_digest, next_digest);
    assert_eq!(recovered.task_state(&task_id), Some(TaskState::Planned));
    drop(recovered);

    let state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("inspect recovered supersession: {error}"));
    assert!(
        state
            .get_state("controller.task", &task_id)
            .unwrap_or_else(|error| panic!("read historical N task: {error}"))
            .is_some(),
        "historical N task runtime must remain auditable"
    );
    let active_raw = state
        .get_state("controller.plan", "active")
        .unwrap_or_else(|error| panic!("read recovered active plan: {error}"))
        .unwrap_or_else(|| panic!("recovered active plan missing"));
    let active: Value = serde_json::from_str(&active_raw)
        .unwrap_or_else(|error| panic!("recovered active plan json: {error}"));
    let plan_id = active["plan_id"]
        .as_str()
        .unwrap_or_else(|| panic!("recovered plan id"));
    assert_eq!(active["revision"], json!(2));
    assert!(
        state
            .get_state("controller.task", &format!("{plan_id}@r2:{task_id}"))
            .unwrap_or_else(|error| panic!("read active N+1 task: {error}"))
            .is_some(),
        "N+1 runtime must use its revision-scoped namespace"
    );
}

#[test]
fn post_activation_pre_checkpoint_recovery_rejects_tampered_n_plus_one_runtime_digest() {
    let fixture = Fixture::create("supersession-tamper");
    let prepared = prepare(&fixture.root);
    let backend = fake_backend(&prepared, false);
    let (controller, task_id) = compile_and_activate(&fixture.base, &prepared, &backend);
    drop(controller);
    let mut state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("state for supersession tamper: {error}"));
    let _ = install_uncheckpointed_supersession(&mut state, &task_id, true);
    drop(state);

    let registry = registry_for(&fixture.root);
    let state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("reopen tampered supersession: {error}"));
    let Err(error) = RecoveryManager::recover(state, &registry) else {
        panic!("tampered N+1 runtime digest must block recovery");
    };
    assert!(error.to_string().contains("task runtime map differs"));
}

#[test]
fn historical_unknown_that_is_now_failed_does_not_block_recovered_readiness() {
    let fixture = Fixture::create("historical-unknown");
    let prepared = prepare(&fixture.root);
    let backend = fake_backend(&prepared, false);
    let (_controller, task_id) = compile_and_activate(&fixture.base, &prepared, &backend);
    let mut state =
        StateStore::open(fixture.state_path()).unwrap_or_else(|error| panic!("state: {error}"));
    let epoch = state
        .current_execution_epoch()
        .unwrap_or_else(|error| panic!("epoch: {error}"));
    state
        .insert_action_record(NewActionRecord {
            action_id: "action.synthetic-history",
            state: "prepared",
            payload_digest: "sha256:synthetic-payload",
            policy_digest: "sha256:synthetic-policy",
            execution_epoch: epoch,
            event_id: "event.synthetic.prepared",
            event_kind: "prepared",
            payload_json: "{}",
        })
        .unwrap_or_else(|error| panic!("insert synthetic action: {error}"));
    for (expected, next, id) in [
        ("prepared", "authorized", "event.synthetic.authorized"),
        ("authorized", "dispatched", "event.synthetic.dispatched"),
        ("dispatched", "unknown", "event.synthetic.unknown"),
        ("unknown", "reconciled", "event.synthetic.reconciled"),
        ("reconciled", "failed", "event.synthetic.failed"),
    ] {
        state
            .transition_action_with_event(ActionTransition {
                action_id: "action.synthetic-history",
                expected_state: expected,
                next_state: next,
                expected_epoch: epoch,
                event_id: id,
                event_kind: next,
                payload_json: "{}",
                result_digest: None,
            })
            .unwrap_or_else(|error| panic!("synthetic transition {expected}->{next}: {error}"));
    }
    drop(state);
    let registry = registry_for(&fixture.root);
    let state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("recovery state: {error}"));
    let (mut controller, summary) = RecoveryManager::recover(state, &registry)
        .unwrap_or_else(|error| panic!("recover historical unknown: {error}"));
    assert!(summary.unknown_action_ids.is_empty());
    let lease = controller
        .derive_ready_lease(
            &registry,
            &task_id,
            ReadinessInputs::permissive_m1("sha256:t08-history-resource"),
        )
        .unwrap_or_else(|error| panic!("historical unknown should not block: {error}"));
    controller
        .cancel_ready_lease(lease)
        .unwrap_or_else(|error| panic!("cancel lease: {error}"));
}
