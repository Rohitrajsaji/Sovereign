#![cfg(target_os = "macos")]

use serde_json::{Value, json};
use sovereign_context::{
    ContextBudget, ContextMode, ContextPacket, ContextPacketInput, ContextPlanner, EvidenceItem,
    EvidenceKind,
};
use sovereign_controller::{
    Controller, ExecutionRuntime, ModelProposalV1, ReadinessInputs, RecoveryManager, RoleId,
    RoleRegistry, TaskState,
};
use sovereign_evidence::ArtifactStore;
use sovereign_model::{
    BackendHealth, LlamaServerLaunch, LocalOpenAiBackend, LocalOpenAiConfig, MODEL_SCHEMA_VERSION,
    ModelBackend, ModelCapabilities, ModelError, ModelFinishReason, ModelLease, ModelLoadProfile,
    ModelRequest, ModelResidencyProof, ModelResponse, ModelTokenAdmission, ModelUsage,
};
use sovereign_plan::{
    PLAN_COMPILATION_SCHEMA_VERSION, PlanCompilationInput, PlanCompilationRepository, PlanCompiler,
    PlanValidator, ValidationEnvironment,
};
use sovereign_policy::{
    CommandPolicy, CommandRisk, IsolationRequest, MacSandboxExecBackend, ModelCallBudget,
    PinnedExecutable,
};
use sovereign_repo::{ExactRetriever, ProjectRegistry, RepositoryIntelligence, RepositorySnapshot};
use sovereign_state::StateStore;
use sovereign_tools::{PermissionClass, ToolManifest};
use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const SETTINGS_FORM: &[u8] = include_bytes!("fixtures/scenario1/src/settings/SettingsForm.tsx");
const SETTINGS_FORM_TEST: &[u8] =
    include_bytes!("fixtures/scenario1/src/settings/SettingsForm.test.tsx");
const WRITE_TOOL_DIGEST: &str =
    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const FORM_EVIDENCE_ID: &str = "file:repo.app:src/settings/SettingsForm.tsx";
const TARGET_PATH: &str = "src/settings/SettingsForm.tsx";
const FAULT_OLD_LITERAL: &str = "Save button that does not exist";

struct Fixture {
    base: PathBuf,
    root: PathBuf,
}

impl Fixture {
    fn create() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let home = std::env::var_os("HOME").map_or_else(
            || panic!("HOME must be set for real qualification fixture"),
            PathBuf::from,
        );
        let base = home.join(format!(
            ".sovereign-eval-m1-real-qualification-{}-{nanos}",
            std::process::id()
        ));
        let root = base.join("repo");
        let settings = root.join("src/settings");
        fs::create_dir_all(&settings)
            .unwrap_or_else(|error| panic!("create qualification fixture: {error}"));
        fs::write(settings.join("SettingsForm.tsx"), SETTINGS_FORM)
            .unwrap_or_else(|error| panic!("write SettingsForm: {error}"));
        fs::write(settings.join("SettingsForm.test.tsx"), SETTINGS_FORM_TEST)
            .unwrap_or_else(|error| panic!("write SettingsForm test: {error}"));
        git(&root, &["init", "-q"]);
        git(
            &root,
            &[
                "config",
                "user.email",
                "sovereign-real-qualification@example.invalid",
            ],
        );
        git(&root, &["config", "user.name", "Sovereign Qualification"]);
        git(&root, &["add", "."]);
        git(&root, &["commit", "-qm", "real qualification baseline"]);
        Self { base, root }
    }

    fn state_path(&self) -> PathBuf {
        self.base.join("state.sqlite3")
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

impl Prepared {
    fn build(fixture: &Fixture) -> Self {
        let mut registry = ProjectRegistry::new();
        registry
            .register("repo.app", &fixture.root)
            .unwrap_or_else(|error| panic!("register qualification repository: {error}"));
        let snapshot = registry
            .snapshot("repo.app")
            .unwrap_or_else(|error| panic!("snapshot qualification repository: {error}"));
        let retriever = ExactRetriever::new(&registry);
        let form = retriever
            .read_path("repo.app", Path::new(TARGET_PATH), None)
            .unwrap_or_else(|error| panic!("read SettingsForm: {error}"));
        let focused_test = retriever
            .read_path(
                "repo.app",
                Path::new("src/settings/SettingsForm.test.tsx"),
                None,
            )
            .unwrap_or_else(|error| panic!("read focused SettingsForm test: {error}"));
        let packet = ContextPlanner::default()
            .build(
                ContextMode::Implementation,
                ContextBudget::m1_8k(),
                ContextPacketInput {
                    controller_prefix:
                        "Controller owns execution and mutation authority. Exact current source and focused-test evidence below fully resolve this known-path smoke task; the minimal planning proposal MUST use evidence_queries=[] and must not invent additional discovery requirements."
                            .to_owned(),
                    task_contract:
                        "Known exact path src/settings/SettingsForm.tsx: rename only the submit label from Save to Apply; preserve submit behavior. No further evidence discovery is required."
                            .to_owned(),
                    current_state:
                        "repository=repo.app; exact_source_evidence_complete=true; active_plan=none"
                            .to_owned(),
                    authorized_tool_schemas: Vec::new(),
                    candidates: vec![
                        EvidenceItem::from_exact_file(&form, "exact current Settings form"),
                        EvidenceItem::from_exact_file(
                            &focused_test,
                            "focused current Settings behavior test",
                        ),
                    ],
                    output_schema: "phase-specific typed proposal".to_owned(),
                },
            )
            .unwrap_or_else(|error| panic!("build qualification context: {error}"));
        Self {
            registry,
            packet,
            snapshot,
            form_digest: form.digest,
        }
    }
}

struct RuntimeHarness {
    artifacts: ArtifactStore,
    command_policy: CommandPolicy,
    isolation_backend: MacSandboxExecBackend,
    isolation_request: IsolationRequest,
    tool_manifest: ToolManifest,
}

impl RuntimeHarness {
    fn new(fixture: &Fixture) -> Self {
        let artifacts = ArtifactStore::open(fixture.base.join("cas"))
            .unwrap_or_else(|error| panic!("open qualification artifact store: {error}"));
        let python = PinnedExecutable::from_path("/usr/bin/python3", "macos-system-python")
            .unwrap_or_else(|error| panic!("pin python: {error}"));
        let toolchain_root = python
            .path
            .parent()
            .unwrap_or_else(|| panic!("python executable must have parent"))
            .to_path_buf();
        let command_policy = CommandPolicy::new([python], [toolchain_root])
            .unwrap_or_else(|error| panic!("qualification command policy: {error}"));
        let isolation_backend = MacSandboxExecBackend::detect()
            .unwrap_or_else(|error| panic!("detect macOS Seatbelt: {error}"));
        let home =
            std::env::var_os("HOME").map_or_else(|| panic!("HOME must be set"), PathBuf::from);
        let isolation_request = IsolationRequest {
            repository_root: fixture.root.clone(),
            user_home_root: home,
            extra_protected_read_roots: Vec::new(),
            network_offline: true,
            allow_repository_write: true,
            require_full_filesystem_read_jail: false,
        };
        let tool_manifest = ToolManifest {
            tool_id: "tool.patch".to_owned(),
            version: "1.0.0".to_owned(),
            content_digest: WRITE_TOOL_DIGEST.to_owned(),
            permission_ceiling: BTreeSet::from([
                PermissionClass::ProcessExec,
                PermissionClass::RepositoryWrite,
            ]),
            declared_risk_floor: CommandRisk::RepositoryMutation,
        };
        Self {
            artifacts,
            command_policy,
            isolation_backend,
            isolation_request,
            tool_manifest,
        }
    }

    fn runtime<'a>(
        &'a self,
        prepared: &'a Prepared,
        backend: &'a dyn ModelBackend,
    ) -> ExecutionRuntime<'a, MacSandboxExecBackend> {
        ExecutionRuntime {
            registry: &prepared.registry,
            backend,
            command_policy: &self.command_policy,
            isolation_backend: &self.isolation_backend,
            isolation_request: &self.isolation_request,
            artifacts: &self.artifacts,
            tool_manifest: &self.tool_manifest,
            python_executable: Path::new("/usr/bin/python3"),
        }
    }
}

#[derive(Clone)]
struct CapturedRealCall {
    phase: String,
    request_id: String,
    admission: ModelTokenAdmission,
    usage: ModelUsage,
    elapsed_ms: u64,
    peak_rss_kb_during_call: Option<u64>,
    finish_reason: ModelFinishReason,
    prompt_sha256: String,
    raw_response_sha256: String,
    delivered_response_sha256: String,
    raw_response_exact_valid: bool,
    fault_injected: bool,
    repair_prompt_contains_failure_context: bool,
}

impl CapturedRealCall {
    fn report(&self) -> Value {
        json!({
            "phase": self.phase,
            "request_id": self.request_id,
            "token_admission": self.admission,
            "provider_usage": self.usage,
            "elapsed_ms": self.elapsed_ms,
            "prefill_decode_peak_rss_kb": self.peak_rss_kb_during_call,
            "finish_reason": self.finish_reason,
            "prompt_sha256": self.prompt_sha256,
            "raw_response_sha256": self.raw_response_sha256,
            "delivered_response_sha256": self.delivered_response_sha256,
            "raw_response_exact_valid": self.raw_response_exact_valid,
            "fault_injected": self.fault_injected,
            "repair_prompt_contains_failure_context": self.repair_prompt_contains_failure_context,
        })
    }
}

struct QualificationBackend {
    inner: LocalOpenAiBackend,
    expected_form_digest: String,
    controller_calls: AtomicUsize,
    calls: Mutex<Vec<CapturedRealCall>>,
    first_delivered_old_literal: Mutex<Option<String>>,
}

impl QualificationBackend {
    fn new(inner: LocalOpenAiBackend, expected_form_digest: String) -> Self {
        Self {
            inner,
            expected_form_digest,
            controller_calls: AtomicUsize::new(0),
            calls: Mutex::new(Vec::new()),
            first_delivered_old_literal: Mutex::new(None),
        }
    }

    fn captured_calls(&self) -> Vec<CapturedRealCall> {
        self.calls
            .lock()
            .unwrap_or_else(|error| panic!("lock qualification call capture: {error}"))
            .clone()
    }

    fn initial_proposal_is_exact(&self, proposal: &ModelProposalV1) -> bool {
        let action = &proposal.action;
        proposal.schema_version == 1
            && proposal
                .evidence_ids
                .iter()
                .any(|evidence_id| evidence_id == FORM_EVIDENCE_ID)
            && action.repository_id == "repo.app"
            && action.path == TARGET_PATH
            && action.expected_source_digest == self.expected_form_digest
            && action.old_literal == "Save"
            && action.new_literal == "Apply"
            && action.expected_occurrences == 1
    }

    fn first_delivered_old_literal(&self) -> String {
        self.first_delivered_old_literal
            .lock()
            .unwrap_or_else(|error| panic!("lock first delivered old literal: {error}"))
            .clone()
            .unwrap_or_else(|| panic!("initial Controller proposal was not delivered"))
    }
}

impl ModelBackend for QualificationBackend {
    fn capabilities(&self) -> ModelCapabilities {
        self.inner.capabilities()
    }

    fn load(&self, profile: ModelLoadProfile) -> Result<ModelLease, ModelError> {
        self.inner.load(profile)
    }

    fn complete(&self, request: &ModelRequest) -> Result<ModelResponse, ModelError> {
        let admission = self.inner.token_admission(request)?;
        let raw_response = self.inner.complete(request)?;
        let prompt = request
            .messages
            .iter()
            .map(|message| message.content.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let prompt_sha256 = sha256_bytes(prompt.as_bytes()).map_err(ModelError::Io)?;
        let raw_response_sha256 =
            sha256_bytes(raw_response.content.as_bytes()).map_err(ModelError::Io)?;
        let mut delivered = raw_response.clone();
        let mut raw_response_exact_valid = false;
        let mut fault_injected = false;
        let mut repair_prompt_contains_failure_context = false;
        let phase = if request.request_id.starts_with("controller.") {
            let controller_index = self.controller_calls.fetch_add(1, Ordering::SeqCst);
            match controller_index {
                0 => {
                    if let Ok(mut proposal) =
                        serde_json::from_str::<ModelProposalV1>(&raw_response.content)
                    {
                        raw_response_exact_valid = self.initial_proposal_is_exact(&proposal);
                        if raw_response_exact_valid {
                            FAULT_OLD_LITERAL.clone_into(&mut proposal.action.old_literal);
                            delivered.content = serde_json::to_string(&proposal)?;
                            delivered.structured = Some(serde_json::to_value(&proposal)?);
                            fault_injected = true;
                        }
                        *self.first_delivered_old_literal.lock().map_err(|_| {
                            ModelError::LockPoisoned("qualification initial old literal")
                        })? = Some(proposal.action.old_literal.clone());
                    }
                    "controller_initial"
                }
                1 => {
                    let expected_old = self
                        .first_delivered_old_literal
                        .lock()
                        .map_err(|_| ModelError::LockPoisoned("qualification repair old literal"))?
                        .clone()
                        .ok_or_else(|| {
                            ModelError::InvalidResponse(
                                "repair dispatched before an initial Controller proposal"
                                    .to_owned(),
                            )
                        })?;
                    repair_prompt_contains_failure_context = prompt
                        .contains("proposal_validation_failure")
                        && prompt.contains("failure_signature")
                        && prompt.contains("failed_action_facts")
                        && prompt.contains(&expected_old);
                    if !repair_prompt_contains_failure_context {
                        return Err(ModelError::InvalidResponse(
                            "real repair request omitted actionable durable FailureRecord diagnostic/facts"
                                .to_owned(),
                        ));
                    }
                    if serde_json::from_str::<ModelProposalV1>(&raw_response.content).is_err() {
                        return Err(ModelError::InvalidResponse(
                            "real repair response failed ModelProposalV1 decode".to_owned(),
                        ));
                    }
                    "controller_repair"
                }
                _ => {
                    return Err(ModelError::InvalidResponse(
                        "qualification unexpectedly issued more than two Controller model calls"
                            .to_owned(),
                    ));
                }
            }
        } else {
            "plan_compiler"
        };
        let delivered_response_sha256 =
            sha256_bytes(delivered.content.as_bytes()).map_err(ModelError::Io)?;
        self.calls
            .lock()
            .map_err(|_| ModelError::LockPoisoned("m1-real-qualification-calls"))?
            .push(CapturedRealCall {
                phase: phase.to_owned(),
                request_id: request.request_id.clone(),
                admission,
                usage: raw_response.usage,
                elapsed_ms: raw_response.elapsed_ms,
                peak_rss_kb_during_call: raw_response.peak_rss_kb_during_call,
                finish_reason: raw_response.finish_reason,
                prompt_sha256,
                raw_response_sha256,
                delivered_response_sha256,
                raw_response_exact_valid,
                fault_injected,
                repair_prompt_contains_failure_context,
            });
        Ok(delivered)
    }

    fn count_tokens(&self, content: &str) -> Result<u32, ModelError> {
        self.inner.count_tokens(content)
    }

    fn health(&self) -> Result<BackendHealth, ModelError> {
        self.inner.health()
    }

    fn unload(&self) -> Result<(), ModelError> {
        self.inner.unload()
    }

    fn residency_proof(&self) -> Result<ModelResidencyProof, ModelError> {
        self.inner.residency_proof()
    }
}

fn capability(id: &str, digest: &str) -> Value {
    json!({"id": id, "version": "1.0.0", "digest": digest})
}

fn canonical_implementer_role() -> Value {
    let pin = RoleRegistry::canonical()
        .canonical_pin(RoleId::Implementer)
        .unwrap_or_else(|error| panic!("canonical implementer pin: {error}"));
    json!({"id": pin.id, "version": pin.version, "digest": pin.digest})
}

fn global_policy() -> Value {
    serde_json::from_str(include_str!("fixtures/scenario1/policy.json"))
        .unwrap_or_else(|error| panic!("parse qualification policy: {error}"))
}

fn compilation_input(prepared: &Prepared) -> PlanCompilationInput {
    PlanCompilationInput {
        schema_version: PLAN_COMPILATION_SCHEMA_VERSION,
        compilation_id: "compile.scenario1.m1-real-qualification".to_owned(),
        compiled_at: "2026-09-13T03:30:00Z".to_owned(),
        project_id: "project.scenario1".to_owned(),
        project_name: "M1 real-model qualification".to_owned(),
        workspace_roots: vec![prepared.snapshot.root.display().to_string()],
        goal_id: "goal.scenario1".to_owned(),
        goal_statement: "Rename the Settings button from Save to Apply.".to_owned(),
        goal_invariants: vec!["Do not alter submit behavior.".to_owned()],
        goal_non_goals: vec!["Do not redesign the Settings form.".to_owned()],
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
        role: canonical_implementer_role(),
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
        max_model_calls: 2,
        model_input_token_ceiling: 8_192,
        max_output_tokens: 768,
        model_deadline_ms: 180_000,
    }
}

fn real_backend(
    runtime: PathBuf,
    model_path: PathBuf,
    expected_form_digest: String,
) -> QualificationBackend {
    let mut config = LocalOpenAiConfig::with_defaults(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        free_port(),
        "Qwen3-4B-Q4_K_M",
        ModelCapabilities {
            schema_version: MODEL_SCHEMA_VERSION,
            model_id: "Qwen3-4B-Q4_K_M".to_owned(),
            parameter_class: "4B".to_owned(),
            quantization: "Q4_K_M".to_owned(),
            max_context_tokens: 16_384,
            supports_tools: true,
            supports_json_schema: true,
            local: true,
        },
    );
    config.request_timeout_ms = 180_000;
    config.launch = Some(LlamaServerLaunch {
        executable: runtime,
        model_path,
        extra_args: vec!["--reasoning".to_owned(), "off".to_owned()],
    });
    QualificationBackend::new(
        LocalOpenAiBackend::new(config)
            .unwrap_or_else(|error| panic!("construct qualification local backend: {error}")),
        expected_form_digest,
    )
}

fn task_contract_and_acceptance(controller: &Controller, task_id: &str) -> (String, Value) {
    let digest = controller
        .task_contract_digest(task_id)
        .unwrap_or_else(|| panic!("task contract digest missing"))
        .to_owned();
    let raw = controller
        .state()
        .get_state("controller.task", task_id)
        .unwrap_or_else(|error| panic!("read task runtime: {error}"))
        .unwrap_or_else(|| panic!("task runtime missing"));
    let runtime: Value =
        serde_json::from_str(&raw).unwrap_or_else(|error| panic!("task runtime JSON: {error}"));
    let acceptance = runtime
        .pointer("/task/acceptance_criteria")
        .cloned()
        .unwrap_or_else(|| panic!("acceptance criteria missing"));
    (digest, acceptance)
}

fn satisfy_compiled_execution_evidence(
    controller: &mut Controller,
    prepared: &Prepared,
    task_id: &str,
) {
    let raw_plan = controller
        .state()
        .get_state("controller.plan_document", "active")
        .unwrap_or_else(|error| panic!("read plan for evidence satisfaction: {error}"))
        .unwrap_or_else(|| panic!("active plan missing for evidence satisfaction"));
    let plan: Value = serde_json::from_str(&raw_plan)
        .unwrap_or_else(|error| panic!("active plan JSON for evidence satisfaction: {error}"));
    let task = plan
        .pointer("/tasks/0")
        .unwrap_or_else(|| panic!("qualification plan has no first task"));
    let requirements = task
        .get("evidence_requirements")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for requirement in requirements.iter().filter(|requirement| {
        requirement.get("required_before").and_then(Value::as_str) == Some("execution")
    }) {
        let requirement_id = requirement
            .get("requirement_id")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("execution evidence requirement lacks ID"));
        let query = requirement
            .get("query")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("execution evidence requirement lacks query"));
        let evidence_id = if query.contains("src/settings/SettingsForm.test.tsx") {
            "file:repo.app:src/settings/SettingsForm.test.tsx"
        } else if query.contains(TARGET_PATH) {
            FORM_EVIDENCE_ID
        } else {
            panic!(
                "real Qwen compiled a non-resolvable execution evidence query for the bounded qualification fixture: {query}"
            );
        };
        controller
            .record_exact_evidence_satisfaction(
                &prepared.registry,
                task_id,
                requirement_id,
                &prepared.packet,
                &[evidence_id.to_owned()],
            )
            .unwrap_or_else(|error| {
                panic!("satisfy real-Qwen evidence requirement {requirement_id} ({query}): {error}")
            });
    }
}

fn latest_controller_event_field(controller: &Controller, kind: &str, field: &str) -> String {
    controller
        .state()
        .journal()
        .unwrap_or_else(|error| panic!("read controller journal: {error}"))
        .into_iter()
        .rev()
        .find_map(|event| {
            if event.entity_type != "controller" || event.event_kind != kind {
                return None;
            }
            let payload: Value = serde_json::from_str(&event.payload_json)
                .unwrap_or_else(|error| panic!("parse {kind} payload: {error}"));
            payload
                .get(field)
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| panic!("missing controller event field {kind}.{field}"))
}

fn git(root: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .unwrap_or_else(|error| panic!("run git {args:?}: {error}"));
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn git_output(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .unwrap_or_else(|error| panic!("run git {args:?}: {error}"));
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn free_port() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap_or_else(|error| panic!("bind qualification loopback port: {error}"));
    listener
        .local_addr()
        .unwrap_or_else(|error| panic!("read qualification loopback port: {error}"))
        .port()
}

fn required_env(name: &str) -> PathBuf {
    std::env::var_os(name).map_or_else(
        || panic!("missing required environment {name}"),
        PathBuf::from,
    )
}

fn command_text(program: &str, args: &[&str]) -> String {
    Command::new(program).args(args).output().map_or_else(
        |error| format!("unavailable: {error}"),
        |output| {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.trim().is_empty() {
                String::from_utf8_lossy(&output.stderr).trim().to_owned()
            } else {
                stdout.trim().to_owned()
            }
        },
    )
}

fn host_observation() -> Value {
    json!({
        "memory_pressure": command_text("/usr/bin/memory_pressure", &["-Q"]),
        "vm_stat": command_text("/usr/bin/vm_stat", &[]),
        "swapusage": command_text("/usr/sbin/sysctl", &["vm.swapusage"]),
    })
}

fn process_absent(pid: Option<u32>) -> bool {
    pid.is_none_or(|value| {
        !Command::new("/bin/ps")
            .args(["-p", &value.to_string()])
            .status()
            .is_ok_and(|status| status.success())
    })
}

fn sha256_bytes(bytes: &[u8]) -> Result<String, std::io::Error> {
    let mut child = Command::new("/usr/bin/shasum")
        .args(["-a", "256"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .as_mut()
        .ok_or_else(|| std::io::Error::other("shasum stdin unavailable"))?
        .write_all(bytes)?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(std::io::Error::other("shasum failed"));
    }
    let digest = String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .map(str::to_owned)
        .ok_or_else(|| std::io::Error::other("shasum returned no digest"))?;
    Ok(format!("sha256:{digest}"))
}

fn sha256_file(path: &Path) -> String {
    let bytes = fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    sha256_bytes(&bytes).unwrap_or_else(|error| panic!("hash {}: {error}", path.display()))
}

fn optional_report(report: &Value) {
    let Some(path) = std::env::var_os("SOVEREIGN_M1_QUAL_REPORT") else {
        return;
    };
    let path = PathBuf::from(path);
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .unwrap_or_else(|error| panic!("create qualification report parent: {error}"));
    }
    fs::write(
        &path,
        serde_json::to_vec_pretty(report)
            .unwrap_or_else(|error| panic!("serialize qualification report: {error}")),
    )
    .unwrap_or_else(|error| panic!("write qualification report {}: {error}", path.display()));
}

#[test]
#[ignore = "requires local Qwen3-4B GGUF + managed llama.cpp; prime owns the explicit qualification run"]
#[allow(clippy::too_many_lines)]
fn m1_real_qwen_implementation_repair_restart_qualification() {
    let runtime_path = required_env("SOVEREIGN_MODEL_RUNTIME");
    let model_path = required_env("SOVEREIGN_MODEL_PATH");
    assert!(runtime_path.is_file(), "model runtime is missing");
    assert!(model_path.is_file(), "model GGUF is missing");
    let fixture = Fixture::create();
    let prepared = Prepared::build(&fixture);
    let runtime_harness = RuntimeHarness::new(&fixture);
    let host_before = host_observation();
    let backend = real_backend(
        runtime_path.clone(),
        model_path.clone(),
        prepared.form_digest.clone(),
    );
    let lease = backend
        .load(ModelLoadProfile {
            context_tokens: 8_192,
            output_reserve_tokens: 1_536,
            startup_timeout_ms: 180_000,
            provider_call_timeout_ms: 180_000,
        })
        .unwrap_or_else(|error| panic!("load real Qwen qualification backend: {error}"));

    let validator = PlanValidator::new(ValidationEnvironment::default())
        .unwrap_or_else(|error| panic!("construct qualification validator: {error}"));
    let compiler = PlanCompiler::new(&backend, &validator, "m1-real-qualification-v1")
        .unwrap_or_else(|error| panic!("construct qualification compiler: {error}"));
    let input = compilation_input(&prepared);
    assert_eq!(input.max_model_calls, 2);
    let mut compiler_budget = ModelCallBudget::new(2, 180_000);
    let compilation = compiler
        .compile(&input, &mut compiler_budget)
        .unwrap_or_else(|error| panic!("real Qwen PlanCompiler qualification: {error}"));
    assert!(validator.validate(compilation.plan()).is_empty());
    let compilation_evidence_digest = compilation.compilation_evidence_digest().to_owned();
    let compiler_plan_digest = compilation.plan_digest().to_owned();
    let compiler_evidence_ids = compilation
        .compilation_evidence()
        .exact_evidence()
        .iter()
        .map(|evidence| evidence.evidence_id.clone())
        .collect::<Vec<_>>();
    let compiler_model_attempts =
        serde_json::to_value(compilation.compilation_evidence().model_attempts())
            .unwrap_or_else(|error| panic!("serialize compiler attempt evidence: {error}"));
    let compiler_calls_used = 2_u32.saturating_sub(compiler_budget.remaining_calls());
    backend
        .unload()
        .unwrap_or_else(|error| panic!("release compiler-only Qwen residency: {error}"));
    assert_eq!(
        backend
            .residency_proof()
            .unwrap_or_else(|error| panic!("prove compiler-only Qwen absence: {error}")),
        ModelResidencyProof::Absent,
        "Controller setup must begin only after compiler-owned model residency is proven absent"
    );

    let state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("open qualification state: {error}"));
    let mut controller = Controller::new(state);
    let activation = controller
        .activate(compilation, &prepared.registry)
        .unwrap_or_else(|error| panic!("activate real-Qwen compilation: {error}"));
    assert_eq!(activation.task_ids.len(), 1);
    assert_eq!(activation.plan_digest, compiler_plan_digest);
    let plan_id = activation.plan_id.clone();
    let plan_digest = activation.plan_digest.clone();
    let task_id = activation.task_ids[0].clone();
    satisfy_compiled_execution_evidence(&mut controller, &prepared, &task_id);
    let plan_before = controller
        .state()
        .get_state("controller.plan_document", "active")
        .unwrap_or_else(|error| panic!("read plan before execution: {error}"))
        .unwrap_or_else(|| panic!("active plan document missing"));
    let plan_before_sha256 =
        sha256_bytes(plan_before.as_bytes()).unwrap_or_else(|error| panic!("hash plan: {error}"));
    let (task_contract_before, acceptance_before) =
        task_contract_and_acceptance(&controller, &task_id);
    let acceptance_before_json = serde_json::to_vec(&acceptance_before)
        .unwrap_or_else(|error| panic!("serialize acceptance before repair: {error}"));
    let acceptance_before_sha256 = sha256_bytes(&acceptance_before_json)
        .unwrap_or_else(|error| panic!("hash acceptance before repair: {error}"));

    let ready = controller
        .derive_ready_lease(
            &prepared.registry,
            &task_id,
            ReadinessInputs::permissive_m1("sha256:m1-real-initial-readiness"),
            &runtime_harness.tool_manifest,
        )
        .unwrap_or_else(|error| panic!("derive real-Qwen initial readiness: {error}"));
    let mut execution_budget = ModelCallBudget::new(2, 30_000);
    {
        let execution_runtime = runtime_harness.runtime(&prepared, &backend);
        let first = controller.execute_replace(
            ready,
            &execution_runtime,
            &prepared.packet,
            &mut execution_budget,
        );
        assert!(
            first.is_err(),
            "initial real Controller proposal must route to repair"
        );
    }
    assert_eq!(
        controller.task_state(&task_id),
        Some(TaskState::RepairPending)
    );
    assert_eq!(controller.task_attempts_started(&task_id), Some(1));
    assert_eq!(controller.task_model_calls_used(&task_id), Some(1));
    let failure = controller
        .latest_failure_record(&task_id)
        .unwrap_or_else(|error| panic!("read qualification FailureRecord: {error}"))
        .unwrap_or_else(|| panic!("qualification FailureRecord missing"));
    assert_eq!(
        failure.category, "proposal_validation_failure",
        "initial Controller failure_code={} synopsis={} facts={:?}",
        failure.failure_code, failure.synopsis, failure.failed_action_facts
    );
    let initial_delivered_old_literal = backend.first_delivered_old_literal();
    assert!(!failure.failure_code.is_empty());
    assert_eq!(failure.decision, "repair");
    assert_eq!(failure.plan_id, plan_id);
    assert_eq!(failure.plan_digest, plan_digest);
    assert_eq!(failure.task_id, task_id);
    assert_eq!(failure.task_contract_digest, task_contract_before);
    assert!(failure.action_id.is_none());
    assert!(failure.synopsis.contains(&failure.failure_code));
    assert_eq!(
        failure
            .failed_action_facts
            .get("old_literal")
            .map(String::as_str),
        Some(initial_delivered_old_literal.as_str())
    );
    let failure_record_digest =
        latest_controller_event_field(&controller, "failure_recorded", "failure_record_digest");
    let attempt1_id = failure.attempt_id.clone();

    drop(controller);
    let reopened = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("reopen qualification state: {error}"));
    let (mut controller, recovery) = RecoveryManager::recover(reopened, &prepared.registry)
        .unwrap_or_else(|error| panic!("recover qualification Controller: {error}"));
    assert!(!recovery.mutation_blocked);
    assert_eq!(recovery.plan_id, plan_id);
    assert_eq!(recovery.plan_digest, plan_digest);
    assert_eq!(
        controller.task_state(&task_id),
        Some(TaskState::RepairPending)
    );
    assert_eq!(controller.task_attempts_started(&task_id), Some(1));
    assert_eq!(controller.task_model_calls_used(&task_id), Some(1));
    assert_eq!(
        controller
            .latest_failure_record(&task_id)
            .unwrap_or_else(|error| panic!("read recovered FailureRecord: {error}")),
        Some(failure.clone())
    );

    let success;
    let repair_packet;
    {
        let execution_runtime = runtime_harness.runtime(&prepared, &backend);
        (success, repair_packet) = controller
            .repair_replace(
                &task_id,
                &execution_runtime,
                &prepared.packet,
                &[],
                ReadinessInputs::permissive_m1("sha256:m1-real-repair-readiness"),
                &mut execution_budget,
            )
            .unwrap_or_else(|error| {
                let latest = controller.latest_failure_record(&task_id).ok().flatten();
                panic!("real Qwen targeted repair: {error}; latest_failure={latest:?}")
            });
    }
    assert!(success.verification.passed);
    assert_eq!(success.task_id, task_id);
    assert_ne!(success.attempt_id, attempt1_id);
    assert_eq!(controller.task_state(&task_id), Some(TaskState::Succeeded));
    assert_eq!(controller.task_attempts_started(&task_id), Some(2));
    assert_eq!(controller.task_model_calls_used(&task_id), Some(2));
    assert_eq!(execution_budget.remaining_calls(), 0);
    assert_eq!(repair_packet.plan_id, plan_id);
    assert_eq!(repair_packet.plan_digest, plan_digest);
    assert_eq!(repair_packet.task_id, task_id);
    assert_eq!(repair_packet.task_contract_digest, task_contract_before);
    assert_eq!(repair_packet.prior_attempt_id, attempt1_id);
    assert_eq!(repair_packet.failure_signature, failure.signature);
    assert_eq!(repair_packet.failure_record_digest, failure_record_digest);
    assert!(
        repair_packet
            .context
            .items
            .iter()
            .any(|item| item.kind == EvidenceKind::FailureSynopsis)
    );
    assert!(repair_packet.context.items.iter().all(|item| !matches!(
        item.kind,
        EvidenceKind::PriorAttemptTranscript
            | EvidenceKind::RawToolLog
            | EvidenceKind::HiddenReasoning
    )));
    let repair_packet_digest =
        latest_controller_event_field(&controller, "repair_packet_built", "repair_packet_digest");

    let (task_contract_after, acceptance_after) =
        task_contract_and_acceptance(&controller, &task_id);
    assert_eq!(task_contract_after, task_contract_before);
    assert_eq!(acceptance_after, acceptance_before);
    let plan_after = controller
        .state()
        .get_state("controller.plan_document", "active")
        .unwrap_or_else(|error| panic!("read plan after repair: {error}"))
        .unwrap_or_else(|| panic!("active plan document missing after repair"));
    assert_eq!(plan_after, plan_before);
    let acceptance_after_json = serde_json::to_vec(&acceptance_after)
        .unwrap_or_else(|error| panic!("serialize acceptance after repair: {error}"));
    let acceptance_after_sha256 = sha256_bytes(&acceptance_after_json)
        .unwrap_or_else(|error| panic!("hash acceptance after repair: {error}"));
    assert_eq!(acceptance_after_sha256, acceptance_before_sha256);

    let source = fs::read_to_string(fixture.root.join(TARGET_PATH))
        .unwrap_or_else(|error| panic!("read qualified source: {error}"));
    assert!(source.contains("Apply"));
    assert!(!source.contains(">Save<"));
    let changed_files = git_output(&fixture.root, &["diff", "--name-only"])
        .lines()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    assert_eq!(changed_files, vec![TARGET_PATH.to_owned()]);
    let final_diff = git_output(&fixture.root, &["diff", "--", TARGET_PATH]);
    let final_diff_sha256 = sha256_bytes(final_diff.as_bytes())
        .unwrap_or_else(|error| panic!("hash final qualification diff: {error}"));

    let action_record = controller
        .state()
        .action_record(&success.action_id)
        .unwrap_or_else(|error| panic!("read qualified action record: {error}"))
        .unwrap_or_else(|| panic!("qualified action record missing"));
    assert_eq!(action_record.state, "committed");
    assert_eq!(
        action_record.result_digest.as_deref(),
        Some(success.action_result_digest.as_str())
    );

    let host_after_work = host_observation();
    backend
        .unload()
        .unwrap_or_else(|error| panic!("unload real Qwen qualification backend: {error}"));
    let process_absent_after_unload = process_absent(lease.process_id);
    assert!(process_absent_after_unload);
    let host_after_unload = host_observation();

    let calls = backend.captured_calls();
    let controller_initial = calls
        .iter()
        .find(|call| call.phase == "controller_initial")
        .unwrap_or_else(|| panic!("initial real Controller call was not captured"));
    if controller_initial.raw_response_exact_valid {
        assert!(controller_initial.fault_injected);
        assert_ne!(
            controller_initial.raw_response_sha256,
            controller_initial.delivered_response_sha256
        );
    } else {
        assert!(!controller_initial.fault_injected);
        assert_eq!(
            controller_initial.raw_response_sha256,
            controller_initial.delivered_response_sha256
        );
    }
    let controller_repair = calls
        .iter()
        .find(|call| call.phase == "controller_repair")
        .unwrap_or_else(|| panic!("real repair Controller call was not captured"));
    assert!(controller_repair.repair_prompt_contains_failure_context);
    assert!(!controller_repair.fault_injected);
    assert_eq!(
        controller_repair.raw_response_sha256,
        controller_repair.delivered_response_sha256
    );
    assert!(calls.iter().any(|call| call.phase == "plan_compiler"));
    for call in &calls {
        assert!(call.admission.admitted_input_tokens <= 8_192);
        assert_eq!(
            call.admission.admitted_input_tokens,
            call.admission
                .rendered_input_tokens
                .saturating_add(call.admission.structured_output_tokens)
        );
        assert_eq!(
            u64::from(call.admission.rendered_input_tokens),
            call.usage.input_tokens
        );
        assert!(call.admission.reserved_output_tokens <= 1_536);
        assert_eq!(call.admission.server_context_tokens, 9_728);
    }

    let report = json!({
        "schema": "sovereign-m1-real-qualification-v1",
        "target": {
            "os": std::env::consts::OS,
            "architecture": std::env::consts::ARCH,
            "profile": "MacBook Air M1 / 8 GB",
        },
        "model": {
            "id": "Qwen3-4B-Q4_K_M",
            "parameter_class": "4B",
            "quantization": "Q4_K_M",
            "path": model_path,
            "sha256": sha256_file(&model_path),
        },
        "runtime": {
            "provider": "managed llama.cpp OpenAI-compatible loopback",
            "path": runtime_path,
            "sha256": sha256_file(&runtime_path),
            "version": command_text(
                runtime_path.to_string_lossy().as_ref(),
                &["--version"]
            ),
        },
        "model_lease": {
            "context_input_tokens": lease.context_tokens,
            "server_context_tokens": lease.server_context_tokens,
            "output_reserve_tokens": 1_536,
            "startup_peak_rss_kb": lease.startup_peak_rss_kb,
            "post_load_steady_rss_kb": lease.post_load_rss_kb,
            "process_absent_after_unload": process_absent_after_unload,
        },
        "real_model_calls": calls.iter().map(CapturedRealCall::report).collect::<Vec<_>>(),
        "compiler": {
            "max_model_calls": 2,
            "model_calls_used": compiler_calls_used,
            "plan_digest": compiler_plan_digest,
            "compilation_evidence_digest": compilation_evidence_digest,
            "exact_evidence_ids": compiler_evidence_ids,
            "model_attempt_evidence": compiler_model_attempts,
        },
        "controller": {
            "plan_id": plan_id,
            "plan_digest": plan_digest,
            "task_id": task_id,
            "task_contract_digest": task_contract_before,
            "plan_document_sha256": plan_before_sha256,
            "acceptance_contract_sha256": acceptance_before_sha256,
            "attempts_started_after_repair": controller.task_attempts_started(&success.task_id),
            "model_calls_used_after_repair": controller.task_model_calls_used(&success.task_id),
        },
        "attempt_1_failure": {
            "attempt_id": attempt1_id,
            "failure_record_digest": failure_record_digest,
            "failure_signature": failure.signature,
            "failure_code": failure.failure_code,
            "failure_category": failure.category,
            "failure_evidence_ids": failure.evidence_refs,
            "action_id": failure.action_id,
            "controlled_post_model_fault": controller_initial.fault_injected,
            "raw_response_exact_valid": controller_initial.raw_response_exact_valid,
            "raw_real_response_preserved_only_as_sha256_and_metrics": true,
        },
        "recovery": {
            "checkpoint_generation": recovery.checkpoint_generation,
            "checkpoint_action_sequence": recovery.checkpoint_action_sequence,
            "execution_epoch_before": recovery.execution_epoch_before,
            "execution_epoch_after": recovery.execution_epoch_after,
            "replayed_events": recovery.replayed_events,
            "fallback_checkpoint_used": recovery.fallback_checkpoint_used,
            "mutation_blocked": recovery.mutation_blocked,
        },
        "repair": {
            "repair_packet_digest": repair_packet_digest,
            "failure_record_digest": repair_packet.failure_record_digest,
            "prior_attempt_id": repair_packet.prior_attempt_id,
            "failure_signature": repair_packet.failure_signature,
            "repair_evidence_ids": repair_packet.context.items.iter().map(|item| item.evidence_id.clone()).collect::<Vec<_>>(),
            "contains_failure_synopsis": repair_packet.context.items.iter().any(|item| item.kind == EvidenceKind::FailureSynopsis),
            "contains_prior_transcript_or_raw_log": repair_packet.context.items.iter().any(|item| matches!(item.kind, EvidenceKind::PriorAttemptTranscript | EvidenceKind::RawToolLog | EvidenceKind::HiddenReasoning)),
        },
        "attempt_2_success": {
            "attempt_id": success.attempt_id,
            "action_id": success.action_id,
            "action_result_digest": success.action_result_digest,
            "verification_id": success.verification.verification_id,
            "verification_evidence_id": success.verification_evidence_id,
            "verification_evidence_ids": success.verification.evidence_ids,
            "verification_passed": success.verification.passed,
            "verification_diff_digest": success.verification.diff_digest,
            "verification_post_snapshot_digest": success.verification.post_snapshot_digest,
        },
        "immutability": {
            "plan_document_unchanged": true,
            "task_contract_unchanged": task_contract_after == task_contract_before,
            "acceptance_contract_unchanged": acceptance_after_sha256 == acceptance_before_sha256,
        },
        "repository_result": {
            "changed_files": changed_files,
            "final_diff_sha256": final_diff_sha256,
            "target_contains_apply": source.contains("Apply"),
            "target_contains_old_rendered_label": source.contains(">Save<"),
        },
        "host": {
            "before_load": host_before,
            "after_qualification_before_unload": host_after_work,
            "after_unload": host_after_unload,
        },
    });
    optional_report(&report);
    println!(
        "SOVEREIGN_M1_QUAL_JSON={}",
        serde_json::to_string(&report)
            .unwrap_or_else(|error| panic!("serialize qualification stdout report: {error}"))
    );
}
