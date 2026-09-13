use serde_json::{Value, json};
use sovereign_context::{
    ContextBudget, ContextMode, ContextPacketInput, ContextPlanner, EvidenceItem,
};
use sovereign_model::{
    BackendHealth, LlamaServerLaunch, LocalOpenAiBackend, LocalOpenAiConfig, MODEL_SCHEMA_VERSION,
    ModelBackend, ModelCapabilities, ModelError, ModelLease, ModelLoadProfile, ModelRequest,
    ModelResponse,
};
use sovereign_plan::{
    PLAN_COMPILATION_SCHEMA_VERSION, PlanCompilationInput, PlanCompilationRepository, PlanCompiler,
    PlanValidator, ValidationEnvironment,
};
use sovereign_policy::ModelCallBudget;
use sovereign_repo::{ExactRetriever, ProjectRegistry, RepositoryIntelligence};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const SETTINGS_FORM: &[u8] = include_bytes!("fixtures/scenario1/src/settings/SettingsForm.tsx");
const SETTINGS_FORM_TEST: &[u8] =
    include_bytes!("fixtures/scenario1/src/settings/SettingsForm.test.tsx");

struct FixtureRepo(PathBuf);

impl FixtureRepo {
    fn create() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let root = std::env::temp_dir().join(format!(
            "sovereign-eval-real-compiler-{}-{nanos}",
            std::process::id()
        ));
        let settings = root.join("src/settings");
        fs::create_dir_all(&settings)
            .unwrap_or_else(|error| panic!("create real-smoke fixture: {error}"));
        fs::write(settings.join("SettingsForm.tsx"), SETTINGS_FORM)
            .unwrap_or_else(|error| panic!("write form fixture: {error}"));
        fs::write(settings.join("SettingsForm.test.tsx"), SETTINGS_FORM_TEST)
            .unwrap_or_else(|error| panic!("write test fixture: {error}"));
        git(&root, &["init", "-q"]);
        git(
            &root,
            &[
                "config",
                "user.email",
                "sovereign-real-smoke@example.invalid",
            ],
        );
        git(&root, &["config", "user.name", "Sovereign Real Smoke"]);
        git(&root, &["add", "."]);
        git(&root, &["commit", "-qm", "real compiler smoke baseline"]);
        Self(root)
    }
}

impl Drop for FixtureRepo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
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

struct CapturingBackend {
    inner: LocalOpenAiBackend,
    request: Mutex<Option<ModelRequest>>,
    response: Mutex<Option<ModelResponse>>,
}

impl CapturingBackend {
    fn new(inner: LocalOpenAiBackend) -> Self {
        Self {
            inner,
            request: Mutex::new(None),
            response: Mutex::new(None),
        }
    }

    fn captured(&self) -> (ModelRequest, ModelResponse) {
        let request = self
            .request
            .lock()
            .unwrap_or_else(|error| panic!("lock captured request: {error}"))
            .clone()
            .unwrap_or_else(|| panic!("compiler did not issue a model request"));
        let response = self
            .response
            .lock()
            .unwrap_or_else(|error| panic!("lock captured response: {error}"))
            .clone()
            .unwrap_or_else(|| panic!("compiler did not receive a model response"));
        (request, response)
    }
}

impl ModelBackend for CapturingBackend {
    fn capabilities(&self) -> ModelCapabilities {
        self.inner.capabilities()
    }

    fn load(&self, profile: ModelLoadProfile) -> Result<ModelLease, ModelError> {
        self.inner.load(profile)
    }

    fn complete(&self, request: &ModelRequest) -> Result<ModelResponse, ModelError> {
        *self
            .request
            .lock()
            .map_err(|_| ModelError::LockPoisoned("compiler-smoke-request"))? =
            Some(request.clone());
        let response = self.inner.complete(request)?;
        *self
            .response
            .lock()
            .map_err(|_| ModelError::LockPoisoned("compiler-smoke-response"))? =
            Some(response.clone());
        Ok(response)
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
}

fn capability(id: &str, digest_byte: char) -> Value {
    json!({
        "id": id,
        "version": "1.0.0",
        "digest": format!("sha256:{}", digest_byte.to_string().repeat(64))
    })
}

fn build_input(root: &Path) -> (PlanCompilationInput, u32) {
    let mut registry = ProjectRegistry::new();
    registry
        .register("repo.app", root)
        .unwrap_or_else(|error| panic!("register smoke repo: {error}"));
    let snapshot = registry
        .snapshot("repo.app")
        .unwrap_or_else(|error| panic!("snapshot smoke repo: {error}"));
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
                controller_prefix:
                    "Compile a candidate only; never activate plans or authorize actions.".to_owned(),
                task_contract: "Rename only the Settings submit label from Save to Apply; preserve submit behavior."
                    .to_owned(),
                current_state: format!(
                    "repository=repo.app; head={:?}; dirty_digest={}; active_plan=none",
                    snapshot.head, snapshot.dirty_digest
                ),
                candidates: vec![
                    EvidenceItem::from_exact_file(&form, "exact current Settings form"),
                    EvidenceItem::from_exact_file(&focused_test, "focused current Settings test"),
                ],
                output_schema: "bounded minimal planning proposal v1".to_owned(),
            },
        )
        .unwrap_or_else(|error| panic!("build smoke context: {error}"));
    let selected_tokens = packet.metrics.final_serialized_input_tokens;
    let policy: Value = serde_json::from_str(include_str!("fixtures/scenario1/policy.json"))
        .unwrap_or_else(|error| panic!("parse policy: {error}"));
    (
        PlanCompilationInput {
            schema_version: PLAN_COMPILATION_SCHEMA_VERSION,
            compilation_id: "compile.scenario1.real".to_owned(),
            compiled_at: "2026-09-12T18:30:00Z".to_owned(),
            project_id: "project.scenario1".to_owned(),
            project_name: "Scenario 1 real-model compiler smoke".to_owned(),
            workspace_roots: vec![snapshot.root.display().to_string()],
            goal_id: "goal.scenario1".to_owned(),
            goal_statement: "Rename the Settings button from Save to Apply.".to_owned(),
            goal_invariants: vec!["Do not alter submit behavior.".to_owned()],
            goal_non_goals: vec!["Do not redesign the Settings form.".to_owned()],
            repository: PlanCompilationRepository {
                repository_id: snapshot.repository_id,
                root: snapshot.root.display().to_string(),
                head: snapshot.head,
                branch: snapshot.branch,
                dirty_digest: snapshot.dirty_digest,
                protected_changes_present: snapshot.protected_changes_present,
                languages: vec!["typescript".to_owned()],
            },
            policy,
            role: capability("role.implementer", 'a'),
            skills: vec![capability("skill.focused-edit", 'b')],
            tools: vec![capability("tool.patch", 'c'), capability("tool.read", 'd')],
            write_tool_id: "tool.patch".to_owned(),
            read_tool_id: "tool.read".to_owned(),
            diff_evaluator: "builtin.diff.scope_and_literal.v1".to_owned(),
            rollback_diff_evaluator: "builtin.diff.controller_patch_absent.v1".to_owned(),
            context_packet: packet,
            m3: None,
            max_model_calls: 2,
            model_input_token_ceiling: 8_192,
            max_output_tokens: 768,
            model_deadline_ms: 180_000,
        },
        selected_tokens,
    )
}

fn free_port() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap_or_else(|error| panic!("bind free port: {error}"));
    listener
        .local_addr()
        .unwrap_or_else(|error| panic!("read free port: {error}"))
        .port()
}

fn required_env(name: &str) -> PathBuf {
    std::env::var_os(name).map_or_else(
        || panic!("missing required environment {name}"),
        PathBuf::from,
    )
}

fn host_observation() -> Value {
    fn command(program: &str, args: &[&str]) -> String {
        Command::new(program).args(args).output().map_or_else(
            |error| format!("unavailable: {error}"),
            |output| String::from_utf8_lossy(&output.stdout).trim().to_owned(),
        )
    }
    json!({
        "swapusage": command("/usr/sbin/sysctl", &["vm.swapusage"]),
        "memory_pressure": command("/usr/bin/memory_pressure", &[]),
        "vm_stat": command("/usr/bin/vm_stat", &[]),
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

#[test]
#[ignore = "requires the local Qwen4B GGUF and managed llama.cpp runtime"]
fn compiler_real_local_8k_smoke() {
    let runtime = required_env("SOVEREIGN_MODEL_RUNTIME");
    let model_path = required_env("SOVEREIGN_MODEL_PATH");
    let fixture = FixtureRepo::create();
    let (input, selected_tokens) = build_input(&fixture.0);
    let host_before = host_observation();

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
        extra_args: Vec::new(),
    });
    let backend = CapturingBackend::new(
        LocalOpenAiBackend::new(config)
            .unwrap_or_else(|error| panic!("construct local backend: {error}")),
    );
    let lease = backend
        .load(ModelLoadProfile {
            context_tokens: 8_192,
            output_reserve_tokens: 1_536,
            startup_timeout_ms: 180_000,
            provider_call_timeout_ms: 180_000,
        })
        .unwrap_or_else(|error| panic!("load local Qwen: {error}"));
    let validator = PlanValidator::new(ValidationEnvironment::default())
        .unwrap_or_else(|error| panic!("construct validator: {error}"));
    let compiler = PlanCompiler::new(&backend, &validator, "m1-real-compiler-v1")
        .unwrap_or_else(|error| panic!("construct compiler: {error}"));
    let mut budget = ModelCallBudget::new(2, 360_000);
    let result = compiler
        .compile(&input, &mut budget)
        .unwrap_or_else(|error| panic!("real local compile: {error}"));
    let (request, response) = backend.captured();
    let admission = backend
        .inner
        .token_admission(&request)
        .unwrap_or_else(|error| panic!("measure exact rendered admission: {error}"));
    assert!(validator.validate(result.plan()).is_empty());
    assert!(admission.admitted_input_tokens <= 8_192);
    assert_eq!(
        u64::from(admission.rendered_input_tokens),
        response.usage.input_tokens
    );
    assert_eq!(
        admission.admitted_input_tokens,
        admission
            .rendered_input_tokens
            .saturating_add(admission.structured_output_tokens)
    );
    backend
        .unload()
        .unwrap_or_else(|error| panic!("unload local Qwen: {error}"));
    let host_after = host_observation();
    let process_absent_after_unload = process_absent(lease.process_id);
    assert!(process_absent_after_unload);
    let report = json!({
        "schema": "sovereign-m1-t10-real-compiler-smoke-v1",
        "context_packet_selected_tokens": selected_tokens,
        "request_token_admission": admission,
        "provider_usage": response.usage,
        "elapsed_ms": response.elapsed_ms,
        "startup_peak_rss_kb": lease.startup_peak_rss_kb,
        "post_load_steady_rss_kb": lease.post_load_rss_kb,
        "prefill_decode_peak_rss_kb": response.peak_rss_kb_during_call,
        "plan_digest": result.plan_digest(),
        "compilation_evidence_digest": result.compilation_evidence_digest(),
        "validator_passed": result.compilation_evidence().validator_passed(),
        "model_calls_used": 2_u32.saturating_sub(budget.remaining_calls()),
        "server_context_tokens": lease.server_context_tokens,
        "process_absent_after_unload": process_absent_after_unload,
        "host_before": host_before,
        "host_after": host_after,
    });
    if let Some(path) = std::env::var_os("SOVEREIGN_T10_SMOKE_REPORT") {
        fs::write(
            PathBuf::from(path),
            serde_json::to_vec_pretty(&report)
                .unwrap_or_else(|error| panic!("serialize smoke report file: {error}")),
        )
        .unwrap_or_else(|error| panic!("write smoke report: {error}"));
    }
    println!(
        "SOVEREIGN_T10_SMOKE_JSON={}",
        serde_json::to_string(&report)
            .unwrap_or_else(|error| panic!("serialize smoke report: {error}"))
    );
}
