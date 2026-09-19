use serde_json::{Value, json};
use sovereign_context::{
    ContextBudget, ContextMode, ContextPacket, ContextPacketInput, ContextPlanner, EvidenceItem,
};
use sovereign_controller::{
    Controller, ExecutionRuntime, REPOSITORY_PROPOSAL_SCHEMA_VERSION, ReadinessInputs,
    RecoveryManager, RepositoryActionV1, RepositoryProposalV1, ResourcePressureProbe, RoleId,
    RoleRegistry, TaskState,
};
use sovereign_evidence::ArtifactStore;
use sovereign_model::{
    BackendHealth, DeterministicFakeBackend, MODEL_SCHEMA_VERSION, ModelBackend, ModelCapabilities,
    ModelError, ModelFinishReason, ModelLease, ModelLoadProfile, ModelRequest, ModelResponse,
    ModelUsage,
};
use sovereign_plan::{
    DepthClassifier, DepthFeatureInput, ExecutionDepth, M3PlanningInput,
    PLAN_COMPILATION_SCHEMA_VERSION, PlanCompilationInput, PlanCompilationRepository,
    PlanCompilationResult, PlanCompiler, PlanIr, PlanValidator, ValidationEnvironment,
};
use sovereign_policy::{
    CommandPolicy, CommandRisk, IsolationRequest, MacSandboxExecBackend, ModelCallBudget,
    OsMemoryPressure, PinnedExecutable, RESOURCE_PRESSURE_EVENT_SCHEMA_VERSION,
    ReconciliationPolicy, ResourcePressureSnapshotV1, ThermalPressure,
};
use sovereign_repo::{ExactRetriever, ProjectRegistry, RepositoryIntelligence, RepositorySnapshot};
use sovereign_state::StateStore;
use sovereign_tools::{PermissionClass, ToolManifest};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static SEQUENCE: AtomicU64 = AtomicU64::new(1);

const WRITE_TOOL_DIGEST: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const READ_TOOL_DIGEST: &str =
    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[derive(Clone)]
struct FixedPressureProbe(ResourcePressureSnapshotV1);

impl ResourcePressureProbe for FixedPressureProbe {
    fn sample(&mut self) -> io::Result<ResourcePressureSnapshotV1> {
        Ok(self.0)
    }
}

struct Fixture {
    base: PathBuf,
    state_path: PathBuf,
    registry: ProjectRegistry,
    snapshots: BTreeMap<String, RepositorySnapshot>,
}

impl Fixture {
    fn create(label: &str) -> Self {
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let home = std::env::var_os("HOME").map_or_else(
            || panic!("HOME must be set for the macOS Seatbelt cross-repo fixture"),
            PathBuf::from,
        );
        let base = home.join(format!(
            ".sovereign-eval-cross-repo-{label}-{}-{nanos}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&base).unwrap_or_else(|error| panic!("create fixture root: {error}"));

        let repositories = [
            (
                "repo.auth",
                "auth",
                "src/auth.rs",
                "pub fn issue_token() {}\n",
            ),
            (
                "repo.gateway",
                "gateway",
                "src/gateway.rs",
                "pub fn authenticate() {}\n",
            ),
            (
                "repo.service-a",
                "service-a",
                "src/auth.rs",
                "pub fn authorize_a() {}\n",
            ),
            (
                "repo.service-b",
                "service-b",
                "src/auth.rs",
                "pub fn authorize_b() {}\n",
            ),
            (
                "repo.web",
                "web",
                "src/auth.ts",
                "export function login() {}\n",
            ),
        ];

        let mut registry = ProjectRegistry::new();
        for (repository_id, directory, relative_path, content) in repositories {
            let root = base.join(directory);
            let path = root.join(relative_path);
            fs::create_dir_all(
                path.parent()
                    .unwrap_or_else(|| panic!("fixture source must have parent")),
            )
            .unwrap_or_else(|error| panic!("create {repository_id} source parent: {error}"));
            fs::write(&path, content)
                .unwrap_or_else(|error| panic!("write {repository_id} source: {error}"));
            git(&root, &["init", "-q"]);
            git(
                &root,
                &[
                    "config",
                    "user.email",
                    "sovereign-cross-repo@example.invalid",
                ],
            );
            git(&root, &["config", "user.name", "Sovereign Cross Repo"]);
            git(&root, &["add", "."]);
            git(&root, &["commit", "-qm", "fixture baseline"]);
            registry
                .register(repository_id, &root)
                .unwrap_or_else(|error| panic!("register {repository_id}: {error}"));
        }

        let snapshots = [
            "repo.auth",
            "repo.gateway",
            "repo.service-a",
            "repo.service-b",
            "repo.web",
        ]
        .into_iter()
        .map(|repository_id| {
            let snapshot = registry
                .snapshot(repository_id)
                .unwrap_or_else(|error| panic!("snapshot {repository_id}: {error}"));
            (repository_id.to_owned(), snapshot)
        })
        .collect();

        Self {
            state_path: base.join("state.sqlite3"),
            base,
            registry,
            snapshots,
        }
    }

    fn snapshot(&self, repository_id: &str) -> &RepositorySnapshot {
        self.snapshots
            .get(repository_id)
            .unwrap_or_else(|| panic!("missing fixture snapshot {repository_id}"))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
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

fn sha(character: char) -> String {
    format!("sha256:{}", character.to_string().repeat(64))
}

fn pinned(id: &str, digest: &str) -> Value {
    json!({"id": id, "version": "1.0.0", "digest": digest})
}

fn policy_fixture() -> Value {
    let mut policy: Value = serde_json::from_str(include_str!("fixtures/scenario1/policy.json"))
        .unwrap_or_else(|error| panic!("parse policy fixture: {error}"));
    policy["retry"]["max_tasks_per_revision"] = json!(12);
    policy["resources"]["heavy_leases"] = json!(["MODEL", "BUILD_HEAVY"]);
    policy
}

fn canonical_role() -> Value {
    let pin = RoleRegistry::canonical()
        .canonical_pin(RoleId::Implementer)
        .unwrap_or_else(|error| panic!("canonical implementer pin: {error}"));
    json!({"id": pin.id, "version": pin.version, "digest": pin.digest})
}

fn repository_input(snapshot: &RepositorySnapshot, language: &str) -> PlanCompilationRepository {
    PlanCompilationRepository {
        repository_id: snapshot.repository_id.clone(),
        root: snapshot.root.display().to_string(),
        head: snapshot.head.clone(),
        branch: snapshot.branch.clone(),
        dirty_digest: snapshot.dirty_digest.clone(),
        protected_changes_present: snapshot.protected_changes_present,
        languages: vec![language.to_owned()],
    }
}

fn exact_source(fixture: &Fixture, repository_id: &str, path: &str) -> EvidenceItem {
    let evidence = ExactRetriever::new(&fixture.registry)
        .read_path(repository_id, Path::new(path), None)
        .unwrap_or_else(|error| panic!("read exact {repository_id}/{path}: {error}"));
    EvidenceItem::from_exact_file(&evidence, "M8 cross-repository exact source")
}

fn context_packet(fixture: &Fixture, multi_repo: bool) -> ContextPacket {
    let mut candidates = vec![exact_source(fixture, "repo.auth", "src/auth.rs")];
    if multi_repo {
        candidates.extend([
            exact_source(fixture, "repo.gateway", "src/gateway.rs"),
            exact_source(fixture, "repo.service-a", "src/auth.rs"),
            exact_source(fixture, "repo.service-b", "src/auth.rs"),
            exact_source(fixture, "repo.web", "src/auth.ts"),
        ]);
    }
    ContextPlanner::default()
        .build(
            ContextMode::Implementation,
            ContextBudget::m1_8k(),
            ContextPacketInput {
                controller_prefix: "Controller owns cross-repository execution authority."
                    .to_owned(),
                task_contract: "Execute the bounded authentication migration safely.".to_owned(),
                current_state: "registered repository baselines are current".to_owned(),
                authorized_tool_schemas: Vec::new(),
                candidates,
                output_schema: "m8-cross-repo-plan-proposal-v1".to_owned(),
            },
        )
        .unwrap_or_else(|error| panic!("context packet: {error}"))
}

fn depth_d4() -> sovereign_plan::DepthDecision {
    let mut decision = DepthClassifier.classify(&DepthFeatureInput {
        repository_count: 5,
        authentication_or_authorization: true,
        schema_or_data_migration: true,
        public_api_or_protocol: true,
        rollback_available: true,
        ..DepthFeatureInput::default()
    });
    assert_eq!(decision.mode, ExecutionDepth::D4);
    "m8-cross-repo-regression".clone_into(&mut decision.reason);
    decision
}

fn compilation_input(fixture: &Fixture, multi_repo: bool) -> PlanCompilationInput {
    let packet = context_packet(fixture, multi_repo);
    let auth = repository_input(fixture.snapshot("repo.auth"), "rust");
    let (workspace_roots, m3) = if multi_repo {
        let additional_repositories = vec![
            repository_input(fixture.snapshot("repo.gateway"), "rust"),
            repository_input(fixture.snapshot("repo.service-a"), "rust"),
            repository_input(fixture.snapshot("repo.service-b"), "rust"),
            repository_input(fixture.snapshot("repo.web"), "typescript"),
        ];
        let roots = std::iter::once(auth.root.clone())
            .chain(
                additional_repositories
                    .iter()
                    .map(|repository| repository.root.clone()),
            )
            .collect();
        (
            roots,
            Some(M3PlanningInput {
                depth: depth_d4(),
                supplied_sources: Vec::new(),
                additional_repositories,
                manual_gates: Vec::new(),
                absence_evaluator: None,
                replan: None,
            }),
        )
    } else {
        (vec![auth.root.clone()], None)
    };
    PlanCompilationInput {
        schema_version: PLAN_COMPILATION_SCHEMA_VERSION,
        compilation_id: if multi_repo {
            "compile.m8.cross-repo".to_owned()
        } else {
            "compile.m8.single-repo-recovery".to_owned()
        },
        compiled_at: "2026-09-19T03:30:00Z".to_owned(),
        project_id: "prj.m8-cross-repo".to_owned(),
        project_name: "M8 cross-repository eval".to_owned(),
        workspace_roots,
        goal_id: "goal.m8-cross-repo".to_owned(),
        goal_statement: "Migrate authentication to JWT while preserving compatibility.".to_owned(),
        goal_invariants: vec!["Compatibility remains available until its gate passes.".to_owned()],
        goal_non_goals: vec!["No network or external side effects.".to_owned()],
        repository: auth,
        policy: policy_fixture(),
        role: canonical_role(),
        skills: vec![pinned("skill.cross-repo", &sha('8'))],
        tools: vec![
            pinned("tool.patch", WRITE_TOOL_DIGEST),
            pinned("tool.read", READ_TOOL_DIGEST),
        ],
        write_tool_id: "tool.patch".to_owned(),
        read_tool_id: "tool.read".to_owned(),
        diff_evaluator: "builtin.diff.scoped_change.v1".to_owned(),
        rollback_diff_evaluator: "builtin.diff.controller_patch_absent.v1".to_owned(),
        context_packet: packet,
        m3,
        max_model_calls: 2,
        model_input_token_ceiling: 8_000,
        max_output_tokens: 1_024,
        model_deadline_ms: 1_000,
    }
}

fn task(local_id: &str, repository_id: &str, file: &str, dependencies: &[&str]) -> Value {
    json!({
        "local_id": local_id,
        "repository_id": repository_id,
        "title": format!("Implement {local_id}"),
        "objective": format!("Complete bounded work for {local_id}."),
        "rationale": "The bounded migration contract requires this task.",
        "files": [file],
        "symbols": [local_id],
        "dependencies": dependencies,
        "evidence_needs": [],
        "expected_change": format!("Required output for {local_id}"),
        "acceptance": [{
            "kind": "diff",
            "description": format!("Scoped diff for {local_id} is accepted."),
            "manual_gate_id": Value::Null
        }]
    })
}

fn single_repo_task() -> Value {
    json!({
        "title": "Single repository recovery task",
        "objective": "Exercise durable restart recovery on the exact auth repository baseline.",
        "rationale": "M8 checkpoint migration must preserve the established one-repository case.",
        "files": ["src/auth.rs"],
        "symbols": ["issue_token"],
        "evidence_queries": [],
        "expected_change": "Bounded auth fixture update"
    })
}

fn integration_gate_task(local_id: &str, dependencies: &[&str]) -> Value {
    json!({
        "local_id": local_id,
        "repository_id": "repo.auth",
        "integration_repository_ids": [
            "repo.auth", "repo.gateway", "repo.service-a", "repo.service-b", "repo.web"
        ],
        "title": "A7 cross-repo integration security gate",
        "objective": "Verify compatibility across all five current repository views.",
        "rationale": "Legacy removal requires fresh cross-repository integration evidence.",
        "files": [],
        "symbols": [],
        "dependencies": dependencies,
        "evidence_needs": [],
        "expected_change": "Fresh cross-repository integration and security evidence",
        "acceptance": [{
            "kind": "command",
            "description": "The bounded integration command passes.",
            "manual_gate_id": Value::Null,
            "command_spec": {
                "tool_id": "tool.read",
                "mode": "exec",
                "program": "true",
                "args": [],
                "repository_id": "repo.auth",
                "working_dir_relative": ".",
                "literal_env": {},
                "secret_env": {},
                "timeout_seconds": 30,
                "output_limit_bytes": 4096
            },
            "expected_exit_codes": [0]
        }]
    })
}

fn migration_proposal() -> Value {
    let mut a2 = task("node.A2", "repo.auth", "src/auth.rs", &["node.A1"]);
    a2["title"] = json!("A2 auth dual issuance");
    let mut a3 = task("node.A3", "repo.gateway", "src/gateway.rs", &["node.A2"]);
    a3["title"] = json!("A3 gateway dual acceptance");
    let mut a4 = task("node.A4", "repo.service-a", "src/auth.rs", &["node.A3"]);
    a4["title"] = json!("A4 service-a dual acceptance");
    let mut a5 = task("node.A5", "repo.service-b", "src/auth.rs", &["node.A3"]);
    a5["title"] = json!("A5 service-b dual acceptance");
    let mut a6 = task("node.A6", "repo.web", "src/auth.ts", &["node.A3"]);
    a6["title"] = json!("A6 web JWT-compatible flow");
    let mut a8 = task("node.A8", "repo.auth", "src/auth.rs", &["node.A7"]);
    a8["title"] = json!("A8 disable legacy issuance");
    let mut a9 = task("node.A9", "repo.auth", "src/auth.rs", &["node.A8"]);
    a9["title"] = json!("A9 remove legacy acceptance");
    json!({
        "tasks": [
            {
                "local_id": "node.A1",
                "repository_id": "repo.auth",
                "title": "A1 JWT compatibility contract",
                "objective": "Pin claims, key rotation, compatibility and rollback invariants.",
                "rationale": "Every rollout mutation consumes this compatibility contract.",
                "files": [],
                "symbols": [],
                "dependencies": [],
                "evidence_needs": [],
                "expected_change": "Signed JWT compatibility contract",
                "acceptance": [{
                    "kind": "artifact",
                    "description": "The compatibility contract artifact is present.",
                    "manual_gate_id": Value::Null
                }]
            },
            a2,
            a3,
            a4,
            a5,
            a6,
            integration_gate_task("node.A7", &["node.A4", "node.A5", "node.A6"]),
            a8,
            a9
        ]
    })
}

fn two_repo_integration_proposal() -> Value {
    let mut producer = task("node.P", "repo.gateway", "src/gateway.rs", &[]);
    producer["title"] = json!("Gateway producer change");
    let mut gate = integration_gate_task("node.A7", &["node.P"]);
    gate["integration_repository_ids"] = json!(["repo.auth", "repo.gateway"]);
    gate["acceptance"][0]["command_spec"]["program"] = json!("make");
    gate["acceptance"][0]["command_spec"]["args"] = json!(["--version"]);
    let mut consumer = task("node.A8", "repo.auth", "src/auth.rs", &["node.A7"]);
    consumer["title"] = json!("A8 checkpoint consumer");
    json!({"tasks": [producer, gate, consumer]})
}

fn response(content: &Value, input_tokens: u32) -> ModelResponse {
    ModelResponse {
        schema_version: MODEL_SCHEMA_VERSION,
        request_id: "m8-cross-repo-response".to_owned(),
        content: content.to_string(),
        structured: None,
        tool_calls: Vec::new(),
        finish_reason: ModelFinishReason::Stop,
        usage: ModelUsage {
            input_tokens: u64::from(input_tokens),
            output_tokens: 256,
        },
        elapsed_ms: 1,
        peak_rss_kb_during_call: None,
    }
}

struct OneShotBackend {
    response: Mutex<Option<ModelResponse>>,
}

impl OneShotBackend {
    fn new(content: &Value, input_tokens: u32) -> Self {
        Self {
            response: Mutex::new(Some(response(content, input_tokens))),
        }
    }
}

impl ModelBackend for OneShotBackend {
    fn capabilities(&self) -> ModelCapabilities {
        panic!("compiler must not request capabilities from one-shot eval backend")
    }

    fn load(&self, _profile: ModelLoadProfile) -> Result<ModelLease, ModelError> {
        Err(ModelError::InvalidContract("unexpected load".to_owned()))
    }

    fn complete(&self, _request: &ModelRequest) -> Result<ModelResponse, ModelError> {
        self.response
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .ok_or_else(|| ModelError::InvalidResponse("eval response exhausted".to_owned()))
    }

    fn count_tokens(&self, _content: &str) -> Result<u32, ModelError> {
        Err(ModelError::InvalidContract(
            "unexpected token count".to_owned(),
        ))
    }

    fn health(&self) -> Result<BackendHealth, ModelError> {
        Err(ModelError::InvalidContract("unexpected health".to_owned()))
    }

    fn unload(&self) -> Result<(), ModelError> {
        Err(ModelError::InvalidContract("unexpected unload".to_owned()))
    }
}

fn deterministic_execution_backend() -> DeterministicFakeBackend {
    DeterministicFakeBackend::new(
        ModelCapabilities {
            schema_version: MODEL_SCHEMA_VERSION,
            model_id: "fake-m8-execution-backend".to_owned(),
            parameter_class: "fixture".to_owned(),
            quantization: "fixture".to_owned(),
            max_context_tokens: 16_384,
            supports_tools: false,
            supports_json_schema: true,
            local: true,
        },
        Vec::new(),
    )
    .unwrap_or_else(|error| panic!("create M8 execution backend: {error}"))
}

fn compile(fixture: &Fixture, multi_repo: bool, proposal: &Value) -> PlanCompilationResult {
    let input = compilation_input(fixture, multi_repo);
    let backend = OneShotBackend::new(
        proposal,
        input.context_packet.metrics.final_serialized_input_tokens,
    );
    let validator = PlanValidator::new(ValidationEnvironment::default())
        .unwrap_or_else(|error| panic!("validator: {error}"));
    let compiler = PlanCompiler::new(&backend, &validator, "m8-cross-repo-eval-v1")
        .unwrap_or_else(|error| panic!("compiler: {error}"));
    let mut budget = ModelCallBudget::new(1, 1_000);
    let result = compiler
        .compile(&input, &mut budget)
        .unwrap_or_else(|error| panic!("compile M8 eval proposal: {error}"));
    assert!(validator.is_valid(result.plan()));
    result
}

fn task_id_with_title(compilation: &PlanCompilationResult, title: &str) -> String {
    compilation.plan().as_value()["tasks"]
        .as_array()
        .unwrap_or_else(|| panic!("compiled tasks"))
        .iter()
        .find(|task| task["title"].as_str() == Some(title))
        .and_then(|task| task["task_id"].as_str())
        .unwrap_or_else(|| panic!("compiled task titled {title}"))
        .to_owned()
}

fn execution_requirement_ids(compilation: &PlanCompilationResult, title: &str) -> Vec<String> {
    compilation.plan().as_value()["tasks"]
        .as_array()
        .unwrap_or_else(|| panic!("compiled tasks"))
        .iter()
        .find(|task| task["title"].as_str() == Some(title))
        .unwrap_or_else(|| panic!("compiled task titled {title}"))["evidence_requirements"]
        .as_array()
        .unwrap_or_else(|| panic!("evidence requirements for {title}"))
        .iter()
        .filter(|requirement| requirement["required_before"].as_str() == Some("execution"))
        .map(|requirement| {
            requirement["requirement_id"]
                .as_str()
                .unwrap_or_else(|| panic!("requirement id for {title}"))
                .to_owned()
        })
        .collect()
}

fn write_tool_manifest() -> ToolManifest {
    ToolManifest {
        tool_id: "tool.patch".to_owned(),
        version: "1.0.0".to_owned(),
        content_digest: WRITE_TOOL_DIGEST.to_owned(),
        permission_ceiling: BTreeSet::from([
            PermissionClass::Read,
            PermissionClass::RepositoryWrite,
            PermissionClass::ProcessExec,
        ]),
        declared_risk_floor: CommandRisk::RepositoryMutation,
        reconciliation_policy: ReconciliationPolicy::proof_required_local(),
    }
}

fn read_tool_manifest() -> ToolManifest {
    ToolManifest {
        tool_id: "tool.read".to_owned(),
        version: "1.0.0".to_owned(),
        content_digest: READ_TOOL_DIGEST.to_owned(),
        permission_ceiling: BTreeSet::from([PermissionClass::Read, PermissionClass::ProcessExec]),
        declared_risk_floor: CommandRisk::ReadOnly,
        reconciliation_policy: ReconciliationPolicy::proof_required_local(),
    }
}

fn green_snapshot(observed_at_ms: i64) -> ResourcePressureSnapshotV1 {
    ResourcePressureSnapshotV1 {
        schema_version: RESOURCE_PRESSURE_EVENT_SCHEMA_VERSION,
        observed_at_ms,
        controlled_working_set_mib: 512,
        host_headroom_mib: 6_144,
        swap_used_mib: Some(0),
        swap_out_growth_mib_per_min: 0,
        compressor_growth_mib_per_min: 0,
        os_memory_pressure: OsMemoryPressure::Normal,
        recent_pressure_event: false,
        thermal_pressure: ThermalPressure::Normal,
        allocation_failure: false,
        repeated_resource_kill: false,
        uncontrolled_child_growth: false,
        host_free_disk_mib: Some(64 * 1_024),
    }
}

#[test]
fn backward_compatible_migration_order_and_producer_contract_drift_are_bound() {
    let fixture = Fixture::create("migration-contracts");
    let compilation = compile(&fixture, true, &migration_proposal());
    let tasks = compilation.plan().as_value()["tasks"]
        .as_array()
        .unwrap_or_else(|| panic!("migration tasks"));
    assert_eq!(
        tasks
            .iter()
            .map(|task| task["title"].as_str().unwrap_or_default())
            .collect::<Vec<_>>(),
        vec![
            "A1 JWT compatibility contract",
            "A2 auth dual issuance",
            "A3 gateway dual acceptance",
            "A4 service-a dual acceptance",
            "A5 service-b dual acceptance",
            "A6 web JWT-compatible flow",
            "A7 cross-repo integration security gate",
            "A8 disable legacy issuance",
            "A9 remove legacy acceptance",
        ]
    );
    assert_eq!(tasks[6]["permissions"], json!(["read", "process_exec"]));
    assert_eq!(tasks[6]["action_policy"]["write_roots"], json!([]));
    assert_eq!(
        tasks[6]["dependency_bindings"].as_array().map(Vec::len),
        Some(3)
    );

    let validator = PlanValidator::new(ValidationEnvironment::default())
        .unwrap_or_else(|error| panic!("validator: {error}"));
    let contracts = compilation
        .cross_repo_contracts()
        .unwrap_or_else(|error| panic!("derive cross-repo contracts: {error}"));
    assert_eq!(contracts.len(), 8);
    let producer_id = tasks[2]["task_id"]
        .as_str()
        .unwrap_or_else(|| panic!("A3 task id"));
    let before = contracts
        .iter()
        .find(|contract| contract.producer_task_id == producer_id)
        .unwrap_or_else(|| panic!("A3 producer contract"))
        .contract_digest
        .clone();

    let mut revision_only = compilation.plan().as_value().clone();
    revision_only["revision"] = json!(2);
    revision_only["supersedes_revision"] = json!(1);
    let revision_only = PlanIr::from_value(revision_only);
    assert_eq!(
        contracts,
        validator
            .cross_repo_contracts(&revision_only)
            .unwrap_or_else(|error| panic!("derive revision-only contracts: {error}")),
        "revision numbering alone must not invalidate immutable interface contracts"
    );

    let mut changed = compilation.plan().as_value().clone();
    changed["tasks"][2]["implementation_contract"]["outputs"][0] =
        json!("Changed gateway compatibility interface");
    let changed = PlanIr::from_value(changed);
    let changed_contracts = validator
        .cross_repo_contracts(&changed)
        .unwrap_or_else(|error| panic!("derive drifted contracts: {error}"));
    let after = changed_contracts
        .iter()
        .find(|contract| contract.producer_task_id == producer_id)
        .unwrap_or_else(|| panic!("drifted A3 producer contract"))
        .contract_digest
        .clone();
    assert_ne!(
        before, after,
        "producer interface drift must invalidate its contract digest"
    );
}

#[test]
fn one_repo_restart_recovers_from_the_current_checkpoint_without_replaying_work() {
    let fixture = Fixture::create("one-repo-restart");
    let proposal = json!({"tasks": [single_repo_task()]});
    let compilation = compile(&fixture, false, &proposal);
    let task_id = task_id_with_title(&compilation, "Single repository recovery task");
    let state = StateStore::open(&fixture.state_path)
        .unwrap_or_else(|error| panic!("open activation state: {error}"));
    let mut controller = Controller::new(state);
    let activated = controller
        .activate(compilation, &fixture.registry)
        .unwrap_or_else(|error| panic!("activate one-repo plan: {error}"));
    assert_eq!(controller.task_state(&task_id), Some(TaskState::Planned));
    let epoch_before = activated.execution_epoch;
    drop(controller);

    let reopened = StateStore::open(&fixture.state_path)
        .unwrap_or_else(|error| panic!("reopen recovery state: {error}"));
    let (recovered, summary) = RecoveryManager::recover(reopened, &fixture.registry)
        .unwrap_or_else(|error| panic!("recover one-repo plan: {error}"));
    assert_eq!(recovered.task_state(&task_id), Some(TaskState::Planned));
    assert!(!summary.mutation_blocked);
    assert!(summary.execution_epoch_after > epoch_before);
    assert!(summary.unknown_action_ids.is_empty());
    assert!(summary.pending_recovery_action_ids.is_empty());
}

#[test]
fn integration_gate_is_read_process_only_and_materializes_multi_repo_views_before_readiness() {
    let fixture = Fixture::create("integration-gate");
    let compilation = compile(&fixture, true, &migration_proposal());
    let gate_id = task_id_with_title(&compilation, "A7 cross-repo integration security gate");
    let state = StateStore::open(&fixture.state_path)
        .unwrap_or_else(|error| panic!("open integration state: {error}"));
    let mut controller = Controller::new(state);
    controller
        .activate(compilation, &fixture.registry)
        .unwrap_or_else(|error| panic!("activate integration plan: {error}"));
    controller.set_resource_pressure_probe(Box::new(FixedPressureProbe(green_snapshot(10_000))));

    let Err(error) = controller.derive_integration_gate_lease(
        &fixture.registry,
        &gate_id,
        ReadinessInputs::permissive_m1("sha256:m8-integration-gate"),
        &read_tool_manifest(),
    ) else {
        panic!("A7 unexpectedly became ready before its hard dependencies succeeded");
    };
    assert!(
        error
            .to_string()
            .contains("hard dependencies are not succeeded"),
        "A7 must reach the Controller dependency gate through its multi-repository integration path: {error}"
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn integration_gate_executes_read_only_publishes_checkpoint_and_unblocks_consumer() {
    let fixture = Fixture::create("integration-execution");
    let compilation = compile(&fixture, true, &two_repo_integration_proposal());
    let producer_id = task_id_with_title(&compilation, "Gateway producer change");
    let gate_id = task_id_with_title(&compilation, "A7 cross-repo integration security gate");
    let consumer_id = task_id_with_title(&compilation, "A8 checkpoint consumer");
    let producer_requirements = execution_requirement_ids(&compilation, "Gateway producer change");
    let consumer_requirements = execution_requirement_ids(&compilation, "A8 checkpoint consumer");
    let context = context_packet(&fixture, true);

    let state = StateStore::open(&fixture.state_path)
        .unwrap_or_else(|error| panic!("open integration execution state: {error}"));
    let artifacts = ArtifactStore::open(fixture.base.join("cas-integration-execution"))
        .unwrap_or_else(|error| panic!("open integration execution artifacts: {error}"));
    let mut controller = Controller::new(state);
    controller
        .activate(compilation, &fixture.registry)
        .unwrap_or_else(|error| panic!("activate integration execution plan: {error}"));
    controller.set_resource_pressure_probe(Box::new(FixedPressureProbe(green_snapshot(30_000))));

    for requirement_id in producer_requirements {
        controller
            .record_exact_evidence_satisfaction(
                &fixture.registry,
                &producer_id,
                &requirement_id,
                &context,
                &["file:repo.gateway:src/gateway.rs".to_owned()],
            )
            .unwrap_or_else(|error| panic!("satisfy producer evidence: {error}"));
    }

    let executable = PinnedExecutable::from_path("/usr/bin/make", "macos-system-make")
        .unwrap_or_else(|error| panic!("pin integration executable: {error}"));
    let toolchain_root = executable
        .path
        .parent()
        .unwrap_or_else(|| panic!("integration executable parent"))
        .to_path_buf();
    let command_policy = CommandPolicy::new([executable], [toolchain_root])
        .unwrap_or_else(|error| panic!("integration command policy: {error}"));
    let isolation_backend = MacSandboxExecBackend::detect()
        .unwrap_or_else(|error| panic!("detect integration isolation: {error}"));
    let home = std::env::var_os("HOME").map_or_else(
        || panic!("HOME must be set for integration isolation"),
        PathBuf::from,
    );
    let isolation_request = IsolationRequest {
        repository_root: fixture.snapshot("repo.auth").root.clone(),
        user_home_root: home,
        extra_protected_read_roots: Vec::new(),
        network_offline: true,
        allow_repository_write: true,
        require_full_filesystem_read_jail: false,
    };
    let backend = deterministic_execution_backend();
    let write_manifest = write_tool_manifest();
    let producer_ready = controller
        .derive_ready_lease(
            &fixture.registry,
            &producer_id,
            ReadinessInputs::permissive_m1("sha256:m8-producer-ready"),
            &write_manifest,
        )
        .unwrap_or_else(|error| panic!("derive producer ready lease: {error}"));
    let gateway_evidence = context
        .items
        .iter()
        .find(|item| item.evidence_id == "file:repo.gateway:src/gateway.rs")
        .unwrap_or_else(|| panic!("gateway exact source evidence"));
    let gateway_source =
        fs::read_to_string(fixture.snapshot("repo.gateway").root.join("src/gateway.rs"))
            .unwrap_or_else(|error| panic!("read gateway source: {error}"));
    let repository_proposal = RepositoryProposalV1 {
        schema_version: REPOSITORY_PROPOSAL_SCHEMA_VERSION,
        evidence_ids: vec![gateway_evidence.evidence_id.clone()],
        action: RepositoryActionV1::UpdateFile {
            repository_id: "repo.gateway".to_owned(),
            path: "src/gateway.rs".to_owned(),
            expected_source_digest: gateway_evidence.source_digest.clone(),
            content: format!("{gateway_source}// M8 producer change\n"),
        },
    };
    let write_runtime = ExecutionRuntime {
        registry: &fixture.registry,
        backend: &backend,
        command_policy: &command_policy,
        isolation_backend: &isolation_backend,
        isolation_request: &isolation_request,
        artifacts: &artifacts,
        tool_manifest: &write_manifest,
        python_executable: Path::new("/usr/bin/python3"),
    };
    let producer_success = controller
        .execute_repository_proposal(
            producer_ready,
            &write_runtime,
            &context,
            repository_proposal,
        )
        .unwrap_or_else(|error| panic!("execute producer mutation: {error}"));
    assert!(producer_success.verification.passed);
    assert_eq!(
        controller.task_state(&producer_id),
        Some(TaskState::Succeeded)
    );
    assert!(controller.task_change_set(&producer_id).is_some());

    let read_manifest = read_tool_manifest();
    let gate_lease = controller
        .derive_integration_gate_lease(
            &fixture.registry,
            &gate_id,
            ReadinessInputs::permissive_m1("sha256:m8-integration-execution"),
            &read_manifest,
        )
        .unwrap_or_else(|error| panic!("derive A7 integration lease: {error}"));
    assert_eq!(gate_lease.task_id(), gate_id);
    assert!(controller.task_worktree_lease(&gate_id).is_none());
    assert!(controller.task_change_set(&gate_id).is_none());
    assert_eq!(controller.task_model_calls_used(&gate_id), Some(0));

    let read_isolation_request = IsolationRequest {
        repository_root: fixture.snapshot("repo.auth").root.clone(),
        user_home_root: isolation_request.user_home_root.clone(),
        extra_protected_read_roots: Vec::new(),
        network_offline: true,
        allow_repository_write: false,
        require_full_filesystem_read_jail: false,
    };
    let read_runtime = ExecutionRuntime {
        registry: &fixture.registry,
        backend: &backend,
        command_policy: &command_policy,
        isolation_backend: &isolation_backend,
        isolation_request: &read_isolation_request,
        artifacts: &artifacts,
        tool_manifest: &read_manifest,
        python_executable: Path::new("/usr/bin/python3"),
    };
    let gate_success = controller
        .execute_integration_gate(gate_lease, &read_runtime)
        .unwrap_or_else(|error| panic!("execute A7 integration gate: {error}"));
    assert!(gate_success.verification.passed);
    assert_eq!(gate_success.checkpoint.gate_task_id, gate_id);
    assert_eq!(controller.task_state(&gate_id), Some(TaskState::Succeeded));
    assert!(controller.task_worktree_lease(&gate_id).is_none());
    assert!(controller.task_change_set(&gate_id).is_none());
    assert!(
        controller
            .resource_snapshot()
            .unwrap_or_else(|error| panic!("resource snapshot after A7: {error}"))
            .model_residency
            .is_none()
    );
    assert_eq!(
        controller
            .state()
            .state_records("controller.integration_checkpoint")
            .unwrap_or_else(|error| panic!("read durable integration checkpoints: {error}"))
            .len(),
        1
    );

    for requirement_id in consumer_requirements {
        controller
            .record_exact_evidence_satisfaction(
                &fixture.registry,
                &consumer_id,
                &requirement_id,
                &context,
                &["file:repo.auth:src/auth.rs".to_owned()],
            )
            .unwrap_or_else(|error| panic!("satisfy A8 evidence: {error}"));
    }
    let consumer_ready = controller
        .derive_ready_lease(
            &fixture.registry,
            &consumer_id,
            ReadinessInputs::permissive_m1("sha256:m8-a8-ready"),
            &write_manifest,
        )
        .unwrap_or_else(|error| panic!("A8 must consume the current A7 checkpoint: {error}"));
    controller
        .cancel_ready_lease(consumer_ready)
        .unwrap_or_else(|error| panic!("cancel A8 proof lease: {error}"));

    drop(controller);
    let reopened = StateStore::open(&fixture.state_path)
        .unwrap_or_else(|error| panic!("reopen integration execution state: {error}"));
    let (mut recovered, summary) = RecoveryManager::recover(reopened, &fixture.registry)
        .unwrap_or_else(|error| panic!("recover integration execution plan: {error}"));
    assert!(!summary.mutation_blocked);
    assert!(summary.unknown_action_ids.is_empty());
    assert!(summary.pending_recovery_action_ids.is_empty());
    assert_eq!(recovered.task_state(&gate_id), Some(TaskState::Succeeded));
    assert!(recovered.task_worktree_lease(&gate_id).is_none());
    assert!(recovered.task_change_set(&gate_id).is_none());
    assert_eq!(
        recovered
            .state()
            .state_records("controller.integration_checkpoint")
            .unwrap_or_else(|error| panic!("read recovered integration checkpoints: {error}"))
            .len(),
        1
    );
    recovered.set_resource_pressure_probe(Box::new(FixedPressureProbe(green_snapshot(40_000))));
    let recovered_consumer_ready = recovered
        .derive_ready_lease(
            &fixture.registry,
            &consumer_id,
            ReadinessInputs::permissive_m1("sha256:m8-a8-ready-after-restart"),
            &write_manifest,
        )
        .unwrap_or_else(|error| {
            panic!("A8 must consume the recovered A7 checkpoint without rerunning A7: {error}")
        });
    recovered
        .cancel_ready_lease(recovered_consumer_ready)
        .unwrap_or_else(|error| panic!("cancel recovered A8 proof lease: {error}"));
}

#[test]
#[allow(clippy::too_many_lines)]
fn integration_gate_checkpoint_survives_recovery_and_unblocks_consumer_without_rerun() {
    let fixture = Fixture::create("integration-restart");
    let compilation = compile(&fixture, true, &two_repo_integration_proposal());
    let producer_id = task_id_with_title(&compilation, "Gateway producer change");
    let gate_id = task_id_with_title(&compilation, "A7 cross-repo integration security gate");
    let consumer_id = task_id_with_title(&compilation, "A8 checkpoint consumer");
    let producer_requirements = execution_requirement_ids(&compilation, "Gateway producer change");
    let consumer_requirements = execution_requirement_ids(&compilation, "A8 checkpoint consumer");
    let context = context_packet(&fixture, true);

    let state = StateStore::open(&fixture.state_path)
        .unwrap_or_else(|error| panic!("open integration restart state: {error}"));
    let artifacts = ArtifactStore::open(fixture.base.join("cas-integration-restart"))
        .unwrap_or_else(|error| panic!("open integration restart artifacts: {error}"));
    let mut controller = Controller::new(state);
    controller
        .activate(compilation, &fixture.registry)
        .unwrap_or_else(|error| panic!("activate integration restart plan: {error}"));
    controller.set_resource_pressure_probe(Box::new(FixedPressureProbe(green_snapshot(50_000))));

    for requirement_id in producer_requirements {
        controller
            .record_exact_evidence_satisfaction(
                &fixture.registry,
                &producer_id,
                &requirement_id,
                &context,
                &["file:repo.gateway:src/gateway.rs".to_owned()],
            )
            .unwrap_or_else(|error| panic!("satisfy restart producer evidence: {error}"));
    }

    let executable = PinnedExecutable::from_path("/usr/bin/make", "macos-system-make")
        .unwrap_or_else(|error| panic!("pin restart integration executable: {error}"));
    let toolchain_root = executable
        .path
        .parent()
        .unwrap_or_else(|| panic!("restart integration executable parent"))
        .to_path_buf();
    let command_policy = CommandPolicy::new([executable], [toolchain_root])
        .unwrap_or_else(|error| panic!("restart integration command policy: {error}"));
    let isolation_backend = MacSandboxExecBackend::detect()
        .unwrap_or_else(|error| panic!("detect restart integration isolation: {error}"));
    let home = std::env::var_os("HOME").map_or_else(
        || panic!("HOME must be set for restart integration isolation"),
        PathBuf::from,
    );
    let isolation_request = IsolationRequest {
        repository_root: fixture.snapshot("repo.auth").root.clone(),
        user_home_root: home,
        extra_protected_read_roots: Vec::new(),
        network_offline: true,
        allow_repository_write: true,
        require_full_filesystem_read_jail: false,
    };
    let backend = deterministic_execution_backend();
    let write_manifest = write_tool_manifest();
    let producer_ready = controller
        .derive_ready_lease(
            &fixture.registry,
            &producer_id,
            ReadinessInputs::permissive_m1("sha256:m8-restart-producer-ready"),
            &write_manifest,
        )
        .unwrap_or_else(|error| panic!("derive restart producer ready lease: {error}"));
    let gateway_evidence = context
        .items
        .iter()
        .find(|item| item.evidence_id == "file:repo.gateway:src/gateway.rs")
        .unwrap_or_else(|| panic!("restart gateway exact source evidence"));
    let gateway_source =
        fs::read_to_string(fixture.snapshot("repo.gateway").root.join("src/gateway.rs"))
            .unwrap_or_else(|error| panic!("read restart gateway source: {error}"));
    let repository_proposal = RepositoryProposalV1 {
        schema_version: REPOSITORY_PROPOSAL_SCHEMA_VERSION,
        evidence_ids: vec![gateway_evidence.evidence_id.clone()],
        action: RepositoryActionV1::UpdateFile {
            repository_id: "repo.gateway".to_owned(),
            path: "src/gateway.rs".to_owned(),
            expected_source_digest: gateway_evidence.source_digest.clone(),
            content: format!("{gateway_source}// M8 restart producer change\n"),
        },
    };
    let write_runtime = ExecutionRuntime {
        registry: &fixture.registry,
        backend: &backend,
        command_policy: &command_policy,
        isolation_backend: &isolation_backend,
        isolation_request: &isolation_request,
        artifacts: &artifacts,
        tool_manifest: &write_manifest,
        python_executable: Path::new("/usr/bin/python3"),
    };
    controller
        .execute_repository_proposal(
            producer_ready,
            &write_runtime,
            &context,
            repository_proposal,
        )
        .unwrap_or_else(|error| panic!("execute restart producer mutation: {error}"));
    assert_eq!(
        controller.task_state(&producer_id),
        Some(TaskState::Succeeded)
    );

    let read_manifest = read_tool_manifest();
    let gate_lease = controller
        .derive_integration_gate_lease(
            &fixture.registry,
            &gate_id,
            ReadinessInputs::permissive_m1("sha256:m8-integration-restart"),
            &read_manifest,
        )
        .unwrap_or_else(|error| panic!("derive restart A7 integration lease: {error}"));
    let read_isolation_request = IsolationRequest {
        repository_root: fixture.snapshot("repo.auth").root.clone(),
        user_home_root: isolation_request.user_home_root.clone(),
        extra_protected_read_roots: Vec::new(),
        network_offline: true,
        allow_repository_write: false,
        require_full_filesystem_read_jail: false,
    };
    let read_runtime = ExecutionRuntime {
        registry: &fixture.registry,
        backend: &backend,
        command_policy: &command_policy,
        isolation_backend: &isolation_backend,
        isolation_request: &read_isolation_request,
        artifacts: &artifacts,
        tool_manifest: &read_manifest,
        python_executable: Path::new("/usr/bin/python3"),
    };
    let gate_success = controller
        .execute_integration_gate(gate_lease, &read_runtime)
        .unwrap_or_else(|error| panic!("execute restart A7 integration gate: {error}"));
    assert!(gate_success.verification.passed);
    assert_eq!(controller.task_state(&gate_id), Some(TaskState::Succeeded));
    let checkpoint_digest = gate_success.checkpoint.checkpoint_digest.clone();
    assert_eq!(
        controller
            .state()
            .state_records("controller.integration_checkpoint")
            .unwrap_or_else(|error| panic!("read restart integration checkpoint: {error}"))
            .len(),
        1
    );

    drop(controller);
    let reopened = StateStore::open(&fixture.state_path)
        .unwrap_or_else(|error| panic!("reopen integration restart state: {error}"));
    let (mut recovered, summary) = RecoveryManager::recover(reopened, &fixture.registry)
        .unwrap_or_else(|error| panic!("recover integration restart plan: {error}"));
    assert!(!summary.mutation_blocked);
    assert!(summary.unknown_action_ids.is_empty());
    assert!(summary.pending_recovery_action_ids.is_empty());
    assert_eq!(recovered.task_state(&gate_id), Some(TaskState::Succeeded));
    let recovered_checkpoints = recovered
        .state()
        .state_records("controller.integration_checkpoint")
        .unwrap_or_else(|error| panic!("read recovered restart checkpoint: {error}"));
    assert_eq!(recovered_checkpoints.len(), 1);
    let recovered_checkpoint: Value = serde_json::from_str(&recovered_checkpoints[0].value_json)
        .unwrap_or_else(|error| panic!("decode recovered restart checkpoint: {error}"));
    assert_eq!(
        recovered_checkpoint["checkpoint_digest"].as_str(),
        Some(checkpoint_digest.as_str())
    );

    recovered.set_resource_pressure_probe(Box::new(FixedPressureProbe(green_snapshot(60_000))));
    for requirement_id in consumer_requirements {
        recovered
            .record_exact_evidence_satisfaction(
                &fixture.registry,
                &consumer_id,
                &requirement_id,
                &context,
                &["file:repo.auth:src/auth.rs".to_owned()],
            )
            .unwrap_or_else(|error| panic!("satisfy recovered A8 evidence: {error}"));
    }
    let consumer_ready = recovered
        .derive_ready_lease(
            &fixture.registry,
            &consumer_id,
            ReadinessInputs::permissive_m1("sha256:m8-a8-ready-after-recovery"),
            &write_manifest,
        )
        .unwrap_or_else(|error| {
            panic!("A8 must consume the recovered A7 checkpoint without rerunning A7: {error}")
        });
    recovered
        .cancel_ready_lease(consumer_ready)
        .unwrap_or_else(|error| panic!("cancel recovered A8 restart proof lease: {error}"));
}

#[test]
fn logically_parallel_cross_repo_roots_still_serialize_local_model_admission() {
    let fixture = Fixture::create("serial-model");
    let proposal = json!({
        "tasks": [
            task("auth-root", "repo.auth", "src/auth.rs", &[]),
            task("gateway-root", "repo.gateway", "src/gateway.rs", &[])
        ]
    });
    let compilation = compile(&fixture, true, &proposal);
    let auth_id = task_id_with_title(&compilation, "Implement auth-root");
    let gateway_id = task_id_with_title(&compilation, "Implement gateway-root");
    let auth_requirements = execution_requirement_ids(&compilation, "Implement auth-root");
    let gateway_requirements = execution_requirement_ids(&compilation, "Implement gateway-root");
    let context = context_packet(&fixture, true);
    let state = StateStore::open(&fixture.state_path)
        .unwrap_or_else(|error| panic!("open serial-model state: {error}"));
    let mut controller = Controller::new(state);
    controller
        .activate(compilation, &fixture.registry)
        .unwrap_or_else(|error| panic!("activate serial-model plan: {error}"));
    controller.set_resource_pressure_probe(Box::new(FixedPressureProbe(green_snapshot(20_000))));
    for requirement_id in auth_requirements {
        controller
            .record_exact_evidence_satisfaction(
                &fixture.registry,
                &auth_id,
                &requirement_id,
                &context,
                &["file:repo.auth:src/auth.rs".to_owned()],
            )
            .unwrap_or_else(|error| panic!("satisfy auth execution evidence: {error}"));
    }
    for requirement_id in gateway_requirements {
        controller
            .record_exact_evidence_satisfaction(
                &fixture.registry,
                &gateway_id,
                &requirement_id,
                &context,
                &["file:repo.gateway:src/gateway.rs".to_owned()],
            )
            .unwrap_or_else(|error| panic!("satisfy gateway execution evidence: {error}"));
    }
    let first = controller
        .derive_ready_lease(
            &fixture.registry,
            &auth_id,
            ReadinessInputs::permissive_m1("sha256:m8-serial-auth"),
            &write_tool_manifest(),
        )
        .unwrap_or_else(|error| panic!("first root must obtain the single MODEL lease: {error}"));
    assert_eq!(first.task_id(), auth_id);

    let second = controller.derive_ready_lease(
        &fixture.registry,
        &gateway_id,
        ReadinessInputs::permissive_m1("sha256:m8-serial-gateway"),
        &write_tool_manifest(),
    );
    let Err(error) = second else {
        panic!("second logically-ready repository unexpectedly acquired the MODEL lease");
    };
    assert!(
        error.to_string().contains("Serialize") || error.to_string().contains("MODEL"),
        "second logically-ready repository must be serialized behind the active MODEL lease: {error}"
    );
}

struct CompletedProducerRuntime {
    backend: DeterministicFakeBackend,
    command_policy: CommandPolicy,
    isolation_backend: MacSandboxExecBackend,
    write_isolation_request: IsolationRequest,
    write_manifest: ToolManifest,
}

fn execute_completed_producer_mutation(
    fixture: &Fixture,
    controller: &mut Controller,
    producer_id: &str,
    producer_requirements: &[String],
    context: &ContextPacket,
    artifacts: &ArtifactStore,
) -> CompletedProducerRuntime {
    for requirement_id in producer_requirements {
        controller
            .record_exact_evidence_satisfaction(
                &fixture.registry,
                producer_id,
                requirement_id,
                context,
                &["file:repo.gateway:src/gateway.rs".to_owned()],
            )
            .unwrap_or_else(|error| panic!("satisfy completed producer evidence: {error}"));
    }

    let executable = PinnedExecutable::from_path("/usr/bin/make", "macos-system-make")
        .unwrap_or_else(|error| panic!("pin completed integration executable: {error}"));
    let toolchain_root = executable
        .path
        .parent()
        .unwrap_or_else(|| panic!("completed integration executable parent"))
        .to_path_buf();
    let command_policy = CommandPolicy::new([executable], [toolchain_root])
        .unwrap_or_else(|error| panic!("completed integration command policy: {error}"));
    let isolation_backend = MacSandboxExecBackend::detect()
        .unwrap_or_else(|error| panic!("detect completed integration isolation: {error}"));
    let home = std::env::var_os("HOME").map_or_else(
        || panic!("HOME must be set for completed integration isolation"),
        PathBuf::from,
    );
    let write_isolation_request = IsolationRequest {
        repository_root: fixture.snapshot("repo.auth").root.clone(),
        user_home_root: home,
        extra_protected_read_roots: Vec::new(),
        network_offline: true,
        allow_repository_write: true,
        require_full_filesystem_read_jail: false,
    };
    let backend = deterministic_execution_backend();
    let write_manifest = write_tool_manifest();
    let producer_ready = controller
        .derive_ready_lease(
            &fixture.registry,
            producer_id,
            ReadinessInputs::permissive_m1("sha256:m8-negative-producer-ready"),
            &write_manifest,
        )
        .unwrap_or_else(|error| panic!("derive completed producer lease: {error}"));
    let gateway_evidence = context
        .items
        .iter()
        .find(|item| item.evidence_id == "file:repo.gateway:src/gateway.rs")
        .unwrap_or_else(|| panic!("completed gateway exact source evidence"));
    let gateway_source =
        fs::read_to_string(fixture.snapshot("repo.gateway").root.join("src/gateway.rs"))
            .unwrap_or_else(|error| panic!("read completed gateway source: {error}"));
    let repository_proposal = RepositoryProposalV1 {
        schema_version: REPOSITORY_PROPOSAL_SCHEMA_VERSION,
        evidence_ids: vec![gateway_evidence.evidence_id.clone()],
        action: RepositoryActionV1::UpdateFile {
            repository_id: "repo.gateway".to_owned(),
            path: "src/gateway.rs".to_owned(),
            expected_source_digest: gateway_evidence.source_digest.clone(),
            content: format!("{gateway_source}// M8 negative checkpoint producer change\n"),
        },
    };
    let write_runtime = ExecutionRuntime {
        registry: &fixture.registry,
        backend: &backend,
        command_policy: &command_policy,
        isolation_backend: &isolation_backend,
        isolation_request: &write_isolation_request,
        artifacts,
        tool_manifest: &write_manifest,
        python_executable: Path::new("/usr/bin/python3"),
    };
    controller
        .execute_repository_proposal(producer_ready, &write_runtime, context, repository_proposal)
        .unwrap_or_else(|error| panic!("execute completed producer mutation: {error}"));

    CompletedProducerRuntime {
        backend,
        command_policy,
        isolation_backend,
        write_isolation_request,
        write_manifest,
    }
}

fn completed_two_repo_integration_gate(
    label: &str,
) -> (
    Fixture,
    Controller,
    String,
    Vec<String>,
    ContextPacket,
    ToolManifest,
    String,
) {
    let fixture = Fixture::create(label);
    let compilation = compile(&fixture, true, &two_repo_integration_proposal());
    let producer_id = task_id_with_title(&compilation, "Gateway producer change");
    let gate_id = task_id_with_title(&compilation, "A7 cross-repo integration security gate");
    let consumer_id = task_id_with_title(&compilation, "A8 checkpoint consumer");
    let producer_requirements = execution_requirement_ids(&compilation, "Gateway producer change");
    let consumer_requirements = execution_requirement_ids(&compilation, "A8 checkpoint consumer");
    let context = context_packet(&fixture, true);

    let state = StateStore::open(&fixture.state_path)
        .unwrap_or_else(|error| panic!("open completed integration state: {error}"));
    let artifacts = ArtifactStore::open(fixture.base.join(format!("cas-{label}")))
        .unwrap_or_else(|error| panic!("open completed integration artifacts: {error}"));
    let mut controller = Controller::new(state);
    controller
        .activate(compilation, &fixture.registry)
        .unwrap_or_else(|error| panic!("activate completed integration plan: {error}"));
    controller.set_resource_pressure_probe(Box::new(FixedPressureProbe(green_snapshot(70_000))));
    let producer_runtime = execute_completed_producer_mutation(
        &fixture,
        &mut controller,
        &producer_id,
        &producer_requirements,
        &context,
        &artifacts,
    );

    let read_manifest = read_tool_manifest();
    let gate_lease = controller
        .derive_integration_gate_lease(
            &fixture.registry,
            &gate_id,
            ReadinessInputs::permissive_m1("sha256:m8-negative-integration-ready"),
            &read_manifest,
        )
        .unwrap_or_else(|error| panic!("derive completed A7 lease: {error}"));
    let read_isolation_request = IsolationRequest {
        repository_root: fixture.snapshot("repo.auth").root.clone(),
        user_home_root: producer_runtime
            .write_isolation_request
            .user_home_root
            .clone(),
        extra_protected_read_roots: Vec::new(),
        network_offline: true,
        allow_repository_write: false,
        require_full_filesystem_read_jail: false,
    };
    let read_runtime = ExecutionRuntime {
        registry: &fixture.registry,
        backend: &producer_runtime.backend,
        command_policy: &producer_runtime.command_policy,
        isolation_backend: &producer_runtime.isolation_backend,
        isolation_request: &read_isolation_request,
        artifacts: &artifacts,
        tool_manifest: &read_manifest,
        python_executable: Path::new("/usr/bin/python3"),
    };
    let success = controller
        .execute_integration_gate(gate_lease, &read_runtime)
        .unwrap_or_else(|error| panic!("execute completed A7 gate: {error}"));
    assert!(success.verification.passed);
    assert_eq!(controller.task_state(&gate_id), Some(TaskState::Succeeded));

    (
        fixture,
        controller,
        consumer_id,
        consumer_requirements,
        context,
        producer_runtime.write_manifest,
        success.checkpoint.checkpoint_digest,
    )
}

fn satisfy_consumer_execution_evidence(
    fixture: &Fixture,
    controller: &mut Controller,
    consumer_id: &str,
    consumer_requirements: &[String],
    context: &ContextPacket,
) {
    for requirement_id in consumer_requirements {
        controller
            .record_exact_evidence_satisfaction(
                &fixture.registry,
                consumer_id,
                requirement_id,
                context,
                &["file:repo.auth:src/auth.rs".to_owned()],
            )
            .unwrap_or_else(|error| panic!("satisfy negative A8 evidence: {error}"));
    }
}

fn checkpoint_object_path(fixture: &Fixture, checkpoint_digest: &str) -> PathBuf {
    let digest = checkpoint_digest
        .strip_prefix("sha256:")
        .unwrap_or_else(|| panic!("checkpoint digest must be SHA-256-prefixed"));
    fixture
        .base
        .join("checkpoint-cas")
        .join("sha256")
        .join(&digest[..2])
        .join(digest)
}

#[test]
fn a8_blocks_when_a7_checkpoint_cas_object_is_missing() {
    let (
        fixture,
        mut controller,
        consumer_id,
        consumer_requirements,
        context,
        write_manifest,
        checkpoint_digest,
    ) = completed_two_repo_integration_gate("checkpoint-missing");
    satisfy_consumer_execution_evidence(
        &fixture,
        &mut controller,
        &consumer_id,
        &consumer_requirements,
        &context,
    );
    let checkpoint_path = checkpoint_object_path(&fixture, &checkpoint_digest);
    assert!(
        checkpoint_path.is_file(),
        "A7 checkpoint CAS object must exist"
    );
    fs::remove_file(&checkpoint_path)
        .unwrap_or_else(|error| panic!("remove checkpoint CAS object: {error}"));

    let Err(error) = controller.derive_ready_lease(
        &fixture.registry,
        &consumer_id,
        ReadinessInputs::permissive_m1("sha256:m8-a8-missing-checkpoint"),
        &write_manifest,
    ) else {
        panic!("A8 unexpectedly became ready without its checkpoint CAS object");
    };
    assert_eq!(
        controller.task_state(&consumer_id),
        Some(TaskState::Planned)
    );
    assert!(
        error.to_string().contains("checkpoint")
            || error.to_string().contains("artifact")
            || error.to_string().contains("No such file"),
        "missing A7 checkpoint object must fail closed before A8 readiness: {error}"
    );
}

#[test]
fn a8_blocks_when_a7_checkpoint_cas_object_is_tampered() {
    let (
        fixture,
        mut controller,
        consumer_id,
        consumer_requirements,
        context,
        write_manifest,
        checkpoint_digest,
    ) = completed_two_repo_integration_gate("checkpoint-tampered");
    satisfy_consumer_execution_evidence(
        &fixture,
        &mut controller,
        &consumer_id,
        &consumer_requirements,
        &context,
    );
    let checkpoint_path = checkpoint_object_path(&fixture, &checkpoint_digest);
    assert!(
        checkpoint_path.is_file(),
        "A7 checkpoint CAS object must exist"
    );
    fs::write(&checkpoint_path, b"{\"tampered\":true}")
        .unwrap_or_else(|error| panic!("tamper checkpoint CAS object: {error}"));

    let Err(error) = controller.derive_ready_lease(
        &fixture.registry,
        &consumer_id,
        ReadinessInputs::permissive_m1("sha256:m8-a8-tampered-checkpoint"),
        &write_manifest,
    ) else {
        panic!("A8 unexpectedly became ready with a tampered checkpoint CAS object");
    };
    assert_eq!(
        controller.task_state(&consumer_id),
        Some(TaskState::Planned)
    );
    assert!(
        error.to_string().contains("digest")
            || error.to_string().contains("checkpoint")
            || error.to_string().contains("artifact"),
        "tampered A7 checkpoint object must fail closed before A8 readiness: {error}"
    );
}

#[test]
fn a8_blocks_after_repository_baseline_drifts_from_the_a7_checkpoint() {
    let (
        fixture,
        mut controller,
        consumer_id,
        consumer_requirements,
        context,
        write_manifest,
        _checkpoint_digest,
    ) = completed_two_repo_integration_gate("checkpoint-stale-baseline");
    satisfy_consumer_execution_evidence(
        &fixture,
        &mut controller,
        &consumer_id,
        &consumer_requirements,
        &context,
    );
    let gateway_path = fixture.snapshot("repo.gateway").root.join("src/gateway.rs");
    let gateway_source = fs::read_to_string(&gateway_path)
        .unwrap_or_else(|error| panic!("read gateway primary source before drift: {error}"));
    fs::write(
        &gateway_path,
        format!("{gateway_source}// external post-checkpoint drift\n"),
    )
    .unwrap_or_else(|error| panic!("write post-checkpoint gateway drift: {error}"));

    let Err(error) = controller.derive_ready_lease(
        &fixture.registry,
        &consumer_id,
        ReadinessInputs::permissive_m1("sha256:m8-a8-stale-checkpoint"),
        &write_manifest,
    ) else {
        panic!("A8 unexpectedly became ready after repository baseline drift");
    };
    assert_eq!(
        controller.task_state(&consumer_id),
        Some(TaskState::Planned)
    );
    assert!(
        error.to_string().contains("baseline")
            || error.to_string().contains("stale")
            || error.to_string().contains("changed"),
        "repository drift after A7 must prevent A8 from consuming stale checkpoint authority: {error}"
    );
}
