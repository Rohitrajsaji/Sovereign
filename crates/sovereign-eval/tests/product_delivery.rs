#![cfg(target_os = "macos")]
#![forbid(unsafe_code)]

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sovereign_context::{
    ContextBudget, ContextMode, ContextPacket, ContextPacketInput, ContextPlanner, EvidenceItem,
};
use sovereign_controller::{
    ApprovalDecisionV1, Controller, ControllerError, ControllerManagedLoopbackApp,
    ExecutionRuntime, ExecutionSuccess, PermissionContext, ReadinessInputs, RecoveryManager,
    RepositoryActionV1, RepositoryProposalV1, ResourcePressureProbe, RoleId, RoleRegistry,
    TaskState,
};
use sovereign_evidence::ArtifactStore;
use sovereign_model::{
    DeterministicFakeBackend, MODEL_SCHEMA_VERSION, ModelBackend, ModelCapabilities,
    ModelFinishReason, ModelLoadProfile, ModelResponse, ModelUsage,
};
use sovereign_plan::{
    DepthClassifier, DepthFeatureInput, ExecutionDepth, M3PlanningInput,
    PLAN_COMPILATION_SCHEMA_VERSION, PlanCompilationInput, PlanCompilationRepository,
    PlanCompilationResult, PlanCompiler, PlanValidator, ValidationEnvironment,
};
use sovereign_policy::{
    CommandPolicy, CommandRisk, IsolationRequest, MacSandboxExecBackend, ModelCallBudget,
    OsMemoryPressure, PinnedExecutable, RESOURCE_PRESSURE_EVENT_SCHEMA_VERSION,
    ReconciliationPolicy, ResourcePressureSnapshotV1, ThermalPressure,
};
use sovereign_repo::{ExactRetriever, ProjectRegistry, RepositoryIntelligence};
use sovereign_state::StateStore;
use sovereign_tools::browser::{BrowserAction, BrowserActionReceipt, BrowserAdapterConfig};
use sovereign_tools::{PermissionClass, ToolManifest};
use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const SERVER: &str = include_str!("fixtures/product_inventory/server.py");
const INVENTORY_TEST: &str = include_str!("fixtures/product_inventory/test_inventory.py");
const INDEX_HTML: &str = include_str!("fixtures/product_inventory/index.html");
const RUNBOOK: &str = include_str!("fixtures/product_inventory/RUNBOOK.md");
const MAKEFILE: &str = include_str!("fixtures/product_inventory/Makefile");
const WRITE_TOOL_DIGEST: &str =
    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const BROWSER_TOOL_DIGEST: &str =
    "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const PRODUCT_NETWORK_BYTES: u64 = 4 * 1024 * 1024;
static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

struct FixedResourcePressureProbe(ResourcePressureSnapshotV1);

impl ResourcePressureProbe for FixedResourcePressureProbe {
    fn sample(&mut self) -> io::Result<ResourcePressureSnapshotV1> {
        Ok(self.0)
    }
}

fn green_pressure_snapshot(observed_at_ms: i64) -> ResourcePressureSnapshotV1 {
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
        host_free_disk_mib: Some(32_768),
    }
}

struct ProductFixture {
    base: PathBuf,
    root: PathBuf,
    state_path: PathBuf,
}

impl ProductFixture {
    fn create() -> Self {
        let sequence = FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let home = std::env::var_os("HOME").map_or_else(
            || panic!("HOME must be set for PD-T03 fixture"),
            PathBuf::from,
        );
        let base = home.join(format!(
            ".sovereign-eval-pd-t03-{}-{nanos}-{sequence}",
            std::process::id()
        ));
        let root = base.join("inventory-app");
        fs::create_dir_all(root.join("tests"))
            .unwrap_or_else(|error| panic!("create product tests directory: {error}"));
        fs::create_dir_all(root.join("web"))
            .unwrap_or_else(|error| panic!("create product web directory: {error}"));
        fs::write(root.join("server.py"), SERVER)
            .unwrap_or_else(|error| panic!("write product server: {error}"));
        fs::write(root.join("tests/test_inventory.py"), INVENTORY_TEST)
            .unwrap_or_else(|error| panic!("write product tests: {error}"));
        fs::write(root.join("Makefile"), MAKEFILE)
            .unwrap_or_else(|error| panic!("write product Makefile: {error}"));
        fs::write(root.join("web/.gitkeep"), "")
            .unwrap_or_else(|error| panic!("write product web sentinel: {error}"));
        git(&root, &["init", "-q"]);
        git(
            &root,
            &["config", "user.email", "sovereign-product@example.invalid"],
        );
        git(&root, &["config", "user.name", "Sovereign Product Proof"]);
        git(&root, &["add", "."]);
        git(&root, &["commit", "-qm", "inventory baseline"]);
        let state_path = base.join("state.sqlite3");
        Self {
            base,
            root,
            state_path,
        }
    }
}

impl Drop for ProductFixture {
    fn drop(&mut self) {
        let _cleanup_result = fs::remove_dir_all(&self.base);
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

fn global_policy(port: u16) -> Value {
    let mut policy: Value = serde_json::from_str(include_str!("fixtures/scenario1/policy.json"))
        .unwrap_or_else(|error| panic!("parse product policy: {error}"));
    policy["capability_ceiling"] = json!([
        "read",
        "repo_write",
        "process_exec",
        "network_read",
        "network_write",
        "browser_interactive"
    ]);
    policy["network"] = json!({
        "default": "task_scoped",
        "allowed_hosts": ["127.0.0.1"],
        "allowed_schemes": ["http"],
        "allowed_ports": [port],
        "allowed_methods": ["GET", "POST"],
        "follow_redirects": true,
        "max_redirects": 1,
        "allow_private_ranges": false,
        "dns_revalidation": true,
        "connected_peer_validation": true,
        "ambient_proxy": "deny",
        "allow_task_loopback": true
    });
    policy["resources"]["heavy_leases"] = json!(["MODEL", "BUILD_HEAVY", "BROWSER"]);
    policy["resources"]["max_disk_write_mb"] = json!(64);
    policy["resources"]["max_network_bytes"] = json!(PRODUCT_NETWORK_BYTES);
    policy["resources"]["max_tool_actions"] = json!(32);
    policy
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

fn product_registry(fixture: &ProductFixture) -> ProjectRegistry {
    let mut registry = ProjectRegistry::new();
    registry
        .register("repo.inventory", &fixture.root)
        .unwrap_or_else(|error| panic!("register inventory repository: {error}"));
    registry
}

fn product_context(registry: &ProjectRegistry, task_contract: &str) -> ContextPacket {
    let snapshot = registry
        .snapshot("repo.inventory")
        .unwrap_or_else(|error| panic!("snapshot inventory repository: {error}"));
    let retriever = ExactRetriever::new(registry);
    let server = retriever
        .read_path("repo.inventory", Path::new("server.py"), None)
        .unwrap_or_else(|error| panic!("read inventory server evidence: {error}"));
    let tests = retriever
        .read_path("repo.inventory", Path::new("tests/test_inventory.py"), None)
        .unwrap_or_else(|error| panic!("read inventory test evidence: {error}"));
    ContextPlanner::default()
        .build(
            ContextMode::Implementation,
            ContextBudget::m1_8k(),
            ContextPacketInput {
                controller_prefix:
                    "Controller owns product mutation, verification, recovery, and completion authority."
                        .to_owned(),
                task_contract: task_contract.to_owned(),
                current_state: format!(
                    "repository=repo.inventory; head={:?}; dirty_digest={}",
                    snapshot.head, snapshot.dirty_digest
                ),
                authorized_tool_schemas: Vec::new(),
                candidates: vec![
                    EvidenceItem::from_exact_file(&server, "exact inventory backend source"),
                    EvidenceItem::from_exact_file(&tests, "exact deterministic inventory tests"),
                ],
                output_schema: "bounded product implementation proposal v1".to_owned(),
            },
        )
        .unwrap_or_else(|error| panic!("build product context: {error}"))
}

fn product_plan_proposal() -> Value {
    json!({
        "tasks": [
            {
                "local_id": "inventory-ui",
                "repository_id": "repo.inventory",
                "title": "Create inventory browser UI",
                "objective": "Create the browser UI for local inventory CRUD, search, and deterministic validation.",
                "rationale": "The backend and deterministic tests are present; the bounded UI file completes the runnable full-stack flow.",
                "files": [],
                "create_files": ["web/index.html"],
                "symbols": ["inventory-ui"],
                "dependencies": [],
                "evidence_needs": [],
                "expected_change": "web/index.html exposes create, invalid-create, search, edit, and delete forms.",
                "acceptance": [
                    {
                        "kind": "diff",
                        "description": "The exact inventory UI create-file diff is accepted.",
                        "manual_gate_id": Value::Null
                    },
                    {
                        "kind": "command",
                        "description": "Run the deterministic inventory unit and UI-contract tests.",
                        "manual_gate_id": Value::Null,
                        "command_spec": {
                            "tool_id": "tool.patch",
                            "mode": "exec",
                            "program": "make",
                            "args": ["test"],
                            "repository_id": "repo.inventory",
                            "working_dir_relative": ".",
                            "literal_env": {},
                            "secret_env": {},
                            "timeout_seconds": 30,
                            "output_limit_bytes": 262_144
                        },
                        "expected_exit_codes": [0]
                    }
                ]
            },
            {
                "local_id": "inventory-runbook",
                "repository_id": "repo.inventory",
                "title": "Create local inventory runbook",
                "objective": "Create reproducible local-only setup, verification, and run instructions for the inventory application.",
                "rationale": "The completed product needs exact instructions that can be verified without package installation or network access.",
                "files": [],
                "create_files": ["RUNBOOK.md"],
                "symbols": ["local-runbook"],
                "dependencies": ["inventory-ui"],
                "evidence_needs": [],
                "expected_change": "RUNBOOK.md records exact local verification and loopback run commands.",
                "acceptance": [{
                    "kind": "diff",
                    "description": "The exact local runbook create-file diff is accepted.",
                    "manual_gate_id": Value::Null
                }]
            },
            {
                "local_id": "inventory-browser-proof",
                "repository_id": "repo.inventory",
                "title": "Verify inventory in real browser",
                "objective": "Exercise local inventory validation, CRUD, search, and restart persistence in a Controller-governed browser session.",
                "rationale": "The selected product profile requires real browser verification after implementation and runbook creation.",
                "files": [],
                "create_files": [],
                "symbols": ["inventory-browser-proof"],
                "dependencies": ["inventory-runbook"],
                "evidence_needs": [],
                "expected_change": "Controller-governed browser evidence proves the runnable local inventory user flow without repository mutation.",
                "acceptance": [{
                    "kind": "command",
                    "description": "Re-run deterministic inventory tests after the browser flow.",
                    "manual_gate_id": Value::Null,
                    "command_spec": {
                        "tool_id": "tool.patch",
                        "mode": "exec",
                        "program": "make",
                        "args": ["test"],
                        "repository_id": "repo.inventory",
                        "working_dir_relative": ".",
                        "literal_env": {},
                        "secret_env": {},
                        "timeout_seconds": 30,
                            "output_limit_bytes": 262_144
                    },
                    "expected_exit_codes": [0]
                }]
            }
        ]
    })
}

fn model_response(content: String, input_tokens: u32) -> ModelResponse {
    ModelResponse {
        schema_version: MODEL_SCHEMA_VERSION,
        request_id: "pd-t03-product-plan".to_owned(),
        content,
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

fn new_fake_backend(responses: Vec<ModelResponse>) -> DeterministicFakeBackend {
    DeterministicFakeBackend::new(
        ModelCapabilities {
            schema_version: MODEL_SCHEMA_VERSION,
            model_id: "fake-pd-t03-local".to_owned(),
            parameter_class: "fixture".to_owned(),
            quantization: "fixture".to_owned(),
            max_context_tokens: 16_384,
            supports_tools: false,
            supports_json_schema: true,
            local: true,
        },
        responses,
    )
    .unwrap_or_else(|error| panic!("create product fake backend: {error}"))
}

fn fake_backend(responses: Vec<ModelResponse>) -> DeterministicFakeBackend {
    let backend = new_fake_backend(responses);
    backend
        .load(ModelLoadProfile {
            context_tokens: 8_000,
            output_reserve_tokens: 1_024,
            startup_timeout_ms: 1_000,
            provider_call_timeout_ms: 1_000,
        })
        .unwrap_or_else(|error| panic!("load product fake backend: {error}"));
    backend
}

struct CompiledProduct {
    compilation: PlanCompilationResult,
    ui_task_id: String,
    runbook_task_id: String,
    browser_task_id: String,
}

fn browser_tool_pin() -> Value {
    capability("tool.browser", BROWSER_TOOL_DIGEST)
}

fn compile_product(
    registry: &ProjectRegistry,
    context: &ContextPacket,
    port: u16,
) -> CompiledProduct {
    let snapshot = registry
        .snapshot("repo.inventory")
        .unwrap_or_else(|error| panic!("snapshot product for compile: {error}"));
    let depth = DepthClassifier.classify(&DepthFeatureInput {
        repository_count: 1,
        language_count: 3,
        expected_files: 3,
        expected_modules: 1,
        expected_symbols: 6,
        ..DepthFeatureInput::default()
    });
    assert_eq!(depth.mode, ExecutionDepth::D2);
    let m3 = M3PlanningInput {
        depth,
        supplied_sources: Vec::new(),
        additional_repositories: Vec::new(),
        manual_gates: Vec::new(),
        absence_evaluator: None,
        replan: None,
    };
    let input = PlanCompilationInput {
        schema_version: PLAN_COMPILATION_SCHEMA_VERSION,
        compilation_id: "compile.pd-t03.inventory".to_owned(),
        compiled_at: "2026-09-19T11:15:00Z".to_owned(),
        project_id: "project.pd-t03.inventory".to_owned(),
        project_name: "Sovereign local inventory product proof".to_owned(),
        workspace_roots: vec![snapshot.root.display().to_string()],
        goal_id: "goal.pd-t03.inventory".to_owned(),
        goal_statement: "Build a local full-stack inventory application with persistent create, edit, delete, search, deterministic validation, real browser verification, and reproducible local setup/run instructions.".to_owned(),
        goal_invariants: vec![
            "Stay local-only and offline with no package installation or secrets.".to_owned(),
            "Persist inventory records in SQLite across application restart.".to_owned(),
        ],
        goal_non_goals: vec!["Do not deploy or publish the application.".to_owned()],
        repository: PlanCompilationRepository {
            repository_id: snapshot.repository_id.clone(),
            root: snapshot.root.display().to_string(),
            head: snapshot.head.clone(),
            branch: snapshot.branch.clone(),
            dirty_digest: snapshot.dirty_digest.clone(),
            protected_changes_present: snapshot.protected_changes_present,
            languages: vec!["python".to_owned(), "html".to_owned(), "sqlite".to_owned()],
        },
        policy: global_policy(port),
        role: canonical_implementer_role(),
        skills: vec![capability(
            "skill.local-product",
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
        diff_evaluator: "builtin.diff.scoped_change.v1".to_owned(),
        rollback_diff_evaluator: "builtin.diff.controller_patch_absent.v1".to_owned(),
        context_packet: context.clone(),
        m3: Some(m3),
        max_model_calls: 2,
        model_input_token_ceiling: 8_000,
        max_output_tokens: 1_024,
        model_deadline_ms: 1_000,
    };
    compile_product_input(&input, context.metrics.final_serialized_input_tokens, port)
}

fn compile_product_input(
    input: &PlanCompilationInput,
    packet_tokens: u32,
    port: u16,
) -> CompiledProduct {
    let planner = fake_backend(vec![model_response(
        product_plan_proposal().to_string(),
        packet_tokens,
    )]);
    let validator = PlanValidator::new(ValidationEnvironment::default())
        .unwrap_or_else(|error| panic!("product validator: {error}"));
    let compiler = PlanCompiler::new(&planner, &validator, "pd-t03-product-compiler-v1")
        .unwrap_or_else(|error| panic!("product compiler: {error}"));
    let mut budget = ModelCallBudget::new(1, 30_000);
    let compilation = compiler
        .compile(input, &mut budget)
        .unwrap_or_else(|error| panic!("compile natural-language product goal: {error}"));
    assert!(validator.validate(compilation.plan()).is_empty());
    let ui_task_id = task_id_by_title(&compilation, "Create inventory browser UI");
    let runbook_task_id = task_id_by_title(&compilation, "Create local inventory runbook");
    let browser_task_id = task_id_by_title(&compilation, "Verify inventory in real browser");
    let compilation = compilation
        .bind_controller_loopback_browser(
            &validator,
            &browser_task_id,
            &browser_tool_pin(),
            port,
            PRODUCT_NETWORK_BYTES,
        )
        .unwrap_or_else(|error| panic!("bind Controller loopback browser authority: {error:?}"));
    assert!(validator.validate(compilation.plan()).is_empty());
    planner
        .unload()
        .unwrap_or_else(|error| panic!("unload product planner: {error}"));
    CompiledProduct {
        compilation,
        ui_task_id,
        runbook_task_id,
        browser_task_id,
    }
}

fn task_id_by_title(compilation: &PlanCompilationResult, title: &str) -> String {
    compilation.plan().as_value()["tasks"]
        .as_array()
        .and_then(|tasks| tasks.iter().find(|task| task["title"] == json!(title)))
        .and_then(|task| task["task_id"].as_str())
        .map_or_else(
            || panic!("compiled product task {title:?} missing"),
            str::to_owned,
        )
}

fn write_tool_manifest() -> ToolManifest {
    ToolManifest {
        tool_id: "tool.patch".to_owned(),
        version: "1.0.0".to_owned(),
        content_digest: WRITE_TOOL_DIGEST.to_owned(),
        permission_ceiling: BTreeSet::from([
            PermissionClass::ProcessExec,
            PermissionClass::RepositoryWrite,
        ]),
        declared_risk_floor: CommandRisk::RepositoryMutation,
        reconciliation_policy: ReconciliationPolicy::proof_required_local(),
    }
}

fn browser_tool_manifest() -> ToolManifest {
    ToolManifest {
        tool_id: "tool.browser".to_owned(),
        version: "1.0.0".to_owned(),
        content_digest: BROWSER_TOOL_DIGEST.to_owned(),
        permission_ceiling: BTreeSet::from([
            PermissionClass::BrowserInteractive,
            PermissionClass::NetworkRead,
            PermissionClass::NetworkWrite,
        ]),
        declared_risk_floor: CommandRisk::ReadOnly,
        reconciliation_policy: ReconciliationPolicy::proof_required_local(),
    }
}

struct RuntimeParts {
    command_policy: CommandPolicy,
    isolation_backend: MacSandboxExecBackend,
    isolation_request: IsolationRequest,
    verification_isolation_request: IsolationRequest,
    artifacts: ArtifactStore,
    manifest: ToolManifest,
}

impl RuntimeParts {
    fn new(fixture: &ProductFixture) -> Self {
        let python = PinnedExecutable::from_path("/usr/bin/python3", "macos-system-python")
            .unwrap_or_else(|error| panic!("pin product python: {error}"));
        let make = PinnedExecutable::from_path("/usr/bin/make", "macos-system-make")
            .unwrap_or_else(|error| panic!("pin product make: {error}"));
        let executable_root = python
            .path
            .parent()
            .unwrap_or_else(|| panic!("product python parent missing"))
            .to_path_buf();
        let command_policy = CommandPolicy::new([python, make], [executable_root])
            .unwrap_or_else(|error| panic!("product command policy: {error}"));
        let isolation_backend = MacSandboxExecBackend::detect()
            .unwrap_or_else(|error| panic!("detect product Seatbelt: {error}"));
        let home = std::env::var_os("HOME").map_or_else(
            || panic!("HOME must be set for product runtime"),
            PathBuf::from,
        );
        let isolation_request = IsolationRequest {
            repository_root: fixture.root.clone(),
            user_home_root: home.clone(),
            extra_protected_read_roots: Vec::new(),
            network_offline: true,
            allow_repository_write: true,
            require_full_filesystem_read_jail: false,
        };
        Self {
            command_policy,
            isolation_backend,
            isolation_request,
            verification_isolation_request: IsolationRequest {
                repository_root: fixture.root.clone(),
                user_home_root: home,
                extra_protected_read_roots: Vec::new(),
                network_offline: true,
                allow_repository_write: false,
                require_full_filesystem_read_jail: false,
            },
            artifacts: ArtifactStore::open(fixture.base.join("cas"))
                .unwrap_or_else(|error| panic!("open product CAS: {error}")),
            manifest: write_tool_manifest(),
        }
    }

    fn runtime<'a>(
        &'a self,
        registry: &'a ProjectRegistry,
        backend: &'a dyn ModelBackend,
    ) -> ExecutionRuntime<'a, MacSandboxExecBackend> {
        ExecutionRuntime {
            registry,
            backend,
            command_policy: &self.command_policy,
            isolation_backend: &self.isolation_backend,
            isolation_request: &self.isolation_request,
            artifacts: &self.artifacts,
            tool_manifest: &self.manifest,
            python_executable: Path::new("/usr/bin/python3"),
        }
    }

    fn verification_runtime<'a>(
        &'a self,
        registry: &'a ProjectRegistry,
        backend: &'a dyn ModelBackend,
    ) -> ExecutionRuntime<'a, MacSandboxExecBackend> {
        ExecutionRuntime {
            registry,
            backend,
            command_policy: &self.command_policy,
            isolation_backend: &self.isolation_backend,
            isolation_request: &self.verification_isolation_request,
            artifacts: &self.artifacts,
            tool_manifest: &self.manifest,
            python_executable: Path::new("/usr/bin/python3"),
        }
    }
}

fn execute_typed_create(
    controller: &mut Controller,
    registry: &ProjectRegistry,
    parts: &RuntimeParts,
    task_id: &str,
    context: &ContextPacket,
    path: &str,
    file_contents: &str,
) -> ExecutionSuccess {
    let ready = controller
        .derive_ready_lease(
            registry,
            task_id,
            ReadinessInputs::permissive_m1("sha256:pd-t03-product-resources"),
            &parts.manifest,
        )
        .unwrap_or_else(|error| panic!("derive typed product ready lease for {task_id}: {error}"));
    let evidence_id = context
        .items
        .iter()
        .find(|item| item.source_uri.ends_with("/server.py"))
        .map_or_else(
            || panic!("typed product server evidence missing"),
            |item| item.evidence_id.clone(),
        );
    let backend = new_fake_backend(Vec::new());
    let runtime = parts.runtime(registry, &backend);
    controller
        .execute_repository_proposal(
            ready,
            &runtime,
            context,
            RepositoryProposalV1 {
                schema_version: 1,
                evidence_ids: vec![evidence_id],
                action: RepositoryActionV1::CreateFile {
                    repository_id: "repo.inventory".to_owned(),
                    path: path.to_owned(),
                    content: file_contents.to_owned(),
                },
            },
        )
        .unwrap_or_else(|error| panic!("execute typed product create {path}: {error}"))
}

fn execute_create_with_model_repair(
    controller: &mut Controller,
    registry: &ProjectRegistry,
    parts: &RuntimeParts,
    task_id: &str,
    context: &ContextPacket,
    path: &str,
    file_contents: &str,
) -> ExecutionSuccess {
    let ready = controller
        .derive_ready_lease(
            registry,
            task_id,
            ReadinessInputs::permissive_m1("sha256:pd-t03-product-repair-resources"),
            &parts.manifest,
        )
        .unwrap_or_else(|error| panic!("derive product repair ready lease for {task_id}: {error}"));
    let evidence_id = context
        .items
        .iter()
        .find(|item| item.source_uri.ends_with("/server.py"))
        .map_or_else(
            || panic!("product repair server evidence missing"),
            |item| item.evidence_id.clone(),
        );
    let malformed = model_response(
        json!({
            "schema_version": 1,
            "evidence_ids": [evidence_id.clone()],
            "task_state": "succeeded",
            "action": {
                "kind": "create_file",
                "repository_id": "repo.inventory",
                "path": path,
                "content": file_contents
            }
        })
        .to_string(),
        context.metrics.final_serialized_input_tokens,
    );
    let repaired = model_response(
        json!({
            "schema_version": 1,
            "evidence_ids": [evidence_id],
            "action": {
                "kind": "create_file",
                "repository_id": "repo.inventory",
                "path": path,
                "content": file_contents
            }
        })
        .to_string(),
        context.metrics.final_serialized_input_tokens,
    );
    let backend = new_fake_backend(vec![malformed, repaired]);
    let runtime = parts.runtime(registry, &backend);
    let mut model_budget = ModelCallBudget::new(2, 30_000);
    let _error = controller
        .execute_repository_with_model(ready, &runtime, context, &mut model_budget)
        .err()
        .unwrap_or_else(|| panic!("malformed product proposal unexpectedly succeeded"));
    assert_eq!(
        controller.task_state(task_id),
        Some(TaskState::RepairPending)
    );
    let failure = controller
        .latest_failure_record(task_id)
        .unwrap_or_else(|error| panic!("read product repair failure: {error}"))
        .unwrap_or_else(|| panic!("product repair failure record missing"));
    assert_eq!(failure.category, "model_proposal_failure");
    assert_eq!(controller.task_model_calls_used(task_id), Some(1));
    assert_eq!(model_budget.remaining_calls(), 1);
    let repair_root = registry
        .snapshot("repo.inventory")
        .unwrap_or_else(|error| panic!("product repair snapshot: {error}"))
        .root;
    assert!(!repair_root.join(path).exists());

    let (success, repair_packet) = controller
        .repair_repository_with_model(
            task_id,
            &runtime,
            context,
            &[],
            ReadinessInputs::permissive_m1("sha256:pd-t03-product-repair-resources"),
            &mut model_budget,
        )
        .unwrap_or_else(|error| panic!("repair product create {path}: {error}"));
    assert_eq!(controller.task_state(task_id), Some(TaskState::Succeeded));
    assert_eq!(controller.task_model_calls_used(task_id), Some(2));
    assert_eq!(model_budget.remaining_calls(), 0);
    assert_eq!(repair_packet.prior_attempt_id, failure.attempt_id);
    assert_eq!(repair_packet.failure_signature, failure.signature);
    success
}

fn activate_product(
    fixture: &ProductFixture,
    registry: &ProjectRegistry,
    compiled: CompiledProduct,
) -> (Controller, String, String, String) {
    let mut controller = Controller::with_permission_context(
        StateStore::open(&fixture.state_path)
            .unwrap_or_else(|error| panic!("open product state: {error}")),
        PermissionContext::m7_local_browser_execution(),
    );
    controller.set_resource_pressure_probe(Box::new(FixedResourcePressureProbe(
        green_pressure_snapshot(1_000),
    )));
    let activation = controller
        .activate(compiled.compilation, registry)
        .unwrap_or_else(|error| panic!("activate product plan: {error}"));
    assert_eq!(activation.task_ids.len(), 3);
    assert_eq!(
        controller.task_state(&compiled.ui_task_id),
        Some(TaskState::Planned)
    );
    assert_eq!(
        controller.task_state(&compiled.runbook_task_id),
        Some(TaskState::Planned)
    );
    assert_eq!(
        controller.task_state(&compiled.browser_task_id),
        Some(TaskState::Planned)
    );
    (
        controller,
        compiled.ui_task_id,
        compiled.runbook_task_id,
        compiled.browser_task_id,
    )
}

fn recover_product(fixture: &ProductFixture, registry: &ProjectRegistry) -> Controller {
    let state = StateStore::open(&fixture.state_path)
        .unwrap_or_else(|error| panic!("reopen product state: {error}"));
    let (mut controller, recovery) = RecoveryManager::recover_with_permission_context(
        state,
        registry,
        PermissionContext::m7_local_browser_execution(),
    )
    .unwrap_or_else(|error| panic!("recover product Controller: {error}"));
    assert!(!recovery.mutation_blocked);
    assert!(recovery.unknown_action_ids.is_empty());
    controller.set_resource_pressure_probe(Box::new(FixedResourcePressureProbe(
        green_pressure_snapshot(2_000),
    )));
    controller
}

fn unused_loopback_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .unwrap_or_else(|error| panic!("reserve inventory loopback port: {error}"));
    listener
        .local_addr()
        .unwrap_or_else(|error| panic!("inventory loopback address: {error}"))
        .port()
}

fn run_exact_generated_runbook_verification(root: &Path) {
    let verification = Command::new("/usr/bin/python3")
        .args([
            "-B",
            "-m",
            "unittest",
            "discover",
            "-s",
            "tests",
            "-p",
            "test_*.py",
            "-q",
        ])
        .current_dir(root)
        .output()
        .unwrap_or_else(|error| panic!("execute exact RUNBOOK verification command: {error}"));
    assert!(
        verification.status.success(),
        "exact RUNBOOK verification failed: {}",
        String::from_utf8_lossy(&verification.stderr)
    );
}

fn run_exact_generated_runbook_server_acceptance(root: &Path) {
    let probe = TcpListener::bind(("127.0.0.1", 8765))
        .unwrap_or_else(|error| panic!("RUNBOOK port 8765 must be available: {error}"));
    drop(probe);
    let mut child = Command::new("/usr/bin/python3")
        .args([
            "-B",
            "server.py",
            "--host",
            "127.0.0.1",
            "--port",
            "8765",
            "--db",
            "inventory.sqlite3",
        ])
        .current_dir(root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("execute exact RUNBOOK application command: {error}"));

    let result = (|| -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if let Some(status) = child
                .try_wait()
                .map_err(|error| format!("poll exact RUNBOOK server: {error}"))?
            {
                return Err(format!(
                    "exact RUNBOOK server exited before readiness with status {status}"
                ));
            }
            match TcpStream::connect_timeout(
                &"127.0.0.1:8765"
                    .parse()
                    .map_err(|error| format!("parse RUNBOOK address: {error}"))?,
                Duration::from_millis(100),
            ) {
                Ok(mut stream) => {
                    stream
                        .set_read_timeout(Some(Duration::from_millis(500)))
                        .map_err(|error| format!("set RUNBOOK read timeout: {error}"))?;
                    stream
                        .set_write_timeout(Some(Duration::from_millis(500)))
                        .map_err(|error| format!("set RUNBOOK write timeout: {error}"))?;
                    stream
                        .write_all(
                            b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
                        )
                        .map_err(|error| format!("write RUNBOOK health request: {error}"))?;
                    let mut response = Vec::new();
                    stream
                        .read_to_end(&mut response)
                        .map_err(|error| format!("read RUNBOOK health response: {error}"))?;
                    let response = String::from_utf8_lossy(&response);
                    if (response.starts_with("HTTP/1.0 200 ")
                        || response.starts_with("HTTP/1.1 200 "))
                        && response.contains("\r\n\r\nok")
                    {
                        return Ok(());
                    }
                }
                Err(_) => thread::sleep(Duration::from_millis(20)),
            }
        }
        Err("exact RUNBOOK server did not become healthy within 5 seconds".to_owned())
    })();

    let _kill = child.kill();
    let _wait = child.wait();
    for suffix in ["", "-wal", "-shm"] {
        let path = root.join(format!("inventory.sqlite3{suffix}"));
        if path.exists() {
            fs::remove_file(&path).unwrap_or_else(|error| {
                panic!("remove exact RUNBOOK database {}: {error}", path.display())
            });
        }
    }
    result.unwrap_or_else(|error| {
        panic!("exact generated RUNBOOK server acceptance failed: {error}")
    });
}

fn run_browser_action(
    controller: &mut Controller,
    session: &mut sovereign_controller::ControllerBrowserSession,
    manifest: &ToolManifest,
    artifacts: &ArtifactStore,
    action: &BrowserAction,
) -> BrowserActionReceipt {
    match controller.execute_browser_action(session, manifest, artifacts, action) {
        Ok(receipt) => receipt,
        Err(ControllerError::AwaitingApproval { request_id, .. }) => {
            controller
                .respond_to_approval(
                    &request_id,
                    ApprovalDecisionV1::Approve,
                    "user:pd-t03-local-browser-proof",
                )
                .unwrap_or_else(|error| panic!("approve exact product browser action: {error}"));
            controller
                .execute_browser_action(session, manifest, artifacts, action)
                .unwrap_or_else(|error| {
                    panic!("execute approved product browser action {action:?}: {error}")
                })
        }
        Err(error) => panic!("execute product browser action {action:?}: {error}"),
    }
}

fn navigate(
    controller: &mut Controller,
    session: &mut sovereign_controller::ControllerBrowserSession,
    manifest: &ToolManifest,
    artifacts: &ArtifactStore,
    receipts: &mut Vec<BrowserActionReceipt>,
    action_id: &str,
    url: &str,
) {
    receipts.push(run_browser_action(
        controller,
        session,
        manifest,
        artifacts,
        &BrowserAction::Navigate {
            action_id: action_id.to_owned(),
            url: url.to_owned(),
        },
    ));
}

fn submit_form(
    controller: &mut Controller,
    session: &mut sovereign_controller::ControllerBrowserSession,
    manifest: &ToolManifest,
    artifacts: &ArtifactStore,
    receipts: &mut Vec<BrowserActionReceipt>,
    action_id: &str,
    selector: &str,
) {
    let payload_digest = format!(
        "sha256:{:x}",
        Sha256::digest(format!("{action_id}\0{selector}").as_bytes())
    );
    receipts.push(run_browser_action(
        controller,
        session,
        manifest,
        artifacts,
        &BrowserAction::SubmitForm {
            action_id: action_id.to_owned(),
            selector: selector.to_owned(),
            payload_digest,
        },
    ));
}

fn synopsis_text(
    controller: &mut Controller,
    session: &mut sovereign_controller::ControllerBrowserSession,
    manifest: &ToolManifest,
    artifacts: &ArtifactStore,
    receipts: &mut Vec<BrowserActionReceipt>,
    action_id: &str,
) -> String {
    let receipt = run_browser_action(
        controller,
        session,
        manifest,
        artifacts,
        &BrowserAction::CaptureSynopsis {
            action_id: action_id.to_owned(),
        },
    );
    let text = receipt
        .synopsis
        .as_ref()
        .unwrap_or_else(|| panic!("product synopsis missing"))
        .text
        .clone();
    receipts.push(receipt);
    text
}

fn assert_browser_create_and_validation(
    controller: &mut Controller,
    session: &mut sovereign_controller::ControllerBrowserSession,
    manifest: &ToolManifest,
    artifacts: &ArtifactStore,
    receipts: &mut Vec<BrowserActionReceipt>,
    origin: &str,
) {
    let observation = format!("{origin}view");
    navigate(
        controller,
        session,
        manifest,
        artifacts,
        receipts,
        "open-empty-inventory",
        &observation,
    );
    assert!(
        synopsis_text(
            controller,
            session,
            manifest,
            artifacts,
            receipts,
            "empty-synopsis",
        )
        .contains("No inventory items")
    );
    navigate(
        controller,
        session,
        manifest,
        artifacts,
        receipts,
        "open-invalid-create-form",
        origin,
    );
    submit_form(
        controller,
        session,
        manifest,
        artifacts,
        receipts,
        "reject-invalid-create",
        "form#invalid-create",
    );
    let invalid = synopsis_text(
        controller,
        session,
        manifest,
        artifacts,
        receipts,
        "invalid-synopsis",
    );
    assert!(invalid.contains("Validation error: name_required"));
    assert!(invalid.contains("No inventory items"));
    navigate(
        controller,
        session,
        manifest,
        artifacts,
        receipts,
        "return-after-invalid",
        origin,
    );
    submit_form(
        controller,
        session,
        manifest,
        artifacts,
        receipts,
        "create-widget",
        "form#create-widget",
    );
    navigate(
        controller,
        session,
        manifest,
        artifacts,
        receipts,
        "observe-created-widget",
        &observation,
    );
    let created = synopsis_text(
        controller,
        session,
        manifest,
        artifacts,
        receipts,
        "created-synopsis",
    );
    assert!(created.contains("Widget"));
    assert!(created.contains("quantity=3"));
}

fn assert_browser_edit_and_search(
    controller: &mut Controller,
    session: &mut sovereign_controller::ControllerBrowserSession,
    manifest: &ToolManifest,
    artifacts: &ArtifactStore,
    receipts: &mut Vec<BrowserActionReceipt>,
    origin: &str,
) {
    let observation = format!("{origin}view");
    navigate(
        controller,
        session,
        manifest,
        artifacts,
        receipts,
        "open-created-widget-form",
        origin,
    );
    submit_form(
        controller,
        session,
        manifest,
        artifacts,
        receipts,
        "edit-widget",
        "form#edit-1",
    );
    navigate(
        controller,
        session,
        manifest,
        artifacts,
        receipts,
        "observe-edited-widget",
        &observation,
    );
    let edited = synopsis_text(
        controller,
        session,
        manifest,
        artifacts,
        receipts,
        "edited-synopsis",
    );
    assert!(edited.contains("Widget Pro"));
    assert!(edited.contains("quantity=5"));
    navigate(
        controller,
        session,
        manifest,
        artifacts,
        receipts,
        "search-widget",
        &format!("{origin}view?q=Widget%20Pro"),
    );
    let searched = synopsis_text(
        controller,
        session,
        manifest,
        artifacts,
        receipts,
        "search-synopsis",
    );
    assert!(searched.contains("Search query: Widget Pro"));
    assert!(searched.contains("Widget Pro"));
}

fn assert_browser_delete(
    controller: &mut Controller,
    session: &mut sovereign_controller::ControllerBrowserSession,
    manifest: &ToolManifest,
    artifacts: &ArtifactStore,
    receipts: &mut Vec<BrowserActionReceipt>,
    origin: &str,
) {
    let observation = format!("{origin}view");
    navigate(
        controller,
        session,
        manifest,
        artifacts,
        receipts,
        "open-delete-widget-form",
        origin,
    );
    submit_form(
        controller,
        session,
        manifest,
        artifacts,
        receipts,
        "delete-widget",
        "form#delete-1",
    );
    navigate(
        controller,
        session,
        manifest,
        artifacts,
        receipts,
        "observe-deleted-widget",
        &observation,
    );
    assert!(
        synopsis_text(
            controller,
            session,
            manifest,
            artifacts,
            receipts,
            "deleted-synopsis",
        )
        .contains("No inventory items")
    );
}

fn assert_browser_persistent_seed(
    controller: &mut Controller,
    session: &mut sovereign_controller::ControllerBrowserSession,
    manifest: &ToolManifest,
    artifacts: &ArtifactStore,
    receipts: &mut Vec<BrowserActionReceipt>,
    origin: &str,
) {
    let observation = format!("{origin}view");
    navigate(
        controller,
        session,
        manifest,
        artifacts,
        receipts,
        "open-persistent-create-form",
        origin,
    );
    submit_form(
        controller,
        session,
        manifest,
        artifacts,
        receipts,
        "create-persistent-widget",
        "form#create-widget",
    );
    navigate(
        controller,
        session,
        manifest,
        artifacts,
        receipts,
        "observe-persistent-seed",
        &observation,
    );
    assert!(
        synopsis_text(
            controller,
            session,
            manifest,
            artifacts,
            receipts,
            "persistent-seed",
        )
        .contains("Widget")
    );
}

fn assert_browser_crud_search(
    controller: &mut Controller,
    session: &mut sovereign_controller::ControllerBrowserSession,
    manifest: &ToolManifest,
    artifacts: &ArtifactStore,
    receipts: &mut Vec<BrowserActionReceipt>,
    origin: &str,
) {
    assert_browser_create_and_validation(
        controller, session, manifest, artifacts, receipts, origin,
    );
    assert_browser_edit_and_search(controller, session, manifest, artifacts, receipts, origin);
    assert_browser_delete(controller, session, manifest, artifacts, receipts, origin);
    assert_browser_persistent_seed(controller, session, manifest, artifacts, receipts, origin);
}

fn assert_restart_persistence(
    controller: &mut Controller,
    session: &mut sovereign_controller::ControllerBrowserSession,
    lifecycle_runtime: &ExecutionRuntime<'_, MacSandboxExecBackend>,
    browser_evidence: (
        &ToolManifest,
        &ArtifactStore,
        &mut Vec<BrowserActionReceipt>,
    ),
    port: u16,
    app: &mut ControllerManagedLoopbackApp,
) {
    let (manifest, artifacts, receipts) = browser_evidence;
    let first_process_group = app.process_group_id();
    let first_leader_identity = app.leader_identity().to_owned();
    let database_path = app.database_path().to_path_buf();
    controller
        .stop_managed_loopback_app(session, lifecycle_runtime, app)
        .unwrap_or_else(|error| panic!("stop first managed inventory generation: {error}"));
    assert!(database_path.is_file());
    let mut restarted = controller
        .start_managed_loopback_app(
            session,
            lifecycle_runtime,
            2,
            Path::new("server.py"),
            "inventory.sqlite3",
        )
        .unwrap_or_else(|error| panic!("start second managed inventory generation: {error}"));
    assert_eq!(restarted.database_path(), database_path.as_path());
    assert_ne!(restarted.process_group_id(), first_process_group);
    assert_ne!(restarted.leader_identity(), first_leader_identity);
    let origin = format!("http://127.0.0.1:{port}/view");
    navigate(
        controller,
        session,
        manifest,
        artifacts,
        receipts,
        "open-after-app-restart",
        &origin,
    );
    let restarted_text = synopsis_text(
        controller,
        session,
        manifest,
        artifacts,
        receipts,
        "restart-persistence-synopsis",
    );
    assert!(restarted_text.contains("Widget"));
    assert!(restarted_text.contains("quantity=3"));
    controller
        .stop_managed_loopback_app(session, lifecycle_runtime, &mut restarted)
        .unwrap_or_else(|error| panic!("stop second managed inventory generation: {error}"));
}

fn assert_controller_clean(controller: &Controller) {
    let actions = controller
        .state()
        .action_records()
        .unwrap_or_else(|error| panic!("read product action records: {error}"));
    assert!(!actions.is_empty());
    assert!(
        actions
            .iter()
            .all(|record| !matches!(record.state.as_str(), "dispatched" | "observed" | "unknown"))
    );
}

#[test]
#[ignore = "requires exclusive local port 8765 exactly as frozen RUNBOOK commands specify"]
fn exact_generated_runbook_server_command_smoke() {
    let fixture = ProductFixture::create();
    fs::write(fixture.root.join("web/index.html"), INDEX_HTML)
        .unwrap_or_else(|error| panic!("write generated RUNBOOK smoke UI: {error}"));
    fs::write(fixture.root.join("RUNBOOK.md"), RUNBOOK)
        .unwrap_or_else(|error| panic!("write generated RUNBOOK smoke instructions: {error}"));
    run_exact_generated_runbook_verification(&fixture.root);
    run_exact_generated_runbook_server_acceptance(&fixture.root);
}

fn prepare_product_before_browser(
    fixture: &ProductFixture,
    registry: &ProjectRegistry,
    parts: &RuntimeParts,
    port: u16,
) -> (Controller, String, String, String) {
    let initial_context = product_context(
        registry,
        "Build the local inventory product with deterministic tests and reproducible run instructions.",
    );
    let compiled = compile_product(registry, &initial_context, port);
    let (mut controller, ui_task_id, runbook_task_id, browser_task_id) =
        activate_product(fixture, registry, compiled);
    let ui_success = execute_create_with_model_repair(
        &mut controller,
        registry,
        parts,
        &ui_task_id,
        &initial_context,
        "web/index.html",
        INDEX_HTML,
    );
    assert!(ui_success.verification.passed);
    assert_eq!(ui_success.verification.command_results.len(), 1);
    assert!(ui_success.verification.command_results[0].passed);
    assert_eq!(
        controller.task_state(&ui_task_id),
        Some(TaskState::Succeeded)
    );

    drop(controller);
    let mut controller = recover_product(fixture, registry);
    assert_eq!(
        controller.task_state(&ui_task_id),
        Some(TaskState::Succeeded)
    );
    assert_eq!(
        controller.task_state(&runbook_task_id),
        Some(TaskState::Planned)
    );
    assert_eq!(
        controller.task_state(&browser_task_id),
        Some(TaskState::Planned)
    );
    let recovered_context = product_context(
        registry,
        "Create exact local-only setup, verification, and run instructions after recovered product state.",
    );
    let runbook_success = execute_typed_create(
        &mut controller,
        registry,
        parts,
        &runbook_task_id,
        &recovered_context,
        "RUNBOOK.md",
        RUNBOOK,
    );
    assert!(runbook_success.verification.passed);
    assert_eq!(
        controller.task_state(&runbook_task_id),
        Some(TaskState::Succeeded)
    );
    assert_eq!(
        controller.task_state(&browser_task_id),
        Some(TaskState::Planned)
    );
    assert_eq!(
        fs::read_to_string(fixture.root.join("web/index.html"))
            .unwrap_or_else(|error| panic!("read generated product UI: {error}")),
        INDEX_HTML
    );
    assert_eq!(
        fs::read_to_string(fixture.root.join("RUNBOOK.md"))
            .unwrap_or_else(|error| panic!("read generated product runbook: {error}")),
        RUNBOOK
    );
    run_exact_generated_runbook_verification(&fixture.root);
    (controller, ui_task_id, runbook_task_id, browser_task_id)
}

#[test]
fn local_full_stack_inventory_product_delivery_proof() {
    let fixture = ProductFixture::create();
    let registry = product_registry(&fixture);
    let port = unused_loopback_port();
    let parts = RuntimeParts::new(&fixture);
    let (mut controller, ui_task_id, runbook_task_id, browser_task_id) =
        prepare_product_before_browser(&fixture, &registry, &parts, port);
    let browser_manifest = browser_tool_manifest();
    let browser_config = BrowserAdapterConfig {
        request_timeout_ms: 5_000,
        ..BrowserAdapterConfig::default()
    };
    let browser_ready = controller
        .derive_browser_ready_lease(
            &registry,
            &browser_task_id,
            ReadinessInputs::permissive_m1("sha256:pd-t03-browser-resources"),
            &browser_manifest,
            browser_config.clone(),
        )
        .unwrap_or_else(|error| panic!("derive product browser ready lease: {error}"));
    let browser_backend = new_fake_backend(Vec::new());
    let chrome = Path::new("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
    assert!(chrome.is_file(), "PD-T03 requires real local Google Chrome");
    let mut session = controller
        .acquire_browser_session_from_ready_lease(
            browser_ready,
            &registry,
            &browser_manifest,
            &browser_backend,
            chrome,
            browser_config,
        )
        .unwrap_or_else(|error| panic!("acquire governed product browser: {error}"));
    controller
        .bind_local_inventory_browser_semantics(&session)
        .unwrap_or_else(|error| panic!("bind Controller inventory browser semantics: {error}"));
    let verification_backend = new_fake_backend(Vec::new());
    let verification_runtime = parts.verification_runtime(&registry, &verification_backend);
    let mut app = controller
        .start_managed_loopback_app(
            &session,
            &verification_runtime,
            1,
            Path::new("server.py"),
            "inventory.sqlite3",
        )
        .unwrap_or_else(|error| panic!("start first managed inventory generation: {error}"));
    assert!(app.database_path().starts_with(&fixture.base));
    assert!(!app.database_path().starts_with(&fixture.root));
    let origin = format!("http://127.0.0.1:{port}/");
    let mut browser_receipts = Vec::new();
    assert_browser_crud_search(
        &mut controller,
        &mut session,
        &browser_manifest,
        &parts.artifacts,
        &mut browser_receipts,
        &origin,
    );
    assert_restart_persistence(
        &mut controller,
        &mut session,
        &verification_runtime,
        (&browser_manifest, &parts.artifacts, &mut browser_receipts),
        port,
        &mut app,
    );
    controller
        .prepare_local_inventory_browser_verification(session, &browser_receipts)
        .unwrap_or_else(|error| panic!("prepare governed browser verification: {error}"));
    assert_eq!(
        controller.task_state(&browser_task_id),
        Some(TaskState::Verifying)
    );
    drop(browser_receipts);
    drop(controller);
    let mut controller = recover_product(&fixture, &registry);
    assert_eq!(
        controller.task_state(&browser_task_id),
        Some(TaskState::Verifying)
    );
    let browser_verification = controller
        .resume_local_inventory_browser_verification(&verification_runtime, &browser_task_id)
        .unwrap_or_else(|error| panic!("resume governed browser verification: {error}"));
    assert!(browser_verification.passed);
    assert_eq!(
        controller.task_state(&browser_task_id),
        Some(TaskState::Succeeded)
    );
    assert_controller_clean(&controller);

    drop(controller);
    let controller = recover_product(&fixture, &registry);
    for task_id in [&ui_task_id, &runbook_task_id, &browser_task_id] {
        assert_eq!(controller.task_state(task_id), Some(TaskState::Succeeded));
    }
    assert_controller_clean(&controller);
}
