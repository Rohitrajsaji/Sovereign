//! Production CLI composition. The Controller owns every lifecycle decision and tool action.

use crate::run_lock::RunLock;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sovereign_context::{
    ContextBudget, ContextMode, ContextPacket, ContextPacketInput, ContextPlanner, EvidenceItem,
};
use sovereign_controller::{
    Controller, ExecutionRuntime, PeakRssRecorder, ProductionAdvanceOutcome,
    ProductionAdvanceResources, ProductionBlockReason, ProductionBrowserResources,
    ProductionCompilationResources, ProductionExecutionCatalog, ProductionExecutionResources,
    ReadinessInputs, RoleId, RoleRegistry,
};
use sovereign_evidence::ArtifactStore;
use sovereign_model::{
    LlamaServerLaunch, LocalOpenAiBackend, LocalOpenAiConfig, MODEL_SCHEMA_VERSION, ModelBackend,
    ModelCapabilities, ModelLease, ModelLoadProfile,
};
use sovereign_plan::{
    DepthClassifier, DepthFeatureInput, ExecutionDepth, M3PlanningInput,
    PLAN_COMPILATION_SCHEMA_VERSION, PlanCompilationInput, PlanCompilationRepository,
    PlanValidator, ValidationEnvironment, local_autonomous_plan_policy,
};
use sovereign_policy::{
    CommandPolicy, IsolationRequest, MacSandboxExecBackend, ModelCallBudget, PinnedExecutable,
    ResourcePressureSnapshotV1,
};
use sovereign_repo::{ExactRetriever, ProjectRegistry, RepositoryIntelligence};
use sovereign_state::StateStore;
use sovereign_tools::browser::BrowserAdapterConfig;
use sovereign_tools::{
    canonical_browser_tool_manifest, canonical_patch_tool_manifest, canonical_patch_tool_schema,
    canonical_process_tool_manifest, canonical_read_tool_manifest, canonical_read_tool_schema,
};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::net::{IpAddr, Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::process::Command;
use std::sync::Arc;

const REPOSITORY_ID: &str = "repo.local";
const COMPILER_VERSION: &str = "sovereign-local-v1";
const DEFAULT_STATE: &str = ".sovereign/state.sqlite3";
const MAX_ADVANCES: usize = 64;
const MAX_ADDITIONAL_REPOSITORIES: usize = 8;
const MAX_SOURCE_CANDIDATES: usize = 16;
const MAX_SOURCE_CANDIDATE_BYTES: usize = 16 * 1024;
const MAX_SOURCE_CANDIDATE_TOTAL_BYTES: usize = 48 * 1024;
const PROJECT_CONFIGURATION_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RunOptions {
    once: bool,
}

/// Explicit project-level source scope for production compilation. Additional
/// roots are exact Git roots and candidates are exact relative paths; neither
/// is inferred from goal prose or model output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectConfigurationV1 {
    schema_version: u32,
    #[serde(default)]
    cargo_executable: Option<PathBuf>,
    #[serde(default)]
    additional_repositories: Vec<ConfiguredRepositoryV1>,
    #[serde(default)]
    source_candidates: Vec<ConfiguredSourceCandidateV1>,
}

impl Default for ProjectConfigurationV1 {
    fn default() -> Self {
        Self {
            schema_version: PROJECT_CONFIGURATION_SCHEMA_VERSION,
            cargo_executable: None,
            additional_repositories: Vec::new(),
            source_candidates: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfiguredRepositoryV1 {
    repository_id: String,
    root: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfiguredSourceCandidateV1 {
    repository_id: String,
    relative_path: PathBuf,
}

fn load_project_configuration() -> Result<ProjectConfigurationV1, String> {
    let Some(path) = env::var_os("SOVEREIGN_PROJECT_CONFIG") else {
        return Ok(ProjectConfigurationV1::default());
    };
    let bytes = std::fs::read(&path).map_err(|error| {
        format!(
            "read SOVEREIGN_PROJECT_CONFIG {}: {error}",
            Path::new(&path).display()
        )
    })?;
    let config: ProjectConfigurationV1 = serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse SOVEREIGN_PROJECT_CONFIG: {error}"))?;
    if config.schema_version != PROJECT_CONFIGURATION_SCHEMA_VERSION {
        return Err(format!(
            "unsupported project configuration schema version {}",
            config.schema_version
        ));
    }
    Ok(config)
}

fn parse_options(args: &[String]) -> Result<RunOptions, String> {
    match args {
        [] => Ok(RunOptions { once: false }),
        [flag] if flag == "--once" => Ok(RunOptions { once: true }),
        _ => Err("run accepts only optional --once".to_owned()),
    }
}

fn git_root(cwd: &Path) -> Result<PathBuf, String> {
    let cwd = cwd
        .canonicalize()
        .map_err(|error| format!("canonicalize current directory: {error}"))?;
    for ancestor in cwd.ancestors() {
        if ancestor.join(".git").exists() {
            let mut registry = ProjectRegistry::new();
            return registry
                .register(REPOSITORY_ID, ancestor)
                .map(|repository| repository.root)
                .map_err(|error| format!("validate exact Git root: {error}"));
        }
    }
    Err("run requires a Git working tree".to_owned())
}

fn state_path(root: &Path, override_path: Option<&Path>) -> Result<PathBuf, String> {
    let candidate = override_path.unwrap_or_else(|| Path::new(DEFAULT_STATE));
    let path = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        root.join(candidate)
    };
    let name = path.file_name().ok_or("state database needs a filename")?;
    let parent = path.parent().ok_or("state database needs a parent")?;
    std::fs::create_dir_all(parent).map_err(|error| format!("create state directory: {error}"))?;
    Ok(parent
        .canonicalize()
        .map_err(|error| format!("canonicalize state directory: {error}"))?
        .join(name))
}

fn utc_timestamp(unix_ms: i64) -> Result<String, String> {
    if unix_ms < 0 {
        return Err("goal submission timestamp precedes Unix epoch".to_owned());
    }
    let seconds = unix_ms / 1_000;
    let days = seconds / 86_400;
    let day_seconds = seconds % 86_400;
    // Gregorian civil date from days since the Unix epoch.
    let era = (days + 719_468) / 146_097;
    let day_of_era = days + 719_468 - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_part = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_part + 2) / 5 + 1;
    let month = month_part + if month_part < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        day_seconds / 3_600,
        day_seconds / 60 % 60,
        day_seconds % 60
    ))
}

fn bounded_context(
    goal: &str,
    current_state: &str,
    candidates: Vec<EvidenceItem>,
) -> Result<ContextPacket, String> {
    ContextPlanner::default().build(
        ContextMode::Implementation, ContextBudget::m1_8k(),
        ContextPacketInput {
            controller_prefix: "Sovereign local offline execution; only Controller-authorized actions are available.".to_owned(),
            task_contract: goal.to_owned(),
            current_state: current_state.to_owned(),
            authorized_tool_schemas: Vec::new(),
            candidates,
            output_schema: "Use the exact Controller-selected task contract and governed tool schema.".to_owned(),
        },
    ).map_err(|error| format!("build bounded context: {error}"))
}

/// Model runtime and GGUF paths. Environment variables override settings.
fn configured_model_paths() -> (Option<PathBuf>, Option<PathBuf>) {
    let settings = crate::app_data::AppData::open_default()
        .and_then(|data| data.load_settings())
        .unwrap_or_default();
    let runtime = env::var_os("SOVEREIGN_MODEL_RUNTIME")
        .map(PathBuf::from)
        .or_else(|| settings.model_runtime.as_ref().map(PathBuf::from));
    let model = env::var_os("SOVEREIGN_MODEL_PATH")
        .map(PathBuf::from)
        .or_else(|| settings.model_path.as_ref().map(PathBuf::from));
    (runtime, model)
}

fn configured_model_name() -> String {
    env::var("SOVEREIGN_MODEL_NAME").unwrap_or_else(|_| "Qwen3-4B-Q4_K_M".to_owned())
}

/// Cheap identity for model calibration: canonical path, size, and modification time of the
/// runtime and weights, plus the model name. Replacing either file changes the identity, so the
/// Controller falls back to the uncalibrated estimate until new samples exist.
/// Returns `None` when either file is not configured or cannot be read.
fn model_calibration_identity() -> Option<String> {
    use sha2::{Digest, Sha256};
    let (Some(runtime), Some(model)) = configured_model_paths() else {
        return None;
    };
    let mut hasher = Sha256::new();
    hasher.update(b"sovereign-model-calibration-identity-v1\0");
    for path in [runtime, model] {
        let canonical = path.canonicalize().ok()?;
        let metadata = std::fs::metadata(&canonical).ok()?;
        if !metadata.is_file() {
            return None;
        }
        let modified = metadata
            .modified()
            .ok()?
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_nanos();
        hasher.update(canonical.as_os_str().as_encoded_bytes());
        hasher.update(b"\0");
        hasher.update(metadata.len().to_le_bytes());
        hasher.update(modified.to_le_bytes());
    }
    hasher.update(configured_model_name().as_bytes());
    Some(format!("sha256:{:x}", hasher.finalize()))
}

fn model_backend(require_launch: bool) -> Result<LocalOpenAiBackend, String> {
    let (runtime, model) = configured_model_paths();
    let launch = match (runtime, model) {
        (Some(runtime), Some(model)) => {
            let runtime = runtime
                .canonicalize()
                .map_err(|error| format!("model runtime: {error}"))?;
            let model = model
                .canonicalize()
                .map_err(|error| format!("model path: {error}"))?;
            if !runtime.is_file() || !model.is_file() {
                return Err("model runtime and GGUF must be files".to_owned());
            }
            Some(LlamaServerLaunch {
                executable: runtime,
                model_path: model,
                extra_args: vec!["--reasoning".to_owned(), "off".to_owned()],
            })
        }
        (None, None) if !require_launch => None,
        (None, None) => {
            return Err(
                "SOVEREIGN_MODEL_RUNTIME and SOVEREIGN_MODEL_PATH are required for model work"
                    .to_owned(),
            );
        }
        _ => return Err("model runtime and path must be configured together".to_owned()),
    };
    let port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .and_then(|socket| socket.local_addr())
        .map_err(|error| format!("allocate model loopback port: {error}"))?
        .port();
    let name = configured_model_name();
    let mut config = LocalOpenAiConfig::with_defaults(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        port,
        &name,
        ModelCapabilities {
            schema_version: MODEL_SCHEMA_VERSION,
            model_id: name.clone(),
            parameter_class: "4B".to_owned(),
            quantization: "Q4_K_M".to_owned(),
            max_context_tokens: 16_384,
            supports_tools: true,
            supports_json_schema: true,
            local: true,
        },
    );
    config.launch = launch;
    LocalOpenAiBackend::new(config).map_err(|error| error.to_string())
}

fn load_model(backend: &dyn ModelBackend) -> Result<ModelLease, String> {
    backend
        .load(ModelLoadProfile {
            context_tokens: 8_192,
            output_reserve_tokens: 1_536,
            startup_timeout_ms: 180_000,
            provider_call_timeout_ms: 180_000,
        })
        .map_err(|error| format!("load local model: {error}"))
}

#[expect(
    clippy::too_many_lines,
    reason = "composition validates explicit configured repositories and bounded source evidence"
)]
fn compilation_input(
    controller: &Controller,
    registry: &ProjectRegistry,
    project_config: &ProjectConfigurationV1,
) -> Result<Option<PlanCompilationInput>, String> {
    let Some(intent) = controller
        .next_queued_goal_intent()
        .map_err(|error| error.to_string())?
    else {
        return Ok(None);
    };
    if project_config.schema_version != PROJECT_CONFIGURATION_SCHEMA_VERSION
        || project_config.additional_repositories.len() > MAX_ADDITIONAL_REPOSITORIES
        || project_config.source_candidates.len() > MAX_SOURCE_CANDIDATES
    {
        return Err(
            "project configuration exceeds its versioned repository/source bounds".to_owned(),
        );
    }
    let mut registered_ids = BTreeSet::from([REPOSITORY_ID.to_owned()]);
    for configured in &project_config.additional_repositories {
        if configured.repository_id == REPOSITORY_ID
            || !registered_ids.insert(configured.repository_id.clone())
        {
            return Err(format!(
                "duplicate or reserved configured repository id {:?}",
                configured.repository_id
            ));
        }
    }
    let mut snapshots = BTreeMap::new();
    for repository_id in &registered_ids {
        snapshots.insert(
            repository_id.clone(),
            registry
                .snapshot(repository_id)
                .map_err(|error| error.to_string())?,
        );
    }
    let mut candidate_keys = BTreeSet::new();
    let mut candidate_bytes = 0usize;
    let mut candidates = Vec::with_capacity(project_config.source_candidates.len());
    let mut repository_languages = BTreeMap::<String, BTreeSet<String>>::new();
    let retriever = ExactRetriever::new(registry);
    for candidate in &project_config.source_candidates {
        if !registered_ids.contains(&candidate.repository_id)
            || !candidate_keys.insert((
                candidate.repository_id.clone(),
                candidate.relative_path.clone(),
            ))
        {
            return Err(
                "source candidate repository is unregistered or candidate is duplicated".to_owned(),
            );
        }
        let exact = retriever
            .read_path(&candidate.repository_id, &candidate.relative_path, None)
            .map_err(|error| format!("read configured exact source candidate: {error}"))?;
        let size = usize::try_from(exact.byte_len).unwrap_or(usize::MAX);
        candidate_bytes = candidate_bytes
            .checked_add(size)
            .ok_or("source candidate byte bound overflow")?;
        if size > MAX_SOURCE_CANDIDATE_BYTES || candidate_bytes > MAX_SOURCE_CANDIDATE_TOTAL_BYTES {
            return Err("configured source candidates exceed the bounded evidence size".to_owned());
        }
        let language = match candidate
            .relative_path
            .extension()
            .and_then(|extension| extension.to_str())
        {
            Some("rs") => "rust",
            Some("js" | "mjs" | "jsx") => "javascript",
            Some("ts" | "tsx") => "typescript",
            Some("py") => "python",
            Some("md") => "markdown",
            Some("json") => "json",
            Some("toml") => "toml",
            Some("txt") | None => "text",
            Some(_) => "source",
        };
        repository_languages
            .entry(candidate.repository_id.clone())
            .or_default()
            .insert(language.to_owned());
        candidates.push(EvidenceItem::from_exact_file(
            &exact,
            "explicit versioned project configuration",
        ));
    }
    for (repository_id, initial) in &snapshots {
        let current = registry
            .snapshot(repository_id)
            .map_err(|error| error.to_string())?;
        if current.head != initial.head
            || current.branch != initial.branch
            || current.dirty_digest != initial.dirty_digest
        {
            return Err(format!(
                "repository {repository_id} changed while compilation evidence was assembled"
            ));
        }
    }
    let role = RoleRegistry::canonical()
        .canonical_pin(RoleId::Implementer)
        .map_err(|error| error.to_string())?;
    let patch = canonical_patch_tool_manifest();
    let read = canonical_read_tool_manifest();
    let primary_snapshot = snapshots
        .get(REPOSITORY_ID)
        .ok_or("primary repository snapshot missing")?;
    let additional_snapshots = project_config
        .additional_repositories
        .iter()
        .map(|configured| {
            snapshots
                .get(&configured.repository_id)
                .ok_or_else(|| format!("repository snapshot {} missing", configured.repository_id))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if !additional_snapshots.is_empty()
        && registered_ids
            .iter()
            .any(|repository_id| !repository_languages.contains_key(repository_id))
    {
        return Err(
            "D4 compilation requires at least one explicitly bounded source candidate per repository"
                .to_owned(),
        );
    }
    let context = bounded_context(
        &intent.natural_language_goal,
        &format!(
            "Exact current repositories are Controller-bound: {}.",
            snapshots
                .iter()
                .map(|(id, snapshot)| format!(
                    "{id} head={:?} dirty={}",
                    snapshot.head, snapshot.dirty_digest
                ))
                .collect::<Vec<_>>()
                .join("; ")
        ),
        candidates,
    )?;
    let process = canonical_process_tool_manifest();
    let m3 = if additional_snapshots.is_empty() {
        None
    } else {
        let depth = DepthClassifier.classify(&DepthFeatureInput {
            repository_count: u32::try_from(snapshots.len()).unwrap_or(u32::MAX),
            coordinated_multi_repo_protocol: true,
            verification_available: true,
            ..DepthFeatureInput::default()
        });
        if depth.mode != ExecutionDepth::D4 {
            return Err(
                "explicit coordinated multi-repository input did not classify as D4".to_owned(),
            );
        }
        Some(M3PlanningInput {
            depth,
            supplied_sources: Vec::new(),
            additional_repositories: additional_snapshots
                .iter()
                .map(|snapshot| PlanCompilationRepository {
                    repository_id: snapshot.repository_id.clone(),
                    root: snapshot.root.display().to_string(),
                    head: snapshot.head.clone(),
                    branch: snapshot.branch.clone(),
                    dirty_digest: snapshot.dirty_digest.clone(),
                    protected_changes_present: snapshot.protected_changes_present,
                    languages: repository_languages
                        .get(&snapshot.repository_id)
                        .map(|languages| languages.iter().cloned().collect())
                        .unwrap_or_default(),
                })
                .collect(),
            manual_gates: Vec::new(),
            absence_evaluator: None,
            replan: None,
        })
    };
    Ok(Some(PlanCompilationInput {
        schema_version: PLAN_COMPILATION_SCHEMA_VERSION,
        compilation_id: format!("compile.{}", intent.goal_id),
        compiled_at: utc_timestamp(intent.submitted_at_ms)?,
        project_id: "project.local".to_owned(),
        project_name: "Local Sovereign project".to_owned(),
        workspace_roots: snapshots
            .values()
            .map(|snapshot| snapshot.root.display().to_string())
            .collect(),
        goal_id: intent.goal_id,
        goal_statement: intent.natural_language_goal,
        goal_invariants: Vec::new(),
        goal_non_goals: Vec::new(),
        repository: PlanCompilationRepository {
            repository_id: primary_snapshot.repository_id.clone(),
            root: primary_snapshot.root.display().to_string(),
            head: primary_snapshot.head.clone(),
            branch: primary_snapshot.branch.clone(),
            dirty_digest: primary_snapshot.dirty_digest.clone(),
            protected_changes_present: primary_snapshot.protected_changes_present,
            languages: repository_languages
                .get(REPOSITORY_ID)
                .map(|languages| languages.iter().cloned().collect())
                .unwrap_or_default(),
        },
        policy: local_autonomous_plan_policy(),
        role: serde_json::to_value(role).map_err(|error| error.to_string())?,
        skills: Vec::new(),
        tools: vec![
            json!({"id":patch.tool_id,"version":patch.version,"digest":patch.content_digest}),
            json!({"id":read.tool_id,"version":read.version,"digest":read.content_digest}),
            json!({"id":process.tool_id,"version":process.version,"digest":process.content_digest}),
        ],
        write_tool_id: "tool.patch".to_owned(),
        read_tool_id: "tool.read".to_owned(),
        diff_evaluator: "builtin.diff.scoped_change.v1".to_owned(),
        rollback_diff_evaluator: "builtin.diff.controller_patch_absent.v1".to_owned(),
        context_packet: context,
        m3,
        max_model_calls: 2,
        model_input_token_ceiling: 8_192,
        max_output_tokens: 768,
        model_deadline_ms: 180_000,
    }))
}

#[expect(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "composition passes explicit pinned capabilities without choosing task authority"
)]
fn advance_with_overrides(
    controller: &mut Controller,
    registry: &ProjectRegistry,
    root: &Path,
    state: &Path,
    backend_override: Option<&dyn ModelBackend>,
    node_override: Option<&Path>,
    chrome_override: Option<&Path>,
    project_config: &ProjectConfigurationV1,
) -> Result<ProductionAdvanceOutcome, String> {
    // Fixture backends are not the configured model, so they never calibrate it.
    controller.set_model_calibration_identity(
        backend_override
            .is_none()
            .then(model_calibration_identity)
            .flatten(),
    );
    let probe = controller
        .advance_production_goal(
            registry,
            ProductionAdvanceResources::<MacSandboxExecBackend>::default(),
        )
        .map_err(|error| error.to_string())?;
    match probe {
        ProductionAdvanceOutcome::Blocked {
            reason: ProductionBlockReason::CompilationInputRequired,
            ..
        } => {
            let input = compilation_input(controller, registry, project_config)?
                .ok_or("queued compilation lost its goal intent")?;
            // The configured model is never started without resource-governor admission.
            // Fixture backends start no process, so they skip this gate.
            if backend_override.is_none()
                && let Some(reason) = controller
                    .compilation_model_admission()
                    .map_err(|error| error.to_string())?
            {
                return Ok(ProductionAdvanceOutcome::Blocked {
                    task_id: None,
                    reason: ProductionBlockReason::Readiness(reason),
                });
            }
            let owned_backend = backend_override
                .is_none()
                .then(|| model_backend(true))
                .transpose()?
                .map(Arc::new);
            let backend: &dyn ModelBackend = backend_override
                .or_else(|| {
                    owned_backend
                        .as_deref()
                        .map(|backend| backend as &dyn ModelBackend)
                })
                .ok_or("compilation backend unavailable")?;
            // A cancel for this goal unloads the model, which ends the load or compile call.
            let _interrupt = owned_backend.as_ref().map(|owned| {
                crate::service_state::register_compile_interrupt(
                    &input.goal_id,
                    Arc::clone(owned) as Arc<dyn ModelBackend>,
                )
            });
            let model_lease = load_model(backend)?;
            // Calibration is telemetry, never authority: a failed write must not block work.
            let _ = controller.record_model_load_calibration(&model_lease);
            let recorder = PeakRssRecorder::new(backend);
            let validator = PlanValidator::new(ValidationEnvironment::default())
                .map_err(|error| error.to_string())?;
            let mut budget = ModelCallBudget::new(2, 180_000);
            let result = controller
                .advance_production_goal(
                    registry,
                    ProductionAdvanceResources::<MacSandboxExecBackend> {
                        compilation: Some(ProductionCompilationResources {
                            input: &input,
                            backend: &recorder,
                            validator: &validator,
                            compiler_version: COMPILER_VERSION,
                            model_budget: &mut budget,
                        }),
                        execution: None,
                    },
                )
                .map_err(|error| error.to_string());
            let _ = controller.record_model_call_calibration(recorder.peak_mib());
            backend
                .unload()
                .map_err(|error| format!("unload local model: {error}"))?;
            result
        }
        ProductionAdvanceOutcome::Blocked {
            reason: ProductionBlockReason::ExecutionInputsRequired,
            task_id: Some(task_id),
        } => {
            let owned_backend = backend_override
                .is_none()
                .then(|| model_backend(false))
                .transpose()?;
            let backend: &dyn ModelBackend = backend_override
                .or_else(|| {
                    owned_backend
                        .as_ref()
                        .map(|backend| backend as &dyn ModelBackend)
                })
                .ok_or("execution backend unavailable")?;
            let python = Path::new("/usr/bin/python3")
                .canonicalize()
                .map_err(|error| format!("pin Python: {error}"))?;
            let mut pins = vec![
                PinnedExecutable::from_path(&python, "macos-system-python")
                    .map_err(|error| error.to_string())?,
            ];
            let mut managed_node = None;
            if let Some(cargo) = project_config.cargo_executable.as_ref() {
                let cargo = if cargo.is_absolute() {
                    cargo.clone()
                } else {
                    root.join(cargo)
                }
                .canonicalize()
                .map_err(|error| format!("pin configured cargo executable: {error}"))?;
                if !cargo.is_file() {
                    return Err("configured cargo executable is not a regular file".to_owned());
                }
                pins.push(
                    PinnedExecutable::from_path(&cargo, "configured-local-cargo")
                        .map_err(|error| error.to_string())?,
                );
                let rustc = cargo
                    .parent()
                    .ok_or("configured Cargo has no bin directory")?
                    .join("rustc");
                pins.push(
                    PinnedExecutable::from_path(&rustc, "configured-local-rustc")
                        .map_err(|error| format!("pin configured Cargo's exact rustc: {error}"))?,
                );
            }
            if let Some(node) = node_override
                .map(Path::to_path_buf)
                .or_else(|| env::var_os("SOVEREIGN_NODE_EXECUTABLE").map(PathBuf::from))
            {
                let pin = PinnedExecutable::from_path(node, "configured-local-node")
                    .map_err(|error| error.to_string())?;
                managed_node = Some(pin.path.clone());
                pins.push(pin);
            }
            let roots = pins
                .iter()
                .filter_map(|pin| pin.path.parent().map(Path::to_path_buf));
            let policy =
                CommandPolicy::new(pins.clone(), roots).map_err(|error| error.to_string())?;
            if let Some(node) = managed_node {
                controller
                    .configure_managed_node_executable(&policy, &node)
                    .map_err(|error| error.to_string())?;
            }
            let isolation = MacSandboxExecBackend::detect().map_err(|error| error.to_string())?;
            let state_dir = state
                .parent()
                .ok_or("state database needs a parent")?
                .to_path_buf();
            let home = env::var_os("HOME").ok_or("HOME is required for isolation")?;
            let request = IsolationRequest {
                repository_root: root.to_path_buf(),
                user_home_root: PathBuf::from(home)
                    .canonicalize()
                    .map_err(|error| error.to_string())?,
                extra_protected_read_roots: vec![state.to_path_buf(), state_dir.join("cas")],
                rust_toolchain: None,
                build_scratch_root: None,
                network_offline: true,
                allow_repository_write: true,
                require_full_filesystem_read_jail: false,
            };
            let resource_digest = request.digest().map_err(|error| error.to_string())?;
            let artifacts =
                ArtifactStore::open(state_dir.join("cas")).map_err(|error| error.to_string())?;
            let manifest = canonical_patch_tool_manifest();
            let schemas = vec![
                canonical_patch_tool_schema().map_err(|error| error.to_string())?,
                canonical_read_tool_schema().map_err(|error| error.to_string())?,
            ];
            let context = controller
                .production_task_context(registry, &task_id)
                .map_err(|error| error.to_string())?;
            let read_manifest = canonical_read_tool_manifest();
            let process_manifest = canonical_process_tool_manifest();
            let browser_manifest = canonical_browser_tool_manifest();
            let chrome_path = chrome_override
                .map(Path::to_path_buf)
                .or_else(|| env::var_os("SOVEREIGN_CHROME_EXECUTABLE").map(PathBuf::from))
                .unwrap_or_else(|| {
                    PathBuf::from("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
                });
            let browser = if chrome_path.is_file() {
                Some(ProductionBrowserResources {
                    tool_manifest: &browser_manifest,
                    chrome_path: &chrome_path,
                    adapter_config: BrowserAdapterConfig::default(),
                })
            } else {
                None
            };
            let catalog = ProductionExecutionCatalog {
                read_tool_manifest: &read_manifest,
                process_tool_manifest: &process_manifest,
                browser,
            };
            let mut budget = ModelCallBudget::new(2, 180_000);
            let runtime = ExecutionRuntime {
                registry,
                backend,
                command_policy: &policy,
                isolation_backend: &isolation,
                isolation_request: &request,
                artifacts: &artifacts,
                tool_manifest: &manifest,
                python_executable: &python,
            };
            controller
                .advance_production_goal_with_catalog(
                    registry,
                    ProductionAdvanceResources {
                        compilation: None,
                        execution: Some(ProductionExecutionResources {
                            runtime: &runtime,
                            context: &context,
                            tool_schemas: &schemas,
                            readiness: ReadinessInputs::permissive_m1(&resource_digest),
                            model_budget: &mut budget,
                        }),
                    },
                    Some(&catalog),
                )
                .map_err(|error| error.to_string())
        }
        outcome => Ok(outcome),
    }
}

#[cfg(test)]
fn run_at(root: &Path, state: &Path, options: RunOptions) -> Result<String, String> {
    run_at_with_overrides(root, state, options, None, None, None, None)
}

#[cfg(test)]
fn run_at_with_overrides(
    root: &Path,
    state: &Path,
    options: RunOptions,
    backend_override: Option<&dyn ModelBackend>,
    node_override: Option<&Path>,
    chrome_override: Option<&Path>,
    pressure_override: Option<ResourcePressureSnapshotV1>,
) -> Result<String, String> {
    run_at_with_project_config_and_overrides(
        root,
        state,
        options,
        &ProjectConfigurationV1::default(),
        backend_override,
        node_override,
        chrome_override,
        pressure_override,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "production composition accepts explicit pinned overrides and a test-only pressure probe"
)]
fn run_at_with_project_config_and_overrides(
    root: &Path,
    state: &Path,
    options: RunOptions,
    project_config: &ProjectConfigurationV1,
    backend_override: Option<&dyn ModelBackend>,
    node_override: Option<&Path>,
    chrome_override: Option<&Path>,
    pressure_override: Option<ResourcePressureSnapshotV1>,
) -> Result<String, String> {
    #[cfg(not(test))]
    let _ = pressure_override;
    let _lock = RunLock::acquire(state).map_err(|error| error.to_string())?;
    let mut registry = ProjectRegistry::new();
    registry
        .register(REPOSITORY_ID, root)
        .map_err(|error| error.to_string())?;
    if project_config.schema_version != PROJECT_CONFIGURATION_SCHEMA_VERSION
        || project_config.additional_repositories.len() > MAX_ADDITIONAL_REPOSITORIES
        || project_config.source_candidates.len() > MAX_SOURCE_CANDIDATES
    {
        return Err(
            "project configuration exceeds its versioned repository/source bounds".to_owned(),
        );
    }
    for configured in &project_config.additional_repositories {
        let configured_root = if configured.root.is_absolute() {
            configured.root.clone()
        } else {
            root.join(&configured.root)
        };
        registry
            .register(&configured.repository_id, configured_root)
            .map_err(|error| format!("register configured exact repository: {error}"))?;
    }
    let store = StateStore::open(state).map_err(|error| error.to_string())?;
    let mut controller =
        Controller::reopen_local(store).map_err(|error| format!("recover Controller: {error}"))?;
    #[cfg(test)]
    if let Some(snapshot) = pressure_override {
        controller.set_resource_pressure_probe(Box::new(FixedFixturePressure(snapshot)));
    }
    let mut last = None;
    for _ in 0..MAX_ADVANCES {
        let outcome = advance_with_overrides(
            &mut controller,
            &registry,
            root,
            state,
            backend_override,
            node_override,
            chrome_override,
            project_config,
        )?;
        let continue_running = !options.once
            && matches!(
                outcome,
                ProductionAdvanceOutcome::PlanActivated { .. }
                    | ProductionAdvanceOutcome::TaskVerified { .. }
                    | ProductionAdvanceOutcome::TaskFailed { .. }
                    | ProductionAdvanceOutcome::GoalCompleted { .. }
            );
        last = Some(outcome);
        if !continue_running {
            break;
        }
    }
    let outcome = last.ok_or("runner did not advance Controller")?;
    let summary = format!("{outcome:?}");
    if matches!(
        outcome,
        ProductionAdvanceOutcome::PlanActivated { .. }
            | ProductionAdvanceOutcome::TaskVerified { .. }
            | ProductionAdvanceOutcome::TaskFailed { .. }
            | ProductionAdvanceOutcome::GoalCompleted { .. }
    ) && !options.once
    {
        return Err(format!(
            "run stopped at bounded {MAX_ADVANCES}-step ceiling after {summary}"
        ));
    }
    Ok(format!("state={}\noutcome={summary}", state.display()))
}

#[cfg(test)]
struct FixedFixturePressure(ResourcePressureSnapshotV1);

#[cfg(test)]
impl sovereign_controller::ResourcePressureProbe for FixedFixturePressure {
    fn sample(&mut self) -> std::io::Result<ResourcePressureSnapshotV1> {
        Ok(self.0)
    }
}

pub(crate) fn run_command(args: &[String]) -> Result<String, String> {
    let options = parse_options(args)?;
    let cwd = env::current_dir().map_err(|error| format!("current directory: {error}"))?;
    let root = git_root(&cwd)?;
    let override_path = env::var_os("SOVEREIGN_STATE_DB").map(PathBuf::from);
    let state = state_path(&root, override_path.as_deref())?;
    let project_config = load_project_configuration()?;
    run_at_with_project_config_and_overrides(
        &root,
        &state,
        options,
        &project_config,
        None,
        None,
        None,
        None,
    )
}

pub(crate) fn advance_production_step(
    controller: &mut Controller,
    registry: &ProjectRegistry,
    root: &Path,
    state: &Path,
) -> Result<ProductionAdvanceOutcome, String> {
    let project_config = load_project_configuration().unwrap_or_default();
    #[cfg(any(test, feature = "e2e-fixtures"))]
    if let Some(backend) = crate::fixture_backend::from_context(state) {
        return advance_with_overrides(
            controller,
            registry,
            root,
            state,
            Some(&backend),
            None,
            None,
            &project_config,
        );
    }
    advance_with_overrides(
        controller,
        registry,
        root,
        state,
        None,
        None,
        None,
        &project_config,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use sha2::{Digest, Sha256};
    use sovereign_model::{DeterministicFakeBackend, ModelFinishReason, ModelResponse, ModelUsage};
    use sovereign_plan::{
        BrowserAcceptanceActionV1, BrowserAcceptanceExpectationV1, BrowserAcceptanceSemanticV1,
        BrowserAcceptanceStepV1, BrowserAcceptanceTemplateV1, BrowserManagedAppLaunchV1,
        BrowserManagedArgBindingV1, BrowserManagedPersistenceBindingV1, BrowserManagedReadinessV1,
    };
    use sovereign_policy::{
        OsMemoryPressure, RESOURCE_PRESSURE_EVENT_SCHEMA_VERSION, ThermalPressure,
    };
    use std::fs;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn green_fixture_pressure() -> ResourcePressureSnapshotV1 {
        ResourcePressureSnapshotV1 {
            schema_version: RESOURCE_PRESSURE_EVENT_SCHEMA_VERSION,
            observed_at_ms: 1_000,
            controlled_working_set_mib: 512,
            host_headroom_mib: 6_144,
            swap_used_mib: Some(4_096),
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

    static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    static RUNNER_LOCK_TEST: Mutex<()> = Mutex::new(());

    #[expect(
        clippy::expect_used,
        reason = "deterministic runner fixture requires exact setup and evidence assertions"
    )]
    fn fixture() -> PathBuf {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let sequence = FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root =
            PathBuf::from(env::var_os("HOME").expect("HOME for isolated fixture")).join(format!(
                ".sovereign-runner-{}-{timestamp}-{sequence}",
                std::process::id()
            ));
        fs::create_dir_all(&root).expect("fixture directory");
        let status = Command::new("/usr/bin/git")
            .arg("init")
            .arg("-q")
            .arg(&root)
            .status()
            .expect("git init");
        assert!(status.success());
        let initial_commit = Command::new("/usr/bin/git")
            .arg("-C")
            .arg(&root)
            .args(["-c", "user.name=Sovereign Fixture"])
            .args(["-c", "user.email=fixture@localhost"])
            .args(["commit", "--allow-empty", "-qm", "fixture baseline"])
            .status()
            .expect("create Git baseline");
        assert!(initial_commit.success());
        root
    }

    #[expect(
        clippy::expect_used,
        reason = "deterministic runner fixture requires exact setup and evidence assertions"
    )]
    fn compilation_fixture_backend() -> DeterministicFakeBackend {
        DeterministicFakeBackend::new(
            ModelCapabilities {
                schema_version: MODEL_SCHEMA_VERSION,
                model_id: "sovereign-run-once-fixture".to_owned(),
                parameter_class: "4B".to_owned(),
                quantization: "Q4_K_M".to_owned(),
                max_context_tokens: 16_384,
                supports_tools: false,
                supports_json_schema: true,
                local: true,
            },
            vec![ModelResponse {
                schema_version: MODEL_SCHEMA_VERSION,
                request_id: "fixture-response".to_owned(),
                content: json!({
                    "tasks": [{
                        "title": "Inspect the local inventory app",
                        "objective": "Verify the local inventory app through the granted browser contract.",
                        "rationale": "The goal requests a bounded, read-only application check.",
                        "files": [],
                        "symbols": [],
                        "evidence_queries": [],
                        "expected_change": "The local app is verified without repository mutation."
                    }]
                })
                .to_string(),
                structured: None,
                tool_calls: Vec::new(),
                finish_reason: ModelFinishReason::Stop,
                usage: ModelUsage::default(),
                elapsed_ms: 0,
                peak_rss_kb_during_call: None,
            }],
        )
        .expect("fixture backend")
    }

    fn fixture_model_response(content: impl Into<String>) -> ModelResponse {
        ModelResponse {
            schema_version: MODEL_SCHEMA_VERSION,
            request_id: "fixture.response".to_owned(),
            content: content.into(),
            structured: None,
            tool_calls: Vec::new(),
            finish_reason: ModelFinishReason::Stop,
            usage: ModelUsage {
                input_tokens: 400,
                output_tokens: 160,
            },
            elapsed_ms: 1,
            peak_rss_kb_during_call: None,
        }
    }

    #[expect(
        clippy::expect_used,
        reason = "deterministic runner fixture requires exact setup and evidence assertions"
    )]
    fn fixture_backend(responses: Vec<ModelResponse>) -> DeterministicFakeBackend {
        DeterministicFakeBackend::new(
            ModelCapabilities {
                schema_version: MODEL_SCHEMA_VERSION,
                model_id: "sovereign-run-once-fixture".to_owned(),
                parameter_class: "4B".to_owned(),
                quantization: "Q4_K_M".to_owned(),
                max_context_tokens: 16_384,
                supports_tools: false,
                supports_json_schema: true,
                local: true,
            },
            responses,
        )
        .expect("fixture backend")
    }

    fn sha256_text(text: &str) -> String {
        format!("sha256:{:x}", Sha256::digest(text.as_bytes()))
    }

    #[expect(
        clippy::needless_pass_by_value,
        reason = "fixture builds a self-contained typed command contract"
    )]
    fn command_acceptance(
        description: &str,
        repository_id: &str,
        program: &str,
        args: Vec<String>,
    ) -> Value {
        json!({
            "kind": "command",
            "description": description,
            "manual_gate_id": Value::Null,
            "command_spec": {
                "tool_id": "tool.process",
                "mode": "exec",
                "program": program,
                "args": args,
                "repository_id": repository_id,
                "working_dir_relative": ".",
                "literal_env": {},
                "secret_env": {},
                "timeout_seconds": 180,
                "output_limit_bytes": 4096
            },
            "expected_exit_codes": [0]
        })
    }

    fn cargo_acceptance(description: &str, repository_id: &str, target_dir: &Path) -> Value {
        command_acceptance(
            description,
            repository_id,
            "cargo",
            vec![
                "--offline".to_owned(),
                "test".to_owned(),
                "--target-dir".to_owned(),
                target_dir.display().to_string(),
                "--test".to_owned(),
                "protocol".to_owned(),
                "--".to_owned(),
                "--quiet".to_owned(),
            ],
        )
    }

    fn c7_m3_proposal(target_base: &Path) -> String {
        let primary_write = json!({
            "local_id": "write.primary",
            "repository_id": REPOSITORY_ID,
            "title": "Update the primary protocol state",
            "objective": "Set the scoped protocol status to approved while preserving its contract marker.",
            "rationale": "The exact current source and deterministic command acceptance define the change.",
            "files": ["src/contract.txt"],
            "symbols": [],
            "dependencies": [],
            "evidence_needs": [],
            "expected_change": "status=approved",
            "acceptance": [
                cargo_acceptance(
                    "The primary protocol status is approved.",
                    REPOSITORY_ID,
                    &target_base.join("primary"),
                )
            ]
        });
        let inspect_shared = json!({
            "local_id": "inspect.shared",
            "repository_id": "repo.shared",
            "title": "Verify the shared protocol contract",
            "objective": "Verify that the second registered repository publishes the protocol marker.",
            "rationale": "The cross-repository gate must depend on exact evidence from both repositories.",
            "files": [],
            "symbols": [],
            "dependencies": ["write.primary"],
            "evidence_needs": [],
            "expected_change": "The shared wire-format contract is verified.",
            "acceptance": [cargo_acceptance(
                "The shared repository contains the required wire format.",
                "repo.shared",
                &target_base.join("shared"),
            )]
        });
        let integration = json!({
            "local_id": "integration.contract",
            "repository_id": REPOSITORY_ID,
            "integration_repository_ids": [REPOSITORY_ID, "repo.shared"],
            "title": "Verify the cross-repository protocol contract",
            "objective": "Run exact repository-scoped checks against both composed integration views.",
            "rationale": "The gate depends on the primary write and shared repository verification.",
            "files": [],
            "symbols": [],
            "dependencies": ["inspect.shared"],
            "evidence_needs": [],
            "expected_change": "Both repositories expose the same wire-format contract.",
            "acceptance": [
                cargo_acceptance(
                    "The primary integration view exposes the protocol marker.",
                    REPOSITORY_ID,
                    &target_base.join("primary"),
                ),
                cargo_acceptance(
                    "The shared integration view exposes the protocol marker.",
                    "repo.shared",
                    &target_base.join("shared"),
                )
            ]
        });
        json!({"tasks": [primary_write, inspect_shared, integration]}).to_string()
    }

    fn update_proposal(source_digest: &str, content: &str) -> String {
        json!({
            "schema_version": 1,
            "evidence_ids": ["file:repo.local:src/contract.txt"],
            "action": {
                "kind": "update_file",
                "repository_id": REPOSITORY_ID,
                "path": "src/contract.txt",
                "expected_source_digest": source_digest,
                "content": content
            }
        })
        .to_string()
    }

    fn browser_grant_template() -> BrowserAcceptanceTemplateV1 {
        BrowserAcceptanceTemplateV1 {
            launch: BrowserManagedAppLaunchV1::NodeManagedServerV1 {
                working_directory_relative_path: "apps/inventory".to_owned(),
                entrypoint_relative_path: "server.js".to_owned(),
                argv: Vec::new(),
                dynamic_port: BrowserManagedArgBindingV1::ArgvFlag {
                    flag: "--port".to_owned(),
                },
                readiness: BrowserManagedReadinessV1 {
                    path: "/health".to_owned(),
                    status: 200,
                    body: "ok".to_owned(),
                    timeout_ms: 5_000,
                },
                persistence: BrowserManagedPersistenceBindingV1::ArgvFlag {
                    flag: "--db".to_owned(),
                    filename: "inventory.sqlite3".to_owned(),
                },
                required_generations: 1,
            },
            steps: vec![
                BrowserAcceptanceStepV1 {
                    step_id: "inventory.open".to_owned(),
                    generation: 1,
                    action: BrowserAcceptanceActionV1::Navigate {
                        path: "/".to_owned(),
                    },
                    expectation: BrowserAcceptanceExpectationV1 {
                        semantic: BrowserAcceptanceSemanticV1::Read,
                        required_contains: Vec::new(),
                        forbidden_contains: Vec::new(),
                    },
                },
                BrowserAcceptanceStepV1 {
                    step_id: "inventory.visible".to_owned(),
                    generation: 1,
                    action: BrowserAcceptanceActionV1::CaptureSynopsis,
                    expectation: BrowserAcceptanceExpectationV1 {
                        semantic: BrowserAcceptanceSemanticV1::Read,
                        required_contains: vec!["Inventory dashboard".to_owned()],
                        forbidden_contains: Vec::new(),
                    },
                },
            ],
        }
    }

    #[expect(
        clippy::expect_used,
        clippy::needless_raw_string_hashes,
        reason = "deterministic runner fixture requires exact setup and evidence assertions"
    )]
    fn prepare_inventory_fixture(root: &Path) -> (PathBuf, PathBuf) {
        let app = root.join("apps/inventory");
        fs::create_dir_all(&app).expect("inventory app directory");
        fs::write(
            app.join("server.js"),
            r#"const http = require('node:http');
const args = process.argv.slice(2);
const value = (flag) => args[args.indexOf(flag) + 1];
const port = Number(value('--port'));
if (!port || !value('--db')) process.exit(2);
http.createServer((request, response) => {
  if (request.url === '/health') { response.writeHead(200); response.end('ok'); return; }
  response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
  response.end('<!doctype html><title>Inventory dashboard</title><h1>Inventory dashboard</h1>');
}).listen(port, '127.0.0.1');
"#,
        )
        .expect("write fixture Node app");
        let node = env::split_paths(&env::var_os("PATH").unwrap_or_default())
            .map(|directory| directory.join("node"))
            .find(|path| path.is_file())
            .expect("installed Node executable")
            .canonicalize()
            .expect("canonical Node executable");
        let chrome = env::var_os("SOVEREIGN_CHROME_EXECUTABLE")
            .map_or_else(
                || PathBuf::from("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
                PathBuf::from,
            )
            .canonicalize()
            .expect("installed Chrome executable");
        (node, chrome)
    }

    #[expect(
        clippy::expect_used,
        reason = "deterministic runner fixture requires exact setup and evidence assertions"
    )]
    fn external_fixture_state(root: &Path) -> PathBuf {
        let name = root
            .file_name()
            .and_then(|value| value.to_str())
            .expect("fixture root name");
        root.parent()
            .expect("fixture parent")
            .join(format!("{name}-external-state"))
            .join("state.sqlite3")
    }

    #[expect(
        clippy::expect_used,
        reason = "deterministic runner fixture requires exact setup and evidence assertions"
    )]
    fn commit_fixture_file(root: &Path, relative: &str, content: &str) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().expect("fixture file parent")).expect("fixture dirs");
        fs::write(path, content).expect("fixture source");
        let add = Command::new("/usr/bin/git")
            .arg("-C")
            .arg(root)
            .args(["add", "--", relative])
            .status()
            .expect("git add fixture");
        assert!(add.success());
        let commit = Command::new("/usr/bin/git")
            .arg("-C")
            .arg(root)
            .args(["-c", "user.name=Sovereign Fixture"])
            .args(["-c", "user.email=fixture@localhost"])
            .args(["commit", "-qm", "fixture source"])
            .status()
            .expect("commit fixture source");
        assert!(commit.success());
    }

    #[expect(
        clippy::expect_used,
        reason = "deterministic runner fixture requires exact setup and evidence assertions"
    )]
    fn rustup_cargo() -> PathBuf {
        let rustup = PathBuf::from(env::var_os("HOME").expect("HOME")).join(".cargo/bin/rustup");
        let output = Command::new(rustup)
            .args(["which", "cargo"])
            .output()
            .expect("resolve exact local Cargo executable");
        assert!(output.status.success(), "rustup which cargo failed");
        PathBuf::from(
            String::from_utf8(output.stdout)
                .expect("Cargo path UTF-8")
                .trim(),
        )
        .canonicalize()
        .expect("canonical Cargo executable")
    }

    #[expect(
        clippy::expect_used,
        reason = "deterministic runner fixture requires exact setup and evidence assertions"
    )]
    fn prepare_protocol_cargo_fixture(root: &Path, package: &str, test_source: &str) {
        commit_fixture_file(
            root,
            "Cargo.toml",
            &format!("[package]\nname = \"{package}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"),
        );
        commit_fixture_file(root, "tests/protocol.rs", test_source);
        let status = Command::new(rustup_cargo())
            .args(["generate-lockfile", "--offline"])
            .current_dir(root)
            .status()
            .expect("generate fixture lockfile");
        assert!(
            status.success(),
            "fixture lockfile must be generated offline"
        );
        let lock = std::fs::read_to_string(root.join("Cargo.lock")).expect("fixture lockfile");
        commit_fixture_file(root, "Cargo.lock", &lock);
    }

    #[expect(
        clippy::expect_used,
        reason = "deterministic runner fixture requires exact setup and evidence assertions"
    )]
    fn queued_compilation(state: &Path, goal: &str) -> Controller {
        let mut control = sovereign_controller::LocalControl::reopen(
            StateStore::open(state).expect("open queued goal state"),
        )
        .expect("open queued goal control");
        control.submit_goal(goal).expect("queue fixture goal");
        drop(control);
        Controller::reopen_local(StateStore::open(state).expect("reopen queued state"))
            .expect("recover queued Controller")
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "deterministic runner fixture requires exact setup and evidence assertions"
    )]
    fn run_cli_accepts_only_once_flag() {
        assert_eq!(
            parse_options(&[]).expect("default"),
            RunOptions { once: false }
        );
        assert_eq!(
            parse_options(&["--once".to_owned()]).expect("once"),
            RunOptions { once: true }
        );
        assert!(parse_options(&["--root".to_owned()]).is_err());
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "deterministic runner fixture requires exact setup and evidence assertions"
    )]
    fn subdirectory_resolves_exact_git_root_and_relative_state() {
        let root = fixture();
        let child = root.join("src");
        fs::create_dir(&child).expect("child");
        assert_eq!(
            git_root(&child).expect("root"),
            root.canonicalize().expect("canonical")
        );
        assert_eq!(
            state_path(&root, None).expect("state"),
            root.canonicalize().expect("canonical").join(DEFAULT_STATE)
        );
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "deterministic runner fixture requires exact setup and evidence assertions"
    )]
    fn goal_timestamp_uses_canonical_utc_format() {
        assert_eq!(utc_timestamp(0).expect("epoch"), "1970-01-01T00:00:00Z");
        assert_eq!(
            utc_timestamp(1_700_000_000_000).expect("later"),
            "2023-11-14T22:13:20Z"
        );
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "deterministic runner fixture requires exact setup and evidence assertions"
    )]
    fn production_compilation_includes_explicit_bounded_current_source_candidates() {
        let root = fixture();
        commit_fixture_file(&root, "src/contract.md", "# Exact current contract\n");
        let state = external_fixture_state(&root);
        let controller = queued_compilation(&state, "Implement the contract in this repository");
        let mut registry = ProjectRegistry::new();
        registry
            .register(REPOSITORY_ID, &root)
            .expect("register exact primary repository");

        let config = ProjectConfigurationV1 {
            source_candidates: vec![ConfiguredSourceCandidateV1 {
                repository_id: REPOSITORY_ID.to_owned(),
                relative_path: PathBuf::from("src/contract.md"),
            }],
            ..ProjectConfigurationV1::default()
        };
        let input = compilation_input(&controller, &registry, &config)
            .expect("construct compilation input")
            .expect("queued goal input");

        assert!(
            input.context_packet.items.iter().any(|item| {
                item.repository_id.as_deref() == Some(REPOSITORY_ID)
                    && item.locator.as_deref() == Some("path:src/contract.md")
                    && item.text == "# Exact current contract\n"
            }),
            "production compilation must receive the exact configured source candidate"
        );
        fs::remove_dir_all(root).expect("cleanup source evidence fixture");
        fs::remove_dir_all(state.parent().expect("state directory"))
            .expect("cleanup state fixture");
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "deterministic runner fixture requires exact setup and evidence assertions"
    )]
    fn production_compilation_includes_explicit_additional_repository_snapshots_for_m3() {
        let root = fixture();
        let second = fixture();
        commit_fixture_file(&root, "src/primary.txt", "primary\n");
        commit_fixture_file(&second, "src/shared.txt", "shared\n");
        let state = external_fixture_state(&root);
        let controller = queued_compilation(&state, "Coordinate the two registered repositories");
        let mut registry = ProjectRegistry::new();
        registry
            .register(REPOSITORY_ID, &root)
            .expect("register exact primary repository");
        registry
            .register("repo.shared", &second)
            .expect("register explicitly configured additional repository");

        let config = ProjectConfigurationV1 {
            additional_repositories: vec![ConfiguredRepositoryV1 {
                repository_id: "repo.shared".to_owned(),
                root: second.clone(),
            }],
            source_candidates: vec![
                ConfiguredSourceCandidateV1 {
                    repository_id: REPOSITORY_ID.to_owned(),
                    relative_path: PathBuf::from("src/primary.txt"),
                },
                ConfiguredSourceCandidateV1 {
                    repository_id: "repo.shared".to_owned(),
                    relative_path: PathBuf::from("src/shared.txt"),
                },
            ],
            ..ProjectConfigurationV1::default()
        };
        let input = compilation_input(&controller, &registry, &config)
            .expect("construct compilation input")
            .expect("queued goal input");

        let m3 = input
            .m3
            .as_ref()
            .expect("multiple exact registered repositories require M3 inputs");
        assert_eq!(m3.additional_repositories.len(), 1);
        assert_eq!(m3.additional_repositories[0].repository_id, "repo.shared");
        assert_eq!(m3.depth.mode, sovereign_plan::ExecutionDepth::D4);
        assert_eq!(input.workspace_roots.len(), 2);
        for (repository_id, path, contents) in [
            (REPOSITORY_ID, "path:src/primary.txt", "primary\n"),
            ("repo.shared", "path:src/shared.txt", "shared\n"),
        ] {
            assert!(
                input.context_packet.items.iter().any(|item| {
                    item.repository_id.as_deref() == Some(repository_id)
                        && item.locator.as_deref() == Some(path)
                        && item.text == contents
                }),
                "exact source candidate {repository_id}/{path} is missing from bounded context"
            );
        }
        fs::remove_dir_all(root).expect("cleanup primary fixture");
        fs::remove_dir_all(second).expect("cleanup additional fixture");
        fs::remove_dir_all(state.parent().expect("state directory"))
            .expect("cleanup state fixture");
    }

    #[test]
    #[expect(
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::too_many_lines,
        reason = "deterministic runner fixture requires exact setup and evidence assertions"
    )]
    fn sovereign_run_once_writes_repairs_and_verifies_a_two_repository_d4_goal_across_restart() {
        let _guard = RUNNER_LOCK_TEST
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let root = fixture();
        let shared = fixture();
        commit_fixture_file(&root, "src/contract.txt", "status=draft\nwire-format=v1\n");
        commit_fixture_file(&shared, "src/contract.txt", "wire-format=v1\n");
        prepare_protocol_cargo_fixture(
            &root,
            "primary-contract",
            "#[test]\nfn status_and_wire_format_are_approved() {\n    let contents = std::fs::read_to_string(\"src/contract.txt\").unwrap();\n    assert!(contents.starts_with(\"status=approved\\n\"));\n    assert!(contents.contains(\"wire-format=v1\"));\n}\n",
        );
        prepare_protocol_cargo_fixture(
            &shared,
            "shared-contract",
            "#[test]\nfn wire_format_is_published() {\n    let contents = std::fs::read_to_string(\"src/contract.txt\").unwrap();\n    assert!(contents.contains(\"wire-format=v1\"));\n}\n",
        );
        let state = external_fixture_state(&root);
        let target_base = PathBuf::from("/tmp").join(format!(
            "sovereign-c7-{}",
            root.file_name().expect("fixture name").to_string_lossy()
        ));
        let cargo = rustup_cargo();
        let config = ProjectConfigurationV1 {
            cargo_executable: Some(cargo),
            additional_repositories: vec![ConfiguredRepositoryV1 {
                repository_id: "repo.shared".to_owned(),
                root: shared.clone(),
            }],
            source_candidates: vec![
                ConfiguredSourceCandidateV1 {
                    repository_id: REPOSITORY_ID.to_owned(),
                    relative_path: PathBuf::from("src/contract.txt"),
                },
                ConfiguredSourceCandidateV1 {
                    repository_id: "repo.shared".to_owned(),
                    relative_path: PathBuf::from("src/contract.txt"),
                },
            ],
            ..ProjectConfigurationV1::default()
        };
        let mut control = sovereign_controller::LocalControl::reopen(
            StateStore::open(&state).expect("open state"),
        )
        .expect("open control");
        let intent = control
            .submit_goal("Coordinate the exact protocol state in both registered repositories")
            .expect("queue explicit multi-repository goal");
        drop(control);

        let compile_backend =
            fixture_backend(vec![fixture_model_response(c7_m3_proposal(&target_base))]);
        let compile = run_at_with_project_config_and_overrides(
            &root,
            &state,
            RunOptions { once: true },
            &config,
            Some(&compile_backend),
            None,
            None,
            Some(green_fixture_pressure()),
        )
        .expect("compile and activate the queued D4 goal");
        assert!(compile.contains("PlanActivated"), "{compile}");
        let store = StateStore::open(&state).expect("state after compile");
        let plan_json = store
            .get_state("controller.plan_document", "active")
            .expect("read active plan")
            .expect("compiled plan");
        let plan: Value = serde_json::from_str(&plan_json).expect("parse compiled plan");
        let plan_id = plan["plan_id"].as_str().expect("plan id").to_owned();
        let tasks = plan["tasks"].as_array().expect("compiled tasks");
        assert_eq!(tasks.len(), 3);
        let write_task = tasks
            .iter()
            .find(|task| task["scope"]["files"] == json!(["src/contract.txt"]))
            .expect("one scoped primary repository write task");
        let write_task_id = write_task["task_id"]
            .as_str()
            .expect("write task id")
            .to_owned();
        let integration_task = tasks
            .iter()
            .find(|task| {
                task["scope"]["repositories"]
                    .as_array()
                    .is_some_and(|ids| ids.len() == 2)
            })
            .expect("genuine two-repository integration task");
        let integration_task_id = integration_task["task_id"]
            .as_str()
            .expect("integration task id")
            .to_owned();
        let integration_repositories = integration_task["scope"]["repositories"]
            .as_array()
            .expect("exact integration repository scope")
            .iter()
            .filter_map(Value::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            integration_repositories,
            BTreeSet::from([REPOSITORY_ID, "repo.shared"])
        );
        let baseline_digest = ExactRetriever::new(&{
            let mut registry = ProjectRegistry::new();
            registry
                .register(REPOSITORY_ID, &root)
                .expect("register source repo");
            registry
        })
        .read_path(REPOSITORY_ID, Path::new("src/contract.txt"), None)
        .expect("read exact baseline")
        .digest;
        let failed_write_backend = fixture_backend(vec![fixture_model_response(update_proposal(
            &baseline_digest,
            "status=wrong\nwire-format=v1\n",
        ))]);
        let failed = run_at_with_project_config_and_overrides(
            &root,
            &state,
            RunOptions { once: true },
            &config,
            Some(&failed_write_backend),
            None,
            None,
            Some(green_fixture_pressure()),
        )
        .expect("first governed write reaches deterministic verification");
        assert!(
            failed.contains("TaskFailed"),
            "first verification must fail: {failed}"
        );
        let controller =
            Controller::reopen_local(StateStore::open(&state).expect("reopen failed state"))
                .expect("recover failed attempt");
        assert_eq!(
            controller.task_state(&write_task_id),
            Some(sovereign_controller::TaskState::RepairPending)
        );
        let failure = controller
            .latest_failure_record(&write_task_id)
            .expect("read durable failure record")
            .expect("verification failure is durable");
        assert_eq!(failure.plan_id, plan_id);
        assert_eq!(failure.task_id, write_task_id);
        assert_eq!(failure.decision, "repair");

        let post_failure_digest = sha256_text("status=wrong\nwire-format=v1\n");
        let repair_backend = fixture_backend(vec![fixture_model_response(update_proposal(
            &post_failure_digest,
            "status=approved\nwire-format=v1\n",
        ))]);
        drop(controller);
        let repaired = run_at_with_project_config_and_overrides(
            &root,
            &state,
            RunOptions { once: true },
            &config,
            Some(&repair_backend),
            None,
            None,
            Some(green_fixture_pressure()),
        )
        .expect("execute Controller-governed repair after restart");
        assert!(
            repaired.contains("TaskVerified"),
            "repair verification: {repaired}"
        );

        for expected in ["TaskVerified", "TaskVerified", "GoalCompleted", "Complete"] {
            let stage_backend = fixture_backend(Vec::new());
            let result = run_at_with_project_config_and_overrides(
                &root,
                &state,
                RunOptions { once: true },
                &config,
                Some(&stage_backend),
                None,
                None,
                Some(green_fixture_pressure()),
            )
            .unwrap_or_else(|error| panic!("advance {expected} after restart: {error}"));
            assert!(
                result.contains(expected),
                "expected {expected}, got {result}"
            );
        }

        let finalized_store = StateStore::open(&state).expect("open finalized state");
        let finalized =
            Controller::reopen_local(finalized_store).expect("recover finalized controller");
        let status = finalized.durable_status().expect("final durable status");
        assert!(status.active_plan.is_none());
        assert!(
            status.tasks.is_empty(),
            "finalization clears the active projection"
        );
        let evidence_store = StateStore::open(&state).expect("archived C7 evidence");
        let scope = format!("{plan_id}@r1:");
        let archived_tasks = evidence_store
            .state_records("controller.task")
            .expect("archived tasks")
            .into_iter()
            .filter(|record| record.key.starts_with(&scope))
            .map(|record| {
                (
                    record.key,
                    serde_json::from_str::<Value>(&record.value_json).unwrap(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(archived_tasks.len(), 3);
        assert!(
            archived_tasks
                .values()
                .all(|task| task["state"] == "succeeded")
        );
        let archived_evidence = evidence_store
            .state_records("controller.verification")
            .expect("archived verification")
            .into_iter()
            .filter(|record| record.key.starts_with(&scope))
            .map(|record| serde_json::from_str::<Value>(&record.value_json).unwrap())
            .collect::<Vec<_>>();
        let actions_before_restart = status
            .actions
            .iter()
            .map(|action| action.action_id.clone())
            .collect::<BTreeSet<_>>();
        let output_root = archived_tasks
            .get(&format!("{scope}{write_task_id}"))
            .and_then(|task| task["worktree_lease"]["worktree_path"].as_str())
            .map(PathBuf::from)
            .expect("durable write worktree path");
        let archived_write = &archived_tasks[&format!("{scope}{write_task_id}")];
        assert_eq!(archived_write["worktree_state"], "released");
        assert!(
            !output_root.exists(),
            "verified task worktree must be released"
        );
        let artifact_store =
            ArtifactStore::open(state.parent().unwrap().join("cas")).expect("result CAS");
        let change_set: Value = serde_json::from_reader(
            artifact_store
                .open_artifact(
                    &evidence_store,
                    archived_write["change_set_artifact_digest"]
                        .as_str()
                        .expect("change-set CAS digest"),
                )
                .expect("verified change-set CAS object"),
        )
        .expect("decode durable change set");
        assert_eq!(change_set, archived_write["change_set"]);
        assert_eq!(change_set["plan_id"], plan_id);
        assert_eq!(change_set["task_id"], write_task_id);
        assert_eq!(change_set["repository_id"], REPOSITORY_ID);
        assert_eq!(change_set["changed_paths"], json!(["src/contract.txt"]));
        assert_eq!(
            change_set["diff_content"]
                .as_str()
                .unwrap()
                .lines()
                .skip(4)
                .collect::<Vec<_>>(),
            vec![
                "@@ -1,2 +1,2 @@",
                "-status=draft",
                "+status=approved",
                " wire-format=v1"
            ]
        );
        let integration_evidence = archived_evidence
            .iter()
            .find(|evidence| {
                evidence["task_id"] == integration_task_id && evidence["passed"] == true
            })
            .expect("accepted integration evidence bound to exact task");
        assert_eq!(integration_evidence["plan_id"], plan_id);
        assert_eq!(
            integration_evidence["command_results"]
                .as_array()
                .map(Vec::len),
            Some(2)
        );
        let verification_steps = integration_task["verification"]["steps"]
            .as_array()
            .expect("integration command verification steps");
        let verified_repositories = verification_steps
            .iter()
            .filter_map(|step| step["command_spec"]["repository_id"].as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            verified_repositories,
            BTreeSet::from([REPOSITORY_ID, "repo.shared"])
        );

        // Every verification receipt must prove group cleanup before finalization.
        // Also check live group membership, rather than only the leader's absence.
        let live_groups = Command::new("/bin/ps")
            .args(["-axo", "pgid="])
            .output()
            .expect("inspect remaining process groups");
        assert!(live_groups.status.success());
        let live_groups = String::from_utf8(live_groups.stdout).expect("process groups UTF-8");
        let live_groups = live_groups.split_whitespace().collect::<BTreeSet<_>>();
        let mut verified_actions = BTreeSet::new();
        for evidence in &archived_evidence {
            if let Some(commands) = evidence["command_results"].as_array() {
                for result in commands {
                    let action_id = result["action_id"]
                        .as_str()
                        .expect("verification action ID");
                    assert_eq!(result["process_group_reaped"], true);
                    let lease: Value = serde_json::from_str(
                        &evidence_store
                            .get_state("controller.process_lease", action_id)
                            .expect("process lease")
                            .expect("durable process lease"),
                    )
                    .expect("decode process lease");
                    assert_eq!(lease["state"], "reaped");
                    let pgid = lease["process_group_id"]
                        .as_u64()
                        .expect("process group ID")
                        .to_string();
                    assert!(
                        !live_groups.contains(pgid.as_str()),
                        "verification group {pgid} survived"
                    );
                    verified_actions.insert(action_id.to_owned());
                }
            }
        }
        assert!(
            verified_actions.len() >= 4,
            "failed write, repair, and both D4 commands need receipts"
        );
        assert_eq!(
            fs::read_to_string(root.join("src/contract.txt")).unwrap(),
            "status=draft\nwire-format=v1\n"
        );
        assert_eq!(
            fs::read_to_string(shared.join("src/contract.txt")).unwrap(),
            "wire-format=v1\n"
        );
        eprintln!(
            "C7 goal={} plan={} write={} integration={} verification_actions={verified_actions:?}",
            intent.goal_id, plan_id, write_task_id, integration_task_id
        );
        drop(evidence_store);

        let restarted = run_at_with_project_config_and_overrides(
            &root,
            &state,
            RunOptions { once: true },
            &config,
            Some(&fixture_backend(Vec::new())),
            None,
            None,
            Some(green_fixture_pressure()),
        )
        .expect("restart after finalization without replay");
        assert!(restarted.contains("Idle"), "{restarted}");
        let after_restart =
            Controller::reopen_local(StateStore::open(&state).expect("restart state"))
                .expect("recover after finalization");
        let actions_after_restart = after_restart
            .durable_status()
            .expect("post-restart status")
            .actions
            .into_iter()
            .map(|action| action.action_id)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            actions_after_restart, actions_before_restart,
            "no completed action replayed"
        );
        let completion = StateStore::open(&state)
            .expect("completion state")
            .get_state("controller.plan_finalization", &format!("{plan_id}@r1"))
            .expect("read finalization")
            .expect("durable finalization receipt");
        let completion: Value = serde_json::from_str(&completion).expect("parse finalization");
        assert_eq!(completion["goal_id"], intent.goal_id);
        assert_eq!(completion["plan_id"], plan_id);

        fs::remove_dir_all(root).expect("cleanup primary repo fixture");
        fs::remove_dir_all(shared).expect("cleanup shared repo fixture");
        fs::remove_dir_all(state.parent().expect("external state directory"))
            .expect("cleanup external state and controller worktrees");
        let _ = fs::remove_dir_all(target_base);
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "deterministic runner fixture requires exact setup and evidence assertions"
    )]
    fn idle_run_reopens_same_state_after_restart_and_holds_lock() {
        let _guard = RUNNER_LOCK_TEST
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let root = fixture();
        let state = state_path(&root, None).expect("state");
        let first = run_at(&root, &state, RunOptions { once: true }).expect("first idle run");
        assert!(first.contains("Idle"));
        let held = RunLock::acquire(&state).expect("hold lock");
        assert!(run_at(&root, &state, RunOptions { once: true }).is_err());
        drop(held);
        let restarted = run_at(&root, &state, RunOptions { once: true }).expect("restart");
        assert!(restarted.contains("Idle"));
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "deterministic runner fixture requires exact setup and evidence assertions"
    )]
    fn paused_queued_goal_survives_runner_restart_without_model_dispatch() {
        let _guard = RUNNER_LOCK_TEST
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let root = fixture();
        let state = state_path(&root, None).expect("state");
        let mut control = sovereign_controller::LocalControl::reopen(
            StateStore::open(&state).expect("open state"),
        )
        .expect("open control");
        let intent = control
            .submit_goal("Create a bounded local test app")
            .expect("queue goal");
        control.pause(Some("restart test")).expect("pause");
        drop(control);
        for _ in 0..2 {
            let result = run_at(&root, &state, RunOptions { once: true }).expect("paused run");
            assert!(result.contains("Paused"));
        }
        let reopened = Controller::reopen_local(StateStore::open(&state).expect("reopen state"))
            .expect("recover Controller");
        assert_eq!(
            reopened
                .next_queued_goal_intent()
                .expect("queued intent")
                .expect("goal")
                .goal_id,
            intent.goal_id
        );
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    #[expect(
        clippy::expect_used,
        clippy::too_many_lines,
        reason = "deterministic runner fixture requires exact setup and evidence assertions"
    )]
    fn browser_goal_run_once_requires_durable_opt_in_and_executes_controller_browser_task() {
        let _guard = RUNNER_LOCK_TEST
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let goal = "Verify the local inventory application in a browser";
        let root = fixture();
        let state = state_path(&root, Some(&external_fixture_state(&root))).expect("state path");
        let (node, chrome) = prepare_inventory_fixture(&root);
        let mut control = sovereign_controller::LocalControl::reopen(
            StateStore::open(&state).expect("open state"),
        )
        .expect("open control");
        let intent = control
            .submit_goal_with_browser_grant(goal, browser_grant_template())
            .expect("submit explicitly browser-authorized goal");
        assert!(intent.browser_grant.is_some());
        drop(control);

        let backend = compilation_fixture_backend();
        let first = run_at_with_overrides(
            &root,
            &state,
            RunOptions { once: true },
            Some(&backend),
            Some(&node),
            Some(&chrome),
            Some(green_fixture_pressure()),
        )
        .expect("compile and activate once");
        assert!(first.contains("PlanActivated"), "{first}");
        let store = StateStore::open(&state).expect("state after compilation");
        let plan_json = store
            .get_state("controller.plan_document", "active")
            .expect("load plan")
            .expect("active plan");
        let plan: Value = serde_json::from_str(&plan_json).expect("parse plan");
        let tasks = plan["tasks"].as_array().expect("compiled tasks");
        assert_eq!(tasks.len(), 1);
        let task_ids = tasks
            .iter()
            .filter_map(|task| task["task_id"].as_str().map(str::to_owned))
            .collect::<Vec<_>>();
        let branch_requirements = ["read", "process", "browser"];
        let represented_branches = tasks
            .iter()
            .flat_map(|task| {
                let permissions = task["permissions"].as_array().into_iter().flatten();
                let mut branches = permissions
                    .filter_map(Value::as_str)
                    .filter_map(|permission| match permission {
                        "read" => Some("read"),
                        "process_exec" => Some("process"),
                        "repo_write" => Some("write"),
                        "browser_interactive" => Some("browser"),
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                if task["scope"]["repositories"]
                    .as_array()
                    .is_some_and(|repositories| repositories.len() > 1)
                {
                    branches.push("integration");
                }
                branches
            })
            .collect::<std::collections::BTreeSet<_>>();
        let missing_branches = branch_requirements
            .into_iter()
            .filter(|branch| !represented_branches.contains(branch))
            .collect::<Vec<_>>();
        assert!(
            missing_branches.is_empty(),
            "queued goal {} compiled plan {} tasks {:?}, missing browser-run branches {:?}; observed {:?}",
            intent.goal_id,
            plan["plan_id"].as_str().unwrap_or("<missing-plan-id>"),
            task_ids,
            missing_branches,
            represented_branches
        );
        // This acceptance fixture is intentionally read-only and the runner
        // supplies one repository; write and D4 integration need separate,
        // explicitly scoped composition inputs and must not be simulated here.
        assert!(!represented_branches.contains("integration"));
        assert!(!represented_branches.contains("write"));
        let task = &tasks[0];
        let plan_id = plan["plan_id"]
            .as_str()
            .expect("compiled plan id")
            .to_owned();
        let permissions = task["permissions"]
            .as_array()
            .expect("typed task permissions")
            .iter()
            .filter_map(Value::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            permissions,
            std::collections::BTreeSet::from([
                "read",
                "process_exec",
                "browser_interactive",
                "network_read",
                "network_write",
            ])
        );
        assert!(task.get("browser_acceptance").is_some());
        assert!(
            task["browser_acceptance"]["loopback"]["port"]
                .as_u64()
                .unwrap_or(0)
                > 0
        );

        let second = run_at_with_overrides(
            &root,
            &state,
            RunOptions { once: true },
            Some(&backend),
            Some(&node),
            Some(&chrome),
            Some(green_fixture_pressure()),
        )
        .expect("recover and execute browser task once");
        assert!(second.contains("TaskVerified"), "{second}");
        let reopened = Controller::reopen_local(StateStore::open(&state).expect("reopen state"))
            .expect("browser authority survives verified recovery");
        let verified_status = reopened.durable_status().expect("durable status");
        let durable_tasks = verified_status.tasks;
        assert_eq!(durable_tasks[0]["state"], "succeeded");
        let action_ids = verified_status
            .actions
            .iter()
            .map(|action| action.action_id.clone())
            .collect::<Vec<_>>();
        let evidence_ids = verified_status
            .evidence
            .iter()
            .flat_map(|evidence| {
                let mut ids = evidence
                    .get("evidence_ids")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect::<Vec<_>>();
                ids.extend(
                    evidence
                        .get("evidence_id")
                        .or_else(|| evidence.get("verification_evidence_id"))
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                );
                ids
            })
            .collect::<Vec<_>>();
        assert!(
            verified_status.evidence.iter().any(|evidence| {
                evidence["plan_id"] == plan_id
                    && evidence["task_id"] == task_ids[0]
                    && evidence["passed"] == true
            }),
            "verified evidence must remain bound to the exact compiled plan/task: {:?}",
            verified_status.evidence
        );
        assert!(
            action_ids
                .iter()
                .any(|action| action.starts_with("managed-loopback-start."))
                && action_ids.iter().any(|action| action == "inventory.open")
                && action_ids
                    .iter()
                    .any(|action| action == "inventory.visible"),
            "browser action ids remain durable: {action_ids:?}"
        );
        let third = run_at_with_overrides(
            &root,
            &state,
            RunOptions { once: true },
            Some(&backend),
            Some(&node),
            Some(&chrome),
            Some(green_fixture_pressure()),
        )
        .expect("restart and complete queued goal");
        assert!(
            third.contains("GoalCompleted"),
            "{third}; goal_id={}; plan_id={}; task_ids={task_ids:?}; action_ids={action_ids:?}; evidence_ids={evidence_ids:?}; evidence_records={:?}",
            intent.goal_id,
            plan_id,
            verified_status.evidence
        );
        let fourth = run_at_with_overrides(
            &root,
            &state,
            RunOptions { once: true },
            Some(&backend),
            Some(&node),
            Some(&chrome),
            Some(green_fixture_pressure()),
        )
        .expect("restart and finalize completed goal");
        assert!(fourth.contains("Complete"), "{fourth}");
        let finalized_store = StateStore::open(&state).expect("reopen finalized state");
        let finalization = finalized_store
            .get_state("controller.plan_finalization", &format!("{plan_id}@r1"))
            .expect("read finalization record")
            .expect("durable finalization record");
        let finalization: Value =
            serde_json::from_str(&finalization).expect("parse finalization record");
        assert_eq!(finalization["goal_id"], intent.goal_id);
        assert_eq!(finalization["plan_id"], plan_id);
        let after_restart =
            Controller::reopen_local(finalized_store).expect("recover finalized controller");
        assert!(
            after_restart
                .durable_status()
                .expect("finalized status")
                .active_plan
                .is_none()
        );
        fs::remove_dir_all(root).expect("cleanup authorized fixture");
        fs::remove_dir_all(state.parent().expect("state directory"))
            .expect("cleanup authorized external state");

        let root = fixture();
        let state =
            state_path(&root, Some(&external_fixture_state(&root))).expect("ungranted state path");
        let (node, chrome) = prepare_inventory_fixture(&root);
        let mut control = sovereign_controller::LocalControl::reopen(
            StateStore::open(&state).expect("open ungranted state"),
        )
        .expect("open ungranted control");
        let ungranted = control.submit_goal(goal).expect("submit ordinary M1 goal");
        assert!(ungranted.browser_grant.is_none());
        drop(control);
        let backend = compilation_fixture_backend();
        let result = run_at_with_overrides(
            &root,
            &state,
            RunOptions { once: true },
            Some(&backend),
            Some(&node),
            Some(&chrome),
            Some(green_fixture_pressure()),
        )
        .expect("compile otherwise-identical ordinary goal");
        assert!(result.contains("PlanActivated"), "{result}");
        let store = StateStore::open(&state).expect("ungranted state after compilation");
        let plan_json = store
            .get_state("controller.plan_document", "active")
            .expect("load ungranted plan")
            .expect("ungranted active plan");
        let plan: Value = serde_json::from_str(&plan_json).expect("parse ungranted plan");
        assert!(
            !plan["policy"]["capability_ceiling"]
                .as_array()
                .expect("capability ceiling")
                .iter()
                .any(|capability| capability == "browser_interactive")
        );
        assert!(
            plan["tasks"].as_array().expect("ungranted tasks")[0]
                .get("browser_acceptance")
                .is_none_or(Value::is_null)
        );
        assert!(
            !plan["tasks"][0]["permissions"]
                .as_array()
                .expect("ungranted task permissions")
                .iter()
                .any(|permission| matches!(
                    permission.as_str(),
                    Some("browser_interactive" | "network_read" | "network_write")
                ))
        );
        fs::remove_dir_all(root).expect("cleanup ungranted fixture");
        fs::remove_dir_all(state.parent().expect("ungranted state directory"))
            .expect("cleanup ungranted external state");
    }
}
