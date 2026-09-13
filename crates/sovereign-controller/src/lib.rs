//! M1 deterministic Controller vertical slice.
//!
//! The Controller is the only authority that activates compiler-produced plans,
//! derives readiness, owns task/attempt state, lowers typed model proposals into
//! exact authorized actions, and accepts fresh deterministic verification.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sovereign_context::{ContextPacket, EvidenceItem, EvidenceKind};
use sovereign_evidence::{ArtifactStore, EvidenceError};
use sovereign_model::{
    MODEL_SCHEMA_VERSION, ModelBackend, ModelError, ModelFinishReason, ModelMessage,
    ModelMessageRole, ModelOutputContract, ModelRequest,
};
use sovereign_plan::PlanCompilationResult;
use sovereign_policy::{
    CommandMode, CommandPolicy, CommandRisk, HeavyLeaseClass, HostPressureSnapshot,
    IsolationRequest, M1ResourceGovernor, ModelCallBudget, PolicyError, ResourceGovernor,
    ResourceLease,
};
use sovereign_repo::{
    ExactRetriever, ProjectRegistry, RepoError, RepositoryIntelligence, RepositorySnapshot,
};
use sovereign_state::{
    CheckpointIntegrityRecord, JournalEvent, NewCheckpointIntegrityRecord, NewJournalEvent,
    StateError, StateRecordUpdate, StateStore,
};
use sovereign_tools::{
    ActionJournal, AuthorizedAction, PermissionClass, ProcessRunner, RawToolResult,
    ReconciliationMode, ToolError, ToolManifest, reap_owned_process_group,
};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const MODEL_PROPOSAL_SCHEMA_VERSION: u32 = 1;
pub const VERIFICATION_RESULT_SCHEMA_VERSION: u32 = 1;
const M1_MODEL_OUTPUT_TOKENS: u32 = 512;
const MAX_LITERAL_BYTES: usize = 4_096;
const EVIDENCE_SATISFACTION_SCHEMA_VERSION: u32 = 1;
const VERIFIED_OUTPUT_BINDING_SCHEMA_VERSION: u32 = 1;
pub const CHECKPOINT_MANIFEST_SCHEMA_VERSION: u32 = 1;
pub const RECOVERY_PROCESS_LEASE_SCHEMA_VERSION: u32 = 1;
const ACTION_INTENT_SCHEMA_VERSION: u32 = 2;
const MAX_PROPOSAL_EVIDENCE_IDS: usize = 16;
const MAX_PROPOSAL_EVIDENCE_ID_BYTES: usize = 512;
const ATOMIC_REPLACE_HELPER: &str = r"import hashlib, os, pathlib, sys
p=pathlib.Path(sys.argv[1]); expected=sys.argv[2]; old=sys.argv[3]; new=sys.argv[4]
data=p.read_bytes()
if 'sha256:'+hashlib.sha256(data).hexdigest()!=expected: sys.exit(41)
text=data.decode('utf-8')
if text.count(old)!=1: sys.exit(42)
out=text.replace(old,new,1).encode('utf-8')
mode=os.stat(p, follow_symlinks=False).st_mode & 0o7777
tmp=p.with_name('.sovereign-'+p.name+'-'+str(os.getpid())+'.tmp')
fd=os.open(tmp, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
try:
 os.write(fd,out); os.fchmod(fd,mode); os.fsync(fd)
finally:
 os.close(fd)
os.replace(tmp,p)
dfd=os.open(p.parent, os.O_RDONLY)
try: os.fsync(dfd)
finally: os.close(dfd)
";

#[derive(Debug)]
pub enum ControllerError {
    State(StateError),
    Model(ModelError),
    Policy(PolicyError),
    Repo(RepoError),
    Tool(ToolError),
    Evidence(EvidenceError),
    Json(serde_json::Error),
    Io(std::io::Error),
    InvalidPlan(String),
    NotReady(String),
    ProposalRejected(String),
    ExecutionFailed(Box<ExecutionFailureV1>),
    VerificationFailed(Box<VerificationResultV1>),
    UnknownAction(String),
}

impl Display for ControllerError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::State(error) => write!(f, "controller state error: {error}"),
            Self::Model(error) => write!(f, "controller model error: {error}"),
            Self::Policy(error) => write!(f, "controller policy error: {error}"),
            Self::Repo(error) => write!(f, "controller repository error: {error}"),
            Self::Tool(error) => write!(f, "controller tool error: {error}"),
            Self::Evidence(error) => write!(f, "controller evidence error: {error}"),
            Self::Json(error) => write!(f, "controller JSON error: {error}"),
            Self::Io(error) => write!(f, "controller I/O error: {error}"),
            Self::InvalidPlan(message) => write!(f, "invalid active plan: {message}"),
            Self::NotReady(message) => write!(f, "task is not ready: {message}"),
            Self::ProposalRejected(message) => write!(f, "model proposal rejected: {message}"),
            Self::ExecutionFailed(failure) => write!(f, "execution failed: {}", failure.signature),
            Self::VerificationFailed(result) => write!(
                f,
                "verification failed: {}",
                result.failure_code.as_deref().unwrap_or("unknown")
            ),
            Self::UnknownAction(action_id) => write!(f, "action outcome is unknown: {action_id}"),
        }
    }
}

impl Error for ControllerError {}

macro_rules! from_error {
    ($source:ty, $variant:ident) => {
        impl From<$source> for ControllerError {
            fn from(value: $source) -> Self {
                Self::$variant(value)
            }
        }
    };
}

from_error!(StateError, State);
from_error!(ModelError, Model);
from_error!(PolicyError, Policy);
from_error!(RepoError, Repo);
from_error!(ToolError, Tool);
from_error!(EvidenceError, Evidence);
from_error!(serde_json::Error, Json);
from_error!(std::io::Error, Io);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanValidity {
    Current,
    StaleEvidence,
    Invalidated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskState {
    Planned,
    Running,
    Verifying,
    RepairPending,
    DeferredResource,
    ReconcilingUnknown,
    FailedTerminal,
    Succeeded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptState {
    Prepared,
    Executing,
    Verifying,
    Failed,
    Aborted,
    Interrupted,
    Succeeded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerView {
    Blocked,
    Running,
    Terminal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationSummary {
    pub plan_id: String,
    pub plan_digest: String,
    pub revision: u32,
    pub execution_epoch: i64,
    pub task_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadinessInputs<'a> {
    pub resource_digest: &'a str,
    pub host_pressure: HostPressureSnapshot,
}

impl<'a> ReadinessInputs<'a> {
    #[must_use]
    pub const fn permissive_m1(resource_digest: &'a str) -> Self {
        Self {
            resource_digest,
            host_pressure: HostPressureSnapshot {
                controlled_working_set_mib: 512,
                host_headroom_mib: 4_096,
                swap_out_growth_mib_per_min: 0,
                compressor_growth_mib_per_min: 0,
                os_pressure_warning: false,
                recent_pressure_event: false,
                thermal_serious: false,
            },
        }
    }
}

#[derive(Debug)]
pub struct ReadyLease {
    plan_id: String,
    plan_revision: u32,
    plan_digest: String,
    task_id: String,
    task_contract_digest: String,
    baseline_digest: String,
    evidence_binding_digest: String,
    checkpoint_generation: i64,
    checkpoint_action_sequence: i64,
    checkpoint_hash: String,
    permission_digest: String,
    resource_digest: String,
    execution_epoch: i64,
    resource_lease: ResourceLease,
    lease_digest: String,
}

impl ReadyLease {
    #[must_use]
    pub fn task_id(&self) -> &str {
        &self.task_id
    }

    #[must_use]
    pub const fn execution_epoch(&self) -> i64 {
        self.execution_epoch
    }

    #[must_use]
    pub fn lease_digest(&self) -> &str {
        &self.lease_digest
    }

    #[must_use]
    pub fn checkpoint_hash(&self) -> &str {
        &self.checkpoint_hash
    }

    #[must_use]
    pub const fn checkpoint_generation(&self) -> i64 {
        self.checkpoint_generation
    }

    #[must_use]
    pub const fn checkpoint_action_sequence(&self) -> i64 {
        self.checkpoint_action_sequence
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionContext {
    controller_ceiling: BTreeSet<PermissionClass>,
    project_ceiling: BTreeSet<PermissionClass>,
    role_ceiling: BTreeSet<PermissionClass>,
    persisted_grants: BTreeSet<PermissionClass>,
}

impl PermissionContext {
    #[must_use]
    pub fn m1_local_autonomous() -> Self {
        let granted = BTreeSet::from([
            PermissionClass::ProcessExec,
            PermissionClass::RepositoryWrite,
        ]);
        Self {
            controller_ceiling: granted.clone(),
            project_ceiling: granted.clone(),
            role_ceiling: granted.clone(),
            persisted_grants: granted,
        }
    }

    #[must_use]
    pub fn read_only() -> Self {
        let granted = BTreeSet::from([PermissionClass::ProcessExec]);
        Self {
            controller_ceiling: granted.clone(),
            project_ceiling: granted.clone(),
            role_ceiling: granted.clone(),
            persisted_grants: granted,
        }
    }

    fn permits(&self, permission: PermissionClass) -> bool {
        self.controller_ceiling.contains(&permission)
            && self.project_ceiling.contains(&permission)
            && self.role_ceiling.contains(&permission)
            && self.persisted_grants.contains(&permission)
    }

    fn digest(&self) -> String {
        let encode = |set: &BTreeSet<PermissionClass>| {
            set.iter()
                .map(|permission| format!("{permission:?}"))
                .collect::<Vec<_>>()
                .join(",")
        };
        sha256_prefixed(
            format!(
                "{}\0{}\0{}\0{}",
                encode(&self.controller_ceiling),
                encode(&self.project_ceiling),
                encode(&self.role_ceiling),
                encode(&self.persisted_grants)
            )
            .as_bytes(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelProposalV1 {
    pub schema_version: u32,
    pub evidence_ids: Vec<String>,
    pub action: ReplaceLiteral,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplaceLiteral {
    pub kind: ReplaceLiteralKind,
    pub repository_id: String,
    pub path: String,
    pub expected_source_digest: String,
    pub old_literal: String,
    pub new_literal: String,
    pub expected_occurrences: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplaceLiteralKind {
    #[serde(rename = "replace_literal")]
    ReplaceLiteral,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionFailureV1 {
    pub schema_version: u32,
    pub plan_id: String,
    pub task_id: String,
    pub attempt_id: String,
    pub action_id: Option<String>,
    pub result_digest: Option<String>,
    pub exit_code: Option<i32>,
    pub signature: String,
    pub category: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationResultV1 {
    pub schema_version: u32,
    pub verification_id: String,
    pub plan_id: String,
    pub plan_revision: u32,
    pub plan_digest: String,
    pub task_id: String,
    pub task_contract_digest: String,
    pub attempt_id: String,
    pub execution_epoch: i64,
    pub evaluator: String,
    pub acceptance_contract_digest: String,
    pub diff_digest: String,
    pub post_snapshot_digest: String,
    pub expected_target_mode: u32,
    pub observed_target_mode: u32,
    pub evidence_ids: Vec<String>,
    pub passed: bool,
    pub failure_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionSuccess {
    pub task_id: String,
    pub attempt_id: String,
    pub action_id: String,
    pub action_result_digest: String,
    pub verification_evidence_id: String,
    pub verification: VerificationResultV1,
}

/// Durable checkpoint body published to the Controller checkpoint CAS. The immutable
/// checkpoint-integrity row stores this manifest's CAS digest and journal sequence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CheckpointManifest {
    pub schema_version: u32,
    pub plan_document: Value,
    pub plan_id: String,
    pub goal_id: String,
    pub plan_revision: u32,
    pub plan_digest: String,
    pub compiler_plan_digest: String,
    pub compilation_evidence_digest: String,
    pub policy_digest: String,
    pub repository_id: String,
    pub repository_root: PathBuf,
    pub repository_snapshot: RepositorySnapshot,
    pub repository_snapshot_digest: String,
    pub baseline_diff_digest: String,
    pub baseline_diff_content: String,
    pub plan_validity: PlanValidity,
    pub task_records: BTreeMap<String, Value>,
    pub attempt_records: BTreeMap<String, Value>,
    pub evidence_binding_digests: BTreeMap<String, String>,
    pub action_records: Vec<CheckpointActionRecord>,
    pub process_leases: Vec<RecoveryProcessLease>,
    pub action_journal_sequence: i64,
    pub execution_epoch: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointActionRecord {
    pub action_id: String,
    pub state: String,
    pub payload_digest: String,
    pub policy_digest: String,
    pub execution_epoch: i64,
    pub result_digest: Option<String>,
    pub last_event_sequence: i64,
}

/// Recovery ownership record for a locally spawned process group. A lease without a
/// PID/identity proof is unresolved and blocks mutation rather than guessing process state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryProcessLease {
    pub schema_version: u32,
    pub lease_id: String,
    pub task_id: String,
    pub attempt_id: String,
    pub action_id: String,
    pub process_group_id: Option<u32>,
    pub leader_identity: Option<String>,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoverySummary {
    pub plan_id: String,
    pub plan_digest: String,
    pub checkpoint_generation: i64,
    pub checkpoint_action_sequence: i64,
    pub replayed_events: usize,
    pub execution_epoch_before: i64,
    pub execution_epoch_after: i64,
    pub interrupted_attempt_ids: Vec<String>,
    pub unknown_action_ids: Vec<String>,
    pub pending_recovery_action_ids: Vec<String>,
    pub unresolved_process_lease_ids: Vec<String>,
    pub fallback_checkpoint_used: bool,
    pub mutation_blocked: bool,
}

/// Controller-owned restart authority. Recovery reconstructs only from durable
/// SQLite/CAS/Git truth and never from chat/model memory.
pub struct RecoveryManager;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceSatisfactionV1 {
    pub schema_version: u32,
    pub plan_id: String,
    pub plan_revision: u32,
    pub plan_digest: String,
    pub task_id: String,
    pub task_contract_digest: String,
    pub requirement_id: String,
    pub requirement_digest: String,
    pub query_digest: String,
    pub evidence_ids: Vec<String>,
    pub evidence_digests: Vec<String>,
    pub evidence_record_keys: Vec<String>,
    pub repository_snapshot_digest: String,
    pub satisfaction: String,
    pub observed_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct VerifiedOutputBindingV1 {
    schema_version: u32,
    plan_id: String,
    plan_revision: u32,
    plan_digest: String,
    task_id: String,
    task_contract_digest: String,
    attempt_id: String,
    binding_kind: String,
    binding_id: String,
    verification_id: String,
    verification_artifact_digest: String,
    repository_snapshot_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TaskRuntime {
    state: TaskState,
    attempts_started: u32,
    model_calls_used: u32,
    failure_counts: BTreeMap<String, u32>,
    retry_exhausted: bool,
    task_contract_digest: String,
    task: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AttemptRuntime {
    task_id: String,
    attempt_id: String,
    state: AttemptState,
    task_contract_digest: String,
    baseline_digest: String,
    pre_snapshot_digest: String,
    pre_diff_digest: String,
    pre_changed_fingerprints: BTreeMap<PathBuf, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedRepositoryBaseline {
    snapshot: RepositorySnapshot,
    diff_digest: String,
    diff_content: String,
}

struct ActivePlan {
    plan_document: Value,
    compiler_plan_digest: String,
    plan_id: String,
    goal_id: String,
    revision: u32,
    plan_digest: String,
    compilation_evidence_digest: String,
    policy_digest: String,
    repository_id: String,
    repository_root: PathBuf,
    baseline: RepositorySnapshot,
    baseline_diff_digest: String,
    baseline_diff_content: String,
    validity: PlanValidity,
    tasks: BTreeMap<String, TaskRuntime>,
    attempts: BTreeMap<String, AttemptRuntime>,
}

pub struct Controller {
    state: StateStore,
    active: Option<ActivePlan>,
    resource_governor: M1ResourceGovernor,
    permission_context: PermissionContext,
    trusted_recovery_intent_digests: BTreeMap<String, String>,
}

impl Controller {
    #[must_use]
    pub fn new(state: StateStore) -> Self {
        Self {
            state,
            active: None,
            resource_governor: M1ResourceGovernor::default(),
            permission_context: PermissionContext::m1_local_autonomous(),
            trusted_recovery_intent_digests: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with_permission_context(
        state: StateStore,
        permission_context: PermissionContext,
    ) -> Self {
        Self {
            state,
            active: None,
            resource_governor: M1ResourceGovernor::default(),
            permission_context,
            trusted_recovery_intent_digests: BTreeMap::new(),
        }
    }

    #[must_use]
    pub const fn state(&self) -> &StateStore {
        &self.state
    }

    #[must_use]
    pub fn task_state(&self, task_id: &str) -> Option<TaskState> {
        self.active
            .as_ref()
            .and_then(|active| active.tasks.get(task_id))
            .map(|task| task.state)
    }

    #[must_use]
    pub fn task_model_calls_used(&self, task_id: &str) -> Option<u32> {
        self.active
            .as_ref()
            .and_then(|active| active.tasks.get(task_id))
            .map(|task| task.model_calls_used)
    }

    #[must_use]
    pub fn plan_validity(&self) -> Option<PlanValidity> {
        self.active.as_ref().map(|active| active.validity)
    }

    #[must_use]
    pub fn scheduler_view(&self, task_id: &str) -> Option<SchedulerView> {
        let task = self.active.as_ref()?.tasks.get(task_id)?;
        Some(match task.state {
            TaskState::Succeeded | TaskState::FailedTerminal => SchedulerView::Terminal,
            TaskState::Running | TaskState::Verifying | TaskState::ReconcilingUnknown => {
                SchedulerView::Running
            }
            TaskState::RepairPending if task.retry_exhausted => SchedulerView::Blocked,
            TaskState::DeferredResource | TaskState::RepairPending | TaskState::Planned => {
                SchedulerView::Blocked
            }
        })
    }

    /// Persists one Controller-validated exact evidence satisfaction record.
    /// Callers choose retained evidence IDs but cannot assert satisfaction directly:
    /// the Controller resolves the Plan-IR requirement, revalidates every selected
    /// repository evidence item against the current baseline, enforces the required
    /// count semantics, and binds the record to the active plan/task/snapshot.
    ///
    /// # Errors
    /// Returns a fail-closed readiness/evidence error when the requirement, evidence,
    /// count semantics, or freshness binding is invalid.
    pub fn record_exact_evidence_satisfaction(
        &mut self,
        registry: &ProjectRegistry,
        task_id: &str,
        requirement_id: &str,
        context: &ContextPacket,
        selected_evidence_ids: &[String],
    ) -> Result<String, ControllerError> {
        self.require_current_baseline(registry)?;
        let (plan_id, plan_revision, plan_digest, task_contract_digest, requirement) = {
            let active = self.active_ref()?;
            let task = active
                .tasks
                .get(task_id)
                .ok_or_else(|| ControllerError::NotReady(format!("unknown task {task_id}")))?;
            let requirement = resolve_execution_requirement(&task.task, requirement_id)?;
            (
                active.plan_id.clone(),
                active.revision,
                active.plan_digest.clone(),
                task.task_contract_digest.clone(),
                requirement,
            )
        };
        let requirement_digest = digest_json(&requirement)?;
        let query = required_str(&requirement, "/query")?;
        let query_digest = sha256_prefixed(query.as_bytes());
        let probe = exact_requirement_probe(query).ok_or_else(|| {
            ControllerError::NotReady(
                "exact evidence requirement has no deterministic path/literal anchor".to_owned(),
            )
        })?;
        let satisfaction = validate_evidence_selection(&requirement, selected_evidence_ids)?;
        let selected = selected_evidence_ids
            .iter()
            .map(|evidence_id| {
                context
                    .items
                    .iter()
                    .find(|item| item.evidence_id == *evidence_id)
                    .ok_or_else(|| {
                        ControllerError::NotReady(format!(
                            "evidence {evidence_id} is absent from the bounded ContextPacket"
                        ))
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let repository_id = self.active_ref()?.repository_id.clone();
        for item in &selected {
            Self::validate_exact_context_evidence(registry, &repository_id, item)?;
            validate_requirement_bound_evidence(registry, &repository_id, item, &probe)?;
        }
        validate_requirement_probe_cardinality(registry, &repository_id, &probe, &satisfaction)?;
        let snapshot = registry.snapshot(&repository_id)?;
        let repository_snapshot_digest = snapshot_digest(&snapshot)?;
        let evidence_digests = selected
            .iter()
            .map(|item| -> Result<String, ControllerError> {
                Ok(digest_json(&serde_json::to_value(item)?)?)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let evidence_record_keys = selected
            .iter()
            .map(|item| {
                let key = evidence_item_key(task_id, requirement_id, &item.evidence_id);
                self.state.put_state(
                    "controller.evidence_item",
                    &key,
                    &serde_json::to_string(item)?,
                )?;
                Ok(key)
            })
            .collect::<Result<Vec<_>, ControllerError>>()?;
        let record = EvidenceSatisfactionV1 {
            schema_version: EVIDENCE_SATISFACTION_SCHEMA_VERSION,
            plan_id,
            plan_revision,
            plan_digest,
            task_id: task_id.to_owned(),
            task_contract_digest,
            requirement_id: requirement_id.to_owned(),
            requirement_digest,
            query_digest,
            evidence_ids: selected_evidence_ids.to_vec(),
            evidence_digests,
            evidence_record_keys,
            repository_snapshot_digest,
            satisfaction,
            observed_at_ms: unix_millis()?,
        };
        let record_json = serde_json::to_value(&record)?;
        let record_digest = digest_json(&record_json)?;
        self.state.put_state(
            "controller.evidence_satisfaction",
            &evidence_satisfaction_key(task_id, requirement_id),
            &serde_json::to_string(&record)?,
        )?;
        self.append_controller_event(
            "evidence_requirement_satisfied",
            task_id,
            &json!({
                "requirement_id": requirement_id,
                "record_digest": record_digest,
            }),
        )?;
        self.checkpoint_now()?;
        Ok(record_digest)
    }

    /// Activates only an owned compiler-produced opaque result. There is intentionally
    /// no activation overload accepting raw [`sovereign_plan::PlanIr`].
    ///
    /// # Errors
    /// Returns a fail-closed validation/state error when the compiler result or baseline is stale.
    #[allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
    pub fn activate(
        &mut self,
        compilation: PlanCompilationResult,
        registry: &ProjectRegistry,
    ) -> Result<ActivationSummary, ControllerError> {
        if self.active.is_some() {
            return Err(ControllerError::InvalidPlan(
                "M1 Controller already has an active plan".to_owned(),
            ));
        }
        if compilation.plan().canonical_digest()? != compilation.plan_digest() {
            return Err(ControllerError::InvalidPlan(
                "compiler result plan digest does not match canonical Plan IR".to_owned(),
            ));
        }
        if !compilation.compilation_evidence().validator_passed()
            || compilation.compilation_evidence().plan_digest() != compilation.plan_digest()
        {
            return Err(ControllerError::InvalidPlan(
                "compiler evidence does not prove validator success for this exact Plan IR"
                    .to_owned(),
            ));
        }
        let plan_document = compilation.plan().as_value().clone();
        let plan = &plan_document;
        let plan_id = required_str(plan, "/plan_id")?.to_owned();
        let goal_id = required_str(plan, "/goal/goal_id")?.to_owned();
        let revision = required_u32(plan, "/revision")?;
        let repositories = required_array(plan, "/repositories")?;
        if repositories.len() != 1 {
            return Err(ControllerError::InvalidPlan(
                "M1-T07 supports exactly one active repository".to_owned(),
            ));
        }
        let repository = &repositories[0];
        let repository_id = required_str(repository, "/repository_id")?.to_owned();
        let registered = registry.repository(&repository_id).ok_or_else(|| {
            ControllerError::InvalidPlan(format!("repository {repository_id} is not registered"))
        })?;
        let repository_root = registered.root.clone();
        let plan_root = PathBuf::from(required_str(repository, "/root")?);
        let canonical_plan_root = plan_root.canonicalize()?;
        if canonical_plan_root != repository_root {
            return Err(ControllerError::InvalidPlan(
                "compiled repository root differs from registered root".to_owned(),
            ));
        }
        let baseline = registry.snapshot(&repository_id)?;
        if baseline.head.as_deref() != optional_str(repository, "/baseline/head")
            || baseline.branch.as_deref() != optional_str(repository, "/baseline/branch")
            || baseline.dirty_digest != required_str(repository, "/baseline/dirty_digest")?
        {
            return Err(ControllerError::NotReady(
                "compiled repository baseline is stale at activation".to_owned(),
            ));
        }
        let baseline_diff = ExactRetriever::new(registry).current_diff(&repository_id)?;
        let mut tasks = BTreeMap::new();
        for task in required_array(plan, "/tasks")? {
            let task_id = required_str(task, "/task_id")?.to_owned();
            let task_contract_digest = digest_json(task)?;
            if tasks
                .insert(
                    task_id.clone(),
                    TaskRuntime {
                        state: TaskState::Planned,
                        attempts_started: 0,
                        model_calls_used: 0,
                        failure_counts: BTreeMap::new(),
                        retry_exhausted: false,
                        task_contract_digest,
                        task: task.clone(),
                    },
                )
                .is_some()
            {
                return Err(ControllerError::InvalidPlan(format!(
                    "duplicate task {task_id}"
                )));
            }
        }
        if tasks.is_empty() {
            return Err(ControllerError::InvalidPlan(
                "active plan requires at least one task".to_owned(),
            ));
        }
        let policy_digest = digest_json(
            plan.pointer("/policy")
                .ok_or_else(|| ControllerError::InvalidPlan("missing policy".to_owned()))?,
        )?;
        let plan_digest = compilation.plan_digest().to_owned();
        let compiler_plan_digest = plan_digest.clone();
        let compilation_evidence_digest = compilation.compilation_evidence_digest().to_owned();
        let epoch = self.state.advance_execution_epoch()?;
        let task_ids = tasks.keys().cloned().collect::<Vec<_>>();
        self.active = Some(ActivePlan {
            plan_document,
            compiler_plan_digest,
            plan_id: plan_id.clone(),
            goal_id,
            revision,
            plan_digest: plan_digest.clone(),
            compilation_evidence_digest,
            policy_digest,
            repository_id,
            repository_root,
            baseline,
            baseline_diff_digest: baseline_diff.digest,
            baseline_diff_content: baseline_diff.content,
            validity: PlanValidity::Current,
            tasks,
            attempts: BTreeMap::new(),
        });
        self.persist_all_runtime()?;
        self.append_controller_event("plan_activated", &plan_id, &json!({"epoch": epoch}))?;
        self.checkpoint_now()?;
        Ok(ActivationSummary {
            plan_id,
            plan_digest,
            revision,
            execution_epoch: epoch,
            task_ids,
        })
    }

    /// Derives one ephemeral readiness lease from current authoritative guards.
    ///
    /// # Errors
    /// Returns [`ControllerError::NotReady`] or a lower-layer error when any guard fails.
    pub fn derive_ready_lease(
        &mut self,
        registry: &ProjectRegistry,
        task_id: &str,
        inputs: ReadinessInputs<'_>,
    ) -> Result<ReadyLease, ControllerError> {
        self.require_current_baseline(registry)?;
        if self.task_state(task_id) == Some(TaskState::DeferredResource) {
            self.transition_task(task_id, TaskState::Planned, "task_resource_recheck")?;
        }
        let epoch = self.state.current_execution_epoch()?;
        let (plan_id, revision, plan_digest, task_digest, task_value, validity) = {
            let active = self.active_ref()?;
            let task = active
                .tasks
                .get(task_id)
                .ok_or_else(|| ControllerError::NotReady(format!("unknown task {task_id}")))?;
            (
                active.plan_id.clone(),
                active.revision,
                active.plan_digest.clone(),
                task.task_contract_digest.clone(),
                task.task.clone(),
                active.validity,
            )
        };
        if validity != PlanValidity::Current {
            return Err(ControllerError::NotReady(
                "active plan validity is not current".to_owned(),
            ));
        }
        self.check_task_readiness(task_id, &task_value, inputs)?;
        let (checkpoint_generation, checkpoint_action_sequence, checkpoint_hash) =
            self.current_checkpoint_binding()?;
        let baseline_digest = snapshot_digest(&self.active_ref()?.baseline)?;
        let evidence_binding_digest =
            self.resolve_readiness_evidence_digest(registry, task_id, &task_value)?;
        let permission_digest = self.effective_permission_digest(&task_value)?;
        let resource_lease = match self.resource_governor.acquire(
            format!("ready:{plan_id}:{task_id}:{epoch}"),
            HeavyLeaseClass::Model,
            inputs.host_pressure,
        ) {
            Ok(lease) => lease,
            Err(error @ PolicyError::ResourceDenied(_)) => {
                self.transition_task(
                    task_id,
                    TaskState::DeferredResource,
                    "task_deferred_resource",
                )?;
                return Err(ControllerError::Policy(error));
            }
            Err(error) => return Err(ControllerError::Policy(error)),
        };
        let resource_digest = sha256_prefixed(
            format!(
                "{}\0{:?}\0{}",
                resource_lease.lease_id, resource_lease.class, inputs.resource_digest
            )
            .as_bytes(),
        );
        let mut lease = ReadyLease {
            plan_id,
            plan_revision: revision,
            plan_digest,
            task_id: task_id.to_owned(),
            task_contract_digest: task_digest,
            baseline_digest,
            evidence_binding_digest,
            checkpoint_generation,
            checkpoint_action_sequence,
            checkpoint_hash,
            permission_digest,
            resource_digest,
            execution_epoch: epoch,
            resource_lease,
            lease_digest: String::new(),
        };
        lease.lease_digest = ready_lease_digest(&lease);
        Ok(lease)
    }

    /// Releases an unused derived readiness lease.
    ///
    /// # Errors
    /// Returns a policy error when the exact resource lease is no longer active.
    pub fn cancel_ready_lease(&mut self, lease: ReadyLease) -> Result<(), ControllerError> {
        let ReadyLease { resource_lease, .. } = lease;
        self.resource_governor.release(&resource_lease)?;
        Ok(())
    }

    /// Executes the single frozen M1 typed mutation and verifies it deterministically.
    ///
    /// # Errors
    /// Returns proposal, authority, execution, unknown-outcome, or verification failures.
    #[allow(clippy::too_many_lines)]
    pub fn execute_replace<I: sovereign_policy::ExecutionIsolationBackend>(
        &mut self,
        mut lease: ReadyLease,
        runtime: &ExecutionRuntime<'_, I>,
        context: &ContextPacket,
        model_budget: &mut ModelCallBudget,
    ) -> Result<ExecutionSuccess, ControllerError> {
        let result = self.execute_replace_inner(&mut lease, runtime, context, model_budget);
        let release = self.resource_governor.release(&lease.resource_lease);
        match (result, release) {
            (Ok(success), Ok(())) => Ok(success),
            (Ok(_), Err(error)) => Err(ControllerError::Policy(error)),
            (Err(error), _) => Err(error),
        }
    }

    /// Resumes a crash-interrupted, not-yet-mutated replacement from the exact durable
    /// Controller action intent without another model call. Recovery creates a new attempt
    /// under the current epoch and revalidates the repository preimage and compiled contract.
    ///
    /// # Errors
    /// Returns a fail-closed recovery/readiness error when the intent, baseline, retry budget,
    /// authority, or current repository content no longer matches.
    pub fn resume_recovered_replace<I: sovereign_policy::ExecutionIsolationBackend>(
        &mut self,
        prior_action_id: &str,
        runtime: &ExecutionRuntime<'_, I>,
        readiness: ReadinessInputs<'_>,
    ) -> Result<ExecutionSuccess, ControllerError> {
        let raw = self
            .state
            .get_state("controller.action_intent", prior_action_id)?
            .ok_or_else(|| {
                ControllerError::NotReady(format!(
                    "recovery action intent {prior_action_id} is missing"
                ))
            })?;
        let trusted_intent_digest = self
            .trusted_recovery_intent_digests
            .get(prior_action_id)
            .ok_or_else(|| {
                ControllerError::NotReady(format!(
                    "recovery action intent {prior_action_id} has no trusted checkpoint binding"
                ))
            })?;
        if sha256_prefixed(raw.as_bytes()) != *trusted_intent_digest {
            return Err(ControllerError::NotReady(
                "recovery action intent differs from its trusted recovery checkpoint binding"
                    .to_owned(),
            ));
        }
        let intent: PersistedActionIntent = serde_json::from_str(&raw)?;
        if intent.schema_version != ACTION_INTENT_SCHEMA_VERSION {
            return Err(ControllerError::NotReady(
                "recovery action intent schema is unsupported".to_owned(),
            ));
        }
        let prior = self.state.action_record(prior_action_id)?.ok_or_else(|| {
            ControllerError::NotReady("recovery action record missing".to_owned())
        })?;
        if !matches!(prior.state.as_str(), "prepared" | "authorized" | "failed") {
            return Err(ControllerError::NotReady(format!(
                "action {} is not eligible for pre-mutation recovery from state {}",
                prior.action_id, prior.state
            )));
        }
        if intent.action_id != prior.action_id
            || intent.payload_digest != prior.payload_digest
            || intent.policy_digest != prior.policy_digest
            || intent.execution_epoch != prior.execution_epoch
        {
            return Err(ControllerError::NotReady(
                "recovery action intent does not match durable prior action authority".to_owned(),
            ));
        }
        let action_seed = persisted_intent_action_seed(&intent)?;
        if intent.action_id != format!("action.{}", &action_seed[7..27])
            || intent.action_nonce != format!("nonce.{}", &action_seed[27..47])
        {
            return Err(ControllerError::NotReady(
                "recovery action intent semantics do not re-derive the prior action identity"
                    .to_owned(),
            ));
        }
        let validated = self.validate_recovered_action_intent(&intent, runtime.registry)?;
        let (attempts_started, max_attempts) = {
            let active = self.active_ref()?;
            let task = active.tasks.get(&intent.task_id).ok_or_else(|| {
                ControllerError::NotReady("recovery task no longer exists".to_owned())
            })?;
            let original_attempt = active.attempts.get(&intent.attempt_id).ok_or_else(|| {
                ControllerError::NotReady("recovery origin attempt no longer exists".to_owned())
            })?;
            if original_attempt.task_id != intent.task_id
                || original_attempt.task_contract_digest != intent.task_contract_digest
            {
                return Err(ControllerError::NotReady(
                    "recovery action intent is misbound to its origin attempt".to_owned(),
                ));
            }
            (
                task.attempts_started,
                required_u32(&task.task, "/failure_policy/max_attempts")?,
            )
        };
        if attempts_started >= max_attempts {
            return Err(ControllerError::NotReady(
                "recovery attempt budget is exhausted".to_owned(),
            ));
        }
        let mut lease = self.derive_ready_lease(runtime.registry, &intent.task_id, readiness)?;
        let result = (|| {
            self.validate_ready_lease(&lease, runtime.registry)?;
            let attempt_id = self.start_attempt(&lease, runtime.registry)?;
            self.execute_validated_replace(&mut lease, runtime, &attempt_id, &validated)
        })();
        let release = self.resource_governor.release(&lease.resource_lease);
        match (result, release) {
            (Ok(success), Ok(())) => Ok(success),
            (Ok(_), Err(error)) => Err(ControllerError::Policy(error)),
            (Err(error), _) => Err(error),
        }
    }

    #[allow(clippy::too_many_lines)]
    fn execute_replace_inner<I: sovereign_policy::ExecutionIsolationBackend>(
        &mut self,
        lease: &mut ReadyLease,
        runtime: &ExecutionRuntime<'_, I>,
        context: &ContextPacket,
        model_budget: &mut ModelCallBudget,
    ) -> Result<ExecutionSuccess, ControllerError> {
        self.validate_ready_lease(lease, runtime.registry)?;
        let model_deadline_ms = self.task_model_deadline_ms(&lease.task_id)?;
        match self.consume_task_model_call(&lease.task_id, model_budget, model_deadline_ms) {
            Ok(()) => {}
            Err(ControllerError::Policy(error @ PolicyError::ResourceDenied(_))) => {
                self.transition_task(
                    &lease.task_id,
                    TaskState::DeferredResource,
                    "task_deferred_resource",
                )?;
                return Err(ControllerError::Policy(error));
            }
            Err(error) => return Err(error),
        }
        let attempt_id = self.start_attempt(lease, runtime.registry)?;
        let proposal = match Self::request_model_proposal(
            runtime.backend,
            context,
            &lease.task_id,
            model_deadline_ms,
        ) {
            Ok(value) => value,
            Err(error) => {
                let signature = sha256_prefixed(format!("proposal\0{error}").as_bytes());
                self.fail_attempt_and_route(&attempt_id, &lease.task_id, &signature)?;
                return Err(error);
            }
        };
        let validated =
            match self.validate_replace_proposal(runtime.registry, context, lease, proposal) {
                Ok(value) => value,
                Err(error) => {
                    let signature = sha256_prefixed(format!("proposal\0{error}").as_bytes());
                    self.fail_attempt_and_route(&attempt_id, &lease.task_id, &signature)?;
                    return Err(error);
                }
            };
        self.execute_validated_replace(lease, runtime, &attempt_id, &validated)
    }

    #[allow(clippy::too_many_lines)]
    fn execute_validated_replace<I: sovereign_policy::ExecutionIsolationBackend>(
        &mut self,
        lease: &mut ReadyLease,
        runtime: &ExecutionRuntime<'_, I>,
        attempt_id: &str,
        validated: &ValidatedReplace,
    ) -> Result<ExecutionSuccess, ControllerError> {
        let action = self.lower_replace_action(lease, attempt_id, validated, runtime)?;
        self.persist_action_intent(&action, validated, runtime.artifacts.root())?;
        {
            let mut journal = ActionJournal::new(&mut self.state);
            journal.authorize(&action, runtime.tool_manifest)?;
        }
        self.checkpoint_now()?;
        self.rebind_ready_checkpoint(lease)?;
        self.validate_ready_lease(lease, runtime.registry)?;
        let runner = ProcessRunner::new(runtime.command_policy, runtime.isolation_backend);
        let raw = {
            let mut journal = ActionJournal::new(&mut self.state);
            runner.run(
                &mut journal,
                &action,
                runtime.isolation_request,
                runtime.artifacts,
            )
        };
        let result = match raw {
            Ok(result) => result,
            Err(error) => {
                let record = self.state.action_record(&action.action_id)?;
                if record
                    .as_ref()
                    .is_some_and(|record| record.state == "unknown")
                {
                    self.mark_unknown(attempt_id, &lease.task_id, &action.action_id)?;
                    return Err(ControllerError::UnknownAction(action.action_id));
                }
                let signature = sha256_prefixed(format!("runner\0{error}").as_bytes());
                self.fail_attempt_and_route(attempt_id, &lease.task_id, &signature)?;
                return Err(ControllerError::Tool(error));
            }
        };
        self.checkpoint_now()?;
        recovery_test_hook("after_mutation_checkpoint");
        if result.exit_code != Some(0) || result.terminated_for_limit.is_some() {
            let failure = self.execution_failure(lease, attempt_id, &action, &result)?;
            self.fail_attempt_and_route(attempt_id, &lease.task_id, &failure.signature)?;
            return Err(ControllerError::ExecutionFailed(Box::new(failure)));
        }
        self.transition_attempt(attempt_id, AttemptState::Verifying, "attempt_verifying")?;
        self.transition_task(&lease.task_id, TaskState::Verifying, "task_verifying")?;
        recovery_test_hook("verification_started");
        let verification_binding = VerificationLeaseBinding::from(&*lease);
        let verification = DeterministicVerifier::verify(
            &self.state,
            self.active_ref()?,
            runtime.registry,
            &verification_binding,
            attempt_id,
            &action.action_id,
            action.destination_digest.as_deref(),
            validated,
        )?;
        let verification_bytes = serde_json::to_vec(&verification)?;
        let artifact = runtime
            .artifacts
            .put(&mut self.state, &verification_bytes)?;
        let verification_evidence_id = format!(
            "evidence.verification.{}",
            digest_fragment(&artifact.digest, 16)
        );
        self.state
            .add_artifact_reference(&verification_evidence_id, &artifact.digest)?;
        self.state.put_state(
            "controller.verification",
            &verification.verification_id,
            &serde_json::to_string(&verification)?,
        )?;
        self.append_controller_event(
            "verification_recorded",
            &verification.verification_id,
            &json!({"passed": verification.passed, "artifact_digest": artifact.digest}),
        )?;
        self.checkpoint_now()?;
        if !verification.passed {
            let signature = sha256_prefixed(
                format!(
                    "verification\0{}",
                    verification.failure_code.as_deref().unwrap_or("unknown")
                )
                .as_bytes(),
            );
            self.fail_attempt_and_route(attempt_id, &lease.task_id, &signature)?;
            return Err(ControllerError::VerificationFailed(Box::new(verification)));
        }
        self.record_verified_output_bindings(&verification, &artifact.digest)?;
        self.apply_verified_success(&verification)?;
        self.refresh_baseline_after_verified_success(runtime.registry)?;
        let action_record = self
            .state
            .action_record(&action.action_id)?
            .ok_or_else(|| {
                ControllerError::InvalidPlan("committed action disappeared".to_owned())
            })?;
        let action_result_digest = action_record.result_digest.ok_or_else(|| {
            ControllerError::InvalidPlan("committed action lacks result digest".to_owned())
        })?;
        Ok(ExecutionSuccess {
            task_id: lease.task_id.clone(),
            attempt_id: attempt_id.to_owned(),
            action_id: action.action_id,
            action_result_digest,
            verification_evidence_id,
            verification,
        })
    }

    fn check_task_readiness(
        &mut self,
        task_id: &str,
        task: &Value,
        inputs: ReadinessInputs<'_>,
    ) -> Result<(), ControllerError> {
        let state = self
            .active_ref()?
            .tasks
            .get(task_id)
            .ok_or_else(|| ControllerError::NotReady("missing task".to_owned()))?
            .state;
        if state != TaskState::Planned {
            return Err(ControllerError::NotReady(format!(
                "task state {state:?} is not eligible"
            )));
        }
        let dependencies = required_array(task, "/dependencies")?;
        let authoritative_dependencies_satisfied = dependencies.iter().all(|dependency| {
            dependency.as_str().is_some_and(|dependency_id| {
                self.active_ref()
                    .ok()
                    .and_then(|active| active.tasks.get(dependency_id))
                    .is_some_and(|dependency_task| dependency_task.state == TaskState::Succeeded)
            })
        });
        if !authoritative_dependencies_satisfied {
            return Err(ControllerError::NotReady(
                "hard dependencies are not succeeded in Controller-owned state".to_owned(),
            ));
        }
        let _ = self.effective_permission_digest(task)?;
        let current_sequence = self.state.latest_journal_sequence()?;
        self.state
            .validate_checkpoint_integrity_floor(current_sequence)?;
        if self.any_unknown_action()? {
            return Err(ControllerError::NotReady(
                "an action outcome remains unknown".to_owned(),
            ));
        }
        for value in [inputs.resource_digest] {
            if value.trim().is_empty() {
                return Err(ControllerError::NotReady(
                    "readiness binding digest is empty".to_owned(),
                ));
            }
        }
        Ok(())
    }

    fn effective_permission_digest(&self, task: &Value) -> Result<String, ControllerError> {
        if !self
            .permission_context
            .permits(PermissionClass::RepositoryWrite)
            || !self
                .permission_context
                .permits(PermissionClass::ProcessExec)
        {
            return Err(ControllerError::NotReady(
                "Controller/project/role/grant permission intersection denies repository mutation"
                    .to_owned(),
            ));
        }
        let active = self.active_ref()?;
        let plan = &active.plan_document;
        let global_permissions = required_array(plan, "/policy/capability_ceiling")?;
        let task_permissions = required_array(task, "/permissions")?;
        let global_repo_write = global_permissions
            .iter()
            .any(|permission| permission.as_str() == Some("repo_write"));
        let task_repo_write = task_permissions
            .iter()
            .any(|permission| permission.as_str() == Some("repo_write"));
        if !global_repo_write || !task_repo_write {
            return Err(ControllerError::NotReady(
                "Plan/task capability ceiling does not authorize repository mutation".to_owned(),
            ));
        }
        let tool = required_array(task, "/tools")?
            .first()
            .ok_or_else(|| ControllerError::InvalidPlan("task has no pinned tool".to_owned()))?;
        Ok(digest_json(&json!({
            "controller_context": self.permission_context.digest(),
            "global_capability_ceiling": global_permissions,
            "task_permissions": task_permissions,
            "pinned_tool": tool,
        }))?)
    }

    fn validate_exact_context_evidence(
        registry: &ProjectRegistry,
        repository_id: &str,
        item: &EvidenceItem,
    ) -> Result<(), ControllerError> {
        if item.repository_id.as_deref() != Some(repository_id) {
            return Err(ControllerError::NotReady(
                "evidence item repository does not match active repository".to_owned(),
            ));
        }
        match item.kind {
            EvidenceKind::SourceSlice | EvidenceKind::SearchHit | EvidenceKind::Instruction => {
                let prefix = format!("repo://{repository_id}/");
                let relative = item.source_uri.strip_prefix(&prefix).ok_or_else(|| {
                    ControllerError::NotReady(
                        "repository evidence lacks an exact repo:// source URI".to_owned(),
                    )
                })?;
                let current = ExactRetriever::new(registry).read_path(
                    repository_id,
                    Path::new(relative),
                    Some(&item.source_digest),
                )?;
                if sha256_prefixed(item.text.as_bytes()) != item.content_digest
                    || current.digest != item.source_digest
                {
                    return Err(ControllerError::NotReady(
                        "retained exact evidence digest is not current".to_owned(),
                    ));
                }
            }
            EvidenceKind::Diff => {
                let current = ExactRetriever::new(registry).current_diff(repository_id)?;
                if current.digest != item.source_digest
                    || sha256_prefixed(item.text.as_bytes()) != item.content_digest
                {
                    return Err(ControllerError::NotReady(
                        "retained diff evidence is not current".to_owned(),
                    ));
                }
            }
            _ => {
                return Err(ControllerError::NotReady(
                    "M1 execution evidence must be exact current repository evidence".to_owned(),
                ));
            }
        }
        Ok(())
    }

    fn resolve_readiness_evidence_digest(
        &self,
        registry: &ProjectRegistry,
        task_id: &str,
        task: &Value,
    ) -> Result<String, ControllerError> {
        let active = self.active_ref()?;
        let current_snapshot = registry.snapshot(&active.repository_id)?;
        let current_snapshot_digest = snapshot_digest(&current_snapshot)?;
        let mut evidence_records = self.resolve_evidence_satisfaction_digests(
            registry,
            task_id,
            task,
            &current_snapshot_digest,
        )?;
        let mut dependency_records =
            self.resolve_dependency_binding_digests(task, &current_snapshot_digest)?;
        evidence_records.sort();
        dependency_records.sort();
        Ok(digest_json(&json!({
            "evidence_satisfactions": evidence_records,
            "dependency_bindings": dependency_records,
        }))?)
    }

    fn resolve_evidence_satisfaction_digests(
        &self,
        registry: &ProjectRegistry,
        task_id: &str,
        task: &Value,
        current_snapshot_digest: &str,
    ) -> Result<Vec<String>, ControllerError> {
        let active = self.active_ref()?;
        let mut evidence_records = Vec::new();
        for requirement in execution_evidence_requirements(task)? {
            let requirement_id = required_str(requirement, "/requirement_id")?;
            let raw = self
                .state
                .get_state(
                    "controller.evidence_satisfaction",
                    &evidence_satisfaction_key(task_id, requirement_id),
                )?
                .ok_or_else(|| {
                    ControllerError::NotReady(format!(
                        "execution evidence requirement {requirement_id} is unsatisfied"
                    ))
                })?;
            let record: EvidenceSatisfactionV1 = serde_json::from_str(&raw)?;
            let query = required_str(requirement, "/query")?;
            let probe = exact_requirement_probe(query).ok_or_else(|| {
                ControllerError::NotReady(format!(
                    "evidence requirement {requirement_id} has no deterministic exact anchor"
                ))
            })?;
            let freshness = required_str(requirement, "/freshness")?;
            let snapshot_fresh = match freshness {
                "current_repository_snapshot" => {
                    record.repository_snapshot_digest == *current_snapshot_digest
                }
                "current_plan_revision" => true,
                _ => false,
            };
            if record.schema_version != EVIDENCE_SATISFACTION_SCHEMA_VERSION
                || record.plan_id != active.plan_id
                || record.plan_revision != active.revision
                || record.plan_digest != active.plan_digest
                || record.task_id != task_id
                || record.task_contract_digest
                    != active
                        .tasks
                        .get(task_id)
                        .ok_or_else(|| ControllerError::NotReady("task disappeared".to_owned()))?
                        .task_contract_digest
                || record.requirement_id != requirement_id
                || record.requirement_digest != digest_json(requirement)?
                || record.query_digest != sha256_prefixed(query.as_bytes())
                || record.evidence_ids.len() != record.evidence_digests.len()
                || record.evidence_ids.len() != record.evidence_record_keys.len()
                || !snapshot_fresh
            {
                return Err(ControllerError::NotReady(format!(
                    "evidence satisfaction {requirement_id} is stale or misbound"
                )));
            }
            for ((evidence_id, evidence_digest), evidence_key) in record
                .evidence_ids
                .iter()
                .zip(&record.evidence_digests)
                .zip(&record.evidence_record_keys)
            {
                let evidence_raw = self
                    .state
                    .get_state("controller.evidence_item", evidence_key)?
                    .ok_or_else(|| {
                        ControllerError::NotReady(format!(
                            "evidence satisfaction {requirement_id} lost retained evidence {evidence_id}"
                        ))
                    })?;
                let item: EvidenceItem = serde_json::from_str(&evidence_raw)?;
                if item.evidence_id != *evidence_id
                    || digest_json(&serde_json::to_value(&item)?)? != *evidence_digest
                {
                    return Err(ControllerError::NotReady(format!(
                        "retained evidence {evidence_id} no longer matches its durable digest"
                    )));
                }
                Self::validate_exact_context_evidence(registry, &active.repository_id, &item)?;
                validate_requirement_bound_evidence(
                    registry,
                    &active.repository_id,
                    &item,
                    &probe,
                )?;
            }
            evidence_records.push(digest_json(&serde_json::to_value(record)?)?);
        }
        Ok(evidence_records)
    }

    fn resolve_dependency_binding_digests(
        &self,
        task: &Value,
        current_snapshot_digest: &str,
    ) -> Result<Vec<String>, ControllerError> {
        let active = self.active_ref()?;
        let mut dependency_records = Vec::new();
        for binding in required_array(task, "/dependency_bindings")? {
            let upstream_task_id = required_str(binding, "/upstream_task_id")?;
            let upstream = active.tasks.get(upstream_task_id).ok_or_else(|| {
                ControllerError::NotReady(format!("unknown dependency task {upstream_task_id}"))
            })?;
            if upstream.state != TaskState::Succeeded {
                return Err(ControllerError::NotReady(format!(
                    "dependency task {upstream_task_id} is not succeeded"
                )));
            }
            for artifact_id in required_array(binding, "/required_artifact_ids")? {
                let artifact_id = artifact_id.as_str().ok_or_else(|| {
                    ControllerError::InvalidPlan(
                        "dependency artifact binding ID must be a string".to_owned(),
                    )
                })?;
                dependency_records.push(self.validated_output_binding_digest(
                    "controller.artifact_binding",
                    upstream_task_id,
                    &upstream.task_contract_digest,
                    artifact_id,
                    current_snapshot_digest,
                )?);
            }
            for criterion_id in required_array(binding, "/required_acceptance_criterion_ids")? {
                let criterion_id = criterion_id.as_str().ok_or_else(|| {
                    ControllerError::InvalidPlan(
                        "dependency criterion binding ID must be a string".to_owned(),
                    )
                })?;
                dependency_records.push(self.validated_output_binding_digest(
                    "controller.acceptance_binding",
                    upstream_task_id,
                    &upstream.task_contract_digest,
                    criterion_id,
                    current_snapshot_digest,
                )?);
            }
        }
        Ok(dependency_records)
    }

    fn validated_output_binding_digest(
        &self,
        namespace: &str,
        upstream_task_id: &str,
        upstream_task_contract_digest: &str,
        binding_id: &str,
        current_snapshot_digest: &str,
    ) -> Result<String, ControllerError> {
        let active = self.active_ref()?;
        let expected_kind = match namespace {
            "controller.artifact_binding" => "artifact",
            "controller.acceptance_binding" => "acceptance",
            other => {
                return Err(ControllerError::InvalidPlan(format!(
                    "unsupported output-binding namespace {other}"
                )));
            }
        };
        let raw = self
            .state
            .get_state(namespace, &output_binding_key(upstream_task_id, binding_id))?
            .ok_or_else(|| {
                ControllerError::NotReady(format!(
                    "missing verified dependency output binding {binding_id}"
                ))
            })?;
        let record: VerifiedOutputBindingV1 = serde_json::from_str(&raw)?;
        if record.schema_version != VERIFIED_OUTPUT_BINDING_SCHEMA_VERSION
            || record.plan_id != active.plan_id
            || record.plan_revision != active.revision
            || record.plan_digest != active.plan_digest
            || record.task_id != upstream_task_id
            || record.task_contract_digest != upstream_task_contract_digest
            || record.binding_kind != expected_kind
            || record.binding_id != binding_id
            || record.repository_snapshot_digest != current_snapshot_digest
        {
            return Err(ControllerError::NotReady(format!(
                "verified dependency output binding {binding_id} is stale or misbound"
            )));
        }
        if self
            .state
            .artifact_metadata(&record.verification_artifact_digest)?
            .is_none()
        {
            return Err(ControllerError::NotReady(format!(
                "verified dependency output binding {binding_id} lost its evidence artifact"
            )));
        }
        let verification_raw = self
            .state
            .get_state("controller.verification", &record.verification_id)?
            .ok_or_else(|| {
                ControllerError::NotReady(format!(
                    "verified dependency output binding {binding_id} lost its verification record"
                ))
            })?;
        let verification: VerificationResultV1 = serde_json::from_str(&verification_raw)?;
        if !verification.passed
            || verification.task_id != upstream_task_id
            || verification.task_contract_digest != upstream_task_contract_digest
            || verification.post_snapshot_digest != current_snapshot_digest
        {
            return Err(ControllerError::NotReady(format!(
                "verified dependency output binding {binding_id} has invalid acceptance evidence"
            )));
        }
        Ok(digest_json(&serde_json::to_value(record)?)?)
    }

    fn task_model_deadline_ms(&self, task_id: &str) -> Result<u64, ControllerError> {
        let active = self.active_ref()?;
        let task = active
            .tasks
            .get(task_id)
            .ok_or_else(|| ControllerError::InvalidPlan("task disappeared".to_owned()))?;
        let seconds = required_u32(&task.task, "/resource_budget/max_model_call_seconds")?;
        Ok(u64::from(seconds).saturating_mul(1_000))
    }

    fn consume_task_model_call(
        &mut self,
        task_id: &str,
        model_budget: &mut ModelCallBudget,
        requested_deadline_ms: u64,
    ) -> Result<(), ControllerError> {
        let (used, limit) = {
            let active = self.active_ref()?;
            let task = active
                .tasks
                .get(task_id)
                .ok_or_else(|| ControllerError::InvalidPlan("task disappeared".to_owned()))?;
            (
                task.model_calls_used,
                required_u32(&task.task, "/resource_budget/max_model_calls")?,
            )
        };
        if used >= limit {
            return Err(ControllerError::Policy(PolicyError::ResourceDenied(
                format!("task model-call budget exhausted: used={used}, limit={limit}"),
            )));
        }
        model_budget.consume_call(requested_deadline_ms)?;
        {
            let active = self.active_mut()?;
            let task = active
                .tasks
                .get_mut(task_id)
                .ok_or_else(|| ControllerError::InvalidPlan("task disappeared".to_owned()))?;
            task.model_calls_used = task.model_calls_used.saturating_add(1);
        }
        let task_json = serde_json::to_string(
            self.active_ref()?
                .tasks
                .get(task_id)
                .ok_or_else(|| ControllerError::InvalidPlan("task disappeared".to_owned()))?,
        )?;
        self.persist_runtime_records_with_events(
            &[("controller.task".to_owned(), task_id.to_owned(), task_json)],
            &[(
                "task_model_call_consumed".to_owned(),
                task_id.to_owned(),
                json!({"used": used.saturating_add(1), "limit": limit}),
            )],
        )?;
        self.checkpoint_now()?;
        Ok(())
    }

    fn validate_ready_lease(
        &mut self,
        lease: &ReadyLease,
        registry: &ProjectRegistry,
    ) -> Result<(), ControllerError> {
        self.require_current_baseline(registry)?;
        let active = self.active_ref()?;
        if active.validity != PlanValidity::Current
            || active.plan_id != lease.plan_id
            || active.revision != lease.plan_revision
            || active.plan_digest != lease.plan_digest
        {
            return Err(ControllerError::NotReady(
                "ready lease no longer binds the sole active/current plan".to_owned(),
            ));
        }
        let task = active
            .tasks
            .get(&lease.task_id)
            .ok_or_else(|| ControllerError::NotReady("ready task disappeared".to_owned()))?;
        if task.task_contract_digest != lease.task_contract_digest
            || snapshot_digest(&active.baseline)? != lease.baseline_digest
            || self.state.current_execution_epoch()? != lease.execution_epoch
            || ready_lease_digest(lease) != lease.lease_digest
        {
            return Err(ControllerError::NotReady(
                "ready lease binding is stale".to_owned(),
            ));
        }
        let (generation, action_sequence, checkpoint_hash) = self.current_checkpoint_binding()?;
        let current_evidence_binding =
            self.resolve_readiness_evidence_digest(registry, &lease.task_id, &task.task)?;
        if generation != lease.checkpoint_generation
            || action_sequence != lease.checkpoint_action_sequence
            || checkpoint_hash != lease.checkpoint_hash
            || self.effective_permission_digest(&task.task)? != lease.permission_digest
            || current_evidence_binding != lease.evidence_binding_digest
        {
            return Err(ControllerError::NotReady(
                "ready lease checkpoint/evidence/permission binding is stale".to_owned(),
            ));
        }
        Ok(())
    }

    fn require_current_baseline(
        &mut self,
        registry: &ProjectRegistry,
    ) -> Result<(), ControllerError> {
        if self.active_ref()?.validity != PlanValidity::Current {
            return Err(ControllerError::NotReady(
                "active plan validity is not current".to_owned(),
            ));
        }
        let (repository_id, expected) = {
            let active = self.active_ref()?;
            (active.repository_id.clone(), active.baseline.clone())
        };
        let current = registry.snapshot(&repository_id)?;
        if current != expected {
            if let Some(active) = self.active.as_mut() {
                active.validity = PlanValidity::StaleEvidence;
            }
            let epoch = self.state.advance_execution_epoch()?;
            let (repository_snapshot_digest, baseline_diff_digest, plan_validity) = {
                let active = self.active_ref()?;
                (
                    snapshot_digest(&active.baseline)?,
                    active.baseline_diff_digest.clone(),
                    active.validity,
                )
            };
            self.persist_plan_baseline_with_event(
                "plan_stale_evidence",
                &repository_id,
                &json!({
                    "execution_epoch": epoch,
                    "repository_snapshot_digest": repository_snapshot_digest,
                    "baseline_diff_digest": baseline_diff_digest,
                    "plan_validity": plan_validity,
                }),
            )?;
            self.checkpoint_now()?;
            return Err(ControllerError::NotReady(
                "repository baseline drifted; stale-evidence revalidation required".to_owned(),
            ));
        }
        Ok(())
    }

    fn request_model_proposal(
        backend: &dyn ModelBackend,
        context: &ContextPacket,
        task_id: &str,
        model_deadline_ms: u64,
    ) -> Result<ModelProposalV1, ControllerError> {
        let request = ModelRequest {
            schema_version: MODEL_SCHEMA_VERSION,
            request_id: format!("controller.{task_id}.proposal"),
            messages: vec![
                ModelMessage {
                    role: ModelMessageRole::System,
                    content: "Return only ModelProposalV1. Propose one exact replace_literal action. Never emit task state, success, permissions, authorization, shell, or tool execution directives.".to_owned(),
                    tool_call_id: None,
                },
                ModelMessage {
                    role: ModelMessageRole::User,
                    content: context.serialized_input.clone(),
                    tool_call_id: None,
                },
            ],
            tools: Vec::new(),
            output_contract: ModelOutputContract::JsonSchema {
                name: "ModelProposalV1".to_owned(),
                schema: model_proposal_schema(),
            },
            input_token_ceiling: context.budget.max_input_tokens,
            max_output_tokens: M1_MODEL_OUTPUT_TOKENS,
            deadline_ms: model_deadline_ms,
            temperature_milli: 0,
        };
        let response = backend.complete(&request)?;
        if response.finish_reason != ModelFinishReason::Stop || !response.tool_calls.is_empty() {
            return Err(ControllerError::ProposalRejected(
                "proposal must finish normally without model tool calls".to_owned(),
            ));
        }
        let proposal: ModelProposalV1 =
            serde_json::from_str(&response.content).map_err(|error| {
                ControllerError::ProposalRejected(format!(
                    "strict ModelProposalV1 decode failed: {error}"
                ))
            })?;
        if proposal.schema_version != MODEL_PROPOSAL_SCHEMA_VERSION {
            return Err(ControllerError::ProposalRejected(
                "unsupported ModelProposalV1 schema_version".to_owned(),
            ));
        }
        let unique_evidence = proposal.evidence_ids.iter().collect::<BTreeSet<_>>();
        if proposal.evidence_ids.is_empty()
            || proposal.evidence_ids.len() > MAX_PROPOSAL_EVIDENCE_IDS
            || unique_evidence.len() != proposal.evidence_ids.len()
            || proposal.evidence_ids.iter().any(|evidence_id| {
                evidence_id.is_empty() || evidence_id.len() > MAX_PROPOSAL_EVIDENCE_ID_BYTES
            })
        {
            return Err(ControllerError::ProposalRejected(
                "ModelProposalV1 evidence_ids violate deterministic bounds".to_owned(),
            ));
        }
        Ok(proposal)
    }

    fn validate_replace_proposal(
        &self,
        registry: &ProjectRegistry,
        context: &ContextPacket,
        lease: &ReadyLease,
        proposal: ModelProposalV1,
    ) -> Result<ValidatedReplace, ControllerError> {
        let active = self.active_ref()?;
        let task = active
            .tasks
            .get(&lease.task_id)
            .ok_or_else(|| ControllerError::ProposalRejected("task disappeared".to_owned()))?;
        let allowed_evidence = context
            .items
            .iter()
            .map(|item| item.evidence_id.as_str())
            .collect::<BTreeSet<_>>();
        if proposal.evidence_ids.is_empty()
            || proposal
                .evidence_ids
                .iter()
                .any(|evidence_id| !allowed_evidence.contains(evidence_id.as_str()))
        {
            return Err(ControllerError::ProposalRejected(
                "proposal cites evidence outside the current ContextPacket".to_owned(),
            ));
        }
        let action = proposal.action;
        if action.repository_id != active.repository_id
            || action.expected_occurrences != 1
            || action.old_literal.is_empty()
            || action.old_literal == action.new_literal
            || action.old_literal.len() > MAX_LITERAL_BYTES
            || action.new_literal.len() > MAX_LITERAL_BYTES
            || !action.expected_source_digest.starts_with("sha256:")
        {
            return Err(ControllerError::ProposalRejected(
                "replace_literal action violates deterministic M1 bounds".to_owned(),
            ));
        }
        let scoped_files = required_array(&task.task, "/scope/files")?;
        if !scoped_files
            .iter()
            .filter_map(Value::as_str)
            .any(|path| path == action.path)
        {
            return Err(ControllerError::ProposalRejected(
                "replace_literal path is outside exact active task scope".to_owned(),
            ));
        }
        let target_path = PathBuf::from(&action.path);
        if active.baseline.untracked.paths.contains(&target_path)
            || baseline_target_added_line_contains_literal(
                &active.baseline_diff_content,
                &action.path,
                &action.old_literal,
            )
        {
            return Err(ControllerError::ProposalRejected(
                "replace_literal would modify a pre-existing user-owned target hunk".to_owned(),
            ));
        }
        if !compiled_literal_contract_allows(&active.plan_document, &task.task, &action)? {
            return Err(ControllerError::ProposalRejected(
                "replace_literal is not entailed by the immutable compiled literal contract"
                    .to_owned(),
            ));
        }
        let retriever = ExactRetriever::new(registry);
        let source = retriever.read_path(
            &action.repository_id,
            Path::new(&action.path),
            Some(&action.expected_source_digest),
        )?;
        if source.content.matches(&action.old_literal).count() != 1 {
            return Err(ControllerError::ProposalRejected(
                "replace_literal preimage does not contain exactly one old literal".to_owned(),
            ));
        }
        let expected_post = source
            .content
            .replacen(&action.old_literal, &action.new_literal, 1);
        let expected_post_digest = sha256_prefixed(expected_post.as_bytes());
        let target_metadata = fs::symlink_metadata(active.repository_root.join(&action.path))?;
        if !target_metadata.is_file() || target_metadata.file_type().is_symlink() {
            return Err(ControllerError::ProposalRejected(
                "replace_literal target must remain a regular non-symlink file".to_owned(),
            ));
        }
        Ok(ValidatedReplace {
            proposal: action,
            expected_post_digest,
            expected_target_mode: permission_mode(&target_metadata),
        })
    }

    fn lower_replace_action<I: sovereign_policy::ExecutionIsolationBackend>(
        &self,
        lease: &ReadyLease,
        attempt_id: &str,
        validated: &ValidatedReplace,
        runtime: &ExecutionRuntime<'_, I>,
    ) -> Result<AuthorizedAction, ControllerError> {
        let command_policy = runtime.command_policy;
        let isolation_request = runtime.isolation_request;
        let manifest = runtime.tool_manifest;
        let python_executable = runtime.python_executable;
        let active = self.active_ref()?;
        let task = active
            .tasks
            .get(&lease.task_id)
            .ok_or_else(|| ControllerError::InvalidPlan("task disappeared".to_owned()))?;
        let tool = required_array(&task.task, "/tools")?
            .first()
            .ok_or_else(|| ControllerError::InvalidPlan("task has no pinned tool".to_owned()))?;
        let tool_id = required_str(tool, "/id")?;
        let tool_version = required_str(tool, "/version")?;
        let tool_digest = required_str(tool, "/digest")?;
        if manifest.tool_id != tool_id
            || manifest.version != tool_version
            || manifest.content_digest != tool_digest
            || !manifest
                .permission_ceiling
                .contains(&PermissionClass::RepositoryWrite)
        {
            return Err(ControllerError::InvalidPlan(
                "runtime tool manifest does not match active task pin/permission".to_owned(),
            ));
        }
        if !isolation_request.allow_repository_write
            || !isolation_request.network_offline
            || isolation_request.repository_root.canonicalize()? != active.repository_root
        {
            return Err(ControllerError::Policy(PolicyError::Denied(
                "replace_literal requires exact offline repository-write isolation".to_owned(),
            )));
        }
        let python = command_policy.pinned_executable(python_executable)?;
        let destination = active.repository_root.join(&validated.proposal.path);
        let command = sovereign_policy::CommandSpec {
            executable: python.path.clone(),
            args: vec![
                "-I".to_owned(),
                "-c".to_owned(),
                ATOMIC_REPLACE_HELPER.to_owned(),
                destination.display().to_string(),
                validated.proposal.expected_source_digest.clone(),
                validated.proposal.old_literal.clone(),
                validated.proposal.new_literal.clone(),
            ],
            working_directory: active.repository_root.clone(),
            environment: BTreeMap::new(),
            mode: CommandMode::Direct,
            declared_risk: CommandRisk::RepositoryMutation,
            timeout_ms: 5_000,
            output_limit_bytes: 64 * 1_024,
            disk_write_limit_bytes: 2 * 1_024 * 1_024,
            subprocess_limit: 0,
        };
        let action_seed = digest_json(&json!({
            "plan": lease.plan_digest,
            "task": lease.task_contract_digest,
            "attempt": attempt_id,
            "proposal": validated.proposal,
        }))?;
        Ok(AuthorizedAction {
            action_id: format!("action.{}", &action_seed[7..27]),
            plan_id: active.plan_id.clone(),
            plan_revision: active.revision,
            task_id: lease.task_id.clone(),
            attempt_id: attempt_id.to_owned(),
            tool_id: tool_id.to_owned(),
            tool_version: tool_version.to_owned(),
            tool_digest: tool_digest.to_owned(),
            executable_digest: python.sha256.clone(),
            repository_id: active.repository_id.clone(),
            destination_digest: Some(validated.proposal.expected_source_digest.clone()),
            permission_class: PermissionClass::RepositoryWrite,
            execution_epoch: lease.execution_epoch,
            policy_digest: active.policy_digest.clone(),
            isolation_policy_digest: isolation_request.digest()?,
            nonce: format!("nonce.{}", &action_seed[27..47]),
            expires_at_ms: unix_millis()?.saturating_add(60_000),
            command,
            individually_authorized_environment: BTreeSet::new(),
            reconciliation_mode: ReconciliationMode::UnsafeSideEffect,
        })
    }

    fn persist_action_intent(
        &mut self,
        action: &AuthorizedAction,
        validated: &ValidatedReplace,
        artifact_store_root: &Path,
    ) -> Result<(), ControllerError> {
        let (plan_digest, task_contract_digest) = {
            let active = self.active_ref()?;
            let task = active.tasks.get(&action.task_id).ok_or_else(|| {
                ControllerError::InvalidPlan("action intent task disappeared".to_owned())
            })?;
            (
                active.plan_digest.clone(),
                task.task_contract_digest.clone(),
            )
        };
        let intent = PersistedActionIntent {
            schema_version: ACTION_INTENT_SCHEMA_VERSION,
            action_id: action.action_id.clone(),
            plan_id: action.plan_id.clone(),
            plan_revision: action.plan_revision,
            plan_digest,
            task_id: action.task_id.clone(),
            task_contract_digest,
            attempt_id: action.attempt_id.clone(),
            execution_epoch: action.execution_epoch,
            payload_digest: action.payload_digest(),
            action_nonce: action.nonce.clone(),
            policy_digest: action.policy_digest.clone(),
            repository_id: action.repository_id.clone(),
            path: validated.proposal.path.clone(),
            expected_source_digest: validated.proposal.expected_source_digest.clone(),
            old_literal: validated.proposal.old_literal.clone(),
            new_literal: validated.proposal.new_literal.clone(),
            expected_post_digest: validated.expected_post_digest.clone(),
            expected_target_mode: validated.expected_target_mode,
            artifact_store_root: artifact_store_root.to_path_buf(),
        };
        self.state.put_state(
            "controller.action_intent",
            &action.action_id,
            &serde_json::to_string(&intent)?,
        )?;
        Ok(())
    }

    fn validate_recovered_action_intent(
        &self,
        intent: &PersistedActionIntent,
        registry: &ProjectRegistry,
    ) -> Result<ValidatedReplace, ControllerError> {
        let active = self.active_ref()?;
        let task = active.tasks.get(&intent.task_id).ok_or_else(|| {
            ControllerError::NotReady("recovery action task disappeared".to_owned())
        })?;
        if intent.schema_version != ACTION_INTENT_SCHEMA_VERSION
            || intent.plan_id != active.plan_id
            || intent.plan_revision != active.revision
            || intent.plan_digest != active.plan_digest
            || intent.repository_id != active.repository_id
            || intent.policy_digest != active.policy_digest
            || intent.task_contract_digest != task.task_contract_digest
        {
            return Err(ControllerError::NotReady(
                "recovery action intent is stale or misbound".to_owned(),
            ));
        }
        let proposal = ReplaceLiteral {
            kind: ReplaceLiteralKind::ReplaceLiteral,
            repository_id: intent.repository_id.clone(),
            path: intent.path.clone(),
            expected_source_digest: intent.expected_source_digest.clone(),
            old_literal: intent.old_literal.clone(),
            new_literal: intent.new_literal.clone(),
            expected_occurrences: 1,
        };
        if !compiled_literal_contract_allows(&active.plan_document, &task.task, &proposal)? {
            return Err(ControllerError::NotReady(
                "recovery action no longer matches compiled acceptance contract".to_owned(),
            ));
        }
        let scoped_files = required_array(&task.task, "/scope/files")?;
        if !scoped_files
            .iter()
            .filter_map(Value::as_str)
            .any(|path| path == proposal.path)
        {
            return Err(ControllerError::NotReady(
                "recovery action target is outside active task scope".to_owned(),
            ));
        }
        let source = ExactRetriever::new(registry).read_path(
            &intent.repository_id,
            Path::new(&intent.path),
            Some(&intent.expected_source_digest),
        )?;
        if source.content.matches(&intent.old_literal).count() != 1 {
            return Err(ControllerError::NotReady(
                "recovery preimage no longer contains exactly one old literal".to_owned(),
            ));
        }
        let expected_post = source
            .content
            .replacen(&intent.old_literal, &intent.new_literal, 1);
        let expected_post_digest = sha256_prefixed(expected_post.as_bytes());
        let current_mode = permission_mode(&fs::symlink_metadata(
            active.repository_root.join(&intent.path),
        )?);
        if expected_post_digest != intent.expected_post_digest
            || current_mode != intent.expected_target_mode
        {
            return Err(ControllerError::NotReady(
                "recovery action postimage/mode contract no longer matches durable intent"
                    .to_owned(),
            ));
        }
        Ok(ValidatedReplace {
            proposal,
            expected_post_digest,
            expected_target_mode: intent.expected_target_mode,
        })
    }

    #[allow(clippy::too_many_lines)]
    fn resume_recovery_verification(
        &mut self,
        registry: &ProjectRegistry,
        action_id: &str,
    ) -> Result<(), ControllerError> {
        let raw = self
            .state
            .get_state("controller.action_intent", action_id)?
            .ok_or_else(|| {
                ControllerError::InvalidPlan(format!(
                    "recovery verification intent {action_id} is missing"
                ))
            })?;
        let intent: PersistedActionIntent = serde_json::from_str(&raw)?;
        let record = self
            .state
            .action_record(action_id)?
            .ok_or_else(|| ControllerError::InvalidPlan("recovery action missing".to_owned()))?;
        if record.state != "committed"
            || record.result_digest.is_none()
            || record.payload_digest != intent.payload_digest
        {
            return Err(ControllerError::NotReady(format!(
                "recovery action {action_id} is not durably committed"
            )));
        }
        let (task_contract_digest, baseline_digest) = {
            let active = self.active_ref()?;
            let task = active.tasks.get(&intent.task_id).ok_or_else(|| {
                ControllerError::InvalidPlan("recovery verification task missing".to_owned())
            })?;
            let attempt = active.attempts.get(&intent.attempt_id).ok_or_else(|| {
                ControllerError::InvalidPlan("recovery verification attempt missing".to_owned())
            })?;
            if task.state != TaskState::Verifying || attempt.state != AttemptState::Verifying {
                return Err(ControllerError::NotReady(
                    "recovery verification state is not Verifying".to_owned(),
                ));
            }
            (
                task.task_contract_digest.clone(),
                attempt.baseline_digest.clone(),
            )
        };
        let proposal = ReplaceLiteral {
            kind: ReplaceLiteralKind::ReplaceLiteral,
            repository_id: intent.repository_id.clone(),
            path: intent.path.clone(),
            expected_source_digest: intent.expected_source_digest.clone(),
            old_literal: intent.old_literal.clone(),
            new_literal: intent.new_literal.clone(),
            expected_occurrences: 1,
        };
        let validated = ValidatedReplace {
            proposal,
            expected_post_digest: intent.expected_post_digest.clone(),
            expected_target_mode: intent.expected_target_mode,
        };
        let active = self.active_ref()?;
        let binding = VerificationLeaseBinding {
            plan_id: active.plan_id.clone(),
            plan_revision: active.revision,
            plan_digest: active.plan_digest.clone(),
            task_id: intent.task_id.clone(),
            task_contract_digest,
            baseline_digest,
            execution_epoch: self.state.current_execution_epoch()?,
        };
        let verification = DeterministicVerifier::verify(
            &self.state,
            self.active_ref()?,
            registry,
            &binding,
            &intent.attempt_id,
            action_id,
            Some(&intent.expected_source_digest),
            &validated,
        )?;
        let artifacts = ArtifactStore::open(&intent.artifact_store_root)?;
        let verification_bytes = serde_json::to_vec(&verification)?;
        let artifact = artifacts.put(&mut self.state, &verification_bytes)?;
        let verification_evidence_id = format!(
            "evidence.verification.{}",
            digest_fragment(&artifact.digest, 16)
        );
        self.state
            .add_artifact_reference(&verification_evidence_id, &artifact.digest)?;
        self.state.put_state(
            "controller.verification",
            &verification.verification_id,
            &serde_json::to_string(&verification)?,
        )?;
        self.append_controller_event(
            "recovery_verification_recorded",
            &verification.verification_id,
            &json!({"passed": verification.passed, "artifact_digest": artifact.digest}),
        )?;
        self.checkpoint_now()?;
        if !verification.passed {
            let signature = sha256_prefixed(
                format!(
                    "recovery-verification\0{}",
                    verification.failure_code.as_deref().unwrap_or("unknown")
                )
                .as_bytes(),
            );
            self.fail_attempt_and_route(&intent.attempt_id, &intent.task_id, &signature)?;
            return Err(ControllerError::VerificationFailed(Box::new(verification)));
        }
        self.record_verified_output_bindings(&verification, &artifact.digest)?;
        self.apply_verified_success(&verification)?;
        self.refresh_baseline_after_verified_success(registry)?;
        Ok(())
    }

    fn execution_failure(
        &self,
        lease: &ReadyLease,
        attempt_id: &str,
        action: &AuthorizedAction,
        result: &RawToolResult,
    ) -> Result<ExecutionFailureV1, ControllerError> {
        let record = self
            .state
            .action_record(&action.action_id)?
            .ok_or_else(|| ControllerError::InvalidPlan("action result missing".to_owned()))?;
        if record.state != "committed" || record.result_digest.is_none() {
            return Err(ControllerError::UnknownAction(action.action_id.clone()));
        }
        let result_digest = record.result_digest;
        let signature = sha256_prefixed(
            format!(
                "execution\0{:?}\0{:?}\0{}",
                result.exit_code,
                result.terminated_for_limit,
                result_digest.as_deref().unwrap_or_default()
            )
            .as_bytes(),
        );
        Ok(ExecutionFailureV1 {
            schema_version: 1,
            plan_id: lease.plan_id.clone(),
            task_id: lease.task_id.clone(),
            attempt_id: attempt_id.to_owned(),
            action_id: Some(action.action_id.clone()),
            result_digest,
            exit_code: result.exit_code,
            signature,
            category: if result.terminated_for_limit.is_some() {
                "resource_failure".to_owned()
            } else {
                "execution_failure".to_owned()
            },
        })
    }

    fn start_attempt(
        &mut self,
        lease: &ReadyLease,
        registry: &ProjectRegistry,
    ) -> Result<String, ControllerError> {
        let (repository_id, repository_root, baseline_diff_digest) = {
            let active = self.active_ref()?;
            (
                active.repository_id.clone(),
                active.repository_root.clone(),
                active.baseline_diff_digest.clone(),
            )
        };
        let pre_snapshot = registry.snapshot(&repository_id)?;
        let pre_snapshot_digest = snapshot_digest(&pre_snapshot)?;
        if pre_snapshot_digest != lease.baseline_digest {
            return Err(ControllerError::NotReady(
                "repository changed before attempt start".to_owned(),
            ));
        }
        let pre_diff = ExactRetriever::new(registry).current_diff(&repository_id)?;
        if pre_diff.digest != baseline_diff_digest {
            return Err(ControllerError::NotReady(
                "repository diff changed before attempt start".to_owned(),
            ));
        }
        let pre_changed_paths = snapshot_changed_paths(&pre_snapshot);
        let pre_changed_fingerprints =
            capture_protected_fingerprints(&repository_root, &pre_changed_paths)?;
        let attempt_number = {
            let active = self.active_mut()?;
            let task = active.tasks.get_mut(&lease.task_id).ok_or_else(|| {
                ControllerError::NotReady("ready task disappeared before attempt".to_owned())
            })?;
            task.attempts_started = task.attempts_started.saturating_add(1);
            task.state = TaskState::Running;
            task.attempts_started
        };
        let seed = sha256_prefixed(
            format!(
                "{}\0{}\0{}\0{}",
                lease.plan_digest,
                lease.task_contract_digest,
                lease.execution_epoch,
                attempt_number
            )
            .as_bytes(),
        );
        let attempt_id = format!("attempt.{}", &seed[7..27]);
        let attempt = AttemptRuntime {
            task_id: lease.task_id.clone(),
            attempt_id: attempt_id.clone(),
            state: AttemptState::Executing,
            task_contract_digest: lease.task_contract_digest.clone(),
            baseline_digest: lease.baseline_digest.clone(),
            pre_snapshot_digest,
            pre_diff_digest: pre_diff.digest,
            pre_changed_fingerprints,
        };
        self.active_mut()?
            .attempts
            .insert(attempt_id.clone(), attempt);
        let task_json = serde_json::to_string(
            self.active_ref()?
                .tasks
                .get(&lease.task_id)
                .ok_or_else(|| ControllerError::InvalidPlan("task disappeared".to_owned()))?,
        )?;
        let attempt_json = serde_json::to_string(
            self.active_ref()?
                .attempts
                .get(&attempt_id)
                .ok_or_else(|| ControllerError::InvalidPlan("attempt disappeared".to_owned()))?,
        )?;
        self.persist_runtime_records_with_events(
            &[
                (
                    "controller.task".to_owned(),
                    lease.task_id.clone(),
                    task_json,
                ),
                (
                    "controller.attempt".to_owned(),
                    attempt_id.clone(),
                    attempt_json,
                ),
            ],
            &[(
                "attempt_started".to_owned(),
                attempt_id.clone(),
                json!({"task_id": lease.task_id, "attempt_number": attempt_number}),
            )],
        )?;
        self.checkpoint_now()?;
        Ok(attempt_id)
    }

    fn transition_attempt(
        &mut self,
        attempt_id: &str,
        next: AttemptState,
        event: &str,
    ) -> Result<(), ControllerError> {
        let active = self.active_mut()?;
        let attempt = active
            .attempts
            .get_mut(attempt_id)
            .ok_or_else(|| ControllerError::InvalidPlan(format!("unknown attempt {attempt_id}")))?;
        if !legal_attempt_transition(attempt.state, next) {
            return Err(ControllerError::InvalidPlan(format!(
                "illegal attempt transition {:?}->{next:?}",
                attempt.state
            )));
        }
        attempt.state = next;
        let value = serde_json::to_string(
            self.active_ref()?
                .attempts
                .get(attempt_id)
                .ok_or_else(|| ControllerError::InvalidPlan("attempt disappeared".to_owned()))?,
        )?;
        self.persist_runtime_records_with_events(
            &[(
                "controller.attempt".to_owned(),
                attempt_id.to_owned(),
                value,
            )],
            &[(
                event.to_owned(),
                attempt_id.to_owned(),
                json!({"state": next}),
            )],
        )?;
        self.checkpoint_now()?;
        Ok(())
    }

    fn transition_task(
        &mut self,
        task_id: &str,
        next: TaskState,
        event: &str,
    ) -> Result<(), ControllerError> {
        let active = self.active_mut()?;
        let task = active
            .tasks
            .get_mut(task_id)
            .ok_or_else(|| ControllerError::InvalidPlan(format!("unknown task {task_id}")))?;
        if !legal_task_transition(task.state, next) {
            return Err(ControllerError::InvalidPlan(format!(
                "illegal task transition {:?}->{next:?}",
                task.state
            )));
        }
        task.state = next;
        let value = serde_json::to_string(
            self.active_ref()?
                .tasks
                .get(task_id)
                .ok_or_else(|| ControllerError::InvalidPlan("task disappeared".to_owned()))?,
        )?;
        self.persist_runtime_records_with_events(
            &[("controller.task".to_owned(), task_id.to_owned(), value)],
            &[(event.to_owned(), task_id.to_owned(), json!({"state": next}))],
        )?;
        self.checkpoint_now()?;
        Ok(())
    }

    fn fail_attempt_and_route(
        &mut self,
        attempt_id: &str,
        task_id: &str,
        signature: &str,
    ) -> Result<(), ControllerError> {
        let (attempt_was_failed, max_attempts, same_failure_limit, attempts_started, same_count) = {
            let active = self.active_mut()?;
            let attempt = active
                .attempts
                .get_mut(attempt_id)
                .ok_or_else(|| ControllerError::InvalidPlan("attempt disappeared".to_owned()))?;
            let attempt_was_failed = attempt.state == AttemptState::Failed;
            if !attempt_was_failed {
                if !legal_attempt_transition(attempt.state, AttemptState::Failed) {
                    return Err(ControllerError::InvalidPlan(format!(
                        "illegal attempt transition {:?}->{:?}",
                        attempt.state,
                        AttemptState::Failed
                    )));
                }
                attempt.state = AttemptState::Failed;
            }
            let task = active
                .tasks
                .get_mut(task_id)
                .ok_or_else(|| ControllerError::InvalidPlan("task disappeared".to_owned()))?;
            let count = task.failure_counts.entry(signature.to_owned()).or_insert(0);
            *count = count.saturating_add(1);
            let max_attempts = required_u32(&task.task, "/failure_policy/max_attempts")?;
            let same_limit = required_u32(&task.task, "/failure_policy/same_failure_limit")?;
            (
                attempt_was_failed,
                max_attempts,
                same_limit,
                task.attempts_started,
                *count,
            )
        };
        let retry_allowed = repair_allowed(
            attempts_started,
            max_attempts,
            same_count,
            same_failure_limit,
        );
        {
            let task = self
                .active_mut()?
                .tasks
                .get_mut(task_id)
                .ok_or_else(|| ControllerError::InvalidPlan("task disappeared".to_owned()))?;
            task.state = TaskState::RepairPending;
            task.retry_exhausted = !retry_allowed;
        }
        let attempt_json = serde_json::to_string(
            self.active_ref()?
                .attempts
                .get(attempt_id)
                .ok_or_else(|| ControllerError::InvalidPlan("attempt disappeared".to_owned()))?,
        )?;
        let task_json = serde_json::to_string(
            self.active_ref()?
                .tasks
                .get(task_id)
                .ok_or_else(|| ControllerError::InvalidPlan("task disappeared".to_owned()))?,
        )?;
        let mut events = Vec::new();
        if !attempt_was_failed {
            events.push((
                "attempt_failed".to_owned(),
                attempt_id.to_owned(),
                json!({"state": AttemptState::Failed}),
            ));
        }
        events.push((
            "task_repair_pending".to_owned(),
            task_id.to_owned(),
            json!({
                "failure_signature": signature,
                "attempts_started": attempts_started,
                "same_failure_count": same_count,
                "retry_allowed": retry_allowed
            }),
        ));
        self.persist_runtime_records_with_events(
            &[
                (
                    "controller.attempt".to_owned(),
                    attempt_id.to_owned(),
                    attempt_json,
                ),
                ("controller.task".to_owned(), task_id.to_owned(), task_json),
            ],
            &events,
        )?;
        self.checkpoint_now()?;
        Ok(())
    }

    fn mark_unknown(
        &mut self,
        attempt_id: &str,
        task_id: &str,
        action_id: &str,
    ) -> Result<(), ControllerError> {
        self.transition_attempt(attempt_id, AttemptState::Interrupted, "attempt_interrupted")?;
        self.transition_task(
            task_id,
            TaskState::ReconcilingUnknown,
            "task_reconciling_unknown",
        )?;
        self.append_controller_event(
            "unknown_action_blocks_replay",
            action_id,
            &json!({"task_id": task_id, "attempt_id": attempt_id}),
        )?;
        self.checkpoint_now()?;
        Ok(())
    }

    fn record_verified_output_bindings(
        &mut self,
        verification: &VerificationResultV1,
        verification_artifact_digest: &str,
    ) -> Result<(), ControllerError> {
        let (expected_artifacts, acceptance_criteria, task_contract_digest) = {
            let active = self.active_ref()?;
            let task = active.tasks.get(&verification.task_id).ok_or_else(|| {
                ControllerError::InvalidPlan("verification task disappeared".to_owned())
            })?;
            (
                required_array(&task.task, "/expected_artifacts")?.clone(),
                required_array(&task.task, "/acceptance_criteria")?.clone(),
                task.task_contract_digest.clone(),
            )
        };
        for artifact in expected_artifacts
            .iter()
            .filter(|artifact| artifact.get("required").and_then(Value::as_bool) == Some(true))
        {
            let binding_id = required_str(artifact, "/artifact_id")?;
            self.persist_verified_output_binding(
                "controller.artifact_binding",
                "artifact",
                binding_id,
                &task_contract_digest,
                verification,
                verification_artifact_digest,
            )?;
        }
        for criterion in acceptance_criteria
            .iter()
            .filter(|criterion| criterion.get("required").and_then(Value::as_bool) == Some(true))
        {
            let binding_id = required_str(criterion, "/criterion_id")?;
            self.persist_verified_output_binding(
                "controller.acceptance_binding",
                "acceptance",
                binding_id,
                &task_contract_digest,
                verification,
                verification_artifact_digest,
            )?;
        }
        self.checkpoint_now()?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn persist_verified_output_binding(
        &mut self,
        namespace: &str,
        binding_kind: &str,
        binding_id: &str,
        task_contract_digest: &str,
        verification: &VerificationResultV1,
        verification_artifact_digest: &str,
    ) -> Result<(), ControllerError> {
        let active = self.active_ref()?;
        let record = VerifiedOutputBindingV1 {
            schema_version: VERIFIED_OUTPUT_BINDING_SCHEMA_VERSION,
            plan_id: active.plan_id.clone(),
            plan_revision: active.revision,
            plan_digest: active.plan_digest.clone(),
            task_id: verification.task_id.clone(),
            task_contract_digest: task_contract_digest.to_owned(),
            attempt_id: verification.attempt_id.clone(),
            binding_kind: binding_kind.to_owned(),
            binding_id: binding_id.to_owned(),
            verification_id: verification.verification_id.clone(),
            verification_artifact_digest: verification_artifact_digest.to_owned(),
            repository_snapshot_digest: verification.post_snapshot_digest.clone(),
        };
        self.state.put_state(
            namespace,
            &output_binding_key(&verification.task_id, binding_id),
            &serde_json::to_string(&record)?,
        )?;
        self.append_controller_event(
            "verified_output_bound",
            &verification.task_id,
            &json!({
                "binding_kind": binding_kind,
                "binding_id": binding_id,
                "verification_id": verification.verification_id,
            }),
        )?;
        Ok(())
    }

    fn apply_verified_success(
        &mut self,
        verification: &VerificationResultV1,
    ) -> Result<(), ControllerError> {
        if !verification.passed {
            return Err(ControllerError::VerificationFailed(Box::new(
                verification.clone(),
            )));
        }
        let active = self.active_ref()?;
        if active.plan_id != verification.plan_id
            || active.revision != verification.plan_revision
            || active.plan_digest != verification.plan_digest
            || self.state.current_execution_epoch()? != verification.execution_epoch
        {
            return Err(ControllerError::VerificationFailed(Box::new(
                verification.clone(),
            )));
        }
        let task = active
            .tasks
            .get(&verification.task_id)
            .ok_or_else(|| ControllerError::VerificationFailed(Box::new(verification.clone())))?;
        let attempt = active
            .attempts
            .get(&verification.attempt_id)
            .ok_or_else(|| ControllerError::VerificationFailed(Box::new(verification.clone())))?;
        if task.state != TaskState::Verifying
            || task.task_contract_digest != verification.task_contract_digest
            || attempt.task_id != verification.task_id
            || attempt.state != AttemptState::Verifying
        {
            return Err(ControllerError::VerificationFailed(Box::new(
                verification.clone(),
            )));
        }
        {
            let active = self.active_mut()?;
            active
                .attempts
                .get_mut(&verification.attempt_id)
                .ok_or_else(|| ControllerError::VerificationFailed(Box::new(verification.clone())))?
                .state = AttemptState::Succeeded;
            active
                .tasks
                .get_mut(&verification.task_id)
                .ok_or_else(|| ControllerError::VerificationFailed(Box::new(verification.clone())))?
                .state = TaskState::Succeeded;
        }
        let attempt_json = serde_json::to_string(
            self.active_ref()?
                .attempts
                .get(&verification.attempt_id)
                .ok_or_else(|| ControllerError::InvalidPlan("attempt disappeared".to_owned()))?,
        )?;
        let task_json = serde_json::to_string(
            self.active_ref()?
                .tasks
                .get(&verification.task_id)
                .ok_or_else(|| ControllerError::InvalidPlan("task disappeared".to_owned()))?,
        )?;
        self.persist_runtime_records_with_events(
            &[
                (
                    "controller.attempt".to_owned(),
                    verification.attempt_id.clone(),
                    attempt_json,
                ),
                (
                    "controller.task".to_owned(),
                    verification.task_id.clone(),
                    task_json,
                ),
            ],
            &[
                (
                    "attempt_succeeded".to_owned(),
                    verification.attempt_id.clone(),
                    json!({"state": AttemptState::Succeeded}),
                ),
                (
                    "task_succeeded".to_owned(),
                    verification.task_id.clone(),
                    json!({"state": TaskState::Succeeded}),
                ),
            ],
        )?;
        self.checkpoint_now()?;
        Ok(())
    }

    fn rebind_ready_checkpoint(&self, lease: &mut ReadyLease) -> Result<(), ControllerError> {
        if self.state.current_execution_epoch()? != lease.execution_epoch {
            return Err(ControllerError::NotReady(
                "execution epoch changed before dispatch".to_owned(),
            ));
        }
        let (generation, action_sequence, checkpoint_hash) = self.current_checkpoint_binding()?;
        lease.checkpoint_generation = generation;
        lease.checkpoint_action_sequence = action_sequence;
        lease.checkpoint_hash = checkpoint_hash;
        lease.lease_digest = ready_lease_digest(lease);
        Ok(())
    }

    fn refresh_baseline_after_verified_success(
        &mut self,
        registry: &ProjectRegistry,
    ) -> Result<(), ControllerError> {
        let repository_id = self.active_ref()?.repository_id.clone();
        let refreshed = registry.snapshot(&repository_id)?;
        let refreshed_diff = ExactRetriever::new(registry).current_diff(&repository_id)?;
        {
            let active = self.active_mut()?;
            active.baseline = refreshed;
            active.baseline_diff_digest = refreshed_diff.digest;
            active.baseline_diff_content = refreshed_diff.content;
            active.validity = PlanValidity::Current;
        }
        let epoch = self.state.advance_execution_epoch()?;
        let (repository_snapshot_digest, baseline_diff_digest, plan_validity) = {
            let active = self.active_ref()?;
            (
                snapshot_digest(&active.baseline)?,
                active.baseline_diff_digest.clone(),
                active.validity,
            )
        };
        self.persist_plan_baseline_with_event(
            "verified_baseline_advanced",
            &repository_id,
            &json!({
                "execution_epoch": epoch,
                "repository_snapshot_digest": repository_snapshot_digest,
                "baseline_diff_digest": baseline_diff_digest,
                "plan_validity": plan_validity,
            }),
        )?;
        self.checkpoint_now()?;
        Ok(())
    }

    fn current_checkpoint_binding(&self) -> Result<(i64, i64, String), ControllerError> {
        let sequence = self.state.latest_journal_sequence()?;
        let checkpoint = self.state.validate_checkpoint_integrity_floor(sequence)?;
        Ok(checkpoint.map_or_else(
            || (0, 0, "genesis:0".to_owned()),
            |record| {
                (
                    record.generation,
                    record.action_sequence,
                    record.checkpoint_hash,
                )
            },
        ))
    }

    fn checkpoint_now(&mut self) -> Result<(), ControllerError> {
        let manifest = self.checkpoint_manifest()?;
        let bytes = serde_json::to_vec(&canonicalize(&serde_json::to_value(&manifest)?))?;
        let store = checkpoint_artifact_store(self.state.path())?;
        let artifact = store.put(&mut self.state, &bytes)?;
        let checkpoint = self
            .state
            .append_checkpoint_integrity(NewCheckpointIntegrityRecord {
                payload_digest: &artifact.digest,
                action_sequence: manifest.action_journal_sequence,
            })?;
        self.state.add_artifact_reference(
            &format!("checkpoint.manifest.{}", checkpoint.generation),
            &artifact.digest,
        )?;
        Ok(())
    }

    fn checkpoint_recovery_reanchor(
        &mut self,
        trusted: &CheckpointIntegrityRecord,
    ) -> Result<(), ControllerError> {
        let manifest = self.checkpoint_manifest()?;
        let bytes = serde_json::to_vec(&canonicalize(&serde_json::to_value(&manifest)?))?;
        let store = checkpoint_artifact_store(self.state.path())?;
        let artifact = store.put(&mut self.state, &bytes)?;
        let checkpoint = self.state.append_recovery_checkpoint_integrity(
            NewCheckpointIntegrityRecord {
                payload_digest: &artifact.digest,
                action_sequence: manifest.action_journal_sequence,
            },
            trusted.generation,
            &trusted.checkpoint_hash,
        )?;
        self.state.add_artifact_reference(
            &format!("checkpoint.manifest.{}", checkpoint.generation),
            &artifact.digest,
        )?;
        Ok(())
    }

    fn checkpoint_manifest(&self) -> Result<CheckpointManifest, ControllerError> {
        let active = self.active_ref()?;
        let task_records = active
            .tasks
            .iter()
            .map(|(id, task)| Ok((id.clone(), serde_json::to_value(task)?)))
            .collect::<Result<BTreeMap<_, _>, serde_json::Error>>()?;
        let attempt_records = active
            .attempts
            .iter()
            .map(|(id, attempt)| Ok((id.clone(), serde_json::to_value(attempt)?)))
            .collect::<Result<BTreeMap<_, _>, serde_json::Error>>()?;
        let mut evidence_binding_digests = BTreeMap::new();
        for namespace in [
            "controller.evidence_satisfaction",
            "controller.evidence_item",
            "controller.artifact_binding",
            "controller.acceptance_binding",
            "controller.verification",
            "controller.action_intent",
        ] {
            for record in self.state.state_records(namespace)? {
                evidence_binding_digests.insert(
                    format!("{}:{}", record.namespace, record.key),
                    sha256_prefixed(record.value_json.as_bytes()),
                );
            }
        }
        let action_records = self
            .state
            .action_records()?
            .into_iter()
            .map(|record| CheckpointActionRecord {
                action_id: record.action_id,
                state: record.state,
                payload_digest: record.payload_digest,
                policy_digest: record.policy_digest,
                execution_epoch: record.execution_epoch,
                result_digest: record.result_digest,
                last_event_sequence: record.last_event_sequence,
            })
            .collect();
        let process_leases = self
            .state
            .state_records("controller.process_lease")?
            .into_iter()
            .map(|record| serde_json::from_str::<RecoveryProcessLease>(&record.value_json))
            .collect::<Result<Vec<_>, _>>()?;
        let repository_snapshot_digest = snapshot_digest(&active.baseline)?;
        Ok(CheckpointManifest {
            schema_version: CHECKPOINT_MANIFEST_SCHEMA_VERSION,
            plan_document: active.plan_document.clone(),
            plan_id: active.plan_id.clone(),
            goal_id: active.goal_id.clone(),
            plan_revision: active.revision,
            plan_digest: active.plan_digest.clone(),
            compiler_plan_digest: active.compiler_plan_digest.clone(),
            compilation_evidence_digest: active.compilation_evidence_digest.clone(),
            policy_digest: active.policy_digest.clone(),
            repository_id: active.repository_id.clone(),
            repository_root: active.repository_root.clone(),
            repository_snapshot: active.baseline.clone(),
            repository_snapshot_digest,
            baseline_diff_digest: active.baseline_diff_digest.clone(),
            baseline_diff_content: active.baseline_diff_content.clone(),
            plan_validity: active.validity,
            task_records,
            attempt_records,
            evidence_binding_digests,
            action_records,
            process_leases,
            action_journal_sequence: self.state.latest_journal_sequence()?,
            execution_epoch: self.state.current_execution_epoch()?,
        })
    }

    fn persist_all_runtime(&mut self) -> Result<(), ControllerError> {
        let task_ids = self.active_ref()?.tasks.keys().cloned().collect::<Vec<_>>();
        let attempt_ids = self
            .active_ref()?
            .attempts
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        let (plan_record, plan_document_json, baseline_json) = {
            let active = self.active_ref()?;
            (
                json!({
                    "plan_id": active.plan_id,
                    "goal_id": active.goal_id,
                    "revision": active.revision,
                    "plan_digest": active.plan_digest,
                    "compilation_evidence_digest": active.compilation_evidence_digest,
                    "validity": active.validity,
                }),
                serde_json::to_string(&active.plan_document)?,
                serde_json::to_string(&PersistedRepositoryBaseline {
                    snapshot: active.baseline.clone(),
                    diff_digest: active.baseline_diff_digest.clone(),
                    diff_content: active.baseline_diff_content.clone(),
                })?,
            )
        };
        self.state.put_state(
            "controller.plan",
            "active",
            &serde_json::to_string(&plan_record)?,
        )?;
        self.state
            .put_state("controller.plan_document", "active", &plan_document_json)?;
        self.state
            .put_state("controller.repository_baseline", "active", &baseline_json)?;
        for task_id in task_ids {
            self.persist_task(&task_id)?;
        }
        for attempt_id in attempt_ids {
            let value =
                serde_json::to_string(self.active_ref()?.attempts.get(&attempt_id).ok_or_else(
                    || ControllerError::InvalidPlan("attempt disappeared".to_owned()),
                )?)?;
            self.state
                .put_state("controller.attempt", &attempt_id, &value)?;
        }
        Ok(())
    }

    fn persist_task(&mut self, task_id: &str) -> Result<(), ControllerError> {
        let value = {
            let task = self
                .active_ref()?
                .tasks
                .get(task_id)
                .ok_or_else(|| ControllerError::InvalidPlan("task disappeared".to_owned()))?;
            serde_json::to_string(task)?
        };
        self.state.put_state("controller.task", task_id, &value)?;
        Ok(())
    }

    fn append_controller_event(
        &mut self,
        event_kind: &str,
        entity_id: &str,
        payload: &Value,
    ) -> Result<(), ControllerError> {
        let seed = sha256_prefixed(
            format!(
                "{}\0{}\0{}\0{}",
                event_kind,
                entity_id,
                self.state.latest_journal_sequence()?,
                serde_json::to_string(&payload)?
            )
            .as_bytes(),
        );
        self.state.append_event(NewJournalEvent {
            event_id: &format!("controller.{}", &seed[7..27]),
            entity_type: "controller",
            entity_id,
            event_kind,
            payload_json: &serde_json::to_string(&payload)?,
        })?;
        Ok(())
    }

    fn persist_runtime_records_with_events(
        &mut self,
        records: &[(String, String, String)],
        events: &[(String, String, Value)],
    ) -> Result<(), ControllerError> {
        let base_sequence = self.state.latest_journal_sequence()?;
        let bound_events = events
            .iter()
            .map(|(event_kind, entity_id, payload)| {
                Ok((
                    event_kind.clone(),
                    entity_id.clone(),
                    self.runtime_bound_event_payload(entity_id, payload)?,
                ))
            })
            .collect::<Result<Vec<_>, ControllerError>>()?;
        let payloads = bound_events
            .iter()
            .map(|(_, _, payload)| serde_json::to_string(payload))
            .collect::<Result<Vec<_>, _>>()?;
        let event_ids = bound_events
            .iter()
            .zip(&payloads)
            .enumerate()
            .map(|(index, ((event_kind, entity_id, _), payload_json))| {
                let sequence_seed =
                    base_sequence.saturating_add(i64::try_from(index).unwrap_or(i64::MAX));
                let seed = sha256_prefixed(
                    format!("{event_kind}\0{entity_id}\0{sequence_seed}\0{payload_json}")
                        .as_bytes(),
                );
                format!("controller.{}", &seed[7..27])
            })
            .collect::<Vec<_>>();
        let updates = records
            .iter()
            .map(|(namespace, key, value_json)| StateRecordUpdate {
                namespace,
                key,
                value_json,
            })
            .collect::<Vec<_>>();
        let journal_events = bound_events
            .iter()
            .zip(&payloads)
            .zip(&event_ids)
            .map(
                |(((event_kind, entity_id, _), payload_json), event_id)| NewJournalEvent {
                    event_id,
                    entity_type: "controller",
                    entity_id,
                    event_kind,
                    payload_json,
                },
            )
            .collect::<Vec<_>>();
        self.state
            .put_state_records_with_events(&updates, &journal_events)?;
        Ok(())
    }

    fn runtime_bound_event_payload(
        &self,
        entity_id: &str,
        payload: &Value,
    ) -> Result<Value, ControllerError> {
        let mut bound = payload.clone();
        let object = bound.as_object_mut().ok_or_else(|| {
            ControllerError::InvalidPlan("controller event payload must be an object".to_owned())
        })?;
        let active = self.active_ref()?;
        if let Some(task) = active.tasks.get(entity_id) {
            object.insert("task_id".to_owned(), Value::String(entity_id.to_owned()));
            object.insert("task_runtime".to_owned(), serde_json::to_value(task)?);
        }
        if let Some(attempt) = active.attempts.get(entity_id) {
            object.insert("attempt_runtime".to_owned(), serde_json::to_value(attempt)?);
            object.insert("task_id".to_owned(), Value::String(attempt.task_id.clone()));
            if let Some(task) = active.tasks.get(&attempt.task_id) {
                object.insert("task_runtime".to_owned(), serde_json::to_value(task)?);
            }
        }
        Ok(bound)
    }

    fn persist_plan_baseline_with_event(
        &mut self,
        event_kind: &str,
        entity_id: &str,
        payload: &Value,
    ) -> Result<(), ControllerError> {
        let (plan_json, baseline_json) = {
            let active = self.active_ref()?;
            (
                serde_json::to_string(&json!({
                    "plan_id": active.plan_id,
                    "goal_id": active.goal_id,
                    "revision": active.revision,
                    "plan_digest": active.plan_digest,
                    "compilation_evidence_digest": active.compilation_evidence_digest,
                    "validity": active.validity,
                }))?,
                serde_json::to_string(&PersistedRepositoryBaseline {
                    snapshot: active.baseline.clone(),
                    diff_digest: active.baseline_diff_digest.clone(),
                    diff_content: active.baseline_diff_content.clone(),
                })?,
            )
        };
        self.persist_runtime_records_with_events(
            &[
                ("controller.plan".to_owned(), "active".to_owned(), plan_json),
                (
                    "controller.repository_baseline".to_owned(),
                    "active".to_owned(),
                    baseline_json,
                ),
            ],
            &[(event_kind.to_owned(), entity_id.to_owned(), payload.clone())],
        )
    }

    fn persist_recovery_runtime_with_event(
        &mut self,
        plan_id: &str,
        payload: &Value,
    ) -> Result<(), ControllerError> {
        let mut records = Vec::new();
        let active = self.active_ref()?;
        records.push((
            "controller.plan".to_owned(),
            "active".to_owned(),
            serde_json::to_string(&json!({
                "plan_id": active.plan_id,
                "goal_id": active.goal_id,
                "revision": active.revision,
                "plan_digest": active.plan_digest,
                "compilation_evidence_digest": active.compilation_evidence_digest,
                "validity": active.validity,
            }))?,
        ));
        records.push((
            "controller.plan_document".to_owned(),
            "active".to_owned(),
            serde_json::to_string(&active.plan_document)?,
        ));
        records.push((
            "controller.repository_baseline".to_owned(),
            "active".to_owned(),
            serde_json::to_string(&PersistedRepositoryBaseline {
                snapshot: active.baseline.clone(),
                diff_digest: active.baseline_diff_digest.clone(),
                diff_content: active.baseline_diff_content.clone(),
            })?,
        ));
        for (task_id, runtime) in &active.tasks {
            records.push((
                "controller.task".to_owned(),
                task_id.clone(),
                serde_json::to_string(runtime)?,
            ));
        }
        for (attempt_id, runtime) in &active.attempts {
            records.push((
                "controller.attempt".to_owned(),
                attempt_id.clone(),
                serde_json::to_string(runtime)?,
            ));
        }
        self.persist_runtime_records_with_events(
            &records,
            &[(
                "recovery_reconstructed".to_owned(),
                plan_id.to_owned(),
                payload.clone(),
            )],
        )
    }

    fn any_unknown_action(&self) -> Result<bool, ControllerError> {
        Ok(self
            .state
            .action_records()?
            .iter()
            .any(|record| record.state == "unknown"))
    }

    fn active_ref(&self) -> Result<&ActivePlan, ControllerError> {
        self.active
            .as_ref()
            .ok_or_else(|| ControllerError::InvalidPlan("no active compiler plan".to_owned()))
    }

    fn active_mut(&mut self) -> Result<&mut ActivePlan, ControllerError> {
        self.active
            .as_mut()
            .ok_or_else(|| ControllerError::InvalidPlan("no active compiler plan".to_owned()))
    }
}

impl RecoveryManager {
    /// Reconstructs the active Controller exclusively from durable SQLite/CAS/Git state.
    /// No chat transcript, model call, or raw `PlanIr` activation surface participates.
    ///
    /// # Errors
    /// Returns a fail-closed recovery error when durable authority cannot be reconciled.
    pub fn recover(
        state: StateStore,
        registry: &ProjectRegistry,
    ) -> Result<(Controller, RecoverySummary), ControllerError> {
        Self::recover_with_permission_context(
            state,
            registry,
            PermissionContext::m1_local_autonomous(),
        )
    }

    /// Same recovery path with an explicitly narrowed Controller permission context.
    ///
    /// # Errors
    /// Returns a fail-closed recovery error when checkpoint, state, process, action, or Git
    /// authority cannot be reconciled.
    #[allow(clippy::too_many_lines)]
    pub fn recover_with_permission_context(
        state: StateStore,
        registry: &ProjectRegistry,
        permission_context: PermissionContext,
    ) -> Result<(Controller, RecoverySummary), ControllerError> {
        state.recovery_integrity_check()?;
        let physical_latest = state.latest_checkpoint_integrity()?.ok_or_else(|| {
            ControllerError::InvalidPlan("recovery requires at least one checkpoint".to_owned())
        })?;
        let latest_valid = state.latest_valid_checkpoint_integrity()?.ok_or_else(|| {
            ControllerError::InvalidPlan("recovery found no valid checkpoint floor".to_owned())
        })?;
        let (trusted_checkpoint, manifest) =
            load_latest_recoverable_manifest(&state, &latest_valid)?;
        validate_checkpoint_manifest(&manifest, &trusted_checkpoint)?;
        validate_checkpoint_immutable_bindings(&state, &manifest)?;
        let fallback_checkpoint_used = trusted_checkpoint.generation != physical_latest.generation;
        let replayed_events = validate_post_checkpoint_runtime_correlation(
            &state,
            &manifest,
            trusted_checkpoint.action_sequence,
        )?;
        let active = reconstruct_active_plan(&state, registry, &manifest)?;
        let trusted_recovery_intent_digests = manifest
            .evidence_binding_digests
            .iter()
            .filter_map(|(key, digest)| {
                key.strip_prefix("controller.action_intent:")
                    .map(|action_id| (action_id.to_owned(), digest.clone()))
            })
            .collect();
        let execution_epoch_before = state.current_execution_epoch()?;
        let mut controller = Controller {
            state,
            active: Some(active),
            resource_governor: M1ResourceGovernor::default(),
            permission_context,
            trusted_recovery_intent_digests,
        };

        let (unresolved_process_lease_ids, unresolved_process_actions) =
            reap_recovery_process_leases(&mut controller.state)?;
        let mut unknown_action_ids = reconcile_recovery_actions(
            &mut controller.state,
            registry,
            &unresolved_process_actions,
            &manifest,
        )?;
        let (interrupted_attempt_ids, pending_recovery_action_ids, verification_actions) =
            normalize_recovered_runtime(&mut controller, &unknown_action_ids)?;
        require_checkpoint_bound_recovery_intents(
            &controller.state,
            &manifest,
            pending_recovery_action_ids
                .iter()
                .chain(verification_actions.iter()),
        )?;

        let execution_epoch_after_reconstruction = controller.state.advance_execution_epoch()?;
        let task_runtimes = controller
            .active_ref()?
            .tasks
            .iter()
            .map(|(task_id, runtime)| Ok((task_id.clone(), serde_json::to_value(runtime)?)))
            .collect::<Result<BTreeMap<_, _>, serde_json::Error>>()?;
        let attempt_runtimes = controller
            .active_ref()?
            .attempts
            .iter()
            .map(|(attempt_id, runtime)| Ok((attempt_id.clone(), serde_json::to_value(runtime)?)))
            .collect::<Result<BTreeMap<_, _>, serde_json::Error>>()?;
        controller.persist_recovery_runtime_with_event(
            &manifest.plan_id,
            &json!({
                "trusted_checkpoint_generation": trusted_checkpoint.generation,
                "trusted_checkpoint_sequence": trusted_checkpoint.action_sequence,
                "fallback_checkpoint_used": fallback_checkpoint_used,
                "replayed_events": replayed_events,
                "interrupted_attempt_ids": interrupted_attempt_ids,
                "unknown_action_ids": unknown_action_ids,
                "pending_recovery_action_ids": pending_recovery_action_ids,
                "unresolved_process_lease_ids": unresolved_process_lease_ids,
                "execution_epoch_before": execution_epoch_before,
                "execution_epoch_after": execution_epoch_after_reconstruction,
                "task_runtimes": task_runtimes,
                "attempt_runtimes": attempt_runtimes,
            }),
        )?;
        if fallback_checkpoint_used {
            controller.checkpoint_recovery_reanchor(&trusted_checkpoint)?;
        } else {
            controller.checkpoint_now()?;
        }

        for action_id in verification_actions {
            controller.resume_recovery_verification(registry, &action_id)?;
        }
        unknown_action_ids = controller
            .state
            .action_records()?
            .into_iter()
            .filter(|record| record.state == "unknown")
            .map(|record| record.action_id)
            .collect();
        let execution_epoch_after = controller.state.current_execution_epoch()?;
        let mutation_blocked = !unknown_action_ids.is_empty()
            || !unresolved_process_lease_ids.is_empty()
            || controller
                .active_ref()?
                .tasks
                .values()
                .any(|task| task.state == TaskState::ReconcilingUnknown);
        let summary = RecoverySummary {
            plan_id: manifest.plan_id,
            plan_digest: manifest.plan_digest,
            checkpoint_generation: trusted_checkpoint.generation,
            checkpoint_action_sequence: trusted_checkpoint.action_sequence,
            replayed_events,
            execution_epoch_before,
            execution_epoch_after,
            interrupted_attempt_ids,
            unknown_action_ids,
            pending_recovery_action_ids,
            unresolved_process_lease_ids,
            fallback_checkpoint_used,
            mutation_blocked,
        };
        Ok((controller, summary))
    }
}

fn load_latest_recoverable_manifest(
    state: &StateStore,
    latest_valid: &CheckpointIntegrityRecord,
) -> Result<(CheckpointIntegrityRecord, CheckpointManifest), ControllerError> {
    let store = checkpoint_artifact_store(state.path())?;
    let ancestry = state.latest_valid_checkpoint_ancestry()?;
    if ancestry.first().is_none_or(|checkpoint| {
        checkpoint.generation != latest_valid.generation
            || checkpoint.checkpoint_hash != latest_valid.checkpoint_hash
    }) {
        return Err(ControllerError::InvalidPlan(
            "latest valid checkpoint is not the head of its trusted ancestry".to_owned(),
        ));
    }
    for checkpoint in ancestry {
        let manifest = (|| -> Result<CheckpointManifest, ControllerError> {
            let mut file = store.open_artifact(state, &checkpoint.payload_digest)?;
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)?;
            let manifest: CheckpointManifest = serde_json::from_slice(&bytes)?;
            validate_checkpoint_manifest(&manifest, &checkpoint)?;
            Ok(manifest)
        })();
        if let Ok(manifest) = manifest {
            return Ok((checkpoint, manifest));
        }
    }
    Err(ControllerError::InvalidPlan(
        "no checkpoint has a verifiable manifest CAS object".to_owned(),
    ))
}

fn validate_checkpoint_manifest(
    manifest: &CheckpointManifest,
    checkpoint: &CheckpointIntegrityRecord,
) -> Result<(), ControllerError> {
    if manifest.schema_version != CHECKPOINT_MANIFEST_SCHEMA_VERSION
        || manifest.action_journal_sequence != checkpoint.action_sequence
        || manifest.compiler_plan_digest != manifest.plan_digest
        || digest_json(&manifest.plan_document)? != manifest.plan_digest
        || snapshot_digest(&manifest.repository_snapshot)? != manifest.repository_snapshot_digest
        || manifest.repository_snapshot.repository_id != manifest.repository_id
        || manifest.repository_snapshot.root != manifest.repository_root
    {
        return Err(ControllerError::InvalidPlan(
            "checkpoint manifest integrity/binding mismatch".to_owned(),
        ));
    }
    let plan_tasks = required_array(&manifest.plan_document, "/tasks")?;
    if manifest.task_records.len() != plan_tasks.len() {
        return Err(ControllerError::InvalidPlan(
            "checkpoint task set does not match canonical plan".to_owned(),
        ));
    }
    for plan_task in plan_tasks {
        let task_id = required_str(plan_task, "/task_id")?;
        let record = manifest.task_records.get(task_id).ok_or_else(|| {
            ControllerError::InvalidPlan(format!("checkpoint is missing task runtime {task_id}"))
        })?;
        let runtime: TaskRuntime = serde_json::from_value(record.clone())?;
        if runtime.task_contract_digest != digest_json(plan_task)? || runtime.task != *plan_task {
            return Err(ControllerError::InvalidPlan(format!(
                "checkpoint task contract {task_id} is misbound"
            )));
        }
    }
    Ok(())
}

fn validate_checkpoint_immutable_bindings(
    state: &StateStore,
    manifest: &CheckpointManifest,
) -> Result<(), ControllerError> {
    for (binding_key, expected_digest) in &manifest.evidence_binding_digests {
        let Some(action_id) = binding_key.strip_prefix("controller.action_intent:") else {
            continue;
        };
        let current = state
            .get_state("controller.action_intent", action_id)?
            .ok_or_else(|| {
                ControllerError::InvalidPlan(format!(
                    "checkpoint-bound action intent {action_id} is missing"
                ))
            })?;
        if sha256_prefixed(current.as_bytes()) != *expected_digest {
            return Err(ControllerError::InvalidPlan(format!(
                "checkpoint-bound action intent {action_id} changed after checkpoint"
            )));
        }
    }
    Ok(())
}

fn validate_post_checkpoint_runtime_correlation(
    state: &StateStore,
    manifest: &CheckpointManifest,
    checkpoint_sequence: i64,
) -> Result<usize, ControllerError> {
    let events = state.journal_after(checkpoint_sequence)?;
    let mut replayed_tasks = manifest.task_records.clone();
    let mut replayed_attempts = manifest.attempt_records.clone();
    for event in &events {
        if event.entity_type != "controller" {
            continue;
        }
        let payload: Value = serde_json::from_str(&event.payload_json)?;
        if let Some(task_runtimes) = payload.get("task_runtimes").and_then(Value::as_object) {
            for (task_id, runtime) in task_runtimes {
                replayed_tasks.insert(task_id.clone(), runtime.clone());
            }
        }
        if let Some(attempt_runtimes) = payload.get("attempt_runtimes").and_then(Value::as_object) {
            for (attempt_id, runtime) in attempt_runtimes {
                replayed_attempts.insert(attempt_id.clone(), runtime.clone());
            }
        }
        if let Some(runtime) = payload.get("task_runtime") {
            let task_id = payload
                .get("task_id")
                .and_then(Value::as_str)
                .unwrap_or(event.entity_id.as_str());
            replayed_tasks.insert(task_id.to_owned(), runtime.clone());
        }
        if let Some(runtime) = payload.get("attempt_runtime") {
            replayed_attempts.insert(event.entity_id.clone(), runtime.clone());
        }
    }
    let current_tasks = state
        .state_records("controller.task")?
        .into_iter()
        .map(|record| {
            Ok((
                record.key,
                serde_json::from_str::<Value>(&record.value_json)?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>, ControllerError>>()?;
    if replayed_tasks != current_tasks {
        return Err(ControllerError::InvalidPlan(
            "current task state does not equal ordered post-checkpoint journal replay".to_owned(),
        ));
    }

    let current_attempts = state
        .state_records("controller.attempt")?
        .into_iter()
        .map(|record| {
            Ok((
                record.key,
                serde_json::from_str::<Value>(&record.value_json)?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>, ControllerError>>()?;
    if replayed_attempts != current_attempts {
        return Err(ControllerError::InvalidPlan(
            "current attempt state does not equal ordered post-checkpoint journal replay"
                .to_owned(),
        ));
    }
    validate_post_checkpoint_baseline_correlation(state, manifest, &events)?;
    Ok(events.len())
}

fn validate_post_checkpoint_baseline_correlation(
    state: &StateStore,
    manifest: &CheckpointManifest,
    events: &[JournalEvent],
) -> Result<(), ControllerError> {
    let raw_plan = state
        .get_state("controller.plan", "active")?
        .ok_or_else(|| ControllerError::InvalidPlan("active plan state is missing".to_owned()))?;
    let current_plan: Value = serde_json::from_str(&raw_plan)?;
    let current_validity: PlanValidity =
        serde_json::from_value(current_plan.get("validity").cloned().ok_or_else(|| {
            ControllerError::InvalidPlan("active validity is missing".to_owned())
        })?)?;
    let raw_baseline = state
        .get_state("controller.repository_baseline", "active")?
        .ok_or_else(|| {
            ControllerError::InvalidPlan("durable repository baseline is missing".to_owned())
        })?;
    let current_baseline: PersistedRepositoryBaseline = serde_json::from_str(&raw_baseline)?;
    let current_snapshot_digest = snapshot_digest(&current_baseline.snapshot)?;
    let baseline_changed = current_snapshot_digest != manifest.repository_snapshot_digest
        || current_baseline.diff_digest != manifest.baseline_diff_digest
        || current_baseline.diff_content != manifest.baseline_diff_content;
    let validity_changed = current_validity != manifest.plan_validity;
    if baseline_changed || validity_changed {
        let exact_transition = events
            .iter()
            .rev()
            .find(|event| {
                event.entity_type == "controller"
                    && event.entity_id == manifest.repository_id
                    && matches!(
                        event.event_kind.as_str(),
                        "verified_baseline_advanced" | "plan_stale_evidence"
                    )
            })
            .is_some_and(|event| {
                let Ok(payload) = serde_json::from_str::<Value>(&event.payload_json) else {
                    return false;
                };
                payload
                    .get("repository_snapshot_digest")
                    .and_then(Value::as_str)
                    == Some(current_snapshot_digest.as_str())
                    && payload.get("baseline_diff_digest").and_then(Value::as_str)
                        == Some(current_baseline.diff_digest.as_str())
                    && payload.get("plan_validity")
                        == serde_json::to_value(current_validity).ok().as_ref()
            });
        if !exact_transition {
            return Err(ControllerError::InvalidPlan(
                "current repository baseline/plan validity differs from checkpoint without an exact post-checkpoint transition event"
                    .to_owned(),
            ));
        }
    }
    Ok(())
}

fn require_checkpoint_bound_recovery_intents<'a>(
    state: &StateStore,
    manifest: &CheckpointManifest,
    action_ids: impl Iterator<Item = &'a String>,
) -> Result<(), ControllerError> {
    for action_id in action_ids {
        let current = state
            .get_state("controller.action_intent", action_id)?
            .ok_or_else(|| {
                ControllerError::NotReady(format!("recovery action intent {action_id} is missing"))
            })?;
        let key = format!("controller.action_intent:{action_id}");
        let Some(expected_digest) = manifest.evidence_binding_digests.get(&key) else {
            return Err(ControllerError::NotReady(format!(
                "recovery action intent {action_id} is not bound by the trusted checkpoint"
            )));
        };
        if sha256_prefixed(current.as_bytes()) != *expected_digest {
            return Err(ControllerError::NotReady(format!(
                "recovery action intent {action_id} differs from its trusted checkpoint binding"
            )));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn reconstruct_active_plan(
    state: &StateStore,
    registry: &ProjectRegistry,
    manifest: &CheckpointManifest,
) -> Result<ActivePlan, ControllerError> {
    let raw_plan = state
        .get_state("controller.plan", "active")?
        .ok_or_else(|| ControllerError::InvalidPlan("active plan state is missing".to_owned()))?;
    let plan_record: Value = serde_json::from_str(&raw_plan)?;
    let active_plan_id = required_str(&plan_record, "/plan_id")?;
    let active_plan_digest = required_str(&plan_record, "/plan_digest")?;
    let active_revision = required_u32(&plan_record, "/revision")?;
    if active_plan_id != manifest.plan_id
        || active_plan_digest != manifest.plan_digest
        || active_revision != manifest.plan_revision
    {
        return Err(ControllerError::InvalidPlan(
            "checkpoint belongs to a superseded plan; explicit N+1 carry-forward proof is required"
                .to_owned(),
        ));
    }
    let raw_document = state
        .get_state("controller.plan_document", "active")?
        .ok_or_else(|| {
            ControllerError::InvalidPlan("durable canonical plan document is missing".to_owned())
        })?;
    let plan_document: Value = serde_json::from_str(&raw_document)?;
    if digest_json(&plan_document)? != active_plan_digest {
        return Err(ControllerError::InvalidPlan(
            "durable canonical plan document digest does not match active plan".to_owned(),
        ));
    }
    let raw_baseline = state
        .get_state("controller.repository_baseline", "active")?
        .ok_or_else(|| {
            ControllerError::InvalidPlan("durable repository baseline is missing".to_owned())
        })?;
    let baseline: PersistedRepositoryBaseline = serde_json::from_str(&raw_baseline)?;
    let repository_id = required_str(&plan_document, "/repositories/0/repository_id")?.to_owned();
    let registered = registry.repository(&repository_id).ok_or_else(|| {
        ControllerError::InvalidPlan(format!(
            "recovery repository {repository_id} is not registered"
        ))
    })?;
    let repository_root = registered.root.canonicalize()?;
    if baseline.snapshot.repository_id != repository_id
        || baseline.snapshot.root.canonicalize()? != repository_root
    {
        return Err(ControllerError::InvalidPlan(
            "durable repository baseline is bound to another repository".to_owned(),
        ));
    }
    let plan_tasks = required_array(&plan_document, "/tasks")?;
    let plan_task_map = plan_tasks
        .iter()
        .map(|task| Ok((required_str(task, "/task_id")?.to_owned(), task)))
        .collect::<Result<BTreeMap<_, _>, ControllerError>>()?;
    let mut tasks = BTreeMap::new();
    for record in state.state_records("controller.task")? {
        let runtime: TaskRuntime = serde_json::from_str(&record.value_json)?;
        let plan_task = plan_task_map.get(&record.key).ok_or_else(|| {
            ControllerError::InvalidPlan(format!(
                "durable task {} is absent from active canonical plan",
                record.key
            ))
        })?;
        if runtime.task_contract_digest != digest_json(plan_task)? || &runtime.task != *plan_task {
            return Err(ControllerError::InvalidPlan(format!(
                "durable task {} contract is stale or altered",
                record.key
            )));
        }
        tasks.insert(record.key, runtime);
    }
    if tasks.len() != plan_task_map.len() {
        return Err(ControllerError::InvalidPlan(
            "durable task set is incomplete".to_owned(),
        ));
    }
    let attempts = state
        .state_records("controller.attempt")?
        .into_iter()
        .map(|record| {
            let attempt: AttemptRuntime = serde_json::from_str(&record.value_json)?;
            Ok((record.key, attempt))
        })
        .collect::<Result<BTreeMap<_, _>, ControllerError>>()?;
    let validity: PlanValidity =
        serde_json::from_value(plan_record.get("validity").cloned().ok_or_else(|| {
            ControllerError::InvalidPlan("active validity is missing".to_owned())
        })?)?;
    let compilation_evidence_digest =
        required_str(&plan_record, "/compilation_evidence_digest")?.to_owned();
    if compilation_evidence_digest != manifest.compilation_evidence_digest {
        return Err(ControllerError::InvalidPlan(
            "active compiler evidence digest differs from checkpoint plan provenance".to_owned(),
        ));
    }
    let policy_digest = digest_json(
        plan_document
            .get("policy")
            .ok_or_else(|| ControllerError::InvalidPlan("plan policy is missing".to_owned()))?,
    )?;
    Ok(ActivePlan {
        plan_document,
        compiler_plan_digest: active_plan_digest.to_owned(),
        plan_id: active_plan_id.to_owned(),
        goal_id: required_str(&plan_record, "/goal_id")?.to_owned(),
        revision: active_revision,
        plan_digest: active_plan_digest.to_owned(),
        compilation_evidence_digest,
        policy_digest,
        repository_id,
        repository_root,
        baseline: baseline.snapshot,
        baseline_diff_digest: baseline.diff_digest,
        baseline_diff_content: baseline.diff_content,
        validity,
        tasks,
        attempts,
    })
}

fn reap_recovery_process_leases(
    state: &mut StateStore,
) -> Result<(Vec<String>, BTreeSet<String>), ControllerError> {
    let mut unresolved = Vec::new();
    let mut unresolved_actions = BTreeSet::new();
    for record in state.state_records("controller.process_lease")? {
        let mut lease: RecoveryProcessLease = serde_json::from_str(&record.value_json)?;
        if lease.schema_version != RECOVERY_PROCESS_LEASE_SCHEMA_VERSION
            || !matches!(
                lease.state.as_str(),
                "active" | "reaped" | "reaped_recovery"
            )
        {
            unresolved.push(lease.lease_id.clone());
            unresolved_actions.insert(lease.action_id.clone());
            continue;
        }
        if lease.state != "active" {
            continue;
        }
        let reaped = match (lease.process_group_id, lease.leader_identity.as_deref()) {
            (Some(pgid), Some(identity)) => reap_owned_process_group(pgid, identity).is_ok(),
            _ => false,
        };
        if reaped {
            "reaped_recovery".clone_into(&mut lease.state);
            state.put_state(
                "controller.process_lease",
                &record.key,
                &serde_json::to_string(&lease)?,
            )?;
        } else {
            unresolved.push(lease.lease_id.clone());
            unresolved_actions.insert(lease.action_id.clone());
        }
    }
    Ok((unresolved, unresolved_actions))
}

#[allow(clippy::too_many_lines)]
fn reconcile_recovery_actions(
    state: &mut StateStore,
    registry: &ProjectRegistry,
    unresolved_process_actions: &BTreeSet<String>,
    manifest: &CheckpointManifest,
) -> Result<Vec<String>, ControllerError> {
    for record in state.action_records()? {
        if record.state == "dispatched" {
            let event_id = recovery_event_id(
                &record.action_id,
                "unknown",
                state.latest_journal_sequence()?,
            );
            state.recover_dispatched_action_as_unknown(
                &record.action_id,
                &event_id,
                "{\"reason\":\"restart_after_dispatched_before_observed\"}",
            )?;
        }
    }
    let mut unknown = Vec::new();
    for record in state.action_records()? {
        if record.state != "unknown" {
            continue;
        }
        if unresolved_process_actions.contains(&record.action_id) {
            unknown.push(record.action_id);
            continue;
        }
        let Some(raw_intent) = state.get_state("controller.action_intent", &record.action_id)?
        else {
            unknown.push(record.action_id);
            continue;
        };
        let binding_key = format!("controller.action_intent:{}", record.action_id);
        if manifest
            .evidence_binding_digests
            .get(&binding_key)
            .is_none_or(|digest| *digest != sha256_prefixed(raw_intent.as_bytes()))
        {
            unknown.push(record.action_id);
            continue;
        }
        let intent: PersistedActionIntent = serde_json::from_str(&raw_intent)?;
        if intent.schema_version != ACTION_INTENT_SCHEMA_VERSION
            || intent.action_id != record.action_id
            || intent.payload_digest != record.payload_digest
            || intent.policy_digest != record.policy_digest
        {
            unknown.push(record.action_id);
            continue;
        }
        let Ok(current) = ExactRetriever::new(registry).read_path(
            &intent.repository_id,
            Path::new(&intent.path),
            None,
        ) else {
            unknown.push(record.action_id);
            continue;
        };
        let current_mode = permission_mode(&fs::symlink_metadata(
            registry
                .repository(&intent.repository_id)
                .ok_or_else(|| {
                    ControllerError::InvalidPlan("recovery intent repository missing".to_owned())
                })?
                .root
                .join(&intent.path),
        )?);
        if current.digest == intent.expected_post_digest
            && current_mode == intent.expected_target_mode
        {
            let store = ArtifactStore::open(&intent.artifact_store_root)?;
            let receipt = serde_json::to_vec(&json!({
                "schema": "sovereign-recovery-result-v1",
                "action_id": record.action_id,
                "proof": "effect_observed",
                "target_digest": current.digest,
                "process_cleanup": "proven_or_absent"
            }))?;
            let artifact = store.put(state, &receipt)?;
            let reconciled_event = recovery_event_id(
                &record.action_id,
                "reconciled_effect_observed",
                state.latest_journal_sequence()?,
            );
            state.reconcile_historical_unknown_action(
                &record.action_id,
                "reconciled",
                Some(&artifact.digest),
                &reconciled_event,
                "reconciled",
                "{\"proof\":\"effect_observed\"}",
            )?;
            let committed_event = recovery_event_id(
                &record.action_id,
                "committed_recovery",
                state.latest_journal_sequence()?,
            );
            state.commit_historical_reconciled_action(
                &record.action_id,
                &committed_event,
                "{\"proof\":\"effect_observed\"}",
            )?;
        } else if current.digest == intent.expected_source_digest
            && current_mode == intent.expected_target_mode
        {
            let reconciled_event = recovery_event_id(
                &record.action_id,
                "reconciled_effect_absent",
                state.latest_journal_sequence()?,
            );
            state.reconcile_historical_unknown_action(
                &record.action_id,
                "reconciled",
                None,
                &reconciled_event,
                "reconciled",
                "{\"proof\":\"effect_absent\"}",
            )?;
            let failed_event = recovery_event_id(
                &record.action_id,
                "failed_recovery",
                state.latest_journal_sequence()?,
            );
            state.fail_historical_reconciled_action(
                &record.action_id,
                &failed_event,
                "{\"proof\":\"effect_absent\"}",
            )?;
        } else {
            unknown.push(record.action_id);
        }
    }
    Ok(unknown)
}

type RecoveryRuntimeNormalization = (Vec<String>, Vec<String>, Vec<String>);

fn normalize_recovered_runtime(
    controller: &mut Controller,
    unknown_action_ids: &[String],
) -> Result<RecoveryRuntimeNormalization, ControllerError> {
    let unknown = unknown_action_ids.iter().cloned().collect::<BTreeSet<_>>();
    let intents = controller
        .state
        .state_records("controller.action_intent")?
        .into_iter()
        .map(|record| {
            let intent: PersistedActionIntent = serde_json::from_str(&record.value_json)?;
            Ok((record.key, intent))
        })
        .collect::<Result<BTreeMap<_, _>, ControllerError>>()?;
    let actions = controller
        .state
        .action_records()?
        .into_iter()
        .map(|record| (record.action_id.clone(), record))
        .collect::<BTreeMap<_, _>>();
    let mut interrupted = Vec::new();
    let mut pending = Vec::new();
    let mut verify = Vec::new();
    let attempt_ids = controller
        .active_ref()?
        .attempts
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    for attempt_id in attempt_ids {
        let (attempt_state, task_id) = {
            let active = controller.active_ref()?;
            let attempt = active.attempts.get(&attempt_id).ok_or_else(|| {
                ControllerError::InvalidPlan("recovery attempt disappeared".to_owned())
            })?;
            (attempt.state, attempt.task_id.clone())
        };
        if !matches!(
            attempt_state,
            AttemptState::Executing | AttemptState::Verifying
        ) {
            continue;
        }
        let intent = intents
            .values()
            .filter(|intent| intent.attempt_id == attempt_id)
            .max_by(|left, right| left.action_id.cmp(&right.action_id));
        let next = intent.and_then(|intent| {
            actions
                .get(&intent.action_id)
                .map(|action| (intent.action_id.clone(), action.state.clone()))
        });
        let (attempt_next, task_next) = match next.as_ref().map(|(_, state)| state.as_str()) {
            Some("committed") => {
                if let Some((action_id, _)) = next {
                    verify.push(action_id);
                }
                (AttemptState::Verifying, TaskState::Verifying)
            }
            Some("unknown") => (AttemptState::Interrupted, TaskState::ReconcilingUnknown),
            Some("prepared" | "authorized" | "failed") => {
                if let Some((action_id, _)) = next {
                    pending.push(action_id);
                }
                (AttemptState::Interrupted, TaskState::Planned)
            }
            _ => (AttemptState::Interrupted, TaskState::Planned),
        };
        {
            let active = controller.active_mut()?;
            if let Some(attempt) = active.attempts.get_mut(&attempt_id) {
                attempt.state = attempt_next;
            }
            if let Some(task) = active.tasks.get_mut(&task_id) {
                task.state = task_next;
            }
        }
        if attempt_next == AttemptState::Interrupted {
            interrupted.push(attempt_id);
        }
    }
    for action_id in &unknown {
        if let Some(intent) = intents.get(action_id)
            && let Some(task) = controller.active_mut()?.tasks.get_mut(&intent.task_id)
        {
            task.state = TaskState::ReconcilingUnknown;
        }
    }
    extend_pending_recovery_actions(controller, &intents, &actions, &mut pending)?;
    interrupted.sort();
    pending.sort();
    pending.dedup();
    verify.sort();
    Ok((interrupted, pending, verify))
}

fn extend_pending_recovery_actions(
    controller: &Controller,
    intents: &BTreeMap<String, PersistedActionIntent>,
    actions: &BTreeMap<String, sovereign_state::PersistedActionRecord>,
    pending: &mut Vec<String>,
) -> Result<(), ControllerError> {
    let active = controller.active_ref()?;
    for (action_id, action) in actions {
        if !matches!(action.state.as_str(), "prepared" | "authorized" | "failed")
            || pending.contains(action_id)
        {
            continue;
        }
        let Some(intent) = intents.get(action_id) else {
            continue;
        };
        let origin_interrupted = active
            .attempts
            .get(&intent.attempt_id)
            .is_some_and(|attempt| {
                attempt.task_id == intent.task_id && attempt.state == AttemptState::Interrupted
            });
        let task_planned = active
            .tasks
            .get(&intent.task_id)
            .is_some_and(|task| task.state == TaskState::Planned);
        if origin_interrupted && task_planned {
            pending.push(action_id.clone());
        }
    }
    Ok(())
}

fn recovery_event_id(entity_id: &str, kind: &str, sequence: i64) -> String {
    let digest = sha256_prefixed(format!("recovery\0{entity_id}\0{kind}\0{sequence}").as_bytes());
    format!("recovery.{}", &digest[7..27])
}

pub struct ExecutionRuntime<'a, I: sovereign_policy::ExecutionIsolationBackend> {
    pub registry: &'a ProjectRegistry,
    pub backend: &'a dyn ModelBackend,
    pub command_policy: &'a CommandPolicy,
    pub isolation_backend: &'a I,
    pub isolation_request: &'a IsolationRequest,
    pub artifacts: &'a ArtifactStore,
    pub tool_manifest: &'a ToolManifest,
    pub python_executable: &'a Path,
}

struct ValidatedReplace {
    proposal: ReplaceLiteral,
    expected_post_digest: String,
    expected_target_mode: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PersistedActionIntent {
    schema_version: u32,
    action_id: String,
    plan_id: String,
    plan_revision: u32,
    plan_digest: String,
    task_id: String,
    task_contract_digest: String,
    attempt_id: String,
    execution_epoch: i64,
    payload_digest: String,
    action_nonce: String,
    policy_digest: String,
    repository_id: String,
    path: String,
    expected_source_digest: String,
    old_literal: String,
    new_literal: String,
    expected_post_digest: String,
    expected_target_mode: u32,
    artifact_store_root: PathBuf,
}

fn persisted_intent_action_seed(intent: &PersistedActionIntent) -> Result<String, ControllerError> {
    let proposal = ReplaceLiteral {
        kind: ReplaceLiteralKind::ReplaceLiteral,
        repository_id: intent.repository_id.clone(),
        path: intent.path.clone(),
        expected_source_digest: intent.expected_source_digest.clone(),
        old_literal: intent.old_literal.clone(),
        new_literal: intent.new_literal.clone(),
        expected_occurrences: 1,
    };
    Ok(digest_json(&json!({
        "plan": intent.plan_digest,
        "task": intent.task_contract_digest,
        "attempt": intent.attempt_id,
        "proposal": proposal,
    }))?)
}

#[derive(Debug, Clone)]
struct VerificationLeaseBinding {
    plan_id: String,
    plan_revision: u32,
    plan_digest: String,
    task_id: String,
    task_contract_digest: String,
    baseline_digest: String,
    execution_epoch: i64,
}

impl From<&ReadyLease> for VerificationLeaseBinding {
    fn from(lease: &ReadyLease) -> Self {
        Self {
            plan_id: lease.plan_id.clone(),
            plan_revision: lease.plan_revision,
            plan_digest: lease.plan_digest.clone(),
            task_id: lease.task_id.clone(),
            task_contract_digest: lease.task_contract_digest.clone(),
            baseline_digest: lease.baseline_digest.clone(),
            execution_epoch: lease.execution_epoch,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ExactRequirementProbe {
    Path { path: String, contains: Vec<String> },
}

pub struct DeterministicVerifier;

impl DeterministicVerifier {
    #[allow(clippy::too_many_arguments)]
    fn verify(
        state: &StateStore,
        active: &ActivePlan,
        registry: &ProjectRegistry,
        lease: &VerificationLeaseBinding,
        attempt_id: &str,
        action_id: &str,
        destination_digest: Option<&str>,
        validated: &ValidatedReplace,
    ) -> Result<VerificationResultV1, ControllerError> {
        let task = active.tasks.get(&lease.task_id).ok_or_else(|| {
            ControllerError::InvalidPlan("verification task disappeared".to_owned())
        })?;
        let attempt = active.attempts.get(attempt_id).ok_or_else(|| {
            ControllerError::InvalidPlan("verification attempt disappeared".to_owned())
        })?;
        let (evaluator, acceptance_contract_digest) = compiled_acceptance_contract(&task.task)?;
        let current_epoch = state.current_execution_epoch()?;
        let post_snapshot = registry.snapshot(&active.repository_id)?;
        let post_snapshot_digest = snapshot_digest(&post_snapshot)?;
        let retriever = ExactRetriever::new(registry);
        let file = retriever.read_path(
            &active.repository_id,
            Path::new(&validated.proposal.path),
            None,
        )?;
        let observed_target_mode = permission_mode(&fs::symlink_metadata(
            active.repository_root.join(&validated.proposal.path),
        )?);
        let diff = retriever.current_diff(&active.repository_id)?;
        let action_record = state.action_record(action_id)?;
        let action_committed = action_record
            .as_ref()
            .is_some_and(|record| record.state == "committed" && record.result_digest.is_some());
        let expected_path = PathBuf::from(&validated.proposal.path);
        let repository_failure =
            repository_verification_failure(active, attempt, lease, &post_snapshot, &expected_path);
        let freshness_ok = required_array(&task.task, "/acceptance_criteria")?
            .iter()
            .all(|criterion| {
                criterion.get("evidence_freshness").and_then(Value::as_str)
                    == Some("current_attempt")
            });
        let bindings_ok = active.validity == PlanValidity::Current
            && active.plan_id == lease.plan_id
            && active.plan_digest == lease.plan_digest
            && active.revision == lease.plan_revision
            && task.task_contract_digest == lease.task_contract_digest
            && current_epoch == lease.execution_epoch;
        let postimage_ok = file.digest == validated.expected_post_digest;
        let accepted_transformation_ok = destination_digest
            == Some(validated.proposal.expected_source_digest.as_str())
            && postimage_ok
            && observed_target_mode == validated.expected_target_mode;
        let compiled_literal_contract_ok = compiled_literal_contract_allows(
            &active.plan_document,
            &task.task,
            &validated.proposal,
        )?;
        let failure_code = verification_failure_code(&[
            (action_committed, "action_not_committed"),
            (bindings_ok, "stale_verification_binding"),
            (freshness_ok, "acceptance_not_current_attempt"),
        ])
        .or(repository_failure)
        .or_else(|| {
            verification_failure_code(&[
                (
                    compiled_literal_contract_ok,
                    "compiled_acceptance_literal_mismatch",
                ),
                (
                    observed_target_mode == validated.expected_target_mode,
                    "target_mode_changed",
                ),
                (accepted_transformation_ok, "postimage_digest_mismatch"),
            ])
        });
        let evidence_ids = action_record
            .and_then(|record| record.result_digest)
            .into_iter()
            .chain([diff.digest.clone(), file.digest.clone()])
            .collect::<Vec<_>>();
        let verification_id = verification_id(
            &active.plan_digest,
            &lease.task_contract_digest,
            attempt_id,
            &diff.digest,
        );
        Ok(VerificationResultV1 {
            schema_version: VERIFICATION_RESULT_SCHEMA_VERSION,
            verification_id,
            plan_id: active.plan_id.clone(),
            plan_revision: active.revision,
            plan_digest: active.plan_digest.clone(),
            task_id: lease.task_id.clone(),
            task_contract_digest: lease.task_contract_digest.clone(),
            attempt_id: attempt_id.to_owned(),
            execution_epoch: current_epoch,
            evaluator,
            acceptance_contract_digest,
            diff_digest: diff.digest,
            post_snapshot_digest,
            expected_target_mode: validated.expected_target_mode,
            observed_target_mode,
            evidence_ids,
            passed: failure_code.is_none(),
            failure_code,
        })
    }
}

fn protected_preexisting_changes_unchanged(
    repository_root: &Path,
    attempt: &AttemptRuntime,
    expected_path: &Path,
) -> bool {
    attempt
        .pre_changed_fingerprints
        .iter()
        .filter(|(path, _)| path.as_path() != expected_path)
        .all(|(path, fingerprint)| {
            path_fingerprint(repository_root, path).is_ok_and(|current| current == *fingerprint)
        })
}

fn repository_verification_failure(
    active: &ActivePlan,
    attempt: &AttemptRuntime,
    lease: &VerificationLeaseBinding,
    post_snapshot: &RepositorySnapshot,
    expected_path: &Path,
) -> Option<String> {
    let mut allowed_changed_paths = attempt
        .pre_changed_fingerprints
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    allowed_changed_paths.insert(expected_path.to_path_buf());
    if !snapshot_changed_paths(post_snapshot).is_subset(&allowed_changed_paths) {
        return Some("scope_audit_failed".to_owned());
    }
    if attempt.pre_snapshot_digest != lease.baseline_digest
        || attempt.baseline_digest != lease.baseline_digest
        || attempt.pre_diff_digest != active.baseline_diff_digest
        || sha256_prefixed(active.baseline_diff_content.as_bytes()) != active.baseline_diff_digest
    {
        return Some("pre_attempt_baseline_binding_invalid".to_owned());
    }
    if !protected_preexisting_changes_unchanged(&active.repository_root, attempt, expected_path) {
        return Some("protected_preexisting_change_modified".to_owned());
    }
    None
}

fn verification_failure_code(checks: &[(bool, &str)]) -> Option<String> {
    checks
        .iter()
        .find_map(|(passed, code)| (!passed).then(|| (*code).to_owned()))
}

fn verification_id(
    plan_digest: &str,
    task_contract_digest: &str,
    attempt_id: &str,
    diff_digest: &str,
) -> String {
    let seed = sha256_prefixed(
        format!("{plan_digest}\0{task_contract_digest}\0{attempt_id}\0{diff_digest}").as_bytes(),
    );
    format!("verification.{}", &seed[7..27])
}

fn model_proposal_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["schema_version", "evidence_ids", "action"],
        "properties": {
            "schema_version": {"const": MODEL_PROPOSAL_SCHEMA_VERSION},
            "evidence_ids": {
                "type": "array",
                "minItems": 1,
                "maxItems": 16,
                "uniqueItems": true,
                "items": {"type": "string", "minLength": 1, "maxLength": 256}
            },
            "action": {
                "type": "object",
                "additionalProperties": false,
                "required": [
                    "kind", "repository_id", "path", "expected_source_digest",
                    "old_literal", "new_literal", "expected_occurrences"
                ],
                "properties": {
                    "kind": {"const": "replace_literal"},
                    "repository_id": {"type": "string", "minLength": 1, "maxLength": 128},
                    "path": {"type": "string", "minLength": 1, "maxLength": 1024},
                    "expected_source_digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
                    "old_literal": {"type": "string", "minLength": 1, "maxLength": MAX_LITERAL_BYTES},
                    "new_literal": {"type": "string", "maxLength": MAX_LITERAL_BYTES},
                    "expected_occurrences": {"const": 1}
                }
            }
        }
    })
}

fn repair_allowed(
    attempts_started: u32,
    max_attempts: u32,
    same_failure_count: u32,
    same_failure_limit: u32,
) -> bool {
    attempts_started < max_attempts && same_failure_count < same_failure_limit
}

fn legal_attempt_transition(from: AttemptState, to: AttemptState) -> bool {
    matches!(
        (from, to),
        (AttemptState::Prepared, AttemptState::Executing)
            | (
                AttemptState::Executing,
                AttemptState::Verifying
                    | AttemptState::Failed
                    | AttemptState::Aborted
                    | AttemptState::Interrupted
            )
            | (
                AttemptState::Verifying,
                AttemptState::Succeeded | AttemptState::Failed
            )
    )
}

fn legal_task_transition(from: TaskState, to: TaskState) -> bool {
    matches!(
        (from, to),
        (
            TaskState::Planned,
            TaskState::Running | TaskState::DeferredResource
        ) | (TaskState::DeferredResource, TaskState::Planned)
            | (
                TaskState::Running,
                TaskState::Verifying
                    | TaskState::RepairPending
                    | TaskState::DeferredResource
                    | TaskState::ReconcilingUnknown
                    | TaskState::FailedTerminal
            )
            | (
                TaskState::Verifying,
                TaskState::Succeeded | TaskState::RepairPending
            )
    )
}

fn ready_lease_digest(lease: &ReadyLease) -> String {
    sha256_prefixed(
        format!(
            "{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
            lease.plan_id,
            lease.plan_revision,
            lease.plan_digest,
            lease.task_id,
            lease.task_contract_digest,
            lease.baseline_digest,
            lease.evidence_binding_digest,
            lease.checkpoint_generation,
            lease.checkpoint_action_sequence,
            lease.checkpoint_hash,
            lease.permission_digest,
            lease.resource_digest,
            lease.execution_epoch,
        )
        .as_bytes(),
    )
}

fn digest_fragment(digest: &str, length: usize) -> &str {
    let body = digest.strip_prefix("sha256:").unwrap_or(digest);
    &body[..body.len().min(length)]
}

fn snapshot_changed_paths(snapshot: &RepositorySnapshot) -> BTreeSet<PathBuf> {
    snapshot
        .staged
        .paths
        .iter()
        .chain(snapshot.unstaged.paths.iter())
        .chain(snapshot.untracked.paths.iter())
        .cloned()
        .collect()
}

fn capture_protected_fingerprints(
    root: &Path,
    paths: &BTreeSet<PathBuf>,
) -> Result<BTreeMap<PathBuf, String>, ControllerError> {
    paths
        .iter()
        .map(|path| Ok((path.clone(), path_fingerprint(root, path)?)))
        .collect()
}

fn path_fingerprint(root: &Path, relative: &Path) -> Result<String, ControllerError> {
    let absolute = root.join(relative);
    let fingerprint = match fs::symlink_metadata(&absolute) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            let target = fs::read_link(&absolute)?;
            format!(
                "symlink:{:o}:{}",
                permission_mode(&metadata),
                sha256_prefixed(target.as_os_str().as_encoded_bytes())
            )
        }
        Ok(metadata) if metadata.is_file() => format!(
            "file:{:o}:{}",
            permission_mode(&metadata),
            sha256_prefixed(&fs::read(&absolute)?)
        ),
        Ok(metadata) if metadata.is_dir() => {
            format!("directory:{:o}", permission_mode(&metadata))
        }
        Ok(metadata) => format!("special:{:o}", permission_mode(&metadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => "missing".to_owned(),
        Err(error) => return Err(ControllerError::Io(error)),
    };
    Ok(fingerprint)
}

fn permission_mode(metadata: &fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o7777
    }
    #[cfg(not(unix))]
    {
        u32::from(metadata.permissions().readonly())
    }
}

fn evidence_satisfaction_key(task_id: &str, requirement_id: &str) -> String {
    format!("{task_id}:{requirement_id}")
}

fn output_binding_key(task_id: &str, binding_id: &str) -> String {
    format!("{task_id}:{binding_id}")
}

fn evidence_item_key(task_id: &str, requirement_id: &str, evidence_id: &str) -> String {
    let digest = sha256_prefixed(format!("{task_id}\0{requirement_id}\0{evidence_id}").as_bytes());
    format!(
        "{task_id}:{requirement_id}:{}",
        digest_fragment(&digest, 24)
    )
}

fn exact_requirement_probe(query: &str) -> Option<ExactRequirementProbe> {
    if let Some(contract) = query.strip_prefix("exact:path=") {
        let mut clauses = contract.split(';');
        let path = clauses.next()?.trim();
        if !valid_repo_relative_path(path) {
            return None;
        }
        let mut contains = Vec::new();
        for clause in clauses {
            let literal = clause.strip_prefix("contains=")?;
            if literal.is_empty() || literal.len() > MAX_LITERAL_BYTES {
                return None;
            }
            contains.push(literal.to_owned());
        }
        if contains.is_empty() || contains.len() > 8 {
            return None;
        }
        return Some(ExactRequirementProbe::Path {
            path: path.to_owned(),
            contains,
        });
    }

    let path = query
        .strip_prefix("Resolve proposed path ")?
        .strip_suffix(" on the current repository snapshot before mutation.")?;
    valid_repo_relative_path(path).then(|| ExactRequirementProbe::Path {
        path: path.to_owned(),
        contains: Vec::new(),
    })
}

fn valid_repo_relative_path(path: &str) -> bool {
    !path.is_empty()
        && !path.contains("://")
        && !Path::new(path).is_absolute()
        && Path::new(path)
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
}

fn evidence_repo_relative_path<'a>(repository_id: &str, item: &'a EvidenceItem) -> Option<&'a str> {
    item.source_uri
        .strip_prefix(&format!("repo://{repository_id}/"))
}

fn validate_requirement_bound_evidence(
    registry: &ProjectRegistry,
    repository_id: &str,
    item: &EvidenceItem,
    probe: &ExactRequirementProbe,
) -> Result<(), ControllerError> {
    let path = evidence_repo_relative_path(repository_id, item).ok_or_else(|| {
        ControllerError::NotReady(
            "requirement-bound exact evidence lacks a repository-relative source".to_owned(),
        )
    })?;
    let ExactRequirementProbe::Path {
        path: expected_path,
        contains,
    } = probe;
    if path != expected_path {
        return Err(ControllerError::NotReady(format!(
            "selected evidence path {path} does not satisfy required exact path {expected_path}"
        )));
    }
    let current = ExactRetriever::new(registry).read_path(
        repository_id,
        Path::new(expected_path),
        Some(&item.source_digest),
    )?;
    for literal in contains {
        if !current.content.contains(literal) {
            return Err(ControllerError::NotReady(format!(
                "selected exact evidence lacks required literal {literal:?}"
            )));
        }
    }
    Ok(())
}

fn validate_requirement_probe_cardinality(
    registry: &ProjectRegistry,
    repository_id: &str,
    probe: &ExactRequirementProbe,
    satisfaction: &str,
) -> Result<(), ControllerError> {
    if satisfaction != "exactly_one" {
        return Ok(());
    }
    let ExactRequirementProbe::Path { path, .. } = probe;
    ExactRetriever::new(registry).read_path(repository_id, Path::new(path), None)?;
    Ok(())
}

fn baseline_target_added_line_contains_literal(diff: &str, path: &str, literal: &str) -> bool {
    let marker = format!("diff --git a/{path} b/{path}");
    let mut target = false;
    for line in diff.lines() {
        if line.starts_with("diff --git ") {
            target = line == marker;
            continue;
        }
        if target
            && line.starts_with('+')
            && !line.starts_with("+++")
            && line[1..].contains(literal)
        {
            return true;
        }
    }
    false
}

fn compiled_literal_contract_allows(
    plan: &Value,
    task: &Value,
    proposal: &ReplaceLiteral,
) -> Result<bool, ControllerError> {
    let goal = required_str(plan, "/goal/statement")?;
    let objective = required_str(task, "/objective")?;
    let outputs = required_array(task, "/implementation_contract/outputs")?;
    let outputs_text = outputs
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join("\n");
    Ok(
        explicit_replace_relation(goal, &proposal.old_literal, &proposal.new_literal)
            && explicit_replace_relation(objective, &proposal.old_literal, &proposal.new_literal)
            && literal_is_explicit_contract_token(&outputs_text, &proposal.new_literal),
    )
}

fn explicit_replace_relation(text: &str, old_literal: &str, new_literal: &str) -> bool {
    if old_literal.is_empty() || new_literal.is_empty() {
        return false;
    }
    text.match_indices(old_literal).any(|(start, matched)| {
        if !literal_match_has_boundaries(text, start, matched) {
            return false;
        }
        let after = &text[start.saturating_add(matched.len())..];
        [" to ", " with ", " -> "].iter().any(|connector| {
            after.strip_prefix(connector).is_some_and(|remainder| {
                remainder.starts_with(new_literal)
                    && literal_match_has_boundaries(remainder, 0, new_literal)
            })
        })
    })
}

fn literal_is_explicit_contract_token(text: &str, literal: &str) -> bool {
    if literal.is_empty() {
        return false;
    }
    let requires_boundary = literal
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || character == '_');
    if !requires_boundary {
        return text.contains(literal);
    }
    text.match_indices(literal)
        .any(|(start, matched)| literal_match_has_boundaries(text, start, matched))
}

fn literal_match_has_boundaries(text: &str, start: usize, literal: &str) -> bool {
    let requires_boundary = literal
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || character == '_');
    if !requires_boundary {
        return text
            .get(start..)
            .is_some_and(|remainder| remainder.starts_with(literal));
    }
    let before = text[..start].chars().next_back();
    let end = start.saturating_add(literal.len());
    let after = text[end..].chars().next();
    let boundary = |value: Option<char>| {
        value.is_none_or(|character| !character.is_ascii_alphanumeric() && character != '_')
    };
    boundary(before) && boundary(after)
}

fn execution_evidence_requirements(task: &Value) -> Result<Vec<&Value>, ControllerError> {
    let mut requirements = required_array(task, "/evidence_requirements")?
        .iter()
        .filter(|requirement| {
            requirement.get("required_before").and_then(Value::as_str) == Some("execution")
        })
        .collect::<Vec<_>>();
    for clause_path in [
        "/implementation_contract/preconditions",
        "/implementation_contract/invariants",
    ] {
        for clause in required_array(task, clause_path)? {
            if let Some(nested) = clause
                .get("evidence_requirements")
                .and_then(Value::as_array)
            {
                requirements.extend(nested.iter().filter(|requirement| {
                    requirement.get("required_before").and_then(Value::as_str) == Some("execution")
                }));
            }
        }
    }
    Ok(requirements)
}

fn resolve_execution_requirement(
    task: &Value,
    requirement_id: &str,
) -> Result<Value, ControllerError> {
    execution_evidence_requirements(task)?
        .into_iter()
        .find(|value| value.get("requirement_id").and_then(Value::as_str) == Some(requirement_id))
        .cloned()
        .ok_or_else(|| {
            ControllerError::NotReady(format!(
                "unknown execution evidence requirement {requirement_id}"
            ))
        })
}

fn validate_evidence_selection(
    requirement: &Value,
    selected_evidence_ids: &[String],
) -> Result<String, ControllerError> {
    let satisfaction = required_str(requirement, "/satisfaction")?;
    let max_items = requirement
        .get("max_items")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(100);
    let unique = selected_evidence_ids.iter().collect::<BTreeSet<_>>();
    if unique.len() != selected_evidence_ids.len() || selected_evidence_ids.len() > max_items {
        return Err(ControllerError::NotReady(
            "evidence satisfaction IDs violate uniqueness/max_items".to_owned(),
        ));
    }
    match satisfaction {
        "exactly_one" if selected_evidence_ids.len() != 1 => Err(ControllerError::NotReady(
            "exactly_one evidence requirement did not resolve exactly one retained item".to_owned(),
        )),
        "at_least_one" if selected_evidence_ids.is_empty() => Err(ControllerError::NotReady(
            "at_least_one evidence requirement has no retained item".to_owned(),
        )),
        "query_completed" | "evaluator_pass" => Err(ControllerError::NotReady(format!(
            "M1-T07 has no governed producer for {satisfaction} evidence satisfaction"
        ))),
        "exactly_one" | "at_least_one" => Ok(satisfaction.to_owned()),
        other => Err(ControllerError::InvalidPlan(format!(
            "unsupported evidence satisfaction mode {other}"
        ))),
    }
}

fn compiled_acceptance_contract(task: &Value) -> Result<(String, String), ControllerError> {
    let criteria = required_array(task, "/acceptance_criteria")?;
    let steps = required_array(task, "/verification/steps")?;
    let required_evidence_types = required_array(task, "/verification/required_evidence_types")?;
    let step_by_id = verification_steps_by_id(steps)?;
    let mut bound_criteria = Vec::new();
    let mut bound_steps = BTreeMap::new();
    let mut bound_evidence_types = BTreeSet::new();
    let mut evaluator: Option<String> = None;
    for criterion in criteria
        .iter()
        .filter(|criterion| criterion.get("required").and_then(Value::as_bool) == Some(true))
    {
        let criterion_id = required_str(criterion, "/criterion_id")?;
        if criterion.get("evidence_freshness").and_then(Value::as_str) != Some("current_attempt") {
            return Err(ControllerError::InvalidPlan(
                "M1 deterministic verifier requires current_attempt acceptance evidence".to_owned(),
            ));
        }
        let evidence_type = required_str(criterion, "/evidence_type")?;
        if !required_evidence_types
            .iter()
            .any(|value| value.as_str() == Some(evidence_type))
        {
            return Err(ControllerError::InvalidPlan(
                "required acceptance evidence type is absent from verification contract".to_owned(),
            ));
        }
        let verification_step_ids = required_array(criterion, "/verification_step_ids")?;
        if verification_step_ids.is_empty() {
            return Err(ControllerError::InvalidPlan(
                "required acceptance criterion has no verification step".to_owned(),
            ));
        }
        for step_id in verification_step_ids {
            let step_id = step_id.as_str().ok_or_else(|| {
                ControllerError::InvalidPlan("verification step ID must be a string".to_owned())
            })?;
            let step = step_by_id.get(step_id).ok_or_else(|| {
                ControllerError::InvalidPlan(format!(
                    "acceptance criterion references unknown verification step {step_id}"
                ))
            })?;
            if !required_array(step, "/criterion_ids")?
                .iter()
                .any(|value| value.as_str() == Some(criterion_id))
            {
                return Err(ControllerError::InvalidPlan(format!(
                    "verification step {step_id} does not bind criterion {criterion_id}"
                )));
            }
            if required_str(step, "/kind")? != "diff"
                || required_str(step, "/evidence_type")? != evidence_type
            {
                return Err(ControllerError::InvalidPlan(
                    "M1 acceptance criterion/verification step contract mismatch".to_owned(),
                ));
            }
            let step_evaluator = required_str(step, "/evaluator")?;
            if step_evaluator != "builtin.diff.scope_and_literal.v1"
                && step_evaluator != "builtin.diff.scoped_change.v1"
            {
                return Err(ControllerError::InvalidPlan(format!(
                    "unsupported deterministic M1 evaluator {step_evaluator}"
                )));
            }
            if let Some(previous) = evaluator.as_deref()
                && previous != step_evaluator
            {
                return Err(ControllerError::InvalidPlan(
                    "M1 required acceptance steps must use one deterministic diff evaluator"
                        .to_owned(),
                ));
            }
            evaluator = Some(step_evaluator.to_owned());
            bound_steps.insert(step_id.to_owned(), (*step).clone());
        }
        bound_evidence_types.insert(evidence_type.to_owned());
        bound_criteria.push(criterion.clone());
    }
    if bound_criteria.is_empty() {
        return Err(ControllerError::InvalidPlan(
            "M1 task has no required acceptance criterion".to_owned(),
        ));
    }
    let evaluator = evaluator.ok_or_else(|| {
        ControllerError::InvalidPlan("M1 task has no deterministic acceptance evaluator".to_owned())
    })?;
    validate_required_evidence_types(required_evidence_types, &bound_evidence_types)?;
    let contract_digest = digest_json(&json!({
        "criteria": bound_criteria,
        "steps": bound_steps,
        "required_evidence_types": required_evidence_types,
    }))?;
    Ok((evaluator, contract_digest))
}

fn verification_steps_by_id(steps: &[Value]) -> Result<BTreeMap<String, &Value>, ControllerError> {
    let mut step_by_id = BTreeMap::new();
    for step in steps {
        let step_id = required_str(step, "/step_id")?.to_owned();
        if step_by_id.insert(step_id.clone(), step).is_some() {
            return Err(ControllerError::InvalidPlan(format!(
                "duplicate verification step ID {step_id}"
            )));
        }
    }
    Ok(step_by_id)
}

fn validate_required_evidence_types(
    required_evidence_types: &[Value],
    bound_evidence_types: &BTreeSet<String>,
) -> Result<(), ControllerError> {
    for evidence_type in required_evidence_types {
        let evidence_type = evidence_type.as_str().ok_or_else(|| {
            ControllerError::InvalidPlan(
                "verification required evidence type must be a string".to_owned(),
            )
        })?;
        if !bound_evidence_types.contains(evidence_type) {
            return Err(ControllerError::InvalidPlan(format!(
                "verification requires unbound evidence type {evidence_type}"
            )));
        }
    }
    Ok(())
}

fn snapshot_digest(snapshot: &RepositorySnapshot) -> Result<String, ControllerError> {
    Ok(sha256_prefixed(snapshot.manifest_json()?.as_bytes()))
}

fn checkpoint_artifact_store(state_path: &Path) -> Result<ArtifactStore, ControllerError> {
    let parent = state_path.parent().ok_or_else(|| {
        ControllerError::InvalidPlan("state database has no checkpoint CAS parent".to_owned())
    })?;
    Ok(ArtifactStore::open(parent.join("checkpoint-cas"))?)
}

#[cfg(feature = "recovery-test-hooks")]
fn recovery_test_hook(point: &str) {
    if std::env::var("SOVEREIGN_RECOVERY_TEST_PAUSE_AT")
        .ok()
        .as_deref()
        != Some(point)
    {
        return;
    }
    if let Ok(marker) = std::env::var("SOVEREIGN_RECOVERY_TEST_MARKER") {
        let _ = fs::write(marker, point.as_bytes());
    }
    loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}

#[cfg(not(feature = "recovery-test-hooks"))]
fn recovery_test_hook(_point: &str) {}

fn digest_json(value: &Value) -> Result<String, serde_json::Error> {
    let canonical = canonicalize(value);
    Ok(sha256_prefixed(&serde_json::to_vec(&canonical)?))
}

fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries = map.iter().collect::<Vec<_>>();
            entries.sort_by(|(left, _), (right, _)| left.cmp(right));
            let mut canonical = serde_json::Map::new();
            for (key, value) in entries {
                canonical.insert(key.clone(), canonicalize(value));
            }
            Value::Object(canonical)
        }
        Value::Array(values) => Value::Array(values.iter().map(canonicalize).collect()),
        _ => value.clone(),
    }
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

fn required_str<'a>(value: &'a Value, pointer: &str) -> Result<&'a str, ControllerError> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| ControllerError::InvalidPlan(format!("missing string {pointer}")))
}

fn optional_str<'a>(value: &'a Value, pointer: &str) -> Option<&'a str> {
    value.pointer(pointer).and_then(Value::as_str)
}

fn required_u32(value: &Value, pointer: &str) -> Result<u32, ControllerError> {
    let raw = value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .ok_or_else(|| ControllerError::InvalidPlan(format!("missing integer {pointer}")))?;
    u32::try_from(raw)
        .map_err(|_| ControllerError::InvalidPlan(format!("integer out of range {pointer}")))
}

fn required_array<'a>(value: &'a Value, pointer: &str) -> Result<&'a Vec<Value>, ControllerError> {
    value
        .pointer(pointer)
        .and_then(Value::as_array)
        .ok_or_else(|| ControllerError::InvalidPlan(format!("missing array {pointer}")))
}

fn unix_millis() -> Result<i64, ControllerError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            ControllerError::InvalidPlan(format!("host clock precedes Unix epoch: {error}"))
        })?;
    Ok(i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::{
        ExactRequirementProbe, exact_requirement_probe, explicit_replace_relation, repair_allowed,
    };

    #[test]
    fn same_failure_circuit_breaker_requires_both_counters_below_limits() {
        assert!(repair_allowed(1, 2, 1, 2));
        assert!(!repair_allowed(2, 2, 1, 2));
        assert!(!repair_allowed(1, 3, 2, 2));
        assert!(!repair_allowed(2, 2, 2, 2));
    }

    #[test]
    fn exact_requirement_query_is_machine_executable_or_fails_closed() {
        assert_eq!(
            exact_requirement_probe("exact:path=src/settings/SettingsForm.tsx;contains=Save"),
            Some(ExactRequirementProbe::Path {
                path: "src/settings/SettingsForm.tsx".to_owned(),
                contains: vec!["Save".to_owned()],
            })
        );
        assert!(exact_requirement_probe("Confirm exact SettingsForm label").is_none());
    }

    #[test]
    fn compiled_literal_relation_requires_old_to_new_relation_not_cooccurrence() {
        assert!(explicit_replace_relation(
            "Change Save to Apply in SettingsForm.",
            "Save",
            "Apply"
        ));
        assert!(!explicit_replace_relation(
            "Rename the Settings button from Save to Apply.",
            "Settings",
            "Apply"
        ));
    }
}
