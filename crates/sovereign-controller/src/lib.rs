//! M1 deterministic Controller vertical slice.
//!
//! The Controller is the only authority that activates compiler-produced plans,
//! derives readiness, owns task/attempt state, lowers typed model proposals into
//! exact authorized actions, and accepts fresh deterministic verification.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sovereign_context::{
    ContextLevel, ContextPacket, ContextPlanner, EvidenceItem, EvidenceKind, PacketSection,
    RepairPacket, RepairPacketInput, TrustClass,
};
use sovereign_evidence::{ArtifactStore, EvidenceError};
use sovereign_memory::{
    ControllerEpisodeOutcomeProof, ControllerEpisodeProof, EpisodeCapture, EpisodeCaptureResult,
    EpisodeRecorder, MemoryError, MemoryScope, MemoryScopeKind, ProcedurePattern,
};
use sovereign_model::{
    MODEL_SCHEMA_VERSION, ModelBackend, ModelError, ModelFinishReason, ModelMessage,
    ModelMessageRole, ModelOutputContract, ModelRequest,
};
use sovereign_plan::{
    PlanCompilationResult, PlanReplanInput, PlanRevisionDiff, ReplanScope,
    smallest_replan_scope_tasks,
};
use sovereign_policy::{
    Capability, CapabilityLayers, CapabilitySet, CommandMode, CommandPolicy, CommandRisk,
    HeavyLeaseClass, HostPressureSnapshot, IsolationRequest, M1ResourceGovernor, ModelCallBudget,
    PermissionDecision, PolicyError, ResourceGovernor, ResourceLease, TaskCapabilityGrant,
};
use sovereign_repo::{
    ChangeSet, ChangeSetCompositionInput, ComposeChangeSetsOutcome, CompositionConflictEvidence,
    ExactDiffEvidence, ExactFileEvidence, ExactRetriever, ProjectRegistry, RepoError,
    RepositoryIntelligence, RepositorySnapshot, WorktreeBaseline, WorktreeLease,
};
use sovereign_state::{
    CheckpointIntegrityRecord, JournalEvent, NewCheckpointIntegrityRecord, NewJournalEvent,
    StateError, StateRecordUpdate, StateStore,
};
use sovereign_tools::{
    ActionJournal, AuthorizedAction, PermissionClass, ProcessRunner, RawToolResult,
    ReconciliationMode, ToolError, ToolManifest, ToolSchemaV1, filter_authorized_tool_schemas,
    reap_owned_process_group,
};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

mod roles;
mod skills;

pub use roles::{
    ROLE_OUTPUT_SCHEMA_VERSION, ROLE_PROFILE_SCHEMA_VERSION, ROLE_PROFILE_VERSION, RoleDisposition,
    RoleId, RoleOutputV1, RolePin, RoleProfile, RoleRegistry, RoleToolClass,
};
pub use skills::{
    DEFAULT_MAX_DISCOVERED_MANIFESTS, DEFAULT_MAX_SELECTED_BODY_BYTES,
    DEFAULT_MAX_SELECTED_BODY_TOKENS, DEFAULT_MAX_SELECTED_METADATA_TOKENS,
    DEFAULT_MAX_SELECTED_SKILLS, DEFAULT_MAX_SKILL_BODY_BYTES, FilesystemSkillBodySource,
    HARD_MAX_SELECTED_BODY_TOKENS, HARD_MAX_SELECTED_SKILLS, HARD_MAX_SKILL_BODY_BYTES,
    HARD_MAX_SKILL_MANIFEST_BYTES, LoadedSkill, SKILL_MANIFEST_SCHEMA_VERSION, SkillBodySource,
    SkillCandidate, SkillError, SkillLoadBudget, SkillManifest, SkillPin, SkillRegistry,
    SkillSelection, SkillSelectionInput, SkillSelector,
};

pub const MODEL_PROPOSAL_SCHEMA_VERSION: u32 = 1;
pub const VERIFICATION_RESULT_SCHEMA_VERSION: u32 = 1;
pub const FAILURE_RECORD_SCHEMA_VERSION: u32 = 1;
const M1_MODEL_OUTPUT_TOKENS: u32 = 512;
const MAX_LITERAL_BYTES: usize = 4_096;
const EVIDENCE_SATISFACTION_SCHEMA_VERSION: u32 = 1;
const VERIFIED_OUTPUT_BINDING_SCHEMA_VERSION: u32 = 1;
const TASK_CARRY_FINGERPRINT_SCHEMA_VERSION: u32 = 1;
pub const CHECKPOINT_MANIFEST_SCHEMA_VERSION: u32 = 1;
pub const RECOVERY_PROCESS_LEASE_SCHEMA_VERSION: u32 = 1;
pub const EXECUTION_CONTROL_SCHEMA_VERSION: u32 = 1;
pub const GOAL_INTENT_SCHEMA_VERSION: u32 = 1;
const LEGACY_ACTION_INTENT_SCHEMA_VERSION: u32 = 2;
const ACTION_INTENT_SCHEMA_VERSION: u32 = 3;
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
    Memory(MemoryError),
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
            Self::Memory(error) => write!(f, "controller memory error: {error}"),
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
from_error!(MemoryError, Memory);
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionControlV1 {
    pub schema_version: u32,
    pub paused: bool,
    pub reason: Option<String>,
    pub changed_at_ms: i64,
}

impl Default for ExecutionControlV1 {
    fn default() -> Self {
        Self {
            schema_version: EXECUTION_CONTROL_SCHEMA_VERSION,
            paused: false,
            reason: None,
            changed_at_ms: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoalIntentV1 {
    pub schema_version: u32,
    pub goal_id: String,
    pub natural_language_goal: String,
    pub status: String,
    pub submitted_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ControllerStatusView {
    pub execution_control: ExecutionControlV1,
    pub active_plan: Option<Value>,
    pub tasks: Vec<Value>,
    pub attempts: Vec<Value>,
    pub actions: Vec<ControllerActionStatusView>,
    pub evidence: Vec<Value>,
    pub goal_intents: Vec<GoalIntentV1>,
    pub approval_requests: Vec<Value>,
}

struct DurableStatusActiveProjection {
    tasks: Vec<Value>,
    attempts: Vec<Value>,
    evidence: Vec<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerActionStatusView {
    pub action_id: String,
    pub state: String,
    pub payload_digest: String,
    pub policy_digest: String,
    pub execution_epoch: i64,
    pub result_digest: Option<String>,
    pub last_event_sequence: i64,
    pub updated_at_ms: i64,
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
    permission_decision: PermissionDecision,
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
    persisted_grant_issuer: String,
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
            persisted_grant_issuer: "user:local-autonomous-profile".to_owned(),
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
            persisted_grant_issuer: "user:read-only-profile".to_owned(),
        }
    }

    #[cfg(test)]
    fn permits(&self, permission: PermissionClass) -> bool {
        self.controller_ceiling.contains(&permission)
            && self.project_ceiling.contains(&permission)
            && self.role_ceiling.contains(&permission)
            && self.persisted_grants.contains(&permission)
    }

    #[cfg(test)]
    fn digest(&self) -> String {
        let encode = |set: &BTreeSet<PermissionClass>| {
            set.iter()
                .map(|permission| permission.as_plan_ir_str())
                .collect::<Vec<_>>()
                .join(",")
        };
        sha256_prefixed(
            format!(
                "{}\0{}\0{}\0{}\0{}",
                encode(&self.controller_ceiling),
                encode(&self.project_ceiling),
                encode(&self.role_ceiling),
                encode(&self.persisted_grants),
                self.persisted_grant_issuer
            )
            .as_bytes(),
        )
    }

    fn controller_capabilities(&self) -> CapabilitySet {
        CapabilitySet::new(self.controller_ceiling.iter().copied())
    }

    fn project_capabilities(&self) -> CapabilitySet {
        CapabilitySet::new(self.project_ceiling.iter().copied())
    }

    fn role_capabilities(&self) -> CapabilitySet {
        CapabilitySet::new(self.role_ceiling.iter().copied())
    }

    fn persisted_grant_capabilities(&self) -> CapabilitySet {
        CapabilitySet::new(self.persisted_grants.iter().copied())
    }
}

const TASK_CAPABILITY_GRANT_SCHEMA_VERSION: u32 = 1;
const TASK_CAPABILITY_GRANT_NAMESPACE: &str = "controller.task_capability_grant";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedTaskCapabilityGrantV1 {
    schema_version: u32,
    plan_id: String,
    plan_revision: u32,
    task_id: String,
    task_contract_digest: String,
    policy_digest: String,
    issued_by: String,
    capabilities: Vec<String>,
}

impl PersistedTaskCapabilityGrantV1 {
    fn from_grant(grant: &TaskCapabilityGrant) -> Self {
        Self {
            schema_version: TASK_CAPABILITY_GRANT_SCHEMA_VERSION,
            plan_id: grant.plan_id.clone(),
            plan_revision: grant.plan_revision,
            task_id: grant.task_id.clone(),
            task_contract_digest: grant.task_contract_digest.clone(),
            policy_digest: grant.policy_digest.clone(),
            issued_by: grant.issued_by.clone(),
            capabilities: grant
                .capabilities
                .iter()
                .map(|capability| capability.as_plan_ir_str().to_owned())
                .collect(),
        }
    }

    fn into_grant(self) -> Result<TaskCapabilityGrant, ControllerError> {
        if self.schema_version != TASK_CAPABILITY_GRANT_SCHEMA_VERSION {
            return Err(ControllerError::NotReady(
                "unsupported persisted task capability grant schema".to_owned(),
            ));
        }
        let capabilities =
            capability_set_from_strings(self.capabilities.iter().map(String::as_str))?;
        let grant = TaskCapabilityGrant {
            plan_id: self.plan_id,
            plan_revision: self.plan_revision,
            task_id: self.task_id,
            task_contract_digest: self.task_contract_digest,
            policy_digest: self.policy_digest,
            issued_by: self.issued_by,
            capabilities,
        };
        grant.validate()?;
        Ok(grant)
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
#[serde(deny_unknown_fields)]
pub struct FailureRecordV1 {
    pub schema_version: u32,
    pub plan_id: String,
    pub plan_revision: u32,
    pub plan_digest: String,
    pub task_id: String,
    pub task_contract_digest: String,
    pub attempt_id: String,
    pub action_id: Option<String>,
    pub result_digest: Option<String>,
    pub exit_code: Option<i32>,
    pub failure_code: String,
    pub signature: String,
    pub category: String,
    pub synopsis: String,
    pub failed_action_facts: BTreeMap<String, String>,
    pub evidence_refs: Vec<String>,
    pub affected_contract_ids: Vec<String>,
    pub confidence_milli: u16,
    pub decision: String,
}

/// One Controller-verified observation that falsifies a stable Plan IR contract.
/// Evidence references must be revalidated against current repository truth before
/// this input is passed to [`FailureClassifier::classify_verified`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StableContractInvalidation {
    pub contract_id: String,
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub observed_fingerprints: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureClassificationKind {
    ExecutionFailure,
    PlanFailure,
}

/// Deterministic result of classifying already-verified invalidation evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureClassification {
    pub kind: FailureClassificationKind,
    pub scope: Option<ReplanScope>,
    pub affected_task_ids: Vec<String>,
    pub affected_contract_ids: Vec<String>,
    pub evidence_refs: Vec<String>,
}

/// Public deterministic failure classifier. Retry exhaustion never participates
/// in this decision; only stable Plan IR contract invalidation does.
pub struct FailureClassifier;

impl FailureClassifier {
    /// Classifies evidence after the Controller has verified every referenced item
    /// against current repository truth. Empty invalidation is execution failure.
    ///
    /// # Errors
    /// Returns a fail-closed Controller error when a cited stable contract does not
    /// resolve, its fingerprint is not actually falsified, or the failing task lies
    /// outside the deterministic invalidation scope.
    pub fn classify_verified(
        plan: &Value,
        failing_task_id: &str,
        invalidations: &[StableContractInvalidation],
    ) -> Result<FailureClassification, ControllerError> {
        if invalidations.is_empty() {
            return Ok(FailureClassification {
                kind: FailureClassificationKind::ExecutionFailure,
                scope: None,
                affected_task_ids: Vec::new(),
                affected_contract_ids: Vec::new(),
                evidence_refs: Vec::new(),
            });
        }
        let mut scope = ReplanScope::Task;
        let mut affected = BTreeSet::new();
        let mut contract_ids = BTreeSet::new();
        let mut evidence_refs = BTreeSet::new();
        for invalidation in invalidations {
            if invalidation.evidence_refs.is_empty() {
                return Err(ControllerError::InvalidPlan(format!(
                    "stable contract {} lacks invalidation evidence",
                    invalidation.contract_id
                )));
            }
            let resolved = resolve_stable_plan_contract(plan, &invalidation.contract_id)?;
            if !resolved.fingerprints.is_empty()
                && (invalidation.observed_fingerprints.is_empty()
                    || resolved.fingerprints == invalidation.observed_fingerprints)
            {
                return Err(ControllerError::InvalidPlan(format!(
                    "stable assumption {} was not falsified by changed fingerprints",
                    invalidation.contract_id
                )));
            }
            scope = scope.max(resolved.scope);
            affected.extend(
                smallest_replan_scope_tasks(plan, &resolved.owner_task_id, resolved.scope)
                    .map_err(ControllerError::InvalidPlan)?,
            );
            contract_ids.insert(invalidation.contract_id.clone());
            evidence_refs.extend(invalidation.evidence_refs.iter().cloned());
        }
        if !affected.contains(failing_task_id) {
            return Err(ControllerError::InvalidPlan(format!(
                "failing task {failing_task_id} is outside the invalidated dependency scope"
            )));
        }
        Ok(FailureClassification {
            kind: FailureClassificationKind::PlanFailure,
            scope: Some(scope),
            affected_task_ids: affected.into_iter().collect(),
            affected_contract_ids: contract_ids.into_iter().collect(),
            evidence_refs: evidence_refs.into_iter().collect(),
        })
    }
}

#[derive(Debug, Clone)]
struct FailureRecordInput {
    task_id: String,
    attempt_id: String,
    action_id: Option<String>,
    result_digest: Option<String>,
    exit_code: Option<i32>,
    category: String,
    failure_code: String,
    diagnostic: String,
    failed_action_facts: BTreeMap<String, String>,
    evidence_refs: Vec<String>,
}

/// Backward-compatible name used by the M1-T07 execution-error surface.
pub type ExecutionFailureV1 = FailureRecordV1;

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
    #[serde(default)]
    pub execution_control: ExecutionControlV1,
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
    #[serde(default)]
    change_set_digest: Option<String>,
    #[serde(default)]
    carried_from_plan_revision: Option<u32>,
    #[serde(default)]
    carried_from_plan_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TaskCarryFingerprintV1 {
    schema_version: u32,
    plan_id: String,
    plan_revision: u32,
    plan_digest: String,
    task_id: String,
    task_contract_digest: String,
    implementation_inputs_digest: String,
    dependency_contract_digest: String,
    instruction_fingerprint_digest: String,
    source_fingerprints: BTreeMap<String, String>,
    #[serde(default)]
    execution_provenance: Option<TaskCarryExecutionProvenanceV1>,
    acceptance_contract_digest: String,
    verification_id: String,
    verification_artifact_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TaskCarryExecutionProvenanceV1 {
    change_set_digest: String,
    composed_change_sets: Vec<ComposedChangeSetBindingV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TaskRuntime {
    state: TaskState,
    attempts_started: u32,
    model_calls_used: u32,
    failure_counts: BTreeMap<String, u32>,
    retry_exhausted: bool,
    #[serde(default)]
    resource_deferrals_used: u32,
    #[serde(default)]
    resource_retry_exhausted: bool,
    #[serde(default)]
    resource_deferred_from: Option<TaskState>,
    #[serde(default)]
    worktree_lease: Option<WorktreeLease>,
    #[serde(default)]
    worktree_state: Option<WorktreeLifecycle>,
    #[serde(default)]
    change_set: Option<ChangeSet>,
    #[serde(default)]
    change_set_artifact_digest: Option<String>,
    #[serde(default)]
    change_set_carry: Option<CarriedChangeSetProvenanceV1>,
    #[serde(default)]
    worktree_baseline: Option<WorktreeBaseline>,
    #[serde(default)]
    worktree_composition: Vec<ComposedChangeSetBindingV1>,
    #[serde(default)]
    worktree_conflict: Option<CompositionConflictEvidence>,
    task_contract_digest: String,
    task: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ComposedChangeSetBindingV1 {
    task_id: String,
    change_set_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CarriedChangeSetProvenanceV1 {
    from_revision: u32,
    to_revision: u32,
    source_change_set_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WorktreeLifecycle {
    Prepared,
    Materialized,
    Conflict,
    Released,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AttemptRuntime {
    task_id: String,
    attempt_id: String,
    state: AttemptState,
    task_contract_digest: String,
    #[serde(default)]
    repair_origin: Option<RepairAttemptOriginV1>,
    baseline_digest: String,
    pre_snapshot_digest: String,
    pre_diff_digest: String,
    pre_changed_fingerprints: BTreeMap<PathBuf, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RepairAttemptOriginV1 {
    schema_version: u32,
    prior_attempt_id: String,
    failure_record_digest: String,
    repair_packet_digest: String,
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

    /// Replaces the exact persisted user-grant layer for one active task.
    /// The requested set can only narrow the Controller-configured user ceiling;
    /// every successful change advances the execution epoch so stale leases/actions fail closed.
    ///
    /// # Errors
    /// Returns a policy/readiness error for an unknown task, stale plan, or attempted grant
    /// outside the configured user-authority ceiling.
    pub fn set_task_capability_grant(
        &mut self,
        task_id: &str,
        capabilities: CapabilitySet,
    ) -> Result<i64, ControllerError> {
        self.require_execution_not_paused()?;
        if !capabilities.is_subset_of(&self.permission_context.persisted_grant_capabilities()) {
            return Err(ControllerError::Policy(PolicyError::Denied(
                "task capability grant cannot exceed configured user authority".to_owned(),
            )));
        }
        let (plan_id, plan_revision, task_contract_digest, policy_digest) = {
            let active = self.active_ref()?;
            if active.validity != PlanValidity::Current {
                return Err(ControllerError::NotReady(
                    "cannot change grants for a non-current plan".to_owned(),
                ));
            }
            let task = active
                .tasks
                .get(task_id)
                .ok_or_else(|| ControllerError::NotReady(format!("unknown task {task_id}")))?;
            (
                active.plan_id.clone(),
                active.revision,
                task.task_contract_digest.clone(),
                active.policy_digest.clone(),
            )
        };
        let grant = TaskCapabilityGrant {
            plan_id: plan_id.clone(),
            plan_revision,
            task_id: task_id.to_owned(),
            task_contract_digest,
            policy_digest: policy_digest.clone(),
            issued_by: self.permission_context.persisted_grant_issuer.clone(),
            capabilities,
        };
        grant.validate()?;
        let persisted = PersistedTaskCapabilityGrantV1::from_grant(&grant);
        let value_json = serde_json::to_string(&persisted)?;
        // Epoch first is deliberately fail-closed: persistence failure only invalidates more
        // previously derived authority; the inverse ordering could leave a stale lease usable.
        let epoch = self.state.advance_execution_epoch()?;
        let key = revision_scoped_key(&plan_id, plan_revision, task_id);
        self.persist_control_record_with_event(
            TASK_CAPABILITY_GRANT_NAMESPACE,
            &key,
            &value_json,
            "task_capability_grant_changed",
            &json!({
                "plan_id": plan_id,
                "plan_revision": plan_revision,
                "task_id": task_id,
                "policy_digest": policy_digest,
                "grant_digest": sha256_prefixed(value_json.as_bytes()),
                "execution_epoch": epoch,
            }),
        )?;
        self.checkpoint_now()?;
        Ok(epoch)
    }

    /// Converts only exact task-pinned schemas visible under the current permission decision into
    /// model-context evidence. This is the sole Controller bridge into
    /// `ContextPacketInput::authorized_tool_schemas`; provider-native tool calls remain disabled.
    ///
    /// # Errors
    /// Fails closed for malformed schema/manifest identities or invalid active authority.
    pub fn authorized_tool_schema_evidence(
        &self,
        task_id: &str,
        schemas: &[ToolSchemaV1],
        manifests: &[ToolManifest],
    ) -> Result<Vec<EvidenceItem>, ControllerError> {
        let task = self
            .active_ref()?
            .tasks
            .get(task_id)
            .ok_or_else(|| ControllerError::NotReady(format!("unknown task {task_id}")))?;
        let task_tools = required_array(&task.task, "/tools")?;
        let mut decisions = Vec::new();
        for manifest in manifests {
            let pinned = task_tools.iter().any(|tool| {
                required_str(tool, "/id").ok() == Some(manifest.tool_id.as_str())
                    && required_str(tool, "/version").ok() == Some(manifest.version.as_str())
                    && required_str(tool, "/digest").ok() == Some(manifest.content_digest.as_str())
            });
            if pinned {
                decisions.push(self.permission_decision_for_task(task_id, manifest)?);
            }
        }
        let visible = filter_authorized_tool_schemas(schemas, manifests, &decisions)?;
        visible
            .into_iter()
            .map(|schema| {
                let required_capabilities = schema
                    .required_capabilities
                    .iter()
                    .map(Capability::as_plan_ir_str)
                    .collect::<Vec<_>>();
                let text = serde_json::to_string(&json!({
                    "schema": "ToolSchemaV1",
                    "tool_id": schema.tool_id,
                    "version": schema.version,
                    "content_digest": schema.content_digest,
                    "name": schema.name,
                    "description": schema.description,
                    "input_schema": schema.input_schema,
                    "required_capabilities": required_capabilities,
                }))?;
                Ok(EvidenceItem::new(
                    format!(
                        "tool-schema:{}:{}:{}",
                        schema.tool_id,
                        schema.version,
                        digest_fragment(&schema.content_digest, 24)
                    ),
                    PacketSection::ToolEvidence,
                    ContextLevel::C1,
                    EvidenceKind::ToolSchema,
                    format!("tool://{}@{}/schema", schema.tool_id, schema.version),
                    schema.content_digest.clone(),
                    "controller_authorized_tool_schema_v1",
                    TrustClass::Tool,
                    "exact task-pinned tool schema allowed by the effective permission decision",
                    text,
                ))
            })
            .collect()
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
    pub fn task_attempts_started(&self, task_id: &str) -> Option<u32> {
        self.active
            .as_ref()
            .and_then(|active| active.tasks.get(task_id))
            .map(|task| task.attempts_started)
    }

    #[must_use]
    pub fn task_resource_deferrals_used(&self, task_id: &str) -> Option<u32> {
        self.active
            .as_ref()
            .and_then(|active| active.tasks.get(task_id))
            .map(|task| task.resource_deferrals_used)
    }

    #[must_use]
    pub fn task_contract_digest(&self, task_id: &str) -> Option<&str> {
        self.active
            .as_ref()?
            .tasks
            .get(task_id)
            .map(|task| task.task_contract_digest.as_str())
    }

    #[must_use]
    pub fn task_worktree_lease(&self, task_id: &str) -> Option<&WorktreeLease> {
        self.active
            .as_ref()?
            .tasks
            .get(task_id)?
            .worktree_lease
            .as_ref()
    }

    #[must_use]
    pub fn task_change_set(&self, task_id: &str) -> Option<&ChangeSet> {
        self.active
            .as_ref()?
            .tasks
            .get(task_id)?
            .change_set
            .as_ref()
    }

    #[must_use]
    pub fn task_worktree_conflict(&self, task_id: &str) -> Option<&CompositionConflictEvidence> {
        self.active
            .as_ref()?
            .tasks
            .get(task_id)?
            .worktree_conflict
            .as_ref()
    }

    fn controller_worktree_root(&self) -> Result<PathBuf, ControllerError> {
        let parent = self.state.path().parent().ok_or_else(|| {
            ControllerError::InvalidPlan(
                "state database has no parent for controller worktrees".to_owned(),
            )
        })?;
        let parent = parent.canonicalize()?;
        let root = parent.join("worktrees");
        if root.exists() {
            Ok(root.canonicalize()?)
        } else {
            Ok(root)
        }
    }

    fn validate_controller_worktree_lease_binding(
        &self,
        task_id: &str,
        lease: &WorktreeLease,
    ) -> Result<(), ControllerError> {
        let active = self.active_ref()?;
        let task = active
            .tasks
            .get(task_id)
            .ok_or_else(|| ControllerError::NotReady(format!("unknown task {task_id}")))?;
        let expected_root = self.controller_worktree_root()?;
        let expected_path = expected_root.join(&lease.lease_id);
        if lease.plan_id != active.plan_id
            || lease.plan_revision != active.revision
            || lease.task_id != task_id
            || lease.task_contract_digest != task.task_contract_digest
            || lease.repository_id != active.repository_id
            || lease.primary_root != active.repository_root
            || lease.controller_root != expected_root
            || lease.worktree_path != expected_path
        {
            return Err(ControllerError::NotReady(
                "worktree lease is stale, path/root-tampered, or bound to another revision/task"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    fn ordered_upstream_change_sets(
        &self,
        task_id: &str,
    ) -> Result<
        (
            Vec<ComposedChangeSetBindingV1>,
            Vec<ChangeSetCompositionInput>,
        ),
        ControllerError,
    > {
        let active = self.active_ref()?;
        let order = dependency_closure_order(&active.tasks, task_id)?;
        let mut bindings = Vec::with_capacity(order.len());
        let mut change_sets = Vec::with_capacity(order.len());
        for upstream_task_id in order {
            let upstream = active.tasks.get(&upstream_task_id).ok_or_else(|| {
                ControllerError::InvalidPlan(format!(
                    "composed dependency task {upstream_task_id} disappeared"
                ))
            })?;
            if upstream.state != TaskState::Succeeded {
                return Err(ControllerError::NotReady(format!(
                    "composed dependency task {upstream_task_id} is not succeeded"
                )));
            }
            let record_key = active_scoped_key(active, &upstream_task_id);
            let change_set = validate_durable_change_set_binding(
                &self.state,
                &record_key,
                &upstream_task_id,
                upstream,
            )?;
            let change_set_digest = change_set.digest()?;
            bindings.push(ComposedChangeSetBindingV1 {
                task_id: upstream_task_id,
                change_set_digest: change_set_digest.clone(),
            });
            let input = if let Some(carry) = upstream.change_set_carry.as_ref() {
                if carry.from_revision != change_set.plan_revision
                    || carry.to_revision != active.revision
                    || carry.source_change_set_digest != change_set_digest
                {
                    return Err(ControllerError::NotReady(
                        "carried ChangeSet provenance is stale or misbound".to_owned(),
                    ));
                }
                ChangeSetCompositionInput::carried(
                    change_set,
                    carry.from_revision,
                    carry.to_revision,
                )?
            } else {
                if change_set.plan_revision != active.revision {
                    return Err(ControllerError::NotReady(
                        "historical ChangeSet lacks explicit carry provenance".to_owned(),
                    ));
                }
                ChangeSetCompositionInput::current(change_set)
            };
            change_sets.push(input);
        }
        Ok((bindings, change_sets))
    }

    #[allow(clippy::too_many_lines)]
    fn ensure_task_worktree(
        &mut self,
        registry: &ProjectRegistry,
        task_id: &str,
    ) -> Result<(), ControllerError> {
        if !self.active_uses_controller_worktrees()? {
            return Ok(());
        }
        let (plan_id, plan_revision, task_contract_digest, repository_id, primary_root) = {
            let active = self.active_ref()?;
            let task = active
                .tasks
                .get(task_id)
                .ok_or_else(|| ControllerError::NotReady(format!("unknown task {task_id}")))?;
            (
                active.plan_id.clone(),
                active.revision,
                task.task_contract_digest.clone(),
                active.repository_id.clone(),
                active.repository_root.clone(),
            )
        };
        if self
            .active_ref()?
            .tasks
            .get(task_id)
            .and_then(|task| task.worktree_lease.as_ref())
            .is_none()
        {
            let controller_root = self.controller_worktree_root()?;
            let lease = registry.prepare_worktree_lease(
                &repository_id,
                &controller_root,
                &plan_id,
                plan_revision,
                task_id,
                &task_contract_digest,
            )?;
            if lease.primary_root != primary_root
                || lease.controller_root != controller_root
                || lease.worktree_path != controller_root.join(&lease.lease_id)
            {
                return Err(ControllerError::NotReady(
                    "prepared worktree lease is not bound to the active repository/controller root"
                        .to_owned(),
                ));
            }
            {
                let task = self
                    .active_mut()?
                    .tasks
                    .get_mut(task_id)
                    .ok_or_else(|| ControllerError::NotReady("task disappeared".to_owned()))?;
                task.worktree_lease = Some(lease.clone());
                task.worktree_state = Some(WorktreeLifecycle::Prepared);
            }
            self.persist_worktree_task_state(
                task_id,
                "worktree_lease_prepared",
                &json!({"lease_id": lease.lease_id, "base_head": lease.base_head}),
            )?;
        }

        let (lease, lifecycle) = {
            let active = self.active_ref()?;
            let task = active
                .tasks
                .get(task_id)
                .ok_or_else(|| ControllerError::NotReady("task disappeared".to_owned()))?;
            let lease = task.worktree_lease.clone().ok_or_else(|| {
                ControllerError::NotReady("D3/D4 task lost its worktree lease".to_owned())
            })?;
            (lease, task.worktree_state)
        };
        self.validate_controller_worktree_lease_binding(task_id, &lease)?;
        let (expected_composition, upstream_change_sets) =
            self.ordered_upstream_change_sets(task_id)?;
        match lifecycle {
            Some(WorktreeLifecycle::Prepared) => {
                if lease.worktree_path.exists() {
                    registry.validate_worktree_lease(&lease)?;
                } else {
                    registry.materialize_worktree(&lease)?;
                }
                match registry.compose_change_sets(&lease, &upstream_change_sets)? {
                    ComposeChangeSetsOutcome::Ready(baseline) => {
                        let task = self.active_mut()?.tasks.get_mut(task_id).ok_or_else(|| {
                            ControllerError::NotReady("task disappeared".to_owned())
                        })?;
                        task.worktree_state = Some(WorktreeLifecycle::Materialized);
                        task.worktree_baseline = Some(baseline.clone());
                        task.worktree_composition.clone_from(&expected_composition);
                        task.worktree_conflict = None;
                        self.persist_worktree_task_state(
                            task_id,
                            "worktree_materialized",
                            &json!({
                                "lease_id": lease.lease_id,
                                "path": lease.worktree_path,
                                "baseline_digest": baseline.digest,
                                "composition": expected_composition,
                            }),
                        )?;
                    }
                    ComposeChangeSetsOutcome::Conflict(conflict) => {
                        let task = self.active_mut()?.tasks.get_mut(task_id).ok_or_else(|| {
                            ControllerError::NotReady("task disappeared".to_owned())
                        })?;
                        task.worktree_state = Some(WorktreeLifecycle::Conflict);
                        task.worktree_composition = expected_composition;
                        task.worktree_conflict = Some(conflict.clone());
                        self.persist_worktree_conflict(task_id, &conflict)?;
                        return Err(ControllerError::NotReady(format!(
                            "dependency ChangeSet composition conflict for task {task_id}"
                        )));
                    }
                }
            }
            Some(WorktreeLifecycle::Materialized) => {
                registry.validate_worktree_lease(&lease)?;
                let task = self
                    .active_ref()?
                    .tasks
                    .get(task_id)
                    .ok_or_else(|| ControllerError::NotReady("task disappeared".to_owned()))?;
                if task.worktree_baseline.is_none()
                    || task.worktree_composition != expected_composition
                    || task.worktree_conflict.is_some()
                {
                    return Err(ControllerError::NotReady(
                        "materialized worktree composition/baseline binding is stale".to_owned(),
                    ));
                }
            }
            Some(WorktreeLifecycle::Conflict) => {
                registry.validate_worktree_lease(&lease)?;
                if self
                    .active_ref()?
                    .tasks
                    .get(task_id)
                    .and_then(|task| task.worktree_conflict.as_ref())
                    .is_none()
                {
                    return Err(ControllerError::InvalidPlan(
                        "conflicted worktree lost durable conflict evidence".to_owned(),
                    ));
                }
                return Err(ControllerError::NotReady(
                    "dependency ChangeSet composition remains conflicted".to_owned(),
                ));
            }
            Some(WorktreeLifecycle::Released) => {
                return Err(ControllerError::NotReady(
                    "completed controller worktree lease cannot authorize another mutation"
                        .to_owned(),
                ));
            }
            None => {
                return Err(ControllerError::NotReady(
                    "D3/D4 worktree lifecycle is missing".to_owned(),
                ));
            }
        }
        Ok(())
    }

    fn persist_worktree_conflict(
        &mut self,
        task_id: &str,
        conflict: &CompositionConflictEvidence,
    ) -> Result<(), ControllerError> {
        let task_json =
            serde_json::to_string(self.active_ref()?.tasks.get(task_id).ok_or_else(|| {
                ControllerError::InvalidPlan("worktree conflict task disappeared".to_owned())
            })?)?;
        let key = active_scoped_key(self.active_ref()?, task_id);
        self.persist_runtime_records_with_events(
            &[
                ("controller.task".to_owned(), task_id.to_owned(), task_json),
                (
                    "controller.worktree_conflict".to_owned(),
                    key,
                    serde_json::to_string(conflict)?,
                ),
            ],
            &[(
                "worktree_composition_conflict".to_owned(),
                task_id.to_owned(),
                serde_json::to_value(conflict)?,
            )],
        )?;
        self.checkpoint_now()?;
        Ok(())
    }

    fn persist_worktree_task_state(
        &mut self,
        task_id: &str,
        event_kind: &str,
        payload: &Value,
    ) -> Result<(), ControllerError> {
        let task_json =
            serde_json::to_string(self.active_ref()?.tasks.get(task_id).ok_or_else(|| {
                ControllerError::InvalidPlan("worktree task disappeared".to_owned())
            })?)?;
        self.persist_runtime_records_with_events(
            &[("controller.task".to_owned(), task_id.to_owned(), task_json)],
            &[(event_kind.to_owned(), task_id.to_owned(), payload.clone())],
        )?;
        self.checkpoint_now()?;
        Ok(())
    }

    fn active_uses_controller_worktrees(&self) -> Result<bool, ControllerError> {
        let mode = required_str(&self.active_ref()?.plan_document, "/depth/mode")?;
        Ok(matches!(mode, "D3" | "D4"))
    }

    fn task_execution_lease(
        &self,
        task_id: &str,
    ) -> Result<Option<&WorktreeLease>, ControllerError> {
        if !self.active_uses_controller_worktrees()? {
            return Ok(None);
        }
        let task = self
            .active_ref()?
            .tasks
            .get(task_id)
            .ok_or_else(|| ControllerError::NotReady(format!("unknown task {task_id}")))?;
        if task.worktree_state != Some(WorktreeLifecycle::Materialized) {
            return Err(ControllerError::NotReady(
                "D3/D4 task worktree is not materialized".to_owned(),
            ));
        }
        let lease = task
            .worktree_lease
            .as_ref()
            .ok_or_else(|| ControllerError::NotReady("D3/D4 task lease is missing".to_owned()))?;
        self.validate_controller_worktree_lease_binding(task_id, lease)?;
        Ok(Some(lease))
    }

    fn task_execution_root(&self, task_id: &str) -> Result<PathBuf, ControllerError> {
        self.task_execution_lease(task_id)?.map_or_else(
            || {
                self.active_ref()
                    .map(|active| active.repository_root.clone())
            },
            |lease| Ok(lease.worktree_path.clone()),
        )
    }

    fn task_execution_snapshot(
        &self,
        registry: &ProjectRegistry,
        task_id: &str,
    ) -> Result<RepositorySnapshot, ControllerError> {
        match self.task_execution_lease(task_id)? {
            Some(lease) => Ok(registry.worktree_snapshot(lease)?),
            None => Ok(registry.snapshot(&self.active_ref()?.repository_id)?),
        }
    }

    fn task_execution_diff(
        &self,
        registry: &ProjectRegistry,
        task_id: &str,
    ) -> Result<ExactDiffEvidence, ControllerError> {
        match self.task_execution_lease(task_id)? {
            Some(lease) => Ok(registry.worktree_diff(lease)?),
            None => Ok(
                ExactRetriever::new(registry).current_diff(&self.active_ref()?.repository_id)?
            ),
        }
    }

    fn task_execution_read(
        &self,
        registry: &ProjectRegistry,
        task_id: &str,
        path: &Path,
        expected_digest: Option<&str>,
    ) -> Result<ExactFileEvidence, ControllerError> {
        match self.task_execution_lease(task_id)? {
            Some(lease) => Ok(registry.read_worktree_path(lease, path, expected_digest)?),
            None => Ok(ExactRetriever::new(registry).read_path(
                &self.active_ref()?.repository_id,
                path,
                expected_digest,
            )?),
        }
    }

    /// Returns the durable Controller-owned execution-control state.
    ///
    /// # Errors
    /// Fails closed on malformed durable state.
    pub fn execution_control(&self) -> Result<ExecutionControlV1, ControllerError> {
        load_execution_control(&self.state)
    }

    /// Durably records a natural-language goal intent without bypassing the `PlanCompiler`.
    /// The intent remains queued until a later execution path compiles and activates it.
    ///
    /// # Errors
    /// Returns an error for an empty goal or durable-state failure.
    pub fn submit_goal_intent(&mut self, goal: &str) -> Result<GoalIntentV1, ControllerError> {
        let goal = goal.trim();
        if goal.is_empty() {
            return Err(ControllerError::InvalidPlan(
                "natural-language goal must not be empty".to_owned(),
            ));
        }
        let submitted_at_ms = unix_millis()?;
        let digest = sha256_prefixed(
            format!(
                "{}\0{}\0{}",
                goal,
                submitted_at_ms,
                self.state.latest_journal_sequence()?
            )
            .as_bytes(),
        );
        let goal_id = format!("goal-{}", &digest[7..23]);
        let intent = GoalIntentV1 {
            schema_version: GOAL_INTENT_SCHEMA_VERSION,
            goal_id: goal_id.clone(),
            natural_language_goal: goal.to_owned(),
            status: "queued_for_plan_compilation".to_owned(),
            submitted_at_ms,
        };
        let intent_json = serde_json::to_string(&intent)?;
        self.persist_control_record_with_event(
            "controller.goal_intent",
            &goal_id,
            &intent_json,
            "goal_intent_submitted",
            &json!({"status": intent.status}),
        )?;
        if self.active.is_some() {
            self.checkpoint_now()?;
        }
        Ok(intent)
    }

    /// Pauses Controller readiness/mutation globally without changing frozen task-state semantics.
    ///
    /// # Errors
    /// Returns a durable-state/checkpoint error when the transition cannot be recorded safely.
    pub fn pause(&mut self, reason: Option<&str>) -> Result<ExecutionControlV1, ControllerError> {
        self.set_execution_paused(true, reason)
    }

    /// Resumes Controller readiness/mutation globally without changing frozen task-state semantics.
    ///
    /// # Errors
    /// Returns a durable-state/checkpoint error when the transition cannot be recorded safely.
    pub fn resume(&mut self) -> Result<ExecutionControlV1, ControllerError> {
        self.set_execution_paused(false, None)
    }

    /// Renders a read-only durable status projection for CLI clients.
    ///
    /// # Errors
    /// Fails closed on malformed Controller-owned durable records.
    pub fn durable_status(&self) -> Result<ControllerStatusView, ControllerError> {
        let decode_values = |namespace: &str| -> Result<Vec<Value>, ControllerError> {
            self.state
                .state_records(namespace)?
                .into_iter()
                .map(|record| Ok(serde_json::from_str(&record.value_json)?))
                .collect()
        };
        let active_plan = self
            .state
            .get_state("controller.plan", "active")?
            .map(|raw| serde_json::from_str::<Value>(&raw))
            .transpose()?;
        let projection = self.durable_status_active_projection(active_plan.as_ref())?;
        let goal_intents = self
            .state
            .state_records("controller.goal_intent")?
            .into_iter()
            .map(|record| Ok(serde_json::from_str(&record.value_json)?))
            .collect::<Result<Vec<GoalIntentV1>, ControllerError>>()?;
        Ok(ControllerStatusView {
            execution_control: self.execution_control()?,
            active_plan,
            tasks: projection.tasks,
            attempts: projection.attempts,
            actions: self
                .state
                .action_records()?
                .into_iter()
                .map(|record| ControllerActionStatusView {
                    action_id: record.action_id,
                    state: record.state,
                    payload_digest: record.payload_digest,
                    policy_digest: record.policy_digest,
                    execution_epoch: record.execution_epoch,
                    result_digest: record.result_digest,
                    last_event_sequence: record.last_event_sequence,
                    updated_at_ms: record.updated_at_ms,
                })
                .collect(),
            evidence: projection.evidence,
            goal_intents,
            approval_requests: decode_values("controller.approval_request")?,
        })
    }

    fn durable_status_active_projection(
        &self,
        active_plan: Option<&Value>,
    ) -> Result<DurableStatusActiveProjection, ControllerError> {
        let durable_scope = if let Some(durable) = active_plan {
            Some((
                required_str(durable, "/plan_id")?.to_owned(),
                required_u32(durable, "/revision")?,
                required_str(durable, "/plan_digest")?.to_owned(),
            ))
        } else {
            None
        };
        let active_scope = if let Some(active) = self.active.as_ref() {
            match durable_scope.as_ref() {
                Some((plan_id, revision, plan_digest))
                    if plan_id != &active.plan_id
                        || *revision != active.revision
                        || plan_digest != &active.plan_digest =>
                {
                    return Err(ControllerError::InvalidPlan(
                        "durable active-plan pointer differs from Controller runtime".to_owned(),
                    ));
                }
                _ => {}
            }
            Some((
                active.plan_id.clone(),
                active.revision,
                active.plan_digest.clone(),
            ))
        } else {
            durable_scope
        };
        let Some((plan_id, revision, plan_digest)) = active_scope else {
            return Ok(DurableStatusActiveProjection {
                tasks: Vec::new(),
                attempts: Vec::new(),
                evidence: Vec::new(),
            });
        };

        let tasks = if let Some(active) = self.active.as_ref() {
            active
                .tasks
                .values()
                .map(serde_json::to_value)
                .collect::<Result<Vec<_>, _>>()?
        } else {
            self.state
                .state_records("controller.task")?
                .into_iter()
                .filter(|record| key_belongs_to_revision(&record.key, &plan_id, revision))
                .map(|record| Ok(serde_json::from_str(&record.value_json)?))
                .collect::<Result<Vec<_>, ControllerError>>()?
        };
        let attempts = if let Some(active) = self.active.as_ref() {
            active
                .attempts
                .values()
                .map(serde_json::to_value)
                .collect::<Result<Vec<_>, _>>()?
        } else {
            self.state
                .state_records("controller.attempt")?
                .into_iter()
                .filter(|record| key_belongs_to_revision(&record.key, &plan_id, revision))
                .map(|record| Ok(serde_json::from_str(&record.value_json)?))
                .collect::<Result<Vec<_>, ControllerError>>()?
        };
        let mut evidence = self
            .state
            .state_records("controller.verification")?
            .into_iter()
            .filter_map(|record| {
                let value: Value = serde_json::from_str(&record.value_json).ok()?;
                (value.get("plan_id").and_then(Value::as_str) == Some(plan_id.as_str())
                    && value.get("plan_revision").and_then(Value::as_u64)
                        == Some(u64::from(revision))
                    && value.get("plan_digest").and_then(Value::as_str)
                        == Some(plan_digest.as_str()))
                .then_some(Ok(value))
            })
            .collect::<Result<Vec<_>, ControllerError>>()?;
        for namespace in [
            "controller.evidence_satisfaction",
            "controller.evidence_item",
        ] {
            for record in self.state.state_records(namespace)? {
                if key_belongs_to_revision(&record.key, &plan_id, revision) {
                    evidence.push(serde_json::from_str(&record.value_json)?);
                }
            }
        }
        Ok(DurableStatusActiveProjection {
            tasks,
            attempts,
            evidence,
        })
    }

    /// Returns the latest Controller-owned durable `FailureRecord v1` for a task.
    ///
    /// # Errors
    /// Fails closed if the journal binding, durable record digest, or schema is inconsistent.
    pub fn latest_failure_record(
        &self,
        task_id: &str,
    ) -> Result<Option<FailureRecordV1>, ControllerError> {
        Ok(self
            .latest_failure_record_with_digest(task_id)?
            .map(|(record, _)| record))
    }

    /// Captures one Controller-owned durable attempt outcome as episodic memory.
    ///
    /// The caller supplies only the attempt identity and an optional reusable
    /// procedure description. Success/failure eligibility, project scope, task
    /// contract, durable verification/failure proof, and promotion support are
    /// derived from Controller-owned state. Learning remains evidence-only and
    /// cannot mutate Plan IR, permissions, task authority, or completion state.
    ///
    /// # Errors
    /// Fails closed when the attempt is not terminal, durable outcome proof is
    /// missing/ambiguous, memory validation fails, or the post-learning
    /// checkpoint cannot cover newly appended journal facts.
    pub fn record_attempt_episode(
        &mut self,
        attempt_id: &str,
        procedure: Option<ProcedurePattern>,
        now_ms: i64,
    ) -> Result<EpisodeCaptureResult, ControllerError> {
        let (scope, proof) = self.episode_capture_proof(attempt_id)?;
        let capture = EpisodeCapture {
            scope,
            procedure,
            proof,
            observed_at_ms: now_ms,
        };
        let journal_before = self.state.latest_journal_sequence()?;
        let result = EpisodeRecorder::new(&mut self.state).record(&capture);
        let journal_after = self.state.latest_journal_sequence()?;
        if journal_after > journal_before {
            self.checkpoint_now()?;
        }
        result.map_err(ControllerError::Memory)
    }

    fn episode_capture_proof(
        &self,
        attempt_id: &str,
    ) -> Result<(MemoryScope, ControllerEpisodeProof), ControllerError> {
        let active = self.active_ref()?;
        let attempt = active.attempts.get(attempt_id).ok_or_else(|| {
            ControllerError::NotReady(format!("unknown attempt {attempt_id} for learning"))
        })?;
        let task = active.tasks.get(&attempt.task_id).ok_or_else(|| {
            ControllerError::InvalidPlan("learning attempt task disappeared".to_owned())
        })?;
        if task.task_contract_digest != attempt.task_contract_digest {
            return Err(ControllerError::InvalidPlan(
                "learning attempt/task contract binding is inconsistent".to_owned(),
            ));
        }
        let project_id = required_str(&active.plan_document, "/project/project_id")?.to_owned();
        let scope = MemoryScope {
            project_id,
            repository_id: Some(active.repository_id.clone()),
            kind: MemoryScopeKind::Project,
            agent_id: None,
            role_visibility: Vec::new(),
        };
        let task_record_key =
            revision_scoped_key(&active.plan_id, active.revision, &attempt.task_id);
        let attempt_record_key = revision_scoped_key(&active.plan_id, active.revision, attempt_id);
        let outcome = match attempt.state {
            AttemptState::Succeeded => {
                self.verified_success_episode_outcome(active, attempt, attempt_id)?
            }
            AttemptState::Failed => self.failed_episode_outcome(active, attempt, attempt_id)?,
            state => {
                return Err(ControllerError::NotReady(format!(
                    "attempt {attempt_id} in state {state:?} is not eligible for episode learning"
                )));
            }
        };
        Ok((
            scope,
            ControllerEpisodeProof {
                plan_id: active.plan_id.clone(),
                plan_revision: active.revision,
                plan_digest: active.plan_digest.clone(),
                task_id: attempt.task_id.clone(),
                task_contract_digest: attempt.task_contract_digest.clone(),
                attempt_id: attempt_id.to_owned(),
                task_record_key,
                attempt_record_key,
                outcome,
            },
        ))
    }

    fn verified_success_episode_outcome(
        &self,
        active: &ActivePlan,
        attempt: &AttemptRuntime,
        attempt_id: &str,
    ) -> Result<ControllerEpisodeOutcomeProof, ControllerError> {
        let mut matches = Vec::new();
        for record in self.state.state_records("controller.verification")? {
            let verification: VerificationResultV1 = serde_json::from_str(&record.value_json)?;
            if verification.schema_version == VERIFICATION_RESULT_SCHEMA_VERSION
                && verification.passed
                && verification.plan_id == active.plan_id
                && verification.plan_revision == active.revision
                && verification.plan_digest == active.plan_digest
                && verification.task_id == attempt.task_id
                && verification.task_contract_digest == attempt.task_contract_digest
                && verification.attempt_id == attempt_id
                && record.key
                    == revision_scoped_key(
                        &verification.plan_id,
                        verification.plan_revision,
                        &verification.verification_id,
                    )
            {
                matches.push(verification);
            }
        }
        if matches.len() != 1 {
            return Err(ControllerError::NotReady(format!(
                "succeeded attempt {attempt_id} requires exactly one durable passed verification; found {}",
                matches.len()
            )));
        }
        let verification = matches.pop().ok_or_else(|| {
            ControllerError::NotReady(
                "succeeded attempt verification disappeared during learning".to_owned(),
            )
        })?;
        Ok(ControllerEpisodeOutcomeProof::VerifiedSuccess {
            verification_record_key: revision_scoped_key(
                &verification.plan_id,
                verification.plan_revision,
                &verification.verification_id,
            ),
            verification_id: verification.verification_id,
        })
    }

    fn failed_episode_outcome(
        &self,
        active: &ActivePlan,
        attempt: &AttemptRuntime,
        attempt_id: &str,
    ) -> Result<ControllerEpisodeOutcomeProof, ControllerError> {
        let failure_record_key = revision_scoped_key(
            &active.plan_id,
            active.revision,
            &format!("{}:{attempt_id}", attempt.task_id),
        );
        let raw = self
            .state
            .get_state("controller.failure_record", &failure_record_key)?
            .ok_or_else(|| {
                ControllerError::NotReady(format!(
                    "failed attempt {attempt_id} lacks its durable FailureRecord"
                ))
            })?;
        let failure: FailureRecordV1 = serde_json::from_str(&raw)?;
        if failure.schema_version != FAILURE_RECORD_SCHEMA_VERSION
            || failure.plan_id != active.plan_id
            || failure.plan_revision != active.revision
            || failure.plan_digest != active.plan_digest
            || failure.task_id != attempt.task_id
            || failure.task_contract_digest != attempt.task_contract_digest
            || failure.attempt_id != attempt_id
            || failure.signature.is_empty()
        {
            return Err(ControllerError::InvalidPlan(
                "durable FailureRecord is misbound to the learned attempt".to_owned(),
            ));
        }
        Ok(ControllerEpisodeOutcomeProof::FailedAttempt {
            failure_record_key,
            failure_signature: failure.signature,
        })
    }

    fn latest_failure_record_with_digest(
        &self,
        task_id: &str,
    ) -> Result<Option<(FailureRecordV1, String)>, ControllerError> {
        let active = self.active_ref()?;
        for event in self.state.journal()?.into_iter().rev() {
            if event.entity_type != "controller" || event.event_kind != "failure_recorded" {
                continue;
            }
            let payload: Value = serde_json::from_str(&event.payload_json)?;
            if payload.get("task_id").and_then(Value::as_str) != Some(task_id) {
                continue;
            }
            let record_key = required_str(&payload, "/record_key")?;
            let expected_digest = required_str(&payload, "/failure_record_digest")?;
            let raw = self
                .state
                .get_state("controller.failure_record", record_key)?
                .ok_or_else(|| {
                    ControllerError::InvalidPlan(
                        "failure journal points to missing durable record".to_owned(),
                    )
                })?;
            let actual_digest = sha256_prefixed(raw.as_bytes());
            if actual_digest != expected_digest {
                return Err(ControllerError::InvalidPlan(
                    "durable FailureRecord digest differs from journal authority".to_owned(),
                ));
            }
            let record: FailureRecordV1 = serde_json::from_str(&raw)?;
            let expected_record_key = revision_scoped_key(
                &record.plan_id,
                record.plan_revision,
                &format!("{}:{}", record.task_id, record.attempt_id),
            );
            if record.schema_version != FAILURE_RECORD_SCHEMA_VERSION
                || record.task_id != task_id
                || expected_record_key != record_key
            {
                return Err(ControllerError::InvalidPlan(
                    "durable FailureRecord binding is malformed".to_owned(),
                ));
            }
            if record.plan_id != active.plan_id
                || record.plan_revision != active.revision
                || record.plan_digest != active.plan_digest
            {
                continue;
            }
            return Ok(Some((record, actual_digest)));
        }
        Ok(None)
    }

    fn durable_plan_failure_classification(
        &self,
    ) -> Result<FailureClassification, ControllerError> {
        let active = self.active_ref()?;
        for event in self.state.journal()?.into_iter().rev() {
            if event.entity_type != "controller" || event.event_kind != "failure_recorded" {
                continue;
            }
            let payload: Value = serde_json::from_str(&event.payload_json)?;
            if payload.get("category").and_then(Value::as_str) != Some("plan_failure") {
                continue;
            }
            let record_key = required_str(&payload, "/record_key")?;
            let expected_digest = required_str(&payload, "/failure_record_digest")?;
            let raw = self
                .state
                .get_state("controller.failure_record", record_key)?
                .ok_or_else(|| {
                    ControllerError::InvalidPlan(
                        "plan-failure journal points to missing durable record".to_owned(),
                    )
                })?;
            if sha256_prefixed(raw.as_bytes()) != expected_digest {
                return Err(ControllerError::InvalidPlan(
                    "durable plan-failure record differs from journal binding".to_owned(),
                ));
            }
            let record: FailureRecordV1 = serde_json::from_str(&raw)?;
            if record.plan_id != active.plan_id
                || record.plan_revision != active.revision
                || record.plan_digest != active.plan_digest
                || record.category != "plan_failure"
                || record.decision != "replan_smallest_scope"
                || record.affected_contract_ids.is_empty()
                || record.evidence_refs.is_empty()
            {
                continue;
            }
            let mut scope = ReplanScope::Task;
            let mut affected = BTreeSet::new();
            for contract_id in &record.affected_contract_ids {
                let resolved = resolve_stable_plan_contract(&active.plan_document, contract_id)?;
                scope = scope.max(resolved.scope);
                affected.extend(
                    smallest_replan_scope_tasks(
                        &active.plan_document,
                        &resolved.owner_task_id,
                        resolved.scope,
                    )
                    .map_err(ControllerError::InvalidPlan)?,
                );
            }
            if !affected.contains(&record.task_id) {
                return Err(ControllerError::InvalidPlan(
                    "durable plan-failure task is outside its recomputed invalidation scope"
                        .to_owned(),
                ));
            }
            let mut affected_contract_ids = record.affected_contract_ids.clone();
            affected_contract_ids.sort();
            affected_contract_ids.dedup();
            let mut evidence_refs = record.evidence_refs.clone();
            evidence_refs.sort();
            evidence_refs.dedup();
            return Ok(FailureClassification {
                kind: FailureClassificationKind::PlanFailure,
                scope: Some(scope),
                affected_task_ids: affected.into_iter().collect(),
                affected_contract_ids,
                evidence_refs,
            });
        }
        Err(ControllerError::NotReady(
            "active invalidated revision lacks durable plan-failure authority".to_owned(),
        ))
    }

    #[must_use]
    pub fn plan_validity(&self) -> Option<PlanValidity> {
        self.active.as_ref().map(|active| active.validity)
    }

    /// Verifies explicit current repository evidence against stable Plan IR contracts,
    /// records a genuine plan failure, and invalidates revision N without consuming an
    /// execution-repair retry. Retry exhaustion is deliberately absent from this API.
    ///
    /// # Errors
    /// Returns a fail-closed Controller error when the baseline/evidence is stale,
    /// the contract cannot be deterministically falsified, or the attempt/runtime
    /// bindings do not match the active revision.
    #[allow(clippy::too_many_lines)]
    pub fn record_plan_failure(
        &mut self,
        registry: &ProjectRegistry,
        task_id: &str,
        attempt_id: &str,
        context: &ContextPacket,
        invalidations: &[StableContractInvalidation],
    ) -> Result<FailureClassification, ControllerError> {
        self.require_current_baseline(registry)?;
        let (repository_id, plan_document, plan_id, plan_revision, plan_digest) = {
            let active = self.active_ref()?;
            if active.validity != PlanValidity::Current {
                return Err(ControllerError::NotReady(
                    "plan failure classification requires the current active revision".to_owned(),
                ));
            }
            (
                active.repository_id.clone(),
                active.plan_document.clone(),
                active.plan_id.clone(),
                active.revision,
                active.plan_digest.clone(),
            )
        };
        let mut verified_invalidations = Vec::with_capacity(invalidations.len());
        let mut evidence_records = Vec::new();
        for invalidation in invalidations {
            let resolved_contract =
                resolve_stable_plan_contract(&plan_document, &invalidation.contract_id)?;
            let mut observed = BTreeSet::new();
            let mut verified_items = Vec::new();
            for evidence_id in &invalidation.evidence_refs {
                let item = context
                    .items
                    .iter()
                    .find(|item| item.evidence_id == *evidence_id)
                    .ok_or_else(|| {
                        ControllerError::NotReady(format!(
                            "plan invalidation evidence {evidence_id} is absent from bounded current context"
                        ))
                    })?;
                Self::validate_exact_context_evidence(registry, &repository_id, item)?;
                observed.insert(item.source_digest.clone());
                verified_items.push(item);
                let logical_key = format!(
                    "plan-failure:{}:{}",
                    invalidation.contract_id,
                    digest_fragment(&item.content_digest, 20)
                );
                let key = revision_scoped_key(&plan_id, plan_revision, &logical_key);
                evidence_records.push((
                    "controller.evidence_item".to_owned(),
                    key,
                    serde_json::to_string(item)?,
                ));
            }
            if !invalidation.observed_fingerprints.is_empty()
                && invalidation
                    .observed_fingerprints
                    .iter()
                    .any(|fingerprint| !observed.contains(fingerprint))
            {
                return Err(ControllerError::NotReady(format!(
                    "plan invalidation {} cites an unverified observed fingerprint",
                    invalidation.contract_id
                )));
            }
            match &resolved_contract.kind {
                ResolvedStableContractKind::Assumption => {
                    let contract_specific = verified_items.iter().any(|item| {
                        resolved_contract.basis_locators.iter().any(|locator| {
                            item.locator.as_deref() == Some(locator.as_str())
                                || item.source_uri == *locator
                        }) && !resolved_contract.fingerprints.contains(&item.source_digest)
                    });
                    if !contract_specific {
                        return Err(ControllerError::NotReady(format!(
                            "evidence does not deterministically falsify assumption {} at its recorded basis locator",
                            invalidation.contract_id
                        )));
                    }
                }
                ResolvedStableContractKind::DependencyBinding { downstream_task_id } => {
                    if !self.dependency_binding_is_stably_invalidated(
                        &resolved_contract.owner_task_id,
                        downstream_task_id,
                    )? {
                        return Err(ControllerError::NotReady(format!(
                            "dependency binding {} has no deterministic contract mismatch",
                            invalidation.contract_id
                        )));
                    }
                }
                ResolvedStableContractKind::Precondition
                | ResolvedStableContractKind::Invariant => {
                    return Err(ControllerError::NotReady(format!(
                        "stable contract {} lacks a machine-revalidatable falsification rule",
                        invalidation.contract_id
                    )));
                }
            }
            verified_invalidations.push(StableContractInvalidation {
                contract_id: invalidation.contract_id.clone(),
                evidence_refs: invalidation.evidence_refs.clone(),
                observed_fingerprints: observed.into_iter().collect(),
            });
        }
        let classification =
            FailureClassifier::classify_verified(&plan_document, task_id, &verified_invalidations)?;
        if classification.kind != FailureClassificationKind::PlanFailure {
            return Err(ControllerError::InvalidPlan(
                "execution failure cannot enter the plan-revision path".to_owned(),
            ));
        }

        let (task_contract_digest, attempt_json, task_json, failure) = {
            let active = self.active_mut()?;
            let attempt = active.attempts.get_mut(attempt_id).ok_or_else(|| {
                ControllerError::NotReady(format!("unknown attempt {attempt_id}"))
            })?;
            if attempt.task_id != task_id
                || !legal_attempt_transition(attempt.state, AttemptState::Failed)
            {
                return Err(ControllerError::NotReady(
                    "plan failure must bind the current executing/verifying attempt".to_owned(),
                ));
            }
            attempt.state = AttemptState::Failed;
            let task = active
                .tasks
                .get_mut(task_id)
                .ok_or_else(|| ControllerError::NotReady(format!("unknown task {task_id}")))?;
            if !matches!(task.state, TaskState::Running | TaskState::Verifying) {
                return Err(ControllerError::NotReady(
                    "plan failure task is not running/verifying".to_owned(),
                ));
            }
            task.state = TaskState::RepairPending;
            task.resource_deferred_from = None;
            active.validity = PlanValidity::Invalidated;
            let task_contract_digest = task.task_contract_digest.clone();
            let diagnostic = format!(
                "verified stable Plan IR contracts invalidated: {}",
                classification.affected_contract_ids.join(",")
            );
            let signature = normalized_failure_signature(
                "plan_failure",
                "stable_contract_invalidated",
                &diagnostic,
                &BTreeMap::new(),
            );
            let failure = FailureRecordV1 {
                schema_version: FAILURE_RECORD_SCHEMA_VERSION,
                plan_id: plan_id.clone(),
                plan_revision,
                plan_digest: plan_digest.clone(),
                task_id: task_id.to_owned(),
                task_contract_digest: task_contract_digest.clone(),
                attempt_id: attempt_id.to_owned(),
                action_id: None,
                result_digest: None,
                exit_code: None,
                failure_code: "stable_contract_invalidated".to_owned(),
                signature,
                category: "plan_failure".to_owned(),
                synopsis: diagnostic,
                failed_action_facts: BTreeMap::new(),
                evidence_refs: classification.evidence_refs.clone(),
                affected_contract_ids: classification.affected_contract_ids.clone(),
                confidence_milli: 1_000,
                decision: "replan_smallest_scope".to_owned(),
            };
            (
                task_contract_digest,
                serde_json::to_string(attempt)?,
                serde_json::to_string(task)?,
                failure,
            )
        };
        let epoch = self.state.advance_execution_epoch()?;
        let failure_json = serde_json::to_string(&failure)?;
        let failure_digest = sha256_prefixed(failure_json.as_bytes());
        let failure_key =
            revision_scoped_key(&plan_id, plan_revision, &format!("{task_id}:{attempt_id}"));
        let (plan_json, snapshot_digest_value, baseline_diff_digest) = {
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
                snapshot_digest(&active.baseline)?,
                active.baseline_diff_digest.clone(),
            )
        };
        let mut records = vec![
            (
                "controller.attempt".to_owned(),
                attempt_id.to_owned(),
                attempt_json,
            ),
            ("controller.task".to_owned(), task_id.to_owned(), task_json),
            (
                "controller.failure_record".to_owned(),
                failure_key.clone(),
                failure_json,
            ),
            ("controller.plan".to_owned(), "active".to_owned(), plan_json),
        ];
        records.extend(evidence_records);
        self.persist_runtime_records_with_events(
            &records,
            &[
                (
                    "attempt_failed".to_owned(),
                    attempt_id.to_owned(),
                    json!({"state": AttemptState::Failed}),
                ),
                (
                    "failure_recorded".to_owned(),
                    attempt_id.to_owned(),
                    json!({
                        "task_id": task_id,
                        "category": "plan_failure",
                        "decision": "replan_smallest_scope",
                        "record_key": failure_key,
                        "failure_record_digest": failure_digest,
                        "affected_contract_ids": classification.affected_contract_ids,
                        "evidence_refs": classification.evidence_refs,
                    }),
                ),
                (
                    "plan_failure_invalidated".to_owned(),
                    repository_id,
                    json!({
                        "task_id": task_id,
                        "task_contract_digest": task_contract_digest,
                        "execution_epoch": epoch,
                        "repository_snapshot_digest": snapshot_digest_value,
                        "baseline_diff_digest": baseline_diff_digest,
                        "plan_validity": PlanValidity::Invalidated,
                    }),
                ),
            ],
        )?;
        self.checkpoint_now()?;
        Ok(classification)
    }

    /// Returns the exact trusted N -> N+1 compiler input derived from the current
    /// invalidated revision and a Controller classification.
    /// Builds the exact trusted N -> N+1 compiler input for a durable plan failure.
    ///
    /// # Errors
    /// Returns a fail-closed Controller error unless the active revision is invalidated
    /// and the classification exactly matches durable Controller plan-failure authority.
    pub fn replan_input(
        &self,
        classification: &FailureClassification,
    ) -> Result<PlanReplanInput, ControllerError> {
        if classification.kind != FailureClassificationKind::PlanFailure {
            return Err(ControllerError::InvalidPlan(
                "execution failure has no replan input".to_owned(),
            ));
        }
        let active = self.active_ref()?;
        if active.validity != PlanValidity::Invalidated {
            return Err(ControllerError::NotReady(
                "active revision is not invalidated".to_owned(),
            ));
        }
        Ok(PlanReplanInput {
            previous_plan: active.plan_document.clone(),
            previous_plan_digest: active.plan_digest.clone(),
            scope: classification.scope.ok_or_else(|| {
                ControllerError::InvalidPlan("plan failure classification lacks scope".to_owned())
            })?,
            invalidated_contract_ids: classification.affected_contract_ids.clone(),
            affected_task_ids: classification.affected_task_ids.clone(),
        })
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
    #[allow(clippy::too_many_lines)]
    pub fn record_exact_evidence_satisfaction(
        &mut self,
        registry: &ProjectRegistry,
        task_id: &str,
        requirement_id: &str,
        context: &ContextPacket,
        selected_evidence_ids: &[String],
    ) -> Result<String, ControllerError> {
        self.require_current_baseline(registry)?;
        self.ensure_task_worktree(registry, task_id)?;
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
            self.validate_task_exact_context_evidence(registry, task_id, &repository_id, item)?;
            self.validate_task_requirement_bound_evidence(
                registry,
                task_id,
                &repository_id,
                item,
                &probe,
            )?;
        }
        if satisfaction == "exactly_one" {
            let ExactRequirementProbe::Path { path, .. } = &probe;
            self.task_execution_read(registry, task_id, Path::new(path), None)?;
        }
        let snapshot = self.task_execution_snapshot(registry, task_id)?;
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
                let key = revision_scoped_key(
                    &plan_id,
                    plan_revision,
                    &evidence_item_key(task_id, requirement_id, &item.evidence_id),
                );
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
            plan_id: plan_id.clone(),
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
            &revision_scoped_key(
                &plan_id,
                plan_revision,
                &evidence_satisfaction_key(task_id, requirement_id),
            ),
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
                        resource_deferrals_used: 0,
                        resource_retry_exhausted: false,
                        resource_deferred_from: None,
                        worktree_lease: None,
                        worktree_state: None,
                        change_set: None,
                        change_set_artifact_digest: None,
                        change_set_carry: None,
                        worktree_baseline: None,
                        worktree_composition: Vec::new(),
                        worktree_conflict: None,
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
        let compilation_evidence_json = serde_json::to_string(compilation.compilation_evidence())?;
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
        self.persist_default_task_capability_grants()?;
        let revision_key = revision_record_key(&plan_id, revision);
        self.state.put_state(
            "controller.compilation_evidence",
            &revision_key,
            &compilation_evidence_json,
        )?;
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

    /// Atomically supersedes invalidated revision N with validated immutable N+1.
    /// Historical runtime/evidence rows remain untouched under their revision keys.
    ///
    /// # Errors
    /// Returns a fail-closed Controller error when compiler authority, direct lineage,
    /// scope/budget/carry proofs, repository baseline, or durable failure authority do
    /// not match the active invalidated revision.
    #[allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
    pub fn activate_superseding_revision(
        &mut self,
        compilation: PlanCompilationResult,
        classification: &FailureClassification,
        registry: &ProjectRegistry,
    ) -> Result<(ActivationSummary, PlanRevisionDiff), ControllerError> {
        if classification.kind != FailureClassificationKind::PlanFailure {
            return Err(ControllerError::InvalidPlan(
                "only a verified plan failure may supersede the active revision".to_owned(),
            ));
        }
        let durable_classification = self.durable_plan_failure_classification()?;
        if durable_classification != *classification {
            return Err(ControllerError::InvalidPlan(
                "superseding classification does not match durable Controller plan-failure authority"
                    .to_owned(),
            ));
        }
        if self.any_unknown_action()? || has_unresolved_process_lease(&self.state)? {
            return Err(ControllerError::NotReady(
                "unknown action or active process lease must be reconciled before replanning"
                    .to_owned(),
            ));
        }
        if compilation.plan().canonical_digest()? != compilation.plan_digest()
            || !compilation.compilation_evidence().validator_passed()
            || compilation.compilation_evidence().plan_digest() != compilation.plan_digest()
        {
            return Err(ControllerError::InvalidPlan(
                "superseding compiler result lacks exact validator/digest authority".to_owned(),
            ));
        }
        let next_plan = compilation.plan().as_value().clone();
        let next_plan_digest = compilation.plan_digest().to_owned();
        let next_compilation_evidence_digest = compilation.compilation_evidence_digest().to_owned();
        let next_compilation_evidence = serde_json::to_value(compilation.compilation_evidence())?;
        let scope = classification.scope.ok_or_else(|| {
            ControllerError::InvalidPlan("plan failure classification lacks scope".to_owned())
        })?;

        let (
            previous_plan,
            previous_plan_id,
            previous_revision,
            previous_plan_digest,
            goal_id,
            repository_id,
            repository_root,
        ) = {
            let active = self.active_ref()?;
            if active.validity != PlanValidity::Invalidated {
                return Err(ControllerError::NotReady(
                    "superseding activation requires invalidated active revision N".to_owned(),
                ));
            }
            (
                active.plan_document.clone(),
                active.plan_id.clone(),
                active.revision,
                active.plan_digest.clone(),
                active.goal_id.clone(),
                active.repository_id.clone(),
                active.repository_root.clone(),
            )
        };
        if required_str(&next_plan, "/plan_id")? != previous_plan_id
            || required_u32(&next_plan, "/revision")? != previous_revision.saturating_add(1)
            || next_plan.get("supersedes_revision").and_then(Value::as_u64)
                != Some(u64::from(previous_revision))
        {
            return Err(ControllerError::InvalidPlan(
                "superseding plan must be immutable N+1 directly over active N".to_owned(),
            ));
        }
        let repositories = required_array(&next_plan, "/repositories")?;
        if repositories.len() != 1
            || required_str(&repositories[0], "/repository_id")? != repository_id
        {
            return Err(ControllerError::InvalidPlan(
                "cross-repository execution remains fail-closed until M8".to_owned(),
            ));
        }
        let registered = registry.repository(&repository_id).ok_or_else(|| {
            ControllerError::InvalidPlan(format!("repository {repository_id} is not registered"))
        })?;
        if registered.root != repository_root {
            return Err(ControllerError::InvalidPlan(
                "registered repository root changed across plan revision".to_owned(),
            ));
        }
        let current_snapshot = registry.snapshot(&repository_id)?;
        if current_snapshot.head.as_deref() != optional_str(&repositories[0], "/baseline/head")
            || current_snapshot.branch.as_deref()
                != optional_str(&repositories[0], "/baseline/branch")
            || current_snapshot.dirty_digest
                != required_str(&repositories[0], "/baseline/dirty_digest")?
        {
            return Err(ControllerError::NotReady(
                "superseding compiler repository baseline is stale".to_owned(),
            ));
        }
        let current_diff = ExactRetriever::new(registry).current_diff(&repository_id)?;
        let current_snapshot_digest = snapshot_digest(&current_snapshot)?;
        let diff = PlanRevisionDiff::between(
            &previous_plan,
            &next_plan,
            scope,
            &classification.affected_contract_ids,
            &classification.affected_task_ids,
        )
        .map_err(ControllerError::InvalidPlan)?;

        let max_replans = next_plan
            .pointer("/policy/retry/max_replans_per_scope")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| {
                ControllerError::InvalidPlan("missing max_replans_per_scope".to_owned())
            })?;
        let lineage_id = scope_lineage_id(&self.state, self.active_ref()?, classification)?;
        let scope_counter_key = lineage_id.clone();
        let used_replans = self
            .state
            .get_state("controller.replan_scope_counter", &scope_counter_key)?
            .map(|raw| serde_json::from_str::<Value>(&raw))
            .transpose()?
            .and_then(|value| value.get("count").and_then(Value::as_u64))
            .and_then(|value| u32::try_from(value).ok())
            .unwrap_or(0);
        if used_replans >= max_replans {
            return Err(ControllerError::NotReady(format!(
                "replan scope budget exhausted: used={used_replans}, limit={max_replans}"
            )));
        }

        self.close_active_worktrees_for_supersession(registry)?;

        let previous_active = ActivePlan {
            plan_document: previous_plan.clone(),
            compiler_plan_digest: previous_plan_digest.clone(),
            plan_id: previous_plan_id.clone(),
            goal_id: goal_id.clone(),
            revision: previous_revision,
            plan_digest: previous_plan_digest.clone(),
            compilation_evidence_digest: self.active_ref()?.compilation_evidence_digest.clone(),
            policy_digest: self.active_ref()?.policy_digest.clone(),
            repository_id: repository_id.clone(),
            repository_root: repository_root.clone(),
            baseline: self.active_ref()?.baseline.clone(),
            baseline_diff_digest: self.active_ref()?.baseline_diff_digest.clone(),
            baseline_diff_content: self.active_ref()?.baseline_diff_content.clone(),
            validity: PlanValidity::Invalidated,
            tasks: self.active_ref()?.tasks.clone(),
            attempts: self.active_ref()?.attempts.clone(),
        };
        let runtime_build = build_superseding_runtime(
            &self.state,
            registry,
            &previous_active,
            &next_plan,
            &next_plan_digest,
            &next_compilation_evidence,
            &diff,
            &current_snapshot_digest,
        )?;
        let policy_digest = digest_json(
            next_plan
                .get("policy")
                .ok_or_else(|| ControllerError::InvalidPlan("plan policy missing".to_owned()))?,
        )?;
        let next_revision = diff.to_revision;
        let next_active = ActivePlan {
            plan_document: next_plan.clone(),
            compiler_plan_digest: next_plan_digest.clone(),
            plan_id: previous_plan_id.clone(),
            goal_id,
            revision: next_revision,
            plan_digest: next_plan_digest.clone(),
            compilation_evidence_digest: next_compilation_evidence_digest.clone(),
            policy_digest,
            repository_id: repository_id.clone(),
            repository_root,
            baseline: current_snapshot.clone(),
            baseline_diff_digest: current_diff.digest.clone(),
            baseline_diff_content: current_diff.content.clone(),
            validity: PlanValidity::Current,
            tasks: runtime_build.tasks,
            attempts: BTreeMap::new(),
        };

        let revision_key = revision_record_key(&previous_plan_id, next_revision);
        if self
            .state
            .get_state("controller.plan_revision", &revision_key)?
            .is_some()
            || self
                .state
                .get_state("controller.plan_revision_diff", &revision_key)?
                .is_some()
        {
            return Err(ControllerError::InvalidPlan(
                "superseding revision history key already exists".to_owned(),
            ));
        }
        let epoch = self.state.advance_execution_epoch()?;
        let diff_json = serde_json::to_string(&diff)?;
        let diff_digest = sha256_prefixed(diff_json.as_bytes());
        let carry_record_digests = runtime_build
            .carry_records
            .iter()
            .map(|(namespace, key, value_json)| {
                (
                    format!("{namespace}:{key}"),
                    sha256_prefixed(value_json.as_bytes()),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let carry_proof_digest = digest_json(&serde_json::to_value(&carry_record_digests)?)?;
        let task_runtime_values = next_active
            .tasks
            .iter()
            .map(|(task_id, runtime)| Ok((task_id.clone(), serde_json::to_value(runtime)?)))
            .collect::<Result<BTreeMap<_, _>, serde_json::Error>>()?;
        let task_runtime_map_digest = digest_json(&serde_json::to_value(&task_runtime_values)?)?;
        let attempt_runtime_map_digest = digest_json(&json!({}))?;
        let plan_record_json = serde_json::to_string(&json!({
            "plan_id": next_active.plan_id,
            "goal_id": next_active.goal_id,
            "revision": next_active.revision,
            "plan_digest": next_active.plan_digest,
            "compilation_evidence_digest": next_active.compilation_evidence_digest,
            "validity": next_active.validity,
        }))?;
        let baseline_json = serde_json::to_string(&PersistedRepositoryBaseline {
            snapshot: current_snapshot,
            diff_digest: current_diff.digest.clone(),
            diff_content: current_diff.content,
        })?;
        let revision_record_json = serde_json::to_string(&json!({
            "plan_id": previous_plan_id,
            "revision": next_revision,
            "plan_digest": next_plan_digest,
            "compilation_evidence_digest": next_compilation_evidence_digest,
            "previous_plan_digest": previous_plan_digest,
            "plan_document": next_plan,
        }))?;
        let scope_counter_json = serde_json::to_string(&json!({
            "plan_id": diff.plan_id,
            "lineage_id": lineage_id,
            "scope": diff.scope,
            "affected_task_ids": diff.affected_task_ids,
            "count": used_replans.saturating_add(1),
        }))?;
        let mut records = vec![
            (
                "controller.plan".to_owned(),
                "active".to_owned(),
                plan_record_json,
            ),
            (
                "controller.plan_document".to_owned(),
                "active".to_owned(),
                serde_json::to_string(&next_active.plan_document)?,
            ),
            (
                "controller.repository_baseline".to_owned(),
                "active".to_owned(),
                baseline_json,
            ),
            (
                "controller.plan_revision".to_owned(),
                revision_key.clone(),
                revision_record_json,
            ),
            (
                "controller.plan_revision_diff".to_owned(),
                revision_key.clone(),
                diff_json,
            ),
            (
                "controller.compilation_evidence".to_owned(),
                revision_key.clone(),
                serde_json::to_string(&next_compilation_evidence)?,
            ),
            (
                "controller.plan_revision_lifecycle".to_owned(),
                revision_record_key(&previous_plan_id, previous_revision),
                serde_json::to_string(&json!({
                    "plan_id": previous_plan_id,
                    "revision": previous_revision,
                    "plan_digest": previous_plan_digest,
                    "status": "superseded",
                    "superseded_by_revision": next_revision,
                    "superseded_by_digest": next_plan_digest,
                }))?,
            ),
            (
                "controller.plan_revision_lifecycle".to_owned(),
                revision_key.clone(),
                serde_json::to_string(&json!({
                    "plan_id": previous_plan_id,
                    "revision": next_revision,
                    "plan_digest": next_plan_digest,
                    "status": "active",
                    "superseded_by_revision": Value::Null,
                    "superseded_by_digest": Value::Null,
                }))?,
            ),
            (
                "controller.replan_scope_counter".to_owned(),
                scope_counter_key,
                scope_counter_json,
            ),
        ];
        let mut task_capability_grant_values = BTreeMap::new();
        for (task_id, runtime) in &next_active.tasks {
            records.push((
                "controller.task".to_owned(),
                revision_scoped_key(&previous_plan_id, next_revision, task_id),
                serde_json::to_string(runtime)?,
            ));
            let grant = TaskCapabilityGrant {
                plan_id: previous_plan_id.clone(),
                plan_revision: next_revision,
                task_id: task_id.clone(),
                task_contract_digest: runtime.task_contract_digest.clone(),
                policy_digest: next_active.policy_digest.clone(),
                issued_by: self.permission_context.persisted_grant_issuer.clone(),
                capabilities: self.permission_context.persisted_grant_capabilities(),
            };
            grant.validate()?;
            let persisted_grant = PersistedTaskCapabilityGrantV1::from_grant(&grant);
            task_capability_grant_values
                .insert(task_id.clone(), serde_json::to_value(&persisted_grant)?);
            records.push((
                TASK_CAPABILITY_GRANT_NAMESPACE.to_owned(),
                revision_scoped_key(&previous_plan_id, next_revision, task_id),
                serde_json::to_string(&persisted_grant)?,
            ));
        }
        let task_capability_grant_map_digest =
            digest_json(&serde_json::to_value(&task_capability_grant_values)?)?;
        records.extend(lineage_records_for_supersession(
            &self.state,
            &previous_active,
            &diff,
            &lineage_id,
        )?);
        records.extend(runtime_build.carry_records);
        let activation_payload = json!({
            "from_revision": previous_revision,
            "to_revision": next_revision,
            "from_plan_digest": previous_active.plan_digest,
            "to_plan_digest": next_active.plan_digest,
            "plan_revision_diff_digest": diff_digest,
            "carry_proof_digest": carry_proof_digest,
            "task_runtime_map_digest": task_runtime_map_digest,
            "attempt_runtime_map_digest": attempt_runtime_map_digest,
            "task_capability_grant_map_digest": task_capability_grant_map_digest,
            "execution_epoch": epoch,
            "repository_snapshot_digest": current_snapshot_digest,
            "baseline_diff_digest": next_active.baseline_diff_digest,
            "plan_validity": PlanValidity::Current,
        });
        let activation_json = serde_json::to_string(&activation_payload)?;
        let event_seed = sha256_prefixed(
            format!(
                "plan_revision_activated\0{}\0{}\0{}",
                previous_plan_id,
                self.state.latest_journal_sequence()?,
                activation_json
            )
            .as_bytes(),
        );
        let updates = records
            .iter()
            .map(|(namespace, key, value_json)| StateRecordUpdate {
                namespace,
                key,
                value_json,
            })
            .collect::<Vec<_>>();
        self.state.put_state_records_with_events(
            &updates,
            &[NewJournalEvent {
                event_id: &format!("controller.{}", &event_seed[7..27]),
                entity_type: "controller",
                entity_id: &previous_plan_id,
                event_kind: "plan_revision_activated",
                payload_json: &activation_json,
            }],
        )?;
        recovery_test_hook("after_plan_revision_activation_commit");
        self.active = Some(next_active);
        self.checkpoint_now()?;
        let task_ids = self.active_ref()?.tasks.keys().cloned().collect::<Vec<_>>();
        Ok((
            ActivationSummary {
                plan_id: previous_plan_id,
                plan_digest: next_plan_digest,
                revision: next_revision,
                execution_epoch: epoch,
                task_ids,
            },
            diff,
        ))
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
        tool_manifest: &ToolManifest,
    ) -> Result<ReadyLease, ControllerError> {
        self.require_execution_not_paused()?;
        self.require_current_baseline(registry)?;
        self.ensure_task_worktree(registry, task_id)?;
        if self.task_state(task_id) == Some(TaskState::DeferredResource) {
            self.restore_resource_deferred_task(task_id, TaskState::Planned)?;
        }
        self.derive_ready_lease_for_state(
            registry,
            task_id,
            inputs,
            TaskState::Planned,
            tool_manifest,
        )
    }

    fn derive_ready_lease_for_state(
        &mut self,
        registry: &ProjectRegistry,
        task_id: &str,
        inputs: ReadinessInputs<'_>,
        eligible_state: TaskState,
        tool_manifest: &ToolManifest,
    ) -> Result<ReadyLease, ControllerError> {
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
        self.check_task_readiness(task_id, &task_value, inputs, eligible_state)?;
        let (checkpoint_generation, checkpoint_action_sequence, checkpoint_hash) =
            self.current_checkpoint_binding()?;
        let baseline_digest = snapshot_digest(&self.task_execution_snapshot(registry, task_id)?)?;
        let evidence_binding_digest =
            self.resolve_readiness_evidence_digest(registry, task_id, &task_value)?;
        let permission_decision = self.permission_decision_for_task(task_id, tool_manifest)?;
        if !permission_decision
            .effective
            .contains(PermissionClass::RepositoryWrite)
            || !permission_decision
                .effective
                .contains(PermissionClass::ProcessExec)
        {
            return Err(ControllerError::NotReady(
                "effective permission intersection denies repository mutation/process execution"
                    .to_owned(),
            ));
        }
        let resource_lease = match self.resource_governor.acquire(
            format!("ready:{plan_id}:{task_id}:{epoch}"),
            HeavyLeaseClass::Model,
            inputs.host_pressure,
        ) {
            Ok(lease) => lease,
            Err(error @ PolicyError::ResourceDenied(_)) => {
                self.record_pre_attempt_resource_deferral(task_id, eligible_state)?;
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
            permission_decision,
            resource_digest,
            execution_epoch: epoch,
            resource_lease,
            lease_digest: String::new(),
        };
        lease.lease_digest = ready_lease_digest(&lease);
        Ok(lease)
    }

    fn derive_repair_lease(
        &mut self,
        registry: &ProjectRegistry,
        task_id: &str,
        inputs: ReadinessInputs<'_>,
        tool_manifest: &ToolManifest,
    ) -> Result<ReadyLease, ControllerError> {
        self.require_execution_not_paused()?;
        self.require_current_baseline(registry)?;
        self.ensure_task_worktree(registry, task_id)?;
        let (state, retry_exhausted, resource_retry_exhausted) = self
            .active_ref()?
            .tasks
            .get(task_id)
            .map(|task| {
                (
                    task.state,
                    task.retry_exhausted,
                    task.resource_retry_exhausted,
                )
            })
            .ok_or_else(|| ControllerError::NotReady(format!("unknown task {task_id}")))?;
        if retry_exhausted || resource_retry_exhausted {
            return Err(ControllerError::NotReady(
                "repair retry policy is exhausted".to_owned(),
            ));
        }
        match state {
            TaskState::RepairPending => {}
            TaskState::DeferredResource => {
                self.restore_resource_deferred_task(task_id, TaskState::RepairPending)?;
            }
            _ => {
                return Err(ControllerError::NotReady(format!(
                    "task state {state:?} is not eligible for repair"
                )));
            }
        }
        self.derive_ready_lease_for_state(
            registry,
            task_id,
            inputs,
            TaskState::RepairPending,
            tool_manifest,
        )
    }

    fn restore_resource_deferred_task(
        &mut self,
        task_id: &str,
        expected_from: TaskState,
    ) -> Result<(), ControllerError> {
        {
            let task = self
                .active_mut()?
                .tasks
                .get_mut(task_id)
                .ok_or_else(|| ControllerError::NotReady(format!("unknown task {task_id}")))?;
            if task.state != TaskState::DeferredResource
                || task.resource_deferred_from != Some(expected_from)
                || task.resource_retry_exhausted
            {
                return Err(ControllerError::NotReady(
                    "resource-deferred task cannot re-enter this execution path".to_owned(),
                ));
            }
            task.state = expected_from;
            task.resource_deferred_from = None;
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
                (if expected_from == TaskState::RepairPending {
                    "task_repair_resource_recheck"
                } else {
                    "task_resource_recheck"
                })
                .to_owned(),
                task_id.to_owned(),
                json!({"state": expected_from}),
            )],
        )?;
        self.checkpoint_now()?;
        Ok(())
    }

    fn record_pre_attempt_resource_deferral(
        &mut self,
        task_id: &str,
        expected_from: TaskState,
    ) -> Result<(), ControllerError> {
        let (used, limit, exhausted) = {
            let task = self
                .active_mut()?
                .tasks
                .get_mut(task_id)
                .ok_or_else(|| ControllerError::NotReady(format!("unknown task {task_id}")))?;
            if task.state != expected_from {
                return Err(ControllerError::InvalidPlan(
                    "resource deferral source state changed unexpectedly".to_owned(),
                ));
            }
            let limit = required_u32(&task.task, "/failure_policy/resource_retry_limit")?;
            task.resource_deferrals_used = task.resource_deferrals_used.saturating_add(1);
            task.resource_retry_exhausted = task.resource_deferrals_used > limit;
            task.resource_deferred_from = Some(expected_from);
            task.state = TaskState::DeferredResource;
            (
                task.resource_deferrals_used,
                limit,
                task.resource_retry_exhausted,
            )
        };
        let task_json = serde_json::to_string(
            self.active_ref()?
                .tasks
                .get(task_id)
                .ok_or_else(|| ControllerError::InvalidPlan("task disappeared".to_owned()))?,
        )?;
        self.persist_runtime_records_with_events(
            &[("controller.task".to_owned(), task_id.to_owned(), task_json)],
            &[(
                "task_deferred_resource".to_owned(),
                task_id.to_owned(),
                json!({
                    "state": TaskState::DeferredResource,
                    "deferred_from": expected_from,
                    "resource_deferrals_used": used,
                    "resource_retry_limit": limit,
                    "retry_allowed": !exhausted,
                }),
            )],
        )?;
        self.checkpoint_now()?;
        Ok(())
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
        let result = self.execute_replace_inner(&mut lease, runtime, context, model_budget, None);
        let release = self.resource_governor.release(&lease.resource_lease);
        match (result, release) {
            (Ok(success), Ok(())) => Ok(success),
            (Ok(_), Err(error)) => Err(ControllerError::Policy(error)),
            (Err(error), _) => Err(error),
        }
    }

    /// Executes one bounded targeted repair attempt against the same active task contract.
    /// The repair packet is rebuilt from current diff/failure evidence and the existing bounded
    /// context; no `PlanCompiler` call or plan/task-contract mutation occurs.
    ///
    /// # Errors
    /// Returns a fail-closed readiness/policy/error result when retry counters, failure evidence,
    /// resources, task contract, or current repository truth do not permit another attempt.
    #[allow(clippy::too_many_lines)]
    pub fn repair_replace<I: sovereign_policy::ExecutionIsolationBackend>(
        &mut self,
        task_id: &str,
        runtime: &ExecutionRuntime<'_, I>,
        base_context: &ContextPacket,
        tool_schemas: &[ToolSchemaV1],
        readiness: ReadinessInputs<'_>,
        model_budget: &mut ModelCallBudget,
    ) -> Result<(ExecutionSuccess, RepairPacket), ControllerError> {
        let (failure, failure_record_digest) = self
            .latest_failure_record_with_digest(task_id)?
            .ok_or_else(|| {
                ControllerError::NotReady("durable FailureRecord v1 is missing".to_owned())
            })?;
        let (
            plan_id,
            plan_revision,
            plan_digest,
            task_contract_digest,
            acceptance_contract_digest,
            task_json,
            attempts_started,
            same_failure_count,
        ) = {
            let active = self.active_ref()?;
            let task = active
                .tasks
                .get(task_id)
                .ok_or_else(|| ControllerError::NotReady(format!("unknown task {task_id}")))?;
            let repair_state_ok = task.state == TaskState::RepairPending
                || (task.state == TaskState::DeferredResource
                    && task.resource_deferred_from == Some(TaskState::RepairPending));
            if !repair_state_ok || task.retry_exhausted || task.resource_retry_exhausted {
                return Err(ControllerError::NotReady(
                    "task is not eligible for targeted repair".to_owned(),
                ));
            }
            if failure.schema_version != FAILURE_RECORD_SCHEMA_VERSION
                || failure.decision != "repair"
                || failure.plan_id != active.plan_id
                || failure.plan_revision != active.revision
                || failure.plan_digest != active.plan_digest
                || failure.task_id != task_id
                || failure.task_contract_digest != task.task_contract_digest
            {
                return Err(ControllerError::NotReady(
                    "durable FailureRecord v1 is not bound to the current plan/task contract"
                        .to_owned(),
                ));
            }
            let prior_attempt = active.attempts.get(&failure.attempt_id).ok_or_else(|| {
                ControllerError::NotReady("repair failure origin attempt is missing".to_owned())
            })?;
            if prior_attempt.task_id != task_id
                || prior_attempt.state != AttemptState::Failed
                || prior_attempt.task_contract_digest != task.task_contract_digest
            {
                return Err(ControllerError::NotReady(
                    "repair failure origin attempt is not the exact failed task attempt".to_owned(),
                ));
            }
            let count = task
                .failure_counts
                .get(&failure.signature)
                .copied()
                .unwrap_or(0);
            let max_attempts = required_u32(&task.task, "/failure_policy/max_attempts")?;
            let same_limit = required_u32(&task.task, "/failure_policy/same_failure_limit")?;
            if count == 0 || !repair_allowed(task.attempts_started, max_attempts, count, same_limit)
            {
                return Err(ControllerError::NotReady(
                    "repair retry policy is exhausted or unbound".to_owned(),
                ));
            }
            let (_, acceptance_digest) = compiled_acceptance_contract(&task.task)?;
            let contract_projection = repair_task_contract_projection(
                task_id,
                &task.task_contract_digest,
                &acceptance_digest,
                &task.task,
            )?;
            (
                active.plan_id.clone(),
                active.revision,
                active.plan_digest.clone(),
                task.task_contract_digest.clone(),
                acceptance_digest,
                contract_projection,
                task.attempts_started,
                count,
            )
        };

        let current_diff = self.task_execution_diff(runtime.registry, task_id)?;
        // Never trust ToolSchema evidence carried by a caller-supplied ContextPacket. Repair
        // re-derives the lane from typed schemas against the exact runtime manifest and current
        // Controller permission decision, so generic EvidenceItem text cannot launder itself
        // into model-visible tool authority.
        let authorized_tool_schemas = self.authorized_tool_schema_evidence(
            task_id,
            tool_schemas,
            std::slice::from_ref(runtime.tool_manifest),
        )?;
        let mut candidates = base_context
            .items
            .iter()
            .filter(|item| {
                item.kind != EvidenceKind::ToolSchema
                    && matches!(
                        item.section,
                        PacketSection::DirectEvidence
                            | PacketSection::RoutedExpansion
                            | PacketSection::ToolEvidence
                    )
            })
            .cloned()
            .collect::<Vec<_>>();
        let implicated_path = failure
            .action_id
            .as_deref()
            .and_then(|action_id| {
                self.state
                    .get_state("controller.action_intent", action_id)
                    .ok()
                    .flatten()
            })
            .and_then(|raw| serde_json::from_str::<PersistedActionIntent>(&raw).ok())
            .map(|intent| format!("path:{}", intent.path));
        for item in &mut candidates {
            if failure.evidence_refs.contains(&item.evidence_id)
                || implicated_path
                    .as_deref()
                    .is_some_and(|path| item.locator.as_deref() == Some(path))
            {
                item.implicated = true;
            }
        }
        candidates.push(EvidenceItem::from_diff(
            &current_diff,
            "current diff for targeted repair",
        ));
        candidates.push(
            EvidenceItem::new(
                format!("failure:{}:{}", task_id, failure.attempt_id),
                PacketSection::ToolEvidence,
                ContextLevel::C1,
                EvidenceKind::FailureSynopsis,
                format!("controller://failure/{}/{}", task_id, failure.attempt_id),
                failure_record_digest.clone(),
                "controller_failure_record_v1",
                TrustClass::Controller,
                "exact prior failure for targeted repair",
                serde_json::to_string(&json!({
                    "attempt_id": failure.attempt_id,
                    "category": failure.category,
                    "failure_code": failure.failure_code,
                    "failure_signature": failure.signature,
                    "synopsis": failure.synopsis,
                    "failed_action_facts": failure.failed_action_facts,
                    "evidence_refs": failure.evidence_refs,
                }))?,
            )
            .with_implicated(true),
        );
        let repair_controller_prefix = failure
            .failed_action_facts
            .get("path")
            .and_then(|path| {
                let locator = format!("path:{path}");
                base_context
                    .items
                    .iter()
                    .find(|item| item.locator.as_deref() == Some(locator.as_str()))
                    .map(|item| {
                        format!(
                            "Repair only the still-valid task using current failure/diff evidence. Controller authority and acceptance are unchanged. The prior failed_action_facts are rejected-attempt diagnostics, not repair instructions. For failed path {path}, current exact evidence {} has source_digest {}; use that exact current digest for expected_source_digest and derive old/new literals only from the immutable task/goal contract.",
                            item.evidence_id, item.source_digest
                        )
                    })
            })
            .unwrap_or_else(|| {
                "Repair only the still-valid task using current failure/diff evidence. Controller authority and acceptance are unchanged. The prior failed_action_facts are rejected-attempt diagnostics, not repair instructions; derive repair action fields from current exact evidence and the immutable task/goal contract."
                    .to_owned()
            });
        let repair_packet = ContextPlanner::default()
            .build_repair(
                base_context.budget,
                RepairPacketInput {
                    plan_id: plan_id.clone(),
                    plan_revision,
                    plan_digest: plan_digest.clone(),
                    task_id: task_id.to_owned(),
                    task_contract_digest: task_contract_digest.clone(),
                    acceptance_contract_digest: acceptance_contract_digest.clone(),
                    prior_attempt_id: failure.attempt_id.clone(),
                    failure_signature: failure.signature.clone(),
                    failure_record_digest: failure_record_digest.clone(),
                    failure_evidence_refs: failure.evidence_refs.clone(),
                    controller_prefix: repair_controller_prefix,
                    task_contract: task_json,
                    current_state: format!(
                        "plan={plan_id}; task={task_id}; attempts_started={attempts_started}; same_failure_count={same_failure_count}; repair_pending=true"
                    ),
                    authorized_tool_schemas,
                    candidates,
                    output_schema: "Strict ModelProposalV1 JSON: schema_version=1, evidence_ids, and exactly one replace_literal action with repository_id, path, expected_source_digest, old_literal, new_literal, expected_occurrences=1. The Controller enforces the full JSON Schema out-of-band."
                        .to_owned(),
                },
            )
            .map_err(|error| {
                ControllerError::NotReady(format!("repair context rejected: {error}"))
            })?;
        if repair_packet.plan_id != plan_id
            || repair_packet.plan_revision != plan_revision
            || repair_packet.plan_digest != plan_digest
            || repair_packet.task_contract_digest != task_contract_digest
            || repair_packet.acceptance_contract_digest != acceptance_contract_digest
            || repair_packet.failure_record_digest != failure_record_digest
        {
            return Err(ControllerError::InvalidPlan(
                "repair packet changed immutable plan/task/acceptance/failure bindings".to_owned(),
            ));
        }
        let packet_key = active_scoped_key(
            self.active_ref()?,
            &format!("{}:{}", task_id, attempts_started.saturating_add(1)),
        );
        let packet_json = serde_json::to_string(&repair_packet)?;
        let repair_packet_digest = sha256_prefixed(packet_json.as_bytes());
        self.persist_runtime_records_with_events(
            &[(
                "controller.repair_packet".to_owned(),
                packet_key.clone(),
                packet_json,
            )],
            &[(
                "repair_packet_built".to_owned(),
                task_id.to_owned(),
                json!({
                    "plan_id": plan_id,
                    "plan_revision": plan_revision,
                    "task_id": task_id,
                    "prior_attempt_id": failure.attempt_id,
                    "failure_signature": failure.signature,
                    "failure_record_digest": failure_record_digest,
                    "repair_packet_digest": repair_packet_digest,
                    "plan_digest": plan_digest,
                    "task_contract_digest": task_contract_digest,
                    "acceptance_contract_digest": acceptance_contract_digest,
                    "packet_key": packet_key,
                }),
            )],
        )?;
        self.checkpoint_now()?;

        let mut lease =
            self.derive_repair_lease(runtime.registry, task_id, readiness, runtime.tool_manifest)?;
        let repair_origin = RepairAttemptOriginV1 {
            schema_version: 1,
            prior_attempt_id: failure.attempt_id.clone(),
            failure_record_digest: repair_packet.failure_record_digest.clone(),
            repair_packet_digest,
        };
        let result = self.execute_replace_inner(
            &mut lease,
            runtime,
            &repair_packet.context,
            model_budget,
            Some(&repair_origin),
        );
        let release = self.resource_governor.release(&lease.resource_lease);
        let success = match (result, release) {
            (Ok(success), Ok(())) => success,
            (Ok(_), Err(error)) => return Err(ControllerError::Policy(error)),
            (Err(error), _) => return Err(error),
        };
        let active = self.active_ref()?;
        let task = active
            .tasks
            .get(task_id)
            .ok_or_else(|| ControllerError::InvalidPlan("repair task disappeared".to_owned()))?;
        let (_, final_acceptance_digest) = compiled_acceptance_contract(&task.task)?;
        if active.plan_id != repair_packet.plan_id
            || active.revision != repair_packet.plan_revision
            || active.plan_digest != repair_packet.plan_digest
            || task.task_contract_digest != repair_packet.task_contract_digest
            || final_acceptance_digest != repair_packet.acceptance_contract_digest
            || success.verification.acceptance_contract_digest
                != repair_packet.acceptance_contract_digest
        {
            return Err(ControllerError::InvalidPlan(
                "repair mutated the active plan/task/acceptance contract".to_owned(),
            ));
        }
        Ok((success, repair_packet))
    }

    /// Resumes a crash-interrupted, not-yet-mutated replacement from the exact durable
    /// Controller action intent without another model call. Recovery creates a new attempt
    /// under the current epoch and revalidates the repository preimage and compiled contract.
    ///
    /// # Errors
    /// Returns a fail-closed recovery/readiness error when the intent, baseline, retry budget,
    /// authority, or current repository content no longer matches.
    #[allow(clippy::too_many_lines)]
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
        let raw_intent: PersistedActionIntent = serde_json::from_str(&raw)?;
        let primary_root = runtime
            .registry
            .repository(&raw_intent.repository_id)
            .ok_or_else(|| {
                ControllerError::NotReady("recovery action repository is missing".to_owned())
            })?
            .root
            .clone();
        let intent = normalize_persisted_action_intent(raw_intent, &primary_root)?;
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
        let mut lease = self.derive_ready_lease(
            runtime.registry,
            &intent.task_id,
            readiness,
            runtime.tool_manifest,
        )?;
        let result = (|| {
            self.validate_ready_lease(&lease, runtime.registry, runtime.tool_manifest)?;
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
        repair_origin: Option<&RepairAttemptOriginV1>,
    ) -> Result<ExecutionSuccess, ControllerError> {
        self.validate_ready_lease(lease, runtime.registry, runtime.tool_manifest)?;
        let model_deadline_ms = self.task_model_deadline_ms(&lease.task_id)?;
        match self.consume_task_model_call(&lease.task_id, model_budget, model_deadline_ms) {
            Ok(()) => {}
            Err(ControllerError::Policy(error @ PolicyError::ResourceDenied(_))) => {
                let current = self.task_state(&lease.task_id).ok_or_else(|| {
                    ControllerError::InvalidPlan(
                        "task disappeared before model admission".to_owned(),
                    )
                })?;
                self.record_pre_attempt_resource_deferral(&lease.task_id, current)?;
                return Err(ControllerError::Policy(error));
            }
            Err(error) => return Err(error),
        }
        let attempt_id = self.start_attempt_with_origin(lease, runtime.registry, repair_origin)?;
        let proposal = match Self::request_model_proposal(
            runtime.backend,
            context,
            &lease.task_id,
            model_deadline_ms,
        ) {
            Ok(value) => value,
            Err(error) => {
                let failure = self.build_failure_record(FailureRecordInput {
                    task_id: lease.task_id.clone(),
                    attempt_id: attempt_id.clone(),
                    action_id: None,
                    result_digest: None,
                    exit_code: None,
                    category: "model_proposal_failure".to_owned(),
                    failure_code: controller_failure_code(&error).to_owned(),
                    diagnostic: error.to_string(),
                    failed_action_facts: BTreeMap::new(),
                    evidence_refs: context
                        .items
                        .iter()
                        .map(|item| item.evidence_id.clone())
                        .collect(),
                })?;
                let _ = self.route_failure_record(failure)?;
                return Err(error);
            }
        };
        let failed_proposal = proposal.clone();
        let validated =
            match self.validate_replace_proposal(runtime.registry, context, lease, proposal) {
                Ok(value) => value,
                Err(error) => {
                    let failure = self.build_failure_record(FailureRecordInput {
                        task_id: lease.task_id.clone(),
                        attempt_id: attempt_id.clone(),
                        action_id: None,
                        result_digest: None,
                        exit_code: None,
                        category: "proposal_validation_failure".to_owned(),
                        failure_code: controller_failure_code(&error).to_owned(),
                        diagnostic: error.to_string(),
                        failed_action_facts: proposal_action_facts(&failed_proposal),
                        evidence_refs: context
                            .items
                            .iter()
                            .map(|item| item.evidence_id.clone())
                            .collect(),
                    })?;
                    let _ = self.route_failure_record(failure)?;
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
        let execution_root = self.task_execution_root(&lease.task_id)?;
        let permission_decision =
            self.permission_decision_for_task(&lease.task_id, runtime.tool_manifest)?;
        if permission_decision != lease.permission_decision {
            return Err(ControllerError::NotReady(
                "ready lease permission decision no longer matches exact runtime authority"
                    .to_owned(),
            ));
        }
        let mut isolation_request = runtime.isolation_request.clone();
        isolation_request
            .repository_root
            .clone_from(&execution_root);
        let action = self.lower_replace_action(
            lease,
            attempt_id,
            validated,
            runtime,
            &isolation_request,
            &execution_root,
        )?;
        self.persist_action_intent(&action, validated, runtime.artifacts.root())?;
        {
            let mut journal = ActionJournal::new(&mut self.state);
            journal.authorize(&action, runtime.tool_manifest, &permission_decision)?;
        }
        self.checkpoint_now()?;
        self.rebind_ready_checkpoint(lease)?;
        self.validate_ready_lease(lease, runtime.registry, runtime.tool_manifest)?;
        let runner = ProcessRunner::new(runtime.command_policy, runtime.isolation_backend);
        let raw = {
            let mut journal = ActionJournal::new(&mut self.state);
            runner.run(&mut journal, &action, &isolation_request, runtime.artifacts)
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
                let failure = self.build_failure_record(FailureRecordInput {
                    task_id: lease.task_id.clone(),
                    attempt_id: attempt_id.to_owned(),
                    action_id: Some(action.action_id.clone()),
                    result_digest: None,
                    exit_code: None,
                    category: "tool_execution_failure".to_owned(),
                    failure_code: tool_error_code(&error).to_owned(),
                    diagnostic: error.to_string(),
                    failed_action_facts: BTreeMap::from([(
                        "action_id".to_owned(),
                        action.action_id.clone(),
                    )]),
                    evidence_refs: vec![format!("action:{}", action.action_id)],
                })?;
                let _ = self.route_failure_record(failure)?;
                return Err(ControllerError::Tool(error));
            }
        };
        self.checkpoint_now()?;
        recovery_test_hook("after_mutation_checkpoint");
        if result.exit_code != Some(0) || result.terminated_for_limit.is_some() {
            let failure = self.execution_failure(lease, attempt_id, &action, &result)?;
            let failure = self.route_failure_record(failure)?;
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
            &revision_scoped_key(
                &verification.plan_id,
                verification.plan_revision,
                &verification.verification_id,
            ),
            &serde_json::to_string(&verification)?,
        )?;
        self.append_controller_event(
            "verification_recorded",
            &verification.verification_id,
            &json!({
                "passed": verification.passed,
                "artifact_digest": artifact.digest,
                "plan_id": verification.plan_id,
                "plan_revision": verification.plan_revision,
                "plan_digest": verification.plan_digest,
                "task_id": verification.task_id,
                "task_contract_digest": verification.task_contract_digest,
                "attempt_id": verification.attempt_id,
            }),
        )?;
        self.checkpoint_now()?;
        if !verification.passed {
            let failure_code = verification
                .failure_code
                .clone()
                .unwrap_or_else(|| "unknown_verification_failure".to_owned());
            let failure = self.build_failure_record(FailureRecordInput {
                task_id: lease.task_id.clone(),
                attempt_id: attempt_id.to_owned(),
                action_id: Some(action.action_id.clone()),
                result_digest: Some(artifact.digest.clone()),
                exit_code: None,
                category: "verification_failure".to_owned(),
                diagnostic: format!("deterministic verification failed: {failure_code}"),
                failure_code,
                failed_action_facts: BTreeMap::from([(
                    "action_id".to_owned(),
                    action.action_id.clone(),
                )]),
                evidence_refs: vec![verification_evidence_id.clone()],
            })?;
            let _ = self.route_failure_record(failure)?;
            return Err(ControllerError::VerificationFailed(Box::new(verification)));
        }
        self.persist_worktree_change_set_if_required(
            runtime.registry,
            &lease.task_id,
            runtime.artifacts,
        )?;
        self.record_verified_output_bindings(&verification, &artifact.digest)?;
        self.apply_verified_success(&verification)?;
        self.finalize_verified_repository_success(runtime.registry, &lease.task_id)?;
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
        eligible_state: TaskState,
    ) -> Result<(), ControllerError> {
        let state = self
            .active_ref()?
            .tasks
            .get(task_id)
            .ok_or_else(|| ControllerError::NotReady("missing task".to_owned()))?
            .state;
        if state != eligible_state {
            return Err(ControllerError::NotReady(format!(
                "task state {state:?} is not eligible; expected {eligible_state:?}"
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

    fn permission_decision_for_task(
        &self,
        task_id: &str,
        manifest: &ToolManifest,
    ) -> Result<PermissionDecision, ControllerError> {
        manifest.validate()?;
        let active = self.active_ref()?;
        let task = active
            .tasks
            .get(task_id)
            .ok_or_else(|| ControllerError::NotReady(format!("unknown task {task_id}")))?;

        let pinned_tool = required_array(&task.task, "/tools")?
            .iter()
            .find(|tool| {
                required_str(tool, "/id").ok() == Some(manifest.tool_id.as_str())
                    && required_str(tool, "/version").ok() == Some(manifest.version.as_str())
                    && required_str(tool, "/digest").ok() == Some(manifest.content_digest.as_str())
            })
            .ok_or_else(|| {
                ControllerError::InvalidPlan(
                    "runtime tool manifest is not an exact active-task tool pin".to_owned(),
                )
            })?;
        let tool_id = required_str(pinned_tool, "/id")?;
        let tool_version = required_str(pinned_tool, "/version")?;
        let tool_digest = required_str(pinned_tool, "/digest")?;

        let role_pin = task
            .task
            .pointer("/role")
            .ok_or_else(|| ControllerError::InvalidPlan("task role pin missing".to_owned()))?;
        let role_registry = RoleRegistry::canonical();
        let role_profile = role_registry.resolve_pin(
            required_str(role_pin, "/id")?,
            required_str(role_pin, "/version")?,
            required_str(role_pin, "/digest")?,
        )?;
        let canonical_role_ceiling = role_profile.capability_ceiling();
        let role = self
            .permission_context
            .role_capabilities()
            .intersection(&canonical_role_ceiling);

        let global_requested = capability_set_from_json_array(required_array(
            &active.plan_document,
            "/policy/capability_ceiling",
        )?)?;
        let global = self
            .permission_context
            .controller_capabilities()
            .intersection(&global_requested);
        let task_requested =
            capability_set_from_json_array(required_array(&task.task, "/permissions")?)?;
        let tool = CapabilitySet::new(manifest.permission_ceiling.iter().copied());
        let grant = self.load_task_capability_grant(active, task_id, task)?;
        let persisted_user = grant.capabilities_for_scope(
            &active.plan_id,
            active.revision,
            task_id,
            &task.task_contract_digest,
            &active.policy_digest,
        )?;
        let user = self
            .permission_context
            .persisted_grant_capabilities()
            .intersection(persisted_user);

        Ok(PermissionDecision::new(
            active.plan_id.clone(),
            active.revision,
            task_id.to_owned(),
            task.task_contract_digest.clone(),
            active.policy_digest.clone(),
            tool_id.to_owned(),
            tool_version.to_owned(),
            tool_digest.to_owned(),
            CapabilityLayers {
                global,
                project: self.permission_context.project_capabilities(),
                task: task_requested,
                role,
                tool,
                user,
            },
        )?)
    }

    fn load_task_capability_grant(
        &self,
        active: &ActivePlan,
        task_id: &str,
        task: &TaskRuntime,
    ) -> Result<TaskCapabilityGrant, ControllerError> {
        let key = revision_scoped_key(&active.plan_id, active.revision, task_id);
        let raw = self
            .state
            .get_state(TASK_CAPABILITY_GRANT_NAMESPACE, &key)?
            .ok_or_else(|| {
                ControllerError::NotReady(format!(
                    "task {task_id} lacks an exact persisted capability grant"
                ))
            })?;
        let persisted: PersistedTaskCapabilityGrantV1 = serde_json::from_str(&raw)?;
        let grant = persisted.into_grant()?;
        grant.capabilities_for_scope(
            &active.plan_id,
            active.revision,
            task_id,
            &task.task_contract_digest,
            &active.policy_digest,
        )?;
        Ok(grant)
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

    fn validate_task_exact_context_evidence(
        &self,
        registry: &ProjectRegistry,
        task_id: &str,
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
                let current = self.task_execution_read(
                    registry,
                    task_id,
                    Path::new(relative),
                    Some(&item.source_digest),
                )?;
                if sha256_prefixed(item.text.as_bytes()) != item.content_digest
                    || current.digest != item.source_digest
                {
                    return Err(ControllerError::NotReady(
                        "retained exact evidence digest is not current in composed execution view"
                            .to_owned(),
                    ));
                }
            }
            EvidenceKind::Diff => {
                let current = self.task_execution_diff(registry, task_id)?;
                if current.digest != item.source_digest
                    || sha256_prefixed(item.text.as_bytes()) != item.content_digest
                {
                    return Err(ControllerError::NotReady(
                        "retained diff evidence is not current in composed execution view"
                            .to_owned(),
                    ));
                }
            }
            _ => {
                return Err(ControllerError::NotReady(
                    "execution evidence must be exact current repository evidence".to_owned(),
                ));
            }
        }
        Ok(())
    }

    fn validate_task_requirement_bound_evidence(
        &self,
        registry: &ProjectRegistry,
        task_id: &str,
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
        let current = self.task_execution_read(
            registry,
            task_id,
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

    fn resolve_readiness_evidence_digest(
        &self,
        registry: &ProjectRegistry,
        task_id: &str,
        task: &Value,
    ) -> Result<String, ControllerError> {
        let current_snapshot = self.task_execution_snapshot(registry, task_id)?;
        let current_snapshot_digest = snapshot_digest(&current_snapshot)?;
        let mut evidence_records = self.resolve_evidence_satisfaction_digests(
            registry,
            task_id,
            task,
            &current_snapshot_digest,
        )?;
        let mut dependency_records =
            self.resolve_dependency_binding_digests(task_id, task, &current_snapshot_digest)?;
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
                    &active_scoped_key(active, &evidence_satisfaction_key(task_id, requirement_id)),
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
                self.validate_task_exact_context_evidence(
                    registry,
                    task_id,
                    &active.repository_id,
                    &item,
                )?;
                self.validate_task_requirement_bound_evidence(
                    registry,
                    task_id,
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
        downstream_task_id: &str,
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
                    downstream_task_id,
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
                    downstream_task_id,
                    current_snapshot_digest,
                )?);
            }
        }
        Ok(dependency_records)
    }

    fn dependency_binding_is_stably_invalidated(
        &self,
        upstream_task_id: &str,
        downstream_task_id: &str,
    ) -> Result<bool, ControllerError> {
        let active = self.active_ref()?;
        let downstream = active.tasks.get(downstream_task_id).ok_or_else(|| {
            ControllerError::InvalidPlan(format!(
                "dependency invalidation downstream task {downstream_task_id} is missing"
            ))
        })?;
        let upstream = active.tasks.get(upstream_task_id).ok_or_else(|| {
            ControllerError::InvalidPlan(format!(
                "dependency invalidation upstream task {upstream_task_id} is missing"
            ))
        })?;
        let binding = required_array(&downstream.task, "/dependency_bindings")?
            .iter()
            .find(|binding| optional_str(binding, "/upstream_task_id") == Some(upstream_task_id))
            .ok_or_else(|| {
                ControllerError::InvalidPlan(format!(
                    "dependency binding {downstream_task_id}->{upstream_task_id} is absent"
                ))
            })?;
        for (namespace, pointer) in [
            ("controller.artifact_binding", "/required_artifact_ids"),
            (
                "controller.acceptance_binding",
                "/required_acceptance_criterion_ids",
            ),
        ] {
            for binding_id in required_array(binding, pointer)? {
                let binding_id = binding_id.as_str().ok_or_else(|| {
                    ControllerError::InvalidPlan("dependency output id must be string".to_owned())
                })?;
                let key =
                    active_scoped_key(active, &output_binding_key(upstream_task_id, binding_id));
                let Some(raw) = self.state.get_state(namespace, &key)? else {
                    return Ok(false);
                };
                let record: VerifiedOutputBindingV1 = serde_json::from_str(&raw)?;
                if record.task_contract_digest != upstream.task_contract_digest
                    || record.plan_id != active.plan_id
                    || record.plan_revision != active.revision
                    || record.plan_digest != active.plan_digest
                {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    #[allow(clippy::too_many_lines)]
    fn validated_output_binding_digest(
        &self,
        namespace: &str,
        upstream_task_id: &str,
        upstream_task_contract_digest: &str,
        binding_id: &str,
        downstream_task_id: &str,
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
            .get_state(
                namespace,
                &active_scoped_key(active, &output_binding_key(upstream_task_id, binding_id)),
            )?
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
        let verification_revision = record
            .carried_from_plan_revision
            .unwrap_or(record.plan_revision);
        let verification_plan_digest = record
            .carried_from_plan_digest
            .as_deref()
            .unwrap_or(record.plan_digest.as_str());
        let verification_raw = self
            .state
            .get_state(
                "controller.verification",
                &revision_scoped_key(
                    &record.plan_id,
                    verification_revision,
                    &record.verification_id,
                ),
            )?
            .ok_or_else(|| {
                ControllerError::NotReady(format!(
                    "verified dependency output binding {binding_id} lost its verification record"
                ))
            })?;
        let verification: VerificationResultV1 = serde_json::from_str(&verification_raw)?;
        if !verification.passed
            || verification.plan_id != record.plan_id
            || verification.plan_revision != verification_revision
            || verification.plan_digest != verification_plan_digest
            || verification.task_id != upstream_task_id
            || verification.task_contract_digest != upstream_task_contract_digest
        {
            return Err(ControllerError::NotReady(format!(
                "verified dependency output binding {binding_id} has invalid acceptance evidence"
            )));
        }
        if record.carried_from_plan_revision.is_some() {
            let carry_key = active_scoped_key(active, upstream_task_id);
            let carry_raw = self
                .state
                .get_state("controller.task_carry_fingerprint", &carry_key)?
                .ok_or_else(|| {
                    ControllerError::NotReady(format!(
                        "carried dependency output binding {binding_id} lost its carry proof"
                    ))
                })?;
            let carry: TaskCarryFingerprintV1 = serde_json::from_str(&carry_raw)?;
            if carry.schema_version != TASK_CARRY_FINGERPRINT_SCHEMA_VERSION
                || carry.plan_id != active.plan_id
                || carry.plan_revision != active.revision
                || carry.plan_digest != active.plan_digest
                || carry.task_id != upstream_task_id
                || carry.task_contract_digest != upstream_task_contract_digest
                || carry.verification_id != record.verification_id
                || carry.verification_artifact_digest != record.verification_artifact_digest
            {
                return Err(ControllerError::NotReady(format!(
                    "carried dependency output binding {binding_id} has invalid carry provenance"
                )));
            }
            if self.active_uses_controller_worktrees()? {
                let upstream = active.tasks.get(upstream_task_id).ok_or_else(|| {
                    ControllerError::NotReady(format!(
                        "carried dependency task {upstream_task_id} disappeared"
                    ))
                })?;
                let change_set = upstream.change_set.as_ref().ok_or_else(|| {
                    ControllerError::NotReady(format!(
                        "carried dependency task {upstream_task_id} lost immutable ChangeSet"
                    ))
                })?;
                let change_set_digest = change_set.digest()?;
                let carried = upstream.change_set_carry.as_ref().ok_or_else(|| {
                    ControllerError::NotReady(format!(
                        "carried dependency task {upstream_task_id} lost explicit ChangeSet carry provenance"
                    ))
                })?;
                let downstream = active.tasks.get(downstream_task_id).ok_or_else(|| {
                    ControllerError::NotReady(format!(
                        "downstream task {downstream_task_id} disappeared"
                    ))
                })?;
                let composed = downstream.worktree_composition.iter().any(|binding| {
                    binding.task_id == upstream_task_id
                        && binding.change_set_digest == change_set_digest
                });
                if carried.from_revision != verification_revision
                    || carried.to_revision != active.revision
                    || carried.source_change_set_digest != change_set_digest
                    || record.change_set_digest.as_deref() != Some(change_set_digest.as_str())
                    || !composed
                {
                    return Err(ControllerError::NotReady(format!(
                        "carried dependency output binding {binding_id} is not present in the exact composed ChangeSet view"
                    )));
                }
            } else if record.repository_snapshot_digest != current_snapshot_digest {
                return Err(ControllerError::NotReady(format!(
                    "carried dependency output binding {binding_id} is stale for the current snapshot"
                )));
            }
        } else if self.active_uses_controller_worktrees()? {
            let upstream = active.tasks.get(upstream_task_id).ok_or_else(|| {
                ControllerError::NotReady(format!("dependency task {upstream_task_id} disappeared"))
            })?;
            let upstream_change_set_digest = upstream
                .change_set
                .as_ref()
                .ok_or_else(|| {
                    ControllerError::NotReady(format!(
                        "dependency task {upstream_task_id} lacks immutable ChangeSet"
                    ))
                })?
                .digest()?;
            let downstream = active.tasks.get(downstream_task_id).ok_or_else(|| {
                ControllerError::NotReady(format!(
                    "downstream task {downstream_task_id} disappeared"
                ))
            })?;
            let composed = downstream.worktree_composition.iter().any(|binding| {
                binding.task_id == upstream_task_id
                    && binding.change_set_digest == upstream_change_set_digest
            });
            if record.change_set_digest.as_deref() != Some(upstream_change_set_digest.as_str())
                || verification.post_snapshot_digest != record.repository_snapshot_digest
                || !composed
            {
                return Err(ControllerError::NotReady(format!(
                    "verified dependency output binding {binding_id} is not present in the current composed execution view"
                )));
            }
        } else if verification.post_snapshot_digest != current_snapshot_digest
            || record.repository_snapshot_digest != current_snapshot_digest
        {
            return Err(ControllerError::NotReady(format!(
                "verified dependency output binding {binding_id} is stale for the current snapshot"
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
        tool_manifest: &ToolManifest,
    ) -> Result<(), ControllerError> {
        self.require_execution_not_paused()?;
        self.require_current_baseline(registry)?;
        let execution_baseline_digest =
            snapshot_digest(&self.task_execution_snapshot(registry, &lease.task_id)?)?;
        let current_permission_decision =
            self.permission_decision_for_task(&lease.task_id, tool_manifest)?;
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
            || execution_baseline_digest != lease.baseline_digest
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
            || current_permission_decision != lease.permission_decision
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
        let source = self.task_execution_read(
            registry,
            &lease.task_id,
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
        let execution_root = self.task_execution_root(&lease.task_id)?;
        let target_metadata = fs::symlink_metadata(execution_root.join(&action.path))?;
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
        isolation_request: &IsolationRequest,
        execution_root: &Path,
    ) -> Result<AuthorizedAction, ControllerError> {
        let command_policy = runtime.command_policy;
        let manifest = runtime.tool_manifest;
        let python_executable = runtime.python_executable;
        let active = self.active_ref()?;
        let task = active
            .tasks
            .get(&lease.task_id)
            .ok_or_else(|| ControllerError::InvalidPlan("task disappeared".to_owned()))?;
        let decision = &lease.permission_decision;
        decision.validate()?;
        if decision.task_id != lease.task_id
            || decision.task_contract_digest != task.task_contract_digest
            || manifest.tool_id != decision.tool_id
            || manifest.version != decision.tool_version
            || manifest.content_digest != decision.tool_digest
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
            || isolation_request.repository_root.canonicalize()? != execution_root.canonicalize()?
        {
            return Err(ControllerError::Policy(PolicyError::Denied(
                "replace_literal requires exact offline repository-write isolation".to_owned(),
            )));
        }
        let python = command_policy.pinned_executable(python_executable)?;
        let destination = execution_root.join(&validated.proposal.path);
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
            working_directory: execution_root.to_path_buf(),
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
            tool_id: decision.tool_id.clone(),
            tool_version: decision.tool_version.clone(),
            tool_digest: decision.tool_digest.clone(),
            executable_digest: python.sha256.clone(),
            repository_id: active.repository_id.clone(),
            destination_digest: Some(validated.proposal.expected_source_digest.clone()),
            permission_class: PermissionClass::RepositoryWrite,
            execution_epoch: lease.execution_epoch,
            policy_digest: active.policy_digest.clone(),
            permission_decision_digest: lease.permission_decision.digest(),
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
        let (plan_digest, task_contract_digest, worktree_lease_id, execution_root) = {
            let active = self.active_ref()?;
            let task = active.tasks.get(&action.task_id).ok_or_else(|| {
                ControllerError::InvalidPlan("action intent task disappeared".to_owned())
            })?;
            (
                active.plan_digest.clone(),
                task.task_contract_digest.clone(),
                task.worktree_lease
                    .as_ref()
                    .map(|lease| lease.lease_id.clone()),
                task.worktree_lease.as_ref().map_or_else(
                    || active.repository_root.clone(),
                    |lease| lease.worktree_path.clone(),
                ),
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
            worktree_lease_id,
            execution_root,
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
        if let Some(lease) = task.worktree_lease.as_ref() {
            self.validate_controller_worktree_lease_binding(&intent.task_id, lease)?;
        }
        let expected_worktree_lease_id = task
            .worktree_lease
            .as_ref()
            .map(|lease| lease.lease_id.as_str());
        let expected_execution_root = task
            .worktree_lease
            .as_ref()
            .map_or(active.repository_root.as_path(), |lease| {
                lease.worktree_path.as_path()
            });
        if intent.schema_version != ACTION_INTENT_SCHEMA_VERSION
            || intent.plan_id != active.plan_id
            || intent.plan_revision != active.revision
            || intent.plan_digest != active.plan_digest
            || intent.repository_id != active.repository_id
            || intent.policy_digest != active.policy_digest
            || intent.task_contract_digest != task.task_contract_digest
            || intent.worktree_lease_id.as_deref() != expected_worktree_lease_id
            || intent.execution_root != expected_execution_root
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
        let source = self.task_execution_read(
            registry,
            &intent.task_id,
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
            expected_execution_root.join(&intent.path),
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
        let raw_intent: PersistedActionIntent = serde_json::from_str(&raw)?;
        let legacy_primary_recovery =
            raw_intent.schema_version == LEGACY_ACTION_INTENT_SCHEMA_VERSION;
        let primary_root = registry
            .repository(&raw_intent.repository_id)
            .ok_or_else(|| {
                ControllerError::InvalidPlan("recovery verification repository missing".to_owned())
            })?
            .root
            .clone();
        let intent = normalize_persisted_action_intent(raw_intent, &primary_root)?;
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
            if legacy_primary_recovery
                && (task.worktree_lease.is_some()
                    || task.worktree_state.is_some()
                    || task.worktree_baseline.is_some()
                    || task.change_set.is_some()
                    || task.change_set_artifact_digest.is_some()
                    || task.change_set_carry.is_some()
                    || !task.worktree_composition.is_empty()
                    || task.worktree_conflict.is_some())
            {
                return Err(ControllerError::NotReady(
                    "legacy v2 committed recovery cannot inherit controller worktree authority"
                        .to_owned(),
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
            legacy_primary_recovery,
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
            &revision_scoped_key(
                &verification.plan_id,
                verification.plan_revision,
                &verification.verification_id,
            ),
            &serde_json::to_string(&verification)?,
        )?;
        self.append_controller_event(
            "recovery_verification_recorded",
            &verification.verification_id,
            &json!({
                "passed": verification.passed,
                "artifact_digest": artifact.digest,
                "plan_id": verification.plan_id,
                "plan_revision": verification.plan_revision,
                "plan_digest": verification.plan_digest,
                "task_id": verification.task_id,
                "task_contract_digest": verification.task_contract_digest,
                "attempt_id": verification.attempt_id,
            }),
        )?;
        self.checkpoint_now()?;
        if !verification.passed {
            let failure_code = verification
                .failure_code
                .clone()
                .unwrap_or_else(|| "unknown_verification_failure".to_owned());
            let failure = self.build_failure_record(FailureRecordInput {
                task_id: intent.task_id.clone(),
                attempt_id: intent.attempt_id.clone(),
                action_id: Some(intent.action_id.clone()),
                result_digest: Some(artifact.digest.clone()),
                exit_code: None,
                category: "verification_failure".to_owned(),
                diagnostic: format!("recovery verification failed: {failure_code}"),
                failure_code,
                failed_action_facts: BTreeMap::from([(
                    "action_id".to_owned(),
                    intent.action_id.clone(),
                )]),
                evidence_refs: vec![verification_evidence_id],
            })?;
            let _ = self.route_failure_record(failure)?;
            return Err(ControllerError::VerificationFailed(Box::new(verification)));
        }
        if legacy_primary_recovery {
            self.apply_verified_success(&verification)?;
            self.refresh_baseline_after_verified_success(registry)?;
            self.append_controller_event(
                "legacy_v2_primary_recovery_verified",
                &intent.task_id,
                &json!({
                    "action_id": action_id,
                    "verification_id": verification.verification_id,
                    "execution_semantics": "historical_primary",
                    "worktree_authority": false,
                    "change_set_authority": false,
                    "carry_authority": false,
                }),
            )?;
            self.checkpoint_now()?;
        } else {
            self.persist_worktree_change_set_if_required(registry, &intent.task_id, &artifacts)?;
            self.record_verified_output_bindings(&verification, &artifact.digest)?;
            self.apply_verified_success(&verification)?;
            self.finalize_verified_repository_success(registry, &intent.task_id)?;
        }
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
        let category = if result.terminated_for_limit.is_some() {
            "resource_failure"
        } else {
            "execution_failure"
        };
        let failure_code = if let Some(limit) = result.terminated_for_limit {
            format!(
                "resource_limit_{}",
                normalized_failure_token(&format!("{limit:?}"))
            )
        } else {
            format!("process_exit_{}", result.exit_code.unwrap_or(-1))
        };
        let diagnostic = raw_tool_failure_diagnostic(result);
        self.build_failure_record(FailureRecordInput {
            task_id: lease.task_id.clone(),
            attempt_id: attempt_id.to_owned(),
            action_id: Some(action.action_id.clone()),
            result_digest: record.result_digest,
            exit_code: result.exit_code,
            category: category.to_owned(),
            failure_code,
            diagnostic,
            failed_action_facts: BTreeMap::from([
                ("action_id".to_owned(), action.action_id.clone()),
                (
                    "exit_code".to_owned(),
                    result
                        .exit_code
                        .map_or_else(|| "none".to_owned(), |code| code.to_string()),
                ),
            ]),
            evidence_refs: vec![format!("action:{}", action.action_id)],
        })
    }

    fn build_failure_record(
        &self,
        input: FailureRecordInput,
    ) -> Result<FailureRecordV1, ControllerError> {
        let active = self.active_ref()?;
        let task = active
            .tasks
            .get(&input.task_id)
            .ok_or_else(|| ControllerError::InvalidPlan("failure task disappeared".to_owned()))?;
        let synopsis = failure_synopsis(
            &input.category,
            &input.failure_code,
            &input.diagnostic,
            &input.failed_action_facts,
        );
        let signature = normalized_failure_signature(
            &input.category,
            &input.failure_code,
            &input.diagnostic,
            &input.failed_action_facts,
        );
        Ok(FailureRecordV1 {
            schema_version: FAILURE_RECORD_SCHEMA_VERSION,
            plan_id: active.plan_id.clone(),
            plan_revision: active.revision,
            plan_digest: active.plan_digest.clone(),
            task_id: input.task_id,
            task_contract_digest: task.task_contract_digest.clone(),
            attempt_id: input.attempt_id,
            action_id: input.action_id,
            result_digest: input.result_digest,
            exit_code: input.exit_code,
            failure_code: input.failure_code,
            signature,
            category: input.category,
            synopsis,
            failed_action_facts: input.failed_action_facts,
            evidence_refs: input.evidence_refs,
            // T09's ordinary execution/proposal/verification failures do not prove that a
            // declared assumption or precondition became false. Replan-invalidating clauses are
            // populated only by a classifier that has explicit evidence for that invalidation.
            affected_contract_ids: Vec::new(),
            confidence_milli: 1_000,
            decision: "pending".to_owned(),
        })
    }

    fn start_attempt(
        &mut self,
        lease: &ReadyLease,
        registry: &ProjectRegistry,
    ) -> Result<String, ControllerError> {
        self.start_attempt_with_origin(lease, registry, None)
    }

    fn start_attempt_with_origin(
        &mut self,
        lease: &ReadyLease,
        registry: &ProjectRegistry,
        repair_origin: Option<&RepairAttemptOriginV1>,
    ) -> Result<String, ControllerError> {
        let repository_root = self.task_execution_root(&lease.task_id)?;
        let pre_snapshot = self.task_execution_snapshot(registry, &lease.task_id)?;
        let pre_snapshot_digest = snapshot_digest(&pre_snapshot)?;
        if pre_snapshot_digest != lease.baseline_digest {
            return Err(ControllerError::NotReady(
                "repository changed before attempt start".to_owned(),
            ));
        }
        let pre_diff = self.task_execution_diff(registry, &lease.task_id)?;
        if !self.active_uses_controller_worktrees()?
            && pre_diff.digest != self.active_ref()?.baseline_diff_digest
        {
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
            repair_origin: repair_origin.cloned(),
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
                json!({
                    "task_id": lease.task_id,
                    "attempt_number": attempt_number,
                    "repair_origin": repair_origin,
                }),
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

    #[allow(clippy::too_many_lines)]
    fn route_failure_record(
        &mut self,
        mut failure: FailureRecordV1,
    ) -> Result<FailureRecordV1, ControllerError> {
        if failure.schema_version != FAILURE_RECORD_SCHEMA_VERSION
            || failure.signature.is_empty()
            || failure.confidence_milli > 1_000
            || failure.decision != "pending"
        {
            return Err(ControllerError::InvalidPlan(
                "FailureRecord v1 is malformed before routing".to_owned(),
            ));
        }
        let record_key = revision_scoped_key(
            &failure.plan_id,
            failure.plan_revision,
            &format!("{}:{}", failure.task_id, failure.attempt_id),
        );
        {
            let active = self.active_ref()?;
            let task = active.tasks.get(&failure.task_id).ok_or_else(|| {
                ControllerError::InvalidPlan("failure task disappeared".to_owned())
            })?;
            let attempt = active.attempts.get(&failure.attempt_id).ok_or_else(|| {
                ControllerError::InvalidPlan("failure attempt disappeared".to_owned())
            })?;
            if failure.plan_id != active.plan_id
                || failure.plan_revision != active.revision
                || failure.plan_digest != active.plan_digest
                || failure.task_contract_digest != task.task_contract_digest
                || attempt.task_id != failure.task_id
                || attempt.task_contract_digest != failure.task_contract_digest
            {
                return Err(ControllerError::InvalidPlan(
                    "FailureRecord v1 authority bindings do not match active runtime".to_owned(),
                ));
            }
            if attempt.state == AttemptState::Failed {
                let raw = self
                    .state
                    .get_state("controller.failure_record", &record_key)?
                    .ok_or_else(|| {
                        ControllerError::InvalidPlan(
                            "failed attempt lacks its durable FailureRecord".to_owned(),
                        )
                    })?;
                let existing: FailureRecordV1 = serde_json::from_str(&raw)?;
                if existing.signature != failure.signature
                    || existing.attempt_id != failure.attempt_id
                    || existing.task_id != failure.task_id
                {
                    return Err(ControllerError::InvalidPlan(
                        "failed attempt is already bound to another failure".to_owned(),
                    ));
                }
                return Ok(existing);
            }
        }

        let (
            max_attempts,
            same_failure_limit,
            attempts_started,
            same_count,
            on_execution_failure,
            on_attempts_exhausted,
            on_same_failure_exhausted,
        ) = {
            let active = self.active_mut()?;
            let attempt = active
                .attempts
                .get_mut(&failure.attempt_id)
                .ok_or_else(|| ControllerError::InvalidPlan("attempt disappeared".to_owned()))?;
            if !legal_attempt_transition(attempt.state, AttemptState::Failed) {
                return Err(ControllerError::InvalidPlan(format!(
                    "illegal attempt transition {:?}->{:?}",
                    attempt.state,
                    AttemptState::Failed
                )));
            }
            attempt.state = AttemptState::Failed;
            let task = active
                .tasks
                .get_mut(&failure.task_id)
                .ok_or_else(|| ControllerError::InvalidPlan("task disappeared".to_owned()))?;
            let count = task
                .failure_counts
                .entry(failure.signature.clone())
                .or_insert(0);
            *count = count.saturating_add(1);
            let max_attempts = required_u32(&task.task, "/failure_policy/max_attempts")?;
            let same_limit = required_u32(&task.task, "/failure_policy/same_failure_limit")?;
            (
                max_attempts,
                same_limit,
                task.attempts_started,
                *count,
                required_str(&task.task, "/failure_policy/on_execution_failure")?.to_owned(),
                required_str(&task.task, "/failure_policy/on_attempts_exhausted")?.to_owned(),
                required_str(&task.task, "/failure_policy/on_same_failure_exhausted")?.to_owned(),
            )
        };
        let capacity_allows_repair = repair_allowed(
            attempts_started,
            max_attempts,
            same_count,
            same_failure_limit,
        );
        let requested_route = if attempts_started >= max_attempts {
            on_attempts_exhausted.as_str()
        } else if same_count >= same_failure_limit {
            on_same_failure_exhausted.as_str()
        } else {
            on_execution_failure.as_str()
        };
        let decision = match requested_route {
            "repair" if capacity_allows_repair => "repair",
            "fail" => "fail",
            _ => "block",
        };
        decision.clone_into(&mut failure.decision);
        {
            let task = self
                .active_mut()?
                .tasks
                .get_mut(&failure.task_id)
                .ok_or_else(|| ControllerError::InvalidPlan("task disappeared".to_owned()))?;
            let next = if decision == "fail" {
                TaskState::FailedTerminal
            } else {
                TaskState::RepairPending
            };
            if task.state != next && !legal_task_transition(task.state, next) {
                return Err(ControllerError::InvalidPlan(format!(
                    "illegal task transition {:?}->{:?}",
                    task.state, next
                )));
            }
            task.state = next;
            task.retry_exhausted = decision != "repair";
            task.resource_deferred_from = None;
        }
        let attempt_json = serde_json::to_string(
            self.active_ref()?
                .attempts
                .get(&failure.attempt_id)
                .ok_or_else(|| ControllerError::InvalidPlan("attempt disappeared".to_owned()))?,
        )?;
        let task_json = serde_json::to_string(
            self.active_ref()?
                .tasks
                .get(&failure.task_id)
                .ok_or_else(|| ControllerError::InvalidPlan("task disappeared".to_owned()))?,
        )?;
        let failure_json = serde_json::to_string(&failure)?;
        let failure_digest = sha256_prefixed(failure_json.as_bytes());
        let events = vec![
            (
                "attempt_failed".to_owned(),
                failure.attempt_id.clone(),
                json!({"state": AttemptState::Failed}),
            ),
            (
                "failure_recorded".to_owned(),
                failure.attempt_id.clone(),
                json!({
                    "task_id": failure.task_id,
                    "signature": failure.signature,
                    "category": failure.category,
                    "decision": failure.decision,
                    "record_key": record_key,
                    "failure_record_digest": failure_digest,
                    "evidence_refs": failure.evidence_refs,
                }),
            ),
            (
                "task_failure_routed".to_owned(),
                failure.task_id.clone(),
                json!({
                    "failure_signature": failure.signature,
                    "attempts_started": attempts_started,
                    "same_failure_count": same_count,
                    "retry_allowed": decision == "repair",
                    "decision": failure.decision,
                    "requested_route": requested_route,
                    "failure_record_digest": failure_digest,
                }),
            ),
        ];
        self.persist_runtime_records_with_events(
            &[
                (
                    "controller.attempt".to_owned(),
                    failure.attempt_id.clone(),
                    attempt_json,
                ),
                (
                    "controller.task".to_owned(),
                    failure.task_id.clone(),
                    task_json,
                ),
                (
                    "controller.failure_record".to_owned(),
                    record_key,
                    failure_json,
                ),
            ],
            &events,
        )?;
        self.checkpoint_now()?;
        Ok(failure)
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
        self.persist_task_carry_fingerprint(
            verification,
            verification_artifact_digest,
            &task_contract_digest,
        )?;
        self.checkpoint_now()?;
        Ok(())
    }

    fn persist_task_carry_fingerprint(
        &mut self,
        verification: &VerificationResultV1,
        verification_artifact_digest: &str,
        task_contract_digest: &str,
    ) -> Result<(), ControllerError> {
        let execution_root = self.task_execution_root(&verification.task_id)?;
        let active = self.active_ref()?;
        let task = active.tasks.get(&verification.task_id).ok_or_else(|| {
            ControllerError::InvalidPlan("carry fingerprint task disappeared".to_owned())
        })?;
        let mut source_fingerprints = BTreeMap::new();
        for path in required_array(&task.task, "/scope/files")? {
            let path = path.as_str().ok_or_else(|| {
                ControllerError::InvalidPlan("task scope file must be a string".to_owned())
            })?;
            source_fingerprints.insert(
                path.to_owned(),
                path_fingerprint(&execution_root, Path::new(path))?,
            );
        }
        let implementation_inputs_digest = digest_json(
            task.task
                .pointer("/implementation_contract/inputs")
                .ok_or_else(|| ControllerError::InvalidPlan("task inputs missing".to_owned()))?,
        )?;
        let dependency_contract_digest =
            digest_json(task.task.get("dependency_bindings").ok_or_else(|| {
                ControllerError::InvalidPlan("task bindings missing".to_owned())
            })?)?;
        let instruction_fingerprint_digest = digest_json(
            active
                .plan_document
                .pointer("/repositories/0/instructions")
                .ok_or_else(|| {
                    ControllerError::InvalidPlan("repository instructions missing".to_owned())
                })?,
        )?;
        let (_, acceptance_contract_digest) = compiled_acceptance_contract(&task.task)?;
        let execution_provenance = if matches!(
            active
                .plan_document
                .pointer("/depth/mode")
                .and_then(Value::as_str),
            Some("D3" | "D4")
        ) {
            Some(
                task_carry_execution_provenance(active, &verification.task_id)?.ok_or_else(
                    || {
                        ControllerError::InvalidPlan(
                            "verified D3/D4 task lacks immutable execution provenance".to_owned(),
                        )
                    },
                )?,
            )
        } else {
            None
        };
        let record = TaskCarryFingerprintV1 {
            schema_version: TASK_CARRY_FINGERPRINT_SCHEMA_VERSION,
            plan_id: active.plan_id.clone(),
            plan_revision: active.revision,
            plan_digest: active.plan_digest.clone(),
            task_id: verification.task_id.clone(),
            task_contract_digest: task_contract_digest.to_owned(),
            implementation_inputs_digest,
            dependency_contract_digest,
            instruction_fingerprint_digest,
            source_fingerprints,
            execution_provenance,
            acceptance_contract_digest,
            verification_id: verification.verification_id.clone(),
            verification_artifact_digest: verification_artifact_digest.to_owned(),
        };
        let key = active_scoped_key(active, &verification.task_id);
        self.state.put_state(
            "controller.task_carry_fingerprint",
            &key,
            &serde_json::to_string(&record)?,
        )?;
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
        let change_set_digest = active
            .tasks
            .get(&verification.task_id)
            .and_then(|task| task.change_set.as_ref())
            .map(ChangeSet::digest)
            .transpose()?;
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
            change_set_digest,
            carried_from_plan_revision: None,
            carried_from_plan_digest: None,
        };
        self.state.put_state(
            namespace,
            &active_scoped_key(
                active,
                &output_binding_key(&verification.task_id, binding_id),
            ),
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

    fn persist_worktree_change_set_if_required(
        &mut self,
        registry: &ProjectRegistry,
        task_id: &str,
        artifacts: &ArtifactStore,
    ) -> Result<(), ControllerError> {
        if !self.active_uses_controller_worktrees()? {
            return Ok(());
        }
        let (lease, baseline, existing, existing_digest, record_key, reference_id) = {
            let active = self.active_ref()?;
            let task = active.tasks.get(task_id).ok_or_else(|| {
                ControllerError::InvalidPlan("ChangeSet task disappeared".to_owned())
            })?;
            if task.worktree_state != Some(WorktreeLifecycle::Materialized) {
                return Err(ControllerError::NotReady(
                    "ChangeSet capture requires a materialized controller worktree".to_owned(),
                ));
            }
            let lease = task.worktree_lease.clone().ok_or_else(|| {
                ControllerError::InvalidPlan("ChangeSet task lacks worktree lease".to_owned())
            })?;
            let baseline = task.worktree_baseline.clone().ok_or_else(|| {
                ControllerError::InvalidPlan(
                    "ChangeSet task lacks composed pre-task baseline".to_owned(),
                )
            })?;
            (
                lease,
                baseline,
                task.change_set.clone(),
                task.change_set_artifact_digest.clone(),
                active_scoped_key(active, task_id),
                format!(
                    "changeset.{}@r{}.{}",
                    active.plan_id, active.revision, task_id
                ),
            )
        };
        let current = registry.capture_change_set_from_baseline(&lease, &baseline)?;
        if !current.unmerged_paths.is_empty() {
            return Err(ControllerError::NotReady(
                "task ChangeSet contains unresolved conflict/unmerged evidence".to_owned(),
            ));
        }
        if let Some(existing) = existing {
            if existing != current || existing_digest.is_none() {
                return Err(ControllerError::NotReady(
                    "current worktree differs from its durable immutable ChangeSet".to_owned(),
                ));
            }
            return Ok(());
        }
        let change_set_json = serde_json::to_string(&current)?;
        let artifact = artifacts.put(&mut self.state, change_set_json.as_bytes())?;
        self.state
            .add_artifact_reference(&reference_id, &artifact.digest)?;
        {
            let task = self.active_mut()?.tasks.get_mut(task_id).ok_or_else(|| {
                ControllerError::InvalidPlan("ChangeSet task disappeared".to_owned())
            })?;
            task.change_set = Some(current.clone());
            task.change_set_artifact_digest = Some(artifact.digest.clone());
        }
        let task_json =
            serde_json::to_string(self.active_ref()?.tasks.get(task_id).ok_or_else(|| {
                ControllerError::InvalidPlan("ChangeSet task disappeared".to_owned())
            })?)?;
        self.persist_runtime_records_with_events(
            &[
                ("controller.task".to_owned(), task_id.to_owned(), task_json),
                (
                    "controller.change_set".to_owned(),
                    record_key,
                    change_set_json,
                ),
            ],
            &[(
                "worktree_change_set_published".to_owned(),
                task_id.to_owned(),
                json!({
                    "lease_id": lease.lease_id,
                    "artifact_digest": artifact.digest,
                    "diff_digest": current.diff_digest,
                    "unmerged_digest": current.unmerged_digest,
                }),
            )],
        )?;
        self.checkpoint_now()?;
        Ok(())
    }

    fn finalize_verified_repository_success(
        &mut self,
        registry: &ProjectRegistry,
        task_id: &str,
    ) -> Result<(), ControllerError> {
        if !self.active_uses_controller_worktrees()? {
            return self.refresh_baseline_after_verified_success(registry);
        }
        let (lease, change_set) = {
            let active = self.active_ref()?;
            let task = active.tasks.get(task_id).ok_or_else(|| {
                ControllerError::InvalidPlan("worktree success task disappeared".to_owned())
            })?;
            if task.worktree_state != Some(WorktreeLifecycle::Materialized) {
                return Err(ControllerError::NotReady(
                    "successful D3/D4 task no longer has a materialized worktree".to_owned(),
                ));
            }
            (
                task.worktree_lease.clone().ok_or_else(|| {
                    ControllerError::InvalidPlan("successful D3/D4 task lacks lease".to_owned())
                })?,
                task.change_set.clone().ok_or_else(|| {
                    ControllerError::InvalidPlan("successful D3/D4 task lacks ChangeSet".to_owned())
                })?,
            )
        };
        registry.release_worktree(&lease, &change_set)?;
        self.active_mut()?
            .tasks
            .get_mut(task_id)
            .ok_or_else(|| {
                ControllerError::InvalidPlan("worktree success task disappeared".to_owned())
            })?
            .worktree_state = Some(WorktreeLifecycle::Released);
        self.persist_worktree_task_state(
            task_id,
            "worktree_released",
            &json!({"lease_id": lease.lease_id, "change_set_diff_digest": change_set.diff_digest}),
        )?;
        Ok(())
    }

    fn close_active_worktrees_for_supersession(
        &mut self,
        registry: &ProjectRegistry,
    ) -> Result<(), ControllerError> {
        if !self.active_uses_controller_worktrees()? {
            return Ok(());
        }
        let task_ids = self.active_ref()?.tasks.keys().cloned().collect::<Vec<_>>();
        for task_id in task_ids {
            let (lease, lifecycle, baseline, existing_change_set) = {
                let task = self.active_ref()?.tasks.get(&task_id).ok_or_else(|| {
                    ControllerError::InvalidPlan("worktree task disappeared".to_owned())
                })?;
                (
                    task.worktree_lease.clone(),
                    task.worktree_state,
                    task.worktree_baseline.clone(),
                    task.change_set.clone(),
                )
            };
            let Some(lease) = lease else {
                continue;
            };
            if lifecycle == Some(WorktreeLifecycle::Released) {
                continue;
            }
            if lifecycle == Some(WorktreeLifecycle::Conflict) {
                return Err(ControllerError::NotReady(format!(
                    "conflicted worktree {} must remain durable for explicit recovery/replan",
                    lease.lease_id
                )));
            }
            if lifecycle == Some(WorktreeLifecycle::Prepared) && !lease.worktree_path.exists() {
                continue;
            }
            registry.validate_worktree_lease(&lease)?;
            let current = match baseline.as_ref() {
                Some(baseline) => registry.capture_change_set_from_baseline(&lease, baseline)?,
                None => registry.capture_change_set(&lease)?,
            };
            if let Some(existing) = existing_change_set
                && existing != current
            {
                return Err(ControllerError::NotReady(format!(
                    "superseded worktree {} differs from its durable ChangeSet",
                    lease.lease_id
                )));
            }
            let change_set_json = serde_json::to_string(&current)?;
            let record_key = active_scoped_key(self.active_ref()?, &task_id);
            {
                let task = self.active_mut()?.tasks.get_mut(&task_id).ok_or_else(|| {
                    ControllerError::InvalidPlan("worktree task disappeared".to_owned())
                })?;
                task.change_set = Some(current.clone());
            }
            let task_json =
                serde_json::to_string(self.active_ref()?.tasks.get(&task_id).ok_or_else(
                    || ControllerError::InvalidPlan("worktree task disappeared".to_owned()),
                )?)?;
            self.persist_runtime_records_with_events(
                &[
                    ("controller.task".to_owned(), task_id.clone(), task_json),
                    (
                        "controller.change_set".to_owned(),
                        record_key,
                        change_set_json,
                    ),
                ],
                &[(
                    "worktree_change_set_published_for_supersession".to_owned(),
                    task_id.clone(),
                    json!({
                        "lease_id": lease.lease_id,
                        "diff_digest": current.diff_digest,
                        "unmerged_digest": current.unmerged_digest,
                    }),
                )],
            )?;
            self.checkpoint_now()?;
            registry.release_worktree(&lease, &current)?;
            self.active_mut()?
                .tasks
                .get_mut(&task_id)
                .ok_or_else(|| {
                    ControllerError::InvalidPlan("worktree task disappeared".to_owned())
                })?
                .worktree_state = Some(WorktreeLifecycle::Released);
            self.persist_worktree_task_state(
                &task_id,
                "worktree_released_for_supersession",
                &json!({"lease_id": lease.lease_id}),
            )?;
        }
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
            "controller.failure_record",
            "controller.repair_packet",
            "controller.change_set",
            "controller.worktree_conflict",
            TASK_CAPABILITY_GRANT_NAMESPACE,
        ] {
            for record in self.state.state_records(namespace)? {
                if namespace != "controller.action_intent"
                    && !key_belongs_to_revision(&record.key, &active.plan_id, active.revision)
                {
                    continue;
                }
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
            execution_control: self.execution_control()?,
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
        let revision_record = {
            let active = self.active_ref()?;
            serde_json::to_string(&json!({
                "plan_id": active.plan_id,
                "revision": active.revision,
                "plan_digest": active.plan_digest,
                "compilation_evidence_digest": active.compilation_evidence_digest,
                "plan_document": active.plan_document,
            }))?
        };
        let revision_key = {
            let active = self.active_ref()?;
            revision_record_key(&active.plan_id, active.revision)
        };
        self.state
            .put_state("controller.plan_revision", &revision_key, &revision_record)?;
        self.state.put_state(
            "controller.plan_revision_lifecycle",
            &revision_key,
            &serde_json::to_string(&json!({
                "plan_id": self.active_ref()?.plan_id,
                "revision": self.active_ref()?.revision,
                "plan_digest": self.active_ref()?.plan_digest,
                "status": "active",
                "superseded_by_revision": Value::Null,
                "superseded_by_digest": Value::Null,
            }))?,
        )?;
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
            let key = active_scoped_key(self.active_ref()?, &attempt_id);
            self.state.put_state("controller.attempt", &key, &value)?;
        }
        Ok(())
    }

    fn persist_default_task_capability_grants(&mut self) -> Result<(), ControllerError> {
        let configured = self.permission_context.persisted_grant_capabilities();
        let issuer = self.permission_context.persisted_grant_issuer.clone();
        let (plan_id, plan_revision, policy_digest, task_scopes) = {
            let active = self.active_ref()?;
            (
                active.plan_id.clone(),
                active.revision,
                active.policy_digest.clone(),
                active
                    .tasks
                    .iter()
                    .map(|(task_id, task)| (task_id.clone(), task.task_contract_digest.clone()))
                    .collect::<Vec<_>>(),
            )
        };
        let mut records = Vec::with_capacity(task_scopes.len());
        for (task_id, task_contract_digest) in &task_scopes {
            let grant = TaskCapabilityGrant {
                plan_id: plan_id.clone(),
                plan_revision,
                task_id: task_id.clone(),
                task_contract_digest: task_contract_digest.clone(),
                policy_digest: policy_digest.clone(),
                issued_by: issuer.clone(),
                capabilities: configured.clone(),
            };
            grant.validate()?;
            let key = revision_scoped_key(&plan_id, plan_revision, task_id);
            records.push((
                key,
                serde_json::to_string(&PersistedTaskCapabilityGrantV1::from_grant(&grant))?,
            ));
        }
        let payload = json!({
            "plan_id": plan_id,
            "plan_revision": plan_revision,
            "policy_digest": policy_digest,
            "issuer": issuer,
            "task_ids": task_scopes.iter().map(|(task_id, _)| task_id).collect::<Vec<_>>(),
            "configured_user_ceiling_digest": configured.digest(),
        });
        let payload_json = serde_json::to_string(&payload)?;
        let seed = sha256_prefixed(
            format!(
                "task_capability_grants_materialized\0{}\0{}\0{}",
                plan_id,
                self.state.latest_journal_sequence()?,
                payload_json
            )
            .as_bytes(),
        );
        let event_id = format!("controller.{}", &seed[7..27]);
        let updates = records
            .iter()
            .map(|(key, value_json)| StateRecordUpdate {
                namespace: TASK_CAPABILITY_GRANT_NAMESPACE,
                key,
                value_json,
            })
            .collect::<Vec<_>>();
        self.state.put_state_records_with_events(
            &updates,
            &[NewJournalEvent {
                event_id: &event_id,
                entity_type: "controller",
                entity_id: &plan_id,
                event_kind: "task_capability_grants_materialized",
                payload_json: &payload_json,
            }],
        )?;
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
        let key = active_scoped_key(self.active_ref()?, task_id);
        self.state.put_state("controller.task", &key, &value)?;
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

    fn persist_control_record_with_event(
        &mut self,
        namespace: &str,
        key: &str,
        value_json: &str,
        event_kind: &str,
        payload: &Value,
    ) -> Result<(), ControllerError> {
        let event_payload = serde_json::to_string(payload)?;
        let seed = sha256_prefixed(
            format!(
                "{}\0{}\0{}\0{}",
                event_kind,
                key,
                self.state.latest_journal_sequence()?,
                event_payload
            )
            .as_bytes(),
        );
        let event_id = format!("controller.{}", &seed[7..27]);
        self.state.put_state_records_with_events(
            &[StateRecordUpdate {
                namespace,
                key,
                value_json,
            }],
            &[NewJournalEvent {
                event_id: &event_id,
                entity_type: "controller",
                entity_id: key,
                event_kind,
                payload_json: &event_payload,
            }],
        )?;
        Ok(())
    }

    fn set_execution_paused(
        &mut self,
        paused: bool,
        reason: Option<&str>,
    ) -> Result<ExecutionControlV1, ControllerError> {
        // Invalidate every previously derived readiness lease before making a resume visible.
        // If the later durable control transition fails, the extra epoch advance is safe and
        // fail-closed; the inverse ordering could briefly make a stale pre-pause lease usable.
        self.state.advance_execution_epoch()?;
        let control = ExecutionControlV1 {
            schema_version: EXECUTION_CONTROL_SCHEMA_VERSION,
            paused,
            reason: reason
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned),
            changed_at_ms: unix_millis()?,
        };
        let value_json = serde_json::to_string(&control)?;
        self.persist_control_record_with_event(
            "controller.execution_control",
            "global",
            &value_json,
            if paused {
                "execution_paused"
            } else {
                "execution_resumed"
            },
            &json!({"paused": paused, "reason": control.reason}),
        )?;
        if self.active.is_some() {
            self.checkpoint_now()?;
        }
        Ok(control)
    }

    fn require_execution_not_paused(&self) -> Result<(), ControllerError> {
        let control = self.execution_control()?;
        if control.paused {
            return Err(ControllerError::NotReady(
                "Controller execution is paused".to_owned(),
            ));
        }
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
        let (plan_id, revision) = {
            let active = self.active_ref()?;
            (active.plan_id.clone(), active.revision)
        };
        let scoped_records = records
            .iter()
            .map(|(namespace, key, value_json)| {
                let key = if matches!(namespace.as_str(), "controller.task" | "controller.attempt")
                {
                    revision_scoped_key(&plan_id, revision, key)
                } else {
                    key.clone()
                };
                (namespace.clone(), key, value_json.clone())
            })
            .collect::<Vec<_>>();
        let updates = scoped_records
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
        object.insert("plan_id".to_owned(), Value::String(active.plan_id.clone()));
        object.insert("plan_revision".to_owned(), json!(active.revision));
        object.insert(
            "plan_digest".to_owned(),
            Value::String(active.plan_digest.clone()),
        );
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

fn task_carry_execution_provenance(
    active: &ActivePlan,
    task_id: &str,
) -> Result<Option<TaskCarryExecutionProvenanceV1>, ControllerError> {
    let task = active.tasks.get(task_id).ok_or_else(|| {
        ControllerError::InvalidPlan(format!(
            "carry execution provenance task {task_id} disappeared"
        ))
    })?;
    let Some(change_set) = task.change_set.as_ref() else {
        return Ok(None);
    };
    let mut composed_change_sets = Vec::new();
    for upstream_task_id in dependency_closure_order(&active.tasks, task_id)? {
        let Some(upstream_change_set) = active
            .tasks
            .get(&upstream_task_id)
            .and_then(|runtime| runtime.change_set.as_ref())
        else {
            return Ok(None);
        };
        composed_change_sets.push(ComposedChangeSetBindingV1 {
            task_id: upstream_task_id,
            change_set_digest: upstream_change_set.digest()?,
        });
    }
    Ok(Some(TaskCarryExecutionProvenanceV1 {
        change_set_digest: change_set.digest()?,
        composed_change_sets,
    }))
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
        let supersession = validate_post_checkpoint_supersession(
            &state,
            &manifest,
            trusted_checkpoint.action_sequence,
        )?;
        let replayed_events = if supersession.is_some() {
            state
                .journal_after(trusted_checkpoint.action_sequence)?
                .len()
        } else {
            let replayed = validate_post_checkpoint_runtime_correlation(
                &state,
                &manifest,
                trusted_checkpoint.action_sequence,
            )?;
            validate_post_checkpoint_task_grant_correlation(
                &state,
                &manifest,
                trusted_checkpoint.action_sequence,
            )?;
            replayed
        };
        validate_post_checkpoint_execution_control(
            &state,
            &manifest,
            trusted_checkpoint.action_sequence,
        )?;
        let execution_epoch_before = state.current_execution_epoch()?;
        let execution_epoch_floor =
            recovery_execution_epoch_floor(&state, &manifest, trusted_checkpoint.action_sequence)?;
        if execution_epoch_before < execution_epoch_floor {
            return Err(ControllerError::InvalidPlan(format!(
                "durable execution epoch {execution_epoch_before} is below trusted recovery floor {execution_epoch_floor}"
            )));
        }
        let active = reconstruct_active_plan(&state, registry, &manifest, supersession.as_ref())?;
        let trusted_recovery_intent_digests = manifest
            .evidence_binding_digests
            .iter()
            .filter_map(|(key, digest)| {
                key.strip_prefix("controller.action_intent:")
                    .map(|action_id| (action_id.to_owned(), digest.clone()))
            })
            .collect();
        let mut controller = Controller {
            state,
            active: Some(active),
            resource_governor: M1ResourceGovernor::default(),
            permission_context,
            trusted_recovery_intent_digests,
        };

        let recovery_worktrees = reconcile_recovered_worktrees(&mut controller, registry)?;
        let (unresolved_process_lease_ids, unresolved_process_actions) =
            reap_recovery_process_leases(&mut controller.state)?;
        let mut unknown_action_ids = reconcile_recovery_actions(
            &mut controller.state,
            registry,
            &unresolved_process_actions,
            &manifest,
            &recovery_worktrees,
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
            || controller.active_ref()?.tasks.values().any(|task| {
                task.state == TaskState::ReconcilingUnknown
                    || task.worktree_state == Some(WorktreeLifecycle::Conflict)
            });
        let (recovered_plan_id, recovered_plan_digest) = {
            let active = controller.active_ref()?;
            (active.plan_id.clone(), active.plan_digest.clone())
        };
        let summary = RecoverySummary {
            plan_id: recovered_plan_id,
            plan_digest: recovered_plan_digest,
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
        || sha256_prefixed(manifest.baseline_diff_content.as_bytes())
            != manifest.baseline_diff_digest
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
        let Some((namespace, key)) = binding_key.split_once(':') else {
            continue;
        };
        if !matches!(
            namespace,
            "controller.action_intent"
                | "controller.failure_record"
                | "controller.repair_packet"
                | "controller.change_set"
                | "controller.worktree_conflict"
        ) {
            continue;
        }
        let current = state.get_state(namespace, key)?.ok_or_else(|| {
            ControllerError::InvalidPlan(format!(
                "checkpoint-bound immutable record {namespace}:{key} is missing"
            ))
        })?;
        if sha256_prefixed(current.as_bytes()) != *expected_digest {
            return Err(ControllerError::InvalidPlan(format!(
                "checkpoint-bound immutable record {namespace}:{key} changed after checkpoint"
            )));
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct ValidatedSupersession {
    plan_id: String,
    revision: u32,
    plan_digest: String,
    compilation_evidence_digest: String,
}

#[allow(clippy::too_many_lines)]
fn validate_post_checkpoint_supersession(
    state: &StateStore,
    manifest: &CheckpointManifest,
    checkpoint_sequence: i64,
) -> Result<Option<ValidatedSupersession>, ControllerError> {
    let raw_active = state
        .get_state("controller.plan", "active")?
        .ok_or_else(|| ControllerError::InvalidPlan("active plan state is missing".to_owned()))?;
    let active: Value = serde_json::from_str(&raw_active)?;
    let active_plan_id = required_str(&active, "/plan_id")?;
    let active_revision = required_u32(&active, "/revision")?;
    let active_plan_digest = required_str(&active, "/plan_digest")?;
    if active_plan_id == manifest.plan_id
        && active_revision == manifest.plan_revision
        && active_plan_digest == manifest.plan_digest
    {
        return Ok(None);
    }
    if active_plan_id != manifest.plan_id
        || active_revision != manifest.plan_revision.saturating_add(1)
    {
        return Err(ControllerError::InvalidPlan(
            "superseded plan checkpoint diverges from durable active plan without one adjacent trusted supersession"
                .to_owned(),
        ));
    }
    let active_validity: PlanValidity = serde_json::from_value(
        active
            .get("validity")
            .cloned()
            .ok_or_else(|| ControllerError::InvalidPlan("active validity missing".to_owned()))?,
    )?;
    if active_validity != PlanValidity::Current {
        return Err(ControllerError::InvalidPlan(
            "post-checkpoint superseding revision is not current".to_owned(),
        ));
    }
    let activation_events = state
        .journal_after(checkpoint_sequence)?
        .into_iter()
        .filter(|event| {
            event.entity_type == "controller"
                && event.entity_id == manifest.plan_id
                && event.event_kind == "plan_revision_activated"
        })
        .collect::<Vec<_>>();
    if activation_events.len() != 1 {
        return Err(ControllerError::InvalidPlan(format!(
            "post-checkpoint supersession requires exactly one activation event, found {}",
            activation_events.len()
        )));
    }
    let payload: Value = serde_json::from_str(&activation_events[0].payload_json)?;
    if required_u32(&payload, "/from_revision")? != manifest.plan_revision
        || required_u32(&payload, "/to_revision")? != active_revision
        || required_str(&payload, "/from_plan_digest")? != manifest.plan_digest
        || required_str(&payload, "/to_plan_digest")? != active_plan_digest
    {
        return Err(ControllerError::InvalidPlan(
            "activation event does not bind exact checkpoint N to active N+1".to_owned(),
        ));
    }
    let event_epoch = payload
        .get("execution_epoch")
        .and_then(Value::as_i64)
        .ok_or_else(|| ControllerError::InvalidPlan("activation event epoch missing".to_owned()))?;
    if state.current_execution_epoch()? != event_epoch {
        return Err(ControllerError::InvalidPlan(
            "post-activation execution epoch changed before N+1 checkpoint".to_owned(),
        ));
    }

    let raw_document = state
        .get_state("controller.plan_document", "active")?
        .ok_or_else(|| ControllerError::InvalidPlan("active plan document missing".to_owned()))?;
    let active_document: Value = serde_json::from_str(&raw_document)?;
    if digest_json(&active_document)? != active_plan_digest {
        return Err(ControllerError::InvalidPlan(
            "active N+1 plan document digest mismatch".to_owned(),
        ));
    }
    let revision_key = revision_record_key(active_plan_id, active_revision);
    let revision_raw = state
        .get_state("controller.plan_revision", &revision_key)?
        .ok_or_else(|| ControllerError::InvalidPlan("N+1 revision record missing".to_owned()))?;
    let revision_record: Value = serde_json::from_str(&revision_raw)?;
    if required_str(&revision_record, "/plan_id")? != active_plan_id
        || required_u32(&revision_record, "/revision")? != active_revision
        || required_str(&revision_record, "/plan_digest")? != active_plan_digest
        || required_str(&revision_record, "/previous_plan_digest")? != manifest.plan_digest
        || revision_record.get("plan_document") != Some(&active_document)
    {
        return Err(ControllerError::InvalidPlan(
            "N+1 immutable revision record is misbound".to_owned(),
        ));
    }
    let compilation_evidence_digest =
        required_str(&revision_record, "/compilation_evidence_digest")?.to_owned();
    if active
        .get("compilation_evidence_digest")
        .and_then(Value::as_str)
        != Some(compilation_evidence_digest.as_str())
    {
        return Err(ControllerError::InvalidPlan(
            "active N+1 compiler evidence digest differs from revision record".to_owned(),
        ));
    }
    let compilation_raw = state
        .get_state("controller.compilation_evidence", &revision_key)?
        .ok_or_else(|| {
            ControllerError::InvalidPlan("N+1 compilation evidence record missing".to_owned())
        })?;
    let compilation_value: Value = serde_json::from_str(&compilation_raw)?;
    if digest_json(&compilation_value)? != compilation_evidence_digest {
        return Err(ControllerError::InvalidPlan(
            "N+1 compilation evidence digest mismatch".to_owned(),
        ));
    }

    let diff_raw = state
        .get_state("controller.plan_revision_diff", &revision_key)?
        .ok_or_else(|| ControllerError::InvalidPlan("N+1 revision diff missing".to_owned()))?;
    if sha256_prefixed(diff_raw.as_bytes()) != required_str(&payload, "/plan_revision_diff_digest")?
    {
        return Err(ControllerError::InvalidPlan(
            "N+1 revision diff differs from activation event binding".to_owned(),
        ));
    }
    let diff: PlanRevisionDiff = serde_json::from_str(&diff_raw)?;
    let recomputed = PlanRevisionDiff::between(
        &manifest.plan_document,
        &active_document,
        diff.scope,
        &diff.invalidated_contract_ids,
        &diff.affected_task_ids,
    )
    .map_err(ControllerError::InvalidPlan)?;
    if recomputed != diff {
        return Err(ControllerError::InvalidPlan(
            "N+1 revision diff does not match canonical adjacent plans".to_owned(),
        ));
    }

    let task_runtime_values = required_array(&active_document, "/tasks")?
        .iter()
        .map(|task| {
            let task_id = required_str(task, "/task_id")?;
            let key = revision_scoped_key(active_plan_id, active_revision, task_id);
            let raw = state.get_state("controller.task", &key)?.ok_or_else(|| {
                ControllerError::InvalidPlan(format!("N+1 runtime {task_id} missing"))
            })?;
            let runtime: Value = serde_json::from_str(&raw)?;
            Ok((task_id.to_owned(), runtime))
        })
        .collect::<Result<BTreeMap<_, _>, ControllerError>>()?;
    if digest_json(&serde_json::to_value(&task_runtime_values)?)?
        != required_str(&payload, "/task_runtime_map_digest")?
    {
        return Err(ControllerError::InvalidPlan(
            "N+1 task runtime map differs from activation event binding".to_owned(),
        ));
    }
    let task_capability_grant_values = state
        .state_records(TASK_CAPABILITY_GRANT_NAMESPACE)?
        .into_iter()
        .filter_map(|record| {
            logical_key_for_revision(&record.key, active_plan_id, active_revision)
                .map(|task_id| (task_id, record.value_json))
        })
        .map(|(task_id, raw)| Ok((task_id, serde_json::from_str::<Value>(&raw)?)))
        .collect::<Result<BTreeMap<_, _>, ControllerError>>()?;
    if digest_json(&serde_json::to_value(&task_capability_grant_values)?)?
        != required_str(&payload, "/task_capability_grant_map_digest")?
    {
        return Err(ControllerError::InvalidPlan(
            "N+1 task capability grants differ from activation event binding".to_owned(),
        ));
    }
    let attempt_values = state
        .state_records("controller.attempt")?
        .into_iter()
        .filter_map(|record| {
            logical_key_for_revision(&record.key, active_plan_id, active_revision)
                .map(|attempt_id| (attempt_id, record.value_json))
        })
        .map(|(attempt_id, raw)| Ok((attempt_id, serde_json::from_str::<Value>(&raw)?)))
        .collect::<Result<BTreeMap<_, _>, ControllerError>>()?;
    if digest_json(&serde_json::to_value(&attempt_values)?)?
        != required_str(&payload, "/attempt_runtime_map_digest")?
    {
        return Err(ControllerError::InvalidPlan(
            "N+1 attempt runtime map differs from activation event binding".to_owned(),
        ));
    }
    let mut carry_record_digests = BTreeMap::new();
    for namespace in [
        "controller.task_carry_fingerprint",
        "controller.artifact_binding",
        "controller.acceptance_binding",
    ] {
        for record in state.state_records(namespace)? {
            if key_belongs_to_revision(&record.key, active_plan_id, active_revision) {
                carry_record_digests.insert(
                    format!("{namespace}:{}", record.key),
                    sha256_prefixed(record.value_json.as_bytes()),
                );
            }
        }
    }
    if digest_json(&serde_json::to_value(&carry_record_digests)?)?
        != required_str(&payload, "/carry_proof_digest")?
    {
        return Err(ControllerError::InvalidPlan(
            "N+1 carry proof set differs from activation event binding".to_owned(),
        ));
    }

    let baseline_raw = state
        .get_state("controller.repository_baseline", "active")?
        .ok_or_else(|| ControllerError::InvalidPlan("active N+1 baseline missing".to_owned()))?;
    let baseline: PersistedRepositoryBaseline = serde_json::from_str(&baseline_raw)?;
    if snapshot_digest(&baseline.snapshot)?
        != required_str(&payload, "/repository_snapshot_digest")?
        || baseline.diff_digest != required_str(&payload, "/baseline_diff_digest")?
    {
        return Err(ControllerError::InvalidPlan(
            "N+1 baseline differs from activation event binding".to_owned(),
        ));
    }
    let previous_lifecycle_raw = state
        .get_state(
            "controller.plan_revision_lifecycle",
            &revision_record_key(active_plan_id, manifest.plan_revision),
        )?
        .ok_or_else(|| ControllerError::InvalidPlan("N lifecycle record missing".to_owned()))?;
    let previous_lifecycle: Value = serde_json::from_str(&previous_lifecycle_raw)?;
    let active_lifecycle_raw = state
        .get_state("controller.plan_revision_lifecycle", &revision_key)?
        .ok_or_else(|| ControllerError::InvalidPlan("N+1 lifecycle record missing".to_owned()))?;
    let active_lifecycle: Value = serde_json::from_str(&active_lifecycle_raw)?;
    if previous_lifecycle.get("status").and_then(Value::as_str) != Some("superseded")
        || previous_lifecycle
            .get("superseded_by_revision")
            .and_then(Value::as_u64)
            != Some(u64::from(active_revision))
        || active_lifecycle.get("status").and_then(Value::as_str) != Some("active")
    {
        return Err(ControllerError::InvalidPlan(
            "plan revision lifecycle does not show exactly N superseded by active N+1".to_owned(),
        ));
    }
    Ok(Some(ValidatedSupersession {
        plan_id: active_plan_id.to_owned(),
        revision: active_revision,
        plan_digest: active_plan_digest.to_owned(),
        compilation_evidence_digest,
    }))
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
    let current_tasks = replayed_tasks
        .keys()
        .map(|task_id| {
            let key = revision_scoped_key(&manifest.plan_id, manifest.plan_revision, task_id);
            let raw = state.get_state("controller.task", &key)?.ok_or_else(|| {
                ControllerError::InvalidPlan(format!(
                    "active revision task runtime {task_id} is missing"
                ))
            })?;
            Ok((task_id.clone(), serde_json::from_str::<Value>(&raw)?))
        })
        .collect::<Result<BTreeMap<_, _>, ControllerError>>()?;
    if replayed_tasks != current_tasks {
        return Err(ControllerError::InvalidPlan(
            "current task state does not equal ordered post-checkpoint journal replay".to_owned(),
        ));
    }

    let current_attempts = replayed_attempts
        .keys()
        .map(|attempt_id| {
            let key = revision_scoped_key(&manifest.plan_id, manifest.plan_revision, attempt_id);
            let raw = state
                .get_state("controller.attempt", &key)?
                .ok_or_else(|| {
                    ControllerError::InvalidPlan(format!(
                        "active revision attempt runtime {attempt_id} is missing"
                    ))
                })?;
            Ok((attempt_id.clone(), serde_json::from_str::<Value>(&raw)?))
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

fn validate_post_checkpoint_task_grant_correlation(
    state: &StateStore,
    manifest: &CheckpointManifest,
    checkpoint_sequence: i64,
) -> Result<(), ControllerError> {
    let binding_prefix = format!("{TASK_CAPABILITY_GRANT_NAMESPACE}:");
    let mut replayed = manifest
        .evidence_binding_digests
        .iter()
        .filter_map(|(binding_key, digest)| {
            binding_key
                .strip_prefix(&binding_prefix)
                .map(|key| (key.to_owned(), digest.clone()))
        })
        .collect::<BTreeMap<_, _>>();
    for event in state.journal_after(checkpoint_sequence)? {
        if event.entity_type != "controller" || event.event_kind != "task_capability_grant_changed"
        {
            continue;
        }
        if !key_belongs_to_revision(&event.entity_id, &manifest.plan_id, manifest.plan_revision) {
            return Err(ControllerError::InvalidPlan(
                "post-checkpoint capability grant event targets a different plan revision"
                    .to_owned(),
            ));
        }
        let payload: Value = serde_json::from_str(&event.payload_json)?;
        if required_str(&payload, "/plan_id")? != manifest.plan_id
            || required_u32(&payload, "/plan_revision")? != manifest.plan_revision
        {
            return Err(ControllerError::InvalidPlan(
                "post-checkpoint capability grant event scope is stale".to_owned(),
            ));
        }
        let grant_digest = required_str(&payload, "/grant_digest")?;
        replayed.insert(event.entity_id.clone(), grant_digest.to_owned());
    }
    let current = state
        .state_records(TASK_CAPABILITY_GRANT_NAMESPACE)?
        .into_iter()
        .filter(|record| {
            key_belongs_to_revision(&record.key, &manifest.plan_id, manifest.plan_revision)
        })
        .map(|record| (record.key, sha256_prefixed(record.value_json.as_bytes())))
        .collect::<BTreeMap<_, _>>();
    if replayed != current {
        return Err(ControllerError::InvalidPlan(
            "current task capability grants do not equal checkpoint plus journal replay".to_owned(),
        ));
    }
    Ok(())
}

fn validate_post_checkpoint_execution_control(
    state: &StateStore,
    manifest: &CheckpointManifest,
    checkpoint_sequence: i64,
) -> Result<(), ControllerError> {
    let mut replayed = manifest.execution_control.clone();
    for event in state.journal_after(checkpoint_sequence)? {
        if event.entity_type != "controller"
            || (event.event_kind != "execution_paused" && event.event_kind != "execution_resumed")
        {
            continue;
        }
        let payload: Value = serde_json::from_str(&event.payload_json)?;
        let paused = payload
            .get("paused")
            .and_then(Value::as_bool)
            .ok_or_else(|| {
                ControllerError::InvalidPlan(
                    "execution-control journal event is missing paused flag".to_owned(),
                )
            })?;
        replayed = ExecutionControlV1 {
            schema_version: EXECUTION_CONTROL_SCHEMA_VERSION,
            paused,
            reason: payload
                .get("reason")
                .and_then(Value::as_str)
                .map(str::to_owned),
            // The authoritative current record supplies the transition timestamp; journal
            // correlation proves the semantic paused/resumed state and reason.
            changed_at_ms: replayed.changed_at_ms,
        };
    }
    let current = load_execution_control(state)?;
    if replayed.paused != current.paused || replayed.reason != current.reason {
        return Err(ControllerError::InvalidPlan(
            "current execution-control state does not equal ordered post-checkpoint journal replay"
                .to_owned(),
        ));
    }
    Ok(())
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
    if sha256_prefixed(current_baseline.diff_content.as_bytes()) != current_baseline.diff_digest {
        return Err(ControllerError::InvalidPlan(
            "durable repository baseline diff content does not match its digest".to_owned(),
        ));
    }
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
                        "verified_baseline_advanced"
                            | "plan_stale_evidence"
                            | "plan_failure_invalidated"
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

fn recovery_execution_epoch_floor(
    state: &StateStore,
    manifest: &CheckpointManifest,
    checkpoint_sequence: i64,
) -> Result<i64, ControllerError> {
    let mut floor = manifest.execution_epoch;
    for record in state.action_records()? {
        floor = floor.max(record.execution_epoch);
    }
    for event in state.journal_after(checkpoint_sequence)? {
        if event.entity_type != "controller" {
            continue;
        }
        let payload: Value = serde_json::from_str(&event.payload_json)?;
        for key in [
            "execution_epoch",
            "execution_epoch_before",
            "execution_epoch_after",
        ] {
            if let Some(epoch) = payload.get(key).and_then(Value::as_i64) {
                floor = floor.max(epoch);
            }
        }
    }
    Ok(floor)
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
    supersession: Option<&ValidatedSupersession>,
) -> Result<ActivePlan, ControllerError> {
    let raw_plan = state
        .get_state("controller.plan", "active")?
        .ok_or_else(|| ControllerError::InvalidPlan("active plan state is missing".to_owned()))?;
    let plan_record: Value = serde_json::from_str(&raw_plan)?;
    let active_plan_id = required_str(&plan_record, "/plan_id")?;
    let active_plan_digest = required_str(&plan_record, "/plan_digest")?;
    let active_revision = required_u32(&plan_record, "/revision")?;
    match supersession {
        Some(validated) => {
            if active_plan_id != validated.plan_id
                || active_plan_digest != validated.plan_digest
                || active_revision != validated.revision
            {
                return Err(ControllerError::InvalidPlan(
                    "durable active plan differs from validated N+1 supersession".to_owned(),
                ));
            }
        }
        None => {
            if active_plan_id != manifest.plan_id
                || active_plan_digest != manifest.plan_digest
                || active_revision != manifest.plan_revision
            {
                return Err(ControllerError::InvalidPlan(
                    "checkpoint belongs to a superseded plan without validated N+1 activation"
                        .to_owned(),
                ));
            }
        }
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
    if sha256_prefixed(baseline.diff_content.as_bytes()) != baseline.diff_digest {
        return Err(ControllerError::InvalidPlan(
            "durable repository baseline diff content does not match its digest".to_owned(),
        ));
    }
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
    for (task_id, plan_task) in &plan_task_map {
        let key = revision_scoped_key(active_plan_id, active_revision, task_id);
        let raw = state.get_state("controller.task", &key)?.ok_or_else(|| {
            ControllerError::InvalidPlan(format!("durable active task {task_id} is missing"))
        })?;
        let runtime: TaskRuntime = serde_json::from_str(&raw)?;
        if runtime.task_contract_digest != digest_json(plan_task)? || &runtime.task != *plan_task {
            return Err(ControllerError::InvalidPlan(format!(
                "durable task {task_id} contract is stale or altered"
            )));
        }
        tasks.insert(task_id.clone(), runtime);
    }
    if tasks.len() != plan_task_map.len() {
        return Err(ControllerError::InvalidPlan(
            "durable task set is incomplete".to_owned(),
        ));
    }
    let attempts = state
        .state_records("controller.attempt")?
        .into_iter()
        .filter_map(|record| {
            let logical_key =
                logical_key_for_revision(&record.key, active_plan_id, active_revision)?;
            Some((logical_key, record.value_json))
        })
        .map(|(attempt_id, raw)| {
            let attempt: AttemptRuntime = serde_json::from_str(&raw)?;
            if !tasks.contains_key(&attempt.task_id) {
                return Err(ControllerError::InvalidPlan(format!(
                    "active attempt {attempt_id} belongs to a superseded task"
                )));
            }
            Ok((attempt_id, attempt))
        })
        .collect::<Result<BTreeMap<_, _>, ControllerError>>()?;
    let validity: PlanValidity =
        serde_json::from_value(plan_record.get("validity").cloned().ok_or_else(|| {
            ControllerError::InvalidPlan("active validity is missing".to_owned())
        })?)?;
    let compilation_evidence_digest =
        required_str(&plan_record, "/compilation_evidence_digest")?.to_owned();
    let expected_compilation_evidence_digest = supersession
        .map_or(manifest.compilation_evidence_digest.as_str(), |validated| {
            validated.compilation_evidence_digest.as_str()
        });
    if compilation_evidence_digest != expected_compilation_evidence_digest {
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
        if process_lease_is_terminal(&lease) {
            continue;
        }
        if lease.schema_version != RECOVERY_PROCESS_LEASE_SCHEMA_VERSION || lease.state != "active"
        {
            unresolved.push(lease.lease_id.clone());
            unresolved_actions.insert(lease.action_id.clone());
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
fn reconcile_recovered_worktrees(
    controller: &mut Controller,
    registry: &ProjectRegistry,
) -> Result<BTreeMap<String, WorktreeLease>, ControllerError> {
    if !controller.active_uses_controller_worktrees()? {
        return Ok(BTreeMap::new());
    }
    let mut leases = BTreeMap::new();
    let task_ids = controller
        .active_ref()?
        .tasks
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    for task_id in task_ids {
        let (lease, lifecycle, change_set, task_state, task_contract_digest) = {
            let task = controller
                .active_ref()?
                .tasks
                .get(&task_id)
                .ok_or_else(|| {
                    ControllerError::InvalidPlan("recovery task disappeared".to_owned())
                })?;
            (
                task.worktree_lease.clone(),
                task.worktree_state,
                task.change_set.clone(),
                task.state,
                task.task_contract_digest.clone(),
            )
        };
        let Some(lease) = lease else {
            if lifecycle.is_some() || change_set.is_some() {
                return Err(ControllerError::InvalidPlan(format!(
                    "recovery task {task_id} has worktree state/evidence without a lease"
                )));
            }
            continue;
        };
        if lease.task_contract_digest != task_contract_digest {
            return Err(ControllerError::InvalidPlan(format!(
                "recovery task {task_id} has a stale task-contract worktree lease"
            )));
        }
        controller.validate_controller_worktree_lease_binding(&task_id, &lease)?;
        match lifecycle {
            Some(WorktreeLifecycle::Prepared) => {
                if lease.worktree_path.exists() {
                    let result = controller.ensure_task_worktree(registry, &task_id);
                    if let Err(error) = result {
                        if controller
                            .active_ref()?
                            .tasks
                            .get(&task_id)
                            .is_some_and(|task| {
                                task.worktree_state == Some(WorktreeLifecycle::Conflict)
                                    && task.worktree_conflict.is_some()
                            })
                        {
                            continue;
                        }
                        return Err(error);
                    }
                    leases.insert(task_id.clone(), lease.clone());
                }
            }
            Some(WorktreeLifecycle::Materialized) => {
                if !lease.worktree_path.exists() {
                    if task_state == TaskState::Succeeded && change_set.is_some() {
                        controller
                            .active_mut()?
                            .tasks
                            .get_mut(&task_id)
                            .ok_or_else(|| {
                                ControllerError::InvalidPlan("recovery task disappeared".to_owned())
                            })?
                            .worktree_state = Some(WorktreeLifecycle::Released);
                        controller.persist_worktree_task_state(
                            &task_id,
                            "worktree_release_reconciled",
                            &json!({"lease_id": lease.lease_id}),
                        )?;
                        continue;
                    }
                    return Err(ControllerError::NotReady(format!(
                        "materialized recovery worktree {} is missing before verified release",
                        lease.lease_id
                    )));
                }
                registry.validate_worktree_lease(&lease)?;
                let (expected_composition, _) =
                    controller.ordered_upstream_change_sets(&task_id)?;
                let task = controller
                    .active_ref()?
                    .tasks
                    .get(&task_id)
                    .ok_or_else(|| {
                        ControllerError::InvalidPlan("recovery task disappeared".to_owned())
                    })?;
                let baseline = task.worktree_baseline.as_ref().ok_or_else(|| {
                    ControllerError::InvalidPlan(format!(
                        "materialized recovery worktree {} lacks composed baseline",
                        lease.lease_id
                    ))
                })?;
                if task.worktree_composition != expected_composition
                    || task.worktree_conflict.is_some()
                {
                    return Err(ControllerError::NotReady(format!(
                        "recovery worktree {} composition binding is stale",
                        lease.lease_id
                    )));
                }
                if let Some(expected) = change_set.as_ref()
                    && registry.capture_change_set_from_baseline(&lease, baseline)? != *expected
                {
                    return Err(ControllerError::NotReady(format!(
                        "recovery worktree {} differs from its immutable ChangeSet",
                        lease.lease_id
                    )));
                }
                leases.insert(task_id.clone(), lease.clone());
            }
            Some(WorktreeLifecycle::Conflict) => {
                if !lease.worktree_path.exists() {
                    return Err(ControllerError::NotReady(format!(
                        "conflicted recovery worktree {} is missing",
                        lease.lease_id
                    )));
                }
                registry.validate_worktree_lease(&lease)?;
                let task = controller
                    .active_ref()?
                    .tasks
                    .get(&task_id)
                    .ok_or_else(|| {
                        ControllerError::InvalidPlan("recovery task disappeared".to_owned())
                    })?;
                let conflict = task.worktree_conflict.as_ref().ok_or_else(|| {
                    ControllerError::InvalidPlan(format!(
                        "conflicted recovery worktree {} lacks durable conflict evidence",
                        lease.lease_id
                    ))
                })?;
                let key = active_scoped_key(controller.active_ref()?, &task_id);
                let durable = controller
                    .state
                    .get_state("controller.worktree_conflict", &key)?
                    .ok_or_else(|| {
                        ControllerError::InvalidPlan(format!(
                            "conflicted recovery worktree {} lost conflict record",
                            lease.lease_id
                        ))
                    })?;
                if serde_json::from_str::<CompositionConflictEvidence>(&durable)? != *conflict {
                    return Err(ControllerError::InvalidPlan(format!(
                        "conflicted recovery worktree {} conflict evidence changed",
                        lease.lease_id
                    )));
                }
            }
            Some(WorktreeLifecycle::Released) => {
                if lease.worktree_path.exists() {
                    return Err(ControllerError::NotReady(format!(
                        "released recovery worktree {} unexpectedly still exists",
                        lease.lease_id
                    )));
                }
                if change_set.is_none() {
                    return Err(ControllerError::InvalidPlan(format!(
                        "released recovery worktree {} lacks immutable ChangeSet evidence",
                        lease.lease_id
                    )));
                }
            }
            None => {
                return Err(ControllerError::InvalidPlan(format!(
                    "recovery worktree {} has no lifecycle state",
                    lease.lease_id
                )));
            }
        }
    }
    Ok(leases)
}

#[allow(clippy::too_many_lines)]
fn reconcile_recovery_actions(
    state: &mut StateStore,
    registry: &ProjectRegistry,
    unresolved_process_actions: &BTreeSet<String>,
    manifest: &CheckpointManifest,
    worktrees: &BTreeMap<String, WorktreeLease>,
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
        let raw_intent: PersistedActionIntent = serde_json::from_str(&raw_intent)?;
        let Some(repository) = registry.repository(&raw_intent.repository_id) else {
            unknown.push(record.action_id);
            continue;
        };
        let Ok(intent) = normalize_persisted_action_intent(raw_intent, &repository.root) else {
            unknown.push(record.action_id);
            continue;
        };
        if intent.action_id != record.action_id
            || intent.payload_digest != record.payload_digest
            || intent.policy_digest != record.policy_digest
        {
            unknown.push(record.action_id);
            continue;
        }
        let current = if let Some(lease_id) = intent.worktree_lease_id.as_deref() {
            let Some(lease) = worktrees.get(&intent.task_id) else {
                unknown.push(record.action_id);
                continue;
            };
            if lease.lease_id != lease_id || lease.worktree_path != intent.execution_root {
                unknown.push(record.action_id);
                continue;
            }
            registry.read_worktree_path(lease, Path::new(&intent.path), None)
        } else {
            if intent.execution_root
                != registry
                    .repository(&intent.repository_id)
                    .ok_or_else(|| {
                        ControllerError::InvalidPlan(
                            "recovery intent repository missing".to_owned(),
                        )
                    })?
                    .root
            {
                unknown.push(record.action_id);
                continue;
            }
            ExactRetriever::new(registry).read_path(
                &intent.repository_id,
                Path::new(&intent.path),
                None,
            )
        };
        let Ok(current) = current else {
            unknown.push(record.action_id);
            continue;
        };
        let current_mode = permission_mode(&fs::symlink_metadata(
            intent.execution_root.join(&intent.path),
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
    let primary_root = controller.active_ref()?.repository_root.clone();
    let intents = controller
        .state
        .state_records("controller.action_intent")?
        .into_iter()
        .map(|record| {
            let raw: PersistedActionIntent = serde_json::from_str(&record.value_json)?;
            let intent = normalize_persisted_action_intent(raw, &primary_root)?;
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
    #[serde(default)]
    worktree_lease_id: Option<String>,
    #[serde(default)]
    execution_root: PathBuf,
    path: String,
    expected_source_digest: String,
    old_literal: String,
    new_literal: String,
    expected_post_digest: String,
    expected_target_mode: u32,
    artifact_store_root: PathBuf,
}

fn normalize_persisted_action_intent(
    mut intent: PersistedActionIntent,
    primary_root: &Path,
) -> Result<PersistedActionIntent, ControllerError> {
    match intent.schema_version {
        ACTION_INTENT_SCHEMA_VERSION => {
            if intent.execution_root.as_os_str().is_empty() {
                return Err(ControllerError::NotReady(
                    "v3 recovery action intent lacks an execution root".to_owned(),
                ));
            }
        }
        LEGACY_ACTION_INTENT_SCHEMA_VERSION => {
            // Committed v2 predates WorktreeLease/execution_root. It can only be interpreted as
            // the historical primary-repository execution view; it never gains worktree authority.
            if intent.worktree_lease_id.is_some() || !intent.execution_root.as_os_str().is_empty() {
                return Err(ControllerError::NotReady(
                    "legacy v2 action intent contains fields that did not exist in v2".to_owned(),
                ));
            }
            intent.worktree_lease_id = None;
            intent.execution_root = primary_root.to_path_buf();
            intent.schema_version = ACTION_INTENT_SCHEMA_VERSION;
        }
        _ => {
            return Err(ControllerError::NotReady(
                "recovery action intent schema is unsupported".to_owned(),
            ));
        }
    }
    Ok(intent)
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
    legacy_primary_recovery: bool,
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
            legacy_primary_recovery: false,
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
    #[allow(clippy::too_many_lines)]
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
        let execution_lease = if lease.legacy_primary_recovery {
            None
        } else {
            active_task_execution_lease(active, &lease.task_id)?
        };
        let execution_root = execution_lease.map_or(active.repository_root.as_path(), |worktree| {
            worktree.worktree_path.as_path()
        });
        let post_snapshot = match execution_lease {
            Some(worktree) => registry.worktree_snapshot(worktree)?,
            None => registry.snapshot(&active.repository_id)?,
        };
        let post_snapshot_digest = snapshot_digest(&post_snapshot)?;
        let file = match execution_lease {
            Some(worktree) => {
                registry.read_worktree_path(worktree, Path::new(&validated.proposal.path), None)?
            }
            None => ExactRetriever::new(registry).read_path(
                &active.repository_id,
                Path::new(&validated.proposal.path),
                None,
            )?,
        };
        let observed_target_mode = permission_mode(&fs::symlink_metadata(
            execution_root.join(&validated.proposal.path),
        )?);
        let diff = match execution_lease {
            Some(worktree) => registry.worktree_diff(worktree)?,
            None => ExactRetriever::new(registry).current_diff(&active.repository_id)?,
        };
        let action_record = state.action_record(action_id)?;
        let action_committed = action_record
            .as_ref()
            .is_some_and(|record| record.state == "committed" && record.result_digest.is_some());
        let expected_path = PathBuf::from(&validated.proposal.path);
        let repository_failure = repository_verification_failure(
            active,
            attempt,
            lease,
            &post_snapshot,
            &expected_path,
            execution_root,
            execution_lease.is_some(),
        );
        let freshness_ok = required_array(&task.task, "/acceptance_criteria")?
            .iter()
            .all(|criterion| {
                matches!(
                    criterion.get("evidence_freshness").and_then(Value::as_str),
                    Some(
                        "current_attempt"
                            | "current_task_revision"
                            | "carry_forward_if_inputs_unchanged"
                    )
                )
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
    execution_root: &Path,
    controller_worktree: bool,
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
        || (!controller_worktree
            && (attempt.pre_diff_digest != active.baseline_diff_digest
                || sha256_prefixed(active.baseline_diff_content.as_bytes())
                    != active.baseline_diff_digest))
    {
        return Some("pre_attempt_baseline_binding_invalid".to_owned());
    }
    if !protected_preexisting_changes_unchanged(execution_root, attempt, expected_path) {
        return Some("protected_preexisting_change_modified".to_owned());
    }
    None
}

fn active_task_execution_lease<'a>(
    active: &'a ActivePlan,
    task_id: &str,
) -> Result<Option<&'a WorktreeLease>, ControllerError> {
    let mode = required_str(&active.plan_document, "/depth/mode")?;
    if !matches!(mode, "D3" | "D4") {
        return Ok(None);
    }
    let task = active
        .tasks
        .get(task_id)
        .ok_or_else(|| ControllerError::InvalidPlan(format!("unknown task {task_id}")))?;
    if task.worktree_state != Some(WorktreeLifecycle::Materialized) {
        return Err(ControllerError::NotReady(
            "D3/D4 verification requires a materialized controller worktree".to_owned(),
        ));
    }
    task.worktree_lease
        .as_ref()
        .map(Some)
        .ok_or_else(|| ControllerError::NotReady("D3/D4 worktree lease is missing".to_owned()))
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

fn controller_failure_code(error: &ControllerError) -> &'static str {
    match error {
        ControllerError::ProposalRejected(message) => proposal_rejection_code(message),
        ControllerError::Model(ModelError::InvalidContract(_)) => "model_invalid_contract",
        ControllerError::Model(ModelError::InvalidResponse(_)) => "model_invalid_response",
        ControllerError::Model(ModelError::NotLoaded) => "model_not_loaded",
        ControllerError::Model(ModelError::AlreadyLoaded) => "model_already_loaded",
        ControllerError::Model(ModelError::LeaseUnavailable(_)) => "model_lease_unavailable",
        ControllerError::Model(ModelError::DeadlineExceeded(_)) => "model_deadline_exceeded",
        ControllerError::Model(ModelError::ProviderStatus { .. }) => "model_provider_status",
        ControllerError::Model(ModelError::ProviderExited(_)) => "model_provider_exited",
        ControllerError::Model(ModelError::HttpProtocol(_)) => "model_http_protocol",
        ControllerError::Model(ModelError::Io(_)) => "model_io",
        ControllerError::Model(ModelError::Json(_)) => "model_json",
        ControllerError::Model(ModelError::LockPoisoned(_)) => "model_lock_poisoned",
        ControllerError::Repo(_) => "repository_error",
        ControllerError::Policy(_) => "policy_error",
        ControllerError::Tool(_) => "tool_error",
        ControllerError::Evidence(_) => "evidence_error",
        ControllerError::Memory(_) => "memory_error",
        ControllerError::Json(_) => "json_error",
        ControllerError::Io(_) => "io_error",
        ControllerError::InvalidPlan(_) => "invalid_plan",
        ControllerError::NotReady(_) => "not_ready",
        ControllerError::ExecutionFailed(_) => "execution_failed",
        ControllerError::VerificationFailed(_) => "verification_failed",
        ControllerError::UnknownAction(_) => "unknown_action",
        ControllerError::State(_) => "state_error",
    }
}

fn proposal_rejection_code(message: &str) -> &'static str {
    if message.starts_with("strict ModelProposalV1 decode failed") {
        "proposal_decode"
    } else if message.contains("finish normally without model tool calls") {
        "proposal_finish_contract"
    } else if message.contains("unsupported ModelProposalV1 schema_version") {
        "proposal_schema_version"
    } else if message.contains("evidence_ids violate deterministic bounds") {
        "proposal_evidence_bounds"
    } else if message.contains("evidence outside the current ContextPacket") {
        "proposal_evidence_outside_context"
    } else if message.contains("violates deterministic M1 bounds") {
        "replace_literal_bounds"
    } else if message.contains("outside exact active task scope") {
        "replace_literal_scope"
    } else if message.contains("pre-existing user-owned target hunk") {
        "replace_literal_user_hunk"
    } else if message.contains("immutable compiled literal contract") {
        "replace_literal_contract"
    } else if message.contains("preimage does not contain exactly one old literal") {
        "replace_literal_preimage_count"
    } else if message.contains("regular non-symlink file") {
        "replace_literal_target_type"
    } else {
        "proposal_rejected"
    }
}

fn tool_error_code(error: &ToolError) -> &'static str {
    match error {
        ToolError::Policy(PolicyError::Denied(_)) => "tool_policy_denied",
        ToolError::Policy(PolicyError::IsolationUnavailable(_)) => "tool_isolation_unavailable",
        ToolError::Policy(PolicyError::ResourceDenied(_)) => "tool_policy_resource_denied",
        ToolError::Policy(PolicyError::Io(_)) => "tool_policy_io",
        ToolError::State(_) => "tool_state",
        ToolError::Evidence(_) => "tool_evidence",
        ToolError::Io(_) => "tool_io",
        ToolError::Authority(_) => "tool_authority",
        ToolError::InvalidTransition(_) => "tool_invalid_transition",
        ToolError::ResourceLimit(_) => "tool_resource_limit",
        ToolError::RecoveryBlocked(_) => "tool_recovery_blocked",
        ToolError::Clock(_) => "tool_clock",
    }
}

fn proposal_action_facts(proposal: &ModelProposalV1) -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "repository_id".to_owned(),
            proposal.action.repository_id.clone(),
        ),
        ("path".to_owned(), proposal.action.path.clone()),
        (
            "expected_source_digest".to_owned(),
            proposal.action.expected_source_digest.clone(),
        ),
        (
            "old_literal".to_owned(),
            bounded_failure_text(&proposal.action.old_literal, 256),
        ),
        (
            "new_literal".to_owned(),
            bounded_failure_text(&proposal.action.new_literal, 256),
        ),
        (
            "expected_occurrences".to_owned(),
            proposal.action.expected_occurrences.to_string(),
        ),
    ])
}

fn failure_synopsis(
    category: &str,
    failure_code: &str,
    diagnostic: &str,
    facts: &BTreeMap<String, String>,
) -> String {
    let mut result = format!(
        "category={category}; code={failure_code}; diagnostic={}",
        bounded_failure_text(diagnostic, 512)
    );
    if !facts.is_empty() {
        result.push_str("; failed_action={");
        for (index, (key, value)) in facts.iter().enumerate() {
            if index > 0 {
                result.push_str(", ");
            }
            result.push_str(key);
            result.push('=');
            result.push_str(&bounded_failure_text(value, 256));
        }
        result.push('}');
    }
    bounded_failure_text(&result, 1_536)
}

fn normalized_failure_signature(
    category: &str,
    failure_code: &str,
    diagnostic: &str,
    facts: &BTreeMap<String, String>,
) -> String {
    let mut stable = format!(
        "{}\0{}\0{}",
        normalized_failure_token(category),
        normalized_failure_token(failure_code),
        normalize_failure_diagnostic(diagnostic)
    );
    for (key, value) in facts {
        if matches!(
            key.as_str(),
            "action_id" | "expected_source_digest" | "result_digest"
        ) {
            continue;
        }
        stable.push('\0');
        stable.push_str(key);
        stable.push('=');
        stable.push_str(&normalize_failure_diagnostic(value));
    }
    let digest = sha256_prefixed(stable.as_bytes());
    format!(
        "{}:{}:{}",
        normalized_failure_token(category),
        normalized_failure_token(failure_code),
        digest_fragment(&digest, 16)
    )
}

fn normalize_failure_diagnostic(value: &str) -> String {
    value
        .split_whitespace()
        .map(normalize_failure_word)
        .collect::<Vec<_>>()
        .join(" ")
}

fn normalize_failure_word(value: &str) -> String {
    let lower = value.to_ascii_lowercase();
    for separator in ['=', ':'] {
        if let Some((key, _)) = lower.split_once(separator) {
            let normalized_key = key.trim_matches(|character: char| {
                !(character.is_ascii_alphanumeric() || character == '_' || character == '-')
            });
            if matches!(
                normalized_key,
                "request_id"
                    | "request-id"
                    | "request"
                    | "attempt_id"
                    | "attempt-id"
                    | "attempt"
                    | "action_id"
                    | "action-id"
                    | "timestamp"
                    | "time"
            ) {
                return format!("{normalized_key}=<volatile>");
            }
        }
    }
    let token = lower.trim_matches(|character: char| {
        !(character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
    });
    let mixed_long_identifier = token.len() >= 16
        && token
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
        && token.chars().any(|character| character.is_ascii_digit())
        && token
            .chars()
            .any(|character| character.is_ascii_alphabetic());
    if token.starts_with("req-")
        || token.starts_with("req_")
        || token.starts_with("request-")
        || mixed_long_identifier
    {
        return "<volatile>".to_owned();
    }
    if let Some(index) = lower.find("sha256:") {
        let digest_start = index.saturating_add(7);
        let digest_end = digest_start.saturating_add(64);
        if lower
            .as_bytes()
            .get(digest_start..digest_end)
            .is_some_and(|digest| digest.iter().all(u8::is_ascii_hexdigit))
        {
            let mut result = lower[..digest_start].to_owned();
            result.push_str("<digest>");
            result.push_str(&lower[digest_end..]);
            return result;
        }
    }
    let mut result = String::with_capacity(lower.len());
    let mut in_digits = false;
    for character in lower.chars() {
        if character.is_ascii_digit() {
            if !in_digits {
                result.push('#');
                in_digits = true;
            }
        } else {
            in_digits = false;
            result.push(character);
        }
    }
    result
}

fn normalized_failure_token(value: &str) -> String {
    value
        .chars()
        .filter_map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '_' | '-') {
                Some(character.to_ascii_lowercase())
            } else {
                None
            }
        })
        .take(64)
        .collect()
}

fn raw_tool_failure_diagnostic(result: &RawToolResult) -> String {
    let stderr = String::from_utf8_lossy(&result.stderr);
    let stdout = String::from_utf8_lossy(&result.stdout);
    let primary = stderr
        .lines()
        .chain(stdout.lines())
        .find(|line| {
            let lower = line.to_ascii_lowercase();
            lower.contains("error") || lower.contains("failed") || lower.contains("panic")
        })
        .or_else(|| stderr.lines().find(|line| !line.trim().is_empty()))
        .or_else(|| stdout.lines().find(|line| !line.trim().is_empty()))
        .map_or(
            "process exited without a retained diagnostic line",
            str::trim,
        );
    bounded_failure_text(primary, 512)
}

fn bounded_failure_text(value: &str, max_chars: usize) -> String {
    let mut result = value.chars().take(max_chars).collect::<String>();
    if value.chars().count() > max_chars {
        result.push('…');
    }
    result
}

fn repair_task_contract_projection(
    task_id: &str,
    task_contract_digest: &str,
    acceptance_contract_digest: &str,
    task: &Value,
) -> Result<String, ControllerError> {
    let scope = task.pointer("/scope").cloned().unwrap_or(Value::Null);
    let outputs = task
        .pointer("/implementation_contract/outputs")
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));
    let invariants = task
        .pointer("/implementation_contract/invariants")
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));
    let non_goals = task
        .pointer("/implementation_contract/non_goals")
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));
    let acceptance = required_array(task, "/acceptance_criteria")?
        .iter()
        .map(|criterion| {
            json!({
                "criterion_id": criterion.get("criterion_id"),
                "description": criterion.get("description"),
                "kind": criterion.get("kind"),
                "required": criterion.get("required"),
            })
        })
        .collect::<Vec<_>>();
    let projection = json!({
        "task_id": task_id,
        "task_contract_digest": task_contract_digest,
        "acceptance_contract_digest": acceptance_contract_digest,
        "title": task.get("title"),
        "objective": task.get("objective"),
        "scope": scope,
        "outputs": outputs,
        "invariants": invariants,
        "non_goals": non_goals,
        "acceptance": acceptance,
        "constraints": task.get("constraints"),
    });
    Ok(serde_json::to_string(&canonicalize(&projection))?)
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
        ) | (
            TaskState::Running,
            TaskState::Verifying
                | TaskState::RepairPending
                | TaskState::DeferredResource
                | TaskState::ReconcilingUnknown
                | TaskState::FailedTerminal
        ) | (
            TaskState::Verifying,
            TaskState::Succeeded | TaskState::RepairPending | TaskState::FailedTerminal
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
            lease.permission_decision.digest(),
            lease.resource_digest,
            lease.execution_epoch,
        )
        .as_bytes(),
    )
}

fn capability_set_from_json_array(values: &[Value]) -> Result<CapabilitySet, ControllerError> {
    let mut capabilities = Vec::with_capacity(values.len());
    for value in values {
        let value = value.as_str().ok_or_else(|| {
            ControllerError::InvalidPlan("capability must be a string".to_owned())
        })?;
        let capability = Capability::from_plan_ir_str(value).ok_or_else(|| {
            ControllerError::InvalidPlan(format!("unknown Plan IR capability {value}"))
        })?;
        capabilities.push(capability);
    }
    Ok(CapabilitySet::new(capabilities))
}

fn capability_set_from_strings<'a, I>(values: I) -> Result<CapabilitySet, ControllerError>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut capabilities = Vec::new();
    for value in values {
        let capability = Capability::from_plan_ir_str(value).ok_or_else(|| {
            ControllerError::InvalidPlan(format!("unknown Plan IR capability {value}"))
        })?;
        capabilities.push(capability);
    }
    Ok(CapabilitySet::new(capabilities))
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

fn revision_scoped_key(plan_id: &str, revision: u32, logical_key: &str) -> String {
    if revision == 1 {
        logical_key.to_owned()
    } else {
        format!("{plan_id}@r{revision}:{logical_key}")
    }
}

fn revision_scoped_prefix(plan_id: &str, revision: u32) -> Option<String> {
    (revision > 1).then(|| format!("{plan_id}@r{revision}:"))
}

fn key_belongs_to_revision(key: &str, plan_id: &str, revision: u32) -> bool {
    revision_scoped_prefix(plan_id, revision)
        .map_or_else(|| !key.contains("@r"), |prefix| key.starts_with(&prefix))
}

fn logical_key_for_revision(key: &str, plan_id: &str, revision: u32) -> Option<String> {
    if revision == 1 {
        (!key.contains("@r")).then(|| key.to_owned())
    } else {
        key.strip_prefix(&format!("{plan_id}@r{revision}:"))
            .map(str::to_owned)
    }
}

fn active_scoped_key(active: &ActivePlan, logical_key: &str) -> String {
    revision_scoped_key(&active.plan_id, active.revision, logical_key)
}

fn validate_durable_change_set_binding(
    state: &StateStore,
    record_key: &str,
    task_id: &str,
    runtime: &TaskRuntime,
) -> Result<ChangeSet, ControllerError> {
    let change_set = runtime.change_set.clone().ok_or_else(|| {
        ControllerError::NotReady(format!(
            "task {task_id} lacks immutable ChangeSet authority"
        ))
    })?;
    let serialized = serde_json::to_string(&change_set)?;
    let durable_raw = state
        .get_state("controller.change_set", record_key)?
        .ok_or_else(|| {
            ControllerError::NotReady(format!("task {task_id} lost durable ChangeSet evidence"))
        })?;
    if durable_raw != serialized {
        return Err(ControllerError::NotReady(format!(
            "task {task_id} ChangeSet differs from durable immutable evidence"
        )));
    }
    let expected_artifact_digest = format!("{:x}", Sha256::digest(serialized.as_bytes()));
    if runtime.change_set_artifact_digest.as_deref() != Some(expected_artifact_digest.as_str()) {
        return Err(ControllerError::NotReady(format!(
            "task {task_id} ChangeSet artifact binding does not match exact durable bytes"
        )));
    }
    if state
        .artifact_metadata(&expected_artifact_digest)?
        .is_none()
    {
        return Err(ControllerError::NotReady(format!(
            "task {task_id} lost exact ChangeSet artifact"
        )));
    }
    Ok(change_set)
}

fn revision_record_key(plan_id: &str, revision: u32) -> String {
    format!("{plan_id}@r{revision}")
}

fn dependency_closure_order(
    tasks: &BTreeMap<String, TaskRuntime>,
    task_id: &str,
) -> Result<Vec<String>, ControllerError> {
    let target = tasks
        .get(task_id)
        .ok_or_else(|| ControllerError::InvalidPlan(format!("unknown task {task_id}")))?;
    let mut closure = BTreeSet::new();
    let mut stack = required_array(&target.task, "/dependencies")?
        .iter()
        .map(|value| {
            value.as_str().map(str::to_owned).ok_or_else(|| {
                ControllerError::InvalidPlan("dependency task id must be a string".to_owned())
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    while let Some(current) = stack.pop() {
        if !closure.insert(current.clone()) {
            continue;
        }
        let runtime = tasks.get(&current).ok_or_else(|| {
            ControllerError::InvalidPlan(format!("unknown dependency task {current}"))
        })?;
        for dependency in required_array(&runtime.task, "/dependencies")? {
            stack.push(
                dependency
                    .as_str()
                    .ok_or_else(|| {
                        ControllerError::InvalidPlan(
                            "dependency task id must be a string".to_owned(),
                        )
                    })?
                    .to_owned(),
            );
        }
    }

    let mut remaining = closure;
    let mut emitted = BTreeSet::new();
    let mut ordered = Vec::new();
    while !remaining.is_empty() {
        let next = remaining.iter().find(|candidate| {
            tasks.get(*candidate).is_some_and(|runtime| {
                required_array(&runtime.task, "/dependencies").is_ok_and(|dependencies| {
                    dependencies.iter().all(|dependency| {
                        dependency.as_str().is_some_and(|dependency_id| {
                            !remaining.contains(dependency_id) || emitted.contains(dependency_id)
                        })
                    })
                })
            })
        });
        let Some(next) = next.cloned() else {
            return Err(ControllerError::InvalidPlan(
                "task dependency graph is cyclic or malformed during ChangeSet composition"
                    .to_owned(),
            ));
        };
        remaining.remove(&next);
        emitted.insert(next.clone());
        ordered.push(next);
    }
    Ok(ordered)
}

fn fresh_task_runtime(task: &Value) -> Result<TaskRuntime, ControllerError> {
    Ok(TaskRuntime {
        state: TaskState::Planned,
        attempts_started: 0,
        model_calls_used: 0,
        failure_counts: BTreeMap::new(),
        retry_exhausted: false,
        resource_deferrals_used: 0,
        resource_retry_exhausted: false,
        resource_deferred_from: None,
        worktree_lease: None,
        worktree_state: None,
        change_set: None,
        change_set_artifact_digest: None,
        change_set_carry: None,
        worktree_baseline: None,
        worktree_composition: Vec::new(),
        worktree_conflict: None,
        task_contract_digest: digest_json(task)?,
        task: task.clone(),
    })
}

fn acceptance_permits_cross_revision_carry(task: &Value) -> Result<bool, ControllerError> {
    Ok(required_array(task, "/acceptance_criteria")?
        .iter()
        .filter(|criterion| criterion.get("required").and_then(Value::as_bool) == Some(true))
        .all(|criterion| {
            criterion.get("evidence_freshness").and_then(Value::as_str)
                == Some("carry_forward_if_inputs_unchanged")
        }))
}

fn dependency_bindings_permit_cross_revision_carry(task: &Value) -> Result<bool, ControllerError> {
    Ok(required_array(task, "/dependency_bindings")?
        .iter()
        .all(|binding| {
            binding.get("freshness").and_then(Value::as_str)
                == Some("carry_forward_if_inputs_unchanged")
        }))
}

fn task_inputs_digest(task: &Value) -> Result<String, ControllerError> {
    Ok(digest_json(
        task.pointer("/implementation_contract/inputs")
            .ok_or_else(|| ControllerError::InvalidPlan("task inputs missing".to_owned()))?,
    )?)
}

fn task_dependency_contract_digest(task: &Value) -> Result<String, ControllerError> {
    Ok(digest_json(task.get("dependency_bindings").ok_or_else(
        || ControllerError::InvalidPlan("task bindings missing".to_owned()),
    )?)?)
}

fn plan_instruction_fingerprint_digest(plan: &Value) -> Result<String, ControllerError> {
    Ok(digest_json(
        plan.pointer("/repositories/0/instructions")
            .ok_or_else(|| {
                ControllerError::InvalidPlan("repository instructions missing".to_owned())
            })?,
    )?)
}

fn scope_lineage_id(
    state: &StateStore,
    active: &ActivePlan,
    classification: &FailureClassification,
) -> Result<String, ControllerError> {
    let mut existing = BTreeSet::new();
    for task_id in &classification.affected_task_ids {
        let key = active_scoped_key(active, task_id);
        if let Some(raw) = state.get_state("controller.replan_task_lineage", &key)? {
            let value: Value = serde_json::from_str(&raw)?;
            let lineage_id = required_str(&value, "/lineage_id")?;
            existing.insert(lineage_id.to_owned());
        }
    }
    if existing.len() > 1 {
        return Err(ControllerError::InvalidPlan(format!(
            "replan scope has ambiguous inherited lineages: {}",
            existing.into_iter().collect::<Vec<_>>().join(",")
        )));
    }
    if let Some(lineage_id) = existing.into_iter().next() {
        return Ok(lineage_id);
    }
    let digest = digest_json(&json!({
        "plan_id": active.plan_id,
        "scope": classification.scope,
        "initial_affected_task_ids": classification.affected_task_ids,
    }))?;
    Ok(format!("replan-lineage.{}", digest_fragment(&digest, 32)))
}

fn process_lease_is_terminal(lease: &RecoveryProcessLease) -> bool {
    lease.schema_version == RECOVERY_PROCESS_LEASE_SCHEMA_VERSION
        && matches!(lease.state.as_str(), "reaped" | "reaped_recovery")
}

fn has_unresolved_process_lease(state: &StateStore) -> Result<bool, ControllerError> {
    for record in state.state_records("controller.process_lease")? {
        let lease: RecoveryProcessLease = serde_json::from_str(&record.value_json)?;
        if !process_lease_is_terminal(&lease) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn lineage_records_for_supersession(
    state: &StateStore,
    previous: &ActivePlan,
    diff: &PlanRevisionDiff,
    lineage_id: &str,
) -> Result<Vec<(String, String, String)>, ControllerError> {
    let changed_or_added = diff
        .changed_task_ids
        .iter()
        .chain(&diff.added_task_ids)
        .cloned()
        .collect::<BTreeSet<_>>();
    let next_revision = diff.to_revision;
    let mut records = Vec::new();
    for task_id in diff
        .unchanged_task_ids
        .iter()
        .chain(&diff.changed_task_ids)
        .chain(&diff.added_task_ids)
    {
        let inherited = if changed_or_added.contains(task_id) {
            Some(lineage_id.to_owned())
        } else {
            let old_key = revision_scoped_key(&previous.plan_id, previous.revision, task_id);
            state
                .get_state("controller.replan_task_lineage", &old_key)?
                .map(|raw| -> Result<String, ControllerError> {
                    let value: Value = serde_json::from_str(&raw)?;
                    if required_str(&value, "/plan_id")? != previous.plan_id
                        || required_u32(&value, "/revision")? != previous.revision
                        || required_str(&value, "/task_id")? != task_id
                    {
                        return Err(ControllerError::InvalidPlan(format!(
                            "replan lineage record for {task_id} is misbound"
                        )));
                    }
                    Ok(required_str(&value, "/lineage_id")?.to_owned())
                })
                .transpose()?
        };
        if let Some(task_lineage_id) = inherited {
            records.push((
                "controller.replan_task_lineage".to_owned(),
                revision_scoped_key(&previous.plan_id, next_revision, task_id),
                serde_json::to_string(&json!({
                    "plan_id": previous.plan_id,
                    "revision": next_revision,
                    "task_id": task_id,
                    "lineage_id": task_lineage_id,
                }))?,
            ));
        }
    }
    Ok(records)
}

struct SupersedingRuntimeBuild {
    tasks: BTreeMap<String, TaskRuntime>,
    carry_records: Vec<(String, String, String)>,
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn build_superseding_runtime(
    state: &StateStore,
    registry: &ProjectRegistry,
    previous: &ActivePlan,
    next_plan: &Value,
    next_plan_digest: &str,
    next_compilation_evidence: &Value,
    diff: &PlanRevisionDiff,
    current_snapshot_digest: &str,
) -> Result<SupersedingRuntimeBuild, ControllerError> {
    let next_revision = diff.to_revision;
    let next_task_values = required_array(next_plan, "/tasks")?;
    let next_task_map = next_task_values
        .iter()
        .map(|task| Ok((required_str(task, "/task_id")?.to_owned(), task)))
        .collect::<Result<BTreeMap<_, _>, ControllerError>>()?;
    let unchanged = diff
        .unchanged_task_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut tasks = BTreeMap::new();
    let mut carry_records = Vec::new();
    let instruction_digest = plan_instruction_fingerprint_digest(next_plan)?;
    let mut local_carry_candidates = BTreeMap::new();
    let previous_uses_worktrees = previous
        .plan_document
        .pointer("/depth/mode")
        .and_then(Value::as_str)
        .is_some_and(|mode| matches!(mode, "D3" | "D4"));

    for (task_id, task) in &next_task_map {
        let mut runtime = fresh_task_runtime(task)?;
        if unchanged.contains(task_id) {
            let previous_runtime = previous.tasks.get(task_id).ok_or_else(|| {
                ControllerError::InvalidPlan(format!(
                    "unchanged task {task_id} is missing from previous runtime"
                ))
            })?;
            if previous_runtime.task_contract_digest != runtime.task_contract_digest
                || previous_runtime.task != **task
            {
                return Err(ControllerError::InvalidPlan(format!(
                    "unchanged task {task_id} contract differs across revisions"
                )));
            }
            runtime.attempts_started = previous_runtime.attempts_started;
            runtime.model_calls_used = previous_runtime.model_calls_used;
            runtime.failure_counts = previous_runtime.failure_counts.clone();
            runtime.retry_exhausted = previous_runtime.retry_exhausted;
            runtime.resource_deferrals_used = previous_runtime.resource_deferrals_used;
            runtime.resource_retry_exhausted = previous_runtime.resource_retry_exhausted;
            runtime.resource_deferred_from = previous_runtime.resource_deferred_from;
            runtime.state = if previous_runtime.retry_exhausted {
                TaskState::RepairPending
            } else if previous_runtime.resource_retry_exhausted {
                TaskState::DeferredResource
            } else {
                TaskState::Planned
            };

            if previous_runtime.state == TaskState::Succeeded
                && acceptance_permits_cross_revision_carry(task)?
                && dependency_bindings_permit_cross_revision_carry(task)?
                && compilation_inputs_are_fresh_for_carry(
                    state,
                    registry,
                    previous,
                    task,
                    next_compilation_evidence,
                )?
            {
                let old_key = revision_scoped_key(&previous.plan_id, previous.revision, task_id);
                if let Some(raw) = state.get_state("controller.task_carry_fingerprint", &old_key)? {
                    let proof: TaskCarryFingerprintV1 = serde_json::from_str(&raw)?;
                    let source_fresh = if previous_uses_worktrees {
                        proof.execution_provenance.is_some()
                            && task_carry_execution_provenance(previous, task_id)?
                                == proof.execution_provenance
                    } else {
                        proof.execution_provenance.is_none()
                            && proof.source_fingerprints.iter().all(|(path, fingerprint)| {
                                path_fingerprint(&previous.repository_root, Path::new(path))
                                    .is_ok_and(|current| current == *fingerprint)
                            })
                    };
                    let proof_matches = proof.schema_version
                        == TASK_CARRY_FINGERPRINT_SCHEMA_VERSION
                        && proof.plan_id == previous.plan_id
                        && proof.plan_revision == previous.revision
                        && proof.plan_digest == previous.plan_digest
                        && proof.task_id == *task_id
                        && proof.task_contract_digest == runtime.task_contract_digest
                        && proof.implementation_inputs_digest == task_inputs_digest(task)?
                        && proof.dependency_contract_digest
                            == task_dependency_contract_digest(task)?
                        && proof.instruction_fingerprint_digest == instruction_digest
                        && source_fresh;
                    let verification_ok = if proof_matches
                        && state
                            .artifact_metadata(&proof.verification_artifact_digest)?
                            .is_some()
                    {
                        state
                            .get_state(
                                "controller.verification",
                                &revision_scoped_key(
                                    &proof.plan_id,
                                    proof.plan_revision,
                                    &proof.verification_id,
                                ),
                            )?
                            .is_some_and(|verification_raw| {
                                serde_json::from_str::<VerificationResultV1>(&verification_raw)
                                    .is_ok_and(|verification| {
                                        verification.passed
                                            && verification.task_id == *task_id
                                            && verification.task_contract_digest
                                                == runtime.task_contract_digest
                                    })
                            })
                    } else {
                        false
                    };
                    let worktree_carry_ok = if previous_uses_worktrees {
                        validate_durable_change_set_binding(
                            state,
                            &old_key,
                            task_id,
                            previous_runtime,
                        )
                        .is_ok()
                    } else {
                        true
                    };
                    if verification_ok && worktree_carry_ok {
                        local_carry_candidates.insert(task_id.clone(), proof);
                    }
                }
            }
        }
        tasks.insert(task_id.clone(), runtime);
    }

    // Cross-revision carry must be dependency-closed in N+1, not merely valid
    // against historical N outputs. Resolve roots first and then transitively
    // admit dependents only after every hard upstream itself carried into N+1.
    let mut carried_task_ids = BTreeSet::new();
    loop {
        let mut changed = false;
        for (task_id, proof) in &local_carry_candidates {
            if carried_task_ids.contains(task_id) {
                continue;
            }
            let task = next_task_map.get(task_id).ok_or_else(|| {
                ControllerError::InvalidPlan(format!(
                    "carry candidate {task_id} disappeared from superseding plan"
                ))
            })?;
            if !validate_prior_dependency_outputs_for_carry(
                state,
                previous,
                task,
                &next_task_map,
                &carried_task_ids,
            )? {
                continue;
            }
            let runtime = tasks.get_mut(task_id).ok_or_else(|| {
                ControllerError::InvalidPlan(format!(
                    "carry candidate {task_id} disappeared from superseding runtime"
                ))
            })?;
            runtime.state = TaskState::Succeeded;
            let previous_runtime = previous.tasks.get(task_id).ok_or_else(|| {
                ControllerError::InvalidPlan(format!(
                    "carry candidate {task_id} disappeared from previous runtime"
                ))
            })?;
            if previous_uses_worktrees {
                let change_set = previous_runtime.change_set.clone().ok_or_else(|| {
                    ControllerError::InvalidPlan(format!(
                        "D3/D4 carry candidate {task_id} lost immutable ChangeSet provenance"
                    ))
                })?;
                let artifact_digest = previous_runtime
                    .change_set_artifact_digest
                    .clone()
                    .ok_or_else(|| {
                        ControllerError::InvalidPlan(format!(
                            "D3/D4 carry candidate {task_id} lost ChangeSet artifact provenance"
                        ))
                    })?;
                let source_change_set_digest = change_set.digest()?;
                runtime.change_set = Some(change_set.clone());
                runtime.change_set_artifact_digest = Some(artifact_digest);
                runtime.change_set_carry = Some(CarriedChangeSetProvenanceV1 {
                    from_revision: previous.revision,
                    to_revision: next_revision,
                    source_change_set_digest,
                });
                // Old worktree leases are never carried. Only immutable verified ChangeSet evidence
                // is rebound as N+1 composition input; a fresh N+1 lease is required for mutation.
                runtime.worktree_lease = None;
                runtime.worktree_state = None;
                runtime.worktree_baseline = None;
                runtime.worktree_composition.clear();
                runtime.worktree_conflict = None;
                carry_records.push((
                    "controller.change_set".to_owned(),
                    revision_scoped_key(&previous.plan_id, next_revision, task_id),
                    serde_json::to_string(&change_set)?,
                ));
            }
            let mut next_proof = proof.clone();
            next_proof.plan_revision = next_revision;
            next_plan_digest.clone_into(&mut next_proof.plan_digest);
            carry_records.push((
                "controller.task_carry_fingerprint".to_owned(),
                revision_scoped_key(&previous.plan_id, next_revision, task_id),
                serde_json::to_string(&next_proof)?,
            ));
            carry_verified_output_records(
                state,
                previous,
                next_revision,
                next_plan_digest,
                current_snapshot_digest,
                task,
                &next_proof,
                &mut carry_records,
            )?;
            carried_task_ids.insert(task_id.clone());
            changed = true;
        }
        if !changed {
            break;
        }
    }
    Ok(SupersedingRuntimeBuild {
        tasks,
        carry_records,
    })
}

fn validate_prior_dependency_outputs_for_carry(
    state: &StateStore,
    previous: &ActivePlan,
    task: &Value,
    next_task_map: &BTreeMap<String, &Value>,
    carried_task_ids: &BTreeSet<String>,
) -> Result<bool, ControllerError> {
    for binding in required_array(task, "/dependency_bindings")? {
        if binding.get("freshness").and_then(Value::as_str)
            != Some("carry_forward_if_inputs_unchanged")
        {
            return Ok(false);
        }
        let upstream_id = required_str(binding, "/upstream_task_id")?;
        let Some(old_upstream) = previous.tasks.get(upstream_id) else {
            return Ok(false);
        };
        let Some(new_upstream) = next_task_map.get(upstream_id) else {
            return Ok(false);
        };
        if !carried_task_ids.contains(upstream_id)
            || old_upstream.state != TaskState::Succeeded
            || old_upstream.task_contract_digest != digest_json(new_upstream)?
        {
            return Ok(false);
        }
        for (namespace, pointer) in [
            ("controller.artifact_binding", "/required_artifact_ids"),
            (
                "controller.acceptance_binding",
                "/required_acceptance_criterion_ids",
            ),
        ] {
            for binding_id in required_array(binding, pointer)? {
                let binding_id = binding_id.as_str().ok_or_else(|| {
                    ControllerError::InvalidPlan("dependency binding id must be string".to_owned())
                })?;
                let key = revision_scoped_key(
                    &previous.plan_id,
                    previous.revision,
                    &output_binding_key(upstream_id, binding_id),
                );
                let Some(raw) = state.get_state(namespace, &key)? else {
                    return Ok(false);
                };
                let record: VerifiedOutputBindingV1 = serde_json::from_str(&raw)?;
                if record.plan_id != previous.plan_id
                    || record.plan_revision != previous.revision
                    || record.plan_digest != previous.plan_digest
                    || record.task_contract_digest != old_upstream.task_contract_digest
                    || state
                        .artifact_metadata(&record.verification_artifact_digest)?
                        .is_none()
                {
                    return Ok(false);
                }
            }
        }
    }
    Ok(true)
}

fn compilation_inputs_are_fresh_for_carry(
    state: &StateStore,
    registry: &ProjectRegistry,
    previous: &ActivePlan,
    task: &Value,
    next_compilation_evidence: &Value,
) -> Result<bool, ControllerError> {
    let previous_evidence_raw = state
        .get_state(
            "controller.compilation_evidence",
            &revision_record_key(&previous.plan_id, previous.revision),
        )?
        .ok_or_else(|| {
            ControllerError::NotReady(
                "previous revision lacks durable compilation input fingerprints".to_owned(),
            )
        })?;
    let previous_evidence: Value = serde_json::from_str(&previous_evidence_raw)?;
    let previous_handles = previous_evidence
        .get("exact_evidence")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            ControllerError::InvalidPlan(
                "previous compilation evidence lacks exact_evidence".to_owned(),
            )
        })?;
    let next_handles = next_compilation_evidence
        .get("exact_evidence")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            ControllerError::InvalidPlan(
                "next compilation evidence lacks exact_evidence".to_owned(),
            )
        })?;
    for input in required_array(task, "/implementation_contract/inputs")? {
        let input = input.as_str().ok_or_else(|| {
            ControllerError::InvalidPlan("task implementation input must be a string".to_owned())
        })?;
        let Some((evidence_id, expected_source_digest)) = input.split_once(' ') else {
            return Ok(false);
        };
        let Some(old_handle) = previous_handles.iter().find(|handle| {
            handle.get("evidence_id").and_then(Value::as_str) == Some(evidence_id)
                && handle.get("source_digest").and_then(Value::as_str)
                    == Some(expected_source_digest)
        }) else {
            return Ok(false);
        };
        let Some(next_handle) = next_handles.iter().find(|handle| {
            handle.get("evidence_id").and_then(Value::as_str) == Some(evidence_id)
                && handle.get("source_digest").and_then(Value::as_str)
                    == Some(expected_source_digest)
                && handle.get("content_digest") == old_handle.get("content_digest")
                && handle.get("source_uri") == old_handle.get("source_uri")
        }) else {
            return Ok(false);
        };
        let source_uri = old_handle
            .get("source_uri")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ControllerError::InvalidPlan(
                    "compilation evidence handle lacks source_uri".to_owned(),
                )
            })?;
        let repo_prefix = format!("repo://{}/", previous.repository_id);
        if let Some(relative) = source_uri.strip_prefix(&repo_prefix) {
            let current = ExactRetriever::new(registry).read_path(
                &previous.repository_id,
                Path::new(relative),
                Some(expected_source_digest),
            );
            if current.is_err() {
                return Ok(false);
            }
        } else if next_handle != old_handle {
            return Ok(false);
        }
    }
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
fn carry_verified_output_records(
    state: &StateStore,
    previous: &ActivePlan,
    next_revision: u32,
    next_plan_digest: &str,
    current_snapshot_digest: &str,
    task: &Value,
    proof: &TaskCarryFingerprintV1,
    records: &mut Vec<(String, String, String)>,
) -> Result<(), ControllerError> {
    let task_id = required_str(task, "/task_id")?;
    for (namespace, items_pointer, id_field) in [
        (
            "controller.artifact_binding",
            "/expected_artifacts",
            "artifact_id",
        ),
        (
            "controller.acceptance_binding",
            "/acceptance_criteria",
            "criterion_id",
        ),
    ] {
        for item in required_array(task, items_pointer)?
            .iter()
            .filter(|item| item.get("required").and_then(Value::as_bool) == Some(true))
        {
            let binding_id = item.get(id_field).and_then(Value::as_str).ok_or_else(|| {
                ControllerError::InvalidPlan("carried output id missing".to_owned())
            })?;
            let old_key = revision_scoped_key(
                &previous.plan_id,
                previous.revision,
                &output_binding_key(task_id, binding_id),
            );
            let raw = state.get_state(namespace, &old_key)?.ok_or_else(|| {
                ControllerError::NotReady(format!(
                    "carried task {task_id} lost verified output {binding_id}"
                ))
            })?;
            let mut binding: VerifiedOutputBindingV1 = serde_json::from_str(&raw)?;
            if binding.verification_id != proof.verification_id
                || binding.verification_artifact_digest != proof.verification_artifact_digest
            {
                return Err(ControllerError::NotReady(format!(
                    "carried task {task_id} output {binding_id} does not match carry proof"
                )));
            }
            binding.carried_from_plan_revision = Some(previous.revision);
            binding.carried_from_plan_digest = Some(previous.plan_digest.clone());
            binding.plan_revision = next_revision;
            next_plan_digest.clone_into(&mut binding.plan_digest);
            current_snapshot_digest.clone_into(&mut binding.repository_snapshot_digest);
            records.push((
                namespace.to_owned(),
                revision_scoped_key(
                    &previous.plan_id,
                    next_revision,
                    &output_binding_key(task_id, binding_id),
                ),
                serde_json::to_string(&binding)?,
            ));
        }
    }
    Ok(())
}

struct ResolvedStableContract {
    owner_task_id: String,
    scope: ReplanScope,
    fingerprints: Vec<String>,
    kind: ResolvedStableContractKind,
    basis_locators: Vec<String>,
}

enum ResolvedStableContractKind {
    Assumption,
    Precondition,
    Invariant,
    DependencyBinding { downstream_task_id: String },
}

fn resolve_stable_plan_contract(
    plan: &Value,
    contract_id: &str,
) -> Result<ResolvedStableContract, ControllerError> {
    for task in required_array(plan, "/tasks")? {
        let task_id = required_str(task, "/task_id")?;
        for assumption in required_array(task, "/implementation_contract/assumptions")? {
            if optional_str(assumption, "/assumption_id") == Some(contract_id) {
                let scope: ReplanScope = serde_json::from_value(
                    assumption
                        .get("invalidation_scope")
                        .cloned()
                        .ok_or_else(|| {
                            ControllerError::InvalidPlan(
                                "assumption lacks invalidation_scope".to_owned(),
                            )
                        })?,
                )?;
                let fingerprints = assumption
                    .get("fingerprints")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect();
                let basis_locators = assumption
                    .get("basis_evidence")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|item| item.get("locator").and_then(Value::as_str))
                    .map(str::to_owned)
                    .collect();
                return Ok(ResolvedStableContract {
                    owner_task_id: task_id.to_owned(),
                    scope,
                    fingerprints,
                    kind: ResolvedStableContractKind::Assumption,
                    basis_locators,
                });
            }
        }
        for clause in required_array(task, "/implementation_contract/preconditions")? {
            if optional_str(clause, "/clause_id") == Some(contract_id) {
                return Ok(ResolvedStableContract {
                    owner_task_id: task_id.to_owned(),
                    scope: ReplanScope::Task,
                    fingerprints: Vec::new(),
                    kind: ResolvedStableContractKind::Precondition,
                    basis_locators: Vec::new(),
                });
            }
        }
        for clause in required_array(task, "/implementation_contract/invariants")? {
            if optional_str(clause, "/clause_id") == Some(contract_id) {
                return Ok(ResolvedStableContract {
                    owner_task_id: task_id.to_owned(),
                    scope: ReplanScope::Plan,
                    fingerprints: Vec::new(),
                    kind: ResolvedStableContractKind::Invariant,
                    basis_locators: Vec::new(),
                });
            }
        }
        for binding in required_array(task, "/dependency_bindings")? {
            let upstream = required_str(binding, "/upstream_task_id")?;
            if contract_id == format!("binding:{task_id}:{upstream}") {
                return Ok(ResolvedStableContract {
                    owner_task_id: upstream.to_owned(),
                    scope: ReplanScope::DependencyBranch,
                    fingerprints: Vec::new(),
                    kind: ResolvedStableContractKind::DependencyBinding {
                        downstream_task_id: task_id.to_owned(),
                    },
                    basis_locators: Vec::new(),
                });
            }
        }
    }
    Err(ControllerError::InvalidPlan(format!(
        "stable plan contract {contract_id} does not resolve"
    )))
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
        if !matches!(
            criterion.get("evidence_freshness").and_then(Value::as_str),
            Some("current_attempt" | "carry_forward_if_inputs_unchanged")
        ) {
            return Err(ControllerError::InvalidPlan(
                "deterministic verifier requires current-attempt evidence or guarded carry-forward freshness"
                    .to_owned(),
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

fn load_execution_control(state: &StateStore) -> Result<ExecutionControlV1, ControllerError> {
    let Some(raw) = state.get_state("controller.execution_control", "global")? else {
        return Ok(ExecutionControlV1::default());
    };
    let control: ExecutionControlV1 = serde_json::from_str(&raw)?;
    if control.schema_version != EXECUTION_CONTROL_SCHEMA_VERSION {
        return Err(ControllerError::InvalidPlan(format!(
            "unsupported execution-control schema version {}",
            control.schema_version
        )));
    }
    Ok(control)
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
        ACTION_INTENT_SCHEMA_VERSION, ActivePlan, Controller, ExactRequirementProbe,
        FailureClassification, FailureClassificationKind, LEGACY_ACTION_INTENT_SCHEMA_VERSION,
        PlanValidity, RecoveryProcessLease, TaskCarryExecutionProvenanceV1, TaskCarryFingerprintV1,
        TaskRuntime, TaskState, VerificationResultV1, VerifiedOutputBindingV1, WorktreeLifecycle,
        acceptance_permits_cross_revision_carry, build_superseding_runtime,
        compilation_inputs_are_fresh_for_carry, compiled_acceptance_contract,
        dependency_bindings_permit_cross_revision_carry, digest_json, exact_requirement_probe,
        explicit_replace_relation, fresh_task_runtime, has_unresolved_process_lease,
        lineage_records_for_supersession, normalize_persisted_action_intent,
        normalized_failure_signature, output_binding_key, plan_instruction_fingerprint_digest,
        process_lease_is_terminal, repair_allowed, revision_record_key, revision_scoped_key,
        scope_lineage_id,
    };
    use serde_json::{Value, json};
    use sovereign_evidence::ArtifactStore;
    use sovereign_plan::{PlanRevisionDiff, ReplanScope};
    use sovereign_repo::{
        ExactRetriever, ProjectRegistry, RepositoryIntelligence, RepositorySnapshot, WorktreeLease,
    };
    use sovereign_state::StateStore;
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn same_failure_circuit_breaker_requires_both_counters_below_limits() {
        assert!(repair_allowed(1, 2, 1, 2));
        assert!(!repair_allowed(2, 2, 1, 2));
        assert!(!repair_allowed(1, 3, 2, 2));
        assert!(!repair_allowed(2, 2, 2, 2));
    }

    #[test]
    fn worktree_depth_gate_covers_d3_and_d4_only() {
        for (index, (mode, expected)) in [("D2", false), ("D3", true), ("D4", true)]
            .into_iter()
            .enumerate()
        {
            let (base, state) = temp_state(&format!("worktree-depth-{index}"));
            let plan_digest = format!("sha256:{}", "a".repeat(64));
            let mut active = active_fixture(&base, 1, &plan_digest);
            active.plan_document["depth"] = json!({"mode": mode});
            let mut controller = Controller::new(state);
            controller.active = Some(active);
            assert_eq!(
                controller
                    .active_uses_controller_worktrees()
                    .unwrap_or_else(|error| panic!("depth gate {mode}: {error}")),
                expected
            );
            drop(controller);
            let _ = std::fs::remove_dir_all(base);
        }
    }

    #[test]
    fn controller_rederives_state_parent_worktree_root_and_rejects_path_root_tamper() {
        let (base, state) = temp_state("worktree-root-binding");
        let repository_root = base.join("repo");
        std::fs::create_dir_all(&repository_root)
            .unwrap_or_else(|error| panic!("create repository root: {error}"));
        let repository_root = repository_root
            .canonicalize()
            .unwrap_or_else(|error| panic!("canonical repository root: {error}"));
        let plan_digest = format!("sha256:{}", "a".repeat(64));
        let mut active = active_fixture(&repository_root, 3, &plan_digest);
        active.plan_document["depth"] = json!({"mode": "D3"});
        let task = json!({"task_id": "task.A"});
        let runtime =
            fresh_task_runtime(&task).unwrap_or_else(|error| panic!("fresh task runtime: {error}"));
        let task_contract_digest = runtime.task_contract_digest.clone();
        active.tasks.insert("task.A".to_owned(), runtime);
        let mut controller = Controller::new(state);
        controller.active = Some(active);
        let expected_root = base
            .canonicalize()
            .unwrap_or_else(|error| panic!("canonical state parent: {error}"))
            .join("worktrees");
        let lease_id = "worktree.bound".to_owned();
        let lease = WorktreeLease {
            schema_version: 1,
            lease_id: lease_id.clone(),
            repository_id: "repo.app".to_owned(),
            plan_id: "plan.fixture".to_owned(),
            plan_revision: 3,
            task_id: "task.A".to_owned(),
            task_contract_digest,
            primary_root: repository_root,
            controller_root: expected_root.clone(),
            worktree_path: expected_root.join(&lease_id),
            base_head: "deadbeef".to_owned(),
        };
        controller
            .validate_controller_worktree_lease_binding("task.A", &lease)
            .unwrap_or_else(|error| panic!("valid controller binding: {error}"));

        let mut root_tampered = lease.clone();
        root_tampered.controller_root = base.join("foreign-root");
        assert!(
            controller
                .validate_controller_worktree_lease_binding("task.A", &root_tampered)
                .is_err()
        );
        let mut path_tampered = lease;
        path_tampered.worktree_path = expected_root.join("foreign-path");
        assert!(
            controller
                .validate_controller_worktree_lease_binding("task.A", &path_tampered)
                .is_err()
        );
        drop(controller);
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn recovery_migrates_genuine_v2_action_intent_without_granting_worktree_authority() {
        let (base, state) = temp_state("action-intent-v2-migration");
        drop(state);
        let primary = base.join("repo");
        std::fs::create_dir_all(&primary).unwrap_or_else(|error| panic!("create primary: {error}"));
        let primary = primary
            .canonicalize()
            .unwrap_or_else(|error| panic!("canonical primary: {error}"));
        let legacy_json = json!({
            "schema_version": LEGACY_ACTION_INTENT_SCHEMA_VERSION,
            "action_id": "action.legacy-v2",
            "plan_id": "plan.fixture",
            "plan_revision": 1,
            "plan_digest": format!("sha256:{}", "a".repeat(64)),
            "task_id": "task.A",
            "task_contract_digest": format!("sha256:{}", "b".repeat(64)),
            "attempt_id": "attempt.A.1",
            "execution_epoch": 7,
            "payload_digest": format!("sha256:{}", "c".repeat(64)),
            "action_nonce": "nonce.legacy",
            "policy_digest": format!("sha256:{}", "d".repeat(64)),
            "repository_id": "repo.app",
            "path": "src/a.rs",
            "expected_source_digest": format!("sha256:{}", "e".repeat(64)),
            "old_literal": "old",
            "new_literal": "new",
            "expected_post_digest": format!("sha256:{}", "f".repeat(64)),
            "expected_target_mode": 420,
            "artifact_store_root": base.join("cas")
        });
        assert!(legacy_json.get("worktree_lease_id").is_none());
        assert!(legacy_json.get("execution_root").is_none());
        let legacy = serde_json::from_value(legacy_json)
            .unwrap_or_else(|error| panic!("decode genuine v2 fixture: {error}"));
        let migrated = normalize_persisted_action_intent(legacy, &primary)
            .unwrap_or_else(|error| panic!("migrate v2 intent: {error}"));
        assert_eq!(migrated.schema_version, ACTION_INTENT_SCHEMA_VERSION);
        assert_eq!(migrated.execution_root, primary);
        assert_eq!(migrated.worktree_lease_id, None);

        let mut forged = migrated;
        forged.schema_version = LEGACY_ACTION_INTENT_SCHEMA_VERSION;
        forged.execution_root = PathBuf::new();
        forged.worktree_lease_id = Some("worktree.old-revision".to_owned());
        assert!(normalize_persisted_action_intent(forged, &primary).is_err());
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn normalized_failure_signature_ignores_volatile_request_time_and_line_noise() {
        let facts = BTreeMap::from([
            (
                "path".to_owned(),
                "src/settings/SettingsForm.tsx".to_owned(),
            ),
            ("old_literal".to_owned(), "Save".to_owned()),
            ("new_literal".to_owned(), "Apply".to_owned()),
        ]);
        let first = normalized_failure_signature(
            "proposal_validation_failure",
            "replace_literal_preimage_count",
            "request_id=req-alpha123 timestamp=2026-09-13T03:01:22Z model proposal rejected at line 41: replace_literal preimage does not contain exactly one old literal",
            &facts,
        );
        let second = normalized_failure_signature(
            "proposal_validation_failure",
            "replace_literal_preimage_count",
            "request_id=req-zeta999 timestamp=2026-09-13T03:07:55Z model proposal rejected at line 912: replace_literal preimage does not contain exactly one old literal",
            &facts,
        );
        assert_eq!(first, second);

        let different = normalized_failure_signature(
            "proposal_validation_failure",
            "replace_literal_scope",
            "model proposal rejected: replace_literal path is outside exact active task scope",
            &facts,
        );
        assert_ne!(first, different);
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

    #[test]
    fn carry_forward_rejects_compilation_input_source_drift() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let base = std::env::temp_dir().join(format!(
            "sovereign-controller-carry-input-drift-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&base).unwrap_or_else(|error| panic!("temp dir: {error}"));
        let mut state = StateStore::open(base.join("state.sqlite3"))
            .unwrap_or_else(|error| panic!("state: {error}"));
        let previous_compilation = json!({
            "exact_evidence": [{
                "evidence_id": "ev.input",
                "source_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "content_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "source_uri": "repo://repo.app/src/lib.rs"
            }]
        });
        state
            .put_state(
                "controller.compilation_evidence",
                &revision_record_key("plan.fixture", 1),
                &previous_compilation.to_string(),
            )
            .unwrap_or_else(|error| panic!("persist compilation evidence: {error}"));
        let empty_change = json!({
            "digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "paths": []
        });
        let baseline: RepositorySnapshot = serde_json::from_value(json!({
            "repository_id": "repo.app",
            "root": base,
            "head": Value::Null,
            "branch": Value::Null,
            "staged": empty_change,
            "unstaged": empty_change,
            "untracked": empty_change,
            "dirty_digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "protected_changes_present": false
        }))
        .unwrap_or_else(|error| panic!("baseline: {error}"));
        let previous = ActivePlan {
            plan_document: json!({}),
            compiler_plan_digest:
                "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_owned(),
            plan_id: "plan.fixture".to_owned(),
            goal_id: "goal.fixture".to_owned(),
            revision: 1,
            plan_digest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                .to_owned(),
            compilation_evidence_digest:
                "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_owned(),
            policy_digest:
                "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned(),
            repository_id: "repo.app".to_owned(),
            repository_root: PathBuf::from("/nonexistent-fixture"),
            baseline,
            baseline_diff_digest:
                "sha256:1111111111111111111111111111111111111111111111111111111111111111".to_owned(),
            baseline_diff_content: String::new(),
            validity: PlanValidity::Current,
            tasks: BTreeMap::new(),
            attempts: BTreeMap::new(),
        };
        let task = json!({
            "implementation_contract": {
                "inputs": ["ev.input sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
            }
        });
        let next_compilation = json!({
            "exact_evidence": [{
                "evidence_id": "ev.input",
                "source_digest": "sha256:9999999999999999999999999999999999999999999999999999999999999999",
                "content_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "source_uri": "repo://repo.app/src/lib.rs"
            }]
        });
        let fresh = compilation_inputs_are_fresh_for_carry(
            &state,
            &ProjectRegistry::new(),
            &previous,
            &task,
            &next_compilation,
        )
        .unwrap_or_else(|error| panic!("carry freshness: {error}"));
        assert!(
            !fresh,
            "changed compilation input source digest must block carry"
        );
        drop(state);
        let _ = std::fs::remove_dir_all(base);
    }

    fn temp_state(label: &str) -> (PathBuf, StateStore) {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let base = std::env::temp_dir().join(format!(
            "sovereign-controller-{label}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&base).unwrap_or_else(|error| panic!("temp dir: {error}"));
        let state = StateStore::open(base.join("state.sqlite3"))
            .unwrap_or_else(|error| panic!("state: {error}"));
        (base, state)
    }

    fn empty_snapshot(root: &std::path::Path) -> RepositorySnapshot {
        let empty_change = json!({
            "digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "paths": []
        });
        serde_json::from_value(json!({
            "repository_id": "repo.app",
            "root": root,
            "head": Value::Null,
            "branch": Value::Null,
            "staged": empty_change,
            "unstaged": empty_change,
            "untracked": empty_change,
            "dirty_digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "protected_changes_present": false
        }))
        .unwrap_or_else(|error| panic!("snapshot: {error}"))
    }

    fn active_fixture(root: &std::path::Path, revision: u32, plan_digest: &str) -> ActivePlan {
        ActivePlan {
            plan_document: json!({}),
            compiler_plan_digest: plan_digest.to_owned(),
            plan_id: "plan.fixture".to_owned(),
            goal_id: "goal.fixture".to_owned(),
            revision,
            plan_digest: plan_digest.to_owned(),
            compilation_evidence_digest:
                "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_owned(),
            policy_digest:
                "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned(),
            repository_id: "repo.app".to_owned(),
            repository_root: root.to_path_buf(),
            baseline: empty_snapshot(root),
            baseline_diff_digest:
                "sha256:1111111111111111111111111111111111111111111111111111111111111111".to_owned(),
            baseline_diff_content: String::new(),
            validity: PlanValidity::Current,
            tasks: BTreeMap::new(),
            attempts: BTreeMap::new(),
        }
    }

    #[test]
    fn deterministic_acceptance_allows_guarded_carry_but_not_current_task_revision() {
        let task = |freshness: &str| {
            json!({
                "acceptance_criteria": [{
                    "criterion_id": "AC.1",
                    "description": "accepted",
                    "kind": "diff",
                    "verification_step_ids": ["verify.1"],
                    "evidence_type": "diff_result",
                    "evidence_freshness": freshness,
                    "required": true
                }],
                "verification": {
                    "steps": [{
                        "step_id": "verify.1",
                        "criterion_ids": ["AC.1"],
                        "kind": "diff",
                        "evidence_type": "diff_result",
                        "evaluator": "builtin.diff.scoped_change.v1"
                    }],
                    "required_evidence_types": ["diff_result"]
                }
            })
        };
        assert!(compiled_acceptance_contract(&task("current_attempt")).is_ok());
        assert!(compiled_acceptance_contract(&task("carry_forward_if_inputs_unchanged")).is_ok());
        assert!(compiled_acceptance_contract(&task("current_task_revision")).is_err());
        assert!(
            !acceptance_permits_cross_revision_carry(&task("current_attempt"))
                .unwrap_or_else(|error| panic!("freshness: {error}"))
        );
    }

    #[test]
    fn dependency_binding_same_plan_revision_is_never_cross_revision_carry_authority() {
        let task = |freshness: &str| {
            json!({
                "dependency_bindings": [{
                    "upstream_task_id": "A",
                    "required_artifact_ids": ["artifact.A"],
                    "required_acceptance_criterion_ids": ["AC.A"],
                    "freshness": freshness
                }]
            })
        };
        assert!(
            !dependency_bindings_permit_cross_revision_carry(&task("same_plan_revision"))
                .unwrap_or_else(|error| panic!("binding freshness: {error}"))
        );
        assert!(
            dependency_bindings_permit_cross_revision_carry(&task(
                "carry_forward_if_inputs_unchanged"
            ))
            .unwrap_or_else(|error| panic!("binding freshness: {error}"))
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn n_plus_one_dependency_consumes_carried_output_through_explicit_old_revision_provenance() {
        let (base, mut state) = temp_state("carried-dependency-provenance");
        let artifact_store = ArtifactStore::open(base.join("cas"))
            .unwrap_or_else(|error| panic!("artifact store: {error}"));
        let artifact = artifact_store
            .put(&mut state, b"verification")
            .unwrap_or_else(|error| panic!("verification artifact: {error}"));
        let plan_one_digest = format!("sha256:{}", "1".repeat(64));
        let plan_two_digest = format!("sha256:{}", "2".repeat(64));
        let upstream_task = json!({"task_id":"A"});
        let upstream_digest =
            digest_json(&upstream_task).unwrap_or_else(|error| panic!("upstream digest: {error}"));
        let downstream_task = json!({
            "task_id": "B",
            "dependency_bindings": [{
                "upstream_task_id": "A",
                "required_artifact_ids": ["artifact.A"],
                "required_acceptance_criterion_ids": ["AC.A"],
                "freshness": "carry_forward_if_inputs_unchanged"
            }]
        });
        let verification = VerificationResultV1 {
            schema_version: super::VERIFICATION_RESULT_SCHEMA_VERSION,
            verification_id: "verification.A".to_owned(),
            plan_id: "plan.fixture".to_owned(),
            plan_revision: 1,
            plan_digest: plan_one_digest.clone(),
            task_id: "A".to_owned(),
            task_contract_digest: upstream_digest.clone(),
            attempt_id: "attempt.A.1".to_owned(),
            execution_epoch: 1,
            evaluator: "builtin.diff.scoped_change.v1".to_owned(),
            acceptance_contract_digest: format!("sha256:{}", "3".repeat(64)),
            diff_digest: format!("sha256:{}", "4".repeat(64)),
            post_snapshot_digest: "snapshot.N".to_owned(),
            expected_target_mode: 0o644,
            observed_target_mode: 0o644,
            evidence_ids: vec!["ev.N".to_owned()],
            passed: true,
            failure_code: None,
        };
        state
            .put_state(
                "controller.verification",
                &revision_scoped_key("plan.fixture", 1, "verification.A"),
                &serde_json::to_string(&verification)
                    .unwrap_or_else(|error| panic!("verification json: {error}")),
            )
            .unwrap_or_else(|error| panic!("persist verification: {error}"));
        let carry = TaskCarryFingerprintV1 {
            schema_version: super::TASK_CARRY_FINGERPRINT_SCHEMA_VERSION,
            plan_id: "plan.fixture".to_owned(),
            plan_revision: 2,
            plan_digest: plan_two_digest.clone(),
            task_id: "A".to_owned(),
            task_contract_digest: upstream_digest.clone(),
            implementation_inputs_digest: format!("sha256:{}", "5".repeat(64)),
            dependency_contract_digest: format!("sha256:{}", "6".repeat(64)),
            instruction_fingerprint_digest: format!("sha256:{}", "7".repeat(64)),
            source_fingerprints: BTreeMap::new(),
            execution_provenance: None,
            acceptance_contract_digest: verification.acceptance_contract_digest.clone(),
            verification_id: verification.verification_id.clone(),
            verification_artifact_digest: artifact.digest.clone(),
        };
        state
            .put_state(
                "controller.task_carry_fingerprint",
                &revision_scoped_key("plan.fixture", 2, "A"),
                &serde_json::to_string(&carry)
                    .unwrap_or_else(|error| panic!("carry json: {error}")),
            )
            .unwrap_or_else(|error| panic!("persist carry: {error}"));
        for (namespace, kind, binding_id) in [
            ("controller.artifact_binding", "artifact", "artifact.A"),
            ("controller.acceptance_binding", "acceptance", "AC.A"),
        ] {
            let binding = VerifiedOutputBindingV1 {
                schema_version: super::VERIFIED_OUTPUT_BINDING_SCHEMA_VERSION,
                plan_id: "plan.fixture".to_owned(),
                plan_revision: 2,
                plan_digest: plan_two_digest.clone(),
                task_id: "A".to_owned(),
                task_contract_digest: upstream_digest.clone(),
                attempt_id: "attempt.A.1".to_owned(),
                binding_kind: kind.to_owned(),
                binding_id: binding_id.to_owned(),
                verification_id: verification.verification_id.clone(),
                verification_artifact_digest: artifact.digest.clone(),
                repository_snapshot_digest: "snapshot.N+1".to_owned(),
                change_set_digest: None,
                carried_from_plan_revision: Some(1),
                carried_from_plan_digest: Some(plan_one_digest.clone()),
            };
            state
                .put_state(
                    namespace,
                    &revision_scoped_key("plan.fixture", 2, &output_binding_key("A", binding_id)),
                    &serde_json::to_string(&binding)
                        .unwrap_or_else(|error| panic!("binding json: {error}")),
                )
                .unwrap_or_else(|error| panic!("persist binding: {error}"));
        }
        let mut active = active_fixture(&base, 2, &plan_two_digest);
        active.plan_document["depth"] = json!({"mode": "D2"});
        active.tasks.insert(
            "A".to_owned(),
            TaskRuntime {
                state: TaskState::Succeeded,
                attempts_started: 1,
                model_calls_used: 1,
                failure_counts: BTreeMap::new(),
                retry_exhausted: false,
                resource_deferrals_used: 0,
                resource_retry_exhausted: false,
                resource_deferred_from: None,
                worktree_lease: None,
                worktree_state: None,
                change_set: None,
                change_set_artifact_digest: None,
                change_set_carry: None,
                worktree_baseline: None,
                worktree_composition: Vec::new(),
                worktree_conflict: None,
                task_contract_digest: upstream_digest,
                task: upstream_task,
            },
        );
        let downstream_digest = digest_json(&downstream_task)
            .unwrap_or_else(|error| panic!("downstream digest: {error}"));
        active.tasks.insert(
            "B".to_owned(),
            TaskRuntime {
                state: TaskState::Planned,
                attempts_started: 0,
                model_calls_used: 0,
                failure_counts: BTreeMap::new(),
                retry_exhausted: false,
                resource_deferrals_used: 0,
                resource_retry_exhausted: false,
                resource_deferred_from: None,
                worktree_lease: None,
                worktree_state: None,
                change_set: None,
                change_set_artifact_digest: None,
                change_set_carry: None,
                worktree_baseline: None,
                worktree_composition: Vec::new(),
                worktree_conflict: None,
                task_contract_digest: downstream_digest,
                task: downstream_task.clone(),
            },
        );
        let mut controller = Controller::new(state);
        controller.active = Some(active);
        let resolved =
            controller.resolve_dependency_binding_digests("B", &downstream_task, "snapshot.N+1");
        assert!(
            resolved.is_ok(),
            "carried N output must be consumable in N+1: {resolved:?}"
        );
        drop(controller);
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn d3_carried_n_changeset_composes_into_fresh_n_plus_one_lease_and_authorizes_downstream() {
        let (base, mut state) = temp_state("d3-carried-changeset-composition");
        let repository_root = base.join("repo");
        std::fs::create_dir_all(&repository_root)
            .unwrap_or_else(|error| panic!("create repository: {error}"));
        let git = |args: &[&str]| {
            let output = Command::new("git")
                .current_dir(&repository_root)
                .args(args)
                .output()
                .unwrap_or_else(|error| panic!("git {args:?}: {error}"));
            assert!(
                output.status.success(),
                "git {args:?} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        };
        git(&["init", "-q"]);
        git(&["config", "user.name", "Sovereign Test"]);
        git(&["config", "user.email", "test@sovereign.invalid"]);
        std::fs::write(repository_root.join("tracked.txt"), "base\n")
            .unwrap_or_else(|error| panic!("write baseline: {error}"));
        git(&["add", "tracked.txt"]);
        git(&["commit", "-qm", "baseline"]);
        let repository_root = repository_root
            .canonicalize()
            .unwrap_or_else(|error| panic!("canonical repository: {error}"));
        let mut registry = ProjectRegistry::new();
        registry
            .register("repo.app", &repository_root)
            .unwrap_or_else(|error| panic!("register repository: {error}"));

        let task_a = json!({
            "task_id": "A",
            "dependencies": [],
            "dependency_bindings": [],
            "implementation_contract": {"inputs": []},
            "acceptance_criteria": [{
                "criterion_id": "AC.A",
                "evidence_freshness": "carry_forward_if_inputs_unchanged",
                "required": true
            }],
            "expected_artifacts": [{"artifact_id": "artifact.A", "required": true}]
        });
        let task_b = json!({
            "task_id": "B",
            "dependencies": ["A"],
            "dependency_bindings": [{
                "upstream_task_id": "A",
                "required_artifact_ids": ["artifact.A"],
                "required_acceptance_criterion_ids": ["AC.A"],
                "freshness": "carry_forward_if_inputs_unchanged"
            }],
            "implementation_contract": {"inputs": []},
            "acceptance_criteria": [],
            "expected_artifacts": []
        });
        let digest_a = digest_json(&task_a).unwrap_or_else(|error| panic!("digest A: {error}"));
        let plan_one_digest = format!("sha256:{}", "1".repeat(64));
        let plan_two_digest = format!("sha256:{}", "2".repeat(64));
        let next_plan = json!({
            "depth": {"mode": "D3"},
            "repositories": [{"instructions": []}],
            "tasks": [task_a.clone(), task_b.clone()]
        });
        let instruction_digest = plan_instruction_fingerprint_digest(&next_plan)
            .unwrap_or_else(|error| panic!("instruction digest: {error}"));

        let historical_lease = registry
            .prepare_worktree_lease(
                "repo.app",
                &base.join("historical-worktrees"),
                "plan.fixture",
                1,
                "A",
                &digest_a,
            )
            .unwrap_or_else(|error| panic!("prepare historical lease: {error}"));
        registry
            .materialize_worktree(&historical_lease)
            .unwrap_or_else(|error| panic!("materialize historical lease: {error}"));
        let historical_baseline = registry
            .capture_worktree_baseline(&historical_lease)
            .unwrap_or_else(|error| panic!("historical baseline: {error}"));
        std::fs::write(
            historical_lease.worktree_path.join("tracked.txt"),
            "from-N\n",
        )
        .unwrap_or_else(|error| panic!("historical mutation: {error}"));
        let change_set = registry
            .capture_change_set_from_baseline(&historical_lease, &historical_baseline)
            .unwrap_or_else(|error| panic!("historical ChangeSet: {error}"));
        let change_set_digest = change_set
            .digest()
            .unwrap_or_else(|error| panic!("ChangeSet digest: {error}"));

        let artifact_store = ArtifactStore::open(base.join("cas"))
            .unwrap_or_else(|error| panic!("artifact store: {error}"));
        let change_set_artifact = artifact_store
            .put(
                &mut state,
                &serde_json::to_vec(&change_set)
                    .unwrap_or_else(|error| panic!("ChangeSet json: {error}")),
            )
            .unwrap_or_else(|error| panic!("ChangeSet artifact: {error}"));
        state
            .put_state(
                "controller.change_set",
                &revision_scoped_key("plan.fixture", 1, "A"),
                &serde_json::to_string(&change_set)
                    .unwrap_or_else(|error| panic!("durable ChangeSet json: {error}")),
            )
            .unwrap_or_else(|error| panic!("persist durable ChangeSet: {error}"));
        let verification_artifact = artifact_store
            .put(&mut state, b"verification")
            .unwrap_or_else(|error| panic!("verification artifact: {error}"));
        let verification = VerificationResultV1 {
            schema_version: super::VERIFICATION_RESULT_SCHEMA_VERSION,
            verification_id: "verification.A".to_owned(),
            plan_id: "plan.fixture".to_owned(),
            plan_revision: 1,
            plan_digest: plan_one_digest.clone(),
            task_id: "A".to_owned(),
            task_contract_digest: digest_a.clone(),
            attempt_id: "attempt.A.1".to_owned(),
            execution_epoch: 1,
            evaluator: "builtin.diff.scoped_change.v1".to_owned(),
            acceptance_contract_digest: format!("sha256:{}", "3".repeat(64)),
            diff_digest: change_set.diff_digest.clone(),
            post_snapshot_digest: "worktree.snapshot.N".to_owned(),
            expected_target_mode: 0o644,
            observed_target_mode: 0o644,
            evidence_ids: vec!["ev.N".to_owned()],
            passed: true,
            failure_code: None,
        };
        state
            .put_state(
                "controller.verification",
                &revision_scoped_key("plan.fixture", 1, "verification.A"),
                &serde_json::to_string(&verification)
                    .unwrap_or_else(|error| panic!("verification json: {error}")),
            )
            .unwrap_or_else(|error| panic!("persist verification: {error}"));
        state
            .put_state(
                "controller.compilation_evidence",
                &revision_record_key("plan.fixture", 1),
                &json!({"exact_evidence": []}).to_string(),
            )
            .unwrap_or_else(|error| panic!("persist compilation evidence: {error}"));
        let source_fingerprints = BTreeMap::from([(
            "tracked.txt".to_owned(),
            super::path_fingerprint(
                &historical_lease.worktree_path,
                std::path::Path::new("tracked.txt"),
            )
            .unwrap_or_else(|error| panic!("post-mutation source fingerprint: {error}")),
        )]);
        assert!(!source_fingerprints.is_empty());
        let proof = TaskCarryFingerprintV1 {
            schema_version: super::TASK_CARRY_FINGERPRINT_SCHEMA_VERSION,
            plan_id: "plan.fixture".to_owned(),
            plan_revision: 1,
            plan_digest: plan_one_digest.clone(),
            task_id: "A".to_owned(),
            task_contract_digest: digest_a.clone(),
            implementation_inputs_digest: digest_json(&json!([]))
                .unwrap_or_else(|error| panic!("inputs digest: {error}")),
            dependency_contract_digest: digest_json(&json!([]))
                .unwrap_or_else(|error| panic!("dependency digest: {error}")),
            instruction_fingerprint_digest: instruction_digest,
            source_fingerprints,
            execution_provenance: Some(TaskCarryExecutionProvenanceV1 {
                change_set_digest: change_set_digest.clone(),
                composed_change_sets: Vec::new(),
            }),
            acceptance_contract_digest: verification.acceptance_contract_digest.clone(),
            verification_id: verification.verification_id.clone(),
            verification_artifact_digest: verification_artifact.digest.clone(),
        };
        state
            .put_state(
                "controller.task_carry_fingerprint",
                &revision_scoped_key("plan.fixture", 1, "A"),
                &serde_json::to_string(&proof)
                    .unwrap_or_else(|error| panic!("carry proof json: {error}")),
            )
            .unwrap_or_else(|error| panic!("persist carry proof: {error}"));
        for (namespace, kind, binding_id) in [
            ("controller.artifact_binding", "artifact", "artifact.A"),
            ("controller.acceptance_binding", "acceptance", "AC.A"),
        ] {
            let binding = VerifiedOutputBindingV1 {
                schema_version: super::VERIFIED_OUTPUT_BINDING_SCHEMA_VERSION,
                plan_id: "plan.fixture".to_owned(),
                plan_revision: 1,
                plan_digest: plan_one_digest.clone(),
                task_id: "A".to_owned(),
                task_contract_digest: digest_a.clone(),
                attempt_id: "attempt.A.1".to_owned(),
                binding_kind: kind.to_owned(),
                binding_id: binding_id.to_owned(),
                verification_id: verification.verification_id.clone(),
                verification_artifact_digest: verification_artifact.digest.clone(),
                repository_snapshot_digest: verification.post_snapshot_digest.clone(),
                change_set_digest: Some(change_set_digest.clone()),
                carried_from_plan_revision: None,
                carried_from_plan_digest: None,
            };
            state
                .put_state(
                    namespace,
                    &revision_scoped_key("plan.fixture", 1, &output_binding_key("A", binding_id)),
                    &serde_json::to_string(&binding)
                        .unwrap_or_else(|error| panic!("binding json: {error}")),
                )
                .unwrap_or_else(|error| panic!("persist binding: {error}"));
        }

        let mut previous = active_fixture(&repository_root, 1, &plan_one_digest);
        previous.plan_document = json!({
            "depth": {"mode": "D3"},
            "repositories": [{"instructions": []}],
            "tasks": [task_a.clone()]
        });
        let mut runtime_a =
            fresh_task_runtime(&task_a).unwrap_or_else(|error| panic!("fresh A runtime: {error}"));
        runtime_a.state = TaskState::Succeeded;
        runtime_a.worktree_lease = Some(historical_lease.clone());
        runtime_a.worktree_state = Some(WorktreeLifecycle::Released);
        runtime_a.change_set = Some(change_set.clone());
        runtime_a.change_set_artifact_digest = Some(change_set_artifact.digest.clone());
        previous.tasks.insert("A".to_owned(), runtime_a);

        let diff = PlanRevisionDiff {
            plan_id: "plan.fixture".to_owned(),
            from_revision: 1,
            to_revision: 2,
            from_plan_digest: plan_one_digest.clone(),
            to_plan_digest: plan_two_digest.clone(),
            scope: ReplanScope::Task,
            invalidated_contract_ids: vec!["ASSUME.unrelated".to_owned()],
            affected_task_ids: vec!["B".to_owned()],
            unchanged_task_ids: vec!["A".to_owned()],
            changed_task_ids: Vec::new(),
            added_task_ids: vec!["B".to_owned()],
            removed_task_ids: Vec::new(),
        };
        let unrelated_artifact = artifact_store
            .put(&mut state, b"unrelated-artifact")
            .unwrap_or_else(|error| panic!("unrelated artifact: {error}"));
        let correct_change_set_artifact_digest = previous
            .tasks
            .get("A")
            .and_then(|runtime| runtime.change_set_artifact_digest.clone())
            .unwrap_or_else(|| panic!("previous A ChangeSet artifact missing"));
        previous
            .tasks
            .get_mut("A")
            .unwrap_or_else(|| panic!("tampered previous A missing"))
            .change_set_artifact_digest = Some(unrelated_artifact.digest);
        let tampered_build = build_superseding_runtime(
            &state,
            &registry,
            &previous,
            &next_plan,
            &plan_two_digest,
            &json!({"exact_evidence": []}),
            &diff,
            "primary.snapshot.N+1",
        )
        .unwrap_or_else(|error| panic!("build tampered superseding D3 runtime: {error}"));
        assert_eq!(
            tampered_build.tasks["A"].state,
            TaskState::Planned,
            "unrelated artifact metadata must not authorize ChangeSet carry"
        );
        previous
            .tasks
            .get_mut("A")
            .unwrap_or_else(|| panic!("restore previous A missing"))
            .change_set_artifact_digest = Some(correct_change_set_artifact_digest);

        let build = build_superseding_runtime(
            &state,
            &registry,
            &previous,
            &next_plan,
            &plan_two_digest,
            &json!({"exact_evidence": []}),
            &diff,
            "primary.snapshot.N+1",
        )
        .unwrap_or_else(|error| panic!("build superseding D3 runtime: {error}"));
        let carried_a = &build.tasks["A"];
        assert_eq!(carried_a.state, TaskState::Succeeded);
        assert!(carried_a.worktree_lease.is_none());
        assert!(carried_a.worktree_state.is_none());
        assert_eq!(carried_a.change_set.as_ref(), Some(&change_set));
        let carried = carried_a
            .change_set_carry
            .as_ref()
            .unwrap_or_else(|| panic!("explicit ChangeSet carry provenance missing"));
        assert_eq!(carried.from_revision, 1);
        assert_eq!(carried.to_revision, 2);
        assert_eq!(carried.source_change_set_digest, change_set_digest);
        for (namespace, key, value) in &build.carry_records {
            state
                .put_state(namespace, key, value)
                .unwrap_or_else(|error| panic!("persist N+1 carry record: {error}"));
        }

        let mut active = active_fixture(&repository_root, 2, &plan_two_digest);
        active.plan_document = next_plan;
        active.tasks = build.tasks;
        active.baseline = registry
            .snapshot("repo.app")
            .unwrap_or_else(|error| panic!("primary snapshot: {error}"));
        let primary_diff = ExactRetriever::new(&registry)
            .current_diff("repo.app")
            .unwrap_or_else(|error| panic!("primary diff: {error}"));
        active.baseline_diff_digest = primary_diff.digest;
        active.baseline_diff_content = primary_diff.content;
        let mut controller = Controller::new(state);
        controller.active = Some(active);
        controller
            .ensure_task_worktree(&registry, "B")
            .unwrap_or_else(|error| panic!("compose carried A into fresh B lease: {error}"));
        let lease_b = controller
            .task_worktree_lease("B")
            .cloned()
            .unwrap_or_else(|| panic!("fresh N+1 downstream lease missing"));
        assert_eq!(lease_b.plan_revision, 2);
        assert_ne!(lease_b.lease_id, historical_lease.lease_id);
        assert_eq!(
            std::fs::read_to_string(lease_b.worktree_path.join("tracked.txt"))
                .unwrap_or_else(|error| panic!("read composed carried output: {error}")),
            "from-N\n"
        );
        let readiness_binding = controller.resolve_dependency_binding_digests(
            "B",
            &task_b,
            "deliberately-not-equal-to-primary-or-historical-snapshot",
        );
        assert!(
            readiness_binding.is_ok(),
            "carried readiness must bind exact composed ChangeSet membership: {readiness_binding:?}"
        );
        assert_eq!(
            std::fs::read_to_string(repository_root.join("tracked.txt"))
                .unwrap_or_else(|error| panic!("read protected primary: {error}")),
            "base\n"
        );
        drop(controller);
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn dependent_carry_requires_upstream_to_actually_carry_into_n_plus_one() {
        let (base, mut state) = temp_state("dependency-closed-carry");
        let artifact_store = ArtifactStore::open(base.join("cas"))
            .unwrap_or_else(|error| panic!("artifact store: {error}"));
        let verification_artifact = artifact_store
            .put(&mut state, b"verification")
            .unwrap_or_else(|error| panic!("verification artifact: {error}"));
        let plan_one_digest = format!("sha256:{}", "1".repeat(64));
        let plan_two_digest = format!("sha256:{}", "2".repeat(64));
        let task = |task_id: &str, dependency: Option<&str>| {
            json!({
                "task_id": task_id,
                "dependencies": dependency.into_iter().collect::<Vec<_>>(),
                "dependency_bindings": dependency.into_iter().map(|upstream| json!({
                    "upstream_task_id": upstream,
                    "required_artifact_ids": [format!("artifact.{upstream}")],
                    "required_acceptance_criterion_ids": [format!("AC.{upstream}")],
                    "freshness": "carry_forward_if_inputs_unchanged"
                })).collect::<Vec<_>>(),
                "implementation_contract": {"inputs": []},
                "acceptance_criteria": [{
                    "criterion_id": format!("AC.{task_id}"),
                    "evidence_freshness": "carry_forward_if_inputs_unchanged",
                    "required": true
                }],
                "expected_artifacts": [{
                    "artifact_id": format!("artifact.{task_id}"),
                    "required": true
                }]
            })
        };
        let task_a = task("A", None);
        let task_b = task("B", Some("A"));
        let digest_a = digest_json(&task_a).unwrap_or_else(|error| panic!("digest A: {error}"));
        let digest_b = digest_json(&task_b).unwrap_or_else(|error| panic!("digest B: {error}"));
        let next_plan = json!({
            "repositories": [{"instructions": []}],
            "tasks": [task_a.clone(), task_b.clone()]
        });
        let instruction_digest = plan_instruction_fingerprint_digest(&next_plan)
            .unwrap_or_else(|error| panic!("instruction digest: {error}"));
        state
            .put_state(
                "controller.compilation_evidence",
                &revision_record_key("plan.fixture", 1),
                &json!({"exact_evidence": []}).to_string(),
            )
            .unwrap_or_else(|error| panic!("persist compilation evidence: {error}"));

        let mut previous = active_fixture(&base, 1, &plan_one_digest);
        for (task_id, task_value, task_digest, source_fingerprints) in [
            (
                "A",
                &task_a,
                &digest_a,
                BTreeMap::from([(
                    "missing-upstream-input.rs".to_owned(),
                    format!("sha256:{}", "9".repeat(64)),
                )]),
            ),
            ("B", &task_b, &digest_b, BTreeMap::new()),
        ] {
            let old_lease = WorktreeLease {
                schema_version: 1,
                lease_id: format!("worktree.old-{task_id}"),
                repository_id: "repo.fixture".to_owned(),
                plan_id: "plan.fixture".to_owned(),
                plan_revision: 1,
                task_id: task_id.to_owned(),
                task_contract_digest: task_digest.clone(),
                primary_root: base.join("repo"),
                controller_root: base.join("worktrees"),
                worktree_path: base.join("worktrees").join(format!("old-{task_id}")),
                base_head: "deadbeef".to_owned(),
            };
            previous.tasks.insert(
                task_id.to_owned(),
                TaskRuntime {
                    state: TaskState::Succeeded,
                    attempts_started: 1,
                    model_calls_used: 1,
                    failure_counts: BTreeMap::new(),
                    retry_exhausted: false,
                    resource_deferrals_used: 0,
                    resource_retry_exhausted: false,
                    resource_deferred_from: None,
                    worktree_lease: Some(old_lease),
                    worktree_state: Some(WorktreeLifecycle::Materialized),
                    change_set: None,
                    change_set_artifact_digest: None,
                    change_set_carry: None,
                    worktree_baseline: None,
                    worktree_composition: Vec::new(),
                    worktree_conflict: None,
                    task_contract_digest: task_digest.clone(),
                    task: task_value.clone(),
                },
            );
            let verification_id = format!("verification.{task_id}");
            let verification = VerificationResultV1 {
                schema_version: super::VERIFICATION_RESULT_SCHEMA_VERSION,
                verification_id: verification_id.clone(),
                plan_id: "plan.fixture".to_owned(),
                plan_revision: 1,
                plan_digest: plan_one_digest.clone(),
                task_id: task_id.to_owned(),
                task_contract_digest: task_digest.clone(),
                attempt_id: format!("attempt.{task_id}.1"),
                execution_epoch: 1,
                evaluator: "builtin.diff.scoped_change.v1".to_owned(),
                acceptance_contract_digest: format!("sha256:{}", "3".repeat(64)),
                diff_digest: format!("sha256:{}", "4".repeat(64)),
                post_snapshot_digest: "snapshot.N".to_owned(),
                expected_target_mode: 0o644,
                observed_target_mode: 0o644,
                evidence_ids: vec!["ev.N".to_owned()],
                passed: true,
                failure_code: None,
            };
            state
                .put_state(
                    "controller.verification",
                    &revision_scoped_key("plan.fixture", 1, &verification_id),
                    &serde_json::to_string(&verification)
                        .unwrap_or_else(|error| panic!("verification json: {error}")),
                )
                .unwrap_or_else(|error| panic!("persist verification: {error}"));
            let proof = TaskCarryFingerprintV1 {
                schema_version: super::TASK_CARRY_FINGERPRINT_SCHEMA_VERSION,
                plan_id: "plan.fixture".to_owned(),
                plan_revision: 1,
                plan_digest: plan_one_digest.clone(),
                task_id: task_id.to_owned(),
                task_contract_digest: task_digest.clone(),
                implementation_inputs_digest: digest_json(&json!([]))
                    .unwrap_or_else(|error| panic!("inputs digest: {error}")),
                dependency_contract_digest: digest_json(&task_value["dependency_bindings"])
                    .unwrap_or_else(|error| panic!("dependency digest: {error}")),
                instruction_fingerprint_digest: instruction_digest.clone(),
                source_fingerprints,
                execution_provenance: None,
                acceptance_contract_digest: verification.acceptance_contract_digest.clone(),
                verification_id: verification_id.clone(),
                verification_artifact_digest: verification_artifact.digest.clone(),
            };
            state
                .put_state(
                    "controller.task_carry_fingerprint",
                    &revision_scoped_key("plan.fixture", 1, task_id),
                    &serde_json::to_string(&proof)
                        .unwrap_or_else(|error| panic!("carry proof json: {error}")),
                )
                .unwrap_or_else(|error| panic!("persist carry proof: {error}"));
            for (namespace, kind, binding_id) in [
                (
                    "controller.artifact_binding",
                    "artifact",
                    format!("artifact.{task_id}"),
                ),
                (
                    "controller.acceptance_binding",
                    "acceptance",
                    format!("AC.{task_id}"),
                ),
            ] {
                let binding = VerifiedOutputBindingV1 {
                    schema_version: super::VERIFIED_OUTPUT_BINDING_SCHEMA_VERSION,
                    plan_id: "plan.fixture".to_owned(),
                    plan_revision: 1,
                    plan_digest: plan_one_digest.clone(),
                    task_id: task_id.to_owned(),
                    task_contract_digest: task_digest.clone(),
                    attempt_id: format!("attempt.{task_id}.1"),
                    binding_kind: kind.to_owned(),
                    binding_id: binding_id.clone(),
                    verification_id: verification_id.clone(),
                    verification_artifact_digest: verification_artifact.digest.clone(),
                    repository_snapshot_digest: "snapshot.N".to_owned(),
                    change_set_digest: None,
                    carried_from_plan_revision: None,
                    carried_from_plan_digest: None,
                };
                state
                    .put_state(
                        namespace,
                        &revision_scoped_key(
                            "plan.fixture",
                            1,
                            &output_binding_key(task_id, &binding_id),
                        ),
                        &serde_json::to_string(&binding)
                            .unwrap_or_else(|error| panic!("binding json: {error}")),
                    )
                    .unwrap_or_else(|error| panic!("persist binding: {error}"));
            }
        }

        let diff = PlanRevisionDiff {
            plan_id: "plan.fixture".to_owned(),
            from_revision: 1,
            to_revision: 2,
            from_plan_digest: plan_one_digest,
            to_plan_digest: plan_two_digest.clone(),
            scope: ReplanScope::Task,
            invalidated_contract_ids: vec!["ASSUME.unrelated".to_owned()],
            affected_task_ids: vec!["X".to_owned()],
            unchanged_task_ids: vec!["A".to_owned(), "B".to_owned()],
            changed_task_ids: vec!["X".to_owned()],
            added_task_ids: Vec::new(),
            removed_task_ids: Vec::new(),
        };
        let build = build_superseding_runtime(
            &state,
            &ProjectRegistry::new(),
            &previous,
            &next_plan,
            &plan_two_digest,
            &json!({"exact_evidence": []}),
            &diff,
            "snapshot.N+1",
        )
        .unwrap_or_else(|error| panic!("superseding runtime: {error}"));
        assert_eq!(build.tasks["A"].state, TaskState::Planned);
        assert_eq!(build.tasks["B"].state, TaskState::Planned);
        assert!(build.tasks.values().all(|task| {
            task.worktree_lease.is_none()
                && task.worktree_state.is_none()
                && task.change_set.is_none()
                && task.change_set_artifact_digest.is_none()
        }));
        assert!(build.carry_records.is_empty());
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn scope_lineage_survives_unrelated_replan_and_reopen_and_split_inherits_it() {
        let (base, mut state) = temp_state("scope-lineage");
        let plan_digest = format!("sha256:{}", "a".repeat(64));
        let active_r2 = active_fixture(&base, 2, &plan_digest);
        let classification_a = FailureClassification {
            kind: FailureClassificationKind::PlanFailure,
            scope: Some(ReplanScope::DependencyBranch),
            affected_task_ids: vec!["A".to_owned()],
            affected_contract_ids: vec!["ASSUME.first".to_owned()],
            evidence_refs: vec!["ev.first".to_owned()],
        };
        let lineage_a = scope_lineage_id(&state, &active_r2, &classification_a)
            .unwrap_or_else(|error| panic!("lineage A: {error}"));
        state
            .put_state(
                "controller.replan_task_lineage",
                &revision_scoped_key("plan.fixture", 2, "A"),
                &json!({
                    "plan_id":"plan.fixture","revision":2,"task_id":"A","lineage_id":lineage_a
                })
                .to_string(),
            )
            .unwrap_or_else(|error| panic!("persist lineage A: {error}"));
        let diff_b = PlanRevisionDiff {
            plan_id: "plan.fixture".to_owned(),
            from_revision: 2,
            to_revision: 3,
            from_plan_digest: plan_digest.clone(),
            to_plan_digest: format!("sha256:{}", "b".repeat(64)),
            scope: ReplanScope::Task,
            invalidated_contract_ids: vec!["ASSUME.B".to_owned()],
            affected_task_ids: vec!["B".to_owned()],
            unchanged_task_ids: vec!["A".to_owned()],
            changed_task_ids: vec!["B".to_owned()],
            added_task_ids: Vec::new(),
            removed_task_ids: Vec::new(),
        };
        let records = lineage_records_for_supersession(&state, &active_r2, &diff_b, "lineage.B")
            .unwrap_or_else(|error| panic!("lineage records B: {error}"));
        for (namespace, key, value) in records {
            state
                .put_state(&namespace, &key, &value)
                .unwrap_or_else(|error| panic!("persist copied lineage: {error}"));
        }
        drop(state);
        let state = StateStore::open(base.join("state.sqlite3"))
            .unwrap_or_else(|error| panic!("reopen state: {error}"));
        let active_r3 = active_fixture(&base, 3, &diff_b.to_plan_digest);
        let classification_a_different_clause = FailureClassification {
            affected_contract_ids: vec!["ASSUME.second".to_owned()],
            evidence_refs: vec!["ev.second".to_owned()],
            ..classification_a
        };
        assert_eq!(
            scope_lineage_id(&state, &active_r3, &classification_a_different_clause)
                .unwrap_or_else(|error| panic!("reused lineage A: {error}")),
            lineage_a
        );
        let split = PlanRevisionDiff {
            plan_id: "plan.fixture".to_owned(),
            from_revision: 3,
            to_revision: 4,
            from_plan_digest: diff_b.to_plan_digest.clone(),
            to_plan_digest: format!("sha256:{}", "c".repeat(64)),
            scope: ReplanScope::DependencyBranch,
            invalidated_contract_ids: vec!["ASSUME.second".to_owned()],
            affected_task_ids: vec!["A".to_owned()],
            unchanged_task_ids: vec!["B".to_owned()],
            changed_task_ids: vec!["A".to_owned()],
            added_task_ids: vec!["A2".to_owned()],
            removed_task_ids: Vec::new(),
        };
        let split_records =
            lineage_records_for_supersession(&state, &active_r3, &split, &lineage_a)
                .unwrap_or_else(|error| panic!("split lineage records: {error}"));
        let a2 = split_records
            .iter()
            .find(|(_, key, _)| key.ends_with(":A2"))
            .unwrap_or_else(|| panic!("split task lineage missing"));
        assert!(a2.2.contains(&lineage_a));
        drop(state);
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn ambiguous_scope_lineage_and_nonterminal_process_leases_fail_closed() {
        let (base, mut state) = temp_state("ambiguous-lineage-lease");
        let active = active_fixture(&base, 2, &format!("sha256:{}", "d".repeat(64)));
        for (task, lineage) in [("A", "lineage.A"), ("B", "lineage.B")] {
            state
                .put_state(
                    "controller.replan_task_lineage",
                    &revision_scoped_key("plan.fixture", 2, task),
                    &json!({
                        "plan_id":"plan.fixture","revision":2,"task_id":task,"lineage_id":lineage
                    })
                    .to_string(),
                )
                .unwrap_or_else(|error| panic!("persist lineage: {error}"));
        }
        let classification = FailureClassification {
            kind: FailureClassificationKind::PlanFailure,
            scope: Some(ReplanScope::DependencyBranch),
            affected_task_ids: vec!["A".to_owned(), "B".to_owned()],
            affected_contract_ids: vec!["binding:B:A".to_owned()],
            evidence_refs: vec!["ev".to_owned()],
        };
        let Err(error) = scope_lineage_id(&state, &active, &classification) else {
            panic!("ambiguous inherited lineages must fail closed");
        };
        assert!(error.to_string().contains("ambiguous inherited lineages"));
        let lease = |schema_version, state: &str| RecoveryProcessLease {
            schema_version,
            lease_id: format!("lease.{state}"),
            task_id: "A".to_owned(),
            attempt_id: "attempt.A".to_owned(),
            action_id: "action.A".to_owned(),
            process_group_id: None,
            leader_identity: None,
            state: state.to_owned(),
        };
        assert!(process_lease_is_terminal(&lease(
            super::RECOVERY_PROCESS_LEASE_SCHEMA_VERSION,
            "reaped"
        )));
        assert!(process_lease_is_terminal(&lease(
            super::RECOVERY_PROCESS_LEASE_SCHEMA_VERSION,
            "reaped_recovery"
        )));
        assert!(!process_lease_is_terminal(&lease(
            super::RECOVERY_PROCESS_LEASE_SCHEMA_VERSION,
            "pending_spawn"
        )));
        assert!(!process_lease_is_terminal(&lease(
            super::RECOVERY_PROCESS_LEASE_SCHEMA_VERSION,
            "active"
        )));
        assert!(!process_lease_is_terminal(&lease(
            super::RECOVERY_PROCESS_LEASE_SCHEMA_VERSION,
            "future_unknown"
        )));
        assert!(!process_lease_is_terminal(&lease(999, "reaped")));
        let pending = lease(
            super::RECOVERY_PROCESS_LEASE_SCHEMA_VERSION,
            "pending_spawn",
        );
        state
            .put_state(
                "controller.process_lease",
                "action.A",
                &serde_json::to_string(&pending)
                    .unwrap_or_else(|error| panic!("pending lease json: {error}")),
            )
            .unwrap_or_else(|error| panic!("persist pending lease: {error}"));
        assert!(
            has_unresolved_process_lease(&state)
                .unwrap_or_else(|error| panic!("pending unresolved check: {error}"))
        );
        let reaped = lease(super::RECOVERY_PROCESS_LEASE_SCHEMA_VERSION, "reaped");
        state
            .put_state(
                "controller.process_lease",
                "action.A",
                &serde_json::to_string(&reaped)
                    .unwrap_or_else(|error| panic!("reaped lease json: {error}")),
            )
            .unwrap_or_else(|error| panic!("persist reaped lease: {error}"));
        assert!(
            !has_unresolved_process_lease(&state)
                .unwrap_or_else(|error| panic!("reaped unresolved check: {error}"))
        );
        let unknown = lease(
            super::RECOVERY_PROCESS_LEASE_SCHEMA_VERSION,
            "future_unknown",
        );
        state
            .put_state(
                "controller.process_lease",
                "action.A",
                &serde_json::to_string(&unknown)
                    .unwrap_or_else(|error| panic!("unknown lease json: {error}")),
            )
            .unwrap_or_else(|error| panic!("persist unknown lease: {error}"));
        assert!(
            has_unresolved_process_lease(&state)
                .unwrap_or_else(|error| panic!("unknown unresolved check: {error}"))
        );
        drop(state);
        let _ = std::fs::remove_dir_all(base);
    }
}
