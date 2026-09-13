//! Deterministic tool authorization, action journaling, reconciliation, and process execution.
//!
//! Models and repository content may propose actions, but this crate requires exact
//! Controller-created authority to exist durably before an operating-system process starts.

use sha2::{Digest, Sha256};
use sovereign_evidence::{ArtifactStore, EvidenceError};
use sovereign_policy::{
    CommandPolicy, CommandRisk, CommandSpec, ExecutionIsolationBackend, IsolatedCommand,
    IsolationRequest, PolicyError, sanitized_environment,
};
use sovereign_state::{
    ActionTransition, NewActionRecord, PersistedActionRecord, StateError, StateStore,
};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs;
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub enum ToolError {
    Policy(PolicyError),
    State(StateError),
    Evidence(EvidenceError),
    Io(std::io::Error),
    Authority(String),
    InvalidTransition(String),
    ResourceLimit(String),
    RecoveryBlocked(String),
    Clock(std::time::SystemTimeError),
}

impl Display for ToolError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Policy(error) => write!(f, "tool policy error: {error}"),
            Self::State(error) => write!(f, "tool state error: {error}"),
            Self::Evidence(error) => write!(f, "tool evidence error: {error}"),
            Self::Io(error) => write!(f, "tool I/O error: {error}"),
            Self::Authority(message) => write!(f, "tool authority error: {message}"),
            Self::InvalidTransition(message) => write!(f, "invalid action transition: {message}"),
            Self::ResourceLimit(message) => write!(f, "tool resource limit: {message}"),
            Self::RecoveryBlocked(message) => write!(f, "tool recovery blocked: {message}"),
            Self::Clock(error) => write!(f, "tool clock error: {error}"),
        }
    }
}

impl Error for ToolError {}

impl From<PolicyError> for ToolError {
    fn from(value: PolicyError) -> Self {
        Self::Policy(value)
    }
}

impl From<StateError> for ToolError {
    fn from(value: StateError) -> Self {
        Self::State(value)
    }
}

impl From<EvidenceError> for ToolError {
    fn from(value: EvidenceError) -> Self {
        Self::Evidence(value)
    }
}

impl From<std::io::Error> for ToolError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<std::time::SystemTimeError> for ToolError {
    fn from(value: std::time::SystemTimeError) -> Self {
        Self::Clock(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PermissionClass {
    ProcessExec,
    RepositoryWrite,
    PackageInstall,
    NetworkRead,
    NetworkWrite,
    Destructive,
    ExternalSideEffect,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolManifest {
    pub tool_id: String,
    pub version: String,
    pub content_digest: String,
    pub permission_ceiling: BTreeSet<PermissionClass>,
    pub declared_risk_floor: CommandRisk,
}

impl ToolManifest {
    /// Validates the stable manifest identity before it participates in authorization.
    ///
    /// # Errors
    /// Returns an authority error when required immutable identity fields are empty.
    pub fn validate(&self) -> Result<(), ToolError> {
        if self.tool_id.trim().is_empty()
            || self.version.trim().is_empty()
            || !self.content_digest.starts_with("sha256:")
        {
            return Err(ToolError::Authority(
                "tool manifest requires id, version, and sha256 content digest".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconciliationMode {
    IdempotentRead,
    UnsafeSideEffect,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedAction {
    pub action_id: String,
    pub plan_id: String,
    pub plan_revision: u32,
    pub task_id: String,
    pub attempt_id: String,
    pub tool_id: String,
    pub tool_version: String,
    pub tool_digest: String,
    pub executable_digest: String,
    pub repository_id: String,
    pub destination_digest: Option<String>,
    pub permission_class: PermissionClass,
    pub execution_epoch: i64,
    pub policy_digest: String,
    pub isolation_policy_digest: String,
    pub nonce: String,
    pub expires_at_ms: i64,
    pub command: CommandSpec,
    pub individually_authorized_environment: BTreeSet<String>,
    pub reconciliation_mode: ReconciliationMode,
}

impl AuthorizedAction {
    /// Computes the exact deterministic payload digest bound by durable authorization.
    #[must_use]
    pub fn payload_digest(&self) -> String {
        let mut hasher = Sha256::new();
        digest_field(&mut hasher, &self.action_id);
        digest_field(&mut hasher, &self.plan_id);
        hasher.update(self.plan_revision.to_be_bytes());
        digest_field(&mut hasher, &self.task_id);
        digest_field(&mut hasher, &self.attempt_id);
        digest_field(&mut hasher, &self.tool_id);
        digest_field(&mut hasher, &self.tool_version);
        digest_field(&mut hasher, &self.tool_digest);
        digest_field(&mut hasher, &self.executable_digest);
        digest_field(&mut hasher, &self.repository_id);
        if let Some(destination_digest) = &self.destination_digest {
            digest_field(&mut hasher, destination_digest);
        } else {
            digest_field(&mut hasher, "none");
        }
        digest_field(&mut hasher, permission_name(self.permission_class));
        hasher.update(self.execution_epoch.to_be_bytes());
        digest_field(&mut hasher, &self.policy_digest);
        digest_field(&mut hasher, &self.isolation_policy_digest);
        digest_field(&mut hasher, &self.nonce);
        hasher.update(self.expires_at_ms.to_be_bytes());
        digest_field(&mut hasher, &self.command.executable.display().to_string());
        for arg in &self.command.args {
            digest_field(&mut hasher, arg);
        }
        digest_field(
            &mut hasher,
            &self.command.working_directory.display().to_string(),
        );
        for (name, value) in &self.command.environment {
            digest_field(&mut hasher, name);
            digest_field(&mut hasher, value);
        }
        digest_field(
            &mut hasher,
            match self.command.mode {
                sovereign_policy::CommandMode::Direct => "direct",
                sovereign_policy::CommandMode::Shell => "shell",
            },
        );
        digest_field(&mut hasher, command_risk_name(self.command.declared_risk));
        hasher.update(self.command.timeout_ms.to_be_bytes());
        hasher.update(self.command.output_limit_bytes.to_be_bytes());
        hasher.update(self.command.disk_write_limit_bytes.to_be_bytes());
        hasher.update(self.command.subprocess_limit.to_be_bytes());
        for name in &self.individually_authorized_environment {
            digest_field(&mut hasher, name);
        }
        digest_field(
            &mut hasher,
            match self.reconciliation_mode {
                ReconciliationMode::IdempotentRead => "idempotent_read",
                ReconciliationMode::UnsafeSideEffect => "unsafe_side_effect",
            },
        );
        format!("sha256:{:x}", hasher.finalize())
    }

    /// Checks static identity and expiry fields that must hold before journal authorization.
    ///
    /// # Errors
    /// Returns an authority error for malformed IDs/digests, negative epochs, or expired claims.
    pub fn validate(&self, now_ms: i64) -> Result<(), ToolError> {
        if self.action_id.trim().is_empty()
            || self.plan_id.trim().is_empty()
            || self.task_id.trim().is_empty()
            || self.attempt_id.trim().is_empty()
            || self.tool_id.trim().is_empty()
            || self.tool_version.trim().is_empty()
            || self.repository_id.trim().is_empty()
            || self.nonce.trim().is_empty()
            || !self.tool_digest.starts_with("sha256:")
            || !self.executable_digest.starts_with("sha256:")
            || !self.policy_digest.starts_with("sha256:")
            || !self.isolation_policy_digest.starts_with("sha256:")
            || self
                .destination_digest
                .as_ref()
                .is_some_and(|digest| !digest.starts_with("sha256:"))
            || self.execution_epoch < 0
        {
            return Err(ToolError::Authority(
                "authorized action has incomplete exact-binding fields".to_owned(),
            ));
        }
        if self.expires_at_ms < now_ms {
            return Err(ToolError::Authority("authorized action expired".to_owned()));
        }
        Ok(())
    }
}

pub struct ActionJournal<'a> {
    store: &'a mut StateStore,
}

impl<'a> ActionJournal<'a> {
    #[must_use]
    pub fn new(store: &'a mut StateStore) -> Self {
        Self { store }
    }

    /// Durably records a proposed exact action before it can be authorized.
    ///
    /// # Errors
    /// Returns an authority or persistence error for malformed or duplicate actions.
    pub fn prepare(&mut self, action: &AuthorizedAction) -> Result<i64, ToolError> {
        action.validate(unix_millis()?)?;
        let payload_digest = action.payload_digest();
        Ok(self.store.insert_action_record(NewActionRecord {
            action_id: &action.action_id,
            state: ActionState::Prepared.as_str(),
            payload_digest: &payload_digest,
            policy_digest: &action.policy_digest,
            execution_epoch: action.execution_epoch,
            event_id: &event_id(&action.action_id, ActionState::Prepared.as_str()),
            event_kind: ActionState::Prepared.as_str(),
            payload_json: "{}",
        })?)
    }

    /// Durably records the exact action authorization before dispatch is possible.
    ///
    /// # Errors
    /// Returns an authority or persistence error when the exact action cannot be recorded.
    pub fn authorize(
        &mut self,
        action: &AuthorizedAction,
        manifest: &ToolManifest,
    ) -> Result<i64, ToolError> {
        let now = unix_millis()?;
        action.validate(now)?;
        manifest.validate()?;
        if manifest.tool_id != action.tool_id {
            return Err(ToolError::Authority(format!(
                "action tool {} does not match manifest {}",
                action.tool_id, manifest.tool_id
            )));
        }
        if manifest.version != action.tool_version || manifest.content_digest != action.tool_digest
        {
            return Err(ToolError::Authority(format!(
                "action tool identity does not match manifest {}@{}",
                manifest.tool_id, manifest.version
            )));
        }
        if !manifest
            .permission_ceiling
            .contains(&action.permission_class)
        {
            return Err(ToolError::Authority(format!(
                "tool manifest does not permit {:?}",
                action.permission_class
            )));
        }
        if action.command.declared_risk < manifest.declared_risk_floor {
            return Err(ToolError::Authority(format!(
                "action risk {:?} is below tool manifest floor {:?}",
                action.command.declared_risk, manifest.declared_risk_floor
            )));
        }
        let current_epoch = self.store.current_execution_epoch()?;
        if current_epoch != action.execution_epoch {
            return Err(ToolError::Authority(format!(
                "authorization epoch mismatch: action={}, controller={current_epoch}",
                action.execution_epoch
            )));
        }
        if self.store.action_record(&action.action_id)?.is_none() {
            self.prepare(action)?;
        }
        let prepared = self
            .store
            .action_record(&action.action_id)?
            .ok_or_else(|| ToolError::Authority("prepared action disappeared".to_owned()))?;
        if prepared.state != ActionState::Prepared.as_str()
            || prepared.payload_digest != action.payload_digest()
            || prepared.policy_digest != action.policy_digest
            || prepared.execution_epoch != action.execution_epoch
        {
            return Err(ToolError::Authority(format!(
                "prepared action does not match exact authorization {}",
                action.action_id
            )));
        }
        self.transition(action, ActionState::Prepared, ActionState::Authorized)
    }

    /// Verifies that current durable authority still matches the exact action payload.
    ///
    /// # Errors
    /// Returns an authority error for missing, stale, mutated, or expired authorization.
    pub fn verify_authorized(
        &self,
        action: &AuthorizedAction,
    ) -> Result<PersistedActionRecord, ToolError> {
        action.validate(unix_millis()?)?;
        let record = self
            .store
            .action_record(&action.action_id)?
            .ok_or_else(|| {
                ToolError::Authority(format!(
                    "missing durable authorization for {}",
                    action.action_id
                ))
            })?;
        if record.state != "authorized"
            || record.payload_digest != action.payload_digest()
            || record.policy_digest != action.policy_digest
            || record.execution_epoch != action.execution_epoch
            || self.store.current_execution_epoch()? != action.execution_epoch
        {
            return Err(ToolError::Authority(format!(
                "durable authorization no longer matches exact action {}",
                action.action_id
            )));
        }
        Ok(record)
    }

    /// Applies one legal action-state transition and appends its durable audit event atomically.
    ///
    /// # Errors
    /// Returns a transition or persistence error for illegal/stale transitions.
    pub fn transition(
        &mut self,
        action: &AuthorizedAction,
        expected: ActionState,
        next: ActionState,
    ) -> Result<i64, ToolError> {
        if !legal_transition(expected, next) {
            return Err(ToolError::InvalidTransition(format!(
                "{} -> {}",
                expected.as_str(),
                next.as_str()
            )));
        }
        Ok(self.store.transition_action_with_event(ActionTransition {
            action_id: &action.action_id,
            expected_state: expected.as_str(),
            next_state: next.as_str(),
            expected_epoch: action.execution_epoch,
            event_id: &event_id(&action.action_id, next.as_str()),
            event_kind: next.as_str(),
            payload_json: "{}",
            result_digest: None,
        })?)
    }

    /// Publishes a durable receipt to CAS and binds it to the observed action before commit.
    ///
    /// # Errors
    /// Returns an evidence/state error when publication or durable observation fails.
    pub fn observe_with_receipt(
        &mut self,
        action: &AuthorizedAction,
        artifacts: &ArtifactStore,
        receipt: &[u8],
    ) -> Result<String, ToolError> {
        let artifact = artifacts.put(self.store, receipt)?;
        let digest = artifact.digest;
        self.store.transition_action_with_event(ActionTransition {
            action_id: &action.action_id,
            expected_state: ActionState::Dispatched.as_str(),
            next_state: ActionState::Observed.as_str(),
            expected_epoch: action.execution_epoch,
            event_id: &event_id(&action.action_id, ActionState::Observed.as_str()),
            event_kind: ActionState::Observed.as_str(),
            payload_json: "{}",
            result_digest: Some(&digest),
        })?;
        Ok(digest)
    }

    /// Commits an observed/reconciled action only when durable result evidence is bound.
    ///
    /// # Errors
    /// Returns an authority/state error when evidence is missing or state is stale.
    pub fn commit_with_bound_result(
        &mut self,
        action: &AuthorizedAction,
        expected: ActionState,
    ) -> Result<i64, ToolError> {
        if !matches!(expected, ActionState::Observed | ActionState::Reconciled) {
            return Err(ToolError::InvalidTransition(
                "commit requires observed or reconciled state".to_owned(),
            ));
        }
        let record = self
            .store
            .action_record(&action.action_id)?
            .ok_or_else(|| ToolError::Authority("missing action for commit".to_owned()))?;
        if record.state != expected.as_str() || record.result_digest.is_none() {
            return Err(ToolError::Authority(
                "committed action requires durable bound result evidence".to_owned(),
            ));
        }
        self.transition(action, expected, ActionState::Committed)
    }

    /// Converts a crash-left dispatched action into explicit unknown state on recovery.
    ///
    /// # Errors
    /// Returns a transition or persistence error when durable state does not match.
    pub fn recover_dispatched_as_unknown(
        &mut self,
        action: &AuthorizedAction,
    ) -> Result<i64, ToolError> {
        self.transition(action, ActionState::Dispatched, ActionState::Unknown)
    }

    /// Reconciles an explicit unknown action using deterministic proof rules.
    /// Unsafe unknown side effects remain unknown without outcome proof.
    ///
    /// # Errors
    /// Returns a transition or persistence error when the durable action state is stale.
    pub fn reconcile_unknown(
        &mut self,
        action: &AuthorizedAction,
        proof: Option<ReconciliationProof>,
    ) -> Result<Reconciliation, ToolError> {
        let decision = reconcile(action.reconciliation_mode, proof);
        match decision {
            Reconciliation::BlockedUnsafeUnknown => {}
            Reconciliation::SafeToRetry => {
                self.transition(action, ActionState::Unknown, ActionState::Reconciled)?;
            }
            Reconciliation::CommitObservedEffect => {
                self.transition(action, ActionState::Unknown, ActionState::Reconciled)?;
            }
            Reconciliation::FailProvenAbsent => {
                self.transition(action, ActionState::Unknown, ActionState::Reconciled)?;
                self.transition(action, ActionState::Reconciled, ActionState::Failed)?;
            }
        }
        Ok(decision)
    }

    /// Returns the durable action record for recovery/tests.
    ///
    /// # Errors
    /// Returns a persistence error on state read failure.
    pub fn record(&self, action_id: &str) -> Result<Option<PersistedActionRecord>, ToolError> {
        Ok(self.store.action_record(action_id)?)
    }

    fn record_process_lease(
        &mut self,
        action: &AuthorizedAction,
        pgid: Option<u32>,
        leader_identity: Option<&str>,
        state: &str,
    ) -> Result<(), ToolError> {
        let value = serde_json::json!({
            "schema_version": 1,
            "lease_id": format!("process.{}", action.action_id),
            "task_id": action.task_id,
            "attempt_id": action.attempt_id,
            "action_id": action.action_id,
            "process_group_id": pgid,
            "leader_identity": leader_identity,
            "state": state,
        });
        self.store.put_state(
            "controller.process_lease",
            &action.action_id,
            &value.to_string(),
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionState {
    Prepared,
    Authorized,
    Dispatched,
    Observed,
    Committed,
    Unknown,
    Reconciled,
    Failed,
}

impl ActionState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Authorized => "authorized",
            Self::Dispatched => "dispatched",
            Self::Observed => "observed",
            Self::Committed => "committed",
            Self::Unknown => "unknown",
            Self::Reconciled => "reconciled",
            Self::Failed => "failed",
        }
    }
}

const fn legal_transition(from: ActionState, to: ActionState) -> bool {
    matches!(
        (from, to),
        (ActionState::Prepared, ActionState::Authorized)
            | (ActionState::Authorized, ActionState::Dispatched)
            | (
                ActionState::Dispatched,
                ActionState::Observed | ActionState::Unknown
            )
            | (
                ActionState::Observed | ActionState::Reconciled,
                ActionState::Committed
            )
            | (ActionState::Unknown, ActionState::Reconciled)
            | (ActionState::Reconciled, ActionState::Failed)
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconciliationProof {
    SafeIdempotentRetry,
    EffectObserved,
    EffectAbsent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reconciliation {
    SafeToRetry,
    CommitObservedEffect,
    FailProvenAbsent,
    BlockedUnsafeUnknown,
}

/// Deterministically decides how an unknown action may proceed. Text cannot override this rule.
#[must_use]
pub const fn reconcile(
    mode: ReconciliationMode,
    proof: Option<ReconciliationProof>,
) -> Reconciliation {
    match (mode, proof) {
        (
            ReconciliationMode::IdempotentRead,
            None | Some(ReconciliationProof::SafeIdempotentRetry),
        ) => Reconciliation::SafeToRetry,
        (_, Some(ReconciliationProof::EffectObserved)) => Reconciliation::CommitObservedEffect,
        (_, Some(ReconciliationProof::EffectAbsent)) => Reconciliation::FailProvenAbsent,
        (
            ReconciliationMode::UnsafeSideEffect,
            None | Some(ReconciliationProof::SafeIdempotentRetry),
        ) => Reconciliation::BlockedUnsafeUnknown,
    }
}

pub trait ToolAdapter {
    fn manifest(&self) -> &ToolManifest;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawToolResult {
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub elapsed_ms: u64,
    pub terminated_for_limit: Option<ResourceLimitKind>,
    pub process_group_reaped: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceLimitKind {
    Timeout,
    OutputBytes,
    DiskBytes,
    Subprocesses,
}

pub struct ProcessRunner<'a, I: ExecutionIsolationBackend> {
    command_policy: &'a CommandPolicy,
    isolation: &'a I,
    poll_interval: Duration,
}

struct PreparedExecution {
    isolated: IsolatedCommand,
    environment: BTreeMap<String, String>,
    baseline_disk: u64,
}

impl<'a, I: ExecutionIsolationBackend> ProcessRunner<'a, I> {
    #[must_use]
    pub fn new(command_policy: &'a CommandPolicy, isolation: &'a I) -> Self {
        Self {
            command_policy,
            isolation,
            poll_interval: Duration::from_millis(20),
        }
    }

    /// Executes one already-durably-authorized action under structured policy and isolation.
    ///
    /// # Errors
    /// Returns policy, authority, resource, or recovery errors. Once dispatch has been
    /// journaled, ambiguous cleanup is represented as `unknown`, never inferred as failure.
    pub fn run(
        &self,
        journal: &mut ActionJournal<'_>,
        action: &AuthorizedAction,
        isolation_request: &IsolationRequest,
        artifacts: &ArtifactStore,
    ) -> Result<RawToolResult, ToolError> {
        journal.verify_authorized(action)?;
        let prepared = self.prepare_execution(action, isolation_request)?;
        journal.transition(action, ActionState::Authorized, ActionState::Dispatched)?;
        journal.record_process_lease(action, None, None, "pending_spawn")?;
        self.execute_dispatched(journal, action, artifacts, prepared)
    }

    fn prepare_execution(
        &self,
        action: &AuthorizedAction,
        isolation_request: &IsolationRequest,
    ) -> Result<PreparedExecution, ToolError> {
        let effective_risk = self.command_policy.authorize(&action.command)?;
        let executable = self
            .command_policy
            .pinned_executable(&action.command.executable)?;
        if executable.sha256 != action.executable_digest {
            return Err(ToolError::Authority(
                "authorized executable digest no longer matches pinned executable".to_owned(),
            ));
        }
        if isolation_request.digest()? != action.isolation_policy_digest {
            return Err(ToolError::Authority(
                "authorized isolation-policy digest does not match execution request".to_owned(),
            ));
        }
        if isolation_request.allow_repository_write
            && !matches!(
                action.permission_class,
                PermissionClass::RepositoryWrite
                    | PermissionClass::PackageInstall
                    | PermissionClass::Destructive
            )
        {
            return Err(ToolError::Authority(
                "process execution alone does not grant repository write authority".to_owned(),
            ));
        }
        if effective_risk == CommandRisk::PackageInstall
            && action.permission_class != PermissionClass::PackageInstall
        {
            return Err(ToolError::Authority(
                "package installation requires exact package_install action authority".to_owned(),
            ));
        }
        if effective_risk == CommandRisk::Destructive
            && action.permission_class != PermissionClass::Destructive
        {
            return Err(ToolError::Authority(
                "destructive command requires exact destructive action authority".to_owned(),
            ));
        }
        let mut environment = sanitized_environment(
            &action.command.environment,
            &action.individually_authorized_environment,
        )?;
        environment.insert("PATH".to_owned(), self.command_policy.approved_path());
        let isolated = self.isolation.isolate(&action.command, isolation_request)?;
        let baseline_disk = directory_size(&action.command.working_directory)?;
        Ok(PreparedExecution {
            isolated,
            environment,
            baseline_disk,
        })
    }

    fn execute_dispatched(
        &self,
        journal: &mut ActionJournal<'_>,
        action: &AuthorizedAction,
        artifacts: &ArtifactStore,
        prepared: PreparedExecution,
    ) -> Result<RawToolResult, ToolError> {
        let mut command = Command::new(&prepared.isolated.executable);
        command
            .args(&prepared.isolated.args)
            .current_dir(&action.command.working_directory)
            .env_clear()
            .envs(prepared.environment)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);

        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                journal.record_process_lease(action, None, None, "reaped")?;
                Self::reconcile_proven_no_child(journal, action)?;
                return Err(ToolError::Io(error));
            }
        };
        let pgid = child.id();
        recovery_test_hook("after_process_spawn_before_identity_lease");
        let Some(leader_identity) = process_group_leader_identity(pgid)? else {
            terminate_process_group(&mut child, pgid)?;
            if wait_group_absent(pgid, Duration::from_millis(500))? {
                journal.record_process_lease(action, Some(pgid), None, "reaped")?;
            }
            journal.transition(action, ActionState::Dispatched, ActionState::Unknown)?;
            return Err(ToolError::RecoveryBlocked(
                "spawned process leader identity could not be proven".to_owned(),
            ));
        };
        if let Err(error) =
            journal.record_process_lease(action, Some(pgid), Some(&leader_identity), "active")
        {
            terminate_process_group(&mut child, pgid)?;
            if !wait_group_absent(pgid, Duration::from_millis(500))? {
                let _ = journal.transition(action, ActionState::Dispatched, ActionState::Unknown);
            }
            return Err(error);
        }
        let output_count = Arc::new(AtomicU64::new(0));
        let stdout_handle = spawn_reader(
            child.stdout.take(),
            action.command.output_limit_bytes,
            Arc::clone(&output_count),
        );
        let stderr_handle = spawn_reader(
            child.stderr.take(),
            action.command.output_limit_bytes,
            Arc::clone(&output_count),
        );
        let start = Instant::now();
        let (status, limited) = self.monitor_child(
            &mut child,
            pgid,
            action,
            prepared.baseline_disk,
            &output_count,
        )?;

        let reaped = wait_group_absent(pgid, Duration::from_millis(500))?;
        if !reaped {
            journal.transition(action, ActionState::Dispatched, ActionState::Unknown)?;
            return Err(ToolError::RecoveryBlocked(format!(
                "process group {pgid} still has members after cleanup"
            )));
        }

        if limited.is_some() && action.command.subprocess_limit > 0 {
            journal.transition(action, ActionState::Dispatched, ActionState::Unknown)?;
            return Err(ToolError::RecoveryBlocked(
                "forced cleanup cannot prove absence of descendants that may have escaped the process group"
                    .to_owned(),
            ));
        }

        let stdout =
            receive_reader(stdout_handle, Duration::from_millis(500)).inspect_err(|_| {
                let _ = journal.transition(action, ActionState::Dispatched, ActionState::Unknown);
            })?;
        let stderr =
            receive_reader(stderr_handle, Duration::from_millis(500)).inspect_err(|_| {
                let _ = journal.transition(action, ActionState::Dispatched, ActionState::Unknown);
            })?;

        let result = RawToolResult {
            exit_code: status.code(),
            stdout,
            stderr,
            elapsed_ms: u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
            terminated_for_limit: limited,
            process_group_reaped: true,
        };
        let receipt = durable_result_receipt(action, &result)?;
        journal.observe_with_receipt(action, artifacts, &receipt)?;
        journal.commit_with_bound_result(action, ActionState::Observed)?;
        journal.record_process_lease(action, Some(pgid), Some(&leader_identity), "reaped")?;
        Ok(result)
    }

    fn monitor_child(
        &self,
        child: &mut Child,
        pgid: u32,
        action: &AuthorizedAction,
        baseline_disk: u64,
        output_count: &AtomicU64,
    ) -> Result<(std::process::ExitStatus, Option<ResourceLimitKind>), ToolError> {
        let start = Instant::now();
        loop {
            if let Some(status) = child.try_wait()? {
                return Ok((status, None));
            }
            let elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
            let limited = if elapsed_ms > action.command.timeout_ms {
                Some(ResourceLimitKind::Timeout)
            } else if output_count.load(Ordering::Relaxed) > action.command.output_limit_bytes {
                Some(ResourceLimitKind::OutputBytes)
            } else if directory_size(&action.command.working_directory)?
                .saturating_sub(baseline_disk)
                > action.command.disk_write_limit_bytes
            {
                Some(ResourceLimitKind::DiskBytes)
            } else if descendant_count(pgid)? > action.command.subprocess_limit {
                Some(ResourceLimitKind::Subprocesses)
            } else {
                None
            };
            if let Some(limit) = limited {
                terminate_process_group(child, pgid)?;
                return Ok((child.wait()?, Some(limit)));
            }
            thread::sleep(self.poll_interval);
        }
    }

    fn reconcile_proven_no_child(
        journal: &mut ActionJournal<'_>,
        action: &AuthorizedAction,
    ) -> Result<(), ToolError> {
        journal.transition(action, ActionState::Dispatched, ActionState::Unknown)?;
        journal.transition(action, ActionState::Unknown, ActionState::Reconciled)?;
        journal.transition(action, ActionState::Reconciled, ActionState::Failed)?;
        Ok(())
    }
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
        thread::sleep(Duration::from_secs(60));
    }
}

#[cfg(not(feature = "recovery-test-hooks"))]
fn recovery_test_hook(_point: &str) {}

fn digest_field(hasher: &mut Sha256, value: &str) {
    let bytes = value.as_bytes();
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(bytes);
}

const fn permission_name(permission: PermissionClass) -> &'static str {
    match permission {
        PermissionClass::ProcessExec => "process_exec",
        PermissionClass::RepositoryWrite => "repository_write",
        PermissionClass::PackageInstall => "package_install",
        PermissionClass::NetworkRead => "network_read",
        PermissionClass::NetworkWrite => "network_write",
        PermissionClass::Destructive => "destructive",
        PermissionClass::ExternalSideEffect => "external_side_effect",
    }
}

const fn command_risk_name(risk: CommandRisk) -> &'static str {
    match risk {
        CommandRisk::ReadOnly => "read_only",
        CommandRisk::RepositoryMutation => "repository_mutation",
        CommandRisk::UntrustedCode => "untrusted_code",
        CommandRisk::PackageInstall => "package_install",
        CommandRisk::Destructive => "destructive",
        CommandRisk::Shell => "shell",
    }
}

fn unix_millis() -> Result<i64, ToolError> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
    Ok(i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX))
}

fn event_id(action_id: &str, state: &str) -> String {
    let mut hasher = Sha256::new();
    digest_field(&mut hasher, action_id);
    digest_field(&mut hasher, state);
    hasher.update(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos())
            .to_be_bytes(),
    );
    format!("event_{:x}", hasher.finalize())
}

struct CapturedOutput {
    bytes: Vec<u8>,
}

type ReaderHandle = Receiver<Result<CapturedOutput, std::io::Error>>;

fn spawn_reader(
    pipe: Option<impl Read + Send + 'static>,
    retain_limit: u64,
    total: Arc<AtomicU64>,
) -> Option<ReaderHandle> {
    pipe.map(|mut pipe| {
        let (sender, receiver) = mpsc::channel();
        let handle = thread::spawn(move || {
            let retain_limit = usize::try_from(retain_limit).unwrap_or(usize::MAX);
            let mut retained = Vec::new();
            let mut buffer = [0_u8; 8 * 1024];
            let outcome = (|| -> Result<CapturedOutput, std::io::Error> {
                loop {
                    let read = pipe.read(&mut buffer)?;
                    if read == 0 {
                        break;
                    }
                    total.fetch_add(u64::try_from(read).unwrap_or(u64::MAX), Ordering::Relaxed);
                    let remaining = retain_limit.saturating_sub(retained.len());
                    retained.extend_from_slice(&buffer[..read.min(remaining)]);
                }
                Ok(CapturedOutput { bytes: retained })
            })();
            let _ = sender.send(outcome);
        });
        drop(handle);
        receiver
    })
}

fn receive_reader(handle: Option<ReaderHandle>, timeout: Duration) -> Result<Vec<u8>, ToolError> {
    let Some(handle) = handle else {
        return Ok(Vec::new());
    };
    handle
        .recv_timeout(timeout)
        .map_err(|_| ToolError::RecoveryBlocked("bounded output drain timed out".to_owned()))?
        .map(|captured| captured.bytes)
        .map_err(ToolError::Io)
}

fn durable_result_receipt(
    action: &AuthorizedAction,
    result: &RawToolResult,
) -> Result<Vec<u8>, ToolError> {
    let stdout_digest = digest_bytes(&result.stdout);
    let stderr_digest = digest_bytes(&result.stderr);
    let value = serde_json::json!({
        "schema": "sovereign-tool-result-receipt-v1",
        "action_id": action.action_id,
        "payload_digest": action.payload_digest(),
        "exit_code": result.exit_code,
        "elapsed_ms": result.elapsed_ms,
        "terminated_for_limit": result.terminated_for_limit.map(resource_limit_name),
        "process_group_reaped": result.process_group_reaped,
        "stdout": {
            "sha256": stdout_digest,
            "retained_bytes": result.stdout.len()
        },
        "stderr": {
            "sha256": stderr_digest,
            "retained_bytes": result.stderr.len()
        }
    });
    serde_json::to_vec(&value).map_err(|error| {
        ToolError::Authority(format!("result receipt serialization failed: {error}"))
    })
}

fn digest_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

const fn resource_limit_name(limit: ResourceLimitKind) -> &'static str {
    match limit {
        ResourceLimitKind::Timeout => "timeout",
        ResourceLimitKind::OutputBytes => "output_bytes",
        ResourceLimitKind::DiskBytes => "disk_bytes",
        ResourceLimitKind::Subprocesses => "subprocesses",
    }
}

fn directory_size(root: &Path) -> Result<u64, ToolError> {
    let mut total = 0_u64;
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                stack.push(entry.path());
            } else if file_type.is_file() {
                total = total.saturating_add(entry.metadata()?.len());
            }
        }
    }
    Ok(total)
}

fn descendant_count(pgid: u32) -> Result<u32, ToolError> {
    let output = Command::new("/bin/ps")
        .args(["-axo", "pgid="])
        .env_clear()
        .output()?;
    if !output.status.success() {
        return Err(ToolError::RecoveryBlocked(
            "cannot observe process-group membership".to_owned(),
        ));
    }
    let group = pgid.to_string();
    let members = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| line.trim() == group)
        .count();
    Ok(u32::try_from(members.saturating_sub(1)).unwrap_or(u32::MAX))
}

fn signal_group(pgid: u32, signal: &str) -> Result<(), ToolError> {
    let status = Command::new("/bin/kill")
        .args([signal, "--", &format!("-{pgid}")])
        .env_clear()
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(ToolError::RecoveryBlocked(format!(
            "failed to send {signal} to process group {pgid}"
        )))
    }
}

/// Returns a PID-reuse-resistant identity string for a process-group leader on macOS/Unix
/// using the leader PID, process group and OS-reported start time. A missing leader returns
/// `None`; malformed or contradictory output fails closed.
///
/// # Errors
/// Returns a recovery error when process identity cannot be observed safely.
pub fn process_group_leader_identity(pgid: u32) -> Result<Option<String>, ToolError> {
    let output = Command::new("/bin/ps")
        .args([
            "-p",
            &pgid.to_string(),
            "-o",
            "pid=",
            "-o",
            "pgid=",
            "-o",
            "lstart=",
        ])
        .env_clear()
        .output()?;
    if !output.status.success() {
        return Ok(None);
    }
    let line = String::from_utf8_lossy(&output.stdout)
        .lines()
        .find(|line| !line.trim().is_empty())
        .map(str::trim)
        .map(str::to_owned);
    let Some(line) = line else {
        return Ok(None);
    };
    let mut fields = line.split_whitespace();
    let observed_pid = fields
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or_else(|| ToolError::RecoveryBlocked("malformed process leader PID".to_owned()))?;
    let observed_group = fields
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or_else(|| ToolError::RecoveryBlocked("malformed process group ID".to_owned()))?;
    let start = fields.collect::<Vec<_>>().join(" ");
    if observed_pid != pgid || observed_group != pgid || start.is_empty() {
        return Err(ToolError::RecoveryBlocked(format!(
            "process leader identity does not match owned group {pgid}"
        )));
    }
    Ok(Some(format!("{observed_pid}:{observed_group}:{start}")))
}

/// Reaps one durably-owned process group only when the current leader identity exactly
/// matches the identity captured at spawn. PID reuse or leaderless surviving groups are
/// recovery-blocking rather than kill targets.
///
/// # Errors
/// Returns a recovery error when ownership cannot be proven or cleanup cannot be proven.
pub fn reap_owned_process_group(pgid: u32, expected_identity: &str) -> Result<(), ToolError> {
    match process_group_leader_identity(pgid)? {
        Some(current) if current == expected_identity => {
            signal_group(pgid, "-TERM")?;
            if wait_group_absent(pgid, Duration::from_millis(200))? {
                return Ok(());
            }
            signal_group(pgid, "-KILL")?;
            if wait_group_absent(pgid, Duration::from_millis(500))? {
                Ok(())
            } else {
                Err(ToolError::RecoveryBlocked(format!(
                    "owned process group {pgid} remains after recovery kill"
                )))
            }
        }
        Some(_) => Err(ToolError::RecoveryBlocked(format!(
            "process group leader identity changed for {pgid}; refusing PID-reuse kill"
        ))),
        None => {
            if wait_group_absent(pgid, Duration::from_millis(50))? {
                Ok(())
            } else {
                Err(ToolError::RecoveryBlocked(format!(
                    "process group {pgid} still exists without its recorded leader identity"
                )))
            }
        }
    }
}

fn terminate_process_group(child: &mut Child, pgid: u32) -> Result<(), ToolError> {
    if child.try_wait()?.is_some() {
        return Ok(());
    }
    signal_group(pgid, "-TERM")?;
    let deadline = Instant::now() + Duration::from_millis(150);
    while Instant::now() < deadline {
        if child.try_wait()?.is_some() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(10));
    }
    signal_group(pgid, "-KILL")?;
    Ok(())
}

fn wait_group_absent(pgid: u32, timeout: Duration) -> Result<bool, ToolError> {
    let deadline = Instant::now() + timeout;
    loop {
        let output = Command::new("/bin/ps")
            .args(["-axo", "pgid="])
            .env_clear()
            .output()?;
        if !output.status.success() {
            return Err(ToolError::RecoveryBlocked(
                "cannot prove process-group cleanup".to_owned(),
            ));
        }
        let group = pgid.to_string();
        let present = String::from_utf8_lossy(&output.stdout)
            .lines()
            .any(|line| line.trim() == group);
        if !present {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        thread::sleep(Duration::from_millis(10));
    }
}
