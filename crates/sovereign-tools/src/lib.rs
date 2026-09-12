//! Deterministic tool authorization, action journaling, reconciliation, and process execution.
//!
//! Models and repository content may propose actions, but this crate requires exact
//! Controller-created authority to exist durably before an operating-system process starts.

use sha2::{Digest, Sha256};
use sovereign_policy::{
    CommandPolicy, CommandRisk, CommandSpec, ExecutionIsolationBackend, IsolationRequest,
    PolicyError, sanitized_environment,
};
use sovereign_state::{
    ActionTransition, NewActionRecord, PersistedActionRecord, StateError, StateStore,
};
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs;
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub enum ToolError {
    Policy(PolicyError),
    State(StateError),
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
    pub tool_id: String,
    pub permission_class: PermissionClass,
    pub execution_epoch: i64,
    pub policy_digest: String,
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
        digest_field(&mut hasher, &self.tool_id);
        digest_field(&mut hasher, permission_name(self.permission_class));
        hasher.update(self.execution_epoch.to_be_bytes());
        digest_field(&mut hasher, &self.policy_digest);
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
            || self.tool_id.trim().is_empty()
            || self.nonce.trim().is_empty()
            || !self.policy_digest.starts_with("sha256:")
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
        })?)
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
                self.transition(action, ActionState::Reconciled, ActionState::Committed)?;
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
    ) -> Result<RawToolResult, ToolError> {
        journal.verify_authorized(action)?;
        self.command_policy.authorize(&action.command)?;
        let mut environment = sanitized_environment(
            &action.command.environment,
            &action.individually_authorized_environment,
        )?;
        environment.insert("PATH".to_owned(), self.command_policy.approved_path());
        let isolated = self.isolation.isolate(&action.command, isolation_request)?;
        let baseline_disk = directory_size(&action.command.working_directory)?;

        journal.transition(action, ActionState::Authorized, ActionState::Dispatched)?;

        let mut command = Command::new(&isolated.executable);
        command
            .args(&isolated.args)
            .current_dir(&action.command.working_directory)
            .env_clear()
            .envs(environment)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);

        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                Self::reconcile_proven_no_child(journal, action)?;
                return Err(ToolError::Io(error));
            }
        };
        let pgid = child.id();
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
        let mut limited = None;
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            let elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
            if elapsed_ms > action.command.timeout_ms {
                limited = Some(ResourceLimitKind::Timeout);
            } else if output_count.load(Ordering::Relaxed) > action.command.output_limit_bytes {
                limited = Some(ResourceLimitKind::OutputBytes);
            } else if directory_size(&action.command.working_directory)?
                .saturating_sub(baseline_disk)
                > action.command.disk_write_limit_bytes
            {
                limited = Some(ResourceLimitKind::DiskBytes);
            } else if descendant_count(pgid)? > action.command.subprocess_limit {
                limited = Some(ResourceLimitKind::Subprocesses);
            }
            if limited.is_some() {
                terminate_process_group(&mut child, pgid)?;
                break child.wait()?;
            }
            thread::sleep(self.poll_interval);
        };

        let stdout = join_reader(stdout_handle)?;
        let stderr = join_reader(stderr_handle)?;
        let reaped = wait_group_absent(pgid, Duration::from_millis(500))?;
        if !reaped {
            journal.transition(action, ActionState::Dispatched, ActionState::Unknown)?;
            return Err(ToolError::RecoveryBlocked(format!(
                "process group {pgid} still has members after cleanup"
            )));
        }

        journal.transition(action, ActionState::Dispatched, ActionState::Observed)?;
        journal.transition(action, ActionState::Observed, ActionState::Committed)?;
        Ok(RawToolResult {
            exit_code: status.code(),
            stdout,
            stderr,
            elapsed_ms: u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
            terminated_for_limit: limited,
            process_group_reaped: true,
        })
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

type ReaderHandle = thread::JoinHandle<Result<CapturedOutput, std::io::Error>>;

fn spawn_reader(
    pipe: Option<impl Read + Send + 'static>,
    retain_limit: u64,
    total: Arc<AtomicU64>,
) -> Option<ReaderHandle> {
    pipe.map(|mut pipe| {
        thread::spawn(move || {
            let retain_limit = usize::try_from(retain_limit).unwrap_or(usize::MAX);
            let mut retained = Vec::new();
            let mut buffer = [0_u8; 8 * 1024];
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
        })
    })
}

fn join_reader(handle: Option<ReaderHandle>) -> Result<Vec<u8>, ToolError> {
    let Some(handle) = handle else {
        return Ok(Vec::new());
    };
    handle
        .join()
        .map_err(|_| ToolError::RecoveryBlocked("output reader thread panicked".to_owned()))?
        .map(|captured| captured.bytes)
        .map_err(ToolError::Io)
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
