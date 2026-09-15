//! Deterministic tool authorization, action journaling, reconciliation, and process execution.
//!
//! Models and repository content may propose actions, but this crate requires exact
//! Controller-created authority to exist durably before an operating-system process starts.

use sha2::{Digest, Sha256};
use sovereign_evidence::{ArtifactStore, EvidenceError, Redactor};
pub use sovereign_policy::{
    ApprovalClaim, ApprovalClaimV1, Capability, CapabilityLayers, CapabilitySet,
    PermissionDecision, ReconciliationClass, ReconciliationPolicy, ReconciliationPolicyV1,
    TaskCapabilityGrant,
};
use sovereign_policy::{
    CommandPolicy, CommandRisk, CommandSpec, ExecutionIsolationBackend, IsolatedCommand,
    IsolationRequest, PolicyError, SecretInjection, SecretLease, SecretScope,
    sanitized_environment,
};
use sovereign_state::{
    ActionTransition, NewActionRecord, PersistedActionRecord, StateError, StateStore,
};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const APPROVAL_CLAIM_NAMESPACE: &str = "controller.approval_claim";
pub const ACTION_RECEIPT_SCHEMA_VERSION: u32 = 1;
pub const ACTION_RECEIPT_SCHEMA: &str = "sovereign-action-receipt-v1";

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

pub type PermissionClass = Capability;

/// Identity snapshot used to bind an authorized filesystem replacement to the exact parent and
/// target observed before bytes are staged. The replacement is always a same-directory rename;
/// an existing hard-linked target inode is never modified in place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtomicReplaceGuard {
    repository_root: std::path::PathBuf,
    relative_path: std::path::PathBuf,
    parent: std::path::PathBuf,
    parent_device: u64,
    parent_inode: u64,
    target_identity: Option<FileIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    file_type: u32,
    content_digest: String,
}

impl AtomicReplaceGuard {
    /// Captures an immutable authorization-to-commit binding for one repository-relative target.
    ///
    /// # Errors
    /// Returns fail-closed for traversal, a non-canonical repository root, symlinked path
    /// components, a non-directory parent, or a non-regular existing target.
    pub fn prepare(
        repository_root: impl AsRef<Path>,
        relative_path: impl AsRef<Path>,
    ) -> Result<Self, ToolError> {
        let repository_root = repository_root.as_ref().canonicalize()?;
        let relative_path = relative_path.as_ref();
        validate_commit_relative_path(relative_path)?;
        let parent_relative = relative_path.parent().unwrap_or_else(|| Path::new(""));
        let parent = repository_root.join(parent_relative);
        ensure_no_symlink_components(&repository_root, parent_relative)?;
        let parent = parent.canonicalize()?;
        if !parent.starts_with(&repository_root) {
            return Err(ToolError::Authority(
                "atomic replacement parent escaped repository root".to_owned(),
            ));
        }
        let parent_metadata = fs::symlink_metadata(&parent)?;
        if !parent_metadata.is_dir() || parent_metadata.file_type().is_symlink() {
            return Err(ToolError::Authority(
                "atomic replacement parent is not a stable directory".to_owned(),
            ));
        }
        let target = repository_root.join(relative_path);
        let target_identity = target_identity(&target)?;
        Ok(Self {
            repository_root,
            relative_path: relative_path.to_path_buf(),
            parent,
            parent_device: parent_metadata.dev(),
            parent_inode: parent_metadata.ino(),
            target_identity,
        })
    }

    #[must_use]
    pub fn relative_path(&self) -> &Path {
        &self.relative_path
    }

    /// Atomically replaces the exact guarded path after revalidating parent and target identity.
    /// A temporary regular file is created in the already-authorized parent, synced, and renamed
    /// over the target only after the authorization snapshot still matches.
    ///
    /// # Errors
    /// Returns fail-closed if any path component, parent identity, or target identity changed
    /// between authorization and commit, or if staging/sync/rename fails.
    pub fn commit(&self, bytes: &[u8], mode: u32) -> Result<(), ToolError> {
        self.revalidate()?;
        let target = self.repository_root.join(&self.relative_path);
        let file_name = target.file_name().ok_or_else(|| {
            ToolError::Authority("atomic replacement target has no file name".to_owned())
        })?;
        let nonce = ATOMIC_REPLACE_NONCE.fetch_add(1, Ordering::Relaxed);
        let temp = self.parent.join(format!(
            ".{}.sovereign-tmp-{}-{nonce}",
            file_name.to_string_lossy(),
            std::process::id()
        ));
        let result = (|| -> Result<(), ToolError> {
            let mut staged = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp)?;
            staged.write_all(bytes)?;
            staged.set_permissions(fs::Permissions::from_mode(mode & 0o777))?;
            staged.sync_all()?;

            // This second check is deliberately immediately before rename. It catches a parent or
            // target swap after authorization without ever opening the old target for writing.
            self.revalidate()?;
            fs::rename(&temp, &target)?;
            File::open(&self.parent)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result
    }

    fn revalidate(&self) -> Result<(), ToolError> {
        let parent_relative = self.relative_path.parent().unwrap_or_else(|| Path::new(""));
        ensure_no_symlink_components(&self.repository_root, parent_relative)?;
        let current_parent = self.repository_root.join(parent_relative).canonicalize()?;
        if current_parent != self.parent {
            return Err(ToolError::Authority(
                "atomic replacement parent path changed after authorization".to_owned(),
            ));
        }
        let metadata = fs::symlink_metadata(&current_parent)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.dev() != self.parent_device
            || metadata.ino() != self.parent_inode
        {
            return Err(ToolError::Authority(
                "atomic replacement parent identity changed after authorization".to_owned(),
            ));
        }
        let current_target = target_identity(&self.repository_root.join(&self.relative_path))?;
        if current_target != self.target_identity {
            return Err(ToolError::Authority(
                "atomic replacement target identity changed after authorization".to_owned(),
            ));
        }
        Ok(())
    }
}

static ATOMIC_REPLACE_NONCE: AtomicU64 = AtomicU64::new(1);

fn validate_commit_relative_path(path: &Path) -> Result<(), ToolError> {
    use std::path::Component;
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err(ToolError::Authority(
            "atomic replacement requires a non-empty repository-relative path".to_owned(),
        ));
    }
    if path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err(ToolError::Authority(
            "atomic replacement path traversal is forbidden".to_owned(),
        ));
    }
    Ok(())
}

fn ensure_no_symlink_components(root: &Path, relative_parent: &Path) -> Result<(), ToolError> {
    let mut cursor = root.to_path_buf();
    for component in relative_parent.components() {
        if matches!(component, std::path::Component::CurDir) {
            continue;
        }
        cursor.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&cursor)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(ToolError::Authority(format!(
                "atomic replacement parent component is not a stable directory: {}",
                cursor.display()
            )));
        }
    }
    Ok(())
}

fn target_identity(path: &Path) -> Result<Option<FileIdentity>, ToolError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(ToolError::Authority(format!(
                    "atomic replacement target is not a regular file: {}",
                    path.display()
                )));
            }
            let bytes = fs::read(path)?;
            let mut hasher = Sha256::new();
            hasher.update(bytes);
            Ok(Some(FileIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
                file_type: metadata.mode() & 0o170_000,
                content_digest: format!("sha256:{:x}", hasher.finalize()),
            }))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolManifest {
    pub tool_id: String,
    pub version: String,
    pub content_digest: String,
    pub permission_ceiling: BTreeSet<PermissionClass>,
    pub declared_risk_floor: CommandRisk,
    pub reconciliation_policy: ReconciliationPolicy,
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
        self.reconciliation_policy
            .validate()
            .map_err(|error| ToolError::Authority(error.to_string()))?;
        Ok(())
    }
}

/// Model-visible v1 schema for one exact tool identity and its minimum required capabilities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolSchemaV1 {
    pub tool_id: String,
    pub version: String,
    pub content_digest: String,
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
    pub required_capabilities: CapabilitySet,
}

impl ToolSchemaV1 {
    /// Validates this schema against the exact executable manifest identity and ceiling.
    ///
    /// # Errors
    /// Returns an authority error when identity differs or schema requirements exceed the
    /// manifest ceiling.
    pub fn validate_against_manifest(&self, manifest: &ToolManifest) -> Result<(), ToolError> {
        manifest.validate()?;
        if self.tool_id.trim().is_empty()
            || self.version.trim().is_empty()
            || !self.content_digest.starts_with("sha256:")
            || self.name.trim().is_empty()
            || !self.input_schema.is_object()
        {
            return Err(ToolError::Authority(
                "tool schema requires exact identity, name, and object input schema".to_owned(),
            ));
        }
        if self.tool_id != manifest.tool_id
            || self.version != manifest.version
            || self.content_digest != manifest.content_digest
        {
            return Err(ToolError::Authority(
                "tool schema identity does not match exact manifest identity".to_owned(),
            ));
        }
        if !self
            .required_capabilities
            .iter()
            .all(|capability| manifest.permission_ceiling.contains(&capability))
        {
            return Err(ToolError::Authority(
                "tool schema required capabilities exceed manifest ceiling".to_owned(),
            ));
        }
        Ok(())
    }

    /// Returns whether this exact schema is relevant under one validated permission decision.
    ///
    /// # Errors
    /// Returns an authority error when the schema/manifest or decision is malformed.
    pub fn visible_under(
        &self,
        manifest: &ToolManifest,
        decision: &PermissionDecision,
    ) -> Result<bool, ToolError> {
        self.validate_against_manifest(manifest)?;
        decision
            .validate()
            .map_err(|error| ToolError::Authority(error.to_string()))?;
        Ok(
            decision.matches_tool(&self.tool_id, &self.version, &self.content_digest)
                && self
                    .required_capabilities
                    .iter()
                    .all(|capability| decision.effective.contains(capability)),
        )
    }
}

/// Filters model-visible schemas through exact manifests and already-scoped permission decisions.
///
/// # Errors
/// Returns an authority error if a schema has no exact manifest or either frozen object is
/// malformed. A valid but unauthorized schema is omitted.
pub fn filter_authorized_tool_schemas<'a>(
    schemas: &'a [ToolSchemaV1],
    manifests: &[ToolManifest],
    decisions: &[PermissionDecision],
) -> Result<Vec<&'a ToolSchemaV1>, ToolError> {
    let mut visible = Vec::new();
    for schema in schemas {
        let manifest = manifests
            .iter()
            .find(|manifest| {
                manifest.tool_id == schema.tool_id
                    && manifest.version == schema.version
                    && manifest.content_digest == schema.content_digest
            })
            .ok_or_else(|| {
                ToolError::Authority(format!(
                    "tool schema {} has no exact manifest identity",
                    schema.tool_id
                ))
            })?;
        schema.validate_against_manifest(manifest)?;
        for decision in decisions {
            if schema.visible_under(manifest, decision)? {
                visible.push(schema);
                break;
            }
        }
    }
    Ok(visible)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconciliationMode {
    IdempotentRead,
    UnsafeSideEffect,
    ConsequentialExternal,
}

impl ReconciliationMode {
    #[must_use]
    pub const fn policy(self) -> ReconciliationPolicy {
        match self {
            Self::IdempotentRead => ReconciliationPolicy::idempotent_local(),
            Self::UnsafeSideEffect => ReconciliationPolicy::proof_required_local(),
            Self::ConsequentialExternal => ReconciliationPolicy::consequential_external(),
        }
    }
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
    pub permission_decision_digest: String,
    pub isolation_policy_digest: String,
    pub nonce: String,
    pub expires_at_ms: i64,
    pub command: CommandSpec,
    pub individually_authorized_environment: BTreeSet<String>,
    pub approval_required: bool,
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
        digest_field(&mut hasher, &self.permission_decision_digest);
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
        hasher.update([u8::from(self.approval_required)]);
        digest_field(
            &mut hasher,
            match self.reconciliation_mode {
                ReconciliationMode::IdempotentRead => "idempotent_read",
                ReconciliationMode::UnsafeSideEffect => "unsafe_side_effect",
                ReconciliationMode::ConsequentialExternal => "consequential_external",
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
            || !self.permission_decision_digest.starts_with("sha256:")
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

    /// Verifies this exact action against the frozen permission decision whose digest it carries.
    ///
    /// # Errors
    /// Returns an authority error for a mismatched decision, scope, policy, tool, or capability.
    pub fn verify_permission_decision(
        &self,
        decision: &PermissionDecision,
    ) -> Result<(), ToolError> {
        decision
            .validate()
            .map_err(|error| ToolError::Authority(error.to_string()))?;
        if self.permission_decision_digest != decision.digest()
            || self.plan_id != decision.plan_id
            || self.plan_revision != decision.plan_revision
            || self.task_id != decision.task_id
            || self.policy_digest != decision.policy_digest
            || self.tool_id != decision.tool_id
            || self.tool_version != decision.tool_version
            || self.tool_digest != decision.tool_digest
            || !decision.effective.contains(self.permission_class)
        {
            return Err(ToolError::Authority(
                "authorized action does not match exact permission decision".to_owned(),
            ));
        }
        Ok(())
    }

    /// Validates one Controller-issued approval against this exact immutable action.
    ///
    /// # Errors
    /// Returns an authority error for any payload/scope/destination/executable/policy/epoch/nonce
    /// drift, expiration, or a claim that outlives the action authorization itself.
    pub fn verify_approval_claim(
        &self,
        claim: &ApprovalClaim,
        now_ms: i64,
    ) -> Result<(), ToolError> {
        claim
            .validate(now_ms)
            .map_err(|error| ToolError::Authority(error.to_string()))?;
        if claim.action_id != self.action_id
            || claim.plan_id != self.plan_id
            || claim.plan_revision != self.plan_revision
            || claim.task_id != self.task_id
            || claim.permission_class != permission_name(self.permission_class)
            || claim.payload_digest != self.payload_digest()
            || claim.destination_digest != self.destination_digest
            || claim.executable_digest != self.executable_digest
            || claim.policy_digest != self.policy_digest
            || claim.execution_epoch != self.execution_epoch
            || claim.nonce != self.nonce
            || claim.expires_at_ms > self.expires_at_ms
        {
            return Err(ToolError::Authority(
                "approval claim does not match exact authorized action".to_owned(),
            ));
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
        permission_decision: &PermissionDecision,
    ) -> Result<i64, ToolError> {
        let now = unix_millis()?;
        action.validate(now)?;
        action.verify_permission_decision(permission_decision)?;
        manifest.validate()?;
        if !manifest
            .reconciliation_policy
            .permits_candidate(action.reconciliation_mode.policy())
        {
            return Err(ToolError::Authority(
                "authorized action reconciliation policy weakens tool/adapter declaration"
                    .to_owned(),
            ));
        }
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
        if expected == ActionState::Authorized && next == ActionState::Dispatched {
            self.verify_dispatch_approval(action)?;
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

    /// Revalidates the durable Controller claim immediately before dispatch.
    ///
    /// Ordinary M1 actions keep their existing behavior when `approval_required=false`. For an
    /// approval-required action the claim must already be durably present in authoritative state;
    /// missing/garbled/stale records deny dispatch before any side effect can start.
    ///
    /// # Errors
    /// Returns an authority/state error when a required current exact claim is unavailable.
    pub fn verify_dispatch_approval(&self, action: &AuthorizedAction) -> Result<(), ToolError> {
        if !action.approval_required {
            return Ok(());
        }
        let raw = self
            .store
            .get_state(APPROVAL_CLAIM_NAMESPACE, &action.action_id)?
            .ok_or_else(|| {
                ToolError::Authority(format!(
                    "approval-required action {} has no durable approval claim",
                    action.action_id
                ))
            })?;
        let claim: ApprovalClaim = serde_json::from_str(&raw)
            .map_err(|_| ToolError::Authority("durable approval claim is malformed".to_owned()))?;
        action.verify_approval_claim(&claim, unix_millis()?)
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
    reconcile_with_policy(mode.policy(), proof)
}

/// Deterministically reconciles unknown outcome under one exact v1 tool/adapter policy.
#[must_use]
pub const fn reconcile_with_policy(
    policy: ReconciliationPolicy,
    proof: Option<ReconciliationProof>,
) -> Reconciliation {
    match proof {
        Some(ReconciliationProof::EffectObserved) => Reconciliation::CommitObservedEffect,
        Some(ReconciliationProof::EffectAbsent) => Reconciliation::FailProvenAbsent,
        None | Some(ReconciliationProof::SafeIdempotentRetry) => {
            if policy.allows_unproven_retry() {
                Reconciliation::SafeToRetry
            } else {
                Reconciliation::BlockedUnsafeUnknown
            }
        }
    }
}

pub trait ToolAdapter {
    fn manifest(&self) -> &ToolManifest;

    #[must_use]
    fn reconciliation_policy(&self) -> ReconciliationPolicy {
        self.manifest().reconciliation_policy
    }
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

/// Fixed environment handle exposed only by the secret-aware runner path. The value is an
/// ephemeral private file path, never secret material.
pub const EPHEMERAL_SECRET_FILE_ENV: &str = "SOVEREIGN_SECRET_FILE";

/// Proof returned to the Controller after the policy-owned temporary secret file has been
/// deleted with an absence check and the owned process group is durably marked reaped. It contains
/// no secret bytes; the Controller must still close the exact `SecretLease` before committing the
/// already-observed action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecretCleanupProof {
    pub process_lease_reaped: bool,
    pub ephemeral_injection_removed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceLimitKind {
    Timeout,
    OutputBytes,
    DiskBytes,
    Subprocesses,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionReceiptStream {
    pub sha256: String,
    pub retained_bytes: usize,
}

/// Durable typed receipt for the already-sanitized result of one exact action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionReceipt {
    pub schema: String,
    pub schema_version: u32,
    pub action_id: String,
    pub payload_digest: String,
    pub policy_digest: String,
    pub execution_epoch: i64,
    pub exit_code: Option<i32>,
    pub elapsed_ms: u64,
    pub terminated_for_limit: Option<ResourceLimitKind>,
    pub process_group_reaped: bool,
    pub stdout: ActionReceiptStream,
    pub stderr: ActionReceiptStream,
}

/// Frozen v1 name for callers that prefer version-suffixed receipt types.
pub type ActionReceiptV1 = ActionReceipt;

impl ActionReceipt {
    /// Builds a durable receipt from a result that has already crossed the ingress/redaction
    /// boundary. The receipt retains only digests/lengths for stdout/stderr, never raw bytes.
    #[must_use]
    pub fn from_sanitized_result(action: &AuthorizedAction, result: &RawToolResult) -> Self {
        Self {
            schema: ACTION_RECEIPT_SCHEMA.to_owned(),
            schema_version: ACTION_RECEIPT_SCHEMA_VERSION,
            action_id: action.action_id.clone(),
            payload_digest: action.payload_digest(),
            policy_digest: action.policy_digest.clone(),
            execution_epoch: action.execution_epoch,
            exit_code: result.exit_code,
            elapsed_ms: result.elapsed_ms,
            terminated_for_limit: result.terminated_for_limit,
            process_group_reaped: result.process_group_reaped,
            stdout: ActionReceiptStream {
                sha256: digest_bytes(&result.stdout),
                retained_bytes: result.stdout.len(),
            },
            stderr: ActionReceiptStream {
                sha256: digest_bytes(&result.stderr),
                retained_bytes: result.stderr.len(),
            },
        }
    }

    /// Validates immutable receipt/action correlation before recovery consumes it.
    ///
    /// # Errors
    /// Returns an authority error for unsupported schema, malformed digests, or action drift.
    pub fn validate_for_action(&self, action: &AuthorizedAction) -> Result<(), ToolError> {
        if self.schema != ACTION_RECEIPT_SCHEMA
            || self.schema_version != ACTION_RECEIPT_SCHEMA_VERSION
            || self.action_id != action.action_id
            || self.payload_digest != action.payload_digest()
            || self.policy_digest != action.policy_digest
            || self.execution_epoch != action.execution_epoch
            || !self.stdout.sha256.starts_with("sha256:")
            || !self.stderr.sha256.starts_with("sha256:")
        {
            return Err(ToolError::Authority(
                "action receipt does not match exact authorized action".to_owned(),
            ));
        }
        Ok(())
    }

    /// Serializes the stable receipt for CAS publication.
    ///
    /// # Errors
    /// Returns an authority error if serialization fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ToolError> {
        let value = serde_json::json!({
            "schema": self.schema,
            "schema_version": self.schema_version,
            "action_id": self.action_id,
            "payload_digest": self.payload_digest,
            "policy_digest": self.policy_digest,
            "execution_epoch": self.execution_epoch,
            "exit_code": self.exit_code,
            "elapsed_ms": self.elapsed_ms,
            "terminated_for_limit": self.terminated_for_limit.map(resource_limit_name),
            "process_group_reaped": self.process_group_reaped,
            "stdout": {
                "sha256": self.stdout.sha256,
                "retained_bytes": self.stdout.retained_bytes,
            },
            "stderr": {
                "sha256": self.stderr.sha256,
                "retained_bytes": self.stderr.retained_bytes,
            },
        });
        serde_json::to_vec(&value).map_err(|error| {
            ToolError::Authority(format!("result receipt serialization failed: {error}"))
        })
    }

    /// Parses one durable v1 receipt for Controller/recovery inspection.
    ///
    /// # Errors
    /// Returns an authority error for malformed JSON.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ToolError> {
        let value: serde_json::Value = serde_json::from_slice(bytes)
            .map_err(|_| ToolError::Authority("durable action receipt is malformed".to_owned()))?;
        let object = value.as_object().ok_or_else(malformed_action_receipt)?;
        let schema_version = receipt_u64(object, "schema_version")
            .and_then(|value| u32::try_from(value).map_err(|_| malformed_action_receipt()))?;
        let execution_epoch = object
            .get("execution_epoch")
            .and_then(serde_json::Value::as_i64)
            .ok_or_else(malformed_action_receipt)?;
        let exit_code = match object.get("exit_code") {
            None | Some(serde_json::Value::Null) => None,
            Some(value) => Some(
                value
                    .as_i64()
                    .and_then(|value| i32::try_from(value).ok())
                    .ok_or_else(malformed_action_receipt)?,
            ),
        };
        let terminated_for_limit = match object.get("terminated_for_limit") {
            None | Some(serde_json::Value::Null) => None,
            Some(value) => Some(parse_resource_limit_name(
                value.as_str().ok_or_else(malformed_action_receipt)?,
            )?),
        };
        Ok(Self {
            schema: receipt_string(object, "schema")?,
            schema_version,
            action_id: receipt_string(object, "action_id")?,
            payload_digest: receipt_string(object, "payload_digest")?,
            policy_digest: receipt_string(object, "policy_digest")?,
            execution_epoch,
            exit_code,
            elapsed_ms: receipt_u64(object, "elapsed_ms")?,
            terminated_for_limit,
            process_group_reaped: object
                .get("process_group_reaped")
                .and_then(serde_json::Value::as_bool)
                .ok_or_else(malformed_action_receipt)?,
            stdout: receipt_stream(object, "stdout")?,
            stderr: receipt_stream(object, "stderr")?,
        })
    }
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
        journal.verify_dispatch_approval(action)?;
        let prepared = self.prepare_execution(action, isolation_request)?;
        journal.transition(action, ActionState::Authorized, ActionState::Dispatched)?;
        journal.record_process_lease(action, None, None, "pending_spawn")?;
        self.execute_dispatched(journal, action, artifacts, prepared)
    }

    /// Executes one exact temporary-file secret lease through durable observation, but deliberately
    /// leaves the action uncommitted. This is the Controller integration seam: after this returns,
    /// the Controller still owns the `SecretLease`, can close it only after the returned cleanup
    /// proof, and may then commit the already-redacted observed action.
    ///
    /// The temporary file is created by the policy-owned lease under a Controller-private root,
    /// with task/action-derived directories and restrictive permissions. Raw secret bytes are used
    /// only inside the lease value-use closure for pre-persistence redaction and never enter the
    /// authorized action, command specification, receipt, CAS object, or returned result.
    ///
    /// # Errors
    /// Returns fail-closed for stale/mismatched authority, non-temporary-file refs, unsafe target
    /// metadata, execution ambiguity, redaction failure, or unproven temporary-file cleanup. On a
    /// successful return the durable action is exactly `observed`, never `committed`.
    #[allow(clippy::too_many_arguments)]
    pub fn run_with_secret_lease_observed(
        &self,
        journal: &mut ActionJournal<'_>,
        action: &AuthorizedAction,
        isolation_request: &IsolationRequest,
        artifacts: &ArtifactStore,
        secret_lease: &mut SecretLease,
        secret_scope: &SecretScope,
        permission_decision: &PermissionDecision,
        now_ms: i64,
        controller_private_root: &Path,
    ) -> Result<(RawToolResult, SecretCleanupProof), ToolError> {
        journal.verify_authorized(action)?;
        journal.verify_dispatch_approval(action)?;
        action.verify_permission_decision(permission_decision)?;
        if !permission_decision
            .effective
            .contains(Capability::ProcessExec)
            || !permission_decision
                .effective
                .contains(Capability::SecretUse)
        {
            return Err(ToolError::Authority(
                "secret process execution requires exact process_exec + secret_use authority"
                    .to_owned(),
            ));
        }
        if secret_scope.plan_id != action.plan_id
            || secret_scope.plan_revision != action.plan_revision
            || secret_scope.task_id != action.task_id
            || secret_scope.task_contract_digest != permission_decision.task_contract_digest
            || secret_scope.action_id != action.action_id
            || secret_scope.permission_decision_digest != action.permission_decision_digest
            || secret_scope.execution_epoch != action.execution_epoch
        {
            return Err(ToolError::Authority(
                "secret scope does not match the exact authorized action and permission decision"
                    .to_owned(),
            ));
        }
        let secret_ref = secret_lease.secret_ref();
        let secret_ref_binding_digest = secret_ref.binding_digest()?;
        if action.destination_digest.as_deref() != Some(secret_ref_binding_digest.as_str()) {
            return Err(ToolError::Authority(
                "authorized action is not bound to the exact SecretRef metadata".to_owned(),
            ));
        }
        if secret_ref.injection != SecretInjection::TemporaryFile
            || secret_ref.target != EPHEMERAL_SECRET_FILE_ENV
        {
            return Err(ToolError::Authority(format!(
                "temporary-file secret execution requires target {EPHEMERAL_SECRET_FILE_ENV}"
            )));
        }
        if action
            .command
            .environment
            .contains_key(EPHEMERAL_SECRET_FILE_ENV)
        {
            return Err(ToolError::Authority(format!(
                "{EPHEMERAL_SECRET_FILE_ENV} is Controller-owned on secret execution paths"
            )));
        }

        let mut prepared = self.prepare_execution(action, isolation_request)?;
        let mut secret_file = secret_lease.inject_temporary_file(
            secret_scope,
            &permission_decision.effective,
            now_ms,
            controller_private_root,
        )?;
        let secret_path = secret_file.path().to_str().ok_or_else(|| {
            ToolError::Authority("ephemeral secret path is not valid UTF-8".to_owned())
        })?;
        prepared
            .environment
            .insert(EPHEMERAL_SECRET_FILE_ENV.to_owned(), secret_path.to_owned());
        journal.transition(action, ActionState::Authorized, ActionState::Dispatched)?;
        journal.record_process_lease(action, None, None, "pending_spawn")?;

        let execution = secret_lease.with_value(
            secret_scope,
            &permission_decision.effective,
            now_ms,
            |secret_bytes| {
                self.execute_secret_dispatched(journal, action, artifacts, prepared, secret_bytes)
            },
        )?;
        match execution {
            Ok(result) => {
                secret_file.close()?;
                Ok((
                    result,
                    SecretCleanupProof {
                        process_lease_reaped: true,
                        ephemeral_injection_removed: true,
                    },
                ))
            }
            Err(error) => {
                secret_file.close()?;
                Err(error)
            }
        }
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

    #[allow(clippy::too_many_lines)]
    fn execute_secret_dispatched(
        &self,
        journal: &mut ActionJournal<'_>,
        action: &AuthorizedAction,
        artifacts: &ArtifactStore,
        prepared: PreparedExecution,
        secret_bytes: &[u8],
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
        journal.record_process_lease(action, Some(pgid), Some(&leader_identity), "reaped")?;

        if limited.is_some() && action.command.subprocess_limit > 0 {
            journal.transition(action, ActionState::Dispatched, ActionState::Unknown)?;
            return Err(ToolError::RecoveryBlocked(
                "forced cleanup cannot prove absence of descendants that may have escaped the process group"
                    .to_owned(),
            ));
        }

        let mut raw_stdout = receive_reader(stdout_handle, Duration::from_millis(500))
            .inspect_err(|_| {
                let _ = journal.transition(action, ActionState::Dispatched, ActionState::Unknown);
            })?;
        let mut raw_stderr = receive_reader(stderr_handle, Duration::from_millis(500))
            .inspect_err(|_| {
                let _ = journal.transition(action, ActionState::Dispatched, ActionState::Unknown);
            })?;
        let redactor = Redactor::v1();
        let stdout = redactor.redact_bytes(&raw_stdout, &[secret_bytes])?.bytes;
        let stderr = redactor.redact_bytes(&raw_stderr, &[secret_bytes])?.bytes;
        raw_stdout.fill(0);
        raw_stderr.fill(0);

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
    permission.as_plan_ir_str()
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
    let receipt = ActionReceipt::from_sanitized_result(action, result);
    receipt.validate_for_action(action)?;
    receipt.to_bytes()
}

fn malformed_action_receipt() -> ToolError {
    ToolError::Authority("durable action receipt is malformed".to_owned())
}

fn receipt_string(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<String, ToolError> {
    object
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(malformed_action_receipt)
}

fn receipt_u64(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<u64, ToolError> {
    object
        .get(key)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(malformed_action_receipt)
}

fn receipt_stream(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<ActionReceiptStream, ToolError> {
    let stream = object
        .get(key)
        .and_then(serde_json::Value::as_object)
        .ok_or_else(malformed_action_receipt)?;
    let retained_bytes = receipt_u64(stream, "retained_bytes")
        .and_then(|value| usize::try_from(value).map_err(|_| malformed_action_receipt()))?;
    Ok(ActionReceiptStream {
        sha256: receipt_string(stream, "sha256")?,
        retained_bytes,
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

fn parse_resource_limit_name(value: &str) -> Result<ResourceLimitKind, ToolError> {
    match value {
        "timeout" => Ok(ResourceLimitKind::Timeout),
        "output_bytes" => Ok(ResourceLimitKind::OutputBytes),
        "disk_bytes" => Ok(ResourceLimitKind::DiskBytes),
        "subprocesses" => Ok(ResourceLimitKind::Subprocesses),
        _ => Err(malformed_action_receipt()),
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
