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
    IsolationRequest, NetworkDestination, NetworkPolicy, PathAuthorizationTicket, PathCommitMode,
    PathPolicy, PolicyError, SecretInjection, SecretLease, SecretScope, sanitized_environment,
};
use sovereign_state::{
    ActionTransition, NewActionRecord, PersistedActionRecord, StateError, StateStore,
};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::{IpAddr, ToSocketAddrs};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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

/// Prepared mechanics for creating one repository file exactly once.
///
/// Authority remains external: callers supply an already configured [`PathPolicy`]. This guard
/// only preserves that path-policy decision across staging and publishes with an atomic no-clobber
/// directory-entry operation, so a target that appears after prepare is never overwritten.
#[derive(Debug, Clone)]
pub struct AtomicCreateGuard {
    path_policy: PathPolicy,
    ticket: PathAuthorizationTicket,
    path_guard: AtomicReplaceGuard,
}

/// Prepared mechanics for replacing one existing regular repository file from an exact preimage.
///
/// This composes [`PathPolicy`] with the existing [`AtomicReplaceGuard`]; it does not grant write
/// authority or choose protected roots.
#[derive(Debug, Clone)]
pub struct AtomicUpdateGuard {
    path_policy: PathPolicy,
    ticket: PathAuthorizationTicket,
    path_guard: AtomicReplaceGuard,
    expected_source_mode: Option<u32>,
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

impl AtomicCreateGuard {
    /// Captures a create-only mutation binding for one currently absent repository-relative target.
    ///
    /// The supplied [`PathPolicy`] is the complete mechanics policy input; this layer does not add
    /// repository authority or protected paths of its own.
    ///
    /// # Errors
    /// Returns fail-closed for traversal, protected paths, symlinked parents, unstable parents,
    /// non-regular targets, or a target that already exists.
    pub fn prepare(
        path_policy: &PathPolicy,
        relative_path: impl AsRef<Path>,
    ) -> Result<Self, ToolError> {
        let relative_path = relative_path.as_ref();
        let ticket = path_policy.authorize_mutation(relative_path)?;
        if ticket.target_identity().is_some() {
            return Err(ToolError::Authority(
                "atomic create requires the target to be absent at prepare".to_owned(),
            ));
        }
        let path_guard = AtomicReplaceGuard::prepare(path_policy.repository_root(), relative_path)?;
        if path_guard.target_identity.is_some() {
            return Err(ToolError::Authority(
                "atomic create target appeared while prepare was establishing path identity"
                    .to_owned(),
            ));
        }
        Ok(Self {
            path_policy: path_policy.clone(),
            ticket,
            path_guard,
        })
    }

    #[must_use]
    pub fn relative_path(&self) -> &Path {
        self.path_guard.relative_path()
    }

    /// Publishes staged bytes atomically without replacing any entry that already exists.
    ///
    /// Staging occurs in the authorized parent. The final `hard_link` is the no-clobber publish:
    /// the kernel either creates the target directory entry pointing at the fully written inode or
    /// fails because an entry already exists. No ordinary overwrite-capable rename is used.
    ///
    /// # Errors
    /// Returns fail-closed if policy/path identity changed, the target appeared, staging failed, or
    /// the atomic no-clobber publish/cleanup could not be completed.
    pub fn commit(&self, bytes: &[u8], mode: u32) -> Result<(), ToolError> {
        self.revalidate_absent()?;
        let target = self
            .path_policy
            .revalidate_for_commit(&self.ticket, PathCommitMode::AtomicReplace)?;
        let file_name = target.file_name().ok_or_else(|| {
            ToolError::Authority("atomic create target has no file name".to_owned())
        })?;
        let nonce = ATOMIC_REPLACE_NONCE.fetch_add(1, Ordering::Relaxed);
        let temp = self.path_guard.parent.join(format!(
            ".{}.sovereign-create-tmp-{}-{nonce}",
            file_name.to_string_lossy(),
            std::process::id()
        ));

        let mut published = false;
        let result = (|| -> Result<(), ToolError> {
            let mut staged = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp)?;
            staged.write_all(bytes)?;
            staged.set_permissions(fs::Permissions::from_mode(mode & 0o777))?;
            staged.sync_all()?;

            // Revalidate immediately before the publish attempt. A last-moment target creation is
            // still fenced by hard_link's atomic EEXIST/no-replace semantics.
            self.revalidate_absent()?;
            self.path_policy
                .revalidate_for_commit(&self.ticket, PathCommitMode::AtomicReplace)?;
            fs::hard_link(&temp, &target)?;
            published = true;
            fs::remove_file(&temp)?;
            File::open(&self.path_guard.parent)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() && !published {
            let _ = fs::remove_file(&temp);
        }
        result
    }

    fn revalidate_absent(&self) -> Result<(), ToolError> {
        self.path_guard.revalidate()?;
        if self.path_guard.target_identity.is_some() {
            return Err(ToolError::Authority(
                "atomic create guard was prepared for an existing target".to_owned(),
            ));
        }
        Ok(())
    }
}

impl AtomicUpdateGuard {
    /// Captures an update-only mutation binding for one exact existing preimage digest.
    ///
    /// # Errors
    /// Returns fail-closed for traversal, protected paths, symlinked parents/targets, a missing or
    /// non-regular target, or a preimage digest mismatch.
    pub fn prepare(
        path_policy: &PathPolicy,
        relative_path: impl AsRef<Path>,
        expected_source_digest: &str,
    ) -> Result<Self, ToolError> {
        Self::prepare_internal(
            path_policy,
            relative_path.as_ref(),
            expected_source_digest,
            None,
        )
    }

    /// Captures an update-only mutation binding for one exact existing preimage digest and mode.
    ///
    /// # Errors
    /// Returns fail-closed for the same conditions as [`AtomicUpdateGuard::prepare`] plus a source
    /// mode mismatch or mode drift observed immediately before commit.
    pub fn prepare_exact(
        path_policy: &PathPolicy,
        relative_path: impl AsRef<Path>,
        expected_source_digest: &str,
        expected_source_mode: u32,
    ) -> Result<Self, ToolError> {
        if expected_source_mode > 0o777 {
            return Err(ToolError::Authority(
                "atomic update expected source mode is outside permission bits".to_owned(),
            ));
        }
        Self::prepare_internal(
            path_policy,
            relative_path.as_ref(),
            expected_source_digest,
            Some(expected_source_mode),
        )
    }

    fn prepare_internal(
        path_policy: &PathPolicy,
        relative_path: &Path,
        expected_source_digest: &str,
        expected_source_mode: Option<u32>,
    ) -> Result<Self, ToolError> {
        let ticket = path_policy.authorize_mutation(relative_path)?;
        if ticket.target_identity().is_none() {
            return Err(ToolError::Authority(
                "atomic update requires an existing regular target".to_owned(),
            ));
        }
        let path_guard = AtomicReplaceGuard::prepare(path_policy.repository_root(), relative_path)?;
        let Some(identity) = path_guard.target_identity.as_ref() else {
            return Err(ToolError::Authority(
                "atomic update target disappeared while prepare was establishing path identity"
                    .to_owned(),
            ));
        };
        if identity.content_digest != expected_source_digest {
            return Err(ToolError::Authority(
                "atomic update preimage digest does not match expected source digest".to_owned(),
            ));
        }
        if let Some(expected_mode) = expected_source_mode {
            let metadata = fs::symlink_metadata(ticket.authorized_target())?;
            if metadata.permissions().mode() & 0o777 != expected_mode {
                return Err(ToolError::Authority(
                    "atomic update preimage mode does not match expected source mode".to_owned(),
                ));
            }
        }
        Ok(Self {
            path_policy: path_policy.clone(),
            ticket,
            path_guard,
            expected_source_mode,
        })
    }

    #[must_use]
    pub fn relative_path(&self) -> &Path {
        self.path_guard.relative_path()
    }

    /// Replaces the exact prepared preimage after policy and identity revalidation.
    ///
    /// # Errors
    /// Returns fail-closed if the parent/target changed after prepare or the underlying atomic
    /// replacement fails.
    pub fn commit(&self, bytes: &[u8], mode: u32) -> Result<(), ToolError> {
        self.path_policy
            .revalidate_for_commit(&self.ticket, PathCommitMode::AtomicReplace)?;
        if let Some(expected_mode) = self.expected_source_mode {
            let metadata = fs::symlink_metadata(self.ticket.authorized_target())?;
            if metadata.permissions().mode() & 0o777 != expected_mode {
                return Err(ToolError::Authority(
                    "atomic update preimage mode changed after prepare".to_owned(),
                ));
            }
        }
        self.path_guard.commit(bytes, mode)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepositoryMutationKind {
    Create,
    Update,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepositoryMutationPrecondition {
    Absent,
    ExactFile { digest: String, mode: u32 },
}

/// Controller-authorized, in-process repository mutation.
///
/// This is deliberately a sibling of [`AuthorizedAction`], not a synthetic process action. It
/// binds the exact repository-relative path plus pre/post image contract while retaining the same
/// durable journal, policy/epoch, tool identity, and reconciliation authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedRepositoryMutation {
    pub action_id: String,
    pub plan_id: String,
    pub plan_revision: u32,
    pub task_id: String,
    pub attempt_id: String,
    pub tool_id: String,
    pub tool_version: String,
    pub tool_digest: String,
    pub repository_id: String,
    pub relative_path: PathBuf,
    pub kind: RepositoryMutationKind,
    pub precondition: RepositoryMutationPrecondition,
    pub expected_post_digest: String,
    pub expected_target_mode: u32,
    pub execution_epoch: i64,
    pub policy_digest: String,
    pub permission_decision_digest: String,
    pub isolation_policy_digest: String,
    pub nonce: String,
    pub expires_at_ms: i64,
    pub action_deadline_ms: u64,
    pub disk_write_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalActionReservation {
    pub tool_actions: u32,
    pub subprocesses: u32,
    pub wall_ms: u64,
    pub output_bytes: u64,
    pub disk_write_bytes: u64,
}

/// Common immutable authority consumed by the single canonical action journal.
///
/// Process-only execution details intentionally remain on [`AuthorizedAction`]. Repository
/// mutations expose only the common identity/policy surface required by authorization, durable
/// lifecycle transitions, approvals, reconciliation, and Controller metering.
pub trait JournalActionAuthority {
    fn action_id(&self) -> &str;
    fn plan_id(&self) -> &str;
    fn plan_revision(&self) -> u32;
    fn task_id(&self) -> &str;
    fn attempt_id(&self) -> &str;
    fn tool_id(&self) -> &str;
    fn tool_version(&self) -> &str;
    fn tool_digest(&self) -> &str;
    fn repository_id(&self) -> &str;
    fn destination_digest(&self) -> Option<&str>;
    fn permission_class(&self) -> PermissionClass;
    fn execution_epoch(&self) -> i64;
    fn policy_digest(&self) -> &str;
    fn permission_decision_digest(&self) -> &str;
    fn isolation_policy_digest(&self) -> &str;
    fn nonce(&self) -> &str;
    fn expires_at_ms(&self) -> i64;
    fn approval_required(&self) -> bool;
    fn reconciliation_mode(&self) -> ReconciliationMode;
    fn declared_risk(&self) -> CommandRisk;
    fn approval_execution_identity_digest(&self) -> Option<&str>;
    fn payload_digest(&self) -> String;
    /// Validates immutable authority shape and expiry.
    ///
    /// # Errors
    /// Returns fail-closed when the action binding is malformed, stale, or expired.
    fn validate(&self, now_ms: i64) -> Result<(), ToolError>;
    /// Verifies this exact action against one frozen Controller permission decision.
    ///
    /// # Errors
    /// Returns fail-closed when task/tool/policy/capability bindings differ.
    fn verify_permission_decision(&self, decision: &PermissionDecision) -> Result<(), ToolError>;
    /// Verifies a durable exact approval claim when this action class permits approval.
    ///
    /// # Errors
    /// Returns fail-closed for malformed/stale claims or action classes that cannot use approval.
    fn verify_approval_claim(&self, claim: &ApprovalClaim, now_ms: i64) -> Result<(), ToolError>;
    fn reservation(&self) -> JournalActionReservation;
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

impl AuthorizedRepositoryMutation {
    /// Computes the domain-separated exact payload digest for one in-process repository mutation.
    #[must_use]
    pub fn payload_digest(&self) -> String {
        let mut hasher = Sha256::new();
        digest_field(&mut hasher, "sovereign.authorized_repository_mutation.v1");
        digest_field(&mut hasher, &self.action_id);
        digest_field(&mut hasher, &self.plan_id);
        hasher.update(self.plan_revision.to_be_bytes());
        digest_field(&mut hasher, &self.task_id);
        digest_field(&mut hasher, &self.attempt_id);
        digest_field(&mut hasher, &self.tool_id);
        digest_field(&mut hasher, &self.tool_version);
        digest_field(&mut hasher, &self.tool_digest);
        digest_field(&mut hasher, &self.repository_id);
        digest_field(&mut hasher, &self.relative_path.display().to_string());
        digest_field(
            &mut hasher,
            match self.kind {
                RepositoryMutationKind::Create => "create",
                RepositoryMutationKind::Update => "update",
            },
        );
        match &self.precondition {
            RepositoryMutationPrecondition::Absent => digest_field(&mut hasher, "absent"),
            RepositoryMutationPrecondition::ExactFile { digest, mode } => {
                digest_field(&mut hasher, "exact_file");
                digest_field(&mut hasher, digest);
                hasher.update(mode.to_be_bytes());
            }
        }
        digest_field(&mut hasher, &self.expected_post_digest);
        hasher.update(self.expected_target_mode.to_be_bytes());
        digest_field(
            &mut hasher,
            permission_name(PermissionClass::RepositoryWrite),
        );
        hasher.update(self.execution_epoch.to_be_bytes());
        digest_field(&mut hasher, &self.policy_digest);
        digest_field(&mut hasher, &self.permission_decision_digest);
        digest_field(&mut hasher, &self.isolation_policy_digest);
        digest_field(&mut hasher, &self.nonce);
        hasher.update(self.expires_at_ms.to_be_bytes());
        digest_field(
            &mut hasher,
            command_risk_name(CommandRisk::RepositoryMutation),
        );
        digest_field(&mut hasher, "unsafe_side_effect");
        hasher.update(self.action_deadline_ms.to_be_bytes());
        hasher.update(self.disk_write_bytes.to_be_bytes());
        format!("sha256:{:x}", hasher.finalize())
    }

    /// Validates exact immutable fields before journal authorization.
    ///
    /// # Errors
    /// Returns fail-closed for malformed identities, path/precondition mismatches, or expiry.
    pub fn validate(&self, now_ms: i64) -> Result<(), ToolError> {
        validate_commit_relative_path(&self.relative_path)?;
        let precondition_valid = match (&self.kind, &self.precondition) {
            (RepositoryMutationKind::Create, RepositoryMutationPrecondition::Absent) => true,
            (
                RepositoryMutationKind::Update,
                RepositoryMutationPrecondition::ExactFile { digest, mode },
            ) => digest.starts_with("sha256:") && *mode <= 0o777,
            _ => false,
        };
        if self.action_id.trim().is_empty()
            || self.plan_id.trim().is_empty()
            || self.task_id.trim().is_empty()
            || self.attempt_id.trim().is_empty()
            || self.tool_id.trim().is_empty()
            || self.tool_version.trim().is_empty()
            || self.repository_id.trim().is_empty()
            || self.nonce.trim().is_empty()
            || !self.tool_digest.starts_with("sha256:")
            || !self.expected_post_digest.starts_with("sha256:")
            || !self.policy_digest.starts_with("sha256:")
            || !self.permission_decision_digest.starts_with("sha256:")
            || !self.isolation_policy_digest.starts_with("sha256:")
            || self.expected_target_mode > 0o777
            || self.execution_epoch < 0
            || self.action_deadline_ms == 0
            || !precondition_valid
        {
            return Err(ToolError::Authority(
                "authorized repository mutation has incomplete exact-binding fields".to_owned(),
            ));
        }
        if self.expires_at_ms < now_ms {
            return Err(ToolError::Authority(
                "authorized repository mutation expired".to_owned(),
            ));
        }
        Ok(())
    }

    /// Verifies exact task/tool/policy authority for repository-write capability.
    ///
    /// # Errors
    /// Returns an authority error on any permission-decision drift.
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
            || !decision
                .effective
                .contains(PermissionClass::RepositoryWrite)
        {
            return Err(ToolError::Authority(
                "authorized repository mutation does not match exact permission decision"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

impl JournalActionAuthority for AuthorizedAction {
    fn action_id(&self) -> &str {
        &self.action_id
    }
    fn plan_id(&self) -> &str {
        &self.plan_id
    }
    fn plan_revision(&self) -> u32 {
        self.plan_revision
    }
    fn task_id(&self) -> &str {
        &self.task_id
    }
    fn attempt_id(&self) -> &str {
        &self.attempt_id
    }
    fn tool_id(&self) -> &str {
        &self.tool_id
    }
    fn tool_version(&self) -> &str {
        &self.tool_version
    }
    fn tool_digest(&self) -> &str {
        &self.tool_digest
    }
    fn repository_id(&self) -> &str {
        &self.repository_id
    }
    fn destination_digest(&self) -> Option<&str> {
        self.destination_digest.as_deref()
    }
    fn permission_class(&self) -> PermissionClass {
        self.permission_class
    }
    fn execution_epoch(&self) -> i64 {
        self.execution_epoch
    }
    fn policy_digest(&self) -> &str {
        &self.policy_digest
    }
    fn permission_decision_digest(&self) -> &str {
        &self.permission_decision_digest
    }
    fn isolation_policy_digest(&self) -> &str {
        &self.isolation_policy_digest
    }
    fn nonce(&self) -> &str {
        &self.nonce
    }
    fn expires_at_ms(&self) -> i64 {
        self.expires_at_ms
    }
    fn approval_required(&self) -> bool {
        self.approval_required
    }
    fn reconciliation_mode(&self) -> ReconciliationMode {
        self.reconciliation_mode
    }
    fn declared_risk(&self) -> CommandRisk {
        self.command.declared_risk
    }
    fn approval_execution_identity_digest(&self) -> Option<&str> {
        Some(&self.executable_digest)
    }
    fn payload_digest(&self) -> String {
        AuthorizedAction::payload_digest(self)
    }
    fn validate(&self, now_ms: i64) -> Result<(), ToolError> {
        AuthorizedAction::validate(self, now_ms)
    }
    fn verify_permission_decision(&self, decision: &PermissionDecision) -> Result<(), ToolError> {
        AuthorizedAction::verify_permission_decision(self, decision)
    }
    fn verify_approval_claim(&self, claim: &ApprovalClaim, now_ms: i64) -> Result<(), ToolError> {
        AuthorizedAction::verify_approval_claim(self, claim, now_ms)
    }
    fn reservation(&self) -> JournalActionReservation {
        JournalActionReservation {
            tool_actions: 1,
            subprocesses: 1,
            wall_ms: self.command.timeout_ms,
            output_bytes: self.command.output_limit_bytes,
            disk_write_bytes: self.command.disk_write_limit_bytes,
        }
    }
}

impl JournalActionAuthority for AuthorizedRepositoryMutation {
    fn action_id(&self) -> &str {
        &self.action_id
    }
    fn plan_id(&self) -> &str {
        &self.plan_id
    }
    fn plan_revision(&self) -> u32 {
        self.plan_revision
    }
    fn task_id(&self) -> &str {
        &self.task_id
    }
    fn attempt_id(&self) -> &str {
        &self.attempt_id
    }
    fn tool_id(&self) -> &str {
        &self.tool_id
    }
    fn tool_version(&self) -> &str {
        &self.tool_version
    }
    fn tool_digest(&self) -> &str {
        &self.tool_digest
    }
    fn repository_id(&self) -> &str {
        &self.repository_id
    }
    fn destination_digest(&self) -> Option<&str> {
        Some(&self.expected_post_digest)
    }
    fn permission_class(&self) -> PermissionClass {
        PermissionClass::RepositoryWrite
    }
    fn execution_epoch(&self) -> i64 {
        self.execution_epoch
    }
    fn policy_digest(&self) -> &str {
        &self.policy_digest
    }
    fn permission_decision_digest(&self) -> &str {
        &self.permission_decision_digest
    }
    fn isolation_policy_digest(&self) -> &str {
        &self.isolation_policy_digest
    }
    fn nonce(&self) -> &str {
        &self.nonce
    }
    fn expires_at_ms(&self) -> i64 {
        self.expires_at_ms
    }
    fn approval_required(&self) -> bool {
        false
    }
    fn reconciliation_mode(&self) -> ReconciliationMode {
        ReconciliationMode::UnsafeSideEffect
    }
    fn declared_risk(&self) -> CommandRisk {
        CommandRisk::RepositoryMutation
    }
    fn approval_execution_identity_digest(&self) -> Option<&str> {
        None
    }
    fn payload_digest(&self) -> String {
        AuthorizedRepositoryMutation::payload_digest(self)
    }
    fn validate(&self, now_ms: i64) -> Result<(), ToolError> {
        AuthorizedRepositoryMutation::validate(self, now_ms)
    }
    fn verify_permission_decision(&self, decision: &PermissionDecision) -> Result<(), ToolError> {
        AuthorizedRepositoryMutation::verify_permission_decision(self, decision)
    }
    fn verify_approval_claim(&self, _claim: &ApprovalClaim, _now_ms: i64) -> Result<(), ToolError> {
        Err(ToolError::Authority(
            "repository mutation actions cannot carry approval claims under Plan IR v1.2"
                .to_owned(),
        ))
    }
    fn reservation(&self) -> JournalActionReservation {
        JournalActionReservation {
            tool_actions: 1,
            subprocesses: 0,
            wall_ms: self.action_deadline_ms,
            output_bytes: 0,
            disk_write_bytes: self.disk_write_bytes,
        }
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
    pub fn prepare(&mut self, action: &dyn JournalActionAuthority) -> Result<i64, ToolError> {
        action.validate(unix_millis()?)?;
        let payload_digest = action.payload_digest();
        Ok(self.store.insert_action_record(NewActionRecord {
            action_id: action.action_id(),
            state: ActionState::Prepared.as_str(),
            payload_digest: &payload_digest,
            policy_digest: action.policy_digest(),
            execution_epoch: action.execution_epoch(),
            event_id: &event_id(action.action_id(), ActionState::Prepared.as_str()),
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
        action: &dyn JournalActionAuthority,
        manifest: &ToolManifest,
        permission_decision: &PermissionDecision,
    ) -> Result<i64, ToolError> {
        let now = unix_millis()?;
        action.validate(now)?;
        action.verify_permission_decision(permission_decision)?;
        manifest.validate()?;
        if !manifest
            .reconciliation_policy
            .permits_candidate(action.reconciliation_mode().policy())
        {
            return Err(ToolError::Authority(
                "authorized action reconciliation policy weakens tool/adapter declaration"
                    .to_owned(),
            ));
        }
        if manifest.tool_id != action.tool_id() {
            return Err(ToolError::Authority(format!(
                "action tool {} does not match manifest {}",
                action.tool_id(),
                manifest.tool_id
            )));
        }
        if manifest.version != action.tool_version()
            || manifest.content_digest != action.tool_digest()
        {
            return Err(ToolError::Authority(format!(
                "action tool identity does not match manifest {}@{}",
                manifest.tool_id, manifest.version
            )));
        }
        if !manifest
            .permission_ceiling
            .contains(&action.permission_class())
        {
            return Err(ToolError::Authority(format!(
                "tool manifest does not permit {:?}",
                action.permission_class()
            )));
        }
        if action.declared_risk() < manifest.declared_risk_floor {
            return Err(ToolError::Authority(format!(
                "action risk {:?} is below tool manifest floor {:?}",
                action.declared_risk(),
                manifest.declared_risk_floor
            )));
        }
        let current_epoch = self.store.current_execution_epoch()?;
        if current_epoch != action.execution_epoch() {
            return Err(ToolError::Authority(format!(
                "authorization epoch mismatch: action={}, controller={current_epoch}",
                action.execution_epoch()
            )));
        }
        if self.store.action_record(action.action_id())?.is_none() {
            self.prepare(action)?;
        }
        let prepared = self
            .store
            .action_record(action.action_id())?
            .ok_or_else(|| ToolError::Authority("prepared action disappeared".to_owned()))?;
        if prepared.state != ActionState::Prepared.as_str()
            || prepared.payload_digest != action.payload_digest()
            || prepared.policy_digest != action.policy_digest()
            || prepared.execution_epoch != action.execution_epoch()
        {
            return Err(ToolError::Authority(format!(
                "prepared action does not match exact authorization {}",
                action.action_id()
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
        action: &dyn JournalActionAuthority,
    ) -> Result<PersistedActionRecord, ToolError> {
        action.validate(unix_millis()?)?;
        let record = self
            .store
            .action_record(action.action_id())?
            .ok_or_else(|| {
                ToolError::Authority(format!(
                    "missing durable authorization for {}",
                    action.action_id()
                ))
            })?;
        if record.state != "authorized"
            || record.payload_digest != action.payload_digest()
            || record.policy_digest != action.policy_digest()
            || record.execution_epoch != action.execution_epoch()
            || self.store.current_execution_epoch()? != action.execution_epoch()
        {
            return Err(ToolError::Authority(format!(
                "durable authorization no longer matches exact action {}",
                action.action_id()
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
        action: &dyn JournalActionAuthority,
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
            action_id: action.action_id(),
            expected_state: expected.as_str(),
            next_state: next.as_str(),
            expected_epoch: action.execution_epoch(),
            event_id: &event_id(action.action_id(), next.as_str()),
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
        action: &dyn JournalActionAuthority,
        artifacts: &ArtifactStore,
        receipt: &[u8],
    ) -> Result<String, ToolError> {
        let artifact = artifacts.put(self.store, receipt)?;
        let digest = artifact.digest;
        self.store.transition_action_with_event(ActionTransition {
            action_id: action.action_id(),
            expected_state: ActionState::Dispatched.as_str(),
            next_state: ActionState::Observed.as_str(),
            expected_epoch: action.execution_epoch(),
            event_id: &event_id(action.action_id(), ActionState::Observed.as_str()),
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
        action: &dyn JournalActionAuthority,
        expected: ActionState,
    ) -> Result<i64, ToolError> {
        if !matches!(expected, ActionState::Observed | ActionState::Reconciled) {
            return Err(ToolError::InvalidTransition(
                "commit requires observed or reconciled state".to_owned(),
            ));
        }
        let record = self
            .store
            .action_record(action.action_id())?
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
        action: &dyn JournalActionAuthority,
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
        action: &dyn JournalActionAuthority,
        proof: Option<ReconciliationProof>,
    ) -> Result<Reconciliation, ToolError> {
        let decision = reconcile(action.reconciliation_mode(), proof);
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
    pub fn verify_dispatch_approval(
        &self,
        action: &dyn JournalActionAuthority,
    ) -> Result<(), ToolError> {
        if !action.approval_required() {
            return Ok(());
        }
        let raw = self
            .store
            .get_state(APPROVAL_CLAIM_NAMESPACE, action.action_id())?
            .ok_or_else(|| {
                ToolError::Authority(format!(
                    "approval-required action {} has no durable approval claim",
                    action.action_id()
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

/// Cloneable cancellation signal for one Controller-owned process dispatch.
///
/// Cancellation is advisory until [`ProcessRunner`] proves ownership of the already-spawned
/// process group and reaps it. A cancelled dispatched action is therefore returned as an error and
/// left `unknown` for ordinary reconciliation rather than being reported as a successful result.
#[derive(Debug, Clone, Default)]
pub struct ProcessCancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl ProcessCancellationToken {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
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

#[derive(Clone, Copy)]
struct ProcessMonitorContext<'a> {
    pgid: u32,
    leader_identity: &'a str,
    action: &'a AuthorizedAction,
    baseline_disk: u64,
    output_count: &'a AtomicU64,
    cancellation: Option<&'a ProcessCancellationToken>,
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
        self.run_cancellable(
            journal,
            action,
            isolation_request,
            artifacts,
            &ProcessCancellationToken::new(),
        )
    }

    /// Executes one authorized action while observing an external cancellation token.
    ///
    /// A cancellation observed before dispatch prevents the process from starting. Once dispatch
    /// has occurred, cancellation succeeds only after the persisted process-group identity still
    /// matches the live leader and the exact owned group is proven absent. The action is then left
    /// `unknown` because a partially executed mutation must be reconciled from durable evidence.
    ///
    /// # Errors
    /// Returns the same errors as [`Self::run`], plus a recovery-blocking cancellation result after
    /// dispatch or when exact process ownership/cleanup cannot be proven.
    pub fn run_cancellable(
        &self,
        journal: &mut ActionJournal<'_>,
        action: &AuthorizedAction,
        isolation_request: &IsolationRequest,
        artifacts: &ArtifactStore,
        cancellation: &ProcessCancellationToken,
    ) -> Result<RawToolResult, ToolError> {
        journal.verify_authorized(action)?;
        journal.verify_dispatch_approval(action)?;
        let prepared = self.prepare_execution(action, isolation_request)?;
        if cancellation.is_cancelled() {
            return Err(ToolError::RecoveryBlocked(
                "process execution cancelled before dispatch".to_owned(),
            ));
        }
        journal.transition(action, ActionState::Authorized, ActionState::Dispatched)?;
        journal.record_process_lease(action, None, None, "pending_spawn")?;
        self.execute_dispatched(journal, action, artifacts, prepared, cancellation)
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
        self.run_with_secret_lease_observed_cancellable(
            journal,
            action,
            isolation_request,
            artifacts,
            secret_lease,
            secret_scope,
            permission_decision,
            now_ms,
            controller_private_root,
            &ProcessCancellationToken::new(),
        )
    }

    /// Secret-aware variant of [`Self::run_with_secret_lease_observed`] that observes an external
    /// cancellation token while the exact owned process group is running.
    ///
    /// Cancellation before dispatch prevents process creation. Cancellation after dispatch first
    /// proves the persisted leader identity still owns the live process group, terminates/reaps that
    /// exact group, drains and redacts any secret-bearing output, and leaves the action `unknown`
    /// for reconciliation. The temporary secret file is closed before the error escapes, while the
    /// Controller-owned `SecretLease` itself remains open for Controller closure.
    ///
    /// # Errors
    /// Returns the same fail-closed errors as [`Self::run_with_secret_lease_observed`], plus a
    /// recovery-blocking cancellation result when execution is cancelled or exact cleanup cannot be
    /// proven.
    #[allow(clippy::too_many_arguments)]
    pub fn run_with_secret_lease_observed_cancellable(
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
        cancellation: &ProcessCancellationToken,
    ) -> Result<(RawToolResult, SecretCleanupProof), ToolError> {
        Self::validate_secret_dispatch_authority(
            journal,
            action,
            secret_lease,
            secret_scope,
            permission_decision,
        )?;
        let mut prepared = self.prepare_execution(action, isolation_request)?;
        if cancellation.is_cancelled() {
            return Err(ToolError::RecoveryBlocked(
                "secret process execution cancelled before dispatch".to_owned(),
            ));
        }
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
                self.execute_secret_dispatched(
                    journal,
                    action,
                    artifacts,
                    prepared,
                    secret_bytes,
                    cancellation,
                )
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

    fn validate_secret_dispatch_authority(
        journal: &mut ActionJournal<'_>,
        action: &AuthorizedAction,
        secret_lease: &SecretLease,
        secret_scope: &SecretScope,
        permission_decision: &PermissionDecision,
    ) -> Result<(), ToolError> {
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
        Ok(())
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
        cancellation: &ProcessCancellationToken,
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

        let (mut child, pgid, leader_identity) =
            Self::spawn_owned_process(journal, action, &mut command)?;
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
        let (status, limited, cancelled) = self.monitor_child(
            &mut child,
            ProcessMonitorContext {
                pgid,
                leader_identity: &leader_identity,
                action,
                baseline_disk: prepared.baseline_disk,
                output_count: &output_count,
                cancellation: Some(cancellation),
            },
        )?;

        let reaped = wait_group_absent(pgid, Duration::from_millis(500))?;
        if !reaped {
            journal.transition(action, ActionState::Dispatched, ActionState::Unknown)?;
            return Err(ToolError::RecoveryBlocked(format!(
                "process group {pgid} still has members after cleanup"
            )));
        }

        if cancelled {
            return Self::finish_cancelled_dispatch(
                journal,
                action,
                pgid,
                &leader_identity,
                stdout_handle,
                stderr_handle,
            );
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
        cancellation: &ProcessCancellationToken,
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

        let (mut child, pgid, leader_identity) =
            Self::spawn_owned_process(journal, action, &mut command)?;
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
        let (status, limited, cancelled) = self.monitor_child(
            &mut child,
            ProcessMonitorContext {
                pgid,
                leader_identity: &leader_identity,
                action,
                baseline_disk: prepared.baseline_disk,
                output_count: &output_count,
                cancellation: Some(cancellation),
            },
        )?;
        let reaped = wait_group_absent(pgid, Duration::from_millis(500))?;
        if !reaped {
            journal.transition(action, ActionState::Dispatched, ActionState::Unknown)?;
            return Err(ToolError::RecoveryBlocked(format!(
                "process group {pgid} still has members after cleanup"
            )));
        }
        journal.record_process_lease(action, Some(pgid), Some(&leader_identity), "reaped")?;

        if cancelled {
            return Self::finish_cancelled_secret_dispatch(
                journal,
                action,
                stdout_handle,
                stderr_handle,
                secret_bytes,
            );
        }

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

    fn finish_cancelled_secret_dispatch(
        journal: &mut ActionJournal<'_>,
        action: &AuthorizedAction,
        stdout_handle: Option<ReaderHandle>,
        stderr_handle: Option<ReaderHandle>,
        secret_bytes: &[u8],
    ) -> Result<RawToolResult, ToolError> {
        journal.transition(action, ActionState::Dispatched, ActionState::Unknown)?;
        let mut raw_stdout = receive_reader(stdout_handle, Duration::from_millis(500))?;
        let mut raw_stderr = receive_reader(stderr_handle, Duration::from_millis(500))?;
        let redactor = Redactor::v1();
        let stdout_redaction = redactor.redact_bytes(&raw_stdout, &[secret_bytes]);
        let stderr_redaction = redactor.redact_bytes(&raw_stderr, &[secret_bytes]);
        raw_stdout.fill(0);
        raw_stderr.fill(0);
        stdout_redaction?;
        stderr_redaction?;
        Err(ToolError::RecoveryBlocked(
            "secret process execution cancelled after dispatch; action outcome requires reconciliation"
                .to_owned(),
        ))
    }

    fn monitor_child(
        &self,
        child: &mut Child,
        context: ProcessMonitorContext<'_>,
    ) -> Result<(std::process::ExitStatus, Option<ResourceLimitKind>, bool), ToolError> {
        let start = Instant::now();
        loop {
            if let Some(status) = child.try_wait()? {
                return Ok((status, None, false));
            }
            if context
                .cancellation
                .is_some_and(ProcessCancellationToken::is_cancelled)
            {
                let status =
                    terminate_owned_process_group(child, context.pgid, context.leader_identity)?;
                return Ok((status, None, true));
            }
            let elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
            let limited = if elapsed_ms > context.action.command.timeout_ms {
                Some(ResourceLimitKind::Timeout)
            } else if context.output_count.load(Ordering::Relaxed)
                > context.action.command.output_limit_bytes
            {
                Some(ResourceLimitKind::OutputBytes)
            } else if directory_size(&context.action.command.working_directory)?
                .saturating_sub(context.baseline_disk)
                > context.action.command.disk_write_limit_bytes
            {
                Some(ResourceLimitKind::DiskBytes)
            } else if descendant_count(context.pgid)? > context.action.command.subprocess_limit {
                Some(ResourceLimitKind::Subprocesses)
            } else {
                None
            };
            if let Some(limit) = limited {
                terminate_process_group(child, context.pgid)?;
                return Ok((child.wait()?, Some(limit), false));
            }
            thread::sleep(self.poll_interval);
        }
    }

    fn finish_cancelled_dispatch(
        journal: &mut ActionJournal<'_>,
        action: &AuthorizedAction,
        pgid: u32,
        leader_identity: &str,
        stdout_handle: Option<ReaderHandle>,
        stderr_handle: Option<ReaderHandle>,
    ) -> Result<RawToolResult, ToolError> {
        journal.record_process_lease(action, Some(pgid), Some(leader_identity), "reaped")?;
        journal.transition(action, ActionState::Dispatched, ActionState::Unknown)?;
        let _ = receive_reader(stdout_handle, Duration::from_millis(500))?;
        let _ = receive_reader(stderr_handle, Duration::from_millis(500))?;
        Err(ToolError::RecoveryBlocked(
            "process execution cancelled after dispatch; action outcome requires reconciliation"
                .to_owned(),
        ))
    }

    fn spawn_owned_process(
        journal: &mut ActionJournal<'_>,
        action: &AuthorizedAction,
        command: &mut Command,
    ) -> Result<(Child, u32, String), ToolError> {
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
        Ok((child, pgid, leader_identity))
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

fn terminate_owned_process_group(
    child: &mut Child,
    pgid: u32,
    expected_identity: &str,
) -> Result<std::process::ExitStatus, ToolError> {
    match process_group_leader_identity(pgid)? {
        Some(current) if current == expected_identity => {}
        Some(_) => {
            return Err(ToolError::RecoveryBlocked(format!(
                "process group leader identity changed for {pgid}; refusing cancellation kill"
            )));
        }
        None => {
            if let Some(status) = child.try_wait()?
                && wait_group_absent(pgid, Duration::from_millis(50))?
            {
                return Ok(status);
            }
            return Err(ToolError::RecoveryBlocked(format!(
                "process group {pgid} lost its recorded leader identity before cancellation"
            )));
        }
    }

    terminate_process_group(child, pgid)?;
    let status = child.wait()?;
    if wait_group_absent(pgid, Duration::from_millis(500))? {
        Ok(status)
    } else {
        Err(ToolError::RecoveryBlocked(format!(
            "owned process group {pgid} remains after cancellation kill"
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

pub const WEB_ACQUIRE_SCHEMA_VERSION: u32 = 1;
const WEB_ACQUIRE_MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const WEB_ACQUIRE_MAX_REDIRECTS: u8 = 8;
const WEB_ACQUIRE_MAX_TIMEOUT_MS: u64 = 60_000;

/// Controller-owned input contract for one bounded static HTTP acquisition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebAcquireRequestV1 {
    pub schema_version: u32,
    pub request_id: String,
    pub url: String,
    pub max_response_bytes: usize,
    pub max_redirects: u8,
    pub timeout_ms: u64,
    pub parse_html: bool,
}

impl WebAcquireRequestV1 {
    /// Validates only shape and resource bounds. Network authority remains exclusively in
    /// [`NetworkPolicy`].
    ///
    /// # Errors
    /// Returns an authority error for unsupported schemas or unbounded requests.
    pub fn validate(&self) -> Result<(), ToolError> {
        if self.schema_version != WEB_ACQUIRE_SCHEMA_VERSION {
            return Err(ToolError::Authority(
                "unsupported web-acquire request schema version".to_owned(),
            ));
        }
        if self.request_id.trim().is_empty() || self.url.trim().is_empty() {
            return Err(ToolError::Authority(
                "web-acquire request requires request_id and url".to_owned(),
            ));
        }
        if self.max_response_bytes == 0
            || self.max_response_bytes > WEB_ACQUIRE_MAX_RESPONSE_BYTES
            || self.max_redirects > WEB_ACQUIRE_MAX_REDIRECTS
            || self.timeout_ms == 0
            || self.timeout_ms > WEB_ACQUIRE_MAX_TIMEOUT_MS
        {
            return Err(ToolError::ResourceLimit(
                "web-acquire request exceeds static acquisition bounds".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebRawResponseEvidenceV1 {
    pub url: String,
    pub status_code: u16,
    pub connected_peer: IpAddr,
    pub headers_sha256: String,
    pub body_sha256: String,
    pub body_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebParsedDocumentV1 {
    pub parser_name: String,
    pub parser_version: String,
    pub title: Option<String>,
    pub text: String,
    pub links: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebAcquireResultV1 {
    pub schema_version: u32,
    pub request_id: String,
    pub final_url: String,
    pub status_code: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
    pub responses: Vec<WebRawResponseEvidenceV1>,
    pub parsed: Option<WebParsedDocumentV1>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebTransportRequestV1 {
    pub url: String,
    pub destination: NetworkDestination,
    pub connect_ip: IpAddr,
    pub max_response_bytes: usize,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebTransportResponseV1 {
    pub status_code: u16,
    pub connected_peer: IpAddr,
    pub headers: BTreeMap<String, String>,
    pub raw_headers: Vec<u8>,
    pub body: Vec<u8>,
}

pub trait WebDnsResolver: Send + Sync {
    /// Returns the complete address set intended for the next connection attempt.
    ///
    /// # Errors
    /// Returns an I/O/policy error when the name cannot be resolved deterministically.
    fn resolve(&self, destination: &NetworkDestination) -> Result<BTreeSet<IpAddr>, ToolError>;
}

pub trait WebHttpTransport: Send + Sync {
    /// Executes one already-authorized, non-redirecting GET. Implementations must connect only to
    /// `request.connect_ip`; redirect following is deliberately owned by [`WebAcquireAdapter`].
    ///
    /// # Errors
    /// Returns an error for transport failure, timeout, or bounded-response failure.
    fn get(&self, request: &WebTransportRequestV1) -> Result<WebTransportResponseV1, ToolError>;
}

pub trait WebHtmlParser: Send + Sync {
    /// Parses already-acquired bytes. Parsing never grants network/browser/tool authority.
    ///
    /// # Errors
    /// Returns an error when the parser is unavailable, crashes, times out, or violates bounds.
    fn parse(&self, html: &[u8], timeout_ms: u64) -> Result<WebParsedDocumentV1, ToolError>;
}

/// Sovereign-owned static HTTP acquisition flow. `NetworkPolicy` is always consulted before the
/// resolver result may reach a transport; redirects repeat the same authorization sequence.
pub struct WebAcquireAdapter<'a> {
    network_policy: &'a NetworkPolicy,
    resolver: &'a dyn WebDnsResolver,
    transport: &'a dyn WebHttpTransport,
    parser: Option<&'a dyn WebHtmlParser>,
}

impl<'a> WebAcquireAdapter<'a> {
    #[must_use]
    pub const fn new(
        network_policy: &'a NetworkPolicy,
        resolver: &'a dyn WebDnsResolver,
        transport: &'a dyn WebHttpTransport,
    ) -> Self {
        Self {
            network_policy,
            resolver,
            transport,
            parser: None,
        }
    }

    #[must_use]
    pub const fn with_parser(mut self, parser: &'a dyn WebHtmlParser) -> Self {
        self.parser = Some(parser);
        self
    }

    /// Acquires one static resource under exact Controller-owned network policy.
    ///
    /// # Errors
    /// Fails closed for offline policy, malformed/unauthorized destinations, unsafe DNS sets,
    /// connected-peer mismatch, disallowed redirects, resource limits, or parser failure.
    pub fn acquire(&self, request: &WebAcquireRequestV1) -> Result<WebAcquireResultV1, ToolError> {
        request.validate()?;
        if self.network_policy.is_offline() {
            return Err(ToolError::Policy(PolicyError::Denied(
                "web acquisition denied by offline network policy".to_owned(),
            )));
        }

        let mut current_url = request.url.clone();
        let mut responses = Vec::new();
        let mut redirects = 0_u8;

        loop {
            let parsed_url = ParsedWebUrl::parse(&current_url)?;
            let canonical_destination = self
                .network_policy
                .authorize_destination(&parsed_url.destination)?;
            let parsed_url = parsed_url.with_destination(canonical_destination);
            let resolved = self.resolver.resolve(&parsed_url.destination)?;
            let authorization = if redirects == 0 {
                self.network_policy
                    .authorize_resolved(&parsed_url.destination, resolved)?
            } else {
                self.network_policy
                    .authorize_redirect(&parsed_url.destination, resolved)?
            };
            let connect_ip = authorization.resolved_ips().next().ok_or_else(|| {
                ToolError::Authority("authorized web destination has no connect IP".to_owned())
            })?;
            let transport_request = WebTransportRequestV1 {
                url: parsed_url.canonical_url.clone(),
                destination: authorization.destination(),
                connect_ip,
                max_response_bytes: request.max_response_bytes,
                timeout_ms: request.timeout_ms,
            };
            let response = self.transport.get(&transport_request)?;
            self.network_policy
                .authorize_connected_peer(&authorization, response.connected_peer)?;
            if response.body.len() > request.max_response_bytes {
                return Err(ToolError::ResourceLimit(
                    "web response exceeded authorized byte bound".to_owned(),
                ));
            }
            let evidence = raw_web_response_evidence(
                &transport_request.url,
                response.status_code,
                response.connected_peer,
                &response.raw_headers,
                &response.body,
            );
            responses.push(evidence);

            if is_redirect_status(response.status_code)
                && let Some(location) = response.headers.get("location")
            {
                if redirects >= request.max_redirects {
                    return Err(ToolError::ResourceLimit(
                        "web redirect limit exhausted".to_owned(),
                    ));
                }
                current_url = resolve_redirect_url(&parsed_url, location)?;
                redirects = redirects.saturating_add(1);
                continue;
            }

            let parsed = if request.parse_html {
                let parser = self.parser.ok_or_else(|| {
                    ToolError::Authority(
                        "static HTML parsing requested without an admitted parser".to_owned(),
                    )
                })?;
                Some(parser.parse(&response.body, request.timeout_ms)?)
            } else {
                None
            };
            return Ok(WebAcquireResultV1 {
                schema_version: WEB_ACQUIRE_SCHEMA_VERSION,
                request_id: request.request_id.clone(),
                final_url: transport_request.url,
                status_code: response.status_code,
                headers: response.headers,
                body: response.body,
                responses,
                parsed,
            });
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemWebDnsResolver;

impl WebDnsResolver for SystemWebDnsResolver {
    fn resolve(&self, destination: &NetworkDestination) -> Result<BTreeSet<IpAddr>, ToolError> {
        let addresses = (destination.host.as_str(), destination.port)
            .to_socket_addrs()?
            .map(|address| address.ip())
            .collect::<BTreeSet<_>>();
        if addresses.is_empty() {
            return Err(ToolError::Authority(
                "web DNS resolver returned no addresses".to_owned(),
            ));
        }
        Ok(addresses)
    }
}

/// Fixed system-curl transport used only after [`WebAcquireAdapter`] has authorized the complete
/// DNS set. It disables curl config, ambient proxies and automatic redirects, and pins the socket
/// connection to the exact public IP selected from that authorized set.
#[derive(Debug, Clone)]
pub struct CurlWebHttpTransport {
    curl_path: PathBuf,
}

impl Default for CurlWebHttpTransport {
    fn default() -> Self {
        Self {
            curl_path: PathBuf::from("/usr/bin/curl"),
        }
    }
}

impl CurlWebHttpTransport {
    #[must_use]
    pub fn system() -> Self {
        Self::default()
    }

    fn execute(
        &self,
        request: &WebTransportRequestV1,
    ) -> Result<WebTransportResponseV1, ToolError> {
        if !self.curl_path.is_absolute() || self.curl_path != Path::new("/usr/bin/curl") {
            return Err(ToolError::Authority(
                "web transport requires pinned /usr/bin/curl".to_owned(),
            ));
        }
        let nonce = ATOMIC_REPLACE_NONCE.fetch_add(1, Ordering::Relaxed);
        let base =
            std::env::temp_dir().join(format!("sovereign-web-{}-{nonce}", std::process::id()));
        fs::create_dir(&base)?;
        let header_path = base.join("headers");
        let body_path = base.join("body");
        let cleanup = || {
            let _ = fs::remove_dir_all(&base);
        };
        let connect_ip = match request.connect_ip {
            IpAddr::V4(address) => address.to_string(),
            IpAddr::V6(address) => format!("[{address}]"),
        };
        let resolve_host = request
            .destination
            .host
            .trim_start_matches('[')
            .trim_end_matches(']');
        let resolve = format!(
            "{}:{}:{}",
            resolve_host, request.destination.port, connect_ip
        );
        let max_seconds = request.timeout_ms.div_ceil(1_000).max(1).to_string();
        let output = Command::new(&self.curl_path)
            .env_clear()
            .args([
                "--disable",
                "--silent",
                "--show-error",
                "--http1.1",
                "--noproxy",
                "*",
                "--proxy",
                "",
                "--proto",
                "=http,https",
                "--max-redirs",
                "0",
                "--max-time",
                &max_seconds,
                "--max-filesize",
                &request.max_response_bytes.to_string(),
                "--resolve",
                &resolve,
                "--dump-header",
                header_path.to_string_lossy().as_ref(),
                "--output",
                body_path.to_string_lossy().as_ref(),
                "--write-out",
                "%{http_code}\n%{remote_ip}\n",
                &request.url,
            ])
            .output();
        let output = match output {
            Ok(output) => output,
            Err(error) => {
                cleanup();
                return Err(error.into());
            }
        };
        let body_len = fs::metadata(&body_path).map_or(0, |metadata| metadata.len());
        let max_response_bytes = u64::try_from(request.max_response_bytes).map_err(|_| {
            ToolError::ResourceLimit("web response byte bound is not representable".to_owned())
        })?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            cleanup();
            if body_len >= max_response_bytes {
                return Err(ToolError::ResourceLimit(
                    "curl web response reached authorized byte bound".to_owned(),
                ));
            }
            return Err(ToolError::Authority(format!(
                "pinned curl transport failed: {}",
                stderr.trim().chars().take(512).collect::<String>()
            )));
        }
        let (status_code, connected_peer) = parse_curl_metadata(output.stdout)?;
        let raw_headers = fs::read(&header_path)?;
        let body = fs::read(&body_path)?;
        cleanup();
        if body.len() > request.max_response_bytes {
            return Err(ToolError::ResourceLimit(
                "curl web response exceeded authorized byte bound".to_owned(),
            ));
        }
        let headers = parse_http_headers(&raw_headers)?;
        Ok(WebTransportResponseV1 {
            status_code,
            connected_peer,
            headers,
            raw_headers,
            body,
        })
    }
}

impl WebHttpTransport for CurlWebHttpTransport {
    fn get(&self, request: &WebTransportRequestV1) -> Result<WebTransportResponseV1, ToolError> {
        self.execute(request)
    }
}

fn parse_curl_metadata(stdout: Vec<u8>) -> Result<(u16, IpAddr), ToolError> {
    let stdout = String::from_utf8(stdout).map_err(|_| {
        ToolError::Authority("curl transport returned non-UTF8 metadata".to_owned())
    })?;
    let mut lines = stdout.lines();
    let status_code = lines
        .next()
        .ok_or_else(|| ToolError::Authority("curl omitted HTTP status".to_owned()))?
        .parse::<u16>()
        .map_err(|_| ToolError::Authority("curl returned invalid HTTP status".to_owned()))?;
    let connected_peer = lines
        .next()
        .ok_or_else(|| ToolError::Authority("curl omitted connected peer".to_owned()))?
        .parse::<IpAddr>()
        .map_err(|_| ToolError::Authority("curl returned invalid connected peer".to_owned()))?;
    Ok((status_code, connected_peer))
}

/// Demand-loaded static parser worker backed by vendored Scrapling. The worker is invoked with an
/// explicit Python runtime chosen by the Controller/operator; no package installation or browser
/// setup is performed here.
#[derive(Debug, Clone)]
pub struct ScraplingStaticParser {
    python_path: PathBuf,
    worker_path: PathBuf,
    vendored_scrapling_root: PathBuf,
    max_output_bytes: usize,
}

impl ScraplingStaticParser {
    #[must_use]
    pub fn new(
        python_path: impl Into<PathBuf>,
        worker_path: impl Into<PathBuf>,
        vendored_scrapling_root: impl Into<PathBuf>,
    ) -> Self {
        Self {
            python_path: python_path.into(),
            worker_path: worker_path.into(),
            vendored_scrapling_root: vendored_scrapling_root.into(),
            max_output_bytes: 256 * 1024,
        }
    }

    fn run_worker(
        &self,
        html: &[u8],
        timeout_ms: u64,
        python: &Path,
        worker: &Path,
        vendor: &Path,
    ) -> Result<Vec<u8>, ToolError> {
        if html.len() > WEB_ACQUIRE_MAX_RESPONSE_BYTES {
            return Err(ToolError::ResourceLimit(
                "Scrapling parser input exceeded static acquisition bound".to_owned(),
            ));
        }
        let timeout_ms = timeout_ms.clamp(1, WEB_ACQUIRE_MAX_TIMEOUT_MS);
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        let mut process = ParserWorkerProcess::spawn(
            python,
            worker,
            vendor,
            html.to_vec(),
            self.max_output_bytes,
        )?;
        let stop = process.wait_until(deadline);
        process.finish(stop)
    }
}

struct ParserWorkerProcess {
    child: Child,
    writer: thread::JoinHandle<std::io::Result<()>>,
    stdout_reader: thread::JoinHandle<std::io::Result<Vec<u8>>>,
    stderr_reader: thread::JoinHandle<std::io::Result<Vec<u8>>>,
    stdout_overflow: Arc<AtomicBool>,
    stderr_overflow: Arc<AtomicBool>,
}

impl ParserWorkerProcess {
    fn spawn(
        python: &Path,
        worker: &Path,
        vendor: &Path,
        input: Vec<u8>,
        max_output_bytes: usize,
    ) -> Result<Self, ToolError> {
        let mut child = Command::new(python)
            .env_clear()
            .env("PYTHONPATH", vendor)
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .env("PYTHONNOUSERSITE", "1")
            .arg("-s")
            .arg(worker)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let Some(mut stdin) = child.stdin.take() else {
            terminate_and_reap_parser_child(&mut child)?;
            return Err(ToolError::Authority(
                "Scrapling parser stdin was unavailable".to_owned(),
            ));
        };
        let Some(stdout) = child.stdout.take() else {
            terminate_and_reap_parser_child(&mut child)?;
            return Err(ToolError::Authority(
                "Scrapling parser stdout was unavailable".to_owned(),
            ));
        };
        let Some(stderr) = child.stderr.take() else {
            terminate_and_reap_parser_child(&mut child)?;
            return Err(ToolError::Authority(
                "Scrapling parser stderr was unavailable".to_owned(),
            ));
        };
        let writer = thread::spawn(move || stdin.write_all(&input));
        let stdout_overflow = Arc::new(AtomicBool::new(false));
        let stderr_overflow = Arc::new(AtomicBool::new(false));
        let stdout_reader =
            spawn_bounded_pipe_reader(stdout, max_output_bytes, Arc::clone(&stdout_overflow));
        let stderr_reader =
            spawn_bounded_pipe_reader(stderr, max_output_bytes, Arc::clone(&stderr_overflow));
        Ok(Self {
            child,
            writer,
            stdout_reader,
            stderr_reader,
            stdout_overflow,
            stderr_overflow,
        })
    }

    fn wait_until(&mut self, deadline: Instant) -> ParserWorkerStop {
        loop {
            if self.stdout_overflow.load(Ordering::Acquire) {
                break ParserWorkerStop::StdoutOverflow;
            }
            if self.stderr_overflow.load(Ordering::Acquire) {
                break ParserWorkerStop::StderrOverflow;
            }
            if Instant::now() >= deadline {
                break ParserWorkerStop::Timeout;
            }
            match self.child.try_wait() {
                Ok(Some(status)) => break ParserWorkerStop::Exited(status),
                Ok(None) => thread::sleep(Duration::from_millis(5)),
                Err(error) => break ParserWorkerStop::PollError(error),
            }
        }
    }

    fn finish(mut self, stop: ParserWorkerStop) -> Result<Vec<u8>, ToolError> {
        let cleanup = match stop {
            ParserWorkerStop::Exited(_) => Ok(()),
            _ => terminate_and_reap_parser_child(&mut self.child),
        };
        let writer_result = join_parser_io_thread(self.writer, "stdin writer")?;
        let stdout_result = join_parser_io_thread(self.stdout_reader, "stdout reader")?;
        let stderr_result = join_parser_io_thread(self.stderr_reader, "stderr reader")?;
        cleanup?;

        if self.stdout_overflow.load(Ordering::Acquire) {
            return Err(ToolError::ResourceLimit(
                "Scrapling static parser stdout exceeded bound".to_owned(),
            ));
        }
        if self.stderr_overflow.load(Ordering::Acquire) {
            return Err(ToolError::ResourceLimit(
                "Scrapling static parser stderr exceeded bound".to_owned(),
            ));
        }

        match stop {
            ParserWorkerStop::Timeout => Err(ToolError::ResourceLimit(
                "Scrapling static parser timed out".to_owned(),
            )),
            ParserWorkerStop::StdoutOverflow => Err(ToolError::ResourceLimit(
                "Scrapling static parser stdout exceeded bound".to_owned(),
            )),
            ParserWorkerStop::StderrOverflow => Err(ToolError::ResourceLimit(
                "Scrapling static parser stderr exceeded bound".to_owned(),
            )),
            ParserWorkerStop::PollError(error) => Err(ToolError::Io(error)),
            ParserWorkerStop::Exited(status) => {
                let stdout = stdout_result?;
                let stderr = stderr_result?;
                if !status.success() {
                    return Err(ToolError::Authority(format!(
                        "Scrapling static parser failed: {}",
                        String::from_utf8_lossy(&stderr)
                            .trim()
                            .chars()
                            .take(512)
                            .collect::<String>()
                    )));
                }
                writer_result?;
                Ok(stdout)
            }
        }
    }
}

#[derive(Debug)]
enum ParserWorkerStop {
    Exited(std::process::ExitStatus),
    Timeout,
    StdoutOverflow,
    StderrOverflow,
    PollError(std::io::Error),
}

fn spawn_bounded_pipe_reader<R: Read + Send + 'static>(
    mut reader: R,
    max_bytes: usize,
    overflow: Arc<AtomicBool>,
) -> thread::JoinHandle<std::io::Result<Vec<u8>>> {
    thread::spawn(move || {
        let mut captured = Vec::with_capacity(max_bytes.min(8 * 1024));
        let mut chunk = [0_u8; 8 * 1024];
        loop {
            let read = reader.read(&mut chunk)?;
            if read == 0 {
                break;
            }
            let remaining = max_bytes.saturating_sub(captured.len());
            let retained = remaining.min(read);
            captured.extend_from_slice(&chunk[..retained]);
            if retained < read {
                overflow.store(true, Ordering::Release);
            }
        }
        Ok(captured)
    })
}

fn join_parser_io_thread<T>(
    handle: thread::JoinHandle<std::io::Result<T>>,
    label: &str,
) -> Result<std::io::Result<T>, ToolError> {
    handle.join().map_err(|_| {
        ToolError::RecoveryBlocked(format!("Scrapling parser {label} thread panicked"))
    })
}

fn terminate_and_reap_parser_child(child: &mut Child) -> Result<(), ToolError> {
    let kill_error = match child.kill() {
        Ok(()) => None,
        Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => None,
        Err(error) => Some(error),
    };
    let wait_result = child.wait();
    if let Some(error) = kill_error {
        return Err(ToolError::RecoveryBlocked(format!(
            "failed to kill Scrapling parser child before cleanup: {error}"
        )));
    }
    wait_result.map_err(|error| {
        ToolError::RecoveryBlocked(format!(
            "failed to reap Scrapling parser child after cleanup: {error}"
        ))
    })?;
    Ok(())
}

impl WebHtmlParser for ScraplingStaticParser {
    fn parse(&self, html: &[u8], timeout_ms: u64) -> Result<WebParsedDocumentV1, ToolError> {
        if !self.python_path.is_absolute() || !fs::metadata(&self.python_path)?.is_file() {
            return Err(ToolError::Authority(
                "Scrapling static parser requires an absolute Python executable path".to_owned(),
            ));
        }
        // Do not canonicalize a virtualenv's interpreter symlink: invoking that symlink path is
        // what makes Python select the virtualenv prefix and its already-installed site-packages.
        let python = self.python_path.clone();
        let worker = self.worker_path.canonicalize()?;
        let vendor = self.vendored_scrapling_root.canonicalize()?;
        if !python.is_file() || !worker.is_file() || !vendor.is_dir() {
            return Err(ToolError::Authority(
                "Scrapling static parser paths are not stable files/directories".to_owned(),
            ));
        }
        let stdout = self.run_worker(html, timeout_ms, &python, &worker, &vendor)?;
        let value: serde_json::Value = serde_json::from_slice(&stdout).map_err(|error| {
            ToolError::Authority(format!("invalid Scrapling parser JSON: {error}"))
        })?;
        if value
            .get("fetcher_or_browser_modules_loaded")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true)
        {
            return Err(ToolError::Authority(
                "Scrapling static parser loaded forbidden fetcher/browser extras".to_owned(),
            ));
        }
        let parser_version = value
            .get("parser_version")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| ToolError::Authority("Scrapling parser omitted version".to_owned()))?
            .to_owned();
        let text = value
            .get("text")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| ToolError::Authority("Scrapling parser omitted text".to_owned()))?
            .to_owned();
        let title = value
            .get("title")
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned);
        let links = value
            .get("links")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| ToolError::Authority("Scrapling parser omitted links".to_owned()))?
            .iter()
            .map(|item| {
                item.as_str().map(ToOwned::to_owned).ok_or_else(|| {
                    ToolError::Authority("Scrapling parser returned non-string link".to_owned())
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(WebParsedDocumentV1 {
            parser_name: "scrapling.parser.Selector".to_owned(),
            parser_version,
            title,
            text,
            links,
        })
    }
}

#[derive(Debug, Clone)]
struct ParsedWebUrl {
    canonical_url: String,
    scheme: String,
    authority: String,
    path_and_query: String,
    destination: NetworkDestination,
}

impl ParsedWebUrl {
    fn parse(url: &str) -> Result<Self, ToolError> {
        if url
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
        {
            return Err(ToolError::Authority(
                "web URL contains whitespace/control bytes".to_owned(),
            ));
        }
        let without_fragment = url.split('#').next().unwrap_or(url);
        let (scheme, rest) = without_fragment.split_once("://").ok_or_else(|| {
            ToolError::Authority("web URL must be absolute http/https".to_owned())
        })?;
        let scheme = scheme.to_ascii_lowercase();
        if !matches!(scheme.as_str(), "http" | "https") {
            return Err(ToolError::Authority(
                "web acquisition permits only http/https schemes".to_owned(),
            ));
        }
        let split_at = rest.find(['/', '?']).unwrap_or(rest.len());
        let authority = &rest[..split_at];
        if authority.is_empty() || authority.contains('@') {
            return Err(ToolError::Authority(
                "web URL requires host and forbids userinfo".to_owned(),
            ));
        }
        let tail = &rest[split_at..];
        let path_and_query = if tail.is_empty() {
            "/".to_owned()
        } else if tail.starts_with('?') {
            format!("/{tail}")
        } else {
            tail.to_owned()
        };
        let default_port = if scheme == "https" { 443 } else { 80 };
        let (host, port) = parse_web_authority(authority, default_port)?;
        let host = if host.starts_with('[') {
            host.to_ascii_lowercase()
        } else {
            host.trim_end_matches('.').to_ascii_lowercase()
        };
        let authority = canonical_authority(&host, port, default_port);
        let canonical_url = format!("{scheme}://{authority}{path_and_query}");
        Ok(Self {
            canonical_url,
            scheme: scheme.clone(),
            authority,
            path_and_query,
            destination: NetworkDestination { scheme, host, port },
        })
    }

    fn with_destination(mut self, destination: NetworkDestination) -> Self {
        let default_port = if destination.scheme == "https" {
            443
        } else {
            80
        };
        self.scheme.clone_from(&destination.scheme);
        self.authority = canonical_authority(&destination.host, destination.port, default_port);
        self.canonical_url = format!(
            "{}://{}{}",
            destination.scheme, self.authority, self.path_and_query
        );
        self.destination = destination;
        self
    }
}

fn parse_web_authority(authority: &str, default_port: u16) -> Result<(String, u16), ToolError> {
    if let Some(rest) = authority.strip_prefix('[') {
        let close = rest.find(']').ok_or_else(|| {
            ToolError::Authority("invalid bracketed IPv6 web authority".to_owned())
        })?;
        let host = format!("[{}]", &rest[..close]);
        let suffix = &rest[close + 1..];
        let port = if suffix.is_empty() {
            default_port
        } else {
            suffix
                .strip_prefix(':')
                .ok_or_else(|| ToolError::Authority("invalid IPv6 web port".to_owned()))?
                .parse::<u16>()
                .map_err(|_| ToolError::Authority("invalid web port".to_owned()))?
        };
        if port == 0 {
            return Err(ToolError::Authority("invalid web port".to_owned()));
        }
        return Ok((host, port));
    }
    if authority.matches(':').count() > 1 {
        return Err(ToolError::Authority(
            "IPv6 web hosts must use bracket notation".to_owned(),
        ));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port))
            if !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            let port = port
                .parse::<u16>()
                .map_err(|_| ToolError::Authority("invalid web port".to_owned()))?;
            (host, port)
        }
        _ => (authority, default_port),
    };
    if host.is_empty() || port == 0 {
        return Err(ToolError::Authority(
            "invalid web host/port authority".to_owned(),
        ));
    }
    Ok((host.to_owned(), port))
}

fn canonical_authority(host: &str, port: u16, default_port: u16) -> String {
    if port == default_port {
        host.to_owned()
    } else {
        format!("{host}:{port}")
    }
}

fn resolve_redirect_url(base: &ParsedWebUrl, location: &str) -> Result<String, ToolError> {
    if location
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        return Err(ToolError::Authority(
            "redirect location contains whitespace/control bytes".to_owned(),
        ));
    }
    if location.starts_with("http://") || location.starts_with("https://") {
        return Ok(location.to_owned());
    }
    if let Some(rest) = location.strip_prefix("//") {
        return Ok(format!("{}://{rest}", base.scheme));
    }
    if location.starts_with('/') {
        return Ok(format!("{}://{}{}", base.scheme, base.authority, location));
    }
    if location.starts_with('?') {
        let path = base.path_and_query.split('?').next().unwrap_or("/");
        return Ok(format!(
            "{}://{}{}{}",
            base.scheme, base.authority, path, location
        ));
    }
    let path = base.path_and_query.split('?').next().unwrap_or("/");
    let directory = path.rsplit_once('/').map_or(
        "/",
        |(prefix, _)| {
            if prefix.is_empty() { "/" } else { prefix }
        },
    );
    let separator = if directory.ends_with('/') { "" } else { "/" };
    Ok(format!(
        "{}://{}{}{}{}",
        base.scheme, base.authority, directory, separator, location
    ))
}

fn is_redirect_status(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

fn raw_web_response_evidence(
    url: &str,
    status_code: u16,
    connected_peer: IpAddr,
    raw_headers: &[u8],
    body: &[u8],
) -> WebRawResponseEvidenceV1 {
    let mut headers_hasher = Sha256::new();
    headers_hasher.update(raw_headers);
    let mut body_hasher = Sha256::new();
    body_hasher.update(body);
    WebRawResponseEvidenceV1 {
        url: url.to_owned(),
        status_code,
        connected_peer,
        headers_sha256: format!("sha256:{:x}", headers_hasher.finalize()),
        body_sha256: format!("sha256:{:x}", body_hasher.finalize()),
        body_bytes: body.len(),
    }
}

fn parse_http_headers(raw: &[u8]) -> Result<BTreeMap<String, String>, ToolError> {
    if raw.len() > 256 * 1024 {
        return Err(ToolError::ResourceLimit(
            "HTTP response headers exceeded bound".to_owned(),
        ));
    }
    let text = std::str::from_utf8(raw)
        .map_err(|_| ToolError::Authority("HTTP response headers are not UTF-8".to_owned()))?;
    let block = text
        .split("\r\n\r\n")
        .filter(|part| part.trim_start().starts_with("HTTP/"))
        .last()
        .ok_or_else(|| ToolError::Authority("HTTP response omitted header block".to_owned()))?;
    let mut headers = BTreeMap::new();
    for line in block.lines().skip(1) {
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            if name.is_empty() {
                continue;
            }
            headers
                .entry(name)
                .and_modify(|existing: &mut String| {
                    existing.push_str(", ");
                    existing.push_str(value.trim());
                })
                .or_insert_with(|| value.trim().to_owned());
        }
    }
    Ok(headers)
}
