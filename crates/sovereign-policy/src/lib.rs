//! Deterministic minimum security and resource policy kernel for Sovereign M1.
//!
//! This crate owns admission policy only. It does not execute tools and it does
//! not grant itself authority from repository/model/tool text.

mod resources;

pub use resources::{
    AdmissionStatus, ConditionalLeaseContextV1, HARDWARE_PROFILE_SCHEMA_VERSION, HardwareProfileV1,
    HeavyLeaseClass, HeavyLeasePairPolicyV1, LeasePairRule, LeaseStateV1,
    M6_RESOURCE_GOVERNOR_SNAPSHOT_SCHEMA_VERSION, M6ResourceGovernor, M6ResourceGovernorSnapshotV1,
    OsMemoryPressure, PlanHeavyLeaseClass, PressureBand, RESOURCE_LEASE_SCHEMA_VERSION,
    RESOURCE_PRESSURE_EVENT_SCHEMA_VERSION, ResourceAdmissionDecisionV1,
    ResourceCapabilityCycleSnapshotV1, ResourceGovernorRestoreError, ResourceLeaseOwnerV1,
    ResourceLeaseRequestV1, ResourceLeaseV1, ResourcePolicyEventV1, ResourcePressureEventV1,
    ResourcePressureSnapshotV1, TaskResourceBudgetV1, ThermalPressure,
};

use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{Display, Formatter, Write as _};
use std::fs;
use std::net::TcpListener;
use std::path::{Component, Path, PathBuf};

pub const CAPABILITY_SET_SCHEMA_VERSION: u32 = 1;
pub const PERMISSION_DECISION_SCHEMA_VERSION: u32 = 1;

/// Canonical Plan IR v1 capability vocabulary.
///
/// Existing `sovereign-tools::PermissionClass` callers keep their Rust variant names through a
/// type alias; the wire names here are the twelve frozen Plan IR permission strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Capability {
    Read,
    SandboxWrite,
    RepositoryWrite,
    ProcessExec,
    PackageInstall,
    NetworkRead,
    NetworkWrite,
    BrowserInteractive,
    SecretUse,
    ExternalSideEffect,
    ExternalIntelligence,
    Destructive,
}

impl Capability {
    pub const ALL: [Self; 12] = [
        Self::Read,
        Self::SandboxWrite,
        Self::RepositoryWrite,
        Self::ProcessExec,
        Self::PackageInstall,
        Self::NetworkRead,
        Self::NetworkWrite,
        Self::BrowserInteractive,
        Self::SecretUse,
        Self::ExternalSideEffect,
        Self::ExternalIntelligence,
        Self::Destructive,
    ];

    #[must_use]
    pub const fn as_plan_ir_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::SandboxWrite => "sandbox_write",
            Self::RepositoryWrite => "repo_write",
            Self::ProcessExec => "process_exec",
            Self::PackageInstall => "package_install",
            Self::NetworkRead => "network_read",
            Self::NetworkWrite => "network_write",
            Self::BrowserInteractive => "browser_interactive",
            Self::SecretUse => "secret_use",
            Self::ExternalSideEffect => "external_side_effect",
            Self::ExternalIntelligence => "external_intelligence",
            Self::Destructive => "destructive",
        }
    }

    #[must_use]
    pub fn from_plan_ir_str(value: &str) -> Option<Self> {
        match value {
            "read" => Some(Self::Read),
            "sandbox_write" => Some(Self::SandboxWrite),
            "repo_write" => Some(Self::RepositoryWrite),
            "process_exec" => Some(Self::ProcessExec),
            "package_install" => Some(Self::PackageInstall),
            "network_read" => Some(Self::NetworkRead),
            "network_write" => Some(Self::NetworkWrite),
            "browser_interactive" => Some(Self::BrowserInteractive),
            "secret_use" => Some(Self::SecretUse),
            "external_side_effect" => Some(Self::ExternalSideEffect),
            "external_intelligence" => Some(Self::ExternalIntelligence),
            "destructive" => Some(Self::Destructive),
            _ => None,
        }
    }
}

/// Deterministic capability set used at every permission-intersection layer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CapabilitySet {
    capabilities: BTreeSet<Capability>,
}

impl CapabilitySet {
    #[must_use]
    pub fn new(capabilities: impl IntoIterator<Item = Capability>) -> Self {
        Self {
            capabilities: capabilities.into_iter().collect(),
        }
    }

    #[must_use]
    pub fn all() -> Self {
        Self::new(Capability::ALL)
    }

    #[must_use]
    pub fn contains(&self, capability: Capability) -> bool {
        self.capabilities.contains(&capability)
    }

    #[must_use]
    pub fn is_subset_of(&self, ceiling: &Self) -> bool {
        self.capabilities.is_subset(&ceiling.capabilities)
    }

    #[must_use]
    pub fn intersection(&self, other: &Self) -> Self {
        Self::new(self.capabilities.intersection(&other.capabilities).copied())
    }

    pub fn iter(&self) -> impl Iterator<Item = Capability> + '_ {
        self.capabilities.iter().copied()
    }

    #[must_use]
    pub fn digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(CAPABILITY_SET_SCHEMA_VERSION.to_be_bytes());
        for capability in &self.capabilities {
            digest_policy_field(&mut hasher, capability.as_plan_ir_str());
        }
        format!("sha256:{:x}", hasher.finalize())
    }
}

impl From<BTreeSet<Capability>> for CapabilitySet {
    fn from(value: BTreeSet<Capability>) -> Self {
        Self {
            capabilities: value,
        }
    }
}

impl From<CapabilitySet> for BTreeSet<Capability> {
    fn from(value: CapabilitySet) -> Self {
        value.capabilities
    }
}

/// Explicit capability grant bound to one exact Plan revision and task contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskCapabilityGrant {
    pub plan_id: String,
    pub plan_revision: u32,
    pub task_id: String,
    pub task_contract_digest: String,
    pub policy_digest: String,
    pub issued_by: String,
    pub capabilities: CapabilitySet,
}

impl TaskCapabilityGrant {
    /// Returns the grant only for its exact task scope. Sibling tasks and stale contracts fail
    /// closed instead of receiving an empty or partially matching grant.
    ///
    /// # Errors
    /// Returns a policy denial when any scope component differs or the grant is malformed.
    pub fn capabilities_for_scope(
        &self,
        plan_id: &str,
        plan_revision: u32,
        task_id: &str,
        task_contract_digest: &str,
        policy_digest: &str,
    ) -> Result<&CapabilitySet, PolicyError> {
        self.validate()?;
        if self.plan_id != plan_id
            || self.plan_revision != plan_revision
            || self.task_id != task_id
            || self.task_contract_digest != task_contract_digest
            || self.policy_digest != policy_digest
        {
            return Err(PolicyError::Denied(
                "task capability grant scope does not match exact task contract/policy".to_owned(),
            ));
        }
        Ok(&self.capabilities)
    }

    /// # Errors
    /// Returns a policy denial for incomplete exact scope fields.
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.plan_id.trim().is_empty()
            || self.task_id.trim().is_empty()
            || !is_sha256_binding(&self.task_contract_digest)
            || !is_sha256_binding(&self.policy_digest)
            || self.issued_by.trim().is_empty()
        {
            return Err(PolicyError::Denied(
                "task capability grant requires exact plan/task/contract/policy scope and issuer"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

/// The six deterministic capability ceilings whose intersection is effective authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityLayers {
    pub global: CapabilitySet,
    pub project: CapabilitySet,
    pub task: CapabilitySet,
    pub role: CapabilitySet,
    pub tool: CapabilitySet,
    pub user: CapabilitySet,
}

impl CapabilityLayers {
    #[must_use]
    pub fn effective(&self) -> CapabilitySet {
        self.global
            .intersection(&self.project)
            .intersection(&self.task)
            .intersection(&self.role)
            .intersection(&self.tool)
            .intersection(&self.user)
    }
}

/// Frozen permission decision bound to an exact task contract, policy, and tool identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionDecision {
    pub plan_id: String,
    pub plan_revision: u32,
    pub task_id: String,
    pub task_contract_digest: String,
    pub policy_digest: String,
    pub tool_id: String,
    pub tool_version: String,
    pub tool_digest: String,
    pub layers: CapabilityLayers,
    pub effective: CapabilitySet,
}

impl PermissionDecision {
    /// Constructs a deterministic v1 decision from the six frozen authority layers.
    ///
    /// # Errors
    /// Returns a policy denial when any exact identity binding is incomplete.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        plan_id: impl Into<String>,
        plan_revision: u32,
        task_id: impl Into<String>,
        task_contract_digest: impl Into<String>,
        policy_digest: impl Into<String>,
        tool_id: impl Into<String>,
        tool_version: impl Into<String>,
        tool_digest: impl Into<String>,
        layers: CapabilityLayers,
    ) -> Result<Self, PolicyError> {
        let decision = Self {
            plan_id: plan_id.into(),
            plan_revision,
            task_id: task_id.into(),
            task_contract_digest: task_contract_digest.into(),
            policy_digest: policy_digest.into(),
            tool_id: tool_id.into(),
            tool_version: tool_version.into(),
            tool_digest: tool_digest.into(),
            effective: layers.effective(),
            layers,
        };
        decision.validate()?;
        Ok(decision)
    }

    /// Revalidates exact bindings and proves the stored effective set is the layer intersection.
    ///
    /// # Errors
    /// Returns a policy denial for malformed bindings or a mutated/inconsistent effective set.
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.plan_id.trim().is_empty()
            || self.task_id.trim().is_empty()
            || self.tool_id.trim().is_empty()
            || self.tool_version.trim().is_empty()
            || !is_sha256_binding(&self.task_contract_digest)
            || !is_sha256_binding(&self.policy_digest)
            || !is_sha256_binding(&self.tool_digest)
        {
            return Err(PolicyError::Denied(
                "permission decision has incomplete exact-binding fields".to_owned(),
            ));
        }
        if self.effective != self.layers.effective() {
            return Err(PolicyError::Denied(
                "permission decision effective capabilities do not match layer intersection"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(PERMISSION_DECISION_SCHEMA_VERSION.to_be_bytes());
        digest_policy_field(&mut hasher, &self.plan_id);
        hasher.update(self.plan_revision.to_be_bytes());
        digest_policy_field(&mut hasher, &self.task_id);
        digest_policy_field(&mut hasher, &self.task_contract_digest);
        digest_policy_field(&mut hasher, &self.policy_digest);
        digest_policy_field(&mut hasher, &self.tool_id);
        digest_policy_field(&mut hasher, &self.tool_version);
        digest_policy_field(&mut hasher, &self.tool_digest);
        for layer in [
            &self.layers.global,
            &self.layers.project,
            &self.layers.task,
            &self.layers.role,
            &self.layers.tool,
            &self.layers.user,
            &self.effective,
        ] {
            digest_policy_field(&mut hasher, &layer.digest());
        }
        format!("sha256:{:x}", hasher.finalize())
    }

    #[must_use]
    pub fn matches_task_scope(
        &self,
        plan_id: &str,
        plan_revision: u32,
        task_id: &str,
        task_contract_digest: &str,
    ) -> bool {
        self.plan_id == plan_id
            && self.plan_revision == plan_revision
            && self.task_id == task_id
            && self.task_contract_digest == task_contract_digest
    }

    #[must_use]
    pub fn matches_tool(&self, tool_id: &str, tool_version: &str, tool_digest: &str) -> bool {
        self.tool_id == tool_id
            && self.tool_version == tool_version
            && self.tool_digest == tool_digest
    }
}

fn is_sha256_binding(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

#[derive(Debug)]
pub enum PolicyError {
    Io(std::io::Error),
    Denied(String),
    IsolationUnavailable(String),
    ResourceDenied(String),
}

impl Display for PolicyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "policy I/O error: {error}"),
            Self::Denied(message) => write!(f, "policy denied: {message}"),
            Self::IsolationUnavailable(message) => write!(f, "isolation unavailable: {message}"),
            Self::ResourceDenied(message) => write!(f, "resource denied: {message}"),
        }
    }
}

impl Error for PolicyError {}

impl From<std::io::Error> for PolicyError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CommandRisk {
    ReadOnly,
    RepositoryMutation,
    UntrustedCode,
    PackageInstall,
    Destructive,
    Shell,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandMode {
    Direct,
    Shell,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSpec {
    pub executable: PathBuf,
    pub args: Vec<String>,
    pub working_directory: PathBuf,
    pub environment: BTreeMap<String, String>,
    pub mode: CommandMode,
    pub declared_risk: CommandRisk,
    pub timeout_ms: u64,
    pub output_limit_bytes: u64,
    pub disk_write_limit_bytes: u64,
    pub subprocess_limit: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedExecutable {
    pub path: PathBuf,
    pub sha256: String,
    pub version: String,
}

impl PinnedExecutable {
    /// Creates a digest-pinned executable record from an existing file.
    ///
    /// # Errors
    /// Returns an I/O error when the executable cannot be canonicalized or read.
    pub fn from_path(
        path: impl AsRef<Path>,
        version: impl Into<String>,
    ) -> Result<Self, PolicyError> {
        let path = path.as_ref().canonicalize()?;
        let bytes = fs::read(&path)?;
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Ok(Self {
            path,
            sha256: format!("sha256:{:x}", hasher.finalize()),
            version: version.into(),
        })
    }

    /// Re-hashes the pinned executable and validates its non-empty version label.
    ///
    /// # Errors
    /// Returns a policy error when the executable changed or provenance is incomplete.
    pub fn verify(&self) -> Result<(), PolicyError> {
        let actual = Self::from_path(&self.path, self.version.clone())?;
        if actual.sha256 != self.sha256 {
            return Err(PolicyError::Denied(format!(
                "executable digest mismatch for {}",
                self.path.display()
            )));
        }
        if self.version.trim().is_empty() {
            return Err(PolicyError::Denied(
                "pinned executable version is empty".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct PathPolicy {
    repository_root: PathBuf,
    protected_roots: Vec<PathBuf>,
}

impl PathPolicy {
    /// Builds a canonical repository jail and protected-root set.
    ///
    /// # Errors
    /// Returns an I/O or policy error for unresolved roots.
    pub fn new(
        repository_root: impl AsRef<Path>,
        protected_roots: impl IntoIterator<Item = PathBuf>,
    ) -> Result<Self, PolicyError> {
        let repository_root = repository_root.as_ref().canonicalize()?;
        let protected_roots = protected_roots
            .into_iter()
            .map(|root| canonicalize_existing_or_parent(&root))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            repository_root,
            protected_roots,
        })
    }

    #[must_use]
    pub fn repository_root(&self) -> &Path {
        &self.repository_root
    }

    /// Resolves and authorizes an existing repository-relative path.
    ///
    /// # Errors
    /// Returns a policy error for traversal, symlink escape, or protected roots.
    pub fn authorize_existing(&self, relative: impl AsRef<Path>) -> Result<PathBuf, PolicyError> {
        validate_relative(relative.as_ref())?;
        let candidate = self
            .repository_root
            .join(relative.as_ref())
            .canonicalize()?;
        self.authorize_canonical(&candidate)?;
        Ok(candidate)
    }

    /// Resolves an authorized parent for a not-yet-existing repository path.
    ///
    /// # Errors
    /// Returns a policy error for traversal, symlink escape, or protected roots.
    pub fn authorize_create(&self, relative: impl AsRef<Path>) -> Result<PathBuf, PolicyError> {
        let relative = relative.as_ref();
        validate_relative(relative)?;
        let candidate = self.repository_root.join(relative);
        let parent = candidate.parent().ok_or_else(|| {
            PolicyError::Denied("create path has no authorized parent".to_owned())
        })?;
        let canonical_parent = parent.canonicalize()?;
        self.authorize_canonical(&canonical_parent)?;
        let file_name = candidate
            .file_name()
            .ok_or_else(|| PolicyError::Denied("create path has no final component".to_owned()))?;
        Ok(canonical_parent.join(file_name))
    }

    fn authorize_canonical(&self, candidate: &Path) -> Result<(), PolicyError> {
        if !candidate.starts_with(&self.repository_root) {
            return Err(PolicyError::Denied(format!(
                "path escapes repository root: {}",
                candidate.display()
            )));
        }
        if self
            .protected_roots
            .iter()
            .any(|protected| candidate.starts_with(protected))
        {
            return Err(PolicyError::Denied(format!(
                "path intersects protected root: {}",
                candidate.display()
            )));
        }
        Ok(())
    }
}

fn validate_relative(path: &Path) -> Result<(), PolicyError> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err(PolicyError::Denied(
            "path must be a non-empty repository-relative selector".to_owned(),
        ));
    }
    if path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err(PolicyError::Denied(
            "path traversal is forbidden".to_owned(),
        ));
    }
    Ok(())
}

fn canonicalize_existing_or_parent(path: &Path) -> Result<PathBuf, PolicyError> {
    if path.exists() {
        return Ok(path.canonicalize()?);
    }
    let Some(parent) = path.parent() else {
        return Err(PolicyError::Denied(format!(
            "protected root has no parent: {}",
            path.display()
        )));
    };
    Ok(parent.canonicalize()?.join(
        path.file_name().ok_or_else(|| {
            PolicyError::Denied("protected root has no final component".to_owned())
        })?,
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkDestination {
    pub scheme: String,
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Default)]
pub struct MinimalNetworkPolicy {
    allowed: BTreeSet<(String, String, u16)>,
}

impl MinimalNetworkPolicy {
    #[must_use]
    pub fn offline() -> Self {
        Self::default()
    }

    /// Adds one exact normalized network destination to the task allowlist.
    ///
    /// # Errors
    /// Returns a policy error when the destination is not already normalized safely.
    pub fn allow(&mut self, scheme: &str, host: &str, port: u16) -> Result<(), PolicyError> {
        self.allowed
            .insert(normalize_destination(scheme, host, port)?);
        Ok(())
    }

    /// Checks one network destination against the exact task allowlist.
    ///
    /// # Errors
    /// Returns a policy denial when the destination is absent or malformed.
    pub fn authorize(&self, destination: &NetworkDestination) -> Result<(), PolicyError> {
        let key = normalize_destination(&destination.scheme, &destination.host, destination.port)?;
        if self.allowed.contains(&key) {
            Ok(())
        } else {
            Err(PolicyError::Denied(format!(
                "network destination not task-authorized: {}://{}:{}",
                destination.scheme, destination.host, destination.port
            )))
        }
    }

    #[must_use]
    pub fn is_offline(&self) -> bool {
        self.allowed.is_empty()
    }
}

fn normalize_destination(
    scheme: &str,
    host: &str,
    port: u16,
) -> Result<(String, String, u16), PolicyError> {
    if scheme.is_empty() || host.is_empty() || port == 0 {
        return Err(PolicyError::Denied(
            "invalid network destination".to_owned(),
        ));
    }
    if !scheme
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
    {
        return Err(PolicyError::Denied("invalid network scheme".to_owned()));
    }
    if !host.is_ascii() {
        return Err(PolicyError::Denied(
            "non-ASCII host requires normalized IDNA form before policy".to_owned(),
        ));
    }
    Ok((
        scheme.to_ascii_lowercase(),
        host.trim_end_matches('.').to_ascii_lowercase(),
        port,
    ))
}

#[derive(Debug, Clone)]
pub struct CommandPolicy {
    pinned: BTreeMap<PathBuf, PinnedExecutable>,
    toolchain_roots: Vec<PathBuf>,
    pub allow_shell: bool,
    pub allow_package_install: bool,
    pub allow_destructive: bool,
}

impl CommandPolicy {
    /// Creates a deterministic command policy from pinned tools and toolchain roots.
    ///
    /// # Errors
    /// Returns a policy error for invalid pins or roots.
    pub fn new(
        pinned: impl IntoIterator<Item = PinnedExecutable>,
        toolchain_roots: impl IntoIterator<Item = PathBuf>,
    ) -> Result<Self, PolicyError> {
        let mut pinned_map = BTreeMap::new();
        for executable in pinned {
            executable.verify()?;
            pinned_map.insert(executable.path.clone(), executable);
        }
        let toolchain_roots = toolchain_roots
            .into_iter()
            .map(|path| path.canonicalize().map_err(PolicyError::from))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            pinned: pinned_map,
            toolchain_roots,
            allow_shell: false,
            allow_package_install: false,
            allow_destructive: false,
        })
    }

    /// Validates an exact structured command and returns its deterministic risk floor.
    ///
    /// # Errors
    /// Returns a denial for unpinned executables or unauthorized risk classes.
    pub fn authorize(&self, spec: &CommandSpec) -> Result<CommandRisk, PolicyError> {
        if spec.timeout_ms == 0 || spec.output_limit_bytes == 0 || spec.disk_write_limit_bytes == 0
        {
            return Err(PolicyError::Denied(
                "command resource ceilings must be positive".to_owned(),
            ));
        }
        let executable = spec.executable.canonicalize()?;
        let Some(pin) = self.pinned.get(&executable) else {
            return Err(PolicyError::Denied(format!(
                "executable is not digest/version pinned: {}",
                executable.display()
            )));
        };
        pin.verify()?;
        if !self
            .toolchain_roots
            .iter()
            .any(|root| executable.starts_with(root))
        {
            return Err(PolicyError::Denied(format!(
                "executable is outside approved toolchain roots: {}",
                executable.display()
            )));
        }
        let risk = deterministic_risk_floor(spec, &spec.executable);
        if risk == CommandRisk::Shell && !self.allow_shell {
            return Err(PolicyError::Denied(
                "shell execution is not authorized".to_owned(),
            ));
        }
        if risk == CommandRisk::PackageInstall && !self.allow_package_install {
            return Err(PolicyError::Denied(
                "package installation is not authorized".to_owned(),
            ));
        }
        if risk == CommandRisk::Destructive && !self.allow_destructive {
            return Err(PolicyError::Denied(
                "destructive command is not authorized".to_owned(),
            ));
        }
        if spec.mode == CommandMode::Shell && !self.allow_shell {
            return Err(PolicyError::Denied(
                "shell mode is not authorized".to_owned(),
            ));
        }
        Ok(risk.max(spec.declared_risk))
    }

    #[must_use]
    pub fn approved_path(&self) -> String {
        self.toolchain_roots
            .iter()
            .map(|root| root.display().to_string())
            .collect::<Vec<_>>()
            .join(":")
    }

    /// Returns the verified pin for one exact executable path.
    ///
    /// # Errors
    /// Returns a denial when the executable is not pinned or its digest changed.
    pub fn pinned_executable(&self, path: &Path) -> Result<&PinnedExecutable, PolicyError> {
        let canonical = path.canonicalize()?;
        let pin = self.pinned.get(&canonical).ok_or_else(|| {
            PolicyError::Denied(format!(
                "executable is not digest/version pinned: {}",
                canonical.display()
            ))
        })?;
        pin.verify()?;
        Ok(pin)
    }
}

fn deterministic_risk_floor(spec: &CommandSpec, executable: &Path) -> CommandRisk {
    let name = executable
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    if spec.mode == CommandMode::Shell || matches!(name, "sh" | "bash" | "zsh" | "fish") {
        return CommandRisk::Shell;
    }
    if is_destructive(name, &spec.args) {
        return CommandRisk::Destructive;
    }
    if is_package_install(name, &spec.args) {
        return CommandRisk::PackageInstall;
    }
    spec.declared_risk
}

fn is_package_install(name: &str, args: &[String]) -> bool {
    match name {
        "npm" | "pnpm" | "yarn" | "pip" | "pip3" | "uv" | "cargo" | "gem" | "brew" => args
            .first()
            .is_some_and(|arg| matches!(arg.as_str(), "install" | "add" | "update")),
        _ => false,
    }
}

fn is_destructive(name: &str, args: &[String]) -> bool {
    if name == "rm"
        && args
            .iter()
            .any(|arg| arg.contains('r') || arg.contains('f'))
    {
        return true;
    }
    if name != "git" {
        return false;
    }
    let joined = args.join(" ");
    joined.contains("reset --hard")
        || joined.contains("clean -fd")
        || joined.contains("clean -df")
        || joined.contains("push --force")
        || joined.contains("push -f")
}

const AMBIENT_DENY_NAMES: &[&str] = &[
    "PATH",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "GIT_CONFIG",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "SSH_AUTH_SOCK",
    "LD_PRELOAD",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "EDITOR",
    "VISUAL",
    "PAGER",
    "GIT_PAGER",
    "NPM_TOKEN",
    "NODE_AUTH_TOKEN",
    "PIP_INDEX_URL",
    "TWINE_PASSWORD",
    "CARGO_REGISTRIES_CRATES_IO_TOKEN",
];

/// Constructs a cleared child environment from explicitly requested entries only.
///
/// # Errors
/// Returns a denial for dangerous ambient-capability variables unless individually authorized.
pub fn sanitized_environment(
    requested: &BTreeMap<String, String>,
    individually_authorized: &BTreeSet<String>,
) -> Result<BTreeMap<String, String>, PolicyError> {
    let mut result = BTreeMap::new();
    for (name, value) in requested {
        if name.contains('=') || name.as_bytes().contains(&0) || value.as_bytes().contains(&0) {
            return Err(PolicyError::Denied("invalid environment entry".to_owned()));
        }
        let upper = name.to_ascii_uppercase();
        if upper == "PATH" {
            return Err(PolicyError::Denied(
                "action-supplied PATH is forbidden; Controller constructs toolchain PATH"
                    .to_owned(),
            ));
        }
        let forbidden = AMBIENT_DENY_NAMES.iter().any(|entry| upper == *entry)
            || upper.ends_with("_TOKEN")
            || upper.ends_with("_PASSWORD")
            || upper.ends_with("_SECRET")
            || upper.starts_with("AWS_")
            || upper.starts_with("GOOGLE_APPLICATION_");
        if forbidden && !individually_authorized.contains(name) {
            return Err(PolicyError::Denied(format!(
                "ambient-capability environment variable requires individual authorization: {name}"
            )));
        }
        result.insert(name.clone(), value.clone());
    }
    Ok(result)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IsolationCapability {
    NetworkDeny,
    ProtectedHomeReadDeny,
    RepositoryWriteJail,
    FullFilesystemReadJail,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationCapabilities {
    supported: BTreeSet<IsolationCapability>,
}

impl IsolationCapabilities {
    #[must_use]
    pub fn supports(&self, capability: IsolationCapability) -> bool {
        self.supported.contains(&capability)
    }
}

#[derive(Debug, Clone)]
pub struct IsolationRequest {
    pub repository_root: PathBuf,
    pub user_home_root: PathBuf,
    pub extra_protected_read_roots: Vec<PathBuf>,
    pub network_offline: bool,
    pub allow_repository_write: bool,
    pub require_full_filesystem_read_jail: bool,
}

impl IsolationRequest {
    /// Computes a canonical digest of the exact enforceable isolation request.
    ///
    /// # Errors
    /// Returns an I/O/policy error when roots cannot be canonicalized.
    pub fn digest(&self) -> Result<String, PolicyError> {
        let repo = self.repository_root.canonicalize()?;
        let home = self.user_home_root.canonicalize()?;
        let mut protected = self
            .extra_protected_read_roots
            .iter()
            .map(|root| canonicalize_existing_or_parent(root))
            .collect::<Result<Vec<_>, _>>()?;
        protected.sort();
        let mut hasher = Sha256::new();
        digest_policy_field(&mut hasher, &repo.display().to_string());
        digest_policy_field(&mut hasher, &home.display().to_string());
        for root in protected {
            digest_policy_field(&mut hasher, &root.display().to_string());
        }
        hasher.update([u8::from(self.network_offline)]);
        hasher.update([u8::from(self.allow_repository_write)]);
        hasher.update([u8::from(self.require_full_filesystem_read_jail)]);
        Ok(format!("sha256:{:x}", hasher.finalize()))
    }
}

fn digest_policy_field(hasher: &mut Sha256, value: &str) {
    let bytes = value.as_bytes();
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(bytes);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolatedCommand {
    pub executable: PathBuf,
    pub args: Vec<String>,
}

pub trait ExecutionIsolationBackend {
    fn capabilities(&self) -> IsolationCapabilities;
    /// Wraps a structured command in an enforceable local isolation boundary.
    ///
    /// # Errors
    /// Returns fail-closed when the requested boundary is stronger than host capability.
    fn isolate(
        &self,
        spec: &CommandSpec,
        request: &IsolationRequest,
    ) -> Result<IsolatedCommand, PolicyError>;
}

#[derive(Debug, Clone)]
pub struct MacSandboxExecBackend {
    sandbox_exec: PathBuf,
}

impl MacSandboxExecBackend {
    /// Detects the macOS Seatbelt command used by the minimum M1 backend.
    ///
    /// # Errors
    /// Returns fail-closed when `sandbox-exec` is unavailable.
    pub fn detect() -> Result<Self, PolicyError> {
        let path = PathBuf::from("/usr/bin/sandbox-exec");
        if !path.is_file() {
            return Err(PolicyError::IsolationUnavailable(
                "macOS sandbox-exec is unavailable".to_owned(),
            ));
        }
        let backend = Self { sandbox_exec: path };
        backend.self_test()?;
        Ok(backend)
    }

    #[must_use]
    pub fn sandbox_exec_path(&self) -> &Path {
        &self.sandbox_exec
    }

    fn self_test(&self) -> Result<(), PolicyError> {
        let nonce = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|error| PolicyError::IsolationUnavailable(error.to_string()))?
                .as_nanos()
        );
        let root = std::env::temp_dir().join(format!("sovereign-seatbelt-selftest-{nonce}"));
        fs::create_dir_all(&root)?;
        let root = root.canonicalize()?;
        let secret = root.join("secret");
        let writable = root.join("writable");
        fs::create_dir_all(&writable)?;
        fs::write(&secret, b"secret")?;
        let profile = format!(
            "(version 1)(allow default)(deny file-read* (subpath {}))(deny network*)",
            seatbelt_string(&root)
        );
        let denied_read = std::process::Command::new(&self.sandbox_exec)
            .args(["-p", &profile, "/bin/cat"])
            .arg(&secret)
            .env_clear()
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let network_probe = format!(
            "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(0.2); s.connect(('127.0.0.1', {}))",
            address.port()
        );
        let denied_network = std::process::Command::new(&self.sandbox_exec)
            .args(["-p", &profile, "/usr/bin/python3", "-c", &network_probe])
            .env_clear()
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()?;
        let write_profile = format!(
            "(version 1)(allow default)(deny file-write* (subpath \"/\"))(allow file-write* (subpath {}))",
            seatbelt_string(&writable)
        );
        let inside_write = writable.join("inside");
        let outside_write = root.join("outside");
        let allowed_write = std::process::Command::new(&self.sandbox_exec)
            .args(["-p", &write_profile, "/bin/sh", "-c"])
            .arg(format!("printf ok > '{}'", inside_write.display()))
            .env_clear()
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()?;
        let denied_write = std::process::Command::new(&self.sandbox_exec)
            .args(["-p", &write_profile, "/bin/sh", "-c"])
            .arg(format!("printf no > '{}'", outside_write.display()))
            .env_clear()
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()?;
        drop(listener);
        let _ = fs::remove_dir_all(&root);
        if denied_read.success()
            || denied_network.success()
            || !allowed_write.success()
            || denied_write.success()
        {
            return Err(PolicyError::IsolationUnavailable(
                "sandbox-exec runtime self-test did not enforce required read/network denial"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

impl ExecutionIsolationBackend for MacSandboxExecBackend {
    fn capabilities(&self) -> IsolationCapabilities {
        IsolationCapabilities {
            supported: BTreeSet::from([
                IsolationCapability::NetworkDeny,
                IsolationCapability::ProtectedHomeReadDeny,
                IsolationCapability::RepositoryWriteJail,
            ]),
        }
    }

    fn isolate(
        &self,
        spec: &CommandSpec,
        request: &IsolationRequest,
    ) -> Result<IsolatedCommand, PolicyError> {
        if request.require_full_filesystem_read_jail {
            return Err(PolicyError::IsolationUnavailable(
                "host Seatbelt profile cannot truthfully prove a complete read namespace jail"
                    .to_owned(),
            ));
        }
        if !request.network_offline {
            return Err(PolicyError::IsolationUnavailable(
                "M1 macOS isolation can prove offline execution only; selective network scopes are unavailable"
                    .to_owned(),
            ));
        }
        let repo = request.repository_root.canonicalize()?;
        let home = request.user_home_root.canonicalize()?;
        if !repo.starts_with(&home) {
            return Err(PolicyError::IsolationUnavailable(
                "M1 Seatbelt profile requires repository under the declared user home so home can be denied then repo re-allowed"
                    .to_owned(),
            ));
        }
        let mut profile = String::from("(version 1)(allow default)");
        write!(
            &mut profile,
            "(deny file-read* (subpath {}))(allow file-read* (subpath {}))",
            seatbelt_string(&home),
            seatbelt_string(&repo)
        )
        .map_err(|_| PolicyError::Denied("failed to build isolation profile".to_owned()))?;
        profile.push_str("(deny file-write* (subpath \"/\"))");
        if request.allow_repository_write {
            write!(
                &mut profile,
                "(allow file-write* (subpath {}))",
                seatbelt_string(&repo)
            )
            .map_err(|_| PolicyError::Denied("failed to build isolation profile".to_owned()))?;
        }
        for root in &request.extra_protected_read_roots {
            let root = canonicalize_existing_or_parent(root)?;
            write!(
                &mut profile,
                "(deny file-read* (subpath {}))",
                seatbelt_string(&root)
            )
            .map_err(|_| PolicyError::Denied("failed to build isolation profile".to_owned()))?;
        }
        profile.push_str("(deny network*)");
        if spec.subprocess_limit == 0 {
            profile.push_str("(deny process-fork)");
        }
        let mut args = vec![
            "-p".to_owned(),
            profile,
            spec.executable.display().to_string(),
        ];
        args.extend(spec.args.clone());
        Ok(IsolatedCommand {
            executable: self.sandbox_exec.clone(),
            args,
        })
    }
}

fn seatbelt_string(path: &Path) -> String {
    let value = path
        .display()
        .to_string()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    format!("\"{value}\"")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostPressureSnapshot {
    pub controlled_working_set_mib: u64,
    pub host_headroom_mib: u64,
    pub swap_out_growth_mib_per_min: u64,
    pub compressor_growth_mib_per_min: u64,
    pub os_pressure_warning: bool,
    pub recent_pressure_event: bool,
    pub thermal_serious: bool,
}

impl HostPressureSnapshot {
    #[must_use]
    pub const fn classify(self) -> PressureBand {
        if self.os_pressure_warning
            || self.thermal_serious
            || self.swap_out_growth_mib_per_min > 256
            || self.compressor_growth_mib_per_min > 256
            || self.controlled_working_set_mib > 5_376
            || self.host_headroom_mib < 1_280
        {
            PressureBand::Constrained
        } else if self.recent_pressure_event
            || self.swap_out_growth_mib_per_min >= 64
            || self.compressor_growth_mib_per_min >= 64
            || self.controlled_working_set_mib >= 4_864
            || self.host_headroom_mib < 1_536
        {
            PressureBand::Guarded
        } else {
            PressureBand::Green
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceLease {
    pub lease_id: String,
    pub class: HeavyLeaseClass,
}

#[derive(Debug, Default)]
pub struct MinimalResourceLeaseAuthority {
    active: BTreeMap<String, HeavyLeaseClass>,
}

impl MinimalResourceLeaseAuthority {
    /// Acquires one heavy-capability lease under the M1 exclusion matrix.
    ///
    /// # Errors
    /// Returns a resource denial when the lease conflicts or duplicates an active lease.
    pub fn acquire(
        &mut self,
        lease_id: impl Into<String>,
        class: HeavyLeaseClass,
    ) -> Result<ResourceLease, PolicyError> {
        let lease_id = lease_id.into();
        if lease_id.is_empty() || self.active.contains_key(&lease_id) {
            return Err(PolicyError::ResourceDenied(
                "lease id is empty or already active".to_owned(),
            ));
        }
        let conflict = self.active.values().any(|active| {
            *active == class
                || matches!(
                    (*active, class),
                    (HeavyLeaseClass::Model, HeavyLeaseClass::BuildHeavy)
                        | (HeavyLeaseClass::BuildHeavy, HeavyLeaseClass::Model)
                )
        });
        if conflict {
            return Err(PolicyError::ResourceDenied(format!(
                "baseline M1 profile forbids overlapping heavy lease {class:?}"
            )));
        }
        self.active.insert(lease_id.clone(), class);
        Ok(ResourceLease { lease_id, class })
    }

    /// Releases one exact active heavy-capability lease.
    ///
    /// # Errors
    /// Returns a resource denial for unknown or mismatched leases.
    pub fn release(&mut self, lease: &ResourceLease) -> Result<(), PolicyError> {
        match self.active.remove(&lease.lease_id) {
            Some(class) if class == lease.class => Ok(()),
            Some(class) => {
                self.active.insert(lease.lease_id.clone(), class);
                Err(PolicyError::ResourceDenied(
                    "lease class mismatch".to_owned(),
                ))
            }
            None => Err(PolicyError::ResourceDenied(
                "lease is not active".to_owned(),
            )),
        }
    }

    #[must_use]
    pub fn active_count(&self) -> usize {
        self.active.len()
    }
}

pub trait ResourceGovernor {
    /// Admits one heavy lease only when both the exclusion matrix and live pressure permit it.
    ///
    /// # Errors
    /// Returns a resource denial when pressure or lease conflicts require serialization/deferral.
    fn acquire(
        &mut self,
        lease_id: String,
        class: HeavyLeaseClass,
        pressure: HostPressureSnapshot,
    ) -> Result<ResourceLease, PolicyError>;

    /// Releases one exact heavy lease.
    ///
    /// # Errors
    /// Returns a resource denial for an unknown or mismatched lease.
    fn release(&mut self, lease: &ResourceLease) -> Result<(), PolicyError>;
}

#[derive(Debug, Default)]
pub struct M1ResourceGovernor {
    leases: MinimalResourceLeaseAuthority,
}

impl ResourceGovernor for M1ResourceGovernor {
    fn acquire(
        &mut self,
        lease_id: String,
        class: HeavyLeaseClass,
        pressure: HostPressureSnapshot,
    ) -> Result<ResourceLease, PolicyError> {
        if pressure.classify() == PressureBand::Constrained {
            return Err(PolicyError::ResourceDenied(
                "live host pressure forbids a new heavy lease".to_owned(),
            ));
        }
        self.leases.acquire(lease_id, class)
    }

    fn release(&mut self, lease: &ResourceLease) -> Result<(), PolicyError> {
        self.leases.release(lease)
    }
}

/// Controller-owned outer budget for model provider calls. Provider code cannot refill it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModelCallBudget {
    remaining_calls: u32,
    max_call_ms: u64,
}

impl ModelCallBudget {
    #[must_use]
    pub const fn new(remaining_calls: u32, max_call_ms: u64) -> Self {
        Self {
            remaining_calls,
            max_call_ms,
        }
    }

    /// Consumes one outer call budget unit before dispatch and validates the deadline.
    ///
    /// # Errors
    /// Returns a resource denial when the outer counter is exhausted or the requested
    /// provider deadline exceeds the Controller ceiling.
    pub fn consume_call(&mut self, requested_deadline_ms: u64) -> Result<(), PolicyError> {
        if self.remaining_calls == 0 {
            return Err(PolicyError::ResourceDenied(
                "model call budget exhausted".to_owned(),
            ));
        }
        if requested_deadline_ms == 0 || requested_deadline_ms > self.max_call_ms {
            return Err(PolicyError::ResourceDenied(format!(
                "model call deadline {requested_deadline_ms} exceeds outer ceiling {}",
                self.max_call_ms
            )));
        }
        self.remaining_calls -= 1;
        Ok(())
    }

    #[must_use]
    pub const fn remaining_calls(self) -> u32 {
        self.remaining_calls
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointIntegrityFloor {
    pub latest_valid_checkpoint_action_sequence: i64,
    pub authoritative_action_sequence: i64,
}

impl CheckpointIntegrityFloor {
    /// Requires the checkpoint floor to bind the exact authoritative journal sequence.
    ///
    /// # Errors
    /// Returns a denial when checkpoint and journal sequences differ.
    pub fn admit_mutation(self) -> Result<(), PolicyError> {
        if self.latest_valid_checkpoint_action_sequence != self.authoritative_action_sequence {
            return Err(PolicyError::Denied(format!(
                "checkpoint/action-journal sequence mismatch: checkpoint={}, journal={}",
                self.latest_valid_checkpoint_action_sequence, self.authoritative_action_sequence
            )));
        }
        Ok(())
    }
}
