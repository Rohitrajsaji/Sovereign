//! Deterministic minimum security and resource policy kernel for Sovereign M1.
//!
//! This crate owns admission policy only. It does not execute tools and it does
//! not grant itself authority from repository/model/tool text.

use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{Display, Formatter, Write as _};
use std::fs;
use std::net::TcpListener;
use std::path::{Component, Path, PathBuf};

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
        if spec.timeout_ms == 0
            || spec.output_limit_bytes == 0
            || spec.disk_write_limit_bytes == 0
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
        fs::write(&secret, b"secret")?;
        let profile = format!(
            "(version 1)(allow default)(deny file-read* (subpath {}))(deny network*)",
            seatbelt_string(&root)
        );
        let denied_read = std::process::Command::new(&self.sandbox_exec)
            .args(["-p", &profile, "/bin/cat"])
            .arg(&secret)
            .env_clear()
            .status()?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let network_probe = format!(
            "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(0.2); s.connect(('127.0.0.1', {}))",
            address.port()
        );
        let denied_network = std::process::Command::new(&self.sandbox_exec)
            .args([
                "-p",
                &profile,
                "/usr/bin/python3",
                "-c",
                &network_probe,
            ])
            .env_clear()
            .status()?;
        drop(listener);
        let _ = fs::remove_dir_all(&root);
        if denied_read.success() || denied_network.success() {
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
            if !root.starts_with(&repo) {
                write!(
                    &mut profile,
                    "(deny file-read* (subpath {}))",
                    seatbelt_string(&root)
                )
                .map_err(|_| PolicyError::Denied("failed to build isolation profile".to_owned()))?;
            }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum HeavyLeaseClass {
    Model,
    BuildHeavy,
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
