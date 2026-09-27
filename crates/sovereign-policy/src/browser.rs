//! Browser-specific policy and macOS isolation primitives.
//!
//! These types deliberately do not modify or weaken the ordinary network or process-isolation
//! policies. Browser loopback is a separate, lease-bound Controller capability scoped to one
//! exact localhost port.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{Display, Formatter, Write as _};
use std::fs;
use std::net::{IpAddr, TcpListener};
use std::path::{Component, Path, PathBuf};
#[cfg(target_os = "macos")]
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(target_os = "macos")]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

pub const BROWSER_LOOPBACK_CAPABILITY_SCHEMA_VERSION: u32 = 1;
pub const TASK_LOOPBACK_GRANT_SCHEMA_VERSION: u32 = 1;
pub const PERSISTENT_BROWSER_PROFILE_GRANT_SCHEMA_VERSION: u32 = 1;
pub const BROWSER_DOWNLOAD_POLICY_SCHEMA_VERSION: u32 = 1;

fn digest_field(hasher: &mut Sha256, value: &str) {
    let bytes = value.as_bytes();
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(bytes);
}

#[derive(Debug)]
pub enum BrowserPolicyError {
    Io(std::io::Error),
    Denied(String),
    IsolationUnavailable(String),
}

impl Display for BrowserPolicyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "browser policy I/O error: {error}"),
            Self::Denied(message) => write!(f, "browser policy denied: {message}"),
            Self::IsolationUnavailable(message) => {
                write!(f, "browser isolation unavailable: {message}")
            }
        }
    }
}

impl Error for BrowserPolicyError {}

impl From<std::io::Error> for BrowserPolicyError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

/// Controller-internal browser IPC authority. The token value itself is never persisted here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserLoopbackCapabilityV1 {
    pub schema_version: u32,
    pub lease_id: String,
    pub execution_epoch: i64,
    pub localhost_port: u16,
    pub token_digest: String,
    pub expires_at_ms: i64,
}

impl BrowserLoopbackCapabilityV1 {
    /// Validates the immutable loopback capability and its current lifetime.
    ///
    /// # Errors
    /// Returns a denial for malformed identity, nonpositive port, stale epoch, invalid digest, or
    /// an expired capability.
    pub fn validate(&self, now_ms: i64) -> Result<(), BrowserPolicyError> {
        if self.schema_version != BROWSER_LOOPBACK_CAPABILITY_SCHEMA_VERSION {
            return Err(BrowserPolicyError::Denied(
                "unsupported browser loopback capability schema".to_owned(),
            ));
        }
        validate_identifier("browser lease", &self.lease_id)?;
        if self.execution_epoch < 0 {
            return Err(BrowserPolicyError::Denied(
                "browser loopback capability has a negative execution epoch".to_owned(),
            ));
        }
        if self.localhost_port == 0 {
            return Err(BrowserPolicyError::Denied(
                "browser loopback capability requires an exact nonzero localhost port".to_owned(),
            ));
        }
        if !is_sha256_binding(&self.token_digest) {
            return Err(BrowserPolicyError::Denied(
                "browser loopback capability requires a sha256 token digest".to_owned(),
            ));
        }
        if self.expires_at_ms <= now_ms {
            return Err(BrowserPolicyError::Denied(
                "browser loopback capability expired".to_owned(),
            ));
        }
        Ok(())
    }

    /// Verifies an in-memory launch token against the persisted digest binding.
    ///
    /// # Errors
    /// Returns a denial when the capability is invalid/expired or the supplied token does not
    /// match its exact SHA-256 binding.
    pub fn verify_token(&self, token: &[u8], now_ms: i64) -> Result<(), BrowserPolicyError> {
        self.validate(now_ms)?;
        let actual = format!("sha256:{:x}", Sha256::digest(token));
        if actual != self.token_digest {
            return Err(BrowserPolicyError::Denied(
                "browser loopback capability token does not match exact launch binding".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Exact Controller grant for one task-owned loopback HTTP(S) destination.
///
/// This is intentionally separate from [`BrowserLoopbackCapabilityV1`], which authorizes only the
/// browser process -> Controller proxy IPC port. A task-loopback grant never changes ordinary
/// [`crate::NetworkPolicy`] semantics and cannot authorize a port other than the exact one carried
/// here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskLoopbackGrantV1 {
    pub schema_version: u32,
    pub plan_id: String,
    pub plan_revision: u32,
    pub task_id: String,
    pub task_contract_digest: String,
    pub resource_lease_id: String,
    pub execution_epoch: i64,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub expires_at_ms: i64,
}

/// Current execution scope presented when consuming one exact task-loopback grant.
#[derive(Debug, Clone, Copy)]
pub struct TaskLoopbackScope<'a> {
    pub plan_id: &'a str,
    pub plan_revision: u32,
    pub task_id: &'a str,
    pub task_contract_digest: &'a str,
    pub resource_lease_id: &'a str,
    pub execution_epoch: i64,
}

impl TaskLoopbackGrantV1 {
    /// Validates immutable task/resource identity, lifetime, and one canonical loopback endpoint.
    ///
    /// # Errors
    /// Returns a denial for malformed identity, stale execution state, non-HTTP(S) schemes,
    /// non-canonical/non-loopback hosts, a wildcard/zero port, or expiry.
    pub fn validate(&self, now_ms: i64) -> Result<(), BrowserPolicyError> {
        if self.schema_version != TASK_LOOPBACK_GRANT_SCHEMA_VERSION {
            return Err(BrowserPolicyError::Denied(
                "unsupported task-loopback grant schema".to_owned(),
            ));
        }
        validate_identifier("plan", &self.plan_id)?;
        validate_identifier("task", &self.task_id)?;
        validate_identifier("browser resource lease", &self.resource_lease_id)?;
        if !is_sha256_binding(&self.task_contract_digest) {
            return Err(BrowserPolicyError::Denied(
                "task-loopback grant requires a sha256 task-contract digest".to_owned(),
            ));
        }
        if self.execution_epoch < 0 {
            return Err(BrowserPolicyError::Denied(
                "task-loopback grant has a negative execution epoch".to_owned(),
            ));
        }
        if !matches!(self.scheme.as_str(), "http" | "https") {
            return Err(BrowserPolicyError::Denied(
                "task-loopback grant requires canonical http or https scheme".to_owned(),
            ));
        }
        if self.port == 0 {
            return Err(BrowserPolicyError::Denied(
                "task-loopback grant requires one exact nonzero port".to_owned(),
            ));
        }
        let canonical_host = canonical_loopback_host(&self.host)?;
        if canonical_host != self.host {
            return Err(BrowserPolicyError::Denied(
                "task-loopback grant host must use canonical loopback literal form".to_owned(),
            ));
        }
        if self.expires_at_ms <= now_ms {
            return Err(BrowserPolicyError::Denied(
                "task-loopback grant expired".to_owned(),
            ));
        }
        Ok(())
    }

    /// Authorizes exactly one loopback destination for the exact current task/resource scope.
    ///
    /// This method never delegates to or mutates ordinary [`crate::NetworkPolicy`].
    ///
    /// # Errors
    /// Returns a denial for stale/mismatched scope or any scheme/host/port different from the grant.
    pub fn authorize(
        &self,
        scope: &TaskLoopbackScope<'_>,
        destination: &crate::NetworkDestination,
        now_ms: i64,
    ) -> Result<(), BrowserPolicyError> {
        self.validate(now_ms)?;
        if self.plan_id != scope.plan_id
            || self.plan_revision != scope.plan_revision
            || self.task_id != scope.task_id
            || self.task_contract_digest != scope.task_contract_digest
            || self.resource_lease_id != scope.resource_lease_id
            || self.execution_epoch != scope.execution_epoch
        {
            return Err(BrowserPolicyError::Denied(
                "task-loopback grant does not match exact current execution scope".to_owned(),
            ));
        }
        let destination_host = canonical_loopback_host(&destination.host)?;
        if destination.scheme != self.scheme
            || destination_host != destination.host
            || destination_host != self.host
            || destination.port != self.port
        {
            return Err(BrowserPolicyError::Denied(
                "task-loopback destination differs from exact granted endpoint".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserProfileMode {
    Isolated,
    Persistent,
}

/// Explicit grant for reusing one persistent browser profile. It grants no network authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistentBrowserProfileGrantV1 {
    pub schema_version: u32,
    pub grant_id: String,
    pub project_id: String,
    pub repository_id: String,
    pub profile_id: String,
    pub allowed_origins: BTreeSet<String>,
    pub policy_digest: String,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
}

impl PersistentBrowserProfileGrantV1 {
    /// Validates grant identity, lifetime, and exact HTTP(S) origin metadata.
    ///
    /// # Errors
    /// Returns a denial for malformed fields, invalid lifetime, non-SHA policy binding, empty
    /// origin scope, or a privileged/non-origin URL.
    pub fn validate(&self, now_ms: i64) -> Result<(), BrowserPolicyError> {
        if self.schema_version != PERSISTENT_BROWSER_PROFILE_GRANT_SCHEMA_VERSION {
            return Err(BrowserPolicyError::Denied(
                "unsupported persistent browser profile grant schema".to_owned(),
            ));
        }
        validate_identifier("profile grant", &self.grant_id)?;
        validate_identifier("project", &self.project_id)?;
        validate_identifier("repository", &self.repository_id)?;
        validate_identifier("browser profile", &self.profile_id)?;
        if !is_sha256_binding(&self.policy_digest) {
            return Err(BrowserPolicyError::Denied(
                "persistent browser profile grant requires a sha256 policy digest".to_owned(),
            ));
        }
        if self.issued_at_ms < 0
            || self.expires_at_ms <= self.issued_at_ms
            || self.expires_at_ms <= now_ms
        {
            return Err(BrowserPolicyError::Denied(
                "persistent browser profile grant has an invalid or expired lifetime".to_owned(),
            ));
        }
        if self.allowed_origins.is_empty() {
            return Err(BrowserPolicyError::Denied(
                "persistent browser profile grant requires an explicit origin scope".to_owned(),
            ));
        }
        for origin in &self.allowed_origins {
            validate_exact_http_origin(origin)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserProfileAuthority {
    Isolated,
    Persistent {
        grant_id: String,
        profile_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserProfilePolicy {
    project_id: String,
    repository_id: String,
    policy_digest: String,
}

impl BrowserProfilePolicy {
    /// Creates a project/repository-scoped profile policy.
    ///
    /// # Errors
    /// Returns a denial for empty or whitespace-padded scope identifiers.
    pub fn new(
        project_id: impl Into<String>,
        repository_id: impl Into<String>,
        policy_digest: impl Into<String>,
    ) -> Result<Self, BrowserPolicyError> {
        let policy = Self {
            project_id: project_id.into(),
            repository_id: repository_id.into(),
            policy_digest: policy_digest.into(),
        };
        validate_identifier("project", &policy.project_id)?;
        validate_identifier("repository", &policy.repository_id)?;
        if !is_sha256_binding(&policy.policy_digest) {
            return Err(BrowserPolicyError::Denied(
                "browser profile policy requires a sha256 policy digest".to_owned(),
            ));
        }
        Ok(policy)
    }

    /// Authorizes isolated mode or validates the exact persisted grant for persistent mode.
    ///
    /// # Errors
    /// Returns a denial when isolated mode carries persistent metadata or persistent mode lacks an
    /// exact current project/repository/profile grant.
    pub fn authorize(
        &self,
        mode: BrowserProfileMode,
        requested_profile_id: Option<&str>,
        grant: Option<&PersistentBrowserProfileGrantV1>,
        now_ms: i64,
    ) -> Result<BrowserProfileAuthority, BrowserPolicyError> {
        match mode {
            BrowserProfileMode::Isolated => {
                if requested_profile_id.is_some() || grant.is_some() {
                    return Err(BrowserPolicyError::Denied(
                        "isolated browser profile mode cannot reuse persistent profile metadata"
                            .to_owned(),
                    ));
                }
                Ok(BrowserProfileAuthority::Isolated)
            }
            BrowserProfileMode::Persistent => {
                let profile_id = requested_profile_id.ok_or_else(|| {
                    BrowserPolicyError::Denied(
                        "persistent browser profile requires an exact profile id".to_owned(),
                    )
                })?;
                validate_identifier("browser profile", profile_id)?;
                let grant = grant.ok_or_else(|| {
                    BrowserPolicyError::Denied(
                        "persistent browser profile requires an explicit grant".to_owned(),
                    )
                })?;
                grant.validate(now_ms)?;
                if grant.project_id != self.project_id
                    || grant.repository_id != self.repository_id
                    || grant.profile_id != profile_id
                    || grant.policy_digest != self.policy_digest
                {
                    return Err(BrowserPolicyError::Denied(
                        "persistent browser profile grant does not match exact scope".to_owned(),
                    ));
                }
                Ok(BrowserProfileAuthority::Persistent {
                    grant_id: grant.grant_id.clone(),
                    profile_id: grant.profile_id.clone(),
                })
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserNavigationScheme {
    Http,
    Https,
}

/// Validates only top-level browser scheme authority. Host/IP authority remains outside this type.
///
/// # Errors
/// Returns a denial for malformed URLs or any privileged/non-HTTP(S) scheme, including `file`,
/// `data`, `chrome`, extension, JavaScript, and custom schemes.
pub fn authorize_top_level_browser_url(
    url: &str,
) -> Result<BrowserNavigationScheme, BrowserPolicyError> {
    if url.trim() != url || url.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(BrowserPolicyError::Denied(
            "browser navigation URL contains whitespace or control characters".to_owned(),
        ));
    }
    let (scheme, remainder) = url.split_once(':').ok_or_else(|| {
        BrowserPolicyError::Denied("browser navigation URL has no scheme".to_owned())
    })?;
    if !remainder.starts_with("//") || remainder.len() <= 2 {
        return Err(BrowserPolicyError::Denied(
            "browser top-level navigation requires an absolute HTTP(S) URL".to_owned(),
        ));
    }
    match scheme.to_ascii_lowercase().as_str() {
        "http" => Ok(BrowserNavigationScheme::Http),
        "https" => Ok(BrowserNavigationScheme::Https),
        _ => Err(BrowserPolicyError::Denied(
            "privileged or custom browser navigation scheme is forbidden".to_owned(),
        )),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserDownloadMode {
    Deny,
    TaskScoped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserDownloadRootAuthorityV1 {
    pub lease_id: String,
    pub execution_epoch: i64,
    pub root: PathBuf,
}

impl BrowserDownloadRootAuthorityV1 {
    /// Validates that the root is an existing non-symlink directory bound to a current lease.
    ///
    /// # Errors
    /// Returns a denial for malformed lease/epoch or an unsafe/non-directory root.
    pub fn validate(&self) -> Result<(), BrowserPolicyError> {
        validate_identifier("browser lease", &self.lease_id)?;
        if self.execution_epoch < 0 {
            return Err(BrowserPolicyError::Denied(
                "browser download authority has a negative execution epoch".to_owned(),
            ));
        }
        validate_existing_directory(&self.root)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserDownloadRetentionPolicyV1 {
    pub max_file_bytes: u64,
    pub allowed_content_types: BTreeSet<String>,
}

impl BrowserDownloadRetentionPolicyV1 {
    /// Validates bounded retention configuration.
    ///
    /// # Errors
    /// Returns a denial when byte limits are zero or content-type selectors are malformed.
    pub fn validate(&self) -> Result<(), BrowserPolicyError> {
        if self.max_file_bytes == 0 {
            return Err(BrowserPolicyError::Denied(
                "browser download retention requires a nonzero byte limit".to_owned(),
            ));
        }
        for content_type in &self.allowed_content_types {
            validate_content_type(content_type)?;
        }
        Ok(())
    }

    /// Authorizes retention metadata without opening or executing the downloaded file.
    ///
    /// # Errors
    /// Returns a denial for credential-bearing content, oversized files, or a content type outside
    /// an explicitly configured allowlist.
    pub fn authorize(
        &self,
        file_bytes: u64,
        content_type: &str,
        credential_bearing: bool,
    ) -> Result<(), BrowserPolicyError> {
        self.validate()?;
        validate_content_type(content_type)?;
        if credential_bearing {
            return Err(BrowserPolicyError::Denied(
                "credential-bearing browser downloads cannot be retained".to_owned(),
            ));
        }
        if file_bytes > self.max_file_bytes {
            return Err(BrowserPolicyError::Denied(
                "browser download exceeds retained byte ceiling".to_owned(),
            ));
        }
        if !self.allowed_content_types.is_empty()
            && !self.allowed_content_types.contains(content_type)
        {
            return Err(BrowserPolicyError::Denied(
                "browser download content type is not retention-authorized".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserDownloadPolicyV1 {
    pub schema_version: u32,
    pub mode: BrowserDownloadMode,
    pub root_authority: Option<BrowserDownloadRootAuthorityV1>,
    pub retention: BrowserDownloadRetentionPolicyV1,
}

impl BrowserDownloadPolicyV1 {
    /// Validates deny/task-scoped root authority and retention ceilings.
    ///
    /// # Errors
    /// Returns a denial when deny mode carries a root or task-scoped mode lacks an exact root.
    pub fn validate(&self) -> Result<(), BrowserPolicyError> {
        if self.schema_version != BROWSER_DOWNLOAD_POLICY_SCHEMA_VERSION {
            return Err(BrowserPolicyError::Denied(
                "unsupported browser download policy schema".to_owned(),
            ));
        }
        self.retention.validate()?;
        match (&self.mode, &self.root_authority) {
            (BrowserDownloadMode::Deny, None) => Ok(()),
            (BrowserDownloadMode::TaskScoped, Some(root)) => root.validate(),
            (BrowserDownloadMode::Deny, Some(_)) => Err(BrowserPolicyError::Denied(
                "denied browser downloads cannot carry filesystem authority".to_owned(),
            )),
            (BrowserDownloadMode::TaskScoped, None) => Err(BrowserPolicyError::Denied(
                "task-scoped browser downloads require an exact root authority".to_owned(),
            )),
        }
    }

    /// Resolves one relative download path beneath the exact task root without following it.
    ///
    /// # Errors
    /// Returns a denial for disabled downloads, absolute/traversing/non-normal paths, or malformed
    /// root authority.
    pub fn authorize_relative_path(&self, relative: &Path) -> Result<PathBuf, BrowserPolicyError> {
        self.validate()?;
        let root = self.root_authority.as_ref().ok_or_else(|| {
            BrowserPolicyError::Denied("browser downloads are disabled".to_owned())
        })?;
        validate_strict_relative_path(relative)?;
        Ok(root.root.join(relative))
    }
}

/// Exact runtime boundary for one demand-loaded browser process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserIsolationRequest {
    pub profile_root: PathBuf,
    pub download_root: Option<PathBuf>,
    pub loopback_capability: BrowserLoopbackCapabilityV1,
    pub now_ms: i64,
}

/// Exact local-only Seatbelt authority for one Controller-owned loopback application server.
///
/// This is intentionally separate from browser isolation and from the generic offline execution
/// backend. The server may bind only the task's exact loopback port, may not initiate outbound
/// network connections, and may write only beneath a Controller-owned application-data root.
/// Protected user-home reads are denied, with exact read access reopened for the repository and
/// application-data roots; explicitly protected subtrees remain unreadable. The repository is
/// never writable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoopbackServerIsolationRequestV1 {
    pub task_loopback_grant: TaskLoopbackGrantV1,
    pub repository_root: PathBuf,
    pub data_root: PathBuf,
    pub user_home_root: PathBuf,
    pub extra_protected_read_roots: Vec<PathBuf>,
    /// Exact Controller-owned `PostgreSQL` broker port. Never the `PostgreSQL` server port.
    pub postgres_broker_port: Option<u16>,
    pub now_ms: i64,
}

impl LoopbackServerIsolationRequestV1 {
    /// Validates the exact loopback grant and disjoint repository/data roots.
    ///
    /// # Errors
    /// Returns a denial when the grant is stale/non-HTTP, roots are unsafe, or writable data is
    /// placed inside the repository tree.
    pub fn validate(&self) -> Result<(), BrowserPolicyError> {
        self.task_loopback_grant.validate(self.now_ms)?;
        if self.task_loopback_grant.scheme != "http" {
            return Err(BrowserPolicyError::Denied(
                "managed loopback server v1 requires exact http authority".to_owned(),
            ));
        }
        if let Some(port) = self.postgres_broker_port
            && (port == 0 || port == self.task_loopback_grant.port)
        {
            return Err(BrowserPolicyError::Denied(
                "managed PostgreSQL broker needs a distinct exact loopback port".to_owned(),
            ));
        }
        validate_existing_directory(&self.repository_root)?;
        validate_existing_directory(&self.data_root)?;
        validate_existing_directory(&self.user_home_root)?;
        let repository_root = self.repository_root.canonicalize()?;
        let data_root = self.data_root.canonicalize()?;
        let user_home_root = self.user_home_root.canonicalize()?;
        if data_root.starts_with(&repository_root) || repository_root.starts_with(&data_root) {
            return Err(BrowserPolicyError::Denied(
                "managed loopback server repository and data roots must be disjoint".to_owned(),
            ));
        }
        if !repository_root.starts_with(&user_home_root) || !data_root.starts_with(&user_home_root)
        {
            return Err(BrowserPolicyError::Denied(
                "managed loopback server repository and data roots must remain beneath the declared protected user home"
                    .to_owned(),
            ));
        }
        for root in &self.extra_protected_read_roots {
            let canonical = canonicalize_existing_or_parent_browser(root)?;
            if repository_root.starts_with(&canonical) || data_root.starts_with(&canonical) {
                return Err(BrowserPolicyError::Denied(
                    "managed loopback protected-read roots cannot contain exact repository/data read authority"
                        .to_owned(),
                ));
            }
        }
        Ok(())
    }

    /// Computes the immutable isolation-policy digest bound into Controller action authority.
    ///
    /// # Errors
    /// Returns a policy error when roots/grant cannot be validated and canonicalized.
    pub fn digest(&self) -> Result<String, BrowserPolicyError> {
        self.validate()?;
        let repository_root = self.repository_root.canonicalize()?;
        let data_root = self.data_root.canonicalize()?;
        let user_home_root = self.user_home_root.canonicalize()?;
        let mut protected = self
            .extra_protected_read_roots
            .iter()
            .map(|root| canonicalize_existing_or_parent_browser(root))
            .collect::<Result<Vec<_>, _>>()?;
        protected.sort();
        let grant = &self.task_loopback_grant;
        let mut hasher = Sha256::new();
        digest_field(&mut hasher, "sovereign.loopback_server_isolation.v1");
        digest_field(&mut hasher, &grant.plan_id);
        hasher.update(grant.plan_revision.to_be_bytes());
        digest_field(&mut hasher, &grant.task_id);
        digest_field(&mut hasher, &grant.task_contract_digest);
        digest_field(&mut hasher, &grant.resource_lease_id);
        hasher.update(grant.execution_epoch.to_be_bytes());
        digest_field(&mut hasher, &grant.scheme);
        digest_field(&mut hasher, &grant.host);
        hasher.update(grant.port.to_be_bytes());
        hasher.update(grant.expires_at_ms.to_be_bytes());
        hasher.update(self.postgres_broker_port.unwrap_or(0).to_be_bytes());
        digest_field(&mut hasher, &repository_root.display().to_string());
        digest_field(&mut hasher, &data_root.display().to_string());
        digest_field(&mut hasher, &user_home_root.display().to_string());
        for root in protected {
            digest_field(&mut hasher, &root.display().to_string());
        }
        Ok(format!("sha256:{:x}", hasher.finalize()))
    }
}

/// Dedicated macOS Seatbelt backend for one exact Controller-owned loopback server.
#[derive(Debug, Clone)]
pub struct MacLoopbackServerSandboxExecBackend {
    sandbox_exec: PathBuf,
}

impl MacLoopbackServerSandboxExecBackend {
    /// Detects macOS Seatbelt and proves the exact-port bind / no-outbound / writable-data-root
    /// boundary with a small runtime self-test.
    ///
    /// # Errors
    /// Returns fail-closed when `sandbox-exec` is unavailable or the required boundary is not
    /// enforced by the host.
    pub fn detect() -> Result<Self, BrowserPolicyError> {
        let sandbox_exec = PathBuf::from("/usr/bin/sandbox-exec");
        if !sandbox_exec.is_file() {
            return Err(BrowserPolicyError::IsolationUnavailable(
                "macOS sandbox-exec is unavailable".to_owned(),
            ));
        }
        let backend = Self { sandbox_exec };
        backend.self_test()?;
        Ok(backend)
    }

    #[must_use]
    pub fn sandbox_exec_path(&self) -> &Path {
        &self.sandbox_exec
    }

    /// Builds the exact server Seatbelt profile. Protected user-home reads are denied then reopened
    /// only for the exact repository and Controller data roots; extra protected roots remain denied.
    /// Writes are denied globally then reopened only for the exact Controller data root. Network is
    /// denied globally then reopened for the granted app listener and, when explicitly supplied,
    /// outbound access to one exact Controller-owned `PostgreSQL` broker port.
    ///
    /// # Errors
    /// Returns a denial for malformed/stale authority or unsafe roots.
    pub fn build_profile(
        request: &LoopbackServerIsolationRequestV1,
    ) -> Result<String, BrowserPolicyError> {
        request.validate()?;
        let repository_root = request.repository_root.canonicalize()?;
        let data_root = request.data_root.canonicalize()?;
        let user_home_root = request.user_home_root.canonicalize()?;
        let mut profile = String::from("(version 1)(allow default)(deny network*)");
        write!(
            &mut profile,
            "(allow network-bind (local ip \"localhost:{}\"))",
            request.task_loopback_grant.port
        )
        .map_err(|_| {
            BrowserPolicyError::Denied("failed to build loopback server network profile".to_owned())
        })?;
        write!(
            &mut profile,
            "(allow network-inbound (local ip \"localhost:{}\"))",
            request.task_loopback_grant.port
        )
        .map_err(|_| {
            BrowserPolicyError::Denied("failed to build loopback server inbound profile".to_owned())
        })?;
        if let Some(port) = request.postgres_broker_port {
            write!(
                &mut profile,
                "(allow network-outbound (remote ip \"localhost:{port}\"))"
            )
            .map_err(|_| {
                BrowserPolicyError::Denied(
                    "failed to build exact PostgreSQL broker profile".to_owned(),
                )
            })?;
        }
        write!(
            &mut profile,
            "(deny file-read* (subpath {}))(allow file-read* (subpath {}))(allow file-read* (subpath {}))",
            seatbelt_string(&user_home_root),
            seatbelt_string(&repository_root),
            seatbelt_string(&data_root)
        )
        .map_err(|_| {
            BrowserPolicyError::Denied("failed to build loopback server read-jail profile".to_owned())
        })?;
        for root in &request.extra_protected_read_roots {
            let root = canonicalize_existing_or_parent_browser(root)?;
            write!(
                &mut profile,
                "(deny file-read* (subpath {}))",
                seatbelt_string(&root)
            )
            .map_err(|_| {
                BrowserPolicyError::Denied(
                    "failed to build loopback server protected-read profile".to_owned(),
                )
            })?;
        }
        // Node resolves its entrypoint with realpath(3), which needs lstat on each parent.
        // Permit metadata on the exact repository/data ancestors only; contents elsewhere in
        // the protected home remain unreadable.
        let mut metadata_ancestors = BTreeSet::new();
        for root in [&repository_root, &data_root] {
            for ancestor in root.ancestors().skip(1) {
                if !ancestor.starts_with(&user_home_root) {
                    break;
                }
                metadata_ancestors.insert(ancestor.to_path_buf());
            }
        }
        for ancestor in metadata_ancestors {
            write!(
                &mut profile,
                "(allow file-read-metadata (literal {}))",
                seatbelt_string(&ancestor)
            )
            .map_err(|_| {
                BrowserPolicyError::Denied(
                    "failed to build loopback server ancestor metadata profile".to_owned(),
                )
            })?;
        }
        profile.push_str("(deny file-write* (subpath \"/\"))");
        profile.push_str("(allow file-write* (literal \"/dev/null\"))");
        write!(
            &mut profile,
            "(allow file-write* (subpath {}))",
            seatbelt_string(&data_root)
        )
        .map_err(|_| {
            BrowserPolicyError::Denied("failed to build loopback server data-root rule".to_owned())
        })?;
        profile.push_str("(deny process-exec (literal \"/usr/bin/security\"))");
        profile.push_str("(deny mach-lookup (global-name \"com.apple.securityd\"))");
        profile.push_str("(deny mach-lookup (global-name \"com.apple.securityd.xpc\"))");
        profile.push_str("(deny mach-lookup (global-name \"com.apple.securityd.system\"))");
        Ok(profile)
    }

    /// Wraps one exact already-authorized server executable/argv in the dedicated Seatbelt profile.
    ///
    /// # Errors
    /// Returns fail-closed for invalid authority or a missing/non-absolute executable.
    pub fn isolate(
        &self,
        executable: &Path,
        args: &[String],
        request: &LoopbackServerIsolationRequestV1,
    ) -> Result<crate::IsolatedCommand, BrowserPolicyError> {
        if !executable.is_absolute() || !executable.is_file() {
            return Err(BrowserPolicyError::Denied(
                "loopback server executable must be an existing absolute file".to_owned(),
            ));
        }
        let profile = Self::build_profile(request)?;
        let mut wrapped = vec!["-p".to_owned(), profile, executable.display().to_string()];
        wrapped.extend(args.iter().cloned());
        Ok(crate::IsolatedCommand {
            executable: self.sandbox_exec.clone(),
            args: wrapped,
        })
    }

    fn self_test(&self) -> Result<(), BrowserPolicyError> {
        let nonce = format!(
            "{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|error| BrowserPolicyError::IsolationUnavailable(error.to_string()))?
                .as_nanos()
        );
        let root = std::env::temp_dir().join(format!("sovereign-loopback-server-{nonce}"));
        let repository_root = root.join("repo");
        let data_root = root.join("data");
        fs::create_dir_all(&repository_root)?;
        fs::create_dir_all(&data_root)?;
        let repository_root = repository_root.canonicalize()?;
        let data_root = data_root.canonicalize()?;
        let protected_root = repository_root.join(".protected");
        fs::create_dir_all(&protected_root)?;
        let protected_file = protected_root.join("secret.txt");
        let repository_file = repository_root.join("readable.txt");
        let data_file = data_root.join("readable.txt");
        fs::write(&protected_file, b"secret")?;
        fs::write(&repository_file, b"repository")?;
        fs::write(&data_file, b"data")?;
        let allowed_listener = TcpListener::bind("127.0.0.1:0")?;
        let denied_listener = TcpListener::bind("127.0.0.1:0")?;
        let allowed_port = allowed_listener.local_addr()?.port();
        let denied_port = denied_listener.local_addr()?.port();
        drop(allowed_listener);
        drop(denied_listener);
        let request = LoopbackServerIsolationRequestV1 {
            task_loopback_grant: TaskLoopbackGrantV1 {
                schema_version: TASK_LOOPBACK_GRANT_SCHEMA_VERSION,
                plan_id: "plan.selftest".to_owned(),
                plan_revision: 1,
                task_id: "task.selftest".to_owned(),
                task_contract_digest: format!("sha256:{}", "1".repeat(64)),
                resource_lease_id: "resource.selftest".to_owned(),
                execution_epoch: 1,
                scheme: "http".to_owned(),
                host: "127.0.0.1".to_owned(),
                port: allowed_port,
                expires_at_ms: i64::MAX,
            },
            repository_root: repository_root.clone(),
            data_root: data_root.clone(),
            user_home_root: root.canonicalize()?,
            extra_protected_read_roots: vec![protected_root],
            postgres_broker_port: None,
            now_ms: 0,
        };
        let profile = Self::build_profile(&request)?;
        let bind_probe = |port: u16| {
            format!(
                "import socket; s=socket.socket(); s.bind(('127.0.0.1',{port})); s.listen(1); s.close()"
            )
        };
        let allowed_bind = self.python_probe(&profile, &bind_probe(allowed_port))?;
        let denied_bind = self.python_probe(&profile, &bind_probe(denied_port))?;
        let repository_read = self.file_read_probe(&profile, &repository_file)?;
        let data_read = self.file_read_probe(&profile, &data_file)?;
        let protected_read = self.file_read_probe(&profile, &protected_file)?;
        let inside = data_root.join("inside");
        let outside = repository_root.join("outside");
        let write_inside =
            self.shell_probe(&profile, &format!("printf ok > '{}'", inside.display()))?;
        let write_outside =
            self.shell_probe(&profile, &format!("printf no > '{}'", outside.display()))?;
        let outbound_listener = TcpListener::bind("127.0.0.1:0")?;
        let outbound_port = outbound_listener.local_addr()?.port();
        let outbound = self.python_probe(
            &profile,
            &format!(
                "import socket; s=socket.socket(); s.settimeout(0.2); s.connect(('127.0.0.1',{outbound_port}))"
            ),
        )?;
        drop(outbound_listener);
        let _ = fs::remove_dir_all(&root);
        if !allowed_bind.success()
            || denied_bind.success()
            || !repository_read.success()
            || !data_read.success()
            || protected_read.success()
            || !write_inside.success()
            || write_outside.success()
            || outbound.success()
        {
            return Err(BrowserPolicyError::IsolationUnavailable(
                "loopback server Seatbelt self-test did not enforce exact bind/read/write/outbound authority"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    fn file_read_probe(
        &self,
        profile: &str,
        path: &Path,
    ) -> Result<std::process::ExitStatus, BrowserPolicyError> {
        Ok(std::process::Command::new(&self.sandbox_exec)
            .args(["-p", profile, "/bin/cat"])
            .arg(path)
            .env_clear()
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()?)
    }

    fn python_probe(
        &self,
        profile: &str,
        source: &str,
    ) -> Result<std::process::ExitStatus, BrowserPolicyError> {
        Ok(std::process::Command::new(&self.sandbox_exec)
            .args(["-p", profile, "/usr/bin/python3", "-B", "-c", source])
            .env_clear()
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()?)
    }

    fn shell_probe(
        &self,
        profile: &str,
        source: &str,
    ) -> Result<std::process::ExitStatus, BrowserPolicyError> {
        Ok(std::process::Command::new(&self.sandbox_exec)
            .args(["-p", profile, "/bin/sh", "-c", source])
            .env_clear()
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()?)
    }
}

impl BrowserIsolationRequest {
    /// Validates exact writable roots and current Controller loopback authority.
    ///
    /// # Errors
    /// Returns a denial for unsafe roots or an invalid/expired loopback capability.
    pub fn validate(&self) -> Result<(), BrowserPolicyError> {
        self.loopback_capability.validate(self.now_ms)?;
        validate_existing_directory(&self.profile_root)?;
        if let Some(root) = &self.download_root {
            validate_existing_directory(root)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolatedBrowserCommand {
    pub executable: PathBuf,
    pub args: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct MacBrowserSandboxExecBackend {
    sandbox_exec: PathBuf,
}

impl MacBrowserSandboxExecBackend {
    /// Detects and runtime-proves exact-port browser Seatbelt isolation.
    ///
    /// # Errors
    /// Returns fail-closed when `sandbox-exec` is absent or its exact-loopback/file boundary cannot
    /// be proven on this host.
    pub fn detect() -> Result<Self, BrowserPolicyError> {
        let sandbox_exec = PathBuf::from("/usr/bin/sandbox-exec");
        if !sandbox_exec.is_file() {
            return Err(BrowserPolicyError::IsolationUnavailable(
                "macOS sandbox-exec is unavailable".to_owned(),
            ));
        }
        let backend = Self { sandbox_exec };
        backend.self_test()?;
        Ok(backend)
    }

    #[must_use]
    pub fn sandbox_exec_path(&self) -> &Path {
        &self.sandbox_exec
    }

    /// Builds the exact Seatbelt profile for one validated browser launch.
    ///
    /// # Errors
    /// Returns a denial when the request is stale or its roots are unsafe.
    pub fn build_profile(request: &BrowserIsolationRequest) -> Result<String, BrowserPolicyError> {
        request.validate()?;
        let profile_root = request.profile_root.canonicalize()?;
        #[cfg(target_os = "macos")]
        let chrome_singleton_prefix = chrome_process_singleton_prefix(&profile_root)?;
        let mut profile = String::from("(version 1)(allow default)(deny network*)");
        write!(
            &mut profile,
            "(allow network-outbound (remote ip \"localhost:{}\"))",
            request.loopback_capability.localhost_port
        )
        .map_err(|_| {
            BrowserPolicyError::Denied("failed to build browser network profile".to_owned())
        })?;
        #[cfg(target_os = "macos")]
        write!(
            &mut profile,
            "(allow network-bind (prefix {}))",
            seatbelt_string(&chrome_singleton_prefix)
        )
        .map_err(|_| {
            BrowserPolicyError::Denied("failed to build browser singleton profile".to_owned())
        })?;
        profile.push_str("(deny file-write* (subpath \"/\"))");
        #[cfg(target_os = "macos")]
        {
            profile.push_str("(allow file-write* (literal \"/dev/null\"))");
            write!(
                &mut profile,
                "(allow file-write* (prefix {}))",
                seatbelt_string(&chrome_singleton_prefix)
            )
            .map_err(|_| {
                BrowserPolicyError::Denied(
                    "failed to build browser singleton file profile".to_owned(),
                )
            })?;
        }
        write!(
            &mut profile,
            "(allow file-write* (subpath {}))",
            seatbelt_string(&profile_root)
        )
        .map_err(|_| {
            BrowserPolicyError::Denied("failed to build browser profile root rule".to_owned())
        })?;
        if let Some(download_root) = &request.download_root {
            let download_root = download_root.canonicalize()?;
            write!(
                &mut profile,
                "(allow file-write* (subpath {}))",
                seatbelt_string(&download_root)
            )
            .map_err(|_| {
                BrowserPolicyError::Denied("failed to build browser download root rule".to_owned())
            })?;
        }
        profile.push_str("(deny process-exec (literal \"/usr/bin/security\"))");
        profile.push_str("(deny mach-lookup (global-name \"com.apple.securityd\"))");
        profile.push_str("(deny mach-lookup (global-name \"com.apple.securityd.xpc\"))");
        profile.push_str("(deny mach-lookup (global-name \"com.apple.securityd.system\"))");
        Ok(profile)
    }

    /// Wraps an exact browser command in the validated browser Seatbelt profile.
    ///
    /// # Errors
    /// Returns fail-closed for an unsafe request or a missing/non-absolute executable.
    pub fn isolate(
        &self,
        executable: &Path,
        args: &[String],
        request: &BrowserIsolationRequest,
    ) -> Result<IsolatedBrowserCommand, BrowserPolicyError> {
        if !executable.is_absolute() || !executable.is_file() {
            return Err(BrowserPolicyError::Denied(
                "browser executable must be an existing absolute file".to_owned(),
            ));
        }
        let profile = Self::build_profile(request)?;
        let mut isolated_args = vec!["-p".to_owned(), profile, executable.display().to_string()];
        isolated_args.extend(args.iter().cloned());
        Ok(IsolatedBrowserCommand {
            executable: self.sandbox_exec.clone(),
            args: isolated_args,
        })
    }

    #[cfg(target_os = "macos")]
    fn self_test(&self) -> Result<(), BrowserPolicyError> {
        let allowed_listener = TcpListener::bind("127.0.0.1:0")?;
        let denied_listener = TcpListener::bind("127.0.0.1:0")?;
        let allowed_port = allowed_listener.local_addr()?.port();
        let denied_port = denied_listener.local_addr()?.port();
        if allowed_port == denied_port {
            return Err(BrowserPolicyError::IsolationUnavailable(
                "browser Seatbelt self-test did not obtain distinct loopback ports".to_owned(),
            ));
        }

        let root = temporary_self_test_root()?;
        let profile_root = root.join("profile");
        fs::create_dir_all(&profile_root)?;
        let token = b"sovereign-browser-seatbelt-self-test";
        let request = BrowserIsolationRequest {
            profile_root: profile_root.clone(),
            download_root: None,
            loopback_capability: BrowserLoopbackCapabilityV1 {
                schema_version: BROWSER_LOOPBACK_CAPABILITY_SCHEMA_VERSION,
                lease_id: "browser.self-test".to_owned(),
                execution_epoch: 0,
                localhost_port: allowed_port,
                token_digest: format!("sha256:{:x}", Sha256::digest(token)),
                expires_at_ms: 1,
            },
            now_ms: 0,
        };
        let profile = Self::build_profile(&request)?;
        let allowed = network_probe_status(&self.sandbox_exec, &profile, allowed_port)?;
        let denied = network_probe_status(&self.sandbox_exec, &profile, denied_port)?;
        let inside = profile_root.join("inside");
        let outside = root.join("outside");
        let inside_write = file_write_probe_status(&self.sandbox_exec, &profile, &inside)?;
        let outside_write = file_write_probe_status(&self.sandbox_exec, &profile, &outside)?;
        drop((allowed_listener, denied_listener));
        let cleanup = fs::remove_dir_all(&root);
        if !allowed.status.success()
            || denied.status.success()
            || !inside_write.success()
            || outside_write.success()
        {
            return Err(BrowserPolicyError::IsolationUnavailable(format!(
                "browser Seatbelt self-test did not enforce exact loopback-port/file-write boundary \
                 (allowed port connect: {} {:?}; denied port connect: {}; \
                 profile write: {inside_write}; outside write: {outside_write})",
                allowed.status,
                probe_error_tail(&allowed.stderr),
                denied.status
            )));
        }
        cleanup?;
        Ok(())
    }

    #[cfg(not(target_os = "macos"))]
    #[allow(clippy::unused_self)]
    fn self_test(&self) -> Result<(), BrowserPolicyError> {
        Err(BrowserPolicyError::IsolationUnavailable(
            "browser Seatbelt isolation is available only on macOS".to_owned(),
        ))
    }
}

fn canonical_loopback_host(host: &str) -> Result<String, BrowserPolicyError> {
    if host.trim() != host || host.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(BrowserPolicyError::Denied(
            "task-loopback host is malformed".to_owned(),
        ));
    }
    let literal = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    let address = literal.parse::<IpAddr>().map_err(|_| {
        BrowserPolicyError::Denied(
            "task-loopback host must be an exact loopback IP literal".to_owned(),
        )
    })?;
    if !address.is_loopback() {
        return Err(BrowserPolicyError::Denied(
            "task-loopback host must be loopback".to_owned(),
        ));
    }
    Ok(match address {
        IpAddr::V4(address) => address.to_string(),
        IpAddr::V6(address) => format!("[{address}]"),
    })
}

fn validate_identifier(label: &str, value: &str) -> Result<(), BrowserPolicyError> {
    if value.is_empty()
        || value.trim() != value
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(BrowserPolicyError::Denied(format!(
            "{label} identifier is empty or malformed"
        )));
    }
    Ok(())
}

fn is_sha256_binding(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn validate_exact_http_origin(origin: &str) -> Result<(), BrowserPolicyError> {
    if origin.trim() != origin {
        return Err(BrowserPolicyError::Denied(
            "browser profile origin must not contain surrounding whitespace".to_owned(),
        ));
    }
    let Some((scheme, authority)) = origin.split_once("://") else {
        return Err(BrowserPolicyError::Denied(
            "browser profile origin must include http:// or https://".to_owned(),
        ));
    };
    if !matches!(scheme, "http" | "https")
        || authority.is_empty()
        || authority.contains(['/', '?', '#', '@'])
        || authority.contains(char::is_whitespace)
    {
        return Err(BrowserPolicyError::Denied(
            "browser profile origin must be an exact HTTP(S) authority without path or userinfo"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_content_type(value: &str) -> Result<(), BrowserPolicyError> {
    let Some((kind, subtype)) = value.split_once('/') else {
        return Err(BrowserPolicyError::Denied(
            "browser download content type must be type/subtype".to_owned(),
        ));
    };
    if kind.is_empty()
        || subtype.is_empty()
        || value.trim() != value
        || value.contains(';')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'+' | b'-' | b'.'))
    {
        return Err(BrowserPolicyError::Denied(
            "browser download content type is malformed".to_owned(),
        ));
    }
    Ok(())
}

fn validate_strict_relative_path(path: &Path) -> Result<(), BrowserPolicyError> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err(BrowserPolicyError::Denied(
            "browser download path must be non-empty and relative".to_owned(),
        ));
    }
    if path
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(BrowserPolicyError::Denied(
            "browser download path traversal or normalization aliases are forbidden".to_owned(),
        ));
    }
    Ok(())
}

fn validate_existing_directory(path: &Path) -> Result<(), BrowserPolicyError> {
    if !path.is_absolute() {
        return Err(BrowserPolicyError::Denied(
            "browser writable root must be absolute".to_owned(),
        ));
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(BrowserPolicyError::Denied(
            "browser writable root must be an existing non-symlink directory".to_owned(),
        ));
    }
    let canonical = path.canonicalize()?;
    if canonical != path {
        return Err(BrowserPolicyError::Denied(
            "browser writable root must already be canonical".to_owned(),
        ));
    }
    Ok(())
}

fn canonicalize_existing_or_parent_browser(path: &Path) -> Result<PathBuf, BrowserPolicyError> {
    if path.exists() {
        return Ok(path.canonicalize()?);
    }
    let Some(parent) = path.parent() else {
        return Err(BrowserPolicyError::Denied(format!(
            "protected browser root has no parent: {}",
            path.display()
        )));
    };
    Ok(parent.canonicalize()?.join(path.file_name().ok_or_else(|| {
        BrowserPolicyError::Denied("protected browser root has no final component".to_owned())
    })?))
}

fn seatbelt_string(path: &Path) -> String {
    let value = path
        .display()
        .to_string()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    format!("\"{value}\"")
}

#[cfg(target_os = "macos")]
fn chrome_process_singleton_prefix(profile_root: &Path) -> Result<PathBuf, BrowserPolicyError> {
    let temp_root = std::env::temp_dir().canonicalize().map_err(|error| {
        BrowserPolicyError::IsolationUnavailable(format!(
            "cannot resolve the macOS per-user temporary directory: {error}"
        ))
    })?;
    let temp_metadata = fs::symlink_metadata(&temp_root)?;
    let profile_metadata = fs::symlink_metadata(profile_root)?;
    if !temp_metadata.is_dir()
        || temp_metadata.uid() != profile_metadata.uid()
        || temp_metadata.permissions().mode() & 0o077 != 0
        || temp_root.file_name().and_then(|name| name.to_str()) != Some("T")
        || !temp_root.starts_with("/private/var/folders")
    {
        return Err(BrowserPolicyError::IsolationUnavailable(
            "macOS browser singleton root is not an owner-private canonical Darwin temporary directory"
                .to_owned(),
        ));
    }
    Ok(temp_root.join("com.google.Chrome."))
}

#[cfg(target_os = "macos")]
fn temporary_self_test_root() -> Result<PathBuf, BrowserPolicyError> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| BrowserPolicyError::IsolationUnavailable(error.to_string()))?
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "sovereign-browser-seatbelt-self-test-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&root)?;
    Ok(root.canonicalize()?)
}

/// Last line of a probe's stderr, bounded, so a failed self-test names the probe's own error.
#[cfg(target_os = "macos")]
fn probe_error_tail(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    let last = text
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("");
    last.chars().take(240).collect()
}

#[cfg(target_os = "macos")]
fn network_probe_status(
    sandbox_exec: &Path,
    profile: &str,
    port: u16,
) -> Result<std::process::Output, BrowserPolicyError> {
    let probe = format!(
        "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.settimeout(0.5); s.connect(('127.0.0.1',{port}))"
    );
    Ok(Command::new(sandbox_exec)
        .args(["-p", profile, "/usr/bin/python3", "-c", &probe])
        .env_clear()
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .stdin(Stdio::null())
        .output()?)
}

#[cfg(target_os = "macos")]
fn file_write_probe_status(
    sandbox_exec: &Path,
    profile: &str,
    path: &Path,
) -> Result<std::process::ExitStatus, BrowserPolicyError> {
    Ok(Command::new(sandbox_exec)
        .args(["-p", profile, "/usr/bin/touch"])
        .arg(path)
        .env_clear()
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?)
}
