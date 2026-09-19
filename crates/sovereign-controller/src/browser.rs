#![forbid(unsafe_code)]

//! Controller-owned browser authority and local proxy mechanics.
//!
//! The browser adapter remains authority-neutral. This module derives exact browser/network scope
//! from already-validated Plan IR, binds browser actions to the canonical `ActionJournal` authority
//! surface, and owns the only localhost gateway Chrome may reach under Seatbelt.

use super::{
    ActionJournal, ActionState, ArtifactStore, AttemptState, Controller, ControllerError,
    NetworkChargePersistence, PlanValidity, ResourceResidencyStateV1, TaskState, active_scoped_key,
    digest_json, required_array, required_str, required_u32, required_u64,
    resources::{
        BROWSER_RESIDENCY_KEY, BROWSER_RESOURCE_RESIDENCY_SCHEMA_VERSION,
        BrowserResourceResidencyStateV1, BrowserResourceResidencyV1, RESOURCE_GOVERNOR_KEY,
        RESOURCE_GOVERNOR_NAMESPACE, RESOURCE_LEASE_NAMESPACE, RESOURCE_PRESSURE_NAMESPACE,
        RESOURCE_RESIDENCY_NAMESPACE, resource_event_payload,
    },
    revision_scoped_key, sha256_prefixed, unix_millis,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sovereign_context::{
    ContextLevel, EvidenceItem, EvidenceKind, ExpansionHandle, PacketSection, TrustClass,
};
use sovereign_model::{ModelBackend, ModelResidencyProof};
use sovereign_policy::browser::{
    BROWSER_DOWNLOAD_POLICY_SCHEMA_VERSION, BROWSER_LOOPBACK_CAPABILITY_SCHEMA_VERSION,
    BrowserDownloadMode, BrowserDownloadPolicyV1, BrowserDownloadRetentionPolicyV1,
    BrowserDownloadRootAuthorityV1, BrowserIsolationRequest, BrowserLoopbackCapabilityV1,
    BrowserProfileAuthority, BrowserProfileMode, BrowserProfilePolicy,
    MacBrowserSandboxExecBackend, PersistentBrowserProfileGrantV1,
    TASK_LOOPBACK_GRANT_SCHEMA_VERSION, TaskLoopbackGrantV1, TaskLoopbackScope,
};
use sovereign_policy::{
    AdmissionStatus, AutonomyBudgetV1, Capability, CommandRisk, ConditionalLeaseContextV1,
    HeavyLeaseClass, IsolatedCommand, LeaseStateV1, NetworkDestination, NetworkPolicy,
    PermissionDecision, PolicyError, ResourceLeaseOwnerV1, ResourceLeaseRequestV1, ResourceLeaseV1,
    ResourcePolicyEventV1, ResourcePressureEventV1, TaskResourceBudgetV1,
};
use sovereign_tools::{
    ApprovalClaim, JournalActionAuthority, JournalActionReservation, ReconciliationMode,
    SystemWebDnsResolver, ToolError, ToolManifest, WebDnsResolver,
    browser::{
        BROWSER_PROXY_AUTH_REALM, BROWSER_PROXY_AUTH_USERNAME, BROWSER_SCHEMA_VERSION,
        BrowserAction, BrowserActionEffect, BrowserActionReceipt, BrowserAdapter,
        BrowserAdapterConfig, BrowserDocumentRequestDecision, BrowserDocumentRequestKind,
        BrowserDocumentRequestObservation, BrowserDownloadPolicy,
        BrowserDownloadTerminalObservation, BrowserDownloadTerminalState, BrowserError,
        BrowserFormInspectionReceipt, BrowserLaunchOptions, BrowserLease, BrowserProfileRoot,
        BrowserProxyAuthBinding, BrowserSensitivePageReason, BrowserSpawnState,
        BrowserStateSynopsis, DownloadReceipt, PreparedBrowserLaunch,
    },
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

pub const BROWSER_AUTHORITY_SCHEMA_VERSION: u32 = 1;

const MAX_PROXY_HEADER_BYTES: usize = 64 * 1024;
const GATEWAY_IO_TIMEOUT: Duration = Duration::from_secs(30);
const GATEWAY_POLL: Duration = Duration::from_millis(2);
const BROWSER_PROFILE_GRANT_NAMESPACE: &str = "controller.browser_profile_grant";
const BROWSER_DOWNLOAD_RECORD_NAMESPACE: &str = "controller.browser_download_record";
const BROWSER_DOWNLOAD_RECORD_SCHEMA_VERSION: u32 = 1;
pub(crate) const BROWSER_NETWORK_RESERVATION_NAMESPACE: &str =
    "controller.browser_network_reservation";
const BROWSER_NETWORK_RESERVATION_SCHEMA_VERSION: u32 = 1;
const BROWSER_RUNTIME_DIR: &str = "browser-runtime";
const BROWSER_UNKNOWN_ADMISSION_MIB: u64 = 1_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BrowserResourceActivity {
    Active,
    Idle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BrowserResourceTerminal {
    Released,
    Evicted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BrowserDownloadActivity {
    Standalone,
    EnclosingAction,
}

struct BrowserLaunchAuthority {
    plan_id: String,
    plan_revision: u32,
    task_id: String,
    attempt_id: String,
    task_contract_digest: String,
    max_retained_raw_bytes: u64,
    execution_epoch: i64,
    authority: BrowserTaskAuthorityV1,
    permission_decision: PermissionDecision,
    task_budget: TaskResourceBudgetV1,
    config: BrowserAdapterConfig,
}

struct AdmittedBrowserLaunch {
    scope: BrowserLaunchAuthority,
    resource_lease: ResourceLeaseV1,
    pressure: ResourcePressureEventV1,
    policy_event: ResourcePolicyEventV1,
}

struct PreparedBrowserSession {
    scope: BrowserLaunchAuthority,
    resource_lease: ResourceLeaseV1,
    browser_lease: BrowserLease,
    profile_authority: BrowserProfileAuthority,
    loopback_capability: BrowserLoopbackCapabilityV1,
    task_loopback_grants: Vec<TaskLoopbackGrantV1>,
    download_root: Option<PathBuf>,
    download_policy: BrowserDownloadPolicyV1,
    max_network_bytes: u64,
    adapter_config: BrowserAdapterConfig,
    gateway: BrowserGateway,
    prepared: PreparedBrowserLaunch,
    isolated: IsolatedCommand,
    residency: BrowserResourceResidencyV1,
    pressure: ResourcePressureEventV1,
    policy_event: ResourcePolicyEventV1,
}

struct BrowserLaunchRuntime {
    admitted: AdmittedBrowserLaunch,
    browser_lease: BrowserLease,
    profile_authority: BrowserProfileAuthority,
    runtime_root: PathBuf,
    profile_root: BrowserProfileRoot,
    download_root: Option<PathBuf>,
    download_policy: BrowserDownloadPolicyV1,
    max_network_bytes: u64,
    task_loopback_grants: Vec<TaskLoopbackGrantV1>,
    gateway: BrowserGateway,
    loopback_capability: BrowserLoopbackCapabilityV1,
    now_ms: i64,
}

pub struct ControllerBrowserSession {
    plan_id: String,
    plan_revision: u32,
    task_id: String,
    task_contract_digest: String,
    attempt_id: String,
    execution_epoch: i64,
    resource_lease: ResourceLeaseV1,
    browser_lease: BrowserLease,
    permission_decision: PermissionDecision,
    authority: BrowserTaskAuthorityV1,
    profile_authority: BrowserProfileAuthority,
    loopback_capability: BrowserLoopbackCapabilityV1,
    task_loopback_grants: Vec<TaskLoopbackGrantV1>,
    download_root: Option<PathBuf>,
    download_policy: BrowserDownloadPolicyV1,
    max_retained_raw_bytes: u64,
    retained_download_bytes: u64,
    reserved_network_bytes: u64,
    sensitive_page_observed: bool,
    adapter_config: BrowserAdapterConfig,
    adapter: Option<BrowserAdapter>,
    gateway: Option<BrowserGateway>,
}

impl std::fmt::Debug for ControllerBrowserSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ControllerBrowserSession")
            .field("plan_id", &self.plan_id)
            .field("plan_revision", &self.plan_revision)
            .field("task_id", &self.task_id)
            .field("task_contract_digest", &self.task_contract_digest)
            .field("attempt_id", &self.attempt_id)
            .field("execution_epoch", &self.execution_epoch)
            .field("resource_lease_id", &self.resource_lease.lease_id)
            .field(
                "browser_lease_binding_digest",
                &self.browser_lease.binding_digest(),
            )
            .field(
                "permission_decision_digest",
                &self.permission_decision.digest(),
            )
            .field("authority", &self.authority)
            .field("profile_authority", &self.profile_authority)
            .field("loopback_capability", &self.loopback_capability)
            .field(
                "task_loopback_grant_count",
                &self.task_loopback_grants.len(),
            )
            .field("download_root", &self.download_root)
            .field("download_policy", &self.download_policy)
            .field("max_retained_raw_bytes", &self.max_retained_raw_bytes)
            .field("retained_download_bytes", &self.retained_download_bytes)
            .field("reserved_network_bytes", &self.reserved_network_bytes)
            .field("sensitive_page_observed", &self.sensitive_page_observed)
            .field("adapter_config", &self.adapter_config)
            .field("adapter_present", &self.adapter.is_some())
            .field("gateway_present", &self.gateway.is_some())
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct BrowserDownloadRecordV1 {
    schema_version: u32,
    plan_id: String,
    plan_revision: u32,
    task_id: String,
    task_contract_digest: String,
    relative_path_digest: String,
    lease_id: String,
    lease_binding_digest: String,
    execution_epoch: i64,
    bytes: u64,
    sha256: String,
    content_type: String,
    updated_at_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum BrowserNetworkReservationStateV1 {
    Active,
    Settled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum BrowserNetworkSettlementV1 {
    CleanObserved,
    ProvenAbsentZero,
    RecoveryFullReserve,
}

impl BrowserNetworkSettlementV1 {
    const fn phase(self) -> &'static str {
        match self {
            Self::CleanObserved => "clean_observed",
            Self::ProvenAbsentZero => "proven_absent_zero",
            Self::RecoveryFullReserve => "recovery_full_reserve",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct BrowserNetworkReservationV1 {
    schema_version: u32,
    plan_id: String,
    plan_revision: u32,
    task_id: String,
    task_contract_digest: String,
    resource_lease_id: String,
    browser_lease_binding_digest: String,
    execution_epoch: i64,
    reserved_bytes: u64,
    state: BrowserNetworkReservationStateV1,
    settled_bytes: Option<u64>,
    settlement: Option<BrowserNetworkSettlementV1>,
    updated_at_ms: i64,
}

impl BrowserNetworkReservationV1 {
    fn validate(&self) -> Result<(), ControllerError> {
        if self.schema_version != BROWSER_NETWORK_RESERVATION_SCHEMA_VERSION
            || self.plan_id.is_empty()
            || self.task_id.is_empty()
            || self.task_contract_digest.is_empty()
            || self.resource_lease_id.is_empty()
            || self.browser_lease_binding_digest.is_empty()
        {
            return Err(ControllerError::InvalidPlan(
                "browser network reservation has invalid shape".to_owned(),
            ));
        }
        match self.state {
            BrowserNetworkReservationStateV1::Active => {
                if self.settled_bytes.is_some() || self.settlement.is_some() {
                    return Err(ControllerError::InvalidPlan(
                        "active browser network reservation may not claim settlement".to_owned(),
                    ));
                }
            }
            BrowserNetworkReservationStateV1::Settled => {
                let settled_bytes = self.settled_bytes.ok_or_else(|| {
                    ControllerError::InvalidPlan(
                        "settled browser network reservation is missing settled bytes".to_owned(),
                    )
                })?;
                let settlement = self.settlement.ok_or_else(|| {
                    ControllerError::InvalidPlan(
                        "settled browser network reservation is missing settlement reason"
                            .to_owned(),
                    )
                })?;
                if settled_bytes > self.reserved_bytes
                    || matches!(settlement, BrowserNetworkSettlementV1::ProvenAbsentZero)
                        && settled_bytes != 0
                    || matches!(settlement, BrowserNetworkSettlementV1::RecoveryFullReserve)
                        && settled_bytes != self.reserved_bytes
                {
                    return Err(ControllerError::InvalidPlan(
                        "browser network settlement is inconsistent with its durable reservation"
                            .to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }
}

impl ControllerBrowserSession {
    #[must_use]
    pub fn task_id(&self) -> &str {
        &self.task_id
    }

    #[must_use]
    pub fn attempt_id(&self) -> &str {
        &self.attempt_id
    }

    #[must_use]
    pub const fn execution_epoch(&self) -> i64 {
        self.execution_epoch
    }

    #[must_use]
    pub fn authority(&self) -> &BrowserTaskAuthorityV1 {
        &self.authority
    }

    #[must_use]
    pub fn browser_lease(&self) -> &BrowserLease {
        &self.browser_lease
    }

    #[must_use]
    pub fn permission_decision(&self) -> &PermissionDecision {
        &self.permission_decision
    }

    #[must_use]
    pub fn profile_authority(&self) -> &BrowserProfileAuthority {
        &self.profile_authority
    }

    #[must_use]
    pub fn adapter(&self) -> Option<&BrowserAdapter> {
        self.adapter.as_ref()
    }

    #[must_use]
    pub fn adapter_mut(&mut self) -> Option<&mut BrowserAdapter> {
        self.adapter.as_mut()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserTaskAuthorityV1 {
    pub schema_version: u32,
    pub allowed_domains: BTreeSet<String>,
    pub allowed_schemes: BTreeSet<String>,
    pub allowed_ports: BTreeSet<u16>,
    pub allowed_methods: BTreeSet<String>,
    pub follow_redirects: bool,
    pub max_redirects: u32,
    pub allow_task_loopback: bool,
    pub max_tabs: u32,
    pub downloads_allowed: bool,
    pub profile_mode: BrowserProfileMode,
    pub download_root: Option<String>,
}

impl BrowserTaskAuthorityV1 {
    /// Builds ordinary public-network authority without weakening its private/loopback deny rules.
    /// Exact task loopback remains a separate grant.
    ///
    /// # Errors
    /// Returns a policy error if one declared public destination is malformed or unsafe.
    pub fn public_network_policy(&self) -> Result<NetworkPolicy, sovereign_policy::PolicyError> {
        let mut policy = NetworkPolicy::offline();
        for host in &self.allowed_domains {
            if is_loopback_literal(host) {
                continue;
            }
            for scheme in &self.allowed_schemes {
                for port in &self.allowed_ports {
                    policy.allow(scheme, host, *port)?;
                }
            }
        }
        Ok(policy)
    }

    #[must_use]
    pub fn permits_domain(&self, host: &str) -> bool {
        self.allowed_domains
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(host))
    }
}

fn required_bool(value: &Value, pointer: &str) -> Result<bool, ControllerError> {
    value
        .pointer(pointer)
        .and_then(Value::as_bool)
        .ok_or_else(|| ControllerError::InvalidPlan(format!("missing boolean {pointer}")))
}

fn string_set_at(value: &Value, pointer: &str) -> Result<BTreeSet<String>, ControllerError> {
    required_array(value, pointer)?
        .iter()
        .map(|item| {
            item.as_str().map(str::to_owned).ok_or_else(|| {
                ControllerError::InvalidPlan(format!("non-string entry in {pointer}"))
            })
        })
        .collect()
}

fn port_set_at(value: &Value, pointer: &str) -> Result<BTreeSet<u16>, ControllerError> {
    required_array(value, pointer)?
        .iter()
        .map(|item| {
            item.as_u64()
                .and_then(|raw| u16::try_from(raw).ok())
                .filter(|port| *port != 0)
                .ok_or_else(|| {
                    ControllerError::InvalidPlan(format!("invalid network port in {pointer}"))
                })
        })
        .collect()
}

fn set_intersection<T: Ord + Clone>(left: &BTreeSet<T>, right: &BTreeSet<T>) -> BTreeSet<T> {
    left.intersection(right).cloned().collect()
}

fn validate_browser_static_plan_safety(plan: &Value, task: &Value) -> Result<(), ControllerError> {
    if !required_bool(task, "/action_policy/browser/allowed")? {
        return Err(ControllerError::Policy(PolicyError::Denied(
            "task browser policy is disabled".to_owned(),
        )));
    }
    for (pointer, expected) in [
        ("/policy/network/allow_private_ranges", false),
        ("/policy/network/dns_revalidation", true),
        ("/policy/network/connected_peer_validation", true),
        ("/policy/browser/auto_open_downloads", false),
        ("/policy/browser/disable_web_security", false),
        ("/action_policy/browser/auto_open_downloads", false),
        ("/action_policy/browser/allow_local_file_navigation", false),
    ] {
        let source = if pointer.starts_with("/policy/") {
            plan
        } else {
            task
        };
        if required_bool(source, pointer)? != expected {
            return Err(ControllerError::Policy(PolicyError::Denied(format!(
                "unsafe browser/network plan setting {pointer}"
            ))));
        }
    }
    for (pointer, expected) in [
        ("/policy/network/ambient_proxy", "deny"),
        ("/policy/browser/local_file_navigation", "deny"),
        ("/policy/browser/extensions", "deny_by_default"),
        ("/policy/browser/clipboard", "deny"),
        ("/policy/browser/notifications", "deny"),
    ] {
        if required_str(plan, pointer)? != expected {
            return Err(ControllerError::Policy(PolicyError::Denied(format!(
                "unsafe browser global policy setting {pointer}"
            ))));
        }
    }
    Ok(())
}

fn profile_id_for(project_id: &str, repository_id: &str, task_id: &str) -> String {
    let mut hasher = Sha256::new();
    digest_field(&mut hasher, "sovereign.browser_profile_id.v1");
    digest_field(&mut hasher, project_id);
    digest_field(&mut hasher, repository_id);
    digest_field(&mut hasher, task_id);
    format!("profile-{:x}", hasher.finalize())
}

fn browser_runtime_root(state_path: &Path) -> Result<PathBuf, ControllerError> {
    let parent = state_path.parent().ok_or_else(|| {
        ControllerError::NotReady("StateStore path has no browser runtime parent".to_owned())
    })?;
    let root = parent.join(BROWSER_RUNTIME_DIR);
    fs::create_dir_all(&root)?;
    #[cfg(unix)]
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    let metadata = fs::symlink_metadata(&root)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ControllerError::NotReady(
            "browser runtime root is not a stable directory".to_owned(),
        ));
    }
    let canonical = root.canonicalize()?;
    let canonical_parent = parent.canonicalize()?;
    if canonical.parent() != Some(canonical_parent.as_path()) {
        return Err(ControllerError::NotReady(
            "browser runtime root escaped the Controller state parent".to_owned(),
        ));
    }
    Ok(canonical)
}

fn persistent_profile_root(
    runtime_root: &Path,
    profile_id: &str,
) -> Result<PathBuf, ControllerError> {
    let mut hasher = Sha256::new();
    digest_field(&mut hasher, "sovereign.persistent_browser_root.v1");
    digest_field(&mut hasher, profile_id);
    let leaf = format!("persistent-{:x}", hasher.finalize());
    let root = runtime_root.join(leaf);
    fs::create_dir_all(&root)?;
    #[cfg(unix)]
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    let metadata = fs::symlink_metadata(&root)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ControllerError::NotReady(
            "persistent browser profile root is not a stable directory".to_owned(),
        ));
    }
    let canonical = root.canonicalize()?;
    if canonical.parent() != Some(runtime_root) {
        return Err(ControllerError::NotReady(
            "persistent browser profile root escaped Controller ownership".to_owned(),
        ));
    }
    Ok(canonical)
}

fn task_download_root(
    runtime_root: &Path,
    authority: &BrowserTaskAuthorityV1,
    resource_lease_id: &str,
) -> Result<Option<PathBuf>, ControllerError> {
    if !authority.downloads_allowed {
        if authority.download_root.is_some() {
            return Err(ControllerError::Policy(PolicyError::Denied(
                "denied browser downloads cannot retain a task download-root selector".to_owned(),
            )));
        }
        return Ok(None);
    }
    let selector = authority.download_root.as_deref().ok_or_else(|| {
        ControllerError::Policy(PolicyError::Denied(
            "task-scoped browser downloads require a governed download-root selector".to_owned(),
        ))
    })?;
    let selector_path = Path::new(selector);
    if selector_path.as_os_str().is_empty()
        || selector_path.is_absolute()
        || selector_path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ControllerError::Policy(PolicyError::Denied(
            "browser download-root selector must remain a normalized relative path".to_owned(),
        )));
    }
    let mut hasher = Sha256::new();
    digest_field(&mut hasher, "sovereign.task_browser_download_root.v1");
    digest_field(&mut hasher, selector);
    digest_field(&mut hasher, resource_lease_id);
    let root = runtime_root.join(format!("downloads-{:x}", hasher.finalize()));
    fs::create_dir_all(&root)?;
    #[cfg(unix)]
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    let metadata = fs::symlink_metadata(&root)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ControllerError::NotReady(
            "browser task download root is not a stable directory".to_owned(),
        ));
    }
    let canonical = root.canonicalize()?;
    if canonical.parent() != Some(runtime_root) {
        return Err(ControllerError::NotReady(
            "browser task download root escaped Controller ownership".to_owned(),
        ));
    }
    Ok(Some(canonical))
}

fn opaque_browser_token() -> Result<String, ControllerError> {
    let mut file = File::open("/dev/urandom")?;
    let mut bytes = [0_u8; 32];
    file.read_exact(&mut bytes)?;
    let mut token = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut token, "{byte:02x}").map_err(|_| {
            ControllerError::InvalidPlan("browser token formatting failed".to_owned())
        })?;
    }
    Ok(token)
}

fn token_digest(token: &str) -> String {
    format!("sha256:{:x}", Sha256::digest(token.as_bytes()))
}

fn checked_expiry(now_ms: i64, ttl_ms: i64) -> Result<i64, ControllerError> {
    now_ms
        .checked_add(ttl_ms)
        .ok_or_else(|| ControllerError::InvalidPlan("browser lease expiry overflow".to_owned()))
}

impl Controller {
    /// Persists one explicit persistent-browser-profile grant for the exact current project,
    /// repository, and policy. This API never derives a grant from plan/model/repository text.
    ///
    /// # Errors
    /// Fails closed for stale/mismatched scope, invalid expiry/origins, or persistence failure.
    pub fn persist_browser_profile_grant(
        &mut self,
        grant: &PersistentBrowserProfileGrantV1,
    ) -> Result<(), ControllerError> {
        let now_ms = unix_millis()?;
        grant
            .validate(now_ms)
            .map_err(|error| ControllerError::Policy(PolicyError::Denied(error.to_string())))?;
        let (project_id, policy_digest) = {
            let active = self.active_ref()?;
            (
                required_str(&active.plan_document, "/project/project_id")?.to_owned(),
                active.policy_digest.clone(),
            )
        };
        if grant.project_id != project_id
            || !self
                .active_ref()?
                .repositories
                .contains_key(&grant.repository_id)
            || grant.policy_digest != policy_digest
        {
            return Err(ControllerError::Policy(PolicyError::Denied(
                "persistent browser profile grant does not match exact current Controller scope"
                    .to_owned(),
            )));
        }
        self.persist_runtime_records_with_events(
            &[(
                BROWSER_PROFILE_GRANT_NAMESPACE.to_owned(),
                grant.profile_id.clone(),
                serde_json::to_string(grant)?,
            )],
            &[(
                "browser_profile_grant_persisted".to_owned(),
                grant.profile_id.clone(),
                serde_json::json!({
                    "grant_id": grant.grant_id,
                    "project_id": grant.project_id,
                    "repository_id": grant.repository_id,
                    "profile_id": grant.profile_id,
                    "policy_digest": grant.policy_digest,
                    "expires_at_ms": grant.expires_at_ms,
                }),
            )],
        )?;
        self.checkpoint_now()?;
        Ok(())
    }

    pub(crate) fn active_browser_network_reservation_bytes(
        &self,
        task_id: &str,
    ) -> Result<(u64, u64), ControllerError> {
        let (plan_id, plan_revision, task_contracts) = {
            let active = self.active_ref()?;
            let contracts = active
                .tasks
                .iter()
                .map(|(id, task)| (id.clone(), task.task_contract_digest.clone()))
                .collect::<BTreeMap<_, _>>();
            (active.plan_id.clone(), active.revision, contracts)
        };
        let mut task_reserved = 0_u64;
        let mut goal_reserved = 0_u64;
        for persisted in self
            .state
            .state_records(BROWSER_NETWORK_RESERVATION_NAMESPACE)?
        {
            let reservation: BrowserNetworkReservationV1 =
                serde_json::from_str(&persisted.value_json)?;
            reservation.validate()?;
            let expected_key = revision_scoped_key(
                &reservation.plan_id,
                reservation.plan_revision,
                &reservation.resource_lease_id,
            );
            if persisted.key != expected_key {
                return Err(ControllerError::InvalidPlan(
                    "browser network reservation key does not match its exact plan/lease binding"
                        .to_owned(),
                ));
            }
            if reservation.plan_id != plan_id || reservation.plan_revision != plan_revision {
                continue;
            }
            let expected_contract = task_contracts.get(&reservation.task_id).ok_or_else(|| {
                ControllerError::InvalidPlan(
                    "active browser network reservation targets an unknown task".to_owned(),
                )
            })?;
            if reservation.task_contract_digest != *expected_contract {
                return Err(ControllerError::InvalidPlan(
                    "active browser network reservation has a stale task-contract binding"
                        .to_owned(),
                ));
            }
            if reservation.state != BrowserNetworkReservationStateV1::Active {
                continue;
            }
            goal_reserved = goal_reserved
                .checked_add(reservation.reserved_bytes)
                .ok_or_else(|| {
                    ControllerError::InvalidPlan(
                        "goal browser network reservation total overflowed".to_owned(),
                    )
                })?;
            if reservation.task_id == task_id {
                task_reserved = task_reserved
                    .checked_add(reservation.reserved_bytes)
                    .ok_or_else(|| {
                        ControllerError::InvalidPlan(
                            "task browser network reservation total overflowed".to_owned(),
                        )
                    })?;
            }
        }
        Ok((task_reserved, goal_reserved))
    }

    fn browser_network_reservation_for_residency(
        &self,
        residency: &BrowserResourceResidencyV1,
    ) -> Result<Option<(String, BrowserNetworkReservationV1)>, ControllerError> {
        let key = revision_scoped_key(
            &residency.plan_id,
            residency.plan_revision,
            &residency.policy_lease.lease_id,
        );
        let Some(raw) = self
            .state
            .get_state(BROWSER_NETWORK_RESERVATION_NAMESPACE, &key)?
        else {
            return Ok(None);
        };
        let reservation: BrowserNetworkReservationV1 = serde_json::from_str(&raw)?;
        reservation.validate()?;
        if reservation.plan_id != residency.plan_id
            || reservation.plan_revision != residency.plan_revision
            || reservation.task_id != residency.task_id
            || reservation.task_contract_digest != residency.task_contract_digest
            || reservation.resource_lease_id != residency.policy_lease.lease_id
            || reservation.browser_lease_binding_digest != residency.browser_lease_binding_digest
            || reservation.execution_epoch != residency.execution_epoch
        {
            return Err(ControllerError::InvalidPlan(
                "browser network reservation does not bind the exact durable browser residency"
                    .to_owned(),
            ));
        }
        Ok(Some((key, reservation)))
    }

    fn persist_browser_network_reservation(
        &mut self,
        residency: &BrowserResourceResidencyV1,
        reserved_bytes: u64,
    ) -> Result<(), ControllerError> {
        let key = revision_scoped_key(
            &residency.plan_id,
            residency.plan_revision,
            &residency.policy_lease.lease_id,
        );
        if self
            .state
            .get_state(BROWSER_NETWORK_RESERVATION_NAMESPACE, &key)?
            .is_some()
        {
            return Err(ControllerError::InvalidPlan(
                "browser network reservation already exists for this exact resource lease"
                    .to_owned(),
            ));
        }
        let reservation = BrowserNetworkReservationV1 {
            schema_version: BROWSER_NETWORK_RESERVATION_SCHEMA_VERSION,
            plan_id: residency.plan_id.clone(),
            plan_revision: residency.plan_revision,
            task_id: residency.task_id.clone(),
            task_contract_digest: residency.task_contract_digest.clone(),
            resource_lease_id: residency.policy_lease.lease_id.clone(),
            browser_lease_binding_digest: residency.browser_lease_binding_digest.clone(),
            execution_epoch: residency.execution_epoch,
            reserved_bytes,
            state: BrowserNetworkReservationStateV1::Active,
            settled_bytes: None,
            settlement: None,
            updated_at_ms: unix_millis()?,
        };
        reservation.validate()?;
        let value_json = serde_json::to_string(&reservation)?;
        let binding_key = format!("{BROWSER_NETWORK_RESERVATION_NAMESPACE}:{key}");
        let mut post_image_digests = BTreeMap::new();
        post_image_digests.insert(binding_key, sha256_prefixed(value_json.as_bytes()));
        self.persist_runtime_records_with_events(
            &[(
                BROWSER_NETWORK_RESERVATION_NAMESPACE.to_owned(),
                key,
                value_json,
            )],
            &[(
                "resource_browser_network_reserved".to_owned(),
                residency.task_id.clone(),
                serde_json::json!({
                    "resource_lease_id": residency.policy_lease.lease_id,
                    "reserved_bytes": reserved_bytes,
                    "post_image_digests": post_image_digests,
                }),
            )],
        )?;
        Ok(())
    }

    fn settle_browser_network_reservation_if_present(
        &mut self,
        residency: &BrowserResourceResidencyV1,
        settled_bytes: u64,
        settlement: BrowserNetworkSettlementV1,
    ) -> Result<bool, ControllerError> {
        let Some((key, current)) = self.browser_network_reservation_for_residency(residency)?
        else {
            return Ok(false);
        };
        if current.state == BrowserNetworkReservationStateV1::Settled {
            if current.settled_bytes != Some(settled_bytes)
                || current.settlement != Some(settlement)
            {
                return Err(ControllerError::InvalidPlan(
                    "browser network reservation was already settled with different durable accounting"
                        .to_owned(),
                ));
            }
            return Ok(true);
        }
        if settled_bytes > current.reserved_bytes
            || matches!(settlement, BrowserNetworkSettlementV1::ProvenAbsentZero)
                && settled_bytes != 0
            || matches!(settlement, BrowserNetworkSettlementV1::RecoveryFullReserve)
                && settled_bytes != current.reserved_bytes
        {
            return Err(ControllerError::InvalidPlan(
                "browser network settlement exceeds or contradicts its active reservation"
                    .to_owned(),
            ));
        }
        let next = BrowserNetworkReservationV1 {
            state: BrowserNetworkReservationStateV1::Settled,
            settled_bytes: Some(settled_bytes),
            settlement: Some(settlement),
            updated_at_ms: unix_millis()?,
            ..current
        };
        next.validate()?;
        let value_json = serde_json::to_string(&next)?;
        let binding_key = format!("{BROWSER_NETWORK_RESERVATION_NAMESPACE}:{key}");
        let mut post_image_digests = BTreeMap::new();
        post_image_digests.insert(binding_key, sha256_prefixed(value_json.as_bytes()));
        let additional = NetworkChargePersistence {
            records: vec![(
                BROWSER_NETWORK_RESERVATION_NAMESPACE.to_owned(),
                key,
                value_json,
            )],
            events: vec![(
                "resource_browser_network_settled".to_owned(),
                residency.task_id.clone(),
                serde_json::json!({
                    "resource_lease_id": residency.policy_lease.lease_id,
                    "reserved_bytes": next.reserved_bytes,
                    "settled_bytes": settled_bytes,
                    "settlement": settlement.phase(),
                    "post_image_digests": post_image_digests,
                }),
            )],
        };
        self.persist_network_charge_with_persistence(
            &residency.task_id,
            &format!(
                "browser-network-settlement:{}",
                residency.policy_lease.lease_id
            ),
            "browser_network_budget_charged",
            settlement.phase(),
            settled_bytes,
            additional,
        )?;
        Ok(true)
    }

    fn require_browser_network_reservation_settlement(
        &mut self,
        residency: &BrowserResourceResidencyV1,
        settled_bytes: u64,
        settlement: BrowserNetworkSettlementV1,
    ) -> Result<(), ControllerError> {
        if self.settle_browser_network_reservation_if_present(
            residency,
            settled_bytes,
            settlement,
        )? {
            return Ok(());
        }
        Err(ControllerError::NotReady(
            "active browser session has no durable network reservation to settle".to_owned(),
        ))
    }

    fn legacy_browser_network_reservation_charge_exists(
        &self,
        residency: &BrowserResourceResidencyV1,
    ) -> Result<bool, ControllerError> {
        let action_id = format!("browser-reservation:{}", residency.policy_lease.lease_id);
        for event in self.state.journal_after(0)? {
            if event.entity_type != "controller"
                || event.event_kind != "browser_network_budget_charged"
            {
                continue;
            }
            let payload: Value = serde_json::from_str(&event.payload_json)?;
            if payload.get("action_id").and_then(Value::as_str) != Some(action_id.as_str()) {
                continue;
            }
            if required_str(&payload, "/plan_id")? != residency.plan_id
                || required_u32(&payload, "/plan_revision")? != residency.plan_revision
                || required_str(&payload, "/task_id")? != residency.task_id
            {
                return Err(ControllerError::InvalidPlan(
                    "legacy browser network reservation charge is misbound to recovered residency"
                        .to_owned(),
                ));
            }
            return Ok(true);
        }
        Ok(false)
    }

    pub(crate) fn reconcile_recovered_browser_network_reservation(
        &mut self,
        residency: &BrowserResourceResidencyV1,
    ) -> Result<(), ControllerError> {
        if let Some((_, reservation)) = self.browser_network_reservation_for_residency(residency)? {
            if reservation.state == BrowserNetworkReservationStateV1::Active {
                self.require_browser_network_reservation_settlement(
                    residency,
                    reservation.reserved_bytes,
                    BrowserNetworkSettlementV1::RecoveryFullReserve,
                )?;
            }
            return Ok(());
        }
        if self.legacy_browser_network_reservation_charge_exists(residency)? {
            return Ok(());
        }
        Err(ControllerError::NotReady(
            "recovered browser lease has neither a durable network reservation nor a legacy full-reservation charge"
                .to_owned(),
        ))
    }

    fn browser_task_authority(
        &self,
        task_id: &str,
    ) -> Result<BrowserTaskAuthorityV1, ControllerError> {
        let active = self.active_ref()?;
        if active.validity != PlanValidity::Current {
            return Err(ControllerError::NotReady(
                "browser authority requires the active plan to remain current".to_owned(),
            ));
        }
        let task = active
            .tasks
            .get(task_id)
            .ok_or_else(|| ControllerError::NotReady(format!("unknown browser task {task_id}")))?;
        let plan = &active.plan_document;
        validate_browser_static_plan_safety(plan, &task.task)?;

        let browser_domains = string_set_at(&task.task, "/action_policy/browser/allowed_domains")?;
        let task_hosts = string_set_at(&task.task, "/action_policy/network/allowed_hosts")?;
        let global_hosts = string_set_at(plan, "/policy/network/allowed_hosts")?;
        let task_global_hosts = set_intersection(&task_hosts, &global_hosts);
        let allowed_domains = set_intersection(&browser_domains, &task_global_hosts);
        if allowed_domains.is_empty() || allowed_domains != browser_domains {
            return Err(ControllerError::Policy(PolicyError::Denied(
                "browser domain scope is not an exact subset of active network authority"
                    .to_owned(),
            )));
        }
        let task_schemes = string_set_at(&task.task, "/action_policy/network/allowed_schemes")?;
        let global_schemes = string_set_at(plan, "/policy/network/allowed_schemes")?;
        let allowed_schemes = set_intersection(&task_schemes, &global_schemes)
            .into_iter()
            .filter(|scheme| matches!(scheme.as_str(), "http" | "https"))
            .collect::<BTreeSet<_>>();
        let task_ports = port_set_at(&task.task, "/action_policy/network/allowed_ports")?;
        let global_ports = port_set_at(plan, "/policy/network/allowed_ports")?;
        let allowed_ports = set_intersection(&task_ports, &global_ports);
        let task_methods = string_set_at(&task.task, "/action_policy/network/allowed_methods")?;
        let global_methods = string_set_at(plan, "/policy/network/allowed_methods")?;
        let allowed_methods = set_intersection(&task_methods, &global_methods);
        if allowed_schemes.is_empty() || allowed_ports.is_empty() || allowed_methods.is_empty() {
            return Err(ControllerError::Policy(PolicyError::Denied(
                "browser network scope has an empty governed scheme/port/method intersection"
                    .to_owned(),
            )));
        }
        let max_tabs = required_u32(&task.task, "/action_policy/browser/max_tabs")?;
        if max_tabs != 1 {
            return Err(ControllerError::Policy(PolicyError::Denied(
                "selected browser profile requires exactly one tab".to_owned(),
            )));
        }
        let global_downloads = required_str(plan, "/policy/browser/downloads")?;
        let task_downloads = required_str(&task.task, "/action_policy/browser/downloads")?;
        let downloads_allowed =
            global_downloads == "task_scoped" && task_downloads == "task_scoped";
        if task_downloads != "deny" && !downloads_allowed {
            return Err(ControllerError::Policy(PolicyError::Denied(
                "task download policy exceeds the global browser ceiling".to_owned(),
            )));
        }
        Ok(BrowserTaskAuthorityV1 {
            schema_version: BROWSER_AUTHORITY_SCHEMA_VERSION,
            allowed_domains,
            allowed_schemes,
            allowed_ports,
            allowed_methods,
            follow_redirects: required_bool(plan, "/policy/network/follow_redirects")?
                && required_bool(&task.task, "/action_policy/network/follow_redirects")?,
            max_redirects: required_u32(plan, "/policy/network/max_redirects")?.min(required_u32(
                &task.task,
                "/action_policy/network/max_redirects",
            )?),
            allow_task_loopback: required_bool(plan, "/policy/network/allow_task_loopback")?
                && required_bool(&task.task, "/action_policy/network/allow_task_loopback")?,
            max_tabs,
            downloads_allowed,
            profile_mode: if required_bool(&task.task, "/action_policy/browser/persistent_profile")?
            {
                BrowserProfileMode::Persistent
            } else {
                BrowserProfileMode::Isolated
            },
            download_root: task
                .task
                .pointer("/action_policy/browser/download_root")
                .and_then(Value::as_str)
                .map(str::to_owned),
        })
    }

    fn browser_profile_authority(
        &self,
        task_id: &str,
        authority: &BrowserTaskAuthorityV1,
        runtime_root: &Path,
        now_ms: i64,
    ) -> Result<(BrowserProfileAuthority, BrowserProfileRoot), ControllerError> {
        let active = self.active_ref()?;
        let project_id = required_str(&active.plan_document, "/project/project_id")?;
        let repository = active.single_task_repository(task_id)?;
        let profile_policy = BrowserProfilePolicy::new(
            project_id,
            repository.repository_id.as_str(),
            active.policy_digest.as_str(),
        )
        .map_err(|error| ControllerError::Policy(PolicyError::Denied(error.to_string())))?;
        if authority.profile_mode == BrowserProfileMode::Isolated {
            let profile_authority = profile_policy
                .authorize(BrowserProfileMode::Isolated, None, None, now_ms)
                .map_err(|error| ControllerError::Policy(PolicyError::Denied(error.to_string())))?;
            return Ok((profile_authority, BrowserProfileRoot::Ephemeral));
        }
        let profile_id = profile_id_for(project_id, &repository.repository_id, task_id);
        let raw = self
            .state
            .get_state(BROWSER_PROFILE_GRANT_NAMESPACE, &profile_id)?
            .ok_or_else(|| {
                ControllerError::Policy(PolicyError::Denied(
                    "persistent browser profile requested without an exact durable grant"
                        .to_owned(),
                ))
            })?;
        let grant: PersistentBrowserProfileGrantV1 = serde_json::from_str(&raw)?;
        let profile_authority = profile_policy
            .authorize(
                BrowserProfileMode::Persistent,
                Some(&profile_id),
                Some(&grant),
                now_ms,
            )
            .map_err(|error| ControllerError::Policy(PolicyError::Denied(error.to_string())))?;
        let required_origins = browser_origins(authority);
        if !required_origins.is_subset(&grant.allowed_origins) {
            return Err(ControllerError::Policy(PolicyError::Denied(
                "persistent browser profile grant does not cover the exact active browser origins"
                    .to_owned(),
            )));
        }
        let root = persistent_profile_root(runtime_root, &profile_id)?;
        Ok((
            profile_authority,
            BrowserProfileRoot::CallerOwnedPersistent(root),
        ))
    }

    fn task_loopback_grants(
        authority: &BrowserTaskAuthorityV1,
        resource_lease: &ResourceLeaseV1,
        execution_epoch: i64,
        task_contract_digest: &str,
        expires_at_ms: i64,
    ) -> Vec<TaskLoopbackGrantV1> {
        if !authority.allow_task_loopback {
            return Vec::new();
        }
        authority
            .allowed_domains
            .iter()
            .filter(|host| is_loopback_literal(host))
            .flat_map(|host| {
                authority.allowed_schemes.iter().flat_map(move |scheme| {
                    authority
                        .allowed_ports
                        .iter()
                        .map(move |port| TaskLoopbackGrantV1 {
                            schema_version: TASK_LOOPBACK_GRANT_SCHEMA_VERSION,
                            plan_id: resource_lease.owner.plan_id.clone(),
                            plan_revision: resource_lease.owner.plan_revision,
                            task_id: resource_lease.owner.task_id.clone(),
                            task_contract_digest: task_contract_digest.to_owned(),
                            resource_lease_id: resource_lease.lease_id.clone(),
                            execution_epoch,
                            scheme: scheme.clone(),
                            host: host.clone(),
                            port: *port,
                            expires_at_ms,
                        })
                })
            })
            .collect()
    }

    fn evict_model_before_browser(
        &mut self,
        backend: &dyn ModelBackend,
    ) -> Result<(), ControllerError> {
        let Some(mut residency) = self.resources.model_residency().cloned() else {
            return Ok(());
        };
        if residency.state == ResourceResidencyStateV1::Unknown {
            return Err(ControllerError::NotReady(
                "MODEL physical state is Unknown; browser admission remains blocked".to_owned(),
            ));
        }
        if residency.state == ResourceResidencyStateV1::Reserved {
            residency.state = ResourceResidencyStateV1::Absent;
            residency.updated_at_ms = unix_millis()?;
            self.persist_resource_residency(&residency, "resource_model_absent_for_browser")?;
        } else if residency.state != ResourceResidencyStateV1::Absent {
            residency.state = ResourceResidencyStateV1::Unloading;
            residency.updated_at_ms = unix_millis()?;
            self.persist_resource_residency(&residency, "resource_model_unloading_for_browser")?;
            self.resources.set_model_residency(residency.clone());
            self.checkpoint_now()?;
            if let Err(error) = backend.unload() {
                residency.state = ResourceResidencyStateV1::Unknown;
                residency.updated_at_ms = unix_millis()?;
                self.persist_resource_residency(&residency, "resource_model_unload_unknown")?;
                self.resources.set_model_residency(residency);
                self.checkpoint_now()?;
                return Err(ControllerError::Model(error));
            }
            if backend.residency_proof()? != ModelResidencyProof::Absent {
                residency.state = ResourceResidencyStateV1::Unknown;
                residency.updated_at_ms = unix_millis()?;
                self.persist_resource_residency(&residency, "resource_model_unload_unproven")?;
                self.resources.set_model_residency(residency);
                self.checkpoint_now()?;
                return Err(ControllerError::NotReady(
                    "MODEL absence is unproven; CDP_BROWSER admission remains blocked".to_owned(),
                ));
            }
            residency.state = ResourceResidencyStateV1::Absent;
            residency.updated_at_ms = unix_millis()?;
            self.persist_resource_residency(&residency, "resource_model_absent_for_browser")?;
        }
        self.resources.clear_model_residency();
        let now_ms = unix_millis()?;
        let event = self
            .resources
            .record_eviction(&residency.policy_lease.lease_id, now_ms)
            .ok_or_else(|| {
                ControllerError::NotReady(
                    "logical MODEL lease disappeared before browser handoff".to_owned(),
                )
            })?;
        let mut evicted = residency.policy_lease.clone();
        evicted.state = LeaseStateV1::Evicted;
        evicted.last_used_at_ms = now_ms;
        self.persist_resource_lease_transition(
            &evicted,
            &event,
            "resource_model_evicted_for_browser",
            &residency.task_id,
        )?;
        self.checkpoint_now()?;
        Ok(())
    }

    fn persist_browser_admission(
        &mut self,
        pressure: &sovereign_policy::ResourcePressureEventV1,
        policy_event: &sovereign_policy::ResourcePolicyEventV1,
        lease: &ResourceLeaseV1,
        residency: &BrowserResourceResidencyV1,
    ) -> Result<(), ControllerError> {
        let (pressure_key, lease_key, residency_key, governor_key) = {
            let active = self.active_ref()?;
            (
                active_scoped_key(active, &pressure.event_id),
                active_scoped_key(active, &lease.lease_id),
                active_scoped_key(active, BROWSER_RESIDENCY_KEY),
                active_scoped_key(active, RESOURCE_GOVERNOR_KEY),
            )
        };
        let records = vec![
            (
                RESOURCE_PRESSURE_NAMESPACE.to_owned(),
                pressure_key,
                serde_json::to_string(pressure)?,
            ),
            (
                RESOURCE_GOVERNOR_NAMESPACE.to_owned(),
                governor_key,
                serde_json::to_string(&self.resources.snapshot())?,
            ),
            (
                RESOURCE_LEASE_NAMESPACE.to_owned(),
                lease_key,
                serde_json::to_string(lease)?,
            ),
            (
                RESOURCE_RESIDENCY_NAMESPACE.to_owned(),
                residency_key,
                serde_json::to_string(residency)?,
            ),
        ];
        let post_image_digests = records
            .iter()
            .map(|(namespace, key, value)| {
                (
                    format!("{namespace}:{key}"),
                    sha256_prefixed(value.as_bytes()),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        let mut payload = resource_event_payload(pressure, policy_event);
        let object = payload.as_object_mut().ok_or_else(|| {
            ControllerError::InvalidPlan(
                "browser resource event payload is not an object".to_owned(),
            )
        })?;
        object.insert(
            "browser_residency".to_owned(),
            serde_json::to_value(residency)?,
        );
        object.insert(
            "post_image_digests".to_owned(),
            serde_json::to_value(post_image_digests)?,
        );
        self.persist_runtime_records_with_events(
            &records,
            &[(
                "browser_resource_admitted".to_owned(),
                residency.task_id.clone(),
                payload,
            )],
        )?;
        Ok(())
    }

    fn persist_browser_resource_activity(
        &mut self,
        lease: &ResourceLeaseV1,
        residency: &BrowserResourceResidencyV1,
        policy_event: &ResourcePolicyEventV1,
        event_kind: &str,
    ) -> Result<(), ControllerError> {
        let (lease_key, residency_key, governor_key) = {
            let active = self.active_ref()?;
            (
                active_scoped_key(active, &lease.lease_id),
                active_scoped_key(active, BROWSER_RESIDENCY_KEY),
                active_scoped_key(active, RESOURCE_GOVERNOR_KEY),
            )
        };
        let records = vec![
            (
                RESOURCE_GOVERNOR_NAMESPACE.to_owned(),
                governor_key,
                serde_json::to_string(&self.resources.snapshot())?,
            ),
            (
                RESOURCE_LEASE_NAMESPACE.to_owned(),
                lease_key,
                serde_json::to_string(lease)?,
            ),
            (
                RESOURCE_RESIDENCY_NAMESPACE.to_owned(),
                residency_key,
                serde_json::to_string(residency)?,
            ),
        ];
        let post_image_digests = records
            .iter()
            .map(|(namespace, key, value)| {
                (
                    format!("{namespace}:{key}"),
                    sha256_prefixed(value.as_bytes()),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        self.persist_runtime_records_with_events(
            &records,
            &[(
                event_kind.to_owned(),
                residency.task_id.clone(),
                serde_json::json!({
                    "policy_event": policy_event,
                    "resource_lease": lease,
                    "browser_residency": residency,
                    "post_image_digests": post_image_digests,
                }),
            )],
        )?;
        Ok(())
    }

    fn synchronize_browser_resource_lease_copies(
        session_lease: &mut ResourceLeaseV1,
        residency: &mut BrowserResourceResidencyV1,
        updated_lease: &ResourceLeaseV1,
        now_ms: i64,
    ) -> Result<(), ControllerError> {
        if updated_lease.class != HeavyLeaseClass::CdpBrowser
            || updated_lease.lease_id != session_lease.lease_id
            || updated_lease.owner != session_lease.owner
            || residency.policy_lease.lease_id != session_lease.lease_id
            || residency.browser_lease_id != session_lease.lease_id
            || residency.plan_id != updated_lease.owner.plan_id
            || residency.plan_revision != updated_lease.owner.plan_revision
            || residency.task_id != updated_lease.owner.task_id
            || !matches!(
                updated_lease.state,
                LeaseStateV1::Active | LeaseStateV1::Idle
            )
        {
            return Err(ControllerError::NotReady(
                "browser resource activity transition is not bound to the exact CDP_BROWSER lease"
                    .to_owned(),
            ));
        }
        *session_lease = updated_lease.clone();
        residency.policy_lease = updated_lease.clone();
        residency.updated_at_ms = now_ms;
        Ok(())
    }

    fn live_browser_residency_for_session(
        &self,
        session: &ControllerBrowserSession,
    ) -> Result<BrowserResourceResidencyV1, ControllerError> {
        let residency = self.resources.browser_residency().cloned().ok_or_else(|| {
            ControllerError::NotReady("browser session has no durable residency".to_owned())
        })?;
        if residency.state != BrowserResourceResidencyStateV1::Resident
            || residency.policy_lease != session.resource_lease
            || residency.browser_lease_id != session.browser_lease.lease_id
            || residency.browser_lease_binding_digest != session.browser_lease.binding_digest()
            || residency.execution_epoch != session.execution_epoch
            || residency.task_id != session.task_id
            || session.adapter.is_none()
            || session.gateway.is_none()
            || self
                .resources
                .active_lease(&session.resource_lease.lease_id)
                .as_ref()
                != Some(&session.resource_lease)
        {
            return Err(ControllerError::NotReady(
                "browser session does not match exact live CDP_BROWSER residency".to_owned(),
            ));
        }
        Ok(residency)
    }

    fn transition_browser_resource_activity(
        &mut self,
        session: &mut ControllerBrowserSession,
        activity: BrowserResourceActivity,
        now_ms: i64,
        event_kind: &str,
    ) -> Result<(), ControllerError> {
        let mut residency = self.live_browser_residency_for_session(session)?;

        let previous_resources = self.resources.clone();
        let previous_session_lease = session.resource_lease.clone();
        let policy_event = match activity {
            BrowserResourceActivity::Active => self
                .resources
                .touch(&session.resource_lease.lease_id, now_ms),
            BrowserResourceActivity::Idle => self
                .resources
                .mark_idle(&session.resource_lease.lease_id, now_ms),
        }
        .ok_or_else(|| {
            ControllerError::NotReady(
                "browser resource activity transition lost its logical lease".to_owned(),
            )
        })?;
        let updated_lease = self
            .resources
            .active_lease(&session.resource_lease.lease_id)
            .ok_or_else(|| {
                ControllerError::NotReady(
                    "browser resource activity transition produced no active lease".to_owned(),
                )
            })?;
        let expected_state = match activity {
            BrowserResourceActivity::Active => LeaseStateV1::Active,
            BrowserResourceActivity::Idle => LeaseStateV1::Idle,
        };
        if updated_lease.state != expected_state {
            self.resources = previous_resources;
            return Err(ControllerError::NotReady(
                "browser resource activity transition produced the wrong logical lease state"
                    .to_owned(),
            ));
        }
        if let Err(error) = Self::synchronize_browser_resource_lease_copies(
            &mut session.resource_lease,
            &mut residency,
            &updated_lease,
            now_ms,
        ) {
            self.resources = previous_resources;
            session.resource_lease = previous_session_lease;
            return Err(error);
        }
        if let Err(error) = self.persist_browser_resource_activity(
            &updated_lease,
            &residency,
            &policy_event,
            event_kind,
        ) {
            self.resources = previous_resources;
            session.resource_lease = previous_session_lease;
            return Err(error);
        }
        self.resources.set_browser_residency(residency);
        self.checkpoint_now()?;
        Ok(())
    }

    fn validate_browser_launch_permissions(
        authority: &BrowserTaskAuthorityV1,
        permission_decision: &PermissionDecision,
    ) -> Result<(), ControllerError> {
        if !permission_decision
            .effective
            .contains(Capability::BrowserInteractive)
        {
            return Err(ControllerError::Policy(PolicyError::Denied(
                "browser launch effective permission intersection lacks browser_interactive"
                    .to_owned(),
            )));
        }
        if authority
            .allowed_methods
            .iter()
            .any(|method| browser_method_is_read(method))
            && !permission_decision
                .effective
                .contains(Capability::NetworkRead)
            && !permission_decision
                .effective
                .contains(Capability::NetworkWrite)
        {
            return Err(ControllerError::Policy(PolicyError::Denied(
                "browser read methods require effective network_read or network_write authority"
                    .to_owned(),
            )));
        }
        if authority
            .allowed_methods
            .iter()
            .any(|method| browser_method_is_write(method))
            && !permission_decision
                .effective
                .contains(Capability::NetworkWrite)
            && !permission_decision
                .effective
                .contains(Capability::ExternalSideEffect)
        {
            return Err(ControllerError::Policy(PolicyError::Denied(
                "browser write methods require effective network_write or external_side_effect authority"
                    .to_owned(),
            )));
        }
        Ok(())
    }

    fn browser_launch_authority(
        &self,
        task_id: &str,
        attempt_id: &str,
        tool_manifest: &ToolManifest,
        mut config: BrowserAdapterConfig,
    ) -> Result<BrowserLaunchAuthority, ControllerError> {
        self.require_execution_not_paused()?;
        let execution_epoch = self.state.current_execution_epoch()?;
        let (plan_id, plan_revision, task_contract_digest, max_retained_raw_bytes) = {
            let active = self.active_ref()?;
            if active.validity != PlanValidity::Current {
                return Err(ControllerError::NotReady(
                    "browser launch requires the current active plan".to_owned(),
                ));
            }
            let task = active.tasks.get(task_id).ok_or_else(|| {
                ControllerError::NotReady(format!("unknown browser task {task_id}"))
            })?;
            let attempt = active.attempts.get(attempt_id).ok_or_else(|| {
                ControllerError::NotReady(format!("unknown browser attempt {attempt_id}"))
            })?;
            if attempt.task_id != task_id
                || attempt.task_contract_digest != task.task_contract_digest
                || !matches!(task.state, TaskState::Running | TaskState::Verifying)
                || !matches!(
                    attempt.state,
                    AttemptState::Executing | AttemptState::Verifying
                )
            {
                return Err(ControllerError::NotReady(
                    "browser launch requires the exact active executing/verifying attempt"
                        .to_owned(),
                ));
            }
            (
                active.plan_id.clone(),
                active.revision,
                task.task_contract_digest.clone(),
                required_u64(&task.task, "/resource_budget/max_retained_raw_bytes")?,
            )
        };
        config.max_download_bytes = config.max_download_bytes.min(max_retained_raw_bytes);
        config.validate().map_err(browser_pre_dispatch_error)?;
        let authority = self.browser_task_authority(task_id)?;
        let permission_decision = self.permission_decision_for_task(task_id, tool_manifest)?;
        Self::validate_browser_launch_permissions(&authority, &permission_decision)?;
        let task_budget = self.task_resource_budget(task_id)?;
        if !task_budget.permits(HeavyLeaseClass::CdpBrowser) || task_budget.max_subprocesses == 0 {
            return Err(ControllerError::Policy(PolicyError::ResourceDenied(
                "task resource contract does not authorize one CDP_BROWSER subprocess".to_owned(),
            )));
        }
        if task_budget.max_peak_rss_mib < BROWSER_UNKNOWN_ADMISSION_MIB {
            return Err(ControllerError::Policy(PolicyError::ResourceDenied(
                format!(
                    "task max-RSS contract {} MiB is below conservative uncalibrated CDP_BROWSER admission {} MiB",
                    task_budget.max_peak_rss_mib, BROWSER_UNKNOWN_ADMISSION_MIB
                ),
            )));
        }
        Ok(BrowserLaunchAuthority {
            plan_id,
            plan_revision,
            task_id: task_id.to_owned(),
            attempt_id: attempt_id.to_owned(),
            task_contract_digest,
            max_retained_raw_bytes,
            execution_epoch,
            authority,
            permission_decision,
            task_budget,
            config,
        })
    }

    fn admit_browser_launch(
        &mut self,
        scope: BrowserLaunchAuthority,
        backend: &dyn ModelBackend,
    ) -> Result<AdmittedBrowserLaunch, ControllerError> {
        self.evict_model_before_browser(backend)?;
        let snapshot = self.resource_probe.sample().map_err(|error| {
            ControllerError::Policy(PolicyError::ResourceDenied(format!(
                "live resource pressure probe failed before CDP_BROWSER: {error}"
            )))
        })?;
        let pressure = self.resources.observe_pressure(snapshot);
        let request = ResourceLeaseRequestV1 {
            lease_id: format!(
                "browser:{}:r{}:{}:{}",
                scope.plan_id, scope.plan_revision, scope.task_id, scope.execution_epoch
            ),
            owner: ResourceLeaseOwnerV1 {
                plan_id: scope.plan_id.clone(),
                plan_revision: scope.plan_revision,
                task_id: scope.task_id.clone(),
            },
            class: HeavyLeaseClass::CdpBrowser,
            calibrated: false,
            calibrated_p95_rss_mib: BROWSER_UNKNOWN_ADMISSION_MIB,
            evictable_idle_rss_mib: 0,
            task_budget: scope.task_budget.clone(),
            conditional: ConditionalLeaseContextV1::default(),
            automatic_reload: false,
            disk_expanding: true,
        };
        let admission = self.resources.admit(&request, &pressure);
        let Some(resource_lease) = admission.lease.clone() else {
            self.persist_resource_policy_decision(&pressure, &admission.event, None, None)?;
            return Err(ControllerError::Policy(PolicyError::ResourceDenied(
                format!(
                    "CDP_BROWSER resource admission {:?}: {:?}",
                    admission.status, admission.event
                ),
            )));
        };
        if admission.status != AdmissionStatus::Admitted {
            let _ = self.resources.release(&resource_lease.lease_id);
            return Err(ControllerError::InvalidPlan(
                "CDP_BROWSER admission returned a lease without admitted status".to_owned(),
            ));
        }
        Ok(AdmittedBrowserLaunch {
            scope,
            resource_lease,
            pressure,
            policy_event: admission.event,
        })
    }

    fn prepare_browser_launch_runtime(
        &mut self,
        admitted: AdmittedBrowserLaunch,
    ) -> Result<BrowserLaunchRuntime, ControllerError> {
        let scope = &admitted.scope;
        let now_ms = unix_millis()?;
        let expires_at_ms = checked_expiry(now_ms, 60_000)?;
        let token = opaque_browser_token()?;
        let browser_lease = BrowserLease {
            schema_version: BROWSER_SCHEMA_VERSION,
            lease_id: admitted.resource_lease.lease_id.clone(),
            task_id: scope.task_id.clone(),
            attempt_id: scope.attempt_id.clone(),
            execution_epoch: scope.execution_epoch,
            token: token.clone(),
        };
        browser_lease
            .validate_shape()
            .map_err(|error| ControllerError::NotReady(error.to_string()))?;
        let runtime_root = browser_runtime_root(self.state.path())?;
        let (profile_authority, profile_root) = self.browser_profile_authority(
            &scope.task_id,
            &scope.authority,
            &runtime_root,
            now_ms,
        )?;
        let download_root = task_download_root(
            &runtime_root,
            &scope.authority,
            &admitted.resource_lease.lease_id,
        )?;
        let download_policy = BrowserDownloadPolicyV1 {
            schema_version: BROWSER_DOWNLOAD_POLICY_SCHEMA_VERSION,
            mode: if scope.authority.downloads_allowed {
                BrowserDownloadMode::TaskScoped
            } else {
                BrowserDownloadMode::Deny
            },
            root_authority: download_root
                .as_ref()
                .map(|root| BrowserDownloadRootAuthorityV1 {
                    lease_id: admitted.resource_lease.lease_id.clone(),
                    execution_epoch: scope.execution_epoch,
                    root: root.clone(),
                }),
            retention: BrowserDownloadRetentionPolicyV1 {
                max_file_bytes: scope.config.max_download_bytes,
                allowed_content_types: BTreeSet::new(),
            },
        };
        download_policy
            .validate()
            .map_err(|error| ControllerError::Policy(PolicyError::Denied(error.to_string())))?;
        let max_network_bytes = self.network_remaining(&scope.task_id, "browser network")?;
        let task_loopback_grants = Self::task_loopback_grants(
            &scope.authority,
            &admitted.resource_lease,
            scope.execution_epoch,
            &scope.task_contract_digest,
            expires_at_ms,
        );
        let gateway_scope = OwnedTaskLoopbackScope {
            plan_id: scope.plan_id.clone(),
            plan_revision: scope.plan_revision,
            task_id: scope.task_id.clone(),
            task_contract_digest: scope.task_contract_digest.clone(),
            resource_lease_id: admitted.resource_lease.lease_id.clone(),
            execution_epoch: scope.execution_epoch,
        };
        let gateway_authority = BrowserGatewayAuthority::new(
            &scope.authority,
            task_loopback_grants.clone(),
            gateway_scope,
            max_network_bytes,
            now_ms,
        )
        .map_err(ControllerError::Tool)?;
        let gateway_capability = BrowserGatewayCapabilityBinding {
            lease_id: admitted.resource_lease.lease_id.clone(),
            execution_epoch: scope.execution_epoch,
            token_digest: token_digest(&token),
            expires_at_ms,
        };
        let (gateway, loopback_capability) =
            BrowserGateway::bind(gateway_authority, &gateway_capability)
                .map_err(ControllerError::Tool)?;
        Ok(BrowserLaunchRuntime {
            admitted,
            browser_lease,
            profile_authority,
            runtime_root,
            profile_root,
            download_root,
            download_policy,
            max_network_bytes,
            task_loopback_grants,
            gateway,
            loopback_capability,
            now_ms,
        })
    }

    fn browser_launch_options(runtime: &BrowserLaunchRuntime) -> BrowserLaunchOptions {
        BrowserLaunchOptions {
            caller_chrome_args: vec![
                format!(
                    "--proxy-server=http://127.0.0.1:{}",
                    runtime.loopback_capability.localhost_port
                ),
                "--proxy-bypass-list=<-loopback>".to_owned(),
                "--disable-quic".to_owned(),
            ],
            download_policy: if runtime.admitted.scope.authority.downloads_allowed {
                BrowserDownloadPolicy::Allow
            } else {
                BrowserDownloadPolicy::Deny
            },
            download_root: runtime.download_root.clone(),
            profile_root: runtime.profile_root.clone(),
            proxy_auth: Some(BrowserProxyAuthBinding {
                origin: format!(
                    "http://127.0.0.1:{}",
                    runtime.loopback_capability.localhost_port
                ),
                scheme: "basic".to_owned(),
                realm: BROWSER_PROXY_AUTH_REALM.to_owned(),
                username: BROWSER_PROXY_AUTH_USERNAME.to_owned(),
            }),
        }
    }

    fn prepare_browser_process(
        runtime: BrowserLaunchRuntime,
        chrome_path: &Path,
    ) -> Result<PreparedBrowserSession, ControllerError> {
        let launch_options = Self::browser_launch_options(&runtime);
        let adapter_config = runtime.admitted.scope.config.clone();
        let mut prepared = BrowserAdapter::prepare_launch(
            chrome_path,
            &runtime.runtime_root,
            &runtime.browser_lease,
            runtime.admitted.scope.config.clone(),
            launch_options,
        )
        .map_err(|error| ControllerError::NotReady(error.to_string()))?;
        prepared
            .set_request_method_ceiling(runtime.admitted.scope.authority.allowed_methods.clone())
            .map_err(browser_pre_dispatch_error)?;
        let profile_path = prepared.profile_root().to_path_buf();
        if prepared.download_root().map(Path::to_path_buf) != runtime.download_root {
            return Err(ControllerError::NotReady(
                "browser adapter changed the exact Controller-owned task download root".to_owned(),
            ));
        }
        let isolation = BrowserIsolationRequest {
            profile_root: profile_path.clone(),
            download_root: runtime.download_root.clone(),
            loopback_capability: runtime.loopback_capability.clone(),
            now_ms: runtime.now_ms,
        };
        let sandbox = MacBrowserSandboxExecBackend::detect()
            .map_err(|error| ControllerError::Policy(PolicyError::Denied(error.to_string())))?;
        let isolated = sandbox
            .isolate(
                &prepared.process_spec().executable,
                &prepared.process_spec().args,
                &isolation,
            )
            .map_err(|error| ControllerError::Policy(PolicyError::Denied(error.to_string())))?;
        let residency = BrowserResourceResidencyV1 {
            schema_version: BROWSER_RESOURCE_RESIDENCY_SCHEMA_VERSION,
            plan_id: runtime.admitted.scope.plan_id.clone(),
            plan_revision: runtime.admitted.scope.plan_revision,
            task_id: runtime.admitted.scope.task_id.clone(),
            task_contract_digest: runtime.admitted.scope.task_contract_digest.clone(),
            execution_epoch: runtime.admitted.scope.execution_epoch,
            policy_lease: runtime.admitted.resource_lease.clone(),
            browser_lease_id: runtime.browser_lease.lease_id.clone(),
            browser_lease_binding_digest: runtime.browser_lease.binding_digest(),
            loopback_capability: runtime.loopback_capability.clone(),
            state: BrowserResourceResidencyStateV1::Reserved,
            process_group_id: None,
            process_group_leader_identity: None,
            private_parent: runtime.runtime_root,
            profile_root: profile_path,
            download_root: runtime.download_root.clone(),
            ephemeral_profile: matches!(
                runtime.profile_authority,
                BrowserProfileAuthority::Isolated
            ),
            updated_at_ms: runtime.now_ms,
        };
        Ok(PreparedBrowserSession {
            scope: runtime.admitted.scope,
            resource_lease: runtime.admitted.resource_lease,
            browser_lease: runtime.browser_lease,
            profile_authority: runtime.profile_authority,
            loopback_capability: runtime.loopback_capability,
            task_loopback_grants: runtime.task_loopback_grants,
            download_root: runtime.download_root,
            download_policy: runtime.download_policy,
            max_network_bytes: runtime.max_network_bytes,
            adapter_config,
            gateway: runtime.gateway,
            prepared,
            isolated: IsolatedCommand {
                executable: isolated.executable,
                args: isolated.args,
            },
            residency,
            pressure: runtime.admitted.pressure,
            policy_event: runtime.admitted.policy_event,
        })
    }

    fn spawn_prepared_browser_adapter(
        &mut self,
        prepared: PreparedBrowserLaunch,
        isolated: &IsolatedCommand,
        residency: &mut BrowserResourceResidencyV1,
    ) -> Result<BrowserAdapter, ControllerError> {
        match BrowserAdapter::spawn_preisolated(prepared, isolated) {
            Ok(adapter) => Ok(adapter),
            Err(failure) => {
                let message = failure.error().to_string();
                match failure.state() {
                    BrowserSpawnState::NeverSpawned | BrowserSpawnState::ProvenAbsent => {
                        self.release_proven_absent_browser_launch(
                            residency,
                            "resource_browser_spawn_absent",
                        )?;
                        Err(ControllerError::NotReady(format!(
                            "browser launch failed with exact physical absence proven: {message}"
                        )))
                    }
                    BrowserSpawnState::Unknown { binding } => {
                        if let Some(binding) = binding {
                            residency.process_group_id = Some(binding.process_group_id);
                            residency.process_group_leader_identity =
                                Some(binding.process_group_identity.clone());
                        }
                        residency.state = BrowserResourceResidencyStateV1::Unknown;
                        residency.updated_at_ms = unix_millis()?;
                        self.persist_browser_resource_residency(
                            residency,
                            "resource_browser_spawn_unknown",
                        )?;
                        self.resources.set_browser_residency(residency.clone());
                        self.checkpoint_now()?;
                        Err(ControllerError::NotReady(format!(
                            "browser launch outcome is physically ambiguous and remains held for exact recovery: {message}"
                        )))
                    }
                }
            }
        }
    }

    fn activate_prepared_browser_session(
        &mut self,
        prepared: PreparedBrowserSession,
    ) -> Result<ControllerBrowserSession, ControllerError> {
        let PreparedBrowserSession {
            scope,
            resource_lease,
            browser_lease,
            profile_authority,
            loopback_capability,
            task_loopback_grants,
            download_root,
            download_policy,
            max_network_bytes,
            adapter_config,
            gateway,
            prepared,
            isolated,
            mut residency,
            pressure,
            policy_event,
        } = prepared;
        self.persist_browser_admission(&pressure, &policy_event, &resource_lease, &residency)?;
        self.resources.set_browser_residency(residency.clone());
        if let Err(error) = self.checkpoint_now() {
            self.release_proven_absent_browser_launch(
                &mut residency,
                "resource_browser_admission_checkpoint_failed",
            )?;
            return Err(error);
        }
        if let Err(error) = self.persist_browser_network_reservation(&residency, max_network_bytes)
        {
            self.release_proven_absent_browser_launch(
                &mut residency,
                "resource_browser_network_reservation_failed",
            )?;
            return Err(error);
        }
        let adapter = self.spawn_prepared_browser_adapter(prepared, &isolated, &mut residency)?;
        residency.process_group_id = Some(adapter.process_group_id());
        residency.process_group_leader_identity = Some(adapter.process_group_identity().to_owned());
        residency.state = BrowserResourceResidencyStateV1::Resident;
        residency.updated_at_ms = unix_millis()?;
        self.persist_browser_resource_residency(&residency, "resource_browser_resident")?;
        self.resources.set_browser_residency(residency);
        self.checkpoint_now()?;
        let mut session = ControllerBrowserSession {
            plan_id: scope.plan_id,
            plan_revision: scope.plan_revision,
            task_id: scope.task_id,
            task_contract_digest: scope.task_contract_digest,
            attempt_id: scope.attempt_id,
            execution_epoch: scope.execution_epoch,
            resource_lease,
            browser_lease,
            permission_decision: scope.permission_decision,
            authority: scope.authority,
            profile_authority,
            loopback_capability,
            task_loopback_grants,
            download_root,
            download_policy,
            max_retained_raw_bytes: scope.max_retained_raw_bytes,
            retained_download_bytes: 0,
            reserved_network_bytes: max_network_bytes,
            sensitive_page_observed: false,
            adapter_config,
            adapter: Some(adapter),
            gateway: Some(gateway),
        };
        self.transition_browser_resource_activity(
            &mut session,
            BrowserResourceActivity::Idle,
            unix_millis()?,
            "resource_browser_idle_after_launch",
        )?;
        Ok(session)
    }

    /// Admits, isolates, and launches one governed single-tab CDP browser for an active attempt.
    /// MODEL is physically unloaded first whenever it is still Controller-resident, so the initial
    /// selected M1/8GB implementation does not assume conditional MODEL+browser concurrency.
    ///
    /// # Errors
    /// Fails closed for stale task/attempt authority, missing browser/network permission, resource
    /// pressure, missing persistent-profile grant, isolation failure, or browser launch ambiguity.
    #[allow(clippy::too_many_arguments)]
    pub fn acquire_browser_session(
        &mut self,
        task_id: &str,
        attempt_id: &str,
        tool_manifest: &ToolManifest,
        backend: &dyn ModelBackend,
        chrome_path: &Path,
        config: BrowserAdapterConfig,
    ) -> Result<ControllerBrowserSession, ControllerError> {
        let scope = self.browser_launch_authority(task_id, attempt_id, tool_manifest, config)?;
        let admitted = self.admit_browser_launch(scope, backend)?;
        let lease_id = admitted.resource_lease.lease_id.clone();
        let runtime = match self.prepare_browser_launch_runtime(admitted) {
            Ok(runtime) => runtime,
            Err(error) => {
                let _ = self.resources.release(&lease_id);
                return Err(error);
            }
        };
        let prepared = match Self::prepare_browser_process(runtime, chrome_path) {
            Ok(prepared) => prepared,
            Err(error) => {
                let _ = self.resources.release(&lease_id);
                return Err(error);
            }
        };
        self.activate_prepared_browser_session(prepared)
    }

    fn validate_browser_session_for_action(
        &self,
        session: &ControllerBrowserSession,
        tool_manifest: &ToolManifest,
    ) -> Result<PermissionDecision, ControllerError> {
        let active = self.active_ref()?;
        let task = active.tasks.get(&session.task_id).ok_or_else(|| {
            ControllerError::NotReady("browser session task disappeared".to_owned())
        })?;
        let attempt = active.attempts.get(&session.attempt_id).ok_or_else(|| {
            ControllerError::NotReady("browser session attempt disappeared".to_owned())
        })?;
        if active.validity != PlanValidity::Current
            || active.plan_id != session.plan_id
            || active.revision != session.plan_revision
            || task.task_contract_digest != session.task_contract_digest
            || attempt.task_id != session.task_id
            || attempt.task_contract_digest != session.task_contract_digest
            || !matches!(task.state, TaskState::Running | TaskState::Verifying)
            || !matches!(
                attempt.state,
                AttemptState::Executing | AttemptState::Verifying
            )
            || self.state.current_execution_epoch()? != session.execution_epoch
            || session.browser_lease.lease_id != session.resource_lease.lease_id
            || session.browser_lease.task_id != session.task_id
            || session.browser_lease.attempt_id != session.attempt_id
            || session.browser_lease.execution_epoch != session.execution_epoch
            || self
                .resources
                .active_lease(&session.resource_lease.lease_id)
                .as_ref()
                != Some(&session.resource_lease)
        {
            return Err(ControllerError::NotReady(
                "browser action session is stale for the exact active task/attempt/resource authority"
                    .to_owned(),
            ));
        }
        session
            .browser_lease
            .validate_shape()
            .map_err(browser_pre_dispatch_error)?;
        session
            .loopback_capability
            .validate(unix_millis()?)
            .map_err(|error| ControllerError::Policy(PolicyError::Denied(error.to_string())))?;
        let residency = self.resources.browser_residency().ok_or_else(|| {
            ControllerError::NotReady("browser action has no durable residency".to_owned())
        })?;
        if residency.state != BrowserResourceResidencyStateV1::Resident
            || residency.policy_lease != session.resource_lease
            || residency.browser_lease_id != session.browser_lease.lease_id
            || residency.browser_lease_binding_digest != session.browser_lease.binding_digest()
            || residency.loopback_capability != session.loopback_capability
        {
            return Err(ControllerError::NotReady(
                "browser action session disagrees with exact durable resident process authority"
                    .to_owned(),
            ));
        }
        let decision = self.permission_decision_for_task(&session.task_id, tool_manifest)?;
        if decision != session.permission_decision {
            return Err(ControllerError::NotReady(
                "browser action permission decision drifted from the launch-time exact intersection"
                    .to_owned(),
            ));
        }
        Ok(decision)
    }

    fn browser_download_accounting(
        &self,
        session: &ControllerBrowserSession,
        record_prefix: &str,
        record_key: &str,
    ) -> Result<(u64, Option<BrowserDownloadRecordV1>), ControllerError> {
        let mut retained_total = 0_u64;
        let mut existing = None;
        for persisted in self
            .state
            .state_records(BROWSER_DOWNLOAD_RECORD_NAMESPACE)?
        {
            if !persisted.key.starts_with(record_prefix) {
                continue;
            }
            let record: BrowserDownloadRecordV1 = serde_json::from_str(&persisted.value_json)?;
            if record.schema_version != BROWSER_DOWNLOAD_RECORD_SCHEMA_VERSION
                || record.plan_id != session.plan_id
                || record.plan_revision != session.plan_revision
                || record.task_id != session.task_id
                || record.task_contract_digest != session.task_contract_digest
                || record.execution_epoch < 0
                || record.bytes == 0
                || !record.sha256.starts_with("sha256:")
                || !record.relative_path_digest.starts_with("sha256:")
            {
                return Err(ControllerError::NotReady(
                    "browser retained-download accounting contains an invalid active-task record"
                        .to_owned(),
                ));
            }
            retained_total = retained_total.checked_add(record.bytes).ok_or_else(|| {
                ControllerError::NotReady(
                    "browser retained-download accounting overflowed its durable byte total"
                        .to_owned(),
                )
            })?;
            if persisted.key == record_key {
                existing = Some(record);
            }
        }
        Ok((retained_total, existing))
    }

    fn persist_browser_download_record(
        &mut self,
        session: &ControllerBrowserSession,
        receipt: &DownloadReceipt,
    ) -> Result<u64, ControllerError> {
        let relative_path = receipt.relative_path.to_str().ok_or_else(|| {
            ControllerError::NotReady(
                "browser download path is not valid UTF-8 for durable retention accounting"
                    .to_owned(),
            )
        })?;
        let relative_path_digest = sha256_prefixed(relative_path.as_bytes());
        let logical_prefix = format!("{}:download:", session.task_id);
        let record_prefix =
            revision_scoped_key(&session.plan_id, session.plan_revision, &logical_prefix);
        let record_key = revision_scoped_key(
            &session.plan_id,
            session.plan_revision,
            &format!("{}:download:{relative_path_digest}", session.task_id),
        );
        let (retained_total, existing) =
            self.browser_download_accounting(session, &record_prefix, &record_key)?;
        if let Some(existing) = existing {
            if existing.plan_id != session.plan_id
                || existing.plan_revision != session.plan_revision
                || existing.task_id != session.task_id
                || existing.task_contract_digest != session.task_contract_digest
                || existing.relative_path_digest != relative_path_digest
                || existing.lease_id != receipt.lease_id
                || existing.lease_binding_digest != receipt.lease_binding_digest
                || existing.execution_epoch != receipt.execution_epoch
                || existing.bytes != receipt.bytes
                || existing.sha256 != receipt.sha256
                || existing.content_type != receipt.content_type
            {
                return Err(ControllerError::InvalidPlan(
                    "durable browser download record drifted from the exact retained receipt"
                        .to_owned(),
                ));
            }
            return Ok(retained_total);
        }
        let next_total = retained_total.checked_add(receipt.bytes).ok_or_else(|| {
            ControllerError::Policy(PolicyError::ResourceDenied(
                "browser retained raw-byte quota arithmetic overflowed".to_owned(),
            ))
        })?;
        if next_total > session.max_retained_raw_bytes {
            return Err(ControllerError::Policy(PolicyError::ResourceDenied(
                format!(
                    "browser retained raw bytes {next_total} exceed task ceiling {}",
                    session.max_retained_raw_bytes
                ),
            )));
        }

        self.persist_new_browser_download_record(
            session,
            receipt,
            &relative_path_digest,
            record_key,
            next_total,
        )?;
        Ok(next_total)
    }

    fn persist_new_browser_download_record(
        &mut self,
        session: &ControllerBrowserSession,
        receipt: &DownloadReceipt,
        relative_path_digest: &str,
        record_key: String,
        next_total: u64,
    ) -> Result<(), ControllerError> {
        let record = BrowserDownloadRecordV1 {
            schema_version: BROWSER_DOWNLOAD_RECORD_SCHEMA_VERSION,
            plan_id: session.plan_id.clone(),
            plan_revision: session.plan_revision,
            task_id: session.task_id.clone(),
            task_contract_digest: session.task_contract_digest.clone(),
            relative_path_digest: relative_path_digest.to_owned(),
            lease_id: receipt.lease_id.clone(),
            lease_binding_digest: receipt.lease_binding_digest.clone(),
            execution_epoch: receipt.execution_epoch,
            bytes: receipt.bytes,
            sha256: receipt.sha256.clone(),
            content_type: receipt.content_type.clone(),
            updated_at_ms: unix_millis()?,
        };
        let (previous_task_budget, previous_goal_budget) = {
            let active = self.active_ref()?;
            let task = active.tasks.get(&session.task_id).ok_or_else(|| {
                ControllerError::InvalidPlan("browser download task disappeared".to_owned())
            })?;
            (
                task.autonomy_budget.clone().ok_or_else(|| {
                    ControllerError::NotReady(
                        "browser download requires a durable task autonomy budget".to_owned(),
                    )
                })?,
                active.goal_autonomy_budget.clone(),
            )
        };
        let mut task_budget = previous_task_budget.clone();
        let mut goal_budget = previous_goal_budget.clone();
        task_budget.validate()?;
        goal_budget.validate()?;
        task_budget.charge_disk_write_bytes(receipt.bytes)?;
        goal_budget.charge_disk_write_bytes(receipt.bytes)?;
        {
            let active = self.active_mut()?;
            let task = active.tasks.get_mut(&session.task_id).ok_or_else(|| {
                ControllerError::InvalidPlan("browser download task disappeared".to_owned())
            })?;
            task.autonomy_budget = Some(task_budget.clone());
            active.goal_autonomy_budget = goal_budget.clone();
        }
        let persistence = self.persist_charged_browser_download_record(
            session,
            receipt,
            record_key,
            &record,
            next_total,
            (&task_budget, &goal_budget),
        );
        if let Err(error) = persistence {
            let active = self.active_mut()?;
            let task = active.tasks.get_mut(&session.task_id).ok_or_else(|| {
                ControllerError::InvalidPlan("browser download task disappeared".to_owned())
            })?;
            task.autonomy_budget = Some(previous_task_budget);
            active.goal_autonomy_budget = previous_goal_budget;
            return Err(error);
        }
        Ok(())
    }

    fn persist_charged_browser_download_record(
        &mut self,
        session: &ControllerBrowserSession,
        receipt: &DownloadReceipt,
        record_key: String,
        record: &BrowserDownloadRecordV1,
        next_total: u64,
        budgets: (&AutonomyBudgetV1, &AutonomyBudgetV1),
    ) -> Result<(), ControllerError> {
        let (task_budget, goal_budget) = budgets;
        let task = self
            .active_ref()?
            .tasks
            .get(&session.task_id)
            .ok_or_else(|| {
                ControllerError::InvalidPlan("browser download task disappeared".to_owned())
            })?;
        let task_runtime = serde_json::to_value(task)?;
        let task_json = serde_json::to_string(task)?;
        let value_json = serde_json::to_string(record)?;
        self.persist_runtime_records_with_events(
            &[
                (
                    "controller.task".to_owned(),
                    session.task_id.clone(),
                    task_json,
                ),
                (
                    BROWSER_DOWNLOAD_RECORD_NAMESPACE.to_owned(),
                    record_key,
                    value_json,
                ),
            ],
            &[(
                "browser_download_retained".to_owned(),
                session.task_id.clone(),
                serde_json::json!({
                    "relative_path_digest": record.relative_path_digest,
                    "lease_id": receipt.lease_id,
                    "lease_binding_digest": receipt.lease_binding_digest,
                    "execution_epoch": receipt.execution_epoch,
                    "bytes": receipt.bytes,
                    "disk_write_bytes_charged": receipt.bytes,
                    "sha256": receipt.sha256,
                    "content_type": receipt.content_type,
                    "retained_task_bytes": next_total,
                    "max_retained_raw_bytes": session.max_retained_raw_bytes,
                    "auto_opened_or_executed": receipt.auto_opened_or_executed,
                    "task_runtime": task_runtime,
                    "autonomy_budget_digest": digest_json(&serde_json::to_value(task_budget)?)?,
                    "goal_autonomy_budget": goal_budget,
                    "goal_autonomy_budget_digest": digest_json(&serde_json::to_value(goal_budget)?)?,
                }),
            )],
        )?;
        Ok(())
    }

    fn browser_download_terminal_path(
        browser_lease: &BrowserLease,
        execution_epoch: i64,
        terminal: &BrowserDownloadTerminalObservation,
    ) -> Result<PathBuf, ControllerError> {
        if terminal.schema_version != BROWSER_SCHEMA_VERSION
            || terminal.lease_id != browser_lease.lease_id
            || terminal.lease_binding_digest != browser_lease.binding_digest()
            || terminal.execution_epoch != execution_epoch
        {
            return Err(ControllerError::NotReady(
                "browser download terminal disagrees with exact Controller session authority"
                    .to_owned(),
            ));
        }
        let guid_path = PathBuf::from(&terminal.guid);
        let mut components = guid_path.components();
        if terminal.guid.is_empty()
            || !matches!(components.next(), Some(Component::Normal(_)))
            || components.next().is_some()
            || terminal.relative_path != guid_path
        {
            return Err(ControllerError::NotReady(
                "browser download terminal did not bind one exact GUID-named relative path"
                    .to_owned(),
            ));
        }
        Ok(guid_path)
    }

    fn discard_browser_download_leaf(
        policy: &BrowserDownloadPolicyV1,
        relative_path: &Path,
    ) -> Result<(), ControllerError> {
        let exact_path = policy
            .authorize_relative_path(relative_path)
            .map_err(|error| ControllerError::Policy(PolicyError::Denied(error.to_string())))?;
        match fs::symlink_metadata(&exact_path) {
            Ok(metadata) if metadata.is_dir() => Err(ControllerError::NotReady(
                "rejected browser download path became a directory; recursive cleanup is refused"
                    .to_owned(),
            )),
            Ok(_) => {
                fs::remove_file(&exact_path)?;
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(ControllerError::Io(error)),
        }
    }

    fn browser_download_root_for_session(
        session: &ControllerBrowserSession,
    ) -> Result<PathBuf, ControllerError> {
        session
            .download_policy
            .validate()
            .map_err(|error| ControllerError::Policy(PolicyError::Denied(error.to_string())))?;
        let root_authority = session
            .download_policy
            .root_authority
            .as_ref()
            .ok_or_else(|| {
                ControllerError::Policy(PolicyError::Denied(
                    "browser downloads are disabled for this task".to_owned(),
                ))
            })?;
        if session.download_policy.mode != BrowserDownloadMode::TaskScoped
            || root_authority.lease_id != session.resource_lease.lease_id
            || root_authority.execution_epoch != session.execution_epoch
            || session.download_root.as_ref() != Some(&root_authority.root)
        {
            return Err(ControllerError::NotReady(
                "browser download policy drifted from the exact live lease/epoch/root authority"
                    .to_owned(),
            ));
        }
        Ok(root_authority.root.clone())
    }

    /// Waits for one exact Chrome download terminal and records only a mechanically completed GUID
    /// through Controller-owned policy and durable task-scoped retained-raw accounting. The file is
    /// hashed as bytes only; it is never opened as a document or program, and browser/page/download
    /// content cannot grant new authority.
    ///
    /// # Errors
    /// Fails closed for stale session/permission/lease bindings, disabled downloads, canceled or
    /// malformed terminal observations, path escape, sensitive/credential-bearing retention,
    /// file/type/size violations, aggregate retained-raw quota exhaustion, or durable accounting
    /// failure. Timeout/crash/cancellation never hashes or accounts a partial file.
    pub fn record_browser_download(
        &mut self,
        session: &mut ControllerBrowserSession,
        tool_manifest: &ToolManifest,
        content_type: &str,
        credential_bearing: bool,
    ) -> Result<DownloadReceipt, ControllerError> {
        self.record_browser_download_with_activity(
            session,
            tool_manifest,
            content_type,
            credential_bearing,
            BrowserDownloadActivity::Standalone,
        )
    }

    fn record_browser_download_with_activity(
        &mut self,
        session: &mut ControllerBrowserSession,
        tool_manifest: &ToolManifest,
        content_type: &str,
        credential_bearing: bool,
        activity: BrowserDownloadActivity,
    ) -> Result<DownloadReceipt, ControllerError> {
        self.require_execution_not_paused()?;
        let _permission_decision =
            self.validate_browser_session_for_action(session, tool_manifest)?;
        let download_root = Self::browser_download_root_for_session(session)?;
        if activity == BrowserDownloadActivity::Standalone {
            self.transition_browser_resource_activity(
                session,
                BrowserResourceActivity::Active,
                unix_millis()?,
                "resource_browser_touched_for_download",
            )?;
        }
        let terminal = session
            .adapter
            .as_mut()
            .ok_or_else(|| ControllerError::NotReady("browser adapter is unavailable".to_owned()))?
            .next_download_terminal(
                &session.browser_lease,
                session.adapter_config.request_timeout_ms,
            )
            .map_err(browser_pre_dispatch_error)?;
        let relative_path = Self::browser_download_terminal_path(
            &session.browser_lease,
            session.execution_epoch,
            &terminal,
        )?;
        if terminal.state == BrowserDownloadTerminalState::Canceled {
            Self::discard_browser_download_leaf(&session.download_policy, &relative_path)?;
            return Err(ControllerError::NotReady(
                "browser download was canceled before durable retention".to_owned(),
            ));
        }
        let expected_path = session
            .download_policy
            .authorize_relative_path(&relative_path)
            .map_err(|error| ControllerError::Policy(PolicyError::Denied(error.to_string())))?;
        let receipt = match session
            .adapter
            .as_ref()
            .ok_or_else(|| ControllerError::NotReady("browser adapter is unavailable".to_owned()))?
            .record_download(&session.browser_lease, &relative_path, content_type)
            .map_err(browser_pre_dispatch_error)
        {
            Ok(receipt) => receipt,
            Err(error) => {
                Self::discard_browser_download_leaf(&session.download_policy, &relative_path)?;
                return Err(error);
            }
        };
        if download_root.join(&receipt.relative_path) != expected_path
            || receipt.relative_path != relative_path
            || receipt.lease_id != session.browser_lease.lease_id
            || receipt.lease_binding_digest != session.browser_lease.binding_digest()
            || receipt.execution_epoch != session.execution_epoch
            || receipt.auto_opened_or_executed
        {
            Self::discard_browser_download_leaf(&session.download_policy, &relative_path)?;
            return Err(ControllerError::NotReady(
                "browser download receipt disagrees with exact Controller session authority"
                    .to_owned(),
            ));
        }
        if let Err(error) = session
            .download_policy
            .retention
            .authorize(
                receipt.bytes,
                &receipt.content_type,
                credential_bearing || session.sensitive_page_observed,
            )
            .map_err(|error| ControllerError::Policy(PolicyError::Denied(error.to_string())))
        {
            Self::discard_browser_download_leaf(&session.download_policy, &relative_path)?;
            return Err(error);
        }
        let retained = match self.persist_browser_download_record(session, &receipt) {
            Ok(retained) => retained,
            Err(error) => {
                Self::discard_browser_download_leaf(&session.download_policy, &relative_path)?;
                return Err(error);
            }
        };
        session.retained_download_bytes = retained;
        self.checkpoint_now()?;
        if activity == BrowserDownloadActivity::Standalone {
            self.transition_browser_resource_activity(
                session,
                BrowserResourceActivity::Idle,
                unix_millis()?,
                "resource_browser_idle_after_download",
            )?;
        }
        Ok(receipt)
    }

    fn authorize_browser_url_scope(
        session: &ControllerBrowserSession,
        url: &str,
    ) -> Result<BrowserDestinationV1, ControllerError> {
        let parsed = browser_destination(url)?;
        let destination = &parsed.destination;
        if !session
            .authority
            .allowed_schemes
            .contains(&destination.scheme)
            || !session.authority.allowed_ports.contains(&destination.port)
            || !session.authority.permits_domain(&destination.host)
        {
            return Err(ControllerError::Policy(PolicyError::Denied(
                "browser destination exceeds exact task scheme/domain/port authority".to_owned(),
            )));
        }
        if loopback_ip(&destination.host).is_some() {
            if !session.authority.allow_task_loopback {
                return Err(ControllerError::Policy(PolicyError::Denied(
                    "browser loopback destination requires explicit task-loopback authority"
                        .to_owned(),
                )));
            }
            let scope = TaskLoopbackScope {
                plan_id: &session.plan_id,
                plan_revision: session.plan_revision,
                task_id: &session.task_id,
                task_contract_digest: &session.task_contract_digest,
                resource_lease_id: &session.resource_lease.lease_id,
                execution_epoch: session.execution_epoch,
            };
            let grant = session
                .task_loopback_grants
                .iter()
                .find(|grant| {
                    grant.scheme == destination.scheme
                        && grant.host == destination.host
                        && grant.port == destination.port
                })
                .ok_or_else(|| {
                    ControllerError::Policy(PolicyError::Denied(
                        "browser loopback destination lacks an exact current task grant".to_owned(),
                    ))
                })?;
            grant
                .authorize(&scope, destination, unix_millis()?)
                .map_err(|error| ControllerError::Policy(PolicyError::Denied(error.to_string())))?;
        } else {
            session
                .authority
                .public_network_policy()?
                .authorize_destination(destination)?;
        }
        Ok(parsed)
    }

    fn authorize_browser_method(
        session: &ControllerBrowserSession,
        method: &str,
    ) -> Result<(), ControllerError> {
        let method = method.to_ascii_uppercase();
        if !session.authority.allowed_methods.contains(&method) {
            return Err(ControllerError::Policy(PolicyError::Denied(format!(
                "browser request method {method} exceeds exact task network authority"
            ))));
        }
        Ok(())
    }

    fn authorize_browser_document_request(
        session: &ControllerBrowserSession,
        observation: &BrowserDocumentRequestObservation,
    ) -> Result<(), ControllerError> {
        match observation.kind {
            BrowserDocumentRequestKind::Initial if observation.chain_index == 0 => {}
            BrowserDocumentRequestKind::Redirect
                if session.authority.follow_redirects
                    && observation.chain_index > 0
                    && observation.chain_index <= session.authority.max_redirects => {}
            BrowserDocumentRequestKind::Redirect if !session.authority.follow_redirects => {
                return Err(ControllerError::Policy(PolicyError::Denied(
                    "browser top-level redirect is disabled by exact task policy".to_owned(),
                )));
            }
            BrowserDocumentRequestKind::Redirect => {
                return Err(ControllerError::Policy(PolicyError::Denied(format!(
                    "browser redirect chain index {} exceeds exact limit {}",
                    observation.chain_index, session.authority.max_redirects
                ))));
            }
            BrowserDocumentRequestKind::Initial => {
                return Err(ControllerError::NotReady(
                    "browser initial document request carried a nonzero chain index".to_owned(),
                ));
            }
        }
        Self::authorize_browser_method(session, &observation.method)?;
        Self::authorize_browser_url_scope(session, &observation.url)?;
        Ok(())
    }

    fn browser_action_destination_binding(
        session: &mut ControllerBrowserSession,
        action: &BrowserAction,
    ) -> Result<Option<BrowserFormInspectionReceipt>, ControllerError> {
        match action {
            BrowserAction::Navigate { url, .. } => {
                Self::authorize_browser_method(session, "GET")?;
                Self::authorize_browser_url_scope(session, url)?;
                Ok(None)
            }
            BrowserAction::CaptureSynopsis { .. } | BrowserAction::CaptureScreenshot { .. } => {
                Ok(None)
            }
            BrowserAction::SubmitForm {
                selector,
                payload_digest,
                ..
            } => {
                let browser_lease = session.browser_lease.clone();
                let inspection = session
                    .adapter
                    .as_mut()
                    .ok_or_else(|| {
                        ControllerError::NotReady(
                            "browser adapter is unavailable for form inspection".to_owned(),
                        )
                    })?
                    .inspect_form(&browser_lease, selector, payload_digest)
                    .map_err(browser_pre_dispatch_error)?;
                Self::authorize_browser_url_scope(session, &inspection.current_page_url)?;
                Self::authorize_browser_method(session, &inspection.normalized_method)?;
                Self::authorize_browser_url_scope(session, &inspection.resolved_action_url)?;
                Ok(Some(inspection))
            }
        }
    }

    fn browser_action_required_capabilities(
        permission_decision: &PermissionDecision,
        action: &BrowserAction,
        approved_form: Option<&BrowserFormInspectionReceipt>,
    ) -> Result<BTreeSet<Capability>, ControllerError> {
        let mut required = BTreeSet::from([Capability::BrowserInteractive]);
        match action {
            BrowserAction::Navigate { .. } => {
                required.insert(browser_read_capability(permission_decision)?);
            }
            BrowserAction::SubmitForm { .. } => {
                let method = &approved_form
                    .ok_or_else(|| {
                        ControllerError::InvalidPlan(
                            "SubmitForm authorization omitted its exact inspection binding"
                                .to_owned(),
                        )
                    })?
                    .normalized_method;
                if browser_method_is_read(method) {
                    required.insert(browser_read_capability(permission_decision)?);
                } else {
                    required.insert(browser_write_capability(permission_decision)?);
                }
            }
            BrowserAction::CaptureSynopsis { .. } | BrowserAction::CaptureScreenshot { .. } => {}
        }
        Ok(required)
    }

    fn lower_browser_action(
        &self,
        session: &ControllerBrowserSession,
        tool_manifest: &ToolManifest,
        permission_decision: &PermissionDecision,
        action: &BrowserAction,
        approved_form: Option<&BrowserFormInspectionReceipt>,
    ) -> Result<AuthorizedBrowserAction, ControllerError> {
        let (repository_id, policy_digest, action_budget) = {
            let active = self.active_ref()?;
            let task = active.tasks.get(&session.task_id).ok_or_else(|| {
                ControllerError::NotReady("browser action task disappeared".to_owned())
            })?;
            let repository = active.single_task_repository(&session.task_id)?;
            (
                repository.repository_id.clone(),
                active.policy_digest.clone(),
                task.autonomy_budget.clone().ok_or_else(|| {
                    ControllerError::NotReady(
                        "browser action requires a durable task autonomy budget".to_owned(),
                    )
                })?,
            )
        };
        action_budget.validate()?;
        let (action_deadline_ms, output_bytes) =
            browser_action_reservation_bounds(session, action, &action_budget)?;
        let destination_digest = browser_action_binding_digest(action, approved_form)?;
        let isolation_policy_digest = browser_isolation_policy_digest(session);
        let required_capabilities =
            Self::browser_action_required_capabilities(permission_decision, action, approved_form)?;
        for capability in &required_capabilities {
            if *capability != Capability::BrowserInteractive
                && self.approval_required_for_task_permission(&session.task_id, *capability)?
            {
                return Err(ControllerError::Policy(PolicyError::Denied(format!(
                    "browser action requires separate {} approval that cannot be represented by the single exact browser-action approval binding",
                    capability.as_plan_ir_str()
                ))));
            }
        }
        let reconciliation_mode = if action.effect().is_side_effectful() {
            ReconciliationMode::ConsequentialExternal
        } else {
            Self::reconciliation_mode_for_manifest(tool_manifest)?
        };
        let now_ms = unix_millis()?;
        let fallback_expires_at_ms = now_ms
            .saturating_add(i64::try_from(action_deadline_ms).unwrap_or(i64::MAX))
            .saturating_add(60_000);
        let expires_at_ms =
            self.approval_bound_action_expiry(action.action_id(), fallback_expires_at_ms)?;
        let action_digest = action.digest();
        let nonce_seed = sha256_prefixed(
            format!(
                "browser-action-nonce-v1\0{}\0{}\0{}\0{}\0{}",
                session.plan_id,
                session.plan_revision,
                session.task_contract_digest,
                session.browser_lease.binding_digest(),
                action_digest
            )
            .as_bytes(),
        );
        Ok(AuthorizedBrowserAction {
            action_id: action.action_id().to_owned(),
            plan_id: session.plan_id.clone(),
            plan_revision: session.plan_revision,
            task_id: session.task_id.clone(),
            attempt_id: session.attempt_id.clone(),
            tool_id: tool_manifest.tool_id.clone(),
            tool_version: tool_manifest.version.clone(),
            tool_digest: tool_manifest.content_digest.clone(),
            repository_id,
            destination_digest,
            execution_epoch: session.execution_epoch,
            policy_digest,
            permission_decision_digest: permission_decision.digest(),
            isolation_policy_digest,
            nonce: format!("nonce.{}", &nonce_seed[7..27]),
            expires_at_ms,
            browser_action_digest: action_digest,
            required_capabilities,
            approval_required: self.approval_required_for_task_permission(
                &session.task_id,
                Capability::BrowserInteractive,
            )?,
            reconciliation_mode,
            declared_risk: tool_manifest.declared_risk_floor,
            action_deadline_ms,
            output_bytes,
        })
    }

    fn mark_dispatched_browser_unknown(
        &mut self,
        session: &ControllerBrowserSession,
        authorized: &AuthorizedBrowserAction,
    ) -> Result<(), ControllerError> {
        {
            let mut journal = ActionJournal::new(&mut self.state);
            journal.recover_dispatched_as_unknown(authorized)?;
        }
        self.mark_unknown(&session.attempt_id, &session.task_id, &authorized.action_id)
    }

    fn run_browser_action_after_dispatch(
        session: &mut ControllerBrowserSession,
        action: &BrowserAction,
        approved_form: Option<&BrowserFormInspectionReceipt>,
    ) -> Result<BrowserActionReceipt, BrowserError> {
        if matches!(
            action,
            BrowserAction::CaptureSynopsis { .. } | BrowserAction::CaptureScreenshot { .. }
        ) {
            return session
                .adapter
                .as_mut()
                .ok_or_else(|| BrowserError::Process("browser adapter is unavailable".to_owned()))?
                .execute(&session.browser_lease, action);
        }
        session
            .adapter
            .as_mut()
            .ok_or_else(|| BrowserError::Process("browser adapter is unavailable".to_owned()))?
            .dispatch_intercepted_action(&session.browser_lease, action, approved_form)?;
        loop {
            match session
                .adapter
                .as_mut()
                .ok_or_else(|| BrowserError::Process("browser adapter is unavailable".to_owned()))?
                .finish_dispatched_action(&session.browser_lease)
            {
                Ok(receipt) => return Ok(receipt),
                Err(BrowserError::InvalidRequest(message))
                    if browser_waits_for_document_authorization(&message) =>
                {
                    let observation = session
                        .adapter
                        .as_mut()
                        .ok_or_else(|| {
                            BrowserError::Process("browser adapter is unavailable".to_owned())
                        })?
                        .next_document_request(
                            &session.browser_lease,
                            session.adapter_config.request_timeout_ms,
                        )?;
                    if Self::authorize_browser_document_request(session, &observation).is_err() {
                        let abort_result = session
                            .adapter
                            .as_mut()
                            .ok_or_else(|| {
                                BrowserError::Process("browser adapter is unavailable".to_owned())
                            })?
                            .resolve_document_request(
                                &session.browser_lease,
                                &observation,
                                BrowserDocumentRequestDecision::Abort,
                            );
                        abort_result?;
                        return Err(BrowserError::Protocol(
                            "Controller denied a paused top-level document request".to_owned(),
                        ));
                    }
                    session
                        .adapter
                        .as_mut()
                        .ok_or_else(|| {
                            BrowserError::Process("browser adapter is unavailable".to_owned())
                        })?
                        .resolve_document_request(
                            &session.browser_lease,
                            &observation,
                            BrowserDocumentRequestDecision::Continue,
                        )?;
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn publish_browser_action_receipt(
        &mut self,
        session: &ControllerBrowserSession,
        authorized: &AuthorizedBrowserAction,
        artifacts: &ArtifactStore,
        receipt: BrowserActionReceipt,
    ) -> Result<(BrowserActionReceipt, String, u64), ControllerError> {
        let Ok(receipt_bytes) = receipt.to_bytes() else {
            self.mark_dispatched_browser_unknown(session, authorized)?;
            return Err(ControllerError::UnknownAction(authorized.action_id.clone()));
        };
        let receipt_bytes_len = u64::try_from(receipt_bytes.len()).map_err(|_| {
            ControllerError::NotReady(
                "browser action receipt length overflowed durable evidence bounds".to_owned(),
            )
        })?;
        let observe_result = {
            let mut journal = ActionJournal::new(&mut self.state);
            match journal.observe_with_receipt(authorized, artifacts, &receipt_bytes) {
                Ok(digest) => Ok(digest),
                Err(error) => {
                    let dispatched = journal
                        .record(&authorized.action_id)?
                        .is_some_and(|record| record.state == ActionState::Dispatched.as_str());
                    if dispatched {
                        journal.recover_dispatched_as_unknown(authorized)?;
                    }
                    Err((error, dispatched))
                }
            }
        };
        let receipt_digest = match observe_result {
            Ok(digest) => digest,
            Err((error, dispatched)) => {
                if dispatched {
                    self.mark_unknown(
                        &session.attempt_id,
                        &session.task_id,
                        &authorized.action_id,
                    )?;
                }
                return Err(ControllerError::Tool(error));
            }
        };
        {
            let mut journal = ActionJournal::new(&mut self.state);
            journal.commit_with_bound_result(authorized, ActionState::Observed)?;
        }
        self.checkpoint_now()?;
        Ok((receipt, receipt_digest, receipt_bytes_len))
    }

    fn committed_browser_synopsis_candidate(
        &self,
        session: &ControllerBrowserSession,
        authorized: &AuthorizedBrowserAction,
        receipt: &BrowserActionReceipt,
        receipt_digest: &str,
        receipt_bytes_len: u64,
    ) -> Result<EvidenceItem, ControllerError> {
        let record = self
            .state
            .action_record(&authorized.action_id)?
            .ok_or_else(|| {
                ControllerError::NotReady(
                    "committed browser synopsis lost its durable action record".to_owned(),
                )
            })?;
        if record.state != ActionState::Committed.as_str()
            || record.payload_digest != authorized.payload_digest()
            || record.policy_digest != authorized.policy_digest
            || record.execution_epoch != authorized.execution_epoch
            || record.result_digest.as_deref() != Some(receipt_digest)
        {
            return Err(ControllerError::NotReady(
                "browser synopsis context candidate is not bound to the exact committed action"
                    .to_owned(),
            ));
        }
        let metadata = self
            .state
            .artifact_metadata(receipt_digest)?
            .ok_or_else(|| {
                ControllerError::NotReady(
                    "committed browser synopsis receipt is missing CAS metadata".to_owned(),
                )
            })?;
        if metadata.digest != receipt_digest || metadata.size_bytes != receipt_bytes_len {
            return Err(ControllerError::NotReady(
                "committed browser synopsis CAS metadata disagrees with the exact receipt"
                    .to_owned(),
            ));
        }
        let receipt_bytes = receipt.to_bytes().map_err(|error| {
            ControllerError::NotReady(format!(
                "committed browser synopsis receipt could not be re-serialized: {error}"
            ))
        })?;
        if browser_receipt_digest(&receipt_bytes) != receipt_digest
            || u64::try_from(receipt_bytes.len()).unwrap_or(u64::MAX) != receipt_bytes_len
            || receipt.action_id != authorized.action_id
            || receipt.action_digest != authorized.browser_action_digest
            || receipt.action_kind != "capture_synopsis"
            || receipt.effect != BrowserActionEffect::Observation
            || receipt.lease_id != session.browser_lease.lease_id
            || receipt.lease_binding_digest != session.browser_lease.binding_digest()
            || receipt.execution_epoch != session.execution_epoch
            || receipt.requested_url.is_some()
        {
            return Err(ControllerError::NotReady(
                "committed browser synopsis receipt disagrees with exact Controller authority"
                    .to_owned(),
            ));
        }
        let synopsis = receipt.synopsis.as_ref().ok_or_else(|| {
            ControllerError::NotReady(
                "committed CaptureSynopsis receipt omitted its bounded browser state".to_owned(),
            )
        })?;
        let text = browser_synopsis_context_text(
            synopsis,
            receipt.screenshots_and_traces_suppressed,
            &session.adapter_config,
        )?;
        let source_uri = format!("cas://{receipt_digest}");
        Ok(EvidenceItem::new(
            format!("browser:{}:{receipt_digest}", authorized.action_id),
            PacketSection::ToolEvidence,
            ContextLevel::C1,
            EvidenceKind::ToolSynopsis,
            source_uri.clone(),
            receipt_digest.to_owned(),
            "controller_committed_browser_action_receipt_v1",
            TrustClass::Tool,
            "bounded committed browser state synopsis for current task",
            text,
        )
        .with_repository(authorized.repository_id.clone())
        .with_locator(format!("browser_action:{}", authorized.action_id))
        .with_expansion_handle(ExpansionHandle {
            source_uri,
            source_digest: receipt_digest.to_owned(),
            offset: 0,
            retained_length: receipt_bytes_len,
            total_length: receipt_bytes_len,
        }))
    }

    fn complete_dispatched_browser_receipt(
        &mut self,
        session: &mut ControllerBrowserSession,
        tool_manifest: &ToolManifest,
        authorized: &AuthorizedBrowserAction,
        action: &BrowserAction,
        mut receipt: BrowserActionReceipt,
    ) -> Result<BrowserActionReceipt, ControllerError> {
        if receipt.navigation_was_download {
            if !matches!(action, BrowserAction::Navigate { .. }) || receipt.download.is_some() {
                self.mark_dispatched_browser_unknown(session, authorized)?;
                return Err(ControllerError::NotReady(
                    "browser download signal was not bound to one unretained Navigate receipt"
                        .to_owned(),
                ));
            }
            match self.record_browser_download_with_activity(
                session,
                tool_manifest,
                "application/octet-stream",
                session.sensitive_page_observed,
                BrowserDownloadActivity::EnclosingAction,
            ) {
                Ok(download) => receipt.download = Some(download),
                Err(error) => {
                    self.mark_dispatched_browser_unknown(session, authorized)?;
                    return Err(error);
                }
            }
        } else if receipt.download.is_some() {
            self.mark_dispatched_browser_unknown(session, authorized)?;
            return Err(ControllerError::NotReady(
                "browser action returned download metadata without a mechanical download signal"
                    .to_owned(),
            ));
        }
        if receipt
            .synopsis
            .as_ref()
            .is_some_and(|synopsis| synopsis.sensitive_page.is_sensitive())
        {
            session.sensitive_page_observed = true;
        }
        if matches!(action, BrowserAction::CaptureSynopsis { .. }) {
            let synopsis = receipt.synopsis.as_ref().ok_or_else(|| {
                ControllerError::NotReady(
                    "CaptureSynopsis receipt omitted its bounded browser state".to_owned(),
                )
            })?;
            if let Err(error) = browser_synopsis_context_text(
                synopsis,
                receipt.screenshots_and_traces_suppressed,
                &session.adapter_config,
            ) {
                self.mark_dispatched_browser_unknown(session, authorized)?;
                return Err(error);
            }
        }
        if matches!(action, BrowserAction::CaptureScreenshot { .. }) {
            if let Err(error) = validate_browser_screenshot_receipt(session, authorized, &receipt) {
                self.mark_dispatched_browser_unknown(session, authorized)?;
                return Err(error);
            }
        } else if receipt.screenshot.is_some() {
            self.mark_dispatched_browser_unknown(session, authorized)?;
            return Err(ControllerError::NotReady(
                "non-screenshot browser action unexpectedly returned raw screenshot data"
                    .to_owned(),
            ));
        }
        Ok(receipt)
    }

    /// Executes one browser action through the Controller-owned durable `ActionJournal` lifecycle.
    /// Top-level requests remain paused until this method re-authorizes their exact method and
    /// destination. Any ambiguity after durable dispatch becomes `Unknown` and is never replayed.
    ///
    /// # Errors
    /// Returns fail-closed for stale authority, denied request/redirect scope, missing approval,
    /// browser failure, durable evidence failure, or any post-dispatch transport uncertainty.
    pub fn execute_browser_action(
        &mut self,
        session: &mut ControllerBrowserSession,
        tool_manifest: &ToolManifest,
        artifacts: &ArtifactStore,
        action: &BrowserAction,
    ) -> Result<BrowserActionReceipt, ControllerError> {
        self.execute_browser_action_with_context_candidate(
            session,
            tool_manifest,
            artifacts,
            action,
        )
        .map(|(receipt, _)| receipt)
    }

    /// Executes one browser action and returns a bounded untrusted context candidate only for a
    /// durably committed `CaptureSynopsis` receipt.
    ///
    /// The candidate is derived only after receipt publication and `ActionJournal` commit. It never
    /// grants tool-schema, policy, permission, or Controller authority.
    ///
    /// # Errors
    /// Returns the same action errors as `execute_browser_action`, and fails closed if a committed
    /// synopsis receipt cannot be proven safe and exactly bound to durable CAS/state.
    pub fn execute_browser_action_with_context_candidate(
        &mut self,
        session: &mut ControllerBrowserSession,
        tool_manifest: &ToolManifest,
        artifacts: &ArtifactStore,
        action: &BrowserAction,
    ) -> Result<(BrowserActionReceipt, Option<EvidenceItem>), ControllerError> {
        self.require_execution_not_paused()?;
        action
            .validate_shape()
            .map_err(browser_pre_dispatch_error)?;
        if matches!(action, BrowserAction::CaptureScreenshot { .. })
            && session.adapter_config.suppress_screenshots_and_traces
        {
            return Err(ControllerError::Policy(PolicyError::Denied(
                "browser screenshot retention is suppressed by Controller configuration".to_owned(),
            )));
        }
        if matches!(action, BrowserAction::CaptureScreenshot { .. })
            && session.sensitive_page_observed
        {
            return Err(ControllerError::Policy(PolicyError::Denied(
                "browser screenshot retention remains suppressed after a sensitive page observation"
                    .to_owned(),
            )));
        }
        let permission_decision =
            self.validate_browser_session_for_action(session, tool_manifest)?;
        let approved_form = Self::browser_action_destination_binding(session, action)?;
        let authorized = self.lower_browser_action(
            session,
            tool_manifest,
            &permission_decision,
            action,
            approved_form.as_ref(),
        )?;
        self.prepare_action_for_dispatch(&authorized, tool_manifest, &permission_decision)?;
        self.transition_browser_resource_activity(
            session,
            BrowserResourceActivity::Active,
            unix_millis()?,
            "resource_browser_touched_for_action",
        )?;
        {
            let mut journal = ActionJournal::new(&mut self.state);
            journal.transition(
                &authorized,
                ActionState::Authorized,
                ActionState::Dispatched,
            )?;
        }
        let Ok(receipt) =
            Self::run_browser_action_after_dispatch(session, action, approved_form.as_ref())
        else {
            self.mark_dispatched_browser_unknown(session, &authorized)?;
            return Err(ControllerError::UnknownAction(authorized.action_id));
        };
        let receipt = self.complete_dispatched_browser_receipt(
            session,
            tool_manifest,
            &authorized,
            action,
            receipt,
        )?;
        let (receipt, receipt_digest, receipt_bytes_len) =
            self.publish_browser_action_receipt(session, &authorized, artifacts, receipt)?;
        self.transition_browser_resource_activity(
            session,
            BrowserResourceActivity::Idle,
            unix_millis()?,
            "resource_browser_idle_after_action",
        )?;
        let context_candidate = if matches!(action, BrowserAction::CaptureSynopsis { .. }) {
            Some(self.committed_browser_synopsis_candidate(
                session,
                &authorized,
                &receipt,
                &receipt_digest,
                receipt_bytes_len,
            )?)
        } else {
            None
        };
        Ok((receipt, context_candidate))
    }

    fn release_proven_absent_browser_launch(
        &mut self,
        residency: &mut BrowserResourceResidencyV1,
        event_kind: &str,
    ) -> Result<(), ControllerError> {
        self.settle_browser_network_reservation_if_present(
            residency,
            0,
            BrowserNetworkSettlementV1::ProvenAbsentZero,
        )?;
        residency.state = BrowserResourceResidencyStateV1::Absent;
        residency.process_group_id = None;
        residency.process_group_leader_identity = None;
        residency.updated_at_ms = unix_millis()?;
        self.persist_browser_resource_residency(residency, event_kind)?;
        self.resources.set_browser_residency(residency.clone());
        self.checkpoint_now()?;
        let policy_event = self
            .resources
            .release(&residency.policy_lease.lease_id)
            .ok_or_else(|| {
                ControllerError::NotReady(
                    "proven-absent browser launch lost its logical CDP_BROWSER lease".to_owned(),
                )
            })?;
        let mut released = residency.policy_lease.clone();
        released.state = LeaseStateV1::Released;
        released.last_used_at_ms = unix_millis()?;
        self.persist_resource_lease_transition(
            &released,
            &policy_event,
            "resource_browser_spawn_lease_released",
            &residency.task_id,
        )?;
        self.resources.clear_browser_residency();
        self.checkpoint_now()?;
        Ok(())
    }

    fn persist_browser_stop_unknown(
        &mut self,
        residency: &mut BrowserResourceResidencyV1,
        event_kind: &str,
    ) -> Result<(), ControllerError> {
        residency.state = BrowserResourceResidencyStateV1::Unknown;
        residency.updated_at_ms = unix_millis()?;
        self.persist_browser_resource_residency(residency, event_kind)?;
        self.resources.set_browser_residency(residency.clone());
        self.checkpoint_now()?;
        Ok(())
    }

    fn stop_browser_session_physical(
        &mut self,
        session: &mut ControllerBrowserSession,
    ) -> Result<BrowserResourceResidencyV1, ControllerError> {
        let mut residency = self.live_browser_residency_for_session(session)?;
        residency.state = BrowserResourceResidencyStateV1::Stopping;
        residency.updated_at_ms = unix_millis()?;
        self.persist_browser_resource_residency(&residency, "resource_browser_stopping")?;
        self.resources.set_browser_residency(residency.clone());
        self.checkpoint_now()?;

        let adapter = session.adapter.take().ok_or_else(|| {
            ControllerError::NotReady("browser adapter already consumed before shutdown".to_owned())
        })?;
        if let Err(error) = adapter.shutdown() {
            self.persist_browser_stop_unknown(&mut residency, "resource_browser_stop_unknown")?;
            return Err(ControllerError::NotReady(format!(
                "browser exact process-group cleanup is unproven: {error}"
            )));
        }
        if residency.ephemeral_profile && residency.profile_root.exists() {
            self.persist_browser_stop_unknown(&mut residency, "resource_browser_profile_unknown")?;
            return Err(ControllerError::NotReady(
                "ephemeral browser profile remains after exact browser shutdown".to_owned(),
            ));
        }

        let gateway = session.gateway.take().ok_or_else(|| {
            ControllerError::NotReady("browser gateway already consumed before shutdown".to_owned())
        })?;
        let observed_bytes = match gateway.shutdown() {
            Ok(observed_bytes) => observed_bytes,
            Err(error) => {
                self.persist_browser_stop_unknown(
                    &mut residency,
                    "resource_browser_gateway_unknown",
                )?;
                return Err(ControllerError::Tool(error));
            }
        };
        if observed_bytes > session.reserved_network_bytes {
            self.persist_browser_stop_unknown(
                &mut residency,
                "resource_browser_network_reservation_exceeded",
            )?;
            return Err(ControllerError::NotReady(format!(
                "browser gateway observed {observed_bytes} bytes above durable reservation {}",
                session.reserved_network_bytes
            )));
        }
        if let Err(error) = self.require_browser_network_reservation_settlement(
            &residency,
            observed_bytes,
            BrowserNetworkSettlementV1::CleanObserved,
        ) {
            self.persist_browser_stop_unknown(
                &mut residency,
                "resource_browser_network_settlement_unknown",
            )?;
            return Err(error);
        }

        residency.state = BrowserResourceResidencyStateV1::Absent;
        residency.updated_at_ms = unix_millis()?;
        self.persist_browser_resource_residency(&residency, "resource_browser_absent")?;
        self.resources.set_browser_residency(residency.clone());
        self.checkpoint_now()?;
        Ok(residency)
    }

    fn finalize_stopped_browser_resource(
        &mut self,
        session: &mut ControllerBrowserSession,
        residency: &BrowserResourceResidencyV1,
        terminal: BrowserResourceTerminal,
    ) -> Result<(), ControllerError> {
        if residency.state != BrowserResourceResidencyStateV1::Absent
            || residency.policy_lease != session.resource_lease
        {
            return Err(ControllerError::NotReady(
                "browser logical transition requires exact proven-absent residency".to_owned(),
            ));
        }
        let previous_resources = self.resources.clone();
        let now_ms = unix_millis()?;
        let policy_event = match terminal {
            BrowserResourceTerminal::Released => {
                self.resources.release(&session.resource_lease.lease_id)
            }
            BrowserResourceTerminal::Evicted => self
                .resources
                .record_eviction(&session.resource_lease.lease_id, now_ms),
        }
        .ok_or_else(|| {
            ControllerError::NotReady(
                "proven-absent browser lost its exact logical CDP_BROWSER lease".to_owned(),
            )
        })?;
        let mut terminal_lease = session.resource_lease.clone();
        terminal_lease.state = match terminal {
            BrowserResourceTerminal::Released => LeaseStateV1::Released,
            BrowserResourceTerminal::Evicted => LeaseStateV1::Evicted,
        };
        terminal_lease.last_used_at_ms = now_ms;
        let event_kind = match terminal {
            BrowserResourceTerminal::Released => "resource_browser_released",
            BrowserResourceTerminal::Evicted => "resource_browser_evicted",
        };
        if let Err(error) = self.persist_resource_lease_transition(
            &terminal_lease,
            &policy_event,
            event_kind,
            &session.task_id,
        ) {
            self.resources = previous_resources;
            return Err(error);
        }
        session.resource_lease = terminal_lease;
        self.resources.clear_browser_residency();
        self.checkpoint_now()?;
        Ok(())
    }

    /// Samples current pressure and applies an exact idle/pressure eviction only to this live
    /// browser session. A `true` result means the session was physically stopped and durably
    /// recorded as evicted; callers must not attempt further browser work with it.
    ///
    /// # Errors
    /// Fails closed for stale session authority, pressure-probe/persistence failure, or any
    /// ambiguity while proving physical browser/gateway absence and network settlement.
    pub fn maintain_browser_session(
        &mut self,
        session: &mut ControllerBrowserSession,
    ) -> Result<bool, ControllerError> {
        let _residency = self.live_browser_residency_for_session(session)?;
        let snapshot = self.resource_probe.sample().map_err(|error| {
            ControllerError::Policy(PolicyError::ResourceDenied(format!(
                "live resource pressure probe failed during browser maintenance: {error}"
            )))
        })?;
        let pressure = self.resources.observe_pressure(snapshot);
        self.persist_resource_pressure_observation(
            &pressure,
            "resource_browser_maintenance_pressure",
            &session.task_id,
        )?;
        self.checkpoint_now()?;
        let now_ms = pressure.snapshot.observed_at_ms;
        let should_evict = self
            .resources
            .eviction_decisions(&pressure, now_ms)
            .iter()
            .any(|decision| {
                matches!(
                    decision,
                    ResourcePolicyEventV1::Evict { lease_id, class }
                        if lease_id == &session.resource_lease.lease_id
                            && *class == HeavyLeaseClass::CdpBrowser
                )
            });
        if !should_evict {
            return Ok(false);
        }
        let residency = self.stop_browser_session_physical(session)?;
        self.finalize_stopped_browser_resource(
            session,
            &residency,
            BrowserResourceTerminal::Evicted,
        )?;
        Ok(true)
    }

    /// Stops one exact browser session, proves physical absence, accounts gateway bytes, then and
    /// only then releases the logical `CDP_BROWSER` lease.
    ///
    /// # Errors
    /// Leaves durable residency Unknown and retains the logical lease if exact cleanup/absence or
    /// network accounting cannot be proven.
    pub fn shutdown_browser_session(
        &mut self,
        mut session: ControllerBrowserSession,
    ) -> Result<(), ControllerError> {
        let residency = self.stop_browser_session_physical(&mut session)?;
        self.finalize_stopped_browser_resource(
            &mut session,
            &residency,
            BrowserResourceTerminal::Released,
        )
    }
}

fn browser_origins(authority: &BrowserTaskAuthorityV1) -> BTreeSet<String> {
    let mut origins = BTreeSet::new();
    for domain in &authority.allowed_domains {
        for scheme in &authority.allowed_schemes {
            for port in &authority.allowed_ports {
                let default =
                    (*port == 80 && scheme == "http") || (*port == 443 && scheme == "https");
                let origin = if default {
                    format!("{scheme}://{domain}")
                } else {
                    format!("{scheme}://{domain}:{port}")
                };
                origins.insert(origin);
            }
        }
    }
    origins
}

fn browser_pre_dispatch_error(error: BrowserError) -> ControllerError {
    match error {
        BrowserError::InvalidRequest(message) | BrowserError::Protocol(message) => {
            ControllerError::Tool(ToolError::Authority(message))
        }
        BrowserError::ResourceLimit(message) => {
            ControllerError::Tool(ToolError::ResourceLimit(message))
        }
        BrowserError::Process(message) => {
            ControllerError::Tool(ToolError::RecoveryBlocked(message))
        }
        BrowserError::TransportUncertain { detail, .. } => {
            ControllerError::Tool(ToolError::RecoveryBlocked(detail))
        }
        BrowserError::Io(error) => ControllerError::Tool(ToolError::Io(error)),
    }
}

fn browser_receipt_digest(receipt_bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(receipt_bytes);
    format!("{:x}", hasher.finalize())
}

fn validate_browser_screenshot_receipt(
    session: &ControllerBrowserSession,
    authorized: &AuthorizedBrowserAction,
    receipt: &BrowserActionReceipt,
) -> Result<(), ControllerError> {
    if receipt.action_id != authorized.action_id
        || receipt.action_digest != authorized.browser_action_digest
        || receipt.action_kind != "capture_screenshot"
        || receipt.effect != BrowserActionEffect::Observation
        || receipt.lease_id != session.browser_lease.lease_id
        || receipt.lease_binding_digest != session.browser_lease.binding_digest()
        || receipt.execution_epoch != session.execution_epoch
        || receipt.cdp_request_id == 0
        || receipt.requested_url.is_some()
    {
        return Err(ControllerError::NotReady(
            "browser screenshot receipt disagrees with exact Controller authority".to_owned(),
        ));
    }
    let synopsis = receipt.synopsis.as_ref().ok_or_else(|| {
        ControllerError::NotReady(
            "CaptureScreenshot receipt omitted its pre-capture browser state".to_owned(),
        )
    })?;
    if synopsis.sensitive_page.is_sensitive() {
        if receipt.screenshot.is_some() || !receipt.screenshots_and_traces_suppressed {
            return Err(ControllerError::NotReady(
                "sensitive browser screenshot receipt retained raw visual data".to_owned(),
            ));
        }
        return Ok(());
    }
    let screenshot = receipt.screenshot.as_ref().ok_or_else(|| {
        ControllerError::NotReady(
            "non-sensitive CaptureScreenshot receipt omitted its bounded PNG".to_owned(),
        )
    })?;
    if receipt.screenshots_and_traces_suppressed
        || screenshot.content_type != "image/png"
        || screenshot.encoding != "base64"
        || screenshot.png_bytes == 0
        || screenshot.retained_base64_bytes != screenshot.png_base64.len()
        || screenshot.retained_base64_bytes > session.adapter_config.max_cdp_frame_bytes
        || !screenshot.png_base64.starts_with("iVBORw0KGgo")
    {
        return Err(ControllerError::NotReady(
            "browser screenshot receipt failed bounded PNG retention validation".to_owned(),
        ));
    }
    Ok(())
}

fn browser_sensitive_reason_name(reason: BrowserSensitivePageReason) -> &'static str {
    match reason {
        BrowserSensitivePageReason::FormControl => "form_control",
        BrowserSensitivePageReason::PasswordControl => "password_control",
        BrowserSensitivePageReason::SensitiveAttribute => "sensitive_attribute",
        BrowserSensitivePageReason::CredentialTextPattern => "credential_text_pattern",
        BrowserSensitivePageReason::Unclassified => "unclassified",
    }
}

fn browser_synopsis_context_text(
    synopsis: &BrowserStateSynopsis,
    screenshots_and_traces_suppressed: bool,
    config: &BrowserAdapterConfig,
) -> Result<String, ControllerError> {
    if synopsis.url.contains(['?', '#'])
        || synopsis.retained_text_bytes != synopsis.text.len()
        || synopsis.retained_dom_bytes != synopsis.dom_excerpt.len()
        || synopsis.retained_text_bytes > config.max_synopsis_bytes
        || synopsis.retained_dom_bytes > config.max_dom_bytes
        || synopsis.retained_dom_sha256 != sha256_prefixed(synopsis.dom_excerpt.as_bytes())
    {
        return Err(ControllerError::NotReady(
            "browser synopsis is not a bounded self-consistent context projection".to_owned(),
        ));
    }
    let reasons = synopsis
        .sensitive_page
        .reasons
        .iter()
        .copied()
        .map(browser_sensitive_reason_name)
        .collect::<Vec<_>>();
    let value = if synopsis.sensitive_page.is_sensitive() {
        if !screenshots_and_traces_suppressed
            || !synopsis.title.is_empty()
            || !synopsis.text.is_empty()
            || !synopsis.dom_excerpt.is_empty()
            || synopsis.retained_text_bytes != 0
            || synopsis.retained_dom_bytes != 0
            || synopsis.retained_dom_sha256 != sha256_prefixed(b"")
        {
            return Err(ControllerError::NotReady(
                "sensitive browser synopsis retained model-visible credential page content"
                    .to_owned(),
            ));
        }
        serde_json::json!({
            "url": synopsis.url,
            "sensitive_page": {
                "sensitive": true,
                "reasons": reasons,
            },
            "retained_text_bytes": 0,
            "retained_dom_bytes": 0,
        })
    } else {
        serde_json::json!({
            "url": synopsis.url,
            "title": synopsis.title,
            "text": synopsis.text,
            "dom_excerpt": synopsis.dom_excerpt,
            "retained_text_bytes": synopsis.retained_text_bytes,
            "retained_dom_bytes": synopsis.retained_dom_bytes,
            "text_truncated": synopsis.text_truncated,
            "dom_truncated": synopsis.dom_truncated,
            "retained_dom_sha256": synopsis.retained_dom_sha256,
            "sensitive_page": {
                "sensitive": false,
                "reasons": reasons,
            },
        })
    };
    serde_json::to_string(&value).map_err(|error| {
        ControllerError::NotReady(format!(
            "browser synopsis context projection serialization failed: {error}"
        ))
    })
}

fn browser_action_reservation_bounds(
    session: &ControllerBrowserSession,
    action: &BrowserAction,
    action_budget: &AutonomyBudgetV1,
) -> Result<(u64, u64), ControllerError> {
    let redirect_windows = u64::from(session.authority.max_redirects).saturating_add(2);
    let action_deadline_ms = session
        .adapter_config
        .request_timeout_ms
        .saturating_mul(redirect_windows);
    if action_deadline_ms == 0 || action_deadline_ms > action_budget.max_single_tool_action_ms {
        return Err(ControllerError::Policy(PolicyError::ResourceDenied(
            format!(
                "browser action worst-case deadline {action_deadline_ms}ms exceeds task single-action ceiling {}ms",
                action_budget.max_single_tool_action_ms
            ),
        )));
    }
    let output_bytes = match action {
        BrowserAction::CaptureSynopsis { .. } => u64::try_from(
            session
                .adapter_config
                .max_synopsis_bytes
                .saturating_add(session.adapter_config.max_dom_bytes)
                .saturating_add(64 * 1024),
        )
        .unwrap_or(u64::MAX),
        BrowserAction::CaptureScreenshot { .. } => u64::try_from(
            session
                .adapter_config
                .max_cdp_frame_bytes
                .saturating_add(session.adapter_config.max_synopsis_bytes)
                .saturating_add(session.adapter_config.max_dom_bytes)
                .saturating_add(128 * 1024),
        )
        .unwrap_or(u64::MAX),
        BrowserAction::Navigate { .. } | BrowserAction::SubmitForm { .. } => {
            u64::try_from(session.adapter_config.max_cdp_frame_bytes).unwrap_or(u64::MAX)
        }
    };
    if output_bytes > action_budget.max_output_bytes {
        return Err(ControllerError::Policy(PolicyError::ResourceDenied(
            format!(
                "browser action receipt bound {output_bytes} exceeds task output ceiling {}",
                action_budget.max_output_bytes
            ),
        )));
    }
    Ok((action_deadline_ms, output_bytes))
}

fn browser_action_binding_digest(
    action: &BrowserAction,
    approved_form: Option<&BrowserFormInspectionReceipt>,
) -> Result<Option<String>, ControllerError> {
    match action {
        BrowserAction::Navigate { url, .. } => Ok(Some(browser_destination_digest(url))),
        BrowserAction::CaptureSynopsis { .. } | BrowserAction::CaptureScreenshot { .. } => Ok(None),
        BrowserAction::SubmitForm { .. } => Ok(Some(
            approved_form
                .ok_or_else(|| {
                    ControllerError::InvalidPlan(
                        "SubmitForm authorization omitted its exact inspection binding".to_owned(),
                    )
                })?
                .binding_digest(),
        )),
    }
}

fn browser_method_is_read(method: &str) -> bool {
    matches!(method, "GET" | "HEAD")
}

fn browser_method_is_write(method: &str) -> bool {
    matches!(method, "POST" | "PUT" | "PATCH" | "DELETE")
}

fn browser_read_capability(
    permission_decision: &PermissionDecision,
) -> Result<Capability, ControllerError> {
    if permission_decision
        .effective
        .contains(Capability::NetworkRead)
    {
        Ok(Capability::NetworkRead)
    } else if permission_decision
        .effective
        .contains(Capability::NetworkWrite)
    {
        Ok(Capability::NetworkWrite)
    } else {
        Err(ControllerError::Policy(PolicyError::Denied(
            "browser read action lacks effective network_read or network_write authority"
                .to_owned(),
        )))
    }
}

fn browser_write_capability(
    permission_decision: &PermissionDecision,
) -> Result<Capability, ControllerError> {
    if permission_decision
        .effective
        .contains(Capability::NetworkWrite)
    {
        Ok(Capability::NetworkWrite)
    } else if permission_decision
        .effective
        .contains(Capability::ExternalSideEffect)
    {
        Ok(Capability::ExternalSideEffect)
    } else {
        Err(ControllerError::Policy(PolicyError::Denied(
            "browser write action lacks effective network_write or external_side_effect authority"
                .to_owned(),
        )))
    }
}

fn browser_waits_for_document_authorization(message: &str) -> bool {
    message.contains("paused awaiting caller authorization")
        || message.contains("request/redirect is paused awaiting caller authorization")
}

fn browser_destination_digest(url: &str) -> String {
    let mut hasher = Sha256::new();
    digest_field(&mut hasher, "sovereign.browser_destination.v1");
    digest_field(&mut hasher, url);
    format!("sha256:{:x}", hasher.finalize())
}

fn browser_isolation_policy_digest(session: &ControllerBrowserSession) -> String {
    let mut hasher = Sha256::new();
    digest_field(&mut hasher, "sovereign.browser_isolation_binding.v1");
    digest_field(&mut hasher, &session.plan_id);
    hasher.update(session.plan_revision.to_be_bytes());
    digest_field(&mut hasher, &session.task_id);
    digest_field(&mut hasher, &session.task_contract_digest);
    digest_field(&mut hasher, &session.resource_lease.lease_id);
    digest_field(&mut hasher, &session.resource_lease.profile_digest);
    digest_field(&mut hasher, &session.browser_lease.binding_digest());
    hasher.update(session.execution_epoch.to_be_bytes());
    digest_field(&mut hasher, &session.loopback_capability.lease_id);
    hasher.update(session.loopback_capability.execution_epoch.to_be_bytes());
    hasher.update(session.loopback_capability.localhost_port.to_be_bytes());
    digest_field(&mut hasher, &session.loopback_capability.token_digest);
    hasher.update(session.loopback_capability.expires_at_ms.to_be_bytes());
    match &session.profile_authority {
        BrowserProfileAuthority::Isolated => digest_field(&mut hasher, "isolated"),
        BrowserProfileAuthority::Persistent {
            grant_id,
            profile_id,
        } => {
            digest_field(&mut hasher, "persistent");
            digest_field(&mut hasher, grant_id);
            digest_field(&mut hasher, profile_id);
        }
    }
    digest_field(
        &mut hasher,
        session.authority.download_root.as_deref().unwrap_or("none"),
    );
    hasher.update([u8::from(session.authority.downloads_allowed)]);
    format!("sha256:{:x}", hasher.finalize())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserDestinationV1 {
    pub destination: NetworkDestination,
    pub absolute_url: String,
}

/// Parses one absolute HTTP(S) top-level URL without doing DNS or network I/O.
///
/// # Errors
/// Returns a tool-authority error for userinfo, malformed authority, or privileged/custom schemes.
pub fn browser_destination(url: &str) -> Result<BrowserDestinationV1, ToolError> {
    sovereign_policy::browser::authorize_top_level_browser_url(url)
        .map_err(|error| ToolError::Authority(error.to_string()))?;
    let (scheme, remainder) = url
        .split_once("://")
        .ok_or_else(|| ToolError::Authority("browser URL has no absolute authority".to_owned()))?;
    let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];
    if authority.is_empty() || authority.contains('@') {
        return Err(ToolError::Authority(
            "browser URL authority is empty or contains forbidden userinfo".to_owned(),
        ));
    }
    let (host, port) = parse_authority(authority, scheme)?;
    Ok(BrowserDestinationV1 {
        destination: NetworkDestination {
            scheme: scheme.to_ascii_lowercase(),
            host,
            port,
        },
        absolute_url: url.to_owned(),
    })
}

fn parse_authority(authority: &str, scheme: &str) -> Result<(String, u16), ToolError> {
    let default_port = match scheme.to_ascii_lowercase().as_str() {
        "http" => 80,
        "https" => 443,
        _ => {
            return Err(ToolError::Authority(
                "browser authority requires http or https".to_owned(),
            ));
        }
    };
    if let Some(rest) = authority.strip_prefix('[') {
        let close = rest.find(']').ok_or_else(|| {
            ToolError::Authority("browser IPv6 authority is missing closing bracket".to_owned())
        })?;
        let host = format!("[{}]", &rest[..close]);
        let suffix = &rest[close + 1..];
        if suffix.is_empty() {
            return Ok((host, default_port));
        }
        let port = suffix.strip_prefix(':').ok_or_else(|| {
            ToolError::Authority("browser IPv6 authority has invalid suffix".to_owned())
        })?;
        return Ok((host, parse_port(port)?));
    }
    let colon_count = authority.bytes().filter(|byte| *byte == b':').count();
    if colon_count > 1 {
        return Err(ToolError::Authority(
            "browser IPv6 literals must use bracketed authority form".to_owned(),
        ));
    }
    if let Some((host, port)) = authority.rsplit_once(':') {
        if host.is_empty() {
            return Err(ToolError::Authority(
                "browser URL authority has an empty host".to_owned(),
            ));
        }
        Ok((host.to_owned(), parse_port(port)?))
    } else {
        Ok((authority.to_owned(), default_port))
    }
}

fn parse_port(value: &str) -> Result<u16, ToolError> {
    value
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| ToolError::Authority("browser URL has an invalid port".to_owned()))
}

fn loopback_ip(host: &str) -> Option<IpAddr> {
    host.strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host)
        .parse::<IpAddr>()
        .ok()
        .filter(IpAddr::is_loopback)
}

fn is_loopback_literal(host: &str) -> bool {
    loopback_ip(host).is_some()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedBrowserAction {
    pub action_id: String,
    pub plan_id: String,
    pub plan_revision: u32,
    pub task_id: String,
    pub attempt_id: String,
    pub tool_id: String,
    pub tool_version: String,
    pub tool_digest: String,
    pub repository_id: String,
    pub destination_digest: Option<String>,
    pub execution_epoch: i64,
    pub policy_digest: String,
    pub permission_decision_digest: String,
    pub isolation_policy_digest: String,
    pub nonce: String,
    pub expires_at_ms: i64,
    pub browser_action_digest: String,
    pub required_capabilities: BTreeSet<Capability>,
    pub approval_required: bool,
    pub reconciliation_mode: ReconciliationMode,
    pub declared_risk: CommandRisk,
    pub action_deadline_ms: u64,
    pub output_bytes: u64,
}

impl AuthorizedBrowserAction {
    #[must_use]
    pub fn payload_digest(&self) -> String {
        let mut hasher = Sha256::new();
        digest_field(&mut hasher, "sovereign.authorized_browser_action.v1");
        digest_field(&mut hasher, &self.action_id);
        digest_field(&mut hasher, &self.plan_id);
        hasher.update(self.plan_revision.to_be_bytes());
        digest_field(&mut hasher, &self.task_id);
        digest_field(&mut hasher, &self.attempt_id);
        digest_field(&mut hasher, &self.tool_id);
        digest_field(&mut hasher, &self.tool_version);
        digest_field(&mut hasher, &self.tool_digest);
        digest_field(&mut hasher, &self.repository_id);
        digest_field(
            &mut hasher,
            self.destination_digest.as_deref().unwrap_or("none"),
        );
        hasher.update(self.execution_epoch.to_be_bytes());
        digest_field(&mut hasher, &self.policy_digest);
        digest_field(&mut hasher, &self.permission_decision_digest);
        digest_field(&mut hasher, &self.isolation_policy_digest);
        digest_field(&mut hasher, &self.nonce);
        hasher.update(self.expires_at_ms.to_be_bytes());
        digest_field(&mut hasher, &self.browser_action_digest);
        for capability in &self.required_capabilities {
            digest_field(&mut hasher, capability.as_plan_ir_str());
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
        hasher.update(self.action_deadline_ms.to_be_bytes());
        hasher.update(self.output_bytes.to_be_bytes());
        format!("sha256:{:x}", hasher.finalize())
    }

    /// # Errors
    /// Returns an authority error for malformed/stale immutable browser action bindings.
    pub fn validate(&self, now_ms: i64) -> Result<(), ToolError> {
        if self.action_id.trim().is_empty()
            || self.plan_id.trim().is_empty()
            || self.task_id.trim().is_empty()
            || self.attempt_id.trim().is_empty()
            || self.tool_id.trim().is_empty()
            || self.tool_version.trim().is_empty()
            || self.repository_id.trim().is_empty()
            || self.nonce.trim().is_empty()
            || !is_sha256(&self.tool_digest)
            || !is_sha256(&self.policy_digest)
            || !is_sha256(&self.permission_decision_digest)
            || !is_sha256(&self.isolation_policy_digest)
            || !is_sha256(&self.browser_action_digest)
            || self
                .destination_digest
                .as_ref()
                .is_some_and(|value| !is_sha256(value))
            || self.required_capabilities.is_empty()
            || !self
                .required_capabilities
                .contains(&Capability::BrowserInteractive)
            || self.execution_epoch < 0
            || self.action_deadline_ms == 0
        {
            return Err(ToolError::Authority(
                "authorized browser action has incomplete exact-binding fields".to_owned(),
            ));
        }
        if self.expires_at_ms < now_ms {
            return Err(ToolError::Authority(
                "authorized browser action expired".to_owned(),
            ));
        }
        Ok(())
    }

    /// # Errors
    /// Returns an authority error unless every browser/network capability and identity layer agrees.
    pub fn verify_permission_decision(
        &self,
        decision: &PermissionDecision,
    ) -> Result<(), ToolError> {
        decision
            .validate()
            .map_err(|error| ToolError::Authority(error.to_string()))?;
        let exact = self.permission_decision_digest == decision.digest()
            && self.plan_id == decision.plan_id
            && self.plan_revision == decision.plan_revision
            && self.task_id == decision.task_id
            && self.policy_digest == decision.policy_digest
            && self.tool_id == decision.tool_id
            && self.tool_version == decision.tool_version
            && self.tool_digest == decision.tool_digest;
        if !exact
            || self
                .required_capabilities
                .iter()
                .any(|capability| !decision.effective.contains(*capability))
        {
            return Err(ToolError::Authority(
                "authorized browser action does not match exact permission decision".to_owned(),
            ));
        }
        Ok(())
    }

    /// # Errors
    /// Returns an authority error unless the approval is bound to this exact immutable action.
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
            || claim.permission_class != Capability::BrowserInteractive.as_plan_ir_str()
            || claim.payload_digest != self.payload_digest()
            || claim.destination_digest != self.destination_digest
            || claim.executable_digest != self.isolation_policy_digest
            || claim.policy_digest != self.policy_digest
            || claim.execution_epoch != self.execution_epoch
            || claim.nonce != self.nonce
            || claim.expires_at_ms > self.expires_at_ms
        {
            return Err(ToolError::Authority(
                "approval claim does not match exact authorized browser action".to_owned(),
            ));
        }
        Ok(())
    }
}

impl JournalActionAuthority for AuthorizedBrowserAction {
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
    fn permission_class(&self) -> Capability {
        Capability::BrowserInteractive
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
        self.declared_risk
    }
    fn approval_execution_identity_digest(&self) -> Option<&str> {
        Some(&self.isolation_policy_digest)
    }
    fn payload_digest(&self) -> String {
        Self::payload_digest(self)
    }
    fn validate(&self, now_ms: i64) -> Result<(), ToolError> {
        Self::validate(self, now_ms)
    }
    fn verify_permission_decision(&self, decision: &PermissionDecision) -> Result<(), ToolError> {
        Self::verify_permission_decision(self, decision)
    }
    fn verify_approval_claim(&self, claim: &ApprovalClaim, now_ms: i64) -> Result<(), ToolError> {
        Self::verify_approval_claim(self, claim, now_ms)
    }
    fn reservation(&self) -> JournalActionReservation {
        JournalActionReservation {
            tool_actions: 1,
            subprocesses: 0,
            wall_ms: self.action_deadline_ms,
            output_bytes: self.output_bytes,
            disk_write_bytes: 0,
        }
    }
}

#[derive(Debug, Clone)]
struct OwnedTaskLoopbackScope {
    plan_id: String,
    plan_revision: u32,
    task_id: String,
    task_contract_digest: String,
    resource_lease_id: String,
    execution_epoch: i64,
}

impl OwnedTaskLoopbackScope {
    fn borrowed(&self) -> TaskLoopbackScope<'_> {
        TaskLoopbackScope {
            plan_id: &self.plan_id,
            plan_revision: self.plan_revision,
            task_id: &self.task_id,
            task_contract_digest: &self.task_contract_digest,
            resource_lease_id: &self.resource_lease_id,
            execution_epoch: self.execution_epoch,
        }
    }
}

#[derive(Clone)]
pub(crate) struct BrowserGatewayAuthority {
    public_network: NetworkPolicy,
    task_loopback_grants: Vec<TaskLoopbackGrantV1>,
    task_loopback_scope: OwnedTaskLoopbackScope,
    allowed_methods: BTreeSet<String>,
    max_network_bytes: u64,
}

impl BrowserGatewayAuthority {
    fn new(
        task_authority: &BrowserTaskAuthorityV1,
        task_loopback_grants: Vec<TaskLoopbackGrantV1>,
        task_loopback_scope: OwnedTaskLoopbackScope,
        max_network_bytes: u64,
        now_ms: i64,
    ) -> Result<Self, ToolError> {
        let public_network = task_authority
            .public_network_policy()
            .map_err(|error| ToolError::Authority(error.to_string()))?;
        for grant in &task_loopback_grants {
            grant
                .validate(now_ms)
                .map_err(|error| ToolError::Authority(error.to_string()))?;
        }
        if max_network_bytes == 0 {
            return Err(ToolError::ResourceLimit(
                "browser gateway requires nonzero remaining network budget".to_owned(),
            ));
        }
        Ok(Self {
            public_network,
            task_loopback_grants,
            task_loopback_scope,
            allowed_methods: task_authority.allowed_methods.clone(),
            max_network_bytes,
        })
    }

    fn connect_authorized(&self, destination: &NetworkDestination) -> Result<TcpStream, ToolError> {
        if let Some(address) = loopback_ip(&destination.host) {
            let scope = self.task_loopback_scope.borrowed();
            let grant = self
                .task_loopback_grants
                .iter()
                .find(|grant| {
                    grant.scheme == destination.scheme.to_ascii_lowercase()
                        && grant.host == destination.host
                        && grant.port == destination.port
                })
                .ok_or_else(|| {
                    ToolError::Authority(
                        "browser task-loopback destination has no exact Controller grant"
                            .to_owned(),
                    )
                })?;
            grant
                .authorize(&scope, destination, current_unix_millis()?)
                .map_err(|error| ToolError::Authority(error.to_string()))?;
            let stream = TcpStream::connect_timeout(
                &SocketAddr::new(address, destination.port),
                GATEWAY_IO_TIMEOUT,
            )?;
            let peer = stream.peer_addr()?;
            if peer.ip() != address || peer.port() != destination.port {
                return Err(ToolError::Authority(
                    "browser task-loopback connected peer differs from exact grant".to_owned(),
                ));
            }
            return Ok(stream);
        }

        let canonical = self
            .public_network
            .authorize_destination(destination)
            .map_err(|error| ToolError::Authority(error.to_string()))?;
        let resolved = SystemWebDnsResolver
            .resolve(&canonical)
            .map_err(|error| ToolError::Authority(error.to_string()))?;
        let authorization = self
            .public_network
            .authorize_resolved(&canonical, resolved.iter().copied())
            .map_err(|error| ToolError::Authority(error.to_string()))?;
        let address = authorization.resolved_ips().next().ok_or_else(|| {
            ToolError::Authority("browser authorized DNS set became empty".to_owned())
        })?;
        let stream = TcpStream::connect_timeout(
            &SocketAddr::new(address, canonical.port),
            GATEWAY_IO_TIMEOUT,
        )?;
        let peer = stream.peer_addr()?;
        self.public_network
            .authorize_connected_peer(&authorization, peer.ip())
            .map_err(|error| ToolError::Authority(error.to_string()))?;
        if peer.port() != canonical.port {
            return Err(ToolError::Authority(
                "browser connected peer port differs from authorized destination".to_owned(),
            ));
        }
        Ok(stream)
    }
}

pub(crate) struct BrowserGateway {
    port: u16,
    stop: Arc<AtomicBool>,
    transferred_bytes: Arc<AtomicU64>,
    failure: Arc<Mutex<Option<String>>>,
    thread: Option<JoinHandle<()>>,
}

#[derive(Debug, Clone)]
struct BrowserGatewayCapabilityBinding {
    lease_id: String,
    execution_epoch: i64,
    token_digest: String,
    expires_at_ms: i64,
}

impl BrowserGatewayCapabilityBinding {
    fn materialize(&self, localhost_port: u16) -> BrowserLoopbackCapabilityV1 {
        BrowserLoopbackCapabilityV1 {
            schema_version: BROWSER_LOOPBACK_CAPABILITY_SCHEMA_VERSION,
            lease_id: self.lease_id.clone(),
            execution_epoch: self.execution_epoch,
            localhost_port,
            token_digest: self.token_digest.clone(),
            expires_at_ms: self.expires_at_ms,
        }
    }
}

impl BrowserGateway {
    /// Binds the Controller-owned exact loopback proxy before Chrome launch.
    ///
    /// # Errors
    /// Returns an I/O error if the loopback listener cannot be established.
    fn bind(
        authority: BrowserGatewayAuthority,
        capability_binding: &BrowserGatewayCapabilityBinding,
    ) -> Result<(Self, BrowserLoopbackCapabilityV1), ToolError> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let loopback_capability = capability_binding.materialize(port);
        loopback_capability
            .validate(current_unix_millis()?)
            .map_err(|error| ToolError::Authority(error.to_string()))?;
        let stop = Arc::new(AtomicBool::new(false));
        let transferred_bytes = Arc::new(AtomicU64::new(0));
        let failure = Arc::new(Mutex::new(None));
        let stop_thread = Arc::clone(&stop);
        let bytes_thread = Arc::clone(&transferred_bytes);
        let failure_thread = Arc::clone(&failure);
        let loopback_capability_thread = loopback_capability.clone();
        let thread = thread::spawn(move || {
            let mut handlers = Vec::new();
            while !stop_thread.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((client, peer)) => {
                        if !peer.ip().is_loopback() {
                            let _ = client.shutdown(Shutdown::Both);
                            continue;
                        }
                        let handler_authority = authority.clone();
                        let handler_stop = Arc::clone(&stop_thread);
                        let handler_bytes = Arc::clone(&bytes_thread);
                        let handler_failure = Arc::clone(&failure_thread);
                        let handler_capability = loopback_capability_thread.clone();
                        handlers.push(thread::spawn(move || {
                            if let Err(error) = handle_proxy_client(
                                client,
                                &handler_authority,
                                &handler_capability,
                                &handler_stop,
                                &handler_bytes,
                            ) {
                                record_gateway_failure(&handler_failure, error.to_string());
                            }
                        }));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(GATEWAY_POLL);
                    }
                    Err(error) => {
                        record_gateway_failure(&failure_thread, error.to_string());
                        break;
                    }
                }
            }
            for handler in handlers {
                if handler.join().is_err() {
                    record_gateway_failure(
                        &failure_thread,
                        "browser gateway handler panicked".to_owned(),
                    );
                }
            }
        });
        Ok((
            Self {
                port,
                stop,
                transferred_bytes,
                failure,
                thread: Some(thread),
            },
            loopback_capability,
        ))
    }

    #[must_use]
    pub(crate) fn transferred_bytes(&self) -> u64 {
        self.transferred_bytes.load(Ordering::Acquire)
    }

    /// Stops the gateway and returns exact observed transfer usage.
    ///
    /// # Errors
    /// Returns fail-closed if a proxy handler observed a policy/I/O failure or a thread panicked.
    pub(crate) fn shutdown(mut self) -> Result<u64, ToolError> {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
        {
            return Err(ToolError::RecoveryBlocked(
                "browser gateway listener panicked during shutdown".to_owned(),
            ));
        }
        let failure = self
            .failure
            .lock()
            .map_err(|_| {
                ToolError::RecoveryBlocked("browser gateway failure lock poisoned".to_owned())
            })?
            .clone();
        if let Some(failure) = failure {
            return Err(ToolError::Authority(format!(
                "browser gateway denied or failed a connection: {failure}"
            )));
        }
        Ok(self.transferred_bytes())
    }
}

impl Drop for BrowserGateway {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn record_gateway_failure(failure: &Mutex<Option<String>>, message: String) {
    if let Ok(mut failure) = failure.lock()
        && failure.is_none()
    {
        *failure = Some(message);
    }
}

fn handle_proxy_client(
    mut client: TcpStream,
    authority: &BrowserGatewayAuthority,
    loopback_capability: &BrowserLoopbackCapabilityV1,
    stop: &AtomicBool,
    transferred_bytes: &AtomicU64,
) -> Result<(), ToolError> {
    client.set_read_timeout(Some(GATEWAY_IO_TIMEOUT))?;
    client.set_write_timeout(Some(GATEWAY_IO_TIMEOUT))?;
    let request = read_proxy_request(&mut client)?;
    if !proxy_request_authenticated(&request, loopback_capability)? {
        write_proxy_auth_challenge(&mut client)?;
        return Ok(());
    }
    if request.method.eq_ignore_ascii_case("CONNECT") {
        if !authority.allowed_methods.contains("GET") {
            return Err(ToolError::Authority(
                "browser HTTPS proxy requires task network-read authority".to_owned(),
            ));
        }
        let (host, port) = parse_authority(&request.target, "https")?;
        let destination = NetworkDestination {
            scheme: "https".to_owned(),
            host,
            port,
        };
        let mut upstream = authority.connect_authorized(&destination)?;
        upstream.set_read_timeout(Some(GATEWAY_IO_TIMEOUT))?;
        upstream.set_write_timeout(Some(GATEWAY_IO_TIMEOUT))?;
        client.write_all(b"HTTP/1.1 200 Connection Established\r\nConnection: close\r\n\r\n")?;
        tunnel_bidirectional(
            &mut client,
            &mut upstream,
            stop,
            transferred_bytes,
            authority.max_network_bytes,
        )?;
        return Ok(());
    }

    let method = request.method.to_ascii_uppercase();
    if !authority.allowed_methods.contains(&method) {
        return Err(ToolError::Authority(format!(
            "browser HTTP method {method} is outside exact task network policy"
        )));
    }
    let parsed = browser_destination(&request.target)?;
    if parsed.destination.scheme != "http" {
        return Err(ToolError::Authority(
            "plain browser proxy requests must use absolute http URLs".to_owned(),
        ));
    }
    let mut upstream = authority.connect_authorized(&parsed.destination)?;
    upstream.set_read_timeout(Some(GATEWAY_IO_TIMEOUT))?;
    upstream.set_write_timeout(Some(GATEWAY_IO_TIMEOUT))?;
    let origin_target = origin_form(&request.target)?;
    let mut outbound = Vec::new();
    write!(
        &mut outbound,
        "{} {} {}\r\n",
        method, origin_target, request.version
    )?;
    for (name, value) in request.headers {
        if name.eq_ignore_ascii_case("proxy-authorization")
            || name.eq_ignore_ascii_case("proxy-connection")
            || name.eq_ignore_ascii_case("connection")
        {
            continue;
        }
        write!(&mut outbound, "{name}: {value}\r\n")?;
    }
    outbound.extend_from_slice(b"Connection: close\r\n\r\n");
    outbound.extend_from_slice(&request.body_prefix);
    charge_gateway_bytes(
        transferred_bytes,
        authority.max_network_bytes,
        outbound.len(),
    )?;
    upstream.write_all(&outbound)?;
    if request.remaining_body_bytes > 0 {
        relay_exact(
            &mut client,
            &mut upstream,
            request.remaining_body_bytes,
            transferred_bytes,
            authority.max_network_bytes,
        )?;
    }
    relay_to_eof(
        &mut upstream,
        &mut client,
        transferred_bytes,
        authority.max_network_bytes,
    )?;
    Ok(())
}

fn proxy_request_authenticated(
    request: &ProxyRequest,
    loopback_capability: &BrowserLoopbackCapabilityV1,
) -> Result<bool, ToolError> {
    let mut authorization = None;
    for (name, value) in &request.headers {
        if name.eq_ignore_ascii_case("proxy-authorization")
            && authorization.replace(value.as_str()).is_some()
        {
            return Ok(false);
        }
    }
    let Some(authorization) = authorization else {
        return Ok(false);
    };
    let Some((scheme, encoded)) = authorization.split_once(' ') else {
        return Ok(false);
    };
    if !scheme.eq_ignore_ascii_case("basic") || encoded.is_empty() {
        return Ok(false);
    }
    let Some(decoded) = decode_base64_basic(encoded) else {
        return Ok(false);
    };
    let Ok(decoded) = std::str::from_utf8(&decoded) else {
        return Ok(false);
    };
    let Some((username, token)) = decoded.split_once(':') else {
        return Ok(false);
    };
    if username != BROWSER_PROXY_AUTH_USERNAME || token.is_empty() {
        return Ok(false);
    }
    Ok(loopback_capability
        .verify_token(token.as_bytes(), current_unix_millis()?)
        .is_ok())
}

fn write_proxy_auth_challenge(client: &mut TcpStream) -> Result<(), ToolError> {
    write!(
        client,
        "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"{BROWSER_PROXY_AUTH_REALM}\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )?;
    client.flush()?;
    Ok(())
}

fn decode_base64_basic(encoded: &str) -> Option<Vec<u8>> {
    let input = encoded.as_bytes();
    if input.is_empty() || !input.len().is_multiple_of(4) {
        return None;
    }
    let mut output = Vec::with_capacity(input.len() / 4 * 3);
    let chunk_count = input.len() / 4;
    for (index, chunk) in input.chunks_exact(4).enumerate() {
        let &[first, second, third, fourth] = chunk else {
            return None;
        };
        if first == b'=' || second == b'=' {
            return None;
        }
        let a = base64_value(first)?;
        let b = base64_value(second)?;
        let last = index + 1 == chunk_count;
        match (third, fourth) {
            (b'=', b'=') if last => {
                output.push((a << 2) | (b >> 4));
            }
            (_, b'=') if last => {
                let c = base64_value(third)?;
                output.push((a << 2) | (b >> 4));
                output.push((b << 4) | (c >> 2));
            }
            (b'=', _) => return None,
            (_, _) => {
                let c = base64_value(third)?;
                let d = base64_value(fourth)?;
                output.push((a << 2) | (b >> 4));
                output.push((b << 4) | (c >> 2));
                output.push((c << 6) | d);
            }
        }
    }
    Some(output)
}

const fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

struct ProxyRequest {
    method: String,
    target: String,
    version: String,
    headers: Vec<(String, String)>,
    body_prefix: Vec<u8>,
    remaining_body_bytes: usize,
}

fn read_proxy_request(stream: &mut TcpStream) -> Result<ProxyRequest, ToolError> {
    let mut buffer = Vec::with_capacity(4096);
    let mut scratch = [0_u8; 4096];
    let header_end = loop {
        let read = stream.read(&mut scratch)?;
        if read == 0 {
            return Err(ToolError::Authority(
                "browser proxy client closed before complete headers".to_owned(),
            ));
        }
        buffer.extend_from_slice(&scratch[..read]);
        if buffer.len() > MAX_PROXY_HEADER_BYTES {
            return Err(ToolError::ResourceLimit(
                "browser proxy headers exceed static bound".to_owned(),
            ));
        }
        if let Some(index) = find_bytes(&buffer, b"\r\n\r\n") {
            break index + 4;
        }
    };
    let head = std::str::from_utf8(&buffer[..header_end]).map_err(|_| {
        ToolError::Authority("browser proxy headers are not UTF-8/ASCII".to_owned())
    })?;
    let mut lines = head.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| ToolError::Authority("browser proxy request line missing".to_owned()))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| ToolError::Authority("browser proxy method missing".to_owned()))?;
    let target = parts
        .next()
        .ok_or_else(|| ToolError::Authority("browser proxy target missing".to_owned()))?;
    let version = parts
        .next()
        .ok_or_else(|| ToolError::Authority("browser proxy HTTP version missing".to_owned()))?;
    if parts.next().is_some() || !version.starts_with("HTTP/1.") {
        return Err(ToolError::Authority(
            "browser proxy request line is malformed".to_owned(),
        ));
    }
    let mut headers = Vec::new();
    let mut content_length = 0_usize;
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| ToolError::Authority("browser proxy header is malformed".to_owned()))?;
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.parse::<usize>().map_err(|_| {
                ToolError::Authority("browser proxy content-length is invalid".to_owned())
            })?;
        }
        headers.push((name.to_owned(), value.to_owned()));
    }
    let already = buffer.len().saturating_sub(header_end).min(content_length);
    let body_prefix = buffer[header_end..header_end + already].to_vec();
    Ok(ProxyRequest {
        method: method.to_owned(),
        target: target.to_owned(),
        version: version.to_owned(),
        headers,
        body_prefix,
        remaining_body_bytes: content_length.saturating_sub(already),
    })
}

fn origin_form(url: &str) -> Result<String, ToolError> {
    let (_, remainder) = url
        .split_once("://")
        .ok_or_else(|| ToolError::Authority("proxy URL is not absolute".to_owned()))?;
    let path = remainder
        .find(['/', '?', '#'])
        .map_or("/", |index| &remainder[index..]);
    if path.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(ToolError::Authority(
            "proxy origin-form target contains control bytes".to_owned(),
        ));
    }
    Ok(path.to_owned())
}

fn relay_exact(
    source: &mut TcpStream,
    destination: &mut TcpStream,
    mut remaining: usize,
    transferred_bytes: &AtomicU64,
    max_network_bytes: u64,
) -> Result<(), ToolError> {
    let mut buffer = [0_u8; 16 * 1024];
    while remaining > 0 {
        let chunk = remaining.min(buffer.len());
        let read = source.read(&mut buffer[..chunk])?;
        if read == 0 {
            return Err(ToolError::Authority(
                "browser proxy body ended before declared content-length".to_owned(),
            ));
        }
        charge_gateway_bytes(transferred_bytes, max_network_bytes, read)?;
        destination.write_all(&buffer[..read])?;
        remaining -= read;
    }
    Ok(())
}

fn relay_to_eof(
    source: &mut TcpStream,
    destination: &mut TcpStream,
    transferred_bytes: &AtomicU64,
    max_network_bytes: u64,
) -> Result<(), ToolError> {
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        match source.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(read) => {
                charge_gateway_bytes(transferred_bytes, max_network_bytes, read)?;
                destination.write_all(&buffer[..read])?;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Ok(());
            }
            Err(error) => return Err(ToolError::Io(error)),
        }
    }
}

fn tunnel_bidirectional(
    client: &mut TcpStream,
    upstream: &mut TcpStream,
    stop: &AtomicBool,
    transferred_bytes: &AtomicU64,
    max_network_bytes: u64,
) -> Result<(), ToolError> {
    client.set_nonblocking(true)?;
    upstream.set_nonblocking(true)?;
    let mut client_open = true;
    let mut upstream_open = true;
    let mut buffer = [0_u8; 16 * 1024];
    while !stop.load(Ordering::Acquire) && (client_open || upstream_open) {
        let mut progressed = false;
        if client_open {
            match client.read(&mut buffer) {
                Ok(0) => client_open = false,
                Ok(read) => {
                    charge_gateway_bytes(transferred_bytes, max_network_bytes, read)?;
                    upstream.write_all(&buffer[..read])?;
                    progressed = true;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(ToolError::Io(error)),
            }
        }
        if upstream_open {
            match upstream.read(&mut buffer) {
                Ok(0) => upstream_open = false,
                Ok(read) => {
                    charge_gateway_bytes(transferred_bytes, max_network_bytes, read)?;
                    client.write_all(&buffer[..read])?;
                    progressed = true;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(ToolError::Io(error)),
            }
        }
        if !progressed {
            thread::sleep(GATEWAY_POLL);
        }
    }
    let _ = client.shutdown(Shutdown::Both);
    let _ = upstream.shutdown(Shutdown::Both);
    Ok(())
}

fn charge_gateway_bytes(
    transferred_bytes: &AtomicU64,
    max_network_bytes: u64,
    delta: usize,
) -> Result<(), ToolError> {
    let delta = u64::try_from(delta).map_err(|_| {
        ToolError::ResourceLimit("browser network byte counter overflow".to_owned())
    })?;
    let mut current = transferred_bytes.load(Ordering::Acquire);
    loop {
        let next = current.checked_add(delta).ok_or_else(|| {
            ToolError::ResourceLimit("browser network byte counter overflow".to_owned())
        })?;
        if next > max_network_bytes {
            return Err(ToolError::ResourceLimit(format!(
                "browser network transfer {next} exceeds exact remaining budget {max_network_bytes}"
            )));
        }
        match transferred_bytes.compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => return Ok(()),
            Err(observed) => current = observed,
        }
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn is_sha256(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn digest_field(hasher: &mut Sha256, value: &str) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn current_unix_millis() -> Result<i64, ToolError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            ToolError::Authority(format!("system clock precedes Unix epoch: {error}"))
        })?
        .as_millis();
    i64::try_from(millis)
        .map_err(|_| ToolError::ResourceLimit("Unix millisecond timestamp overflow".to_owned()))
}

#[cfg(test)]
mod browser_download_terminal_tests {
    use super::{
        AuthorizedBrowserAction, BROWSER_DOWNLOAD_RECORD_NAMESPACE,
        BROWSER_RESOURCE_RESIDENCY_SCHEMA_VERSION, BROWSER_SCHEMA_VERSION, BrowserAdapterConfig,
        BrowserDownloadMode, BrowserDownloadPolicyV1, BrowserDownloadRetentionPolicyV1,
        BrowserDownloadRootAuthorityV1, BrowserNetworkReservationStateV1,
        BrowserNetworkSettlementV1, BrowserProfileAuthority, BrowserProfileMode,
        BrowserResourceResidencyStateV1, BrowserResourceResidencyV1, BrowserTaskAuthorityV1,
        Controller, ControllerBrowserSession,
    };
    use crate::{
        ActivePlan, ActiveRepositoryState, AttemptRuntime, AttemptState, PlanValidity,
        ResourceResidencyStateV1, ResourceResidencyV1, TaskRuntime, TaskState,
        valid_plan_ir_fixture, valid_task_fixture,
    };
    use serde_json::json;
    use sovereign_context::{ContextLevel, EvidenceKind, PacketSection, TrustClass};
    use sovereign_evidence::ArtifactStore;
    use sovereign_model::{
        BackendHealth, MODEL_SCHEMA_VERSION, ModelBackend, ModelCapabilities, ModelError,
        ModelLease, ModelLoadProfile, ModelRequest, ModelResidencyProof, ModelResponse,
    };
    use sovereign_policy::browser::{
        BROWSER_DOWNLOAD_POLICY_SCHEMA_VERSION, BROWSER_LOOPBACK_CAPABILITY_SCHEMA_VERSION,
        BrowserLoopbackCapabilityV1,
    };
    use sovereign_policy::{
        AUTONOMY_BUDGET_SCHEMA_VERSION, AdmissionStatus, AutonomyBudgetV1, Capability,
        CapabilityLayers, CapabilitySet, CommandRisk, ConditionalLeaseContextV1, HeavyLeaseClass,
        LeaseStateV1, OsMemoryPressure, PermissionDecision, PlanHeavyLeaseClass,
        RESOURCE_LEASE_SCHEMA_VERSION, ResourceLeaseOwnerV1, ResourceLeaseRequestV1,
        ResourceLeaseV1, ResourcePressureSnapshotV1, TaskResourceBudgetV1, ThermalPressure,
        TrustLevel, TrustSource,
    };
    use sovereign_repo::{ChangeClassSnapshot, RepositorySnapshot};
    use sovereign_state::{ActionTransition, NewActionRecord, StateStore};
    use sovereign_tools::browser::{
        BrowserAction, BrowserActionEffect, BrowserDownloadTerminalObservation,
        BrowserDownloadTerminalState, BrowserLease, BrowserSensitivePageReason,
        BrowserSensitivePageSignal, BrowserStateSynopsis, DownloadReceipt,
    };
    use sovereign_tools::{ActionState, ReconciliationMode};
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    fn lease() -> BrowserLease {
        BrowserLease {
            schema_version: BROWSER_SCHEMA_VERSION,
            lease_id: "browser.controller.download.lease".to_owned(),
            task_id: "task.browser.download".to_owned(),
            attempt_id: "attempt.browser.download".to_owned(),
            execution_epoch: 17,
            token: "controller-download-terminal-token".to_owned(),
        }
    }

    fn terminal(
        lease: &BrowserLease,
        state: BrowserDownloadTerminalState,
        guid: &str,
    ) -> BrowserDownloadTerminalObservation {
        BrowserDownloadTerminalObservation {
            schema_version: BROWSER_SCHEMA_VERSION,
            lease_id: lease.lease_id.clone(),
            lease_binding_digest: lease.binding_digest(),
            execution_epoch: lease.execution_epoch,
            guid: guid.to_owned(),
            relative_path: PathBuf::from(guid),
            state,
        }
    }

    fn resource_lease() -> ResourceLeaseV1 {
        ResourceLeaseV1 {
            schema_version: RESOURCE_LEASE_SCHEMA_VERSION,
            lease_id: "browser:plan.browser:r1:task.browser:17".to_owned(),
            owner: ResourceLeaseOwnerV1 {
                plan_id: "plan.browser".to_owned(),
                plan_revision: 1,
                task_id: "task.browser".to_owned(),
            },
            class: HeavyLeaseClass::CdpBrowser,
            plan_ir_class: PlanHeavyLeaseClass::Browser,
            profile_id: "m1-8gb".to_owned(),
            profile_digest: "sha256:profile".to_owned(),
            admitted_pressure_event_id: "pressure.browser".to_owned(),
            admitted_at_ms: 1,
            last_used_at_ms: 1,
            idle_since_ms: None,
            idle_ttl_seconds: 60,
            state: LeaseStateV1::Active,
            calibrated: false,
            admission_rss_mib: 1_536,
            projected_controlled_rss_mib: 2_048,
            projected_host_headroom_mib: 4_096,
            task_max_peak_rss_mib: 5_500,
        }
    }

    fn browser_residency(lease: &ResourceLeaseV1) -> BrowserResourceResidencyV1 {
        BrowserResourceResidencyV1 {
            schema_version: BROWSER_RESOURCE_RESIDENCY_SCHEMA_VERSION,
            plan_id: lease.owner.plan_id.clone(),
            plan_revision: lease.owner.plan_revision,
            task_id: lease.owner.task_id.clone(),
            task_contract_digest: "sha256:task-contract".to_owned(),
            execution_epoch: 17,
            policy_lease: lease.clone(),
            browser_lease_id: lease.lease_id.clone(),
            browser_lease_binding_digest: "sha256:browser-binding".to_owned(),
            loopback_capability: BrowserLoopbackCapabilityV1 {
                schema_version: BROWSER_LOOPBACK_CAPABILITY_SCHEMA_VERSION,
                lease_id: lease.lease_id.clone(),
                execution_epoch: 17,
                localhost_port: 49_999,
                token_digest: "sha256:browser-token".to_owned(),
                expires_at_ms: 60_000,
            },
            state: BrowserResourceResidencyStateV1::Resident,
            process_group_id: Some(42),
            process_group_leader_identity: Some("fixture-browser-process".to_owned()),
            private_parent: PathBuf::from("/tmp/sovereign-browser"),
            profile_root: PathBuf::from("/tmp/sovereign-browser/profile"),
            download_root: None,
            ephemeral_profile: true,
            updated_at_ms: 1,
        }
    }

    static NEXT_FIXTURE_ID: AtomicU64 = AtomicU64::new(1);

    struct DurableFixture {
        controller: Controller,
        root: PathBuf,
    }

    struct HandoffModelBackend {
        unloaded: AtomicBool,
        prove_absent: bool,
    }

    fn fixture_resource_policy(budget: &AutonomyBudgetV1) -> serde_json::Value {
        assert_eq!(budget.max_wall_ms % 1_000, 0);
        assert_eq!(budget.max_model_call_ms % 1_000, 0);
        assert_eq!(budget.max_single_tool_action_ms % 1_000, 0);
        assert_eq!(budget.max_child_cpu_ms % 1_000, 0);
        json!({
            "max_wall_seconds": budget.max_wall_ms / 1_000,
            "max_model_calls": budget.max_model_calls,
            "max_model_call_seconds": budget.max_model_call_ms / 1_000,
            "max_tool_actions": budget.max_tool_actions,
            "max_single_tool_action_seconds": budget.max_single_tool_action_ms / 1_000,
            "max_peak_rss_mb": 4096,
            "max_output_bytes": budget.max_output_bytes,
            "max_retained_raw_bytes": budget.max_output_bytes,
            "max_disk_write_mb": budget.max_disk_write_bytes / (1024 * 1024),
            "max_network_bytes": budget.max_network_bytes,
            "max_subprocesses": budget.max_subprocesses,
            "max_child_cpu_seconds": budget.max_child_cpu_ms / 1_000,
            "heavy_leases": ["MODEL", "BUILD_HEAVY"]
        })
    }

    impl HandoffModelBackend {
        const fn new(prove_absent: bool) -> Self {
            Self {
                unloaded: AtomicBool::new(false),
                prove_absent,
            }
        }
    }

    impl ModelBackend for HandoffModelBackend {
        fn capabilities(&self) -> ModelCapabilities {
            ModelCapabilities {
                schema_version: MODEL_SCHEMA_VERSION,
                model_id: "handoff-test-model".to_owned(),
                parameter_class: "test".to_owned(),
                quantization: "test".to_owned(),
                max_context_tokens: 4_096,
                supports_tools: false,
                supports_json_schema: false,
                local: true,
            }
        }

        fn load(&self, _profile: ModelLoadProfile) -> Result<ModelLease, ModelError> {
            Err(ModelError::NotLoaded)
        }

        fn complete(&self, _request: &ModelRequest) -> Result<ModelResponse, ModelError> {
            Err(ModelError::NotLoaded)
        }

        fn count_tokens(&self, _content: &str) -> Result<u32, ModelError> {
            Err(ModelError::NotLoaded)
        }

        fn health(&self) -> Result<BackendHealth, ModelError> {
            Ok(BackendHealth {
                reachable: true,
                loaded: !self.unloaded.load(Ordering::Acquire),
                detail: "test backend".to_owned(),
            })
        }

        fn residency_proof(&self) -> Result<ModelResidencyProof, ModelError> {
            if !self.unloaded.load(Ordering::Acquire) {
                return Ok(ModelResidencyProof::Resident { process_id: None });
            }
            Ok(if self.prove_absent {
                ModelResidencyProof::Absent
            } else {
                ModelResidencyProof::Unknown
            })
        }

        fn unload(&self) -> Result<(), ModelError> {
            self.unloaded.store(true, Ordering::Release);
            Ok(())
        }
    }

    impl Drop for DurableFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn autonomy_budget(
        max_network_bytes: u64,
        used_network_bytes: u64,
        max_disk_write_bytes: u64,
        used_disk_write_bytes: u64,
    ) -> AutonomyBudgetV1 {
        AutonomyBudgetV1 {
            schema_version: AUTONOMY_BUDGET_SCHEMA_VERSION,
            max_wall_ms: 60_000,
            max_model_calls: 10,
            max_model_call_ms: 30_000,
            max_tool_actions: 20,
            max_single_tool_action_ms: 30_000,
            max_output_bytes: 1_000_000,
            max_disk_write_bytes,
            max_network_bytes,
            max_subprocesses: 4,
            max_child_cpu_ms: 60_000,
            used_wall_ms: 0,
            used_model_calls: 0,
            used_tool_actions: 0,
            used_output_bytes: 0,
            used_disk_write_bytes,
            used_network_bytes,
            used_subprocesses: 0,
            used_child_cpu_ms: 0,
        }
    }

    fn green_pressure(observed_at_ms: i64) -> ResourcePressureSnapshotV1 {
        ResourcePressureSnapshotV1 {
            schema_version: 1,
            observed_at_ms,
            controlled_working_set_mib: 512,
            host_headroom_mib: 6_000,
            swap_used_mib: Some(0),
            swap_out_growth_mib_per_min: 0,
            compressor_growth_mib_per_min: 0,
            os_memory_pressure: OsMemoryPressure::Normal,
            recent_pressure_event: false,
            thermal_pressure: ThermalPressure::Normal,
            allocation_failure: false,
            repeated_resource_kill: false,
            uncontrolled_child_growth: false,
            host_free_disk_mib: Some(64 * 1_024),
        }
    }

    fn install_resident_model(controller: &mut Controller) -> ResourceLeaseV1 {
        let pressure = controller.resources.observe_pressure(green_pressure(1_000));
        let request = ResourceLeaseRequestV1 {
            lease_id: "model:plan.browser:r1:task.browser:17".to_owned(),
            owner: ResourceLeaseOwnerV1 {
                plan_id: "plan.browser".to_owned(),
                plan_revision: 1,
                task_id: "task.browser".to_owned(),
            },
            class: HeavyLeaseClass::Model,
            calibrated: true,
            calibrated_p95_rss_mib: 2_048,
            evictable_idle_rss_mib: 2_048,
            task_budget: TaskResourceBudgetV1::new(5_500, 4, [PlanHeavyLeaseClass::Model]),
            conditional: ConditionalLeaseContextV1::default(),
            automatic_reload: false,
            disk_expanding: false,
        };
        let admission = controller.resources.admit(&request, &pressure);
        assert_eq!(admission.status, AdmissionStatus::Admitted);
        let lease = admission
            .lease
            .unwrap_or_else(|| panic!("MODEL fixture admission omitted its lease"));
        controller
            .resources
            .set_model_residency(ResourceResidencyV1 {
                schema_version: 1,
                plan_id: "plan.browser".to_owned(),
                plan_revision: 1,
                task_id: "task.browser".to_owned(),
                task_contract_digest: "sha256:task-contract".to_owned(),
                execution_epoch: 17,
                policy_lease: lease.clone(),
                model_lease: None,
                state: ResourceResidencyStateV1::Resident,
                updated_at_ms: 1_000,
            });
        lease
    }

    fn empty_snapshot(root: &Path) -> RepositorySnapshot {
        let empty = ChangeClassSnapshot {
            digest: "sha256:empty".to_owned(),
            paths: Vec::new(),
        };
        RepositorySnapshot {
            repository_id: "repo.browser".to_owned(),
            root: root.to_path_buf(),
            head: Some("0123456789abcdef".to_owned()),
            branch: Some("main".to_owned()),
            staged: empty.clone(),
            unstaged: empty.clone(),
            untracked: empty,
            dirty_digest: "sha256:clean".to_owned(),
            protected_changes_present: false,
        }
    }

    fn durable_fixture(
        task_budget: AutonomyBudgetV1,
        goal_budget: AutonomyBudgetV1,
    ) -> DurableFixture {
        let id = NEXT_FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "sovereign-browser-controller-test-{}-{id}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap_or_else(|error| panic!("create fixture root: {error}"));
        let state = StateStore::open(root.join("state.sqlite"))
            .unwrap_or_else(|error| panic!("open fixture state: {error}"));
        let mut controller = Controller::new(state);
        let mut task = valid_task_fixture("task.browser", &["repo.browser"], false);
        task["resource_budget"] = fixture_resource_policy(&task_budget);
        let mut plan_document = valid_plan_ir_fixture();
        plan_document["plan_id"] = json!("plan.browser");
        plan_document["revision"] = json!(1);
        plan_document["supersedes_revision"] = serde_json::Value::Null;
        plan_document["compiled_at"] = json!("2026-09-19T05:00:00Z");
        plan_document["goal"]["goal_id"] = json!("goal.browser");
        plan_document["policy"]["resources"] = fixture_resource_policy(&goal_budget);
        plan_document["repositories"][0]["repository_id"] = json!("repo.browser");
        plan_document["repositories"][0]["root"] = json!(root);
        plan_document["repositories"][0]["instructions"] = json!([]);
        plan_document["tasks"] = json!([task.clone()]);
        plan_document["edges"] = json!([]);
        let task_runtime = TaskRuntime {
            state: crate::TaskState::Running,
            attempts_started: 1,
            model_calls_used: 0,
            autonomy_budget: Some(task_budget),
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
            integration_views: BTreeMap::new(),
            task_contract_digest: "sha256:task-contract".to_owned(),
            task,
        };
        controller.active = Some(ActivePlan {
            plan_document,
            compiler_plan_digest: "sha256:compiler-plan".to_owned(),
            plan_id: "plan.browser".to_owned(),
            goal_id: "goal.browser".to_owned(),
            revision: 1,
            plan_digest: "sha256:plan".to_owned(),
            compilation_evidence_digest: "sha256:compile".to_owned(),
            policy_digest: "sha256:policy".to_owned(),
            repositories: BTreeMap::from([(
                "repo.browser".to_owned(),
                ActiveRepositoryState {
                    repository_id: "repo.browser".to_owned(),
                    repository_root: root.clone(),
                    baseline: empty_snapshot(&root),
                    baseline_diff_digest: "sha256:diff".to_owned(),
                    baseline_diff_content: String::new(),
                },
            )]),
            validity: PlanValidity::Current,
            goal_autonomy_budget: goal_budget,
            tasks: BTreeMap::from([("task.browser".to_owned(), task_runtime)]),
            attempts: BTreeMap::new(),
        });
        DurableFixture { controller, root }
    }

    fn budget_usage(controller: &Controller) -> (u64, u64, u64, u64) {
        let active = controller
            .active
            .as_ref()
            .unwrap_or_else(|| panic!("fixture active plan disappeared"));
        let task = active
            .tasks
            .get("task.browser")
            .and_then(|task| task.autonomy_budget.as_ref())
            .unwrap_or_else(|| panic!("fixture task budget disappeared"));
        (
            task.used_network_bytes,
            active.goal_autonomy_budget.used_network_bytes,
            task.used_disk_write_bytes,
            active.goal_autonomy_budget.used_disk_write_bytes,
        )
    }

    fn seed_checkpoint_resource_policy(controller: &mut Controller) {
        let budget = controller.active.as_ref().map_or_else(
            || panic!("fixture active plan disappeared"),
            |active| active.goal_autonomy_budget.clone(),
        );
        controller
            .active
            .as_mut()
            .unwrap_or_else(|| panic!("fixture active plan disappeared"))
            .plan_document["policy"]["resources"] = fixture_resource_policy(&budget);
    }

    fn seed_running_attempt(controller: &mut Controller) {
        controller
            .active
            .as_mut()
            .unwrap_or_else(|| panic!("fixture active plan disappeared"))
            .attempts
            .insert(
                "attempt.browser".to_owned(),
                AttemptRuntime {
                    task_id: "task.browser".to_owned(),
                    attempt_id: "attempt.browser".to_owned(),
                    state: AttemptState::Executing,
                    task_contract_digest: "sha256:task-contract".to_owned(),
                    repair_origin: None,
                    baseline_digest: "sha256:baseline".to_owned(),
                    pre_snapshot_digest: "sha256:pre-snapshot".to_owned(),
                    pre_diff_digest: "sha256:pre-diff".to_owned(),
                    pre_changed_fingerprints: BTreeMap::new(),
                },
            );
    }

    fn admit_browser_lease_for_unknown_test(controller: &mut Controller) -> ResourceLeaseV1 {
        let pressure = controller.resources.observe_pressure(green_pressure(2_000));
        let request = ResourceLeaseRequestV1 {
            lease_id: "browser:unknown-test".to_owned(),
            owner: ResourceLeaseOwnerV1 {
                plan_id: "plan.browser".to_owned(),
                plan_revision: 1,
                task_id: "task.browser".to_owned(),
            },
            class: HeavyLeaseClass::CdpBrowser,
            calibrated: true,
            calibrated_p95_rss_mib: 512,
            evictable_idle_rss_mib: 512,
            task_budget: TaskResourceBudgetV1::new(5_500, 4, [PlanHeavyLeaseClass::Browser]),
            conditional: ConditionalLeaseContextV1::default(),
            automatic_reload: false,
            disk_expanding: false,
        };
        let admission = controller.resources.admit(&request, &pressure);
        assert_eq!(admission.status, AdmissionStatus::Admitted);
        admission
            .lease
            .unwrap_or_else(|| panic!("browser unknown fixture admission omitted lease"))
    }

    fn download_session(root: &Path, max_retained_raw_bytes: u64) -> ControllerBrowserSession {
        let root = fs::canonicalize(root)
            .unwrap_or_else(|error| panic!("canonicalize download root: {error}"));
        let resource_lease = resource_lease();
        let browser_lease = BrowserLease {
            schema_version: BROWSER_SCHEMA_VERSION,
            lease_id: resource_lease.lease_id.clone(),
            task_id: "task.browser".to_owned(),
            attempt_id: "attempt.browser".to_owned(),
            execution_epoch: 17,
            token: "controller-download-budget-token".to_owned(),
        };
        let capability_set =
            CapabilitySet::new([Capability::BrowserInteractive, Capability::NetworkRead]);
        let layers = CapabilityLayers {
            global: capability_set.clone(),
            project: capability_set.clone(),
            task: capability_set.clone(),
            role: capability_set.clone(),
            tool: capability_set.clone(),
            user: capability_set,
        };
        let permission_decision = PermissionDecision::new(
            "plan.browser",
            1,
            "task.browser",
            format!("sha256:{:064x}", 1),
            format!("sha256:{:064x}", 2),
            "browser.test",
            "1",
            format!("sha256:{:064x}", 3),
            layers,
        )
        .unwrap_or_else(|error| panic!("create permission decision: {error}"));
        let download_policy = BrowserDownloadPolicyV1 {
            schema_version: BROWSER_DOWNLOAD_POLICY_SCHEMA_VERSION,
            mode: BrowserDownloadMode::TaskScoped,
            root_authority: Some(BrowserDownloadRootAuthorityV1 {
                lease_id: resource_lease.lease_id.clone(),
                execution_epoch: 17,
                root: root.clone(),
            }),
            retention: BrowserDownloadRetentionPolicyV1 {
                max_file_bytes: max_retained_raw_bytes.max(1),
                allowed_content_types: BTreeSet::new(),
            },
        };
        ControllerBrowserSession {
            plan_id: "plan.browser".to_owned(),
            plan_revision: 1,
            task_id: "task.browser".to_owned(),
            task_contract_digest: "sha256:task-contract".to_owned(),
            attempt_id: "attempt.browser".to_owned(),
            execution_epoch: 17,
            resource_lease,
            browser_lease,
            permission_decision,
            authority: BrowserTaskAuthorityV1 {
                schema_version: super::BROWSER_AUTHORITY_SCHEMA_VERSION,
                allowed_domains: BTreeSet::new(),
                allowed_schemes: BTreeSet::new(),
                allowed_ports: BTreeSet::new(),
                allowed_methods: BTreeSet::new(),
                follow_redirects: false,
                max_redirects: 0,
                allow_task_loopback: false,
                max_tabs: 1,
                downloads_allowed: true,
                profile_mode: BrowserProfileMode::Isolated,
                download_root: Some("downloads".to_owned()),
            },
            profile_authority: BrowserProfileAuthority::Isolated,
            loopback_capability: BrowserLoopbackCapabilityV1 {
                schema_version: BROWSER_LOOPBACK_CAPABILITY_SCHEMA_VERSION,
                lease_id: "browser:plan.browser:r1:task.browser:17".to_owned(),
                execution_epoch: 17,
                localhost_port: 49_999,
                token_digest: "sha256:browser-token".to_owned(),
                expires_at_ms: i64::MAX,
            },
            task_loopback_grants: Vec::new(),
            download_root: Some(root),
            download_policy,
            max_retained_raw_bytes,
            retained_download_bytes: 0,
            reserved_network_bytes: 0,
            sensitive_page_observed: false,
            adapter_config: BrowserAdapterConfig::default(),
            adapter: None,
            gateway: None,
        }
    }

    fn download_receipt(
        session: &ControllerBrowserSession,
        path: &str,
        bytes: u64,
    ) -> DownloadReceipt {
        DownloadReceipt {
            schema_version: BROWSER_SCHEMA_VERSION,
            lease_id: session.browser_lease.lease_id.clone(),
            lease_binding_digest: session.browser_lease.binding_digest(),
            execution_epoch: session.execution_epoch,
            relative_path: PathBuf::from(path),
            bytes,
            sha256: format!("sha256:{bytes:064x}"),
            content_type: "application/octet-stream".to_owned(),
            auto_opened_or_executed: false,
        }
    }

    fn authorized_synopsis_action(execution_epoch: i64) -> AuthorizedBrowserAction {
        AuthorizedBrowserAction {
            action_id: "browser.capture.synopsis.test".to_owned(),
            plan_id: "plan.browser".to_owned(),
            plan_revision: 1,
            task_id: "task.browser".to_owned(),
            attempt_id: "attempt.browser".to_owned(),
            tool_id: "browser.test".to_owned(),
            tool_version: "1".to_owned(),
            tool_digest: format!("sha256:{:064x}", 3),
            repository_id: "repo.browser".to_owned(),
            destination_digest: None,
            execution_epoch,
            policy_digest: format!("sha256:{:064x}", 2),
            permission_decision_digest: format!("sha256:{:064x}", 4),
            isolation_policy_digest: format!("sha256:{:064x}", 5),
            nonce: "nonce.browser-synopsis-test".to_owned(),
            expires_at_ms: i64::MAX,
            browser_action_digest: format!("sha256:{:064x}", 6),
            required_capabilities: BTreeSet::from([Capability::BrowserInteractive]),
            approval_required: false,
            reconciliation_mode: ReconciliationMode::IdempotentRead,
            declared_risk: CommandRisk::ReadOnly,
            action_deadline_ms: 5_000,
            output_bytes: 8_192,
        }
    }

    fn seed_committed_browser_receipt(
        controller: &mut Controller,
        authorized: &AuthorizedBrowserAction,
        receipt_bytes: &[u8],
        artifacts: &ArtifactStore,
    ) -> String {
        let artifact = artifacts
            .put(&mut controller.state, receipt_bytes)
            .unwrap_or_else(|error| panic!("publish synopsis receipt: {error}"));
        let payload_digest = authorized.payload_digest();
        controller
            .state
            .insert_action_record(NewActionRecord {
                action_id: &authorized.action_id,
                state: ActionState::Dispatched.as_str(),
                payload_digest: &payload_digest,
                policy_digest: &authorized.policy_digest,
                execution_epoch: authorized.execution_epoch,
                event_id: "browser-synopsis-dispatched",
                event_kind: ActionState::Dispatched.as_str(),
                payload_json: "{}",
            })
            .unwrap_or_else(|error| panic!("seed dispatched synopsis action: {error}"));
        controller
            .state
            .transition_action_with_event(ActionTransition {
                action_id: &authorized.action_id,
                expected_state: ActionState::Dispatched.as_str(),
                next_state: ActionState::Observed.as_str(),
                expected_epoch: authorized.execution_epoch,
                event_id: "browser-synopsis-observed",
                event_kind: ActionState::Observed.as_str(),
                payload_json: "{}",
                result_digest: Some(&artifact.digest),
            })
            .unwrap_or_else(|error| panic!("seed observed synopsis action: {error}"));
        controller
            .state
            .transition_action_with_event(ActionTransition {
                action_id: &authorized.action_id,
                expected_state: ActionState::Observed.as_str(),
                next_state: ActionState::Committed.as_str(),
                expected_epoch: authorized.execution_epoch,
                event_id: "browser-synopsis-committed",
                event_kind: ActionState::Committed.as_str(),
                payload_json: "{}",
                result_digest: None,
            })
            .unwrap_or_else(|error| panic!("seed committed synopsis action: {error}"));
        artifact.digest
    }

    #[test]
    fn browser_resource_activity_synchronizes_only_the_exact_logical_lease() {
        let mut session_lease = resource_lease();
        let mut residency = browser_residency(&session_lease);
        let mut idle = session_lease.clone();
        idle.state = LeaseStateV1::Idle;
        idle.idle_since_ms = Some(5_000);

        Controller::synchronize_browser_resource_lease_copies(
            &mut session_lease,
            &mut residency,
            &idle,
            5_000,
        )
        .unwrap_or_else(|error| panic!("exact idle lease synchronization failed: {error}"));
        assert_eq!(session_lease, idle);
        assert_eq!(residency.policy_lease, idle);
        assert_eq!(residency.updated_at_ms, 5_000);

        let exact_session = session_lease.clone();
        let exact_residency = residency.clone();
        let mut foreign = idle;
        foreign.lease_id = "browser:foreign".to_owned();
        assert!(
            Controller::synchronize_browser_resource_lease_copies(
                &mut session_lease,
                &mut residency,
                &foreign,
                6_000,
            )
            .is_err()
        );
        assert_eq!(session_lease, exact_session);
        assert_eq!(residency, exact_residency);
    }

    #[test]
    fn browser_handoff_evicts_resident_model_only_after_proven_physical_absence() {
        let mut fixture = durable_fixture(
            autonomy_budget(1_000, 0, 1_048_576, 0),
            autonomy_budget(1_000, 0, 1_048_576, 0),
        );
        seed_checkpoint_resource_policy(&mut fixture.controller);
        let lease = install_resident_model(&mut fixture.controller);
        let backend = HandoffModelBackend::new(true);

        fixture
            .controller
            .evict_model_before_browser(&backend)
            .unwrap_or_else(|error| panic!("MODEL handoff should prove absence: {error}"));
        assert!(backend.unloaded.load(Ordering::Acquire));
        assert!(fixture.controller.resources.model_residency().is_none());
        assert!(
            fixture
                .controller
                .resources
                .active_lease(&lease.lease_id)
                .is_none(),
            "logical MODEL lease must be retired only after absence proof"
        );
    }

    #[test]
    fn browser_handoff_keeps_model_lease_when_post_unload_absence_is_unknown() {
        let mut fixture = durable_fixture(
            autonomy_budget(1_000, 0, 1_048_576, 0),
            autonomy_budget(1_000, 0, 1_048_576, 0),
        );
        seed_checkpoint_resource_policy(&mut fixture.controller);
        let lease = install_resident_model(&mut fixture.controller);
        let backend = HandoffModelBackend::new(false);

        assert!(
            fixture
                .controller
                .evict_model_before_browser(&backend)
                .is_err(),
            "unproven MODEL absence must fail browser handoff closed"
        );
        assert!(backend.unloaded.load(Ordering::Acquire));
        assert_eq!(
            fixture
                .controller
                .resources
                .model_residency()
                .map(|residency| residency.state),
            Some(ResourceResidencyStateV1::Unknown)
        );
        assert!(
            fixture
                .controller
                .resources
                .active_lease(&lease.lease_id)
                .is_some(),
            "Unknown physical MODEL state must retain logical authority"
        );
    }

    #[test]
    fn committed_sensitive_synopsis_is_bounded_untrusted_tool_evidence_with_exact_cas_expansion() {
        let mut fixture = durable_fixture(
            autonomy_budget(1_000, 0, 1_000, 0),
            autonomy_budget(1_000, 0, 1_000, 0),
        );
        let download_root = fixture.root.join("downloads");
        fs::create_dir_all(&download_root)
            .unwrap_or_else(|error| panic!("create synopsis fixture root: {error}"));
        let mut session = download_session(&download_root, 500);
        let execution_epoch = fixture
            .controller
            .state
            .current_execution_epoch()
            .unwrap_or_else(|error| panic!("read synopsis test epoch: {error}"));
        session.execution_epoch = execution_epoch;
        session.browser_lease.execution_epoch = execution_epoch;
        let authorized = authorized_synopsis_action(execution_epoch);
        let synopsis = BrowserStateSynopsis {
            url: "https://example.test/login".to_owned(),
            title: String::new(),
            text: String::new(),
            dom_excerpt: String::new(),
            retained_text_bytes: 0,
            retained_dom_bytes: 0,
            text_truncated: false,
            dom_truncated: false,
            retained_dom_sha256: super::sha256_prefixed(b""),
            sensitive_page: BrowserSensitivePageSignal {
                reasons: BTreeSet::from([BrowserSensitivePageReason::PasswordControl]),
            },
        };
        let receipt = super::BrowserActionReceipt {
            schema_version: BROWSER_SCHEMA_VERSION,
            action_id: authorized.action_id.clone(),
            action_digest: authorized.browser_action_digest.clone(),
            action_kind: "capture_synopsis".to_owned(),
            effect: BrowserActionEffect::Observation,
            lease_id: session.browser_lease.lease_id.clone(),
            lease_binding_digest: session.browser_lease.binding_digest(),
            execution_epoch,
            cdp_request_id: 7,
            requested_url: None,
            navigation_was_download: false,
            download: None,
            synopsis: Some(synopsis),
            screenshot: None,
            screenshots_and_traces_suppressed: true,
        };
        let receipt_bytes = receipt
            .to_bytes()
            .unwrap_or_else(|error| panic!("serialize synopsis receipt: {error}"));
        let artifacts = ArtifactStore::open(fixture.root.join("cas"))
            .unwrap_or_else(|error| panic!("open synopsis CAS: {error}"));
        let receipt_digest = seed_committed_browser_receipt(
            &mut fixture.controller,
            &authorized,
            &receipt_bytes,
            &artifacts,
        );
        assert_eq!(
            super::browser_receipt_digest(&receipt_bytes),
            receipt_digest
        );

        let candidate = fixture
            .controller
            .committed_browser_synopsis_candidate(
                &session,
                &authorized,
                &receipt,
                &receipt_digest,
                u64::try_from(receipt_bytes.len())
                    .unwrap_or_else(|_| panic!("synopsis receipt length overflow")),
            )
            .unwrap_or_else(|error| panic!("build committed synopsis evidence: {error}"));
        assert_eq!(candidate.section, PacketSection::ToolEvidence);
        assert_eq!(candidate.level, ContextLevel::C1);
        assert_eq!(candidate.kind, EvidenceKind::ToolSynopsis);
        assert_eq!(candidate.trust_class, TrustClass::Tool);
        assert_eq!(candidate.trust_label.level, TrustLevel::Untrusted);
        assert_eq!(candidate.trust_label.source, TrustSource::ToolOutput);
        assert_eq!(candidate.repository_id.as_deref(), Some("repo.browser"));
        assert_eq!(candidate.source_uri, format!("cas://{receipt_digest}"));
        assert!(candidate.text.contains("https://example.test/login"));
        assert!(candidate.text.contains("password_control"));
        assert!(!candidate.text.contains("password\":"));
        let expansion = candidate
            .expansion_handle
            .as_ref()
            .unwrap_or_else(|| panic!("committed synopsis omitted CAS expansion handle"));
        assert_eq!(expansion.source_uri, format!("cas://{receipt_digest}"));
        assert_eq!(expansion.source_digest, receipt_digest);
        assert_eq!(expansion.offset, 0);
        assert_eq!(expansion.retained_length, expansion.total_length);
        assert_eq!(expansion.total_length, receipt_bytes.len() as u64);
    }

    #[test]
    fn dispatched_submit_form_unknown_sink_blocks_replay_and_never_marks_browser_idle() {
        let mut fixture = durable_fixture(
            autonomy_budget(1_000, 0, 1_048_576, 0),
            autonomy_budget(1_000, 0, 1_048_576, 0),
        );
        seed_checkpoint_resource_policy(&mut fixture.controller);
        seed_running_attempt(&mut fixture.controller);
        let lease = admit_browser_lease_for_unknown_test(&mut fixture.controller);
        let download_root = fixture.root.join("downloads");
        fs::create_dir_all(&download_root)
            .unwrap_or_else(|error| panic!("create submit-form fixture root: {error}"));
        let mut session = download_session(&download_root, 500);
        session.resource_lease = lease.clone();
        session.browser_lease.lease_id = lease.lease_id.clone();
        session.browser_lease.task_id = "task.browser".to_owned();
        session.browser_lease.attempt_id = "attempt.browser".to_owned();
        let execution_epoch = fixture
            .controller
            .state
            .current_execution_epoch()
            .unwrap_or_else(|error| panic!("read submit-form test epoch: {error}"));
        session.execution_epoch = execution_epoch;
        session.browser_lease.execution_epoch = execution_epoch;

        let submit = BrowserAction::SubmitForm {
            action_id: "browser.submit.unknown.test".to_owned(),
            selector: "form#checkout".to_owned(),
            payload_digest: format!("sha256:{:064x}", 7),
        };
        let mut authorized = authorized_synopsis_action(execution_epoch);
        authorized.action_id = submit.action_id().to_owned();
        authorized.browser_action_digest = submit.digest();
        authorized.reconciliation_mode = ReconciliationMode::ConsequentialExternal;
        let payload_digest = authorized.payload_digest();
        fixture
            .controller
            .state
            .insert_action_record(NewActionRecord {
                action_id: &authorized.action_id,
                state: ActionState::Dispatched.as_str(),
                payload_digest: &payload_digest,
                policy_digest: &authorized.policy_digest,
                execution_epoch,
                event_id: "browser-submit-dispatched",
                event_kind: ActionState::Dispatched.as_str(),
                payload_json: "{}",
            })
            .unwrap_or_else(|error| panic!("seed dispatched SubmitForm: {error}"));

        fixture
            .controller
            .mark_dispatched_browser_unknown(&session, &authorized)
            .unwrap_or_else(|error| panic!("mark dispatched SubmitForm unknown: {error}"));
        let action = fixture
            .controller
            .state
            .action_record(&authorized.action_id)
            .unwrap_or_else(|error| panic!("read unknown SubmitForm: {error}"))
            .unwrap_or_else(|| panic!("unknown SubmitForm action disappeared"));
        assert_eq!(action.state, ActionState::Unknown.as_str());
        let active = fixture
            .controller
            .active
            .as_ref()
            .unwrap_or_else(|| panic!("active plan disappeared after unknown"));
        assert_eq!(
            active
                .attempts
                .get("attempt.browser")
                .map(|attempt| attempt.state),
            Some(AttemptState::Interrupted)
        );
        assert_eq!(
            active.tasks.get("task.browser").map(|task| task.state),
            Some(TaskState::ReconcilingUnknown)
        );
        let resource = fixture
            .controller
            .resources
            .active_lease(&lease.lease_id)
            .unwrap_or_else(|| panic!("unknown SubmitForm lost live browser lease"));
        assert_eq!(resource.state, LeaseStateV1::Active);
        assert_eq!(resource.idle_since_ms, None);
        assert!(
            fixture
                .controller
                .state
                .journal_after(0)
                .unwrap_or_else(|error| panic!("read unknown replay-block event: {error}"))
                .iter()
                .any(|event| event.event_kind == "unknown_action_blocks_replay"
                    && event.entity_id == authorized.action_id)
        );
    }

    #[test]
    fn active_browser_network_reservation_reduces_remaining_and_clean_settlement_is_exact() {
        let task_budget = autonomy_budget(1_000, 100, 1_000, 0);
        let goal_budget = autonomy_budget(800, 50, 1_000, 0);
        let mut fixture = durable_fixture(task_budget, goal_budget);
        let lease = resource_lease();
        let residency = browser_residency(&lease);

        fixture
            .controller
            .persist_browser_network_reservation(&residency, 300)
            .unwrap_or_else(|error| panic!("persist browser reservation: {error}"));
        assert_eq!(
            fixture
                .controller
                .network_remaining("task.browser", "test browser network")
                .unwrap_or_else(|error| panic!("remaining with active reservation: {error}")),
            450
        );
        assert_eq!(
            fixture
                .controller
                .active_browser_network_reservation_bytes("task.browser")
                .unwrap_or_else(|error| panic!("active reservation totals: {error}")),
            (300, 300)
        );

        fixture
            .controller
            .require_browser_network_reservation_settlement(
                &residency,
                120,
                BrowserNetworkSettlementV1::CleanObserved,
            )
            .unwrap_or_else(|error| panic!("clean settlement: {error}"));
        assert_eq!(budget_usage(&fixture.controller), (220, 170, 0, 0));
        assert_eq!(
            fixture
                .controller
                .active_browser_network_reservation_bytes("task.browser")
                .unwrap_or_else(|error| panic!("post-settlement reservation totals: {error}")),
            (0, 0)
        );
        assert_eq!(
            fixture
                .controller
                .network_remaining("task.browser", "test browser network")
                .unwrap_or_else(|error| panic!("remaining after settlement: {error}")),
            630
        );
        let (_, settled) = fixture
            .controller
            .browser_network_reservation_for_residency(&residency)
            .unwrap_or_else(|error| panic!("read settled reservation: {error}"))
            .unwrap_or_else(|| panic!("settled reservation disappeared"));
        assert_eq!(settled.state, BrowserNetworkReservationStateV1::Settled);
        assert_eq!(settled.settled_bytes, Some(120));
        assert_eq!(
            settled.settlement,
            Some(BrowserNetworkSettlementV1::CleanObserved)
        );

        fixture
            .controller
            .require_browser_network_reservation_settlement(
                &residency,
                120,
                BrowserNetworkSettlementV1::CleanObserved,
            )
            .unwrap_or_else(|error| panic!("idempotent settlement repeat: {error}"));
        assert_eq!(budget_usage(&fixture.controller), (220, 170, 0, 0));
        assert!(
            fixture
                .controller
                .require_browser_network_reservation_settlement(
                    &residency,
                    121,
                    BrowserNetworkSettlementV1::CleanObserved,
                )
                .is_err(),
            "different repeat must be rejected"
        );
        assert_eq!(budget_usage(&fixture.controller), (220, 170, 0, 0));
    }

    #[test]
    fn recovered_legacy_browser_network_charge_is_not_charged_twice() {
        let task_budget = autonomy_budget(1_000, 100, 1_000, 0);
        let goal_budget = autonomy_budget(1_000, 50, 1_000, 0);
        let mut fixture = durable_fixture(task_budget, goal_budget);
        let residency = browser_residency(&resource_lease());
        let action_id = format!("browser-reservation:{}", residency.policy_lease.lease_id);

        fixture
            .controller
            .persist_network_charge(
                "task.browser",
                &action_id,
                "browser_network_budget_charged",
                "legacy_full_reservation",
                300,
            )
            .unwrap_or_else(|error| panic!("persist legacy reservation charge: {error}"));
        assert_eq!(budget_usage(&fixture.controller), (400, 350, 0, 0));
        fixture
            .controller
            .reconcile_recovered_browser_network_reservation(&residency)
            .unwrap_or_else(|error| panic!("reconcile legacy reservation charge: {error}"));
        assert_eq!(budget_usage(&fixture.controller), (400, 350, 0, 0));
    }

    #[test]
    fn retained_download_charges_task_and_goal_once_and_rejects_same_key_drift() {
        let task_budget = autonomy_budget(1_000, 0, 1_000, 10);
        let goal_budget = autonomy_budget(1_000, 0, 1_000, 20);
        let mut fixture = durable_fixture(task_budget, goal_budget);
        let download_root = fixture.root.join("downloads");
        fs::create_dir_all(&download_root)
            .unwrap_or_else(|error| panic!("create download root: {error}"));
        let session = download_session(&download_root, 500);
        let receipt = download_receipt(&session, "guid-retained-001", 100);

        assert_eq!(
            fixture
                .controller
                .persist_browser_download_record(&session, &receipt)
                .unwrap_or_else(|error| panic!("persist retained download: {error}")),
            100
        );
        assert_eq!(budget_usage(&fixture.controller), (0, 0, 110, 120));
        assert_eq!(
            fixture
                .controller
                .state
                .state_records(BROWSER_DOWNLOAD_RECORD_NAMESPACE)
                .unwrap_or_else(|error| panic!("read retained download records: {error}"))
                .len(),
            1
        );

        assert_eq!(
            fixture
                .controller
                .persist_browser_download_record(&session, &receipt)
                .unwrap_or_else(|error| panic!("idempotent retained download retry: {error}")),
            100
        );
        assert_eq!(budget_usage(&fixture.controller), (0, 0, 110, 120));

        let mut drift = receipt.clone();
        drift.bytes = 101;
        drift.sha256 = format!("sha256:{:064x}", 101);
        assert!(
            fixture
                .controller
                .persist_browser_download_record(&session, &drift)
                .is_err(),
            "same retained path with changed receipt must fail closed"
        );
        assert_eq!(budget_usage(&fixture.controller), (0, 0, 110, 120));
    }

    #[test]
    fn download_cleanup_deletes_only_exact_authorized_leaf_and_budget_failure_does_not_charge() {
        let task_budget = autonomy_budget(1_000, 0, 50, 10);
        let goal_budget = autonomy_budget(1_000, 0, 80, 20);
        let mut fixture = durable_fixture(task_budget, goal_budget);
        let download_root = fixture.root.join("downloads");
        fs::create_dir_all(&download_root)
            .unwrap_or_else(|error| panic!("create download root: {error}"));
        let session = download_session(&download_root, 500);

        let canceled_leaf = download_root.join("guid-canceled-001");
        fs::write(&canceled_leaf, b"partial")
            .unwrap_or_else(|error| panic!("write canceled leaf: {error}"));
        let canceled = terminal(
            &session.browser_lease,
            BrowserDownloadTerminalState::Canceled,
            "guid-canceled-001",
        );
        let canceled_path = Controller::browser_download_terminal_path(
            &session.browser_lease,
            session.execution_epoch,
            &canceled,
        )
        .unwrap_or_else(|error| panic!("exact canceled terminal rejected: {error}"));
        Controller::discard_browser_download_leaf(&session.download_policy, &canceled_path)
            .unwrap_or_else(|error| panic!("discard exact canceled leaf: {error}"));
        assert!(!canceled_leaf.exists());

        let protected_leaf = download_root.join("guid-protected-002");
        fs::write(&protected_leaf, b"must remain")
            .unwrap_or_else(|error| panic!("write protected leaf: {error}"));
        let mut misbound = terminal(
            &session.browser_lease,
            BrowserDownloadTerminalState::Canceled,
            "guid-protected-002",
        );
        misbound.lease_id = "browser:foreign".to_owned();
        assert!(
            Controller::browser_download_terminal_path(
                &session.browser_lease,
                session.execution_epoch,
                &misbound,
            )
            .is_err()
        );
        assert!(
            protected_leaf.exists(),
            "misbound terminal must not delete a leaf"
        );

        let oversized_leaf = download_root.join("guid-budget-003");
        fs::write(&oversized_leaf, vec![7_u8; 50])
            .unwrap_or_else(|error| panic!("write budget leaf: {error}"));
        let receipt = download_receipt(&session, "guid-budget-003", 50);
        let Err(error) = fixture
            .controller
            .persist_browser_download_record(&session, &receipt)
        else {
            panic!("disk budget exhaustion must reject retention");
        };
        Controller::discard_browser_download_leaf(
            &session.download_policy,
            Path::new("guid-budget-003"),
        )
        .unwrap_or_else(|cleanup| panic!("cleanup after {error}: {cleanup}"));
        assert!(!oversized_leaf.exists());
        assert!(
            protected_leaf.exists(),
            "cleanup must remain exact-leaf only"
        );
        assert_eq!(budget_usage(&fixture.controller), (0, 0, 10, 20));
        assert!(
            fixture
                .controller
                .state
                .state_records(BROWSER_DOWNLOAD_RECORD_NAMESPACE)
                .unwrap_or_else(|state_error| panic!("read download records: {state_error}"))
                .is_empty()
        );
    }

    #[test]
    fn completed_download_terminal_binds_exact_guid_path_once() {
        let lease = lease();
        let completed = terminal(
            &lease,
            BrowserDownloadTerminalState::Completed,
            "guid-controller-001",
        );
        let path =
            Controller::browser_download_terminal_path(&lease, lease.execution_epoch, &completed)
                .unwrap_or_else(|error| panic!("completed terminal rejected: {error}"));
        assert_eq!(path, Path::new("guid-controller-001"));

        let canceled = terminal(
            &lease,
            BrowserDownloadTerminalState::Canceled,
            "guid-controller-002",
        );
        let canceled_path =
            Controller::browser_download_terminal_path(&lease, lease.execution_epoch, &canceled)
                .unwrap_or_else(|error| {
                    panic!("exact canceled GUID must remain safely cleanable: {error}")
                });
        assert_eq!(canceled_path, Path::new("guid-controller-002"));
    }

    #[test]
    fn download_terminal_rejects_stale_or_non_guid_path_bindings() {
        let lease = lease();
        let mut stale = terminal(
            &lease,
            BrowserDownloadTerminalState::Completed,
            "guid-controller-003",
        );
        stale.execution_epoch += 1;
        assert!(
            Controller::browser_download_terminal_path(&lease, lease.execution_epoch, &stale,)
                .is_err()
        );

        let mut mismatched = terminal(
            &lease,
            BrowserDownloadTerminalState::Completed,
            "guid-controller-004",
        );
        mismatched.relative_path = PathBuf::from("other-guid");
        assert!(
            Controller::browser_download_terminal_path(&lease, lease.execution_epoch, &mismatched,)
                .is_err()
        );

        let nested = terminal(
            &lease,
            BrowserDownloadTerminalState::Completed,
            "nested/guid-controller-005",
        );
        assert!(
            Controller::browser_download_terminal_path(&lease, lease.execution_epoch, &nested,)
                .is_err(),
            "Controller must independently require one normal GUID path component"
        );
    }
}
