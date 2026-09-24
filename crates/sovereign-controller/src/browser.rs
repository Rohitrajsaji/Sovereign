#![forbid(unsafe_code)]

//! Controller-owned browser authority and local proxy mechanics.
//!
//! The browser adapter remains authority-neutral. This module derives exact browser/network scope
//! from already-validated Plan IR, binds browser actions to the canonical `ActionJournal` authority
//! surface, and owns the only localhost gateway Chrome may reach under Seatbelt.

#[cfg(unix)]
use super::postgres_broker::{ControllerPostgresBroker, PostgresBrokerConfig};
use super::{
    ActionJournal, ActionState, ArtifactStore, AttemptStartBinding, AttemptState, Controller,
    ControllerError, ExecutionRuntime, FailureRecordInput, NetworkChargePersistence, PlanValidity,
    ProjectRegistry, ReadinessInputs, ResourceResidencyStateV1, TaskState, VerificationResultV1,
    active_scoped_key, aggregate_command_verification, compiled_acceptance_contract, digest_json,
    required_array, required_str, required_u32, required_u64,
    resources::{
        BROWSER_RESIDENCY_KEY, BROWSER_RESOURCE_RESIDENCY_SCHEMA_VERSION,
        BrowserResourceResidencyStateV1, BrowserResourceResidencyV1, RESOURCE_GOVERNOR_KEY,
        RESOURCE_GOVERNOR_NAMESPACE, RESOURCE_LEASE_NAMESPACE, RESOURCE_PRESSURE_NAMESPACE,
        RESOURCE_RESIDENCY_NAMESPACE, resource_event_payload,
    },
    revision_scoped_key, sha256_prefixed, snapshot_digest, unix_millis, verification_id,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sovereign_context::{
    ContextLevel, EvidenceItem, EvidenceKind, ExpansionHandle, PacketSection, TrustClass,
};
use sovereign_model::{ModelBackend, ModelResidencyProof};
use sovereign_plan::{
    BROWSER_ACCEPTANCE_CONTRACT_SCHEMA_VERSION, BrowserAcceptanceActionV1,
    BrowserAcceptanceContractV1, BrowserAcceptanceSemanticV1, BrowserManagedAppLaunchV1,
    BrowserManagedArgBindingV1, BrowserManagedPersistenceBindingV1, BrowserManagedReadinessV1,
};
use sovereign_policy::browser::{
    BROWSER_DOWNLOAD_POLICY_SCHEMA_VERSION, BROWSER_LOOPBACK_CAPABILITY_SCHEMA_VERSION,
    BrowserDownloadMode, BrowserDownloadPolicyV1, BrowserDownloadRetentionPolicyV1,
    BrowserDownloadRootAuthorityV1, BrowserIsolationRequest, BrowserLoopbackCapabilityV1,
    BrowserPolicyError, BrowserProfileAuthority, BrowserProfileMode, BrowserProfilePolicy,
    LoopbackServerIsolationRequestV1, MacBrowserSandboxExecBackend,
    MacLoopbackServerSandboxExecBackend, PersistentBrowserProfileGrantV1,
    TASK_LOOPBACK_GRANT_SCHEMA_VERSION, TaskLoopbackGrantV1, TaskLoopbackScope,
};
use sovereign_policy::{
    AdmissionStatus, AutonomyBudgetV1, Capability, CommandMode, CommandRisk, CommandSpec,
    ConditionalLeaseContextV1, HeavyLeaseClass, IsolatedCommand, LeaseStateV1, NetworkDestination,
    NetworkPolicy, PermissionDecision, PolicyError, ResourceLeaseOwnerV1, ResourceLeaseRequestV1,
    ResourceLeaseV1, ResourcePolicyEventV1, ResourcePressureEventV1, TaskResourceBudgetV1,
};
use sovereign_tools::{
    ApprovalClaim, AuthorizedAction, JournalActionAuthority, JournalActionReservation,
    ManagedProcess, ProcessRunner, ReconciliationMode, SystemWebDnsResolver, ToolError,
    ToolManifest, WebDnsResolver,
    browser::{
        BROWSER_PROXY_AUTH_REALM, BROWSER_PROXY_AUTH_USERNAME, BROWSER_SCHEMA_VERSION,
        BrowserAction, BrowserActionEffect, BrowserActionReceipt, BrowserAdapter,
        BrowserAdapterConfig, BrowserDocumentRequestDecision, BrowserDocumentRequestKind,
        BrowserDocumentRequestObservation, BrowserDownloadPolicy,
        BrowserDownloadTerminalObservation, BrowserDownloadTerminalState, BrowserError,
        BrowserFormFieldValues, BrowserFormInspectionReceipt, BrowserLaunchOptions, BrowserLease,
        BrowserProfileRoot, BrowserProxyAuthBinding, BrowserSensitivePageReason, BrowserSpawnState,
        BrowserStateSynopsis, DownloadReceipt, PreparedBrowserLaunch,
    },
    process_group_leader_identity,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
const MANAGED_LOOPBACK_APP_NAMESPACE: &str = "controller.managed_loopback_app";
const MANAGED_LOOPBACK_APP_SCHEMA_VERSION: u32 = 1;
const BROWSER_SEMANTIC_CONTRACT_NAMESPACE: &str = "controller.browser_semantic_contract";
const BROWSER_SEMANTIC_CONTRACT_SCHEMA_VERSION: u32 = 1;
const BROWSER_SEMANTIC_PROOF_NAMESPACE: &str = "controller.browser_semantic_proof";
const BROWSER_SEMANTIC_PROOF_SCHEMA_VERSION: u32 = 1;
const MANAGED_LOOPBACK_MAX_LIFETIME_MS: u64 = 30_000;
const MANAGED_LOOPBACK_START_OUTPUT_BYTES: u64 = 64 * 1024;
const MANAGED_LOOPBACK_START_DISK_BYTES: u64 = 1024 * 1024;
const MANAGED_LOOPBACK_SUBPROCESS_LIMIT: u32 = 0;
const MANAGED_LOOPBACK_READY_TIMEOUT: Duration = Duration::from_secs(5);

enum ManagedLoopbackLaunch<'a> {
    Python {
        server_relative_path: &'a Path,
        database_filename: &'a str,
    },
    Node {
        executable: &'a Path,
        working_directory_relative_path: &'a Path,
        entrypoint_relative_path: &'a Path,
        argv: &'a [String],
        dynamic_port: &'a BrowserManagedArgBindingV1,
        readiness: &'a BrowserManagedReadinessV1,
        persistence: &'a BrowserManagedPersistenceBindingV1,
    },
}

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

#[derive(Debug, Clone)]
struct BrowserPreflightAuthority {
    plan_id: String,
    plan_revision: u32,
    plan_digest: String,
    task_id: String,
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
    tool_manifest: ToolManifest,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ManagedLoopbackAppBindingV1 {
    schema_version: u32,
    app_id: String,
    generation: u32,
    plan_id: String,
    plan_revision: u32,
    task_id: String,
    task_contract_digest: String,
    attempt_id: String,
    execution_epoch: i64,
    browser_resource_lease_id: String,
    loopback_grant_digest: String,
    port: u16,
    repository_root: String,
    data_root: String,
    database_path: String,
    #[serde(default)]
    postgres_broker_port: Option<u16>,
    #[serde(default)]
    postgres_database_oid: Option<u32>,
    start_action_id: String,
    start_result_digest: String,
    process_group_id: u32,
    leader_identity: String,
    state: String,
}

/// Ephemeral ownership handle for one Controller-governed loopback application generation.
/// Durable lifecycle truth is stored in the canonical ActionJournal/process lease plus the typed
/// `controller.managed_loopback_app` projection; this value never replaces those records.
pub struct ControllerManagedLoopbackApp {
    binding: ManagedLoopbackAppBindingV1,
    process: ManagedProcess,
    #[cfg(unix)]
    postgres_broker: Option<ControllerPostgresBroker>,
}

/// One exact Plan-IR-derived browser action with its managed-app generation boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControllerBrowserPlannedAction {
    pub generation: u32,
    pub semantic: BrowserAcceptanceSemanticV1,
    pub action: BrowserAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct BrowserSemanticStepV1 {
    action_id: String,
    action_kind: String,
    action_digest: String,
    generation: u32,
    semantic: BrowserAcceptanceSemanticV1,
    required_synopsis_contains: Vec<String>,
    forbidden_synopsis_contains: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct BrowserSemanticContractV1 {
    schema_version: u32,
    plan_contract_digest: String,
    plan_id: String,
    plan_revision: u32,
    task_id: String,
    task_contract_digest: String,
    attempt_id: String,
    execution_epoch: i64,
    browser_lease_id: String,
    browser_binding_digest: String,
    loopback_port: u16,
    steps: Vec<BrowserSemanticStepV1>,
    required_managed_generations: u32,
    contract_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct BrowserSemanticObservedStepV1 {
    action_id: String,
    action_kind: String,
    action_digest: String,
    generation: u32,
    semantic: BrowserAcceptanceSemanticV1,
    committed_sequence: i64,
    receipt_digest: String,
    matched_synopsis_predicates: Vec<String>,
    verified_absent_synopsis_predicates: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct BrowserSemanticManagedGenerationV1 {
    app_id: String,
    generation: u32,
    start_action_id: String,
    start_result_digest: String,
    process_group_id: u32,
    leader_identity: String,
    database_path: String,
    ready_sequence: i64,
    stopped_sequence: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct BrowserSemanticProofV1 {
    schema_version: u32,
    contract_digest: String,
    plan_id: String,
    plan_revision: u32,
    task_id: String,
    task_contract_digest: String,
    attempt_id: String,
    execution_epoch: i64,
    browser_lease_id: String,
    browser_binding_digest: String,
    observed_steps: Vec<BrowserSemanticObservedStepV1>,
    managed_generations: Vec<BrowserSemanticManagedGenerationV1>,
    evidence_ids: Vec<String>,
    proof_digest: String,
}

impl ControllerManagedLoopbackApp {
    #[must_use]
    pub fn database_path(&self) -> &Path {
        Path::new(&self.binding.database_path)
    }

    #[must_use]
    pub const fn postgres_broker_port(&self) -> Option<u16> {
        self.binding.postgres_broker_port
    }

    #[must_use]
    pub const fn generation(&self) -> u32 {
        self.binding.generation
    }

    #[must_use]
    pub const fn port(&self) -> u16 {
        self.binding.port
    }

    #[must_use]
    pub fn app_id(&self) -> &str {
        &self.binding.app_id
    }

    #[must_use]
    pub const fn process_group_id(&self) -> u32 {
        self.binding.process_group_id
    }

    #[must_use]
    pub fn leader_identity(&self) -> &str {
        &self.binding.leader_identity
    }
}

/// Ephemeral Controller authority for starting a browser-only task without repository-write or
/// MODEL residency. The lease is bound to the current plan/task/checkpoint/evidence and to the
/// exact browser manifest, static browser authority, resource contract, and adapter configuration.
#[derive(Debug, Clone)]
pub struct BrowserReadyLeaseV1 {
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
    browser_authority_digest: String,
    browser_config_digest: String,
    task_budget_digest: String,
    input_resource_digest: String,
    execution_epoch: i64,
    lease_digest: String,
}

impl BrowserReadyLeaseV1 {
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
}

fn browser_task_authority_digest(authority: &BrowserTaskAuthorityV1) -> String {
    let mut hasher = Sha256::new();
    digest_field(&mut hasher, "sovereign.browser_task_authority.v1");
    for value in &authority.allowed_domains {
        digest_field(&mut hasher, value);
    }
    for value in &authority.allowed_schemes {
        digest_field(&mut hasher, value);
    }
    for value in &authority.allowed_ports {
        hasher.update(value.to_be_bytes());
    }
    for value in &authority.allowed_methods {
        digest_field(&mut hasher, value);
    }
    hasher.update([u8::from(authority.follow_redirects)]);
    hasher.update(authority.max_redirects.to_be_bytes());
    hasher.update([u8::from(authority.allow_task_loopback)]);
    hasher.update(authority.max_tabs.to_be_bytes());
    hasher.update([u8::from(authority.downloads_allowed)]);
    digest_field(
        &mut hasher,
        match authority.profile_mode {
            BrowserProfileMode::Isolated => "isolated",
            BrowserProfileMode::Persistent => "persistent",
        },
    );
    digest_field(
        &mut hasher,
        authority.download_root.as_deref().unwrap_or("none"),
    );
    format!("sha256:{:x}", hasher.finalize())
}

fn browser_adapter_config_digest(config: &BrowserAdapterConfig) -> String {
    let mut hasher = Sha256::new();
    digest_field(&mut hasher, "sovereign.browser_adapter_config.v1");
    hasher.update(
        u64::try_from(config.max_cdp_frame_bytes)
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    hasher.update(
        u64::try_from(config.max_synopsis_bytes)
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    hasher.update(
        u64::try_from(config.max_dom_bytes)
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    hasher.update(config.max_download_bytes.to_be_bytes());
    hasher.update(config.request_timeout_ms.to_be_bytes());
    hasher.update([u8::from(config.suppress_screenshots_and_traces)]);
    format!("sha256:{:x}", hasher.finalize())
}

fn browser_ready_lease_digest(lease: &BrowserReadyLeaseV1) -> String {
    let mut hasher = Sha256::new();
    digest_field(&mut hasher, "sovereign.browser_ready_lease.v1");
    digest_field(&mut hasher, &lease.plan_id);
    hasher.update(lease.plan_revision.to_be_bytes());
    digest_field(&mut hasher, &lease.plan_digest);
    digest_field(&mut hasher, &lease.task_id);
    digest_field(&mut hasher, &lease.task_contract_digest);
    digest_field(&mut hasher, &lease.baseline_digest);
    digest_field(&mut hasher, &lease.evidence_binding_digest);
    hasher.update(lease.checkpoint_generation.to_be_bytes());
    hasher.update(lease.checkpoint_action_sequence.to_be_bytes());
    digest_field(&mut hasher, &lease.checkpoint_hash);
    digest_field(&mut hasher, &lease.permission_decision.digest());
    digest_field(&mut hasher, &lease.browser_authority_digest);
    digest_field(&mut hasher, &lease.browser_config_digest);
    digest_field(&mut hasher, &lease.task_budget_digest);
    digest_field(&mut hasher, &lease.input_resource_digest);
    hasher.update(lease.execution_epoch.to_be_bytes());
    format!("sha256:{:x}", hasher.finalize())
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

    fn browser_preflight_authority(
        &self,
        task_id: &str,
        tool_manifest: &ToolManifest,
        mut config: BrowserAdapterConfig,
    ) -> Result<BrowserPreflightAuthority, ControllerError> {
        self.require_execution_not_paused()?;
        let execution_epoch = self.state.current_execution_epoch()?;
        let (plan_id, plan_revision, plan_digest, task_contract_digest, max_retained_raw_bytes) = {
            let active = self.active_ref()?;
            if active.validity != PlanValidity::Current {
                return Err(ControllerError::NotReady(
                    "browser launch requires the current active plan".to_owned(),
                ));
            }
            let task = active.tasks.get(task_id).ok_or_else(|| {
                ControllerError::NotReady(format!("unknown browser task {task_id}"))
            })?;
            (
                active.plan_id.clone(),
                active.revision,
                active.plan_digest.clone(),
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
        let task_permissions = {
            let active = self.active_ref()?;
            let task = active.tasks.get(task_id).ok_or_else(|| {
                ControllerError::NotReady(format!("unknown browser task {task_id}"))
            })?;
            string_set_at(&task.task, "/permissions")?
        };
        if task_permissions.contains("repo_write")
            || permission_decision
                .effective
                .contains(Capability::RepositoryWrite)
        {
            return Err(ControllerError::Policy(PolicyError::Denied(
                "browser-only readiness forbids repository-write authority".to_owned(),
            )));
        }
        if task_budget.permits(HeavyLeaseClass::Model) {
            return Err(ControllerError::Policy(PolicyError::ResourceDenied(
                "browser-only task must not retain MODEL heavy-lease authority".to_owned(),
            )));
        }
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
        Ok(BrowserPreflightAuthority {
            plan_id,
            plan_revision,
            plan_digest,
            task_id: task_id.to_owned(),
            task_contract_digest,
            max_retained_raw_bytes,
            execution_epoch,
            authority,
            permission_decision,
            task_budget,
            config,
        })
    }

    fn bind_browser_launch_authority(
        &self,
        preflight: BrowserPreflightAuthority,
        attempt_id: &str,
    ) -> Result<BrowserLaunchAuthority, ControllerError> {
        let active = self.active_ref()?;
        let task = active.tasks.get(&preflight.task_id).ok_or_else(|| {
            ControllerError::NotReady("browser task disappeared after preflight".to_owned())
        })?;
        let attempt = active.attempts.get(attempt_id).ok_or_else(|| {
            ControllerError::NotReady(format!("unknown browser attempt {attempt_id}"))
        })?;
        if active.validity != PlanValidity::Current
            || active.plan_id != preflight.plan_id
            || active.revision != preflight.plan_revision
            || active.plan_digest != preflight.plan_digest
            || task.task_contract_digest != preflight.task_contract_digest
            || attempt.task_id != preflight.task_id
            || attempt.task_contract_digest != preflight.task_contract_digest
            || !matches!(task.state, TaskState::Running | TaskState::Verifying)
            || !matches!(
                attempt.state,
                AttemptState::Executing | AttemptState::Verifying
            )
            || self.state.current_execution_epoch()? != preflight.execution_epoch
        {
            return Err(ControllerError::NotReady(
                "browser preflight drifted before exact attempt binding".to_owned(),
            ));
        }
        Ok(BrowserLaunchAuthority {
            plan_id: preflight.plan_id,
            plan_revision: preflight.plan_revision,
            task_id: preflight.task_id,
            attempt_id: attempt_id.to_owned(),
            task_contract_digest: preflight.task_contract_digest,
            max_retained_raw_bytes: preflight.max_retained_raw_bytes,
            execution_epoch: preflight.execution_epoch,
            authority: preflight.authority,
            permission_decision: preflight.permission_decision,
            task_budget: preflight.task_budget,
            config: preflight.config,
        })
    }

    fn browser_launch_authority(
        &self,
        task_id: &str,
        attempt_id: &str,
        tool_manifest: &ToolManifest,
        config: BrowserAdapterConfig,
    ) -> Result<BrowserLaunchAuthority, ControllerError> {
        let preflight = self.browser_preflight_authority(task_id, tool_manifest, config)?;
        self.bind_browser_launch_authority(preflight, attempt_id)
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
                // Chrome's own macOS sandbox cannot initialize after the Controller has already
                // entered the stricter Seatbelt profile. The outer Controller profile is inherited
                // by the whole browser process tree and remains the execution boundary.
                "--no-sandbox".to_owned(),
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
        tool_manifest: &ToolManifest,
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
            tool_manifest: tool_manifest.clone(),
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

    /// Derives browser-only readiness without repository-write authority or MODEL residency.
    ///
    /// # Errors
    /// Fails closed when the task, dependency/checkpoint/evidence binding, browser manifest/policy,
    /// browser resource contract, adapter configuration, or repository baseline is not current.
    pub fn derive_browser_ready_lease(
        &mut self,
        registry: &ProjectRegistry,
        task_id: &str,
        inputs: ReadinessInputs<'_>,
        browser_tool_manifest: &ToolManifest,
        config: BrowserAdapterConfig,
    ) -> Result<BrowserReadyLeaseV1, ControllerError> {
        self.require_execution_not_paused()?;
        if self.cancellation_blocks_task(task_id)? {
            return Err(ControllerError::NotReady(
                "browser task is durably cancelled".to_owned(),
            ));
        }
        let cancellation = self.task_cancellation_handle(task_id)?;
        if cancellation.is_cancelled() {
            self.persist_observed_cancellation(&cancellation)?;
            return Err(ControllerError::NotReady(
                "browser task cancellation blocks readiness".to_owned(),
            ));
        }
        super::require_no_unresolved_secret_action_lifecycles(&self.state, None)?;
        self.require_current_baseline(registry)?;
        let (plan_id, plan_revision, plan_digest, task_contract_digest, task_value) = {
            let active = self.active_ref()?;
            let task = active.tasks.get(task_id).ok_or_else(|| {
                ControllerError::NotReady(format!("unknown browser task {task_id}"))
            })?;
            if active.validity != PlanValidity::Current {
                return Err(ControllerError::NotReady(
                    "browser readiness requires the current active plan".to_owned(),
                ));
            }
            (
                active.plan_id.clone(),
                active.revision,
                active.plan_digest.clone(),
                task.task_contract_digest.clone(),
                task.task.clone(),
            )
        };
        self.check_task_readiness(task_id, &task_value, inputs, TaskState::Planned)?;
        let baseline_digest = snapshot_digest(&self.task_execution_snapshot(registry, task_id)?)?;
        let evidence_binding_digest =
            self.resolve_readiness_evidence_digest(registry, task_id, &task_value)?;
        let preflight = self.browser_preflight_authority(task_id, browser_tool_manifest, config)?;
        let browser_authority_digest = browser_task_authority_digest(&preflight.authority);
        let browser_config_digest = browser_adapter_config_digest(&preflight.config);
        let task_budget_digest = digest_json(&serde_json::to_value(&preflight.task_budget)?)?;
        if inputs.resource_digest.trim().is_empty() {
            return Err(ControllerError::NotReady(
                "browser readiness resource digest is empty".to_owned(),
            ));
        }
        self.checkpoint_now()?;
        let (checkpoint_generation, checkpoint_action_sequence, checkpoint_hash) =
            self.current_checkpoint_binding()?;
        let execution_epoch = self.state.current_execution_epoch()?;
        if execution_epoch != preflight.execution_epoch {
            return Err(ControllerError::NotReady(
                "browser readiness epoch changed during preflight".to_owned(),
            ));
        }
        let mut lease = BrowserReadyLeaseV1 {
            plan_id,
            plan_revision,
            plan_digest,
            task_id: task_id.to_owned(),
            task_contract_digest,
            baseline_digest,
            evidence_binding_digest,
            checkpoint_generation,
            checkpoint_action_sequence,
            checkpoint_hash,
            permission_decision: preflight.permission_decision,
            browser_authority_digest,
            browser_config_digest,
            task_budget_digest,
            input_resource_digest: inputs.resource_digest.to_owned(),
            execution_epoch,
            lease_digest: String::new(),
        };
        lease.lease_digest = browser_ready_lease_digest(&lease);
        Ok(lease)
    }

    fn validate_browser_ready_lease(
        &mut self,
        lease: &BrowserReadyLeaseV1,
        registry: &ProjectRegistry,
        browser_tool_manifest: &ToolManifest,
        config: BrowserAdapterConfig,
    ) -> Result<BrowserPreflightAuthority, ControllerError> {
        self.require_execution_not_paused()?;
        super::require_no_unresolved_secret_action_lifecycles(&self.state, None)?;
        if self.cancellation_blocks_task(&lease.task_id)? {
            return Err(ControllerError::NotReady(
                "browser task is durably cancelled".to_owned(),
            ));
        }
        self.require_current_baseline(registry)?;
        let task_value = {
            let active = self.active_ref()?;
            if active.validity != PlanValidity::Current
                || active.plan_id != lease.plan_id
                || active.revision != lease.plan_revision
                || active.plan_digest != lease.plan_digest
            {
                return Err(ControllerError::NotReady(
                    "browser ready lease no longer binds the sole active/current plan".to_owned(),
                ));
            }
            let task = active.tasks.get(&lease.task_id).ok_or_else(|| {
                ControllerError::NotReady("browser ready task disappeared".to_owned())
            })?;
            if task.task_contract_digest != lease.task_contract_digest {
                return Err(ControllerError::NotReady(
                    "browser ready task contract changed".to_owned(),
                ));
            }
            task.task.clone()
        };
        self.check_task_readiness(
            &lease.task_id,
            &task_value,
            ReadinessInputs::permissive_m1(&lease.input_resource_digest),
            TaskState::Planned,
        )?;
        let baseline_digest =
            snapshot_digest(&self.task_execution_snapshot(registry, &lease.task_id)?)?;
        let evidence_binding_digest =
            self.resolve_readiness_evidence_digest(registry, &lease.task_id, &task_value)?;
        let preflight =
            self.browser_preflight_authority(&lease.task_id, browser_tool_manifest, config)?;
        let task_budget_digest = digest_json(&serde_json::to_value(&preflight.task_budget)?)?;
        let (checkpoint_generation, checkpoint_action_sequence, checkpoint_hash) =
            self.current_checkpoint_binding()?;
        if baseline_digest != lease.baseline_digest
            || evidence_binding_digest != lease.evidence_binding_digest
            || checkpoint_generation != lease.checkpoint_generation
            || checkpoint_action_sequence != lease.checkpoint_action_sequence
            || checkpoint_hash != lease.checkpoint_hash
            || self.state.current_execution_epoch()? != lease.execution_epoch
            || preflight.permission_decision != lease.permission_decision
            || browser_task_authority_digest(&preflight.authority) != lease.browser_authority_digest
            || browser_adapter_config_digest(&preflight.config) != lease.browser_config_digest
            || task_budget_digest != lease.task_budget_digest
            || browser_ready_lease_digest(lease) != lease.lease_digest
        {
            return Err(ControllerError::NotReady(
                "browser ready lease binding is stale".to_owned(),
            ));
        }
        Ok(preflight)
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
        self.activate_prepared_browser_session(prepared, tool_manifest)
    }

    /// Revalidates one browser-only ready lease before creating any durable attempt, then starts the
    /// exact attempt and launches the Controller-owned browser session for that attempt.
    ///
    /// # Errors
    /// Fails closed for stale ready authority, baseline/checkpoint drift, browser
    /// permission/resource denial, model-eviction ambiguity, or browser launch uncertainty.
    #[allow(clippy::too_many_arguments)]
    pub fn acquire_browser_session_from_ready_lease(
        &mut self,
        lease: BrowserReadyLeaseV1,
        registry: &ProjectRegistry,
        browser_tool_manifest: &ToolManifest,
        backend: &dyn ModelBackend,
        chrome_path: &Path,
        config: BrowserAdapterConfig,
    ) -> Result<ControllerBrowserSession, ControllerError> {
        let preflight =
            self.validate_browser_ready_lease(&lease, registry, browser_tool_manifest, config)?;
        let binding = AttemptStartBinding {
            task_id: lease.task_id.clone(),
            plan_digest: lease.plan_digest.clone(),
            task_contract_digest: lease.task_contract_digest.clone(),
            execution_epoch: lease.execution_epoch,
            baseline_digest: lease.baseline_digest.clone(),
        };
        let attempt_id = self.start_attempt_from_binding(&binding, registry, None)?;
        let scope = self.bind_browser_launch_authority(preflight, &attempt_id)?;
        drop(lease);
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
        self.activate_prepared_browser_session(prepared, browser_tool_manifest)
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
            None,
        )
    }

    fn record_browser_download_with_activity(
        &mut self,
        session: &mut ControllerBrowserSession,
        tool_manifest: &ToolManifest,
        content_type: &str,
        credential_bearing: bool,
        activity: BrowserDownloadActivity,
        deadline: Option<Instant>,
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
        let adapter = session.adapter.as_mut().ok_or_else(|| {
            ControllerError::NotReady("browser adapter is unavailable".to_owned())
        })?;
        let terminal = match deadline {
            Some(deadline) => adapter
                .next_download_terminal_until(&session.browser_lease, deadline)
                .map_err(browser_pre_dispatch_error)?,
            None => adapter
                .next_download_terminal(
                    &session.browser_lease,
                    session.adapter_config.request_timeout_ms,
                )
                .map_err(browser_pre_dispatch_error)?,
        };
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
        deadline: Instant,
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
                    .inspect_form_until(&browser_lease, selector, payload_digest, deadline)
                    .map_err(browser_pre_dispatch_error)?;
                Self::authorize_browser_url_scope(session, &inspection.current_page_url)?;
                Self::authorize_browser_method(session, &inspection.normalized_method)?;
                Self::authorize_browser_url_scope(session, &inspection.resolved_action_url)?;
                Ok(Some(inspection))
            }
            BrowserAction::SubmitFormWithValues {
                selector, fields, ..
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
                    .inspect_form_values_until(&browser_lease, selector, fields, deadline)
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
            BrowserAction::SubmitForm { .. } | BrowserAction::SubmitFormWithValues { .. } => {
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

    fn browser_action_approval_binding(
        &self,
        task_id: &str,
        required_capabilities: &BTreeSet<Capability>,
    ) -> Result<(Capability, bool), ControllerError> {
        let mut selected: Option<Capability> = None;
        for capability in required_capabilities {
            if !self.approval_required_for_task_permission(task_id, *capability)? {
                continue;
            }
            if let Some(existing) = selected {
                return Err(ControllerError::Policy(PolicyError::Denied(format!(
                    "browser action requires multiple separately approved permissions that cannot share one exact approval binding: {},{}",
                    existing.as_plan_ir_str(),
                    capability.as_plan_ir_str()
                ))));
            }
            selected = Some(*capability);
        }
        let approval_required = selected.is_some();
        Ok((
            selected.unwrap_or(Capability::BrowserInteractive),
            approval_required,
        ))
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
        let (permission_class, approval_required) =
            self.browser_action_approval_binding(&session.task_id, &required_capabilities)?;
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
            permission_class,
            approval_required,
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
        deadline: Instant,
    ) -> Result<BrowserActionReceipt, BrowserError> {
        if matches!(
            action,
            BrowserAction::CaptureSynopsis { .. } | BrowserAction::CaptureScreenshot { .. }
        ) {
            return session
                .adapter
                .as_mut()
                .ok_or_else(|| BrowserError::Process("browser adapter is unavailable".to_owned()))?
                .execute_until(&session.browser_lease, action, deadline);
        }
        session
            .adapter
            .as_mut()
            .ok_or_else(|| BrowserError::Process("browser adapter is unavailable".to_owned()))?
            .dispatch_intercepted_action_until(
                &session.browser_lease,
                action,
                approved_form,
                deadline,
            )?;
        loop {
            match session
                .adapter
                .as_mut()
                .ok_or_else(|| BrowserError::Process("browser adapter is unavailable".to_owned()))?
                .finish_dispatched_action_until(&session.browser_lease, deadline)
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
                        .next_document_request_until(&session.browser_lease, deadline)?;
                    if Self::authorize_browser_document_request(session, &observation).is_err() {
                        let abort_result = session
                            .adapter
                            .as_mut()
                            .ok_or_else(|| {
                                BrowserError::Process("browser adapter is unavailable".to_owned())
                            })?
                            .resolve_document_request_until(
                                &session.browser_lease,
                                &observation,
                                BrowserDocumentRequestDecision::Abort,
                                deadline,
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
                        .resolve_document_request_until(
                            &session.browser_lease,
                            &observation,
                            BrowserDocumentRequestDecision::Continue,
                            deadline,
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
        if receipt_bytes_len > authorized.output_bytes {
            self.mark_dispatched_browser_unknown(session, authorized)?;
            return Err(ControllerError::UnknownAction(authorized.action_id.clone()));
        }
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
        deadline: Instant,
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
                Some(deadline),
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

    fn browser_action_deadline(
        &self,
        session: &ControllerBrowserSession,
        action: &BrowserAction,
    ) -> Result<(u64, Instant), ControllerError> {
        let active = self.active_ref()?;
        let task = active.tasks.get(&session.task_id).ok_or_else(|| {
            ControllerError::NotReady("browser action task disappeared".to_owned())
        })?;
        let action_budget = task.autonomy_budget.as_ref().ok_or_else(|| {
            ControllerError::NotReady(
                "browser action requires a durable task autonomy budget".to_owned(),
            )
        })?;
        action_budget.validate()?;
        let action_deadline_ms =
            browser_action_reservation_bounds(session, action, action_budget)?.0;
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(action_deadline_ms))
            .ok_or_else(|| {
                ControllerError::NotReady(
                    "browser action absolute deadline overflowed monotonic clock".to_owned(),
                )
            })?;
        Ok((action_deadline_ms, deadline))
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
        let (action_deadline_ms, deadline) = self.browser_action_deadline(session, action)?;
        let approved_form = Self::browser_action_destination_binding(session, action, deadline)?;
        let authorized = self.lower_browser_action(
            session,
            tool_manifest,
            &permission_decision,
            action,
            approved_form.as_ref(),
        )?;
        if authorized.action_deadline_ms != action_deadline_ms {
            return Err(ControllerError::InvalidPlan(
                "browser action deadline changed after pre-dispatch destination binding".to_owned(),
            ));
        }
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
        let receipt = match Self::run_browser_action_after_dispatch(
            session,
            action,
            approved_form.as_ref(),
            deadline,
        ) {
            Ok(receipt) => receipt,
            Err(error) => {
                eprintln!(
                    "PD-T03 browser diagnostic {}: {error}",
                    authorized.action_id
                );
                self.mark_dispatched_browser_unknown(session, &authorized)?;
                return Err(ControllerError::UnknownAction(authorized.action_id));
            }
        };
        let receipt = self.complete_dispatched_browser_receipt(
            session,
            tool_manifest,
            &authorized,
            action,
            receipt,
            deadline,
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

    /// Starts one exact generated loopback application generation under Controller process,
    /// `ActionJournal`, task-loopback, and Seatbelt authority.
    ///
    /// The browser session must already own the exact task loopback grant. Runtime `SQLite` is placed
    /// in a Controller-owned data root adjacent to CAS rather than in the repository. The start
    /// action is committed only after an exact `/health` response and live process identity are
    /// proven.
    ///
    /// # Errors
    /// Fails closed for stale session/task authority, unpinned Python, malformed paths, process or
    /// Seatbelt ambiguity, approval/policy denial, readiness timeout, or durable state drift.
    #[allow(clippy::too_many_lines)]
    pub fn start_managed_loopback_app<I: sovereign_policy::ExecutionIsolationBackend>(
        &mut self,
        session: &ControllerBrowserSession,
        runtime: &ExecutionRuntime<'_, I>,
        generation: u32,
        server_relative_path: &Path,
        database_filename: &str,
    ) -> Result<ControllerManagedLoopbackApp, ControllerError> {
        self.start_managed_loopback_app_inner(
            session,
            runtime,
            generation,
            ManagedLoopbackLaunch::Python {
                server_relative_path,
                database_filename,
            },
        )
    }

    /// Configures the Controller-owned, digest-pinned Node executable for typed managed launches.
    /// The Plan may choose the Node runtime but cannot select or replace this executable.
    /// Reconfigure after recovery, before the first Node launch.
    pub fn configure_managed_node_executable(
        &mut self,
        command_policy: &sovereign_policy::CommandPolicy,
        executable: &Path,
    ) -> Result<(), ControllerError> {
        let pinned = command_policy.pinned_executable(executable)?;
        self.managed_node_executable = Some(pinned.path.clone());
        Ok(())
    }

    /// Pins the Controller's local PostgreSQL socket and dedicated `sovereign_app` database OID.
    /// The Plan cannot supply or override either value. Reconfigure after Controller recovery.
    #[cfg(unix)]
    pub fn configure_managed_postgres_backend(
        &mut self,
        backend_socket: &Path,
        database_oid: u32,
    ) -> Result<(), ControllerError> {
        if !backend_socket.is_absolute() || database_oid == 0 {
            return Err(ControllerError::NotReady(
                "managed PostgreSQL needs an absolute socket and nonzero database OID".to_owned(),
            ));
        }
        let metadata = fs::symlink_metadata(backend_socket)?;
        if !std::os::unix::fs::FileTypeExt::is_socket(&metadata.file_type()) {
            return Err(ControllerError::NotReady(
                "managed PostgreSQL endpoint is not a Unix socket".to_owned(),
            ));
        }
        self.managed_postgres_backend = Some(PostgresBrokerConfig {
            backend_socket: backend_socket.to_path_buf(),
            database_oid,
        });
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    #[cfg(unix)]
    fn commit_managed_postgres_network_grant(
        &mut self,
        action: &AuthorizedBrowserAction,
        manifest: &ToolManifest,
        decision: &PermissionDecision,
        artifacts: &ArtifactStore,
    ) -> Result<(), ControllerError> {
        self.prepare_action_for_dispatch(action, manifest, decision)?;
        let receipt = serde_json::to_vec(&serde_json::json!({
            "schema": "controller.postgres_broker_network_grant.v1",
            "action_id": action.action_id,
            "destination_digest": action.destination_digest,
            "execution_identity_digest": action.isolation_policy_digest,
            "outcome": "authority_recorded_no_network_dispatched",
        }))?;
        let mut journal = ActionJournal::new(&mut self.state);
        journal.transition(action, ActionState::Authorized, ActionState::Dispatched)?;
        journal.observe_with_receipt(action, artifacts, &receipt)?;
        journal.commit_with_bound_result(action, ActionState::Observed)?;
        Ok(())
    }

    fn start_managed_loopback_app_inner<I: sovereign_policy::ExecutionIsolationBackend>(
        &mut self,
        session: &ControllerBrowserSession,
        runtime: &ExecutionRuntime<'_, I>,
        generation: u32,
        launch: ManagedLoopbackLaunch<'_>,
    ) -> Result<ControllerManagedLoopbackApp, ControllerError> {
        self.require_execution_not_paused()?;
        if generation == 0 {
            return Err(ControllerError::NotReady(
                "managed loopback generation must be positive".to_owned(),
            ));
        }
        let database_filename = match &launch {
            ManagedLoopbackLaunch::Python {
                server_relative_path,
                database_filename,
            } => {
                validate_managed_relative_file(server_relative_path, "server")?;
                *database_filename
            }
            ManagedLoopbackLaunch::Node {
                working_directory_relative_path,
                entrypoint_relative_path,
                persistence,
                ..
            } => {
                if *working_directory_relative_path != Path::new(".") {
                    validate_managed_relative_file(
                        working_directory_relative_path,
                        "working directory",
                    )?;
                }
                validate_managed_relative_file(entrypoint_relative_path, "entrypoint")?;
                match persistence {
                    BrowserManagedPersistenceBindingV1::ArgvFlag { filename, .. } => {
                        filename.as_str()
                    }
                    BrowserManagedPersistenceBindingV1::PostgresBrokerV1 { .. } => "sovereign_app",
                }
            }
        };
        validate_managed_database_filename(database_filename)?;
        let current_epoch = self.state.current_execution_epoch()?;
        let active = self.active_ref()?;
        if active.plan_id != session.plan_id
            || active.revision != session.plan_revision
            || current_epoch != session.execution_epoch
        {
            return Err(ControllerError::NotReady(
                "managed loopback app requires the exact active browser plan/epoch".to_owned(),
            ));
        }
        let task = active.tasks.get(&session.task_id).ok_or_else(|| {
            ControllerError::NotReady("managed loopback browser task disappeared".to_owned())
        })?;
        let attempt = active.attempts.get(&session.attempt_id).ok_or_else(|| {
            ControllerError::NotReady("managed loopback browser attempt disappeared".to_owned())
        })?;
        if task.task_contract_digest != session.task_contract_digest
            || task.state != TaskState::Running
            || attempt.task_id != session.task_id
            || attempt.state != AttemptState::Executing
        {
            return Err(ControllerError::NotReady(
                "managed loopback app requires exact Running/Executing browser authority"
                    .to_owned(),
            ));
        }
        let grant = session
            .task_loopback_grants
            .iter()
            .find(|grant| grant.resource_lease_id == session.resource_lease.lease_id)
            .ok_or_else(|| {
                ControllerError::NotReady(
                    "managed loopback app lost exact browser task-loopback grant".to_owned(),
                )
            })?
            .clone();
        grant
            .validate(unix_millis()?)
            .map_err(|error| managed_loopback_policy_error(&error))?;
        let permission_decision =
            self.permission_decision_for_task(&session.task_id, runtime.tool_manifest)?;
        if !permission_decision
            .effective
            .contains(Capability::ProcessExec)
        {
            return Err(ControllerError::Policy(PolicyError::Denied(
                "managed loopback app requires process_exec capability".to_owned(),
            )));
        }
        let postgres_permission_decision = if matches!(
            &launch,
            ManagedLoopbackLaunch::Node {
                persistence: BrowserManagedPersistenceBindingV1::PostgresBrokerV1 { .. },
                ..
            }
        ) {
            let decision =
                self.validate_browser_session_for_action(session, &session.tool_manifest)?;
            if !decision.effective.contains(Capability::NetworkWrite) {
                return Err(ControllerError::Policy(PolicyError::Denied(
                    "managed PostgreSQL broker requires network_write capability".to_owned(),
                )));
            }
            Some(decision)
        } else {
            None
        };

        let repository_root = self.task_execution_root(&session.task_id)?.canonicalize()?;
        let runtime_repository_root = runtime
            .isolation_request
            .repository_root
            .canonicalize()
            .map_err(|_| {
                ControllerError::NotReady(
                    "managed loopback runtime repository root is unavailable".to_owned(),
                )
            })?;
        if runtime_repository_root != repository_root {
            return Err(ControllerError::Policy(PolicyError::Denied(
                "managed loopback runtime repository authority does not match the exact task repository"
                    .to_owned(),
            )));
        }
        let working_directory = match &launch {
            ManagedLoopbackLaunch::Python { .. } => repository_root.clone(),
            ManagedLoopbackLaunch::Node {
                working_directory_relative_path,
                ..
            } => {
                let directory = repository_root
                    .join(working_directory_relative_path)
                    .canonicalize()
                    .map_err(|_| {
                        ControllerError::NotReady(
                            "managed Node working directory does not exist".to_owned(),
                        )
                    })?;
                if !directory.starts_with(&repository_root) || !directory.is_dir() {
                    return Err(ControllerError::NotReady(
                        "managed Node working directory escaped the canonical repository"
                            .to_owned(),
                    ));
                }
                directory
            }
        };
        let server_path = match &launch {
            ManagedLoopbackLaunch::Python {
                server_relative_path,
                ..
            } => repository_root.join(server_relative_path),
            ManagedLoopbackLaunch::Node {
                entrypoint_relative_path,
                ..
            } => working_directory.join(entrypoint_relative_path),
        };
        let canonical_server_path = server_path.canonicalize().map_err(|_| {
            ControllerError::NotReady(
                "managed loopback server path is not an existing regular file".to_owned(),
            )
        })?;
        if !canonical_server_path.starts_with(&working_directory)
            || !canonical_server_path.is_file()
            || canonical_server_path.parent().is_none()
        {
            return Err(ControllerError::NotReady(
                "managed loopback server path escaped the canonical repository or is not a regular file"
                    .to_owned(),
            ));
        }
        let scope_digest = sha256_prefixed(
            format!(
                "{}\0{}\0{}\0{}",
                session.plan_id, session.task_id, session.attempt_id, grant.port
            )
            .as_bytes(),
        );
        let data_root = runtime
            .artifacts
            .root()
            .parent()
            .ok_or_else(|| {
                ControllerError::NotReady(
                    "artifact store has no parent for managed application data".to_owned(),
                )
            })?
            .join("managed-app-data")
            .join(&scope_digest[7..27]);
        fs::create_dir_all(&data_root)?;
        #[cfg(unix)]
        fs::set_permissions(&data_root, fs::Permissions::from_mode(0o700))?;
        let data_root = data_root.canonicalize()?;
        let database_path = data_root.join(database_filename);
        #[cfg(unix)]
        let mut postgres_broker = if matches!(
            &launch,
            ManagedLoopbackLaunch::Node {
                persistence: BrowserManagedPersistenceBindingV1::PostgresBrokerV1 { .. },
                ..
            }
        ) {
            let config = self.managed_postgres_backend.clone().ok_or_else(|| {
                ControllerError::NotReady(
                    "Controller-owned PostgreSQL backend is not configured".to_owned(),
                )
            })?;
            Some(ControllerPostgresBroker::prepare(config).map_err(|error| {
                ControllerError::NotReady(format!(
                    "Controller-owned PostgreSQL broker refused to prepare: {error}"
                ))
            })?)
        } else {
            None
        };
        #[cfg(not(unix))]
        let postgres_broker_port: Option<u16> = None;
        #[cfg(unix)]
        let postgres_broker_port = postgres_broker.as_ref().map(ControllerPostgresBroker::port);
        let isolation = LoopbackServerIsolationRequestV1 {
            task_loopback_grant: grant.clone(),
            repository_root: repository_root.clone(),
            data_root: data_root.clone(),
            user_home_root: runtime.isolation_request.user_home_root.clone(),
            extra_protected_read_roots: runtime
                .isolation_request
                .extra_protected_read_roots
                .clone(),
            postgres_broker_port,
            now_ms: unix_millis()?,
        };
        let isolation_policy_digest = isolation
            .digest()
            .map_err(|error| managed_loopback_policy_error(&error))?;
        let server_backend = MacLoopbackServerSandboxExecBackend::detect()
            .map_err(|error| managed_loopback_policy_error(&error))?;
        let (pinned, args, readiness) = match &launch {
            ManagedLoopbackLaunch::Python { .. } => (
                runtime
                    .command_policy
                    .pinned_executable(runtime.python_executable)?,
                vec![
                    "-B".to_owned(),
                    canonical_server_path.display().to_string(),
                    "--host".to_owned(),
                    "127.0.0.1".to_owned(),
                    "--port".to_owned(),
                    grant.port.to_string(),
                    "--db".to_owned(),
                    database_path.display().to_string(),
                ],
                None,
            ),
            ManagedLoopbackLaunch::Node {
                executable,
                argv,
                dynamic_port,
                readiness,
                persistence,
                ..
            } => {
                let BrowserManagedArgBindingV1::ArgvFlag { flag: port_flag } = dynamic_port;
                let (data_flag, data_value) = match persistence {
                    BrowserManagedPersistenceBindingV1::ArgvFlag { flag, .. } => {
                        (flag, database_path.display().to_string())
                    }
                    BrowserManagedPersistenceBindingV1::PostgresBrokerV1 { flag } => {
                        let broker_port = postgres_broker_port.ok_or_else(|| {
                            ControllerError::NotReady(
                                "PostgreSQL broker is unavailable for managed app".to_owned(),
                            )
                        })?;
                        (
                            flag,
                            format!(
                                "postgresql://sovereign_app_runtime@127.0.0.1:{broker_port}/sovereign_app"
                            ),
                        )
                    }
                };
                let mut args = Vec::with_capacity(argv.len() + 5);
                args.push(canonical_server_path.display().to_string());
                args.extend(argv.iter().cloned());
                args.extend([
                    port_flag.clone(),
                    grant.port.to_string(),
                    data_flag.clone(),
                    data_value,
                ]);
                (
                    runtime.command_policy.pinned_executable(executable)?,
                    args,
                    Some(*readiness),
                )
            }
        };
        let isolated = server_backend
            .isolate(&pinned.path, &args, &isolation)
            .map_err(|error| managed_loopback_policy_error(&error))?;
        let managed_deadline_base = Instant::now();
        let managed_now_ms = unix_millis()?;
        let grant_remaining_ms = grant.expires_at_ms.saturating_sub(managed_now_ms);
        let grant_remaining_ms = u64::try_from(grant_remaining_ms).map_err(|_| {
            ControllerError::NotReady(
                "managed loopback grant expired before process dispatch".to_owned(),
            )
        })?;
        let managed_lifetime_ms = MANAGED_LOOPBACK_MAX_LIFETIME_MS.min(grant_remaining_ms);
        if managed_lifetime_ms == 0 {
            return Err(ControllerError::NotReady(
                "managed loopback grant expired before process dispatch".to_owned(),
            ));
        }
        let managed_deadline = managed_deadline_base
            .checked_add(Duration::from_millis(managed_lifetime_ms))
            .ok_or_else(|| {
                ControllerError::NotReady(
                    "managed loopback absolute lifetime deadline overflowed monotonic clock"
                        .to_owned(),
                )
            })?;
        let command = CommandSpec {
            executable: pinned.path.clone(),
            args,
            working_directory,
            environment: BTreeMap::new(),
            mode: CommandMode::Direct,
            declared_risk: CommandRisk::RepositoryMutation,
            timeout_ms: managed_lifetime_ms,
            output_limit_bytes: MANAGED_LOOPBACK_START_OUTPUT_BYTES,
            disk_write_limit_bytes: MANAGED_LOOPBACK_START_DISK_BYTES,
            subprocess_limit: MANAGED_LOOPBACK_SUBPROCESS_LIMIT,
        };
        let generation_binding = sha256_prefixed(
            format!(
                "{}\0{}\0{}\0{}\0{}",
                session.plan_id,
                session.task_id,
                session.attempt_id,
                session.execution_epoch,
                generation
            )
            .as_bytes(),
        );
        let action_id = format!("managed-loopback-start.{}", &generation_binding[7..27]);
        let now_ms = unix_millis()?;
        let expires_at_ms = self.approval_bound_action_expiry(
            &action_id,
            now_ms
                .saturating_add(i64::try_from(managed_lifetime_ms).unwrap_or(i64::MAX))
                .saturating_add(60_000),
        )?;
        let grant_digest = digest_json(&serde_json::to_value(&grant)?)?;
        #[cfg(unix)]
        let destination_digest = if let Some(broker_port) = postgres_broker_port {
            let config = self.managed_postgres_backend.as_ref().ok_or_else(|| {
                ControllerError::NotReady("PostgreSQL backend configuration disappeared".to_owned())
            })?;
            digest_json(&serde_json::json!({
                "loopback_grant_digest": grant_digest,
                "postgres_broker_port": broker_port,
                "postgres_database": "sovereign_app",
                "postgres_role": "sovereign_app_runtime",
                "postgres_database_oid": config.database_oid,
                "postgres_backend_socket": config.backend_socket,
            }))?
        } else {
            grant_digest.clone()
        };
        #[cfg(not(unix))]
        let destination_digest = grant_digest.clone();
        let repository_id = active
            .single_task_repository(&session.task_id)?
            .repository_id
            .clone();
        let active_policy_digest = active.policy_digest.clone();
        #[cfg(unix)]
        if let Some(broker) = postgres_broker.as_ref() {
            let browser_decision = postgres_permission_decision.as_ref().ok_or_else(|| {
                ControllerError::NotReady(
                    "PostgreSQL broker lost browser network authority".to_owned(),
                )
            })?;
            let config = self.managed_postgres_backend.as_ref().ok_or_else(|| {
                ControllerError::NotReady("PostgreSQL backend configuration disappeared".to_owned())
            })?;
            let (socket_device, socket_inode, socket_owner) = broker.backend_identity();
            let broker_destination_digest = digest_json(&serde_json::json!({
                "schema": "controller.postgres_broker_destination.v1",
                "database": "sovereign_app",
                "role": "sovereign_app_runtime",
                "database_oid": config.database_oid,
                "socket": config.backend_socket,
                "socket_device": socket_device,
                "socket_inode": socket_inode,
                "socket_owner": socket_owner,
                "task_loopback_grant_digest": grant_digest,
                "generation": generation,
            }))?;
            let broker_isolation_digest = digest_json(&serde_json::json!({
                "schema": "controller.postgres_broker_execution.v1",
                "destination_digest": broker_destination_digest,
                "executable_digest": pinned.sha256,
                "entrypoint": canonical_server_path,
                "repository_root": repository_root,
            }))?;
            let broker_action_id =
                format!("managed-postgres-broker.{}", &generation_binding[7..27]);
            let broker_expires_at_ms =
                self.approval_bound_action_expiry(&broker_action_id, expires_at_ms)?;
            let network_action = AuthorizedBrowserAction {
                action_id: broker_action_id.clone(),
                plan_id: session.plan_id.clone(),
                plan_revision: session.plan_revision,
                task_id: session.task_id.clone(),
                attempt_id: session.attempt_id.clone(),
                tool_id: session.tool_manifest.tool_id.clone(),
                tool_version: session.tool_manifest.version.clone(),
                tool_digest: session.tool_manifest.content_digest.clone(),
                repository_id: repository_id.clone(),
                destination_digest: Some(broker_destination_digest.clone()),
                execution_epoch: session.execution_epoch,
                policy_digest: active_policy_digest.clone(),
                permission_decision_digest: browser_decision.digest(),
                isolation_policy_digest: broker_isolation_digest.clone(),
                nonce: format!("nonce.{broker_action_id}"),
                expires_at_ms: broker_expires_at_ms,
                browser_action_digest: broker_isolation_digest,
                required_capabilities: BTreeSet::from([
                    Capability::BrowserInteractive,
                    Capability::NetworkWrite,
                ]),
                permission_class: Capability::NetworkWrite,
                approval_required: self.approval_required_for_task_permission(
                    &session.task_id,
                    Capability::NetworkWrite,
                )?,
                reconciliation_mode: ReconciliationMode::UnsafeSideEffect,
                declared_risk: CommandRisk::RepositoryMutation,
                action_deadline_ms: MANAGED_LOOPBACK_MAX_LIFETIME_MS,
                output_bytes: 1024,
            };
            if let Some(record) = self.state.action_record(&broker_action_id)? {
                if record.state == ActionState::Committed.as_str() {
                    network_action.validate(unix_millis()?)?;
                    network_action.verify_permission_decision(browser_decision)?;
                    if record.payload_digest != network_action.payload_digest()
                        || record.policy_digest != network_action.policy_digest
                        || record.execution_epoch != network_action.execution_epoch
                        || record.result_digest.is_none()
                    {
                        return Err(ControllerError::NotReady(
                            "committed PostgreSQL broker authority drifted".to_owned(),
                        ));
                    }
                } else {
                    self.commit_managed_postgres_network_grant(
                        &network_action,
                        &session.tool_manifest,
                        browser_decision,
                        runtime.artifacts,
                    )?;
                }
            } else {
                self.commit_managed_postgres_network_grant(
                    &network_action,
                    &session.tool_manifest,
                    browser_decision,
                    runtime.artifacts,
                )?;
            }
        }
        let authorized = AuthorizedAction {
            action_id: action_id.clone(),
            plan_id: session.plan_id.clone(),
            plan_revision: session.plan_revision,
            task_id: session.task_id.clone(),
            attempt_id: session.attempt_id.clone(),
            tool_id: runtime.tool_manifest.tool_id.clone(),
            tool_version: runtime.tool_manifest.version.clone(),
            tool_digest: runtime.tool_manifest.content_digest.clone(),
            executable_digest: pinned.sha256.clone(),
            repository_id,
            destination_digest: Some(destination_digest),
            permission_class: Capability::ProcessExec,
            execution_epoch: session.execution_epoch,
            policy_digest: active_policy_digest,
            permission_decision_digest: permission_decision.digest(),
            isolation_policy_digest: isolation_policy_digest.clone(),
            nonce: format!("nonce.{action_id}"),
            expires_at_ms,
            command,
            individually_authorized_environment: BTreeSet::new(),
            approval_required: self
                .approval_required_for_task_permission(&session.task_id, Capability::ProcessExec)?,
            reconciliation_mode: Self::reconciliation_mode_for_manifest(runtime.tool_manifest)?,
        };
        self.prepare_action_for_dispatch(&authorized, runtime.tool_manifest, &permission_decision)?;
        self.require_current_baseline(runtime.registry)?;
        let runner = ProcessRunner::new(runtime.command_policy, runtime.isolation_backend);
        let mut process = {
            let mut journal = ActionJournal::new(&mut self.state);
            runner.start_managed_preisolated_with_write_root_until(
                &mut journal,
                &authorized,
                &isolated,
                &isolation_policy_digest,
                &data_root,
                managed_deadline,
            )?
        };
        #[cfg(unix)]
        let broker_ready = if let Some(broker) = &mut postgres_broker {
            broker
                .activate_for_process(
                    process.process_group_id(),
                    process.leader_identity().to_owned(),
                    managed_deadline,
                )
                .map_err(|error| {
                    ControllerError::NotReady(format!(
                        "dispatched PostgreSQL broker activation failed: {error}"
                    ))
                })
        } else {
            Ok(())
        };
        #[cfg(not(unix))]
        let broker_ready: Result<(), ControllerError> = Ok(());
        let ready = broker_ready
            .and_then(|()| wait_for_managed_loopback_health(&mut process, grant.port, readiness));
        if let Err(error) = ready {
            let cleanup = {
                let mut journal = ActionJournal::new(&mut self.state);
                runner.stop_managed(&mut journal, &mut process)
            };
            if cleanup.is_ok() {
                let mut journal = ActionJournal::new(&mut self.state);
                journal.transition(&authorized, ActionState::Dispatched, ActionState::Unknown)?;
                let _ = journal.reconcile_unknown(
                    &authorized,
                    Some(sovereign_tools::ReconciliationProof::EffectAbsent),
                )?;
            }
            return Err(error);
        }
        let process_group_id = process.process_group_id();
        let leader_identity = process.leader_identity().to_owned();
        let start_result_digest = {
            let mut journal = ActionJournal::new(&mut self.state);
            runner.commit_managed_started(
                &mut journal,
                &authorized,
                runtime.artifacts,
                &mut process,
            )?
        };
        #[cfg(unix)]
        let postgres_database_oid = if postgres_broker_port.is_some() {
            self.managed_postgres_backend
                .as_ref()
                .map(|config| config.database_oid)
        } else {
            None
        };
        #[cfg(not(unix))]
        let postgres_database_oid = None;
        let binding = ManagedLoopbackAppBindingV1 {
            schema_version: MANAGED_LOOPBACK_APP_SCHEMA_VERSION,
            app_id: format!("managed-loopback.{}", &generation_binding[7..27]),
            generation,
            plan_id: session.plan_id.clone(),
            plan_revision: session.plan_revision,
            task_id: session.task_id.clone(),
            task_contract_digest: session.task_contract_digest.clone(),
            attempt_id: session.attempt_id.clone(),
            execution_epoch: session.execution_epoch,
            browser_resource_lease_id: session.resource_lease.lease_id.clone(),
            loopback_grant_digest: grant_digest,
            port: grant.port,
            repository_root: repository_root.display().to_string(),
            data_root: data_root.display().to_string(),
            database_path: if postgres_broker_port.is_some() {
                "postgresql:sovereign_app".to_owned()
            } else {
                database_path.display().to_string()
            },
            postgres_broker_port,
            postgres_database_oid,
            start_action_id: action_id.clone(),
            start_result_digest,
            process_group_id,
            leader_identity,
            state: "ready".to_owned(),
        };
        self.state.put_state(
            MANAGED_LOOPBACK_APP_NAMESPACE,
            &action_id,
            &serde_json::to_string(&binding)?,
        )?;
        self.append_controller_event(
            "managed_loopback_ready",
            &binding.app_id,
            &serde_json::to_value(&binding)?,
        )?;
        self.checkpoint_now()?;
        Ok(ControllerManagedLoopbackApp {
            binding,
            process,
            #[cfg(unix)]
            postgres_broker,
        })
    }

    /// Starts one managed application generation using only the typed browser acceptance launch
    /// contract already persisted in the active Plan IR. Callers select the generation number but
    /// cannot substitute a server path, database filename, runtime ABI, host, or port.
    ///
    /// # Errors
    /// Returns fail-closed for missing/stale Plan browser acceptance, unsupported runtime ABI,
    /// generation overflow, loopback-grant drift, or any error from the governed managed-app path.
    pub fn start_plan_managed_loopback_app<I: sovereign_policy::ExecutionIsolationBackend>(
        &mut self,
        session: &ControllerBrowserSession,
        runtime: &ExecutionRuntime<'_, I>,
        generation: u32,
    ) -> Result<ControllerManagedLoopbackApp, ControllerError> {
        let contract = {
            let active = self.active_ref()?;
            let task = active.tasks.get(&session.task_id).ok_or_else(|| {
                ControllerError::NotReady("browser launch task disappeared".to_owned())
            })?;
            browser_acceptance_contract(&task.task)?.ok_or_else(|| {
                ControllerError::InvalidPlan(
                    "browser launch requires a typed Plan IR browser_acceptance contract"
                        .to_owned(),
                )
            })?
        };
        if generation == 0 || generation > contract.launch.required_generations() {
            return Err(ControllerError::InvalidPlan(format!(
                "browser launch generation {generation} exceeds Plan IR required_generations {}",
                contract.launch.required_generations()
            )));
        }
        let grant = session
            .task_loopback_grants
            .iter()
            .find(|grant| grant.resource_lease_id == session.resource_lease.lease_id)
            .ok_or_else(|| {
                ControllerError::NotReady(
                    "browser launch lost exact task-loopback grant".to_owned(),
                )
            })?;
        if grant.port != contract.loopback.port {
            return Err(ControllerError::InvalidPlan(
                "browser launch Plan IR loopback port differs from exact Controller grant"
                    .to_owned(),
            ));
        }
        match &contract.launch {
            BrowserManagedAppLaunchV1::PythonManagedServerV1 {
                server_relative_path,
                database_filename,
                ..
            } => self.start_managed_loopback_app(
                session,
                runtime,
                generation,
                Path::new(server_relative_path),
                database_filename,
            ),
            BrowserManagedAppLaunchV1::NodeManagedServerV1 {
                working_directory_relative_path,
                entrypoint_relative_path,
                argv,
                dynamic_port,
                readiness,
                persistence,
                ..
            } => {
                let executable = self.managed_node_executable.clone().ok_or_else(|| {
                    ControllerError::NotReady(
                        "Controller-owned Node executable is not configured".to_owned(),
                    )
                })?;
                self.start_managed_loopback_app_inner(
                    session,
                    runtime,
                    generation,
                    ManagedLoopbackLaunch::Node {
                        executable: &executable,
                        working_directory_relative_path: Path::new(working_directory_relative_path),
                        entrypoint_relative_path: Path::new(entrypoint_relative_path),
                        argv,
                        dynamic_port,
                        readiness,
                        persistence,
                    },
                )
            }
        }
    }

    /// Stops one exact Controller-owned loopback generation and proves physical group absence before
    /// marking its durable process lease/lifecycle projection stopped.
    ///
    /// # Errors
    /// Fails closed for session/generation drift, PID reuse, cleanup ambiguity, or durable state
    /// failure.
    pub fn stop_managed_loopback_app<I: sovereign_policy::ExecutionIsolationBackend>(
        &mut self,
        session: &ControllerBrowserSession,
        runtime: &ExecutionRuntime<'_, I>,
        app: &mut ControllerManagedLoopbackApp,
    ) -> Result<(), ControllerError> {
        if app.binding.state != "ready"
            || app.binding.plan_id != session.plan_id
            || app.binding.plan_revision != session.plan_revision
            || app.binding.task_id != session.task_id
            || app.binding.task_contract_digest != session.task_contract_digest
            || app.binding.attempt_id != session.attempt_id
            || app.binding.execution_epoch != session.execution_epoch
            || app.binding.browser_resource_lease_id != session.resource_lease.lease_id
        {
            return Err(ControllerError::NotReady(
                "managed loopback stop authority drifted from exact browser session".to_owned(),
            ));
        }
        let runner = ProcessRunner::new(runtime.command_policy, runtime.isolation_backend);
        {
            let mut journal = ActionJournal::new(&mut self.state);
            runner.stop_managed(&mut journal, &mut app.process)?;
        }
        #[cfg(unix)]
        if let Some(broker) = &mut app.postgres_broker {
            broker.stop().map_err(|error| {
                ControllerError::NotReady(format!(
                    "managed PostgreSQL broker cleanup failed: {error}"
                ))
            })?;
        }
        "stopped".clone_into(&mut app.binding.state);
        self.state.put_state(
            MANAGED_LOOPBACK_APP_NAMESPACE,
            &app.binding.start_action_id,
            &serde_json::to_string(&app.binding)?,
        )?;
        self.append_controller_event(
            "managed_loopback_stopped",
            &app.binding.app_id,
            &serde_json::to_value(&app.binding)?,
        )?;
        self.checkpoint_now()?;
        Ok(())
    }

    /// Returns true only when a nonterminal process lease is not the single exact ready managed
    /// loopback app owned by this same browser action task/attempt/epoch.
    pub(crate) fn has_blocking_process_lease_for_action(
        &self,
        action: &dyn JournalActionAuthority,
    ) -> Result<bool, ControllerError> {
        let browser_action = matches!(
            action.permission_class(),
            Capability::BrowserInteractive | Capability::NetworkRead | Capability::NetworkWrite
        );
        let mut tolerated = 0_u32;
        for record in self.state.state_records("controller.process_lease")? {
            let lease: super::RecoveryProcessLease = serde_json::from_str(&record.value_json)?;
            if matches!(lease.state.as_str(), "reaped" | "reaped_recovery") {
                continue;
            }
            if !browser_action || lease.state != "active" {
                return Ok(true);
            }
            let Some(raw_binding) = self
                .state
                .get_state(MANAGED_LOOPBACK_APP_NAMESPACE, &lease.action_id)?
            else {
                return Ok(true);
            };
            let binding: ManagedLoopbackAppBindingV1 = serde_json::from_str(&raw_binding)?;
            let action_record = self.state.action_record(&lease.action_id)?.ok_or_else(|| {
                ControllerError::InvalidPlan(
                    "managed loopback process lease lost its start action".to_owned(),
                )
            })?;
            if binding.schema_version != MANAGED_LOOPBACK_APP_SCHEMA_VERSION
                || binding.state != "ready"
                || binding.start_action_id != lease.action_id
                || binding.task_id != action.task_id()
                || binding.attempt_id != action.attempt_id()
                || binding.execution_epoch != action.execution_epoch()
                || binding.process_group_id != lease.process_group_id.unwrap_or_default()
                || lease.leader_identity.as_deref() != Some(binding.leader_identity.as_str())
                || action_record.state != ActionState::Committed.as_str()
                || action_record.execution_epoch != action.execution_epoch()
            {
                return Ok(true);
            }
            match process_group_leader_identity(binding.process_group_id)? {
                Some(identity) if identity == binding.leader_identity => {}
                _ => return Ok(true),
            }
            tolerated = tolerated.saturating_add(1);
            if tolerated > 1 {
                return Ok(true);
            }
        }
        Ok(false)
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

    /// Binds the active task's typed Plan IR browser acceptance semantics to one live browser
    /// task/attempt/session. Callers do not supply action expectations: the Controller derives every
    /// launch/action/restart expectation from the already-validated task contract and exact loopback
    /// grant.
    ///
    /// # Errors
    /// Fails closed when the task lacks browser acceptance, session authority is stale, Plan IR
    /// loopback authority differs from the exact grant, or a durable semantic contract drifts.
    pub fn bind_plan_browser_semantics(
        &mut self,
        session: &ControllerBrowserSession,
    ) -> Result<String, ControllerError> {
        let active = self.active_ref()?;
        let task = active.tasks.get(&session.task_id).ok_or_else(|| {
            ControllerError::NotReady("browser semantic task disappeared".to_owned())
        })?;
        let attempt = active.attempts.get(&session.attempt_id).ok_or_else(|| {
            ControllerError::NotReady("browser semantic attempt disappeared".to_owned())
        })?;
        let plan_contract = browser_acceptance_contract(&task.task)?.ok_or_else(|| {
            ControllerError::InvalidPlan(
                "browser semantic binding requires typed Plan IR browser_acceptance".to_owned(),
            )
        })?;
        if active.plan_id != session.plan_id
            || active.revision != session.plan_revision
            || task.task_contract_digest != session.task_contract_digest
            || attempt.task_id != session.task_id
            || attempt.state != AttemptState::Executing
            || task.state != TaskState::Running
        {
            return Err(ControllerError::NotReady(
                "browser semantic binding requires the exact Running/Executing Plan task"
                    .to_owned(),
            ));
        }
        let current_epoch = self.state.current_execution_epoch()?;
        if current_epoch != session.execution_epoch {
            return Err(ControllerError::NotReady(
                "browser semantic binding execution epoch is stale".to_owned(),
            ));
        }
        let grant = session
            .task_loopback_grants
            .iter()
            .find(|grant| grant.resource_lease_id == session.resource_lease.lease_id)
            .ok_or_else(|| {
                ControllerError::NotReady(
                    "browser semantic binding lost exact task-loopback grant".to_owned(),
                )
            })?;
        if grant.port != plan_contract.loopback.port {
            return Err(ControllerError::InvalidPlan(
                "browser semantic Plan IR loopback port differs from exact Controller grant"
                    .to_owned(),
            ));
        }
        let plan_contract_digest = digest_json(&serde_json::to_value(&plan_contract)?)?;
        let mut contract = BrowserSemanticContractV1 {
            schema_version: BROWSER_SEMANTIC_CONTRACT_SCHEMA_VERSION,
            plan_contract_digest,
            plan_id: session.plan_id.clone(),
            plan_revision: session.plan_revision,
            task_id: session.task_id.clone(),
            task_contract_digest: session.task_contract_digest.clone(),
            attempt_id: session.attempt_id.clone(),
            execution_epoch: session.execution_epoch,
            browser_lease_id: session.browser_lease.lease_id.clone(),
            browser_binding_digest: session.browser_lease.binding_digest(),
            loopback_port: grant.port,
            steps: plan_browser_semantic_steps(&plan_contract)?,
            required_managed_generations: plan_contract.launch.required_generations(),
            contract_digest: String::new(),
        };
        contract.contract_digest = browser_semantic_contract_digest(&contract)?;
        let value_json = serde_json::to_string(&contract)?;
        if let Some(existing) = self
            .state
            .get_state(BROWSER_SEMANTIC_CONTRACT_NAMESPACE, &session.attempt_id)?
        {
            let durable: BrowserSemanticContractV1 = serde_json::from_str(&existing)?;
            if durable != contract {
                return Err(ControllerError::NotReady(
                    "durable browser semantic contract differs from typed Plan IR contract"
                        .to_owned(),
                ));
            }
            return Ok(contract.contract_digest);
        }
        self.state.put_state(
            BROWSER_SEMANTIC_CONTRACT_NAMESPACE,
            &session.attempt_id,
            &value_json,
        )?;
        self.append_controller_event(
            "browser_semantic_contract_bound",
            &session.attempt_id,
            &serde_json::to_value(&contract)?,
        )?;
        self.checkpoint_now()?;
        Ok(contract.contract_digest)
    }

    /// Returns the exact ordered browser actions and generation boundaries encoded in the active
    /// Plan IR browser acceptance contract. The returned actions are already bound to the exact
    /// Controller loopback grant; callers do not construct URLs, selectors, payload digests, or
    /// restart boundaries themselves.
    ///
    /// # Errors
    /// Returns fail-closed for stale session/task authority, missing typed acceptance, or loopback
    /// port drift.
    pub fn plan_browser_actions_for_session(
        &self,
        session: &ControllerBrowserSession,
    ) -> Result<Vec<ControllerBrowserPlannedAction>, ControllerError> {
        let active = self.active_ref()?;
        let task = active.tasks.get(&session.task_id).ok_or_else(|| {
            ControllerError::NotReady("browser action-plan task disappeared".to_owned())
        })?;
        let attempt = active.attempts.get(&session.attempt_id).ok_or_else(|| {
            ControllerError::NotReady("browser action-plan attempt disappeared".to_owned())
        })?;
        if active.plan_id != session.plan_id
            || active.revision != session.plan_revision
            || task.task_contract_digest != session.task_contract_digest
            || task.state != TaskState::Running
            || attempt.task_id != session.task_id
            || attempt.state != AttemptState::Executing
        {
            return Err(ControllerError::NotReady(
                "browser action plan requires exact Running/Executing session authority".to_owned(),
            ));
        }
        let contract = browser_acceptance_contract(&task.task)?.ok_or_else(|| {
            ControllerError::InvalidPlan(
                "browser action plan requires typed Plan IR browser_acceptance".to_owned(),
            )
        })?;
        let grant = session
            .task_loopback_grants
            .iter()
            .find(|grant| grant.resource_lease_id == session.resource_lease.lease_id)
            .ok_or_else(|| {
                ControllerError::NotReady("browser action plan lost task-loopback grant".to_owned())
            })?;
        if grant.port != contract.loopback.port {
            return Err(ControllerError::InvalidPlan(
                "browser action Plan IR loopback port differs from exact Controller grant"
                    .to_owned(),
            ));
        }
        plan_browser_actions_from_contract(&contract)
    }

    /// Backward-compatible method name retained for callers compiled against the earlier focused
    /// proof API. It now delegates exclusively to typed Plan IR semantics and performs no symbol,
    /// title, application-name, or selector heuristic.
    pub fn bind_local_inventory_browser_semantics(
        &mut self,
        session: &ControllerBrowserSession,
    ) -> Result<String, ControllerError> {
        self.bind_plan_browser_semantics(session)
    }

    fn plan_semantic_contract_for_session(
        &self,
        session: &ControllerBrowserSession,
    ) -> Result<Option<BrowserSemanticContractV1>, ControllerError> {
        let active = self.active_ref()?;
        let task = active.tasks.get(&session.task_id).ok_or_else(|| {
            ControllerError::NotReady("browser semantic task disappeared".to_owned())
        })?;
        let Some(plan_contract) = browser_acceptance_contract(&task.task)? else {
            return Ok(None);
        };
        let raw = self
            .state
            .get_state(BROWSER_SEMANTIC_CONTRACT_NAMESPACE, &session.attempt_id)?
            .ok_or_else(|| {
                ControllerError::NotReady(
                    "typed browser task has no durable Controller semantic contract".to_owned(),
                )
            })?;
        let contract: BrowserSemanticContractV1 = serde_json::from_str(&raw)?;
        let plan_contract_digest = digest_json(&serde_json::to_value(&plan_contract)?)?;
        if contract.schema_version != BROWSER_SEMANTIC_CONTRACT_SCHEMA_VERSION
            || contract.plan_contract_digest != plan_contract_digest
            || contract.plan_id != session.plan_id
            || contract.plan_revision != session.plan_revision
            || contract.task_id != session.task_id
            || contract.task_contract_digest != session.task_contract_digest
            || contract.attempt_id != session.attempt_id
            || contract.execution_epoch != session.execution_epoch
            || contract.browser_lease_id != session.browser_lease.lease_id
            || contract.browser_binding_digest != session.browser_lease.binding_digest()
            || contract.contract_digest != browser_semantic_contract_digest(&contract)?
        {
            return Err(ControllerError::InvalidPlan(
                "durable Plan-driven browser semantic contract is malformed or stale".to_owned(),
            ));
        }
        Ok(Some(contract))
    }

    fn managed_generations_for_semantic_contract(
        &self,
        contract: &BrowserSemanticContractV1,
    ) -> Result<Vec<BrowserSemanticManagedGenerationV1>, ControllerError> {
        let mut bindings = self
            .state
            .state_records(MANAGED_LOOPBACK_APP_NAMESPACE)?
            .into_iter()
            .map(|record| serde_json::from_str::<ManagedLoopbackAppBindingV1>(&record.value_json))
            .collect::<Result<Vec<_>, _>>()?;
        bindings.retain(|binding| {
            binding.plan_id == contract.plan_id
                && binding.plan_revision == contract.plan_revision
                && binding.task_id == contract.task_id
                && binding.task_contract_digest == contract.task_contract_digest
                && binding.attempt_id == contract.attempt_id
                && binding.execution_epoch == contract.execution_epoch
                && binding.port == contract.loopback_port
        });
        bindings.sort_by_key(|binding| binding.generation);
        if bindings.len()
            != usize::try_from(contract.required_managed_generations).unwrap_or(usize::MAX)
        {
            return Err(ControllerError::NotReady(format!(
                "inventory semantic proof requires exactly {} managed app generations",
                contract.required_managed_generations
            )));
        }
        let journal = self.state.journal()?;
        let mut observed = Vec::with_capacity(bindings.len());
        let mut database_path: Option<String> = None;
        let mut previous_stopped_sequence = 0_i64;
        let mut process_identities = BTreeSet::new();
        for (index, binding) in bindings.iter().enumerate() {
            let expected_generation = u32::try_from(index + 1).unwrap_or(u32::MAX);
            validate_managed_generation_binding(
                binding,
                expected_generation,
                &mut database_path,
                &mut process_identities,
            )?;
            let generation = self.managed_generation_observation(
                contract,
                binding,
                &journal,
                previous_stopped_sequence,
            )?;
            previous_stopped_sequence = generation.stopped_sequence;
            observed.push(generation);
        }
        Ok(observed)
    }

    fn managed_generation_observation(
        &self,
        contract: &BrowserSemanticContractV1,
        binding: &ManagedLoopbackAppBindingV1,
        journal: &[sovereign_state::JournalEvent],
        previous_stopped_sequence: i64,
    ) -> Result<BrowserSemanticManagedGenerationV1, ControllerError> {
        let action = self
            .state
            .action_record(&binding.start_action_id)?
            .ok_or_else(|| {
                ControllerError::InvalidPlan(
                    "managed inventory generation lost start action record".to_owned(),
                )
            })?;
        if action.state != ActionState::Committed.as_str()
            || action.execution_epoch != contract.execution_epoch
            || action.result_digest.as_deref() != Some(binding.start_result_digest.as_str())
        {
            return Err(ControllerError::NotReady(
                "managed inventory generation start is not exact committed durable evidence"
                    .to_owned(),
            ));
        }
        let lease_raw = self
            .state
            .get_state("controller.process_lease", &binding.start_action_id)?
            .ok_or_else(|| {
                ControllerError::InvalidPlan(
                    "managed inventory generation lost durable process lease".to_owned(),
                )
            })?;
        let lease: super::RecoveryProcessLease = serde_json::from_str(&lease_raw)?;
        if !matches!(lease.state.as_str(), "reaped" | "reaped_recovery")
            || lease.process_group_id != Some(binding.process_group_id)
            || lease.leader_identity.as_deref() != Some(binding.leader_identity.as_str())
        {
            return Err(ControllerError::NotReady(
                "managed inventory generation is not proven physically stopped".to_owned(),
            ));
        }
        let (ready_sequence, stopped_sequence) =
            managed_generation_event_bounds(journal, binding, previous_stopped_sequence)?;
        Ok(BrowserSemanticManagedGenerationV1 {
            app_id: binding.app_id.clone(),
            generation: binding.generation,
            start_action_id: binding.start_action_id.clone(),
            start_result_digest: binding.start_result_digest.clone(),
            process_group_id: binding.process_group_id,
            leader_identity: binding.leader_identity.clone(),
            database_path: binding.database_path.clone(),
            ready_sequence,
            stopped_sequence,
        })
    }

    fn verify_and_persist_plan_semantic_proof(
        &mut self,
        session: &ControllerBrowserSession,
        receipts: &[BrowserActionReceipt],
        evidence_ids: &[String],
    ) -> Result<(), ControllerError> {
        let Some(contract) = self.plan_semantic_contract_for_session(session)? else {
            return Ok(());
        };
        if receipts.len() != contract.steps.len() || evidence_ids.len() != contract.steps.len() {
            return Err(ControllerError::NotReady(format!(
                "Plan-driven browser semantic proof requires exactly {} ordered receipts",
                contract.steps.len()
            )));
        }
        let managed_generations = self.managed_generations_for_semantic_contract(&contract)?;
        let mut observed_steps = Vec::with_capacity(receipts.len());
        for ((receipt, expected), receipt_digest) in receipts
            .iter()
            .zip(contract.steps.iter())
            .zip(evidence_ids.iter())
        {
            if receipt.action_id != expected.action_id
                || receipt.action_kind != expected.action_kind
                || receipt.action_digest != expected.action_digest
            {
                return Err(ControllerError::NotReady(format!(
                    "Plan-driven browser semantic action mismatch at {}",
                    expected.action_id
                )));
            }
            let action = self
                .state
                .action_record(&expected.action_id)?
                .ok_or_else(|| {
                    ControllerError::InvalidPlan(format!(
                        "browser semantic proof lost action {}",
                        expected.action_id
                    ))
                })?;
            let generation = managed_generations
                .iter()
                .find(|generation| generation.generation == expected.generation)
                .ok_or_else(|| {
                    ControllerError::InvalidPlan(format!(
                        "browser semantic step {} references missing managed generation {}",
                        expected.action_id, expected.generation
                    ))
                })?;
            if action.state != ActionState::Committed.as_str()
                || action.execution_epoch != contract.execution_epoch
                || action.result_digest.as_deref() != Some(receipt_digest.as_str())
            {
                return Err(ControllerError::NotReady(format!(
                    "browser semantic action {} is not exact committed evidence",
                    expected.action_id
                )));
            }
            validate_browser_action_generation_sequence(
                action.last_event_sequence,
                generation,
                &expected.action_id,
            )?;
            let mut matched = Vec::new();
            let mut verified_absent = Vec::new();
            if !expected.required_synopsis_contains.is_empty()
                || !expected.forbidden_synopsis_contains.is_empty()
            {
                let synopsis = receipt.synopsis.as_ref().ok_or_else(|| {
                    ControllerError::NotReady(format!(
                        "browser semantic synopsis {} is missing",
                        expected.action_id
                    ))
                })?;
                for predicate in &expected.required_synopsis_contains {
                    if !synopsis.text.contains(predicate) {
                        return Err(ControllerError::NotReady(format!(
                            "browser semantic synopsis {} lacks required predicate {predicate:?}",
                            expected.action_id
                        )));
                    }
                    matched.push(predicate.clone());
                }
                for predicate in &expected.forbidden_synopsis_contains {
                    if synopsis.text.contains(predicate) {
                        return Err(ControllerError::NotReady(format!(
                            "browser semantic synopsis {} contains forbidden predicate {predicate:?}",
                            expected.action_id
                        )));
                    }
                    verified_absent.push(predicate.clone());
                }
            }
            observed_steps.push(BrowserSemanticObservedStepV1 {
                action_id: receipt.action_id.clone(),
                action_kind: receipt.action_kind.clone(),
                action_digest: receipt.action_digest.clone(),
                generation: expected.generation,
                semantic: expected.semantic,
                committed_sequence: action.last_event_sequence,
                receipt_digest: receipt_digest.clone(),
                matched_synopsis_predicates: matched,
                verified_absent_synopsis_predicates: verified_absent,
            });
        }
        let mut proof = BrowserSemanticProofV1 {
            schema_version: BROWSER_SEMANTIC_PROOF_SCHEMA_VERSION,
            contract_digest: contract.contract_digest.clone(),
            plan_id: contract.plan_id.clone(),
            plan_revision: contract.plan_revision,
            task_id: contract.task_id.clone(),
            task_contract_digest: contract.task_contract_digest.clone(),
            attempt_id: contract.attempt_id.clone(),
            execution_epoch: contract.execution_epoch,
            browser_lease_id: contract.browser_lease_id.clone(),
            browser_binding_digest: contract.browser_binding_digest.clone(),
            observed_steps,
            managed_generations,
            evidence_ids: evidence_ids.to_vec(),
            proof_digest: String::new(),
        };
        proof.proof_digest = browser_semantic_proof_digest(&proof)?;
        let value_json = serde_json::to_string(&proof)?;
        if let Some(existing) = self
            .state
            .get_state(BROWSER_SEMANTIC_PROOF_NAMESPACE, &session.attempt_id)?
        {
            let durable: BrowserSemanticProofV1 = serde_json::from_str(&existing)?;
            if durable != proof {
                return Err(ControllerError::NotReady(
                    "durable browser semantic proof drifted from exact committed receipt sequence"
                        .to_owned(),
                ));
            }
            return Ok(());
        }
        self.state.put_state(
            BROWSER_SEMANTIC_PROOF_NAMESPACE,
            &session.attempt_id,
            &value_json,
        )?;
        self.append_controller_event(
            "browser_semantic_proof_recorded",
            &session.attempt_id,
            &serde_json::to_value(&proof)?,
        )?;
        self.checkpoint_now()?;
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn validate_durable_plan_semantic_proof(
        &self,
        artifacts: &ArtifactStore,
        attempt_id: &str,
        plan_id: &str,
        plan_revision: u32,
        task_id: &str,
        task_contract_digest: &str,
    ) -> Result<BrowserSemanticProofV1, ControllerError> {
        let plan_contract = {
            let active = self.active_ref()?;
            let task = active.tasks.get(task_id).ok_or_else(|| {
                ControllerError::NotReady("browser verification resume task disappeared".to_owned())
            })?;
            browser_acceptance_contract(&task.task)?.ok_or_else(|| {
                ControllerError::InvalidPlan(
                    "browser verification resume task lost typed Plan IR acceptance".to_owned(),
                )
            })?
        };
        let plan_contract_digest = digest_json(&serde_json::to_value(&plan_contract)?)?;
        let raw_contract = self
            .state
            .get_state(BROWSER_SEMANTIC_CONTRACT_NAMESPACE, attempt_id)?
            .ok_or_else(|| {
                ControllerError::NotReady(
                    "browser verification resume has no durable semantic contract".to_owned(),
                )
            })?;
        let contract: BrowserSemanticContractV1 = serde_json::from_str(&raw_contract)?;
        if contract.schema_version != BROWSER_SEMANTIC_CONTRACT_SCHEMA_VERSION
            || contract.plan_contract_digest != plan_contract_digest
            || contract.plan_id != plan_id
            || contract.plan_revision != plan_revision
            || contract.task_id != task_id
            || contract.task_contract_digest != task_contract_digest
            || contract.attempt_id != attempt_id
            || contract.contract_digest != browser_semantic_contract_digest(&contract)?
        {
            return Err(ControllerError::InvalidPlan(
                "browser verification resume semantic contract is malformed or stale".to_owned(),
            ));
        }
        let raw_proof = self
            .state
            .get_state(BROWSER_SEMANTIC_PROOF_NAMESPACE, attempt_id)?
            .ok_or_else(|| {
                ControllerError::NotReady(
                    "browser verification resume has no durable semantic proof".to_owned(),
                )
            })?;
        let proof: BrowserSemanticProofV1 = serde_json::from_str(&raw_proof)?;
        if proof.schema_version != BROWSER_SEMANTIC_PROOF_SCHEMA_VERSION
            || proof.contract_digest != contract.contract_digest
            || proof.plan_id != plan_id
            || proof.plan_revision != plan_revision
            || proof.task_id != task_id
            || proof.task_contract_digest != task_contract_digest
            || proof.attempt_id != attempt_id
            || proof.execution_epoch != contract.execution_epoch
            || proof.browser_lease_id != contract.browser_lease_id
            || proof.browser_binding_digest != contract.browser_binding_digest
            || proof.proof_digest != browser_semantic_proof_digest(&proof)?
            || proof.observed_steps.len() != contract.steps.len()
            || proof.evidence_ids.len() != contract.steps.len()
        {
            return Err(ControllerError::InvalidPlan(
                "browser verification resume semantic proof is malformed or stale".to_owned(),
            ));
        }
        let current_generations = self.managed_generations_for_semantic_contract(&contract)?;
        if current_generations != proof.managed_generations {
            return Err(ControllerError::NotReady(
                "browser verification managed restart proof drifted after semantic binding"
                    .to_owned(),
            ));
        }

        for (((expected, observed), evidence_id), index) in contract
            .steps
            .iter()
            .zip(proof.observed_steps.iter())
            .zip(proof.evidence_ids.iter())
            .zip(0_usize..)
        {
            if observed.action_id != expected.action_id
                || observed.action_kind != expected.action_kind
                || observed.action_digest != expected.action_digest
                || observed.generation != expected.generation
                || observed.semantic != expected.semantic
                || observed.receipt_digest != *evidence_id
                || observed.matched_synopsis_predicates != expected.required_synopsis_contains
                || observed.verified_absent_synopsis_predicates
                    != expected.forbidden_synopsis_contains
            {
                return Err(ControllerError::InvalidPlan(format!(
                    "browser verification resume semantic step {index} drifted from canonical contract"
                )));
            }
            let action = self
                .state
                .action_record(&expected.action_id)?
                .ok_or_else(|| {
                    ControllerError::InvalidPlan(format!(
                        "browser verification resume lost action {}",
                        expected.action_id
                    ))
                })?;
            let generation = current_generations
                .iter()
                .find(|generation| generation.generation == expected.generation)
                .ok_or_else(|| {
                    ControllerError::InvalidPlan(format!(
                        "browser verification resume lost managed generation {}",
                        expected.generation
                    ))
                })?;
            if action.state != ActionState::Committed.as_str()
                || action.execution_epoch != proof.execution_epoch
                || action.result_digest.as_deref() != Some(evidence_id.as_str())
                || action.last_event_sequence != observed.committed_sequence
            {
                return Err(ControllerError::NotReady(format!(
                    "browser verification resume action {} is no longer exact committed evidence",
                    expected.action_id
                )));
            }
            validate_browser_action_generation_sequence(
                observed.committed_sequence,
                generation,
                &expected.action_id,
            )?;
            let metadata = self.state.artifact_metadata(evidence_id)?.ok_or_else(|| {
                ControllerError::InvalidPlan(format!(
                    "browser verification resume lost receipt artifact {evidence_id}"
                ))
            })?;
            let length = usize::try_from(metadata.size_bytes).map_err(|_| {
                ControllerError::InvalidPlan(
                    "browser verification receipt artifact size cannot fit memory bound".to_owned(),
                )
            })?;
            let receipt_bytes = artifacts.range(&self.state, evidence_id, 0, length)?;
            let receipt_json: Value = serde_json::from_slice(&receipt_bytes)?;
            if required_str(&receipt_json, "/action_id")? != expected.action_id
                || required_str(&receipt_json, "/action_kind")? != expected.action_kind
                || required_str(&receipt_json, "/action_digest")? != expected.action_digest
                || required_str(&receipt_json, "/lease_id")? != proof.browser_lease_id
                || required_str(&receipt_json, "/lease_binding_digest")?
                    != proof.browser_binding_digest
                || receipt_json
                    .pointer("/execution_epoch")
                    .and_then(Value::as_i64)
                    != Some(proof.execution_epoch)
            {
                return Err(ControllerError::InvalidPlan(format!(
                    "browser verification durable receipt {} drifted from semantic proof",
                    expected.action_id
                )));
            }
            if !expected.required_synopsis_contains.is_empty()
                || !expected.forbidden_synopsis_contains.is_empty()
            {
                let text = required_str(&receipt_json, "/synopsis/text")?;
                if expected
                    .required_synopsis_contains
                    .iter()
                    .any(|predicate| !text.contains(predicate))
                {
                    return Err(ControllerError::NotReady(format!(
                        "browser verification durable synopsis {} no longer satisfies semantic predicates",
                        expected.action_id
                    )));
                }
                if expected
                    .forbidden_synopsis_contains
                    .iter()
                    .any(|predicate| text.contains(predicate))
                {
                    return Err(ControllerError::NotReady(format!(
                        "browser verification durable synopsis {} contains a forbidden semantic predicate",
                        expected.action_id
                    )));
                }
            }
        }
        Ok(proof)
    }

    fn verify_browser_receipts_for_session(
        &self,
        session: &ControllerBrowserSession,
        receipts: &[BrowserActionReceipt],
    ) -> Result<Vec<String>, ControllerError> {
        if receipts.is_empty() {
            return Err(ControllerError::NotReady(
                "browser verification requires at least one committed browser receipt".to_owned(),
            ));
        }
        let typed_plan_acceptance = {
            let active = self.active_ref()?;
            let task = active.tasks.get(&session.task_id).ok_or_else(|| {
                ControllerError::NotReady("browser verification task disappeared".to_owned())
            })?;
            browser_task_has_plan_acceptance(&task.task)?
        };
        let mut action_kinds = BTreeSet::new();
        let mut evidence_ids = Vec::with_capacity(receipts.len());
        for receipt in receipts {
            let bytes = receipt.to_bytes().map_err(browser_pre_dispatch_error)?;
            let receipt_digest = browser_receipt_digest(&bytes);
            let action = self
                .state
                .action_record(&receipt.action_id)?
                .ok_or_else(|| {
                    ControllerError::NotReady(format!(
                        "browser verification receipt {} lost its action record",
                        receipt.action_id
                    ))
                })?;
            if action.state != ActionState::Committed.as_str()
                || action.execution_epoch != session.execution_epoch
                || action.result_digest.as_deref() != Some(receipt_digest.as_str())
                || receipt.lease_id != session.browser_lease.lease_id
                || receipt.lease_binding_digest != session.browser_lease.binding_digest()
                || receipt.execution_epoch != session.execution_epoch
            {
                return Err(ControllerError::NotReady(format!(
                    "browser verification receipt {} is not bound to the exact live session/action",
                    receipt.action_id
                )));
            }
            action_kinds.insert(receipt.action_kind.as_str());
            evidence_ids.push(receipt_digest);
        }
        if !typed_plan_acceptance
            && !["navigate", "submit_form", "capture_synopsis"]
                .iter()
                .all(|kind| action_kinds.contains(kind))
        {
            return Err(ControllerError::NotReady(
                "browser verification requires committed navigate, submit_form, and capture_synopsis evidence"
                    .to_owned(),
            ));
        }
        Ok(evidence_ids)
    }

    /// Completes one browser-verification task through normal Controller
    /// verification/completion authority after exact browser receipts are bound
    /// to the live session.
    ///
    /// The browser is shut down before deterministic command verification so
    /// the selected 8GB profile never depends on concurrent `BROWSER+BUILD_HEAVY`
    /// residency.
    ///
    /// # Errors
    /// Fails closed for receipt/session drift, browser shutdown ambiguity,
    /// repository changes during the read-only browser attempt, command
    /// verification failure, or stale Plan/attempt authority.
    pub fn complete_browser_verification_task<I: sovereign_policy::ExecutionIsolationBackend>(
        &mut self,
        session: ControllerBrowserSession,
        runtime: &ExecutionRuntime<'_, I>,
        receipts: &[BrowserActionReceipt],
    ) -> Result<VerificationResultV1, ControllerError> {
        let plan_acceptance = {
            let active = self.active_ref()?;
            let task = active.tasks.get(&session.task_id).ok_or_else(|| {
                ControllerError::NotReady("browser verification task disappeared".to_owned())
            })?;
            browser_task_has_plan_acceptance(&task.task)?
        };
        if plan_acceptance {
            let task_id = session.task_id.clone();
            self.prepare_plan_browser_verification(session, receipts)?;
            return self.resume_plan_browser_verification(runtime, &task_id);
        }
        let _residency = self.live_browser_residency_for_session(&session)?;
        let browser_evidence_ids = self.verify_browser_receipts_for_session(&session, receipts)?;
        let task_id = session.task_id.clone();
        let attempt_id = session.attempt_id.clone();
        let execution_epoch = session.execution_epoch;
        self.transition_attempt(&attempt_id, AttemptState::Verifying, "attempt_verifying")?;
        self.transition_task(&task_id, TaskState::Verifying, "task_verifying")?;
        self.checkpoint_now()?;
        self.shutdown_browser_session(session)?;
        self.finish_browser_task_verification(
            runtime,
            task_id,
            attempt_id,
            execution_epoch,
            browser_evidence_ids,
        )
    }

    /// Records complete Plan-driven semantic proof, moves the exact browser task/attempt into
    /// `Verifying`, checkpoints, and physically shuts down Chrome. No deterministic verification is
    /// run here. A fresh Controller process can continue with
    /// [`Self::resume_plan_browser_verification`] using only durable state/CAS.
    ///
    /// # Errors
    /// Fails closed before task completion for semantic/receipt drift, incomplete managed restart
    /// proof, stale authority, or browser shutdown ambiguity.
    pub fn prepare_plan_browser_verification(
        &mut self,
        session: ControllerBrowserSession,
        receipts: &[BrowserActionReceipt],
    ) -> Result<(), ControllerError> {
        let _residency = self.live_browser_residency_for_session(&session)?;
        let browser_evidence_ids = self.verify_browser_receipts_for_session(&session, receipts)?;
        self.verify_and_persist_plan_semantic_proof(&session, receipts, &browser_evidence_ids)?;
        let task_id = session.task_id.clone();
        let attempt_id = session.attempt_id.clone();
        self.transition_attempt(&attempt_id, AttemptState::Verifying, "attempt_verifying")?;
        self.transition_task(&task_id, TaskState::Verifying, "task_verifying")?;
        self.checkpoint_now()?;
        self.shutdown_browser_session(session)?;
        self.append_controller_event(
            "browser_verification_browser_absent",
            &attempt_id,
            &serde_json::json!({
                "task_id": task_id,
                "attempt_id": attempt_id,
                "semantic_proof": true,
            }),
        )?;
        self.checkpoint_now()?;
        Ok(())
    }

    /// Backward-compatible focused-proof method name. This delegates to typed Plan IR semantics.
    pub fn prepare_local_inventory_browser_verification(
        &mut self,
        session: ControllerBrowserSession,
        receipts: &[BrowserActionReceipt],
    ) -> Result<(), ControllerError> {
        self.prepare_plan_browser_verification(session, receipts)
    }

    /// Resumes selected-profile browser completion from durable Controller state after Chrome has
    /// already been proven absent. No browser action is dispatched and no committed POST can be
    /// replayed by this path.
    ///
    /// # Errors
    /// Fails closed unless a unique exact Verifying attempt has a valid semantic contract/proof,
    /// every bound receipt still exists and verifies from CAS, all browser actions remain committed,
    /// both managed generations remain stopped, and durable browser residency is `Absent`.
    pub fn resume_plan_browser_verification<I: sovereign_policy::ExecutionIsolationBackend>(
        &mut self,
        runtime: &ExecutionRuntime<'_, I>,
        task_id: &str,
    ) -> Result<VerificationResultV1, ControllerError> {
        self.require_execution_not_paused()?;
        if self.any_unresolved_action()? || super::has_unresolved_process_lease(&self.state)? {
            return Err(ControllerError::NotReady(
                "browser verification resume is blocked by unresolved action/process authority"
                    .to_owned(),
            ));
        }
        let (attempt_id, task_contract_digest, plan_id, plan_revision, current_execution_epoch) = {
            let active = self.active_ref()?;
            let task = active.tasks.get(task_id).ok_or_else(|| {
                ControllerError::NotReady("browser resume task disappeared".to_owned())
            })?;
            if task.state != TaskState::Verifying || !browser_task_has_plan_acceptance(&task.task)?
            {
                return Err(ControllerError::NotReady(
                    "browser resume requires a typed Plan acceptance task in Verifying state"
                        .to_owned(),
                ));
            }
            let attempts = active
                .attempts
                .iter()
                .filter(|(_, attempt)| {
                    attempt.task_id == task_id && attempt.state == AttemptState::Verifying
                })
                .map(|(attempt_id, _)| attempt_id.clone())
                .collect::<Vec<_>>();
            if attempts.len() != 1 {
                return Err(ControllerError::NotReady(
                    "browser resume requires exactly one Verifying attempt".to_owned(),
                ));
            }
            (
                attempts[0].clone(),
                task.task_contract_digest.clone(),
                active.plan_id.clone(),
                active.revision,
                self.state.current_execution_epoch()?,
            )
        };
        let proof = self.validate_durable_plan_semantic_proof(
            runtime.artifacts,
            &attempt_id,
            &plan_id,
            plan_revision,
            task_id,
            &task_contract_digest,
        )?;
        let residency_key = active_scoped_key(self.active_ref()?, BROWSER_RESIDENCY_KEY);
        let raw_residency = self
            .state
            .get_state(RESOURCE_RESIDENCY_NAMESPACE, &residency_key)?
            .ok_or_else(|| {
                ControllerError::NotReady(
                    "browser verification resume lost durable browser residency".to_owned(),
                )
            })?;
        let residency: BrowserResourceResidencyV1 = serde_json::from_str(&raw_residency)?;
        if residency.schema_version != BROWSER_RESOURCE_RESIDENCY_SCHEMA_VERSION
            || residency.state != BrowserResourceResidencyStateV1::Absent
            || residency.plan_id != plan_id
            || residency.plan_revision != plan_revision
            || residency.task_id != task_id
            || residency.task_contract_digest != task_contract_digest
            || residency.execution_epoch != proof.execution_epoch
            || residency.browser_lease_id != proof.browser_lease_id
            || residency.browser_lease_binding_digest != proof.browser_binding_digest
        {
            return Err(ControllerError::NotReady(
                "browser verification resume requires exact proven-absent browser residency"
                    .to_owned(),
            ));
        }
        self.finish_browser_task_verification(
            runtime,
            task_id.to_owned(),
            attempt_id,
            current_execution_epoch,
            proof.evidence_ids,
        )
    }

    /// Backward-compatible focused-proof method name. This delegates to typed Plan IR semantics.
    pub fn resume_local_inventory_browser_verification<
        I: sovereign_policy::ExecutionIsolationBackend,
    >(
        &mut self,
        runtime: &ExecutionRuntime<'_, I>,
        task_id: &str,
    ) -> Result<VerificationResultV1, ControllerError> {
        self.resume_plan_browser_verification(runtime, task_id)
    }

    fn finish_browser_task_verification<I: sovereign_policy::ExecutionIsolationBackend>(
        &mut self,
        runtime: &ExecutionRuntime<'_, I>,
        task_id: String,
        attempt_id: String,
        execution_epoch: i64,
        browser_evidence_ids: Vec<String>,
    ) -> Result<VerificationResultV1, ControllerError> {
        let active = self.active_ref()?;
        let task = active.tasks.get(&task_id).ok_or_else(|| {
            ControllerError::NotReady("browser verification task disappeared".to_owned())
        })?;
        let attempt = active.attempts.get(&attempt_id).ok_or_else(|| {
            ControllerError::NotReady("browser verification attempt disappeared".to_owned())
        })?;
        if task.state != TaskState::Verifying
            || attempt.state != AttemptState::Verifying
            || attempt.task_id != task_id
        {
            return Err(ControllerError::NotReady(
                "browser verification requires exact durable Verifying task/attempt authority"
                    .to_owned(),
            ));
        }
        let command_results =
            self.run_required_command_verification(runtime, &task_id, &attempt_id)?;
        let has_typed_browser_acceptance = {
            let active = self.active_ref()?;
            let task = active.tasks.get(&task_id).ok_or_else(|| {
                ControllerError::NotReady("browser verification task disappeared".to_owned())
            })?;
            browser_task_has_plan_acceptance(&task.task)?
        };
        if command_results.is_empty() && !has_typed_browser_acceptance {
            return Err(ControllerError::InvalidPlan(
                "browser verification task has no required deterministic command verification"
                    .to_owned(),
            ));
        }

        let post_snapshot = self.task_execution_snapshot(runtime.registry, &task_id)?;
        let post_snapshot_digest = snapshot_digest(&post_snapshot)?;
        let current_diff = self.task_execution_diff(runtime.registry, &task_id)?;
        let (task_contract_digest, pre_snapshot_digest, evaluator, acceptance_contract_digest) =
            self.browser_task_verification_binding(&task_id, &attempt_id)?;
        let repository_unchanged = post_snapshot_digest == pre_snapshot_digest;
        let mut verification = VerificationResultV1 {
            schema_version: super::VERIFICATION_RESULT_SCHEMA_VERSION,
            verification_id: verification_id(
                self.active_ref()?.plan_digest.as_str(),
                &task_contract_digest,
                &attempt_id,
                &current_diff.digest,
            ),
            plan_id: self.active_ref()?.plan_id.clone(),
            plan_revision: self.active_ref()?.revision,
            plan_digest: self.active_ref()?.plan_digest.clone(),
            task_id: task_id.clone(),
            task_contract_digest,
            attempt_id: attempt_id.clone(),
            execution_epoch,
            evaluator,
            acceptance_contract_digest,
            diff_digest: current_diff.digest,
            post_snapshot_digest,
            expected_target_mode: 0,
            observed_target_mode: 0,
            evidence_ids: browser_evidence_ids,
            command_results: Vec::new(),
            passed: repository_unchanged,
            failure_code: (!repository_unchanged)
                .then(|| "browser_verification_repository_changed".to_owned()),
        };
        verification = aggregate_command_verification(verification, command_results);
        let (verification_artifact_digest, verification_evidence_id) = self
            .persist_verification_result(
                runtime.artifacts,
                &verification,
                "verification_recorded",
            )?;
        if !verification.passed {
            let failure_code = verification
                .failure_code
                .clone()
                .unwrap_or_else(|| "browser_verification_failed".to_owned());
            let failed = verification
                .command_results
                .iter()
                .find(|result| !result.passed);
            let failure = self.build_failure_record(FailureRecordInput {
                task_id,
                attempt_id,
                action_id: failed.map(|result| result.action_id.clone()),
                result_digest: Some(verification_artifact_digest),
                exit_code: failed.and_then(|result| result.exit_code),
                category: "verification_failure".to_owned(),
                failure_code,
                diagnostic: "browser task deterministic completion verification failed".to_owned(),
                failed_action_facts: failed.map_or_else(BTreeMap::new, |result| {
                    BTreeMap::from([
                        ("step_id".to_owned(), result.step_id.clone()),
                        ("action_id".to_owned(), result.action_id.clone()),
                    ])
                }),
                evidence_refs: vec![verification_evidence_id],
            })?;
            let _ = self.route_failure_record(failure)?;
            return Err(ControllerError::VerificationFailed(Box::new(verification)));
        }
        self.record_verified_output_bindings(&verification, &verification_artifact_digest)?;
        self.apply_verified_success(&verification)?;
        Ok(verification)
    }

    fn browser_task_verification_binding(
        &self,
        task_id: &str,
        attempt_id: &str,
    ) -> Result<(String, String, String, String), ControllerError> {
        let active = self.active_ref()?;
        let task = active.tasks.get(task_id).ok_or_else(|| {
            ControllerError::InvalidPlan(
                "browser verification task disappeared before completion".to_owned(),
            )
        })?;
        let attempt = active.attempts.get(attempt_id).ok_or_else(|| {
            ControllerError::InvalidPlan(
                "browser verification attempt disappeared before completion".to_owned(),
            )
        })?;
        let (evaluator, acceptance_contract_digest) = compiled_acceptance_contract(&task.task)?;
        Ok((
            task.task_contract_digest.clone(),
            attempt.pre_snapshot_digest.clone(),
            evaluator,
            acceptance_contract_digest,
        ))
    }
}

fn validate_managed_generation_binding(
    binding: &ManagedLoopbackAppBindingV1,
    expected_generation: u32,
    database_path: &mut Option<String>,
    process_identities: &mut BTreeSet<(u32, String)>,
) -> Result<(), ControllerError> {
    if binding.schema_version != MANAGED_LOOPBACK_APP_SCHEMA_VERSION
        || binding.generation != expected_generation
        || binding.state != "stopped"
    {
        return Err(ControllerError::NotReady(
            "managed inventory generations are incomplete or out of canonical order".to_owned(),
        ));
    }
    if let Some(expected_database_path) = database_path {
        if expected_database_path != &binding.database_path {
            return Err(ControllerError::NotReady(
                "managed inventory restart changed the Controller-owned database path".to_owned(),
            ));
        }
    } else {
        *database_path = Some(binding.database_path.clone());
    }
    if !process_identities.insert((binding.process_group_id, binding.leader_identity.clone())) {
        return Err(ControllerError::NotReady(
            "managed inventory restart reused a prior process identity".to_owned(),
        ));
    }
    Ok(())
}

fn managed_generation_event_bounds(
    journal: &[sovereign_state::JournalEvent],
    binding: &ManagedLoopbackAppBindingV1,
    previous_stopped_sequence: i64,
) -> Result<(i64, i64), ControllerError> {
    let ready_events = journal
        .iter()
        .filter(|event| {
            event.entity_id == binding.app_id && event.event_kind == "managed_loopback_ready"
        })
        .collect::<Vec<_>>();
    let stopped_events = journal
        .iter()
        .filter(|event| {
            event.entity_id == binding.app_id && event.event_kind == "managed_loopback_stopped"
        })
        .collect::<Vec<_>>();
    if ready_events.len() != 1 || stopped_events.len() != 1 {
        return Err(ControllerError::InvalidPlan(
            "managed inventory generation lacks unique ready/stopped journal boundaries".to_owned(),
        ));
    }
    let ready_sequence = ready_events[0].sequence;
    let stopped_sequence = stopped_events[0].sequence;
    if ready_sequence >= stopped_sequence
        || (previous_stopped_sequence != 0 && previous_stopped_sequence >= ready_sequence)
    {
        return Err(ControllerError::NotReady(
            "managed inventory restart generation boundaries overlap or reorder".to_owned(),
        ));
    }
    Ok((ready_sequence, stopped_sequence))
}

fn validate_browser_action_generation_sequence(
    committed_sequence: i64,
    generation: &BrowserSemanticManagedGenerationV1,
    action_id: &str,
) -> Result<(), ControllerError> {
    if committed_sequence <= generation.ready_sequence
        || committed_sequence >= generation.stopped_sequence
    {
        return Err(ControllerError::NotReady(format!(
            "browser semantic action {action_id} committed outside managed generation {}",
            generation.generation
        )));
    }
    Ok(())
}

fn browser_acceptance_contract(
    task: &Value,
) -> Result<Option<BrowserAcceptanceContractV1>, ControllerError> {
    let Some(raw) = task.get("browser_acceptance") else {
        return Ok(None);
    };
    let contract: BrowserAcceptanceContractV1 = serde_json::from_value(raw.clone())?;
    if contract.schema_version != BROWSER_ACCEPTANCE_CONTRACT_SCHEMA_VERSION {
        return Err(ControllerError::InvalidPlan(
            "browser acceptance contract schema version is unsupported".to_owned(),
        ));
    }
    contract
        .validate()
        .map_err(|error| ControllerError::InvalidPlan(error.to_string()))?;
    Ok(Some(contract))
}

fn browser_task_has_plan_acceptance(task: &Value) -> Result<bool, ControllerError> {
    Ok(browser_acceptance_contract(task)?.is_some())
}

fn semantic_step(
    action: &BrowserAction,
    generation: u32,
    semantic: BrowserAcceptanceSemanticV1,
    required: &[String],
    forbidden: &[String],
) -> BrowserSemanticStepV1 {
    BrowserSemanticStepV1 {
        action_id: action.action_id().to_owned(),
        action_kind: action.kind_name().to_owned(),
        action_digest: action.digest(),
        generation,
        semantic,
        required_synopsis_contains: required.to_vec(),
        forbidden_synopsis_contains: forbidden.to_vec(),
    }
}

fn semantic_submit(
    action_id: &str,
    selector: &str,
    fields: &[sovereign_plan::BrowserAcceptanceFieldValueV1],
) -> Result<BrowserAction, ControllerError> {
    if !fields.is_empty() {
        let field_values = fields
            .iter()
            .map(|field| (field.selector.clone(), field.value.clone()))
            .collect::<BTreeMap<_, _>>();
        if field_values.len() != fields.len() {
            return Err(ControllerError::InvalidPlan(
                "browser form values contain duplicate field selectors".to_owned(),
            ));
        }
        let field_values = BrowserFormFieldValues::new(field_values).map_err(|_| {
            ControllerError::InvalidPlan(
                "browser form values failed bounded nonsensitive field validation".to_owned(),
            )
        })?;
        return Ok(BrowserAction::SubmitFormWithValues {
            action_id: action_id.to_owned(),
            selector: selector.to_owned(),
            fields: field_values,
        });
    }
    let payload_digest = format!(
        "sha256:{:x}",
        Sha256::digest(format!("{action_id}\0{selector}").as_bytes())
    );
    Ok(BrowserAction::SubmitForm {
        action_id: action_id.to_owned(),
        selector: selector.to_owned(),
        payload_digest,
    })
}

fn plan_browser_actions_from_contract(
    contract: &BrowserAcceptanceContractV1,
) -> Result<Vec<ControllerBrowserPlannedAction>, ControllerError> {
    let origin = format!(
        "{}://{}:{}",
        contract.loopback.scheme, contract.loopback.host, contract.loopback.port
    );
    contract
        .steps
        .iter()
        .map(|step| {
            let action = match &step.action {
                BrowserAcceptanceActionV1::Navigate { path } => BrowserAction::Navigate {
                    action_id: step.step_id.clone(),
                    url: format!("{origin}{path}"),
                },
                BrowserAcceptanceActionV1::SubmitForm { selector, fields } => {
                    semantic_submit(&step.step_id, selector, fields)?
                }
                BrowserAcceptanceActionV1::CaptureSynopsis => BrowserAction::CaptureSynopsis {
                    action_id: step.step_id.clone(),
                },
            };
            Ok(ControllerBrowserPlannedAction {
                generation: step.generation,
                semantic: step.expectation.semantic,
                action,
            })
        })
        .collect()
}

fn plan_browser_semantic_steps(
    contract: &BrowserAcceptanceContractV1,
) -> Result<Vec<BrowserSemanticStepV1>, ControllerError> {
    Ok(plan_browser_actions_from_contract(contract)?
        .into_iter()
        .zip(contract.steps.iter())
        .map(|(planned, step)| {
            semantic_step(
                &planned.action,
                planned.generation,
                planned.semantic,
                &step.expectation.required_contains,
                &step.expectation.forbidden_contains,
            )
        })
        .collect::<Vec<_>>())
}

fn browser_semantic_contract_digest(
    contract: &BrowserSemanticContractV1,
) -> Result<String, ControllerError> {
    Ok(digest_json(&serde_json::json!({
        "schema_version": contract.schema_version,
        "plan_contract_digest": contract.plan_contract_digest,
        "plan_id": contract.plan_id,
        "plan_revision": contract.plan_revision,
        "task_id": contract.task_id,
        "task_contract_digest": contract.task_contract_digest,
        "attempt_id": contract.attempt_id,
        "execution_epoch": contract.execution_epoch,
        "browser_lease_id": contract.browser_lease_id,
        "browser_binding_digest": contract.browser_binding_digest,
        "loopback_port": contract.loopback_port,
        "steps": contract.steps,
        "required_managed_generations": contract.required_managed_generations,
    }))?)
}

fn browser_semantic_proof_digest(
    proof: &BrowserSemanticProofV1,
) -> Result<String, ControllerError> {
    Ok(digest_json(&serde_json::json!({
        "schema_version": proof.schema_version,
        "contract_digest": proof.contract_digest,
        "plan_id": proof.plan_id,
        "plan_revision": proof.plan_revision,
        "task_id": proof.task_id,
        "task_contract_digest": proof.task_contract_digest,
        "attempt_id": proof.attempt_id,
        "execution_epoch": proof.execution_epoch,
        "browser_lease_id": proof.browser_lease_id,
        "browser_binding_digest": proof.browser_binding_digest,
        "observed_steps": proof.observed_steps,
        "managed_generations": proof.managed_generations,
        "evidence_ids": proof.evidence_ids,
    }))?)
}

fn validate_managed_relative_file(path: &Path, label: &str) -> Result<(), ControllerError> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ControllerError::Policy(PolicyError::Denied(format!(
            "managed loopback {label} path must be a strict repository-relative path"
        ))));
    }
    Ok(())
}

fn managed_loopback_policy_error(error: &BrowserPolicyError) -> ControllerError {
    ControllerError::Policy(PolicyError::Denied(error.to_string()))
}

fn validate_managed_database_filename(filename: &str) -> Result<(), ControllerError> {
    let path = Path::new(filename);
    let mut components = path.components();
    if filename.trim().is_empty()
        || path.is_absolute()
        || !matches!(components.next(), Some(Component::Normal(_)))
        || components.next().is_some()
    {
        return Err(ControllerError::Policy(PolicyError::Denied(
            "managed loopback database must be one plain filename beneath Controller data root"
                .to_owned(),
        )));
    }
    Ok(())
}

fn wait_for_managed_loopback_health(
    process: &mut ManagedProcess,
    port: u16,
    readiness: Option<&BrowserManagedReadinessV1>,
) -> Result<(), ControllerError> {
    let timeout = readiness.map_or(MANAGED_LOOPBACK_READY_TIMEOUT, |rule| {
        Duration::from_millis(u64::from(rule.timeout_ms))
    });
    let deadline = Instant::now() + timeout;
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let path = readiness.map_or("/health", |rule| rule.path.as_str());
    let request = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    while Instant::now() < deadline {
        process.verify_live()?;
        if let Ok(mut stream) = TcpStream::connect_timeout(&address, Duration::from_millis(100)) {
            stream.set_read_timeout(Some(Duration::from_millis(200)))?;
            stream.set_write_timeout(Some(Duration::from_millis(200)))?;
            stream.write_all(request.as_bytes())?;
            let mut response = Vec::with_capacity(1024);
            let mut chunk = [0_u8; 256];
            while response.len() < 1024 && Instant::now() < deadline {
                match stream.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(read) => response.extend_from_slice(&chunk[..read]),
                    Err(error)
                        if error.kind() == std::io::ErrorKind::TimedOut
                            || error.kind() == std::io::ErrorKind::WouldBlock =>
                    {
                        break;
                    }
                    Err(error) => return Err(ControllerError::Io(error)),
                }
            }
            let response = String::from_utf8_lossy(&response);
            if (response.starts_with("HTTP/1.0 200 ") || response.starts_with("HTTP/1.1 200 "))
                && response
                    .split_once("\r\n\r\n")
                    .is_some_and(|(_, received)| {
                        readiness.map_or_else(
                            || received.starts_with("ok"),
                            |rule| received.contains(&rule.body),
                        )
                    })
            {
                return Ok(());
            }
        }
        thread::sleep(Duration::from_millis(20));
    }
    Err(ControllerError::NotReady(
        "managed loopback application did not prove exact /health readiness".to_owned(),
    ))
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
        BrowserAction::Navigate { .. }
            if session.download_policy.mode == BrowserDownloadMode::Deny
                && !session.authority.downloads_allowed =>
        {
            browser_action_retained_receipt_bound(session, action)?
        }
        BrowserAction::SubmitForm { .. } | BrowserAction::SubmitFormWithValues { .. } => {
            browser_action_retained_receipt_bound(session, action)?
        }
        BrowserAction::Navigate { .. } => {
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

fn browser_action_retained_receipt_bound(
    session: &ControllerBrowserSession,
    action: &BrowserAction,
) -> Result<u64, ControllerError> {
    let requested_url = match action {
        BrowserAction::Navigate { url, .. } => Some(url.clone()),
        BrowserAction::SubmitForm { .. } | BrowserAction::SubmitFormWithValues { .. } => None,
        BrowserAction::CaptureSynopsis { .. } | BrowserAction::CaptureScreenshot { .. } => {
            return Err(ControllerError::InvalidPlan(
                "retained browser receipt bound is valid only for navigation-capable actions"
                    .to_owned(),
            ));
        }
    };
    let maximal_receipt = BrowserActionReceipt {
        schema_version: BROWSER_SCHEMA_VERSION,
        action_id: action.action_id().to_owned(),
        action_digest: action.digest(),
        action_kind: action.kind_name().to_owned(),
        effect: action.effect(),
        lease_id: session.browser_lease.lease_id.clone(),
        lease_binding_digest: session.browser_lease.binding_digest(),
        execution_epoch: session.execution_epoch,
        cdp_request_id: u64::MAX,
        requested_url,
        navigation_was_download: false,
        download: None,
        synopsis: None,
        screenshot: None,
        screenshots_and_traces_suppressed: session.adapter_config.suppress_screenshots_and_traces,
    };
    let bytes = maximal_receipt.to_bytes().map_err(|error| {
        ControllerError::NotReady(format!(
            "browser action retained receipt bound serialization failed: {error}"
        ))
    })?;
    u64::try_from(bytes.len()).map_err(|_| {
        ControllerError::NotReady(
            "browser action retained receipt bound length overflowed durable evidence bounds"
                .to_owned(),
        )
    })
}

fn browser_action_binding_digest(
    action: &BrowserAction,
    approved_form: Option<&BrowserFormInspectionReceipt>,
) -> Result<Option<String>, ControllerError> {
    match action {
        BrowserAction::Navigate { url, .. } => Ok(Some(browser_destination_digest(url))),
        BrowserAction::CaptureSynopsis { .. } | BrowserAction::CaptureScreenshot { .. } => Ok(None),
        BrowserAction::SubmitForm { .. } | BrowserAction::SubmitFormWithValues { .. } => Ok(Some(
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
    pub permission_class: Capability,
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
        digest_field(&mut hasher, self.permission_class.as_plan_ir_str());
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
            || !self.required_capabilities.contains(&self.permission_class)
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
            || claim.permission_class != self.permission_class.as_plan_ir_str()
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

    fn connect_authorized(
        &self,
        destination: &NetworkDestination,
    ) -> Result<TcpStream, BrowserGatewayConnectError> {
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
                .ok_or(BrowserGatewayConnectError::Denied)?;
            let now_ms = current_unix_millis().map_err(BrowserGatewayConnectError::Failure)?;
            grant
                .authorize(&scope, destination, now_ms)
                .map_err(|_| BrowserGatewayConnectError::Denied)?;
            let stream = TcpStream::connect_timeout(
                &SocketAddr::new(address, destination.port),
                GATEWAY_IO_TIMEOUT,
            )
            .map_err(ToolError::Io)
            .map_err(BrowserGatewayConnectError::Failure)?;
            let peer = stream
                .peer_addr()
                .map_err(ToolError::Io)
                .map_err(BrowserGatewayConnectError::Failure)?;
            if peer.ip() != address || peer.port() != destination.port {
                return Err(BrowserGatewayConnectError::Failure(ToolError::Authority(
                    "browser task-loopback connected peer differs from exact grant".to_owned(),
                )));
            }
            return Ok(stream);
        }

        let canonical = self
            .public_network
            .authorize_destination(destination)
            .map_err(|_| BrowserGatewayConnectError::Denied)?;
        let resolved = SystemWebDnsResolver.resolve(&canonical).map_err(|error| {
            BrowserGatewayConnectError::Failure(ToolError::Authority(error.to_string()))
        })?;
        let authorization = self
            .public_network
            .authorize_resolved(&canonical, resolved.iter().copied())
            .map_err(|error| {
                BrowserGatewayConnectError::Failure(ToolError::Authority(error.to_string()))
            })?;
        let address = authorization.resolved_ips().next().ok_or_else(|| {
            BrowserGatewayConnectError::Failure(ToolError::Authority(
                "browser authorized DNS set became empty".to_owned(),
            ))
        })?;
        let stream = TcpStream::connect_timeout(
            &SocketAddr::new(address, canonical.port),
            GATEWAY_IO_TIMEOUT,
        )
        .map_err(ToolError::Io)
        .map_err(BrowserGatewayConnectError::Failure)?;
        let peer = stream
            .peer_addr()
            .map_err(ToolError::Io)
            .map_err(BrowserGatewayConnectError::Failure)?;
        self.public_network
            .authorize_connected_peer(&authorization, peer.ip())
            .map_err(|error| {
                BrowserGatewayConnectError::Failure(ToolError::Authority(error.to_string()))
            })?;
        if peer.port() != canonical.port {
            return Err(BrowserGatewayConnectError::Failure(ToolError::Authority(
                "browser connected peer port differs from authorized destination".to_owned(),
            )));
        }
        Ok(stream)
    }
}

enum BrowserGatewayConnectError {
    Denied,
    Failure(ToolError),
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
                        // `shutdown()` wakes the nonblocking accept loop with one local connection.
                        // That connection is not browser traffic and must never become a handler
                        // failure that poisons otherwise clean network settlement.
                        if stop_thread.load(Ordering::Acquire) {
                            let _ = client.shutdown(Shutdown::Both);
                            break;
                        }
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
    // The listener is deliberately nonblocking. Make accepted request streams explicitly blocking
    // before bounded read/write timeouts are installed so EAGAIN is not misclassified as a gateway
    // policy/I/O failure on platforms where the accepted descriptor inherits nonblocking state.
    client.set_nonblocking(false)?;
    client.set_read_timeout(Some(GATEWAY_IO_TIMEOUT))?;
    client.set_write_timeout(Some(GATEWAY_IO_TIMEOUT))?;
    let Some(request) = read_proxy_request(&mut client)? else {
        return Ok(());
    };
    if !proxy_request_authenticated(&request, loopback_capability)? {
        write_proxy_auth_challenge(&mut client)?;
        return Ok(());
    }
    if request.method.eq_ignore_ascii_case("CONNECT") {
        return handle_connect_proxy_request(
            &mut client,
            &request,
            authority,
            stop,
            transferred_bytes,
        );
    }
    handle_http_proxy_request(client, request, authority, transferred_bytes)
}

fn handle_connect_proxy_request(
    client: &mut TcpStream,
    request: &ProxyRequest,
    authority: &BrowserGatewayAuthority,
    stop: &AtomicBool,
    transferred_bytes: &AtomicU64,
) -> Result<(), ToolError> {
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
    let mut upstream = match authority.connect_authorized(&destination) {
        Ok(upstream) => upstream,
        Err(BrowserGatewayConnectError::Denied) => {
            write_proxy_policy_denial(client)?;
            return Ok(());
        }
        Err(BrowserGatewayConnectError::Failure(error)) => return Err(error),
    };
    upstream.set_read_timeout(Some(GATEWAY_IO_TIMEOUT))?;
    upstream.set_write_timeout(Some(GATEWAY_IO_TIMEOUT))?;
    client.write_all(b"HTTP/1.1 200 Connection Established\r\nConnection: close\r\n\r\n")?;
    tunnel_bidirectional(
        client,
        &mut upstream,
        stop,
        transferred_bytes,
        authority.max_network_bytes,
    )?;
    Ok(())
}

fn handle_http_proxy_request(
    mut client: TcpStream,
    request: ProxyRequest,
    authority: &BrowserGatewayAuthority,
    transferred_bytes: &AtomicU64,
) -> Result<(), ToolError> {
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
    let mut upstream = match authority.connect_authorized(&parsed.destination) {
        Ok(upstream) => upstream,
        Err(BrowserGatewayConnectError::Denied) => {
            write_proxy_policy_denial(&mut client)?;
            return Ok(());
        }
        Err(BrowserGatewayConnectError::Failure(error)) => return Err(error),
    };
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

fn write_proxy_policy_denial(client: &mut TcpStream) -> Result<(), ToolError> {
    write!(
        client,
        "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
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

fn read_proxy_request(stream: &mut TcpStream) -> Result<Option<ProxyRequest>, ToolError> {
    let mut buffer = Vec::with_capacity(4096);
    let mut scratch = [0_u8; 4096];
    let header_end = loop {
        let read = stream.read(&mut scratch)?;
        if read == 0 {
            if buffer.is_empty() {
                return Ok(None);
            }
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
    Ok(Some(ProxyRequest {
        method: method.to_owned(),
        target: target.to_owned(),
        version: version.to_owned(),
        headers,
        body_prefix,
        remaining_body_bytes: content_length.saturating_sub(already),
    }))
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
mod plan_browser_acceptance_tests {
    use super::{
        BrowserAcceptanceSemanticV1, BrowserSemanticManagedGenerationV1, ControllerError,
        plan_browser_actions_from_contract, plan_browser_semantic_steps,
        validate_browser_action_generation_sequence,
    };
    use sovereign_plan::{
        BrowserAcceptanceActionV1, BrowserAcceptanceExpectationV1, BrowserAcceptanceFieldValueV1,
        BrowserAcceptanceStepV1, BrowserAcceptanceTemplateV1, BrowserManagedAppLaunchV1,
    };
    use sovereign_tools::browser::BrowserAction;
    use sovereign_tools::browser::BrowserFormFieldValues;
    use std::collections::BTreeMap;

    fn contract() -> sovereign_plan::BrowserAcceptanceContractV1 {
        BrowserAcceptanceTemplateV1 {
            launch: BrowserManagedAppLaunchV1::PythonManagedServerV1 {
                server_relative_path: "apps/demo/server.py".to_owned(),
                database_filename: "demo.sqlite3".to_owned(),
                required_generations: 2,
            },
            steps: vec![
                BrowserAcceptanceStepV1 {
                    step_id: "browser.read".to_owned(),
                    generation: 1,
                    action: BrowserAcceptanceActionV1::Navigate {
                        path: "/people?active=1".to_owned(),
                    },
                    expectation: BrowserAcceptanceExpectationV1 {
                        semantic: BrowserAcceptanceSemanticV1::Read,
                        required_contains: Vec::new(),
                        forbidden_contains: Vec::new(),
                    },
                },
                BrowserAcceptanceStepV1 {
                    step_id: "browser.create".to_owned(),
                    generation: 1,
                    action: BrowserAcceptanceActionV1::SubmitForm {
                        selector: "form#create-person".to_owned(),
                        fields: Vec::new(),
                    },
                    expectation: BrowserAcceptanceExpectationV1 {
                        semantic: BrowserAcceptanceSemanticV1::Create,
                        required_contains: Vec::new(),
                        forbidden_contains: Vec::new(),
                    },
                },
                BrowserAcceptanceStepV1 {
                    step_id: "browser.update".to_owned(),
                    generation: 1,
                    action: BrowserAcceptanceActionV1::SubmitForm {
                        selector: "form#edit-person".to_owned(),
                        fields: Vec::new(),
                    },
                    expectation: BrowserAcceptanceExpectationV1 {
                        semantic: BrowserAcceptanceSemanticV1::Update,
                        required_contains: Vec::new(),
                        forbidden_contains: Vec::new(),
                    },
                },
                BrowserAcceptanceStepV1 {
                    step_id: "browser.delete".to_owned(),
                    generation: 1,
                    action: BrowserAcceptanceActionV1::SubmitForm {
                        selector: "form#delete-person".to_owned(),
                        fields: Vec::new(),
                    },
                    expectation: BrowserAcceptanceExpectationV1 {
                        semantic: BrowserAcceptanceSemanticV1::Delete,
                        required_contains: Vec::new(),
                        forbidden_contains: Vec::new(),
                    },
                },
                BrowserAcceptanceStepV1 {
                    step_id: "browser.invalid".to_owned(),
                    generation: 1,
                    action: BrowserAcceptanceActionV1::CaptureSynopsis,
                    expectation: BrowserAcceptanceExpectationV1 {
                        semantic: BrowserAcceptanceSemanticV1::InvalidValidation,
                        required_contains: vec!["Name is required".to_owned()],
                        forbidden_contains: vec!["Created person".to_owned()],
                    },
                },
                BrowserAcceptanceStepV1 {
                    step_id: "browser.restart".to_owned(),
                    generation: 2,
                    action: BrowserAcceptanceActionV1::CaptureSynopsis,
                    expectation: BrowserAcceptanceExpectationV1 {
                        semantic: BrowserAcceptanceSemanticV1::RestartPersistence,
                        required_contains: vec!["Alice".to_owned()],
                        forbidden_contains: Vec::new(),
                    },
                },
            ],
        }
        .bind_loopback(41_731, vec!["AC.people-browser".to_owned()])
        .unwrap_or_else(|error| panic!("bind test browser contract: {error}"))
    }

    #[test]
    fn plan_browser_actions_are_generic_typed_and_exact_loopback_bound() {
        let contract = contract();
        let actions = plan_browser_actions_from_contract(&contract)
            .unwrap_or_else(|error| panic!("map Plan browser actions: {error}"));
        assert_eq!(actions.len(), 6);
        assert!(matches!(
            &actions[0].action,
            BrowserAction::Navigate { action_id, url }
                if action_id == "browser.read"
                    && url == "http://127.0.0.1:41731/people?active=1"
        ));
        assert_eq!(actions[1].semantic, BrowserAcceptanceSemanticV1::Create);
        assert_eq!(actions[2].semantic, BrowserAcceptanceSemanticV1::Update);
        assert_eq!(actions[3].semantic, BrowserAcceptanceSemanticV1::Delete);
        assert_eq!(actions[5].generation, 2);
        let semantic = plan_browser_semantic_steps(&contract)
            .unwrap_or_else(|error| panic!("map Plan browser semantic steps: {error}"));
        assert_eq!(semantic[4].required_synopsis_contains, ["Name is required"]);
        assert_eq!(semantic[4].forbidden_synopsis_contains, ["Created person"]);
        assert_eq!(
            semantic[5].semantic,
            BrowserAcceptanceSemanticV1::RestartPersistence
        );
    }

    #[test]
    fn typed_form_values_bind_employee_and_invalid_values_without_persisting_them() {
        let mut contract = contract();
        let chosen_value = "Avery Chen";
        let invalid_value = "not-a-valid-employee";
        contract.steps[1].action = BrowserAcceptanceActionV1::SubmitForm {
            selector: "form#create-person".to_owned(),
            fields: vec![BrowserAcceptanceFieldValueV1 {
                selector: "input[name='employee']".to_owned(),
                value: chosen_value.to_owned(),
            }],
        };
        contract.steps[4].action = BrowserAcceptanceActionV1::SubmitForm {
            selector: "form#create-person".to_owned(),
            fields: vec![BrowserAcceptanceFieldValueV1 {
                selector: "input[name='employee']".to_owned(),
                value: invalid_value.to_owned(),
            }],
        };
        contract.steps[4].expectation.required_contains.clear();
        contract.steps[4].expectation.forbidden_contains.clear();
        contract.steps[4].expectation.semantic = BrowserAcceptanceSemanticV1::InvalidValidation;
        contract
            .validate()
            .unwrap_or_else(|error| panic!("validate value-bearing contract: {error}"));

        let actions = plan_browser_actions_from_contract(&contract)
            .unwrap_or_else(|error| panic!("map value-bearing browser actions: {error}"));
        let BrowserAction::SubmitFormWithValues { fields, .. } = &actions[1].action else {
            panic!("chosen employee value was not mapped to a value-bearing submit action");
        };
        let chosen = BrowserFormFieldValues::new(BTreeMap::from([(
            "input[name='employee']".to_owned(),
            chosen_value.to_owned(),
        )]))
        .unwrap_or_else(|error| panic!("construct expected chosen value digest: {error}"));
        assert_eq!(fields.digest(), chosen.digest());
        let BrowserAction::SubmitFormWithValues { fields, .. } = &actions[4].action else {
            panic!("invalid validation value was not mapped to a value-bearing submit action");
        };
        let invalid = BrowserFormFieldValues::new(BTreeMap::from([(
            "input[name='employee']".to_owned(),
            invalid_value.to_owned(),
        )]))
        .unwrap_or_else(|error| panic!("construct expected invalid value digest: {error}"));
        assert_eq!(fields.digest(), invalid.digest());

        let semantic = plan_browser_semantic_steps(&contract)
            .unwrap_or_else(|error| panic!("map semantic steps: {error}"));
        let semantic_json = serde_json::to_string(&semantic)
            .unwrap_or_else(|error| panic!("serialize semantic steps: {error}"));
        assert!(!semantic_json.contains(chosen_value));
        assert!(!semantic_json.contains(invalid_value));
        assert!(!format!("{:?}", actions[1].action).contains(chosen_value));
        assert!(!format!("{:?}", actions[4].action).contains(invalid_value));
    }

    #[test]
    fn browser_action_commit_must_be_strictly_inside_its_managed_generation() {
        let generation = BrowserSemanticManagedGenerationV1 {
            app_id: "app.1".to_owned(),
            generation: 2,
            start_action_id: "start.2".to_owned(),
            start_result_digest: "sha256:start".to_owned(),
            process_group_id: 123,
            leader_identity: "leader".to_owned(),
            database_path: "/private/demo.sqlite3".to_owned(),
            ready_sequence: 100,
            stopped_sequence: 200,
        };
        assert!(
            validate_browser_action_generation_sequence(101, &generation, "browser.ok").is_ok()
        );
        assert!(
            validate_browser_action_generation_sequence(199, &generation, "browser.ok").is_ok()
        );
        for sequence in [99, 100, 200, 201] {
            assert!(matches!(
                validate_browser_action_generation_sequence(sequence, &generation, "browser.bad"),
                Err(ControllerError::NotReady(_))
            ));
        }
    }
}

#[cfg(test)]
mod browser_download_terminal_tests {
    use super::{
        AuthorizedBrowserAction, BROWSER_DOWNLOAD_RECORD_NAMESPACE,
        BROWSER_RESOURCE_RESIDENCY_SCHEMA_VERSION, BROWSER_SCHEMA_VERSION, BrowserAdapterConfig,
        BrowserDownloadMode, BrowserDownloadPolicyV1, BrowserDownloadRetentionPolicyV1,
        BrowserDownloadRootAuthorityV1, BrowserGateway, BrowserGatewayAuthority,
        BrowserGatewayCapabilityBinding, BrowserNetworkReservationStateV1,
        BrowserNetworkSettlementV1, BrowserProfileAuthority, BrowserProfileMode,
        BrowserResourceResidencyStateV1, BrowserResourceResidencyV1, BrowserTaskAuthorityV1,
        Controller, ControllerBrowserSession, OwnedTaskLoopbackScope,
        browser_action_reservation_bounds, current_unix_millis, handle_proxy_client,
    };
    use crate::{
        ActivePlan, ActiveRepositoryState, AttemptRuntime, AttemptState, PlanValidity,
        ResourceResidencyStateV1, ResourceResidencyV1, TaskRuntime, TaskState, digest_json,
        load_latest_recoverable_manifest, reconcile_recovery_actions, valid_plan_ir_fixture,
        valid_task_fixture,
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
    use sovereign_repo::{ChangeClassSnapshot, ProjectRegistry, RepositorySnapshot};
    use sovereign_state::{ActionTransition, NewActionRecord, StateStore};
    use sovereign_tools::browser::{
        BrowserAction, BrowserActionEffect, BrowserDownloadTerminalObservation,
        BrowserDownloadTerminalState, BrowserFormFieldValues, BrowserLease,
        BrowserSensitivePageReason, BrowserSensitivePageSignal, BrowserStateSynopsis,
        DownloadReceipt,
    };
    use sovereign_tools::{ActionState, ReconciliationMode, ToolError};
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::thread;
    use std::time::Duration;

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

    fn bind_manual_fixture_checkpoint(controller: &mut Controller) {
        let active = controller
            .active
            .as_mut()
            .unwrap_or_else(|| panic!("fixture active plan disappeared"));
        let plan_digest = digest_json(&active.plan_document)
            .unwrap_or_else(|error| panic!("digest fixture plan: {error}"));
        active.plan_digest.clone_from(&plan_digest);
        active.compiler_plan_digest = plan_digest;
        for runtime in active.tasks.values_mut() {
            runtime.task_contract_digest = digest_json(&runtime.task)
                .unwrap_or_else(|error| panic!("digest fixture task: {error}"));
        }
        for attempt in active.attempts.values_mut() {
            attempt.task_contract_digest = active
                .tasks
                .get(&attempt.task_id)
                .unwrap_or_else(|| panic!("fixture attempt task disappeared"))
                .task_contract_digest
                .clone();
        }
        for repository in active.repositories.values_mut() {
            repository.baseline_diff_digest =
                super::sha256_prefixed(repository.baseline_diff_content.as_bytes());
        }
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
            tool_manifest: sovereign_tools::ToolManifest {
                tool_id: "browser.test".to_owned(),
                version: "1".to_owned(),
                content_digest: format!("sha256:{:064x}", 3),
                permission_ceiling: BTreeSet::from([
                    Capability::BrowserInteractive,
                    Capability::NetworkRead,
                ]),
                declared_risk_floor: CommandRisk::ReadOnly,
                reconciliation_policy: sovereign_policy::ReconciliationPolicy::proof_required_local(
                ),
            },
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
            permission_class: Capability::BrowserInteractive,
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

    fn gateway_authority() -> BrowserGatewayAuthority {
        let task_authority = BrowserTaskAuthorityV1 {
            schema_version: super::BROWSER_AUTHORITY_SCHEMA_VERSION,
            allowed_domains: BTreeSet::new(),
            allowed_schemes: BTreeSet::new(),
            allowed_ports: BTreeSet::new(),
            allowed_methods: BTreeSet::from(["GET".to_owned()]),
            follow_redirects: false,
            max_redirects: 0,
            allow_task_loopback: false,
            max_tabs: 1,
            downloads_allowed: false,
            profile_mode: BrowserProfileMode::Isolated,
            download_root: None,
        };
        BrowserGatewayAuthority::new(
            &task_authority,
            Vec::new(),
            OwnedTaskLoopbackScope {
                plan_id: "plan.gateway-test".to_owned(),
                plan_revision: 1,
                task_id: "task.gateway-test".to_owned(),
                task_contract_digest: format!("sha256:{:064x}", 1),
                resource_lease_id: "browser:gateway-test".to_owned(),
                execution_epoch: 17,
            },
            64 * 1024,
            current_unix_millis().unwrap_or_else(|error| panic!("gateway test clock: {error}")),
        )
        .unwrap_or_else(|error| panic!("gateway test authority: {error}"))
    }

    fn gateway_capability_binding() -> BrowserGatewayCapabilityBinding {
        BrowserGatewayCapabilityBinding {
            lease_id: "browser:gateway-test".to_owned(),
            execution_epoch: 17,
            token_digest: "sha256:f87a91451b3bc19d132d3965109e7d131c69e9fc04fef54a5ab34fa7b369ba9d"
                .to_owned(),
            expires_at_ms: current_unix_millis()
                .unwrap_or_else(|error| panic!("gateway test clock: {error}"))
                + 60_000,
        }
    }

    fn no_download_session(root: &Path) -> ControllerBrowserSession {
        let mut session = download_session(root, 1_000_000);
        session.authority.downloads_allowed = false;
        session.authority.download_root = None;
        session.download_root = None;
        session.download_policy.mode = BrowserDownloadMode::Deny;
        session.download_policy.root_authority = None;
        session
    }

    fn browser_output_budget() -> AutonomyBudgetV1 {
        let mut budget = autonomy_budget(1_000_000, 0, 1_048_576, 0);
        budget.max_output_bytes = 64 * 1024 * 1024;
        budget
    }

    fn seed_dispatched_browser_action(
        controller: &mut Controller,
        authorized: &AuthorizedBrowserAction,
    ) {
        let payload_digest = authorized.payload_digest();
        controller
            .state
            .insert_action_record(NewActionRecord {
                action_id: &authorized.action_id,
                state: ActionState::Dispatched.as_str(),
                payload_digest: &payload_digest,
                policy_digest: &authorized.policy_digest,
                execution_epoch: authorized.execution_epoch,
                event_id: "browser-output-boundary-dispatched",
                event_kind: ActionState::Dispatched.as_str(),
                payload_json: "{}",
            })
            .unwrap_or_else(|error| panic!("seed dispatched browser action: {error}"));
    }

    fn navigation_receipt(
        session: &ControllerBrowserSession,
        action: &BrowserAction,
        cdp_request_id: u64,
    ) -> super::BrowserActionReceipt {
        let BrowserAction::Navigate { url, .. } = action else {
            panic!("navigation receipt helper requires Navigate");
        };
        super::BrowserActionReceipt {
            schema_version: BROWSER_SCHEMA_VERSION,
            action_id: action.action_id().to_owned(),
            action_digest: action.digest(),
            action_kind: action.kind_name().to_owned(),
            effect: action.effect(),
            lease_id: session.browser_lease.lease_id.clone(),
            lease_binding_digest: session.browser_lease.binding_digest(),
            execution_epoch: session.execution_epoch,
            cdp_request_id,
            requested_url: Some(url.clone()),
            navigation_was_download: false,
            download: None,
            synopsis: None,
            screenshot: None,
            screenshots_and_traces_suppressed: session
                .adapter_config
                .suppress_screenshots_and_traces,
        }
    }

    fn reservation_navigate(action_id: &str, url: &str) -> BrowserAction {
        BrowserAction::Navigate {
            action_id: action_id.to_owned(),
            url: url.to_owned(),
        }
    }

    fn reservation_submit(action_id: &str, selector: &str, payload_seed: u64) -> BrowserAction {
        BrowserAction::SubmitForm {
            action_id: action_id.to_owned(),
            selector: selector.to_owned(),
            payload_digest: format!("sha256:{payload_seed:064x}"),
        }
    }

    fn pd_t03_reservation_actions() -> Vec<BrowserAction> {
        vec![
            reservation_navigate("open-empty-inventory", "http://127.0.0.1:4173/view"),
            reservation_navigate("open-invalid-create-form", "http://127.0.0.1:4173/"),
            reservation_submit("reject-invalid-create", "form#invalid-create", 1),
            reservation_navigate("return-after-invalid", "http://127.0.0.1:4173/"),
            reservation_submit("create-widget", "form#create-widget", 2),
            reservation_navigate("observe-created-widget", "http://127.0.0.1:4173/view"),
            reservation_navigate("open-created-widget-form", "http://127.0.0.1:4173/"),
            reservation_submit("edit-widget", "form#edit-1", 3),
            reservation_navigate("observe-edited-widget", "http://127.0.0.1:4173/view"),
            reservation_navigate("search-widget", "http://127.0.0.1:4173/view?q=Widget%20Pro"),
            reservation_navigate("open-delete-widget-form", "http://127.0.0.1:4173/"),
            reservation_submit("delete-widget", "form#delete-1", 4),
            reservation_navigate("observe-deleted-widget", "http://127.0.0.1:4173/view"),
            reservation_navigate("open-persistent-create-form", "http://127.0.0.1:4173/"),
            reservation_submit("create-persistent-widget", "form#create-widget", 5),
            reservation_navigate("observe-persistent-seed", "http://127.0.0.1:4173/view"),
        ]
    }

    #[test]
    fn browser_retained_navigation_reservations_are_small_and_pd_t03_sequence_stays_bounded() {
        let root = std::env::temp_dir().join(format!(
            "sovereign-browser-output-bound-test-{}",
            NEXT_FIXTURE_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root)
            .unwrap_or_else(|error| panic!("create reservation fixture root: {error}"));
        let session = no_download_session(&root);
        let budget = browser_output_budget();
        let frame_bound = u64::try_from(session.adapter_config.max_cdp_frame_bytes)
            .unwrap_or_else(|_| panic!("CDP frame bound overflow"));
        let navigate = reservation_navigate("open-empty-inventory", "http://127.0.0.1:4173/view");
        let submit = reservation_submit("create-widget", "form#create-widget", 7);
        let (_, navigate_bound) = browser_action_reservation_bounds(&session, &navigate, &budget)
            .unwrap_or_else(|error| panic!("reserve no-download Navigate: {error}"));
        let (_, submit_bound) = browser_action_reservation_bounds(&session, &submit, &budget)
            .unwrap_or_else(|error| panic!("reserve SubmitForm: {error}"));
        assert!(navigate_bound < frame_bound / 100);
        assert!(submit_bound < frame_bound / 100);

        let pd_t03_actions = pd_t03_reservation_actions();
        let cumulative = pd_t03_actions.iter().fold(0_u64, |total, action| {
            let (_, bound) = browser_action_reservation_bounds(&session, action, &budget)
                .unwrap_or_else(|error| {
                    panic!("reserve PD-T03 browser action {action:?}: {error}")
                });
            total.saturating_add(bound)
        });
        assert!(cumulative < 8 * 1024 * 1024);

        let mut download_enabled = download_session(&root, 1_000_000);
        download_enabled.adapter_config = session.adapter_config.clone();
        let (_, download_bound) =
            browser_action_reservation_bounds(&download_enabled, &navigate, &budget)
                .unwrap_or_else(|error| panic!("reserve download-enabled Navigate: {error}"));
        assert_eq!(download_bound, frame_bound);
        fs::remove_dir_all(&root)
            .unwrap_or_else(|error| panic!("remove reservation fixture root: {error}"));
    }

    fn assert_oversized_browser_receipt_is_rejected() {
        let mut oversized_fixture = durable_fixture(
            autonomy_budget(1_000, 0, 1_048_576, 0),
            autonomy_budget(1_000, 0, 1_048_576, 0),
        );
        seed_running_attempt(&mut oversized_fixture.controller);
        let oversized_download_root = oversized_fixture.root.join("downloads");
        fs::create_dir_all(&oversized_download_root)
            .unwrap_or_else(|error| panic!("create oversized receipt download root: {error}"));
        let mut oversized_session = no_download_session(&oversized_download_root);
        let oversized_epoch = oversized_fixture
            .controller
            .state
            .current_execution_epoch()
            .unwrap_or_else(|error| panic!("read oversized receipt epoch: {error}"));
        oversized_session.execution_epoch = oversized_epoch;
        oversized_session.browser_lease.execution_epoch = oversized_epoch;
        let oversized_action =
            reservation_navigate("browser.output.oversized", "http://127.0.0.1:4173/view");
        let oversized_receipt = navigation_receipt(&oversized_session, &oversized_action, 1);
        let oversized_bytes = oversized_receipt
            .to_bytes()
            .unwrap_or_else(|error| panic!("serialize oversized receipt: {error}"));
        let oversized_digest = super::browser_receipt_digest(&oversized_bytes);
        let mut oversized_authorized = authorized_synopsis_action(oversized_epoch);
        oversized_authorized.action_id = oversized_action.action_id().to_owned();
        oversized_authorized.browser_action_digest = oversized_action.digest();
        oversized_authorized.output_bytes = u64::try_from(oversized_bytes.len())
            .unwrap_or_else(|_| panic!("oversized receipt length overflow"))
            .saturating_sub(1);
        seed_dispatched_browser_action(&mut oversized_fixture.controller, &oversized_authorized);
        let oversized_artifacts = ArtifactStore::open(oversized_fixture.root.join("cas"))
            .unwrap_or_else(|error| panic!("open oversized receipt CAS: {error}"));
        let Err(error) = oversized_fixture.controller.publish_browser_action_receipt(
            &oversized_session,
            &oversized_authorized,
            &oversized_artifacts,
            oversized_receipt,
        ) else {
            panic!("receipt above authorized output reservation must fail closed");
        };
        assert!(matches!(
            error,
            crate::ControllerError::UnknownAction(ref action_id)
                if action_id == &oversized_authorized.action_id
        ));
        let oversized_record = oversized_fixture
            .controller
            .state
            .action_record(&oversized_authorized.action_id)
            .unwrap_or_else(|error| panic!("read oversized action record: {error}"))
            .unwrap_or_else(|| panic!("oversized action record disappeared"));
        assert_eq!(oversized_record.state, ActionState::Unknown.as_str());
        assert!(oversized_record.result_digest.is_none());
        assert_eq!(
            oversized_fixture
                .controller
                .active
                .as_ref()
                .and_then(|active| active.attempts.get("attempt.browser"))
                .map(|attempt| attempt.state),
            Some(AttemptState::Interrupted)
        );
        assert_eq!(
            oversized_fixture
                .controller
                .active
                .as_ref()
                .and_then(|active| active.tasks.get("task.browser"))
                .map(|task| task.state),
            Some(TaskState::ReconcilingUnknown)
        );
        assert!(
            oversized_fixture
                .controller
                .state
                .artifact_metadata(&oversized_digest)
                .unwrap_or_else(|error| panic!("read oversized artifact metadata: {error}"))
                .is_none()
        );
        let oversized_object = oversized_artifacts
            .root()
            .join("sha256")
            .join(&oversized_digest[..2])
            .join(&oversized_digest);
        assert!(!oversized_object.exists());
    }

    fn assert_exact_fit_browser_receipt_is_published() {
        let mut exact_fixture = durable_fixture(
            autonomy_budget(1_000, 0, 1_048_576, 0),
            autonomy_budget(1_000, 0, 1_048_576, 0),
        );
        let exact_download_root = exact_fixture.root.join("downloads");
        fs::create_dir_all(&exact_download_root)
            .unwrap_or_else(|error| panic!("create exact receipt download root: {error}"));
        let mut exact_session = no_download_session(&exact_download_root);
        let exact_epoch = exact_fixture
            .controller
            .state
            .current_execution_epoch()
            .unwrap_or_else(|error| panic!("read exact receipt epoch: {error}"));
        exact_session.execution_epoch = exact_epoch;
        exact_session.browser_lease.execution_epoch = exact_epoch;
        let exact_action =
            reservation_navigate("browser.output.exact", "http://127.0.0.1:4173/view");
        let exact_receipt = navigation_receipt(&exact_session, &exact_action, 2);
        let exact_bytes = exact_receipt
            .to_bytes()
            .unwrap_or_else(|error| panic!("serialize exact receipt: {error}"));
        let exact_len = u64::try_from(exact_bytes.len())
            .unwrap_or_else(|_| panic!("exact receipt length overflow"));
        let exact_digest = super::browser_receipt_digest(&exact_bytes);
        let mut exact_authorized = authorized_synopsis_action(exact_epoch);
        exact_authorized.action_id = exact_action.action_id().to_owned();
        exact_authorized.browser_action_digest = exact_action.digest();
        exact_authorized.output_bytes = exact_len;
        seed_dispatched_browser_action(&mut exact_fixture.controller, &exact_authorized);
        let exact_artifacts = ArtifactStore::open(exact_fixture.root.join("cas"))
            .unwrap_or_else(|error| panic!("open exact receipt CAS: {error}"));
        let (_, published_digest, published_len) = exact_fixture
            .controller
            .publish_browser_action_receipt(
                &exact_session,
                &exact_authorized,
                &exact_artifacts,
                exact_receipt,
            )
            .unwrap_or_else(|error| panic!("publish exact-fit receipt: {error}"));
        assert_eq!(published_digest, exact_digest);
        assert_eq!(published_len, exact_len);
        let exact_record = exact_fixture
            .controller
            .state
            .action_record(&exact_authorized.action_id)
            .unwrap_or_else(|error| panic!("read exact action record: {error}"))
            .unwrap_or_else(|| panic!("exact action record disappeared"));
        assert_eq!(exact_record.state, ActionState::Committed.as_str());
        assert_eq!(
            exact_record.result_digest.as_deref(),
            Some(exact_digest.as_str())
        );
        assert!(
            exact_fixture
                .controller
                .state
                .artifact_metadata(&exact_digest)
                .unwrap_or_else(|error| panic!("read exact artifact metadata: {error}"))
                .is_some()
        );
        let exact_object = exact_artifacts
            .root()
            .join("sha256")
            .join(&exact_digest[..2])
            .join(&exact_digest);
        assert!(exact_object.is_file());
    }

    #[test]
    fn browser_receipt_publication_enforces_exact_authorized_output_boundary() {
        assert_oversized_browser_receipt_is_rejected();
        assert_exact_fit_browser_receipt_is_published();
    }

    #[test]
    fn browser_gateway_authenticated_unapproved_destination_is_local_403_and_clean() {
        let (gateway, capability) =
            BrowserGateway::bind(gateway_authority(), &gateway_capability_binding())
                .unwrap_or_else(|error| panic!("bind gateway: {error}"));
        let mut client = TcpStream::connect(("127.0.0.1", capability.localhost_port))
            .unwrap_or_else(|error| panic!("connect authenticated denied request: {error}"));
        client
            .write_all(
                b"GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\nProxy-Authorization: Basic c292ZXJlaWduLWJyb3dzZXI6Z2F0ZXdheS10ZXN0LXRva2Vu\r\n\r\n",
            )
            .unwrap_or_else(|error| panic!("write authenticated denied request: {error}"));
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .unwrap_or_else(|error| panic!("read authenticated denial: {error}"));
        assert!(response.starts_with(b"HTTP/1.1 403 Forbidden"));
        assert_eq!(gateway.transferred_bytes(), 0);

        let transferred = gateway.shutdown().unwrap_or_else(|error| {
            panic!("policy-local 403 must leave gateway settlement clean: {error}")
        });
        assert_eq!(transferred, 0);
    }

    #[test]
    fn browser_gateway_exact_zero_byte_client_close_is_clean() {
        let (gateway, capability) =
            BrowserGateway::bind(gateway_authority(), &gateway_capability_binding())
                .unwrap_or_else(|error| panic!("bind gateway: {error}"));
        let mut client = TcpStream::connect(("127.0.0.1", capability.localhost_port))
            .unwrap_or_else(|error| panic!("connect zero-byte client: {error}"));
        client
            .shutdown(Shutdown::Write)
            .unwrap_or_else(|error| panic!("close zero-byte request side: {error}"));
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .unwrap_or_else(|error| panic!("wait for zero-byte handler close: {error}"));
        assert!(response.is_empty());

        let transferred = gateway.shutdown().unwrap_or_else(|error| {
            panic!("exact zero-byte client close must remain clean: {error}")
        });
        assert_eq!(transferred, 0);
    }

    #[test]
    fn browser_gateway_partial_request_close_remains_fail_closed() {
        let (gateway, capability) =
            BrowserGateway::bind(gateway_authority(), &gateway_capability_binding())
                .unwrap_or_else(|error| panic!("bind gateway: {error}"));
        let mut client = TcpStream::connect(("127.0.0.1", capability.localhost_port))
            .unwrap_or_else(|error| panic!("connect partial gateway request: {error}"));
        client
            .write_all(b"GET http://example.test/ HTTP/1.1\r\nHost: example.test")
            .unwrap_or_else(|error| panic!("write partial gateway request: {error}"));
        client
            .shutdown(Shutdown::Write)
            .unwrap_or_else(|error| panic!("close partial request write side: {error}"));
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .unwrap_or_else(|error| panic!("wait for partial gateway close: {error}"));
        assert!(response.is_empty());

        let Err(error) = gateway.shutdown() else {
            panic!("partial proxy request must poison gateway settlement");
        };
        assert!(matches!(
            error,
            ToolError::Authority(message)
                if message.contains("browser gateway denied or failed a connection")
                    && message.contains("browser proxy client closed before complete headers")
        ));
    }

    #[test]
    fn browser_gateway_shutdown_wake_is_not_recorded_as_failure() {
        let (gateway, capability) =
            BrowserGateway::bind(gateway_authority(), &gateway_capability_binding())
                .unwrap_or_else(|error| panic!("bind gateway: {error}"));
        let mut client = TcpStream::connect(("127.0.0.1", capability.localhost_port))
            .unwrap_or_else(|error| panic!("connect gateway warm-up: {error}"));
        client
            .write_all(b"GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n")
            .unwrap_or_else(|error| panic!("write gateway warm-up: {error}"));
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .unwrap_or_else(|error| panic!("read gateway warm-up: {error}"));
        assert!(response.starts_with(b"HTTP/1.1 407 Proxy Authentication Required"));

        let transferred = gateway
            .shutdown()
            .unwrap_or_else(|error| panic!("clean gateway shutdown wake was poisoned: {error}"));
        assert_eq!(transferred, 0);
    }

    #[test]
    fn proxy_handler_clears_inherited_nonblocking_before_request_read() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .unwrap_or_else(|error| panic!("bind handler test listener: {error}"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("handler test address: {error}"));
        let client = thread::spawn(move || {
            let mut client = TcpStream::connect(address)
                .unwrap_or_else(|error| panic!("connect handler test client: {error}"));
            thread::sleep(Duration::from_millis(25));
            client
                .write_all(b"GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n")
                .unwrap_or_else(|error| panic!("write delayed handler request: {error}"));
            let mut response = Vec::new();
            client
                .read_to_end(&mut response)
                .unwrap_or_else(|error| panic!("read handler response: {error}"));
            response
        });
        let (accepted, _) = listener
            .accept()
            .unwrap_or_else(|error| panic!("accept handler test client: {error}"));
        accepted
            .set_nonblocking(true)
            .unwrap_or_else(|error| panic!("force inherited nonblocking mode: {error}"));
        let capability = gateway_capability_binding().materialize(address.port());
        let stop = AtomicBool::new(false);
        let transferred = AtomicU64::new(0);

        handle_proxy_client(
            accepted,
            &gateway_authority(),
            &capability,
            &stop,
            &transferred,
        )
        .unwrap_or_else(|error| panic!("handler surfaced inherited nonblocking failure: {error}"));
        let response = client
            .join()
            .unwrap_or_else(|_| panic!("handler test client thread panicked"));
        assert!(response.starts_with(b"HTTP/1.1 407 Proxy Authentication Required"));
        assert_eq!(transferred.load(Ordering::Acquire), 0);
    }

    #[test]
    fn browser_gateway_real_request_failure_remains_fail_closed() {
        let (gateway, capability) =
            BrowserGateway::bind(gateway_authority(), &gateway_capability_binding())
                .unwrap_or_else(|error| panic!("bind gateway: {error}"));
        let mut client = TcpStream::connect(("127.0.0.1", capability.localhost_port))
            .unwrap_or_else(|error| panic!("connect malformed gateway request: {error}"));
        client
            .write_all(b"MALFORMED\r\n\r\n")
            .unwrap_or_else(|error| panic!("write malformed gateway request: {error}"));
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .unwrap_or_else(|error| panic!("wait for malformed gateway close: {error}"));
        assert!(response.is_empty());

        let Err(error) = gateway.shutdown() else {
            panic!("real malformed proxy request must poison gateway settlement");
        };
        assert!(matches!(
            error,
            ToolError::Authority(message)
                if message.contains("browser gateway denied or failed a connection")
                    && message.contains("browser proxy target missing")
        ));
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
    fn dispatched_submit_form_recovery_after_restart_blocks_replay() {
        let mut fixture = durable_fixture(
            autonomy_budget(1_000, 0, 1_048_576, 0),
            autonomy_budget(1_000, 0, 1_048_576, 0),
        );
        seed_checkpoint_resource_policy(&mut fixture.controller);
        seed_running_attempt(&mut fixture.controller);
        bind_manual_fixture_checkpoint(&mut fixture.controller);
        fixture
            .controller
            .checkpoint_now()
            .unwrap_or_else(|error| panic!("write valid pre-dispatch checkpoint: {error}"));
        let checkpoint = fixture
            .controller
            .state
            .latest_valid_checkpoint_integrity()
            .unwrap_or_else(|error| panic!("read valid pre-dispatch checkpoint: {error}"))
            .unwrap_or_else(|| panic!("fixture checkpoint was not recorded"));
        let (_, manifest) =
            load_latest_recoverable_manifest(&fixture.controller.state, &checkpoint)
                .unwrap_or_else(|error| {
                    panic!("verify pre-dispatch checkpoint CAS manifest: {error}")
                });
        let lease = admit_browser_lease_for_unknown_test(&mut fixture.controller);
        let execution_epoch = fixture
            .controller
            .state
            .current_execution_epoch()
            .unwrap_or_else(|error| panic!("read submit-form test epoch: {error}"));

        let fields = BrowserFormFieldValues::new(BTreeMap::from([(
            "input[name=employee]".to_owned(),
            "employee-42".to_owned(),
        )]))
        .unwrap_or_else(|error| panic!("build uncertain employee form values: {error}"));
        let submit = BrowserAction::SubmitFormWithValues {
            action_id: "browser.submit.unknown.test".to_owned(),
            selector: "form#checkout".to_owned(),
            fields,
        };
        assert_eq!(submit.kind_name(), "submit_form");
        assert!(submit.effect().is_side_effectful());
        let payload_digest = submit.digest();
        let policy_digest = format!("sha256:{:064x}", 7);
        fixture
            .controller
            .state
            .insert_action_record(NewActionRecord {
                action_id: submit.action_id(),
                state: ActionState::Dispatched.as_str(),
                payload_digest: &payload_digest,
                policy_digest: &policy_digest,
                execution_epoch,
                event_id: "browser-submit-dispatched",
                event_kind: ActionState::Dispatched.as_str(),
                payload_json: "{}",
            })
            .unwrap_or_else(|error| panic!("seed dispatched SubmitForm: {error}"));
        assert_eq!(
            fixture
                .controller
                .resources
                .active_lease(&lease.lease_id)
                .map(|resource| resource.state),
            Some(LeaseStateV1::Active),
            "the pre-crash browser lease remains active while the form action is dispatched"
        );

        // Model process loss after the POST may have reached its destination: reopen the durable
        // database and run the same action-reconciliation phase used by RecoveryManager.
        let state_path = fixture.controller.state.path().to_path_buf();
        let placeholder_state = StateStore::open(fixture.root.join("placeholder-state.sqlite"))
            .unwrap_or_else(|error| panic!("open placeholder state for fixture drop: {error}"));
        drop(std::mem::replace(
            &mut fixture.controller.state,
            placeholder_state,
        ));
        let mut recovered_state = StateStore::open(&state_path)
            .unwrap_or_else(|error| panic!("reopen state after uncertain form POST: {error}"));
        let registry = ProjectRegistry::new();
        let unknown = reconcile_recovery_actions(
            &mut recovered_state,
            &registry,
            &BTreeSet::new(),
            &manifest,
            &BTreeMap::new(),
        )
        .unwrap_or_else(|error| panic!("reconcile uncertain form POST after restart: {error}"));
        assert_eq!(unknown, vec![submit.action_id().to_owned()]);
        let action = recovered_state
            .action_record(submit.action_id())
            .unwrap_or_else(|error| panic!("read recovered form action: {error}"))
            .unwrap_or_else(|| panic!("recovered form action disappeared"));
        assert_eq!(action.state, ActionState::Unknown.as_str());
        let action_events = recovered_state
            .journal()
            .unwrap_or_else(|error| panic!("read recovered form action events: {error}"))
            .into_iter()
            .filter(|event| event.entity_type == "action" && event.entity_id == submit.action_id())
            .collect::<Vec<_>>();
        assert_eq!(
            action_events
                .iter()
                .filter(|event| event.event_kind == "dispatched")
                .count(),
            1,
            "recovery must not dispatch the form again"
        );
        assert_eq!(
            action_events
                .iter()
                .filter(|event| event.event_kind == "unknown")
                .count(),
            1,
            "the uncertain external effect is fenced exactly once"
        );

        // A second recovery pass must leave the external action fenced without another dispatch.
        let unknown_again = reconcile_recovery_actions(
            &mut recovered_state,
            &registry,
            &BTreeSet::new(),
            &manifest,
            &BTreeMap::new(),
        )
        .unwrap_or_else(|error| panic!("repeat form action recovery: {error}"));
        assert_eq!(unknown_again, vec![submit.action_id().to_owned()]);
        let repeated_events = recovered_state
            .journal()
            .unwrap_or_else(|error| panic!("read repeated recovery events: {error}"))
            .into_iter()
            .filter(|event| event.entity_type == "action" && event.entity_id == submit.action_id())
            .collect::<Vec<_>>();
        assert_eq!(repeated_events, action_events);
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
