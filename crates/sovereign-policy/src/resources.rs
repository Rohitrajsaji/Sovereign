use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::error::Error;
use std::fmt::{Display, Formatter};

pub const HARDWARE_PROFILE_SCHEMA_VERSION: u32 = 1;
pub const RESOURCE_LEASE_SCHEMA_VERSION: u32 = 1;
pub const RESOURCE_PRESSURE_EVENT_SCHEMA_VERSION: u32 = 1;
pub const M6_RESOURCE_GOVERNOR_SNAPSHOT_SCHEMA_VERSION: u32 = 1;

const MIB_PER_GIB: u64 = 1_024;

/// Runtime heavyweight capability classes owned by the resource governor.
///
/// Browser and indexer classes intentionally refine the broader Plan IR
/// vocabulary so the hardware profile can encode the frozen M1/8GB matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HeavyLeaseClass {
    Model,
    Embedder,
    CdpBrowser,
    AdaptiveBrowser,
    BuildHeavy,
    Indexer,
    CodegraphWiki,
    Lsp,
    /// Conservative fallback for an uncalibrated heavyweight whose finer
    /// runtime class is not yet known. It consumes `BUILD_HEAVY` task authority.
    Unknown,
}

impl HeavyLeaseClass {
    pub const KNOWN: [Self; 8] = [
        Self::Model,
        Self::Embedder,
        Self::CdpBrowser,
        Self::AdaptiveBrowser,
        Self::BuildHeavy,
        Self::Indexer,
        Self::CodegraphWiki,
        Self::Lsp,
    ];

    #[must_use]
    pub const fn plan_ir_class(self) -> PlanHeavyLeaseClass {
        match self {
            Self::Model => PlanHeavyLeaseClass::Model,
            Self::Embedder => PlanHeavyLeaseClass::Embedder,
            Self::CdpBrowser | Self::AdaptiveBrowser => PlanHeavyLeaseClass::Browser,
            Self::Indexer | Self::CodegraphWiki => PlanHeavyLeaseClass::Indexer,
            Self::Lsp => PlanHeavyLeaseClass::LanguageServer,
            Self::BuildHeavy | Self::Unknown => PlanHeavyLeaseClass::BuildHeavy,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Model => "MODEL",
            Self::Embedder => "EMBEDDER",
            Self::CdpBrowser => "CDP_BROWSER",
            Self::AdaptiveBrowser => "ADAPTIVE_BROWSER",
            Self::BuildHeavy => "BUILD_HEAVY",
            Self::Indexer => "INDEXER",
            Self::CodegraphWiki => "CODEGRAPH_WIKI",
            Self::Lsp => "LSP",
            Self::Unknown => "UNKNOWN",
        }
    }
}

/// Broad Plan IR heavy-lease classes used to prove a task may request a
/// runtime heavyweight across its lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PlanHeavyLeaseClass {
    Model,
    Embedder,
    Browser,
    Indexer,
    LanguageServer,
    BuildHeavy,
}

impl PlanHeavyLeaseClass {
    #[must_use]
    pub const fn as_plan_ir_str(self) -> &'static str {
        match self {
            Self::Model => "MODEL",
            Self::Embedder => "EMBEDDER",
            Self::Browser => "BROWSER",
            Self::Indexer => "INDEXER",
            Self::LanguageServer => "LANGUAGE_SERVER",
            Self::BuildHeavy => "BUILD_HEAVY",
        }
    }

    #[must_use]
    pub fn from_plan_ir_str(value: &str) -> Option<Self> {
        match value {
            "MODEL" => Some(Self::Model),
            "EMBEDDER" => Some(Self::Embedder),
            "BROWSER" => Some(Self::Browser),
            "INDEXER" => Some(Self::Indexer),
            "LANGUAGE_SERVER" => Some(Self::LanguageServer),
            "BUILD_HEAVY" => Some(Self::BuildHeavy),
            _ => None,
        }
    }
}

/// Frozen pairwise hardware-policy outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LeasePairRule {
    Safe,
    Conditional,
    Serialize,
    Forbidden,
}

/// One symmetric pair rule materialized in `HardwareProfile` v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeavyLeasePairPolicyV1 {
    pub active: HeavyLeaseClass,
    pub requested: HeavyLeaseClass,
    pub rule: LeasePairRule,
}

/// Frozen target-machine hardware contract for the first local profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareProfileV1 {
    pub schema_version: u32,
    pub profile_id: String,
    pub physical_memory_mib: u64,
    pub logical_cpus: u32,
    pub normal_model_slots: u32,
    pub mutating_task_slots: u32,
    pub browser_slots: u32,
    pub embedder_slots: u32,
    pub heavy_build_slots: u32,
    pub heavy_index_slots: u32,
    pub minimum_host_free_disk_mib: u64,
    pub sovereign_disk_soft_limit_mib: u64,
    pub sovereign_disk_hard_limit_mib: u64,
    pub normal_controlled_working_set_soft_mib: u64,
    pub normal_controlled_working_set_hard_mib: u64,
    pub minimum_launch_headroom_soft_mib: u64,
    pub minimum_launch_headroom_hard_mib: u64,
    pub default_model_input_tokens: u32,
    pub default_model_output_reserve_tokens: u32,
    pub hard_model_input_tokens_without_profile_override: u32,
    pub guarded_growth_mib_per_min: u64,
    pub constrained_growth_mib_per_min: u64,
    pub constrained_controlled_working_set_mib: u64,
    pub heavy_lease_recovery_green_seconds: u64,
    pub heavy_lease_reload_cooldown_seconds: u64,
    pub heavy_lease_oscillation_window_seconds: u64,
    pub max_completed_eviction_cycles_per_window: usize,
    pub unknown_heavy_admission_mib: u64,
    pub unknown_heavy_first_run_max_jobs: u32,
    pub calibrated_build_max_jobs: u32,
    pub unknown_heavy_first_run_max_subprocesses: u32,
    pub pair_rules: Vec<HeavyLeasePairPolicyV1>,
}

impl HardwareProfileV1 {
    /// Frozen `MacBook` Air M1 / 8GB baseline from `RESOURCE_STRESS_TEST.md`.
    #[must_use]
    pub fn m1_8gb() -> Self {
        let mut pair_rules = Vec::new();
        for (left_index, left) in HeavyLeaseClass::KNOWN.iter().copied().enumerate() {
            for right in HeavyLeaseClass::KNOWN[left_index..].iter().copied() {
                pair_rules.push(HeavyLeasePairPolicyV1 {
                    active: left,
                    requested: right,
                    rule: m1_pair_rule(left, right),
                });
            }
        }
        Self {
            schema_version: HARDWARE_PROFILE_SCHEMA_VERSION,
            profile_id: "m1-8gb".to_owned(),
            physical_memory_mib: 8_192,
            logical_cpus: 8,
            normal_model_slots: 1,
            mutating_task_slots: 1,
            browser_slots: 1,
            embedder_slots: 1,
            heavy_build_slots: 1,
            heavy_index_slots: 1,
            minimum_host_free_disk_mib: 20 * MIB_PER_GIB,
            sovereign_disk_soft_limit_mib: 40 * MIB_PER_GIB,
            sovereign_disk_hard_limit_mib: 60 * MIB_PER_GIB,
            normal_controlled_working_set_soft_mib: 4_864,
            normal_controlled_working_set_hard_mib: 5_632,
            minimum_launch_headroom_soft_mib: 1_536,
            minimum_launch_headroom_hard_mib: 1_280,
            default_model_input_tokens: 8_192,
            default_model_output_reserve_tokens: 1_536,
            hard_model_input_tokens_without_profile_override: 16_384,
            guarded_growth_mib_per_min: 64,
            constrained_growth_mib_per_min: 256,
            constrained_controlled_working_set_mib: 5_376,
            heavy_lease_recovery_green_seconds: 120,
            heavy_lease_reload_cooldown_seconds: 30,
            heavy_lease_oscillation_window_seconds: 300,
            max_completed_eviction_cycles_per_window: 1,
            unknown_heavy_admission_mib: 3_072,
            unknown_heavy_first_run_max_jobs: 2,
            calibrated_build_max_jobs: 4,
            unknown_heavy_first_run_max_subprocesses: 2,
            pair_rules,
        }
    }

    #[must_use]
    pub fn pair_rule(&self, active: HeavyLeaseClass, requested: HeavyLeaseClass) -> LeasePairRule {
        if active == HeavyLeaseClass::Unknown || requested == HeavyLeaseClass::Unknown {
            return LeasePairRule::Serialize;
        }
        self.pair_rules
            .iter()
            .find(|entry| {
                (entry.active == active && entry.requested == requested)
                    || (entry.active == requested && entry.requested == active)
            })
            .map_or(LeasePairRule::Serialize, |entry| entry.rule)
    }

    #[must_use]
    pub const fn idle_ttl_seconds(&self, class: HeavyLeaseClass) -> u64 {
        match class {
            HeavyLeaseClass::Embedder => 30,
            HeavyLeaseClass::CdpBrowser | HeavyLeaseClass::AdaptiveBrowser => 60,
            HeavyLeaseClass::Model | HeavyLeaseClass::Lsp => 120,
            HeavyLeaseClass::BuildHeavy
            | HeavyLeaseClass::Indexer
            | HeavyLeaseClass::CodegraphWiki
            | HeavyLeaseClass::Unknown => 0,
        }
    }

    #[must_use]
    pub fn digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.schema_version.to_le_bytes());
        hasher.update(
            u64::try_from(self.profile_id.len())
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
        );
        hasher.update(self.profile_id.as_bytes());
        for value in [
            self.physical_memory_mib,
            u64::from(self.logical_cpus),
            u64::from(self.normal_model_slots),
            u64::from(self.mutating_task_slots),
            u64::from(self.browser_slots),
            u64::from(self.embedder_slots),
            u64::from(self.heavy_build_slots),
            u64::from(self.heavy_index_slots),
            self.minimum_host_free_disk_mib,
            self.sovereign_disk_soft_limit_mib,
            self.sovereign_disk_hard_limit_mib,
            self.normal_controlled_working_set_soft_mib,
            self.normal_controlled_working_set_hard_mib,
            self.minimum_launch_headroom_soft_mib,
            self.minimum_launch_headroom_hard_mib,
            u64::from(self.default_model_input_tokens),
            u64::from(self.default_model_output_reserve_tokens),
            u64::from(self.hard_model_input_tokens_without_profile_override),
            self.guarded_growth_mib_per_min,
            self.constrained_growth_mib_per_min,
            self.constrained_controlled_working_set_mib,
            self.heavy_lease_recovery_green_seconds,
            self.heavy_lease_reload_cooldown_seconds,
            self.heavy_lease_oscillation_window_seconds,
            u64::try_from(self.max_completed_eviction_cycles_per_window).unwrap_or(u64::MAX),
            self.unknown_heavy_admission_mib,
            u64::from(self.unknown_heavy_first_run_max_jobs),
            u64::from(self.calibrated_build_max_jobs),
            u64::from(self.unknown_heavy_first_run_max_subprocesses),
        ] {
            hasher.update(value.to_le_bytes());
        }
        for class in HeavyLeaseClass::KNOWN
            .into_iter()
            .chain(std::iter::once(HeavyLeaseClass::Unknown))
        {
            hasher.update(class.as_str().as_bytes());
            hasher.update(self.idle_ttl_seconds(class).to_le_bytes());
        }
        for pair in &self.pair_rules {
            hasher.update(pair.active.as_str().as_bytes());
            hasher.update(pair.requested.as_str().as_bytes());
            hasher.update(match pair.rule {
                LeasePairRule::Safe => [0],
                LeasePairRule::Conditional => [1],
                LeasePairRule::Serialize => [2],
                LeasePairRule::Forbidden => [3],
            });
        }
        format!("sha256:{:x}", hasher.finalize())
    }
}

#[must_use]
fn m1_pair_rule(active: HeavyLeaseClass, requested: HeavyLeaseClass) -> LeasePairRule {
    use HeavyLeaseClass::{AdaptiveBrowser, CdpBrowser, Embedder, Indexer, Lsp, Model, Unknown};
    if active == Unknown || requested == Unknown {
        return LeasePairRule::Serialize;
    }
    if active == requested {
        return LeasePairRule::Forbidden;
    }
    match (active, requested) {
        (Model, CdpBrowser | AdaptiveBrowser | Indexer | Lsp)
        | (CdpBrowser | AdaptiveBrowser | Indexer | Lsp, Model)
        | (Embedder, Indexer)
        | (Indexer, Embedder) => LeasePairRule::Conditional,
        (CdpBrowser, AdaptiveBrowser) | (AdaptiveBrowser, CdpBrowser) => LeasePairRule::Forbidden,
        _ => LeasePairRule::Serialize,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PressureBand {
    Green,
    Guarded,
    Constrained,
    Emergency,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OsMemoryPressure {
    Normal,
    Warning,
    Critical,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ThermalPressure {
    Normal,
    Serious,
    Critical,
    Unknown,
}

/// One measured host-pressure sample. Absolute swap occupancy is retained for
/// diagnostics but deliberately excluded from band classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct ResourcePressureSnapshotV1 {
    pub schema_version: u32,
    pub observed_at_ms: i64,
    pub controlled_working_set_mib: u64,
    pub host_headroom_mib: u64,
    pub swap_used_mib: Option<u64>,
    pub swap_out_growth_mib_per_min: u64,
    pub compressor_growth_mib_per_min: u64,
    pub os_memory_pressure: OsMemoryPressure,
    pub recent_pressure_event: bool,
    pub thermal_pressure: ThermalPressure,
    pub allocation_failure: bool,
    pub repeated_resource_kill: bool,
    pub uncontrolled_child_growth: bool,
    pub host_free_disk_mib: Option<u64>,
}

impl ResourcePressureSnapshotV1 {
    #[must_use]
    pub const fn classify(self, profile: &HardwareProfileV1) -> PressureBand {
        if matches!(self.os_memory_pressure, OsMemoryPressure::Critical)
            || matches!(self.thermal_pressure, ThermalPressure::Critical)
            || self.allocation_failure
            || self.repeated_resource_kill
            || self.uncontrolled_child_growth
        {
            return PressureBand::Emergency;
        }
        if matches!(self.os_memory_pressure, OsMemoryPressure::Warning)
            || matches!(self.thermal_pressure, ThermalPressure::Serious)
            || self.swap_out_growth_mib_per_min > profile.constrained_growth_mib_per_min
            || self.compressor_growth_mib_per_min > profile.constrained_growth_mib_per_min
            || self.controlled_working_set_mib > profile.constrained_controlled_working_set_mib
            || self.host_headroom_mib < profile.minimum_launch_headroom_hard_mib
        {
            return PressureBand::Constrained;
        }
        if self.recent_pressure_event
            || matches!(self.os_memory_pressure, OsMemoryPressure::Unknown)
            || matches!(self.thermal_pressure, ThermalPressure::Unknown)
            || self.swap_out_growth_mib_per_min >= profile.guarded_growth_mib_per_min
            || self.compressor_growth_mib_per_min >= profile.guarded_growth_mib_per_min
            || self.controlled_working_set_mib >= profile.normal_controlled_working_set_soft_mib
            || self.host_headroom_mib < profile.minimum_launch_headroom_soft_mib
        {
            return PressureBand::Guarded;
        }
        PressureBand::Green
    }
}

/// Durable pressure event after applying recovery hysteresis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourcePressureEventV1 {
    pub schema_version: u32,
    pub event_id: String,
    pub snapshot: ResourcePressureSnapshotV1,
    pub raw_band: PressureBand,
    pub effective_band: PressureBand,
    pub green_stable_since_ms: Option<i64>,
    pub last_non_green_at_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceLeaseOwnerV1 {
    pub plan_id: String,
    pub plan_revision: u32,
    pub task_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LeaseStateV1 {
    Active,
    Idle,
    Evicted,
    Released,
}

/// Durable v1 resource lease. RSS fields are admission estimates/telemetry,
/// never a claim about physical unified-memory truth.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceLeaseV1 {
    pub schema_version: u32,
    pub lease_id: String,
    pub owner: ResourceLeaseOwnerV1,
    pub class: HeavyLeaseClass,
    pub plan_ir_class: PlanHeavyLeaseClass,
    pub profile_id: String,
    pub profile_digest: String,
    pub admitted_pressure_event_id: String,
    pub admitted_at_ms: i64,
    pub last_used_at_ms: i64,
    pub idle_since_ms: Option<i64>,
    pub idle_ttl_seconds: u64,
    pub state: LeaseStateV1,
    pub calibrated: bool,
    pub admission_rss_mib: u64,
    pub projected_controlled_rss_mib: u64,
    pub projected_host_headroom_mib: u64,
    pub task_max_peak_rss_mib: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskResourceBudgetV1 {
    pub max_peak_rss_mib: u64,
    pub max_subprocesses: u32,
    pub heavy_leases: BTreeSet<PlanHeavyLeaseClass>,
}

impl TaskResourceBudgetV1 {
    #[must_use]
    pub fn new(
        max_peak_rss_mib: u64,
        max_subprocesses: u32,
        heavy_leases: impl IntoIterator<Item = PlanHeavyLeaseClass>,
    ) -> Self {
        Self {
            max_peak_rss_mib,
            max_subprocesses,
            heavy_leases: heavy_leases.into_iter().collect(),
        }
    }

    #[must_use]
    pub fn permits(&self, class: HeavyLeaseClass) -> bool {
        self.heavy_leases.contains(&class.plan_ir_class())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConditionalLeaseContextV1 {
    pub small_incremental_index: bool,
    pub same_semantic_build_phase: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceLeaseRequestV1 {
    pub lease_id: String,
    pub owner: ResourceLeaseOwnerV1,
    pub class: HeavyLeaseClass,
    pub calibrated: bool,
    pub calibrated_p95_rss_mib: u64,
    pub evictable_idle_rss_mib: u64,
    pub task_budget: TaskResourceBudgetV1,
    pub conditional: ConditionalLeaseContextV1,
    pub automatic_reload: bool,
    pub disk_expanding: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AdmissionStatus {
    Admitted,
    Serialize,
    Cooldown,
    Deferred,
    Denied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResourcePolicyEventV1 {
    Admit {
        lease_id: String,
    },
    Serialize {
        requested: HeavyLeaseClass,
        conflicting_lease_ids: Vec<String>,
    },
    Cooldown {
        class: HeavyLeaseClass,
        retry_after_ms: i64,
    },
    Defer {
        class: HeavyLeaseClass,
        reason: String,
    },
    Deny {
        class: HeavyLeaseClass,
        reason: String,
    },
    MarkIdle {
        lease_id: String,
    },
    Touch {
        lease_id: String,
    },
    Evict {
        lease_id: String,
        class: HeavyLeaseClass,
    },
    Release {
        lease_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceAdmissionDecisionV1 {
    pub status: AdmissionStatus,
    pub lease: Option<ResourceLeaseV1>,
    pub event: ResourcePolicyEventV1,
    pub projected_controlled_rss_mib: u64,
    pub projected_host_headroom_mib: u64,
    pub parallel_job_cap: Option<u32>,
    pub subprocess_cap: u32,
}

#[derive(Debug, Clone, Default)]
struct CapabilityCycleState {
    last_evicted: Option<i64>,
    last_reloaded: Option<i64>,
    completed_cycles: VecDeque<i64>,
}

/// Durable per-capability oscillation history used to prevent unload/reload thrash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceCapabilityCycleSnapshotV1 {
    pub class: HeavyLeaseClass,
    pub last_evicted_at_ms: Option<i64>,
    pub last_reloaded_at_ms: Option<i64>,
    pub completed_cycle_at_ms: Vec<i64>,
}

/// Complete durable policy state required to resume M6 resource admission after restart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct M6ResourceGovernorSnapshotV1 {
    pub schema_version: u32,
    pub profile_id: String,
    pub profile_digest: String,
    pub active_leases: Vec<ResourceLeaseV1>,
    pub effective_band: PressureBand,
    pub green_stable_since_ms: Option<i64>,
    pub last_non_green_at_ms: Option<i64>,
    pub capability_cycles: Vec<ResourceCapabilityCycleSnapshotV1>,
}

/// Fail-closed validation error for durable governor restoration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceGovernorRestoreError {
    UnsupportedSchemaVersion(u32),
    ProfileMismatch,
    DuplicateLeaseId(String),
    InvalidLease {
        lease_id: String,
        reason: String,
    },
    InvalidPressureState(String),
    DuplicateCycleClass(HeavyLeaseClass),
    InvalidCycleState {
        class: HeavyLeaseClass,
        reason: String,
    },
    InconsistentLeasePair {
        left_lease_id: String,
        right_lease_id: String,
    },
}

impl Display for ResourceGovernorRestoreError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedSchemaVersion(version) => {
                write!(
                    formatter,
                    "unsupported resource governor snapshot schema {version}"
                )
            }
            Self::ProfileMismatch => {
                formatter.write_str("resource governor snapshot profile mismatch")
            }
            Self::DuplicateLeaseId(lease_id) => {
                write!(formatter, "duplicate resource lease id {lease_id}")
            }
            Self::InvalidLease { lease_id, reason } => {
                write!(formatter, "invalid resource lease {lease_id}: {reason}")
            }
            Self::InvalidPressureState(reason) => {
                write!(formatter, "invalid resource pressure state: {reason}")
            }
            Self::DuplicateCycleClass(class) => {
                write!(formatter, "duplicate resource cycle state for {class:?}")
            }
            Self::InvalidCycleState { class, reason } => {
                write!(
                    formatter,
                    "invalid resource cycle state for {class:?}: {reason}"
                )
            }
            Self::InconsistentLeasePair {
                left_lease_id,
                right_lease_id,
            } => write!(
                formatter,
                "resource leases {left_lease_id} and {right_lease_id} cannot coexist under profile"
            ),
        }
    }
}

impl Error for ResourceGovernorRestoreError {}

/// Pressure-aware M6 governor. It decides and records policy state only; the
/// Controller remains responsible for checkpointing, process unload/reload,
/// reaping, and durable event persistence.
#[derive(Debug, Clone)]
pub struct M6ResourceGovernor {
    profile: HardwareProfileV1,
    leases: BTreeMap<String, ResourceLeaseV1>,
    effective_band: PressureBand,
    green_stable_since_ms: Option<i64>,
    last_non_green_at_ms: Option<i64>,
    cycles: BTreeMap<HeavyLeaseClass, CapabilityCycleState>,
}

impl Default for M6ResourceGovernor {
    fn default() -> Self {
        Self::new(HardwareProfileV1::m1_8gb())
    }
}

impl M6ResourceGovernor {
    #[must_use]
    pub fn new(profile: HardwareProfileV1) -> Self {
        Self {
            profile,
            leases: BTreeMap::new(),
            effective_band: PressureBand::Green,
            green_stable_since_ms: None,
            last_non_green_at_ms: None,
            cycles: BTreeMap::new(),
        }
    }

    #[must_use]
    pub const fn profile(&self) -> &HardwareProfileV1 {
        &self.profile
    }

    pub fn active_leases(&self) -> impl Iterator<Item = &ResourceLeaseV1> {
        self.leases.values()
    }

    /// Captures all policy state required for deterministic restart recovery.
    #[must_use]
    pub fn snapshot(&self) -> M6ResourceGovernorSnapshotV1 {
        M6ResourceGovernorSnapshotV1 {
            schema_version: M6_RESOURCE_GOVERNOR_SNAPSHOT_SCHEMA_VERSION,
            profile_id: self.profile.profile_id.clone(),
            profile_digest: self.profile.digest(),
            active_leases: self.leases.values().cloned().collect(),
            effective_band: self.effective_band,
            green_stable_since_ms: self.green_stable_since_ms,
            last_non_green_at_ms: self.last_non_green_at_ms,
            capability_cycles: self
                .cycles
                .iter()
                .map(|(class, state)| ResourceCapabilityCycleSnapshotV1 {
                    class: *class,
                    last_evicted_at_ms: state.last_evicted,
                    last_reloaded_at_ms: state.last_reloaded,
                    completed_cycle_at_ms: state.completed_cycles.iter().copied().collect(),
                })
                .collect(),
        }
    }

    /// Restores a durable governor snapshot only when every persisted invariant
    /// still matches the supplied current hardware profile.
    ///
    /// # Errors
    /// Fails closed for schema/profile mismatch, malformed leases, impossible
    /// pressure hysteresis, duplicate identifiers/classes, or inconsistent
    /// pair/cycle state.
    pub fn restore(
        profile: HardwareProfileV1,
        snapshot: &M6ResourceGovernorSnapshotV1,
    ) -> Result<Self, ResourceGovernorRestoreError> {
        validate_snapshot_header(&profile, snapshot)?;
        validate_pressure_snapshot_state(snapshot)?;
        let leases = restore_leases(&profile, snapshot)?;
        let cycles = restore_cycles(snapshot)?;
        Ok(Self {
            profile,
            leases,
            effective_band: snapshot.effective_band,
            green_stable_since_ms: snapshot.green_stable_since_ms,
            last_non_green_at_ms: snapshot.last_non_green_at_ms,
            cycles,
        })
    }

    /// Applies 120-second healthy recovery hysteresis to one measured sample.
    pub fn observe_pressure(
        &mut self,
        snapshot: ResourcePressureSnapshotV1,
    ) -> ResourcePressureEventV1 {
        let raw_band = snapshot.classify(&self.profile);
        let effective_band = if raw_band == PressureBand::Green {
            let green_since = *self
                .green_stable_since_ms
                .get_or_insert(snapshot.observed_at_ms);
            let recovered = elapsed_ms(snapshot.observed_at_ms, green_since)
                >= seconds_to_ms(self.profile.heavy_lease_recovery_green_seconds);
            if self.last_non_green_at_ms.is_none() || recovered {
                PressureBand::Green
            } else {
                PressureBand::Guarded
            }
        } else {
            self.green_stable_since_ms = None;
            self.last_non_green_at_ms = Some(snapshot.observed_at_ms);
            raw_band
        };
        self.effective_band = effective_band;
        ResourcePressureEventV1 {
            schema_version: RESOURCE_PRESSURE_EVENT_SCHEMA_VERSION,
            event_id: pressure_event_id(snapshot, raw_band, effective_band),
            snapshot,
            raw_band,
            effective_band,
            green_stable_since_ms: self.green_stable_since_ms,
            last_non_green_at_ms: self.last_non_green_at_ms,
        }
    }

    /// Performs deterministic admission. Returned Serialize/Evict/Cooldown
    /// events are instructions for the Controller; this method never launches
    /// or kills a process.
    #[must_use]
    pub fn admit(
        &mut self,
        request: &ResourceLeaseRequestV1,
        pressure: &ResourcePressureEventV1,
    ) -> ResourceAdmissionDecisionV1 {
        let admission_rss_mib = self.admission_rss_mib(request);
        let projected_controlled_rss_mib = pressure
            .snapshot
            .controlled_working_set_mib
            .saturating_sub(request.evictable_idle_rss_mib)
            .saturating_add(admission_rss_mib);
        let incremental_rss_mib = admission_rss_mib.saturating_sub(request.evictable_idle_rss_mib);
        let projected_host_headroom_mib = pressure
            .snapshot
            .host_headroom_mib
            .saturating_sub(incremental_rss_mib);
        let (parallel_job_cap, subprocess_cap) = self.execution_caps(request, pressure);

        let decision = self.preflight_decision(
            request,
            pressure,
            admission_rss_mib,
            projected_controlled_rss_mib,
            projected_host_headroom_mib,
            subprocess_cap,
        );
        if let Some((status, event)) = decision {
            return ResourceAdmissionDecisionV1 {
                status,
                lease: None,
                event,
                projected_controlled_rss_mib,
                projected_host_headroom_mib,
                parallel_job_cap,
                subprocess_cap,
            };
        }

        let lease = ResourceLeaseV1 {
            schema_version: RESOURCE_LEASE_SCHEMA_VERSION,
            lease_id: request.lease_id.clone(),
            owner: request.owner.clone(),
            class: request.class,
            plan_ir_class: request.class.plan_ir_class(),
            profile_id: self.profile.profile_id.clone(),
            profile_digest: self.profile.digest(),
            admitted_pressure_event_id: pressure.event_id.clone(),
            admitted_at_ms: pressure.snapshot.observed_at_ms,
            last_used_at_ms: pressure.snapshot.observed_at_ms,
            idle_since_ms: None,
            idle_ttl_seconds: self.profile.idle_ttl_seconds(request.class),
            state: LeaseStateV1::Active,
            calibrated: request.calibrated,
            admission_rss_mib,
            projected_controlled_rss_mib,
            projected_host_headroom_mib,
            task_max_peak_rss_mib: request.task_budget.max_peak_rss_mib,
        };
        let reload_after_eviction = self.reload_after_eviction(request.class);
        self.leases.insert(request.lease_id.clone(), lease.clone());
        if reload_after_eviction {
            self.record_reload(request.class, pressure.snapshot.observed_at_ms);
        }
        ResourceAdmissionDecisionV1 {
            status: AdmissionStatus::Admitted,
            lease: Some(lease),
            event: ResourcePolicyEventV1::Admit {
                lease_id: request.lease_id.clone(),
            },
            projected_controlled_rss_mib,
            projected_host_headroom_mib,
            parallel_job_cap,
            subprocess_cap,
        }
    }

    fn preflight_decision(
        &self,
        request: &ResourceLeaseRequestV1,
        pressure: &ResourcePressureEventV1,
        admission_rss_mib: u64,
        projected_controlled_rss_mib: u64,
        projected_host_headroom_mib: u64,
        subprocess_cap: u32,
    ) -> Option<(AdmissionStatus, ResourcePolicyEventV1)> {
        self.request_constraint_decision(
            request,
            pressure,
            admission_rss_mib,
            projected_controlled_rss_mib,
            projected_host_headroom_mib,
            subprocess_cap,
        )
        .or_else(|| {
            self.pair_admission_decision(
                request,
                pressure,
                projected_controlled_rss_mib,
                projected_host_headroom_mib,
            )
        })
    }

    fn request_constraint_decision(
        &self,
        request: &ResourceLeaseRequestV1,
        pressure: &ResourcePressureEventV1,
        admission_rss_mib: u64,
        projected_controlled_rss_mib: u64,
        projected_host_headroom_mib: u64,
        subprocess_cap: u32,
    ) -> Option<(AdmissionStatus, ResourcePolicyEventV1)> {
        if request.lease_id.trim().is_empty() || self.leases.contains_key(&request.lease_id) {
            return Some(deny(request.class, "lease id is empty or already active"));
        }
        if !request.task_budget.permits(request.class) {
            return Some(deny(
                request.class,
                "task heavy-lease budget does not permit requested runtime class",
            ));
        }
        if subprocess_cap == 0 {
            return Some(deny(request.class, "task subprocess budget is zero"));
        }
        if pressure.effective_band == PressureBand::Emergency {
            return Some(defer(
                request.class,
                "emergency host pressure blocks new heavy admission",
            ));
        }
        if pressure.effective_band == PressureBand::Constrained {
            return Some(defer(
                request.class,
                "constrained host pressure blocks new heavy admission",
            ));
        }
        if request.disk_expanding
            && pressure
                .snapshot
                .host_free_disk_mib
                .is_some_and(|free| free < self.profile.minimum_host_free_disk_mib)
        {
            return Some(defer(
                request.class,
                "host free-disk reserve is below profile minimum",
            ));
        }
        if admission_rss_mib > request.task_budget.max_peak_rss_mib {
            return Some(deny(
                request.class,
                "requested lease estimate exceeds task max-RSS budget",
            ));
        }
        if projected_controlled_rss_mib > self.profile.normal_controlled_working_set_hard_mib {
            return Some(defer(
                request.class,
                "projected controlled RSS exceeds hard admission ceiling",
            ));
        }
        if projected_controlled_rss_mib > self.profile.normal_controlled_working_set_soft_mib
            && (!request.calibrated
                || !self.leases.is_empty()
                || pressure.raw_band != PressureBand::Green
                || pressure.effective_band != PressureBand::Green)
        {
            return Some(defer(
                request.class,
                "projected controlled RSS exceeds normal soft target without calibrated single-lease fit",
            ));
        }
        if projected_host_headroom_mib < self.profile.minimum_launch_headroom_soft_mib {
            return Some(defer(
                request.class,
                "projected host headroom is below launch reserve",
            ));
        }
        if self.reload_after_eviction(request.class)
            && let Some(decision) = self.reload_admission_decision(request.class, pressure)
        {
            return Some(decision);
        }
        None
    }

    fn pair_admission_decision(
        &self,
        request: &ResourceLeaseRequestV1,
        pressure: &ResourcePressureEventV1,
        projected_controlled_rss_mib: u64,
        projected_host_headroom_mib: u64,
    ) -> Option<(AdmissionStatus, ResourcePolicyEventV1)> {
        let mut conflicts = Vec::new();
        for active in self.leases.values() {
            match self.profile.pair_rule(active.class, request.class) {
                LeasePairRule::Safe => {}
                LeasePairRule::Forbidden => {
                    return Some(deny(
                        request.class,
                        "hardware profile forbids requested heavy pair",
                    ));
                }
                LeasePairRule::Serialize => conflicts.push(active.lease_id.clone()),
                LeasePairRule::Conditional => {
                    if !self.conditional_pair_is_safe(
                        active,
                        request,
                        pressure,
                        projected_controlled_rss_mib,
                        projected_host_headroom_mib,
                    ) {
                        conflicts.push(active.lease_id.clone());
                    }
                }
            }
        }
        if pressure.effective_band == PressureBand::Guarded && !self.leases.is_empty() {
            conflicts.extend(self.leases.keys().cloned());
        }
        conflicts.sort();
        conflicts.dedup();
        if conflicts.is_empty() {
            None
        } else {
            Some((
                AdmissionStatus::Serialize,
                ResourcePolicyEventV1::Serialize {
                    requested: request.class,
                    conflicting_lease_ids: conflicts,
                },
            ))
        }
    }

    fn conditional_pair_is_safe(
        &self,
        active: &ResourceLeaseV1,
        request: &ResourceLeaseRequestV1,
        pressure: &ResourcePressureEventV1,
        projected_controlled_rss_mib: u64,
        projected_host_headroom_mib: u64,
    ) -> bool {
        if pressure.raw_band != PressureBand::Green
            || pressure.effective_band != PressureBand::Green
            || pressure.snapshot.recent_pressure_event
            || !request.calibrated
            || !active.calibrated
            || projected_controlled_rss_mib > self.profile.normal_controlled_working_set_soft_mib
            || projected_host_headroom_mib < self.profile.minimum_launch_headroom_soft_mib
        {
            return false;
        }
        let model_indexer = matches!(
            (active.class, request.class),
            (HeavyLeaseClass::Model, HeavyLeaseClass::Indexer)
                | (HeavyLeaseClass::Indexer, HeavyLeaseClass::Model)
        );
        if model_indexer && !request.conditional.small_incremental_index {
            return false;
        }
        let embedder_indexer = matches!(
            (active.class, request.class),
            (HeavyLeaseClass::Embedder, HeavyLeaseClass::Indexer)
                | (HeavyLeaseClass::Indexer, HeavyLeaseClass::Embedder)
        );
        !embedder_indexer || request.conditional.same_semantic_build_phase
    }

    fn admission_rss_mib(&self, request: &ResourceLeaseRequestV1) -> u64 {
        if request.class == HeavyLeaseClass::Unknown
            || (request.class == HeavyLeaseClass::BuildHeavy && !request.calibrated)
        {
            request
                .calibrated_p95_rss_mib
                .max(self.profile.unknown_heavy_admission_mib)
        } else {
            request.calibrated_p95_rss_mib
        }
    }

    fn execution_caps(
        &self,
        request: &ResourceLeaseRequestV1,
        pressure: &ResourcePressureEventV1,
    ) -> (Option<u32>, u32) {
        let conservative = request.class == HeavyLeaseClass::Unknown
            || (request.class == HeavyLeaseClass::BuildHeavy && !request.calibrated);
        let subprocess_cap = if conservative {
            request
                .task_budget
                .max_subprocesses
                .min(self.profile.unknown_heavy_first_run_max_subprocesses)
        } else {
            request.task_budget.max_subprocesses
        };
        let parallel_job_cap = if conservative {
            Some(self.profile.unknown_heavy_first_run_max_jobs)
        } else if request.class == HeavyLeaseClass::BuildHeavy {
            let elevated_calibrated_parallelism = pressure.raw_band == PressureBand::Green
                && pressure.effective_band == PressureBand::Green
                && self.leases.values().all(|lease| {
                    !matches!(
                        lease.class,
                        HeavyLeaseClass::Model
                            | HeavyLeaseClass::Embedder
                            | HeavyLeaseClass::CdpBrowser
                            | HeavyLeaseClass::AdaptiveBrowser
                    )
                });
            Some(if elevated_calibrated_parallelism {
                self.profile.calibrated_build_max_jobs
            } else {
                self.profile.unknown_heavy_first_run_max_jobs
            })
        } else {
            None
        };
        (parallel_job_cap, subprocess_cap)
    }

    fn reload_after_eviction(&self, class: HeavyLeaseClass) -> bool {
        self.cycles.get(&class).is_some_and(|state| {
            state.last_evicted.is_some_and(|evicted_at| {
                state
                    .last_reloaded
                    .is_none_or(|reloaded_at| reloaded_at <= evicted_at)
            })
        })
    }

    fn reload_admission_decision(
        &self,
        class: HeavyLeaseClass,
        pressure: &ResourcePressureEventV1,
    ) -> Option<(AdmissionStatus, ResourcePolicyEventV1)> {
        let state = self.cycles.get(&class)?;
        let evicted_at = state.last_evicted?;
        let oscillation_window_ms =
            seconds_to_ms(self.profile.heavy_lease_oscillation_window_seconds);
        let completed_cycles_in_window = state
            .completed_cycles
            .iter()
            .filter(|completed_at| {
                elapsed_ms(pressure.snapshot.observed_at_ms, **completed_at)
                    <= oscillation_window_ms
            })
            .count();
        if completed_cycles_in_window > self.profile.max_completed_eviction_cycles_per_window {
            return Some(defer(
                class,
                "repeated evict/reload oscillation inside profile window",
            ));
        }
        let green_since = pressure.green_stable_since_ms?;
        if pressure.raw_band != PressureBand::Green {
            return Some((
                AdmissionStatus::Cooldown,
                ResourcePolicyEventV1::Cooldown {
                    class,
                    retry_after_ms: pressure
                        .snapshot
                        .observed_at_ms
                        .saturating_add(seconds_to_ms(
                            self.profile.heavy_lease_reload_cooldown_seconds,
                        )),
                },
            ));
        }
        let stable_from = evicted_at.max(green_since);
        let ready_at = stable_from.saturating_add(seconds_to_ms(
            self.profile.heavy_lease_reload_cooldown_seconds,
        ));
        (pressure.snapshot.observed_at_ms < ready_at).then_some((
            AdmissionStatus::Cooldown,
            ResourcePolicyEventV1::Cooldown {
                class,
                retry_after_ms: ready_at,
            },
        ))
    }

    pub fn mark_idle(&mut self, lease_id: &str, now_ms: i64) -> Option<ResourcePolicyEventV1> {
        let lease = self.leases.get_mut(lease_id)?;
        lease.state = LeaseStateV1::Idle;
        lease.idle_since_ms = Some(now_ms);
        Some(ResourcePolicyEventV1::MarkIdle {
            lease_id: lease_id.to_owned(),
        })
    }

    pub fn touch(&mut self, lease_id: &str, now_ms: i64) -> Option<ResourcePolicyEventV1> {
        let lease = self.leases.get_mut(lease_id)?;
        lease.state = LeaseStateV1::Active;
        lease.last_used_at_ms = now_ms;
        lease.idle_since_ms = None;
        Some(ResourcePolicyEventV1::Touch {
            lease_id: lease_id.to_owned(),
        })
    }

    /// Returns ordered idle/pressure eviction instructions without performing
    /// the process side effect or changing the lease table.
    #[must_use]
    pub fn eviction_decisions(
        &self,
        pressure: &ResourcePressureEventV1,
        now_ms: i64,
    ) -> Vec<ResourcePolicyEventV1> {
        let pressure_eviction = pressure.effective_band != PressureBand::Green;
        let mut candidates = self
            .leases
            .values()
            .filter(|lease| {
                if lease.state != LeaseStateV1::Idle {
                    return false;
                }
                pressure_eviction
                    || lease.idle_since_ms.is_some_and(|idle_since| {
                        elapsed_ms(now_ms, idle_since) >= seconds_to_ms(lease.idle_ttl_seconds)
                    })
            })
            .collect::<Vec<_>>();
        candidates.sort_by_key(|lease| (eviction_priority(lease.class), lease.lease_id.clone()));
        candidates
            .into_iter()
            .map(|lease| ResourcePolicyEventV1::Evict {
                lease_id: lease.lease_id.clone(),
                class: lease.class,
            })
            .collect()
    }

    /// Records a Controller-confirmed eviction and detects repeated
    /// evict/reload oscillation. A second completed cycle inside five minutes
    /// returns a defer event rather than encouraging another automatic reload.
    pub fn record_eviction(
        &mut self,
        lease_id: &str,
        now_ms: i64,
    ) -> Option<ResourcePolicyEventV1> {
        let mut lease = self.leases.remove(lease_id)?;
        lease.state = LeaseStateV1::Evicted;
        let state = self.cycles.entry(lease.class).or_default();
        prune_cycles(
            &mut state.completed_cycles,
            now_ms,
            self.profile.heavy_lease_oscillation_window_seconds,
        );
        if state.last_reloaded.is_some_and(|reloaded| {
            state.last_evicted.is_some() && reloaded > state.last_evicted.unwrap_or(i64::MIN)
        }) {
            state.completed_cycles.push_back(now_ms);
        }
        state.last_evicted = Some(now_ms);
        if state.completed_cycles.len() > self.profile.max_completed_eviction_cycles_per_window {
            return Some(ResourcePolicyEventV1::Defer {
                class: lease.class,
                reason: "repeated evict/reload oscillation inside profile window".to_owned(),
            });
        }
        Some(ResourcePolicyEventV1::Evict {
            lease_id: lease.lease_id,
            class: lease.class,
        })
    }

    pub fn release(&mut self, lease_id: &str) -> Option<ResourcePolicyEventV1> {
        let mut lease = self.leases.remove(lease_id)?;
        lease.state = LeaseStateV1::Released;
        Some(ResourcePolicyEventV1::Release {
            lease_id: lease.lease_id,
        })
    }

    fn record_reload(&mut self, class: HeavyLeaseClass, now_ms: i64) {
        self.cycles.entry(class).or_default().last_reloaded = Some(now_ms);
    }
}

fn validate_snapshot_header(
    profile: &HardwareProfileV1,
    snapshot: &M6ResourceGovernorSnapshotV1,
) -> Result<(), ResourceGovernorRestoreError> {
    if snapshot.schema_version != M6_RESOURCE_GOVERNOR_SNAPSHOT_SCHEMA_VERSION {
        return Err(ResourceGovernorRestoreError::UnsupportedSchemaVersion(
            snapshot.schema_version,
        ));
    }
    if snapshot.profile_id != profile.profile_id || snapshot.profile_digest != profile.digest() {
        return Err(ResourceGovernorRestoreError::ProfileMismatch);
    }
    Ok(())
}

fn validate_pressure_snapshot_state(
    snapshot: &M6ResourceGovernorSnapshotV1,
) -> Result<(), ResourceGovernorRestoreError> {
    if snapshot
        .green_stable_since_ms
        .is_some_and(|value| value < 0)
        || snapshot.last_non_green_at_ms.is_some_and(|value| value < 0)
    {
        return Err(ResourceGovernorRestoreError::InvalidPressureState(
            "hysteresis clocks cannot be negative".to_owned(),
        ));
    }
    if let (Some(green), Some(non_green)) = (
        snapshot.green_stable_since_ms,
        snapshot.last_non_green_at_ms,
    ) && green < non_green
    {
        return Err(ResourceGovernorRestoreError::InvalidPressureState(
            "green recovery cannot begin before the last non-green sample".to_owned(),
        ));
    }
    match snapshot.effective_band {
        PressureBand::Green => {
            if snapshot.last_non_green_at_ms.is_some() && snapshot.green_stable_since_ms.is_none() {
                return Err(ResourceGovernorRestoreError::InvalidPressureState(
                    "recovered green state is missing its green-stable clock".to_owned(),
                ));
            }
        }
        PressureBand::Guarded => {
            if snapshot.last_non_green_at_ms.is_none() {
                return Err(ResourceGovernorRestoreError::InvalidPressureState(
                    "guarded state is missing the last non-green clock".to_owned(),
                ));
            }
        }
        PressureBand::Constrained | PressureBand::Emergency => {
            if snapshot.last_non_green_at_ms.is_none() || snapshot.green_stable_since_ms.is_some() {
                return Err(ResourceGovernorRestoreError::InvalidPressureState(
                    "constrained/emergency state has inconsistent recovery clocks".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn restore_leases(
    profile: &HardwareProfileV1,
    snapshot: &M6ResourceGovernorSnapshotV1,
) -> Result<BTreeMap<String, ResourceLeaseV1>, ResourceGovernorRestoreError> {
    let mut leases = BTreeMap::new();
    for lease in &snapshot.active_leases {
        validate_restored_lease(profile, snapshot, lease)?;
        if leases
            .insert(lease.lease_id.clone(), lease.clone())
            .is_some()
        {
            return Err(ResourceGovernorRestoreError::DuplicateLeaseId(
                lease.lease_id.clone(),
            ));
        }
    }
    validate_restored_pairs(profile, leases.values().collect::<Vec<_>>().as_slice())?;
    Ok(leases)
}

fn validate_restored_lease(
    profile: &HardwareProfileV1,
    snapshot: &M6ResourceGovernorSnapshotV1,
    lease: &ResourceLeaseV1,
) -> Result<(), ResourceGovernorRestoreError> {
    let invalid = |reason: &str| ResourceGovernorRestoreError::InvalidLease {
        lease_id: lease.lease_id.clone(),
        reason: reason.to_owned(),
    };
    if lease.schema_version != RESOURCE_LEASE_SCHEMA_VERSION {
        return Err(invalid("unsupported lease schema version"));
    }
    if lease.lease_id.trim().is_empty() {
        return Err(invalid("lease id is empty"));
    }
    if lease.profile_id != snapshot.profile_id || lease.profile_digest != snapshot.profile_digest {
        return Err(invalid(
            "lease profile binding does not match snapshot profile",
        ));
    }
    if lease.plan_ir_class != lease.class.plan_ir_class() {
        return Err(invalid(
            "runtime class does not match Plan IR heavy-lease class",
        ));
    }
    if lease.idle_ttl_seconds != profile.idle_ttl_seconds(lease.class) {
        return Err(invalid("idle TTL does not match current hardware profile"));
    }
    if lease.admitted_pressure_event_id.trim().is_empty() {
        return Err(invalid("admitted pressure event id is empty"));
    }
    if lease.admitted_at_ms < 0
        || lease.last_used_at_ms < lease.admitted_at_ms
        || lease
            .idle_since_ms
            .is_some_and(|idle| idle < lease.last_used_at_ms)
    {
        return Err(invalid("lease timestamps are inconsistent"));
    }
    match lease.state {
        LeaseStateV1::Active if lease.idle_since_ms.is_none() => Ok(()),
        LeaseStateV1::Idle if lease.idle_since_ms.is_some() => Ok(()),
        LeaseStateV1::Active | LeaseStateV1::Idle => {
            Err(invalid("lease idle state and idle timestamp disagree"))
        }
        LeaseStateV1::Evicted | LeaseStateV1::Released => Err(invalid(
            "non-resident lease cannot appear in active lease snapshot",
        )),
    }
}

fn validate_restored_pairs(
    profile: &HardwareProfileV1,
    leases: &[&ResourceLeaseV1],
) -> Result<(), ResourceGovernorRestoreError> {
    for (left_index, left) in leases.iter().enumerate() {
        for right in &leases[left_index + 1..] {
            match profile.pair_rule(left.class, right.class) {
                LeasePairRule::Safe => {}
                // Conditional co-residency requires live Green pressure plus request-specific
                // predicates. Those proofs are not part of the durable lease snapshot, so a
                // calibrated pair alone can never authorize restore.
                LeasePairRule::Conditional
                | LeasePairRule::Serialize
                | LeasePairRule::Forbidden => {
                    return Err(ResourceGovernorRestoreError::InconsistentLeasePair {
                        left_lease_id: left.lease_id.clone(),
                        right_lease_id: right.lease_id.clone(),
                    });
                }
            }
        }
    }
    Ok(())
}

fn restore_cycles(
    snapshot: &M6ResourceGovernorSnapshotV1,
) -> Result<BTreeMap<HeavyLeaseClass, CapabilityCycleState>, ResourceGovernorRestoreError> {
    let mut cycles = BTreeMap::new();
    for persisted in &snapshot.capability_cycles {
        validate_cycle_snapshot(persisted)?;
        let state = CapabilityCycleState {
            last_evicted: persisted.last_evicted_at_ms,
            last_reloaded: persisted.last_reloaded_at_ms,
            completed_cycles: persisted.completed_cycle_at_ms.iter().copied().collect(),
        };
        if cycles.insert(persisted.class, state).is_some() {
            return Err(ResourceGovernorRestoreError::DuplicateCycleClass(
                persisted.class,
            ));
        }
    }
    Ok(cycles)
}

fn validate_cycle_snapshot(
    persisted: &ResourceCapabilityCycleSnapshotV1,
) -> Result<(), ResourceGovernorRestoreError> {
    let invalid = |reason: &str| ResourceGovernorRestoreError::InvalidCycleState {
        class: persisted.class,
        reason: reason.to_owned(),
    };
    if persisted.last_evicted_at_ms.is_some_and(|value| value < 0)
        || persisted.last_reloaded_at_ms.is_some_and(|value| value < 0)
        || persisted
            .completed_cycle_at_ms
            .iter()
            .any(|value| *value < 0)
    {
        return Err(invalid("cycle timestamps cannot be negative"));
    }
    if persisted
        .completed_cycle_at_ms
        .windows(2)
        .any(|window| window[0] > window[1])
    {
        return Err(invalid("completed cycle timestamps must be ordered"));
    }
    if !persisted.completed_cycle_at_ms.is_empty()
        && (persisted.last_evicted_at_ms.is_none() || persisted.last_reloaded_at_ms.is_none())
    {
        return Err(invalid(
            "completed cycles require both eviction and reload history",
        ));
    }
    if let (Some(last_completed), Some(last_evicted)) = (
        persisted.completed_cycle_at_ms.last(),
        persisted.last_evicted_at_ms,
    ) && *last_completed > last_evicted
    {
        return Err(invalid("completed cycle occurs after the last eviction"));
    }
    Ok(())
}

#[must_use]
fn deny(class: HeavyLeaseClass, reason: &str) -> (AdmissionStatus, ResourcePolicyEventV1) {
    (
        AdmissionStatus::Denied,
        ResourcePolicyEventV1::Deny {
            class,
            reason: reason.to_owned(),
        },
    )
}

#[must_use]
fn defer(class: HeavyLeaseClass, reason: &str) -> (AdmissionStatus, ResourcePolicyEventV1) {
    (
        AdmissionStatus::Deferred,
        ResourcePolicyEventV1::Defer {
            class,
            reason: reason.to_owned(),
        },
    )
}

fn pressure_event_id(
    snapshot: ResourcePressureSnapshotV1,
    raw_band: PressureBand,
    effective_band: PressureBand,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(snapshot.observed_at_ms.to_le_bytes());
    hasher.update(snapshot.controlled_working_set_mib.to_le_bytes());
    hasher.update(snapshot.host_headroom_mib.to_le_bytes());
    hasher.update(snapshot.swap_out_growth_mib_per_min.to_le_bytes());
    hasher.update(snapshot.compressor_growth_mib_per_min.to_le_bytes());
    hasher.update(format!("{raw_band:?}:{effective_band:?}"));
    let digest = format!("{:x}", hasher.finalize());
    format!("resource-pressure.{}", &digest[..20])
}

#[must_use]
const fn eviction_priority(class: HeavyLeaseClass) -> u8 {
    match class {
        HeavyLeaseClass::Embedder => 0,
        HeavyLeaseClass::CdpBrowser | HeavyLeaseClass::AdaptiveBrowser => 1,
        HeavyLeaseClass::Lsp => 2,
        HeavyLeaseClass::CodegraphWiki => 3,
        HeavyLeaseClass::Indexer => 4,
        HeavyLeaseClass::Model => 5,
        HeavyLeaseClass::BuildHeavy | HeavyLeaseClass::Unknown => 6,
    }
}

fn prune_cycles(cycles: &mut VecDeque<i64>, now_ms: i64, window_seconds: u64) {
    let window_ms = seconds_to_ms(window_seconds);
    while cycles
        .front()
        .is_some_and(|timestamp| elapsed_ms(now_ms, *timestamp) > window_ms)
    {
        let _ = cycles.pop_front();
    }
}

#[must_use]
fn seconds_to_ms(seconds: u64) -> i64 {
    i64::try_from(seconds.saturating_mul(1_000)).unwrap_or(i64::MAX)
}

#[must_use]
fn elapsed_ms(now_ms: i64, then_ms: i64) -> i64 {
    now_ms.saturating_sub(then_ms).max(0)
}
