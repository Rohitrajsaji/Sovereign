//! Versioned ownership boundaries for Sovereign's stable destination
//! interfaces.

use serde::{Deserialize, Serialize};

/// Semantic version of the interface-contract manifest format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractVersion {
    pub major: u16,
    pub minor: u16,
}

/// Crates that own stable destination interfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InterfaceOwner {
    #[serde(rename = "crates/sovereign-controller")]
    Controller,
    #[serde(rename = "crates/sovereign-plan")]
    Plan,
    #[serde(rename = "crates/sovereign-repo")]
    Repository,
    #[serde(rename = "crates/sovereign-context")]
    Context,
    #[serde(rename = "crates/sovereign-model")]
    Model,
    #[serde(rename = "crates/sovereign-tools")]
    Tools,
    #[serde(rename = "crates/sovereign-evidence")]
    Evidence,
    #[serde(rename = "crates/sovereign-state")]
    State,
    #[serde(rename = "crates/sovereign-policy")]
    Policy,
    #[serde(rename = "crates/sovereign-memory")]
    Memory,
}

/// Stable destination interface names frozen by roadmap `1.4-frozen`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StableInterface {
    Controller,
    TaskStateMachine,
    AttemptStateMachine,
    Scheduler,
    PlanCompiler,
    PlanValidator,
    RepositoryIntelligence,
    ContextPlanner,
    ModelBackend,
    ToolAdapter,
    AuthorizedAction,
    EvidenceStore,
    EvidenceCompressor,
    Verifier,
    CheckpointManager,
    RecoveryManager,
    ResourceGovernor,
    MemoryManager,
    RoleRegistry,
    SkillRegistry,
    SecretBroker,
    ExternalIntelligenceGateway,
}

/// One stable interface ownership contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceContract {
    pub interface: StableInterface,
    pub owner: InterfaceOwner,
    pub introduced_by: String,
    pub extended_by: Vec<String>,
    pub invariant: String,
}

/// One forbidden crate-dependency direction encoded by the foundation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyRule {
    pub subject: String,
    pub must_not_depend_on: Vec<String>,
    pub rationale: String,
}

/// Machine-readable stable interface and dependency contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceContractManifest {
    pub schema: String,
    pub contract_version: ContractVersion,
    pub stable_interface_contracts: Vec<InterfaceContract>,
    pub forbidden_dependency_rules: Vec<DependencyRule>,
}
