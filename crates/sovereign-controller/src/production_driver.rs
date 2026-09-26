//! One Controller-owned advancement step over the canonical goal, plan, and task records.
//! The caller supplies capabilities and bounded context; it never selects a task or interprets a
//! Plan. Each consequential operation remains delegated to the existing governed Controller API.

use serde::{Deserialize, Serialize};
use serde_json::json;
use sovereign_context::{
    ContextBudget, ContextMode, ContextPacket, ContextPacketInput, ContextPlanner, EvidenceItem,
};
use sovereign_model::{
    BackendHealth, ModelBackend, ModelCapabilities, ModelError, ModelLease, ModelLoadProfile,
    ModelRequest, ModelResidencyProof, ModelResponse,
};
use sovereign_plan::{PlanCompilationInput, PlanCompiler, PlanValidator};
use sovereign_policy::{ExecutionIsolationBackend, ModelCallBudget, PolicyError};
use sovereign_repo::{ExactRetriever, ProjectRegistry};
use sovereign_state::{
    NewJournalEvent, StateRecordCasAssertion, StateRecordCasMutation, StateStore,
};
use sovereign_tools::browser::{BrowserActionReceipt, BrowserAdapterConfig};
use sovereign_tools::{ToolManifest, ToolSchemaV1};
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Mutex;

use super::goal_runner::{
    GOAL_REASON_CANCELLED_BY_USER, GOAL_REASON_COMPILATION_BUDGET_EXHAUSTED,
    GOAL_REASON_COMPILATION_FAILED, GOAL_REASON_TASK_FAILED, GoalOutcomeKindV1,
};
use super::{
    Controller, ControllerError, ExecutionRuntime, GoalIntentV1, ReadinessInputs, TaskState,
    digest_json, required_array, required_str, sha256_prefixed,
};

const COMPILATION_BUDGET_NAMESPACE: &str = "controller.goal_compilation_budget";
const COMPILATION_BUDGET_SCHEMA_VERSION: u32 = 1;
const MAX_PRODUCTION_TASK_CONTRACT_BYTES: usize = 3_000;

fn required_from(
    value: &serde_json::Value,
    pointer: &str,
) -> Result<serde_json::Value, ControllerError> {
    value
        .pointer(pointer)
        .cloned()
        .ok_or_else(|| ControllerError::InvalidPlan(format!("task contract is missing {pointer}")))
}

/// Resources for one exact queued goal. The Controller checks every binding against the durable
/// intent before invoking the compiler and reserves each provider call in `SQLite` before dispatch.
pub struct ProductionCompilationResources<'a> {
    pub input: &'a PlanCompilationInput,
    pub backend: &'a dyn ModelBackend,
    pub validator: &'a PlanValidator,
    pub compiler_version: &'a str,
    pub model_budget: &'a mut ModelCallBudget,
}

/// Execution capabilities and a bounded task context. The Controller chooses the task and its
/// existing governed execution API; these values do not grant new Plan authority.
pub struct ProductionExecutionResources<'a, I: ExecutionIsolationBackend> {
    pub runtime: &'a ExecutionRuntime<'a, I>,
    pub context: &'a ContextPacket,
    pub tool_schemas: &'a [ToolSchemaV1],
    pub readiness: ReadinessInputs<'a>,
    pub model_budget: &'a mut ModelCallBudget,
}

/// Exact caller-owned browser process capability. The Controller selects the task, launch
/// contract, action sequence, and managed generations from the validated active Plan.
pub struct ProductionBrowserResources<'a> {
    pub tool_manifest: &'a ToolManifest,
    pub chrome_path: &'a Path,
    pub adapter_config: BrowserAdapterConfig,
}

/// Pinned alternatives supplied without knowing which task the Controller will choose.
/// The Controller selects the matching manifest only after inspecting its own active task.
pub struct ProductionExecutionCatalog<'a> {
    pub read_tool_manifest: &'a ToolManifest,
    pub process_tool_manifest: &'a ToolManifest,
    pub browser: Option<ProductionBrowserResources<'a>>,
}

/// Optional capability inputs for one step. Completion and finalization need neither model nor
/// execution runtime, while a queued goal needs only compilation resources.
pub struct ProductionAdvanceResources<'a, I: ExecutionIsolationBackend> {
    pub compilation: Option<ProductionCompilationResources<'a>>,
    pub execution: Option<ProductionExecutionResources<'a, I>>,
}

impl<I: ExecutionIsolationBackend> Default for ProductionAdvanceResources<'_, I> {
    fn default() -> Self {
        Self {
            compilation: None,
            execution: None,
        }
    }
}

/// A reason for stopping without guessing a missing permission, context, or recovery result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProductionBlockReason {
    CompilationInputRequired,
    CompilationFailed(String),
    CompilationBudgetExhausted,
    ExecutionInputsRequired,
    BrowserHandoffRequired,
    FailedTerminal,
    NoRunnableTask,
    Readiness(String),
}

/// One step's typed result. Repeated calls use only canonical SQLite/Controller state; there is
/// no separate driver cursor, task queue, or task-state shadow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProductionAdvanceOutcome {
    Idle,
    Paused,
    RecoveryRequired,
    AwaitingApproval {
        action_id: String,
        request_id: String,
    },
    Blocked {
        task_id: Option<String>,
        reason: ProductionBlockReason,
    },
    PlanActivated {
        goal_id: String,
        plan_id: String,
    },
    TaskVerified {
        task_id: String,
    },
    TaskFailed {
        task_id: String,
    },
    GoalCompleted {
        goal_id: String,
    },
    Complete {
        goal_id: String,
    },
    /// The goal ended as failed and its plan, if any, was retired. The queue moves on.
    GoalFailed {
        goal_id: String,
        reason_code: String,
    },
    /// The goal ended as cancelled and its plan, if any, was retired. The queue moves on.
    GoalCancelled {
        goal_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompilationBudgetRecord {
    schema_version: u32,
    goal_id: String,
    goal_statement_digest: String,
    compilation_input_digest: String,
    compiler_version: String,
    max_model_calls: u32,
    calls_used: u32,
}

impl Controller {
    /// Builds a bounded exact-file context for the Controller-selected task. The caller supplies
    /// only the task ID returned by the typed driver; Plan contents remain Controller-owned.
    ///
    /// # Errors
    /// Rejects a missing or stale Controller-selected task and invalid bounded source context.
    #[expect(
        clippy::too_many_lines,
        reason = "bounded task context includes all scoped source and evidence checks"
    )]
    pub fn production_task_context(
        &self,
        registry: &ProjectRegistry,
        task_id: &str,
    ) -> Result<ContextPacket, ControllerError> {
        let active = self.active_ref()?;
        let task = active.tasks.get(task_id).ok_or_else(|| {
            ControllerError::NotReady(format!("unknown Controller-selected task {task_id}"))
        })?;
        let browser = task
            .task
            .get("browser_acceptance")
            .is_some_and(|value| !value.is_null());
        let non_write = !Self::task_has_repository_mutation_authority(&task.task)?;
        let contract = if browser || non_write {
            format!(
                "Controller-selected task {task_id}; validated contract digest {}. Execution authority and actions remain in the Controller.",
                digest_json(&task.task)?,
            )
        } else {
            let required = |pointer: &str| {
                task.task.pointer(pointer).cloned().ok_or_else(|| {
                    ControllerError::InvalidPlan(format!("task contract lacks {pointer}"))
                })
            };
            let criteria = required_array(&task.task, "/acceptance_criteria")?
                .iter()
                .map(|criterion| {
                    Ok(json!({
                        "criterion_id": required_from(criterion, "/criterion_id")?,
                        "description": required_from(criterion, "/description")?,
                        "kind": required_from(criterion, "/kind")?,
                        "evidence_type": required_from(criterion, "/evidence_type")?,
                        "required": required_from(criterion, "/required")?,
                    }))
                })
                .collect::<Result<Vec<_>, ControllerError>>()?;
            let verification_steps = required_array(&task.task, "/verification/steps")?
                .iter()
                .map(|step| {
                    Ok(json!({
                        "step_id": required_from(step, "/step_id")?,
                        "kind": required_from(step, "/kind")?,
                        "evidence_type": required_from(step, "/evidence_type")?,
                    }))
                })
                .collect::<Result<Vec<_>, ControllerError>>()?;
            let tools = required_array(&task.task, "/tools")?
                .iter()
                .map(|tool| {
                    Ok(json!({
                        "id": required_from(tool, "/id")?,
                        "version": required_from(tool, "/version")?,
                        "digest": required_from(tool, "/digest")?,
                    }))
                })
                .collect::<Result<Vec<_>, ControllerError>>()?;
            serde_json::to_string(&json!({
                "task_id": task_id,
                "title": required("/title")?,
                "objective": required("/objective")?,
                "rationale": required("/rationale")?,
                "expected_change": required("/implementation_contract/outputs")?,
                "permissions": required("/permissions")?,
                "tools": tools,
                "scope": {
                    "repositories": active.task_repository_ids(task_id)?,
                    "files": required("/scope/files")?,
                    "allow_create": required("/scope/allow_create")?,
                    "write_roots": required("/action_policy/write_roots")?,
                },
                "acceptance_criteria": criteria,
                "verification": {
                    "required_evidence_types": required("/verification/required_evidence_types")?,
                    "steps": verification_steps,
                },
                "note": "Controller enforces the full immutable Plan contract; this is its bounded model-facing summary."
            }))?
        };
        if contract.len() > MAX_PRODUCTION_TASK_CONTRACT_BYTES {
            return Err(ControllerError::NotReady(
                "task exceeds the bounded production contract byte ceiling".to_owned(),
            ));
        }
        let files = required_array(&task.task, "/scope/files")?;
        if files.len() > 16 {
            return Err(ControllerError::NotReady(
                "task file scope exceeds bounded context retrieval".to_owned(),
            ));
        }
        let repositories = active.task_repository_ids(task_id)?;
        let mut candidates = Vec::new();
        if repositories.len() == 1 && !browser && !non_write {
            let repository_id = &repositories[0];
            let root = &registry
                .repository(repository_id)
                .ok_or_else(|| {
                    ControllerError::NotReady("task repository is not registered".to_owned())
                })?
                .root;
            let retriever = ExactRetriever::new(registry);
            for value in files {
                let relative = value.as_str().ok_or_else(|| {
                    ControllerError::InvalidPlan("task file scope has a non-path".to_owned())
                })?;
                let path = Path::new(relative);
                if path.is_absolute()
                    || relative
                        .split('/')
                        .any(|part| part == ".." || part == ".sovereign")
                {
                    return Err(ControllerError::NotReady(
                        "task file scope contains an unsafe path".to_owned(),
                    ));
                }
                let metadata = match std::fs::symlink_metadata(root.join(path)) {
                    Ok(metadata) => metadata,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(error) => return Err(error.into()),
                };
                if !metadata.is_file() || metadata.len() > 32_768 {
                    return Err(ControllerError::NotReady(format!(
                        "task source {relative} is not a bounded regular file",
                    )));
                }
                let exact = retriever.read_path(repository_id, path, None)?;
                candidates.push(EvidenceItem::from_exact_file(
                    &exact,
                    "Controller-selected current task source",
                ));
            }
        }
        ContextPlanner::default().build(
            ContextMode::Implementation, ContextBudget::m1_8k(),
            ContextPacketInput {
                controller_prefix: "Sovereign local offline execution; only Controller-authorized actions are available.".to_owned(),
                task_contract: contract,
                current_state: format!("Controller-selected task {task_id}; source evidence has exact current repository digests."),
                authorized_tool_schemas: Vec::new(), candidates,
                output_schema: "Use the exact Controller-selected task contract and governed tool schema.".to_owned(),
            },
        ).map_err(|error| ControllerError::NotReady(format!("bounded task context: {error}")))
    }

    /// Advances at most one canonical lifecycle stage. This is the production composition point
    /// for queued compilation, task execution, goal completion, and finalization. On restart, the
    /// caller must recover the Controller first; this method then reconciles queued-goal claims
    /// before choosing from current durable state.
    ///
    /// # Errors
    /// Fails closed for malformed/stale durable state and errors that cannot be represented as a
    /// safe typed stop. No unknown consequential action is redispatched.
    #[allow(clippy::too_many_lines)]
    pub fn advance_production_goal<I: ExecutionIsolationBackend>(
        &mut self,
        registry: &ProjectRegistry,
        resources: ProductionAdvanceResources<'_, I>,
    ) -> Result<ProductionAdvanceOutcome, ControllerError> {
        self.advance_production_goal_with_catalog(registry, resources, None)
    }

    /// Advances through the same durable driver with exact pinned read/browser alternatives.
    /// This keeps task-kind and authority selection inside Controller-owned code.
    ///
    /// # Errors
    /// Propagates fail-closed compilation, dispatch, verification, and recovery failures.
    #[expect(
        clippy::too_many_lines,
        reason = "production driver owns one durable task transition per call"
    )]
    pub fn advance_production_goal_with_catalog<I: ExecutionIsolationBackend>(
        &mut self,
        registry: &ProjectRegistry,
        resources: ProductionAdvanceResources<'_, I>,
        catalog: Option<&ProductionExecutionCatalog<'_>>,
    ) -> Result<ProductionAdvanceOutcome, ControllerError> {
        self.reconcile_queued_goal_lifecycle()?;
        if self.execution_control()?.paused {
            return Ok(ProductionAdvanceOutcome::Paused);
        }
        if self.any_unresolved_action()? {
            return Ok(ProductionAdvanceOutcome::RecoveryRequired);
        }

        if let Some(active) = self.active.as_ref() {
            if super::goal_runner::plan_has_durable_goal_intent(&self.state, &active.plan_document)?
            {
                let browser_grant = super::goal_runner::durable_browser_grant_for_plan(
                    &self.state,
                    &active.plan_document,
                )?;
                self.permission_context = if browser_grant.is_some() {
                    super::PermissionContext::for_durable_goal_browser_grant()
                } else {
                    super::PermissionContext::m1_local_autonomous()
                };
            }
        } else {
            self.permission_context = super::PermissionContext::m1_local_autonomous();
        }

        if self.active.is_none() {
            let Some(intent) = self.next_queued_goal_intent()? else {
                return Ok(ProductionAdvanceOutcome::Idle);
            };
            let Some(compilation) = resources.compilation else {
                return Ok(ProductionAdvanceOutcome::Blocked {
                    task_id: None,
                    reason: ProductionBlockReason::CompilationInputRequired,
                });
            };
            return self.advance_queued_compilation(intent, compilation, registry);
        }

        let goal_id = self.active_ref()?.goal_id.clone();
        if self.completion_record()?.is_some() {
            return match self.finalize_completed_active_plan() {
                Ok(_) => Ok(ProductionAdvanceOutcome::Complete { goal_id }),
                Err(ControllerError::NotReady(reason)) => Ok(ProductionAdvanceOutcome::Blocked {
                    task_id: None,
                    reason: ProductionBlockReason::Readiness(reason),
                }),
                Err(error) => Err(error),
            };
        }

        let active = self.active_ref()?;
        if active
            .tasks
            .values()
            .all(|task| task.state == TaskState::Succeeded)
        {
            return match self.complete_queued_goal_intent(registry) {
                Ok(_) => Ok(ProductionAdvanceOutcome::GoalCompleted { goal_id }),
                Err(ControllerError::NotReady(reason)) => Ok(ProductionAdvanceOutcome::Blocked {
                    task_id: None,
                    reason: ProductionBlockReason::Readiness(reason),
                }),
                Err(error) => Err(error),
            };
        }
        if super::goal_runner::plan_has_durable_goal_intent(&self.state, &active.plan_document)?
            && self.active_plan_cancellation_requested()?
        {
            // A cancelled goal must not wait on a question nobody will answer.
            for request_id in self.pending_approval_request_ids_for_active_plan()? {
                self.respond_to_approval(
                    &request_id,
                    super::ApprovalDecisionV1::Deny,
                    "sovereign@cancellation",
                )?;
            }
            return self.end_active_goal(
                &goal_id,
                GoalOutcomeKindV1::Cancelled,
                GOAL_REASON_CANCELLED_BY_USER,
                "Cancelled while in progress.",
            );
        }
        if active.tasks.values().any(|task| {
            matches!(
                task.state,
                TaskState::ReconcilingUnknown | TaskState::Running | TaskState::Verifying
            )
        }) {
            return Ok(ProductionAdvanceOutcome::RecoveryRequired);
        }

        let mut task_id = None;
        for (candidate_id, task) in &active.tasks {
            if !matches!(
                task.state,
                TaskState::Planned | TaskState::RepairPending | TaskState::DeferredResource
            ) {
                continue;
            }
            let dependencies = required_array(&task.task, "/dependencies")?;
            if dependencies.iter().all(|dependency| {
                dependency.as_str().is_some_and(|id| {
                    active
                        .tasks
                        .get(id)
                        .is_some_and(|upstream| upstream.state == TaskState::Succeeded)
                })
            }) {
                task_id = Some(candidate_id.clone());
                break;
            }
        }
        let Some(task_id) = task_id else {
            let failed_task = active
                .tasks
                .iter()
                .find(|(_, task)| task.state == TaskState::FailedTerminal)
                .map(|(task_id, _)| task_id.clone());
            if let Some(failed_task) = failed_task {
                if super::goal_runner::plan_has_durable_goal_intent(
                    &self.state,
                    &active.plan_document,
                )? {
                    return self.end_active_goal(
                        &goal_id,
                        GoalOutcomeKindV1::Failed,
                        GOAL_REASON_TASK_FAILED,
                        &format!(
                            "Step {failed_task} failed and could not be repaired automatically."
                        ),
                    );
                }
                return Ok(ProductionAdvanceOutcome::Blocked {
                    task_id: None,
                    reason: ProductionBlockReason::FailedTerminal,
                });
            }
            return Ok(ProductionAdvanceOutcome::Blocked {
                task_id: None,
                reason: ProductionBlockReason::NoRunnableTask,
            });
        };
        let task = self.active_ref()?.tasks.get(&task_id).ok_or_else(|| {
            ControllerError::InvalidPlan("selected Controller task disappeared".to_owned())
        })?;
        let task_state = task.state;
        let permissions = required_array(&task.task, "/permissions")?;
        let browser = permissions
            .iter()
            .any(|permission| permission.as_str() == Some("browser_interactive"))
            || task
                .task
                .get("browser_acceptance")
                .is_some_and(|value| !value.is_null());
        let integration = self.task_is_multi_repo_integration_gate(&task_id)?;
        let non_write = !Self::task_has_repository_mutation_authority(&task.task)?;
        let literal = required_array(&task.task, "/verification/steps")?
            .iter()
            .any(|step| {
                required_str(step, "/evaluator").ok() == Some("builtin.diff.scope_and_literal.v1")
            });
        let Some(execution) = resources.execution else {
            return Ok(ProductionAdvanceOutcome::Blocked {
                task_id: Some(task_id),
                reason: ProductionBlockReason::ExecutionInputsRequired,
            });
        };
        if !std::ptr::eq(execution.runtime.registry, registry) {
            return Err(ControllerError::InvalidPlan(
                "production runtime registry must be the exact driver registry".to_owned(),
            ));
        }

        let executed = if browser {
            let Some(browser_resources) = catalog.and_then(|catalog| catalog.browser.as_ref())
            else {
                return Ok(ProductionAdvanceOutcome::Blocked {
                    task_id: Some(task_id),
                    reason: ProductionBlockReason::ExecutionInputsRequired,
                });
            };
            let read_process_manifest = catalog.map(|catalog| catalog.read_tool_manifest);
            let process_tool_manifest = if read_process_manifest.is_some_and(|manifest| {
                required_array(&task.task, "/tools").is_ok_and(|tools| {
                    tools.iter().any(|tool| {
                        required_str(tool, "/id").ok() == Some(manifest.tool_id.as_str())
                            && required_str(tool, "/version").ok()
                                == Some(manifest.version.as_str())
                            && required_str(tool, "/digest").ok()
                                == Some(manifest.content_digest.as_str())
                    })
                })
            }) {
                read_process_manifest.ok_or_else(|| {
                    ControllerError::NotReady(
                        "browser execution requires its exact read/process tool pin".to_owned(),
                    )
                })?
            } else {
                execution.runtime.tool_manifest
            };
            let runtime = ExecutionRuntime {
                registry: execution.runtime.registry,
                backend: execution.runtime.backend,
                command_policy: execution.runtime.command_policy,
                isolation_backend: execution.runtime.isolation_backend,
                isolation_request: execution.runtime.isolation_request,
                artifacts: execution.runtime.artifacts,
                tool_manifest: process_tool_manifest,
                python_executable: execution.runtime.python_executable,
            };
            let browser_execution = ProductionExecutionResources {
                runtime: &runtime,
                context: execution.context,
                tool_schemas: execution.tool_schemas,
                readiness: execution.readiness,
                model_budget: execution.model_budget,
            };
            self.execute_production_browser_task(
                registry,
                &task_id,
                &browser_execution,
                browser_resources,
            )
        } else if task_state == TaskState::RepairPending {
            if non_write || integration {
                return Ok(ProductionAdvanceOutcome::Blocked {
                    task_id: Some(task_id),
                    reason: ProductionBlockReason::Readiness(
                        "non-write repair requires recovery classification".to_owned(),
                    ),
                });
            }
            let repair_tool_schemas = execution
                .tool_schemas
                .iter()
                .filter(|schema| {
                    schema.tool_id == execution.runtime.tool_manifest.tool_id
                        && schema.version == execution.runtime.tool_manifest.version
                        && schema.content_digest == execution.runtime.tool_manifest.content_digest
                })
                .cloned()
                .collect::<Vec<_>>();
            if literal {
                self.repair_replace(
                    &task_id,
                    execution.runtime,
                    execution.context,
                    &repair_tool_schemas,
                    execution.readiness,
                    execution.model_budget,
                )
                .map(|_| ())
            } else {
                self.repair_repository_with_model(
                    &task_id,
                    execution.runtime,
                    execution.context,
                    &repair_tool_schemas,
                    execution.readiness,
                    execution.model_budget,
                )
                .map(|_| ())
            }
        } else if integration {
            let selected_runtime = catalog.map(|catalog| ExecutionRuntime {
                registry: execution.runtime.registry,
                backend: execution.runtime.backend,
                command_policy: execution.runtime.command_policy,
                isolation_backend: execution.runtime.isolation_backend,
                isolation_request: execution.runtime.isolation_request,
                artifacts: execution.runtime.artifacts,
                tool_manifest: catalog.process_tool_manifest,
                python_executable: execution.runtime.python_executable,
            });
            let runtime = selected_runtime.as_ref().unwrap_or(execution.runtime);
            self.derive_integration_gate_lease(
                registry,
                &task_id,
                execution.readiness,
                runtime.tool_manifest,
            )
            .and_then(|lease| self.execute_integration_gate(lease, runtime))
            .map(|_| ())
        } else if non_write {
            let selected_runtime = catalog.map(|catalog| ExecutionRuntime {
                registry: execution.runtime.registry,
                backend: execution.runtime.backend,
                command_policy: execution.runtime.command_policy,
                isolation_backend: execution.runtime.isolation_backend,
                isolation_request: execution.runtime.isolation_request,
                artifacts: execution.runtime.artifacts,
                tool_manifest: catalog.read_tool_manifest,
                python_executable: execution.runtime.python_executable,
            });
            let runtime = selected_runtime.as_ref().unwrap_or(execution.runtime);
            self.derive_non_write_task_lease(
                registry,
                &task_id,
                execution.readiness,
                runtime.tool_manifest,
            )
            .and_then(|lease| self.execute_non_write_task(lease, runtime))
            .map(|_| ())
        } else {
            self.derive_ready_lease(
                registry,
                &task_id,
                execution.readiness,
                execution.runtime.tool_manifest,
            )
            .and_then(|lease| {
                if literal {
                    self.execute_replace(
                        lease,
                        execution.runtime,
                        execution.context,
                        execution.model_budget,
                    )
                } else {
                    self.execute_repository_with_model(
                        lease,
                        execution.runtime,
                        execution.context,
                        execution.model_budget,
                    )
                }
            })
            .map(|_| ())
        };
        match executed {
            Ok(()) => {
                super::recovery_test_hook("after_production_task_verified");
                Ok(ProductionAdvanceOutcome::TaskVerified { task_id })
            }
            Err(ControllerError::AwaitingApproval {
                action_id,
                request_id,
            }) => Ok(ProductionAdvanceOutcome::AwaitingApproval {
                action_id,
                request_id,
            }),
            Err(ControllerError::UnknownAction(_)) => {
                Ok(ProductionAdvanceOutcome::RecoveryRequired)
            }
            Err(ControllerError::NotReady(reason)) => {
                if self.any_unresolved_action()? {
                    Ok(ProductionAdvanceOutcome::RecoveryRequired)
                } else {
                    Ok(ProductionAdvanceOutcome::Blocked {
                        task_id: Some(task_id),
                        reason: ProductionBlockReason::Readiness(reason),
                    })
                }
            }
            Err(ControllerError::Policy(PolicyError::ResourceDenied(reason))) => {
                Ok(ProductionAdvanceOutcome::Blocked {
                    task_id: Some(task_id),
                    reason: ProductionBlockReason::Readiness(reason),
                })
            }
            Err(ControllerError::ExecutionFailed(_) | ControllerError::VerificationFailed(_)) => {
                Ok(ProductionAdvanceOutcome::TaskFailed { task_id })
            }
            Err(error) => Err(error),
        }
    }

    fn execute_production_browser_task<I: ExecutionIsolationBackend>(
        &mut self,
        registry: &ProjectRegistry,
        task_id: &str,
        execution: &ProductionExecutionResources<'_, I>,
        browser: &ProductionBrowserResources<'_>,
    ) -> Result<(), ControllerError> {
        let ready = self.derive_browser_ready_lease(
            registry,
            task_id,
            execution.readiness,
            browser.tool_manifest,
            browser.adapter_config.clone(),
        )?;
        let mut session = self.acquire_browser_session_from_ready_lease(
            ready,
            registry,
            browser.tool_manifest,
            execution.runtime.backend,
            browser.chrome_path,
            browser.adapter_config.clone(),
        )?;
        let result = self.execute_production_browser_session(
            &mut session,
            execution.runtime,
            browser.tool_manifest,
        );
        match result {
            Ok(receipts) => self
                .complete_browser_verification_task(session, execution.runtime, &receipts)
                .map(|_| ()),
            Err(error) => {
                self.shutdown_browser_session(session)?;
                Err(error)
            }
        }
    }

    fn execute_production_browser_session<I: ExecutionIsolationBackend>(
        &mut self,
        session: &mut super::ControllerBrowserSession,
        runtime: &ExecutionRuntime<'_, I>,
        browser_manifest: &ToolManifest,
    ) -> Result<Vec<BrowserActionReceipt>, ControllerError> {
        self.bind_plan_browser_semantics(session)?;
        let actions = self.plan_browser_actions_for_session(session)?;
        let mut receipts = Vec::with_capacity(actions.len());
        let mut generation = 0;
        let mut app = None;
        for planned in actions {
            if generation != planned.generation {
                if let Some(mut previous) = app.take() {
                    self.stop_managed_loopback_app(session, runtime, &mut previous)?;
                }
                let next =
                    self.start_plan_managed_loopback_app(session, runtime, planned.generation)?;
                generation = planned.generation;
                app = Some(next);
            }
            match self.execute_browser_action(
                session,
                browser_manifest,
                runtime.artifacts,
                &planned.action,
            ) {
                Ok(receipt) => receipts.push(receipt),
                Err(error) => {
                    if let Some(mut current) = app.take() {
                        self.stop_managed_loopback_app(session, runtime, &mut current)?;
                    }
                    return Err(error);
                }
            }
        }
        if let Some(mut current) = app {
            self.stop_managed_loopback_app(session, runtime, &mut current)?;
        }
        Ok(receipts)
    }

    #[expect(
        clippy::too_many_lines,
        clippy::needless_pass_by_value,
        reason = "compilation binds the owned durable goal to one exact revision"
    )]
    fn advance_queued_compilation(
        &mut self,
        intent: GoalIntentV1,
        compilation: ProductionCompilationResources<'_>,
        registry: &ProjectRegistry,
    ) -> Result<ProductionAdvanceOutcome, ControllerError> {
        let input = compilation.input;
        if input.goal_id != intent.goal_id || input.goal_statement != intent.natural_language_goal {
            return Err(ControllerError::InvalidPlan(
                "production compilation input is not bound to exact queued goal".to_owned(),
            ));
        }
        let input_digest = digest_json(&serde_json::to_value(input)?)?;
        let binding = CompilationBudgetRecord {
            schema_version: COMPILATION_BUDGET_SCHEMA_VERSION,
            goal_id: intent.goal_id.clone(),
            goal_statement_digest: sha256_prefixed(intent.natural_language_goal.as_bytes()),
            compilation_input_digest: input_digest,
            compiler_version: compilation.compiler_version.to_owned(),
            max_model_calls: u32::from(input.max_model_calls),
            calls_used: 0,
        };
        if compilation_budget_exhausted(&self.state, &binding)? {
            return self.end_queued_goal_as_failed(
                &intent.goal_id,
                GOAL_REASON_COMPILATION_BUDGET_EXHAUSTED,
                "Sovereign could not turn this request into a plan after every allowed attempt.",
            );
        }
        let calls_before = compilation_calls_used(&self.state, &binding)?;
        let result = {
            let backend = ReservedCompilationBackend {
                backend: compilation.backend,
                state: Mutex::new(&mut self.state),
                binding,
            };
            let compiler = PlanCompiler::new(
                &backend,
                compilation.validator,
                compilation.compiler_version,
            )
            .map_err(|error| ControllerError::InvalidPlan(error.to_string()))?;
            compiler.compile(input, compilation.model_budget)
        };
        let plan = match result {
            Ok(plan) => plan,
            Err(error) => {
                let expected = CompilationBudgetRecord {
                    schema_version: COMPILATION_BUDGET_SCHEMA_VERSION,
                    goal_id: intent.goal_id.clone(),
                    goal_statement_digest: sha256_prefixed(intent.natural_language_goal.as_bytes()),
                    compilation_input_digest: digest_json(&serde_json::to_value(input)?)?,
                    compiler_version: compilation.compiler_version.to_owned(),
                    max_model_calls: u32::from(input.max_model_calls),
                    calls_used: 0,
                };
                if compilation_budget_exhausted(&self.state, &expected)? {
                    return self.end_queued_goal_as_failed(
                        &intent.goal_id,
                        GOAL_REASON_COMPILATION_BUDGET_EXHAUSTED,
                        &format!(
                            "Sovereign could not turn this request into a plan after every allowed attempt. Last error: {error}"
                        ),
                    );
                }
                // A failure that consumed no model call is deterministic for this input and
                // would repeat forever, so it ends the goal. A failure that consumed a call can
                // succeed on the next attempt, so the goal stays queued for the remaining budget.
                if compilation_calls_used(&self.state, &expected)? == calls_before {
                    return self.end_queued_goal_as_failed(
                        &intent.goal_id,
                        GOAL_REASON_COMPILATION_FAILED,
                        &format!("Sovereign could not plan this request: {error}"),
                    );
                }
                return Ok(ProductionAdvanceOutcome::Blocked {
                    task_id: None,
                    reason: ProductionBlockReason::CompilationFailed(error.to_string()),
                });
            }
        };
        super::recovery_test_hook("after_goal_compilation_before_claim");
        let plan = if let Some(grant) = intent.browser_grant.as_ref() {
            let browser = sovereign_tools::canonical_browser_tool_manifest();
            let pin = serde_json::json!({
                "id": browser.tool_id,
                "version": browser.version,
                "digest": browser.content_digest,
            });
            let port = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?
                .local_addr()?
                .port();
            let grant_digest = digest_json(&serde_json::to_value(grant)?)?;
            plan.bind_goal_granted_loopback_browser_acceptance(
                compilation.validator,
                &pin,
                port,
                4 * 1024 * 1024,
                &grant_digest,
                &grant.acceptance,
            )
            .map_err(|error| ControllerError::InvalidPlan(error.to_string()))?
        } else {
            plan
        };
        self.permission_context = if intent.browser_grant.is_some() {
            super::PermissionContext::for_durable_goal_browser_grant()
        } else {
            super::PermissionContext::m1_local_autonomous()
        };
        let activation = match self.activate_queued_goal_intent(&intent.goal_id, plan, registry) {
            Ok(activation) => activation,
            Err(error) => {
                self.permission_context = super::PermissionContext::m1_local_autonomous();
                return Err(error);
            }
        };
        Ok(ProductionAdvanceOutcome::PlanActivated {
            goal_id: intent.goal_id,
            plan_id: activation.plan_id,
        })
    }
}

impl Controller {
    /// Ends the active goal and maps a still-busy precondition to a readiness block.
    fn end_active_goal(
        &mut self,
        goal_id: &str,
        kind: GoalOutcomeKindV1,
        reason_code: &str,
        detail: &str,
    ) -> Result<ProductionAdvanceOutcome, ControllerError> {
        match self.abandon_active_goal(kind, reason_code, detail) {
            Ok(_) => Ok(match kind {
                GoalOutcomeKindV1::Failed => ProductionAdvanceOutcome::GoalFailed {
                    goal_id: goal_id.to_owned(),
                    reason_code: reason_code.to_owned(),
                },
                GoalOutcomeKindV1::Cancelled => ProductionAdvanceOutcome::GoalCancelled {
                    goal_id: goal_id.to_owned(),
                },
            }),
            Err(ControllerError::NotReady(reason)) => Ok(ProductionAdvanceOutcome::Blocked {
                task_id: None,
                reason: ProductionBlockReason::Readiness(reason),
            }),
            Err(error) => Err(error),
        }
    }

    fn end_queued_goal_as_failed(
        &mut self,
        goal_id: &str,
        reason_code: &str,
        detail: &str,
    ) -> Result<ProductionAdvanceOutcome, ControllerError> {
        self.fail_queued_goal_intent(goal_id, reason_code, detail)?;
        Ok(ProductionAdvanceOutcome::GoalFailed {
            goal_id: goal_id.to_owned(),
            reason_code: reason_code.to_owned(),
        })
    }
}

/// Model calls already charged to this goal's compilation budget.
fn compilation_calls_used(
    state: &StateStore,
    expected: &CompilationBudgetRecord,
) -> Result<u32, ControllerError> {
    let Some(row) = state
        .state_records(COMPILATION_BUDGET_NAMESPACE)?
        .into_iter()
        .find(|row| row.key == expected.goal_id)
    else {
        return Ok(0);
    };
    let current: CompilationBudgetRecord = serde_json::from_str(&row.value_json)?;
    validate_compilation_budget_binding(&current, expected)?;
    Ok(current.calls_used)
}

fn compilation_budget_exhausted(
    state: &StateStore,
    expected: &CompilationBudgetRecord,
) -> Result<bool, ControllerError> {
    let Some(row) = state
        .state_records(COMPILATION_BUDGET_NAMESPACE)?
        .into_iter()
        .find(|row| row.key == expected.goal_id)
    else {
        return Ok(false);
    };
    let current: CompilationBudgetRecord = serde_json::from_str(&row.value_json)?;
    validate_compilation_budget_binding(&current, expected)?;
    validate_compilation_budget_history(state, &current, row.version)?;
    Ok(current.calls_used >= current.max_model_calls)
}

fn validate_compilation_budget_history(
    state: &StateStore,
    record: &CompilationBudgetRecord,
    version: i64,
) -> Result<(), ControllerError> {
    if i64::from(record.calls_used) != version {
        return Err(ControllerError::InvalidPlan(
            "compilation budget version does not match reserved call count".to_owned(),
        ));
    }
    let mut ordinals = BTreeSet::new();
    for event in state.journal()?.into_iter().filter(|event| {
        event.entity_id == record.goal_id
            && event.event_kind == "goal_compilation_model_call_reserved"
    }) {
        let payload: serde_json::Value = serde_json::from_str(&event.payload_json)?;
        let ordinal = payload
            .get("call_ordinal")
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| u32::try_from(value).ok());
        if payload.get("goal_id").and_then(serde_json::Value::as_str)
            != Some(record.goal_id.as_str())
            || payload
                .get("compilation_input_digest")
                .and_then(serde_json::Value::as_str)
                != Some(record.compilation_input_digest.as_str())
            || payload
                .get("max_model_calls")
                .and_then(serde_json::Value::as_u64)
                != Some(u64::from(record.max_model_calls))
            || !ordinal.is_some_and(|ordinal| ordinal > 0 && ordinals.insert(ordinal))
        {
            return Err(ControllerError::InvalidPlan(
                "compilation budget journal event is malformed or conflicting".to_owned(),
            ));
        }
    }
    if ordinals != (1..=record.calls_used).collect() {
        return Err(ControllerError::InvalidPlan(
            "compilation budget is not backed by exact call reservation events".to_owned(),
        ));
    }
    Ok(())
}

fn validate_compilation_budget_binding(
    current: &CompilationBudgetRecord,
    expected: &CompilationBudgetRecord,
) -> Result<(), ControllerError> {
    if current.schema_version != COMPILATION_BUDGET_SCHEMA_VERSION
        || current.goal_id != expected.goal_id
        || current.goal_statement_digest != expected.goal_statement_digest
        || current.compilation_input_digest != expected.compilation_input_digest
        || current.compiler_version != expected.compiler_version
        || current.max_model_calls != expected.max_model_calls
        || current.calls_used > current.max_model_calls
    {
        return Err(ControllerError::InvalidPlan(
            "durable queued-goal compilation budget binding drifted".to_owned(),
        ));
    }
    Ok(())
}

struct ReservedCompilationBackend<'a> {
    backend: &'a dyn ModelBackend,
    state: Mutex<&'a mut StateStore>,
    binding: CompilationBudgetRecord,
}

impl ReservedCompilationBackend<'_> {
    fn reserve_call(&self) -> Result<(), ControllerError> {
        let mut state = self.state.lock().map_err(|_| {
            ControllerError::InvalidPlan("compilation budget lock poisoned".to_owned())
        })?;
        let intent_row = state
            .state_records("controller.goal_intent")?
            .into_iter()
            .find(|row| row.key == self.binding.goal_id)
            .ok_or_else(|| {
                ControllerError::InvalidPlan(
                    "queued goal disappeared during compilation".to_owned(),
                )
            })?;
        let intent: GoalIntentV1 = serde_json::from_str(&intent_row.value_json)?;
        if intent.status != "queued_for_plan_compilation"
            || sha256_prefixed(intent.natural_language_goal.as_bytes())
                != self.binding.goal_statement_digest
        {
            return Err(ControllerError::NotReady(
                "queued goal changed during compilation".to_owned(),
            ));
        }
        let existing = state
            .state_records(COMPILATION_BUDGET_NAMESPACE)?
            .into_iter()
            .find(|row| row.key == self.binding.goal_id);
        let (version, mut next) = if let Some(row) = existing.as_ref() {
            let current: CompilationBudgetRecord = serde_json::from_str(&row.value_json)?;
            validate_compilation_budget_binding(&current, &self.binding)?;
            validate_compilation_budget_history(&state, &current, row.version)?;
            (Some(row.version), current)
        } else {
            (None, self.binding.clone())
        };
        if next.calls_used >= next.max_model_calls {
            return Err(ControllerError::NotReady(
                "durable compilation model-call budget exhausted".to_owned(),
            ));
        }
        next.calls_used += 1;
        let value_json = serde_json::to_string(&next)?;
        let payload_json = json!({
            "goal_id": next.goal_id,
            "compilation_input_digest": next.compilation_input_digest,
            "call_ordinal": next.calls_used,
            "max_model_calls": next.max_model_calls,
        })
        .to_string();
        let event_seed =
            sha256_prefixed(format!("{}\0{}", next.goal_id, next.calls_used).as_bytes());
        let event_id = format!("controller.{}", &event_seed[7..27]);
        let journal_tail = state.latest_journal_sequence()?;
        state.compare_and_apply_state_records_with_events_guarded(
            Some(journal_tail),
            &[StateRecordCasAssertion {
                namespace: "controller.goal_intent",
                key: &self.binding.goal_id,
                expected_version: intent_row.version,
                expected_value_json: Some(&intent_row.value_json),
                expected_value_digest: None,
            }],
            &[StateRecordCasMutation {
                namespace: COMPILATION_BUDGET_NAMESPACE,
                key: &self.binding.goal_id,
                expected_version: version,
                value_json: Some(&value_json),
            }],
            &[NewJournalEvent {
                event_id: &event_id,
                entity_type: "controller",
                entity_id: &self.binding.goal_id,
                event_kind: "goal_compilation_model_call_reserved",
                payload_json: &payload_json,
            }],
        )?;
        Ok(())
    }
}

impl ModelBackend for ReservedCompilationBackend<'_> {
    fn capabilities(&self) -> ModelCapabilities {
        self.backend.capabilities()
    }
    fn load(&self, profile: ModelLoadProfile) -> Result<ModelLease, ModelError> {
        self.backend.load(profile)
    }
    fn complete(&self, request: &ModelRequest) -> Result<ModelResponse, ModelError> {
        self.reserve_call()
            .map_err(|error| ModelError::LeaseUnavailable(error.to_string()))?;
        self.backend.complete(request)
    }
    fn count_tokens(&self, content: &str) -> Result<u32, ModelError> {
        self.backend.count_tokens(content)
    }
    fn health(&self) -> Result<BackendHealth, ModelError> {
        self.backend.health()
    }
    fn residency_proof(&self) -> Result<ModelResidencyProof, ModelError> {
        self.backend.residency_proof()
    }
    fn unload(&self) -> Result<(), ModelError> {
        self.backend.unload()
    }
}
