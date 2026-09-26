//! Actor-backed Control API dispatch. The UI never writes `SQLite`.
//! Callers: `main.rs` `serve` and `e2e_server`.
//! API: `handle_actor_request`.
//! Schema: `schemas/control-api-v2.json`.
//! User instruction: verify the consumer plan and execute only what is genuinely missing.

use crate::actor::{ControllerActorHandle, Reply};
use crate::control_api::ControlApiRequest;
use crate::{app_data, doctor, goal_views, model_assets, projections, projects};
use serde::Serialize;
use serde_json::{Value, json};
use sovereign_controller::ApprovalDecisionV1;
use sovereign_state::StateStore;
use std::path::{Path, PathBuf};

/// Serializes an applied command, or explains in plain words that it is queued behind the
/// current step.
fn reply_json<T: Serialize>(reply: Reply<T>, queued_message: &str) -> Result<Value, String> {
    match reply {
        Reply::Applied(value) => serde_json::to_value(value).map_err(|error| error.to_string()),
        Reply::Queued { ticket } => Ok(json!({
            "accepted": true,
            "applied": false,
            "ticket": ticket,
            "message": queued_message,
        })),
    }
}

/// Request views for the current project, including commands still waiting to apply.
fn current_goal_views(
    actor: &ControllerActorHandle,
) -> Result<Vec<goal_views::GoalViewV1>, String> {
    let model = actor.read_model()?;
    let store = actor.open_state()?;
    let outcomes = sovereign_controller::goal_outcomes(&store).map_err(|e| e.to_string())?;
    let status = actor.service_status();
    let pending = actor.pending_commands();
    Ok(goal_views::goal_views(
        &model,
        &outcomes,
        &goal_views::ServiceFacts {
            status: &status,
            working: actor.working(),
            paused: model.status.execution_control.paused,
            pending: &pending,
        },
    ))
}

/// Plan ids a goal was bound to, from its claim and outcome records.
fn goal_plan_ids(store: &StateStore, goal_id: &str) -> Result<Vec<String>, String> {
    let mut plan_ids = Vec::new();
    if let Some(raw) = store
        .get_state("controller.goal_intent_claim", goal_id)
        .map_err(|e| e.to_string())?
        && let Ok(claim) = serde_json::from_str::<Value>(&raw)
        && let Some(plan_id) = claim.get("plan_id").and_then(Value::as_str)
    {
        plan_ids.push(plan_id.to_owned());
    }
    Ok(plan_ids)
}

pub(crate) fn artifact_response(
    path: &Path,
    digest: &str,
    offset: u64,
    length: usize,
) -> Result<Value, String> {
    let store = StateStore::open(path).map_err(|error| error.to_string())?;
    let cas = path.parent().unwrap_or(Path::new(".")).join("cas");
    let artifacts =
        sovereign_evidence::ArtifactStore::open(&cas).map_err(|error| error.to_string())?;
    match projections::read_artifact_text(&artifacts, &store, digest, offset, length) {
        Ok(read) => serde_json::to_value(read).map_err(|error| error.to_string()),
        Err(error) => Err(format!("not found: {error}")),
    }
}

pub(crate) fn download_model_response(confirmation: Option<&str>) -> Result<Value, String> {
    if confirmation.is_none() {
        return Err("download without the confirmation token is rejected".to_owned());
    }
    Err("model download is disabled because the committed manifest has no URL".to_owned())
}

#[expect(clippy::too_many_lines, reason = "v2 dispatch is an explicit match")]
pub(crate) fn handle_actor_request(
    actor: &ControllerActorHandle,
    request: ControlApiRequest,
) -> Result<Value, String> {
    match request {
        ControlApiRequest::Dashboard => {
            Err("dashboard route is served as static read-only content".to_owned())
        }
        ControlApiRequest::ReadModel => actor
            .read_model()
            .and_then(|view| serde_json::to_value(view).map_err(|e| e.to_string())),
        ControlApiRequest::SubmitGoal { goal } => reply_json(
            actor.submit_goal(goal)?,
            "Got it. Sovereign will add this request as soon as the current step finishes.",
        ),
        ControlApiRequest::Pause { reason } => reply_json(
            actor.pause(reason)?,
            "Sovereign will pause as soon as the current step finishes.",
        ),
        ControlApiRequest::Resume => reply_json(
            actor.resume()?,
            "Sovereign will resume as soon as the current step finishes.",
        ),
        ControlApiRequest::CancelGoal { goal_id, principal } => reply_json(
            actor.cancel_goal(goal_id, principal)?,
            "Stopping. The current work was interrupted and the request will show as cancelled in a moment.",
        ),
        ControlApiRequest::RespondToApproval {
            request_id,
            decision,
            principal,
        } => {
            let decision = match decision.as_str() {
                "approve" => ApprovalDecisionV1::Approve,
                "deny" => ApprovalDecisionV1::Deny,
                _ => return Err("approval decision must be `approve` or `deny`".to_owned()),
            };
            reply_json(
                actor.respond_to_approval(request_id, decision, principal)?,
                "Your answer is recorded and applies as soon as the current step finishes.",
            )
        }
        ControlApiRequest::Session => Ok(serde_json::json!({"authenticated": true})),
        ControlApiRequest::Doctor => {
            let settings = app_data::AppData::open_default()
                .and_then(|data| data.load_settings())
                .unwrap_or_default();
            let model = settings.model_path.as_deref().map(Path::new);
            let runtime = settings.model_runtime.as_deref().map(Path::new);
            let checks = doctor::doctor_checks(model, runtime);
            serde_json::to_value(checks).map_err(|e| e.to_string())
        }
        ControlApiRequest::Overview => {
            let model = actor.read_model()?;
            let service = actor.service_status();
            let phase = if model.recovery.mutation_blocked {
                "recovery_blocked"
            } else if model.status.execution_control.paused {
                "paused"
            } else {
                service.phase.as_str()
            };
            let active_project = app_data::AppData::open_default()
                .and_then(|d| d.load_projects())
                .ok()
                .and_then(|p| p.active_project_id);
            let (residency, pressure) = actor.open_state().ok().map_or_else(
                || ("unknown".to_owned(), "unknown".to_owned()),
                |store| {
                    (
                        projections::model_residency_label(&store),
                        projections::pressure_band_label(&store),
                    )
                },
            );
            Ok(serde_json::json!({
                "schema_version": 1,
                "service_phase": phase,
                "active_project": active_project,
                "paused": model.status.execution_control.paused,
                "detail": service.detail,
                "last_outcome": service.last_outcome,
                "model_residency": residency,
                "pressure_band": pressure,
                "goal_count": model.status.goal_intents.len(),
                "approval_count": model.blocked_approvals.len() + model.pending_approvals.len(),
                "unknown_action_count": model.recovery.unknown_action_ids.len(),
                "blocked_approvals": model.blocked_approvals,
                "working": actor.working(),
                "pending_commands": actor.pending_commands(),
            }))
        }
        ControlApiRequest::ListProjects => {
            let projects = app_data::AppData::open_default()
                .and_then(|d| d.load_projects())
                .unwrap_or_default();
            serde_json::to_value(projects).map_err(|e| e.to_string())
        }
        ControlApiRequest::AddProject { root, display_name } => {
            let data = app_data::AppData::open_default().map_err(|e| e.to_string())?;
            let projects = projects::register_project(&data, Path::new(&root), &display_name)?;
            if let Some(record) = projects::active_record(&projects) {
                let _ = actor.switch_project(
                    PathBuf::from(&record.state_path),
                    Some(PathBuf::from(&record.root)),
                )?;
            }
            serde_json::to_value(projects).map_err(|e| e.to_string())
        }
        ControlApiRequest::ActivateProject { project_id } => {
            let data = app_data::AppData::open_default().map_err(|e| e.to_string())?;
            let mut projects = data.load_projects().unwrap_or_default();
            let Some(target) = projects
                .projects
                .iter()
                .find(|p| p.project_id == project_id)
            else {
                return Err(format!("unknown project id {project_id}"));
            };
            let _ = actor.switch_project(
                PathBuf::from(&target.state_path),
                Some(PathBuf::from(&target.root)),
            )?;
            projects.active_project_id = Some(project_id);
            data.save_projects(&projects).map_err(|e| e.to_string())?;
            serde_json::to_value(projects).map_err(|e| e.to_string())
        }
        ControlApiRequest::ListGoals => {
            let views = current_goal_views(actor)?;
            serde_json::to_value(views).map_err(|e| e.to_string())
        }
        ControlApiRequest::GetGoal { goal_id } => {
            let model = actor.read_model()?;
            let view = current_goal_views(actor)?
                .into_iter()
                .find(|view| view.goal_id == goal_id)
                .ok_or_else(|| format!("not found: unknown goal {goal_id}"))?;
            projections::goal_detail(&model, &view)
                .ok_or_else(|| format!("not found: unknown goal {goal_id}"))
        }
        ControlApiRequest::GetGoalActivity { goal_id } => {
            let store = actor.open_state()?;
            let plan_ids = goal_plan_ids(&store, &goal_id)?;
            let events = store.journal().map_err(|e| e.to_string())?;
            serde_json::to_value(goal_views::goal_activity(&events, &goal_id, &plan_ids))
                .map_err(|e| e.to_string())
        }
        ControlApiRequest::ListEvents { after, limit } => {
            let store = actor.open_state()?;
            let events = store.journal_after(after).map_err(|e| e.to_string())?;
            let projected = projections::project_events(&events, after, limit);
            serde_json::to_value(projected).map_err(|e| e.to_string())
        }
        ControlApiRequest::GetRecovery => {
            let model = actor.read_model()?;
            let explanation = projections::explain_recovery(&model.recovery);
            serde_json::to_value(json!({
                "recovery": model.recovery,
                "explanation": explanation,
            }))
            .map_err(|e| e.to_string())
        }
        ControlApiRequest::VerifyModel {
            runtime_path,
            model_path,
        } => {
            let result =
                model_assets::verify_model_paths(Path::new(&runtime_path), Path::new(&model_path))?;
            if result.ok
                && let Ok(data) = app_data::AppData::open_default()
            {
                let mut settings = data.load_settings().unwrap_or_default();
                settings.model_runtime = Some(runtime_path);
                settings.model_path = Some(model_path);
                let _ = data.save_settings(&settings);
            }
            serde_json::to_value(result).map_err(|e| e.to_string())
        }
        ControlApiRequest::GetSettings => {
            let settings = app_data::AppData::open_default()
                .and_then(|data| data.load_settings())
                .unwrap_or_default();
            serde_json::to_value(settings).map_err(|e| e.to_string())
        }
        ControlApiRequest::SaveSettings {
            approval_principal,
            chrome_path,
            node_path,
            execute_on_start,
        } => {
            let data = app_data::AppData::open_default().map_err(|e| e.to_string())?;
            let mut settings = data.load_settings().unwrap_or_default();
            if let Some(principal) = approval_principal {
                settings.approval_principal = principal;
            }
            if let Some(path) = chrome_path {
                settings.chrome_path = Some(path);
            }
            if let Some(path) = node_path {
                settings.node_path = Some(path);
            }
            if let Some(execute) = execute_on_start {
                settings.execute_on_start = execute;
            }
            data.save_settings(&settings).map_err(|e| e.to_string())?;
            serde_json::to_value(settings).map_err(|e| e.to_string())
        }
        ControlApiRequest::EventStream { .. } => {
            Err("event stream is served by the HTTP layer".to_owned())
        }
        ControlApiRequest::GetArtifact {
            digest,
            offset,
            length,
        } => artifact_response(&actor.state_path(), &digest, offset, length),
        ControlApiRequest::GetTaskDiff { key } => {
            let model = actor.read_model()?;
            projections::task_diff_from_status(&model.status.tasks, &key)
                .ok_or_else(|| format!("not found: no diff for task {key}"))
                .map(|diff| serde_json::json!({"task_id": key, "diff": diff}))
        }
        ControlApiRequest::GetApproval { request_id } => {
            let model = actor.read_model()?;
            model
                .pending_approvals
                .iter()
                .chain(model.blocked_approvals.iter())
                .find(|item| item.request_id == request_id)
                .ok_or_else(|| format!("not found: approval {request_id}"))
                .and_then(|item| serde_json::to_value(item).map_err(|e| e.to_string()))
        }
        ControlApiRequest::DownloadModel { confirmation } => {
            download_model_response(confirmation.as_deref())
        }
    }
}
