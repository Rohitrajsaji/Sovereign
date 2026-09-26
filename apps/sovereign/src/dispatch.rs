//! Actor-backed Control API dispatch. The UI never writes `SQLite`.
//! Callers: `main.rs` `serve` and `e2e_server`.
//! API: `handle_actor_request`.
//! Schema: `schemas/control-api-v2.json`.
//! User instruction: verify the consumer plan and execute only what is genuinely missing.

use crate::actor::ControllerActorHandle;
use crate::control_api::ControlApiRequest;
use crate::{app_data, doctor, model_assets, projections, projects};
use serde_json::{Value, json};
use sovereign_controller::ApprovalDecisionV1;
use sovereign_state::StateStore;
use std::path::{Path, PathBuf};

const STATE_DB_ENV: &str = "SOVEREIGN_STATE_DB";

pub(crate) fn artifact_response(digest: &str, offset: u64, length: usize) -> Result<Value, String> {
    let path = std::env::var_os(STATE_DB_ENV)
        .map_or_else(|| PathBuf::from(".sovereign/state.sqlite3"), PathBuf::from);
    let store = StateStore::open(&path).map_err(|error| error.to_string())?;
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
        ControlApiRequest::SubmitGoal { goal } => actor
            .submit_goal(goal)
            .and_then(|intent| serde_json::to_value(intent).map_err(|e| e.to_string())),
        ControlApiRequest::Pause { reason } => actor
            .pause(reason)
            .and_then(|control| serde_json::to_value(control).map_err(|e| e.to_string())),
        ControlApiRequest::Resume => actor
            .resume()
            .and_then(|control| serde_json::to_value(control).map_err(|e| e.to_string())),
        ControlApiRequest::CancelGoal { goal_id, principal } => actor
            .cancel_goal(goal_id, principal)
            .and_then(|intent| serde_json::to_value(intent).map_err(|e| e.to_string())),
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
            actor
                .respond_to_approval(request_id, decision, principal)
                .and_then(|request| serde_json::to_value(request).map_err(|e| e.to_string()))
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
            let service = actor.service_status().unwrap_or_default();
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
            let path = std::env::var_os(STATE_DB_ENV)
                .map_or_else(|| PathBuf::from(".sovereign/state.sqlite3"), PathBuf::from);
            let residency = StateStore::open(&path).ok().map_or_else(
                || "unknown".to_owned(),
                |store| projections::model_residency_label(&store),
            );
            let pressure = StateStore::open(&path).ok().map_or_else(
                || "unknown".to_owned(),
                |store| projections::pressure_band_label(&store),
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
                actor.switch_project(
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
            actor.switch_project(
                PathBuf::from(&target.state_path),
                Some(PathBuf::from(&target.root)),
            )?;
            projects.active_project_id = Some(project_id);
            data.save_projects(&projects).map_err(|e| e.to_string())?;
            serde_json::to_value(projects).map_err(|e| e.to_string())
        }
        ControlApiRequest::ListGoals => {
            let model = actor.read_model()?;
            serde_json::to_value(&model.status.goal_intents).map_err(|e| e.to_string())
        }
        ControlApiRequest::GetGoal { goal_id } => {
            let model = actor.read_model()?;
            projections::goal_detail(&model, &goal_id)
                .ok_or_else(|| format!("unknown goal {goal_id}"))
        }
        ControlApiRequest::ListEvents { after, limit } => {
            let store = StateStore::open(
                std::env::var_os(STATE_DB_ENV)
                    .map_or_else(|| PathBuf::from(".sovereign/state.sqlite3"), PathBuf::from),
            )
            .map_err(|e| e.to_string())?;
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
        } => artifact_response(&digest, offset, length),
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
