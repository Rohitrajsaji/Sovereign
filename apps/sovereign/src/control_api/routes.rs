//! Explicit Control API route table. Unknown routes fail closed.
//! Callers: `parse.rs` (`parse_request`) and `server.rs`.
//! API: `parse_control_request`.
//! Schema: `schemas/control-api-v2.json`.
//! User instruction: implement the attached consumer product plan (CX-T03, CX-T12).

use super::parse::{
    HttpEnvelope, optional_string, parse_json_object, parse_optional_json_object, query_i64,
    query_usize, require_empty_body, require_only_fields, required_string,
};
use super::{ApiError, ApiStatus, ControlApiRequest};

#[expect(
    clippy::too_many_lines,
    reason = "route table is intentionally explicit"
)]
pub(crate) fn parse_control_request(
    info: &HttpEnvelope,
    bytes: &[u8],
) -> Result<ControlApiRequest, ApiError> {
    let body = &bytes[info.header_end..info.header_end.saturating_add(info.content_length)];

    match (info.method.as_str(), info.path.as_str()) {
        ("GET", "/" | "/dashboard") => {
            require_empty_body(body)?;
            Ok(ControlApiRequest::Dashboard)
        }
        ("GET", "/v1/status") => {
            require_empty_body(body)?;
            Ok(ControlApiRequest::ReadModel)
        }
        ("POST", "/v1/goals") => {
            let value = parse_json_object(body)?;
            require_only_fields(&value, &["goal"])?;
            Ok(ControlApiRequest::SubmitGoal {
                goal: required_string(&value, "goal")?,
            })
        }
        ("POST", "/v1/control/pause") => {
            let value = parse_optional_json_object(body)?;
            require_only_fields(&value, &["reason"])?;
            let reason = optional_string(&value, "reason")?;
            Ok(ControlApiRequest::Pause { reason })
        }
        ("POST", "/v1/control/resume") => {
            if !body.is_empty() {
                let value = parse_json_object(body)?;
                if !value.as_object().is_some_and(serde_json::Map::is_empty) {
                    return Err(ApiError::new(
                        ApiStatus::BadRequest,
                        "resume accepts only an empty JSON object",
                    ));
                }
            }
            Ok(ControlApiRequest::Resume)
        }
        ("POST", "/v1/approvals/respond") => {
            let value = parse_json_object(body)?;
            require_only_fields(&value, &["request_id", "decision", "principal"])?;
            let decision = required_string(&value, "decision")?;
            if !matches!(decision.as_str(), "approve" | "deny") {
                return Err(ApiError::new(
                    ApiStatus::BadRequest,
                    "approval decision must be `approve` or `deny`",
                ));
            }
            Ok(ControlApiRequest::RespondToApproval {
                request_id: required_string(&value, "request_id")?,
                decision,
                principal: required_string(&value, "principal")?,
            })
        }
        // v2 endpoints
        ("GET", "/v2/session") => {
            require_empty_body(body)?;
            Ok(ControlApiRequest::Session)
        }
        ("GET", "/v2/doctor") => {
            require_empty_body(body)?;
            Ok(ControlApiRequest::Doctor)
        }
        ("GET", "/v2/overview") => {
            require_empty_body(body)?;
            Ok(ControlApiRequest::Overview)
        }
        ("GET", "/v2/projects") => {
            require_empty_body(body)?;
            Ok(ControlApiRequest::ListProjects)
        }
        ("POST", "/v2/projects") => {
            let value = parse_json_object(body)?;
            require_only_fields(&value, &["root", "display_name"])?;
            Ok(ControlApiRequest::AddProject {
                root: required_string(&value, "root")?,
                display_name: required_string(&value, "display_name")?,
            })
        }
        ("POST", "/v2/projects/create") => {
            let value = parse_json_object(body)?;
            require_only_fields(&value, &["name"])?;
            Ok(ControlApiRequest::CreateProject {
                name: required_string(&value, "name")?,
            })
        }
        ("POST", "/v2/projects/open") => {
            let value = parse_optional_json_object(body)?;
            require_only_fields(&value, &["root"])?;
            Ok(ControlApiRequest::OpenFolder {
                root: optional_string(&value, "root")?,
            })
        }
        ("GET", "/v2/goals") => {
            require_empty_body(body)?;
            Ok(ControlApiRequest::ListGoals)
        }
        ("GET", "/v2/events") => {
            require_empty_body(body)?;
            Ok(ControlApiRequest::ListEvents {
                after: query_i64(&info.query, "after", 0).max(0),
                limit: query_usize(&info.query, "limit", 50, 200),
            })
        }
        ("GET", "/v2/events/stream") => {
            require_empty_body(body)?;
            let from_query = query_i64(&info.query, "after", -1);
            let from_header = info
                .last_event_id
                .as_deref()
                .and_then(|value| value.parse::<i64>().ok())
                .unwrap_or(-1);
            Ok(ControlApiRequest::EventStream {
                last_event_id: from_query.max(from_header).max(0),
            })
        }
        ("GET", "/v2/recovery") => {
            require_empty_body(body)?;
            Ok(ControlApiRequest::GetRecovery)
        }
        ("GET", "/v2/settings") => {
            require_empty_body(body)?;
            Ok(ControlApiRequest::GetSettings)
        }
        ("POST", "/v2/settings") => {
            let value = parse_json_object(body)?;
            require_only_fields(
                &value,
                &[
                    "approval_principal",
                    "chrome_path",
                    "node_path",
                    "execute_on_start",
                ],
            )?;
            Ok(ControlApiRequest::SaveSettings {
                approval_principal: optional_string(&value, "approval_principal")?,
                chrome_path: optional_string(&value, "chrome_path")?,
                node_path: optional_string(&value, "node_path")?,
                execute_on_start: value
                    .get("execute_on_start")
                    .and_then(serde_json::Value::as_bool),
            })
        }
        ("POST", "/v2/setup/model/verify") => {
            let value = parse_json_object(body)?;
            require_only_fields(&value, &["runtime_path", "model_path"])?;
            Ok(ControlApiRequest::VerifyModel {
                runtime_path: required_string(&value, "runtime_path")?,
                model_path: required_string(&value, "model_path")?,
            })
        }
        ("POST", "/v2/goals") => {
            let value = parse_json_object(body)?;
            require_only_fields(&value, &["goal"])?;
            Ok(ControlApiRequest::SubmitGoal {
                goal: required_string(&value, "goal")?,
            })
        }
        ("POST", "/v2/control/pause") => {
            let value = parse_optional_json_object(body)?;
            require_only_fields(&value, &["reason"])?;
            let reason = optional_string(&value, "reason")?;
            Ok(ControlApiRequest::Pause { reason })
        }
        ("POST", "/v2/control/resume") => {
            if !body.is_empty() {
                let value = parse_json_object(body)?;
                if !value.as_object().is_some_and(serde_json::Map::is_empty) {
                    return Err(ApiError::new(
                        ApiStatus::BadRequest,
                        "resume accepts only an empty JSON object",
                    ));
                }
            }
            Ok(ControlApiRequest::Resume)
        }
        ("POST", "/v2/approvals/respond") => {
            let value = parse_json_object(body)?;
            require_only_fields(&value, &["request_id", "decision", "principal"])?;
            let decision = required_string(&value, "decision")?;
            if !matches!(decision.as_str(), "approve" | "deny") {
                return Err(ApiError::new(
                    ApiStatus::BadRequest,
                    "approval decision must be `approve` or `deny`",
                ));
            }
            Ok(ControlApiRequest::RespondToApproval {
                request_id: required_string(&value, "request_id")?,
                decision,
                principal: required_string(&value, "principal")?,
            })
        }
        ("POST", path) if path.starts_with("/v2/projects/") && path.ends_with("/activate") => {
            let project_id = path
                .strip_prefix("/v2/projects/")
                .and_then(|p| p.strip_suffix("/activate"))
                .ok_or_else(|| {
                    ApiError::new(ApiStatus::BadRequest, "invalid project activate path")
                })?;
            Ok(ControlApiRequest::ActivateProject {
                project_id: project_id.to_owned(),
            })
        }
        ("GET", path) if path.starts_with("/v2/goals/") && path.ends_with("/activity") => {
            require_empty_body(body)?;
            let goal_id = path
                .strip_prefix("/v2/goals/")
                .and_then(|p| p.strip_suffix("/activity"))
                .ok_or_else(|| ApiError::new(ApiStatus::BadRequest, "invalid goal path"))?;
            if goal_id.is_empty() || goal_id.contains('/') {
                return Err(ApiError::new(ApiStatus::BadRequest, "invalid goal path"));
            }
            Ok(ControlApiRequest::GetGoalActivity {
                goal_id: goal_id.to_owned(),
            })
        }
        ("GET", path) if path.starts_with("/v2/goals/") && !path.contains("/cancel") => {
            require_empty_body(body)?;
            let goal_id = path
                .strip_prefix("/v2/goals/")
                .ok_or_else(|| ApiError::new(ApiStatus::BadRequest, "invalid goal path"))?;
            if goal_id.is_empty() || goal_id.contains('/') {
                return Err(ApiError::new(ApiStatus::BadRequest, "invalid goal path"));
            }
            Ok(ControlApiRequest::GetGoal {
                goal_id: goal_id.to_owned(),
            })
        }
        ("POST", path) if path.starts_with("/v2/goals/") && path.ends_with("/cancel") => {
            let goal_id = path
                .strip_prefix("/v2/goals/")
                .and_then(|p| p.strip_suffix("/cancel"))
                .ok_or_else(|| ApiError::new(ApiStatus::BadRequest, "invalid goal cancel path"))?;
            let value = parse_optional_json_object(body)?;
            let principal =
                optional_string(&value, "principal")?.unwrap_or_else(|| "operator".to_owned());
            Ok(ControlApiRequest::CancelGoal {
                goal_id: goal_id.to_owned(),
                principal,
            })
        }
        ("POST", path)
            if path.starts_with("/v2/goals/")
                && (path.ends_with("/undo") || path.ends_with("/apply")) =>
        {
            let (goal_id, undo) = match path.strip_prefix("/v2/goals/") {
                Some(rest) if rest.ends_with("/undo") => (rest.strip_suffix("/undo"), true),
                Some(rest) => (rest.strip_suffix("/apply"), false),
                None => (None, false),
            };
            let goal_id = goal_id
                .filter(|goal_id| !goal_id.is_empty() && !goal_id.contains('/'))
                .ok_or_else(|| ApiError::new(ApiStatus::BadRequest, "invalid goal path"))?
                .to_owned();
            let value = parse_optional_json_object(body)?;
            require_only_fields(&value, &[])?;
            Ok(if undo {
                ControlApiRequest::UndoGoal { goal_id }
            } else {
                ControlApiRequest::ApplyGoal { goal_id }
            })
        }
        ("GET", "/v2/setup") => {
            require_empty_body(body)?;
            Ok(ControlApiRequest::SetupStatus)
        }
        ("POST", "/v2/setup/model/cancel") => {
            let value = parse_optional_json_object(body)?;
            require_only_fields(&value, &[])?;
            Ok(ControlApiRequest::CancelModelDownload)
        }
        ("POST", "/v2/setup/developer-tools/install") => {
            let value = parse_optional_json_object(body)?;
            require_only_fields(&value, &[])?;
            Ok(ControlApiRequest::InstallDeveloperTools)
        }
        ("POST", "/v2/setup/model/download") => {
            let value = parse_optional_json_object(body)?;
            require_only_fields(&value, &["confirmation"])?;
            Ok(ControlApiRequest::DownloadModel {
                confirmation: optional_string(&value, "confirmation")?,
            })
        }
        ("GET", path) if path.starts_with("/v2/artifacts/") => {
            require_empty_body(body)?;
            let digest = path.strip_prefix("/v2/artifacts/").unwrap_or_default();
            if digest.is_empty() || digest.contains('/') {
                return Err(ApiError::new(
                    ApiStatus::BadRequest,
                    "invalid artifact digest",
                ));
            }
            Ok(ControlApiRequest::GetArtifact {
                digest: digest.to_owned(),
                offset: u64::try_from(query_i64(&info.query, "offset", 0).max(0)).unwrap_or(0),
                length: query_usize(&info.query, "length", 16 * 1024, 256 * 1024),
            })
        }
        ("GET", path) if path.starts_with("/v2/tasks/") && path.ends_with("/diff") => {
            require_empty_body(body)?;
            let key = path
                .strip_prefix("/v2/tasks/")
                .and_then(|rest| rest.strip_suffix("/diff"))
                .unwrap_or_default();
            if key.is_empty() {
                return Err(ApiError::new(ApiStatus::BadRequest, "invalid task key"));
            }
            Ok(ControlApiRequest::GetTaskDiff {
                key: key.to_owned(),
            })
        }
        ("GET", path) if path.starts_with("/v2/approvals/") => {
            require_empty_body(body)?;
            let request_id = path.strip_prefix("/v2/approvals/").unwrap_or_default();
            if request_id.is_empty() || request_id.contains('/') {
                return Err(ApiError::new(ApiStatus::BadRequest, "invalid approval id"));
            }
            Ok(ControlApiRequest::GetApproval {
                request_id: request_id.to_owned(),
            })
        }
        ("GET" | "POST", _) => Err(ApiError::new(
            ApiStatus::NotFound,
            "unknown local control API route",
        )),
        _ => Err(ApiError::new(
            ApiStatus::MethodNotAllowed,
            "local control API supports only GET and POST",
        )),
    }
}
