//! Read-only projections for the consumer API.
//! Callers: `main.rs` `/v2/events`, `/v2/recovery`, `/v2/artifacts`.
//! API: `project_events`, `explain_recovery`, `read_artifact_text`.
//! Schema: `EventProjectionV1`, `RecoveryExplanationV1`.
//! User instruction: implement the attached consumer product plan (CX-T12).

use serde::Serialize;
use sovereign_controller::LocalControlRecoveryProjectionV1;
use sovereign_evidence::ArtifactStore;
use sovereign_state::{JournalEvent, StateStore};

const MAX_EVENTS: usize = 200;
const MAX_ARTIFACT_BYTES: usize = 256 * 1024;
const MAX_DIFF_BYTES: usize = 512 * 1024;

const EVENT_WHITELIST: &[&str] = &[
    "goal_intent",
    "plan",
    "task",
    "approval_request",
    "execution_control",
    "action",
];

/// Bounded journal row returned to the UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EventProjectionV1 {
    pub sequence: i64,
    pub event_id: String,
    pub entity_type: String,
    pub entity_id: String,
    pub event_kind: String,
    pub summary: String,
    pub occurred_at_ms: i64,
}

/// Plain-language recovery copy. Never grants a capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecoveryExplanationV1 {
    pub mutation_blocked: bool,
    pub headline: String,
    pub explanation: String,
    pub next_steps: Vec<String>,
}

/// Projects journal events after `after`, capped at `limit` (max 200).
#[must_use]
pub fn project_events(events: &[JournalEvent], after: i64, limit: usize) -> Vec<EventProjectionV1> {
    let cap = limit.clamp(1, MAX_EVENTS);
    events
        .iter()
        .filter(|event| {
            event.sequence > after && EVENT_WHITELIST.contains(&event.entity_type.as_str())
        })
        .take(cap)
        .map(project_event)
        .collect()
}

fn project_event(event: &JournalEvent) -> EventProjectionV1 {
    EventProjectionV1 {
        sequence: event.sequence,
        event_id: event.event_id.clone(),
        entity_type: event.entity_type.clone(),
        entity_id: event.entity_id.clone(),
        event_kind: event.event_kind.clone(),
        summary: redact_summary(&event.payload_json),
        occurred_at_ms: event.occurred_at_ms,
    }
}

fn redact_summary(payload_json: &str) -> String {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(payload_json) else {
        return "unreadable payload".to_owned();
    };
    let object = value.as_object();
    let keys = object.map_or_else(Vec::new, |map| map.keys().cloned().collect::<Vec<_>>());
    if keys
        .iter()
        .any(|key| key.contains("value_json") || key.contains("secret"))
    {
        return "redacted payload".to_owned();
    }
    format!("fields={}", keys.join(","))
}

/// Explains why mutation is blocked using only Controller recovery facts.
#[must_use]
pub fn explain_recovery(recovery: &LocalControlRecoveryProjectionV1) -> RecoveryExplanationV1 {
    if !recovery.mutation_blocked {
        return RecoveryExplanationV1 {
            mutation_blocked: false,
            headline: "Controller can accept new work.".to_owned(),
            explanation: "No unknown actions, unresolved rollbacks, or conflicted worktrees are blocking mutation.".to_owned(),
            next_steps: vec!["Submit a goal or resume if you previously paused.".to_owned()],
        };
    }
    let mut reasons = Vec::new();
    if !recovery.unknown_action_ids.is_empty() {
        reasons.push(format!(
            "{} action(s) finished without a receipt and are unknown, not retried.",
            recovery.unknown_action_ids.len()
        ));
    }
    if !recovery.unresolved_rollback_ids.is_empty() {
        reasons.push("A rollback is still unresolved.".to_owned());
    }
    if !recovery.conflicted_worktree_task_ids.is_empty() {
        reasons
            .push("A worktree is conflicted. Sovereign will not reset your git work.".to_owned());
    }
    if !recovery.nonterminal_process_leases.is_empty() {
        reasons.push("A process lease is still open.".to_owned());
    }
    if !recovery.reconciling_task_ids.is_empty() {
        reasons.push("A task is reconciling an unknown outcome.".to_owned());
    }
    RecoveryExplanationV1 {
        mutation_blocked: true,
        headline: "Mutation is blocked until the Controller finishes recovery.".to_owned(),
        explanation: reasons.join(" "),
        next_steps: vec![
            "Read the unknown action ids. Do not replay them.".to_owned(),
            "Resolve git conflicts yourself if a worktree is conflicted.".to_owned(),
            "Restart Sovereign after the Controller records a recovered checkpoint.".to_owned(),
        ],
    }
}

/// Reads UTF-8 artifact bytes only. Non-text returns metadata.
///
/// # Errors
/// Returns when the digest is unknown or the range is invalid.
pub fn read_artifact_text(
    store: &ArtifactStore,
    state: &StateStore,
    digest: &str,
    offset: u64,
    length: usize,
) -> Result<ArtifactRead, String> {
    let length = length.min(MAX_ARTIFACT_BYTES);
    let bytes = store
        .range(state, digest, offset, length)
        .map_err(|error| error.to_string())?;
    match String::from_utf8(bytes.clone()) {
        Ok(text) => Ok(ArtifactRead {
            digest: digest.to_owned(),
            utf8: true,
            text: Some(text),
            byte_len: bytes.len(),
        }),
        Err(_) => Ok(ArtifactRead {
            digest: digest.to_owned(),
            utf8: false,
            text: None,
            byte_len: bytes.len(),
        }),
    }
}

/// Artifact read result. Content is omitted when bytes are not UTF-8.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArtifactRead {
    pub digest: String,
    pub utf8: bool,
    pub text: Option<String>,
    pub byte_len: usize,
}

/// Caps a unified diff at 512 KiB.
#[must_use]
pub fn cap_diff(diff: &str) -> String {
    if diff.len() <= MAX_DIFF_BYTES {
        return diff.to_owned();
    }
    let mut end = MAX_DIFF_BYTES;
    while end > 0 && !diff.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &diff[..end])
}

/// Goal detail assembled from the Controller read model. Plan revisions, tasks, attempts,
/// verifications, and evidence belong to the active plan, so they are returned only for the
/// goal that plan is bound to. The model does not decide completion.
#[must_use]
pub fn goal_detail(
    model: &sovereign_controller::LocalControlReadModelV1,
    view: &crate::goal_views::GoalViewV1,
) -> Option<serde_json::Value> {
    let is_active = model
        .status
        .active_plan
        .as_ref()
        .and_then(|plan| plan.get("goal_id"))
        .and_then(serde_json::Value::as_str)
        == Some(view.goal_id.as_str());
    let intent = serde_json::json!({
        "schema_version": view.schema_version,
        "goal_id": view.goal_id,
        "natural_language_goal": view.natural_language_goal,
        "status": view.status,
        "submitted_at_ms": view.submitted_at_ms,
    });
    let empty = serde_json::Value::Array(Vec::new());
    Some(serde_json::json!({
        "intent": intent,
        "view": view,
        "plan_revisions": if is_active { serde_json::to_value(&model.plan_revisions).ok()? } else { empty.clone() },
        "tasks": if is_active { serde_json::Value::Array(model.status.tasks.clone()) } else { empty.clone() },
        "attempts": if is_active { serde_json::Value::Array(model.status.attempts.clone()) } else { empty.clone() },
        "verifications": if is_active { serde_json::to_value(&model.verifications).ok()? } else { empty.clone() },
        "evidence": if is_active { serde_json::Value::Array(model.status.evidence.clone()) } else { empty },
        "completion_decided_by": "verification",
    }))
}

/// Unified diff text from a task JSON value, capped at 512 KiB.
#[must_use]
pub fn task_diff_from_status(tasks: &[serde_json::Value], key: &str) -> Option<String> {
    for task in tasks {
        let id = task.get("task_id").and_then(|value| value.as_str());
        if id != Some(key) {
            continue;
        }
        if let Some(diff) = task.get("unified_diff").and_then(|value| value.as_str()) {
            return Some(cap_diff(diff));
        }
        if let Some(change_set) = task.get("change_set") {
            return Some(cap_diff(&change_set.to_string()));
        }
    }
    None
}

/// Model residency label. Unknown is not treated as loaded.
#[must_use]
pub fn model_residency_label(store: &StateStore) -> String {
    match store.get_state("controller.resource_residency", "model") {
        Ok(Some(raw)) => {
            if raw.contains("\"resident\"") || raw.contains("\"Resident\"") {
                "loaded".to_owned()
            } else if raw.contains("\"absent\"") {
                "idle".to_owned()
            } else {
                "unknown".to_owned()
            }
        }
        Ok(None) => "idle".to_owned(),
        Err(_) => "unknown".to_owned(),
    }
}

/// Pressure band from the last durable pressure record when present.
#[must_use]
pub fn pressure_band_label(store: &StateStore) -> String {
    match store.get_state("controller.resource_pressure", "active") {
        Ok(Some(raw)) if raw.contains("critical") => "critical".to_owned(),
        Ok(Some(raw)) if raw.contains("warning") => "warning".to_owned(),
        Ok(Some(_)) => "normal".to_owned(),
        _ => "unknown".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_recovery() -> LocalControlRecoveryProjectionV1 {
        LocalControlRecoveryProjectionV1 {
            execution_epoch: 1,
            checkpoint: None,
            unknown_action_ids: Vec::new(),
            unresolved_action_ids: Vec::new(),
            pending_recovery_action_ids: Vec::new(),
            nonterminal_process_leases: Vec::new(),
            unresolved_rollback_ids: Vec::new(),
            reconciling_task_ids: Vec::new(),
            conflicted_worktree_task_ids: Vec::new(),
            mutation_blocked: false,
        }
    }

    #[test]
    fn recovery_explanation_covers_unknown_and_clear() {
        let explained = explain_recovery(&empty_recovery());
        assert!(!explained.mutation_blocked);
        let mut blocked = empty_recovery();
        blocked.unknown_action_ids = vec!["action-1".to_owned()];
        blocked.mutation_blocked = true;
        let explained = explain_recovery(&blocked);
        assert!(explained.mutation_blocked);
        assert!(explained.explanation.contains("unknown"));
    }

    #[test]
    fn journal_whitelist_redacts_value_json() {
        let event = JournalEvent {
            sequence: 2,
            event_id: "e1".to_owned(),
            entity_type: "goal_intent".to_owned(),
            entity_id: "g1".to_owned(),
            event_kind: "goal_intent_queued".to_owned(),
            payload_json: r#"{"value_json":"secret"}"#.to_owned(),
            occurred_at_ms: 1,
        };
        let projected = project_events(&[event], 0, 10);
        assert_eq!(projected.len(), 1);
        assert_eq!(projected[0].summary, "redacted payload");
    }

    #[test]
    fn pagination_respects_limit_and_secret_shaped_payload_is_redacted() {
        let events = (1..=5)
            .map(|sequence| JournalEvent {
                sequence,
                event_id: format!("e{sequence}"),
                entity_type: "task".to_owned(),
                entity_id: format!("t{sequence}"),
                event_kind: "task_updated".to_owned(),
                payload_json: r#"{"secret":"SOVEREIGN_SECRET_FILE"}"#.to_owned(),
                occurred_at_ms: sequence,
            })
            .collect::<Vec<_>>();
        let projected = project_events(&events, 0, 2);
        assert_eq!(projected.len(), 2);
        assert!(
            projected
                .iter()
                .all(|event| event.summary == "redacted payload")
        );
        assert_eq!(cap_diff("short"), "short");
    }
}
