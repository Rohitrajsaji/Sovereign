//! Plain-language goal views for the consumer UI: phase, real progress, steps, and outcome.
//!
//! Callers: `dispatch.rs` (`/v2/goals`, `/v2/goals/{id}`, `/v2/goals/{id}/activity`).
//! API: `goal_views`, `goal_activity`, `GoalViewV1`, `GoalProgressV1`, `GoalActivityV1`.
//!
//! Everything here is derived from Controller state. Nothing in this module decides progress on
//! the model's word: a step counts as done only when the Controller recorded it as succeeded.
//! Task titles come from the compiled plan and are untrusted text; clients render them as text.

use crate::execution::ServiceStatusV1;
use crate::landing_service::{LandingRecordV1, LandingStatusV1, LandingsV1};
use crate::service_state::PendingCommandV1;
use serde::Serialize;
use serde_json::Value;
use sovereign_controller::{GoalOutcomeKindV1, GoalOutcomeV1, LocalControlReadModelV1};
use sovereign_state::JournalEvent;

pub const GOAL_VIEW_SCHEMA_VERSION: u32 = 1;
const MAX_TITLE_CHARS: usize = 160;
const MAX_ACTIVITY: usize = 200;

/// One step of the active plan.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GoalStepV1 {
    pub task_id: String,
    pub title: String,
    /// `waiting`, `working`, `checking`, `done`, `failed`, or `stopped`.
    pub phase: String,
}

/// Progress of one request.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GoalProgressV1 {
    /// `received`, `queued`, `waiting`, `planning`, `building`, `checking`, `waiting_for_you`,
    /// `stopping`, `applying`, `done`, `not_applied`, `undone`, `failed`, or `cancelled`.
    pub phase: String,
    pub headline: String,
    pub sentence: String,
    pub steps_done: u32,
    pub steps_total: u32,
    pub percent: u8,
    pub terminal: bool,
}

/// A request as the UI shows it. Field names up to `submitted_at_ms` match `GoalIntentV1`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GoalViewV1 {
    pub schema_version: u32,
    pub goal_id: String,
    pub natural_language_goal: String,
    pub status: String,
    pub submitted_at_ms: i64,
    pub progress: GoalProgressV1,
    pub steps: Vec<GoalStepV1>,
    pub outcome: Option<GoalOutcomeV1>,
    pub queue_position: Option<u32>,
    /// Where a finished request's result stands in the project folder.
    pub landing: Option<LandingRecordV1>,
}

/// One activity line for a request, in plain words.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GoalActivityV1 {
    pub sequence: i64,
    pub occurred_at_ms: i64,
    pub text: String,
    /// `info`, `success`, `warning`, or `error`.
    pub tone: String,
}

/// Facts about the service that change how a request reads right now.
pub struct ServiceFacts<'a> {
    pub status: &'a ServiceStatusV1,
    pub working: bool,
    pub paused: bool,
    pub pending: &'a [PendingCommandV1],
}

fn progress(
    phase: &str,
    headline: &str,
    sentence: impl Into<String>,
    (steps_done, steps_total): (u32, u32),
    percent: u8,
) -> GoalProgressV1 {
    GoalProgressV1 {
        phase: phase.to_owned(),
        headline: headline.to_owned(),
        sentence: sentence.into(),
        steps_done,
        steps_total,
        percent,
        terminal: matches!(
            phase,
            "done" | "not_applied" | "undone" | "failed" | "cancelled"
        ),
    }
}

fn bounded_title(title: &str) -> String {
    let trimmed = title.trim();
    if trimmed.chars().count() <= MAX_TITLE_CHARS {
        return trimmed.to_owned();
    }
    let mut shortened: String = trimmed.chars().take(MAX_TITLE_CHARS).collect();
    shortened.push('…');
    shortened
}

fn step_phase(state: &str) -> &'static str {
    match state {
        "succeeded" => "done",
        "running" => "working",
        "verifying" => "checking",
        "failed_terminal" => "failed",
        "reconciling_unknown" => "stopped",
        _ => "waiting",
    }
}

fn steps_from_tasks(tasks: &[Value]) -> Vec<GoalStepV1> {
    tasks
        .iter()
        .filter_map(|task| {
            let state = task.get("state").and_then(Value::as_str)?;
            let contract = task.get("task")?;
            let task_id = contract.get("task_id").and_then(Value::as_str)?;
            let title = contract
                .get("title")
                .and_then(Value::as_str)
                .unwrap_or(task_id);
            Some(GoalStepV1 {
                task_id: task_id.to_owned(),
                title: bounded_title(title),
                phase: step_phase(state).to_owned(),
            })
        })
        .collect()
}

/// Plain sentence for why a request ended without completing.
#[must_use]
pub fn outcome_sentence(outcome: &GoalOutcomeV1) -> String {
    match outcome.reason_code.as_str() {
        "cancelled_by_user" => "You cancelled this request. Nothing was changed.".to_owned(),
        "compilation_budget_exhausted" => {
            "Sovereign couldn't turn this into a plan. Try a smaller or more specific request."
                .to_owned()
        }
        "compilation_failed" => {
            "Sovereign couldn't work out how to do this. Try describing it differently.".to_owned()
        }
        "task_failed" => {
            "One step failed its checks and couldn't be fixed automatically. Your project was not changed."
                .to_owned()
        }
        "composition_error" => {
            "Sovereign couldn't prepare this request. See Details for what went wrong.".to_owned()
        }
        _ => match outcome.kind {
            GoalOutcomeKindV1::Cancelled => "This request was cancelled.".to_owned(),
            GoalOutcomeKindV1::Failed => "This request stopped without finishing.".to_owned(),
        },
    }
}

fn active_progress(
    steps: &[GoalStepV1],
    waiting_for_you: bool,
    facts: &ServiceFacts<'_>,
) -> GoalProgressV1 {
    let total = u32::try_from(steps.len()).unwrap_or(u32::MAX);
    let done =
        u32::try_from(steps.iter().filter(|step| step.phase == "done").count()).unwrap_or(u32::MAX);
    let in_flight = steps
        .iter()
        .any(|step| matches!(step.phase.as_str(), "working" | "checking"));
    // Planning is the first 10 percent. Each finished step moves the rest proportionally, and a
    // step in flight counts as half done.
    let percent = if total == 0 {
        10
    } else {
        let doubled_units = u64::from(done) * 2 + u64::from(in_flight);
        let scaled = 10 + (doubled_units * 85) / (u64::from(total) * 2);
        u8::try_from(scaled.min(95)).unwrap_or(95)
    };
    let current = steps
        .iter()
        .find(|step| step.phase != "done")
        .map(|step| step.title.clone());
    let position = done.saturating_add(1).min(total.max(1));
    if waiting_for_you {
        return progress(
            "waiting_for_you",
            "Needs your answer",
            "Sovereign is waiting for you to allow or decline an action.",
            (done, total),
            percent,
        );
    }
    if facts.paused {
        return progress(
            "waiting",
            "Paused",
            "Sovereign is paused. Resume to continue.",
            (done, total),
            percent,
        );
    }
    if facts.status.phase == "deferred_resource" && !facts.status.detail.is_empty() {
        return progress(
            "waiting",
            "Waiting for memory",
            facts.status.detail.clone(),
            (done, total),
            percent,
        );
    }
    if let Some(problem) = service_problem(facts, (done, total), percent) {
        return problem;
    }
    if steps.iter().any(|step| step.phase == "checking") {
        return progress(
            "checking",
            "Checking",
            format!(
                "Checking step {position} of {total}: {}",
                current.unwrap_or_default()
            ),
            (done, total),
            percent,
        );
    }
    progress(
        "building",
        "Building",
        match current {
            Some(title) if total > 0 => format!("Step {position} of {total}: {title}"),
            _ => "Sovereign is working on it.".to_owned(),
        },
        (done, total),
        percent,
    )
}

/// A service problem in words a person can act on. The raw detail stays in Details.
fn plain_service_problem(detail: &str) -> String {
    let lowered = detail.to_ascii_lowercase();
    if lowered.contains("sandbox-exec") || lowered.contains("isolation unavailable") {
        "Sovereign's safety sandbox isn't available on this computer, so it can't run the checks. Sovereign needs macOS.".to_owned()
    } else if lowered.contains("sovereign_model_runtime")
        || lowered.contains("model runtime")
        || lowered.contains("model path")
        || lowered.contains("load local model")
    {
        "The AI model isn't set up yet. Finish setup and Sovereign continues on its own.".to_owned()
    } else {
        "Sovereign hit a problem and keeps retrying. Details has what went wrong.".to_owned()
    }
}

/// The request cannot move because the service keeps failing; says why instead of "Building".
fn service_problem(
    facts: &ServiceFacts<'_>,
    done_total: (u32, u32),
    percent: u8,
) -> Option<GoalProgressV1> {
    (facts.status.phase == "error" && !facts.status.detail.is_empty()).then(|| {
        progress(
            "waiting",
            "Having trouble",
            plain_service_problem(&facts.status.detail),
            done_total,
            percent,
        )
    })
}

fn queued_progress(position: u32, head_is_next: bool, facts: &ServiceFacts<'_>) -> GoalProgressV1 {
    if !head_is_next {
        let ahead = position.saturating_sub(1);
        let sentence = if ahead == 1 {
            "Waiting for 1 request ahead of it.".to_owned()
        } else {
            format!("Waiting for {ahead} requests ahead of it.")
        };
        return progress("queued", "Queued", sentence, (0, 0), 0);
    }
    if facts.paused {
        return progress(
            "waiting",
            "Paused",
            "Sovereign is paused. Resume to start this request.",
            (0, 0),
            0,
        );
    }
    if facts.status.phase == "deferred_resource" && !facts.status.detail.is_empty() {
        return progress(
            "waiting",
            "Waiting for memory",
            facts.status.detail.clone(),
            (0, 0),
            2,
        );
    }
    if let Some(problem) = service_problem(facts, (0, 0), 2) {
        return problem;
    }
    if facts.working {
        return progress(
            "planning",
            "Planning",
            "Sovereign is working out the steps. This can take a minute.",
            (0, 0),
            5,
        );
    }
    progress("queued", "Starting", "Starting soon.", (0, 0), 0)
}

/// How a finished request reads once its result is (or is not) in the project folder.
/// `landings` is `None` for a project whose results Sovereign does not apply itself.
fn completed_progress(
    landings: Option<&LandingsV1>,
    record: Option<&LandingRecordV1>,
) -> GoalProgressV1 {
    let Some(record) = record else {
        return if landings.is_some() {
            progress(
                "applying",
                "Finishing",
                "Checked. Putting the changes in your project.",
                (0, 0),
                98,
            )
        } else {
            progress("done", "Done", "Finished and checked.", (0, 0), 100)
        };
    };
    match record.status {
        LandingStatusV1::Landed => progress(
            "done",
            "Done",
            "Finished, checked, and saved in your project.",
            (0, 0),
            100,
        ),
        LandingStatusV1::NothingToLand => progress(
            "done",
            "Done",
            "Finished and checked. Nothing in your project needed to change.",
            (0, 0),
            100,
        ),
        LandingStatusV1::PredatesLanding => {
            progress("done", "Done", "Finished and checked.", (0, 0), 100)
        }
        LandingStatusV1::Undone => progress(
            "undone",
            "Undone",
            "Undone. Your project is back to how it was before this request.",
            (0, 0),
            100,
        ),
        LandingStatusV1::BlockedByLocalChanges
        | LandingStatusV1::Conflict
        | LandingStatusV1::Failed => progress(
            "not_applied",
            "Not applied yet",
            record
                .detail
                .clone()
                .unwrap_or_else(|| "The result could not be applied to your project.".to_owned()),
            (0, 0),
            100,
        ),
    }
}

/// Builds every request view: durable goals in submission order, then submissions still waiting
/// for the current step to finish.
#[must_use]
#[expect(
    clippy::too_many_lines,
    reason = "one explicit mapping from every durable goal status to a plain-language view"
)]
pub fn goal_views(
    model: &LocalControlReadModelV1,
    outcomes: &[GoalOutcomeV1],
    landings: Option<&LandingsV1>,
    facts: &ServiceFacts<'_>,
) -> Vec<GoalViewV1> {
    let active_goal_id = model
        .status
        .active_plan
        .as_ref()
        .and_then(|plan| plan.get("goal_id"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let active_steps = steps_from_tasks(&model.status.tasks);
    let approvals_waiting =
        !model.pending_approvals.is_empty() || !model.blocked_approvals.is_empty();

    let mut intents = model.status.goal_intents.clone();
    intents.sort_by(|left, right| {
        (left.submitted_at_ms, left.goal_id.as_str())
            .cmp(&(right.submitted_at_ms, right.goal_id.as_str()))
    });
    let queued_ids = intents
        .iter()
        .filter(|intent| intent.status == "queued_for_plan_compilation")
        .map(|intent| intent.goal_id.clone())
        .collect::<Vec<_>>();

    let mut views = Vec::with_capacity(intents.len() + facts.pending.len());
    for intent in &intents {
        let outcome = outcomes
            .iter()
            .find(|outcome| outcome.goal_id == intent.goal_id)
            .cloned();
        let cancel_pending = facts.pending.iter().any(|command| {
            command.kind == "cancel_goal" && command.goal_id.as_deref() == Some(&intent.goal_id)
        });
        let is_active = active_goal_id.as_deref() == Some(intent.goal_id.as_str());
        let mut queue_position = None;
        let mut steps = Vec::new();
        let landing = landings
            .and_then(|landings| landings.record(&intent.goal_id))
            .cloned();
        let mut view_progress = match intent.status.as_str() {
            "completed" => completed_progress(landings, landing.as_ref()),
            "failed" => progress(
                "failed",
                "Didn't finish",
                outcome.as_ref().map_or_else(
                    || "This request stopped without finishing.".to_owned(),
                    outcome_sentence,
                ),
                (0, 0),
                0,
            ),
            "cancelled" | "cancelled_before_dispatch" => progress(
                "cancelled",
                "Cancelled",
                outcome.as_ref().map_or_else(
                    || "This request was cancelled.".to_owned(),
                    outcome_sentence,
                ),
                (0, 0),
                0,
            ),
            "claimed_for_plan_compilation" => progress(
                "planning",
                "Planning",
                "Sovereign is working out the steps.",
                (0, 0),
                8,
            ),
            "active_plan" if is_active => {
                steps.clone_from(&active_steps);
                active_progress(&steps, approvals_waiting, facts)
            }
            "active_plan" => progress(
                "building",
                "Building",
                "Sovereign is working on it.",
                (0, 0),
                10,
            ),
            _ => {
                let index = queued_ids
                    .iter()
                    .position(|goal_id| goal_id == &intent.goal_id)
                    .unwrap_or(0);
                let position = u32::try_from(index).unwrap_or(u32::MAX).saturating_add(1);
                queue_position = Some(position);
                queued_progress(position, index == 0 && active_goal_id.is_none(), facts)
            }
        };
        if cancel_pending && !view_progress.terminal {
            view_progress = progress(
                "stopping",
                "Stopping",
                "Stopping. This takes a moment if a step is running.",
                (view_progress.steps_done, view_progress.steps_total),
                view_progress.percent,
            );
        }
        views.push(GoalViewV1 {
            schema_version: GOAL_VIEW_SCHEMA_VERSION,
            goal_id: intent.goal_id.clone(),
            natural_language_goal: intent.natural_language_goal.clone(),
            status: intent.status.clone(),
            submitted_at_ms: intent.submitted_at_ms,
            progress: view_progress,
            steps,
            outcome,
            queue_position,
            landing,
        });
    }
    for command in facts
        .pending
        .iter()
        .filter(|command| command.kind == "submit_goal")
    {
        views.push(GoalViewV1 {
            schema_version: GOAL_VIEW_SCHEMA_VERSION,
            goal_id: format!("pending-{}", command.ticket),
            natural_language_goal: command.text.clone().unwrap_or_default(),
            status: "received".to_owned(),
            submitted_at_ms: command.accepted_at_ms,
            progress: progress(
                "received",
                "Received",
                "Got it. This request will be added as soon as the current step finishes.",
                (0, 0),
                0,
            ),
            steps: Vec::new(),
            outcome: None,
            queue_position: None,
            landing: None,
        });
    }
    views
}

fn event_mentions(event: &JournalEvent, needles: &[&str]) -> bool {
    needles.iter().any(|needle| {
        !needle.is_empty()
            && (event.entity_id == *needle
                || event.entity_id.starts_with(&format!("{needle}@"))
                || event.payload_json.contains(&format!("\"{needle}\"")))
    })
}

fn activity_line(event: &JournalEvent) -> Option<(&'static str, String)> {
    let payload: Value = serde_json::from_str(&event.payload_json).unwrap_or(Value::Null);
    let text = match event.event_kind.as_str() {
        "goal_intent_submitted" => ("info", "Request received.".to_owned()),
        "goal_intent_claimed" => ("info", "Planning started.".to_owned()),
        "goal_compilation_model_call_reserved" => {
            let ordinal = payload
                .get("call_ordinal")
                .and_then(Value::as_u64)
                .unwrap_or(1);
            (
                "info",
                format!("Asked the local model for a plan (try {ordinal})."),
            )
        }
        "goal_intent_activated" | "goal_intent_claim_reconciled_to_active" => {
            ("success", "Plan ready. Work started.".to_owned())
        }
        "goal_intent_claim_released" | "goal_intent_claim_reconciled_to_queue" => (
            "warning",
            "Planning was interrupted. The request is back in line.".to_owned(),
        ),
        "task_verifying" | "non_write_task_verifying" | "integration_task_verifying" => {
            ("info", "Checking a step.".to_owned())
        }
        "task_succeeded" => ("success", "A step passed its checks.".to_owned()),
        "verification_failed" | "task_failure_routed" => (
            "warning",
            "A check failed. Sovereign is trying a fix.".to_owned(),
        ),
        "task_failed" | "task_cancelled_terminal" => {
            ("error", "A step could not be completed.".to_owned())
        }
        "task_deferred_resource" => ("warning", "Waiting for memory to free up.".to_owned()),
        "approval_request_pending" => ("warning", "Waiting for your answer.".to_owned()),
        "approval_claim_issued" => ("success", "You allowed an action.".to_owned()),
        "approval_request_denied" => ("warning", "An action was declined.".to_owned()),
        "cancellation_requested" => ("warning", "Stop requested.".to_owned()),
        "goal_intent_completed" => ("success", "Finished and checked.".to_owned()),
        "plan_finalized" => ("success", "Work recorded as complete.".to_owned()),
        "plan_abandoned" if payload.get("kind").and_then(Value::as_str) != Some("cancelled") => {
            ("error", "Stopped without finishing.".to_owned())
        }
        "goal_intent_cancelled" | "plan_abandoned" => ("warning", "Cancelled.".to_owned()),
        "goal_intent_failed" => ("error", "Stopped without finishing.".to_owned()),
        _ => return None,
    };
    Some(text)
}

/// Activity for one request, oldest first, limited to events that name the goal or its plan.
#[must_use]
pub fn goal_activity(
    events: &[JournalEvent],
    goal_id: &str,
    plan_ids: &[String],
) -> Vec<GoalActivityV1> {
    let mut needles = vec![goal_id];
    needles.extend(plan_ids.iter().map(String::as_str));
    events
        .iter()
        .filter(|event| event_mentions(event, &needles))
        .filter_map(|event| {
            activity_line(event).map(|(tone, text)| GoalActivityV1 {
                sequence: event.sequence,
                occurred_at_ms: event.occurred_at_ms,
                text,
                tone: tone.to_owned(),
            })
        })
        .take(MAX_ACTIVITY)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn step(state: &str, title: &str) -> Value {
        json!({"state": state, "task": {"task_id": format!("t-{title}"), "title": title}})
    }

    fn facts(status: &ServiceStatusV1) -> ServiceFacts<'_> {
        ServiceFacts {
            status,
            working: false,
            paused: false,
            pending: &[],
        }
    }

    #[test]
    fn active_progress_counts_only_recorded_steps() {
        let status = ServiceStatusV1::default();
        let steps = steps_from_tasks(&[
            step("succeeded", "Create page"),
            step("running", "Add styles"),
            step("planned", "Add tests"),
            step("planned", "Wire form"),
        ]);
        let view = active_progress(&steps, false, &facts(&status));
        assert_eq!(view.phase, "building");
        assert_eq!((view.steps_done, view.steps_total), (1, 4));
        // 10 + 85 * (1 done + half) / 4, rounded down.
        assert_eq!(view.percent, 41);
        assert_eq!(view.sentence, "Step 2 of 4: Add styles");
        assert!(!view.terminal);
    }

    #[test]
    fn a_failing_service_is_explained_instead_of_building() {
        let mut status = ServiceStatusV1 {
            phase: "error".to_owned(),
            detail: "invalid active plan: isolation unavailable: macOS sandbox-exec is unavailable"
                .to_owned(),
            ..ServiceStatusV1::default()
        };
        let steps = steps_from_tasks(&[step("planned", "A")]);
        let view = active_progress(&steps, false, &facts(&status));
        assert_eq!(view.headline, "Having trouble");
        assert!(
            view.sentence.contains("safety sandbox"),
            "{}",
            view.sentence
        );
        status.detail = "load local model: connection refused".to_owned();
        let queued = queued_progress(1, true, &facts(&status));
        assert!(
            queued.sentence.contains("Finish setup"),
            "{}",
            queued.sentence
        );
    }

    #[test]
    fn finished_request_reads_by_where_its_result_stands() {
        let record = |status: LandingStatusV1| LandingRecordV1 {
            goal_id: "goal-1".to_owned(),
            status,
            commit: None,
            undo_commit: None,
            changed_paths: Vec::new(),
            detail: Some("Your folder has unsaved changes.".to_owned()),
            technical_detail: None,
            updated_at_ms: 1,
        };
        let landings = LandingsV1 {
            schema_version: 1,
            records: Vec::new(),
        };
        assert_eq!(completed_progress(None, None).phase, "done");
        let applying = completed_progress(Some(&landings), None);
        assert_eq!(applying.phase, "applying");
        assert!(!applying.terminal);
        let landed = record(LandingStatusV1::Landed);
        assert_eq!(
            completed_progress(Some(&landings), Some(&landed)).phase,
            "done"
        );
        let blocked = record(LandingStatusV1::BlockedByLocalChanges);
        let view = completed_progress(Some(&landings), Some(&blocked));
        assert_eq!(view.phase, "not_applied");
        assert_eq!(view.sentence, "Your folder has unsaved changes.");
        assert!(view.terminal);
        let undone = record(LandingStatusV1::Undone);
        assert_eq!(
            completed_progress(Some(&landings), Some(&undone)).phase,
            "undone"
        );
    }

    #[test]
    fn all_steps_done_never_claims_completion_before_the_controller() {
        let status = ServiceStatusV1::default();
        let steps = steps_from_tasks(&[step("succeeded", "A"), step("succeeded", "B")]);
        let view = active_progress(&steps, false, &facts(&status));
        assert_eq!(view.percent, 95);
        assert_ne!(view.phase, "done");
    }

    #[test]
    fn approval_wait_and_memory_wait_explain_themselves() {
        let mut status = ServiceStatusV1::default();
        let steps = steps_from_tasks(&[step("planned", "A")]);
        assert_eq!(
            active_progress(&steps, true, &facts(&status)).phase,
            "waiting_for_you"
        );
        status.phase = "deferred_resource".to_owned();
        status.detail = "waiting for memory: needs 5000 MiB".to_owned();
        let view = queued_progress(1, true, &facts(&status));
        assert_eq!(view.headline, "Waiting for memory");
        assert!(view.sentence.contains("5000 MiB"));
    }

    #[test]
    fn queue_position_is_explained() {
        let status = ServiceStatusV1::default();
        assert_eq!(
            queued_progress(3, false, &facts(&status)).sentence,
            "Waiting for 2 requests ahead of it."
        );
        let working = ServiceFacts {
            status: &status,
            working: true,
            paused: false,
            pending: &[],
        };
        assert_eq!(queued_progress(1, true, &working).phase, "planning");
    }

    #[test]
    fn long_titles_are_bounded() {
        let long = "x".repeat(500);
        assert_eq!(bounded_title(&long).chars().count(), MAX_TITLE_CHARS + 1);
    }

    #[test]
    fn activity_is_scoped_to_the_goal_and_plan() {
        let event = |sequence: i64, entity_id: &str, kind: &str, payload: &str| JournalEvent {
            sequence,
            event_id: format!("e{sequence}"),
            entity_type: "controller".to_owned(),
            entity_id: entity_id.to_owned(),
            event_kind: kind.to_owned(),
            payload_json: payload.to_owned(),
            occurred_at_ms: sequence,
        };
        let events = vec![
            event(1, "goal-a", "goal_intent_claimed", "{}"),
            event(2, "goal-b", "goal_intent_claimed", "{}"),
            event(3, "plan-a@r1", "plan_abandoned", r#"{"kind":"cancelled"}"#),
            event(4, "goal-a", "unrelated_internal_event", "{}"),
        ];
        let activity = goal_activity(&events, "goal-a", &["plan-a".to_owned()]);
        let texts = activity
            .iter()
            .map(|line| line.text.as_str())
            .collect::<Vec<_>>();
        assert_eq!(texts, vec!["Planning started.", "Cancelled."]);
    }
}
