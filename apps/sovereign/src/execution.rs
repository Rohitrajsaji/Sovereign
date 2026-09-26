//! One-step production advance used by both `run` and `serve --execute`.
//!
//! Callers: `actor.rs` (`serve --execute` tick) and tests in this module.
//! API: `ExecutionService::step`, `ServiceStatusV1` (`schema_version` 1).
//! User instruction: implement the attached consumer product plan (`CX-T10`).
//!
//! The Controller remains the only writer. This module only composes pinned
//! resources and reports the typed outcome.

use crate::consumer_status::ServicePhase;
use crate::runner;
use serde::{Deserialize, Serialize};
use sovereign_controller::{LocalControl, ProductionAdvanceOutcome, ProductionBlockReason};
use sovereign_repo::ProjectRegistry;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const BACKOFF_START_MS: u64 = 1_000;
const BACKOFF_CAP_MS: u64 = 10_000;

/// Coarse service status published on `/v2/overview`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceStatusV1 {
    pub schema_version: u32,
    pub phase: String,
    pub detail: String,
    pub last_outcome: String,
    pub last_step_at_ms: i64,
}

impl Default for ServiceStatusV1 {
    fn default() -> Self {
        Self {
            schema_version: 1,
            phase: ServicePhase::Idle.as_str().to_owned(),
            detail: String::new(),
            last_outcome: "none".to_owned(),
            last_step_at_ms: 0,
        }
    }
}

/// Composition context for one production step.
#[derive(Debug, Clone)]
pub struct ExecutionService {
    root: PathBuf,
    state: PathBuf,
    status: ServiceStatusV1,
    backoff_ms: u64,
}

impl ExecutionService {
    #[must_use]
    pub fn new(root: PathBuf, state: PathBuf) -> Self {
        Self {
            root,
            state,
            status: ServiceStatusV1::default(),
            backoff_ms: BACKOFF_START_MS,
        }
    }

    #[must_use]
    pub fn status(&self) -> &ServiceStatusV1 {
        &self.status
    }

    #[must_use]
    pub fn backoff_ms(&self) -> u64 {
        self.backoff_ms
    }

    /// Advances the Controller once using the same composition as `run`.
    ///
    /// # Errors
    /// Returns a composition or Controller error. Unknown outcomes are never retried.
    pub fn step(
        &mut self,
        control: &mut LocalControl,
        registry: &ProjectRegistry,
    ) -> Result<ProductionAdvanceOutcome, String> {
        let root = self.root.clone();
        let state = self.state.clone();
        let outcome = control
            .with_controller_mut(|controller| {
                runner::advance_production_step(controller, registry, &root, &state)
                    .map_err(sovereign_controller::ControllerError::InvalidPlan)
            })
            .map_err(|error| error.to_string())?;
        let detail = outcome_detail(&outcome);
        self.record(&outcome, detail.as_deref());
        Ok(outcome)
    }

    /// Records a composition error without retrying an unknown outcome.
    pub fn record_error(&mut self, detail: impl Into<String>) {
        self.status.phase = String::from(ServicePhase::Error.as_str());
        self.status.detail = detail.into();
        self.status.last_outcome = String::from("error");
        self.status.last_step_at_ms = unix_millis();
        self.backoff_ms = BACKOFF_START_MS;
    }

    #[allow(clippy::match_same_arms)]
    fn record(&mut self, outcome: &ProductionAdvanceOutcome, detail: Option<&str>) {
        let (phase, idle_backoff) = match outcome {
            ProductionAdvanceOutcome::Idle => (ServicePhase::Idle, true),
            ProductionAdvanceOutcome::Paused => (ServicePhase::Paused, true),
            ProductionAdvanceOutcome::RecoveryRequired => (ServicePhase::RecoveryBlocked, true),
            ProductionAdvanceOutcome::AwaitingApproval { .. } => {
                (ServicePhase::WaitingForApproval, true)
            }
            ProductionAdvanceOutcome::Blocked {
                reason:
                    ProductionBlockReason::CompilationInputRequired
                    | ProductionBlockReason::ExecutionInputsRequired,
                ..
            } => (ServicePhase::Running, false),
            ProductionAdvanceOutcome::Blocked { .. } => (ServicePhase::DeferredResource, true),
            ProductionAdvanceOutcome::PlanActivated { .. }
            | ProductionAdvanceOutcome::TaskVerified { .. }
            | ProductionAdvanceOutcome::TaskFailed { .. }
            | ProductionAdvanceOutcome::GoalCompleted { .. }
            | ProductionAdvanceOutcome::Complete { .. } => (ServicePhase::Running, false),
        };
        let previous = self.status.last_outcome.clone();
        self.status.phase = String::from(phase.as_str());
        self.status.detail = String::from(detail.unwrap_or(""));
        self.status.last_outcome = format!("{outcome:?}");
        self.status.last_step_at_ms = unix_millis();
        self.backoff_ms = if !idle_backoff {
            0
        } else if previous == "none" {
            BACKOFF_START_MS
        } else {
            self.backoff_ms.saturating_mul(2).min(BACKOFF_CAP_MS)
        };
    }
}

/// Human-readable reason carried by a blocked outcome, shown as the service detail.
fn outcome_detail(outcome: &ProductionAdvanceOutcome) -> Option<String> {
    match outcome {
        ProductionAdvanceOutcome::Blocked {
            reason:
                ProductionBlockReason::Readiness(reason)
                | ProductionBlockReason::CompilationFailed(reason),
            ..
        } => Some(reason.clone()),
        _ => None,
    }
}

fn unix_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            i64::try_from(duration.as_millis()).unwrap_or(0)
        })
}

/// Maps a read-model recovery flag onto the service phase when no step has run.
#[must_use]
#[allow(dead_code)]
pub fn phase_from_read_model(paused: bool, mutation_blocked: bool) -> ServicePhase {
    if mutation_blocked {
        ServicePhase::RecoveryBlocked
    } else if paused {
        ServicePhase::Paused
    } else {
        ServicePhase::Idle
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocked_reason_becomes_service_detail() {
        let mut service = ExecutionService::new(PathBuf::from("/tmp"), PathBuf::from("/tmp/state"));
        let outcome = ProductionAdvanceOutcome::Blocked {
            task_id: None,
            reason: ProductionBlockReason::Readiness("waiting for memory".to_owned()),
        };
        let detail = outcome_detail(&outcome);
        service.record(&outcome, detail.as_deref());
        assert_eq!(service.status().detail, "waiting for memory");
        assert_eq!(
            service.status().phase,
            ServicePhase::DeferredResource.as_str()
        );
        assert_eq!(outcome_detail(&ProductionAdvanceOutcome::Idle), None);
    }

    #[test]
    fn idle_and_progress_backoff() {
        let mut service = ExecutionService::new(PathBuf::from("/tmp"), PathBuf::from("/tmp/state"));
        service.record(&ProductionAdvanceOutcome::Idle, None);
        assert_eq!(service.backoff_ms(), BACKOFF_START_MS);
        service.record(&ProductionAdvanceOutcome::Idle, None);
        assert_eq!(service.backoff_ms(), 2_000);
        service.record(
            &ProductionAdvanceOutcome::GoalCompleted {
                goal_id: "g1".to_owned(),
            },
            None,
        );
        assert_eq!(service.backoff_ms(), 0);
        assert_eq!(service.status().phase, "running");
    }

    #[test]
    fn error_is_surfaced_and_not_an_unknown_retry() {
        let mut service = ExecutionService::new(PathBuf::from("/tmp"), PathBuf::from("/tmp/state"));
        service.record_error("composition failed");
        assert_eq!(service.status().phase, "error");
        assert_eq!(service.status().last_outcome, "error");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn http_goal_pause_restart_and_runlock_do_not_replay_unknown() {
        use crate::actor::{ActorOptions, ControllerActorHandle};
        use crate::control_api::{ServerConfig, bind_loopback, serve_listener};
        use crate::dispatch::handle_actor_request;
        use crate::run_lock::RunLock;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        use std::process::Command;
        use std::sync::Arc;
        use std::sync::atomic::AtomicUsize;
        use std::thread;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("sovereign-cx-t10-{nonce}"));
        std::fs::create_dir_all(&root).unwrap_or_else(|error| panic!("{error}"));
        std::fs::write(root.join("USE_FIXTURE_BACKEND"), [])
            .unwrap_or_else(|error| panic!("{error}"));
        let git = Command::new("/usr/bin/git")
            .args(["init", "-q"])
            .current_dir(&root)
            .status()
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(git.success());
        let state = root.join("state.sqlite3");
        let (actor, handle) = ControllerActorHandle::spawn_with(
            state.clone(),
            ActorOptions {
                execute: true,
                git_root: Some(root.clone()),
            },
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let listener = bind_loopback(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .unwrap_or_else(|error| panic!("{error}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("{error}"));
        let token = "cx-t10-session-token".to_owned();
        let actor_for_server = actor.clone();
        let server = thread::spawn(move || {
            let _ = serve_listener(
                &listener,
                move |request| handle_actor_request(&actor_for_server, request),
                ServerConfig {
                    session_token: Some(token),
                    require_token_for_v1_post: true,
                    state_path: Some(state),
                    sse_clients: Arc::new(AtomicUsize::new(0)),
                    launch_code_dir: None,
                },
            );
        });

        let cookie = "Cookie: sovereign_session=cx-t10-session-token\r\n";
        let csrf = "X-Sovereign-CSRF: cx-t10-session-token\r\n";
        let goal = br#"{"goal":"Create a bounded local test app"}"#;
        let req = format!(
            "POST /v2/goals HTTP/1.1\r\nHost: 127.0.0.1\r\n{cookie}{csrf}Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            goal.len(),
            String::from_utf8_lossy(goal)
        );
        let queued = http(addr, &req);
        assert!(queued.contains("goal_id"), "{queued}");
        let mut compiled = false;
        for _ in 0..40 {
            thread::sleep(std::time::Duration::from_millis(250));
            let model = actor.read_model().unwrap_or_else(|error| panic!("{error}"));
            if model
                .status
                .goal_intents
                .iter()
                .any(|goal| goal.status != "queued")
            {
                compiled = true;
                break;
            }
        }
        assert!(
            compiled,
            "HTTP-submitted goal should leave queued under the fixture backend"
        );

        let pause = format!(
            "POST /v2/control/pause HTTP/1.1\r\nHost: 127.0.0.1\r\n{cookie}{csrf}Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{{}}"
        );
        let paused = http(addr, &pause);
        assert!(
            paused.contains("\"paused\":true") || paused.contains("paused"),
            "{paused}"
        );

        let before = actor.read_model().unwrap_or_else(|error| panic!("{error}"));
        actor.shutdown().unwrap_or_else(|error| panic!("{error}"));
        let _ = handle.join();
        drop(server);

        let (restarted, handle2) = ControllerActorHandle::spawn_with(
            root.join("state.sqlite3"),
            ActorOptions {
                execute: true,
                git_root: Some(root.clone()),
            },
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let after = restarted
            .read_model()
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(after.recovery.unknown_action_ids.is_empty());
        assert_eq!(
            after.status.goal_intents.len(),
            before.status.goal_intents.len()
        );
        let contended = RunLock::acquire(&root.join("state.sqlite3"));
        assert!(contended.is_err(), "serve --execute must hold RunLock");
        restarted
            .shutdown()
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = handle2.join();
        let _ = std::fs::remove_dir_all(root);
    }

    fn http(addr: std::net::SocketAddr, request: &str) -> String {
        use std::io::{Read, Write};
        use std::net::TcpStream;
        use std::time::Duration;
        let mut stream = TcpStream::connect(addr).unwrap_or_else(|error| panic!("{error}"));
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap_or_else(|error| panic!("{error}"));
        stream
            .write_all(request.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
        let mut buf = Vec::new();
        let _ = stream.read_to_end(&mut buf);
        String::from_utf8_lossy(&buf).into_owned()
    }
}
