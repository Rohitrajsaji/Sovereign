//! Single-writer actor for Controller lifecycle and mutation operations.
//!
//! Web request handlers communicate with this actor over bounded channels,
//! ensuring all mutations are serialized and the `RunLock` is held continuously.

use sovereign_controller::{
    ApprovalDecisionV1, ApprovalRequestV1, ExecutionControlV1, GoalIntentV1, LocalControl,
    LocalControlReadModelV1,
};
use sovereign_state::StateStore;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, SyncSender};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::execution::{ExecutionService, ServiceStatusV1};
use crate::run_lock::RunLock;
use sovereign_repo::ProjectRegistry;

const ACTOR_QUEUE_BOUND: usize = 64;
const DEFAULT_RECV_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub enum ActorCommand {
    SubmitGoal {
        goal: String,
        reply: Sender<Result<GoalIntentV1, String>>,
    },
    Pause {
        reason: Option<String>,
        reply: Sender<Result<ExecutionControlV1, String>>,
    },
    Resume {
        reply: Sender<Result<ExecutionControlV1, String>>,
    },
    CancelGoal {
        goal_id: String,
        principal: String,
        reply: Sender<Result<GoalIntentV1, String>>,
    },
    RespondToApproval {
        request_id: String,
        decision: ApprovalDecisionV1,
        principal: String,
        reply: Sender<Result<ApprovalRequestV1, String>>,
    },
    ReadModel {
        reply: Sender<Result<LocalControlReadModelV1, String>>,
    },
    SwitchProject {
        state_path: PathBuf,
        git_root: Option<PathBuf>,
        reply: Sender<Result<(), String>>,
    },
    Shutdown {
        reply: Sender<Result<(), String>>,
    },
    ServiceStatus {
        reply: Sender<Result<ServiceStatusV1, String>>,
    },
}

#[derive(Debug, Clone, Default)]
pub struct ActorOptions {
    pub execute: bool,
    pub git_root: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct ControllerActorHandle {
    sender: SyncSender<ActorCommand>,
}

impl ControllerActorHandle {
    /// Launches a new `ControllerActor` owning the `RunLock` and `LocalControl` for `state_path`.
    ///
    /// # Errors
    /// Returns an error if the thread fails to spawn.
    #[allow(dead_code)]
    pub fn spawn(state_path: PathBuf) -> Result<(Self, JoinHandle<()>), String> {
        Self::spawn_with(state_path, ActorOptions::default())
    }

    /// # Errors
    /// Returns an error if the thread fails to spawn.
    pub fn spawn_with(
        state_path: PathBuf,
        options: ActorOptions,
    ) -> Result<(Self, JoinHandle<()>), String> {
        let (sender, receiver) = mpsc::sync_channel(ACTOR_QUEUE_BOUND);
        let thread = thread::Builder::new()
            .name("sovereign-controller-actor".to_owned())
            .spawn(move || {
                run_actor_loop(state_path, receiver, options);
            })
            .map_err(|error| format!("failed to spawn controller actor thread: {error}"))?;

        Ok((Self { sender }, thread))
    }

    /// # Errors
    /// Returns an error if the actor is dead or times out.
    pub fn service_status(&self) -> Result<ServiceStatusV1, String> {
        let (reply, rx) = mpsc::channel();
        self.send_cmd(ActorCommand::ServiceStatus { reply }, &rx)
    }

    /// Submits a natural-language goal.
    ///
    /// # Errors
    /// Returns an error if the actor is dead, times out, or Controller rejects the goal.
    pub fn submit_goal(&self, goal: String) -> Result<GoalIntentV1, String> {
        let (reply, rx) = mpsc::channel();
        self.send_cmd(ActorCommand::SubmitGoal { goal, reply }, &rx)
    }

    /// Pauses execution.
    ///
    /// # Errors
    /// Returns an error if the actor is dead, times out, or Controller rejects pause.
    pub fn pause(&self, reason: Option<String>) -> Result<ExecutionControlV1, String> {
        let (reply, rx) = mpsc::channel();
        self.send_cmd(ActorCommand::Pause { reason, reply }, &rx)
    }

    /// Resumes execution.
    ///
    /// # Errors
    /// Returns an error if the actor is dead, times out, or Controller rejects resume.
    pub fn resume(&self) -> Result<ExecutionControlV1, String> {
        let (reply, rx) = mpsc::channel();
        self.send_cmd(ActorCommand::Resume { reply }, &rx)
    }

    /// Cancels a goal.
    ///
    /// # Errors
    /// Returns an error if the actor is dead, times out, or Controller rejects cancel.
    pub fn cancel_goal(&self, goal_id: String, principal: String) -> Result<GoalIntentV1, String> {
        let (reply, rx) = mpsc::channel();
        self.send_cmd(
            ActorCommand::CancelGoal {
                goal_id,
                principal,
                reply,
            },
            &rx,
        )
    }

    /// Responds to an approval request.
    ///
    /// # Errors
    /// Returns an error if the actor is dead, times out, or Controller rejects the decision.
    pub fn respond_to_approval(
        &self,
        request_id: String,
        decision: ApprovalDecisionV1,
        principal: String,
    ) -> Result<ApprovalRequestV1, String> {
        let (reply, rx) = mpsc::channel();
        self.send_cmd(
            ActorCommand::RespondToApproval {
                request_id,
                decision,
                principal,
                reply,
            },
            &rx,
        )
    }

    /// Fetches the read model.
    ///
    /// # Errors
    /// Returns an error if the actor is dead, times out, or read model generation fails.
    pub fn read_model(&self) -> Result<LocalControlReadModelV1, String> {
        let (reply, rx) = mpsc::channel();
        self.send_cmd(ActorCommand::ReadModel { reply }, &rx)
    }

    /// Switches the active project, re-acquiring `RunLock` on the new state path.
    /// When `git_root` is set and this actor was spawned with `execute`, the
    /// production tick binds that work tree so UI-registered projects can run.
    ///
    /// # Errors
    /// Returns an error if the actor is dead, times out, or switching project fails.
    pub fn switch_project(
        &self,
        state_path: PathBuf,
        git_root: Option<PathBuf>,
    ) -> Result<(), String> {
        let (reply, rx) = mpsc::channel();
        self.send_cmd(
            ActorCommand::SwitchProject {
                state_path,
                git_root,
                reply,
            },
            &rx,
        )
    }

    /// Gracefully shuts down the actor thread.
    ///
    /// # Errors
    /// Returns an error if the actor is dead or times out.
    pub fn shutdown(&self) -> Result<(), String> {
        let (reply, rx) = mpsc::channel();
        self.send_cmd(ActorCommand::Shutdown { reply }, &rx)
    }

    fn send_cmd<T>(
        &self,
        cmd: ActorCommand,
        rx: &Receiver<Result<T, String>>,
    ) -> Result<T, String> {
        self.sender
            .send(cmd)
            .map_err(|_| "controller actor is not running".to_owned())?;
        rx.recv_timeout(DEFAULT_RECV_TIMEOUT)
            .map_err(|err| match err {
                RecvTimeoutError::Timeout => "controller actor request timed out".to_owned(),
                RecvTimeoutError::Disconnected => "controller actor disconnected".to_owned(),
            })?
    }
}

struct ActorState {
    current_state_path: PathBuf,
    lock: Option<RunLock>,
    control: Option<LocalControl>,
}

impl ActorState {
    fn open(state_path: PathBuf) -> Result<Self, String> {
        let lock = RunLock::acquire(&state_path).map_err(|err| format!("run lock error: {err}"))?;
        let store =
            StateStore::open(&state_path).map_err(|err| format!("state store error: {err}"))?;
        let control =
            LocalControl::reopen(store).map_err(|err| format!("controller error: {err}"))?;

        Ok(Self {
            current_state_path: state_path,
            lock: Some(lock),
            control: Some(control),
        })
    }

    fn switch(&mut self, new_path: PathBuf) -> Result<(), String> {
        if self.current_state_path == new_path && self.control.is_some() {
            return Ok(());
        }
        self.control = None;
        self.lock = None;
        let new_lock =
            RunLock::acquire(&new_path).map_err(|err| format!("run lock error: {err}"))?;
        let new_store =
            StateStore::open(&new_path).map_err(|err| format!("state store error: {err}"))?;
        let new_control =
            LocalControl::reopen(new_store).map_err(|err| format!("controller error: {err}"))?;

        self.current_state_path = new_path;
        self.lock = Some(new_lock);
        self.control = Some(new_control);
        Ok(())
    }
}

fn bind_workspace(
    execute: bool,
    execution: &mut Option<ExecutionService>,
    registry: &mut ProjectRegistry,
    git_root: Option<&Path>,
    state_path: &Path,
) {
    *registry = ProjectRegistry::new();
    *execution = None;
    if let Some(root) = git_root {
        let _ = registry.register("repo.local", root);
        if execute {
            *execution = Some(ExecutionService::new(
                root.to_path_buf(),
                state_path.to_path_buf(),
            ));
        }
    }
}

#[expect(
    clippy::too_many_lines,
    clippy::needless_pass_by_value,
    reason = "actor loop serializes every command"
)]
fn run_actor_loop(initial_state: PathBuf, receiver: Receiver<ActorCommand>, options: ActorOptions) {
    let mut execution = options
        .git_root
        .as_ref()
        .map(|root| ExecutionService::new(root.clone(), initial_state.clone()));
    let mut registry = ProjectRegistry::new();
    if let Some(root) = options.git_root.as_ref() {
        let _ = registry.register("repo.local", root);
    }
    let mut actor_state = match ActorState::open(initial_state.clone()) {
        Ok(state) => Some(state),
        Err(err) => {
            eprintln!("controller actor initial state open failed: {err}");
            None
        }
    };

    loop {
        let cmd = if options.execute {
            match receiver.recv_timeout(Duration::from_millis(
                execution
                    .as_ref()
                    .map_or(1_000, ExecutionService::backoff_ms)
                    .max(1),
            )) {
                Ok(cmd) => Some(cmd),
                Err(RecvTimeoutError::Timeout) => {
                    if let (Some(service), Some(state)) = (execution.as_mut(), actor_state.as_mut())
                        && let Some(control) = state.control.as_mut()
                        && let Err(error) = service.step(control, &registry)
                    {
                        service.record_error(error);
                    }
                    None
                }
                Err(RecvTimeoutError::Disconnected) => break,
            }
        } else {
            match receiver.recv() {
                Ok(cmd) => Some(cmd),
                Err(_) => break,
            }
        };
        let Some(cmd) = cmd else { continue };
        match cmd {
            ActorCommand::Shutdown { reply } => {
                let _ = actor_state.take(); // drops lock and control
                let _ = reply.send(Ok(()));
                break;
            }
            ActorCommand::SwitchProject {
                state_path,
                git_root,
                reply,
            } => {
                let res = match &mut actor_state {
                    Some(state) => state.switch(state_path.clone()),
                    None => match ActorState::open(state_path.clone()) {
                        Ok(new_state) => {
                            actor_state = Some(new_state);
                            Ok(())
                        }
                        Err(e) => Err(e),
                    },
                };
                if res.is_ok() {
                    bind_workspace(
                        options.execute,
                        &mut execution,
                        &mut registry,
                        git_root.as_deref(),
                        &state_path,
                    );
                }
                let _ = reply.send(res);
            }
            ActorCommand::SubmitGoal { goal, reply } => {
                let res = match &mut actor_state {
                    Some(s) if s.control.is_some() => {
                        if let Some(control) = s.control.as_mut() {
                            control.submit_goal(&goal).map_err(|e| e.to_string())
                        } else {
                            Err("controller unavailable".to_owned())
                        }
                    }
                    _ => Err("actor controller state not available".to_owned()),
                };
                let _ = reply.send(res);
            }
            ActorCommand::Pause { reason, reply } => {
                let res = match &mut actor_state {
                    Some(s) if s.control.is_some() => {
                        if let Some(control) = s.control.as_mut() {
                            control.pause(reason.as_deref()).map_err(|e| e.to_string())
                        } else {
                            Err("controller unavailable".to_owned())
                        }
                    }
                    _ => Err("actor controller state not available".to_owned()),
                };
                let _ = reply.send(res);
            }
            ActorCommand::Resume { reply } => {
                let res = match &mut actor_state {
                    Some(s) if s.control.is_some() => {
                        if let Some(control) = s.control.as_mut() {
                            control.resume().map_err(|e| e.to_string())
                        } else {
                            Err("controller unavailable".to_owned())
                        }
                    }
                    _ => Err("actor controller state not available".to_owned()),
                };
                let _ = reply.send(res);
            }
            ActorCommand::CancelGoal {
                goal_id,
                principal,
                reply,
            } => {
                let res = match &mut actor_state {
                    Some(s) if s.control.is_some() => {
                        if let Some(control) = s.control.as_mut() {
                            control
                                .cancel_goal(&goal_id, &principal)
                                .map_err(|e| e.to_string())
                        } else {
                            Err("controller unavailable".to_owned())
                        }
                    }
                    _ => Err("actor controller state not available".to_owned()),
                };
                let _ = reply.send(res);
            }
            ActorCommand::RespondToApproval {
                request_id,
                decision,
                principal,
                reply,
            } => {
                let res = match &mut actor_state {
                    Some(s) if s.control.is_some() => {
                        if let Some(control) = s.control.as_mut() {
                            control
                                .respond_to_approval(&request_id, decision, &principal)
                                .map_err(|e| e.to_string())
                        } else {
                            Err("controller unavailable".to_owned())
                        }
                    }
                    _ => Err("actor controller state not available".to_owned()),
                };
                let _ = reply.send(res);
            }
            ActorCommand::ServiceStatus { reply } => {
                let status = execution
                    .as_ref()
                    .map_or_else(ServiceStatusV1::default, |service| service.status().clone());
                let _ = reply.send(Ok(status));
            }
            ActorCommand::ReadModel { reply } => {
                let res = match &mut actor_state {
                    Some(s) if s.control.is_some() => {
                        if let Some(control) = s.control.as_mut() {
                            control.read_model().map_err(|e| e.to_string())
                        } else {
                            Err("controller unavailable".to_owned())
                        }
                    }
                    _ => Err("actor controller state not available".to_owned()),
                };
                let _ = reply.send(res);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_state(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("sovereign-actor-{label}-{nonce}"));
        fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("create temp dir: {e}"));
        dir.join("state.sqlite3")
    }

    #[test]
    fn actor_lifecycle_and_serialization() {
        let state_path = temp_state("lifecycle");
        let (actor, handle) = ControllerActorHandle::spawn(state_path.clone())
            .unwrap_or_else(|e| panic!("spawn failed: {e}"));

        let status = actor
            .read_model()
            .unwrap_or_else(|e| panic!("read model: {e}"));
        assert!(!status.status.execution_control.paused);

        let paused = actor
            .pause(Some("test pause".to_owned()))
            .unwrap_or_else(|e| panic!("pause: {e}"));
        assert!(paused.paused);
        assert_eq!(paused.reason.as_deref(), Some("test pause"));

        let resumed = actor.resume().unwrap_or_else(|e| panic!("resume: {e}"));
        assert!(!resumed.paused);

        actor.shutdown().unwrap_or_else(|e| panic!("shutdown: {e}"));
        handle
            .join()
            .unwrap_or_else(|_| panic!("join actor failed"));

        // Second process can now acquire RunLock on the same state
        let lock2 = RunLock::acquire(&state_path);
        assert!(lock2.is_ok());

        let _ = fs::remove_file(&state_path);
    }

    #[test]
    fn execute_tick_binds_after_project_switch() {
        let state_path = temp_state("bind-exec");
        let repo = state_path
            .parent()
            .unwrap_or_else(|| panic!("state parent"))
            .join("repo");
        fs::create_dir_all(&repo).unwrap_or_else(|error| panic!("create repo: {error}"));
        let git = std::process::Command::new("/usr/bin/git")
            .args(["init", "-q"])
            .current_dir(&repo)
            .status()
            .unwrap_or_else(|error| panic!("git init: {error}"));
        assert!(git.success());

        let (actor, handle) = ControllerActorHandle::spawn_with(
            state_path.clone(),
            ActorOptions {
                execute: true,
                git_root: None,
            },
        )
        .unwrap_or_else(|error| panic!("spawn: {error}"));
        thread::sleep(Duration::from_millis(1_200));
        let before = actor
            .service_status()
            .unwrap_or_else(|error| panic!("status before: {error}"));
        assert_eq!(before.last_outcome, "none");

        actor
            .switch_project(state_path.clone(), Some(repo))
            .unwrap_or_else(|error| panic!("switch: {error}"));
        thread::sleep(Duration::from_millis(1_500));
        let after = actor
            .service_status()
            .unwrap_or_else(|error| panic!("status after: {error}"));
        assert_ne!(
            after.last_outcome, "none",
            "execute tick must run after a UI project bind"
        );

        actor
            .shutdown()
            .unwrap_or_else(|error| panic!("shutdown: {error}"));
        handle
            .join()
            .unwrap_or_else(|_| panic!("join actor failed"));
    }
}
