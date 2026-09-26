//! Single-writer actor for Controller lifecycle and mutation operations.
//!
//! Callers: `dispatch.rs` (HTTP), `execution.rs` tests, `main.rs` `serve`.
//! API: `ControllerActorHandle`, `Reply`, `ActorOptions`.
//!
//! Every mutation is serialized on the actor thread, which holds the `RunLock` continuously.
//! Reads never go through the actor: they open read-only state handles on the current project
//! database, so they answer while a long step (model load, plan compilation, tests) runs. A
//! command sent during such a step is acknowledged as queued instead of timing out, and a cancel
//! interrupts the running step at once through `ServiceShared`.

use sovereign_controller::{
    ApprovalDecisionV1, ApprovalRequestV1, ExecutionControlV1, GOAL_REASON_COMPOSITION_ERROR,
    GoalIntentV1, LocalControl, LocalControlReadModelV1,
};
use sovereign_state::StateStore;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, SyncSender, TrySendError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::execution::{ExecutionService, ServiceStatusV1};
use crate::landing_service::{self, LandingRecordV1, ProjectWorkspace};
use crate::run_lock::RunLock;
use crate::service_state::{PendingCommandV1, ServiceShared, with_step_context};
use sovereign_repo::ProjectRegistry;

const ACTOR_QUEUE_BOUND: usize = 64;
/// How long a command waits for the actor when it is idle.
const IDLE_REPLY_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a command waits while a step runs before it is acknowledged as queued.
const BUSY_REPLY_TIMEOUT: Duration = Duration::from_millis(600);
/// How often a waiting command checks whether the actor has started a step.
const REPLY_POLL: Duration = Duration::from_millis(50);
/// Identical composition errors in a row before the queued goal is failed.
const COMPOSITION_ERROR_LIMIT: u32 = 3;
const STATE_READY_POLLS: u32 = 40;
const STATE_BUSY_RETRIES: u32 = 5;
const STATE_RETRY_DELAY: Duration = Duration::from_millis(50);
const NO_LANDING_WORKSPACE: &str =
    "This project's folder is not managed by Sovereign's results, so there is nothing to change.";

/// Result of a command sent to the actor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply<T> {
    /// The Controller applied the command.
    Applied(T),
    /// The actor was busy; the command is queued and applies at the next safe point.
    Queued { ticket: u64 },
}

impl<T> Reply<T> {
    /// The applied value, or `None` while the command is queued.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn applied(self) -> Option<T> {
        match self {
            Self::Applied(value) => Some(value),
            Self::Queued { .. } => None,
        }
    }
}

#[derive(Debug)]
pub enum ActorCommand {
    SubmitGoal {
        ticket: u64,
        goal: String,
        reply: Sender<Result<GoalIntentV1, String>>,
    },
    Pause {
        ticket: u64,
        reason: Option<String>,
        reply: Sender<Result<ExecutionControlV1, String>>,
    },
    Resume {
        ticket: u64,
        reply: Sender<Result<ExecutionControlV1, String>>,
    },
    CancelGoal {
        ticket: u64,
        goal_id: String,
        principal: String,
        reply: Sender<Result<GoalIntentV1, String>>,
    },
    RespondToApproval {
        ticket: u64,
        request_id: String,
        decision: ApprovalDecisionV1,
        principal: String,
        reply: Sender<Result<ApprovalRequestV1, String>>,
    },
    SwitchProject {
        ticket: u64,
        state_path: PathBuf,
        git_root: Option<PathBuf>,
        managed: bool,
        reply: Sender<Result<(), String>>,
    },
    UndoGoal {
        ticket: u64,
        goal_id: String,
        reply: Sender<Result<LandingRecordV1, String>>,
    },
    ApplyGoal {
        ticket: u64,
        goal_id: String,
        reply: Sender<Result<LandingRecordV1, String>>,
    },
    Shutdown {
        reply: Sender<Result<(), String>>,
    },
}

#[derive(Debug, Clone, Default)]
pub struct ActorOptions {
    pub execute: bool,
    pub git_root: Option<PathBuf>,
    /// Sovereign keeps the folder's history itself (a project it created or first versioned).
    pub managed: bool,
    /// The folder is a registered project, so completed requests are applied to it. The
    /// developer fallback (`serve` inside an unregistered repository) never applies results.
    pub lands_results: bool,
}

#[derive(Clone)]
pub struct ControllerActorHandle {
    sender: SyncSender<ActorCommand>,
    shared: Arc<ServiceShared>,
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
        let shared = ServiceShared::new(state_path.clone());
        let actor_shared = Arc::clone(&shared);
        let thread = thread::Builder::new()
            .name("sovereign-controller-actor".to_owned())
            .spawn(move || {
                run_actor_loop(state_path, receiver, options, &actor_shared);
            })
            .map_err(|error| format!("failed to spawn controller actor thread: {error}"))?;

        Ok((Self { sender, shared }, thread))
    }

    /// The current project database. Reads open their own handle on it.
    #[must_use]
    pub fn state_path(&self) -> PathBuf {
        self.shared.state_path()
    }

    /// The last status the execution service published.
    #[must_use]
    pub fn service_status(&self) -> ServiceStatusV1 {
        self.shared.status()
    }

    /// True while a step has been running for more than a moment.
    #[must_use]
    pub fn working(&self) -> bool {
        self.shared.working()
    }

    /// Commands accepted but not yet applied.
    #[must_use]
    pub fn pending_commands(&self) -> Vec<PendingCommandV1> {
        self.shared.pending()
    }

    /// Onboarding's model download, which runs beside the actor.
    #[must_use]
    pub fn model_setup(&self) -> Arc<crate::model_setup::ModelSetup> {
        self.shared.model_setup()
    }

    /// The bound project's folder, shown read-only by the preview and the Files tab.
    #[must_use]
    pub fn project_root(&self) -> Option<PathBuf> {
        self.shared.project_root()
    }

    /// Starts the project preview for the app at `app_origin` and allows the app to frame it.
    ///
    /// # Errors
    /// Returns when no loopback port can be bound.
    pub fn start_preview(
        &self,
        app_origin: &str,
    ) -> Result<crate::preview::PreviewAddressV1, String> {
        let address =
            crate::preview::start_preview(&self.shared.project_root_handle(), app_origin)?;
        crate::control_api::allow_preview_frames(address.origin());
        self.shared.set_preview(address.clone());
        Ok(address)
    }

    #[must_use]
    pub fn preview(&self) -> Option<crate::preview::PreviewAddressV1> {
        self.shared.preview()
    }

    /// Opens a read handle on the current project database. Waits briefly while the actor is
    /// still opening it, and retries a busy database a few times.
    ///
    /// # Errors
    /// Returns an error while Sovereign is still starting, or a state error.
    pub fn open_state(&self) -> Result<StateStore, String> {
        for _ in 0..STATE_READY_POLLS {
            if self.shared.state_ready() {
                break;
            }
            thread::sleep(STATE_RETRY_DELAY);
        }
        if !self.shared.state_ready() {
            return Err("Sovereign is still starting. Try again in a moment.".to_owned());
        }
        let mut last_error = String::new();
        for _ in 0..STATE_BUSY_RETRIES {
            match StateStore::open(self.shared.state_path()) {
                Ok(store) => return Ok(store),
                Err(error) => {
                    last_error = error.to_string();
                    if !last_error.contains("locked") && !last_error.contains("busy") {
                        break;
                    }
                    thread::sleep(STATE_RETRY_DELAY);
                }
            }
        }
        Err(format!("state store error: {last_error}"))
    }

    /// Reads the Controller read model from a read-only handle, without waiting on the actor.
    ///
    /// # Errors
    /// Returns a state or read-model error.
    pub fn read_model(&self) -> Result<LocalControlReadModelV1, String> {
        LocalControl::read_only(self.open_state()?)
            .read_model()
            .map_err(|error| error.to_string())
    }

    /// Submits a natural-language goal.
    ///
    /// # Errors
    /// Returns an error if the actor is gone or the Controller rejects the goal.
    pub fn submit_goal(&self, goal: String) -> Result<Reply<GoalIntentV1>, String> {
        let ticket = self.shared.enqueue("submit_goal", None, Some(goal.clone()));
        let (reply, rx) = mpsc::channel();
        self.send_tracked(
            ticket,
            ActorCommand::SubmitGoal {
                ticket,
                goal,
                reply,
            },
            &rx,
        )
    }

    /// Pauses execution after the current step.
    ///
    /// # Errors
    /// Returns an error if the actor is gone or the Controller rejects pause.
    pub fn pause(&self, reason: Option<String>) -> Result<Reply<ExecutionControlV1>, String> {
        let ticket = self.shared.enqueue("pause", None, None);
        let (reply, rx) = mpsc::channel();
        self.send_tracked(
            ticket,
            ActorCommand::Pause {
                ticket,
                reason,
                reply,
            },
            &rx,
        )
    }

    /// Resumes execution.
    ///
    /// # Errors
    /// Returns an error if the actor is gone or the Controller rejects resume.
    pub fn resume(&self) -> Result<Reply<ExecutionControlV1>, String> {
        let ticket = self.shared.enqueue("resume", None, None);
        let (reply, rx) = mpsc::channel();
        self.send_tracked(ticket, ActorCommand::Resume { ticket, reply }, &rx)
    }

    /// Cancels a goal. In-flight work for it is interrupted at once; the Controller records the
    /// cancellation at the next safe point.
    ///
    /// # Errors
    /// Returns an error if the actor is gone or the Controller rejects cancel.
    pub fn cancel_goal(
        &self,
        goal_id: String,
        principal: String,
    ) -> Result<Reply<GoalIntentV1>, String> {
        self.shared.interrupt_goal(&goal_id);
        let ticket = self
            .shared
            .enqueue("cancel_goal", Some(goal_id.clone()), None);
        let (reply, rx) = mpsc::channel();
        self.send_tracked(
            ticket,
            ActorCommand::CancelGoal {
                ticket,
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
    /// Returns an error if the actor is gone or the Controller rejects the decision.
    pub fn respond_to_approval(
        &self,
        request_id: String,
        decision: ApprovalDecisionV1,
        principal: String,
    ) -> Result<Reply<ApprovalRequestV1>, String> {
        let ticket = self.shared.enqueue("approval", None, None);
        let (reply, rx) = mpsc::channel();
        self.send_tracked(
            ticket,
            ActorCommand::RespondToApproval {
                ticket,
                request_id,
                decision,
                principal,
                reply,
            },
            &rx,
        )
    }

    /// Switches the active project, re-acquiring `RunLock` on the new state path.
    /// When `git_root` is set and this actor was spawned with `execute`, the
    /// production tick binds that work tree so UI-registered projects can run.
    ///
    /// # Errors
    /// Returns an error if the actor is gone or switching project fails.
    pub fn switch_project(
        &self,
        state_path: PathBuf,
        git_root: Option<PathBuf>,
        managed: bool,
    ) -> Result<Reply<()>, String> {
        let ticket = self.shared.enqueue("switch_project", None, None);
        let (reply, rx) = mpsc::channel();
        self.send_tracked(
            ticket,
            ActorCommand::SwitchProject {
                ticket,
                state_path,
                git_root,
                managed,
                reply,
            },
            &rx,
        )
    }

    /// Undoes a request's result in the project folder with a new commit that reverses it.
    ///
    /// # Errors
    /// Returns an error if the actor is gone or the result cannot be undone.
    pub fn undo_goal(&self, goal_id: String) -> Result<Reply<LandingRecordV1>, String> {
        let ticket = self
            .shared
            .enqueue("undo_goal", Some(goal_id.clone()), None);
        let (reply, rx) = mpsc::channel();
        self.send_tracked(
            ticket,
            ActorCommand::UndoGoal {
                ticket,
                goal_id,
                reply,
            },
            &rx,
        )
    }

    /// Tries again to apply a request's kept result to the project folder.
    ///
    /// # Errors
    /// Returns an error if the actor is gone or there is nothing to apply.
    pub fn apply_goal(&self, goal_id: String) -> Result<Reply<LandingRecordV1>, String> {
        let ticket = self
            .shared
            .enqueue("apply_goal", Some(goal_id.clone()), None);
        let (reply, rx) = mpsc::channel();
        self.send_tracked(
            ticket,
            ActorCommand::ApplyGoal {
                ticket,
                goal_id,
                reply,
            },
            &rx,
        )
    }

    /// Gracefully shuts down the actor thread.
    ///
    /// # Errors
    /// Returns an error if the actor is gone or times out.
    pub fn shutdown(&self) -> Result<(), String> {
        let (reply, rx) = mpsc::channel();
        self.sender
            .send(ActorCommand::Shutdown { reply })
            .map_err(|_| "controller actor is not running".to_owned())?;
        rx.recv_timeout(IDLE_REPLY_TIMEOUT)
            .map_err(|_| "controller actor did not stop in time".to_owned())?
    }

    fn send_tracked<T>(
        &self,
        ticket: u64,
        cmd: ActorCommand,
        rx: &Receiver<Result<T, String>>,
    ) -> Result<Reply<T>, String> {
        if let Err(error) = self.sender.try_send(cmd) {
            self.shared.complete(ticket);
            return Err(match error {
                TrySendError::Full(_) => {
                    "Sovereign is busy with many requests. Try again in a moment.".to_owned()
                }
                TrySendError::Disconnected(_) => "controller actor is not running".to_owned(),
            });
        }
        // Busy is checked again while waiting: a command sent just before a step starts is
        // acknowledged as queued once the step begins, instead of waiting the idle timeout.
        let started = Instant::now();
        loop {
            let limit = if self.shared.is_busy() {
                BUSY_REPLY_TIMEOUT
            } else {
                IDLE_REPLY_TIMEOUT
            };
            let Some(left) = limit.checked_sub(started.elapsed()) else {
                return Ok(Reply::Queued { ticket });
            };
            match rx.recv_timeout(left.min(REPLY_POLL)) {
                Ok(result) => return result.map(Reply::Applied),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    self.shared.complete(ticket);
                    return Err("controller actor disconnected".to_owned());
                }
            }
        }
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

    fn with_control<T>(
        &mut self,
        apply: impl FnOnce(&mut LocalControl) -> Result<T, String>,
    ) -> Result<T, String> {
        match self.control.as_mut() {
            Some(control) => apply(control),
            None => Err("actor controller state not available".to_owned()),
        }
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

/// Completed requests, oldest first, as (goal id, the person's words).
fn completed_goals(model: &LocalControlReadModelV1) -> Vec<(String, String)> {
    let mut goals = model
        .status
        .goal_intents
        .iter()
        .filter(|goal| goal.status == "completed")
        .map(|goal| {
            (
                goal.submitted_at_ms,
                goal.goal_id.clone(),
                goal.natural_language_goal.clone(),
            )
        })
        .collect::<Vec<_>>();
    goals.sort();
    goals
        .into_iter()
        .map(|(_, goal_id, words)| (goal_id, words))
        .collect()
}

/// The folder the bound project's results land in, when Sovereign lands them. Landing records
/// start only once the current completions are known, so earlier work is never applied.
fn bind_landing(
    state: Option<&ActorState>,
    git_root: Option<&Path>,
    managed: bool,
    state_path: &Path,
) -> Option<ProjectWorkspace> {
    let workspace = ProjectWorkspace::new(git_root?, managed, state_path)?;
    let model = state?.control.as_ref()?.read_model().ok()?;
    let completed = completed_goals(&model)
        .into_iter()
        .map(|(goal_id, _)| goal_id)
        .collect::<Vec<_>>();
    match landing_service::ensure_landings(&workspace, &completed) {
        Ok(_) => Some(workspace),
        Err(error) => {
            eprintln!("sovereign: landing records unavailable: {error}");
            None
        }
    }
}

/// Before a request is planned, saves the person's own edits in a managed project so the plan
/// builds on them. Nothing happens while a plan is active: its worktrees are bound to HEAD.
fn prepare_folder_for_planning(control: &LocalControl, workspace: &ProjectWorkspace) {
    if !workspace.managed {
        return;
    }
    let Ok(model) = control.read_model() else {
        return;
    };
    let waiting = model
        .status
        .goal_intents
        .iter()
        .any(|goal| goal.status == "queued_for_plan_compilation");
    let busy = model.status.active_plan.is_some()
        || model
            .status
            .goal_intents
            .iter()
            .any(|goal| goal.status == "claimed_for_plan_compilation");
    if waiting && !busy {
        landing_service::save_your_edits(workspace);
    }
}

/// Applies every completed request's verified work to the folder once its plan is finalized.
fn land_finished_goals(control: &LocalControl, workspace: &ProjectWorkspace) {
    let Ok(model) = control.read_model() else {
        return;
    };
    if model.status.active_plan.is_some() {
        return;
    }
    let completed = completed_goals(&model);
    if completed.is_empty() {
        return;
    }
    if let Err(error) = landing_service::land_completed_goals(workspace, &completed, |goal_id| {
        control
            .completed_goal_work(goal_id)
            .map_err(|error| error.to_string())
    }) {
        eprintln!("sovereign: could not record a landed result: {error}");
    }
}

/// The person's words for a goal, used as the history message for its result.
fn goal_words(control: &LocalControl, goal_id: &str) -> String {
    control
        .read_model()
        .ok()
        .and_then(|model| {
            model
                .status
                .goal_intents
                .into_iter()
                .find(|goal| goal.goal_id == goal_id)
                .map(|goal| goal.natural_language_goal)
        })
        .unwrap_or_else(|| "Sovereign change".to_owned())
}

/// Errors that come from the environment (model files, memory probe) rather than from the
/// queued goal. They never fail the goal: fixing setup lets it run.
fn is_environment_error(error: &str) -> bool {
    let lowered = error.to_ascii_lowercase();
    [
        "load local model",
        "sovereign_model",
        "model runtime",
        "model path",
        "llama",
        "memory pressure",
        "pressure probe",
        "run lock",
        "state store error",
        "sandbox",
    ]
    .iter()
    .any(|needle| lowered.contains(needle))
}

/// Tracks identical composition errors so one bad request cannot block the queue forever.
#[derive(Default)]
struct CompositionErrors {
    last: Option<String>,
    count: u32,
}

impl CompositionErrors {
    /// Returns true when this error has now repeated often enough to fail the queued goal.
    fn record(&mut self, error: &str) -> bool {
        if is_environment_error(error) {
            self.clear();
            return false;
        }
        if self.last.as_deref() == Some(error) {
            self.count += 1;
        } else {
            self.last = Some(error.to_owned());
            self.count = 1;
        }
        self.count >= COMPOSITION_ERROR_LIMIT
    }

    fn clear(&mut self) {
        self.last = None;
        self.count = 0;
    }
}

/// Runs one execution step with interrupt registration and status publication around it.
fn run_step(
    service: &mut ExecutionService,
    state: &mut ActorState,
    registry: &ProjectRegistry,
    workspace: Option<&ProjectWorkspace>,
    shared: &Arc<ServiceShared>,
    errors: &mut CompositionErrors,
) {
    let Some(control) = state.control.as_mut() else {
        return;
    };
    // Busy from the first Git command to the last, so commands sent meanwhile are acknowledged
    // as queued instead of waiting the idle timeout.
    shared.begin_step();
    if let Some(workspace) = workspace {
        prepare_folder_for_planning(control, workspace);
    }
    if let Some((goal_id, handle)) = control.active_goal_interrupt() {
        shared.set_goal_interrupt(goal_id, handle);
    }
    let result = with_step_context(shared, || service.step(control, registry));
    shared.clear_interrupt();
    match result {
        Ok(_) => errors.clear(),
        Err(error) => {
            if errors.record(&error) {
                let failed = control
                    .with_controller_mut(|controller| {
                        match controller.next_queued_goal_intent()? {
                            Some(head) => controller
                                .fail_queued_goal_intent(
                                    &head.goal_id,
                                    GOAL_REASON_COMPOSITION_ERROR,
                                    &error,
                                )
                                .map(Some),
                            None => Ok(None),
                        }
                    })
                    .ok()
                    .flatten();
                errors.clear();
                if failed.is_some() {
                    service.record_error(format!(
                        "A request could not be prepared and was stopped: {error}"
                    ));
                } else {
                    service.record_error(error);
                }
            } else {
                service.record_error(error);
            }
        }
    }
    if let Some(workspace) = workspace {
        land_finished_goals(control, workspace);
    }
    shared.end_step();
    shared.publish_status(service.status().clone());
}

#[expect(
    clippy::too_many_lines,
    clippy::needless_pass_by_value,
    reason = "actor loop serializes every command"
)]
fn run_actor_loop(
    initial_state: PathBuf,
    receiver: Receiver<ActorCommand>,
    options: ActorOptions,
    shared: &Arc<ServiceShared>,
) {
    let mut execution = options
        .git_root
        .as_ref()
        .map(|root| ExecutionService::new(root.clone(), initial_state.clone()));
    let mut registry = ProjectRegistry::new();
    if let Some(root) = options.git_root.as_ref() {
        let _ = registry.register("repo.local", root);
    }
    let mut actor_state = match ActorState::open(initial_state.clone()) {
        Ok(state) => {
            shared.mark_state_ready();
            Some(state)
        }
        Err(err) => {
            eprintln!("controller actor initial state open failed: {err}");
            None
        }
    };
    shared.set_project_root(
        options
            .git_root
            .as_deref()
            .and_then(|root| root.canonicalize().ok()),
    );
    let mut workspace = options
        .lands_results
        .then(|| {
            bind_landing(
                actor_state.as_ref(),
                options.git_root.as_deref(),
                options.managed,
                &initial_state,
            )
        })
        .flatten();
    let mut errors = CompositionErrors::default();

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
                    {
                        run_step(
                            service,
                            state,
                            &registry,
                            workspace.as_ref(),
                            shared,
                            &mut errors,
                        );
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
                ticket,
                state_path,
                git_root,
                managed,
                reply,
            } => {
                let res = match &mut actor_state {
                    Some(state) => state.switch(state_path.clone()),
                    None => match ActorState::open(state_path.clone()) {
                        Ok(new_state) => {
                            actor_state = Some(new_state);
                            shared.mark_state_ready();
                            Ok(())
                        }
                        Err(e) => Err(e),
                    },
                };
                if res.is_ok() {
                    shared.set_state_path(state_path.clone());
                    bind_workspace(
                        options.execute,
                        &mut execution,
                        &mut registry,
                        git_root.as_deref(),
                        &state_path,
                    );
                    workspace = bind_landing(
                        actor_state.as_ref(),
                        git_root.as_deref(),
                        managed,
                        &state_path,
                    );
                    shared.set_project_root(
                        git_root
                            .as_deref()
                            .and_then(|root| root.canonicalize().ok()),
                    );
                    errors.clear();
                    shared.publish_status(
                        execution
                            .as_ref()
                            .map_or_else(ServiceStatusV1::default, |service| {
                                service.status().clone()
                            }),
                    );
                }
                shared.complete(ticket);
                let _ = reply.send(res);
            }
            ActorCommand::SubmitGoal {
                ticket,
                goal,
                reply,
            } => {
                let res = with_state(&mut actor_state, |control| {
                    control.submit_goal(&goal).map_err(|e| e.to_string())
                });
                shared.complete(ticket);
                let _ = reply.send(res);
            }
            ActorCommand::Pause {
                ticket,
                reason,
                reply,
            } => {
                let res = with_state(&mut actor_state, |control| {
                    control.pause(reason.as_deref()).map_err(|e| e.to_string())
                });
                shared.complete(ticket);
                let _ = reply.send(res);
            }
            ActorCommand::Resume { ticket, reply } => {
                let res = with_state(&mut actor_state, |control| {
                    control.resume().map_err(|e| e.to_string())
                });
                shared.complete(ticket);
                let _ = reply.send(res);
            }
            ActorCommand::CancelGoal {
                ticket,
                goal_id,
                principal,
                reply,
            } => {
                let res = with_state(&mut actor_state, |control| {
                    control
                        .cancel_goal(&goal_id, &principal)
                        .map_err(|e| e.to_string())
                });
                shared.complete(ticket);
                let _ = reply.send(res);
            }
            ActorCommand::UndoGoal {
                ticket,
                goal_id,
                reply,
            } => {
                let res = match (workspace.as_ref(), actor_state.as_ref()) {
                    (
                        Some(workspace),
                        Some(ActorState {
                            control: Some(control),
                            ..
                        }),
                    ) => landing_service::undo_goal(
                        workspace,
                        &goal_id,
                        &goal_words(control, &goal_id),
                    ),
                    _ => Err(NO_LANDING_WORKSPACE.to_owned()),
                };
                shared.complete(ticket);
                let _ = reply.send(res);
            }
            ActorCommand::ApplyGoal {
                ticket,
                goal_id,
                reply,
            } => {
                let res = match (workspace.as_ref(), actor_state.as_ref()) {
                    (
                        Some(workspace),
                        Some(ActorState {
                            control: Some(control),
                            ..
                        }),
                    ) => {
                        if control
                            .read_model()
                            .is_ok_and(|model| model.status.active_plan.is_some())
                        {
                            Err("Sovereign is working on another request. Try again when it finishes."
                                .to_owned())
                        } else {
                            landing_service::apply_goal(
                                workspace,
                                &goal_id,
                                &goal_words(control, &goal_id),
                                |goal_id| {
                                    control
                                        .completed_goal_work(goal_id)
                                        .map_err(|error| error.to_string())
                                },
                            )
                        }
                    }
                    _ => Err(NO_LANDING_WORKSPACE.to_owned()),
                };
                shared.complete(ticket);
                let _ = reply.send(res);
            }
            ActorCommand::RespondToApproval {
                ticket,
                request_id,
                decision,
                principal,
                reply,
            } => {
                let res = with_state(&mut actor_state, |control| {
                    control
                        .respond_to_approval(&request_id, decision, &principal)
                        .map_err(|e| e.to_string())
                });
                shared.complete(ticket);
                let _ = reply.send(res);
            }
        }
    }
}

fn with_state<T>(
    actor_state: &mut Option<ActorState>,
    apply: impl FnOnce(&mut LocalControl) -> Result<T, String>,
) -> Result<T, String> {
    match actor_state {
        Some(state) => state.with_control(apply),
        None => Err("actor controller state not available".to_owned()),
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
            .unwrap_or_else(|e| panic!("pause: {e}"))
            .applied()
            .unwrap_or_else(|| panic!("idle actor applies pause at once"));
        assert!(paused.paused);
        assert_eq!(paused.reason.as_deref(), Some("test pause"));

        let resumed = actor
            .resume()
            .unwrap_or_else(|e| panic!("resume: {e}"))
            .applied()
            .unwrap_or_else(|| panic!("idle actor applies resume at once"));
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
    fn command_during_a_long_step_is_queued_not_timed_out() {
        let (sender, receiver) = mpsc::sync_channel(ACTOR_QUEUE_BOUND);
        let shared = ServiceShared::new(temp_state("queued-command"));
        let actor = ControllerActorHandle {
            sender,
            shared: Arc::clone(&shared),
        };
        // Simulate the actor thread inside a long step: nothing drains the channel.
        shared.begin_step();
        let started = std::time::Instant::now();
        let reply = actor
            .pause(Some("while busy".to_owned()))
            .unwrap_or_else(|error| panic!("pause while busy: {error}"));
        assert!(started.elapsed() < Duration::from_secs(2));
        let Reply::Queued { ticket } = reply else {
            panic!("a busy actor must acknowledge the command as queued");
        };
        let pending = actor.pending_commands();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].kind, "pause");
        assert_eq!(pending[0].ticket, ticket);

        // The actor applies it at the next safe point and clears the pending entry.
        match receiver.recv_timeout(Duration::from_secs(1)) {
            Ok(ActorCommand::Pause { ticket: queued, .. }) => shared.complete(queued),
            other => panic!("expected the queued pause, got {other:?}"),
        }
        shared.end_step();
        assert!(actor.pending_commands().is_empty());
    }

    #[test]
    fn command_sent_just_before_a_step_is_queued_once_the_step_starts() {
        let (sender, _receiver) = mpsc::sync_channel(ACTOR_QUEUE_BOUND);
        let shared = ServiceShared::new(temp_state("step-starts"));
        let actor = ControllerActorHandle {
            sender,
            shared: Arc::clone(&shared),
        };
        // The actor is between steps when the command arrives, then starts a long step.
        let step_thread = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(200));
                shared.begin_step();
            })
        };
        let started = Instant::now();
        let reply = actor
            .pause(None)
            .unwrap_or_else(|error| panic!("pause before a step: {error}"));
        let waited = started.elapsed();
        step_thread
            .join()
            .unwrap_or_else(|_| panic!("join step thread"));
        assert!(
            waited < Duration::from_secs(2),
            "waited {waited:?}: once a step starts, the idle timeout no longer applies"
        );
        assert!(matches!(reply, Reply::Queued { .. }));
        shared.end_step();
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
                managed: false,
                lands_results: false,
            },
        )
        .unwrap_or_else(|error| panic!("spawn: {error}"));
        thread::sleep(Duration::from_millis(1_200));
        let before = actor.service_status();
        assert_eq!(before.last_outcome, "none");

        actor
            .switch_project(state_path.clone(), Some(repo), false)
            .unwrap_or_else(|error| panic!("switch: {error}"));
        thread::sleep(Duration::from_millis(1_500));
        let after = actor.service_status();
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
