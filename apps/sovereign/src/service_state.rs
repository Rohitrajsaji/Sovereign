//! Service-level state shared between the Controller actor and HTTP worker threads.
//!
//! Callers: `actor.rs` (writes), `dispatch.rs` (reads), `runner.rs` (compile interrupt).
//! API: `ServiceShared`, `PendingCommandV1`, `with_step_context`, `register_compile_interrupt`.
//!
//! The Controller remains the only writer of execution state. This module holds only facts about
//! the service: which project database is current, the last published service status, whether a
//! step is running, commands accepted but not yet applied, and what a cancel can interrupt right
//! now. Interrupting only sets a cancellation bit or unloads the model; the durable cancellation
//! is still recorded by the Controller at the next safe point.

use crate::execution::ServiceStatusV1;
use crate::model_setup::ModelSetup;
use crate::preview::{PreviewAddressV1, PreviewRoot};
use serde::Serialize;
use sovereign_controller::{CancellationHandle, MAX_MEMORY_ALLOWANCE_MIB, MemoryWaitV1};
use sovereign_model::ModelBackend;
use std::cell::RefCell;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// A step shorter than this is not shown as "working".
const WORKING_AFTER_MS: i64 = 1_000;

/// A command the service accepted while a step was running. The actor applies it at the next
/// safe point and then removes it.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PendingCommandV1 {
    pub ticket: u64,
    pub kind: String,
    pub goal_id: Option<String>,
    /// The user's own words for a submitted request. Never model or repository text.
    pub text: Option<String>,
    pub accepted_at_ms: i64,
}

#[derive(Default)]
struct InterruptTarget {
    goal_id: Option<String>,
    goal_handle: Option<CancellationHandle>,
    compile_backend: Option<Arc<dyn ModelBackend>>,
}

/// Shared service facts. Cheap to clone through `Arc`.
pub struct ServiceShared {
    state_path: RwLock<PathBuf>,
    /// Set once the actor has opened (and migrated) the current state database. Reads wait for
    /// it so two connections never race the first-time schema setup.
    state_ready: AtomicBool,
    status: Mutex<ServiceStatusV1>,
    busy_since_ms: Mutex<Option<i64>>,
    pending: Mutex<Vec<PendingCommandV1>>,
    next_ticket: AtomicU64,
    interrupt: Mutex<InterruptTarget>,
    /// Onboarding's model download. It runs beside the actor and never touches Controller state.
    model_setup: Arc<ModelSetup>,
    /// The bound project's folder, which the preview and the Files tab show read-only.
    project_root: PreviewRoot,
    preview: std::sync::OnceLock<PreviewAddressV1>,
    /// The request waiting for memory and by how much, and the memory the person lent it with
    /// "Start anyway". Neither is durable: a restart measures again.
    memory: Mutex<MemoryFacts>,
}

#[derive(Debug, Default)]
struct MemoryFacts {
    wait: Option<(String, MemoryWaitV1)>,
    allowance: Option<(String, u64)>,
}

/// Extra memory lent on top of the shortfall, so a small change in free memory between the
/// wait and the next try does not stop it again.
const ALLOWANCE_MARGIN_MIB: u64 = 128;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

pub(crate) fn unix_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
        })
}

impl ServiceShared {
    #[must_use]
    pub fn new(state_path: PathBuf) -> Arc<Self> {
        Arc::new(Self {
            state_path: RwLock::new(state_path),
            state_ready: AtomicBool::new(false),
            status: Mutex::new(ServiceStatusV1::default()),
            busy_since_ms: Mutex::new(None),
            pending: Mutex::new(Vec::new()),
            next_ticket: AtomicU64::new(1),
            interrupt: Mutex::new(InterruptTarget::default()),
            model_setup: Arc::new(ModelSetup::default()),
            project_root: Arc::new(RwLock::new(None)),
            preview: std::sync::OnceLock::new(),
            memory: Mutex::new(MemoryFacts::default()),
        })
    }

    /// The request waiting for memory, and how short it is.
    #[must_use]
    pub fn memory_wait(&self) -> Option<(String, MemoryWaitV1)> {
        lock(&self.memory).wait.clone()
    }

    fn publish_memory_wait(&self, goal_id: &str, wait: Option<MemoryWaitV1>) {
        let mut memory = lock(&self.memory);
        memory.wait = wait.map(|wait| (goal_id.to_owned(), wait));
        if memory.wait.is_none()
            && memory
                .allowance
                .as_ref()
                .is_some_and(|(allowed, _)| allowed != goal_id)
        {
            memory.allowance = None;
        }
    }

    /// "Start anyway": lends the waiting request the memory it is short by, when that is at
    /// most [`MAX_MEMORY_ALLOWANCE_MIB`]. Returns the amount lent.
    ///
    /// # Errors
    /// Returns a plain reason when the request is not waiting for memory or is too far short.
    pub fn grant_memory_allowance(&self, goal_id: &str) -> Result<u64, String> {
        let mut memory = lock(&self.memory);
        let Some((waiting, wait)) = memory.wait.as_ref() else {
            return Err("This request isn't waiting for memory.".to_owned());
        };
        if waiting != goal_id {
            return Err("This request isn't the one waiting for memory.".to_owned());
        }
        let short = wait.short_mib();
        if short > MAX_MEMORY_ALLOWANCE_MIB {
            return Err(format!(
                "This request needs about {:.1} GB more free memory, too much to start anyway. Close other apps or choose a smaller model in Settings.",
                gib(short)
            ));
        }
        let lent = short
            .saturating_add(ALLOWANCE_MARGIN_MIB)
            .min(MAX_MEMORY_ALLOWANCE_MIB);
        memory.allowance = Some((goal_id.to_owned(), lent));
        Ok(lent)
    }

    fn memory_allowance_for(&self, goal_id: &str) -> u64 {
        lock(&self.memory)
            .allowance
            .as_ref()
            .filter(|(allowed, _)| allowed == goal_id)
            .map_or(0, |(_, mib)| *mib)
    }

    /// The folder shared with the preview server.
    #[must_use]
    pub fn project_root_handle(&self) -> PreviewRoot {
        Arc::clone(&self.project_root)
    }

    #[must_use]
    pub fn project_root(&self) -> Option<PathBuf> {
        self.project_root
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub fn set_project_root(&self, root: Option<PathBuf>) {
        *self
            .project_root
            .write()
            .unwrap_or_else(PoisonError::into_inner) = root;
    }

    pub fn set_preview(&self, address: PreviewAddressV1) {
        let _ = self.preview.set(address);
    }

    #[must_use]
    pub fn preview(&self) -> Option<PreviewAddressV1> {
        self.preview.get().cloned()
    }

    #[must_use]
    pub fn model_setup(&self) -> Arc<ModelSetup> {
        Arc::clone(&self.model_setup)
    }

    /// The state database of the project the actor currently holds.
    #[must_use]
    pub fn state_path(&self) -> PathBuf {
        self.state_path
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub fn set_state_path(&self, path: PathBuf) {
        *self
            .state_path
            .write()
            .unwrap_or_else(PoisonError::into_inner) = path;
    }

    pub fn mark_state_ready(&self) {
        self.state_ready.store(true, Ordering::Release);
    }

    #[must_use]
    pub fn state_ready(&self) -> bool {
        self.state_ready.load(Ordering::Acquire)
    }

    #[must_use]
    pub fn status(&self) -> ServiceStatusV1 {
        lock(&self.status).clone()
    }

    pub fn publish_status(&self, status: ServiceStatusV1) {
        *lock(&self.status) = status;
    }

    pub fn begin_step(&self) {
        *lock(&self.busy_since_ms) = Some(unix_millis());
    }

    pub fn end_step(&self) {
        *lock(&self.busy_since_ms) = None;
    }

    #[must_use]
    pub fn is_busy(&self) -> bool {
        lock(&self.busy_since_ms).is_some()
    }

    /// True while a step has been running long enough to be worth showing.
    #[must_use]
    pub fn working(&self) -> bool {
        lock(&self.busy_since_ms).is_some_and(|since| unix_millis() - since >= WORKING_AFTER_MS)
    }

    /// Records a command as accepted and returns its ticket.
    pub fn enqueue(&self, kind: &str, goal_id: Option<String>, text: Option<String>) -> u64 {
        let ticket = self.next_ticket.fetch_add(1, Ordering::Relaxed);
        lock(&self.pending).push(PendingCommandV1 {
            ticket,
            kind: kind.to_owned(),
            goal_id,
            text,
            accepted_at_ms: unix_millis(),
        });
        ticket
    }

    /// Removes a command once the actor has applied or rejected it.
    pub fn complete(&self, ticket: u64) {
        lock(&self.pending).retain(|command| command.ticket != ticket);
    }

    #[must_use]
    pub fn pending(&self) -> Vec<PendingCommandV1> {
        lock(&self.pending).clone()
    }

    pub fn set_goal_interrupt(&self, goal_id: String, handle: CancellationHandle) {
        let mut target = lock(&self.interrupt);
        target.goal_id = Some(goal_id);
        target.goal_handle = Some(handle);
    }

    pub fn clear_interrupt(&self) {
        *lock(&self.interrupt) = InterruptTarget::default();
    }

    /// Stops in-flight work for `goal_id` now: cancels its running tasks, or unloads the model
    /// while its plan is being compiled. Returns true when something was interrupted.
    pub fn interrupt_goal(&self, goal_id: &str) -> bool {
        let target = lock(&self.interrupt);
        if target.goal_id.as_deref() != Some(goal_id) {
            return false;
        }
        let mut interrupted = false;
        if let Some(handle) = target.goal_handle.as_ref() {
            interrupted |= handle.cancel().is_ok();
        }
        if let Some(backend) = target.compile_backend.as_ref() {
            interrupted |= backend.unload().is_ok();
        }
        interrupted
    }
}

thread_local! {
    static STEP_CONTEXT: RefCell<Option<Arc<ServiceShared>>> = const { RefCell::new(None) };
}

/// Runs one production step with `shared` available to code deep inside the step (the runner's
/// compile path) on this thread only.
pub fn with_step_context<T>(shared: &Arc<ServiceShared>, step: impl FnOnce() -> T) -> T {
    STEP_CONTEXT.with(|slot| *slot.borrow_mut() = Some(Arc::clone(shared)));
    let result = step();
    STEP_CONTEXT.with(|slot| *slot.borrow_mut() = None);
    result
}

/// Clears the compile interrupt when dropped, so every exit from the compile path clears it.
#[must_use]
pub struct CompileInterruptGuard(());

impl Drop for CompileInterruptGuard {
    fn drop(&mut self) {
        clear_compile_interrupt();
    }
}

/// Lets a cancel unload the model while `goal_id`'s plan is being compiled, until the returned
/// guard drops. No-op outside a service step (for example `sovereign run`).
pub fn register_compile_interrupt(
    goal_id: &str,
    backend: Arc<dyn ModelBackend>,
) -> CompileInterruptGuard {
    STEP_CONTEXT.with(|slot| {
        if let Some(shared) = slot.borrow().as_ref() {
            let mut target = lock(&shared.interrupt);
            target.goal_id = Some(goal_id.to_owned());
            target.compile_backend = Some(backend);
        }
    });
    CompileInterruptGuard(())
}

/// Memory lent to `goal_id` with "Start anyway". Zero outside a service step.
#[must_use]
pub fn memory_allowance_for(goal_id: &str) -> u64 {
    STEP_CONTEXT.with(|slot| {
        slot.borrow()
            .as_ref()
            .map_or(0, |shared| shared.memory_allowance_for(goal_id))
    })
}

/// Reports whether `goal_id`'s model is waiting for memory. No-op outside a service step.
pub fn publish_memory_wait(goal_id: &str, wait: Option<MemoryWaitV1>) {
    STEP_CONTEXT.with(|slot| {
        if let Some(shared) = slot.borrow().as_ref() {
            shared.publish_memory_wait(goal_id, wait);
        }
    });
}

/// Mebibytes as gigabytes for plain sentences.
#[must_use]
#[expect(clippy::cast_precision_loss, reason = "a rounded figure for people")]
pub fn gib(mib: u64) -> f64 {
    mib as f64 / 1_024.0
}

fn clear_compile_interrupt() {
    STEP_CONTEXT.with(|slot| {
        if let Some(shared) = slot.borrow().as_ref() {
            lock(&shared.interrupt).compile_backend = None;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_anyway_lends_only_a_small_shortfall_to_the_waiting_request() {
        let shared = ServiceShared::new(PathBuf::from("/tmp/state.sqlite3"));
        assert!(shared.grant_memory_allowance("goal-1").is_err());
        shared.publish_memory_wait(
            "goal-1",
            Some(MemoryWaitV1 {
                needed_mib: 5_632,
                free_mib: 5_324,
            }),
        );
        assert!(shared.grant_memory_allowance("goal-2").is_err());
        assert_eq!(shared.grant_memory_allowance("goal-1"), Ok(308 + 128));
        assert_eq!(shared.memory_allowance_for("goal-1"), 436);
        assert_eq!(shared.memory_allowance_for("goal-2"), 0);
        // Admitted: the wait clears but the allowance stays with its request.
        shared.publish_memory_wait("goal-1", None);
        assert_eq!(shared.memory_allowance_for("goal-1"), 436);
        // Another request runs: the old allowance is dropped.
        shared.publish_memory_wait("goal-2", None);
        assert_eq!(shared.memory_allowance_for("goal-1"), 0);

        shared.publish_memory_wait(
            "goal-3",
            Some(MemoryWaitV1 {
                needed_mib: 5_632,
                free_mib: 2_000,
            }),
        );
        let refused = shared.grant_memory_allowance("goal-3");
        assert!(
            refused
                .as_ref()
                .is_err_and(|reason| reason.contains("smaller model")),
            "{refused:?}"
        );
    }

    #[test]
    fn pending_commands_are_tracked_by_ticket() {
        let shared = ServiceShared::new(PathBuf::from("/tmp/state.sqlite3"));
        let first = shared.enqueue("submit_goal", None, Some("Make a page".to_owned()));
        let second = shared.enqueue("cancel_goal", Some("goal-1".to_owned()), None);
        assert_ne!(first, second);
        assert_eq!(shared.pending().len(), 2);
        shared.complete(second);
        assert_eq!(shared.pending().len(), 1);
        assert_eq!(shared.pending()[0].ticket, first);
    }

    #[test]
    fn working_needs_a_running_step() {
        let shared = ServiceShared::new(PathBuf::from("/tmp/state.sqlite3"));
        assert!(!shared.is_busy());
        assert!(!shared.working());
        shared.begin_step();
        assert!(shared.is_busy());
        shared.end_step();
        assert!(!shared.is_busy());
    }

    #[test]
    fn interrupt_only_targets_the_registered_goal() {
        let shared = ServiceShared::new(PathBuf::from("/tmp/state.sqlite3"));
        assert!(!shared.interrupt_goal("goal-1"));
        shared.set_state_path(PathBuf::from("/tmp/other.sqlite3"));
        assert_eq!(shared.state_path(), PathBuf::from("/tmp/other.sqlite3"));
    }
}
