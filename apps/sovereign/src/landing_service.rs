//! Applies completed requests' verified work to the project folder, and undoes it on request.
//!
//! Callers: `actor.rs` (after each step, and the Undo and Apply commands), `dispatch.rs` (reads
//! the records for goal views).
//! API: `ProjectWorkspace`, `LandingsV1`, `LandingRecordV1`, `LandingStatusV1`, `load_landings`,
//! `ensure_landings`, `save_your_edits`, `land_completed_goals`, `undo_goal`,
//! `apply_goal`.
//!
//! Landing is a repository operation, not execution state. The Controller has verified the work
//! and recorded the goal complete; this module only replays the recorded change sets in the
//! person's folder through `sovereign_repo::land_change_sets`, which never overwrites unsaved
//! edits. Records live in `landings-v1.json` beside the project's state database and are written
//! only on the actor thread.

use serde::{Deserialize, Serialize};
use sovereign_controller::CompletedGoalWorkV1;
use sovereign_repo::{LandingOutcome, UndoOutcome, checkpoint_user_edits};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const LANDINGS_FILE: &str = "landings-v1.json";
const LANDINGS_SCHEMA_VERSION: u32 = 1;
const SCRATCH_DIR: &str = "landing-scratch";
const YOUR_EDITS_MESSAGE: &str = "Your edits";
const MAX_TECHNICAL_DETAIL_CHARS: usize = 2_000;

const BLOCKED_DETAIL: &str = "Your project folder has unsaved changes to files this result also \
changes, so Sovereign did not apply it. Save or set aside those changes, then choose Apply.";
const CONFLICT_DETAIL: &str = "Your project changed in the same places while Sovereign was \
working, so the result could not be applied automatically. It is kept, and nothing in your \
folder was changed.";
const UNDO_BLOCKED_DETAIL: &str = "Your project folder has unsaved changes to the same files, so \
nothing was undone.";
const UNDO_CONFLICT_DETAIL: &str = "Later changes touch the same lines, so this can't be undone \
automatically. Nothing was changed.";

/// Where a completed request's result stands in the project folder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LandingStatusV1 {
    /// Completed before this project kept landing records; never applied automatically.
    PredatesLanding,
    Landed,
    /// The request finished without changing any file.
    NothingToLand,
    /// Unsaved edits in the folder would be overwritten. The result is kept for Apply.
    BlockedByLocalChanges,
    /// The folder changed in the same places. The result is kept for Apply.
    Conflict,
    Undone,
    /// Applying hit an unexpected error; `technical_detail` has it.
    Failed,
}

/// One request's result in the project folder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LandingRecordV1 {
    pub goal_id: String,
    pub status: LandingStatusV1,
    /// The commit that applied the result, once landed.
    #[serde(default)]
    pub commit: Option<String>,
    #[serde(default)]
    pub undo_commit: Option<String>,
    #[serde(default)]
    pub changed_paths: Vec<String>,
    /// Plain-language explanation for a status that needs the person.
    #[serde(default)]
    pub detail: Option<String>,
    /// Git's own words, for the Advanced view.
    #[serde(default)]
    pub technical_detail: Option<String>,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LandingsV1 {
    pub schema_version: u32,
    pub records: Vec<LandingRecordV1>,
}

impl LandingsV1 {
    #[must_use]
    pub fn record(&self, goal_id: &str) -> Option<&LandingRecordV1> {
        self.records.iter().find(|record| record.goal_id == goal_id)
    }

    fn upsert(&mut self, record: LandingRecordV1) {
        match self
            .records
            .iter_mut()
            .find(|existing| existing.goal_id == record.goal_id)
        {
            Some(existing) => *existing = record,
            None => self.records.push(record),
        }
    }
}

/// The folder a project's requests land in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectWorkspace {
    pub root: PathBuf,
    /// Sovereign keeps this folder's history itself, so it may save the person's own edits.
    pub managed: bool,
    /// Directory of the project's state database, outside `root`.
    pub state_dir: PathBuf,
}

impl ProjectWorkspace {
    /// `None` when the state lives inside the folder (developer `run` layouts): there the
    /// developer applies results, and Sovereign never writes history into the folder itself.
    #[must_use]
    pub fn new(root: &Path, managed: bool, state_path: &Path) -> Option<Self> {
        let state_dir = state_path.parent()?.to_path_buf();
        let canonical_root = root.canonicalize().ok()?;
        let canonical_state = state_dir
            .canonicalize()
            .unwrap_or_else(|_| state_dir.clone());
        if canonical_state.starts_with(&canonical_root) {
            return None;
        }
        Some(Self {
            root: canonical_root,
            managed,
            state_dir,
        })
    }

    fn scratch(&self) -> PathBuf {
        self.state_dir.join(SCRATCH_DIR)
    }
}

fn now_ms() -> i64 {
    crate::service_state::unix_millis()
}

fn technical(text: &str) -> Option<String> {
    let trimmed = text.trim();
    (!trimmed.is_empty()).then(|| trimmed.chars().take(MAX_TECHNICAL_DETAIL_CHARS).collect())
}

/// Loads a project's landing records. A missing file reads as `None`.
///
/// # Errors
/// Returns an I/O or decoding error.
pub fn load_landings(state_dir: &Path) -> Result<Option<LandingsV1>, String> {
    let path = state_dir.join(LANDINGS_FILE);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("read {}: {error}", path.display())),
    };
    let landings: LandingsV1 = serde_json::from_str(&text)
        .map_err(|error| format!("parse {}: {error}", path.display()))?;
    if landings.schema_version != LANDINGS_SCHEMA_VERSION {
        return Err(format!(
            "unsupported landing records version {}",
            landings.schema_version
        ));
    }
    Ok(Some(landings))
}

fn save_landings(state_dir: &Path, landings: &LandingsV1) -> Result<(), String> {
    fs::create_dir_all(state_dir).map_err(|error| error.to_string())?;
    let path = state_dir.join(LANDINGS_FILE);
    let temporary = state_dir.join(format!("{LANDINGS_FILE}.tmp"));
    let text = serde_json::to_string_pretty(landings).map_err(|error| error.to_string())?;
    let mut file = fs::File::create(&temporary).map_err(|error| error.to_string())?;
    file.write_all(text.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|error| error.to_string())?;
    fs::rename(&temporary, &path).map_err(|error| error.to_string())
}

/// Starts landing records the first time a project is bound. Requests that completed before
/// then are marked `predates_landing`, so old work is never applied by surprise.
///
/// # Errors
/// Returns an I/O or decoding error.
pub fn ensure_landings(
    workspace: &ProjectWorkspace,
    completed_goal_ids: &[String],
) -> Result<LandingsV1, String> {
    if let Some(landings) = load_landings(&workspace.state_dir)? {
        return Ok(landings);
    }
    let updated_at_ms = now_ms();
    let landings = LandingsV1 {
        schema_version: LANDINGS_SCHEMA_VERSION,
        records: completed_goal_ids
            .iter()
            .map(|goal_id| LandingRecordV1 {
                goal_id: goal_id.clone(),
                status: LandingStatusV1::PredatesLanding,
                commit: None,
                undo_commit: None,
                changed_paths: Vec::new(),
                detail: None,
                technical_detail: None,
                updated_at_ms,
            })
            .collect(),
    };
    save_landings(&workspace.state_dir, &landings)?;
    Ok(landings)
}

/// In a managed project, saves the person's own edits to history so the next plan and its
/// result build on them. Call only while no plan is active: task worktrees are bound to HEAD.
pub fn save_your_edits(workspace: &ProjectWorkspace) {
    if workspace.managed {
        let _ = checkpoint_user_edits(&workspace.root, YOUR_EDITS_MESSAGE);
    }
}

fn record_from_outcome(goal_id: &str, outcome: Result<LandingOutcome, String>) -> LandingRecordV1 {
    let mut record = LandingRecordV1 {
        goal_id: goal_id.to_owned(),
        status: LandingStatusV1::Failed,
        commit: None,
        undo_commit: None,
        changed_paths: Vec::new(),
        detail: None,
        technical_detail: None,
        updated_at_ms: now_ms(),
    };
    match outcome {
        Ok(LandingOutcome::Landed {
            commit,
            changed_paths,
        }) => {
            record.status = LandingStatusV1::Landed;
            record.commit = Some(commit);
            record.changed_paths = changed_paths
                .iter()
                .map(|path| path.display().to_string())
                .collect();
        }
        Ok(LandingOutcome::AlreadyLanded { commit }) => {
            record.status = LandingStatusV1::Landed;
            record.commit = Some(commit);
        }
        Ok(LandingOutcome::NothingToLand) => record.status = LandingStatusV1::NothingToLand,
        Ok(LandingOutcome::BlockedByLocalChanges { detail, .. }) => {
            record.status = LandingStatusV1::BlockedByLocalChanges;
            record.detail = Some(BLOCKED_DETAIL.to_owned());
            record.technical_detail = technical(&detail);
        }
        Ok(LandingOutcome::Conflict { detail }) => {
            record.status = LandingStatusV1::Conflict;
            record.detail = Some(CONFLICT_DETAIL.to_owned());
            record.technical_detail = technical(&detail);
        }
        Err(error) => {
            record.detail =
                Some("Sovereign could not apply this result to your project.".to_owned());
            record.technical_detail = technical(&error);
        }
    }
    record
}

fn land_one(
    workspace: &ProjectWorkspace,
    goal_id: &str,
    title: &str,
    work: &impl Fn(&str) -> Result<Option<CompletedGoalWorkV1>, String>,
) -> LandingRecordV1 {
    let outcome = match work(goal_id) {
        Ok(Some(work)) => {
            save_your_edits(workspace);
            sovereign_repo::land_change_sets(
                &workspace.root,
                &workspace.scratch(),
                goal_id,
                title,
                &work.change_sets,
            )
            .map_err(|error| error.to_string())
        }
        Ok(None) => Err("the request has no completed work to apply".to_owned()),
        Err(error) => Err(error),
    };
    record_from_outcome(goal_id, outcome)
}

/// Lands every completed request that has no record yet, in the order given (oldest first).
/// Call only while no plan is active. Returns the new records.
///
/// # Errors
/// Returns an error when the records cannot be read or saved; a failed landing is a record.
pub fn land_completed_goals(
    workspace: &ProjectWorkspace,
    completed: &[(String, String)],
    work: impl Fn(&str) -> Result<Option<CompletedGoalWorkV1>, String>,
) -> Result<Vec<LandingRecordV1>, String> {
    let Some(mut landings) = load_landings(&workspace.state_dir)? else {
        return Ok(Vec::new());
    };
    let mut landed = Vec::new();
    for (goal_id, title) in completed {
        if landings.record(goal_id).is_some() {
            continue;
        }
        let record = land_one(workspace, goal_id, title, &work);
        landings.upsert(record.clone());
        save_landings(&workspace.state_dir, &landings)?;
        landed.push(record);
    }
    Ok(landed)
}

/// Tries again to apply a request whose result was blocked, conflicted, or failed.
///
/// # Errors
/// Returns a plain-language error when there is nothing to apply.
pub fn apply_goal(
    workspace: &ProjectWorkspace,
    goal_id: &str,
    title: &str,
    work: impl Fn(&str) -> Result<Option<CompletedGoalWorkV1>, String>,
) -> Result<LandingRecordV1, String> {
    let mut landings = load_landings(&workspace.state_dir)?
        .ok_or_else(|| "This project has no results to apply yet.".to_owned())?;
    match landings.record(goal_id).map(|record| record.status) {
        Some(
            LandingStatusV1::BlockedByLocalChanges
            | LandingStatusV1::Conflict
            | LandingStatusV1::Failed
            | LandingStatusV1::PredatesLanding,
        ) => {}
        Some(LandingStatusV1::Landed) => {
            return Err("This result is already in your project.".to_owned());
        }
        Some(LandingStatusV1::Undone) => {
            return Err("This result was undone. Ask again to redo it.".to_owned());
        }
        Some(LandingStatusV1::NothingToLand) => {
            return Err("This request did not change any files.".to_owned());
        }
        None => return Err("This request has no result to apply yet.".to_owned()),
    }
    let record = land_one(workspace, goal_id, title, &work);
    landings.upsert(record.clone());
    save_landings(&workspace.state_dir, &landings)?;
    Ok(record)
}

/// Undoes a landed request with a new commit that reverses it. Later history is kept.
///
/// # Errors
/// Returns a plain-language error when the request's result is not in the project.
pub fn undo_goal(
    workspace: &ProjectWorkspace,
    goal_id: &str,
    title: &str,
) -> Result<LandingRecordV1, String> {
    let mut landings = load_landings(&workspace.state_dir)?
        .ok_or_else(|| "This project has no results to undo.".to_owned())?;
    let mut record = landings
        .record(goal_id)
        .cloned()
        .ok_or_else(|| "This request has no result to undo.".to_owned())?;
    if record.status == LandingStatusV1::Undone {
        return Ok(record);
    }
    let Some(commit) = record
        .commit
        .clone()
        .filter(|_| record.status == LandingStatusV1::Landed)
    else {
        return Err(
            "This request's result is not in your project, so there is nothing to undo.".to_owned(),
        );
    };
    save_your_edits(workspace);
    let outcome = sovereign_repo::undo_landing(
        &workspace.root,
        &workspace.scratch(),
        goal_id,
        &commit,
        title,
    )
    .map_err(|error| error.to_string())?;
    record.updated_at_ms = now_ms();
    match outcome {
        UndoOutcome::Undone { commit } | UndoOutcome::AlreadyUndone { commit } => {
            record.status = LandingStatusV1::Undone;
            record.undo_commit = Some(commit);
            record.detail = None;
            record.technical_detail = None;
        }
        UndoOutcome::NotLanded => {
            return Err(
                "This result is no longer part of your project's history, so there is nothing to undo."
                    .to_owned(),
            );
        }
        UndoOutcome::BlockedByLocalChanges { detail } => {
            record.detail = Some(UNDO_BLOCKED_DETAIL.to_owned());
            record.technical_detail = technical(&detail);
        }
        UndoOutcome::Conflict { detail } => {
            record.detail = Some(UNDO_CONFLICT_DETAIL.to_owned());
            record.technical_detail = technical(&detail);
        }
    }
    landings.upsert(record.clone());
    save_landings(&workspace.state_dir, &landings)?;
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sovereign_repo::{ChangeSet, ProjectRegistry, init_managed_repository};
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQUENCE: AtomicU64 = AtomicU64::new(1);

    struct Fixture {
        base: PathBuf,
        workspace: ProjectWorkspace,
    }

    impl Fixture {
        fn new(label: &str, managed: bool) -> Self {
            let base = std::env::temp_dir().join(format!(
                "sovereign-landing-service-{label}-{}-{}-{}",
                std::process::id(),
                now_ms(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            let project = base.join("project");
            fs::create_dir_all(&project).unwrap_or_else(|error| panic!("{error}"));
            fs::write(project.join("index.html"), "<h1>Hello</h1>\n")
                .unwrap_or_else(|error| panic!("{error}"));
            init_managed_repository(&project).unwrap_or_else(|error| panic!("{error}"));
            let state_path = base.join("state").join("state.sqlite3");
            fs::create_dir_all(base.join("state")).unwrap_or_else(|error| panic!("{error}"));
            let workspace = ProjectWorkspace::new(&project, managed, &state_path)
                .unwrap_or_else(|| panic!("state outside the folder gives a workspace"));
            Self { base, workspace }
        }

        fn read(&self, relative: &str) -> Option<String> {
            fs::read_to_string(self.workspace.root.join(relative)).ok()
        }

        /// One task's change set that rewrites index.html.
        fn change_set(&self, content: &str) -> ChangeSet {
            let mut registry = ProjectRegistry::new();
            registry
                .register("repo.local", &self.workspace.root)
                .unwrap_or_else(|error| panic!("{error}"));
            let lease = registry
                .prepare_worktree_lease(
                    "repo.local",
                    &self.base.join("worktrees"),
                    "plan.page",
                    1,
                    "task.page",
                    "sha256:page-contract",
                )
                .unwrap_or_else(|error| panic!("{error}"));
            registry
                .materialize_worktree(&lease)
                .unwrap_or_else(|error| panic!("{error}"));
            let baseline = registry
                .capture_worktree_baseline(&lease)
                .unwrap_or_else(|error| panic!("{error}"));
            fs::write(lease.worktree_path.join("index.html"), content)
                .unwrap_or_else(|error| panic!("{error}"));
            registry
                .capture_change_set_from_baseline(&lease, &baseline)
                .unwrap_or_else(|error| panic!("{error}"))
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.base);
        }
    }

    fn work_for(
        change_set: ChangeSet,
    ) -> impl Fn(&str) -> Result<Option<CompletedGoalWorkV1>, String> {
        move |goal_id: &str| {
            Ok(Some(CompletedGoalWorkV1 {
                goal_id: goal_id.to_owned(),
                natural_language_goal: "Make the page say hi".to_owned(),
                plan_id: "plan.page".to_owned(),
                plan_revision: 1,
                change_sets: vec![change_set.clone()],
            }))
        }
    }

    fn completed(goal_id: &str) -> Vec<(String, String)> {
        vec![(goal_id.to_owned(), "Make the page say hi".to_owned())]
    }

    #[test]
    fn state_inside_the_folder_never_lands() {
        let fixture = Fixture::new("inside", true);
        let inside = fixture.workspace.root.join(".sovereign/state.sqlite3");
        assert!(ProjectWorkspace::new(&fixture.workspace.root, true, &inside).is_none());
    }

    #[test]
    fn earlier_completions_are_never_applied_by_surprise() {
        let fixture = Fixture::new("predates", true);
        let change_set = fixture.change_set("<h1>Old</h1>\n");
        ensure_landings(&fixture.workspace, &["goal-old".to_owned()])
            .unwrap_or_else(|error| panic!("{error}"));
        let landed = land_completed_goals(
            &fixture.workspace,
            &completed("goal-old"),
            work_for(change_set),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(landed.is_empty());
        assert_eq!(
            fixture.read("index.html").as_deref(),
            Some("<h1>Hello</h1>\n")
        );
    }

    #[test]
    fn completed_goal_lands_once_and_undo_restores_the_folder() {
        let fixture = Fixture::new("land-undo", true);
        ensure_landings(&fixture.workspace, &[]).unwrap_or_else(|error| panic!("{error}"));
        let change_set = fixture.change_set("<h1>Hi</h1>\n");
        let landed = land_completed_goals(
            &fixture.workspace,
            &completed("goal-hi"),
            work_for(change_set.clone()),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(landed.len(), 1);
        assert_eq!(landed[0].status, LandingStatusV1::Landed);
        assert_eq!(landed[0].changed_paths, vec!["index.html".to_owned()]);
        assert_eq!(fixture.read("index.html").as_deref(), Some("<h1>Hi</h1>\n"));

        // A second pass does not land it again.
        let again = land_completed_goals(
            &fixture.workspace,
            &completed("goal-hi"),
            work_for(change_set),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(again.is_empty());

        let undone = undo_goal(&fixture.workspace, "goal-hi", "Make the page say hi")
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(undone.status, LandingStatusV1::Undone);
        assert_eq!(
            fixture.read("index.html").as_deref(),
            Some("<h1>Hello</h1>\n")
        );
        let reloaded = load_landings(&fixture.workspace.state_dir)
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("records exist"));
        assert_eq!(
            reloaded.record("goal-hi").map(|record| record.status),
            Some(LandingStatusV1::Undone)
        );
    }

    #[test]
    fn managed_project_keeps_the_persons_own_edits_under_the_result() {
        let fixture = Fixture::new("managed-edits", true);
        ensure_landings(&fixture.workspace, &[]).unwrap_or_else(|error| panic!("{error}"));
        let change_set = fixture.change_set("<h1>Hi</h1>\n");
        // The person edits another file while the request runs.
        fs::write(fixture.workspace.root.join("notes.txt"), "mine\n")
            .unwrap_or_else(|error| panic!("{error}"));
        let landed = land_completed_goals(
            &fixture.workspace,
            &completed("goal-hi"),
            work_for(change_set),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(landed[0].status, LandingStatusV1::Landed);
        assert_eq!(fixture.read("notes.txt").as_deref(), Some("mine\n"));
        assert_eq!(fixture.read("index.html").as_deref(), Some("<h1>Hi</h1>\n"));
        let log = Command::new("/usr/bin/git")
            .args(["log", "--format=%s"])
            .current_dir(&fixture.workspace.root)
            .output()
            .unwrap_or_else(|error| panic!("{error}"));
        let subjects = String::from_utf8_lossy(&log.stdout).into_owned();
        assert!(subjects.contains("Your edits"), "{subjects}");
    }

    #[test]
    fn unmanaged_folder_with_unsaved_edits_is_blocked_then_applies() {
        let fixture = Fixture::new("unmanaged", false);
        ensure_landings(&fixture.workspace, &[]).unwrap_or_else(|error| panic!("{error}"));
        let change_set = fixture.change_set("<h1>Hi</h1>\n");
        fs::write(fixture.workspace.root.join("index.html"), "<h1>Mine</h1>\n")
            .unwrap_or_else(|error| panic!("{error}"));
        let landed = land_completed_goals(
            &fixture.workspace,
            &completed("goal-hi"),
            work_for(change_set.clone()),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(landed[0].status, LandingStatusV1::BlockedByLocalChanges);
        assert!(landed[0].detail.is_some());
        assert_eq!(
            fixture.read("index.html").as_deref(),
            Some("<h1>Mine</h1>\n")
        );

        // The person sets their edit aside; Apply now lands the kept result.
        fs::write(
            fixture.workspace.root.join("index.html"),
            "<h1>Hello</h1>\n",
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let applied = apply_goal(
            &fixture.workspace,
            "goal-hi",
            "Make the page say hi",
            work_for(change_set),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(applied.status, LandingStatusV1::Landed);
        assert_eq!(fixture.read("index.html").as_deref(), Some("<h1>Hi</h1>\n"));
        assert!(apply_goal(&fixture.workspace, "goal-hi", "x", |_| Ok(None)).is_err());
    }
}
