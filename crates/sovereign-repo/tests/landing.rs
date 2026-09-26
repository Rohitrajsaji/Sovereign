//! Landing verified change sets in the user's folder, undoing them, and managed-project setup.

use sovereign_repo::{
    ChangeSet, ChangeSetCompositionInput, ComposeChangeSetsOutcome, LandingOutcome,
    ManagedRepositoryInit, ProjectRegistry, RESULT_REF_PREFIX, UndoOutcome, checkpoint_user_edits,
    init_managed_repository, land_change_sets, project_text_files, undo_landing,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static SEQUENCE: AtomicU64 = AtomicU64::new(1);

struct Fixture {
    base: PathBuf,
    project: PathBuf,
    worktrees: PathBuf,
    scratch: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let base = std::env::temp_dir().join(format!(
            "sovereign-landing-{label}-{}-{nanos}-{sequence}",
            std::process::id()
        ));
        let project = base.join("project");
        fs::create_dir_all(&project).unwrap_or_else(|error| panic!("create project: {error}"));
        fs::write(project.join("index.html"), "<h1>Hello</h1>\n")
            .unwrap_or_else(|error| panic!("write index: {error}"));
        fs::write(project.join("notes.txt"), "keep me\n")
            .unwrap_or_else(|error| panic!("write notes: {error}"));
        match init_managed_repository(&project)
            .unwrap_or_else(|error| panic!("init managed repository: {error}"))
        {
            ManagedRepositoryInit::Created { .. } => {}
            other @ ManagedRepositoryInit::AlreadyRepository { .. } => {
                panic!("expected a new repository, got {other:?}")
            }
        }
        Self {
            worktrees: base.join("state/worktrees"),
            scratch: base.join("state/landing"),
            base,
            project,
        }
    }

    fn registry(&self) -> ProjectRegistry {
        let mut registry = ProjectRegistry::new();
        registry
            .register("repo.local", &self.project)
            .unwrap_or_else(|error| panic!("register: {error}"));
        registry
    }

    fn read(&self, relative: &str) -> Option<String> {
        fs::read_to_string(self.project.join(relative)).ok()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("/usr/bin/git")
        .current_dir(root)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .args([
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
        ])
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("git {args:?}: {error}"));
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// Two dependent tasks: A edits index.html and creates app.js; B builds on A and edits app.js.
fn two_task_change_sets(fixture: &Fixture) -> Vec<ChangeSet> {
    let registry = fixture.registry();
    let prepare = |task: &str| {
        let lease = registry
            .prepare_worktree_lease(
                "repo.local",
                &fixture.worktrees,
                "plan.site",
                1,
                task,
                &format!("sha256:{task}-contract"),
            )
            .unwrap_or_else(|error| panic!("prepare {task}: {error}"));
        registry
            .materialize_worktree(&lease)
            .unwrap_or_else(|error| panic!("materialize {task}: {error}"));
        lease
    };

    let a = prepare("task.a");
    let a_baseline = registry
        .capture_worktree_baseline(&a)
        .unwrap_or_else(|error| panic!("A baseline: {error}"));
    fs::write(a.worktree_path.join("index.html"), "<h1>Budget</h1>\n")
        .unwrap_or_else(|error| panic!("A edit: {error}"));
    fs::write(a.worktree_path.join("app.js"), "console.log('v1');\n")
        .unwrap_or_else(|error| panic!("A create: {error}"));
    let change_a = registry
        .capture_change_set_from_baseline(&a, &a_baseline)
        .unwrap_or_else(|error| panic!("A change set: {error}"));

    let b = prepare("task.b");
    let b_baseline = match registry
        .compose_change_sets(&b, &[ChangeSetCompositionInput::current(change_a.clone())])
        .unwrap_or_else(|error| panic!("compose A into B: {error}"))
    {
        ComposeChangeSetsOutcome::Ready(baseline) => baseline,
        ComposeChangeSetsOutcome::Conflict(conflict) => panic!("unexpected conflict {conflict:?}"),
    };
    fs::write(b.worktree_path.join("app.js"), "console.log('v2');\n")
        .unwrap_or_else(|error| panic!("B edit: {error}"));
    let change_b = registry
        .capture_change_set_from_baseline(&b, &b_baseline)
        .unwrap_or_else(|error| panic!("B change set: {error}"));
    vec![change_a, change_b]
}

#[test]
fn landing_applies_the_verified_result_once_and_undo_reverses_it() {
    let fixture = Fixture::new("land-undo");
    let before = git(&fixture.project, &["rev-parse", "HEAD"]);
    let change_sets = two_task_change_sets(&fixture);

    let outcome = land_change_sets(
        &fixture.project,
        &fixture.scratch,
        "goal-budget",
        "Make a budget page",
        &change_sets,
    )
    .unwrap_or_else(|error| panic!("land: {error}"));
    let LandingOutcome::Landed {
        commit,
        changed_paths,
    } = outcome
    else {
        panic!("expected Landed, got {outcome:?}");
    };
    assert_eq!(
        fixture.read("index.html").as_deref(),
        Some("<h1>Budget</h1>\n")
    );
    assert_eq!(
        fixture.read("app.js").as_deref(),
        Some("console.log('v2');\n")
    );
    assert_eq!(fixture.read("notes.txt").as_deref(), Some("keep me\n"));
    assert_eq!(
        changed_paths,
        vec![PathBuf::from("app.js"), PathBuf::from("index.html")]
    );
    assert_eq!(git(&fixture.project, &["rev-parse", "HEAD"]), commit);
    assert_eq!(git(&fixture.project, &["rev-parse", "HEAD^"]), before);
    let message = git(&fixture.project, &["log", "-1", "--format=%B"]);
    assert!(message.starts_with("Make a budget page"), "{message}");
    assert!(message.contains("Sovereign-Goal: goal-budget"), "{message}");
    assert_eq!(
        git(
            &fixture.project,
            &["rev-parse", &format!("{RESULT_REF_PREFIX}goal-budget")]
        ),
        commit
    );
    // The folder is clean: nothing half-applied, no temporary worktree left behind.
    assert_eq!(git(&fixture.project, &["status", "--porcelain"]), "");
    assert_eq!(
        git(&fixture.project, &["worktree", "list", "--porcelain"])
            .lines()
            .filter(|line| line.starts_with("worktree "))
            .count(),
        3,
        "only the project and the two task worktrees may remain"
    );

    // Landing again (for example after a restart) is a no-op.
    assert_eq!(
        land_change_sets(
            &fixture.project,
            &fixture.scratch,
            "goal-budget",
            "Make a budget page",
            &change_sets,
        )
        .unwrap_or_else(|error| panic!("land again: {error}")),
        LandingOutcome::AlreadyLanded {
            commit: commit.clone()
        }
    );

    let undone = undo_landing(
        &fixture.project,
        &fixture.scratch,
        "goal-budget",
        &commit,
        "Make a budget page",
    )
    .unwrap_or_else(|error| panic!("undo: {error}"));
    let UndoOutcome::Undone {
        commit: undo_commit,
    } = undone
    else {
        panic!("expected Undone, got {undone:?}");
    };
    assert_eq!(
        fixture.read("index.html").as_deref(),
        Some("<h1>Hello</h1>\n")
    );
    assert_eq!(fixture.read("app.js"), None);
    assert_eq!(fixture.read("notes.txt").as_deref(), Some("keep me\n"));
    // History is kept: the landed commit is still an ancestor of the undo.
    assert_eq!(git(&fixture.project, &["rev-parse", "HEAD^"]), commit);
    assert_eq!(
        undo_landing(
            &fixture.project,
            &fixture.scratch,
            "goal-budget",
            &commit,
            "Make a budget page",
        )
        .unwrap_or_else(|error| panic!("undo again: {error}")),
        UndoOutcome::AlreadyUndone {
            commit: undo_commit
        }
    );
}

#[test]
fn landing_never_overwrites_unsaved_user_edits() {
    let fixture = Fixture::new("land-local-edits");
    let change_sets = two_task_change_sets(&fixture);
    // The user edits the same file without saving it to history.
    fs::write(fixture.project.join("index.html"), "<h1>Mine</h1>\n")
        .unwrap_or_else(|error| panic!("user edit: {error}"));

    let outcome = land_change_sets(
        &fixture.project,
        &fixture.scratch,
        "goal-blocked",
        "Make a budget page",
        &change_sets,
    )
    .unwrap_or_else(|error| panic!("land: {error}"));
    let LandingOutcome::BlockedByLocalChanges { result_commit, .. } = outcome else {
        panic!("expected BlockedByLocalChanges, got {outcome:?}");
    };
    assert_eq!(
        fixture.read("index.html").as_deref(),
        Some("<h1>Mine</h1>\n")
    );
    assert_eq!(fixture.read("app.js"), None);
    // The result is kept for later.
    assert_eq!(
        git(
            &fixture.project,
            &["rev-parse", &format!("{RESULT_REF_PREFIX}goal-blocked")]
        ),
        result_commit
    );

    // After the user's edit is saved, landing replays the result on top of it when it applies.
    fs::write(fixture.project.join("notes.txt"), "keep me too\n")
        .unwrap_or_else(|error| panic!("user edit 2: {error}"));
    fs::write(fixture.project.join("index.html"), "<h1>Hello</h1>\n")
        .unwrap_or_else(|error| panic!("restore index: {error}"));
    let saved = checkpoint_user_edits(&fixture.project, "Your edits")
        .unwrap_or_else(|error| panic!("checkpoint: {error}"));
    assert!(saved.is_some());
    assert_eq!(
        checkpoint_user_edits(&fixture.project, "Your edits")
            .unwrap_or_else(|error| panic!("checkpoint again: {error}")),
        None
    );
    let outcome = land_change_sets(
        &fixture.project,
        &fixture.scratch,
        "goal-blocked",
        "Make a budget page",
        &change_sets,
    )
    .unwrap_or_else(|error| panic!("land after save: {error}"));
    assert!(
        matches!(outcome, LandingOutcome::Landed { .. }),
        "{outcome:?}"
    );
    assert_eq!(fixture.read("notes.txt").as_deref(), Some("keep me too\n"));
    assert_eq!(
        fixture.read("app.js").as_deref(),
        Some("console.log('v2');\n")
    );
}

#[test]
fn conflicting_later_history_keeps_the_result_aside() {
    let fixture = Fixture::new("land-conflict");
    let change_sets = two_task_change_sets(&fixture);
    fs::write(
        fixture.project.join("index.html"),
        "<h1>Changed meanwhile</h1>\n",
    )
    .unwrap_or_else(|error| panic!("user edit: {error}"));
    checkpoint_user_edits(&fixture.project, "Your edits")
        .unwrap_or_else(|error| panic!("checkpoint: {error}"));
    let head = git(&fixture.project, &["rev-parse", "HEAD"]);

    let outcome = land_change_sets(
        &fixture.project,
        &fixture.scratch,
        "goal-conflict",
        "Make a budget page",
        &change_sets,
    )
    .unwrap_or_else(|error| panic!("land: {error}"));
    assert!(
        matches!(outcome, LandingOutcome::Conflict { .. }),
        "{outcome:?}"
    );
    assert_eq!(git(&fixture.project, &["rev-parse", "HEAD"]), head);
    assert_eq!(
        fixture.read("index.html").as_deref(),
        Some("<h1>Changed meanwhile</h1>\n")
    );
    assert_eq!(git(&fixture.project, &["status", "--porcelain"]), "");
}

#[test]
fn managed_setup_and_file_listing() {
    let fixture = Fixture::new("managed");
    assert!(matches!(
        init_managed_repository(&fixture.project)
            .unwrap_or_else(|error| panic!("init again: {error}")),
        ManagedRepositoryInit::AlreadyRepository { .. }
    ));
    assert!(fixture.project.join(".gitignore").is_file());
    assert_eq!(
        git(&fixture.project, &["log", "-1", "--format=%s"]),
        "Starting point"
    );

    fs::create_dir_all(fixture.project.join("node_modules/pkg"))
        .unwrap_or_else(|error| panic!("create ignored dir: {error}"));
    fs::write(fixture.project.join("node_modules/pkg/index.js"), "ignored")
        .unwrap_or_else(|error| panic!("write ignored: {error}"));
    fs::write(fixture.project.join("big.txt"), "x".repeat(4_096))
        .unwrap_or_else(|error| panic!("write big: {error}"));
    fs::write(fixture.project.join("draft.md"), "untracked but visible")
        .unwrap_or_else(|error| panic!("write draft: {error}"));
    let files = project_text_files(&fixture.project, 1_024)
        .unwrap_or_else(|error| panic!("list files: {error}"));
    assert_eq!(
        files,
        vec![
            PathBuf::from(".gitignore"),
            PathBuf::from("draft.md"),
            PathBuf::from("index.html"),
            PathBuf::from("notes.txt"),
        ]
    );
}

#[test]
fn nothing_to_land_and_invalid_goal_ids() {
    let fixture = Fixture::new("nothing");
    assert_eq!(
        land_change_sets(&fixture.project, &fixture.scratch, "goal-empty", "x", &[])
            .unwrap_or_else(|error| panic!("land nothing: {error}")),
        LandingOutcome::NothingToLand
    );
    assert!(land_change_sets(&fixture.project, &fixture.scratch, "../escape", "x", &[]).is_err());
}
