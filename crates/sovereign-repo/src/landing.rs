//! Landing verified work in the user's project folder, undoing it, and keeping a Sovereign-managed
//! folder under version control without the user having to know Git.
//!
//! Callers: the local service (`apps/sovereign`) after the Controller records a goal complete.
//! API: `land_change_sets`, `undo_landing`, `init_managed_repository`, `checkpoint_user_edits`,
//! `project_text_files`.
//!
//! Nothing here resets, rewrites, or force-updates the user's work:
//! - results are built in a temporary detached worktree and reach the user's folder only through
//!   `git merge --ff-only`, which refuses rather than overwrite uncommitted edits;
//! - Undo is a `git revert` commit, built the same way;
//! - every result commit is also kept under `refs/sovereign/results/<goal>` so a result that could
//!   not be applied is never lost.
//!
//! All Git calls use the hardened command (no hooks, no global config, no network protocols).

use crate::worktree::{
    ChangeSet, apply_untracked_deltas, git_failure, git_output_with_input, git_required_dynamic,
    reject_checkout_side_effects,
};
use crate::{RepoError, git_output};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};

/// Hidden ref namespace that keeps every result commit reachable.
pub const RESULT_REF_PREFIX: &str = "refs/sovereign/results/";
const GOAL_TRAILER: &str = "Sovereign-Goal";
const UNDO_TRAILER: &str = "Sovereign-Undo";
const IDENTITY: [&str; 4] = [
    "-c",
    "user.name=Sovereign",
    "-c",
    "user.email=sovereign@localhost",
];
const MAX_SUBJECT_CHARS: usize = 72;
const DEFAULT_GITIGNORE: &str = ".DS_Store\nnode_modules/\n__pycache__/\n*.pyc\n.venv/\n";

/// Result of applying a completed goal's verified work to the project folder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LandingOutcome {
    /// The folder now contains the result, as one new commit.
    Landed {
        commit: String,
        changed_paths: Vec<PathBuf>,
    },
    /// This goal's result was applied before (for example before a restart).
    AlreadyLanded { commit: String },
    /// The goal verified without changing any file.
    NothingToLand,
    /// Applying would overwrite edits the user has not saved to history. The result is kept
    /// under its result ref.
    BlockedByLocalChanges {
        result_commit: String,
        detail: String,
    },
    /// The project changed in the same places since the goal started. The result is kept.
    Conflict { detail: String },
}

/// Result of undoing a landed goal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UndoOutcome {
    Undone {
        commit: String,
    },
    AlreadyUndone {
        commit: String,
    },
    /// The landed commit is not part of the project's current history.
    NotLanded,
    BlockedByLocalChanges {
        detail: String,
    },
    /// Later changes touch the same lines, so the undo cannot be applied automatically.
    Conflict {
        detail: String,
    },
}

/// Result of preparing a folder as a Sovereign-managed project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ManagedRepositoryInit {
    /// A new repository was created with a first "Starting point" commit.
    Created { head: String },
    /// The folder already is (or is inside) a Git repository; nothing was changed.
    AlreadyRepository { root: PathBuf },
}

fn git_text(root: &Path, operation: &'static str, args: &[&str]) -> Result<String, RepoError> {
    let output = git_required_dynamic(root, operation, args)?;
    Ok(String::from_utf8(output.stdout)
        .map_err(|_| RepoError::NonUtf8GitOutput(operation))?
        .trim()
        .to_owned())
}

fn valid_goal_id(goal_id: &str) -> bool {
    (1..=128).contains(&goal_id.len())
        && goal_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn commit_subject(title: &str) -> String {
    let single_line = title.split_whitespace().collect::<Vec<_>>().join(" ");
    let subject = if single_line.is_empty() {
        "Sovereign change".to_owned()
    } else {
        single_line
    };
    if subject.chars().count() <= MAX_SUBJECT_CHARS {
        return subject;
    }
    let mut shortened: String = subject.chars().take(MAX_SUBJECT_CHARS - 1).collect();
    shortened.push('…');
    shortened
}

fn canonical_repository_root(root: &Path) -> Result<PathBuf, RepoError> {
    let canonical = root.canonicalize()?;
    let top = git_text(
        &canonical,
        "read repository root",
        &["rev-parse", "--show-toplevel"],
    )?;
    let top = PathBuf::from(top).canonicalize()?;
    if top != canonical {
        return Err(RepoError::RepositoryRootMismatch {
            requested: canonical,
            actual: top,
        });
    }
    Ok(canonical)
}

fn head(root: &Path) -> Result<String, RepoError> {
    git_text(root, "read HEAD", &["rev-parse", "--verify", "HEAD"])
}

fn find_trailer_commit(
    root: &Path,
    trailer: &str,
    goal_id: &str,
    range: &str,
) -> Result<Option<String>, RepoError> {
    let pattern = format!("^{trailer}: {goal_id}$");
    let found = git_text(
        root,
        "search Sovereign history",
        &["log", "--format=%H", "-n", "1", "--grep", &pattern, range],
    )?;
    Ok((!found.is_empty()).then_some(found))
}

/// A Sovereign-owned temporary worktree that is always removed.
struct TempWorktree {
    repository: PathBuf,
    path: PathBuf,
}

impl TempWorktree {
    fn create(
        repository: &Path,
        scratch_root: &Path,
        name: &str,
        commit: &str,
    ) -> Result<Self, RepoError> {
        reject_checkout_side_effects(repository, commit)?;
        fs::create_dir_all(scratch_root)?;
        let scratch_root = scratch_root.canonicalize()?;
        let path = scratch_root.join(name);
        let path_text = path.to_str().ok_or_else(|| {
            RepoError::InvalidWorktreeLease("landing worktree path is not UTF-8".to_owned())
        })?;
        if path.exists() {
            // Left over from an interrupted landing; it is Sovereign's own worktree.
            let _ = git_output(repository, &["worktree", "remove", "--force", path_text]);
            if path.exists() {
                fs::remove_dir_all(&path)?;
            }
            let _ = git_output(repository, &["worktree", "prune"]);
        }
        git_required_dynamic(
            repository,
            "create landing worktree",
            &[
                "worktree",
                "add",
                "--detach",
                "--no-checkout",
                path_text,
                commit,
            ],
        )?;
        let worktree = Self {
            repository: repository.to_path_buf(),
            path,
        };
        git_required_dynamic(
            &worktree.path,
            "populate landing index",
            &["read-tree", commit],
        )?;
        git_required_dynamic(
            &worktree.path,
            "populate landing files",
            &["checkout-index", "-a"],
        )?;
        git_required_dynamic(
            &worktree.path,
            "refresh landing index",
            &["update-index", "--refresh"],
        )?;
        Ok(worktree)
    }

    fn commit(&self, message: &str) -> Result<Option<String>, RepoError> {
        git_required_dynamic(&self.path, "stage landing result", &["add", "-A"])?;
        let staged = git_output(&self.path, &["diff", "--cached", "--quiet"])?;
        if staged.status.success() {
            return Ok(None);
        }
        let mut args = IDENTITY.to_vec();
        args.extend([
            "commit",
            "-q",
            "--no-verify",
            "--no-gpg-sign",
            "-m",
            message,
        ]);
        git_required_dynamic(&self.path, "commit landing result", &args)?;
        head(&self.path).map(Some)
    }
}

impl Drop for TempWorktree {
    fn drop(&mut self) {
        if let Some(path) = self.path.to_str() {
            let _ = git_output(&self.repository, &["worktree", "remove", "--force", path]);
        }
        if self.path.exists() {
            let _ = fs::remove_dir_all(&self.path);
        }
        let _ = git_output(&self.repository, &["worktree", "prune"]);
    }
}

/// Moves the user's folder forward to `commit`, refusing rather than overwrite local edits.
/// Returns `Err(detail)` in the refusal case.
fn fast_forward(root: &Path, commit: &str) -> Result<Result<(), String>, RepoError> {
    let output = git_output(root, &["merge", "--ff-only", "--no-edit", "-q", commit])?;
    if output.status.success() {
        return Ok(Ok(()));
    }
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if stderr.contains("would be overwritten") || stderr.contains("untracked working tree files") {
        return Ok(Err(stderr));
    }
    Err(git_failure("apply result to project", &output))
}

fn changed_paths(root: &Path, from: &str, to: &str) -> Result<Vec<PathBuf>, RepoError> {
    let output = git_required_dynamic(
        root,
        "list landed paths",
        &["diff", "--name-only", "-z", from, to],
    )?;
    Ok(output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
        .map(|entry| PathBuf::from(String::from_utf8_lossy(entry).into_owned()))
        .collect())
}

/// Applies a completed goal's verified change sets to the project folder as one commit.
///
/// `ordered` must list every task's change set in dependency order (upstream first); each is that
/// task's own delta on top of its composed baseline, so replaying them in order reproduces the
/// verified result. All must share one base commit. If the project moved on since, the result is
/// replayed on top of the current commit when that applies cleanly.
///
/// # Errors
/// Returns a repository error for an invalid goal id, mismatched change sets, unsafe checkout
/// configuration, or a Git failure other than the refusals reported in [`LandingOutcome`].
#[allow(clippy::too_many_lines)]
pub fn land_change_sets(
    repository_root: &Path,
    scratch_root: &Path,
    goal_id: &str,
    title: &str,
    ordered: &[ChangeSet],
) -> Result<LandingOutcome, RepoError> {
    if !valid_goal_id(goal_id) {
        return Err(RepoError::InvalidWorktreeLease(format!(
            "invalid goal id for landing {goal_id:?}"
        )));
    }
    let root = canonical_repository_root(repository_root)?;
    let current_head = head(&root)?;
    if let Some(commit) = find_trailer_commit(&root, GOAL_TRAILER, goal_id, "HEAD")? {
        return Ok(LandingOutcome::AlreadyLanded { commit });
    }
    let changes = ordered
        .iter()
        .filter(|change_set| {
            !change_set.diff_content.is_empty() || !change_set.untracked_deltas.is_empty()
        })
        .collect::<Vec<_>>();
    let Some(first) = changes.first() else {
        return Ok(LandingOutcome::NothingToLand);
    };
    let base_head = first.base_head.clone();
    if changes
        .iter()
        .any(|change_set| change_set.base_head != base_head)
    {
        return Err(RepoError::InvalidWorktreeLease(
            "change sets for one goal do not share a base commit".to_owned(),
        ));
    }

    let subject = commit_subject(title);
    let message = format!("{subject}\n\n{GOAL_TRAILER}: {goal_id}");
    let result = {
        let worktree =
            TempWorktree::create(&root, scratch_root, &format!("land-{goal_id}"), &base_head)?;
        for change_set in &changes {
            if !change_set.diff_content.is_empty() {
                let applied = git_output_with_input(
                    &worktree.path,
                    &["apply", "--index", "--binary", "--whitespace=nowarn", "-"],
                    change_set.diff_content.as_bytes(),
                )?;
                if !applied.status.success() {
                    return Ok(LandingOutcome::Conflict {
                        detail: String::from_utf8_lossy(&applied.stderr).into_owned(),
                    });
                }
            }
            apply_untracked_deltas(&worktree.path, &change_set.untracked_deltas)?;
        }
        match worktree.commit(&message)? {
            Some(commit) => commit,
            None => return Ok(LandingOutcome::NothingToLand),
        }
    };
    let result_ref = format!("{RESULT_REF_PREFIX}{goal_id}");
    git_required_dynamic(
        &root,
        "keep result commit",
        &["update-ref", &result_ref, &result],
    )?;

    // Replay on top of newer project history when the folder moved on since the goal started.
    let candidate = if current_head == base_head {
        result
    } else {
        let worktree = TempWorktree::create(
            &root,
            scratch_root,
            &format!("rebase-{goal_id}"),
            &current_head,
        )?;
        let picked = git_output(
            &worktree.path,
            &["cherry-pick", "--no-commit", "--allow-empty", &result],
        )?;
        if !picked.status.success() {
            let _ = git_output(&worktree.path, &["cherry-pick", "--abort"]);
            return Ok(LandingOutcome::Conflict {
                detail: String::from_utf8_lossy(&picked.stderr).into_owned(),
            });
        }
        match worktree.commit(&message)? {
            Some(commit) => {
                git_required_dynamic(
                    &root,
                    "keep result commit",
                    &["update-ref", &result_ref, &commit],
                )?;
                commit
            }
            None => return Ok(LandingOutcome::NothingToLand),
        }
    };

    reject_checkout_side_effects(&root, &candidate)?;
    match fast_forward(&root, &candidate)? {
        Ok(()) => Ok(LandingOutcome::Landed {
            changed_paths: changed_paths(&root, &current_head, &candidate)?,
            commit: candidate,
        }),
        Err(detail) => Ok(LandingOutcome::BlockedByLocalChanges {
            result_commit: candidate,
            detail,
        }),
    }
}

/// Undoes a landed goal with a new commit that reverses it. Later history is kept.
///
/// # Errors
/// Returns a repository error for an invalid goal id or a Git failure other than the refusals
/// reported in [`UndoOutcome`].
pub fn undo_landing(
    repository_root: &Path,
    scratch_root: &Path,
    goal_id: &str,
    landed_commit: &str,
    title: &str,
) -> Result<UndoOutcome, RepoError> {
    if !valid_goal_id(goal_id) {
        return Err(RepoError::InvalidWorktreeLease(format!(
            "invalid goal id for undo {goal_id:?}"
        )));
    }
    let root = canonical_repository_root(repository_root)?;
    let landed = git_text(
        &root,
        "resolve landed commit",
        &[
            "rev-parse",
            "--verify",
            &format!("{landed_commit}^{{commit}}"),
        ],
    )?;
    let is_ancestor = git_output(&root, &["merge-base", "--is-ancestor", &landed, "HEAD"])?;
    if !is_ancestor.status.success() {
        return Ok(UndoOutcome::NotLanded);
    }
    if let Some(commit) =
        find_trailer_commit(&root, UNDO_TRAILER, goal_id, &format!("{landed}..HEAD"))?
    {
        return Ok(UndoOutcome::AlreadyUndone { commit });
    }
    let current_head = head(&root)?;
    let message = format!(
        "Undo: {}\n\n{UNDO_TRAILER}: {goal_id}",
        commit_subject(title)
    );
    let candidate = {
        let worktree = TempWorktree::create(
            &root,
            scratch_root,
            &format!("undo-{goal_id}"),
            &current_head,
        )?;
        let reverted = git_output(&worktree.path, &["revert", "--no-commit", &landed])?;
        if !reverted.status.success() {
            let _ = git_output(&worktree.path, &["revert", "--abort"]);
            return Ok(UndoOutcome::Conflict {
                detail: String::from_utf8_lossy(&reverted.stderr).into_owned(),
            });
        }
        match worktree.commit(&message)? {
            Some(commit) => commit,
            None => {
                return Ok(UndoOutcome::AlreadyUndone {
                    commit: current_head,
                });
            }
        }
    };
    reject_checkout_side_effects(&root, &candidate)?;
    match fast_forward(&root, &candidate)? {
        Ok(()) => Ok(UndoOutcome::Undone { commit: candidate }),
        Err(detail) => Ok(UndoOutcome::BlockedByLocalChanges { detail }),
    }
}

/// Puts a plain folder under version control for a Sovereign-managed project: `git init`, a
/// default `.gitignore` when none exists, and a first "Starting point" commit of everything in
/// it. A folder that already is (or is inside) a repository is left untouched.
///
/// # Errors
/// Returns a repository or I/O error.
pub fn init_managed_repository(root: &Path) -> Result<ManagedRepositoryInit, RepoError> {
    let canonical = root.canonicalize()?;
    let inside = git_output(&canonical, &["rev-parse", "--show-toplevel"])?;
    if inside.status.success() {
        let top = String::from_utf8(inside.stdout)
            .map_err(|_| RepoError::NonUtf8GitOutput("repository root"))?;
        return Ok(ManagedRepositoryInit::AlreadyRepository {
            root: PathBuf::from(top.trim()),
        });
    }
    git_required_dynamic(
        &canonical,
        "create project history",
        &["-c", "init.defaultBranch=main", "init", "-q"],
    )?;
    let gitignore = canonical.join(".gitignore");
    if fs::symlink_metadata(&gitignore).is_err() {
        fs::write(&gitignore, DEFAULT_GITIGNORE)?;
    }
    git_required_dynamic(&canonical, "stage starting point", &["add", "-A"])?;
    let mut args = IDENTITY.to_vec();
    args.extend([
        "commit",
        "-q",
        "--no-verify",
        "--no-gpg-sign",
        "--allow-empty",
        "-m",
        "Starting point",
    ]);
    git_required_dynamic(&canonical, "record starting point", &args)?;
    Ok(ManagedRepositoryInit::Created {
        head: head(&canonical)?,
    })
}

/// Saves the user's own unsaved edits in a Sovereign-managed project as one "Your edits" commit,
/// so Sovereign's next result builds on them. Returns the new commit, or `None` when there was
/// nothing to save. It never discards or rewrites anything.
///
/// # Errors
/// Returns a repository error.
pub fn checkpoint_user_edits(root: &Path, message: &str) -> Result<Option<String>, RepoError> {
    let root = canonical_repository_root(root)?;
    let status = git_required_dynamic(
        &root,
        "read project status",
        &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    )?;
    if status.stdout.is_empty() {
        return Ok(None);
    }
    git_required_dynamic(&root, "stage your edits", &["add", "-A"])?;
    let staged = git_output(&root, &["diff", "--cached", "--quiet"])?;
    if staged.status.success() {
        return Ok(None);
    }
    let mut args = IDENTITY.to_vec();
    args.extend([
        "commit",
        "-q",
        "--no-verify",
        "--no-gpg-sign",
        "-m",
        message,
    ]);
    git_required_dynamic(&root, "save your edits", &args)?;
    head(&root).map(Some)
}

/// Project files Sovereign may show the model: tracked plus untracked-but-not-ignored regular
/// files no larger than `max_bytes`, as sorted relative paths. Symlinks are skipped.
///
/// # Errors
/// Returns a repository error.
pub fn project_text_files(root: &Path, max_bytes: u64) -> Result<Vec<PathBuf>, RepoError> {
    let root = canonical_repository_root(root)?;
    let listed = git_required_dynamic(
        &root,
        "list project files",
        &["ls-files", "-co", "--exclude-standard", "-z"],
    )?;
    let mut files = Vec::new();
    for raw in listed.stdout.split(|byte| *byte == 0) {
        if raw.is_empty() {
            continue;
        }
        let Ok(relative) = std::str::from_utf8(raw) else {
            continue;
        };
        let relative = PathBuf::from(relative);
        let Ok(metadata) = fs::symlink_metadata(root.join(&relative)) else {
            continue;
        };
        if metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= max_bytes {
            files.push(relative);
        }
    }
    files.sort();
    files.dedup();
    Ok(files)
}
