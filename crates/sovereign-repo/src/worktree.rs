use super::{
    ExactDiffEvidence, ExactFileEvidence, ProjectRegistry, RegisteredRepository, RepoError,
    RepositorySnapshot, capture_snapshot, git_output, hardened_git_command,
    reject_existing_symlink_components, sha256_prefixed, validate_relative_path,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};

const WORKTREE_LEASE_SCHEMA_VERSION: u32 = 1;
const CHANGE_SET_SCHEMA_VERSION: u32 = 2;
const COMPOSITION_CONFLICT_SCHEMA_VERSION: u32 = 1;
static ATOMIC_WRITE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Controller-owned detached Git worktree authority for one exact plan/task revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorktreeLease {
    pub schema_version: u32,
    pub lease_id: String,
    pub repository_id: String,
    pub plan_id: String,
    pub plan_revision: u32,
    pub task_id: String,
    pub task_contract_digest: String,
    pub primary_root: PathBuf,
    pub controller_root: PathBuf,
    pub worktree_path: PathBuf,
    pub base_head: String,
}

/// Immutable evidence for all repository changes observed in one controller worktree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeSet {
    pub schema_version: u32,
    pub lease_id: String,
    pub repository_id: String,
    pub plan_id: String,
    pub plan_revision: u32,
    pub task_id: String,
    pub task_contract_digest: String,
    pub base_head: String,
    pub worktree_path: PathBuf,
    pub pre_task_baseline: WorktreeBaseline,
    pub diff_digest: String,
    pub diff_content: String,
    pub changed_paths: Vec<PathBuf>,
    pub snapshot: RepositorySnapshot,
    pub untracked_digest: String,
    pub untracked_paths: Vec<PathBuf>,
    pub untracked_deltas: Vec<UntrackedFileDelta>,
    pub unmerged_digest: String,
    pub unmerged_paths: Vec<PathBuf>,
}

/// Exact binary-preserving content for one untracked path in a composed worktree baseline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorktreeFileContent {
    pub path: PathBuf,
    pub digest: String,
    pub mode: u32,
    pub content: Vec<u8>,
}

/// Exact pre-task execution baseline after dependency-closed `ChangeSet` composition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorktreeBaseline {
    pub index_digest: String,
    pub untracked_files: Vec<WorktreeFileContent>,
    pub digest: String,
}

/// Reconstructible untracked-file delta relative to a composed pre-task baseline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UntrackedFileDelta {
    pub path: PathBuf,
    pub pre_digest: Option<String>,
    pub post: Option<WorktreeFileContent>,
}

/// Durable fail-closed evidence that ordered upstream `ChangeSet`s could not be composed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompositionConflictEvidence {
    pub schema_version: u32,
    pub incoming_task_id: String,
    pub incoming_change_set_digest: String,
    pub applied_change_set_digests: Vec<String>,
    pub conflict_paths: Vec<PathBuf>,
    pub unmerged_paths: Vec<PathBuf>,
    pub diagnostic_digest: String,
    pub diagnostic: String,
}

/// Deterministic result of composing verified upstream `ChangeSet`s into a task worktree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComposeChangeSetsOutcome {
    Ready(WorktreeBaseline),
    Conflict(CompositionConflictEvidence),
}

/// Explicit authority for using one immutable `ChangeSet` during composition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChangeSetCompositionProvenance {
    CurrentRevision,
    Carried {
        from_revision: u32,
        to_revision: u32,
        source_change_set_digest: String,
    },
}

/// One immutable `ChangeSet` plus explicit current/cross-revision composition provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeSetCompositionInput {
    pub change_set: ChangeSet,
    pub provenance: ChangeSetCompositionProvenance,
}

impl ChangeSetCompositionInput {
    #[must_use]
    pub fn current(change_set: ChangeSet) -> Self {
        Self {
            change_set,
            provenance: ChangeSetCompositionProvenance::CurrentRevision,
        }
    }

    /// Creates an explicit carried-delta input bound to the immutable source `ChangeSet` digest.
    ///
    /// # Errors
    /// Returns a repository serialization error if the source `ChangeSet` digest cannot be derived.
    pub fn carried(
        change_set: ChangeSet,
        from_revision: u32,
        to_revision: u32,
    ) -> Result<Self, RepoError> {
        let source_change_set_digest = change_set.digest()?;
        Ok(Self {
            change_set,
            provenance: ChangeSetCompositionProvenance::Carried {
                from_revision,
                to_revision,
                source_change_set_digest,
            },
        })
    }
}

impl ChangeSet {
    /// Computes the exact digest used to bind this immutable `ChangeSet` into dependency composition.
    ///
    /// # Errors
    /// Returns a serialization error if the immutable record cannot be encoded.
    pub fn digest(&self) -> Result<String, RepoError> {
        Ok(sha256_prefixed(&serde_json::to_vec(self)?))
    }
}

impl ProjectRegistry {
    /// Prepares an immutable worktree lease without touching the primary worktree.
    ///
    /// # Errors
    /// Returns a fail-closed repository error for an unknown repository, invalid root,
    /// missing exact `HEAD`, or a controller root overlapping the primary repository.
    pub fn prepare_worktree_lease(
        &self,
        repository_id: &str,
        controller_root: &Path,
        plan_id: &str,
        plan_revision: u32,
        task_id: &str,
        task_contract_digest: &str,
    ) -> Result<WorktreeLease, RepoError> {
        let repository = self.registered(repository_id)?;
        let primary_root = repository.root.canonicalize()?;
        let base_head = git_text(
            &primary_root,
            "resolve worktree base HEAD",
            &["rev-parse", "--verify", "HEAD^{commit}"],
        )?;
        let controller_root = absolute_controller_root(controller_root)?;
        if path_is_within(&controller_root, &primary_root)
            || path_is_within(&primary_root, &controller_root)
        {
            return Err(RepoError::InvalidWorktreeLease(
                "controller worktree root must be outside the primary repository".to_owned(),
            ));
        }
        let seed = format!(
            "{repository_id}\0{plan_id}\0{plan_revision}\0{task_id}\0{task_contract_digest}\0{base_head}\0{}",
            controller_root.display()
        );
        let digest = sha256_prefixed(seed.as_bytes());
        let lease_id = format!("worktree.{}", &digest[7..27]);
        let worktree_path = controller_root.join(&lease_id);
        Ok(WorktreeLease {
            schema_version: WORKTREE_LEASE_SCHEMA_VERSION,
            lease_id,
            repository_id: repository_id.to_owned(),
            plan_id: plan_id.to_owned(),
            plan_revision,
            task_id: task_id.to_owned(),
            task_contract_digest: task_contract_digest.to_owned(),
            primary_root,
            controller_root,
            worktree_path,
            base_head,
        })
    }

    /// Materializes a prepared lease as a detached exact-HEAD controller-owned worktree.
    ///
    /// # Errors
    /// Returns a fail-closed repository error when lease ownership changed, checkout may
    /// execute hidden Git behavior, or exact detached worktree creation cannot be proven.
    pub fn materialize_worktree(&self, lease: &WorktreeLease) -> Result<(), RepoError> {
        self.validate_prepared_lease(lease)?;
        reject_checkout_side_effects(&lease.primary_root, &lease.base_head)?;
        if lease.worktree_path.exists() {
            return Err(RepoError::InvalidWorktreeLease(
                "worktree path already exists before materialization".to_owned(),
            ));
        }
        fs::create_dir_all(&lease.controller_root)?;
        let canonical_root = lease.controller_root.canonicalize()?;
        if canonical_root != lease.controller_root {
            return Err(RepoError::InvalidWorktreeLease(
                "controller worktree root changed identity".to_owned(),
            ));
        }
        let worktree = lease.worktree_path.to_str().ok_or_else(|| {
            RepoError::InvalidWorktreeLease("worktree path is not UTF-8".to_owned())
        })?;
        git_required_dynamic(
            &lease.primary_root,
            "create detached controller worktree",
            &[
                "worktree",
                "add",
                "--detach",
                "--no-checkout",
                worktree,
                &lease.base_head,
            ],
        )?;
        let populate = (|| {
            self.validate_worktree_lease(lease)?;
            git_required_dynamic(
                &lease.worktree_path,
                "populate controller worktree index",
                &["read-tree", &lease.base_head],
            )?;
            git_required_dynamic(
                &lease.worktree_path,
                "populate controller worktree files",
                &["checkout-index", "-a"],
            )?;
            git_required_dynamic(
                &lease.worktree_path,
                "refresh controller worktree index metadata",
                &["update-index", "--refresh"],
            )?;
            self.validate_worktree_lease(lease)
        })();
        if let Err(error) = populate {
            let _ = git_required_dynamic(
                &lease.primary_root,
                "remove failed controller worktree",
                &["worktree", "remove", "--force", worktree],
            );
            return Err(error);
        }
        Ok(())
    }

    /// Revalidates ownership, exact detached HEAD, path, and common Git directory.
    ///
    /// # Errors
    /// Returns a fail-closed repository error when any lease binding or Git identity differs.
    pub fn validate_worktree_lease(&self, lease: &WorktreeLease) -> Result<(), RepoError> {
        self.validate_prepared_lease(lease)?;
        let root = lease.worktree_path.canonicalize().map_err(|_| {
            RepoError::InvalidWorktreeLease("materialized worktree path is missing".to_owned())
        })?;
        if root != lease.worktree_path {
            return Err(RepoError::InvalidWorktreeLease(
                "materialized worktree path changed identity".to_owned(),
            ));
        }
        let top = git_text(
            &root,
            "validate worktree top-level",
            &["rev-parse", "--show-toplevel"],
        )?;
        if Path::new(&top).canonicalize()? != root {
            return Err(RepoError::InvalidWorktreeLease(
                "worktree top-level does not match lease path".to_owned(),
            ));
        }
        let head = git_text(
            &root,
            "validate worktree HEAD",
            &["rev-parse", "--verify", "HEAD^{commit}"],
        )?;
        if head != lease.base_head {
            return Err(RepoError::InvalidWorktreeLease(
                "worktree HEAD differs from leased base commit".to_owned(),
            ));
        }
        let symbolic = git_output(&root, &["symbolic-ref", "--quiet", "HEAD"])?;
        if symbolic.status.success() {
            return Err(RepoError::InvalidWorktreeLease(
                "controller worktree is attached to a branch".to_owned(),
            ));
        }
        if symbolic.status.code() != Some(1) {
            return Err(git_failure("validate detached worktree", &symbolic));
        }
        let leased_common = git_text(
            &root,
            "validate worktree common dir",
            &["rev-parse", "--git-common-dir"],
        )?;
        let primary_common = git_text(
            &lease.primary_root,
            "validate primary common dir",
            &["rev-parse", "--git-common-dir"],
        )?;
        if resolve_git_path(&root, &leased_common)?
            != resolve_git_path(&lease.primary_root, &primary_common)?
        {
            return Err(RepoError::InvalidWorktreeLease(
                "worktree common Git directory is not the registered repository".to_owned(),
            ));
        }
        Ok(())
    }

    /// Captures the exact current baseline for a validated controller worktree.
    ///
    /// # Errors
    /// Returns a repository error when lease validation or exact snapshot capture fails.
    pub fn worktree_snapshot(
        &self,
        lease: &WorktreeLease,
    ) -> Result<RepositorySnapshot, RepoError> {
        self.validate_worktree_lease(lease)?;
        capture_snapshot(&RegisteredRepository {
            repository_id: lease.repository_id.clone(),
            root: lease.worktree_path.clone(),
        })
    }

    /// Reads one exact file from a validated controller worktree.
    ///
    /// # Errors
    /// Returns a repository error for an invalid lease/path, stale digest, symlink, or I/O failure.
    pub fn read_worktree_path(
        &self,
        lease: &WorktreeLease,
        relative_path: &Path,
        expected_digest: Option<&str>,
    ) -> Result<ExactFileEvidence, RepoError> {
        self.validate_worktree_lease(lease)?;
        validate_relative_path(relative_path)?;
        reject_existing_symlink_components(&lease.worktree_path, relative_path)?;
        let absolute = lease.worktree_path.join(relative_path);
        let metadata = fs::symlink_metadata(&absolute)?;
        if metadata.file_type().is_symlink() {
            return Err(RepoError::SymlinkPath(absolute));
        }
        if !metadata.is_file() {
            return Err(RepoError::NotRegularFile(absolute));
        }
        let bytes = fs::read(&absolute)?;
        let digest = sha256_prefixed(&bytes);
        if let Some(expected) = expected_digest
            && expected != digest
        {
            return Err(RepoError::StaleFileHash {
                path: relative_path.to_path_buf(),
                expected: expected.to_owned(),
                actual: digest,
            });
        }
        let content = String::from_utf8(bytes)
            .map_err(|_| RepoError::NonUtf8GitOutput("controller worktree file read"))?;
        Ok(ExactFileEvidence {
            repository_id: lease.repository_id.clone(),
            relative_path: relative_path.to_path_buf(),
            digest,
            byte_len: u64::try_from(content.len()).unwrap_or(u64::MAX),
            content,
        })
    }

    /// Captures the tracked binary/full-index task delta relative to the composed index baseline.
    ///
    /// # Errors
    /// Returns a repository error when lease validation or hardened Git diff capture fails.
    pub fn worktree_diff(&self, lease: &WorktreeLease) -> Result<ExactDiffEvidence, RepoError> {
        self.validate_worktree_lease(lease)?;
        let output = git_required_dynamic(
            &lease.worktree_path,
            "read controller worktree diff",
            &[
                "diff",
                "--binary",
                "--full-index",
                "--no-ext-diff",
                "--no-textconv",
                "--no-color",
                "--",
            ],
        )?;
        let content = String::from_utf8(output.stdout)
            .map_err(|_| RepoError::NonUtf8GitOutput("controller worktree diff"))?;
        Ok(ExactDiffEvidence {
            repository_id: lease.repository_id.clone(),
            digest: sha256_prefixed(content.as_bytes()),
            content,
        })
    }

    /// Captures the exact composed pre-task baseline for a validated controller worktree.
    ///
    /// # Errors
    /// Returns a repository error when the index or untracked binary state cannot be proven.
    pub fn capture_worktree_baseline(
        &self,
        lease: &WorktreeLease,
    ) -> Result<WorktreeBaseline, RepoError> {
        self.validate_worktree_lease(lease)?;
        capture_worktree_baseline(&lease.worktree_path)
    }

    /// Deterministically composes ordered verified upstream `ChangeSet`s into the task worktree.
    /// Shared ancestors must be supplied once by the caller. Each tracked delta is applied against
    /// the exact current index/worktree preimage; untracked binary content is checked and replayed
    /// explicitly. Conflicts are returned as evidence and are never auto-resolved or discarded.
    ///
    /// # Errors
    /// Returns a repository error when a `ChangeSet` is malformed/misbound or hardened Git/I/O fails.
    #[allow(clippy::too_many_lines)]
    pub fn compose_change_sets(
        &self,
        lease: &WorktreeLease,
        ordered: &[ChangeSetCompositionInput],
    ) -> Result<ComposeChangeSetsOutcome, RepoError> {
        self.validate_worktree_lease(lease)?;
        let mut applied = Vec::new();
        for input in ordered {
            validate_composable_change_set(lease, input)?;
            let change_set = &input.change_set;
            let change_set_digest = change_set.digest()?;
            if !change_set.unmerged_paths.is_empty() {
                return Ok(ComposeChangeSetsOutcome::Conflict(composition_conflict(
                    change_set,
                    &change_set_digest,
                    &applied,
                    change_set.unmerged_paths.clone(),
                    change_set.unmerged_paths.clone(),
                    "incoming ChangeSet carries unresolved index conflicts".to_owned(),
                )));
            }

            if !change_set.diff_content.is_empty() {
                let checked = git_output_with_input(
                    &lease.worktree_path,
                    &[
                        "apply",
                        "--check",
                        "--index",
                        "--binary",
                        "--whitespace=nowarn",
                        "-",
                    ],
                    change_set.diff_content.as_bytes(),
                )?;
                if !checked.status.success() {
                    let diagnostic = String::from_utf8_lossy(&checked.stderr).into_owned();
                    return Ok(ComposeChangeSetsOutcome::Conflict(composition_conflict(
                        change_set,
                        &change_set_digest,
                        &applied,
                        change_set.changed_paths.clone(),
                        current_unmerged_paths(&lease.worktree_path)?,
                        diagnostic,
                    )));
                }
            }

            if let Some(conflict) = detect_untracked_composition_conflict(
                &lease.worktree_path,
                change_set,
                &change_set_digest,
                &applied,
            )? {
                return Ok(ComposeChangeSetsOutcome::Conflict(conflict));
            }

            if !change_set.diff_content.is_empty() {
                let applied_output = git_output_with_input(
                    &lease.worktree_path,
                    &["apply", "--index", "--binary", "--whitespace=nowarn", "-"],
                    change_set.diff_content.as_bytes(),
                )?;
                if !applied_output.status.success() {
                    return Err(git_failure("compose controller ChangeSet", &applied_output));
                }
            }
            apply_untracked_deltas(&lease.worktree_path, &change_set.untracked_deltas)?;
            let unmerged = current_unmerged_paths(&lease.worktree_path)?;
            if !unmerged.is_empty() {
                return Ok(ComposeChangeSetsOutcome::Conflict(composition_conflict(
                    change_set,
                    &change_set_digest,
                    &applied,
                    change_set.changed_paths.clone(),
                    unmerged,
                    "composition produced unresolved index entries".to_owned(),
                )));
            }
            applied.push(change_set_digest);
        }
        Ok(ComposeChangeSetsOutcome::Ready(
            self.capture_worktree_baseline(lease)?,
        ))
    }

    /// Captures immutable task-local change/conflict evidence relative to a composed baseline.
    ///
    /// # Errors
    /// Returns a repository error when snapshot, diff, or unmerged-index evidence cannot be proven.
    pub fn capture_change_set(&self, lease: &WorktreeLease) -> Result<ChangeSet, RepoError> {
        self.validate_worktree_lease(lease)?;
        let mut baseline = capture_worktree_baseline(&lease.worktree_path)?;
        baseline.untracked_files.clear();
        baseline.digest = worktree_baseline_digest(&baseline)?;
        self.capture_change_set_from_baseline(lease, &baseline)
    }

    /// Captures immutable task-local evidence against the exact supplied pre-task baseline.
    ///
    /// # Errors
    /// Returns a repository error when the baseline/index binding drifted or evidence capture fails.
    pub fn capture_change_set_from_baseline(
        &self,
        lease: &WorktreeLease,
        baseline: &WorktreeBaseline,
    ) -> Result<ChangeSet, RepoError> {
        let snapshot = self.worktree_snapshot(lease)?;
        validate_worktree_baseline(baseline)?;
        let current_index_digest = index_digest(&lease.worktree_path)?;
        if current_index_digest != baseline.index_digest {
            return Err(RepoError::InvalidWorktreeLease(
                "controller worktree index drifted from its composed pre-task baseline".to_owned(),
            ));
        }
        let diff = self.worktree_diff(lease)?;
        let changed_paths = changed_tracked_paths(&lease.worktree_path)?;
        let current_untracked = capture_untracked_files(&lease.worktree_path)?;
        let untracked_deltas = untracked_deltas(&baseline.untracked_files, &current_untracked);
        let unmerged = git_required_dynamic(
            &lease.worktree_path,
            "read controller worktree conflicts",
            &["ls-files", "-u", "-z"],
        )?;
        let unmerged_paths = parse_unmerged_paths(&unmerged.stdout)?;
        Ok(ChangeSet {
            schema_version: CHANGE_SET_SCHEMA_VERSION,
            lease_id: lease.lease_id.clone(),
            repository_id: lease.repository_id.clone(),
            plan_id: lease.plan_id.clone(),
            plan_revision: lease.plan_revision,
            task_id: lease.task_id.clone(),
            task_contract_digest: lease.task_contract_digest.clone(),
            base_head: lease.base_head.clone(),
            worktree_path: lease.worktree_path.clone(),
            pre_task_baseline: baseline.clone(),
            diff_digest: diff.digest,
            diff_content: diff.content,
            changed_paths,
            untracked_digest: snapshot.untracked.digest.clone(),
            untracked_paths: snapshot.untracked.paths.clone(),
            untracked_deltas,
            unmerged_digest: sha256_prefixed(&unmerged.stdout),
            unmerged_paths,
            snapshot,
        })
    }

    /// Removes only the exact controller worktree after its final `ChangeSet` is proven unchanged.
    ///
    /// # Errors
    /// Returns a fail-closed repository error when the change set is stale/misbound or cleanup
    /// cannot prove it removed only the exact controller-owned worktree.
    pub fn release_worktree(
        &self,
        lease: &WorktreeLease,
        expected: &ChangeSet,
    ) -> Result<(), RepoError> {
        validate_change_set_binding(lease, expected)?;
        let current = self.capture_change_set_from_baseline(lease, &expected.pre_task_baseline)?;
        if &current != expected {
            return Err(RepoError::InvalidWorktreeLease(
                "worktree changed after immutable ChangeSet capture".to_owned(),
            ));
        }
        let worktree = lease.worktree_path.to_str().ok_or_else(|| {
            RepoError::InvalidWorktreeLease("worktree path is not UTF-8".to_owned())
        })?;
        git_required_dynamic(
            &lease.primary_root,
            "release controller worktree",
            &["worktree", "remove", "--force", worktree],
        )?;
        if lease.worktree_path.exists() {
            return Err(RepoError::InvalidWorktreeLease(
                "released controller worktree path still exists".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_prepared_lease(&self, lease: &WorktreeLease) -> Result<(), RepoError> {
        if lease.schema_version != WORKTREE_LEASE_SCHEMA_VERSION
            || lease.plan_revision == 0
            || lease.task_contract_digest.is_empty()
        {
            return Err(RepoError::InvalidWorktreeLease(
                "unsupported or incomplete lease binding".to_owned(),
            ));
        }
        let repository = self.registered(&lease.repository_id)?;
        let expected_worktree_path = lease.controller_root.join(&lease.lease_id);
        if repository.root != lease.primary_root
            || lease.worktree_path != expected_worktree_path
            || path_is_within(&lease.worktree_path, &lease.primary_root)
        {
            return Err(RepoError::InvalidWorktreeLease(
                "lease path/repository ownership mismatch".to_owned(),
            ));
        }
        let current_head = git_text(
            &repository.root,
            "revalidate worktree base HEAD",
            &["rev-parse", "--verify", "HEAD^{commit}"],
        )?;
        if current_head != lease.base_head {
            return Err(RepoError::InvalidWorktreeLease(
                "primary HEAD changed after worktree lease preparation".to_owned(),
            ));
        }
        let seed = format!(
            "{}\0{}\0{}\0{}\0{}\0{}\0{}",
            lease.repository_id,
            lease.plan_id,
            lease.plan_revision,
            lease.task_id,
            lease.task_contract_digest,
            lease.base_head,
            lease.controller_root.display()
        );
        let digest = sha256_prefixed(seed.as_bytes());
        if lease.lease_id != format!("worktree.{}", &digest[7..27]) {
            return Err(RepoError::InvalidWorktreeLease(
                "lease identifier does not match immutable bindings".to_owned(),
            ));
        }
        Ok(())
    }
}

fn validate_composable_change_set(
    lease: &WorktreeLease,
    input: &ChangeSetCompositionInput,
) -> Result<(), RepoError> {
    let change_set = &input.change_set;
    validate_worktree_baseline(&change_set.pre_task_baseline)?;
    if change_set.schema_version != CHANGE_SET_SCHEMA_VERSION
        || change_set.repository_id != lease.repository_id
        || change_set.plan_id != lease.plan_id
        || change_set.base_head != lease.base_head
        || sha256_prefixed(change_set.diff_content.as_bytes()) != change_set.diff_digest
    {
        return Err(RepoError::InvalidWorktreeLease(
            "upstream ChangeSet is malformed or bound to another repository/revision/base"
                .to_owned(),
        ));
    }
    match &input.provenance {
        ChangeSetCompositionProvenance::CurrentRevision => {
            if change_set.plan_revision != lease.plan_revision {
                return Err(RepoError::InvalidWorktreeLease(
                    "current-revision ChangeSet composition input has a different revision"
                        .to_owned(),
                ));
            }
        }
        ChangeSetCompositionProvenance::Carried {
            from_revision,
            to_revision,
            source_change_set_digest,
        } => {
            if *from_revision != change_set.plan_revision
                || *to_revision != lease.plan_revision
                || from_revision >= to_revision
                || *source_change_set_digest != change_set.digest()?
            {
                return Err(RepoError::InvalidWorktreeLease(
                    "carried ChangeSet composition provenance is stale or misbound".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn composition_conflict(
    change_set: &ChangeSet,
    change_set_digest: &str,
    applied: &[String],
    conflict_paths: Vec<PathBuf>,
    unmerged_paths: Vec<PathBuf>,
    diagnostic: String,
) -> CompositionConflictEvidence {
    CompositionConflictEvidence {
        schema_version: COMPOSITION_CONFLICT_SCHEMA_VERSION,
        incoming_task_id: change_set.task_id.clone(),
        incoming_change_set_digest: change_set_digest.to_owned(),
        applied_change_set_digests: applied.to_vec(),
        conflict_paths,
        unmerged_paths,
        diagnostic_digest: sha256_prefixed(diagnostic.as_bytes()),
        diagnostic,
    }
}

fn capture_worktree_baseline(root: &Path) -> Result<WorktreeBaseline, RepoError> {
    let mut baseline = WorktreeBaseline {
        index_digest: index_digest(root)?,
        untracked_files: capture_untracked_files(root)?,
        digest: String::new(),
    };
    baseline.digest = worktree_baseline_digest(&baseline)?;
    Ok(baseline)
}

fn validate_worktree_baseline(baseline: &WorktreeBaseline) -> Result<(), RepoError> {
    if worktree_baseline_digest(baseline)? != baseline.digest {
        return Err(RepoError::InvalidWorktreeLease(
            "composed pre-task baseline digest is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn worktree_baseline_digest(baseline: &WorktreeBaseline) -> Result<String, RepoError> {
    Ok(sha256_prefixed(&serde_json::to_vec(&(
        &baseline.index_digest,
        &baseline.untracked_files,
    ))?))
}

fn index_digest(root: &Path) -> Result<String, RepoError> {
    let output = git_required_dynamic(
        root,
        "read controller worktree index",
        &["ls-files", "--stage", "-z"],
    )?;
    Ok(sha256_prefixed(&output.stdout))
}

fn capture_untracked_files(root: &Path) -> Result<Vec<WorktreeFileContent>, RepoError> {
    let output = git_required_dynamic(
        root,
        "read controller untracked paths",
        &["ls-files", "--others", "--exclude-standard", "-z"],
    )?;
    let mut files = Vec::new();
    for raw in output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
    {
        let text = std::str::from_utf8(raw)
            .map_err(|_| RepoError::NonUtf8GitOutput("controller untracked path"))?;
        let relative = PathBuf::from(text);
        validate_relative_path(&relative)?;
        reject_existing_symlink_components(root, &relative)?;
        let absolute = root.join(&relative);
        let metadata = fs::symlink_metadata(&absolute)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(RepoError::NotRegularFile(absolute));
        }
        let content = fs::read(&absolute)?;
        files.push(WorktreeFileContent {
            path: relative,
            digest: sha256_prefixed(&content),
            mode: metadata.permissions().mode() & 0o7777,
            content,
        });
    }
    files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(files)
}

fn untracked_deltas(
    before: &[WorktreeFileContent],
    after: &[WorktreeFileContent],
) -> Vec<UntrackedFileDelta> {
    let before = before
        .iter()
        .map(|file| (file.path.clone(), file))
        .collect::<BTreeMap<_, _>>();
    let after = after
        .iter()
        .map(|file| (file.path.clone(), file))
        .collect::<BTreeMap<_, _>>();
    before
        .keys()
        .chain(after.keys())
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter_map(|path| {
            let pre = before.get(&path).copied();
            let post = after.get(&path).copied();
            (pre != post).then(|| UntrackedFileDelta {
                path,
                pre_digest: pre.map(|file| file.digest.clone()),
                post: post.cloned(),
            })
        })
        .collect()
}

fn changed_tracked_paths(root: &Path) -> Result<Vec<PathBuf>, RepoError> {
    let output = git_required_dynamic(
        root,
        "read controller task changed paths",
        &["diff", "--name-only", "-z", "--"],
    )?;
    parse_nul_paths(&output.stdout, "controller task changed path")
}

fn current_unmerged_paths(root: &Path) -> Result<Vec<PathBuf>, RepoError> {
    let output = git_required_dynamic(
        root,
        "read controller worktree conflicts",
        &["ls-files", "-u", "-z"],
    )?;
    parse_unmerged_paths(&output.stdout)
}

fn parse_nul_paths(bytes: &[u8], operation: &'static str) -> Result<Vec<PathBuf>, RepoError> {
    let mut paths = BTreeSet::new();
    for raw in bytes
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
    {
        let text = std::str::from_utf8(raw).map_err(|_| RepoError::NonUtf8GitOutput(operation))?;
        paths.insert(PathBuf::from(text));
    }
    Ok(paths.into_iter().collect())
}

fn detect_untracked_composition_conflict(
    root: &Path,
    change_set: &ChangeSet,
    change_set_digest: &str,
    applied: &[String],
) -> Result<Option<CompositionConflictEvidence>, RepoError> {
    for delta in &change_set.untracked_deltas {
        validate_relative_path(&delta.path)?;
        reject_existing_symlink_components(root, &delta.path)?;
        let absolute = root.join(&delta.path);
        let observed = if absolute.exists() {
            let metadata = fs::symlink_metadata(&absolute)?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Ok(Some(composition_conflict(
                    change_set,
                    change_set_digest,
                    applied,
                    vec![delta.path.clone()],
                    current_unmerged_paths(root)?,
                    format!(
                        "untracked composition path {} is not a regular file",
                        delta.path.display()
                    ),
                )));
            }
            Some(sha256_prefixed(&fs::read(&absolute)?))
        } else {
            None
        };
        if observed != delta.pre_digest {
            return Ok(Some(composition_conflict(
                change_set,
                change_set_digest,
                applied,
                vec![delta.path.clone()],
                current_unmerged_paths(root)?,
                format!(
                    "untracked composition preimage mismatch for {}: expected {:?}, observed {:?}",
                    delta.path.display(),
                    delta.pre_digest,
                    observed
                ),
            )));
        }
    }
    Ok(None)
}

fn apply_untracked_deltas(root: &Path, deltas: &[UntrackedFileDelta]) -> Result<(), RepoError> {
    for delta in deltas {
        validate_relative_path(&delta.path)?;
        reject_existing_symlink_components(root, &delta.path)?;
        let absolute = root.join(&delta.path);
        match &delta.post {
            Some(post) => {
                if post.path != delta.path || sha256_prefixed(&post.content) != post.digest {
                    return Err(RepoError::InvalidWorktreeLease(
                        "untracked ChangeSet content digest/path is invalid".to_owned(),
                    ));
                }
                atomic_replace_untracked(root, delta, post)?;
            }
            None => {
                remove_untracked_atomically(root, delta, &absolute)?;
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

fn identity(metadata: &fs::Metadata) -> FileIdentity {
    FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

fn directory_identity(path: &Path) -> Result<FileIdentity, RepoError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(RepoError::SymlinkPath(path.to_path_buf()));
    }
    Ok(identity(&metadata))
}

fn ensure_secure_parent(
    root: &Path,
    relative: &Path,
) -> Result<(PathBuf, FileIdentity), RepoError> {
    let parent_relative = relative.parent().unwrap_or_else(|| Path::new(""));
    let mut current = root.to_path_buf();
    let canonical_root = root.canonicalize()?;
    if canonical_root != root {
        return Err(RepoError::InvalidWorktreeLease(
            "controller worktree root changed identity during untracked composition".to_owned(),
        ));
    }
    for component in parent_relative.components() {
        let std::path::Component::Normal(segment) = component else {
            return Err(RepoError::InvalidRelativePath(relative.to_path_buf()));
        };
        let before = directory_identity(&current)?;
        let next = current.join(segment);
        match fs::symlink_metadata(&next) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(RepoError::SymlinkPath(next));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&next)?;
            }
            Err(error) => return Err(RepoError::Io(error)),
        }
        if directory_identity(&current)? != before {
            return Err(RepoError::InvalidWorktreeLease(
                "untracked composition parent changed identity while creating path".to_owned(),
            ));
        }
        current = next;
    }
    reject_existing_symlink_components(root, parent_relative)?;
    let canonical_parent = current.canonicalize()?;
    if !canonical_parent.starts_with(&canonical_root) || canonical_parent != current {
        return Err(RepoError::InvalidWorktreeLease(
            "untracked composition parent escaped or changed identity".to_owned(),
        ));
    }
    let parent_identity = directory_identity(&current)?;
    Ok((current, parent_identity))
}

fn current_target_state(path: &Path) -> Result<Option<(FileIdentity, String)>, RepoError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(RepoError::NotRegularFile(path.to_path_buf()));
            }
            let bytes = fs::read(path)?;
            Ok(Some((identity(&metadata), sha256_prefixed(&bytes))))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(RepoError::Io(error)),
    }
}

fn validate_target_preimage(
    path: &Path,
    expected_digest: Option<&str>,
) -> Result<Option<FileIdentity>, RepoError> {
    let state = current_target_state(path)?;
    let actual_digest = state.as_ref().map(|(_, digest)| digest.as_str());
    if actual_digest != expected_digest {
        return Err(RepoError::InvalidWorktreeLease(format!(
            "untracked composition target changed before commit: {}",
            path.display()
        )));
    }
    Ok(state.map(|(identity, _)| identity))
}

fn atomic_replace_untracked(
    root: &Path,
    delta: &UntrackedFileDelta,
    post: &WorktreeFileContent,
) -> Result<(), RepoError> {
    let (parent, parent_identity) = ensure_secure_parent(root, &delta.path)?;
    let target = root.join(&delta.path);
    let target_identity = validate_target_preimage(&target, delta.pre_digest.as_deref())?;
    let sequence = ATOMIC_WRITE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temp = parent.join(format!(
        ".sovereign-compose-{}-{sequence}.tmp",
        std::process::id()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        file.write_all(&post.content)?;
        file.set_permissions(fs::Permissions::from_mode(post.mode))?;
        file.sync_all()?;

        if directory_identity(&parent)? != parent_identity {
            return Err(RepoError::InvalidWorktreeLease(
                "untracked composition parent changed identity before atomic rename".to_owned(),
            ));
        }
        reject_existing_symlink_components(root, &delta.path)?;
        let current_identity = validate_target_preimage(&target, delta.pre_digest.as_deref())?;
        if current_identity != target_identity {
            return Err(RepoError::InvalidWorktreeLease(
                "untracked composition target inode changed before atomic rename".to_owned(),
            ));
        }
        fs::rename(&temp, &target)?;
        OpenOptions::new().read(true).open(&parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn remove_untracked_atomically(
    root: &Path,
    delta: &UntrackedFileDelta,
    target: &Path,
) -> Result<(), RepoError> {
    let Some(expected_digest) = delta.pre_digest.as_deref() else {
        if target.exists() {
            return Err(RepoError::InvalidWorktreeLease(
                "untracked delete had no preimage but target exists".to_owned(),
            ));
        }
        return Ok(());
    };
    let (parent, parent_identity) = ensure_secure_parent(root, &delta.path)?;
    let target_identity = validate_target_preimage(target, Some(expected_digest))?;
    if directory_identity(&parent)? != parent_identity {
        return Err(RepoError::InvalidWorktreeLease(
            "untracked composition parent changed identity before delete".to_owned(),
        ));
    }
    reject_existing_symlink_components(root, &delta.path)?;
    if validate_target_preimage(target, Some(expected_digest))? != target_identity {
        return Err(RepoError::InvalidWorktreeLease(
            "untracked composition target inode changed before delete".to_owned(),
        ));
    }
    fs::remove_file(target)?;
    OpenOptions::new().read(true).open(&parent)?.sync_all()?;
    Ok(())
}

fn validate_change_set_binding(
    lease: &WorktreeLease,
    change_set: &ChangeSet,
) -> Result<(), RepoError> {
    if change_set.schema_version != CHANGE_SET_SCHEMA_VERSION
        || change_set.lease_id != lease.lease_id
        || change_set.repository_id != lease.repository_id
        || change_set.plan_id != lease.plan_id
        || change_set.plan_revision != lease.plan_revision
        || change_set.task_id != lease.task_id
        || change_set.task_contract_digest != lease.task_contract_digest
        || change_set.base_head != lease.base_head
        || change_set.worktree_path != lease.worktree_path
        || sha256_prefixed(change_set.diff_content.as_bytes()) != change_set.diff_digest
    {
        return Err(RepoError::InvalidWorktreeLease(
            "ChangeSet is stale, altered, or bound to another lease".to_owned(),
        ));
    }
    Ok(())
}

fn reject_checkout_side_effects(root: &Path, base_head: &str) -> Result<(), RepoError> {
    let local_keys = git_output(
        root,
        &[
            "config",
            "--local",
            "--no-includes",
            "--name-only",
            "--get-regexp",
            ".*",
        ],
    )?;
    if !local_keys.status.success() && local_keys.status.code() != Some(1) {
        return Err(git_failure("inspect local Git config", &local_keys));
    }
    for key in String::from_utf8_lossy(&local_keys.stdout).lines() {
        let lower = key.trim().to_ascii_lowercase();
        if unsafe_local_git_config_key(&lower) {
            return Err(RepoError::UnsafeGitConfiguration(format!(
                "local Git config key {key} may execute, include, or lazy-fetch during checkout"
            )));
        }
    }

    let tree = git_required_dynamic(
        root,
        "enumerate Git attributes",
        &["ls-tree", "-r", "--name-only", "-z", base_head],
    )?;
    for raw in tree
        .stdout
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
    {
        let path =
            std::str::from_utf8(raw).map_err(|_| RepoError::NonUtf8GitOutput("attribute path"))?;
        if matches!(
            Path::new(path).file_name().and_then(|name| name.to_str()),
            Some(".gitmodules" | ".lfsconfig")
        ) {
            return Err(RepoError::UnsafeGitConfiguration(format!(
                "tracked {path} may configure hidden submodule/LFS execution or network access"
            )));
        }
        if Path::new(path).file_name().and_then(|name| name.to_str()) != Some(".gitattributes") {
            continue;
        }
        let spec = format!("{base_head}:{path}");
        let content =
            git_required_dynamic(root, "inspect tracked Git attributes", &["show", &spec])?;
        reject_filter_attributes(path, &content.stdout)?;
    }
    let primary_git = resolve_git_path(
        root,
        &git_text(root, "resolve primary git dir", &["rev-parse", "--git-dir"])?,
    )?;
    let info_attributes = primary_git.join("info/attributes");
    if info_attributes.is_file() {
        reject_filter_attributes(".git/info/attributes", &fs::read(info_attributes)?)?;
    }
    Ok(())
}

fn unsafe_local_git_config_key(lower: &str) -> bool {
    let suffix = lower.rsplit('.').next();
    let credential_helper = lower == "credential.helper" || suffix == Some("helper");
    let external_diff = lower == "diff.external"
        || (lower.starts_with("diff.") && matches!(suffix, Some("command" | "textconv")));
    let include =
        lower == "include.path" || lower.starts_with("include.") || lower.starts_with("includeif.");
    let partial_clone = lower == "extensions.partialclone"
        || (lower.starts_with("remote.")
            && matches!(
                suffix,
                Some(
                    "promisor"
                        | "partialclonefilter"
                        | "proxy"
                        | "uploadpack"
                        | "receivepack"
                        | "vcs"
                )
            ));
    let url_rewrite =
        lower.starts_with("url.") && matches!(suffix, Some("insteadof" | "pushinsteadof"));
    let proxy = lower == "core.gitproxy"
        || lower == "http.proxy"
        || (lower.starts_with("http.") && suffix == Some("proxy"));
    credential_helper
        || lower == "core.sshcommand"
        || lower.starts_with("alias.")
        || external_diff
        || lower.starts_with("filter.")
        || matches!(lower, "core.fsmonitor" | "core.hookspath")
        || include
        || partial_clone
        || url_rewrite
        || proxy
        || lower.starts_with("submodule.")
}

fn reject_filter_attributes(source: &str, bytes: &[u8]) -> Result<(), RepoError> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        RepoError::UnsafeGitConfiguration(format!("non-UTF-8 attributes in {source}"))
    })?;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line
            .split_whitespace()
            .skip(1)
            .any(|token| token.to_ascii_lowercase().contains("filter"))
        {
            return Err(RepoError::UnsafeGitConfiguration(format!(
                "Git filter/LFS attribute in {source}: {line}"
            )));
        }
    }
    Ok(())
}

fn parse_unmerged_paths(bytes: &[u8]) -> Result<Vec<PathBuf>, RepoError> {
    let mut paths = BTreeSet::new();
    for raw in bytes
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
    {
        let text =
            std::str::from_utf8(raw).map_err(|_| RepoError::NonUtf8GitOutput("unmerged index"))?;
        let (_, path) = text.split_once('\t').ok_or_else(|| {
            RepoError::InvalidWorktreeLease("malformed unmerged index entry".to_owned())
        })?;
        paths.insert(PathBuf::from(path));
    }
    Ok(paths.into_iter().collect())
}

fn absolute_controller_root(root: &Path) -> Result<PathBuf, RepoError> {
    let absolute = if root.is_absolute() {
        root.to_path_buf()
    } else {
        std::env::current_dir()?.join(root)
    };
    canonicalize_nonexistent_path(&absolute)
}

fn canonicalize_nonexistent_path(path: &Path) -> Result<PathBuf, RepoError> {
    let mut cursor = path;
    let mut missing = Vec::new();
    while !cursor.exists() {
        let name = cursor.file_name().ok_or_else(|| {
            RepoError::InvalidWorktreeLease("controller root has no existing ancestor".to_owned())
        })?;
        missing.push(name.to_os_string());
        cursor = cursor.parent().ok_or_else(|| {
            RepoError::InvalidWorktreeLease("controller root has no existing ancestor".to_owned())
        })?;
    }
    let mut canonical = cursor.canonicalize()?;
    for name in missing.iter().rev() {
        canonical.push(name);
    }
    Ok(canonical)
}

fn path_is_within(path: &Path, ancestor: &Path) -> bool {
    path == ancestor || path.starts_with(ancestor)
}

fn resolve_git_path(root: &Path, value: &str) -> Result<PathBuf, RepoError> {
    let path = PathBuf::from(value.trim());
    let absolute = if path.is_absolute() {
        path
    } else {
        root.join(path)
    };
    Ok(absolute.canonicalize()?)
}

fn git_text(root: &Path, operation: &'static str, args: &[&str]) -> Result<String, RepoError> {
    let output = git_required_dynamic(root, operation, args)?;
    Ok(String::from_utf8(output.stdout)
        .map_err(|_| RepoError::NonUtf8GitOutput(operation))?
        .trim()
        .to_owned())
}

fn git_required_dynamic(
    root: &Path,
    operation: &'static str,
    args: &[&str],
) -> Result<std::process::Output, RepoError> {
    let output = git_output(root, args)?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(git_failure(operation, &output))
    }
}

fn git_output_with_input(
    root: &Path,
    args: &[&str],
    input: &[u8],
) -> Result<std::process::Output, RepoError> {
    let mut command = hardened_git_command(root)?;
    let mut child = command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or_else(|| RepoError::InvalidWorktreeLease("Git stdin pipe missing".to_owned()))?
        .write_all(input)?;
    Ok(child.wait_with_output()?)
}

fn git_failure(operation: &'static str, output: &std::process::Output) -> RepoError {
    RepoError::GitFailed {
        operation,
        status: output.status.code(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}
