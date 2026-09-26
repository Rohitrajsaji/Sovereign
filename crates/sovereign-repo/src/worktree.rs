use super::{
    ExactDiffEvidence, ExactFileEvidence, ProjectRegistry, RegisteredRepository, RepoError,
    RepositorySnapshot, capture_snapshot, git_output, hardened_git_command,
    reject_existing_symlink_components, sha256_prefixed, validate_relative_path,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};

const WORKTREE_LEASE_SCHEMA_VERSION: u32 = 1;
const CHANGE_SET_SCHEMA_VERSION: u32 = 2;
const COMPOSITION_CONFLICT_SCHEMA_VERSION: u32 = 1;
const OFFLINE_NODE_MODULES_PROVENANCE_SCHEMA_VERSION: u32 = 1;
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

/// Hard ceilings for copying one existing offline dependency tree into a Controller worktree.
/// `max_entries` counts directories, regular files, and symlinks below the `node_modules` root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfflineDependencyLimits {
    pub max_entries: u64,
    pub max_bytes: u64,
}

/// Deterministic content/shape digest for one safe `node_modules` tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfflineDependencyManifest {
    pub digest: String,
    pub entry_count: u64,
    pub directory_count: u64,
    pub regular_file_count: u64,
    pub symlink_count: u64,
    pub total_bytes: u64,
}

/// Exact repository/worktree facts returned after a successful offline dependency materialization.
/// The Controller may bind these facts into its own durable authority/evidence; this record grants
/// no execution or package-install authority by itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfflineNodeModulesProvenance {
    pub schema_version: u32,
    pub repository_id: String,
    pub plan_id: String,
    pub plan_revision: u32,
    pub task_id: String,
    pub task_contract_digest: String,
    pub worktree_lease_id: String,
    pub base_head: String,
    pub project_root: PathBuf,
    pub source_node_modules: PathBuf,
    pub destination_node_modules: PathBuf,
    pub ignore_evidence_digest: String,
    pub source_manifest: OfflineDependencyManifest,
    pub destination_manifest: OfflineDependencyManifest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum OfflineDependencyEntryKind {
    Directory,
    RegularFile { content_digest: String },
    Symlink { target: PathBuf },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OfflineDependencyEntry {
    relative_path: PathBuf,
    mode: u32,
    size_bytes: u64,
    identity: FileIdentity,
    kind: OfflineDependencyEntryKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OfflineDependencyTree {
    root_mode: u32,
    root_identity: FileIdentity,
    entries: Vec<OfflineDependencyEntry>,
    manifest: OfflineDependencyManifest,
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

    /// Copies one already-present, Git-ignored and untracked `node_modules` tree from the
    /// registered primary repository into the exact Controller-owned worktree.
    ///
    /// This is a filesystem materialization only: it never invokes a package manager or network
    /// operation. The source tree is bounded and content-addressed, unsafe filesystem objects are
    /// rejected, the copy is staged beneath the Controller-owned worktree root, and the final
    /// directory appears through one same-filesystem atomic rename. Returned provenance is bound to
    /// the exact worktree lease so a higher layer can persist its own authority/evidence record.
    ///
    /// An empty `project_root` denotes the registered repository root. Otherwise every component
    /// must be a normal repository-relative path component.
    ///
    /// # Errors
    /// Returns a fail-closed repository error for a stale lease, unsafe project/source path,
    /// tracked or non-ignored dependencies, an existing destination, resource-limit excess,
    /// external/unsafe symlinks, special files, source drift, or staging/destination mismatch.
    #[allow(clippy::too_many_lines)]
    pub fn materialize_existing_node_modules(
        &self,
        lease: &WorktreeLease,
        project_root: &Path,
        limits: OfflineDependencyLimits,
    ) -> Result<OfflineNodeModulesProvenance, RepoError> {
        self.validate_worktree_lease(lease)?;
        validate_offline_dependency_limits(limits)?;
        validate_offline_project_root(project_root)?;

        let primary_root = lease.primary_root.canonicalize()?;
        let worktree_root = lease.worktree_path.canonicalize()?;
        if primary_root != lease.primary_root || worktree_root != lease.worktree_path {
            return Err(offline_dependency_error(
                "repository/worktree root changed identity before dependency materialization",
            ));
        }
        reject_existing_symlink_components(&primary_root, project_root)?;
        reject_existing_symlink_components(&worktree_root, project_root)?;
        let primary_project = primary_root.join(project_root);
        let worktree_project = worktree_root.join(project_root);
        require_existing_canonical_directory(
            &primary_project,
            &primary_root,
            "primary project root",
        )?;
        require_existing_canonical_directory(
            &worktree_project,
            &worktree_root,
            "worktree project root",
        )?;

        let source = primary_project.join("node_modules");
        let destination = worktree_project.join("node_modules");
        require_existing_canonical_directory(&source, &primary_root, "source node_modules")?;
        require_absent_path(&destination, "destination node_modules")?;

        let source_relative = project_node_modules_relative(project_root);
        let source_tree = scan_offline_dependency_tree(&source, limits)?;
        let ignore_evidence_digest = verify_offline_node_modules_git_state(
            &primary_root,
            &source_relative,
            &source_tree.entries,
        )?;

        let controller_root = lease.controller_root.canonicalize()?;
        if controller_root != lease.controller_root {
            return Err(offline_dependency_error(
                "Controller worktree root changed identity before dependency staging",
            ));
        }
        let destination_parent_identity = directory_identity(&worktree_project)?;
        if fs::symlink_metadata(&controller_root)?.dev()
            != fs::symlink_metadata(&worktree_project)?.dev()
        {
            return Err(offline_dependency_error(
                "dependency staging and destination are not on the same filesystem",
            ));
        }

        let sequence = ATOMIC_WRITE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let staging = controller_root.join(format!(
            ".sovereign-node-modules-{}-{sequence}",
            std::process::id()
        ));
        require_absent_path(&staging, "dependency staging path")?;
        fs::create_dir(&staging)?;
        let staged_result = (|| {
            copy_offline_dependency_tree(&source, &staging, &source_tree)?;
            let staged_tree = scan_offline_dependency_tree(&staging, limits)?;
            if staged_tree.manifest != source_tree.manifest {
                return Err(offline_dependency_error(
                    "staged node_modules manifest differs from the verified source manifest",
                ));
            }

            let source_revalidated = scan_offline_dependency_tree(&source, limits)?;
            if source_revalidated.manifest != source_tree.manifest {
                return Err(offline_dependency_error(
                    "source node_modules changed while the offline copy was staged",
                ));
            }
            let revalidated_ignore_digest = verify_offline_node_modules_git_state(
                &primary_root,
                &source_relative,
                &source_revalidated.entries,
            )?;
            if revalidated_ignore_digest != ignore_evidence_digest {
                return Err(offline_dependency_error(
                    "source node_modules Git-ignore evidence changed while staging",
                ));
            }
            require_absent_path(&destination, "destination node_modules")?;
            if directory_identity(&worktree_project)? != destination_parent_identity {
                return Err(offline_dependency_error(
                    "worktree project root changed identity before dependency commit",
                ));
            }
            reject_existing_symlink_components(&worktree_root, project_root)?;
            fs::rename(&staging, &destination)?;
            OpenOptions::new()
                .read(true)
                .open(&worktree_project)?
                .sync_all()?;
            Ok(source_revalidated)
        })();
        let source_revalidated = match staged_result {
            Ok(tree) => tree,
            Err(error) => {
                cleanup_owned_staging_path(&staging);
                return Err(error);
            }
        };

        let destination_tree = scan_offline_dependency_tree(&destination, limits)?;
        if destination_tree.manifest != source_revalidated.manifest {
            return Err(offline_dependency_error(
                "atomically installed node_modules manifest differs from its verified source",
            ));
        }
        Ok(OfflineNodeModulesProvenance {
            schema_version: OFFLINE_NODE_MODULES_PROVENANCE_SCHEMA_VERSION,
            repository_id: lease.repository_id.clone(),
            plan_id: lease.plan_id.clone(),
            plan_revision: lease.plan_revision,
            task_id: lease.task_id.clone(),
            task_contract_digest: lease.task_contract_digest.clone(),
            worktree_lease_id: lease.lease_id.clone(),
            base_head: lease.base_head.clone(),
            project_root: project_root.to_path_buf(),
            source_node_modules: source,
            destination_node_modules: destination,
            ignore_evidence_digest,
            source_manifest: source_revalidated.manifest,
            destination_manifest: destination_tree.manifest,
        })
    }

    /// Rechecks an earlier offline dependency receipt against the exact live lease, source,
    /// ignored Git state, and destination. This grants no copy or installation authority.
    ///
    /// # Errors
    /// Returns an error when the receipt is misbound or either tree has drifted or become unsafe.
    pub fn validate_existing_node_modules_provenance(
        &self,
        lease: &WorktreeLease,
        provenance: &OfflineNodeModulesProvenance,
        limits: OfflineDependencyLimits,
    ) -> Result<(), RepoError> {
        self.validate_worktree_lease(lease)?;
        validate_offline_dependency_limits(limits)?;
        validate_offline_project_root(&provenance.project_root)?;
        let primary_root = lease.primary_root.canonicalize()?;
        let worktree_root = lease.worktree_path.canonicalize()?;
        if primary_root != lease.primary_root || worktree_root != lease.worktree_path {
            return Err(offline_dependency_error(
                "offline dependency roots changed identity",
            ));
        }
        reject_existing_symlink_components(&primary_root, &provenance.project_root)?;
        reject_existing_symlink_components(&worktree_root, &provenance.project_root)?;
        let relative = project_node_modules_relative(&provenance.project_root);
        let source = primary_root.join(&relative);
        let destination = worktree_root.join(&relative);
        if provenance.schema_version != OFFLINE_NODE_MODULES_PROVENANCE_SCHEMA_VERSION
            || provenance.repository_id != lease.repository_id
            || provenance.plan_id != lease.plan_id
            || provenance.plan_revision != lease.plan_revision
            || provenance.task_id != lease.task_id
            || provenance.task_contract_digest != lease.task_contract_digest
            || provenance.worktree_lease_id != lease.lease_id
            || provenance.base_head != lease.base_head
            || provenance.source_node_modules != source
            || provenance.destination_node_modules != destination
            || provenance.source_manifest != provenance.destination_manifest
        {
            return Err(offline_dependency_error(
                "offline dependency receipt is not bound to the exact lease and paths",
            ));
        }
        require_existing_canonical_directory(&source, &primary_root, "source node_modules")?;
        require_existing_canonical_directory(
            &destination,
            &worktree_root,
            "destination node_modules",
        )?;
        let source_tree = scan_offline_dependency_tree(&source, limits)?;
        let destination_tree = scan_offline_dependency_tree(&destination, limits)?;
        let ignore_digest =
            verify_offline_node_modules_git_state(&primary_root, &relative, &source_tree.entries)?;
        if source_tree.manifest != provenance.source_manifest
            || destination_tree.manifest != provenance.destination_manifest
            || ignore_digest != provenance.ignore_evidence_digest
        {
            return Err(offline_dependency_error(
                "offline dependency receipt manifest or Git-ignore evidence drifted",
            ));
        }
        Ok(())
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

fn offline_dependency_error(message: impl Into<String>) -> RepoError {
    RepoError::InvalidOfflineDependency(message.into())
}

fn validate_offline_dependency_limits(limits: OfflineDependencyLimits) -> Result<(), RepoError> {
    if limits.max_entries == 0 || limits.max_bytes == 0 {
        return Err(offline_dependency_error(
            "offline dependency entry and byte ceilings must both be positive",
        ));
    }
    Ok(())
}

fn validate_offline_project_root(project_root: &Path) -> Result<(), RepoError> {
    if project_root.is_absolute()
        || project_root
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(offline_dependency_error(format!(
            "project root must be strict repository-relative normal components: {}",
            project_root.display()
        )));
    }
    if project_root.to_str().is_none() {
        return Err(offline_dependency_error(
            "project root must be UTF-8 for hardened Git path binding",
        ));
    }
    Ok(())
}

fn project_node_modules_relative(project_root: &Path) -> PathBuf {
    if project_root.as_os_str().is_empty() {
        PathBuf::from("node_modules")
    } else {
        project_root.join("node_modules")
    }
}

fn require_existing_canonical_directory(
    path: &Path,
    boundary: &Path,
    label: &str,
) -> Result<(), RepoError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        offline_dependency_error(format!(
            "{label} is unavailable at {}: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(offline_dependency_error(format!(
            "{label} must be an existing non-symlink directory: {}",
            path.display()
        )));
    }
    let canonical = path.canonicalize()?;
    if canonical != path || !canonical.starts_with(boundary) {
        return Err(offline_dependency_error(format!(
            "{label} escaped or changed canonical identity: {}",
            path.display()
        )));
    }
    Ok(())
}

fn require_absent_path(path: &Path, label: &str) -> Result<(), RepoError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(offline_dependency_error(format!(
            "{label} must be absent before materialization: {}",
            path.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(RepoError::Io(error)),
    }
}

fn verify_offline_node_modules_git_state(
    repository_root: &Path,
    node_modules_relative: &Path,
    entries: &[OfflineDependencyEntry],
) -> Result<String, RepoError> {
    let pathspec = node_modules_relative.to_str().ok_or_else(|| {
        offline_dependency_error("node_modules path must be UTF-8 for hardened Git inspection")
    })?;
    let tracked = git_required_dynamic(
        repository_root,
        "verify offline node_modules is untracked",
        &["ls-files", "-z", "--", pathspec],
    )?;
    if !tracked.stdout.is_empty() {
        return Err(offline_dependency_error(
            "source node_modules contains Git-tracked paths",
        ));
    }

    let mut paths = Vec::with_capacity(entries.len().saturating_add(1));
    paths.push(node_modules_relative.to_path_buf());
    paths.extend(
        entries
            .iter()
            .map(|entry| node_modules_relative.join(&entry.relative_path)),
    );
    let expected = paths
        .iter()
        .map(|path| path.as_os_str().as_bytes().to_vec())
        .collect::<BTreeSet<_>>();
    let mut input = Vec::new();
    for path in &paths {
        input.extend_from_slice(path.as_os_str().as_bytes());
        input.push(0);
    }
    let ignored = git_output_with_input(
        repository_root,
        &["check-ignore", "--no-index", "-z", "--stdin"],
        &input,
    )?;
    if !ignored.status.success() && ignored.status.code() != Some(1) {
        return Err(git_failure(
            "verify offline node_modules ignore state",
            &ignored,
        ));
    }
    let ignored_paths = ignored
        .stdout
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .map(<[u8]>::to_vec)
        .collect::<BTreeSet<_>>();
    if ignored_paths != expected {
        return Err(offline_dependency_error(
            "source node_modules and every materialized entry must be Git-ignored",
        ));
    }

    let verbose = git_output_with_input(
        repository_root,
        &["check-ignore", "--no-index", "-v", "-z", "--stdin"],
        &input,
    )?;
    if !verbose.status.success() {
        if verbose.status.code() == Some(1) {
            return Err(offline_dependency_error(
                "source node_modules ignore provenance changed during verification",
            ));
        }
        return Err(git_failure(
            "capture offline node_modules ignore provenance",
            &verbose,
        ));
    }
    Ok(sha256_prefixed(&verbose.stdout))
}

fn scan_offline_dependency_tree(
    root: &Path,
    limits: OfflineDependencyLimits,
) -> Result<OfflineDependencyTree, RepoError> {
    validate_offline_dependency_limits(limits)?;
    let root_metadata = fs::symlink_metadata(root)?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(offline_dependency_error(format!(
            "offline dependency root must be a non-symlink directory: {}",
            root.display()
        )));
    }
    validate_offline_dependency_mode(root, &root_metadata)?;
    let canonical_root = root.canonicalize()?;
    if canonical_root != root {
        return Err(offline_dependency_error(
            "offline dependency root changed canonical identity",
        ));
    }
    let root_identity = identity(&root_metadata);
    let root_mode = root_metadata.permissions().mode() & 0o7777;
    let root_device = root_metadata.dev();
    let mut entries = Vec::new();
    let mut total_bytes = 0_u64;
    scan_offline_dependency_directory(
        &canonical_root,
        Path::new(""),
        root_device,
        limits,
        &mut entries,
        &mut total_bytes,
    )?;
    if directory_identity(root)? != root_identity {
        return Err(offline_dependency_error(
            "offline dependency root changed identity during manifest capture",
        ));
    }
    entries.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    let manifest = offline_dependency_manifest(root_mode, &entries, total_bytes)?;
    Ok(OfflineDependencyTree {
        root_mode,
        root_identity,
        entries,
        manifest,
    })
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
fn scan_offline_dependency_directory(
    root: &Path,
    relative_directory: &Path,
    root_device: u64,
    limits: OfflineDependencyLimits,
    entries: &mut Vec<OfflineDependencyEntry>,
    total_bytes: &mut u64,
) -> Result<(), RepoError> {
    let directory = root.join(relative_directory);
    let before_identity = directory_identity(&directory)?;
    let mut children = fs::read_dir(&directory)?.collect::<Result<Vec<_>, _>>()?;
    children.sort_by_key(std::fs::DirEntry::file_name);
    if directory_identity(&directory)? != before_identity {
        return Err(offline_dependency_error(
            "offline dependency directory changed identity during enumeration",
        ));
    }
    for child in children {
        let name = child.file_name();
        if name.as_os_str().as_bytes() == b".git" {
            return Err(offline_dependency_error(
                "offline dependency tree cannot contain a .git filesystem entry",
            ));
        }
        let relative_path = relative_directory.join(&name);
        let path = root.join(&relative_path);
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.dev() != root_device {
            return Err(offline_dependency_error(format!(
                "offline dependency entry crosses a filesystem boundary: {}",
                relative_path.display()
            )));
        }
        validate_offline_dependency_mode(&path, &metadata)?;
        let next_entries = u64::try_from(entries.len())
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        if next_entries > limits.max_entries {
            return Err(offline_dependency_error(format!(
                "offline dependency entry ceiling exceeded: {} > {}",
                next_entries, limits.max_entries
            )));
        }
        let entry_identity = identity(&metadata);
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            require_existing_canonical_directory(&path, root, "dependency directory")?;
            entries.push(OfflineDependencyEntry {
                relative_path: relative_path.clone(),
                mode: metadata.permissions().mode() & 0o7777,
                size_bytes: 0,
                identity: entry_identity,
                kind: OfflineDependencyEntryKind::Directory,
            });
            scan_offline_dependency_directory(
                root,
                &relative_path,
                root_device,
                limits,
                entries,
                total_bytes,
            )?;
            if directory_identity(&path)? != entry_identity {
                return Err(offline_dependency_error(format!(
                    "offline dependency directory changed identity: {}",
                    relative_path.display()
                )));
            }
        } else if metadata.is_file() && !metadata.file_type().is_symlink() {
            let size_bytes = metadata.len();
            *total_bytes = total_bytes.checked_add(size_bytes).ok_or_else(|| {
                offline_dependency_error("offline dependency byte count overflowed")
            })?;
            if *total_bytes > limits.max_bytes {
                return Err(offline_dependency_error(format!(
                    "offline dependency byte ceiling exceeded: {} > {}",
                    *total_bytes, limits.max_bytes
                )));
            }
            let content_digest = hash_verified_regular_file(&path, entry_identity, size_bytes)?;
            entries.push(OfflineDependencyEntry {
                relative_path,
                mode: metadata.permissions().mode() & 0o7777,
                size_bytes,
                identity: entry_identity,
                kind: OfflineDependencyEntryKind::RegularFile { content_digest },
            });
        } else if metadata.file_type().is_symlink() {
            let target =
                validated_internal_symlink_target(root, &path, entry_identity, root_device)?;
            let size_bytes = u64::try_from(target.as_os_str().as_bytes().len()).unwrap_or(u64::MAX);
            *total_bytes = total_bytes.checked_add(size_bytes).ok_or_else(|| {
                offline_dependency_error("offline dependency byte count overflowed")
            })?;
            if *total_bytes > limits.max_bytes {
                return Err(offline_dependency_error(format!(
                    "offline dependency byte ceiling exceeded: {} > {}",
                    *total_bytes, limits.max_bytes
                )));
            }
            entries.push(OfflineDependencyEntry {
                relative_path,
                mode: metadata.permissions().mode() & 0o7777,
                size_bytes,
                identity: entry_identity,
                kind: OfflineDependencyEntryKind::Symlink { target },
            });
        } else {
            return Err(offline_dependency_error(format!(
                "offline dependency tree contains a special filesystem entry: {}",
                relative_path.display()
            )));
        }
    }
    if directory_identity(&directory)? != before_identity {
        return Err(offline_dependency_error(
            "offline dependency directory changed identity during traversal",
        ));
    }
    Ok(())
}

fn validate_offline_dependency_mode(path: &Path, metadata: &fs::Metadata) -> Result<(), RepoError> {
    let mode = metadata.permissions().mode() & 0o7777;
    if mode & 0o7000 != 0 {
        return Err(offline_dependency_error(format!(
            "offline dependency entry has unsafe special permission bits: {}",
            path.display()
        )));
    }
    Ok(())
}

fn hash_verified_regular_file(
    path: &Path,
    expected_identity: FileIdentity,
    expected_size: u64,
) -> Result<String, RepoError> {
    let before = fs::symlink_metadata(path)?;
    if before.file_type().is_symlink()
        || !before.is_file()
        || identity(&before) != expected_identity
        || before.len() != expected_size
    {
        return Err(offline_dependency_error(format!(
            "offline dependency file changed before hashing: {}",
            path.display()
        )));
    }
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() || identity(&opened) != expected_identity || opened.len() != expected_size
    {
        return Err(offline_dependency_error(format!(
            "offline dependency file identity changed at open: {}",
            path.display()
        )));
    }
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    let mut read_bytes = 0_u64;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        read_bytes = read_bytes
            .checked_add(u64::try_from(count).unwrap_or(u64::MAX))
            .ok_or_else(|| offline_dependency_error("offline dependency file size overflowed"))?;
        hasher.update(&buffer[..count]);
    }
    if read_bytes != expected_size || identity(&fs::symlink_metadata(path)?) != expected_identity {
        return Err(offline_dependency_error(format!(
            "offline dependency file changed while hashing: {}",
            path.display()
        )));
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn validated_internal_symlink_target(
    root: &Path,
    path: &Path,
    expected_identity: FileIdentity,
    root_device: u64,
) -> Result<PathBuf, RepoError> {
    let before = fs::symlink_metadata(path)?;
    if !before.file_type().is_symlink() || identity(&before) != expected_identity {
        return Err(offline_dependency_error(format!(
            "offline dependency symlink changed identity: {}",
            path.display()
        )));
    }
    let target = fs::read_link(path)?;
    if target.is_absolute() {
        return Err(offline_dependency_error(format!(
            "offline dependency symlink target must be relative: {}",
            path.display()
        )));
    }
    let lexical_target = resolve_symlink_lexically_within_root(root, path, &target)?;
    let canonical_target = lexical_target.canonicalize().map_err(|error| {
        offline_dependency_error(format!(
            "offline dependency symlink target is missing or unsafe at {}: {error}",
            path.display()
        ))
    })?;
    if canonical_target == root || !canonical_target.starts_with(root) {
        return Err(offline_dependency_error(format!(
            "offline dependency symlink escapes or cycles to its node_modules root: {}",
            path.display()
        )));
    }
    if fs::metadata(&canonical_target)?.dev() != root_device {
        return Err(offline_dependency_error(format!(
            "offline dependency symlink target crosses a filesystem boundary: {}",
            path.display()
        )));
    }
    let after = fs::symlink_metadata(path)?;
    if !after.file_type().is_symlink()
        || identity(&after) != expected_identity
        || fs::read_link(path)? != target
    {
        return Err(offline_dependency_error(format!(
            "offline dependency symlink changed while validating: {}",
            path.display()
        )));
    }
    Ok(target)
}

fn resolve_symlink_lexically_within_root(
    root: &Path,
    symlink_path: &Path,
    target: &Path,
) -> Result<PathBuf, RepoError> {
    let parent = symlink_path.parent().ok_or_else(|| {
        offline_dependency_error("offline dependency symlink has no parent directory")
    })?;
    let parent_relative = parent.strip_prefix(root).map_err(|_| {
        offline_dependency_error("offline dependency symlink parent escaped its root")
    })?;
    let mut components = parent_relative
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(value) => Some(value.to_os_string()),
            _ => None,
        })
        .collect::<Vec<_>>();
    for component in target.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::Normal(value) => components.push(value.to_os_string()),
            std::path::Component::ParentDir => {
                if components.pop().is_none() {
                    return Err(offline_dependency_error(
                        "offline dependency symlink lexically escapes node_modules",
                    ));
                }
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                return Err(offline_dependency_error(
                    "offline dependency symlink target is not relative",
                ));
            }
        }
    }
    let mut resolved = root.to_path_buf();
    for component in components {
        resolved.push(component);
    }
    Ok(resolved)
}

fn offline_dependency_manifest(
    root_mode: u32,
    entries: &[OfflineDependencyEntry],
    total_bytes: u64,
) -> Result<OfflineDependencyManifest, RepoError> {
    let mut hasher = Sha256::new();
    digest_manifest_field(&mut hasher, b"sovereign.offline_node_modules.v1");
    hasher.update(root_mode.to_be_bytes());
    let mut directory_count = 0_u64;
    let mut regular_file_count = 0_u64;
    let mut symlink_count = 0_u64;
    for entry in entries {
        digest_manifest_field(&mut hasher, entry.relative_path.as_os_str().as_bytes());
        hasher.update(entry.mode.to_be_bytes());
        hasher.update(entry.size_bytes.to_be_bytes());
        match &entry.kind {
            OfflineDependencyEntryKind::Directory => {
                digest_manifest_field(&mut hasher, b"directory");
                directory_count = directory_count.saturating_add(1);
            }
            OfflineDependencyEntryKind::RegularFile { content_digest } => {
                digest_manifest_field(&mut hasher, b"regular_file");
                digest_manifest_field(&mut hasher, content_digest.as_bytes());
                regular_file_count = regular_file_count.saturating_add(1);
            }
            OfflineDependencyEntryKind::Symlink { target } => {
                digest_manifest_field(&mut hasher, b"symlink");
                digest_manifest_field(&mut hasher, target.as_os_str().as_bytes());
                symlink_count = symlink_count.saturating_add(1);
            }
        }
    }
    Ok(OfflineDependencyManifest {
        digest: format!("sha256:{:x}", hasher.finalize()),
        entry_count: u64::try_from(entries.len()).map_err(|_| {
            offline_dependency_error("offline dependency entry count cannot fit u64")
        })?,
        directory_count,
        regular_file_count,
        symlink_count,
        total_bytes,
    })
}

fn digest_manifest_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value);
}

fn copy_offline_dependency_tree(
    source_root: &Path,
    staging_root: &Path,
    source_tree: &OfflineDependencyTree,
) -> Result<(), RepoError> {
    if directory_identity(source_root)? != source_tree.root_identity {
        return Err(offline_dependency_error(
            "source node_modules root changed before staging copy",
        ));
    }
    fs::set_permissions(staging_root, fs::Permissions::from_mode(0o700))?;
    let root_device = fs::symlink_metadata(source_root)?.dev();
    for entry in &source_tree.entries {
        let source = source_root.join(&entry.relative_path);
        let destination = staging_root.join(&entry.relative_path);
        match &entry.kind {
            OfflineDependencyEntryKind::Directory => {
                let metadata = fs::symlink_metadata(&source)?;
                if metadata.file_type().is_symlink()
                    || !metadata.is_dir()
                    || identity(&metadata) != entry.identity
                {
                    return Err(offline_dependency_error(format!(
                        "source dependency directory changed before copy: {}",
                        entry.relative_path.display()
                    )));
                }
                fs::create_dir(&destination)?;
                fs::set_permissions(&destination, fs::Permissions::from_mode(0o700))?;
            }
            OfflineDependencyEntryKind::RegularFile { .. } => {
                copy_verified_regular_file(&source, &destination, entry)?;
            }
            OfflineDependencyEntryKind::Symlink { target } => {
                let current_target = validated_internal_symlink_target(
                    source_root,
                    &source,
                    entry.identity,
                    root_device,
                )?;
                if &current_target != target {
                    return Err(offline_dependency_error(format!(
                        "source dependency symlink target changed before copy: {}",
                        entry.relative_path.display()
                    )));
                }
                symlink(target, &destination)?;
            }
        }
    }
    for entry in source_tree.entries.iter().rev() {
        if matches!(entry.kind, OfflineDependencyEntryKind::Directory) {
            fs::set_permissions(
                staging_root.join(&entry.relative_path),
                fs::Permissions::from_mode(entry.mode & 0o777),
            )?;
        }
    }
    fs::set_permissions(
        staging_root,
        fs::Permissions::from_mode(source_tree.root_mode & 0o777),
    )?;
    OpenOptions::new()
        .read(true)
        .open(staging_root)?
        .sync_all()?;
    Ok(())
}

fn copy_verified_regular_file(
    source: &Path,
    destination: &Path,
    entry: &OfflineDependencyEntry,
) -> Result<(), RepoError> {
    let before = fs::symlink_metadata(source)?;
    if before.file_type().is_symlink()
        || !before.is_file()
        || identity(&before) != entry.identity
        || before.len() != entry.size_bytes
    {
        return Err(offline_dependency_error(format!(
            "source dependency file changed before copy: {}",
            entry.relative_path.display()
        )));
    }
    let mut input = File::open(source)?;
    let opened = input.metadata()?;
    if !opened.is_file() || identity(&opened) != entry.identity || opened.len() != entry.size_bytes
    {
        return Err(offline_dependency_error(format!(
            "source dependency file identity changed at copy open: {}",
            entry.relative_path.display()
        )));
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    let copied = std::io::copy(&mut input, &mut output)?;
    if copied != entry.size_bytes || identity(&fs::symlink_metadata(source)?) != entry.identity {
        return Err(offline_dependency_error(format!(
            "source dependency file changed during copy: {}",
            entry.relative_path.display()
        )));
    }
    output.set_permissions(fs::Permissions::from_mode(entry.mode & 0o777))?;
    output.sync_all()?;
    Ok(())
}

fn cleanup_owned_staging_path(path: &Path) {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || metadata.is_file() => {
            let _ = fs::remove_file(path);
        }
        Ok(_) => {
            let _ = fs::remove_dir_all(path);
        }
        Err(_) => {}
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

pub(crate) fn apply_untracked_deltas(
    root: &Path,
    deltas: &[UntrackedFileDelta],
) -> Result<(), RepoError> {
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

pub(crate) fn reject_checkout_side_effects(root: &Path, base_head: &str) -> Result<(), RepoError> {
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

pub(crate) fn git_required_dynamic(
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

pub(crate) fn git_output_with_input(
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

pub(crate) fn git_failure(operation: &'static str, output: &std::process::Output) -> RepoError {
    RepoError::GitFailed {
        operation,
        status: output.status.code(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}
