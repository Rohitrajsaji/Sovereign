//! Filesystem/Git source-of-truth primitives for Sovereign repository intelligence.
//!
//! M1 intentionally keeps this layer exact and deterministic. Rich lexical,
//! symbol, dependency, and semantic projections are later derived extensions;
//! they never replace source files or Git as repository truth.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output};

const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Deterministic repository-layer failure.
#[derive(Debug)]
pub enum RepoError {
    Io(std::io::Error),
    InvalidRepositoryId(String),
    DuplicateRepository(String),
    UnknownRepository(String),
    NotRepository(PathBuf),
    RepositoryRootMismatch {
        requested: PathBuf,
        actual: PathBuf,
    },
    SymlinkPath(PathBuf),
    InvalidRelativePath(PathBuf),
    NonUtf8GitOutput(&'static str),
    MalformedGitStatus(String),
    GitFailed {
        operation: &'static str,
        status: Option<i32>,
        stderr: String,
    },
    Serialization(serde_json::Error),
}

impl Display for RepoError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "repository I/O error: {error}"),
            Self::InvalidRepositoryId(id) => write!(f, "invalid repository id {id:?}"),
            Self::DuplicateRepository(id) => write!(f, "repository id {id} is already registered"),
            Self::UnknownRepository(id) => write!(f, "unknown repository id {id}"),
            Self::NotRepository(path) => write!(f, "{} is not a Git repository", path.display()),
            Self::RepositoryRootMismatch { requested, actual } => write!(
                f,
                "registered path {} is not the Git top-level {}",
                requested.display(),
                actual.display()
            ),
            Self::SymlinkPath(path) => {
                write!(
                    f,
                    "symlink path is not accepted for repository scope: {}",
                    path.display()
                )
            }
            Self::InvalidRelativePath(path) => {
                write!(
                    f,
                    "path must be repository-relative without parent traversal: {}",
                    path.display()
                )
            }
            Self::NonUtf8GitOutput(operation) => {
                write!(f, "Git {operation} returned a non-UTF-8 path/output")
            }
            Self::MalformedGitStatus(record) => write!(f, "malformed Git status record {record:?}"),
            Self::GitFailed {
                operation,
                status,
                stderr,
            } => write!(
                f,
                "Git {operation} failed with status {status:?}: {}",
                stderr.trim()
            ),
            Self::Serialization(error) => {
                write!(f, "repository manifest serialization error: {error}")
            }
        }
    }
}

impl Error for RepoError {}

impl From<std::io::Error> for RepoError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for RepoError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialization(value)
    }
}

/// One registered source-of-truth repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisteredRepository {
    pub repository_id: String,
    pub root: PathBuf,
}

/// Fingerprint and affected paths for one Git change class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeClassSnapshot {
    pub digest: String,
    pub paths: Vec<PathBuf>,
}

impl ChangeClassSnapshot {
    fn empty() -> Self {
        Self {
            digest: format!("sha256:{EMPTY_SHA256}"),
            paths: Vec::new(),
        }
    }
}

/// Exact Git/filesystem baseline captured before a task may mutate a repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepositorySnapshot {
    pub repository_id: String,
    pub root: PathBuf,
    pub head: Option<String>,
    pub branch: Option<String>,
    pub staged: ChangeClassSnapshot,
    pub unstaged: ChangeClassSnapshot,
    pub untracked: ChangeClassSnapshot,
    pub dirty_digest: String,
    pub protected_changes_present: bool,
}

impl RepositorySnapshot {
    /// Serializes a stable manifest with recursively deterministic struct field
    /// order for completion evidence and later checkpoint binding.
    ///
    /// # Errors
    ///
    /// Returns [`RepoError`] if JSON serialization fails.
    pub fn manifest_json(&self) -> Result<String, RepoError> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}

/// Difference between two exact repository baselines.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoDelta {
    pub changed_dimensions: Vec<RepoChangeKind>,
    pub dirty_digest_before: String,
    pub dirty_digest_after: String,
}

/// Repository dimensions whose exact baseline changed between snapshots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RepoChangeKind {
    Head,
    Branch,
    Staged,
    Unstaged,
    Untracked,
}

impl RepoDelta {
    #[must_use]
    pub fn changed(&self) -> bool {
        !self.changed_dimensions.is_empty()
    }

    #[must_use]
    pub fn contains(&self, kind: RepoChangeKind) -> bool {
        self.changed_dimensions.binary_search(&kind).is_ok()
    }
}

/// One instruction file applying to a repository-relative target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstructionDocument {
    pub relative_path: PathBuf,
    pub digest: String,
    pub content: String,
}

/// Deterministically resolves root-to-leaf `AGENTS.md` instruction scope.
#[derive(Debug, Clone)]
pub struct InstructionResolver {
    root: PathBuf,
}

impl InstructionResolver {
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// Resolves all `AGENTS.md` files whose directory scope contains `target`.
    /// Results are ordered from repository root to the deepest applicable file.
    /// Existing symlink components and symlink instruction files fail closed.
    ///
    /// # Errors
    ///
    /// Returns [`RepoError`] for path traversal, symlink scope, or file I/O
    /// failure.
    pub fn resolve_for_path(
        &self,
        target: impl AsRef<Path>,
    ) -> Result<Vec<InstructionDocument>, RepoError> {
        let target = target.as_ref();
        validate_relative_path(target)?;
        reject_existing_symlink_components(&self.root, target)?;

        let target_absolute = self.root.join(target);
        let target_is_directory =
            fs::metadata(&target_absolute).is_ok_and(|metadata| metadata.is_dir());
        let scope = if target_is_directory {
            target
        } else {
            target.parent().unwrap_or_else(|| Path::new(""))
        };

        let mut directories = vec![PathBuf::new()];
        let mut current = PathBuf::new();
        for component in scope.components() {
            let Component::Normal(segment) = component else {
                return Err(RepoError::InvalidRelativePath(target.to_path_buf()));
            };
            current.push(segment);
            directories.push(current.clone());
        }

        let mut resolved = Vec::new();
        for directory in directories {
            let relative = directory.join("AGENTS.md");
            let candidate = self.root.join(&relative);
            let metadata = match fs::symlink_metadata(&candidate) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(RepoError::Io(error)),
            };
            if metadata.file_type().is_symlink() {
                return Err(RepoError::SymlinkPath(candidate));
            }
            if !metadata.is_file() {
                continue;
            }
            let bytes = fs::read(&candidate)?;
            let content = String::from_utf8(bytes.clone())
                .map_err(|_| RepoError::NonUtf8GitOutput("instruction read"))?;
            resolved.push(InstructionDocument {
                relative_path: relative,
                digest: sha256_prefixed(&bytes),
                content,
            });
        }
        Ok(resolved)
    }
}

/// M1 repository authority surface. Later milestones extend retrieval through
/// derived indexes while these exact baseline/instruction semantics remain the
/// source-of-truth foundation.
pub trait RepositoryIntelligence {
    /// Captures the current exact repository baseline.
    ///
    /// # Errors
    ///
    /// Returns [`RepoError`] for unknown repositories or Git/filesystem errors.
    fn snapshot(&self, repository_id: &str) -> Result<RepositorySnapshot, RepoError>;

    /// Resolves scoped repository instructions for one path.
    ///
    /// # Errors
    ///
    /// Returns [`RepoError`] for unknown repositories or unsafe/invalid paths.
    fn instructions_for_path(
        &self,
        repository_id: &str,
        relative_path: &Path,
    ) -> Result<Vec<InstructionDocument>, RepoError>;
}

/// Registry and exact baseline manager for local repositories.
#[derive(Debug, Default)]
pub struct ProjectRegistry {
    repositories: BTreeMap<String, RegisteredRepository>,
}

impl ProjectRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers exactly one Git top-level directory under a stable ID.
    /// Registration rejects a symlink root so later repository-relative scope
    /// cannot silently point at a different tree.
    ///
    /// # Errors
    ///
    /// Returns [`RepoError`] for invalid/duplicate IDs, symlink roots, non-Git
    /// paths, Git command failure, or a path below/above the Git top level.
    pub fn register(
        &mut self,
        repository_id: impl Into<String>,
        root: impl AsRef<Path>,
    ) -> Result<RegisteredRepository, RepoError> {
        let repository_id = repository_id.into();
        if !valid_repository_id(&repository_id) {
            return Err(RepoError::InvalidRepositoryId(repository_id));
        }
        if self.repositories.contains_key(&repository_id) {
            return Err(RepoError::DuplicateRepository(repository_id));
        }

        let root = root.as_ref();
        let metadata = fs::symlink_metadata(root)?;
        if metadata.file_type().is_symlink() {
            return Err(RepoError::SymlinkPath(root.to_path_buf()));
        }
        if !metadata.is_dir() {
            return Err(RepoError::NotRepository(root.to_path_buf()));
        }
        let canonical = fs::canonicalize(root)?;
        let top_level_output = git_required(
            &canonical,
            "show top-level",
            &["rev-parse", "--show-toplevel"],
        )?;
        let top_level = String::from_utf8(top_level_output.stdout)
            .map_err(|_| RepoError::NonUtf8GitOutput("show top-level"))?;
        let actual = fs::canonicalize(Path::new(top_level.trim()))?;
        if actual != canonical {
            return Err(RepoError::RepositoryRootMismatch {
                requested: canonical,
                actual,
            });
        }

        let registered = RegisteredRepository {
            repository_id: repository_id.clone(),
            root: actual,
        };
        self.repositories.insert(repository_id, registered.clone());
        Ok(registered)
    }

    #[must_use]
    pub fn repository(&self, repository_id: &str) -> Option<&RegisteredRepository> {
        self.repositories.get(repository_id)
    }

    /// Computes an exact change summary between two snapshots of the same
    /// registered repository.
    ///
    /// # Errors
    ///
    /// Returns [`RepoError`] if the snapshots belong to different repository
    /// IDs or roots.
    pub fn delta(
        &self,
        before: &RepositorySnapshot,
        after: &RepositorySnapshot,
    ) -> Result<RepoDelta, RepoError> {
        if before.repository_id != after.repository_id || before.root != after.root {
            return Err(RepoError::UnknownRepository(format!(
                "snapshot mismatch {} -> {}",
                before.repository_id, after.repository_id
            )));
        }
        let mut changed_dimensions = Vec::new();
        if before.head != after.head {
            changed_dimensions.push(RepoChangeKind::Head);
        }
        if before.branch != after.branch {
            changed_dimensions.push(RepoChangeKind::Branch);
        }
        if before.staged.digest != after.staged.digest {
            changed_dimensions.push(RepoChangeKind::Staged);
        }
        if before.unstaged.digest != after.unstaged.digest {
            changed_dimensions.push(RepoChangeKind::Unstaged);
        }
        if before.untracked.digest != after.untracked.digest {
            changed_dimensions.push(RepoChangeKind::Untracked);
        }
        Ok(RepoDelta {
            changed_dimensions,
            dirty_digest_before: before.dirty_digest.clone(),
            dirty_digest_after: after.dirty_digest.clone(),
        })
    }

    fn registered(&self, repository_id: &str) -> Result<&RegisteredRepository, RepoError> {
        self.repositories
            .get(repository_id)
            .ok_or_else(|| RepoError::UnknownRepository(repository_id.to_owned()))
    }
}

impl RepositoryIntelligence for ProjectRegistry {
    fn snapshot(&self, repository_id: &str) -> Result<RepositorySnapshot, RepoError> {
        let repository = self.registered(repository_id)?;
        capture_snapshot(repository)
    }

    fn instructions_for_path(
        &self,
        repository_id: &str,
        relative_path: &Path,
    ) -> Result<Vec<InstructionDocument>, RepoError> {
        let repository = self.registered(repository_id)?;
        InstructionResolver::new(repository.root.clone()).resolve_for_path(relative_path)
    }
}

fn capture_snapshot(repository: &RegisteredRepository) -> Result<RepositorySnapshot, RepoError> {
    let head = git_optional_text(
        &repository.root,
        "read HEAD",
        &["rev-parse", "--verify", "--quiet", "HEAD"],
    )?
    .map(|value| value.trim().to_owned());
    let branch = git_optional_text(
        &repository.root,
        "read branch",
        &["symbolic-ref", "--quiet", "--short", "HEAD"],
    )?
    .map(|value| value.trim().to_owned());

    let status = git_required(
        &repository.root,
        "read status",
        &[
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--no-renames",
        ],
    )?;
    let records = parse_status(&status.stdout)?;

    let mut staged_entries = Vec::new();
    let mut unstaged_entries = Vec::new();
    let mut untracked_entries = Vec::new();
    for record in records {
        if record.index_status == '?' && record.worktree_status == '?' {
            untracked_entries.push(worktree_entry(&repository.root, '?', &record.path)?);
            continue;
        }
        if record.index_status != ' ' {
            staged_entries.push(index_entry(
                &repository.root,
                record.index_status,
                &record.path,
            )?);
        }
        if record.worktree_status != ' ' {
            unstaged_entries.push(worktree_entry(
                &repository.root,
                record.worktree_status,
                &record.path,
            )?);
        }
    }

    let staged = snapshot_entries(staged_entries);
    let unstaged = snapshot_entries(unstaged_entries);
    let untracked = snapshot_entries(untracked_entries);
    let dirty_digest = digest_dirty_classes(&staged, &unstaged, &untracked);
    let protected_changes_present =
        !staged.paths.is_empty() || !unstaged.paths.is_empty() || !untracked.paths.is_empty();

    Ok(RepositorySnapshot {
        repository_id: repository.repository_id.clone(),
        root: repository.root.clone(),
        head,
        branch,
        staged,
        unstaged,
        untracked,
        dirty_digest,
        protected_changes_present,
    })
}

#[derive(Debug)]
struct StatusRecord {
    index_status: char,
    worktree_status: char,
    path: PathBuf,
}

fn parse_status(bytes: &[u8]) -> Result<Vec<StatusRecord>, RepoError> {
    let mut records = Vec::new();
    for raw in bytes
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        let text = std::str::from_utf8(raw).map_err(|_| RepoError::NonUtf8GitOutput("status"))?;
        let mut chars = text.chars();
        let Some(index_status) = chars.next() else {
            return Err(RepoError::MalformedGitStatus(text.to_owned()));
        };
        let Some(worktree_status) = chars.next() else {
            return Err(RepoError::MalformedGitStatus(text.to_owned()));
        };
        if chars.next() != Some(' ') {
            return Err(RepoError::MalformedGitStatus(text.to_owned()));
        }
        let path: String = chars.collect();
        if path.is_empty() {
            return Err(RepoError::MalformedGitStatus(text.to_owned()));
        }
        let path = PathBuf::from(path);
        validate_relative_path(&path)?;
        records.push(StatusRecord {
            index_status,
            worktree_status,
            path,
        });
    }
    Ok(records)
}

fn index_entry(root: &Path, status: char, path: &Path) -> Result<(PathBuf, String), RepoError> {
    if status == 'D' {
        return Ok((path.to_path_buf(), format!("D\0{}", path.display())));
    }
    let path_text = path
        .to_str()
        .ok_or(RepoError::NonUtf8GitOutput("index path"))?;
    let output = git_required(
        root,
        "read index entry",
        &["ls-files", "--stage", "-z", "--", path_text],
    )?;
    if output.stdout.is_empty() {
        return Err(RepoError::MalformedGitStatus(format!(
            "missing index entry for {}",
            path.display()
        )));
    }
    Ok((
        path.to_path_buf(),
        format!(
            "{status}\0{}\0{}",
            path.display(),
            sha256_prefixed(&output.stdout)
        ),
    ))
}

fn worktree_entry(root: &Path, status: char, path: &Path) -> Result<(PathBuf, String), RepoError> {
    let absolute = root.join(path);
    let state = match fs::symlink_metadata(&absolute) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            let target = fs::read_link(&absolute)?;
            format!(
                "symlink:{}",
                sha256_prefixed(target.as_os_str().as_encoded_bytes())
            )
        }
        Ok(metadata) if metadata.is_file() => sha256_prefixed(&fs::read(&absolute)?),
        Ok(metadata) if metadata.is_dir() => "directory".to_owned(),
        Ok(_) => "special".to_owned(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => "missing".to_owned(),
        Err(error) => return Err(RepoError::Io(error)),
    };
    Ok((
        path.to_path_buf(),
        format!("{status}\0{}\0{state}", path.display()),
    ))
}

fn snapshot_entries(mut entries: Vec<(PathBuf, String)>) -> ChangeClassSnapshot {
    if entries.is_empty() {
        return ChangeClassSnapshot::empty();
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let mut hasher = Sha256::new();
    let mut paths = Vec::with_capacity(entries.len());
    for (path, fingerprint) in entries {
        hasher.update(fingerprint.as_bytes());
        hasher.update([0]);
        paths.push(path);
    }
    ChangeClassSnapshot {
        digest: format!("sha256:{:x}", hasher.finalize()),
        paths,
    }
}

fn digest_dirty_classes(
    staged: &ChangeClassSnapshot,
    unstaged: &ChangeClassSnapshot,
    untracked: &ChangeClassSnapshot,
) -> String {
    let mut hasher = Sha256::new();
    for (label, digest) in [
        ("staged", &staged.digest),
        ("unstaged", &unstaged.digest),
        ("untracked", &untracked.digest),
    ] {
        hasher.update(label.as_bytes());
        hasher.update([0]);
        hasher.update(digest.as_bytes());
        hasher.update([0]);
    }
    format!("sha256:{:x}", hasher.finalize())
}

fn validate_relative_path(path: &Path) -> Result<(), RepoError> {
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(RepoError::InvalidRelativePath(path.to_path_buf()));
    }
    Ok(())
}

fn reject_existing_symlink_components(root: &Path, path: &Path) -> Result<(), RepoError> {
    let mut current = root.to_path_buf();
    for component in path.components() {
        let Component::Normal(segment) = component else {
            return Err(RepoError::InvalidRelativePath(path.to_path_buf()));
        };
        current.push(segment);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(RepoError::SymlinkPath(current));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(RepoError::Io(error)),
        }
    }
    Ok(())
}

fn valid_repository_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    (3..=128).contains(&bytes.len())
        && bytes.first().is_some_and(u8::is_ascii_alphabetic)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'.' | b':' | b'-'))
}

fn git_required(root: &Path, operation: &'static str, args: &[&str]) -> Result<Output, RepoError> {
    let output = git_output(root, args)?;
    if output.status.success() {
        return Ok(output);
    }
    Err(RepoError::GitFailed {
        operation,
        status: output.status.code(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

fn git_optional_text(
    root: &Path,
    operation: &'static str,
    args: &[&str],
) -> Result<Option<String>, RepoError> {
    let output = git_output(root, args)?;
    if output.status.success() {
        let text =
            String::from_utf8(output.stdout).map_err(|_| RepoError::NonUtf8GitOutput(operation))?;
        return Ok(Some(text));
    }
    if output.status.code() == Some(1) {
        return Ok(None);
    }
    Err(RepoError::GitFailed {
        operation,
        status: output.status.code(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

fn git_output(root: &Path, args: &[&str]) -> Result<Output, RepoError> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let mut command = Command::new("git");
    command
        .current_dir(root)
        .env_clear()
        .env("PATH", path)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "color.ui=false",
            "-c",
            "pager.status=false",
        ])
        .args(args);
    Ok(command.output()?)
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}
