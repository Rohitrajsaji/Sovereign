use sovereign_repo::{ProjectRegistry, RepoChangeKind, RepoError, RepositoryIntelligence};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

struct TestRepo(PathBuf);

impl TestRepo {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "sovereign-repo-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap_or_else(|error| panic!("create test repo: {error}"));
        git(&path, &["init", "-q"]);
        fs::write(path.join("tracked.txt"), "base\n")
            .unwrap_or_else(|error| panic!("write tracked: {error}"));
        git(&path, &["add", "tracked.txt"]);
        git(&path, &["commit", "-q", "-m", "fixture"]);
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestRepo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn git(root: &Path, args: &[&str]) {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let status = Command::new("git")
        .current_dir(root)
        .env_clear()
        .env("PATH", path)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "Sovereign Fixture")
        .env("GIT_AUTHOR_EMAIL", "fixture@sovereign.invalid")
        .env("GIT_COMMITTER_NAME", "Sovereign Fixture")
        .env("GIT_COMMITTER_EMAIL", "fixture@sovereign.invalid")
        .env("GIT_AUTHOR_DATE", "2026-01-01T00:00:00Z")
        .env("GIT_COMMITTER_DATE", "2026-01-01T00:00:00Z")
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
        ])
        .args(args)
        .status()
        .unwrap_or_else(|error| panic!("run git {args:?}: {error}"));
    assert!(status.success(), "git command failed: {args:?}");
}

fn registry_for(repo: &TestRepo) -> ProjectRegistry {
    let mut registry = ProjectRegistry::new();
    registry
        .register("repo.fixture", repo.path())
        .unwrap_or_else(|error| panic!("register: {error}"));
    registry
}

#[test]
fn clean_repo_snapshot_has_no_protected_changes() {
    let repo = TestRepo::new("clean");
    let registry = registry_for(&repo);
    let snapshot = registry
        .snapshot("repo.fixture")
        .unwrap_or_else(|error| panic!("snapshot: {error}"));

    assert!(snapshot.head.is_some());
    assert!(!snapshot.protected_changes_present);
    assert!(snapshot.staged.paths.is_empty());
    assert!(snapshot.unstaged.paths.is_empty());
    assert!(snapshot.untracked.paths.is_empty());
    assert!(snapshot.manifest_json().is_ok());
}

#[test]
fn dirty_repo_separates_staged_unstaged_and_untracked_changes() {
    let repo = TestRepo::new("dirty");
    fs::write(repo.path().join("tracked.txt"), "staged\n")
        .unwrap_or_else(|error| panic!("write staged: {error}"));
    git(repo.path(), &["add", "tracked.txt"]);
    fs::write(repo.path().join("tracked.txt"), "staged\nunstaged\n")
        .unwrap_or_else(|error| panic!("write unstaged: {error}"));
    fs::write(repo.path().join("new.txt"), "untracked\n")
        .unwrap_or_else(|error| panic!("write untracked: {error}"));

    let registry = registry_for(&repo);
    let snapshot = registry
        .snapshot("repo.fixture")
        .unwrap_or_else(|error| panic!("snapshot: {error}"));

    assert!(snapshot.protected_changes_present);
    assert_eq!(snapshot.staged.paths, vec![PathBuf::from("tracked.txt")]);
    assert_eq!(snapshot.unstaged.paths, vec![PathBuf::from("tracked.txt")]);
    assert_eq!(snapshot.untracked.paths, vec![PathBuf::from("new.txt")]);
}

#[test]
fn nested_agents_scope_is_root_to_leaf_and_deterministic() {
    let repo = TestRepo::new("instructions");
    fs::write(repo.path().join("AGENTS.md"), "root rules\n")
        .unwrap_or_else(|error| panic!("write root instructions: {error}"));
    fs::create_dir_all(repo.path().join("src/ui"))
        .unwrap_or_else(|error| panic!("create nested: {error}"));
    fs::write(repo.path().join("src/AGENTS.md"), "src rules\n")
        .unwrap_or_else(|error| panic!("write nested instructions: {error}"));
    fs::write(repo.path().join("src/ui/button.rs"), "fn button() {}\n")
        .unwrap_or_else(|error| panic!("write target: {error}"));

    let registry = registry_for(&repo);
    let first = registry
        .instructions_for_path("repo.fixture", Path::new("src/ui/button.rs"))
        .unwrap_or_else(|error| panic!("resolve instructions: {error}"));
    let second = registry
        .instructions_for_path("repo.fixture", Path::new("src/ui/button.rs"))
        .unwrap_or_else(|error| panic!("resolve instructions again: {error}"));

    assert_eq!(first, second);
    assert_eq!(first.len(), 2);
    assert_eq!(first[0].relative_path, PathBuf::from("AGENTS.md"));
    assert_eq!(first[0].content, "root rules\n");
    assert_eq!(first[1].relative_path, PathBuf::from("src/AGENTS.md"));
    assert_eq!(first[1].content, "src rules\n");
}

#[cfg(unix)]
#[test]
fn symlink_repository_and_scoped_path_are_rejected() {
    use std::os::unix::fs::symlink;

    let repo = TestRepo::new("symlink");
    let link_root = repo.path().with_extension("link");
    symlink(repo.path(), &link_root).unwrap_or_else(|error| panic!("symlink repo: {error}"));
    let mut registry = ProjectRegistry::new();
    assert!(matches!(
        registry.register("repo.link", &link_root),
        Err(RepoError::SymlinkPath(_))
    ));
    fs::remove_file(&link_root).unwrap_or_else(|error| panic!("remove root link: {error}"));

    let registry = registry_for(&repo);
    let outside = repo.path().with_extension("outside");
    fs::create_dir_all(&outside).unwrap_or_else(|error| panic!("create outside: {error}"));
    symlink(&outside, repo.path().join("escape"))
        .unwrap_or_else(|error| panic!("symlink scoped path: {error}"));
    assert!(matches!(
        registry.instructions_for_path("repo.fixture", Path::new("escape/file.rs")),
        Err(RepoError::SymlinkPath(_))
    ));
    fs::remove_dir_all(&outside).unwrap_or_else(|error| panic!("remove outside: {error}"));
}

#[test]
fn snapshot_and_delta_change_after_worktree_edit() {
    let repo = TestRepo::new("delta");
    let registry = registry_for(&repo);
    let before = registry
        .snapshot("repo.fixture")
        .unwrap_or_else(|error| panic!("before snapshot: {error}"));
    fs::write(repo.path().join("tracked.txt"), "changed\n")
        .unwrap_or_else(|error| panic!("edit tracked: {error}"));
    let after = registry
        .snapshot("repo.fixture")
        .unwrap_or_else(|error| panic!("after snapshot: {error}"));
    let delta = registry
        .delta(&before, &after)
        .unwrap_or_else(|error| panic!("delta: {error}"));

    assert_ne!(before.dirty_digest, after.dirty_digest);
    assert!(delta.changed());
    assert!(delta.contains(RepoChangeKind::Unstaged));
    assert!(!delta.contains(RepoChangeKind::Head));
}
