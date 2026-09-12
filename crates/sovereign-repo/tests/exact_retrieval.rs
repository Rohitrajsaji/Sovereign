use sovereign_repo::{
    ExactRetriever, ExactSearchQuery, ProjectRegistry, RepoError, RepositoryIntelligence,
};
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
            "sovereign-repo-exact-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(path.join("src"))
            .unwrap_or_else(|error| panic!("create test repo: {error}"));
        git(&path, &["init", "-q"]);
        fs::write(
            path.join("src/lib.rs"),
            "pub fn alpha() -> &'static str { \"needle\" }\n",
        )
        .unwrap_or_else(|error| panic!("write source: {error}"));
        fs::write(
            path.join("src/other.rs"),
            "pub const VALUE: &str = \"needle second\";\n",
        )
        .unwrap_or_else(|error| panic!("write source: {error}"));
        fs::write(path.join("AGENTS.md"), "root instructions\n")
            .unwrap_or_else(|error| panic!("write instructions: {error}"));
        git(&path, &["add", "."]);
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

fn registry(repo: &TestRepo) -> ProjectRegistry {
    let mut registry = ProjectRegistry::new();
    registry
        .register("repo.fixture", repo.path())
        .unwrap_or_else(|error| panic!("register: {error}"));
    registry
}

#[test]
fn stale_file_hash_is_rejected_then_current_read_refreshes() {
    let repo = TestRepo::new("stale");
    let registry = registry(&repo);
    let retriever = ExactRetriever::new(&registry);
    let first = retriever
        .read_path("repo.fixture", Path::new("src/lib.rs"), None)
        .unwrap_or_else(|error| panic!("read first: {error}"));

    fs::write(
        repo.path().join("src/lib.rs"),
        "pub fn alpha() -> &'static str { \"changed\" }\n",
    )
    .unwrap_or_else(|error| panic!("edit source: {error}"));

    assert!(matches!(
        retriever.read_path("repo.fixture", Path::new("src/lib.rs"), Some(&first.digest)),
        Err(RepoError::StaleFileHash { .. })
    ));
    let refreshed = retriever
        .read_path("repo.fixture", Path::new("src/lib.rs"), None)
        .unwrap_or_else(|error| panic!("refresh: {error}"));
    assert_ne!(first.digest, refreshed.digest);
    assert!(refreshed.content.contains("changed"));
}

#[test]
fn literal_search_is_bounded_current_and_stably_ordered() {
    let repo = TestRepo::new("search");
    let registry = registry(&repo);
    let retriever = ExactRetriever::new(&registry);
    let hits = retriever
        .search_literal(
            "repo.fixture",
            &ExactSearchQuery {
                text: "needle",
                max_hits: 8,
                max_files: 32,
                max_file_bytes: 64 * 1024,
                max_line_bytes: 128,
            },
        )
        .unwrap_or_else(|error| panic!("search: {error}"));

    assert_eq!(hits.len(), 2);
    assert_eq!(hits[0].relative_path, PathBuf::from("src/lib.rs"));
    assert_eq!(hits[1].relative_path, PathBuf::from("src/other.rs"));
    assert!(
        hits.iter()
            .all(|hit| hit.source_digest.starts_with("sha256:"))
    );
    assert!(hits.iter().all(|hit| hit.line.len() <= 128));
}

#[test]
fn current_diff_returns_source_bearing_digest_without_index_dependency() {
    let repo = TestRepo::new("diff");
    fs::write(
        repo.path().join("src/lib.rs"),
        "pub fn alpha() -> &'static str { \"new-value\" }\n",
    )
    .unwrap_or_else(|error| panic!("edit source: {error}"));
    let registry = registry(&repo);
    let retriever = ExactRetriever::new(&registry);
    let diff = retriever
        .current_diff("repo.fixture")
        .unwrap_or_else(|error| panic!("diff: {error}"));

    assert!(diff.digest.starts_with("sha256:"));
    assert!(diff.content.contains("new-value"));
    let snapshot = registry
        .snapshot("repo.fixture")
        .unwrap_or_else(|error| panic!("snapshot: {error}"));
    assert!(snapshot.protected_changes_present);
}
