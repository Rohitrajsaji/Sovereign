use sovereign_repo::{
    ChangeSet, ChangeSetCompositionInput, ComposeChangeSetsOutcome, OfflineDependencyLimits,
    ProjectRegistry, RepoError, RepositoryIntelligence, WorktreeLease,
};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static SEQUENCE: AtomicU64 = AtomicU64::new(1);

struct Fixture {
    base: PathBuf,
    primary: PathBuf,
    worktrees: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let base = std::env::temp_dir().join(format!(
            "sovereign-worktree-{label}-{}-{nanos}-{sequence}",
            std::process::id()
        ));
        let primary = base.join("primary");
        let worktrees = base.join("state/worktrees");
        fs::create_dir_all(&primary).unwrap_or_else(|error| panic!("create primary: {error}"));
        git(&primary, &["init", "-q"]);
        git(&primary, &["config", "user.name", "Sovereign Fixture"]);
        git(
            &primary,
            &["config", "user.email", "fixture@sovereign.invalid"],
        );
        fs::write(primary.join("tracked.txt"), "base\n")
            .unwrap_or_else(|error| panic!("write tracked: {error}"));
        fs::write(primary.join("other.txt"), "other\n")
            .unwrap_or_else(|error| panic!("write other: {error}"));
        git(&primary, &["add", "."]);
        git(&primary, &["commit", "-qm", "baseline"]);
        Self {
            base,
            primary,
            worktrees,
        }
    }

    fn registry(&self) -> ProjectRegistry {
        let mut registry = ProjectRegistry::new();
        registry
            .register("repo.fixture", &self.primary)
            .unwrap_or_else(|error| panic!("register: {error}"));
        registry
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
        .env("GIT_ATTR_NOSYSTEM", "1")
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("git {args:?}: {error}"));
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .unwrap_or_else(|error| panic!("git output not UTF-8: {error}"))
        .trim()
        .to_owned()
}

fn git_input(root: &Path, args: &[&str], input: &str) -> String {
    let mut child = Command::new("/usr/bin/git")
        .current_dir(root)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_ATTR_NOSYSTEM", "1")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("spawn git {args:?}: {error}"));
    child
        .stdin
        .as_mut()
        .unwrap_or_else(|| panic!("git stdin unavailable"))
        .write_all(input.as_bytes())
        .unwrap_or_else(|error| panic!("write git stdin: {error}"));
    let output = child
        .wait_with_output()
        .unwrap_or_else(|error| panic!("wait git {args:?}: {error}"));
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .unwrap_or_else(|error| panic!("git output not UTF-8: {error}"))
        .trim()
        .to_owned()
}

fn configure_offline_node_project(fixture: &Fixture) {
    fs::create_dir_all(fixture.primary.join("app"))
        .unwrap_or_else(|error| panic!("create app: {error}"));
    fs::write(
        fixture.primary.join("app/package-lock.json"),
        "{\"lockfileVersion\":3}\n",
    )
    .unwrap_or_else(|error| panic!("write package lock: {error}"));
    fs::write(fixture.primary.join(".gitignore"), "app/node_modules/\n")
        .unwrap_or_else(|error| panic!("write gitignore: {error}"));
    git(
        &fixture.primary,
        &["add", ".gitignore", "app/package-lock.json"],
    );
    git(&fixture.primary, &["commit", "-qm", "offline node project"]);
}

fn materialized_offline_lease(fixture: &Fixture, registry: &ProjectRegistry) -> WorktreeLease {
    let lease = registry
        .prepare_worktree_lease(
            "repo.fixture",
            &fixture.worktrees,
            "plan.offline-deps",
            1,
            "task.offline-deps",
            "sha256:offline-dependency-contract",
        )
        .unwrap_or_else(|error| panic!("prepare offline dependency lease: {error}"));
    registry
        .materialize_worktree(&lease)
        .unwrap_or_else(|error| panic!("materialize offline dependency lease: {error}"));
    lease
}

const OFFLINE_LIMITS: OfflineDependencyLimits = OfflineDependencyLimits {
    max_entries: 128,
    max_bytes: 1024 * 1024,
};

#[test]
fn worktree_dirty_primary_is_byte_for_byte_protected_and_cleanup_is_owned() {
    let fixture = Fixture::new("dirty-primary");
    fs::write(fixture.primary.join("tracked.txt"), "staged\n")
        .unwrap_or_else(|error| panic!("write staged: {error}"));
    git(&fixture.primary, &["add", "tracked.txt"]);
    fs::write(fixture.primary.join("tracked.txt"), "staged\nunstaged\n")
        .unwrap_or_else(|error| panic!("write unstaged: {error}"));
    fs::write(fixture.primary.join("untracked.txt"), "user-owned\n")
        .unwrap_or_else(|error| panic!("write untracked: {error}"));

    let registry = fixture.registry();
    let before = registry
        .snapshot("repo.fixture")
        .unwrap_or_else(|error| panic!("snapshot before: {error}"));
    let primary_bytes = fs::read(fixture.primary.join("tracked.txt"))
        .unwrap_or_else(|error| panic!("read primary: {error}"));
    let lease = registry
        .prepare_worktree_lease(
            "repo.fixture",
            &fixture.worktrees,
            "plan.fixture",
            3,
            "task.fixture",
            "sha256:task-contract",
        )
        .unwrap_or_else(|error| panic!("prepare lease: {error}"));
    registry
        .materialize_worktree(&lease)
        .unwrap_or_else(|error| panic!("materialize: {error}"));

    assert_eq!(
        lease.worktree_path.parent(),
        Some(lease.controller_root.as_path())
    );
    assert!(
        !lease.worktree_path.starts_with(
            fixture
                .primary
                .canonicalize()
                .unwrap_or_else(|error| { panic!("canonical primary: {error}") })
        )
    );
    assert_eq!(
        git(&lease.worktree_path, &["rev-parse", "HEAD"]),
        lease.base_head
    );
    assert_eq!(
        git(&lease.worktree_path, &["rev-parse", "--abbrev-ref", "HEAD"]),
        "HEAD"
    );

    fs::write(lease.worktree_path.join("tracked.txt"), "controller\n")
        .unwrap_or_else(|error| panic!("write worktree: {error}"));
    fs::write(lease.worktree_path.join("created.txt"), "new\n")
        .unwrap_or_else(|error| panic!("write untracked worktree file: {error}"));
    let change_set = registry
        .capture_change_set(&lease)
        .unwrap_or_else(|error| panic!("capture changes: {error}"));
    assert!(change_set.diff_content.contains("tracked.txt"));
    assert_eq!(
        change_set.untracked_paths,
        vec![PathBuf::from("created.txt")]
    );

    let after = registry
        .snapshot("repo.fixture")
        .unwrap_or_else(|error| panic!("snapshot after: {error}"));
    assert_eq!(before, after);
    assert_eq!(
        primary_bytes,
        fs::read(fixture.primary.join("tracked.txt"))
            .unwrap_or_else(|error| panic!("read protected primary: {error}"))
    );
    assert_eq!(
        fs::read_to_string(fixture.primary.join("untracked.txt"))
            .unwrap_or_else(|error| panic!("read protected untracked: {error}")),
        "user-owned\n"
    );

    registry
        .release_worktree(&lease, &change_set)
        .unwrap_or_else(|error| panic!("release: {error}"));
    assert!(!lease.worktree_path.exists());
    assert!(fixture.primary.exists());
    assert_eq!(
        before,
        registry
            .snapshot("repo.fixture")
            .unwrap_or_else(|error| panic!("final primary snapshot: {error}"))
    );
}

#[test]
fn worktree_change_set_preserves_unmerged_conflict_evidence() {
    let fixture = Fixture::new("conflict");
    let registry = fixture.registry();
    let lease = registry
        .prepare_worktree_lease(
            "repo.fixture",
            &fixture.worktrees,
            "plan.fixture",
            1,
            "task.conflict",
            "sha256:conflict-contract",
        )
        .unwrap_or_else(|error| panic!("prepare lease: {error}"));
    registry
        .materialize_worktree(&lease)
        .unwrap_or_else(|error| panic!("materialize: {error}"));

    let base = git_input(
        &lease.worktree_path,
        &["hash-object", "-w", "--stdin"],
        "base\n",
    );
    let ours = git_input(
        &lease.worktree_path,
        &["hash-object", "-w", "--stdin"],
        "ours\n",
    );
    let theirs = git_input(
        &lease.worktree_path,
        &["hash-object", "-w", "--stdin"],
        "theirs\n",
    );
    git(
        &lease.worktree_path,
        &["update-index", "--force-remove", "tracked.txt"],
    );
    let index_info = format!(
        "100644 {base} 1\ttracked.txt\n100644 {ours} 2\ttracked.txt\n100644 {theirs} 3\ttracked.txt\n"
    );
    git_input(
        &lease.worktree_path,
        &["update-index", "--index-info"],
        &index_info,
    );
    let change_set = registry
        .capture_change_set(&lease)
        .unwrap_or_else(|error| panic!("capture conflict: {error}"));
    assert_eq!(
        change_set.unmerged_paths,
        vec![PathBuf::from("tracked.txt")]
    );
    assert_ne!(
        change_set.unmerged_digest,
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );

    registry
        .release_worktree(&lease, &change_set)
        .unwrap_or_else(|error| panic!("release conflict worktree: {error}"));
}

#[test]
#[allow(clippy::too_many_lines)]
fn worktree_checkout_rejects_filters_lfs_and_promisor_before_side_effects() {
    let fixture = Fixture::new("unsafe-checkout");
    let sentinel = fixture.base.join("filter-ran");
    fs::write(
        fixture.primary.join(".gitattributes"),
        "*.txt filter=evil\n",
    )
    .unwrap_or_else(|error| panic!("write attrs: {error}"));
    git(&fixture.primary, &["add", ".gitattributes"]);
    git(&fixture.primary, &["commit", "-qm", "attributes"]);
    git(
        &fixture.primary,
        &[
            "config",
            "filter.evil.smudge",
            &format!("touch {}", sentinel.display()),
        ],
    );
    git(
        &fixture.primary,
        &[
            "config",
            "filter.evil.clean",
            &format!("touch {}", sentinel.display()),
        ],
    );
    git(
        &fixture.primary,
        &[
            "config",
            "filter.evil.process",
            &format!("touch {}", sentinel.display()),
        ],
    );
    let registry = fixture.registry();
    let lease = registry
        .prepare_worktree_lease(
            "repo.fixture",
            &fixture.worktrees,
            "plan.fixture",
            1,
            "task.filters",
            "sha256:filter-contract",
        )
        .unwrap_or_else(|error| panic!("prepare filter lease: {error}"));
    assert!(matches!(
        registry.materialize_worktree(&lease),
        Err(RepoError::UnsafeGitConfiguration(_))
    ));
    assert!(!sentinel.exists());
    assert!(!lease.worktree_path.exists());

    git(
        &fixture.primary,
        &["config", "--unset", "filter.evil.smudge"],
    );
    git(
        &fixture.primary,
        &["config", "--unset", "filter.evil.clean"],
    );
    git(
        &fixture.primary,
        &["config", "--unset", "filter.evil.process"],
    );
    fs::write(
        fixture.primary.join(".gitattributes"),
        "*.txt filter=lfs diff=lfs merge=lfs -text\n",
    )
    .unwrap_or_else(|error| panic!("write LFS attrs: {error}"));
    git(&fixture.primary, &["add", ".gitattributes"]);
    git(&fixture.primary, &["commit", "-qm", "lfs attributes"]);
    let lfs = registry
        .prepare_worktree_lease(
            "repo.fixture",
            &fixture.worktrees,
            "plan.fixture",
            1,
            "task.lfs",
            "sha256:lfs-contract",
        )
        .unwrap_or_else(|error| panic!("prepare LFS lease: {error}"));
    assert!(matches!(
        registry.materialize_worktree(&lfs),
        Err(RepoError::UnsafeGitConfiguration(_))
    ));
    assert!(!lfs.worktree_path.exists());

    git(
        &fixture.primary,
        &["config", "remote.origin.promisor", "true"],
    );
    let promisor = registry
        .prepare_worktree_lease(
            "repo.fixture",
            &fixture.worktrees,
            "plan.fixture",
            1,
            "task.promisor",
            "sha256:promisor-contract",
        )
        .unwrap_or_else(|error| panic!("prepare promisor lease: {error}"));
    assert!(matches!(
        registry.materialize_worktree(&promisor),
        Err(RepoError::UnsafeGitConfiguration(_))
    ));
    assert!(!promisor.worktree_path.exists());
}

#[test]
fn worktree_production_git_ignores_path_shim_and_disables_checkout_hooks() {
    const CHILD: &str = "SOVEREIGN_REPO_PATH_SHIM_CHILD";
    const SENTINEL: &str = "SOVEREIGN_REPO_PATH_SHIM_SENTINEL";
    if std::env::var_os(CHILD).is_some() {
        let sentinel = PathBuf::from(
            std::env::var_os(SENTINEL).unwrap_or_else(|| panic!("child sentinel missing")),
        );
        let fixture = Fixture::new("path-shim-child");
        let hook_sentinel = fixture.base.join("hook-ran");
        let hook = fixture.primary.join(".git/hooks/post-checkout");
        fs::write(
            &hook,
            format!("#!/bin/sh\n: > '{}'\n", hook_sentinel.display()),
        )
        .unwrap_or_else(|error| panic!("write checkout hook: {error}"));
        fs::set_permissions(&hook, fs::Permissions::from_mode(0o755))
            .unwrap_or_else(|error| panic!("chmod checkout hook: {error}"));

        let registry = fixture.registry();
        let lease = registry
            .prepare_worktree_lease(
                "repo.fixture",
                &fixture.worktrees,
                "plan.fixture",
                1,
                "task.path-shim",
                "sha256:path-shim-contract",
            )
            .unwrap_or_else(|error| panic!("prepare child lease: {error}"));
        registry
            .materialize_worktree(&lease)
            .unwrap_or_else(|error| panic!("materialize under hostile PATH: {error}"));
        assert!(!sentinel.exists(), "PATH git shim executed");
        assert!(!hook_sentinel.exists(), "checkout hook executed");
        return;
    }

    let fixture = Fixture::new("path-shim-parent");
    let shim_dir = fixture.base.join("shim-bin");
    fs::create_dir_all(&shim_dir).unwrap_or_else(|error| panic!("create shim dir: {error}"));
    let sentinel = fixture.base.join("git-shim-ran");
    let shim = shim_dir.join("git");
    fs::write(
        &shim,
        "#!/bin/sh\n: > \"$SOVEREIGN_REPO_PATH_SHIM_SENTINEL\"\nexit 97\n",
    )
    .unwrap_or_else(|error| panic!("write git shim: {error}"));
    fs::set_permissions(&shim, fs::Permissions::from_mode(0o755))
        .unwrap_or_else(|error| panic!("chmod git shim: {error}"));
    let status = Command::new(
        std::env::current_exe().unwrap_or_else(|error| panic!("current test exe: {error}")),
    )
    .arg("--exact")
    .arg("worktree_production_git_ignores_path_shim_and_disables_checkout_hooks")
    .arg("--nocapture")
    .env(CHILD, "1")
    .env(SENTINEL, &sentinel)
    .env("PATH", &shim_dir)
    .status()
    .unwrap_or_else(|error| panic!("spawn PATH-shim child: {error}"));
    assert!(status.success(), "PATH-shim child failed: {status:?}");
    assert!(!sentinel.exists(), "hostile PATH shim was executed");
}

#[test]
fn worktree_checkout_rejects_local_execution_and_network_config_surfaces() {
    let cases = [
        ("credential.helper", "!false"),
        ("core.sshCommand", "/usr/bin/false"),
        ("alias.evil", "!false"),
        ("diff.external", "/usr/bin/false"),
        ("diff.evil.command", "/usr/bin/false"),
        ("diff.evil.textconv", "/usr/bin/false"),
        ("filter.evil.process", "/usr/bin/false"),
        ("core.fsmonitor", "/usr/bin/false"),
        ("core.hooksPath", "/tmp/sovereign-forbidden-hooks"),
        ("include.path", "/tmp/sovereign-forbidden-gitconfig"),
        ("remote.origin.promisor", "true"),
        ("remote.origin.partialclonefilter", "blob:none"),
        ("remote.origin.proxy", "http://127.0.0.1:9"),
        ("extensions.partialClone", "origin"),
        ("url.evil.insteadOf", "https://example.invalid/"),
        ("http.proxy", "http://127.0.0.1:9"),
        ("submodule.evil.update", "!false"),
    ];
    for (index, (key, value)) in cases.into_iter().enumerate() {
        let fixture = Fixture::new(&format!("unsafe-local-config-{index}"));
        git(&fixture.primary, &["config", key, value]);
        let registry = fixture.registry();
        let lease = registry
            .prepare_worktree_lease(
                "repo.fixture",
                &fixture.worktrees,
                "plan.fixture",
                1,
                "task.unsafe-config",
                "sha256:unsafe-config-contract",
            )
            .unwrap_or_else(|error| panic!("prepare unsafe config {key}: {error}"));
        assert!(
            matches!(
                registry.materialize_worktree(&lease),
                Err(RepoError::UnsafeGitConfiguration(_))
            ),
            "unsafe local Git config key was accepted: {key}"
        );
        assert!(!lease.worktree_path.exists());
    }
}

#[test]
fn worktree_release_fails_closed_if_change_set_or_lease_drifted() {
    let fixture = Fixture::new("release-drift");
    let registry = fixture.registry();
    let lease = registry
        .prepare_worktree_lease(
            "repo.fixture",
            &fixture.worktrees,
            "plan.fixture",
            4,
            "task.release",
            "sha256:release-contract",
        )
        .unwrap_or_else(|error| panic!("prepare lease: {error}"));
    registry
        .materialize_worktree(&lease)
        .unwrap_or_else(|error| panic!("materialize: {error}"));
    fs::write(lease.worktree_path.join("tracked.txt"), "first\n")
        .unwrap_or_else(|error| panic!("write first: {error}"));
    let change_set = registry
        .capture_change_set(&lease)
        .unwrap_or_else(|error| panic!("capture: {error}"));
    fs::write(lease.worktree_path.join("tracked.txt"), "second\n")
        .unwrap_or_else(|error| panic!("write drift: {error}"));
    assert!(matches!(
        registry.release_worktree(&lease, &change_set),
        Err(RepoError::InvalidWorktreeLease(_))
    ));
    assert!(lease.worktree_path.exists());
}

#[test]
fn worktree_validation_rejects_foreign_common_git_directory() {
    let fixture = Fixture::new("foreign-common-dir");
    let registry = fixture.registry();
    let lease = registry
        .prepare_worktree_lease(
            "repo.fixture",
            &fixture.worktrees,
            "plan.fixture",
            1,
            "task.foreign",
            "sha256:foreign-contract",
        )
        .unwrap_or_else(|error| panic!("prepare lease: {error}"));
    fs::create_dir_all(&lease.controller_root)
        .unwrap_or_else(|error| panic!("create controller root: {error}"));
    let source = fixture
        .primary
        .to_str()
        .unwrap_or_else(|| panic!("primary path must be UTF-8"));
    let destination = lease
        .worktree_path
        .to_str()
        .unwrap_or_else(|| panic!("worktree path must be UTF-8"));
    git(
        &lease.controller_root,
        &["clone", "-q", "--no-checkout", source, destination],
    );
    git(
        &lease.worktree_path,
        &["checkout", "-q", "--detach", &lease.base_head],
    );
    assert!(matches!(
        registry.validate_worktree_lease(&lease),
        Err(RepoError::InvalidWorktreeLease(message))
            if message.contains("common Git directory")
    ));
}

#[test]
fn worktree_lease_binds_canonical_controller_root_and_exact_derived_path() {
    let fixture = Fixture::new("lease-root-path-binding");
    let registry = fixture.registry();
    let lease = registry
        .prepare_worktree_lease(
            "repo.fixture",
            &fixture.worktrees,
            "plan.fixture",
            3,
            "task.bound",
            "sha256:bound-contract",
        )
        .unwrap_or_else(|error| panic!("prepare lease: {error}"));
    let canonical_base = fixture
        .base
        .canonicalize()
        .unwrap_or_else(|error| panic!("canonical fixture base: {error}"));
    assert_eq!(
        lease.controller_root,
        canonical_base.join("state").join("worktrees")
    );
    assert_eq!(
        lease.worktree_path,
        lease.controller_root.join(&lease.lease_id)
    );

    let mut root_tampered = lease.clone();
    root_tampered.controller_root = fixture.base.join("foreign-worktrees");
    assert!(matches!(
        registry.materialize_worktree(&root_tampered),
        Err(RepoError::InvalidWorktreeLease(_))
    ));

    let mut path_tampered = lease;
    path_tampered.worktree_path = path_tampered.controller_root.join("foreign-path");
    assert!(matches!(
        registry.materialize_worktree(&path_tampered),
        Err(RepoError::InvalidWorktreeLease(_))
    ));
}

#[test]
#[allow(clippy::too_many_lines)]
fn worktree_composition_preserves_binary_untracked_and_join_deduplicates_shared_ancestor() {
    let fixture = Fixture::new("composition-join");
    let registry = fixture.registry();
    let prepare = |task: &str| {
        registry
            .prepare_worktree_lease(
                "repo.fixture",
                &fixture.worktrees,
                "plan.fixture",
                1,
                task,
                &format!("sha256:{task}-contract"),
            )
            .unwrap_or_else(|error| panic!("prepare {task}: {error}"))
    };

    let t1 = prepare("T1");
    registry
        .materialize_worktree(&t1)
        .unwrap_or_else(|error| panic!("materialize T1: {error}"));
    let t1_baseline = registry
        .capture_worktree_baseline(&t1)
        .unwrap_or_else(|error| panic!("T1 baseline: {error}"));
    let binary = vec![0, 1, 2, 3, 255, 0, 9];
    let shared_untracked = vec![9, 0, 8, 7, 0, 6];
    fs::write(t1.worktree_path.join("tracked.txt"), &binary)
        .unwrap_or_else(|error| panic!("T1 binary write: {error}"));
    fs::write(t1.worktree_path.join("shared.bin"), &shared_untracked)
        .unwrap_or_else(|error| panic!("T1 untracked write: {error}"));
    let cs1 = registry
        .capture_change_set_from_baseline(&t1, &t1_baseline)
        .unwrap_or_else(|error| panic!("T1 changeset: {error}"));
    assert!(cs1.diff_content.contains("GIT binary patch"));
    assert_eq!(cs1.untracked_deltas.len(), 1);
    assert_eq!(
        cs1.untracked_deltas[0]
            .post
            .as_ref()
            .map(|file| file.content.as_slice()),
        Some(shared_untracked.as_slice())
    );

    let t2 = prepare("T2");
    registry
        .materialize_worktree(&t2)
        .unwrap_or_else(|error| panic!("materialize T2: {error}"));
    let t2_baseline = match registry
        .compose_change_sets(&t2, &[ChangeSetCompositionInput::current(cs1.clone())])
        .unwrap_or_else(|error| panic!("compose T1 into T2: {error}"))
    {
        ComposeChangeSetsOutcome::Ready(baseline) => baseline,
        ComposeChangeSetsOutcome::Conflict(conflict) => {
            panic!("unexpected T2 conflict: {conflict:?}")
        }
    };
    assert_eq!(
        fs::read(t2.worktree_path.join("tracked.txt"))
            .unwrap_or_else(|error| panic!("read T2 inherited binary: {error}")),
        binary
    );
    fs::write(t2.worktree_path.join("other.txt"), "branch-two\n")
        .unwrap_or_else(|error| panic!("T2 branch write: {error}"));
    let cs2 = registry
        .capture_change_set_from_baseline(&t2, &t2_baseline)
        .unwrap_or_else(|error| panic!("T2 changeset: {error}"));
    assert_eq!(cs2.changed_paths, vec![PathBuf::from("other.txt")]);
    assert!(!cs2.diff_content.contains("tracked.txt"));

    let t3 = prepare("T3");
    registry
        .materialize_worktree(&t3)
        .unwrap_or_else(|error| panic!("materialize T3: {error}"));
    let t3_baseline = match registry
        .compose_change_sets(&t3, &[ChangeSetCompositionInput::current(cs1.clone())])
        .unwrap_or_else(|error| panic!("compose T1 into T3: {error}"))
    {
        ComposeChangeSetsOutcome::Ready(baseline) => baseline,
        ComposeChangeSetsOutcome::Conflict(conflict) => {
            panic!("unexpected T3 conflict: {conflict:?}")
        }
    };
    let branch_three = vec![4, 0, 5, 0, 6];
    fs::write(t3.worktree_path.join("branch-three.bin"), &branch_three)
        .unwrap_or_else(|error| panic!("T3 branch write: {error}"));
    let cs3 = registry
        .capture_change_set_from_baseline(&t3, &t3_baseline)
        .unwrap_or_else(|error| panic!("T3 changeset: {error}"));
    assert_eq!(cs3.untracked_deltas.len(), 1);

    let t4 = prepare("T4");
    registry
        .materialize_worktree(&t4)
        .unwrap_or_else(|error| panic!("materialize T4: {error}"));
    let joined = match registry
        .compose_change_sets(
            &t4,
            &[
                ChangeSetCompositionInput::current(cs1.clone()),
                ChangeSetCompositionInput::current(cs2),
                ChangeSetCompositionInput::current(cs3),
            ],
        )
        .unwrap_or_else(|error| panic!("compose join: {error}"))
    {
        ComposeChangeSetsOutcome::Ready(baseline) => baseline,
        ComposeChangeSetsOutcome::Conflict(conflict) => {
            panic!("unexpected join conflict: {conflict:?}")
        }
    };
    assert_eq!(
        fs::read(t4.worktree_path.join("tracked.txt"))
            .unwrap_or_else(|error| panic!("read joined binary: {error}")),
        binary
    );
    assert_eq!(
        fs::read(t4.worktree_path.join("shared.bin"))
            .unwrap_or_else(|error| panic!("read joined shared untracked: {error}")),
        shared_untracked
    );
    assert_eq!(
        fs::read_to_string(t4.worktree_path.join("other.txt"))
            .unwrap_or_else(|error| panic!("read joined branch two: {error}")),
        "branch-two\n"
    );
    assert_eq!(
        fs::read(t4.worktree_path.join("branch-three.bin"))
            .unwrap_or_else(|error| panic!("read joined branch three: {error}")),
        branch_three
    );
    let empty = registry
        .capture_change_set_from_baseline(&t4, &joined)
        .unwrap_or_else(|error| panic!("joined local delta: {error}"));
    assert!(empty.diff_content.is_empty());
    assert!(empty.untracked_deltas.is_empty());
}

fn multi_repo_registry(repo_a: &Fixture, repo_b: &Fixture) -> ProjectRegistry {
    let mut registry = ProjectRegistry::new();
    registry
        .register("repo.a", &repo_a.primary)
        .unwrap_or_else(|error| panic!("register repo A: {error}"));
    registry
        .register("repo.b", &repo_b.primary)
        .unwrap_or_else(|error| panic!("register repo B: {error}"));
    registry
}

fn prepare_multi_repo_lease(
    registry: &ProjectRegistry,
    integration_root: &Path,
    repository_id: &str,
    task_id: &str,
) -> WorktreeLease {
    registry
        .prepare_worktree_lease(
            repository_id,
            integration_root,
            "plan.multi-repo",
            1,
            task_id,
            &format!("sha256:{task_id}-contract"),
        )
        .unwrap_or_else(|error| panic!("prepare {repository_id}/{task_id}: {error}"))
}

fn capture_multi_repo_change(
    registry: &ProjectRegistry,
    lease: &WorktreeLease,
    path: &str,
    value: &str,
    repository_label: &str,
) -> ChangeSet {
    let baseline = registry
        .capture_worktree_baseline(lease)
        .unwrap_or_else(|error| panic!("{repository_label} source baseline: {error}"));
    fs::write(lease.worktree_path.join(path), value)
        .unwrap_or_else(|error| panic!("write {repository_label} source: {error}"));
    registry
        .capture_change_set_from_baseline(lease, &baseline)
        .unwrap_or_else(|error| panic!("capture {repository_label} ChangeSet: {error}"))
}

fn assert_multi_repo_composed_files(target_a: &WorktreeLease, target_b: &WorktreeLease) {
    assert_eq!(
        fs::read_to_string(target_a.worktree_path.join("tracked.txt"))
            .unwrap_or_else(|error| panic!("read repo A composed tracked file: {error}")),
        "repo-a\n"
    );
    assert_eq!(
        fs::read_to_string(target_a.worktree_path.join("other.txt"))
            .unwrap_or_else(|error| panic!("read repo A untouched file: {error}")),
        "other\n"
    );
    assert_eq!(
        fs::read_to_string(target_b.worktree_path.join("tracked.txt"))
            .unwrap_or_else(|error| panic!("read repo B untouched file: {error}")),
        "base\n"
    );
    assert_eq!(
        fs::read_to_string(target_b.worktree_path.join("other.txt"))
            .unwrap_or_else(|error| panic!("read repo B composed file: {error}")),
        "repo-b\n"
    );
}

#[test]
fn worktree_multi_repo_leases_share_controller_root_without_cross_repo_composition() {
    let repo_a = Fixture::new("multi-repo-a");
    let repo_b = Fixture::new("multi-repo-b");
    let integration_root = repo_a.base.join("integration/worktrees");
    let registry = multi_repo_registry(&repo_a, &repo_b);

    let source_a = prepare_multi_repo_lease(&registry, &integration_root, "repo.a", "A-source");
    let source_b = prepare_multi_repo_lease(&registry, &integration_root, "repo.b", "B-source");
    assert_eq!(source_a.controller_root, source_b.controller_root);
    assert_eq!(
        source_a.worktree_path.parent(),
        source_b.worktree_path.parent()
    );
    assert_ne!(source_a.lease_id, source_b.lease_id);
    assert_ne!(source_a.worktree_path, source_b.worktree_path);
    registry
        .materialize_worktree(&source_a)
        .unwrap_or_else(|error| panic!("materialize repo A source: {error}"));
    registry
        .materialize_worktree(&source_b)
        .unwrap_or_else(|error| panic!("materialize repo B source: {error}"));
    assert!(source_a.worktree_path.exists());
    assert!(source_b.worktree_path.exists());

    let change_a =
        capture_multi_repo_change(&registry, &source_a, "tracked.txt", "repo-a\n", "repo A");
    let change_b =
        capture_multi_repo_change(&registry, &source_b, "other.txt", "repo-b\n", "repo B");

    let target_a = prepare_multi_repo_lease(&registry, &integration_root, "repo.a", "A-target");
    let target_b = prepare_multi_repo_lease(&registry, &integration_root, "repo.b", "B-target");
    registry
        .materialize_worktree(&target_a)
        .unwrap_or_else(|error| panic!("materialize repo A target: {error}"));
    registry
        .materialize_worktree(&target_b)
        .unwrap_or_else(|error| panic!("materialize repo B target: {error}"));

    assert!(matches!(
        registry.compose_change_sets(
            &target_b,
            &[ChangeSetCompositionInput::current(change_a.clone())]
        ),
        Err(RepoError::InvalidWorktreeLease(_))
    ));
    assert_eq!(
        fs::read_to_string(target_b.worktree_path.join("tracked.txt")).unwrap_or_else(
            |error| panic!("read repo B after rejected cross-repo compose: {error}")
        ),
        "base\n"
    );

    assert!(matches!(
        registry
            .compose_change_sets(&target_a, &[ChangeSetCompositionInput::current(change_a)])
            .unwrap_or_else(|error| panic!("compose repo A ChangeSet: {error}")),
        ComposeChangeSetsOutcome::Ready(_)
    ));
    assert!(matches!(
        registry
            .compose_change_sets(&target_b, &[ChangeSetCompositionInput::current(change_b)])
            .unwrap_or_else(|error| panic!("compose repo B ChangeSet: {error}")),
        ComposeChangeSetsOutcome::Ready(_)
    ));
    assert_multi_repo_composed_files(&target_a, &target_b);
}

#[test]
fn worktree_untracked_composition_replaces_hardlink_without_mutating_external_inode() {
    let fixture = Fixture::new("composition-hardlink");
    let registry = fixture.registry();
    let prepare = |task: &str| {
        registry
            .prepare_worktree_lease(
                "repo.fixture",
                &fixture.worktrees,
                "plan.fixture",
                1,
                task,
                &format!("sha256:{task}-contract"),
            )
            .unwrap_or_else(|error| panic!("prepare {task}: {error}"))
    };

    let source = prepare("hardlink-source");
    registry
        .materialize_worktree(&source)
        .unwrap_or_else(|error| panic!("materialize source: {error}"));
    let source_path = source.worktree_path.join("shared.bin");
    fs::write(&source_path, b"old-bytes\n")
        .unwrap_or_else(|error| panic!("write source preimage: {error}"));
    let baseline = registry
        .capture_worktree_baseline(&source)
        .unwrap_or_else(|error| panic!("source baseline: {error}"));
    fs::write(&source_path, b"new-bytes\n")
        .unwrap_or_else(|error| panic!("write source postimage: {error}"));
    let change_set = registry
        .capture_change_set_from_baseline(&source, &baseline)
        .unwrap_or_else(|error| panic!("capture hardlink changeset: {error}"));
    assert_eq!(change_set.untracked_deltas.len(), 1);
    assert!(change_set.untracked_deltas[0].pre_digest.is_some());

    let target = prepare("hardlink-target");
    registry
        .materialize_worktree(&target)
        .unwrap_or_else(|error| panic!("materialize target: {error}"));
    let external = fixture.base.join("external-hardlink.bin");
    fs::write(&external, b"old-bytes\n")
        .unwrap_or_else(|error| panic!("write external inode: {error}"));
    let target_path = target.worktree_path.join("shared.bin");
    fs::hard_link(&external, &target_path)
        .unwrap_or_else(|error| panic!("create hostile hardlink: {error}"));
    let external_before =
        fs::metadata(&external).unwrap_or_else(|error| panic!("external metadata: {error}"));
    let target_before =
        fs::metadata(&target_path).unwrap_or_else(|error| panic!("target metadata: {error}"));
    assert_eq!(external_before.ino(), target_before.ino());

    let outcome = registry
        .compose_change_sets(&target, &[ChangeSetCompositionInput::current(change_set)])
        .unwrap_or_else(|error| panic!("compose hardlink changeset: {error}"));
    assert!(matches!(outcome, ComposeChangeSetsOutcome::Ready(_)));
    assert_eq!(
        fs::read(&external).unwrap_or_else(|error| panic!("read external after compose: {error}")),
        b"old-bytes\n"
    );
    assert_eq!(
        fs::read(&target_path).unwrap_or_else(|error| panic!("read target after compose: {error}")),
        b"new-bytes\n"
    );
    assert_ne!(
        fs::metadata(&external)
            .unwrap_or_else(|error| panic!("external metadata after: {error}"))
            .ino(),
        fs::metadata(&target_path)
            .unwrap_or_else(|error| panic!("target metadata after: {error}"))
            .ino()
    );
}

#[test]
fn worktree_untracked_composition_rejects_symlink_parent_without_external_write() {
    let fixture = Fixture::new("composition-symlink-parent");
    let registry = fixture.registry();
    let prepare = |task: &str| {
        registry
            .prepare_worktree_lease(
                "repo.fixture",
                &fixture.worktrees,
                "plan.fixture",
                1,
                task,
                &format!("sha256:{task}-contract"),
            )
            .unwrap_or_else(|error| panic!("prepare {task}: {error}"))
    };

    let source = prepare("symlink-source");
    registry
        .materialize_worktree(&source)
        .unwrap_or_else(|error| panic!("materialize source: {error}"));
    let baseline = registry
        .capture_worktree_baseline(&source)
        .unwrap_or_else(|error| panic!("source baseline: {error}"));
    fs::create_dir_all(source.worktree_path.join("nested"))
        .unwrap_or_else(|error| panic!("create source nested: {error}"));
    fs::write(
        source.worktree_path.join("nested/payload.bin"),
        b"payload\n",
    )
    .unwrap_or_else(|error| panic!("write nested payload: {error}"));
    let change_set = registry
        .capture_change_set_from_baseline(&source, &baseline)
        .unwrap_or_else(|error| panic!("capture symlink changeset: {error}"));

    let target = prepare("symlink-target");
    registry
        .materialize_worktree(&target)
        .unwrap_or_else(|error| panic!("materialize target: {error}"));
    let external_dir = fixture.base.join("external-dir");
    fs::create_dir_all(&external_dir)
        .unwrap_or_else(|error| panic!("create external dir: {error}"));
    symlink(&external_dir, target.worktree_path.join("nested"))
        .unwrap_or_else(|error| panic!("create hostile parent symlink: {error}"));
    assert!(matches!(
        registry.compose_change_sets(&target, &[ChangeSetCompositionInput::current(change_set)]),
        Err(RepoError::SymlinkPath(_))
    ));
    assert!(!external_dir.join("payload.bin").exists());
}

#[test]
fn worktree_join_conflict_is_evidence_and_never_auto_resolved() {
    let fixture = Fixture::new("composition-conflict");
    let registry = fixture.registry();
    let prepare = |task: &str| {
        registry
            .prepare_worktree_lease(
                "repo.fixture",
                &fixture.worktrees,
                "plan.fixture",
                1,
                task,
                &format!("sha256:{task}-contract"),
            )
            .unwrap_or_else(|error| panic!("prepare {task}: {error}"))
    };
    let root = prepare("T1");
    registry
        .materialize_worktree(&root)
        .unwrap_or_else(|error| panic!("materialize root: {error}"));
    let root_baseline = registry
        .capture_worktree_baseline(&root)
        .unwrap_or_else(|error| panic!("root baseline: {error}"));
    fs::write(root.worktree_path.join("tracked.txt"), "root\n")
        .unwrap_or_else(|error| panic!("root write: {error}"));
    let root_cs = registry
        .capture_change_set_from_baseline(&root, &root_baseline)
        .unwrap_or_else(|error| panic!("root changeset: {error}"));

    let branch = |task: &str, value: &str| {
        let lease = prepare(task);
        registry
            .materialize_worktree(&lease)
            .unwrap_or_else(|error| panic!("materialize {task}: {error}"));
        let baseline = match registry
            .compose_change_sets(
                &lease,
                &[ChangeSetCompositionInput::current(root_cs.clone())],
            )
            .unwrap_or_else(|error| panic!("compose root into {task}: {error}"))
        {
            ComposeChangeSetsOutcome::Ready(baseline) => baseline,
            ComposeChangeSetsOutcome::Conflict(conflict) => {
                panic!("unexpected branch conflict: {conflict:?}")
            }
        };
        fs::write(lease.worktree_path.join("tracked.txt"), value)
            .unwrap_or_else(|error| panic!("branch write {task}: {error}"));
        registry
            .capture_change_set_from_baseline(&lease, &baseline)
            .unwrap_or_else(|error| panic!("branch changeset {task}: {error}"))
    };
    let left = branch("T2", "left\n");
    let right = branch("T3", "right\n");
    let join = prepare("T4");
    registry
        .materialize_worktree(&join)
        .unwrap_or_else(|error| panic!("materialize join: {error}"));
    let conflict = match registry
        .compose_change_sets(
            &join,
            &[
                ChangeSetCompositionInput::current(root_cs),
                ChangeSetCompositionInput::current(left),
                ChangeSetCompositionInput::current(right),
            ],
        )
        .unwrap_or_else(|error| panic!("compose conflicting join: {error}"))
    {
        ComposeChangeSetsOutcome::Conflict(conflict) => conflict,
        ComposeChangeSetsOutcome::Ready(_) => panic!("conflicting join unexpectedly composed"),
    };
    assert_eq!(conflict.incoming_task_id, "T3");
    assert!(
        conflict
            .conflict_paths
            .contains(&PathBuf::from("tracked.txt"))
    );
    assert_eq!(
        fs::read_to_string(join.worktree_path.join("tracked.txt"))
            .unwrap_or_else(|error| panic!("read unresolved join: {error}")),
        "left\n",
        "failed incoming branch must not be auto-resolved or partially applied"
    );
}

#[test]
fn offline_node_modules_materialization_is_bounded_hashed_and_primary_preserving() {
    let fixture = Fixture::new("offline-node-modules-success");
    configure_offline_node_project(&fixture);
    let source = fixture.primary.join("app/node_modules");
    fs::create_dir_all(source.join("pkg"))
        .unwrap_or_else(|error| panic!("create source package: {error}"));
    fs::write(source.join("pkg/index.js"), "module.exports = 42;\n")
        .unwrap_or_else(|error| panic!("write source package: {error}"));
    symlink("pkg/index.js", source.join("alias.js"))
        .unwrap_or_else(|error| panic!("create internal dependency symlink: {error}"));
    let primary_before = fs::read(source.join("pkg/index.js"))
        .unwrap_or_else(|error| panic!("read primary dependency before: {error}"));

    let registry = fixture.registry();
    let lease = materialized_offline_lease(&fixture, &registry);
    let provenance = registry
        .materialize_existing_node_modules(&lease, Path::new("app"), OFFLINE_LIMITS)
        .unwrap_or_else(|error| panic!("materialize offline node_modules: {error}"));

    assert_eq!(provenance.repository_id, "repo.fixture");
    assert_eq!(provenance.plan_id, "plan.offline-deps");
    assert_eq!(provenance.task_id, "task.offline-deps");
    assert_eq!(provenance.worktree_lease_id, lease.lease_id);
    assert_eq!(provenance.project_root, PathBuf::from("app"));
    assert_eq!(provenance.source_manifest, provenance.destination_manifest);
    registry
        .validate_existing_node_modules_provenance(&lease, &provenance, OFFLINE_LIMITS)
        .unwrap_or_else(|error| panic!("verify materialized dependency receipt: {error}"));
    assert_eq!(provenance.source_manifest.regular_file_count, 1);
    assert_eq!(provenance.source_manifest.symlink_count, 1);
    assert_eq!(provenance.source_manifest.directory_count, 1);
    assert_eq!(provenance.source_manifest.entry_count, 3);
    assert!(provenance.ignore_evidence_digest.starts_with("sha256:"));
    assert_eq!(
        fs::read(lease.worktree_path.join("app/node_modules/pkg/index.js"))
            .unwrap_or_else(|error| panic!("read materialized dependency: {error}")),
        primary_before
    );
    assert_eq!(
        fs::read_link(lease.worktree_path.join("app/node_modules/alias.js"))
            .unwrap_or_else(|error| panic!("read materialized symlink: {error}")),
        PathBuf::from("pkg/index.js")
    );
    assert_eq!(
        fs::read(source.join("pkg/index.js"))
            .unwrap_or_else(|error| panic!("read primary dependency after: {error}")),
        primary_before,
        "offline materialization must not mutate the primary dependency tree"
    );
    assert!(
        registry
            .worktree_snapshot(&lease)
            .unwrap_or_else(|error| panic!("snapshot worktree after materialization: {error}"))
            .untracked
            .paths
            .iter()
            .all(|path| !path.starts_with("app/node_modules")),
        "Git-ignored runtime dependencies must stay outside repository change evidence"
    );
}

#[test]
fn offline_node_modules_receipt_validation_detects_tree_and_identity_drift() {
    let fixture = Fixture::new("offline-node-modules-receipt-drift");
    configure_offline_node_project(&fixture);
    let source = fixture.primary.join("app/node_modules/pkg/index.js");
    fs::create_dir_all(source.parent().unwrap_or_else(|| panic!("package parent")))
        .unwrap_or_else(|error| panic!("create source: {error}"));
    fs::write(&source, "original\n").unwrap_or_else(|error| panic!("write source: {error}"));
    let registry = fixture.registry();
    let lease = materialized_offline_lease(&fixture, &registry);
    let receipt = registry
        .materialize_existing_node_modules(&lease, Path::new("app"), OFFLINE_LIMITS)
        .unwrap_or_else(|error| panic!("copy ignored dependencies: {error}"));
    let mut misbound = receipt.clone();
    misbound.worktree_lease_id = "worktree.unrelated".to_owned();
    assert!(
        registry
            .validate_existing_node_modules_provenance(&lease, &misbound, OFFLINE_LIMITS)
            .is_err()
    );
    let destination = lease.worktree_path.join("app/node_modules/pkg/index.js");
    fs::write(&destination, "destination drift\n")
        .unwrap_or_else(|error| panic!("drift destination: {error}"));
    assert!(
        registry
            .validate_existing_node_modules_provenance(&lease, &receipt, OFFLINE_LIMITS)
            .is_err()
    );
    fs::write(&destination, "original\n")
        .unwrap_or_else(|error| panic!("restore destination: {error}"));
    fs::write(&source, "source drift\n").unwrap_or_else(|error| panic!("drift source: {error}"));
    assert!(
        registry
            .validate_existing_node_modules_provenance(&lease, &receipt, OFFLINE_LIMITS)
            .is_err()
    );
    fs::write(&source, "original\n").unwrap_or_else(|error| panic!("restore source: {error}"));
    fs::write(fixture.primary.join(".gitignore"), "")
        .unwrap_or_else(|error| panic!("remove ignore rule: {error}"));
    assert!(
        registry
            .validate_existing_node_modules_provenance(&lease, &receipt, OFFLINE_LIMITS)
            .is_err()
    );
}

#[test]
fn offline_node_modules_materialization_rejects_nonignored_or_existing_destination() {
    let nonignored = Fixture::new("offline-node-modules-nonignored");
    fs::create_dir_all(nonignored.primary.join("app/node_modules/pkg"))
        .unwrap_or_else(|error| panic!("create nonignored dependency: {error}"));
    fs::write(nonignored.primary.join("app/package-lock.json"), "{}\n")
        .unwrap_or_else(|error| panic!("write package lock: {error}"));
    fs::write(
        nonignored.primary.join("app/node_modules/pkg/index.js"),
        "export {};\n",
    )
    .unwrap_or_else(|error| panic!("write nonignored dependency: {error}"));
    git(&nonignored.primary, &["add", "app/package-lock.json"]);
    git(&nonignored.primary, &["commit", "-qm", "app root"]);
    let registry = nonignored.registry();
    let lease = materialized_offline_lease(&nonignored, &registry);
    assert!(matches!(
        registry.materialize_existing_node_modules(&lease, Path::new("app"), OFFLINE_LIMITS),
        Err(RepoError::InvalidOfflineDependency(_))
    ));
    assert!(!lease.worktree_path.join("app/node_modules").exists());

    let existing = Fixture::new("offline-node-modules-existing-destination");
    configure_offline_node_project(&existing);
    fs::create_dir_all(existing.primary.join("app/node_modules/pkg"))
        .unwrap_or_else(|error| panic!("create ignored source: {error}"));
    fs::write(
        existing.primary.join("app/node_modules/pkg/index.js"),
        "export {};\n",
    )
    .unwrap_or_else(|error| panic!("write ignored source: {error}"));
    let registry = existing.registry();
    let lease = materialized_offline_lease(&existing, &registry);
    fs::create_dir(lease.worktree_path.join("app/node_modules"))
        .unwrap_or_else(|error| panic!("create preexisting destination: {error}"));
    assert!(matches!(
        registry.materialize_existing_node_modules(&lease, Path::new("app"), OFFLINE_LIMITS),
        Err(RepoError::InvalidOfflineDependency(_))
    ));
}

#[test]
fn offline_node_modules_materialization_enforces_entry_and_byte_ceilings() {
    let fixture = Fixture::new("offline-node-modules-limits");
    configure_offline_node_project(&fixture);
    let source = fixture.primary.join("app/node_modules");
    fs::create_dir_all(source.join("pkg"))
        .unwrap_or_else(|error| panic!("create package: {error}"));
    fs::write(source.join("pkg/a.js"), "1234567890")
        .unwrap_or_else(|error| panic!("write first package file: {error}"));
    fs::write(source.join("pkg/b.js"), "abcdefghij")
        .unwrap_or_else(|error| panic!("write second package file: {error}"));
    let registry = fixture.registry();
    let lease = materialized_offline_lease(&fixture, &registry);

    assert!(matches!(
        registry.materialize_existing_node_modules(
            &lease,
            Path::new("app"),
            OfflineDependencyLimits {
                max_entries: 2,
                max_bytes: 1024,
            },
        ),
        Err(RepoError::InvalidOfflineDependency(_))
    ));
    assert!(!lease.worktree_path.join("app/node_modules").exists());
    assert!(matches!(
        registry.materialize_existing_node_modules(
            &lease,
            Path::new("app"),
            OfflineDependencyLimits {
                max_entries: 16,
                max_bytes: 5,
            },
        ),
        Err(RepoError::InvalidOfflineDependency(_))
    ));
    assert!(!lease.worktree_path.join("app/node_modules").exists());
}

#[test]
fn offline_node_modules_materialization_rejects_external_symlink_and_special_file() {
    let symlink_fixture = Fixture::new("offline-node-modules-external-symlink");
    configure_offline_node_project(&symlink_fixture);
    let source = symlink_fixture.primary.join("app/node_modules");
    fs::create_dir_all(&source).unwrap_or_else(|error| panic!("create source: {error}"));
    fs::write(symlink_fixture.primary.join("outside.js"), "outside\n")
        .unwrap_or_else(|error| panic!("write outside target: {error}"));
    symlink("../../outside.js", source.join("escape.js"))
        .unwrap_or_else(|error| panic!("create external symlink: {error}"));
    let registry = symlink_fixture.registry();
    let lease = materialized_offline_lease(&symlink_fixture, &registry);
    assert!(matches!(
        registry.materialize_existing_node_modules(&lease, Path::new("app"), OFFLINE_LIMITS),
        Err(RepoError::InvalidOfflineDependency(_))
    ));
    assert!(!lease.worktree_path.join("app/node_modules").exists());

    let special_fixture = Fixture::new("offline-node-modules-special-file");
    configure_offline_node_project(&special_fixture);
    let source = special_fixture.primary.join("app/node_modules");
    fs::create_dir_all(&source).unwrap_or_else(|error| panic!("create source: {error}"));
    let fifo = source.join("runtime.fifo");
    let output = Command::new("/usr/bin/mkfifo")
        .arg(&fifo)
        .output()
        .unwrap_or_else(|error| panic!("create FIFO dependency entry: {error}"));
    assert!(
        output.status.success(),
        "mkfifo failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let registry = special_fixture.registry();
    let lease = materialized_offline_lease(&special_fixture, &registry);
    assert!(matches!(
        registry.materialize_existing_node_modules(&lease, Path::new("app"), OFFLINE_LIMITS),
        Err(RepoError::InvalidOfflineDependency(_))
    ));
    assert!(!lease.worktree_path.join("app/node_modules").exists());
}

#[test]
fn offline_node_modules_materialization_rejects_tracked_source_tree() {
    let fixture = Fixture::new("offline-node-modules-tracked");
    configure_offline_node_project(&fixture);
    fs::create_dir_all(fixture.primary.join("app/node_modules/pkg"))
        .unwrap_or_else(|error| panic!("create tracked dependency: {error}"));
    fs::write(
        fixture.primary.join("app/node_modules/pkg/index.js"),
        "tracked\n",
    )
    .unwrap_or_else(|error| panic!("write tracked dependency: {error}"));
    git(
        &fixture.primary,
        &["add", "-f", "app/node_modules/pkg/index.js"],
    );
    git(&fixture.primary, &["commit", "-qm", "tracked dependency"]);
    let registry = fixture.registry();
    let lease = materialized_offline_lease(&fixture, &registry);
    assert!(
        lease
            .worktree_path
            .join("app/node_modules/pkg/index.js")
            .exists()
    );
    assert!(matches!(
        registry.materialize_existing_node_modules(&lease, Path::new("app"), OFFLINE_LIMITS),
        Err(RepoError::InvalidOfflineDependency(_))
    ));
}
