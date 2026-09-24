use sovereign_evidence::ArtifactStore;
use sovereign_policy::{
    CommandMode, CommandPolicy, CommandRisk, CommandSpec, ControllerSecretLocator,
    ExecutionIsolationBackend, FakeSecretProvider, IsolatedCommand, IsolationCapabilities,
    IsolationRequest, MacSandboxExecBackend, PathPolicy, PinnedExecutable, PolicyError,
    SecretBroker, SecretInjection, SecretProviderKind, SecretRef, SecretScope,
};
use sovereign_state::StateStore;
use sovereign_tools::{
    ACTION_RECEIPT_SCHEMA_VERSION, APPROVAL_CLAIM_NAMESPACE, ActionJournal, ActionReceipt,
    ActionState, ApprovalClaim, AtomicCreateGuard, AtomicReplaceGuard, AtomicUpdateGuard,
    AuthorizedAction, AuthorizedRepositoryMutation, CapabilityLayers, CapabilitySet,
    JournalActionAuthority, PermissionClass, PermissionDecision, ProcessCancellationToken,
    ProcessRunner, RawToolResult, Reconciliation, ReconciliationMode, ReconciliationPolicy,
    RepositoryMutationKind, RepositoryMutationPrecondition, ResourceLimitKind, SecretCleanupProof,
    ToolManifest, ToolSchemaV1, filter_authorized_tool_schemas, process_group_leader_identity,
    reap_owned_process_group,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct TestDir(PathBuf);

impl TestDir {
    fn under(base: &Path, label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let path = base.join(format!(
            "sovereign-tools-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap_or_else(|error| panic!("create test dir: {error}"));
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn now_ms() -> i64 {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|error| panic!("clock: {error}"));
    i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
}

fn shell_policy() -> CommandPolicy {
    let shell = PinnedExecutable::from_path("/bin/sh", "macos-system")
        .unwrap_or_else(|error| panic!("pin shell: {error}"));
    let root = shell
        .path
        .parent()
        .unwrap_or_else(|| panic!("shell parent"))
        .to_path_buf();
    let mut policy = CommandPolicy::new([shell], [root])
        .unwrap_or_else(|error| panic!("command policy: {error}"));
    policy.allow_shell = true;
    policy
}

fn test_digest(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

fn manifest() -> ToolManifest {
    ToolManifest {
        tool_id: "tool_shell".to_owned(),
        version: "1".to_owned(),
        content_digest: test_digest('1'),
        permission_ceiling: BTreeSet::from([
            PermissionClass::ProcessExec,
            PermissionClass::RepositoryWrite,
        ]),
        declared_risk_floor: CommandRisk::Shell,
        reconciliation_policy: ReconciliationPolicy::idempotent_local(),
    }
}

#[derive(Debug, Clone, Copy)]
struct Limits {
    timeout_ms: u64,
    output_bytes: u64,
    disk_bytes: u64,
    subprocesses: u32,
}

fn shell_action(
    id: &str,
    repo: &Path,
    script: &str,
    limits: Limits,
    mode: ReconciliationMode,
) -> AuthorizedAction {
    let executable = PinnedExecutable::from_path("/bin/sh", "macos-system")
        .unwrap_or_else(|error| panic!("pin shell action: {error}"));
    let mut action = AuthorizedAction {
        action_id: id.to_owned(),
        plan_id: "plan_m1".to_owned(),
        plan_revision: 1,
        task_id: "task_t04".to_owned(),
        attempt_id: format!("attempt-{id}"),
        tool_id: "tool_shell".to_owned(),
        tool_version: "1".to_owned(),
        tool_digest: test_digest('1'),
        executable_digest: executable.sha256,
        repository_id: "repo_fixture".to_owned(),
        destination_digest: None,
        permission_class: PermissionClass::ProcessExec,
        execution_epoch: 0,
        policy_digest: test_digest('2'),
        permission_decision_digest: "sha256:pending-decision".to_owned(),
        isolation_policy_digest: "sha256:pending-isolation".to_owned(),
        nonce: format!("nonce-{id}"),
        expires_at_ms: now_ms() + 60_000,
        command: CommandSpec {
            executable: PathBuf::from("/bin/sh"),
            args: vec!["-c".to_owned(), script.to_owned()],
            working_directory: repo.to_path_buf(),
            environment: BTreeMap::new(),
            mode: CommandMode::Shell,
            declared_risk: CommandRisk::Shell,
            timeout_ms: limits.timeout_ms,
            output_limit_bytes: limits.output_bytes,
            disk_write_limit_bytes: limits.disk_bytes,
            subprocess_limit: limits.subprocesses,
        },
        individually_authorized_environment: BTreeSet::new(),
        approval_required: false,
        reconciliation_mode: mode,
    };
    action.permission_decision_digest = permission_decision(&action).digest();
    action
}

fn permission_decision(action: &AuthorizedAction) -> PermissionDecision {
    PermissionDecision::new(
        action.plan_id.clone(),
        action.plan_revision,
        action.task_id.clone(),
        test_digest('3'),
        action.policy_digest.clone(),
        action.tool_id.clone(),
        action.tool_version.clone(),
        action.tool_digest.clone(),
        CapabilityLayers {
            global: CapabilitySet::all(),
            project: CapabilitySet::all(),
            task: CapabilitySet::all(),
            role: CapabilitySet::all(),
            tool: CapabilitySet::all(),
            user: CapabilitySet::all(),
        },
    )
    .unwrap_or_else(|error| panic!("permission decision: {error}"))
}

fn authorize(
    journal: &mut ActionJournal<'_>,
    action: &AuthorizedAction,
    tool_manifest: &ToolManifest,
) -> Result<i64, sovereign_tools::ToolError> {
    journal.authorize(action, tool_manifest, &permission_decision(action))
}

fn repository_manifest() -> ToolManifest {
    ToolManifest {
        tool_id: "tool_repo".to_owned(),
        version: "1".to_owned(),
        content_digest: test_digest('4'),
        permission_ceiling: BTreeSet::from([PermissionClass::RepositoryWrite]),
        declared_risk_floor: CommandRisk::RepositoryMutation,
        reconciliation_policy: ReconciliationPolicy::proof_required_local(),
    }
}

fn repository_mutation(id: &str, path: &str) -> AuthorizedRepositoryMutation {
    let mut action = AuthorizedRepositoryMutation {
        action_id: id.to_owned(),
        plan_id: "plan_m1".to_owned(),
        plan_revision: 1,
        task_id: "task_t04".to_owned(),
        attempt_id: format!("attempt-{id}"),
        tool_id: "tool_repo".to_owned(),
        tool_version: "1".to_owned(),
        tool_digest: test_digest('4'),
        repository_id: "repo_fixture".to_owned(),
        relative_path: PathBuf::from(path),
        kind: RepositoryMutationKind::Create,
        precondition: RepositoryMutationPrecondition::Absent,
        expected_post_digest: test_digest('5'),
        expected_target_mode: 0o644,
        execution_epoch: 0,
        policy_digest: test_digest('2'),
        permission_decision_digest: "sha256:pending-decision".to_owned(),
        isolation_policy_digest: test_digest('6'),
        nonce: format!("nonce-{id}"),
        expires_at_ms: now_ms() + 60_000,
        action_deadline_ms: 5_000,
        disk_write_bytes: 1_024,
    };
    action.permission_decision_digest = repository_permission_decision(&action).digest();
    action
}

fn repository_permission_decision(action: &AuthorizedRepositoryMutation) -> PermissionDecision {
    PermissionDecision::new(
        action.plan_id.clone(),
        action.plan_revision,
        action.task_id.clone(),
        test_digest('3'),
        action.policy_digest.clone(),
        action.tool_id.clone(),
        action.tool_version.clone(),
        action.tool_digest.clone(),
        CapabilityLayers {
            global: CapabilitySet::all(),
            project: CapabilitySet::all(),
            task: CapabilitySet::new([PermissionClass::RepositoryWrite]),
            role: CapabilitySet::all(),
            tool: CapabilitySet::new([PermissionClass::RepositoryWrite]),
            user: CapabilitySet::all(),
        },
    )
    .unwrap_or_else(|error| panic!("repository permission decision: {error}"))
}

fn approval_claim(action: &AuthorizedAction, issued_at_ms: i64) -> ApprovalClaim {
    ApprovalClaim {
        schema_version: 1,
        claim_id: format!("claim.{}", action.action_id),
        action_id: action.action_id.clone(),
        plan_id: action.plan_id.clone(),
        plan_revision: action.plan_revision,
        task_id: action.task_id.clone(),
        permission_class: action.permission_class.as_plan_ir_str().to_owned(),
        payload_digest: action.payload_digest(),
        destination_digest: action.destination_digest.clone(),
        executable_digest: action.executable_digest.clone(),
        policy_digest: action.policy_digest.clone(),
        execution_epoch: action.execution_epoch,
        nonce: action.nonce.clone(),
        issued_by: "user:test-approver".to_owned(),
        issued_at_ms,
        expires_at_ms: action.expires_at_ms.min(issued_at_ms + 30_000),
    }
}

fn fixture(label: &str) -> (TestDir, PathBuf, PathBuf, StateStore) {
    let home = std::env::var_os("HOME").map_or_else(|| panic!("HOME"), PathBuf::from);
    let temp = TestDir::under(&home, label);
    let repo = temp.0.join("repo");
    fs::create_dir_all(&repo).unwrap_or_else(|error| panic!("repo: {error}"));
    let db = temp.0.join("state.sqlite3");
    let store = StateStore::open(db).unwrap_or_else(|error| panic!("state: {error}"));
    (temp, repo, home, store)
}

fn artifacts(temp: &TestDir) -> ArtifactStore {
    ArtifactStore::open(temp.0.join("cas")).unwrap_or_else(|error| panic!("artifacts: {error}"))
}

fn assert_tree_excludes_bytes(root: &Path, needle: &[u8]) {
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        let Ok(entries) = fs::read_dir(&path) else {
            continue;
        };
        for entry in entries.flatten() {
            let entry_path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir() {
                stack.push(entry_path);
            } else if file_type.is_file() {
                let bytes = fs::read(&entry_path)
                    .unwrap_or_else(|error| panic!("read {}: {error}", entry_path.display()));
                assert!(
                    !bytes.windows(needle.len()).any(|window| window == needle),
                    "secret bytes persisted in {}",
                    entry_path.display()
                );
            }
        }
    }
}

fn isolation(repo: &Path, home: &Path, allow_repository_write: bool) -> IsolationRequest {
    IsolationRequest {
        repository_root: repo.to_path_buf(),
        user_home_root: home.to_path_buf(),
        extra_protected_read_roots: Vec::new(),
        rust_toolchain: None,
        build_scratch_root: None,
        network_offline: true,
        allow_repository_write,
        require_full_filesystem_read_jail: false,
    }
}

fn bind_isolation(action: &mut AuthorizedAction, request: &IsolationRequest) {
    action.isolation_policy_digest = request
        .digest()
        .unwrap_or_else(|error| panic!("isolation digest: {error}"));
}

#[test]
fn atomic_replace_does_not_mutate_external_hard_link_inode() {
    let temp = TestDir::under(&std::env::temp_dir(), "atomic-hardlink");
    let repo = temp.0.join("repo");
    let outside = temp.0.join("outside.txt");
    fs::create_dir_all(&repo).unwrap_or_else(|error| panic!("repo: {error}"));
    fs::write(&outside, b"outside-original").unwrap_or_else(|error| panic!("outside: {error}"));
    fs::hard_link(&outside, repo.join("target.txt"))
        .unwrap_or_else(|error| panic!("hard link: {error}"));

    let guard = AtomicReplaceGuard::prepare(&repo, "target.txt")
        .unwrap_or_else(|error| panic!("prepare: {error}"));
    guard
        .commit(b"repository-replacement", 0o644)
        .unwrap_or_else(|error| panic!("commit: {error}"));

    assert_eq!(fs::read(&outside).unwrap_or_default(), b"outside-original");
    assert_eq!(
        fs::read(repo.join("target.txt")).unwrap_or_default(),
        b"repository-replacement"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let outside_meta = fs::metadata(&outside).unwrap_or_else(|error| panic!("meta: {error}"));
        let target_meta = fs::metadata(repo.join("target.txt"))
            .unwrap_or_else(|error| panic!("target meta: {error}"));
        assert_ne!(outside_meta.ino(), target_meta.ino());
    }
}

#[test]
fn atomic_create_is_no_clobber_if_target_appears_after_prepare() {
    let temp = TestDir::under(&std::env::temp_dir(), "atomic-create-race");
    let repo = temp.0.join("repo");
    fs::create_dir_all(&repo).unwrap_or_else(|error| panic!("repo: {error}"));
    let policy = PathPolicy::new(&repo, std::iter::empty::<PathBuf>())
        .unwrap_or_else(|error| panic!("policy: {error}"));
    let guard = AtomicCreateGuard::prepare(&policy, "created.txt")
        .unwrap_or_else(|error| panic!("prepare create: {error}"));

    fs::write(repo.join("created.txt"), b"racing-writer")
        .unwrap_or_else(|error| panic!("race target: {error}"));
    let Err(error) = guard.commit(b"must-not-clobber", 0o644) else {
        panic!("appeared target must fail create commit");
    };

    assert!(error.to_string().contains("target"));
    assert_eq!(
        fs::read(repo.join("created.txt")).unwrap_or_default(),
        b"racing-writer"
    );
}

#[test]
fn atomic_create_concurrent_publish_allows_exactly_one_writer() {
    let temp = TestDir::under(&std::env::temp_dir(), "atomic-create-concurrent");
    let repo = temp.0.join("repo");
    fs::create_dir_all(&repo).unwrap_or_else(|error| panic!("repo: {error}"));
    let policy = PathPolicy::new(&repo, std::iter::empty::<PathBuf>())
        .unwrap_or_else(|error| panic!("policy: {error}"));
    let left = AtomicCreateGuard::prepare(&policy, "created.txt")
        .unwrap_or_else(|error| panic!("left prepare: {error}"));
    let right = AtomicCreateGuard::prepare(&policy, "created.txt")
        .unwrap_or_else(|error| panic!("right prepare: {error}"));
    let barrier = Arc::new(Barrier::new(3));
    let left_barrier = Arc::clone(&barrier);
    let right_barrier = Arc::clone(&barrier);
    let left_thread = thread::spawn(move || {
        left_barrier.wait();
        left.commit(b"left-writer", 0o644)
    });
    let right_thread = thread::spawn(move || {
        right_barrier.wait();
        right.commit(b"right-writer", 0o644)
    });
    barrier.wait();
    let left_result = left_thread.join().unwrap_or_else(|_| panic!("left thread"));
    let right_result = right_thread
        .join()
        .unwrap_or_else(|_| panic!("right thread"));

    assert_ne!(left_result.is_ok(), right_result.is_ok());
    let bytes = fs::read(repo.join("created.txt")).unwrap_or_default();
    assert!(bytes == b"left-writer" || bytes == b"right-writer");
}

#[cfg(unix)]
#[test]
fn atomic_create_rejects_symlink_parent_and_target_at_prepare() {
    let temp = TestDir::under(&std::env::temp_dir(), "atomic-create-symlinks");
    let repo = temp.0.join("repo");
    let real_dir = repo.join("real");
    fs::create_dir_all(&real_dir).unwrap_or_else(|error| panic!("real dir: {error}"));
    std::os::unix::fs::symlink(&real_dir, repo.join("linked"))
        .unwrap_or_else(|error| panic!("parent symlink: {error}"));
    fs::write(real_dir.join("real-target.txt"), b"existing")
        .unwrap_or_else(|error| panic!("real target: {error}"));
    std::os::unix::fs::symlink(
        real_dir.join("real-target.txt"),
        repo.join("target-link.txt"),
    )
    .unwrap_or_else(|error| panic!("target symlink: {error}"));
    let policy = PathPolicy::new(&repo, std::iter::empty::<PathBuf>())
        .unwrap_or_else(|error| panic!("policy: {error}"));

    assert!(AtomicCreateGuard::prepare(&policy, "linked/new.txt").is_err());
    assert!(AtomicCreateGuard::prepare(&policy, "target-link.txt").is_err());
}

#[test]
fn atomic_create_respects_supplied_path_policy_and_never_invents_scope() {
    let temp = TestDir::under(&std::env::temp_dir(), "atomic-create-policy");
    let repo = temp.0.join("repo");
    fs::create_dir_all(repo.join("protected")).unwrap_or_else(|error| panic!("protected: {error}"));
    let policy = PathPolicy::new(&repo, [repo.join("protected")])
        .unwrap_or_else(|error| panic!("policy: {error}"));

    assert!(AtomicCreateGuard::prepare(&policy, "../escape.txt").is_err());
    assert!(AtomicCreateGuard::prepare(&policy, "protected/new.txt").is_err());

    let guard = AtomicCreateGuard::prepare(&policy, "allowed.txt")
        .unwrap_or_else(|error| panic!("allowed prepare: {error}"));
    guard
        .commit(b"created", 0o640)
        .unwrap_or_else(|error| panic!("allowed commit: {error}"));
    assert_eq!(
        fs::read(repo.join("allowed.txt")).unwrap_or_default(),
        b"created"
    );
}

#[test]
fn atomic_update_rejects_stale_preimage_without_overwriting_it() {
    let temp = TestDir::under(&std::env::temp_dir(), "atomic-update-stale");
    let repo = temp.0.join("repo");
    fs::create_dir_all(&repo).unwrap_or_else(|error| panic!("repo: {error}"));
    fs::write(repo.join("target.txt"), b"authorized-preimage")
        .unwrap_or_else(|error| panic!("target: {error}"));
    let expected = {
        use sha2::{Digest, Sha256};
        format!("sha256:{:x}", Sha256::digest(b"authorized-preimage"))
    };
    let policy = PathPolicy::new(&repo, std::iter::empty::<PathBuf>())
        .unwrap_or_else(|error| panic!("policy: {error}"));
    let guard = AtomicUpdateGuard::prepare(&policy, "target.txt", &expected)
        .unwrap_or_else(|error| panic!("prepare update: {error}"));

    fs::write(repo.join("target.txt"), b"newer-preimage")
        .unwrap_or_else(|error| panic!("stale target: {error}"));
    assert!(guard.commit(b"must-not-land", 0o644).is_err());
    assert_eq!(
        fs::read(repo.join("target.txt")).unwrap_or_default(),
        b"newer-preimage"
    );
}

#[test]
fn atomic_update_requires_exact_preimage_digest_and_preserves_replace_behavior() {
    let temp = TestDir::under(&std::env::temp_dir(), "atomic-update-success");
    let repo = temp.0.join("repo");
    fs::create_dir_all(&repo).unwrap_or_else(|error| panic!("repo: {error}"));
    fs::write(repo.join("target.txt"), b"before").unwrap_or_else(|error| panic!("target: {error}"));
    let policy = PathPolicy::new(&repo, std::iter::empty::<PathBuf>())
        .unwrap_or_else(|error| panic!("policy: {error}"));
    assert!(AtomicUpdateGuard::prepare(&policy, "target.txt", "sha256:deadbeef").is_err());
    let expected = {
        use sha2::{Digest, Sha256};
        format!("sha256:{:x}", Sha256::digest(b"before"))
    };
    let guard = AtomicUpdateGuard::prepare(&policy, "target.txt", &expected)
        .unwrap_or_else(|error| panic!("prepare: {error}"));
    guard
        .commit(b"after", 0o644)
        .unwrap_or_else(|error| panic!("commit: {error}"));
    assert_eq!(
        fs::read(repo.join("target.txt")).unwrap_or_default(),
        b"after"
    );
}

#[cfg(unix)]
#[test]
fn atomic_replace_rejects_target_symlink_swap_after_authorization() {
    let temp = TestDir::under(&std::env::temp_dir(), "atomic-symlink-swap");
    let repo = temp.0.join("repo");
    let outside = temp.0.join("outside.txt");
    fs::create_dir_all(&repo).unwrap_or_else(|error| panic!("repo: {error}"));
    fs::write(repo.join("target.txt"), b"before").unwrap_or_else(|error| panic!("target: {error}"));
    fs::write(&outside, b"outside-original").unwrap_or_else(|error| panic!("outside: {error}"));

    let guard = AtomicReplaceGuard::prepare(&repo, "target.txt")
        .unwrap_or_else(|error| panic!("prepare: {error}"));
    fs::remove_file(repo.join("target.txt")).unwrap_or_else(|error| panic!("remove: {error}"));
    std::os::unix::fs::symlink(&outside, repo.join("target.txt"))
        .unwrap_or_else(|error| panic!("swap symlink: {error}"));

    assert!(guard.commit(b"should-not-land", 0o644).is_err());
    assert_eq!(fs::read(&outside).unwrap_or_default(), b"outside-original");
}

#[cfg(unix)]
#[test]
fn atomic_replace_rejects_parent_symlink_swap_after_authorization() {
    let temp = TestDir::under(&std::env::temp_dir(), "atomic-parent-swap");
    let repo = temp.0.join("repo");
    let outside = temp.0.join("outside");
    fs::create_dir_all(repo.join("dir")).unwrap_or_else(|error| panic!("repo dir: {error}"));
    fs::create_dir_all(&outside).unwrap_or_else(|error| panic!("outside dir: {error}"));
    fs::write(repo.join("dir/target.txt"), b"before")
        .unwrap_or_else(|error| panic!("target: {error}"));
    fs::write(outside.join("target.txt"), b"outside-original")
        .unwrap_or_else(|error| panic!("outside target: {error}"));

    let guard = AtomicReplaceGuard::prepare(&repo, "dir/target.txt")
        .unwrap_or_else(|error| panic!("prepare: {error}"));
    fs::rename(repo.join("dir"), repo.join("dir-old"))
        .unwrap_or_else(|error| panic!("rename parent: {error}"));
    std::os::unix::fs::symlink(&outside, repo.join("dir"))
        .unwrap_or_else(|error| panic!("parent symlink: {error}"));

    assert!(guard.commit(b"should-not-land", 0o644).is_err());
    assert_eq!(
        fs::read(outside.join("target.txt")).unwrap_or_default(),
        b"outside-original"
    );
}

struct RejectIsolation;

impl ExecutionIsolationBackend for RejectIsolation {
    fn capabilities(&self) -> IsolationCapabilities {
        panic!("capabilities must not be queried by ProcessRunner::prepare_execution")
    }

    fn isolate(
        &self,
        _spec: &CommandSpec,
        _request: &IsolationRequest,
    ) -> Result<IsolatedCommand, PolicyError> {
        Err(PolicyError::IsolationUnavailable(
            "fixture isolation unavailable".to_owned(),
        ))
    }
}

struct PassthroughIsolation;

impl ExecutionIsolationBackend for PassthroughIsolation {
    fn capabilities(&self) -> IsolationCapabilities {
        panic!("capabilities must not be queried by ProcessRunner::prepare_execution")
    }

    fn isolate(
        &self,
        spec: &CommandSpec,
        _request: &IsolationRequest,
    ) -> Result<IsolatedCommand, PolicyError> {
        Ok(IsolatedCommand {
            executable: spec.executable.clone(),
            args: spec.args.clone(),
        })
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn secret_lease_runner_stops_observed_until_controller_closes_lease_and_commits() {
    let (temp, repo, home, mut store) = fixture("secret-lease-observed");
    let artifact_store = artifacts(&temp);
    let sentinel = b"controller-owned-secret-lifecycle";
    let script = "IFS= read -r secret < \"$SOVEREIGN_SECRET_FILE\"; printf 'stdout:%s\\n' \"$secret\"; printf 'stderr:%s\\n' \"$secret\" >&2";
    let mut action = shell_action(
        "action_secret_lease_observed",
        &repo,
        script,
        Limits {
            timeout_ms: 2_000,
            output_bytes: 8 * 1024,
            disk_bytes: 8 * 1024,
            subprocesses: 0,
        },
        ReconciliationMode::UnsafeSideEffect,
    );
    let request = isolation(&repo, &home, false);
    bind_isolation(&mut action, &request);
    let decision = permission_decision(&action);
    action.permission_decision_digest = decision.digest();

    let secret_ref = SecretRef {
        secret_ref_id: "secret.fixture.tools".to_owned(),
        provider: SecretProviderKind::ExternalBroker,
        purpose: "exercise exact Controller-owned tools lifecycle".to_owned(),
        injection: SecretInjection::TemporaryFile,
        target: "SOVEREIGN_SECRET_FILE".to_owned(),
    };
    action.destination_digest = Some(
        secret_ref
            .binding_digest()
            .unwrap_or_else(|error| panic!("SecretRef binding digest: {error}")),
    );
    let mut broker = SecretBroker::new();
    broker
        .register_provider(Arc::new(FakeSecretProvider::new(
            SecretProviderKind::ExternalBroker,
            [("tools-fixture".to_owned(), sentinel.to_vec())],
        )))
        .unwrap_or_else(|error| panic!("register fake secret provider: {error}"));
    broker
        .register_secret(
            secret_ref.clone(),
            ControllerSecretLocator::FakeKey {
                provider: SecretProviderKind::ExternalBroker,
                key: "tools-fixture".to_owned(),
            },
        )
        .unwrap_or_else(|error| panic!("register secret: {error}"));
    let scope = SecretScope {
        plan_id: action.plan_id.clone(),
        plan_revision: action.plan_revision,
        task_id: action.task_id.clone(),
        task_contract_digest: decision.task_contract_digest.clone(),
        action_id: action.action_id.clone(),
        permission_decision_digest: action.permission_decision_digest.clone(),
        execution_epoch: action.execution_epoch,
    };
    let now = now_ms();
    let mut lease = broker
        .resolve(
            &secret_ref,
            scope.clone(),
            &decision.effective,
            now,
            now + 10_000,
        )
        .unwrap_or_else(|error| panic!("resolve secret lease: {error}"));
    let private_root = temp.0.join("controller-private-secrets");
    let command_policy = shell_policy();
    let runner = ProcessRunner::new(&command_policy, &PassthroughIsolation);

    {
        let mut journal = ActionJournal::new(&mut store);
        authorize(&mut journal, &action, &manifest())
            .unwrap_or_else(|error| panic!("authorize: {error}"));
        let (result, proof) = runner
            .run_with_secret_lease_observed(
                &mut journal,
                &action,
                &request,
                &artifact_store,
                &mut lease,
                &scope,
                &decision,
                now,
                &private_root,
            )
            .unwrap_or_else(|error| panic!("secret lease run: {error}"));
        assert_eq!(result.stdout, b"stdout:[REDACTED]\n");
        assert_eq!(result.stderr, b"stderr:[REDACTED]\n");
        assert_eq!(
            proof,
            SecretCleanupProof {
                process_lease_reaped: true,
                ephemeral_injection_removed: true,
            }
        );
        assert!(!lease.is_closed());
        let observed = journal
            .record(&action.action_id)
            .unwrap_or_else(|error| panic!("observed record: {error}"))
            .unwrap_or_else(|| panic!("missing observed action"));
        assert_eq!(observed.state, "observed");

        lease
            .close(&scope)
            .unwrap_or_else(|error| panic!("Controller lease close: {error}"));
        assert!(lease.is_closed());
        journal
            .commit_with_bound_result(&action, ActionState::Observed)
            .unwrap_or_else(|error| panic!("Controller commit: {error}"));
        assert_eq!(
            journal
                .record(&action.action_id)
                .unwrap_or_else(|error| panic!("committed record: {error}"))
                .map(|record| record.state)
                .as_deref(),
            Some("committed")
        );
    }
    assert_tree_excludes_bytes(&temp.0, sentinel);
}

#[test]
#[allow(clippy::too_many_lines)]
fn cancellable_secret_runner_reaps_exact_group_and_never_persists_secret() {
    let (temp, repo, home, mut store) = fixture("secret-lease-cancelled");
    let artifact_store = artifacts(&temp);
    let sentinel = b"secret-cancellation-must-never-persist";
    let marker = repo.join("secret-cancel.started");
    let script = "IFS= read -r secret < \"$SOVEREIGN_SECRET_FILE\"; printf 'stdout:%s\\n' \"$secret\"; printf 'stderr:%s\\n' \"$secret\" >&2; printf started > secret-cancel.started; while :; do :; done";
    let mut action = shell_action(
        "action_secret_lease_cancelled",
        &repo,
        script,
        Limits {
            timeout_ms: 10_000,
            output_bytes: 8 * 1024,
            disk_bytes: 8 * 1024,
            subprocesses: 0,
        },
        ReconciliationMode::UnsafeSideEffect,
    );
    action.permission_class = PermissionClass::RepositoryWrite;
    let request = isolation(&repo, &home, true);
    bind_isolation(&mut action, &request);
    let decision = permission_decision(&action);
    action.permission_decision_digest = decision.digest();

    let secret_ref = SecretRef {
        secret_ref_id: "secret.fixture.tools.cancel".to_owned(),
        provider: SecretProviderKind::ExternalBroker,
        purpose: "exercise cancellable Controller-owned tools lifecycle".to_owned(),
        injection: SecretInjection::TemporaryFile,
        target: "SOVEREIGN_SECRET_FILE".to_owned(),
    };
    action.destination_digest = Some(
        secret_ref
            .binding_digest()
            .unwrap_or_else(|error| panic!("SecretRef binding digest: {error}")),
    );
    let mut broker = SecretBroker::new();
    broker
        .register_provider(Arc::new(FakeSecretProvider::new(
            SecretProviderKind::ExternalBroker,
            [("tools-cancel-fixture".to_owned(), sentinel.to_vec())],
        )))
        .unwrap_or_else(|error| panic!("register fake secret provider: {error}"));
    broker
        .register_secret(
            secret_ref.clone(),
            ControllerSecretLocator::FakeKey {
                provider: SecretProviderKind::ExternalBroker,
                key: "tools-cancel-fixture".to_owned(),
            },
        )
        .unwrap_or_else(|error| panic!("register secret: {error}"));
    let scope = SecretScope {
        plan_id: action.plan_id.clone(),
        plan_revision: action.plan_revision,
        task_id: action.task_id.clone(),
        task_contract_digest: decision.task_contract_digest.clone(),
        action_id: action.action_id.clone(),
        permission_decision_digest: action.permission_decision_digest.clone(),
        execution_epoch: action.execution_epoch,
    };
    let now = now_ms();
    let mut lease = broker
        .resolve(
            &secret_ref,
            scope.clone(),
            &decision.effective,
            now,
            now + 10_000,
        )
        .unwrap_or_else(|error| panic!("resolve secret lease: {error}"));
    let private_root = temp.0.join("controller-private-secrets");
    let command_policy = shell_policy();
    let runner = ProcessRunner::new(&command_policy, &PassthroughIsolation);
    let cancellation = ProcessCancellationToken::new();
    let cancellation_worker = cancellation.clone();
    let marker_worker = marker.clone();
    let canceller = thread::spawn(move || {
        for _ in 0..200 {
            if marker_worker.exists() {
                cancellation_worker.cancel();
                return true;
            }
            thread::sleep(Duration::from_millis(10));
        }
        cancellation_worker.cancel();
        false
    });

    let error = {
        let mut journal = ActionJournal::new(&mut store);
        authorize(&mut journal, &action, &manifest())
            .unwrap_or_else(|error| panic!("authorize: {error}"));
        let Err(error) = runner.run_with_secret_lease_observed_cancellable(
            &mut journal,
            &action,
            &request,
            &artifact_store,
            &mut lease,
            &scope,
            &decision,
            now,
            &private_root,
            &cancellation,
        ) else {
            panic!("cancelled secret process must not report success");
        };
        assert_eq!(
            journal
                .record(&action.action_id)
                .unwrap_or_else(|read_error| panic!("action record: {read_error}"))
                .map(|record| record.state),
            Some("unknown".to_owned())
        );
        assert_eq!(
            journal
                .reconcile_unknown(&action, None)
                .unwrap_or_else(|reconcile_error| panic!("reconcile unknown: {reconcile_error}")),
            Reconciliation::BlockedUnsafeUnknown
        );
        assert_eq!(
            journal
                .record(&action.action_id)
                .unwrap_or_else(|read_error| panic!("reconciled record: {read_error}"))
                .map(|record| record.state),
            Some("unknown".to_owned())
        );
        error
    };
    assert!(
        canceller
            .join()
            .unwrap_or_else(|_| panic!("secret canceller thread panicked")),
        "secret child never reached the in-flight marker before cancellation"
    );
    assert!(
        error
            .to_string()
            .contains("secret process execution cancelled after dispatch")
    );
    assert!(
        !lease.is_closed(),
        "Controller still owns SecretLease closure"
    );

    let process_lease: serde_json::Value = serde_json::from_str(
        &store
            .get_state("controller.process_lease", &action.action_id)
            .unwrap_or_else(|read_error| panic!("process lease: {read_error}"))
            .unwrap_or_else(|| panic!("missing process lease")),
    )
    .unwrap_or_else(|decode_error| panic!("decode process lease: {decode_error}"));
    assert_eq!(process_lease["state"], "reaped");
    let pgid = process_lease["process_group_id"]
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or_else(|| panic!("process lease pgid"));
    assert!(
        process_lease["leader_identity"]
            .as_str()
            .is_some_and(|identity| !identity.is_empty())
    );
    assert_eq!(
        process_group_leader_identity(pgid).unwrap_or_else(|observe_error| panic!(
            "observe cancelled secret group: {observe_error}"
        )),
        None
    );
    assert_tree_excludes_bytes(&temp.0, sentinel);
    lease
        .close(&scope)
        .unwrap_or_else(|close_error| panic!("Controller lease close: {close_error}"));
    assert!(lease.is_closed());
}

#[cfg(target_os = "macos")]
#[test]
fn mismatched_process_leader_identity_cannot_authorize_reap() {
    let mut child = Command::new("/bin/sleep")
        .arg("30")
        .process_group(0)
        .spawn()
        .unwrap_or_else(|error| panic!("spawn owned test process: {error}"));
    let pgid = child.id();
    let identity = process_group_leader_identity(pgid)
        .unwrap_or_else(|error| panic!("read process identity: {error}"))
        .unwrap_or_else(|| panic!("missing live process identity"));
    let stale_identity = format!("stale-persisted-identity:{identity}");
    let Err(error) = reap_owned_process_group(pgid, &stale_identity) else {
        panic!("stale persisted process identity must not authorize reap");
    };
    assert!(error.to_string().contains("identity changed"));
    assert!(
        child
            .try_wait()
            .unwrap_or_else(|wait_error| panic!("observe live child: {wait_error}"))
            .is_none(),
        "mismatched identity must not kill or reattach the live process"
    );
    assert_eq!(
        process_group_leader_identity(pgid)
            .unwrap_or_else(|observe_error| panic!("re-read process identity: {observe_error}")),
        Some(identity)
    );
    child
        .kill()
        .unwrap_or_else(|kill_error| panic!("cleanup test child: {kill_error}"));
    let _ = child
        .wait()
        .unwrap_or_else(|wait_error| panic!("reap test child: {wait_error}"));
}

#[test]
fn unavailable_isolation_backend_blocks_before_dispatch_or_spawn() {
    let (temp, repo, home, mut store) = fixture("isolation-unavailable");
    let artifact_store = artifacts(&temp);
    let mut action = shell_action(
        "action_isolation_unavailable",
        &repo,
        "printf forbidden > marker.txt",
        Limits {
            timeout_ms: 1_000,
            output_bytes: 4 * 1024,
            disk_bytes: 4 * 1024,
            subprocesses: 1,
        },
        ReconciliationMode::UnsafeSideEffect,
    );
    action.permission_class = PermissionClass::RepositoryWrite;
    let request = isolation(&repo, &home, true);
    bind_isolation(&mut action, &request);
    let command_policy = shell_policy();
    let backend = RejectIsolation;
    let runner = ProcessRunner::new(&command_policy, &backend);
    let mut journal = ActionJournal::new(&mut store);
    authorize(&mut journal, &action, &manifest())
        .unwrap_or_else(|error| panic!("authorize: {error}"));

    assert!(
        runner
            .run(&mut journal, &action, &request, &artifact_store)
            .is_err()
    );
    assert!(!repo.join("marker.txt").exists());
    assert_eq!(
        journal
            .record(&action.action_id)
            .unwrap_or(None)
            .map(|record| record.state),
        Some("authorized".to_owned())
    );
    assert!(
        store
            .get_state("controller.process_lease", &action.action_id)
            .unwrap_or(None)
            .is_none()
    );
}

#[test]
fn tool_schema_required_capabilities_must_be_within_manifest_and_decision() {
    let tool_manifest = manifest();
    let schema = ToolSchemaV1 {
        tool_id: tool_manifest.tool_id.clone(),
        version: tool_manifest.version.clone(),
        content_digest: tool_manifest.content_digest.clone(),
        name: "shell".to_owned(),
        description: "Run one structured shell command".to_owned(),
        input_schema: serde_json::json!({"type": "object"}),
        required_capabilities: CapabilitySet::new([PermissionClass::ProcessExec]),
    };
    assert!(schema.validate_against_manifest(&tool_manifest).is_ok());

    let (_temp, repo, _home, _store) = fixture("schema-filter");
    let action = shell_action(
        "action_schema_filter",
        &repo,
        "true",
        Limits {
            timeout_ms: 1_000,
            output_bytes: 1_024,
            disk_bytes: 1_024,
            subprocesses: 0,
        },
        ReconciliationMode::IdempotentRead,
    );
    let decision = permission_decision(&action);
    let schemas = [schema.clone()];
    let manifests = [tool_manifest.clone()];
    let decisions = [decision];
    let visible = filter_authorized_tool_schemas(&schemas, &manifests, &decisions)
        .unwrap_or_else(|error| panic!("filter schemas: {error}"));
    assert_eq!(visible, vec![&schema]);

    let too_broad = ToolSchemaV1 {
        required_capabilities: CapabilitySet::new([PermissionClass::NetworkRead]),
        ..schema
    };
    assert!(too_broad.validate_against_manifest(&tool_manifest).is_err());
}

#[test]
fn mismatched_permission_decision_cannot_authorize_action() {
    let (_temp, repo, _home, mut store) = fixture("decision-binding");
    let action = shell_action(
        "action_decision_binding",
        &repo,
        "true",
        Limits {
            timeout_ms: 1_000,
            output_bytes: 1_024,
            disk_bytes: 1_024,
            subprocesses: 0,
        },
        ReconciliationMode::IdempotentRead,
    );
    let mismatched = PermissionDecision::new(
        action.plan_id.clone(),
        action.plan_revision,
        "sibling-task",
        test_digest('3'),
        action.policy_digest.clone(),
        action.tool_id.clone(),
        action.tool_version.clone(),
        action.tool_digest.clone(),
        CapabilityLayers {
            global: CapabilitySet::all(),
            project: CapabilitySet::all(),
            task: CapabilitySet::all(),
            role: CapabilitySet::all(),
            tool: CapabilitySet::all(),
            user: CapabilitySet::all(),
        },
    )
    .unwrap_or_else(|error| panic!("mismatched decision: {error}"));
    let original_payload_digest = action.payload_digest();
    let mut changed_binding = action.clone();
    changed_binding.permission_decision_digest = mismatched.digest();
    assert_ne!(original_payload_digest, changed_binding.payload_digest());

    let mut journal = ActionJournal::new(&mut store);
    assert!(
        journal
            .authorize(&action, &manifest(), &mismatched)
            .is_err()
    );
    assert!(journal.record(&action.action_id).unwrap_or(None).is_none());
}

#[cfg(target_os = "macos")]
#[test]
fn process_runner_refuses_execution_until_exact_action_is_durably_authorized() {
    let (temp, repo, home, mut store) = fixture("authorization");
    let artifact_store = artifacts(&temp);
    let mut action = shell_action(
        "action_auth",
        &repo,
        "printf ran > marker.txt",
        Limits {
            timeout_ms: 2_000,
            output_bytes: 32 * 1024,
            disk_bytes: 32 * 1024,
            subprocesses: 2,
        },
        ReconciliationMode::UnsafeSideEffect,
    );
    action.permission_class = PermissionClass::RepositoryWrite;
    let command_policy = shell_policy();
    let backend =
        MacSandboxExecBackend::detect().unwrap_or_else(|error| panic!("sandbox: {error}"));
    let runner = ProcessRunner::new(&command_policy, &backend);
    let request = isolation(&repo, &home, true);
    bind_isolation(&mut action, &request);
    let result_digest = {
        let mut journal = ActionJournal::new(&mut store);
        assert!(
            runner
                .run(&mut journal, &action, &request, &artifact_store)
                .is_err()
        );
        assert!(!repo.join("marker.txt").exists());
        assert!(journal.record(&action.action_id).unwrap_or(None).is_none());

        authorize(&mut journal, &action, &manifest())
            .unwrap_or_else(|error| panic!("authorize: {error}"));
        let result = runner
            .run(&mut journal, &action, &request, &artifact_store)
            .unwrap_or_else(|error| panic!("run: {error}"));
        assert_eq!(result.exit_code, Some(0));
        assert!(repo.join("marker.txt").exists());
        let record = journal
            .record(&action.action_id)
            .unwrap_or_else(|error| panic!("record: {error}"))
            .unwrap_or_else(|| panic!("missing action"));
        assert_eq!(record.state, "committed");
        record
            .result_digest
            .unwrap_or_else(|| panic!("committed action missing result digest"))
    };
    let mut receipt_file = artifact_store
        .open_artifact(&store, &result_digest)
        .unwrap_or_else(|error| panic!("open receipt: {error}"));
    let mut receipt = Vec::new();
    receipt_file
        .read_to_end(&mut receipt)
        .unwrap_or_else(|error| panic!("read receipt: {error}"));
    let value: serde_json::Value =
        serde_json::from_slice(&receipt).unwrap_or_else(|error| panic!("receipt json: {error}"));
    assert_eq!(value["action_id"].as_str(), Some("action_auth"));
    assert_eq!(value["exit_code"].as_i64(), Some(0));
}

#[cfg(target_os = "macos")]
#[test]
fn process_exec_does_not_imply_repository_write_and_isolation_binding_is_exact() {
    let (temp, repo, home, mut store) = fixture("process-exec-no-write");
    let artifact_store = artifacts(&temp);
    let mut action = shell_action(
        "action_process_exec_no_write",
        &repo,
        "printf denied > marker.txt",
        Limits {
            timeout_ms: 1_000,
            output_bytes: 4 * 1024,
            disk_bytes: 4 * 1024,
            subprocesses: 0,
        },
        ReconciliationMode::UnsafeSideEffect,
    );
    let request = isolation(&repo, &home, true);
    bind_isolation(&mut action, &request);
    let command_policy = shell_policy();
    let backend =
        MacSandboxExecBackend::detect().unwrap_or_else(|error| panic!("sandbox: {error}"));
    let runner = ProcessRunner::new(&command_policy, &backend);
    let mut journal = ActionJournal::new(&mut store);
    authorize(&mut journal, &action, &manifest())
        .unwrap_or_else(|error| panic!("authorize: {error}"));
    assert!(
        runner
            .run(&mut journal, &action, &request, &artifact_store)
            .is_err()
    );
    assert!(!repo.join("marker.txt").exists());
    assert_eq!(
        journal
            .record(&action.action_id)
            .unwrap_or(None)
            .map(|record| record.state),
        Some("authorized".to_owned())
    );

    let mut read_action = shell_action(
        "action_isolation_digest",
        &repo,
        "true",
        Limits {
            timeout_ms: 1_000,
            output_bytes: 4 * 1024,
            disk_bytes: 4 * 1024,
            subprocesses: 0,
        },
        ReconciliationMode::IdempotentRead,
    );
    let offline = isolation(&repo, &home, false);
    bind_isolation(&mut read_action, &offline);
    authorize(&mut journal, &read_action, &manifest())
        .unwrap_or_else(|error| panic!("authorize read: {error}"));
    let mut changed = offline;
    changed.allow_repository_write = true;
    assert!(
        runner
            .run(&mut journal, &read_action, &changed, &artifact_store)
            .is_err()
    );
    assert_eq!(
        journal
            .record(&read_action.action_id)
            .unwrap_or(None)
            .map(|record| record.state),
        Some("authorized".to_owned())
    );
}

#[test]
fn published_receipt_before_state_observation_never_creates_false_commit() {
    let (temp, repo, _home, mut store) = fixture("receipt-before-observe");
    let db = temp.0.join("state.sqlite3");
    let artifact_store = artifacts(&temp);
    let action = shell_action(
        "action_receipt_gap",
        &repo,
        "true",
        Limits {
            timeout_ms: 1_000,
            output_bytes: 1_024,
            disk_bytes: 1_024,
            subprocesses: 0,
        },
        ReconciliationMode::IdempotentRead,
    );
    {
        let mut journal = ActionJournal::new(&mut store);
        authorize(&mut journal, &action, &manifest())
            .unwrap_or_else(|error| panic!("authorize: {error}"));
        journal
            .transition(&action, ActionState::Authorized, ActionState::Dispatched)
            .unwrap_or_else(|error| panic!("dispatch: {error}"));
    }
    let artifact = artifact_store
        .put(&mut store, b"{\"schema\":\"test-receipt\"}")
        .unwrap_or_else(|error| panic!("publish receipt: {error}"));
    drop(store);

    let mut reopened = StateStore::open(&db).unwrap_or_else(|error| panic!("reopen: {error}"));
    assert!(
        artifact_store
            .open_artifact(&reopened, &artifact.digest)
            .is_ok()
    );
    let mut journal = ActionJournal::new(&mut reopened);
    let record = journal
        .record(&action.action_id)
        .unwrap_or_else(|error| panic!("record: {error}"))
        .unwrap_or_else(|| panic!("missing action"));
    assert_eq!(record.state, "dispatched");
    assert!(record.result_digest.is_none());
    journal
        .recover_dispatched_as_unknown(&action)
        .unwrap_or_else(|error| panic!("recover unknown: {error}"));
    assert_eq!(
        journal
            .record(&action.action_id)
            .unwrap_or(None)
            .map(|record| record.state),
        Some("unknown".to_owned())
    );
}

#[test]
fn observed_receipt_survives_restart_and_can_then_commit() {
    let (temp, repo, _home, mut store) = fixture("observe-restart");
    let db = temp.0.join("state.sqlite3");
    let artifact_store = artifacts(&temp);
    let action = shell_action(
        "action_observed_restart",
        &repo,
        "true",
        Limits {
            timeout_ms: 1_000,
            output_bytes: 1_024,
            disk_bytes: 1_024,
            subprocesses: 0,
        },
        ReconciliationMode::IdempotentRead,
    );
    let digest = {
        let mut journal = ActionJournal::new(&mut store);
        authorize(&mut journal, &action, &manifest())
            .unwrap_or_else(|error| panic!("authorize: {error}"));
        journal
            .transition(&action, ActionState::Authorized, ActionState::Dispatched)
            .unwrap_or_else(|error| panic!("dispatch: {error}"));
        journal
            .observe_with_receipt(&action, &artifact_store, b"{\"result\":\"known\"}")
            .unwrap_or_else(|error| panic!("observe receipt: {error}"))
    };
    drop(store);

    let mut reopened = StateStore::open(&db).unwrap_or_else(|error| panic!("reopen: {error}"));
    let mut journal = ActionJournal::new(&mut reopened);
    let observed = journal
        .record(&action.action_id)
        .unwrap_or_else(|error| panic!("record: {error}"))
        .unwrap_or_else(|| panic!("missing observed action"));
    assert_eq!(observed.state, "observed");
    assert_eq!(observed.result_digest.as_deref(), Some(digest.as_str()));
    journal
        .commit_with_bound_result(&action, ActionState::Observed)
        .unwrap_or_else(|error| panic!("commit after restart: {error}"));
    let committed = journal
        .record(&action.action_id)
        .unwrap_or_else(|error| panic!("committed record: {error}"))
        .unwrap_or_else(|| panic!("missing committed action"));
    assert_eq!(committed.state, "committed");
    assert_eq!(committed.result_digest.as_deref(), Some(digest.as_str()));
}

#[test]
fn repository_mutation_authority_is_domain_separated_and_exactly_bound() {
    let (_temp, repo, _home, _store) = fixture("repo-mutation-payload");
    let process = shell_action(
        "action_repo_mutation_payload",
        &repo,
        "true",
        Limits {
            timeout_ms: 5_000,
            output_bytes: 0,
            disk_bytes: 1_024,
            subprocesses: 0,
        },
        ReconciliationMode::UnsafeSideEffect,
    );
    let create = repository_mutation("action_repo_mutation_payload", "src/new.rs");
    assert_ne!(process.payload_digest(), create.payload_digest());

    let mut changed_post = create.clone();
    changed_post.expected_post_digest = test_digest('7');
    assert_ne!(create.payload_digest(), changed_post.payload_digest());

    let mut update = create.clone();
    update.kind = RepositoryMutationKind::Update;
    update.precondition = RepositoryMutationPrecondition::ExactFile {
        digest: test_digest('8'),
        mode: 0o644,
    };
    assert_ne!(create.payload_digest(), update.payload_digest());
    assert!(create.validate(now_ms()).is_ok());
    assert!(update.validate(now_ms()).is_ok());

    let mut invalid_update = update;
    invalid_update.precondition = RepositoryMutationPrecondition::Absent;
    assert!(invalid_update.validate(now_ms()).is_err());
}

#[test]
fn repository_mutation_uses_canonical_journal_without_process_charge() {
    let (temp, _repo, _home, mut store) = fixture("repo-mutation-journal");
    let artifact_store = artifacts(&temp);
    let action = repository_mutation("action_repo_mutation_journal", "src/new.rs");
    let decision = repository_permission_decision(&action);
    let reservation = action.reservation();
    assert_eq!(reservation.tool_actions, 1);
    assert_eq!(reservation.subprocesses, 0);
    assert_eq!(reservation.output_bytes, 0);
    assert_eq!(reservation.wall_ms, 5_000);
    assert_eq!(reservation.disk_write_bytes, 1_024);
    assert!(!action.approval_required());

    let mut journal = ActionJournal::new(&mut store);
    journal
        .authorize(&action, &repository_manifest(), &decision)
        .unwrap_or_else(|error| panic!("authorize repository mutation: {error}"));
    journal
        .transition(&action, ActionState::Authorized, ActionState::Dispatched)
        .unwrap_or_else(|error| panic!("dispatch repository mutation: {error}"));
    let receipt_digest = journal
        .observe_with_receipt(
            &action,
            &artifact_store,
            b"{\"kind\":\"repository_mutation\",\"result\":\"known\"}",
        )
        .unwrap_or_else(|error| panic!("observe repository mutation: {error}"));
    journal
        .commit_with_bound_result(&action, ActionState::Observed)
        .unwrap_or_else(|error| panic!("commit repository mutation: {error}"));
    let record = journal
        .record(&action.action_id)
        .unwrap_or_else(|error| panic!("repository mutation record: {error}"))
        .unwrap_or_else(|| panic!("missing repository mutation record"));
    assert_eq!(record.state, "committed");
    assert_eq!(
        record.result_digest.as_deref(),
        Some(receipt_digest.as_str())
    );
}

#[test]
fn repository_mutation_journal_fails_closed_on_manifest_permission_epoch_and_risk_drift() {
    let (_temp, _repo, _home, mut store) = fixture("repo-mutation-authority");
    let action = repository_mutation("action_repo_mutation_authority", "src/new.rs");
    let decision = repository_permission_decision(&action);

    let mut wrong_permission = repository_manifest();
    wrong_permission.permission_ceiling = BTreeSet::from([PermissionClass::ProcessExec]);
    let mut journal = ActionJournal::new(&mut store);
    assert!(
        journal
            .authorize(&action, &wrong_permission, &decision)
            .is_err()
    );
    assert!(journal.record(&action.action_id).unwrap_or(None).is_none());

    let mut too_high_risk = repository_manifest();
    too_high_risk.declared_risk_floor = CommandRisk::Destructive;
    assert!(
        journal
            .authorize(&action, &too_high_risk, &decision)
            .is_err()
    );

    store
        .advance_execution_epoch()
        .unwrap_or_else(|error| panic!("advance epoch: {error}"));
    let mut journal = ActionJournal::new(&mut store);
    assert!(
        journal
            .authorize(&action, &repository_manifest(), &decision)
            .is_err()
    );
}

#[test]
fn manifest_cannot_enlarge_action_permission_or_lower_risk_floor() {
    let (_temp, repo, _home, mut store) = fixture("manifest");
    let mut action = shell_action(
        "action_manifest",
        &repo,
        "true",
        Limits {
            timeout_ms: 1_000,
            output_bytes: 1_024,
            disk_bytes: 1_024,
            subprocesses: 1,
        },
        ReconciliationMode::IdempotentRead,
    );
    action.permission_class = PermissionClass::NetworkWrite;
    let mut journal = ActionJournal::new(&mut store);
    assert!(authorize(&mut journal, &action, &manifest()).is_err());
    assert!(journal.record(&action.action_id).unwrap_or(None).is_none());

    action.permission_class = PermissionClass::ProcessExec;
    action.command.declared_risk = CommandRisk::ReadOnly;
    assert!(authorize(&mut journal, &action, &manifest()).is_err());
}

#[test]
fn crash_after_dispatch_becomes_unknown_safe_read_reconciles_and_unsafe_unknown_blocks() {
    let (_temp, repo, _home, mut store) = fixture("reconcile");
    let safe = shell_action(
        "action_safe",
        &repo,
        "true",
        Limits {
            timeout_ms: 1_000,
            output_bytes: 1_024,
            disk_bytes: 1_024,
            subprocesses: 1,
        },
        ReconciliationMode::IdempotentRead,
    );
    let unsafe_action = shell_action(
        "action_unsafe",
        &repo,
        "true",
        Limits {
            timeout_ms: 1_000,
            output_bytes: 1_024,
            disk_bytes: 1_024,
            subprocesses: 1,
        },
        ReconciliationMode::UnsafeSideEffect,
    );
    let tool_manifest = manifest();
    let mut journal = ActionJournal::new(&mut store);

    for action in [&safe, &unsafe_action] {
        authorize(&mut journal, action, &tool_manifest)
            .unwrap_or_else(|error| panic!("authorize: {error}"));
        journal
            .transition(action, ActionState::Authorized, ActionState::Dispatched)
            .unwrap_or_else(|error| panic!("dispatch: {error}"));
        journal
            .recover_dispatched_as_unknown(action)
            .unwrap_or_else(|error| panic!("unknown: {error}"));
    }

    let safe_decision = journal
        .reconcile_unknown(&safe, None)
        .unwrap_or_else(|error| panic!("safe reconcile: {error}"));
    assert_eq!(safe_decision, Reconciliation::SafeToRetry);
    assert_eq!(
        journal
            .record(&safe.action_id)
            .unwrap_or(None)
            .map(|record| record.state),
        Some("reconciled".to_owned())
    );

    let unsafe_decision = journal
        .reconcile_unknown(&unsafe_action, None)
        .unwrap_or_else(|error| panic!("unsafe reconcile: {error}"));
    assert_eq!(unsafe_decision, Reconciliation::BlockedUnsafeUnknown);
    assert_eq!(
        journal
            .record(&unsafe_action.action_id)
            .unwrap_or(None)
            .map(|record| record.state),
        Some("unknown".to_owned())
    );
}

#[test]
fn reconciliation_approval_claim_is_exact_expiring_and_durable_before_dispatch() {
    let (_temp, repo, _home, mut store) = fixture("reconciliation-approval");
    let mut action = shell_action(
        "action_reconciliation_approval",
        &repo,
        "true",
        Limits {
            timeout_ms: 1_000,
            output_bytes: 1_024,
            disk_bytes: 1_024,
            subprocesses: 0,
        },
        ReconciliationMode::IdempotentRead,
    );
    action.approval_required = true;
    let issued_at_ms = now_ms().saturating_sub(1);
    let claim = approval_claim(&action, issued_at_ms);
    action
        .verify_approval_claim(&claim, now_ms())
        .unwrap_or_else(|error| panic!("exact claim should validate: {error}"));

    let mut changed = action.clone();
    changed.command.args.push("payload-drift".to_owned());
    assert!(changed.verify_approval_claim(&claim, now_ms()).is_err());
    let mut changed = action.clone();
    changed.executable_digest = test_digest('4');
    assert!(changed.verify_approval_claim(&claim, now_ms()).is_err());
    let mut changed = action.clone();
    changed.destination_digest = Some(test_digest('5'));
    assert!(changed.verify_approval_claim(&claim, now_ms()).is_err());
    let mut changed = action.clone();
    changed.policy_digest = test_digest('6');
    assert!(changed.verify_approval_claim(&claim, now_ms()).is_err());
    let mut changed = action.clone();
    changed.execution_epoch = action.execution_epoch.saturating_add(1);
    assert!(changed.verify_approval_claim(&claim, now_ms()).is_err());
    let mut expired = claim.clone();
    expired.expires_at_ms = expired.issued_at_ms.saturating_add(1);
    assert!(
        action
            .verify_approval_claim(&expired, expired.expires_at_ms)
            .is_err()
    );

    {
        let mut journal = ActionJournal::new(&mut store);
        authorize(&mut journal, &action, &manifest())
            .unwrap_or_else(|error| panic!("authorize approval-required action: {error}"));
        let error = journal
            .transition(&action, ActionState::Authorized, ActionState::Dispatched)
            .err()
            .unwrap_or_else(|| panic!("missing durable claim must deny dispatch"));
        assert!(error.to_string().contains("no durable approval claim"));
        assert_eq!(
            journal
                .record(&action.action_id)
                .unwrap_or_else(|error| panic!("authorized record: {error}"))
                .map(|record| record.state),
            Some("authorized".to_owned())
        );
    }

    store
        .put_state(
            APPROVAL_CLAIM_NAMESPACE,
            &action.action_id,
            &serde_json::to_string(&claim)
                .unwrap_or_else(|error| panic!("serialize claim: {error}")),
        )
        .unwrap_or_else(|error| panic!("persist claim: {error}"));
    let mut journal = ActionJournal::new(&mut store);
    journal
        .transition(&action, ActionState::Authorized, ActionState::Dispatched)
        .unwrap_or_else(|error| panic!("durable exact claim dispatch: {error}"));
}

#[test]
fn reconciliation_tool_policy_is_non_downgradable_and_external_unknown_never_blind_replays() {
    let (_temp, repo, _home, mut store) = fixture("reconciliation-policy");
    let mut tool_manifest = manifest();
    tool_manifest.reconciliation_policy = ReconciliationPolicy::consequential_external();
    let mut action = shell_action(
        "action_external_reconciliation",
        &repo,
        "true",
        Limits {
            timeout_ms: 1_000,
            output_bytes: 1_024,
            disk_bytes: 1_024,
            subprocesses: 0,
        },
        ReconciliationMode::UnsafeSideEffect,
    );
    {
        let mut journal = ActionJournal::new(&mut store);
        assert!(authorize(&mut journal, &action, &tool_manifest).is_err());
        assert!(journal.record(&action.action_id).unwrap_or(None).is_none());
    }

    action.reconciliation_mode = ReconciliationMode::ConsequentialExternal;
    let mut journal = ActionJournal::new(&mut store);
    authorize(&mut journal, &action, &tool_manifest)
        .unwrap_or_else(|error| panic!("strict external authorization: {error}"));
    journal
        .transition(&action, ActionState::Authorized, ActionState::Dispatched)
        .unwrap_or_else(|error| panic!("dispatch: {error}"));
    journal
        .recover_dispatched_as_unknown(&action)
        .unwrap_or_else(|error| panic!("unknown: {error}"));
    assert_eq!(
        journal
            .reconcile_unknown(&action, None)
            .unwrap_or_else(|error| panic!("external reconcile: {error}")),
        Reconciliation::BlockedUnsafeUnknown
    );
    assert_eq!(
        journal
            .reconcile_unknown(
                &action,
                Some(sovereign_tools::ReconciliationProof::SafeIdempotentRetry),
            )
            .unwrap_or_else(|error| panic!("external retry proof: {error}")),
        Reconciliation::BlockedUnsafeUnknown
    );
    assert_eq!(
        journal
            .record(&action.action_id)
            .unwrap_or_else(|error| panic!("external record: {error}"))
            .map(|record| record.state),
        Some("unknown".to_owned())
    );
}

#[test]
fn reconciliation_idempotent_local_retry_requires_explicit_policy_and_new_dispatch_authority() {
    let (_temp, repo, _home, mut store) = fixture("reconciliation-idempotent");
    let action = shell_action(
        "action_idempotent_reconciliation",
        &repo,
        "true",
        Limits {
            timeout_ms: 1_000,
            output_bytes: 1_024,
            disk_bytes: 1_024,
            subprocesses: 0,
        },
        ReconciliationMode::IdempotentRead,
    );
    let mut journal = ActionJournal::new(&mut store);
    authorize(&mut journal, &action, &manifest())
        .unwrap_or_else(|error| panic!("authorize: {error}"));
    journal
        .transition(&action, ActionState::Authorized, ActionState::Dispatched)
        .unwrap_or_else(|error| panic!("dispatch: {error}"));
    journal
        .recover_dispatched_as_unknown(&action)
        .unwrap_or_else(|error| panic!("unknown: {error}"));
    assert_eq!(
        journal
            .reconcile_unknown(&action, None)
            .unwrap_or_else(|error| panic!("idempotent reconcile: {error}")),
        Reconciliation::SafeToRetry
    );
    assert_eq!(
        journal
            .record(&action.action_id)
            .unwrap_or_else(|error| panic!("reconciled record: {error}"))
            .map(|record| record.state),
        Some("reconciled".to_owned())
    );
    assert!(
        journal
            .transition(&action, ActionState::Reconciled, ActionState::Dispatched)
            .is_err(),
        "reconciliation never grants blind replay of the old action"
    );
}

#[test]
fn reconciliation_action_receipt_v1_binds_only_sanitized_durable_result() {
    let (_temp, repo, _home, _store) = fixture("reconciliation-receipt");
    let action = shell_action(
        "action_receipt_reconciliation",
        &repo,
        "true",
        Limits {
            timeout_ms: 1_000,
            output_bytes: 1_024,
            disk_bytes: 1_024,
            subprocesses: 0,
        },
        ReconciliationMode::IdempotentRead,
    );
    let result = RawToolResult {
        exit_code: Some(0),
        stdout: b"stdout:[REDACTED]\n".to_vec(),
        stderr: b"stderr:[REDACTED]\n".to_vec(),
        elapsed_ms: 7,
        terminated_for_limit: None,
        process_group_reaped: true,
    };
    let receipt = ActionReceipt::from_sanitized_result(&action, &result);
    assert_eq!(receipt.schema_version, ACTION_RECEIPT_SCHEMA_VERSION);
    receipt
        .validate_for_action(&action)
        .unwrap_or_else(|error| panic!("receipt binding: {error}"));
    let bytes = receipt
        .to_bytes()
        .unwrap_or_else(|error| panic!("receipt bytes: {error}"));
    assert!(
        !bytes
            .windows(b"raw-secret".len())
            .any(|window| window == b"raw-secret")
    );
    assert!(
        !bytes
            .windows(result.stdout.len())
            .any(|window| window == result.stdout)
    );
    let decoded =
        ActionReceipt::from_bytes(&bytes).unwrap_or_else(|error| panic!("decode receipt: {error}"));
    assert_eq!(decoded, receipt);
    let mut drifted = action.clone();
    drifted.command.args.push("changed".to_owned());
    assert!(decoded.validate_for_action(&drifted).is_err());
}

#[test]
fn reconciliation_rollback_compensation_uses_same_claim_and_external_unknown_contract() {
    let (_temp, repo, _home, mut store) = fixture("reconciliation-rollback");
    let mut tool_manifest = manifest();
    tool_manifest.reconciliation_policy = ReconciliationPolicy::consequential_external();
    let mut rollback = shell_action(
        "rollback_action_reconciliation",
        &repo,
        "true",
        Limits {
            timeout_ms: 1_000,
            output_bytes: 1_024,
            disk_bytes: 1_024,
            subprocesses: 0,
        },
        ReconciliationMode::ConsequentialExternal,
    );
    rollback.approval_required = true;
    let claim = approval_claim(&rollback, now_ms().saturating_sub(1));
    store
        .put_state(
            APPROVAL_CLAIM_NAMESPACE,
            &rollback.action_id,
            &serde_json::to_string(&claim)
                .unwrap_or_else(|error| panic!("serialize rollback claim: {error}")),
        )
        .unwrap_or_else(|error| panic!("persist rollback claim: {error}"));
    let mut journal = ActionJournal::new(&mut store);
    authorize(&mut journal, &rollback, &tool_manifest)
        .unwrap_or_else(|error| panic!("authorize rollback: {error}"));
    journal
        .transition(&rollback, ActionState::Authorized, ActionState::Dispatched)
        .unwrap_or_else(|error| panic!("dispatch rollback: {error}"));
    journal
        .recover_dispatched_as_unknown(&rollback)
        .unwrap_or_else(|error| panic!("unknown rollback: {error}"));
    assert_eq!(
        journal
            .reconcile_unknown(&rollback, None)
            .unwrap_or_else(|error| panic!("rollback reconcile: {error}")),
        Reconciliation::BlockedUnsafeUnknown
    );
}

#[cfg(target_os = "macos")]
#[test]
fn timeout_kills_and_reaps_the_entire_process_group() {
    let (temp, repo, home, mut store) = fixture("timeout");
    let artifact_store = artifacts(&temp);
    let mut action = shell_action(
        "action_timeout",
        &repo,
        "while :; do :; done",
        Limits {
            timeout_ms: 120,
            output_bytes: 16 * 1024,
            disk_bytes: 16 * 1024,
            subprocesses: 0,
        },
        ReconciliationMode::IdempotentRead,
    );
    let command_policy = shell_policy();
    let backend =
        MacSandboxExecBackend::detect().unwrap_or_else(|error| panic!("sandbox: {error}"));
    let runner = ProcessRunner::new(&command_policy, &backend);
    let request = isolation(&repo, &home, false);
    bind_isolation(&mut action, &request);
    let mut journal = ActionJournal::new(&mut store);
    authorize(&mut journal, &action, &manifest())
        .unwrap_or_else(|error| panic!("authorize: {error}"));
    let result = runner
        .run(&mut journal, &action, &request, &artifact_store)
        .unwrap_or_else(|error| panic!("run: {error}"));
    assert_eq!(
        result.terminated_for_limit,
        Some(ResourceLimitKind::Timeout)
    );
    assert!(result.process_group_reaped);
}

#[cfg(target_os = "macos")]
#[test]
fn cancellation_kills_and_reaps_the_exact_owned_process_group() {
    let (temp, repo, home, mut store) = fixture("cancel-owned-process");
    let artifact_store = artifacts(&temp);
    let marker = repo.join("cancel.started");
    let mut action = shell_action(
        "action_cancel_owned_process",
        &repo,
        "echo started > cancel.started; while :; do :; done",
        Limits {
            timeout_ms: 10_000,
            output_bytes: 16 * 1024,
            disk_bytes: 16 * 1024,
            subprocesses: 0,
        },
        ReconciliationMode::UnsafeSideEffect,
    );
    action.permission_class = PermissionClass::RepositoryWrite;
    let command_policy = shell_policy();
    let backend =
        MacSandboxExecBackend::detect().unwrap_or_else(|error| panic!("sandbox: {error}"));
    let runner = ProcessRunner::new(&command_policy, &backend);
    let request = isolation(&repo, &home, true);
    bind_isolation(&mut action, &request);
    let cancellation = ProcessCancellationToken::new();
    let cancellation_worker = cancellation.clone();
    let marker_worker = marker.clone();
    let canceller = thread::spawn(move || {
        for _ in 0..200 {
            if marker_worker.exists() {
                cancellation_worker.cancel();
                return true;
            }
            thread::sleep(Duration::from_millis(10));
        }
        cancellation_worker.cancel();
        false
    });
    let started = std::time::Instant::now();
    let error = {
        let mut journal = ActionJournal::new(&mut store);
        authorize(&mut journal, &action, &manifest())
            .unwrap_or_else(|error| panic!("authorize: {error}"));
        let Err(error) = runner.run_cancellable(
            &mut journal,
            &action,
            &request,
            &artifact_store,
            &cancellation,
        ) else {
            panic!("cancelled process must not report success");
        };
        assert_eq!(
            journal
                .record(&action.action_id)
                .unwrap_or_else(|error| panic!("action record: {error}"))
                .map(|record| record.state),
            Some("unknown".to_owned())
        );
        error
    };
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(
        canceller
            .join()
            .unwrap_or_else(|_| panic!("canceller thread panicked")),
        "child never reached in-flight marker before cancellation"
    );
    assert!(
        error
            .to_string()
            .contains("cancelled after dispatch; action outcome requires reconciliation")
    );
    let process_lease: serde_json::Value = serde_json::from_str(
        &store
            .get_state("controller.process_lease", &action.action_id)
            .unwrap_or_else(|error| panic!("process lease: {error}"))
            .unwrap_or_else(|| panic!("missing process lease")),
    )
    .unwrap_or_else(|error| panic!("decode process lease: {error}"));
    assert_eq!(process_lease["state"], "reaped");
    let pgid = process_lease["process_group_id"]
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or_else(|| panic!("process lease pgid"));
    assert!(
        process_lease["leader_identity"]
            .as_str()
            .is_some_and(|identity| !identity.is_empty())
    );
    assert_eq!(
        process_group_leader_identity(pgid)
            .unwrap_or_else(|error| panic!("observe cancelled process group: {error}")),
        None
    );
}

#[cfg(target_os = "macos")]
#[test]
fn output_disk_and_subprocess_ceilings_terminate_bounded_commands() {
    let cases = [
        (
            "action_output",
            "i=0; while [ $i -lt 10000 ]; do echo 12345678901234567890; i=$((i+1)); done",
            128,
            64 * 1024,
            0,
            ResourceLimitKind::OutputBytes,
        ),
        (
            "action_disk",
            "i=0; while [ $i -lt 10000 ]; do printf 12345678901234567890 >> growing.bin; i=$((i+1)); done",
            64 * 1024,
            80,
            0,
            ResourceLimitKind::DiskBytes,
        ),
    ];

    for (label, script, output_limit, disk_limit, process_limit, expected) in cases {
        let (temp, repo, home, mut store) = fixture(label);
        let artifact_store = artifacts(&temp);
        let mut action = shell_action(
            label,
            &repo,
            script,
            Limits {
                timeout_ms: 4_000,
                output_bytes: output_limit,
                disk_bytes: disk_limit,
                subprocesses: process_limit,
            },
            ReconciliationMode::IdempotentRead,
        );
        let allow_write = label == "action_disk";
        if allow_write {
            action.permission_class = PermissionClass::RepositoryWrite;
        }
        let command_policy = shell_policy();
        let backend =
            MacSandboxExecBackend::detect().unwrap_or_else(|error| panic!("sandbox: {error}"));
        let runner = ProcessRunner::new(&command_policy, &backend);
        let request = isolation(&repo, &home, allow_write);
        bind_isolation(&mut action, &request);
        let mut journal = ActionJournal::new(&mut store);
        authorize(&mut journal, &action, &manifest())
            .unwrap_or_else(|error| panic!("authorize {label}: {error}"));
        let result = runner
            .run(&mut journal, &action, &request, &artifact_store)
            .unwrap_or_else(|error| panic!("run {label}: {error}"));
        assert_eq!(result.terminated_for_limit, Some(expected), "{label}");
        assert!(result.process_group_reaped, "{label}");
    }

    let (temp, repo, home, mut store) = fixture("action_children");
    let artifact_store = artifacts(&temp);
    let mut action = shell_action(
        "action_children",
        &repo,
        "/bin/sleep 30 & /bin/sleep 30 & wait",
        Limits {
            timeout_ms: 4_000,
            output_bytes: 16 * 1024,
            disk_bytes: 16 * 1024,
            subprocesses: 1,
        },
        ReconciliationMode::IdempotentRead,
    );
    let command_policy = shell_policy();
    let backend =
        MacSandboxExecBackend::detect().unwrap_or_else(|error| panic!("sandbox: {error}"));
    let runner = ProcessRunner::new(&command_policy, &backend);
    let request = isolation(&repo, &home, false);
    bind_isolation(&mut action, &request);
    let mut journal = ActionJournal::new(&mut store);
    authorize(&mut journal, &action, &manifest())
        .unwrap_or_else(|error| panic!("authorize children: {error}"));
    assert!(
        runner
            .run(&mut journal, &action, &request, &artifact_store)
            .is_err()
    );
    let record = journal
        .record(&action.action_id)
        .unwrap_or_else(|error| panic!("record children: {error}"))
        .unwrap_or_else(|| panic!("missing child action"));
    assert_eq!(record.state, "unknown");
}

#[cfg(target_os = "macos")]
#[test]
fn escaped_descendant_holding_output_pipe_is_bounded_and_recovery_blocked() {
    let (temp, repo, home, mut store) = fixture("escaped-pipe");
    let artifact_store = artifacts(&temp);
    let mut action = shell_action(
        "action_escaped_pipe",
        &repo,
        "/usr/bin/python3 -c 'import os,time; os.setsid(); open(\"escaped.pid\",\"w\").write(str(os.getpid())); time.sleep(10)' & exit 0",
        Limits {
            timeout_ms: 2_000,
            output_bytes: 16 * 1024,
            disk_bytes: 16 * 1024,
            subprocesses: 2,
        },
        ReconciliationMode::UnsafeSideEffect,
    );
    action.permission_class = PermissionClass::RepositoryWrite;
    let command_policy = shell_policy();
    let backend =
        MacSandboxExecBackend::detect().unwrap_or_else(|error| panic!("sandbox: {error}"));
    let runner = ProcessRunner::new(&command_policy, &backend);
    let request = isolation(&repo, &home, true);
    bind_isolation(&mut action, &request);
    let mut journal = ActionJournal::new(&mut store);
    authorize(&mut journal, &action, &manifest())
        .unwrap_or_else(|error| panic!("authorize: {error}"));
    let started = std::time::Instant::now();
    assert!(
        runner
            .run(&mut journal, &action, &request, &artifact_store)
            .is_err()
    );
    assert!(started.elapsed() < Duration::from_secs(3));
    let record = journal
        .record(&action.action_id)
        .unwrap_or_else(|error| panic!("record: {error}"))
        .unwrap_or_else(|| panic!("missing action"));
    assert_eq!(record.state, "unknown");

    let pid_path = repo.join("escaped.pid");
    for _ in 0..20 {
        if pid_path.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(25));
    }
    if let Ok(pid) = fs::read_to_string(&pid_path) {
        let _ = Command::new("/bin/kill")
            .args(["-KILL", pid.trim()])
            .status();
    }
}
