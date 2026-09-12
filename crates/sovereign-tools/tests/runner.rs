use sovereign_policy::{
    CommandMode, CommandPolicy, CommandRisk, CommandSpec, IsolationRequest, MacSandboxExecBackend,
    PinnedExecutable,
};
use sovereign_state::StateStore;
use sovereign_tools::{
    ActionJournal, ActionState, AuthorizedAction, PermissionClass, ProcessRunner, Reconciliation,
    ReconciliationMode, ResourceLimitKind, ToolManifest,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

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

fn manifest() -> ToolManifest {
    ToolManifest {
        tool_id: "tool_shell".to_owned(),
        version: "1".to_owned(),
        content_digest: "sha256:manifest".to_owned(),
        permission_ceiling: BTreeSet::from([PermissionClass::ProcessExec]),
        declared_risk_floor: CommandRisk::Shell,
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
    AuthorizedAction {
        action_id: id.to_owned(),
        plan_id: "plan_m1".to_owned(),
        plan_revision: 1,
        task_id: "task_t04".to_owned(),
        tool_id: "tool_shell".to_owned(),
        permission_class: PermissionClass::ProcessExec,
        execution_epoch: 0,
        policy_digest: "sha256:policy".to_owned(),
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
        reconciliation_mode: mode,
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

fn isolation(repo: &Path, home: &Path) -> IsolationRequest {
    IsolationRequest {
        repository_root: repo.to_path_buf(),
        user_home_root: home.to_path_buf(),
        extra_protected_read_roots: Vec::new(),
        network_offline: true,
        allow_repository_write: true,
        require_full_filesystem_read_jail: false,
    }
}

#[cfg(target_os = "macos")]
#[test]
fn process_runner_refuses_execution_until_exact_action_is_durably_authorized() {
    let (_temp, repo, home, mut store) = fixture("authorization");
    let action = shell_action(
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
    let command_policy = shell_policy();
    let backend =
        MacSandboxExecBackend::detect().unwrap_or_else(|error| panic!("sandbox: {error}"));
    let runner = ProcessRunner::new(&command_policy, &backend);
    let request = isolation(&repo, &home);
    let mut journal = ActionJournal::new(&mut store);

    assert!(runner.run(&mut journal, &action, &request).is_err());
    assert!(!repo.join("marker.txt").exists());
    assert!(journal.record(&action.action_id).unwrap_or(None).is_none());

    journal
        .authorize(&action, &manifest())
        .unwrap_or_else(|error| panic!("authorize: {error}"));
    let result = runner
        .run(&mut journal, &action, &request)
        .unwrap_or_else(|error| panic!("run: {error}"));
    assert_eq!(result.exit_code, Some(0));
    assert!(repo.join("marker.txt").exists());
    let record = journal
        .record(&action.action_id)
        .unwrap_or_else(|error| panic!("record: {error}"))
        .unwrap_or_else(|| panic!("missing action"));
    assert_eq!(record.state, "committed");
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
    assert!(journal.authorize(&action, &manifest()).is_err());
    assert!(journal.record(&action.action_id).unwrap_or(None).is_none());

    action.permission_class = PermissionClass::ProcessExec;
    action.command.declared_risk = CommandRisk::ReadOnly;
    assert!(journal.authorize(&action, &manifest()).is_err());
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
        journal
            .authorize(action, &tool_manifest)
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

#[cfg(target_os = "macos")]
#[test]
fn timeout_kills_and_reaps_the_entire_process_group() {
    let (_temp, repo, home, mut store) = fixture("timeout");
    let action = shell_action(
        "action_timeout",
        &repo,
        "sleep 30 & wait",
        Limits {
            timeout_ms: 120,
            output_bytes: 16 * 1024,
            disk_bytes: 16 * 1024,
            subprocesses: 4,
        },
        ReconciliationMode::IdempotentRead,
    );
    let command_policy = shell_policy();
    let backend =
        MacSandboxExecBackend::detect().unwrap_or_else(|error| panic!("sandbox: {error}"));
    let runner = ProcessRunner::new(&command_policy, &backend);
    let request = isolation(&repo, &home);
    let mut journal = ActionJournal::new(&mut store);
    journal
        .authorize(&action, &manifest())
        .unwrap_or_else(|error| panic!("authorize: {error}"));
    let result = runner
        .run(&mut journal, &action, &request)
        .unwrap_or_else(|error| panic!("run: {error}"));
    assert_eq!(
        result.terminated_for_limit,
        Some(ResourceLimitKind::Timeout)
    );
    assert!(result.process_group_reaped);
}

#[cfg(target_os = "macos")]
#[test]
fn output_disk_and_subprocess_ceilings_terminate_bounded_commands() {
    let cases = [
        (
            "action_output",
            "i=0; while [ $i -lt 1000 ]; do echo 12345678901234567890; i=$((i+1)); sleep 0.005; done",
            128,
            64 * 1024,
            4,
            ResourceLimitKind::OutputBytes,
        ),
        (
            "action_disk",
            "i=0; while [ $i -lt 1000 ]; do printf 12345678901234567890 >> growing.bin; i=$((i+1)); sleep 0.005; done",
            64 * 1024,
            80,
            4,
            ResourceLimitKind::DiskBytes,
        ),
        (
            "action_children",
            "sleep 30 & sleep 30 & wait",
            16 * 1024,
            16 * 1024,
            1,
            ResourceLimitKind::Subprocesses,
        ),
    ];

    for (label, script, output_limit, disk_limit, process_limit, expected) in cases {
        let (_temp, repo, home, mut store) = fixture(label);
        let action = shell_action(
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
        let command_policy = shell_policy();
        let backend =
            MacSandboxExecBackend::detect().unwrap_or_else(|error| panic!("sandbox: {error}"));
        let runner = ProcessRunner::new(&command_policy, &backend);
        let request = isolation(&repo, &home);
        let mut journal = ActionJournal::new(&mut store);
        journal
            .authorize(&action, &manifest())
            .unwrap_or_else(|error| panic!("authorize {label}: {error}"));
        let result = runner
            .run(&mut journal, &action, &request)
            .unwrap_or_else(|error| panic!("run {label}: {error}"));
        assert_eq!(result.terminated_for_limit, Some(expected), "{label}");
        assert!(result.process_group_reaped, "{label}");
    }
}
