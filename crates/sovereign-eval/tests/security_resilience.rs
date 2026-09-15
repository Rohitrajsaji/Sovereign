use rusqlite::Connection;
use sovereign_controller::{
    CancellationScopeKindV1, CancellationScopeV1, CancellationTree, RecoveryIntegrityGate,
};
use sovereign_evidence::{ArtifactStore, EvidenceError};
use sovereign_policy::{
    AUTONOMY_BUDGET_SCHEMA_VERSION, AutonomyBudgetV1, CommandMode, CommandPolicy, CommandRisk,
    CommandSpec, IsolationRequest, MacSandboxExecBackend, PinnedExecutable,
};
use sovereign_state::{
    NewCheckpointIntegrityRecord, NewJournalEvent, SecurityAuditEventV1, StateStore,
};
use sovereign_tools::{
    ActionJournal, ActionState, AuthorizedAction, CapabilityLayers, CapabilitySet, PermissionClass,
    PermissionDecision, ProcessCancellationToken, ProcessRunner, ReconciliationMode,
    ReconciliationPolicy, ToolManifest, process_group_leader_identity,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct TestDir(PathBuf);

impl TestDir {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "sovereign-eval-security-resilience-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap_or_else(|error| panic!("create test dir: {error}"));
        Self(path)
    }

    #[cfg(target_os = "macos")]
    fn under_home(label: &str) -> Self {
        let home = std::env::var_os("HOME").map_or_else(|| panic!("HOME"), PathBuf::from);
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let path = home.join(format!(
            ".sovereign-eval-security-resilience-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap_or_else(|error| panic!("create test dir: {error}"));
        Self(path)
    }

    fn db(&self) -> PathBuf {
        self.0.join("state.sqlite3")
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn audit_event(action_id: &str, evidence_digest: &str) -> SecurityAuditEventV1 {
    SecurityAuditEventV1 {
        actor_id: "controller:prime".to_owned(),
        plan_id: Some("plan:m6".to_owned()),
        task_id: Some("M6-T06".to_owned()),
        attempt_id: Some("attempt:security-resilience".to_owned()),
        action_id: Some(action_id.to_owned()),
        execution_epoch: Some(7),
        decision: "allow".to_owned(),
        action: "authorized_mutation".to_owned(),
        policy_digest: test_digest('a'),
        config_digest: test_digest('b'),
        tool_digest: test_digest('c'),
        approval_provenance_digest: Some(test_digest('d')),
        evidence_provenance_digest: Some(evidence_digest.to_owned()),
        occurred_at_ms: 1_700_000_000_000,
        result: "authorized".to_owned(),
    }
}

fn test_digest(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

fn test_budget(max_model_calls: u32, max_tool_actions: u32) -> AutonomyBudgetV1 {
    AutonomyBudgetV1 {
        schema_version: AUTONOMY_BUDGET_SCHEMA_VERSION,
        max_wall_ms: 1_000,
        max_model_calls,
        max_model_call_ms: 100,
        max_tool_actions,
        max_single_tool_action_ms: 100,
        max_output_bytes: 4_096,
        max_disk_write_bytes: 4_096,
        max_network_bytes: 4_096,
        max_subprocesses: 2,
        max_child_cpu_ms: 1_000,
        used_wall_ms: 0,
        used_model_calls: 0,
        used_tool_actions: 0,
        used_output_bytes: 0,
        used_disk_write_bytes: 0,
        used_network_bytes: 0,
        used_subprocesses: 0,
        used_child_cpu_ms: 0,
    }
}

#[test]
fn audit_chain_binds_provenance_and_recovery_gate_rejects_tamper_or_missing_history() {
    let tampered = TestDir::new("audit-tamper");
    let evidence_digest = test_digest('e');
    let expected = audit_event("action:tamper", &evidence_digest);
    {
        let mut store =
            StateStore::open(tampered.db()).unwrap_or_else(|error| panic!("open: {error}"));
        let head = store
            .security_audit_log()
            .append(&expected)
            .unwrap_or_else(|error| panic!("append audit event: {error}"));
        assert_eq!(head.event_count, 1);
        RecoveryIntegrityGate::verify_before_high_risk_mutation(&mut store)
            .unwrap_or_else(|error| panic!("clean audit gate: {error}"));
    }

    let connection =
        Connection::open(tampered.db()).unwrap_or_else(|error| panic!("raw open: {error}"));
    let bound: (String, i64, String, String, String, String, String) = connection
        .query_row(
            "SELECT action_id, execution_epoch, policy_digest, config_digest, tool_digest, approval_provenance_digest, evidence_provenance_digest FROM security_audit_events WHERE sequence=1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .unwrap_or_else(|error| panic!("read audit provenance: {error}"));
    assert_eq!(bound.0, "action:tamper");
    assert_eq!(bound.1, 7);
    assert_eq!(bound.2, expected.policy_digest);
    assert_eq!(bound.3, expected.config_digest);
    assert_eq!(bound.4, expected.tool_digest);
    assert_eq!(
        bound.5,
        expected.approval_provenance_digest.unwrap_or_default()
    );
    assert_eq!(bound.6, evidence_digest);
    connection
        .execute_batch(
            "DROP TRIGGER security_audit_events_no_update;\
             UPDATE security_audit_events SET policy_digest='sha256:tampered' WHERE sequence=1;",
        )
        .unwrap_or_else(|error| panic!("tamper audit row: {error}"));
    drop(connection);
    let mut reopened =
        StateStore::open(tampered.db()).unwrap_or_else(|error| panic!("reopen: {error}"));
    assert!(RecoveryIntegrityGate::verify_before_high_risk_mutation(&mut reopened).is_err());

    let missing = TestDir::new("audit-missing");
    {
        let mut store =
            StateStore::open(missing.db()).unwrap_or_else(|error| panic!("open missing: {error}"));
        let mut log = store.security_audit_log();
        log.append(&audit_event("action:one", &test_digest('1')))
            .unwrap_or_else(|error| panic!("append one: {error}"));
        log.append(&audit_event("action:two", &test_digest('2')))
            .unwrap_or_else(|error| panic!("append two: {error}"));
    }
    let connection =
        Connection::open(missing.db()).unwrap_or_else(|error| panic!("raw missing open: {error}"));
    connection
        .execute_batch(
            "DROP TRIGGER security_audit_events_no_delete;\
             DELETE FROM security_audit_events WHERE sequence=2;",
        )
        .unwrap_or_else(|error| panic!("delete audit tail: {error}"));
    drop(connection);
    let mut reopened =
        StateStore::open(missing.db()).unwrap_or_else(|error| panic!("reopen missing: {error}"));
    assert!(RecoveryIntegrityGate::verify_before_high_risk_mutation(&mut reopened).is_err());
}

#[test]
fn autonomy_budgets_bound_goal_task_model_retry_browser_and_never_refill_on_restore() {
    let mut goal = test_budget(2, 4);
    let mut task = test_budget(1, 2);
    goal.validate()
        .unwrap_or_else(|error| panic!("goal budget valid: {error}"));
    task.validate()
        .unwrap_or_else(|error| panic!("task budget valid: {error}"));

    task.charge_model_call(50)
        .unwrap_or_else(|error| panic!("task model call: {error}"));
    goal.charge_model_call(50)
        .unwrap_or_else(|error| panic!("goal model call: {error}"));
    assert!(task.charge_model_call(50).is_err());
    assert_eq!(task.used_model_calls, 1);
    assert_eq!(goal.used_model_calls, 1);

    task.charge_tool_action(50)
        .unwrap_or_else(|error| panic!("task tool action: {error}"));
    goal.charge_tool_action(50)
        .unwrap_or_else(|error| panic!("goal tool action: {error}"));
    task.charge_browser_action(50)
        .unwrap_or_else(|error| panic!("task browser action: {error}"));
    goal.charge_browser_action(50)
        .unwrap_or_else(|error| panic!("goal browser action: {error}"));
    assert_eq!(task.used_tool_actions, 2);
    assert_eq!(goal.used_tool_actions, 2);

    let goal_before_retry = goal.used_tool_actions;
    assert!(task.charge_tool_action(50).is_err());
    assert_eq!(task.used_tool_actions, 2);
    assert_eq!(goal.used_tool_actions, goal_before_retry);

    task.charge_wall_ms(1_000)
        .unwrap_or_else(|error| panic!("consume task wall budget: {error}"));
    assert!(task.charge_wall_ms(1).is_err());
    assert_eq!(task.used_wall_ms, 1_000);

    let encoded =
        serde_json::to_vec(&task).unwrap_or_else(|error| panic!("serialize budget: {error}"));
    let mut restored: AutonomyBudgetV1 =
        serde_json::from_slice(&encoded).unwrap_or_else(|error| panic!("restore budget: {error}"));
    restored
        .validate()
        .unwrap_or_else(|error| panic!("restored budget remains valid: {error}"));
    assert_eq!(restored.used_model_calls, 1);
    assert_eq!(restored.used_tool_actions, 2);
    assert_eq!(restored.used_wall_ms, 1_000);
    assert!(restored.charge_browser_action(50).is_err());
}

#[test]
fn cas_and_checkpoint_corruption_fail_closed_against_authoritative_state() {
    let temp = TestDir::new("cas-checkpoint");
    let mut state =
        StateStore::open(temp.db()).unwrap_or_else(|error| panic!("open state: {error}"));
    let artifacts =
        ArtifactStore::open(temp.0.join("cas")).unwrap_or_else(|error| panic!("open CAS: {error}"));
    let artifact = artifacts
        .put(&mut state, b"trusted evidence")
        .unwrap_or_else(|error| panic!("publish evidence: {error}"));
    let object_path = artifacts
        .root()
        .join("sha256")
        .join(&artifact.digest[..2])
        .join(&artifact.digest);
    fs::write(&object_path, b"corrupted evidence")
        .unwrap_or_else(|error| panic!("corrupt CAS object: {error}"));
    assert!(matches!(
        artifacts.open_artifact(&state, &artifact.digest),
        Err(EvidenceError::CorruptArtifact { .. })
    ));

    let sequence = state
        .append_event(NewJournalEvent {
            event_id: "event:checkpoint-one",
            entity_type: "security_resilience",
            entity_id: "checkpoint",
            event_kind: "seed",
            payload_json: "{}",
        })
        .unwrap_or_else(|error| panic!("append journal event: {error}"));
    let first = state
        .append_checkpoint_integrity(NewCheckpointIntegrityRecord {
            payload_digest: &test_digest('4'),
            action_sequence: sequence,
        })
        .unwrap_or_else(|error| panic!("append first checkpoint: {error}"));
    let second = state
        .append_checkpoint_integrity(NewCheckpointIntegrityRecord {
            payload_digest: &test_digest('5'),
            action_sequence: sequence,
        })
        .unwrap_or_else(|error| panic!("append second checkpoint: {error}"));
    assert_eq!(
        second.previous_hash.as_deref(),
        Some(first.checkpoint_hash.as_str())
    );
    drop(state);

    let connection =
        Connection::open(temp.db()).unwrap_or_else(|error| panic!("raw checkpoint open: {error}"));
    connection
        .execute(
            "INSERT INTO checkpoint_integrity(generation, previous_hash, checkpoint_hash, payload_digest, action_sequence, created_at_ms) VALUES (3, ?1, 'sha256:corrupt', 'sha256:tail', ?2, 0)",
            rusqlite::params![second.checkpoint_hash, sequence],
        )
        .unwrap_or_else(|error| panic!("insert corrupt checkpoint tail: {error}"));
    drop(connection);

    let mut state =
        StateStore::open(temp.db()).unwrap_or_else(|error| panic!("reopen state: {error}"));
    let fallback = state
        .validate_checkpoint_integrity_floor(sequence)
        .unwrap_or_else(|error| panic!("validate fallback floor: {error}"))
        .unwrap_or_else(|| panic!("missing trusted checkpoint floor"));
    assert_eq!(fallback.generation, second.generation);
    let newer_sequence = state
        .append_event(NewJournalEvent {
            event_id: "event:uncheckpointed",
            entity_type: "security_resilience",
            entity_id: "checkpoint",
            event_kind: "mutation",
            payload_json: "{}",
        })
        .unwrap_or_else(|error| panic!("append uncheckpointed event: {error}"));
    assert!(
        state
            .validate_checkpoint_integrity_floor(newer_sequence)
            .is_err()
    );
}

#[test]
fn cancellation_tree_propagates_downward_and_late_children_inherit_cancellation() {
    let tree = CancellationTree::default();
    let goal = tree
        .register_root(CancellationScopeV1 {
            scope_id: "cancel:goal".to_owned(),
            kind: CancellationScopeKindV1::Goal,
            plan_id: "plan:m6".to_owned(),
            plan_revision: 1,
            goal_id: "goal:m6".to_owned(),
            task_id: None,
            attempt_id: None,
            action_id: None,
        })
        .unwrap_or_else(|error| panic!("register goal cancellation: {error}"));
    let task = tree
        .register_child(
            CancellationScopeV1 {
                scope_id: "cancel:task".to_owned(),
                kind: CancellationScopeKindV1::Task,
                plan_id: "plan:m6".to_owned(),
                plan_revision: 1,
                goal_id: "goal:m6".to_owned(),
                task_id: Some("M6-T06".to_owned()),
                attempt_id: None,
                action_id: None,
            },
            "cancel:goal",
        )
        .unwrap_or_else(|error| panic!("register task cancellation: {error}"));
    assert!(!goal.is_cancelled());
    assert!(!task.is_cancelled());

    goal.cancel()
        .unwrap_or_else(|error| panic!("cancel goal: {error}"));
    assert!(goal.is_cancelled());
    assert!(task.is_cancelled());

    let late_action = tree
        .register_child(
            CancellationScopeV1 {
                scope_id: "cancel:late-action".to_owned(),
                kind: CancellationScopeKindV1::Action,
                plan_id: "plan:m6".to_owned(),
                plan_revision: 1,
                goal_id: "goal:m6".to_owned(),
                task_id: Some("M6-T06".to_owned()),
                attempt_id: Some("attempt:late".to_owned()),
                action_id: Some("action:late".to_owned()),
            },
            "cancel:task",
        )
        .unwrap_or_else(|error| panic!("register late action cancellation: {error}"));
    assert!(late_action.is_cancelled());
}

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
fn shell_action(repo: &Path) -> AuthorizedAction {
    let executable = PinnedExecutable::from_path("/bin/sh", "macos-system")
        .unwrap_or_else(|error| panic!("pin shell action: {error}"));
    let mut action = AuthorizedAction {
        action_id: "action_security_resilience_cancel".to_owned(),
        plan_id: "plan_m6".to_owned(),
        plan_revision: 1,
        task_id: "M6-T06".to_owned(),
        attempt_id: "attempt-security-resilience-cancel".to_owned(),
        tool_id: "tool_shell".to_owned(),
        tool_version: "1".to_owned(),
        tool_digest: test_digest('1'),
        executable_digest: executable.sha256,
        repository_id: "repo_fixture".to_owned(),
        destination_digest: None,
        permission_class: PermissionClass::RepositoryWrite,
        execution_epoch: 0,
        policy_digest: test_digest('2'),
        permission_decision_digest: "sha256:pending-decision".to_owned(),
        isolation_policy_digest: "sha256:pending-isolation".to_owned(),
        nonce: "nonce-security-resilience-cancel".to_owned(),
        expires_at_ms: now_ms() + 60_000,
        command: CommandSpec {
            executable: PathBuf::from("/bin/sh"),
            args: vec![
                "-c".to_owned(),
                "echo started > cancel.started; while :; do :; done".to_owned(),
            ],
            working_directory: repo.to_path_buf(),
            environment: BTreeMap::new(),
            mode: CommandMode::Shell,
            declared_risk: CommandRisk::Shell,
            timeout_ms: 10_000,
            output_limit_bytes: 16 * 1024,
            disk_write_limit_bytes: 16 * 1024,
            subprocess_limit: 0,
        },
        individually_authorized_environment: BTreeSet::new(),
        approval_required: false,
        reconciliation_mode: ReconciliationMode::UnsafeSideEffect,
    };
    action.permission_decision_digest = permission_decision(&action).digest();
    action
}

#[cfg(target_os = "macos")]
fn tool_manifest() -> ToolManifest {
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

#[cfg(target_os = "macos")]
fn now_ms() -> i64 {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|error| panic!("clock: {error}"));
    i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
}

#[cfg(target_os = "macos")]
#[test]
fn cancellation_reaps_the_exact_owned_process_group_and_cannot_report_success() {
    let temp = TestDir::under_home("process-cancel");
    let repo = temp.0.join("repo");
    fs::create_dir_all(&repo).unwrap_or_else(|error| panic!("create repo: {error}"));
    let home = std::env::var_os("HOME").map_or_else(|| panic!("HOME"), PathBuf::from);
    let mut state =
        StateStore::open(temp.db()).unwrap_or_else(|error| panic!("open state: {error}"));
    let artifacts =
        ArtifactStore::open(temp.0.join("cas")).unwrap_or_else(|error| panic!("open CAS: {error}"));
    let command_policy = shell_policy();
    let isolation_backend =
        MacSandboxExecBackend::detect().unwrap_or_else(|error| panic!("sandbox: {error}"));
    let runner = ProcessRunner::new(&command_policy, &isolation_backend);
    let mut action = shell_action(&repo);
    let isolation_request = IsolationRequest {
        repository_root: repo.clone(),
        user_home_root: home,
        extra_protected_read_roots: Vec::new(),
        network_offline: true,
        allow_repository_write: true,
        require_full_filesystem_read_jail: false,
    };
    action.isolation_policy_digest = isolation_request
        .digest()
        .unwrap_or_else(|error| panic!("isolation digest: {error}"));

    let cancellation = ProcessCancellationToken::new();
    let cancellation_worker = cancellation.clone();
    let marker = repo.join("cancel.started");
    let canceller = thread::spawn(move || {
        for _ in 0..200 {
            if marker.exists() {
                cancellation_worker.cancel();
                return true;
            }
            thread::sleep(Duration::from_millis(10));
        }
        cancellation_worker.cancel();
        false
    });

    let error = {
        let mut journal = ActionJournal::new(&mut state);
        journal
            .authorize(&action, &tool_manifest(), &permission_decision(&action))
            .unwrap_or_else(|error| panic!("authorize action: {error}"));
        let Err(error) = runner.run_cancellable(
            &mut journal,
            &action,
            &isolation_request,
            &artifacts,
            &cancellation,
        ) else {
            panic!("cancelled process must not report success");
        };
        assert_eq!(
            journal
                .record(&action.action_id)
                .unwrap_or_else(|error| panic!("action record: {error}"))
                .map(|record| record.state),
            Some(ActionState::Unknown.as_str().to_owned())
        );
        error
    };
    assert!(
        canceller
            .join()
            .unwrap_or_else(|_| panic!("canceller thread panicked")),
        "child never reached the in-flight marker"
    );
    assert!(
        error
            .to_string()
            .contains("cancelled after dispatch; action outcome requires reconciliation")
    );

    let process_lease: serde_json::Value = serde_json::from_str(
        &state
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
