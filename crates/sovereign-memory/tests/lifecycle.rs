use sovereign_memory::{
    FingerprintChange, InvalidationPredicate, InvalidationPredicateKind, MemoryAccessScope,
    MemoryKind, MemoryLifecycle, MemoryManager, MemoryProvenance, MemoryRepositoryDelta,
    MemoryScope, MemoryScopeKind, MemoryStatus, MemoryTrust, NewMemoryRecord, SourceFingerprint,
    SourceFingerprintKind,
};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const NOW: i64 = 1_800_000_000_000;

struct TestDir(PathBuf);

impl TestDir {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "sovereign-memory-{label}-{}-{nonce}",
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

fn manager(label: &str) -> (TestDir, MemoryManager) {
    let temp = TestDir::new(label);
    let memory = MemoryManager::open(temp.db()).unwrap_or_else(|error| panic!("open: {error}"));
    (temp, memory)
}

fn scope(project_id: &str) -> MemoryScope {
    MemoryScope {
        project_id: project_id.to_owned(),
        kind: MemoryScopeKind::Project,
        agent_id: None,
        role_visibility: Vec::new(),
    }
}

fn provenance(repository_id: Option<&str>, evidence_id: &str) -> MemoryProvenance {
    MemoryProvenance {
        source_evidence_ids: vec![evidence_id.to_owned()],
        producing_task_id: Some("task.fixture".to_owned()),
        producing_attempt_id: Some("attempt.fixture".to_owned()),
        repository_id: repository_id.map(str::to_owned),
        repository_revision: repository_id.map(|_| "rev-a".to_owned()),
        source_fingerprints: repository_id.map_or_else(Vec::new, |_| {
            vec![SourceFingerprint {
                kind: SourceFingerprintKind::FileBlob,
                key: "src/lib.rs".to_owned(),
                digest: "sha256:old".to_owned(),
            }]
        }),
    }
}

fn record(
    id: &str,
    project_id: &str,
    kind: MemoryKind,
    trust: MemoryTrust,
    subject: &str,
    assertion: &str,
) -> NewMemoryRecord {
    NewMemoryRecord {
        id: id.to_owned(),
        kind,
        scope: scope(project_id),
        subject: subject.to_owned(),
        predicate: "has_value".to_owned(),
        assertion: assertion.to_owned(),
        trust,
        confidence: 0.9,
        provenance: provenance(None, &format!("evidence.{id}")),
        expires_at_ms: None,
        invalidation_predicates: Vec::new(),
    }
}

fn ids(records: &[sovereign_memory::MemoryRecord]) -> Vec<&str> {
    records.iter().map(|record| record.id.as_str()).collect()
}

#[test]
fn lifecycle_project_isolation_is_fail_closed() {
    let (_temp, mut memory) = manager("project-isolation");
    memory
        .capture(
            record(
                "mem.a",
                "project-a",
                MemoryKind::PreferenceContext,
                MemoryTrust::Observed,
                "format",
                "compact",
            ),
            NOW,
        )
        .unwrap_or_else(|error| panic!("capture a: {error}"));
    memory
        .capture(
            record(
                "mem.b",
                "project-b",
                MemoryKind::PreferenceContext,
                MemoryTrust::Observed,
                "format",
                "verbose",
            ),
            NOW,
        )
        .unwrap_or_else(|error| panic!("capture b: {error}"));

    let visible = memory
        .injectable_records(
            MemoryAccessScope {
                project_id: "project-a",
                agent_id: None,
                role_id: None,
            },
            NOW,
        )
        .unwrap_or_else(|error| panic!("injectable: {error}"));
    assert_eq!(ids(&visible), vec!["mem.a"]);
}

#[test]
fn lifecycle_role_and_agent_isolation_are_uniform_scope_rules() {
    let (_temp, mut memory) = manager("role-agent-isolation");
    let mut role_record = record(
        "mem.role",
        "project-a",
        MemoryKind::PreferenceContext,
        MemoryTrust::Observed,
        "review-style",
        "strict",
    );
    role_record.scope.role_visibility = vec!["implementer".to_owned()];
    memory
        .capture(role_record, NOW)
        .unwrap_or_else(|error| panic!("capture role: {error}"));

    let mut agent_record = record(
        "mem.agent",
        "project-a",
        MemoryKind::Episodic,
        MemoryTrust::Observed,
        "failure-signature",
        "E42",
    );
    agent_record.scope.kind = MemoryScopeKind::Agent;
    agent_record.scope.agent_id = Some("agent-a".to_owned());
    memory
        .capture(agent_record, NOW)
        .unwrap_or_else(|error| panic!("capture agent: {error}"));

    let implementer = memory
        .injectable_records(
            MemoryAccessScope {
                project_id: "project-a",
                agent_id: Some("agent-a"),
                role_id: Some("implementer"),
            },
            NOW,
        )
        .unwrap_or_else(|error| panic!("implementer view: {error}"));
    assert_eq!(ids(&implementer), vec!["mem.agent", "mem.role"]);

    let reviewer = memory
        .injectable_records(
            MemoryAccessScope {
                project_id: "project-a",
                agent_id: Some("agent-b"),
                role_id: Some("reviewer"),
            },
            NOW,
        )
        .unwrap_or_else(|error| panic!("reviewer view: {error}"));
    assert!(reviewer.is_empty());
}

#[test]
fn lifecycle_governed_replacement_is_versioned_supersession() {
    let (_temp, mut memory) = manager("supersession");
    let old = record(
        "mem.governed.v1",
        "project-a",
        MemoryKind::GovernedKnowledge,
        MemoryTrust::Governed,
        "release-policy",
        "local-only",
    );
    memory
        .capture(old, NOW)
        .unwrap_or_else(|error| panic!("capture old: {error}"));
    let replacement = record(
        "mem.governed.v2",
        "project-a",
        MemoryKind::GovernedKnowledge,
        MemoryTrust::Governed,
        "release-policy",
        "local-only-with-signed-bundle",
    );
    let new = memory
        .replace_governed("mem.governed.v1", replacement, NOW + 1)
        .unwrap_or_else(|error| panic!("replace: {error}"));
    let old = memory
        .record("mem.governed.v1")
        .unwrap_or_else(|error| panic!("read old: {error}"))
        .unwrap_or_else(|| panic!("old missing"));
    assert_eq!(old.status, MemoryStatus::Superseded);
    assert_eq!(old.superseded_by.as_deref(), Some("mem.governed.v2"));
    assert_eq!(new.version, 2);
    assert_eq!(new.supersedes.as_deref(), Some("mem.governed.v1"));

    let visible = memory
        .injectable_records(
            MemoryAccessScope {
                project_id: "project-a",
                agent_id: None,
                role_id: None,
            },
            NOW + 1,
        )
        .unwrap_or_else(|error| panic!("visible: {error}"));
    assert_eq!(ids(&visible), vec!["mem.governed.v2"]);
}

#[test]
fn lifecycle_parallel_governed_contradiction_requires_explicit_supersession() {
    let (_temp, mut memory) = manager("governed-parallel");
    memory
        .capture(
            record(
                "mem.g1",
                "project-a",
                MemoryKind::GovernedKnowledge,
                MemoryTrust::Governed,
                "branch-policy",
                "main",
            ),
            NOW,
        )
        .unwrap_or_else(|error| panic!("capture first: {error}"));
    let second = memory.capture(
        record(
            "mem.g2",
            "project-a",
            MemoryKind::GovernedKnowledge,
            MemoryTrust::Governed,
            "branch-policy",
            "develop",
        ),
        NOW + 1,
    );
    assert!(second.is_err());
    assert!(
        memory
            .record("mem.g2")
            .unwrap_or_else(|error| panic!("read rollback: {error}"))
            .is_none()
    );
}

#[test]
fn lifecycle_fresh_validated_contradiction_retains_conflict_set_not_last_write() {
    let (_temp, mut memory) = manager("conflict");
    let mut left = record(
        "mem.fact.left",
        "project-a",
        MemoryKind::ValidatedProjectFact,
        MemoryTrust::Validated,
        "database",
        "sqlite",
    );
    left.provenance = provenance(Some("repo.app"), "evidence.left");
    let mut right = record(
        "mem.fact.right",
        "project-a",
        MemoryKind::ValidatedProjectFact,
        MemoryTrust::Validated,
        "database",
        "postgres",
    );
    right.provenance = provenance(Some("repo.app"), "evidence.right");
    memory
        .capture(left, NOW)
        .unwrap_or_else(|error| panic!("capture left: {error}"));
    let right = memory
        .capture(right, NOW + 1)
        .unwrap_or_else(|error| panic!("capture right: {error}"));
    let left = memory
        .record("mem.fact.left")
        .unwrap_or_else(|error| panic!("left: {error}"))
        .unwrap_or_else(|| panic!("left missing"));
    assert_eq!(left.status, MemoryStatus::Active);
    assert_eq!(right.status, MemoryStatus::Active);
    assert_eq!(left.conflict_set_id, right.conflict_set_id);
    assert!(!left.normal_injection);
    assert!(!right.normal_injection);
    let conflict_id = left
        .conflict_set_id
        .as_deref()
        .unwrap_or_else(|| panic!("conflict id missing"));
    let conflict = memory
        .conflict_set(conflict_id)
        .unwrap_or_else(|error| panic!("conflict read: {error}"))
        .unwrap_or_else(|| panic!("conflict missing"));
    assert_eq!(
        conflict.member_ids,
        vec!["mem.fact.left".to_owned(), "mem.fact.right".to_owned()]
    );
    assert!(conflict.resolved_at_ms.is_none());

    let visible = memory
        .injectable_records(
            MemoryAccessScope {
                project_id: "project-a",
                agent_id: None,
                role_id: None,
            },
            NOW + 1,
        )
        .unwrap_or_else(|error| panic!("visible: {error}"));
    assert!(visible.is_empty());
}

#[test]
fn lifecycle_observed_contradiction_is_demoted_below_governed_truth() {
    let (_temp, mut memory) = manager("demotion");
    memory
        .capture(
            record(
                "mem.truth",
                "project-a",
                MemoryKind::GovernedKnowledge,
                MemoryTrust::Governed,
                "network-policy",
                "offline",
            ),
            NOW,
        )
        .unwrap_or_else(|error| panic!("capture governed: {error}"));
    let observed = memory
        .capture(
            record(
                "mem.observed",
                "project-a",
                MemoryKind::Episodic,
                MemoryTrust::Observed,
                "network-policy",
                "online",
            ),
            NOW + 1,
        )
        .unwrap_or_else(|error| panic!("capture observed: {error}"));
    assert_eq!(observed.status, MemoryStatus::Active);
    assert!(!observed.normal_injection);
    assert_eq!(
        observed.exclusion_reason.as_deref(),
        Some("contradicts_governed")
    );
    let visible = memory
        .injectable_records(
            MemoryAccessScope {
                project_id: "project-a",
                agent_id: None,
                role_id: None,
            },
            NOW + 1,
        )
        .unwrap_or_else(|error| panic!("visible: {error}"));
    assert_eq!(ids(&visible), vec!["mem.truth"]);
}

#[test]
fn lifecycle_expiry_is_durable_before_injection() {
    let (_temp, mut memory) = manager("expiry");
    let mut expiring = record(
        "mem.expiring",
        "project-a",
        MemoryKind::PreferenceContext,
        MemoryTrust::Observed,
        "temporary-preference",
        "short-lived",
    );
    expiring.expires_at_ms = Some(NOW + 10);
    expiring.invalidation_predicates = vec![InvalidationPredicate {
        kind: InvalidationPredicateKind::ExpiresAt,
        key: "ttl".to_owned(),
        expected_value: Some((NOW + 10).to_string()),
    }];
    memory
        .capture(expiring, NOW)
        .unwrap_or_else(|error| panic!("capture: {error}"));
    let before = memory
        .injectable_records(
            MemoryAccessScope {
                project_id: "project-a",
                agent_id: None,
                role_id: None,
            },
            NOW + 9,
        )
        .unwrap_or_else(|error| panic!("before: {error}"));
    assert_eq!(ids(&before), vec!["mem.expiring"]);
    let after = memory
        .injectable_records(
            MemoryAccessScope {
                project_id: "project-a",
                agent_id: None,
                role_id: None,
            },
            NOW + 10,
        )
        .unwrap_or_else(|error| panic!("after: {error}"));
    assert!(after.is_empty());
    let expired = memory
        .record("mem.expiring")
        .unwrap_or_else(|error| panic!("read: {error}"))
        .unwrap_or_else(|| panic!("missing"));
    assert_eq!(expired.status, MemoryStatus::Expired);
}

#[test]
fn lifecycle_repository_delta_stales_exact_fingerprint_before_injection() {
    let (_temp, mut memory) = manager("repo-delta");
    let mut affected = record(
        "mem.affected",
        "project-a",
        MemoryKind::ValidatedProjectFact,
        MemoryTrust::Validated,
        "storage-layer",
        "state-store",
    );
    affected.provenance = provenance(Some("repo.app"), "evidence.affected");
    affected.invalidation_predicates = vec![InvalidationPredicate {
        kind: InvalidationPredicateKind::FingerprintChanged,
        key: "src/lib.rs".to_owned(),
        expected_value: Some("sha256:old".to_owned()),
    }];
    memory
        .capture(affected, NOW)
        .unwrap_or_else(|error| panic!("capture affected: {error}"));

    let mut unaffected = record(
        "mem.unaffected",
        "project-a",
        MemoryKind::ValidatedProjectFact,
        MemoryTrust::Validated,
        "other-fact",
        "stable",
    );
    unaffected.provenance = MemoryProvenance {
        source_evidence_ids: vec!["evidence.unaffected".to_owned()],
        producing_task_id: Some("task.fixture".to_owned()),
        producing_attempt_id: Some("attempt.fixture".to_owned()),
        repository_id: Some("repo.app".to_owned()),
        repository_revision: Some("rev-a".to_owned()),
        source_fingerprints: vec![SourceFingerprint {
            kind: SourceFingerprintKind::FileBlob,
            key: "src/other.rs".to_owned(),
            digest: "sha256:other".to_owned(),
        }],
    };
    memory
        .capture(unaffected, NOW)
        .unwrap_or_else(|error| panic!("capture unaffected: {error}"));

    let stale = memory
        .apply_repository_delta(
            &MemoryRepositoryDelta {
                repository_id: "repo.app".to_owned(),
                current_revision: None,
                changed_fingerprints: vec![FingerprintChange {
                    kind: SourceFingerprintKind::FileBlob,
                    key: "src/lib.rs".to_owned(),
                    current_digest: Some("sha256:new".to_owned()),
                }],
            },
            NOW + 1,
        )
        .unwrap_or_else(|error| panic!("delta: {error}"));
    assert_eq!(stale, vec!["mem.affected"]);
    let affected = memory
        .record("mem.affected")
        .unwrap_or_else(|error| panic!("read affected: {error}"))
        .unwrap_or_else(|| panic!("affected missing"));
    assert_eq!(affected.status, MemoryStatus::Stale);

    let visible = memory
        .injectable_records(
            MemoryAccessScope {
                project_id: "project-a",
                agent_id: None,
                role_id: None,
            },
            NOW + 1,
        )
        .unwrap_or_else(|error| panic!("visible: {error}"));
    assert_eq!(ids(&visible), vec!["mem.unaffected"]);
}

#[test]
fn lifecycle_all_memory_classes_share_one_scope_and_provenance_envelope() {
    let (_temp, mut memory) = manager("uniform-envelope");
    let fixtures = [
        (
            "mem.governed",
            MemoryKind::GovernedKnowledge,
            MemoryTrust::Governed,
        ),
        (
            "mem.validated",
            MemoryKind::ValidatedProjectFact,
            MemoryTrust::Validated,
        ),
        ("mem.episode", MemoryKind::Episodic, MemoryTrust::Observed),
        (
            "mem.procedure",
            MemoryKind::ProceduralCandidate,
            MemoryTrust::Observed,
        ),
        (
            "mem.preference",
            MemoryKind::PreferenceContext,
            MemoryTrust::Unreviewed,
        ),
    ];
    for (index, (id, kind, trust)) in fixtures.into_iter().enumerate() {
        let mut fixture = record(
            id,
            "project-a",
            kind,
            trust,
            &format!("subject-{index}"),
            "value",
        );
        if trust == MemoryTrust::Validated {
            fixture.provenance = provenance(Some("repo.app"), &format!("evidence.{id}"));
        }
        let stored = memory
            .capture(fixture, NOW + i64::try_from(index).unwrap_or(0))
            .unwrap_or_else(|error| panic!("capture {id}: {error}"));
        assert_eq!(stored.scope.project_id, "project-a");
        assert!(!stored.provenance.source_evidence_ids.is_empty());
        assert_eq!(stored.schema_version, 1);
    }

    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../schemas/memory-record-v1.json"))
            .unwrap_or_else(|error| panic!("schema parse: {error}"));
    assert_eq!(schema["title"], "Sovereign MemoryRecord v1");
    assert_eq!(schema["properties"]["schema_version"]["const"], 1);
}

#[test]
fn lifecycle_conflict_resolves_when_one_source_becomes_stale() {
    let (_temp, mut memory) = manager("conflict-resolution");
    let mut left = record(
        "mem.left",
        "project-a",
        MemoryKind::ValidatedProjectFact,
        MemoryTrust::Validated,
        "runtime",
        "rust-1",
    );
    left.provenance = provenance(Some("repo.app"), "evidence.left");
    let mut right = record(
        "mem.right",
        "project-a",
        MemoryKind::ValidatedProjectFact,
        MemoryTrust::Validated,
        "runtime",
        "rust-2",
    );
    right.provenance = MemoryProvenance {
        source_evidence_ids: vec!["evidence.right".to_owned()],
        producing_task_id: Some("task.fixture".to_owned()),
        producing_attempt_id: Some("attempt.fixture".to_owned()),
        repository_id: Some("repo.app".to_owned()),
        repository_revision: Some("rev-a".to_owned()),
        source_fingerprints: vec![SourceFingerprint {
            kind: SourceFingerprintKind::FileBlob,
            key: "src/right.rs".to_owned(),
            digest: "sha256:right".to_owned(),
        }],
    };
    memory
        .capture(left, NOW)
        .unwrap_or_else(|error| panic!("left: {error}"));
    let right = memory
        .capture(right, NOW + 1)
        .unwrap_or_else(|error| panic!("right: {error}"));
    let conflict_id = right
        .conflict_set_id
        .clone()
        .unwrap_or_else(|| panic!("conflict missing"));

    memory
        .apply_repository_delta(
            &MemoryRepositoryDelta {
                repository_id: "repo.app".to_owned(),
                current_revision: None,
                changed_fingerprints: vec![FingerprintChange {
                    kind: SourceFingerprintKind::FileBlob,
                    key: "src/right.rs".to_owned(),
                    current_digest: Some("sha256:right-new".to_owned()),
                }],
            },
            NOW + 2,
        )
        .unwrap_or_else(|error| panic!("delta: {error}"));
    let left = memory
        .record("mem.left")
        .unwrap_or_else(|error| panic!("read left: {error}"))
        .unwrap_or_else(|| panic!("left missing"));
    let right = memory
        .record("mem.right")
        .unwrap_or_else(|error| panic!("read right: {error}"))
        .unwrap_or_else(|| panic!("right missing"));
    assert_eq!(right.status, MemoryStatus::Stale);
    assert!(left.conflict_set_id.is_none());
    assert!(left.normal_injection);
    let conflict = memory
        .conflict_set(&conflict_id)
        .unwrap_or_else(|error| panic!("conflict read: {error}"))
        .unwrap_or_else(|| panic!("conflict missing"));
    assert_eq!(conflict.resolved_at_ms, Some(NOW + 2));
}

#[test]
fn lifecycle_deprecate_then_archive_preserves_history_and_rejects_active_archive() {
    let (_temp, mut memory) = manager("deprecate-archive");
    memory
        .capture(
            record(
                "mem.history",
                "project-a",
                MemoryKind::Episodic,
                MemoryTrust::Observed,
                "old-observation",
                "retained",
            ),
            NOW,
        )
        .unwrap_or_else(|error| panic!("capture: {error}"));
    assert!(memory.archive("mem.history", NOW + 1).is_err());
    memory
        .deprecate("mem.history", NOW + 1)
        .unwrap_or_else(|error| panic!("deprecate: {error}"));
    let deprecated = memory
        .record("mem.history")
        .unwrap_or_else(|error| panic!("read deprecated: {error}"))
        .unwrap_or_else(|| panic!("missing deprecated"));
    assert_eq!(deprecated.status, MemoryStatus::Deprecated);
    memory
        .archive("mem.history", NOW + 2)
        .unwrap_or_else(|error| panic!("archive: {error}"));
    let archived = memory
        .record("mem.history")
        .unwrap_or_else(|error| panic!("read archived: {error}"))
        .unwrap_or_else(|| panic!("missing archived"));
    assert_eq!(archived.status, MemoryStatus::Archived);
    assert_eq!(archived.assertion, "retained");
}

#[test]
fn lifecycle_conflict_never_erases_existing_higher_trust_demotion() {
    let (_temp, mut memory) = manager("conflict-demotion-precedence");
    memory
        .capture(
            record(
                "mem.governed",
                "project-a",
                MemoryKind::GovernedKnowledge,
                MemoryTrust::Governed,
                "policy",
                "A",
            ),
            NOW,
        )
        .unwrap_or_else(|error| panic!("governed: {error}"));
    memory
        .capture(
            record(
                "mem.observed-1",
                "project-a",
                MemoryKind::Episodic,
                MemoryTrust::Observed,
                "policy",
                "B",
            ),
            NOW + 1,
        )
        .unwrap_or_else(|error| panic!("observed 1: {error}"));
    let second = memory
        .capture(
            record(
                "mem.observed-2",
                "project-a",
                MemoryKind::Episodic,
                MemoryTrust::Observed,
                "policy",
                "C",
            ),
            NOW + 2,
        )
        .unwrap_or_else(|error| panic!("observed 2: {error}"));
    assert!(second.conflict_set_id.is_some());
    let first = memory
        .record("mem.observed-1")
        .unwrap_or_else(|error| panic!("read first: {error}"))
        .unwrap_or_else(|| panic!("first missing"));
    assert_eq!(
        first.exclusion_reason.as_deref(),
        Some("contradicts_governed")
    );
    assert!(!first.normal_injection);
}
