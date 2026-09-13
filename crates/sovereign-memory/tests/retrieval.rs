use rusqlite::Connection;
use sovereign_memory::{
    FailureSignatureFilter, FingerprintChange, MemoryAccessScope, MemoryKind, MemoryLifecycle,
    MemoryManager, MemoryProvenance, MemoryQuery, MemoryQueryMode, MemoryRepositoryDelta,
    MemoryRetriever, MemoryScope, MemoryScopeKind, MemoryStatus, MemoryTrust, NewMemoryRecord,
    SourceFingerprint, SourceFingerprintKind,
};
use sovereign_state::{MIGRATIONS, MigrationRunner};
use std::collections::BTreeSet;
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
            "sovereign-memory-retrieval-{label}-{}-{nonce}",
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
    let manager = MemoryManager::open(temp.db()).unwrap_or_else(|error| panic!("open: {error}"));
    (temp, manager)
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
        scope: MemoryScope {
            project_id: project_id.to_owned(),
            repository_id: None,
            kind: MemoryScopeKind::Project,
            agent_id: None,
            role_visibility: Vec::new(),
        },
        subject: subject.to_owned(),
        predicate: "fact".to_owned(),
        conflict_key: format!("{subject}\u{1f}fact"),
        assertion: assertion.to_owned(),
        trust,
        confidence: 90,
        provenance: MemoryProvenance {
            source_evidence_ids: vec![format!("evidence.{id}")],
            producing_task_id: Some("task.fixture".to_owned()),
            producing_attempt_id: Some("attempt.fixture".to_owned()),
            repository_revision: None,
            source_fingerprints: Vec::new(),
        },
        expires_at_ms: None,
        invalidation_predicates: Vec::new(),
    }
}

fn repository_record(
    id: &str,
    project_id: &str,
    repository_id: &str,
    subject: &str,
    assertion: &str,
    path: &str,
    digest: &str,
) -> NewMemoryRecord {
    let mut record = record(
        id,
        project_id,
        MemoryKind::ValidatedProjectFact,
        MemoryTrust::Validated,
        subject,
        assertion,
    );
    record.scope.repository_id = Some(repository_id.to_owned());
    record.provenance.repository_revision = Some("rev-a".to_owned());
    record.provenance.source_fingerprints = vec![SourceFingerprint {
        kind: SourceFingerprintKind::FileBlob,
        key: path.to_owned(),
        digest: digest.to_owned(),
    }];
    record
}

fn ordinary(project: &str, text: &str) -> MemoryQuery {
    let mut query = MemoryQuery::ordinary(project, text);
    query.max_results = 16;
    query.max_tokens = 1_024;
    query
}

fn seed_stale_memory(manager: &mut MemoryManager) {
    manager
        .capture(
            repository_record(
                "mem.stale",
                "project-a",
                "repo-a",
                "stale-subject",
                "excludedmarker stale",
                "stale.rs",
                "sha256:old",
            ),
            NOW,
        )
        .unwrap_or_else(|error| panic!("stale capture: {error}"));
    manager
        .apply_repository_delta(
            &MemoryRepositoryDelta {
                repository_id: "repo-a".to_owned(),
                current_revision: None,
                changed_fingerprints: vec![FingerprintChange {
                    kind: SourceFingerprintKind::FileBlob,
                    key: "stale.rs".to_owned(),
                    old_digest: Some("sha256:old".to_owned()),
                    new_digest: Some("sha256:new".to_owned()),
                }],
            },
            NOW + 1,
        )
        .unwrap_or_else(|error| panic!("stale delta: {error}"));
}

fn seed_superseded_memory(manager: &mut MemoryManager) {
    manager
        .capture(
            record(
                "mem.governed.v1",
                "project-a",
                MemoryKind::GovernedKnowledge,
                MemoryTrust::Governed,
                "supersession-subject",
                "excludedmarker superseded",
            ),
            NOW,
        )
        .unwrap_or_else(|error| panic!("governed old: {error}"));
    manager
        .replace_governed(
            "mem.governed.v1",
            record(
                "mem.governed.v2",
                "project-a",
                MemoryKind::GovernedKnowledge,
                MemoryTrust::Governed,
                "supersession-subject",
                "current replacement without marker",
            ),
            NOW + 1,
        )
        .unwrap_or_else(|error| panic!("replace: {error}"));
}

fn seed_deprecated_and_expired_memory(manager: &mut MemoryManager) {
    manager
        .capture(
            record(
                "mem.deprecated",
                "project-a",
                MemoryKind::Episodic,
                MemoryTrust::Observed,
                "deprecated-subject",
                "excludedmarker deprecated",
            ),
            NOW,
        )
        .unwrap_or_else(|error| panic!("deprecated capture: {error}"));
    manager
        .deprecate("mem.deprecated", NOW + 1)
        .unwrap_or_else(|error| panic!("deprecate: {error}"));

    let mut expired = record(
        "mem.expired",
        "project-a",
        MemoryKind::PreferenceContext,
        MemoryTrust::Observed,
        "expired-subject",
        "excludedmarker expired",
    );
    expired.expires_at_ms = Some(NOW + 1);
    manager
        .capture(expired, NOW)
        .unwrap_or_else(|error| panic!("expired capture: {error}"));
}

fn seed_conflicted_memory(manager: &mut MemoryManager) {
    let left = record(
        "mem.conflict.left",
        "project-a",
        MemoryKind::ValidatedProjectFact,
        MemoryTrust::Validated,
        "conflict-subject",
        "excludedmarker alpha",
    );
    let right = record(
        "mem.conflict.right",
        "project-a",
        MemoryKind::ValidatedProjectFact,
        MemoryTrust::Validated,
        "conflict-subject",
        "excludedmarker beta",
    );
    manager
        .capture(left, NOW)
        .unwrap_or_else(|error| panic!("conflict left: {error}"));
    manager
        .capture(right, NOW + 1)
        .unwrap_or_else(|error| panic!("conflict right: {error}"));
}

#[test]
fn retrieval_project_and_repository_filters_are_fail_closed() {
    let (_temp, mut manager) = manager("scope-filter");
    for record in [
        repository_record(
            "mem.a.repo1",
            "project-a",
            "repo-1",
            "database",
            "sqlite storage engine",
            "a.rs",
            "sha256:a",
        ),
        repository_record(
            "mem.a.repo2",
            "project-a",
            "repo-2",
            "database",
            "sqlite storage engine",
            "b.rs",
            "sha256:b",
        ),
        repository_record(
            "mem.b.repo1",
            "project-b",
            "repo-1",
            "database",
            "sqlite storage engine",
            "c.rs",
            "sha256:c",
        ),
    ] {
        manager
            .capture(record, NOW)
            .unwrap_or_else(|error| panic!("capture: {error}"));
    }
    let mut retriever = MemoryRetriever::new(&mut manager);
    let mut query = ordinary("project-a", "sqlite storage");
    query.repository_id = Some("repo-1".to_owned());
    let result = retriever
        .retrieve(&query, NOW)
        .unwrap_or_else(|error| panic!("retrieve: {error}"));
    assert_eq!(result.synopses.len(), 1);
    assert_eq!(result.synopses[0].memory_id, "mem.a.repo1");
    assert_eq!(result.synopses[0].project_id, "project-a");
    assert_eq!(result.synopses[0].repository_id.as_deref(), Some("repo-1"));
}

#[test]
fn retrieval_trust_precedence_dominates_lexical_rank() {
    let (_temp, mut manager) = manager("trust-precedence");
    manager
        .capture(
            record(
                "mem.observed",
                "project-a",
                MemoryKind::Episodic,
                MemoryTrust::Observed,
                "cache-observation",
                "cache cache cache cache warm path",
            ),
            NOW,
        )
        .unwrap_or_else(|error| panic!("capture observed: {error}"));
    manager
        .capture(
            record(
                "mem.governed",
                "project-a",
                MemoryKind::GovernedKnowledge,
                MemoryTrust::Governed,
                "cache-policy",
                "cache policy",
            ),
            NOW,
        )
        .unwrap_or_else(|error| panic!("capture governed: {error}"));

    let mut retriever = MemoryRetriever::new(&mut manager);
    let result = retriever
        .retrieve(&ordinary("project-a", "cache"), NOW)
        .unwrap_or_else(|error| panic!("retrieve: {error}"));
    assert_eq!(result.synopses.len(), 2);
    assert_eq!(result.synopses[0].memory_id, "mem.governed");
    assert_eq!(result.synopses[0].trust, MemoryTrust::Governed);
}

#[test]
fn retrieval_stale_memory_is_excluded_normally_and_visible_in_history() {
    let (_temp, mut manager) = manager("stale-history");
    manager
        .capture(
            repository_record(
                "mem.stale",
                "project-a",
                "repo-a",
                "storage",
                "sqlite stalehistorymarker",
                "src/lib.rs",
                "sha256:old",
            ),
            NOW,
        )
        .unwrap_or_else(|error| panic!("capture: {error}"));
    manager
        .apply_repository_delta(
            &MemoryRepositoryDelta {
                repository_id: "repo-a".to_owned(),
                current_revision: None,
                changed_fingerprints: vec![FingerprintChange {
                    kind: SourceFingerprintKind::FileBlob,
                    key: "src/lib.rs".to_owned(),
                    old_digest: Some("sha256:old".to_owned()),
                    new_digest: Some("sha256:new".to_owned()),
                }],
            },
            NOW + 1,
        )
        .unwrap_or_else(|error| panic!("delta: {error}"));

    let mut retriever = MemoryRetriever::new(&mut manager);
    let mut current = ordinary("project-a", "stalehistorymarker");
    current.repository_id = Some("repo-a".to_owned());
    assert!(
        retriever
            .retrieve(&current, NOW + 1)
            .unwrap_or_else(|error| panic!("ordinary: {error}"))
            .synopses
            .is_empty()
    );

    let mut history = current;
    history.mode = MemoryQueryMode::History;
    let result = retriever
        .retrieve(&history, NOW + 1)
        .unwrap_or_else(|error| panic!("history: {error}"));
    assert_eq!(result.synopses.len(), 1);
    assert_eq!(result.synopses[0].status, MemoryStatus::Stale);
    assert!(!result.synopses[0].expansion.evidence_ids.is_empty());
}

#[test]
fn retrieval_compact_results_respect_hard_token_budget() {
    let (_temp, mut manager) = manager("token-cap");
    for index in 0..6 {
        manager
            .capture(
                record(
                    &format!("mem.long.{index}"),
                    "project-a",
                    MemoryKind::Episodic,
                    MemoryTrust::Observed,
                    &format!("long-{index}"),
                    &format!("tokenmarker {}", "x".repeat(2_000)),
                ),
                NOW,
            )
            .unwrap_or_else(|error| panic!("capture: {error}"));
    }
    let mut query = ordinary("project-a", "tokenmarker");
    query.max_tokens = 160;
    query.max_results = 16;
    let mut retriever = MemoryRetriever::new(&mut manager);
    let result = retriever
        .retrieve(&query, NOW)
        .unwrap_or_else(|error| panic!("retrieve: {error}"));
    assert!(!result.synopses.is_empty());
    assert!(result.trace.selected_tokens <= 160);
    assert!(
        result
            .synopses
            .iter()
            .map(|synopsis| synopsis.token_cost)
            .sum::<u32>()
            <= 160
    );
    assert!(
        result
            .synopses
            .iter()
            .all(|synopsis| synopsis.rendered.len() < 800)
    );
}

#[test]
fn retrieval_compact_hit_expands_only_through_its_provenance_evidence_id() {
    let (_temp, mut manager) = manager("expansion");
    manager
        .capture(
            record(
                "mem.expand",
                "project-a",
                MemoryKind::Episodic,
                MemoryTrust::Observed,
                "expansion",
                "expansionmarker full body retained",
            ),
            NOW,
        )
        .unwrap_or_else(|error| panic!("capture: {error}"));
    let mut retriever = MemoryRetriever::new(&mut manager);
    let result = retriever
        .retrieve(&ordinary("project-a", "expansionmarker"), NOW)
        .unwrap_or_else(|error| panic!("retrieve: {error}"));
    let synopsis = result
        .synopses
        .first()
        .unwrap_or_else(|| panic!("missing synopsis"));
    let evidence_id = synopsis
        .expansion
        .evidence_ids
        .first()
        .cloned()
        .unwrap_or_else(|| panic!("missing evidence handle"));
    let access = MemoryAccessScope {
        project_id: "project-a",
        repository_id: None,
        agent_id: None,
        role_id: None,
    };
    assert!(
        retriever
            .expand_by_evidence(
                access,
                &synopsis.expansion,
                "evidence.not-this-memory",
                NOW + 1,
            )
            .is_err()
    );
    let expansion = retriever
        .expand_by_evidence(access, &synopsis.expansion, &evidence_id, NOW + 1)
        .unwrap_or_else(|error| panic!("expand: {error}"));
    assert_eq!(expansion.selected_evidence_id, evidence_id);
    assert_eq!(expansion.record.id, "mem.expand");
    assert_eq!(expansion.record.access_count, 1);
    assert_eq!(expansion.record.last_accessed_at_ms, Some(NOW + 1));
}

#[test]
fn retrieval_expansion_is_bound_to_scope_digest_and_provenance_handle() {
    let (_temp, mut manager) = manager("expansion-binding");
    let mut fixture = repository_record(
        "mem.bound",
        "project-a",
        "repo-a",
        "bound-expansion",
        "boundmarker full retained body",
        "src/bound.rs",
        "sha256:source",
    );
    fixture.scope.kind = MemoryScopeKind::Agent;
    fixture.scope.agent_id = Some("agent-a".to_owned());
    fixture.scope.role_visibility = vec!["implementer".to_owned()];
    manager
        .capture(fixture, NOW)
        .unwrap_or_else(|error| panic!("capture: {error}"));

    let mut query = ordinary("project-a", "boundmarker");
    query.repository_id = Some("repo-a".to_owned());
    query.agent_id = Some("agent-a".to_owned());
    query.role_id = Some("implementer".to_owned());
    let mut retriever = MemoryRetriever::new(&mut manager);
    let result = retriever
        .retrieve(&query, NOW)
        .unwrap_or_else(|error| panic!("retrieve: {error}"));
    let handle = result
        .synopses
        .first()
        .unwrap_or_else(|| panic!("missing synopsis"))
        .expansion
        .clone();
    let evidence_id = handle
        .evidence_ids
        .first()
        .cloned()
        .unwrap_or_else(|| panic!("missing evidence id"));

    for denied in [
        MemoryAccessScope {
            project_id: "project-b",
            repository_id: Some("repo-a"),
            agent_id: Some("agent-a"),
            role_id: Some("implementer"),
        },
        MemoryAccessScope {
            project_id: "project-a",
            repository_id: Some("repo-b"),
            agent_id: Some("agent-a"),
            role_id: Some("implementer"),
        },
        MemoryAccessScope {
            project_id: "project-a",
            repository_id: Some("repo-a"),
            agent_id: Some("agent-b"),
            role_id: Some("implementer"),
        },
        MemoryAccessScope {
            project_id: "project-a",
            repository_id: Some("repo-a"),
            agent_id: Some("agent-a"),
            role_id: Some("reviewer"),
        },
    ] {
        assert!(
            retriever
                .expand_by_evidence(denied, &handle, &evidence_id, NOW + 1)
                .is_err()
        );
    }

    let mut tampered = handle.clone();
    tampered.content_digest = "sha256:tampered".to_owned();
    let allowed = MemoryAccessScope {
        project_id: "project-a",
        repository_id: Some("repo-a"),
        agent_id: Some("agent-a"),
        role_id: Some("implementer"),
    };
    assert!(
        retriever
            .expand_by_evidence(allowed, &tampered, &evidence_id, NOW + 1)
            .is_err()
    );
    let expansion = retriever
        .expand_by_evidence(allowed, &handle, &evidence_id, NOW + 1)
        .unwrap_or_else(|error| panic!("valid expansion: {error}"));
    assert_eq!(expansion.record.id, "mem.bound");
    assert_eq!(expansion.record.content_digest, handle.content_digest);
}

#[test]
fn retrieval_episodic_exact_signature_filters_precede_broad_lexical_search() {
    let (_temp, mut manager) = manager("episodic-exact");
    let mut exact = record(
        "mem.failure.exact",
        "project-a",
        MemoryKind::Episodic,
        MemoryTrust::Observed,
        "error-e0425-cannot-find-value",
        "rustc compile failure exact episode",
    );
    exact.scope.repository_id = Some("repo-a".to_owned());
    exact.predicate = "compile".to_owned();
    exact.conflict_key = "failure:error-e0425-cannot-find-value".to_owned();
    exact.provenance.source_fingerprints = vec![
        SourceFingerprint {
            kind: SourceFingerprintKind::CommandToolVersion,
            key: "rustc".to_owned(),
            digest: "1.90.0".to_owned(),
        },
        SourceFingerprint {
            kind: SourceFingerprintKind::Symbol,
            key: "compile_target".to_owned(),
            digest: "sha256:symbol".to_owned(),
        },
    ];
    manager
        .capture(exact, NOW)
        .unwrap_or_else(|error| panic!("capture exact: {error}"));
    manager
        .capture(
            record(
                "mem.failure.distractor",
                "project-a",
                MemoryKind::Episodic,
                MemoryTrust::Observed,
                "different-failure",
                "rustc compile failure error-e0425-cannot-find-value lexical distractor",
            ),
            NOW,
        )
        .unwrap_or_else(|error| panic!("capture distractor: {error}"));

    let mut query = ordinary("project-a", "rustc compile failure");
    query.repository_id = Some("repo-a".to_owned());
    query.failure_signature = Some(FailureSignatureFilter {
        normalized_signature: "error-e0425-cannot-find-value".to_owned(),
        tool: "rustc".to_owned(),
        runtime_version: Some("1.90.0".to_owned()),
        symbol: Some("compile_target".to_owned()),
        task_kind: Some("compile".to_owned()),
    });
    let mut retriever = MemoryRetriever::new(&mut manager);
    let result = retriever
        .retrieve(&query, NOW)
        .unwrap_or_else(|error| panic!("retrieve: {error}"));
    assert_eq!(result.synopses.len(), 1);
    assert_eq!(result.synopses[0].memory_id, "mem.failure.exact");
    assert!(result.trace.used_episodic_exact);
    assert!(!result.trace.lexical_fallback_used);
    assert_eq!(
        result.trace.stages[0].phase,
        sovereign_memory::MemoryRetrievalPhase::EpisodicExact
    );
    assert!(result.trace.stages.iter().all(|stage| {
        stage.phase != sovereign_memory::MemoryRetrievalPhase::ProjectionRead
            && stage.phase != sovereign_memory::MemoryRetrievalPhase::Lexical
    }));
}

#[test]
fn retrieval_lexical_lookup_does_not_rewrite_the_full_projection() {
    let (temp, mut manager) = manager("projection-read-only");
    manager
        .capture(
            record(
                "mem.projection",
                "project-a",
                MemoryKind::ValidatedProjectFact,
                MemoryTrust::Validated,
                "projection",
                "projectionmarker searchable fact",
            ),
            NOW,
        )
        .unwrap_or_else(|error| panic!("capture: {error}"));

    let observer = Connection::open(temp.db()).unwrap_or_else(|error| panic!("observer: {error}"));
    let before: i64 = observer
        .query_row("PRAGMA data_version", [], |row| row.get(0))
        .unwrap_or_else(|error| panic!("data_version before: {error}"));
    let projection_rows: i64 = observer
        .query_row("SELECT COUNT(*) FROM memory_fts_projection", [], |row| {
            row.get(0)
        })
        .unwrap_or_else(|error| panic!("projection count: {error}"));
    assert_eq!(projection_rows, 1);

    let mut retriever = MemoryRetriever::new(&mut manager);
    for _ in 0..2 {
        let result = retriever
            .retrieve(&ordinary("project-a", "projectionmarker"), NOW)
            .unwrap_or_else(|error| panic!("retrieve: {error}"));
        assert_eq!(result.synopses.len(), 1);
        assert!(result.trace.stages.iter().any(|stage| {
            stage.phase == sovereign_memory::MemoryRetrievalPhase::ProjectionRead
        }));
    }

    let after: i64 = observer
        .query_row("PRAGMA data_version", [], |row| row.get(0))
        .unwrap_or_else(|error| panic!("data_version after: {error}"));
    assert_eq!(
        after, before,
        "lexical lookup must not mutate the FTS projection"
    );
}

#[test]
fn retrieval_v4_memory_is_searchable_after_one_time_v5_projection_migration() {
    let temp = TestDir::new("v4-projection-migration");
    {
        let mut connection =
            Connection::open(temp.db()).unwrap_or_else(|error| panic!("open v4 fixture: {error}"));
        MigrationRunner::apply(&mut connection, &MIGRATIONS[..4])
            .unwrap_or_else(|error| panic!("apply v4 migrations: {error}"));
        connection
            .execute(
                "INSERT INTO memory_records(\
                    memory_id, kind, project_id, scope_kind, agent_id, subject, predicate, assertion, \
                    trust, confidence, status, repository_id, repository_revision, producing_task_id, \
                    producing_attempt_id, created_at_ms, updated_at_ms, validated_at_ms, version, \
                    supersedes_id, superseded_by_id, expires_at_ms, access_count, last_accessed_at_ms, \
                    conflict_set_id, normal_injection, exclusion_reason\
                 ) VALUES (\
                    'mem.v4', 'episodic', 'project-a', 'project', NULL, 'migration-subject', 'fact', \
                    'migrationmarker pre-v5 searchable memory', 'observed', 0.75, 'active', NULL, NULL, \
                    'task.v4', 'attempt.v4', ?1, ?1, NULL, 1, NULL, NULL, NULL, 0, NULL, NULL, 1, NULL\
                 )",
                [NOW],
            )
            .unwrap_or_else(|error| panic!("seed v4 memory: {error}"));
        connection
            .execute(
                "INSERT INTO memory_source_evidence(memory_id, evidence_id) VALUES ('mem.v4', 'evidence.v4')",
                [],
            )
            .unwrap_or_else(|error| panic!("seed v4 evidence: {error}"));
    }

    let mut manager =
        MemoryManager::open(temp.db()).unwrap_or_else(|error| panic!("migrate/open v5: {error}"));
    let migrated = manager
        .record("mem.v4")
        .unwrap_or_else(|error| panic!("read migrated memory: {error}"))
        .unwrap_or_else(|| panic!("migrated memory missing"));
    assert!(!migrated.content_digest.is_empty());
    assert_eq!(migrated.confidence, 75);

    let mut retriever = MemoryRetriever::new(&mut manager);
    let result = retriever
        .retrieve(&ordinary("project-a", "migrationmarker"), NOW + 1)
        .unwrap_or_else(|error| panic!("retrieve migrated memory: {error}"));
    assert_eq!(result.synopses.len(), 1);
    assert_eq!(result.synopses[0].memory_id, "mem.v4");
    assert!(
        result
            .trace
            .stages
            .iter()
            .any(|stage| { stage.phase == sovereign_memory::MemoryRetrievalPhase::ProjectionRead })
    );
}

#[test]
fn retrieval_ordinary_excludes_all_noncurrent_and_conflicted_fact_states() {
    let (_temp, mut manager) = manager("noncurrent-exclusion");
    seed_stale_memory(&mut manager);
    seed_superseded_memory(&mut manager);
    seed_deprecated_and_expired_memory(&mut manager);
    seed_conflicted_memory(&mut manager);

    let mut retriever = MemoryRetriever::new(&mut manager);
    let result = retriever
        .retrieve(&ordinary("project-a", "excludedmarker"), NOW + 2)
        .unwrap_or_else(|error| panic!("ordinary: {error}"));
    assert!(result.synopses.is_empty());

    let mut history = ordinary("project-a", "excludedmarker");
    history.mode = MemoryQueryMode::History;
    let history = retriever
        .retrieve(&history, NOW + 2)
        .unwrap_or_else(|error| panic!("history: {error}"));
    let statuses = history
        .synopses
        .iter()
        .map(|synopsis| synopsis.status)
        .collect::<BTreeSet<_>>();
    assert!(statuses.contains(&MemoryStatus::Stale));
    assert!(statuses.contains(&MemoryStatus::Superseded));
    assert!(statuses.contains(&MemoryStatus::Deprecated));
    assert!(statuses.contains(&MemoryStatus::Expired));
    assert!(history.synopses.iter().any(|synopsis| synopsis.conflicted));
    assert!(
        history
            .synopses
            .iter()
            .all(|synopsis| !synopsis.expansion.evidence_ids.is_empty())
    );
}

#[test]
fn retrieval_explicit_conflict_query_returns_statement_and_both_provenance_handles() {
    let (_temp, mut manager) = manager("conflict-query");
    manager
        .capture(
            record(
                "mem.conflict.a",
                "project-a",
                MemoryKind::ValidatedProjectFact,
                MemoryTrust::Validated,
                "database-engine",
                "sqlite",
            ),
            NOW,
        )
        .unwrap_or_else(|error| panic!("left: {error}"));
    manager
        .capture(
            record(
                "mem.conflict.b",
                "project-a",
                MemoryKind::ValidatedProjectFact,
                MemoryTrust::Validated,
                "database-engine",
                "postgres",
            ),
            NOW + 1,
        )
        .unwrap_or_else(|error| panic!("right: {error}"));

    let mut query = ordinary("project-a", "database-engine");
    query.mode = MemoryQueryMode::Conflict;
    let mut retriever = MemoryRetriever::new(&mut manager);
    let result = retriever
        .retrieve(&query, NOW + 1)
        .unwrap_or_else(|error| panic!("conflict query: {error}"));
    assert!(result.synopses.is_empty());
    assert_eq!(result.conflicts.len(), 1);
    let conflict = &result.conflicts[0];
    assert!(conflict.statement.contains("UNRESOLVED MEMORY CONFLICT"));
    assert_eq!(conflict.member_handles.len(), 2);
    assert!(
        conflict
            .member_handles
            .iter()
            .all(|handle| !handle.evidence_ids.is_empty())
    );
}

#[test]
fn retrieval_conflict_mode_respects_kind_and_minimum_trust_filters() {
    let (_temp, mut manager) = manager("conflict-filters");
    for (id, assertion) in [
        ("mem.conflict.filter.a", "sqlite"),
        ("mem.conflict.filter.b", "postgres"),
    ] {
        manager
            .capture(
                record(
                    id,
                    "project-a",
                    MemoryKind::ValidatedProjectFact,
                    MemoryTrust::Validated,
                    "database-engine-filtered",
                    assertion,
                ),
                NOW,
            )
            .unwrap_or_else(|error| panic!("filtered conflict seed: {error}"));
    }

    let mut wrong_kind = ordinary("project-a", "database-engine-filtered");
    wrong_kind.mode = MemoryQueryMode::Conflict;
    wrong_kind.kinds = vec![MemoryKind::Episodic];
    let mut retriever = MemoryRetriever::new(&mut manager);
    let result = retriever
        .retrieve(&wrong_kind, NOW + 1)
        .unwrap_or_else(|error| panic!("wrong-kind conflict query: {error}"));
    assert!(result.conflicts.is_empty());

    let mut too_trusted = ordinary("project-a", "database-engine-filtered");
    too_trusted.mode = MemoryQueryMode::Conflict;
    too_trusted.minimum_trust = Some(MemoryTrust::Governed);
    let result = retriever
        .retrieve(&too_trusted, NOW + 1)
        .unwrap_or_else(|error| panic!("minimum-trust conflict query: {error}"));
    assert!(result.conflicts.is_empty());

    let mut matching = ordinary("project-a", "database-engine-filtered");
    matching.mode = MemoryQueryMode::Conflict;
    matching.kinds = vec![MemoryKind::ValidatedProjectFact];
    matching.minimum_trust = Some(MemoryTrust::Validated);
    let result = retriever
        .retrieve(&matching, NOW + 1)
        .unwrap_or_else(|error| panic!("matching conflict query: {error}"));
    assert_eq!(result.conflicts.len(), 1);
    assert_eq!(result.conflicts[0].member_handles.len(), 2);
}

#[test]
fn retrieval_conflict_provenance_handles_are_hard_bounded() {
    let (_temp, mut manager) = manager("conflict-provenance-bound");
    for index in 0..24 {
        let mut fixture = record(
            &format!("mem.conflict.bound.{index:02}"),
            "project-a",
            MemoryKind::ValidatedProjectFact,
            MemoryTrust::Validated,
            &format!("bounded-subject-{index:02}"),
            &format!("value-{index:02}"),
        );
        fixture.conflict_key = "shared-bounded-conflict-key".to_owned();
        manager
            .capture(fixture, NOW + i64::from(index))
            .unwrap_or_else(|error| panic!("bounded conflict seed: {error}"));
    }

    let mut query = ordinary("project-a", "shared-bounded-conflict-key");
    query.mode = MemoryQueryMode::Conflict;
    query.max_tokens = 2_048;
    let mut retriever = MemoryRetriever::new(&mut manager);
    let result = retriever
        .retrieve(&query, NOW + 30)
        .unwrap_or_else(|error| panic!("bounded conflict query: {error}"));
    assert_eq!(result.conflicts.len(), 1);
    let conflict = &result.conflicts[0];
    assert_eq!(conflict.member_handles.len(), 16);
    assert!(conflict.member_handles_truncated);
    assert!(conflict.token_cost <= result.trace.max_tokens);
}

#[test]
fn retrieval_large_conflict_still_fail_closes_on_late_hidden_member() {
    let (_temp, mut manager) = manager("conflict-late-hidden");
    for index in 0..17 {
        let mut fixture = record(
            &format!("mem.conflict.scope.{index:02}"),
            "project-a",
            MemoryKind::ValidatedProjectFact,
            MemoryTrust::Validated,
            &format!("scope-subject-{index:02}"),
            &format!("visible-{index:02}"),
        );
        fixture.conflict_key = "shared-scope-conflict-key".to_owned();
        manager
            .capture(fixture, NOW + i64::from(index))
            .unwrap_or_else(|error| panic!("visible conflict seed: {error}"));
    }
    let mut hidden = record(
        "mem.conflict.scope.zz-hidden",
        "project-a",
        MemoryKind::ValidatedProjectFact,
        MemoryTrust::Validated,
        "scope-subject-hidden",
        "hidden-value",
    );
    hidden.conflict_key = "shared-scope-conflict-key".to_owned();
    hidden.scope.role_visibility = vec!["reviewer-only".to_owned()];
    manager
        .capture(hidden, NOW + 20)
        .unwrap_or_else(|error| panic!("hidden conflict seed: {error}"));

    let mut query = ordinary("project-a", "shared-scope-conflict-key");
    query.mode = MemoryQueryMode::Conflict;
    let mut retriever = MemoryRetriever::new(&mut manager);
    let result = retriever
        .retrieve(&query, NOW + 21)
        .unwrap_or_else(|error| panic!("late-hidden conflict query: {error}"));
    assert!(result.conflicts.is_empty());
}

#[test]
fn retrieval_conflict_scan_window_fails_closed_instead_of_validating_a_prefix() {
    let (_temp, mut manager) = manager("conflict-scan-window");
    for index in 0..129 {
        let mut fixture = record(
            &format!("mem.conflict.scan.{index:03}"),
            "project-a",
            MemoryKind::ValidatedProjectFact,
            MemoryTrust::Validated,
            &format!("scan-subject-{index:03}"),
            &format!("scan-value-{index:03}"),
        );
        fixture.conflict_key = "shared-scan-conflict-key".to_owned();
        manager
            .capture(fixture, NOW + i64::from(index))
            .unwrap_or_else(|error| panic!("scan conflict seed: {error}"));
    }

    let mut query = ordinary("project-a", "shared-scan-conflict-key");
    query.mode = MemoryQueryMode::Conflict;
    let mut retriever = MemoryRetriever::new(&mut manager);
    let result = retriever
        .retrieve(&query, NOW + 200)
        .unwrap_or_else(|error| panic!("scan-window conflict query: {error}"));
    assert!(result.conflicts.is_empty());
}

#[test]
fn retrieval_merged_conflict_is_found_through_active_member_and_hides_noncurrent_members() {
    let (_temp, mut manager) = manager("merged-conflict-query");
    let mut fixtures = [
        record(
            "mem.a",
            "project-a",
            MemoryKind::ValidatedProjectFact,
            MemoryTrust::Validated,
            "subject-one",
            "alpha",
        ),
        record(
            "mem.b",
            "project-a",
            MemoryKind::ValidatedProjectFact,
            MemoryTrust::Validated,
            "subject-one",
            "beta",
        ),
        record(
            "mem.c",
            "project-a",
            MemoryKind::ValidatedProjectFact,
            MemoryTrust::Validated,
            "subject-two",
            "gamma",
        ),
        record(
            "mem.d",
            "project-a",
            MemoryKind::ValidatedProjectFact,
            MemoryTrust::Validated,
            "subject-three",
            "delta",
        ),
    ];
    fixtures[0].conflict_key = "key-a".to_owned();
    fixtures[1].conflict_key = "key-b".to_owned();
    fixtures[2].conflict_key = "shared-key".to_owned();
    fixtures[3].conflict_key = "shared-key".to_owned();
    for (index, fixture) in fixtures.into_iter().enumerate() {
        manager
            .capture(fixture, NOW + i64::try_from(index).unwrap_or(0))
            .unwrap_or_else(|error| panic!("seed conflict fixture: {error}"));
    }
    let mut bridge = record(
        "mem.bridge",
        "project-a",
        MemoryKind::ValidatedProjectFact,
        MemoryTrust::Validated,
        "subject-one",
        "bridge-query-marker",
    );
    bridge.conflict_key = "shared-key".to_owned();
    manager
        .capture(bridge, NOW + 10)
        .unwrap_or_else(|error| panic!("capture bridge: {error}"));
    manager
        .deprecate("mem.c", NOW + 11)
        .unwrap_or_else(|error| panic!("deprecate member: {error}"));

    let mut query = ordinary("project-a", "bridge-query-marker");
    query.mode = MemoryQueryMode::Conflict;
    let mut retriever = MemoryRetriever::new(&mut manager);
    let result = retriever
        .retrieve(&query, NOW + 11)
        .unwrap_or_else(|error| panic!("retrieve merged conflict: {error}"));
    assert_eq!(result.conflicts.len(), 1);
    let member_ids = result.conflicts[0]
        .member_handles
        .iter()
        .map(|handle| handle.memory_id.as_str())
        .collect::<BTreeSet<_>>();
    assert!(member_ids.contains("mem.bridge"));
    assert!(!member_ids.contains("mem.c"));
    assert!(member_ids.len() >= 2);
}

#[test]
fn retrieval_graph_expansion_requires_anchor_and_is_hard_bounded() {
    let (_temp, mut manager) = manager("graph-bound");
    for index in 0..24 {
        manager
            .capture(
                record(
                    &format!("mem.graph.{index:02}"),
                    "project-a",
                    MemoryKind::Episodic,
                    MemoryTrust::Observed,
                    &format!("graph-subject-{index}"),
                    "graph relation",
                ),
                NOW,
            )
            .unwrap_or_else(|error| panic!("capture graph: {error}"));
    }
    let mut retriever = MemoryRetriever::new(&mut manager);
    let access = MemoryAccessScope {
        project_id: "project-a",
        repository_id: None,
        agent_id: None,
        role_id: None,
    };
    assert!(retriever.graph_neighborhood(access, None, 3, NOW).is_err());
    let neighborhood = retriever
        .graph_neighborhood(access, Some("mem.graph.00"), 3, NOW)
        .unwrap_or_else(|error| panic!("graph: {error}"));
    assert_eq!(neighborhood.anchor.memory_id, "mem.graph.00");
    assert_eq!(neighborhood.limit, 3);
    assert_eq!(neighborhood.neighbors.len(), 3);
    assert!(neighborhood.observed_neighbors > neighborhood.limit);
    assert!(neighborhood.truncated);
}

#[test]
fn retrieval_repository_delta_invalidates_only_the_exact_old_digest() {
    let (_temp, mut manager) = manager("delta-old-digest");
    for (id, digest) in [("mem.old", "sha256:old"), ("mem.other", "sha256:other")] {
        manager
            .capture(
                repository_record(
                    id,
                    "project-a",
                    "repo-a",
                    id,
                    "digestmarker",
                    "same.rs",
                    digest,
                ),
                NOW,
            )
            .unwrap_or_else(|error| panic!("capture: {error}"));
    }
    let stale = manager
        .apply_repository_delta(
            &MemoryRepositoryDelta {
                repository_id: "repo-a".to_owned(),
                current_revision: None,
                changed_fingerprints: vec![FingerprintChange {
                    kind: SourceFingerprintKind::FileBlob,
                    key: "same.rs".to_owned(),
                    old_digest: Some("sha256:old".to_owned()),
                    new_digest: Some("sha256:new".to_owned()),
                }],
            },
            NOW + 1,
        )
        .unwrap_or_else(|error| panic!("delta: {error}"));
    assert_eq!(stale, vec!["mem.old"]);
    assert_eq!(
        manager
            .record("mem.other")
            .unwrap_or_else(|error| panic!("read other: {error}"))
            .unwrap_or_else(|| panic!("other missing"))
            .status,
        MemoryStatus::Active
    );
}
