use rusqlite::Connection;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sovereign_eval::{
    COMPATIBILITY_SUITE_SCHEMA_VERSION, CompatibilityCaseV1, MigrationCompatibilitySuite,
    ProviderConformanceSuite,
};
use sovereign_memory::{MemoryManager, MemoryStatus, SourceFingerprintKind};
use sovereign_model::{
    DeterministicFakeBackend, MODEL_SCHEMA_VERSION, ModelBackend, ModelCapabilities,
    ModelFinishReason, ModelLoadProfile, ModelMessage, ModelMessageRole, ModelOutputContract,
    ModelRequest, ModelResidencyProof, ModelResponse, ModelUsage,
};
use sovereign_plan::{CompilationEvidence, PlanIr, PlanValidator, ValidationEnvironment};
use sovereign_repo::{
    DependencyGraph, IndexConfig, LexicalQuery, LexicalRetriever, ProjectRegistry,
    RepositoryIntelligence, StructuralConfig, StructuralIndex, SymbolIndex,
};
use sovereign_state::{
    CURRENT_SCHEMA_VERSION, MIGRATIONS, Migration, MigrationRunner, StateError, StateStore,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const NOW: i64 = 1_800_000_000_000;
const ARTIFACT_DIGEST: &str =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111";

struct TestDir(PathBuf);

impl TestDir {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "sovereign-upgrade-compat-{label}-{}-{nonce}",
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

fn current_plan_json() -> &'static str {
    include_str!("../../sovereign-plan/tests/fixtures/valid_trivial_plan.json")
}

fn assert_valid_current_plan(raw: &str) {
    let plan = PlanIr::from_slice(raw.as_bytes())
        .unwrap_or_else(|error| panic!("parse current Plan IR: {error}"));
    let validator = PlanValidator::new(ValidationEnvironment::default())
        .unwrap_or_else(|error| panic!("build Plan IR validator: {error}"));
    let diagnostics = validator.validate(&plan);
    assert!(
        diagnostics.is_empty(),
        "current Plan IR rejected: {diagnostics:?}"
    );
}

fn canonical_json(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries = map.iter().collect::<Vec<_>>();
            entries.sort_by(|(left, _), (right, _)| left.cmp(right));
            let mut canonical = serde_json::Map::new();
            for (key, value) in entries {
                canonical.insert(key.clone(), canonical_json(value));
            }
            Value::Object(canonical)
        }
        Value::Array(values) => Value::Array(values.iter().map(canonical_json).collect()),
        other => other.clone(),
    }
}

fn canonical_json_digest(value: &Value) -> String {
    let bytes = serde_json::to_vec(&canonical_json(value))
        .unwrap_or_else(|error| panic!("canonical json: {error}"));
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn git_fixture(root: &Path, args: &[&str]) {
    let status = Command::new("/usr/bin/git")
        .current_dir(root)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
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
        .unwrap_or_else(|error| panic!("git {args:?}: {error}"));
    assert!(status.success());
}

fn initialize_projection_repository(root: &Path) {
    fs::create_dir_all(root.join("src"))
        .unwrap_or_else(|error| panic!("create projection repo: {error}"));
    git_fixture(root, &["init", "-q"]);
    fs::write(
        root.join("src/lib.rs"),
        "mod service;\npub fn compatibility_root() { /* compatneedle */ }\n",
    )
    .unwrap_or_else(|error| panic!("write lib: {error}"));
    fs::write(
        root.join("src/service.rs"),
        "use crate::util::helper;\npub struct CompatService;\npub fn run(){ helper(); }\n",
    )
    .unwrap_or_else(|error| panic!("write service: {error}"));
    fs::write(root.join("src/util.rs"), "pub fn helper() {}\n")
        .unwrap_or_else(|error| panic!("write util: {error}"));
    fs::write(root.join("README.md"), "compatneedle projection fixture\n")
        .unwrap_or_else(|error| panic!("write readme: {error}"));
    git_fixture(root, &["add", "."]);
    git_fixture(root, &["commit", "-q", "-m", "fixture"]);
}

fn fake_capabilities(model_id: &str) -> ModelCapabilities {
    ModelCapabilities {
        schema_version: MODEL_SCHEMA_VERSION,
        model_id: model_id.to_owned(),
        parameter_class: "fixture".to_owned(),
        quantization: "fixture".to_owned(),
        max_context_tokens: 16_384,
        supports_tools: false,
        supports_json_schema: true,
        local: true,
    }
}

fn fake_profile() -> ModelLoadProfile {
    ModelLoadProfile {
        context_tokens: 4_096,
        output_reserve_tokens: 512,
        startup_timeout_ms: 1_000,
        provider_call_timeout_ms: 500,
    }
}

fn fake_request(request_id: &str) -> ModelRequest {
    ModelRequest {
        schema_version: MODEL_SCHEMA_VERSION,
        request_id: request_id.to_owned(),
        messages: vec![ModelMessage {
            role: ModelMessageRole::User,
            content: "Return the compatibility result.".to_owned(),
            tool_call_id: None,
        }],
        tools: Vec::new(),
        output_contract: ModelOutputContract::JsonSchema {
            name: "compatibility".to_owned(),
            schema: json!({
                "type": "object",
                "required": ["ok"],
                "additionalProperties": false,
                "properties": {"ok": {"type": "boolean"}}
            }),
        },
        input_token_ceiling: 4_096,
        max_output_tokens: 128,
        deadline_ms: 500,
        temperature_milli: 0,
    }
}

fn fake_response() -> ModelResponse {
    ModelResponse {
        schema_version: MODEL_SCHEMA_VERSION,
        request_id: "template".to_owned(),
        content: "{\"ok\":true}".to_owned(),
        structured: None,
        tool_calls: Vec::new(),
        finish_reason: ModelFinishReason::Stop,
        usage: ModelUsage {
            input_tokens: 12,
            output_tokens: 4,
        },
        elapsed_ms: 1,
        peak_rss_kb_during_call: None,
    }
}

fn migration_report(case_ids: &[&str]) -> MigrationCompatibilitySuite {
    MigrationCompatibilitySuite {
        schema_version: COMPATIBILITY_SUITE_SCHEMA_VERSION,
        cases: case_ids
            .iter()
            .map(|case_id| CompatibilityCaseV1 {
                case_id: (*case_id).to_owned(),
                passed: true,
            })
            .collect(),
    }
}

struct HistoricalControllerFixture {
    plan: &'static str,
    plan_digest: String,
    evidence: String,
    revision_key: &'static str,
    revision_record: String,
    compilation_evidence_raw: String,
}

fn historical_controller_fixture() -> HistoricalControllerFixture {
    let plan = current_plan_json();
    let plan_value: Value =
        serde_json::from_str(plan).unwrap_or_else(|error| panic!("parse plan fixture: {error}"));
    let plan_digest = PlanIr::from_value(plan_value.clone())
        .canonical_digest()
        .unwrap_or_else(|error| panic!("plan digest: {error}"));
    let compilation_evidence = json!({
        "schema": "sovereign-plan-compilation-evidence-v1",
        "compilation_id": "compilation.compat",
        "compiler_version": "fixture-1",
        "context_packet_digest": format!("sha256:{}", "c".repeat(64)),
        "exact_evidence": [],
        "model_attempts": [{
            "attempt": 1,
            "request_digest": format!("sha256:{}", "a".repeat(64)),
            "response_digest": format!("sha256:{}", "b".repeat(64)),
            "accepted": true,
            "rejection_reason": null,
        }],
        "validator_passed": true,
        "plan_digest": plan_digest,
    });
    let compilation_evidence_digest = canonical_json_digest(&compilation_evidence);
    let revision_record = json!({
        "plan_id": "plan.fixture-trivial",
        "revision": 1,
        "plan_digest": plan_digest,
        "compilation_evidence_digest": compilation_evidence_digest,
        "plan_document": plan_value,
    })
    .to_string();
    HistoricalControllerFixture {
        plan,
        plan_digest,
        evidence: json!({
            "schema_version": 1,
            "evidence_id": "evidence.compat",
            "kind": "fixture",
            "digest": ARTIFACT_DIGEST
        })
        .to_string(),
        revision_key: "plan.fixture-trivial@r1",
        revision_record,
        compilation_evidence_raw: compilation_evidence.to_string(),
    }
}

fn seed_historical_controller_fixture(db: &Path, fixture: &HistoricalControllerFixture) {
    let mut connection = Connection::open(db).unwrap_or_else(|error| panic!("open v3: {error}"));
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .unwrap_or_else(|error| panic!("foreign keys: {error}"));
    MigrationRunner::apply(&mut connection, &MIGRATIONS[..3])
        .unwrap_or_else(|error| panic!("apply v3 fixture: {error}"));
    for (namespace, record_key, value) in [
        ("controller.plan_document", "active", fixture.plan),
        (
            "controller.evidence_item",
            "evidence.compat",
            fixture.evidence.as_str(),
        ),
        (
            "controller.plan_revision",
            fixture.revision_key,
            fixture.revision_record.as_str(),
        ),
        (
            "controller.compilation_evidence",
            fixture.revision_key,
            fixture.compilation_evidence_raw.as_str(),
        ),
    ] {
        connection
            .execute(
                "INSERT INTO state_records(namespace, record_key, value_json, version, updated_at_ms) VALUES (?1, ?2, ?3, 1, ?4)",
                (namespace, record_key, value, NOW),
            )
            .unwrap_or_else(|error| panic!("seed {namespace}/{record_key}: {error}"));
    }
    connection
        .execute(
            "INSERT INTO artifact_metadata(digest, size_bytes, created_at_ms) VALUES (?1, 4, ?2)",
            (ARTIFACT_DIGEST, NOW),
        )
        .unwrap_or_else(|error| panic!("seed artifact: {error}"));
    connection
        .execute(
            "INSERT INTO artifact_references(reference_id, digest, created_at_ms) VALUES ('evidence.compat', ?1, ?2)",
            (ARTIFACT_DIGEST, NOW),
        )
        .unwrap_or_else(|error| panic!("seed artifact reference: {error}"));
}

fn assert_historical_controller_fixture(store: &StateStore, fixture: &HistoricalControllerFixture) {
    assert_eq!(store.schema_version().unwrap_or(-1), CURRENT_SCHEMA_VERSION);
    let upgraded_plan = store
        .get_state("controller.plan_document", "active")
        .unwrap_or_else(|error| panic!("read plan: {error}"))
        .unwrap_or_else(|| panic!("plan orphaned by upgrade"));
    let upgraded_evidence = store
        .get_state("controller.evidence_item", "evidence.compat")
        .unwrap_or_else(|error| panic!("read evidence: {error}"))
        .unwrap_or_else(|| panic!("evidence orphaned by upgrade"));
    let upgraded_revision = store
        .get_state("controller.plan_revision", fixture.revision_key)
        .unwrap_or_else(|error| panic!("read historical revision: {error}"))
        .unwrap_or_else(|| panic!("historical plan revision orphaned by upgrade"));
    let upgraded_compilation_evidence = store
        .get_state("controller.compilation_evidence", fixture.revision_key)
        .unwrap_or_else(|error| panic!("read compilation evidence: {error}"))
        .unwrap_or_else(|| panic!("compilation evidence orphaned by upgrade"));
    assert_eq!(upgraded_plan, fixture.plan);
    assert_eq!(upgraded_evidence, fixture.evidence);
    assert_eq!(upgraded_revision, fixture.revision_record);
    assert_eq!(
        upgraded_compilation_evidence,
        fixture.compilation_evidence_raw
    );

    let revision_value: Value = serde_json::from_str(&upgraded_revision)
        .unwrap_or_else(|error| panic!("decode historical revision: {error}"));
    assert_eq!(
        fixture.revision_key,
        format!(
            "{}@r{}",
            revision_value["plan_id"].as_str().unwrap_or_default(),
            revision_value["revision"].as_u64().unwrap_or_default()
        )
    );
    let revision_plan = revision_value
        .get("plan_document")
        .cloned()
        .unwrap_or_else(|| panic!("historical revision lost plan document"));
    assert_eq!(
        PlanIr::from_value(revision_plan)
            .canonical_digest()
            .unwrap_or_else(|error| panic!("historical plan digest: {error}")),
        revision_value["plan_digest"].as_str().unwrap_or_default()
    );

    let compilation_value: Value = serde_json::from_str(&upgraded_compilation_evidence)
        .unwrap_or_else(|error| panic!("decode compilation evidence: {error}"));
    let typed_compilation: CompilationEvidence = serde_json::from_value(compilation_value.clone())
        .unwrap_or_else(|error| panic!("decode typed compilation evidence: {error}"));
    assert!(typed_compilation.validator_passed());
    assert_eq!(typed_compilation.plan_digest(), fixture.plan_digest);
    assert_eq!(typed_compilation.compiler_version(), "fixture-1");
    assert_eq!(typed_compilation.model_attempts().len(), 1);
    assert!(typed_compilation.model_attempts()[0].accepted);
    assert_eq!(
        typed_compilation.plan_digest(),
        revision_value["plan_digest"].as_str().unwrap_or_default()
    );
    assert_eq!(
        canonical_json_digest(&compilation_value),
        revision_value["compilation_evidence_digest"]
            .as_str()
            .unwrap_or_default()
    );
    assert!(
        store
            .artifact_reference_exists("evidence.compat", ARTIFACT_DIGEST)
            .unwrap_or(false)
    );
    assert!(
        store
            .artifact_metadata(ARTIFACT_DIGEST)
            .unwrap_or(None)
            .is_some()
    );
    assert_valid_current_plan(&upgraded_plan);
}

#[test]
fn old_database_upgrade_preserves_plan_evidence_and_artifact_reference() {
    let temp = TestDir::new("old-db");
    let db = temp.db();
    let fixture = historical_controller_fixture();
    seed_historical_controller_fixture(&db, &fixture);
    let store = StateStore::open(&db).unwrap_or_else(|error| panic!("upgrade old db: {error}"));
    assert_historical_controller_fixture(&store, &fixture);
    migration_report(&[
        "old_database_plan_evidence_artifact_preserved",
        "historical_plan_revision_and_compilation_evidence_preserved",
    ])
    .validate()
    .unwrap_or_else(|error| panic!("migration report: {error}"));
}

#[test]
fn unsupported_future_plan_version_fails_closed_without_synthesizing_authority() {
    let validator = PlanValidator::new(ValidationEnvironment::default())
        .unwrap_or_else(|error| panic!("validator: {error}"));
    let current: Value = serde_json::from_str(current_plan_json())
        .unwrap_or_else(|error| panic!("parse fixture: {error}"));
    assert!(
        validator
            .validate(&PlanIr::from_value(current.clone()))
            .is_empty()
    );

    let mut candidate = current;
    candidate["ir_version"] = json!("9.9");
    let diagnostics = validator.validate(&PlanIr::from_value(candidate));
    assert!(
        diagnostics
            .iter()
            .any(|diagnostic| diagnostic.path == "/ir_version"),
        "unsupported future Plan IR must fail structurally: {diagnostics:?}"
    );

    migration_report(&["unsupported_future_plan_ir_rejected_without_synthesis"])
        .validate()
        .unwrap_or_else(|error| panic!("migration report: {error}"));
}

#[test]
fn future_state_schema_is_rejected_without_mutating_canonical_state() {
    let temp = TestDir::new("future-schema");
    let db = temp.db();
    let mut store = StateStore::open(&db).unwrap_or_else(|error| panic!("open: {error}"));
    store
        .put_state("fixture", "preserved", "{\"value\":1}")
        .unwrap_or_else(|error| panic!("seed: {error}"));
    store
        .checkpoint_wal()
        .unwrap_or_else(|error| panic!("checkpoint: {error}"));
    drop(store);

    let connection = Connection::open(&db).unwrap_or_else(|error| panic!("raw open: {error}"));
    connection
        .execute(
            "INSERT INTO schema_migrations(version, name, checksum, applied_at_ms) VALUES (?1, 'future', 'future', ?2)",
            (CURRENT_SCHEMA_VERSION + 1, NOW),
        )
        .unwrap_or_else(|error| panic!("seed future schema: {error}"));
    drop(connection);

    let error = StateStore::open(&db)
        .err()
        .unwrap_or_else(|| panic!("future schema unexpectedly accepted"));
    assert!(matches!(
        error,
        StateError::UnsupportedSchemaVersion { found, supported }
            if found == CURRENT_SCHEMA_VERSION + 1 && supported == CURRENT_SCHEMA_VERSION
    ));
    let observer = Connection::open(&db).unwrap_or_else(|error| panic!("observe: {error}"));
    let preserved: String = observer
        .query_row(
            "SELECT value_json FROM state_records WHERE namespace='fixture' AND record_key='preserved'",
            [],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("read preserved: {error}"));
    assert_eq!(preserved, "{\"value\":1}");
}

#[test]
fn failed_numbered_migration_rolls_back_and_backup_stays_readable() {
    const BROKEN: Migration = Migration {
        version: CURRENT_SCHEMA_VERSION + 1,
        name: "upgrade_compat_broken",
        sql: "CREATE TABLE upgrade_partial(value TEXT); INSERT INTO definitely_missing_table VALUES (1);",
    };

    let temp = TestDir::new("rollback");
    let db = temp.db();
    let backup = temp.0.join("backup.sqlite3");
    let mut store = StateStore::open(&db).unwrap_or_else(|error| panic!("open: {error}"));
    store
        .put_state("fixture", "before-failure", "{\"ok\":true}")
        .unwrap_or_else(|error| panic!("seed: {error}"));
    store
        .checkpoint_wal()
        .unwrap_or_else(|error| panic!("checkpoint: {error}"));
    drop(store);
    fs::copy(&db, &backup).unwrap_or_else(|error| panic!("backup: {error}"));

    let mut connection = Connection::open(&db).unwrap_or_else(|error| panic!("raw open: {error}"));
    let mut migrations = MIGRATIONS.to_vec();
    migrations.push(BROKEN);
    assert!(MigrationRunner::apply(&mut connection, &migrations).is_err());
    let partial: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='upgrade_partial'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(-1);
    assert_eq!(partial, 0);
    drop(connection);

    for path in [&db, &backup] {
        let readable = StateStore::open(path)
            .unwrap_or_else(|error| panic!("readable {}: {error}", path.display()));
        assert_eq!(
            readable
                .get_state("fixture", "before-failure")
                .unwrap_or_default(),
            Some("{\"ok\":true}".to_owned())
        );
    }
}

fn seed_v4_memory_compatibility_fixture(connection: &Connection) {
    connection
        .execute_batch(
            "INSERT INTO memory_conflict_sets(
                 conflict_set_id, project_id, repository_id, subject, predicate, created_at_ms, resolved_at_ms
             ) VALUES ('conflict.compat', 'project.compat', 'repo.app', 'database', 'has_value', 1800000000002, NULL);

             INSERT INTO memory_records(
                 memory_id, kind, project_id, scope_kind, agent_id, subject, predicate, assertion,
                 trust, confidence, status, repository_id, repository_revision, producing_task_id,
                 producing_attempt_id, created_at_ms, updated_at_ms, validated_at_ms, version,
                 supersedes_id, superseded_by_id, expires_at_ms, access_count, last_accessed_at_ms,
                 conflict_set_id, normal_injection, exclusion_reason
             ) VALUES
             ('mem.governed.v1', 'governed_knowledge', 'project.compat', 'project', NULL,
              'release-policy', 'has_value', 'local-only', 'governed', 0.90, 'superseded', NULL, NULL,
              'task.compat', 'attempt.compat', 1800000000000, 1800000000000, NULL, 1,
              NULL, NULL, NULL, 0, NULL, NULL, 1, NULL),
             ('mem.governed.v2', 'governed_knowledge', 'project.compat', 'project', NULL,
              'release-policy', 'has_value', 'local-only-signed', 'governed', 0.90, 'active', NULL, NULL,
              'task.compat', 'attempt.compat', 1800000000001, 1800000000001, NULL, 2,
              'mem.governed.v1', NULL, NULL, 0, NULL, NULL, 1, NULL),
             ('mem.fact.left', 'validated_project_fact', 'project.compat', 'project', NULL,
              'database', 'has_value', 'sqlite', 'validated', 0.90, 'active', 'repo.app', 'rev.compat',
              'task.compat', 'attempt.compat', 1800000000002, 1800000000002, 1800000000002, 1,
              NULL, NULL, NULL, 0, NULL, 'conflict.compat', 1, NULL),
             ('mem.fact.right', 'validated_project_fact', 'project.compat', 'project', NULL,
              'database', 'has_value', 'postgres', 'validated', 0.90, 'active', 'repo.app', 'rev.compat',
              'task.compat', 'attempt.compat', 1800000000003, 1800000000003, 1800000000003, 1,
              NULL, NULL, NULL, 0, NULL, 'conflict.compat', 1, NULL);

             UPDATE memory_records
             SET superseded_by_id='mem.governed.v2'
             WHERE memory_id='mem.governed.v1';

             INSERT INTO memory_source_evidence(memory_id, evidence_id) VALUES
             ('mem.governed.v1', 'evidence.governed.v1'),
             ('mem.governed.v2', 'evidence.governed.v2'),
             ('mem.fact.left', 'evidence.left'),
             ('mem.fact.right', 'evidence.right');

             INSERT INTO memory_source_fingerprints(
                 memory_id, fingerprint_kind, fingerprint_key, fingerprint_digest
             ) VALUES ('mem.fact.left', 'file_blob', 'src/lib.rs', 'sha256:compat');

             INSERT INTO memory_conflict_members(conflict_set_id, memory_id) VALUES
             ('conflict.compat', 'mem.fact.left'),
             ('conflict.compat', 'mem.fact.right');",
        )
        .unwrap_or_else(|error| panic!("seed v4 memory compatibility fixture: {error}"));
}

fn assert_migrated_memory_semantics(memory: &mut MemoryManager) {
    let old = memory
        .record("mem.governed.v1")
        .unwrap_or_else(|error| panic!("read governed v1: {error}"))
        .unwrap_or_else(|| panic!("governed v1 missing"));
    let new = memory
        .record("mem.governed.v2")
        .unwrap_or_else(|error| panic!("read governed v2: {error}"))
        .unwrap_or_else(|| panic!("governed v2 missing"));
    let left = memory
        .record("mem.fact.left")
        .unwrap_or_else(|error| panic!("read left fact: {error}"))
        .unwrap_or_else(|| panic!("left fact missing"));
    let conflict = memory
        .conflict_set("conflict.compat")
        .unwrap_or_else(|error| panic!("read conflict set: {error}"))
        .unwrap_or_else(|| panic!("conflict set missing"));

    assert_eq!(old.status, MemoryStatus::Superseded);
    assert_eq!(old.superseded_by.as_deref(), Some("mem.governed.v2"));
    assert_eq!(new.supersedes.as_deref(), Some("mem.governed.v1"));
    assert_eq!(new.lineage_id, "mem.governed.v1");
    assert_eq!(
        left.provenance.repository_revision.as_deref(),
        Some("rev.compat")
    );
    assert_eq!(
        left.provenance.source_evidence_ids,
        vec!["evidence.left".to_owned()]
    );
    assert_eq!(left.provenance.source_fingerprints.len(), 1);
    assert_eq!(
        left.provenance.source_fingerprints[0].kind,
        SourceFingerprintKind::FileBlob
    );
    assert_eq!(left.conflict_set_id.as_deref(), Some("conflict.compat"));
    assert_eq!(
        conflict.member_ids,
        vec!["mem.fact.left".to_owned(), "mem.fact.right".to_owned()]
    );
}

#[test]
fn memory_provenance_conflict_supersession_and_projection_rebuild_preserve_canonical_data() {
    let temp = TestDir::new("memory");
    let db = temp.db();
    let mut connection =
        Connection::open(&db).unwrap_or_else(|error| panic!("open v4 memory fixture: {error}"));
    MigrationRunner::apply(&mut connection, &MIGRATIONS[..4])
        .unwrap_or_else(|error| panic!("apply v4 memory schema: {error}"));
    seed_v4_memory_compatibility_fixture(&connection);
    MigrationRunner::apply(&mut connection, &MIGRATIONS[..5])
        .unwrap_or_else(|error| panic!("migrate compatibility memory to v5: {error}"));
    let v5_lineage: String = connection
        .query_row(
            "SELECT lineage_id FROM memory_records WHERE memory_id='mem.governed.v2'",
            [],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("read v5 lineage: {error}"));
    assert_eq!(v5_lineage, "mem.governed.v1");
    MigrationRunner::apply(&mut connection, MIGRATIONS)
        .unwrap_or_else(|error| panic!("migrate compatibility memory to current: {error}"));
    let queued: i64 = connection
        .query_row("SELECT COUNT(*) FROM memory_projection_outbox", [], |row| {
            row.get(0)
        })
        .unwrap_or(-1);
    let projection_rows: i64 = connection
        .query_row("SELECT COUNT(*) FROM memory_fts_projection", [], |row| {
            row.get(0)
        })
        .unwrap_or(-1);
    assert_eq!(queued, 4);
    assert_eq!(projection_rows, 0, "v6 must discard stale FTS rows");
    drop(connection);

    let mut memory =
        MemoryManager::open(&db).unwrap_or_else(|error| panic!("open migrated memory: {error}"));
    assert_migrated_memory_semantics(&mut memory);
    assert!(memory.projection_outbox().unwrap_or_default().is_empty());
    let observer = Connection::open(&db).unwrap_or_else(|error| panic!("observe FTS: {error}"));
    let rebuilt_rows: i64 = observer
        .query_row("SELECT COUNT(*) FROM memory_fts_projection", [], |row| {
            row.get(0)
        })
        .unwrap_or(-1);
    assert_eq!(
        rebuilt_rows, 4,
        "canonical memory must rebuild disposable FTS"
    );

    migration_report(&[
        "historical_memory_schema_and_outbox_migration_preserved",
        "memory_provenance_conflict_supersession_preserved",
        "disposable_projection_rebuilt_from_canonical_state",
    ])
    .validate()
    .unwrap_or_else(|error| panic!("migration report: {error}"));
}

fn assert_lexical_projection_rebuild(registry: &ProjectRegistry, db: &Path) {
    {
        let mut lexical =
            LexicalRetriever::open(registry, "repo.compat", db, IndexConfig::default())
                .unwrap_or_else(|error| panic!("open lexical projection: {error}"));
        lexical
            .rebuild()
            .unwrap_or_else(|error| panic!("initial lexical rebuild: {error}"));
    }
    let connection =
        Connection::open(db).unwrap_or_else(|error| panic!("open lexical db: {error}"));
    connection
        .execute(
            "UPDATE metadata SET value_int=0 WHERE key='schema_version'",
            [],
        )
        .unwrap_or_else(|error| panic!("invalidate lexical schema: {error}"));
    drop(connection);

    let mut lexical = LexicalRetriever::open(registry, "repo.compat", db, IndexConfig::default())
        .unwrap_or_else(|error| panic!("reopen lexical projection: {error}"));
    assert!(lexical.snapshot().unwrap_or_default().is_none());
    assert!(
        !lexical
            .search(&LexicalQuery {
                text: "compatneedle",
                max_hits: 8,
            })
            .unwrap_or_else(|error| panic!("search rebuilt lexical projection: {error}"))
            .is_empty()
    );
}

fn assert_structural_projection_rebuild(registry: &ProjectRegistry, db: &Path) {
    {
        let mut structural =
            StructuralIndex::open(registry, "repo.compat", db, StructuralConfig::default())
                .unwrap_or_else(|error| panic!("open structural projection: {error}"));
        structural
            .rebuild()
            .unwrap_or_else(|error| panic!("initial structural rebuild: {error}"));
    }
    let connection =
        Connection::open(db).unwrap_or_else(|error| panic!("open structural db: {error}"));
    connection
        .execute(
            "UPDATE structural_metadata SET value_text='sha256:incompatible' WHERE key='parser_fingerprint'",
            [],
        )
        .unwrap_or_else(|error| panic!("invalidate structural parser fingerprint: {error}"));
    drop(connection);

    let mut structural =
        StructuralIndex::open(registry, "repo.compat", db, StructuralConfig::default())
            .unwrap_or_else(|error| panic!("reopen structural projection: {error}"));
    assert!(structural.snapshot().unwrap_or_default().is_none());
    assert_eq!(
        structural
            .definitions("CompatService")
            .unwrap_or_else(|error| panic!("rebuild symbol projection: {error}"))
            .len(),
        1
    );
    assert!(
        structural
            .import_neighborhood(Path::new("src/service.rs"))
            .unwrap_or_else(|error| panic!("rebuild dependency projection: {error}"))
            .iter()
            .any(|edge| edge.target.contains("crate::util::helper"))
    );
}

#[test]
fn lexical_symbol_and_dependency_projections_rebuild_without_mutating_source_or_canonical_state() {
    let temp = TestDir::new("repo-projections");
    let repo_root = temp.0.join("repo");
    let lexical_db = temp.0.join("lexical.sqlite3");
    let structural_db = temp.0.join("structural.sqlite3");
    let canonical_db = temp.0.join("canonical.sqlite3");
    initialize_projection_repository(&repo_root);

    let mut registry = ProjectRegistry::new();
    registry
        .register("repo.compat", &repo_root)
        .unwrap_or_else(|error| panic!("register projection repo: {error}"));
    let source_before = fs::read(repo_root.join("src/service.rs"))
        .unwrap_or_else(|error| panic!("read source before rebuilds: {error}"));
    let snapshot_before = registry
        .snapshot("repo.compat")
        .unwrap_or_else(|error| panic!("snapshot before rebuilds: {error}"));
    let mut canonical =
        StateStore::open(&canonical_db).unwrap_or_else(|error| panic!("canonical state: {error}"));
    canonical
        .put_state("fixture", "canonical", "{\"value\":\"preserved\"}")
        .unwrap_or_else(|error| panic!("seed canonical state: {error}"));

    assert_lexical_projection_rebuild(&registry, &lexical_db);
    assert_structural_projection_rebuild(&registry, &structural_db);

    assert_eq!(
        canonical
            .get_state("fixture", "canonical")
            .unwrap_or_default(),
        Some("{\"value\":\"preserved\"}".to_owned())
    );
    assert_eq!(
        fs::read(repo_root.join("src/service.rs")).unwrap_or_default(),
        source_before
    );
    assert_eq!(
        registry
            .snapshot("repo.compat")
            .unwrap_or_else(|error| panic!("snapshot after rebuilds: {error}")),
        snapshot_before
    );

    migration_report(&[
        "lexical_projection_rebuilt_from_repository_truth",
        "symbol_dependency_projection_rebuilt_from_repository_truth",
        "derived_projection_rebuild_preserves_canonical_and_source_truth",
    ])
    .validate()
    .unwrap_or_else(|error| panic!("projection migration report: {error}"));
}

#[test]
fn optional_adapter_absence_leaves_core_durable_state_valid() {
    let temp = TestDir::new("optional-adapter-absent");
    let db = temp.db();
    {
        let mut store = StateStore::open(&db).unwrap_or_else(|error| panic!("open: {error}"));
        store
            .put_state("fixture", "core", "{\"adapter\":\"absent\"}")
            .unwrap_or_else(|error| panic!("seed core state: {error}"));
    }
    let reopened = StateStore::open(&db).unwrap_or_else(|error| panic!("reopen: {error}"));
    assert_eq!(
        reopened.schema_version().unwrap_or(-1),
        CURRENT_SCHEMA_VERSION
    );
    assert_eq!(
        reopened.get_state("fixture", "core").unwrap_or_default(),
        Some("{\"adapter\":\"absent\"}".to_owned())
    );
    assert_valid_current_plan(current_plan_json());
}

#[derive(Debug, PartialEq)]
struct ProviderVisibleSemantics {
    content: String,
    structured: Option<Value>,
    tool_calls: Vec<sovereign_model::ModelToolCall>,
    finish_reason: ModelFinishReason,
    usage: ModelUsage,
    token_count: u32,
}

fn provider_visible_semantics(model_id: &str) -> ProviderVisibleSemantics {
    let backend = DeterministicFakeBackend::new(fake_capabilities(model_id), vec![fake_response()])
        .unwrap_or_else(|error| panic!("fake backend {model_id}: {error}"));
    assert!(
        !backend
            .health()
            .unwrap_or_else(|error| panic!("health: {error}"))
            .loaded
    );
    backend
        .load(fake_profile())
        .unwrap_or_else(|error| panic!("load {model_id}: {error}"));
    let token_count = backend
        .count_tokens("same provider-neutral content")
        .unwrap_or_else(|error| panic!("count tokens {model_id}: {error}"));
    let response = backend
        .complete(&fake_request("request.compat"))
        .unwrap_or_else(|error| panic!("complete {model_id}: {error}"));
    backend
        .unload()
        .unwrap_or_else(|error| panic!("unload {model_id}: {error}"));
    assert_eq!(
        backend
            .residency_proof()
            .unwrap_or_else(|error| panic!("residency {model_id}: {error}")),
        ModelResidencyProof::Absent
    );
    ProviderVisibleSemantics {
        content: response.content,
        structured: response.structured,
        tool_calls: response.tool_calls,
        finish_reason: response.finish_reason,
        usage: response.usage,
        token_count,
    }
}

#[test]
fn provider_swap_preserves_normalized_controller_visible_semantics() {
    let first = provider_visible_semantics("provider-a");
    let second = provider_visible_semantics("provider-b");
    assert_eq!(first, second);

    ProviderConformanceSuite {
        schema_version: COMPATIBILITY_SUITE_SCHEMA_VERSION,
        cases: vec![CompatibilityCaseV1 {
            case_id: "provider_swap_normalized_semantics".to_owned(),
            passed: true,
        }],
    }
    .validate()
    .unwrap_or_else(|error| panic!("provider report: {error}"));
}

#[test]
fn compatibility_report_schema_is_fail_closed() {
    let mut migration = migration_report(&["case.a"]);
    migration.schema_version = COMPATIBILITY_SUITE_SCHEMA_VERSION + 1;
    assert!(migration.validate().is_err());

    let provider = ProviderConformanceSuite {
        schema_version: COMPATIBILITY_SUITE_SCHEMA_VERSION,
        cases: vec![
            CompatibilityCaseV1 {
                case_id: "duplicate".to_owned(),
                passed: true,
            },
            CompatibilityCaseV1 {
                case_id: "duplicate".to_owned(),
                passed: true,
            },
        ],
    };
    assert!(provider.validate().is_err());
}
