use sovereign_context::{
    Channel, ChannelResult, ContextLevel, DiffResult, EvidenceKind, MemoryHistoryProvider,
    PacketSection, RetrievalBackend, RetrievalIntent, RetrievalRouter, StopCondition, TrustClass,
    TrustLevel, TrustSource,
};
use sovereign_memory::{
    MemoryKind, MemoryLifecycle, MemoryManager, MemoryProvenance, MemoryScope, MemoryScopeKind,
    MemoryTrust, NewMemoryRecord, SourceFingerprint, SourceFingerprintKind,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const NOW: i64 = 1_800_000_000_000;

struct TestDir(PathBuf);

impl TestDir {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "sovereign-context-memory-{label}-{}-{nonce}",
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

#[derive(Default)]
struct NeverRepositoryBackend {
    calls: usize,
}

impl NeverRepositoryBackend {
    fn unexpected(&mut self) -> ChannelResult {
        self.calls = self.calls.saturating_add(1);
        ChannelResult::empty()
    }
}

impl RetrievalBackend for NeverRepositoryBackend {
    type Error = String;

    fn current_diff(&mut self, _repository_id: &str) -> Result<DiffResult, Self::Error> {
        Ok(DiffResult {
            evidence: self.unexpected(),
            touched_paths: Vec::new(),
        })
    }

    fn exact_path(
        &mut self,
        _repository_id: &str,
        _path: &Path,
    ) -> Result<ChannelResult, Self::Error> {
        Ok(self.unexpected())
    }

    fn exact_literal(
        &mut self,
        _repository_id: &str,
        _literal: &str,
    ) -> Result<ChannelResult, Self::Error> {
        Ok(self.unexpected())
    }

    fn lexical(
        &mut self,
        _repository_id: &str,
        _query: &str,
    ) -> Result<ChannelResult, Self::Error> {
        Ok(self.unexpected())
    }

    fn symbol(
        &mut self,
        _repository_id: &str,
        _symbol: &str,
    ) -> Result<ChannelResult, Self::Error> {
        Ok(self.unexpected())
    }

    fn symbols_for_path(
        &mut self,
        _repository_id: &str,
        _path: &Path,
    ) -> Result<ChannelResult, Self::Error> {
        Ok(self.unexpected())
    }

    fn structural(
        &mut self,
        _repository_id: &str,
        _anchor: &Path,
    ) -> Result<ChannelResult, Self::Error> {
        Ok(self.unexpected())
    }
}

fn episode(id: &str, signature: &str, assertion: &str, roles: Vec<String>) -> NewMemoryRecord {
    NewMemoryRecord {
        id: id.to_owned(),
        kind: MemoryKind::Episodic,
        scope: MemoryScope {
            project_id: "project-a".to_owned(),
            repository_id: Some("repo-a".to_owned()),
            kind: MemoryScopeKind::Project,
            agent_id: None,
            role_visibility: roles,
        },
        subject: signature.to_owned(),
        predicate: "compile".to_owned(),
        conflict_key: format!("failure:{signature}"),
        assertion: assertion.to_owned(),
        trust: MemoryTrust::Observed,
        confidence: 85,
        provenance: MemoryProvenance {
            source_evidence_ids: vec![format!("evidence.{id}")],
            producing_task_id: Some("task.compile".to_owned()),
            producing_attempt_id: Some("attempt.1".to_owned()),
            repository_revision: Some("rev-a".to_owned()),
            source_fingerprints: vec![
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
            ],
        },
        expires_at_ms: None,
        invalidation_predicates: Vec::new(),
    }
}

fn history_intent(signature: &str, fallback: &str) -> RetrievalIntent {
    RetrievalIntent::FailureHistory {
        repository_id: "repo-a".to_owned(),
        normalized_signature: signature.to_owned(),
        tool: "rustc".to_owned(),
        symbol: Some("compile_target".to_owned()),
        text_fallback: fallback.to_owned(),
    }
}

#[test]
fn memory_history_exact_episode_enters_context_as_derived_c3_evidence_only() {
    let temp = TestDir::new("exact");
    let mut manager =
        MemoryManager::open(temp.db()).unwrap_or_else(|error| panic!("open: {error}"));
    let stored = manager
        .capture(
            episode(
                "mem.failure.exact",
                "error-e0425-cannot-find-value",
                "previous verified repair used the missing import",
                Vec::new(),
            ),
            NOW,
        )
        .unwrap_or_else(|error| panic!("capture: {error}"));
    let mut provider =
        MemoryHistoryProvider::new(&mut manager, "project-a", None, None, NOW, |error| {
            error.to_string()
        });
    let mut backend = NeverRepositoryBackend::default();
    let outcome = RetrievalRouter
        .route_with_history(
            &mut backend,
            &history_intent("error-e0425-cannot-find-value", "missing import"),
            Some(&mut provider),
        )
        .unwrap_or_else(|error| panic!("route: {error}"));

    assert_eq!(backend.calls, 0);
    assert_eq!(outcome.trace.route.len(), 1);
    assert_eq!(outcome.trace.route[0].channel, Channel::History);
    assert_eq!(outcome.trace.stop_reason, StopCondition::Satisfied);
    let item = outcome
        .evidence
        .first()
        .unwrap_or_else(|| panic!("missing memory evidence"));
    assert_eq!(item.section, PacketSection::RoutedExpansion);
    assert_eq!(item.level, ContextLevel::C3);
    assert_eq!(item.kind, EvidenceKind::FailureSynopsis);
    assert_eq!(item.trust_class, TrustClass::Derived);
    assert_eq!(item.trust_label.source, TrustSource::Memory);
    assert_eq!(item.trust_label.level, TrustLevel::Untrusted);
    assert_eq!(item.repository_id.as_deref(), Some("repo-a"));
    assert_eq!(item.source_digest, stored.content_digest);
    assert!(item.source_uri.starts_with("memory://"));
    assert!(item.routing_reason.contains("evidence only"));
    let handle = item
        .expansion_handle
        .as_ref()
        .unwrap_or_else(|| panic!("missing expansion handle"));
    assert_eq!(handle.source_digest, item.source_digest);
}

#[test]
fn memory_history_router_runs_exact_key_before_lexical_fallback() {
    let temp = TestDir::new("fallback");
    let mut manager =
        MemoryManager::open(temp.db()).unwrap_or_else(|error| panic!("open: {error}"));
    manager
        .capture(
            episode(
                "mem.failure.lexical",
                "different-signature",
                "fallbackmarker prior compile episode",
                Vec::new(),
            ),
            NOW,
        )
        .unwrap_or_else(|error| panic!("capture: {error}"));
    let mut provider =
        MemoryHistoryProvider::new(&mut manager, "project-a", None, None, NOW, |error| {
            error.to_string()
        });
    let mut backend = NeverRepositoryBackend::default();
    let outcome = RetrievalRouter
        .route_with_history(
            &mut backend,
            &history_intent("missing-signature", "fallbackmarker"),
            Some(&mut provider),
        )
        .unwrap_or_else(|error| panic!("route: {error}"));

    assert_eq!(backend.calls, 0);
    assert_eq!(outcome.trace.route.len(), 2);
    assert!(
        outcome
            .trace
            .route
            .iter()
            .all(|step| step.channel == Channel::History)
    );
    assert_eq!(outcome.trace.stop_reason, StopCondition::Satisfied);
    assert_eq!(outcome.evidence.len(), 1);
}

#[test]
fn memory_history_preserves_role_visibility_fail_closed() {
    let temp = TestDir::new("role-scope");
    let mut manager =
        MemoryManager::open(temp.db()).unwrap_or_else(|error| panic!("open: {error}"));
    manager
        .capture(
            episode(
                "mem.failure.role",
                "role-scoped-signature",
                "rolemarker repair",
                vec!["implementer".to_owned()],
            ),
            NOW,
        )
        .unwrap_or_else(|error| panic!("capture: {error}"));
    let mut backend = NeverRepositoryBackend::default();
    {
        let mut denied = MemoryHistoryProvider::new(
            &mut manager,
            "project-a",
            None,
            Some("reviewer".to_owned()),
            NOW,
            |error| error.to_string(),
        );
        let outcome = RetrievalRouter
            .route_with_history(
                &mut backend,
                &history_intent("role-scoped-signature", "rolemarker"),
                Some(&mut denied),
            )
            .unwrap_or_else(|error| panic!("denied route: {error}"));
        assert!(outcome.evidence.is_empty());
        assert_eq!(outcome.trace.stop_reason, StopCondition::NoEvidence);
    }
    let mut allowed = MemoryHistoryProvider::new(
        &mut manager,
        "project-a",
        None,
        Some("implementer".to_owned()),
        NOW,
        |error| error.to_string(),
    );
    let outcome = RetrievalRouter
        .route_with_history(
            &mut backend,
            &history_intent("role-scoped-signature", "rolemarker"),
            Some(&mut allowed),
        )
        .unwrap_or_else(|error| panic!("allowed route: {error}"));
    assert_eq!(backend.calls, 0);
    assert_eq!(outcome.evidence.len(), 1);
    assert_eq!(outcome.evidence[0].trust_class, TrustClass::Derived);
    assert_eq!(outcome.evidence[0].trust_label.source, TrustSource::Memory);
    assert_eq!(outcome.evidence[0].trust_label.level, TrustLevel::Untrusted);
}
