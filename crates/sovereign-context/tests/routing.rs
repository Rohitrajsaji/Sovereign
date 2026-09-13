use sovereign_context::{
    Channel, ChannelResult, ContextBudget, ContextLevel, ContextLevelPolicy, ContextMode,
    ContextPacketInput, ContextPlanner, DiffResult, EvidenceItem, EvidenceKind, FailureHistoryKey,
    HistoryProvider, PacketSection, RepositoryRetrievalBackend, RetrievalBackend, RetrievalIntent,
    RetrievalRouter, StopCondition, TrustClass,
};
use sovereign_repo::{
    IndexConfig, LexicalRetriever, ProjectRegistry, StructuralConfig, StructuralIndex,
};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Default)]
struct MockBackend {
    calls: Vec<String>,
    exact_sufficient: bool,
    lexical_sufficient: bool,
    structural_sufficient: bool,
    diff_paths: Vec<PathBuf>,
    evidence_tag: String,
}

impl MockBackend {
    fn result(&self, id: &str, path: &str, sufficient: bool) -> ChannelResult {
        let item = fixture_item_tagged(id, path, &self.evidence_tag);
        ChannelResult {
            candidates: 1,
            candidate_ids: vec![item.evidence_id.clone()],
            selected: vec![item],
            sufficient,
            freshness_checked: true,
            stale_rejected: Some(1),
            source_refresh_count: 1,
            source_snapshot: Some("snapshot:g1".to_owned()),
            source_fingerprint: Some("sha256:source-fixture".to_owned()),
            bound: None,
        }
    }
}

impl RetrievalBackend for MockBackend {
    type Error = String;

    fn current_diff(&mut self, _repository_id: &str) -> Result<DiffResult, Self::Error> {
        self.calls.push("current_diff".to_owned());
        let item = fixture_item_tagged("diff", "working-diff", &self.evidence_tag);
        Ok(DiffResult {
            evidence: ChannelResult {
                candidates: 1,
                candidate_ids: vec![item.evidence_id.clone()],
                selected: vec![item],
                sufficient: true,
                freshness_checked: true,
                stale_rejected: Some(0),
                source_refresh_count: 0,
                source_snapshot: Some("snapshot:diff".to_owned()),
                source_fingerprint: Some("sha256:diff".to_owned()),
                bound: None,
            },
            touched_paths: self.diff_paths.clone(),
        })
    }

    fn exact_path(
        &mut self,
        _repository_id: &str,
        path: &Path,
    ) -> Result<ChannelResult, Self::Error> {
        self.calls.push(format!("exact_path:{}", path.display()));
        Ok(self.result(
            "exact",
            path.to_string_lossy().as_ref(),
            self.exact_sufficient,
        ))
    }

    fn exact_literal(
        &mut self,
        _repository_id: &str,
        literal: &str,
    ) -> Result<ChannelResult, Self::Error> {
        self.calls.push(format!("exact_literal:{literal}"));
        Ok(self.result("literal", "src/lib.rs", self.exact_sufficient))
    }

    fn lexical(&mut self, _repository_id: &str, query: &str) -> Result<ChannelResult, Self::Error> {
        self.calls.push(format!("lexical:{query}"));
        Ok(self.result("lexical", "src/router.rs", self.lexical_sufficient))
    }

    fn symbol(&mut self, _repository_id: &str, symbol: &str) -> Result<ChannelResult, Self::Error> {
        self.calls.push(format!("symbol:{symbol}"));
        Ok(self.result("symbol", "src/symbol.rs", true))
    }

    fn symbols_for_path(
        &mut self,
        _repository_id: &str,
        path: &Path,
    ) -> Result<ChannelResult, Self::Error> {
        self.calls
            .push(format!("symbols_for_path:{}", path.display()));
        Ok(self.result("touched-symbol", path.to_string_lossy().as_ref(), true))
    }

    fn structural(
        &mut self,
        _repository_id: &str,
        anchor: &Path,
    ) -> Result<ChannelResult, Self::Error> {
        self.calls.push(format!("structural:{}", anchor.display()));
        Ok(self.result(
            "structural",
            anchor.to_string_lossy().as_ref(),
            self.structural_sufficient,
        ))
    }
}

#[derive(Default)]
struct MockHistory {
    calls: Vec<String>,
    keyed_sufficient: bool,
}

impl HistoryProvider for MockHistory {
    type Error = String;

    fn lookup_key(&mut self, key: &FailureHistoryKey) -> Result<ChannelResult, Self::Error> {
        self.calls.push(format!(
            "key:{}:{}:{}:{}",
            key.normalized_signature,
            key.repository_id,
            key.tool,
            key.symbol.as_deref().unwrap_or("")
        ));
        Ok(history_result("history-key", self.keyed_sufficient))
    }

    fn lookup_text(
        &mut self,
        _repository_id: &str,
        text: &str,
    ) -> Result<ChannelResult, Self::Error> {
        self.calls.push(format!("text:{text}"));
        Ok(history_result("history-text", true))
    }
}

fn fixture_item(id: &str, path: &str) -> EvidenceItem {
    fixture_item_tagged(id, path, "")
}

fn fixture_item_tagged(id: &str, path: &str, tag: &str) -> EvidenceItem {
    EvidenceItem::new(
        id,
        PacketSection::DirectEvidence,
        ContextLevel::C1,
        EvidenceKind::SourceSlice,
        format!("repo://fixture/{path}"),
        format!("sha256:{id}:{tag}"),
        "fixture",
        TrustClass::Repository,
        "fixture",
        format!("evidence {id} {tag}"),
    )
    .with_locator(format!("path:{path}"))
}

fn history_result(id: &str, sufficient: bool) -> ChannelResult {
    let item = fixture_item(id, "history");
    ChannelResult {
        candidates: 1,
        candidate_ids: vec![item.evidence_id.clone()],
        selected: vec![item],
        sufficient,
        freshness_checked: true,
        stale_rejected: Some(0),
        source_refresh_count: 0,
        source_snapshot: Some("history:g1".to_owned()),
        source_fingerprint: Some("sha256:history".to_owned()),
        bound: None,
    }
}

struct RoutingRepo {
    base: PathBuf,
    root: PathBuf,
}

impl RoutingRepo {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|error| panic!("clock: {error}"))
            .as_nanos();
        let base = std::env::temp_dir().join(format!(
            "sovereign-context-routing-{label}-{}-{nonce}",
            std::process::id()
        ));
        let root = base.join("repo");
        fs::create_dir_all(root.join("src"))
            .unwrap_or_else(|error| panic!("create routing repo: {error}"));
        fs::write(
            root.join("src/lib.rs"),
            "mod helper;\npub fn route() { helper::work(); }\n",
        )
        .unwrap_or_else(|error| panic!("write lib: {error}"));
        fs::write(root.join("src/helper.rs"), "pub fn work() {}\n")
            .unwrap_or_else(|error| panic!("write helper: {error}"));
        run_git(&root, &["init", "-q"]);
        run_git(&root, &["add", "."]);
        run_git(
            &root,
            &[
                "-c",
                "user.name=Sovereign Tests",
                "-c",
                "user.email=sovereign@example.invalid",
                "commit",
                "-qm",
                "initial",
            ],
        );
        Self { base, root }
    }
}

impl Drop for RoutingRepo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

fn run_git(root: &Path, args: &[&str]) {
    let status = Command::new("git")
        .current_dir(root)
        .args(args)
        .status()
        .unwrap_or_else(|error| panic!("git {args:?}: {error}"));
    assert!(status.success(), "git command failed: {args:?}");
}

#[test]
fn routing_known_path_uses_exact_only_and_stops() {
    let mut backend = MockBackend::default();
    let intent = RetrievalIntent::KnownPath {
        repository_id: "repo.fixture".to_owned(),
        path: PathBuf::from("src/lib.rs"),
    };
    let outcome = RetrievalRouter
        .route(&mut backend, &intent)
        .unwrap_or_else(|error| panic!("route: {error}"));

    assert_eq!(backend.calls, vec!["exact_path:src/lib.rs"]);
    assert_eq!(outcome.trace.route.len(), 1);
    assert_eq!(outcome.trace.route[0].channel, Channel::Exact);
    assert!(!outcome.trace.semantic_available);
    assert_eq!(outcome.evidence[0].level, ContextLevel::C1);
}

#[test]
fn routing_known_path_insufficient_does_not_report_satisfied() {
    let mut backend = MockBackend::default();
    let intent = RetrievalIntent::KnownPath {
        repository_id: "repo.fixture".to_owned(),
        path: PathBuf::from("src/missing.rs"),
    };
    let outcome = RetrievalRouter
        .route(&mut backend, &intent)
        .unwrap_or_else(|error| panic!("route: {error}"));

    assert_eq!(backend.calls, vec!["exact_path:src/missing.rs"]);
    assert_eq!(outcome.trace.stop_reason, StopCondition::InsufficientExact);
}

#[test]
fn routing_literal_error_escalates_to_lexical_only_when_exact_is_insufficient() {
    let intent = RetrievalIntent::LiteralError {
        repository_id: "repo.fixture".to_owned(),
        literal: "E0382 moved value".to_owned(),
    };
    let mut sufficient = MockBackend {
        exact_sufficient: true,
        lexical_sufficient: true,
        ..MockBackend::default()
    };
    RetrievalRouter
        .route(&mut sufficient, &intent)
        .unwrap_or_else(|error| panic!("route: {error}"));
    assert_eq!(sufficient.calls, vec!["exact_literal:E0382 moved value"]);

    let mut insufficient = MockBackend {
        exact_sufficient: false,
        lexical_sufficient: true,
        ..MockBackend::default()
    };
    let outcome = RetrievalRouter
        .route(&mut insufficient, &intent)
        .unwrap_or_else(|error| panic!("route: {error}"));
    assert_eq!(
        insufficient.calls,
        vec![
            "exact_literal:E0382 moved value",
            "lexical:E0382 moved value"
        ]
    );
    assert_eq!(outcome.trace.route[1].channel, Channel::Lexical);
    assert_eq!(outcome.evidence[1].level, ContextLevel::C2);
}

#[test]
fn routing_known_symbol_avoids_lexical_and_graph_fanout() {
    let mut backend = MockBackend::default();
    let intent = RetrievalIntent::KnownSymbol {
        repository_id: "repo.fixture".to_owned(),
        symbol: "ContextPlanner".to_owned(),
    };
    let outcome = RetrievalRouter
        .route(&mut backend, &intent)
        .unwrap_or_else(|error| panic!("route: {error}"));
    assert_eq!(
        backend.calls,
        vec!["exact_literal:ContextPlanner", "symbol:ContextPlanner"]
    );
    assert_eq!(outcome.trace.route[0].channel, Channel::Exact);
    assert_eq!(outcome.trace.route[1].channel, Channel::Symbol);
}

#[test]
fn routing_behavior_uses_lexical_then_at_most_one_structural_anchor() {
    let mut backend = MockBackend {
        lexical_sufficient: false,
        structural_sufficient: true,
        ..MockBackend::default()
    };
    let intent = RetrievalIntent::Behavior {
        repository_id: "repo.fixture".to_owned(),
        query: "persist settings".to_owned(),
    };
    let outcome = RetrievalRouter
        .route(&mut backend, &intent)
        .unwrap_or_else(|error| panic!("route: {error}"));
    assert_eq!(
        backend.calls,
        vec!["lexical:persist settings", "structural:src/router.rs"]
    );
    assert_eq!(outcome.trace.expansion_count, 1);
    assert_eq!(
        outcome.trace.stop_reason,
        StopCondition::StructuralExpansionComplete
    );
}

#[test]
fn routing_impact_uses_structural_graph_as_primary_c3() {
    let mut backend = MockBackend::default();
    let intent = RetrievalIntent::Impact {
        repository_id: "repo.fixture".to_owned(),
        anchor: PathBuf::from("src/state.rs"),
    };
    let outcome = RetrievalRouter
        .route(&mut backend, &intent)
        .unwrap_or_else(|error| panic!("route: {error}"));
    assert_eq!(backend.calls, vec!["structural:src/state.rs"]);
    assert_eq!(outcome.evidence[0].level, ContextLevel::C3);
    assert_eq!(outcome.trace.route[0].channel, Channel::Structural);
}

#[test]
fn routing_diff_prioritizes_exact_touched_paths_before_structural_expansion() {
    let mut backend = MockBackend {
        diff_paths: vec![PathBuf::from("src/b.rs"), PathBuf::from("src/a.rs")],
        ..MockBackend::default()
    };
    let intent = RetrievalIntent::Diff {
        repository_id: "repo.fixture".to_owned(),
    };
    let outcome = RetrievalRouter
        .route(&mut backend, &intent)
        .unwrap_or_else(|error| panic!("route: {error}"));
    assert_eq!(
        backend.calls,
        vec![
            "current_diff",
            "exact_path:src/a.rs",
            "exact_path:src/b.rs",
            "symbols_for_path:src/a.rs",
            "symbols_for_path:src/b.rs",
            "structural:src/a.rs",
            "structural:src/b.rs",
        ]
    );
    assert_eq!(outcome.trace.route[0].channel, Channel::Diff);
    assert_eq!(outcome.trace.expansion_count, 2);
}

#[test]
fn routing_diff_caps_authoritative_touched_paths_and_records_truncation() {
    let mut backend = MockBackend {
        diff_paths: (0..20)
            .map(|index| PathBuf::from(format!("src/file_{index:02}.rs")))
            .collect(),
        ..MockBackend::default()
    };
    let intent = RetrievalIntent::Diff {
        repository_id: "repo.fixture".to_owned(),
    };
    let outcome = RetrievalRouter
        .route(&mut backend, &intent)
        .unwrap_or_else(|error| panic!("route: {error}"));

    assert_eq!(outcome.trace.expansion_count, 16);
    assert_eq!(backend.calls.len(), 49);
    let bound = outcome.trace.route[0]
        .bound
        .as_ref()
        .unwrap_or_else(|| panic!("diff bound missing"));
    assert_eq!(bound.subject, "diff_touched_paths");
    assert_eq!(bound.observed, 20);
    assert_eq!(bound.limit, 16);
    assert!(bound.truncated);
    assert!(
        backend
            .calls
            .contains(&"exact_path:src/file_15.rs".to_owned())
    );
    assert!(
        !backend
            .calls
            .contains(&"exact_path:src/file_16.rs".to_owned())
    );
}

#[test]
fn routing_production_backend_uses_current_git_diff_as_diff_authority() {
    let repo = RoutingRepo::new("production-diff");
    fs::write(
        repo.root.join("src/lib.rs"),
        "mod helper;\npub fn route() { helper::work(); }\npub fn changed() {}\n",
    )
    .unwrap_or_else(|error| panic!("mutate lib: {error}"));

    let mut registry = ProjectRegistry::new();
    registry
        .register("repo.fixture", &repo.root)
        .unwrap_or_else(|error| panic!("register: {error}"));
    let mut lexical = LexicalRetriever::open(
        &registry,
        "repo.fixture",
        repo.base.join("lexical.sqlite3"),
        IndexConfig::default(),
    )
    .unwrap_or_else(|error| panic!("open lexical: {error}"));
    let mut structural = StructuralIndex::open(
        &registry,
        "repo.fixture",
        repo.base.join("structural.sqlite3"),
        StructuralConfig::default(),
    )
    .unwrap_or_else(|error| panic!("open structural: {error}"));
    let mut backend =
        RepositoryRetrievalBackend::new("repo.fixture", &registry, &mut lexical, &mut structural)
            .unwrap_or_else(|error| panic!("backend: {error}"));
    let outcome = RetrievalRouter
        .route(
            &mut backend,
            &RetrievalIntent::Diff {
                repository_id: "repo.fixture".to_owned(),
            },
        )
        .unwrap_or_else(|error| panic!("route: {error}"));

    assert_eq!(outcome.trace.route[0].channel, Channel::Diff);
    assert_eq!(outcome.trace.route[1].channel, Channel::Exact);
    assert_eq!(outcome.trace.route[2].channel, Channel::Symbol);
    assert_eq!(outcome.trace.route[3].channel, Channel::Structural);
    assert!(
        outcome
            .evidence
            .iter()
            .any(|item| item.kind == EvidenceKind::Diff && item.text.contains("pub fn changed"))
    );
    assert!(
        outcome
            .trace
            .route
            .iter()
            .any(|step| step.channel == Channel::Exact && step.selected_count == 1)
    );
    let touched_symbol_step = &outcome.trace.route[2];
    assert!(touched_symbol_step.selected_count > 0);
    assert!(outcome.evidence.iter().any(|item| {
        touched_symbol_step.selected_ids.contains(&item.evidence_id)
            && item.text.contains("changed")
    }));
    let bound = outcome.trace.route[0]
        .bound
        .as_ref()
        .unwrap_or_else(|| panic!("diff bound missing"));
    assert_eq!(bound.observed, 1);
    assert!(!bound.truncated);
}

#[test]
fn routing_production_diff_routes_pure_tracked_rename_paths() {
    let repo = RoutingRepo::new("production-diff-rename");
    let old_path = "src/helper.rs";
    let new_path = "src/helper renamed.rs";
    run_git(&repo.root, &["mv", old_path, new_path]);

    let diff = Command::new("git")
        .current_dir(&repo.root)
        .args(["diff", "HEAD", "--"])
        .output()
        .unwrap_or_else(|error| panic!("git diff: {error}"));
    assert!(diff.status.success());
    let diff = String::from_utf8(diff.stdout).unwrap_or_else(|error| panic!("utf8 diff: {error}"));
    assert!(diff.contains("rename from src/helper.rs"));
    assert!(diff.contains("rename to src/helper renamed.rs"));
    assert!(!diff.contains("--- a/src/helper.rs"));
    assert!(!diff.contains("+++ b/src/helper renamed.rs"));

    let mut registry = ProjectRegistry::new();
    registry
        .register("repo.fixture", &repo.root)
        .unwrap_or_else(|error| panic!("register: {error}"));
    let mut lexical = LexicalRetriever::open(
        &registry,
        "repo.fixture",
        repo.base.join("lexical.sqlite3"),
        IndexConfig::default(),
    )
    .unwrap_or_else(|error| panic!("open lexical: {error}"));
    let mut structural = StructuralIndex::open(
        &registry,
        "repo.fixture",
        repo.base.join("structural.sqlite3"),
        StructuralConfig::default(),
    )
    .unwrap_or_else(|error| panic!("open structural: {error}"));
    let mut backend =
        RepositoryRetrievalBackend::new("repo.fixture", &registry, &mut lexical, &mut structural)
            .unwrap_or_else(|error| panic!("backend: {error}"));
    let outcome = RetrievalRouter
        .route(
            &mut backend,
            &RetrievalIntent::Diff {
                repository_id: "repo.fixture".to_owned(),
            },
        )
        .unwrap_or_else(|error| panic!("route: {error}"));

    let bound = outcome.trace.route[0]
        .bound
        .as_ref()
        .unwrap_or_else(|| panic!("diff bound missing"));
    assert_eq!(bound.observed, 2);
    assert!(!bound.truncated);

    let exact_steps = outcome
        .trace
        .route
        .iter()
        .filter(|step| step.channel == Channel::Exact)
        .collect::<Vec<_>>();
    assert_eq!(exact_steps.len(), 2);
    let mut exact_selected = exact_steps
        .iter()
        .map(|step| step.selected_count)
        .collect::<Vec<_>>();
    exact_selected.sort_unstable();
    assert_eq!(exact_selected, vec![0, 1]);

    let symbol_steps = outcome
        .trace
        .route
        .iter()
        .filter(|step| step.channel == Channel::Symbol)
        .collect::<Vec<_>>();
    assert_eq!(symbol_steps.len(), 2);
    assert!(symbol_steps.iter().any(|step| step.selected_count == 0));
    assert!(symbol_steps.iter().any(|step| step.selected_count > 0));

    let structural_steps = outcome
        .trace
        .route
        .iter()
        .filter(|step| step.channel == Channel::Structural)
        .collect::<Vec<_>>();
    assert_eq!(structural_steps.len(), 2);
    assert!(outcome.evidence.iter().any(|item| {
        item.locator.as_deref() == Some("path:src/helper renamed.rs") && item.text.contains("work")
    }));
}

#[test]
fn routing_production_impact_includes_dependent_importers() {
    let repo = RoutingRepo::new("production-impact-dependent");
    let mut registry = ProjectRegistry::new();
    registry
        .register("repo.fixture", &repo.root)
        .unwrap_or_else(|error| panic!("register: {error}"));
    let mut lexical = LexicalRetriever::open(
        &registry,
        "repo.fixture",
        repo.base.join("lexical.sqlite3"),
        IndexConfig::default(),
    )
    .unwrap_or_else(|error| panic!("open lexical: {error}"));
    let mut structural = StructuralIndex::open(
        &registry,
        "repo.fixture",
        repo.base.join("structural.sqlite3"),
        StructuralConfig::default(),
    )
    .unwrap_or_else(|error| panic!("open structural: {error}"));
    let mut backend =
        RepositoryRetrievalBackend::new("repo.fixture", &registry, &mut lexical, &mut structural)
            .unwrap_or_else(|error| panic!("backend: {error}"));
    let outcome = RetrievalRouter
        .route(
            &mut backend,
            &RetrievalIntent::Impact {
                repository_id: "repo.fixture".to_owned(),
                anchor: PathBuf::from("src/helper.rs"),
            },
        )
        .unwrap_or_else(|error| panic!("impact route: {error}"));

    let step = &outcome.trace.route[0];
    assert_eq!(step.channel, Channel::Structural);
    assert!(step.freshness_checked);
    assert_eq!(step.stale_rejected, None);
    assert!(outcome.evidence.iter().any(|item| {
        item.text.contains("src/lib.rs")
            && item.text.contains("module")
            && item.text.contains("helper")
    }));
}

#[test]
fn routing_production_symbol_and_structural_results_are_query_bounded() {
    let repo = RoutingRepo::new("production-cardinality");
    let repeated = (0..12)
        .map(|_| "pub fn repeated() {}\n")
        .collect::<String>();
    fs::write(repo.root.join("src/many.rs"), repeated)
        .unwrap_or_else(|error| panic!("write many symbols: {error}"));
    let mut modules = String::new();
    for index in 0..20 {
        writeln!(&mut modules, "mod dep_{index:02};")
            .unwrap_or_else(|error| panic!("format many edges: {error}"));
    }
    fs::write(repo.root.join("src/lib.rs"), modules)
        .unwrap_or_else(|error| panic!("write many edges: {error}"));

    let mut registry = ProjectRegistry::new();
    registry
        .register("repo.fixture", &repo.root)
        .unwrap_or_else(|error| panic!("register: {error}"));
    let mut lexical = LexicalRetriever::open(
        &registry,
        "repo.fixture",
        repo.base.join("lexical.sqlite3"),
        IndexConfig::default(),
    )
    .unwrap_or_else(|error| panic!("open lexical: {error}"));
    let mut structural = StructuralIndex::open(
        &registry,
        "repo.fixture",
        repo.base.join("structural.sqlite3"),
        StructuralConfig::default(),
    )
    .unwrap_or_else(|error| panic!("open structural: {error}"));
    let mut backend =
        RepositoryRetrievalBackend::new("repo.fixture", &registry, &mut lexical, &mut structural)
            .unwrap_or_else(|error| panic!("backend: {error}"));

    let symbol_outcome = RetrievalRouter
        .route(
            &mut backend,
            &RetrievalIntent::KnownSymbol {
                repository_id: "repo.fixture".to_owned(),
                symbol: "repeated".to_owned(),
            },
        )
        .unwrap_or_else(|error| panic!("symbol route: {error}"));
    let symbol_step = symbol_outcome
        .trace
        .route
        .iter()
        .find(|step| step.channel == Channel::Symbol)
        .unwrap_or_else(|| panic!("symbol route step missing"));
    let symbol_bound = symbol_step
        .bound
        .as_ref()
        .unwrap_or_else(|| panic!("symbol result bound missing"));
    assert_eq!(symbol_step.candidate_count, 12);
    assert_eq!(symbol_step.selected_count, 8);
    assert_eq!(symbol_step.candidate_ids.len(), 8);
    assert_eq!(symbol_step.selected_ids.len(), 8);
    assert_eq!(symbol_bound.subject, "symbol_results");
    assert_eq!(symbol_bound.observed, 12);
    assert_eq!(symbol_bound.limit, 8);
    assert!(symbol_bound.truncated);
    assert_eq!(symbol_step.stale_rejected, None);
    assert_eq!(symbol_outcome.trace.stale_rejected, None);

    let lexical_outcome = RetrievalRouter
        .route(
            &mut backend,
            &RetrievalIntent::Behavior {
                repository_id: "repo.fixture".to_owned(),
                query: "repeated".to_owned(),
            },
        )
        .unwrap_or_else(|error| panic!("lexical route: {error}"));
    assert_eq!(lexical_outcome.trace.route[0].channel, Channel::Lexical);
    assert_eq!(lexical_outcome.trace.route[0].stale_rejected, None);
    assert_eq!(lexical_outcome.trace.stale_rejected, None);

    let impact_outcome = RetrievalRouter
        .route(
            &mut backend,
            &RetrievalIntent::Impact {
                repository_id: "repo.fixture".to_owned(),
                anchor: PathBuf::from("src/lib.rs"),
            },
        )
        .unwrap_or_else(|error| panic!("impact route: {error}"));
    let structural_step = &impact_outcome.trace.route[0];
    let structural_bound = structural_step
        .bound
        .as_ref()
        .unwrap_or_else(|| panic!("structural result bound missing"));
    assert_eq!(structural_step.candidate_count, 20);
    assert_eq!(structural_step.selected_count, 12);
    assert_eq!(structural_step.candidate_ids.len(), 12);
    assert_eq!(structural_step.selected_ids.len(), 12);
    assert_eq!(structural_bound.subject, "structural_neighborhood_results");
    assert_eq!(structural_bound.observed, 20);
    assert_eq!(structural_bound.limit, 12);
    assert!(structural_bound.truncated);
    assert_eq!(structural_step.stale_rejected, None);
    assert_eq!(impact_outcome.trace.stale_rejected, None);
}

#[test]
fn routing_failure_history_uses_normalized_key_before_optional_text_fallback() {
    let mut backend = MockBackend::default();
    let intent = RetrievalIntent::FailureHistory {
        repository_id: "repo.fixture".to_owned(),
        normalized_signature: "test:settings:abc".to_owned(),
        tool: "cargo-test".to_owned(),
        symbol: Some("persist_settings".to_owned()),
        text_fallback: "settings test failure".to_owned(),
    };
    let absent = RetrievalRouter
        .route(&mut backend, &intent)
        .unwrap_or_else(|error| panic!("route: {error}"));
    assert_eq!(absent.trace.stop_reason, StopCondition::HistoryUnavailable);
    assert!(backend.calls.is_empty());

    let mut history = MockHistory::default();
    let outcome = RetrievalRouter
        .route_with_history(&mut backend, &intent, Some(&mut history))
        .unwrap_or_else(|error| panic!("route: {error}"));
    assert_eq!(
        history.calls,
        vec![
            "key:test:settings:abc:repo.fixture:cargo-test:persist_settings",
            "text:settings test failure",
        ]
    );
    assert_eq!(outcome.trace.route.len(), 2);
}

#[test]
fn routing_trace_is_stable_and_carries_required_source_and_channel_facts() {
    let mut first_backend = MockBackend {
        exact_sufficient: false,
        lexical_sufficient: true,
        ..MockBackend::default()
    };
    let mut second_backend = MockBackend {
        exact_sufficient: false,
        lexical_sufficient: true,
        ..MockBackend::default()
    };
    let intent = RetrievalIntent::LiteralError {
        repository_id: "repo.fixture".to_owned(),
        literal: "panic marker".to_owned(),
    };
    let first = RetrievalRouter
        .route(&mut first_backend, &intent)
        .unwrap_or_else(|error| panic!("route: {error}"));
    let second = RetrievalRouter
        .route(&mut second_backend, &intent)
        .unwrap_or_else(|error| panic!("route: {error}"));
    assert_eq!(first.trace.trace_id, second.trace.trace_id);
    assert_eq!(first.trace.candidate_count, 2);
    assert_eq!(first.trace.selected_count, 2);
    assert_eq!(first.trace.evidence_channels.len(), 2);
    assert!(first.trace.freshness_checked);
    assert_eq!(first.trace.stale_rejected, Some(2));
    assert_eq!(first.trace.source_refresh_count, 2);
    assert_eq!(first.trace.source_snapshot.as_deref(), Some("snapshot:g1"));
    assert_eq!(
        first.trace.source_fingerprint.as_deref(),
        Some("sha256:source-fixture")
    );
    assert_eq!(
        first.trace.semantic_unavailable_reason.as_deref(),
        Some("semantic retrieval is unavailable in M2")
    );
    let exact_step = &first.trace.route[0];
    assert_eq!(exact_step.candidate_count, 1);
    assert_eq!(exact_step.selected_count, 1);
    assert_eq!(exact_step.candidate_ids, vec!["literal"]);
    assert_eq!(exact_step.selected_ids, vec!["literal"]);
    assert!(exact_step.freshness_checked);
    assert_eq!(exact_step.stale_rejected, Some(1));
    assert_eq!(exact_step.source_refresh_count, 1);
    assert_eq!(exact_step.source_snapshot.as_deref(), Some("snapshot:g1"));
    assert_eq!(
        exact_step.source_fingerprint.as_deref(),
        Some("sha256:source-fixture")
    );
}

#[test]
fn routing_semantic_is_explicitly_unavailable_in_m2() {
    let mut backend = MockBackend {
        lexical_sufficient: false,
        structural_sufficient: false,
        ..MockBackend::default()
    };
    let intent = RetrievalIntent::Fuzzy {
        repository_id: "repo.fixture".to_owned(),
        query: "code that feels related to startup".to_owned(),
    };
    let outcome = RetrievalRouter
        .route(&mut backend, &intent)
        .unwrap_or_else(|error| panic!("route: {error}"));
    assert_eq!(
        backend.calls,
        vec![
            "lexical:code that feels related to startup",
            "structural:src/router.rs"
        ]
    );
    assert_eq!(outcome.trace.route[0].channel, Channel::Lexical);
    assert_eq!(outcome.trace.route[1].channel, Channel::Structural);
    assert_eq!(outcome.trace.route[2].channel, Channel::Semantic);
    assert_eq!(
        outcome.trace.stop_reason,
        StopCondition::SemanticUnavailable
    );
    assert!(!outcome.trace.semantic_available);
}

#[test]
fn routing_trace_id_changes_when_route_outcome_changes() {
    let intent = RetrievalIntent::LiteralError {
        repository_id: "repo.fixture".to_owned(),
        literal: "same intent".to_owned(),
    };
    let mut exact_only = MockBackend {
        exact_sufficient: true,
        ..MockBackend::default()
    };
    let mut escalated = MockBackend {
        exact_sufficient: false,
        lexical_sufficient: true,
        ..MockBackend::default()
    };
    let first = RetrievalRouter
        .route(&mut exact_only, &intent)
        .unwrap_or_else(|error| panic!("route: {error}"));
    let second = RetrievalRouter
        .route(&mut escalated, &intent)
        .unwrap_or_else(|error| panic!("route: {error}"));
    assert_ne!(first.trace.trace_id, second.trace.trace_id);
}

#[test]
fn routing_trace_id_binds_selected_source_and_content_digests() {
    let intent = RetrievalIntent::KnownPath {
        repository_id: "repo.fixture".to_owned(),
        path: PathBuf::from("src/lib.rs"),
    };
    let mut first_backend = MockBackend {
        exact_sufficient: true,
        evidence_tag: "generation-a".to_owned(),
        ..MockBackend::default()
    };
    let mut second_backend = MockBackend {
        exact_sufficient: true,
        evidence_tag: "generation-b".to_owned(),
        ..MockBackend::default()
    };
    let first = RetrievalRouter
        .route(&mut first_backend, &intent)
        .unwrap_or_else(|error| panic!("route: {error}"));
    let second = RetrievalRouter
        .route(&mut second_backend, &intent)
        .unwrap_or_else(|error| panic!("route: {error}"));

    assert_eq!(
        first.trace.route[0].selected_ids,
        second.trace.route[0].selected_ids
    );
    assert_ne!(
        first.evidence[0].source_digest,
        second.evidence[0].source_digest
    );
    assert_ne!(
        first.evidence[0].content_digest,
        second.evidence[0].content_digest
    );
    assert_ne!(first.trace.trace_id, second.trace.trace_id);
}

#[test]
fn routing_context_policy_and_packet_keep_c0_c3_bounded_without_semantic_or_history() {
    assert_eq!(
        ContextLevelPolicy::maximum_for(&RetrievalIntent::Impact {
            repository_id: "repo.fixture".to_owned(),
            anchor: PathBuf::from("src/lib.rs"),
        }),
        ContextLevel::C3
    );
    let mut c1 = fixture_item("c1", "src/c1.rs");
    c1.level = ContextLevel::C1;
    let mut c2 = fixture_item("c2", "src/c2.rs");
    c2.level = ContextLevel::C2;
    c2.section = PacketSection::RoutedExpansion;
    let mut c3 = fixture_item("c3", "src/c3.rs");
    c3.level = ContextLevel::C3;
    c3.section = PacketSection::RoutedExpansion;

    let packet = ContextPlanner::default()
        .build(
            ContextMode::Implementation,
            ContextBudget::m1_8k(),
            ContextPacketInput {
                controller_prefix: "controller".to_owned(),
                task_contract: "task".to_owned(),
                current_state: "state".to_owned(),
                candidates: vec![c1, c2, c3],
                output_schema: "schema".to_owned(),
            },
        )
        .unwrap_or_else(|error| panic!("build: {error}"));
    assert!(packet.metrics.tokens_by_level.contains_key("c0"));
    assert!(packet.metrics.tokens_by_level.contains_key("c1"));
    assert!(packet.metrics.tokens_by_level.contains_key("c2"));
    assert!(packet.metrics.tokens_by_level.contains_key("c3"));
    assert!(packet.metrics.final_serialized_input_tokens <= packet.budget.max_input_tokens);
}
