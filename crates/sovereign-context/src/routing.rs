#![allow(clippy::missing_errors_doc, clippy::too_many_lines)]

use crate::{ContextLevel, EvidenceItem, EvidenceKind, PacketSection, TrustClass, sha256_prefixed};
use serde::{Deserialize, Serialize};
use sovereign_repo::{
    ExactRetriever, ExactSearchQuery, LexicalQuery, LexicalRetriever, ProjectRegistry, RepoError,
    RepositoryIntelligence, StructuralIndex, StructuralLookup,
};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};

const MAX_DIFF_TOUCHED_PATHS: usize = 16;
const MAX_EXACT_LITERAL_HITS: usize = 8;
const MAX_EXACT_SCAN_FILES: usize = 50_000;
const MAX_EXACT_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_EXACT_LINE_BYTES: usize = 4 * 1024;
const MAX_LEXICAL_HITS: usize = 8;
const MAX_SYMBOL_RESULTS: usize = 8;
const MAX_STRUCTURAL_RESULTS: usize = 12;

/// Deterministic retrieval intent classified before any retriever is invoked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RetrievalIntent {
    KnownPath {
        repository_id: String,
        path: PathBuf,
    },
    LiteralError {
        repository_id: String,
        literal: String,
    },
    KnownSymbol {
        repository_id: String,
        symbol: String,
    },
    Behavior {
        repository_id: String,
        query: String,
    },
    Impact {
        repository_id: String,
        anchor: PathBuf,
    },
    Diff {
        repository_id: String,
    },
    FailureHistory {
        repository_id: String,
        normalized_signature: String,
        tool: String,
        symbol: Option<String>,
        text_fallback: String,
    },
    Fuzzy {
        repository_id: String,
        query: String,
    },
}

impl RetrievalIntent {
    #[must_use]
    pub fn repository_id(&self) -> &str {
        match self {
            Self::KnownPath { repository_id, .. }
            | Self::LiteralError { repository_id, .. }
            | Self::KnownSymbol { repository_id, .. }
            | Self::Behavior { repository_id, .. }
            | Self::Impact { repository_id, .. }
            | Self::Diff { repository_id, .. }
            | Self::FailureHistory { repository_id, .. }
            | Self::Fuzzy { repository_id, .. } => repository_id,
        }
    }
}

/// Retrieval channels available to M2. Semantic is typed for trace compatibility but unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    Diff,
    Exact,
    Lexical,
    Symbol,
    Structural,
    History,
    Semantic,
}

/// Why a deterministic route stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopCondition {
    Satisfied,
    InsufficientExact,
    StructuralExpansionComplete,
    HistoryUnavailable,
    SemanticUnavailable,
    NoEvidence,
}

/// One ordered routing decision recorded for later telemetry aggregation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteStep {
    pub channel: Channel,
    pub reason: String,
    pub candidate_count: usize,
    pub selected_count: usize,
    pub candidate_ids: Vec<String>,
    pub selected_ids: Vec<String>,
    pub freshness_checked: bool,
    pub stale_rejected: Option<usize>,
    pub source_refresh_count: usize,
    pub source_snapshot: Option<String>,
    pub source_fingerprint: Option<String>,
    pub bound: Option<RouteBoundFact>,
}

/// Deterministic cap/truncation fact for one routing step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteBoundFact {
    pub subject: String,
    pub observed: usize,
    pub limit: usize,
    pub truncated: bool,
}

/// Evidence provenance linkage required to attribute packet tokens/usefulness by channel later.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceChannelLink {
    pub evidence_id: String,
    pub channel: Channel,
    pub source_digest: String,
    pub content_digest: String,
}

/// Freshness and source identity returned by one bounded channel invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelResult {
    pub candidates: usize,
    pub candidate_ids: Vec<String>,
    pub selected: Vec<EvidenceItem>,
    pub sufficient: bool,
    pub freshness_checked: bool,
    pub stale_rejected: Option<usize>,
    pub source_refresh_count: usize,
    pub source_snapshot: Option<String>,
    pub source_fingerprint: Option<String>,
    pub bound: Option<RouteBoundFact>,
}

impl ChannelResult {
    #[must_use]
    pub fn empty() -> Self {
        Self {
            candidates: 0,
            candidate_ids: Vec::new(),
            selected: Vec::new(),
            sufficient: false,
            freshness_checked: true,
            stale_rejected: Some(0),
            source_refresh_count: 0,
            source_snapshot: None,
            source_fingerprint: None,
            bound: None,
        }
    }
}

/// Authoritative current Git diff plus touched paths derived from that exact diff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffResult {
    pub evidence: ChannelResult,
    pub touched_paths: Vec<PathBuf>,
}

/// Repository retrieval operations used by the router. Implementations may wrap sovereign-repo's
/// exact, lexical, and structural retrievers while retaining their source-freshness guarantees.
pub trait RetrievalBackend {
    type Error;

    fn current_diff(&mut self, repository_id: &str) -> Result<DiffResult, Self::Error>;

    fn exact_path(
        &mut self,
        repository_id: &str,
        path: &Path,
    ) -> Result<ChannelResult, Self::Error>;
    fn exact_literal(
        &mut self,
        repository_id: &str,
        literal: &str,
    ) -> Result<ChannelResult, Self::Error>;
    fn lexical(&mut self, repository_id: &str, query: &str) -> Result<ChannelResult, Self::Error>;
    fn symbol(&mut self, repository_id: &str, symbol: &str) -> Result<ChannelResult, Self::Error>;
    fn symbols_for_path(
        &mut self,
        repository_id: &str,
        path: &Path,
    ) -> Result<ChannelResult, Self::Error>;
    fn structural(
        &mut self,
        repository_id: &str,
        anchor: &Path,
    ) -> Result<ChannelResult, Self::Error>;
}

/// Production M2 retrieval adapter over sovereign-repo's exact, lexical, and structural APIs.
pub struct RepositoryRetrievalBackend<'registry, 'indices> {
    repository_id: String,
    registry: &'registry ProjectRegistry,
    exact: ExactRetriever<'registry>,
    lexical: &'indices mut LexicalRetriever<'registry>,
    structural: &'indices mut StructuralIndex<'registry>,
}

struct SourceDiagnostics {
    generation: Option<u64>,
    snapshot: Option<String>,
    fingerprint: Option<String>,
}

impl<'registry, 'indices> RepositoryRetrievalBackend<'registry, 'indices> {
    /// Creates a production adapter for one already-registered repository.
    ///
    /// # Errors
    /// Returns [`RepoError::UnknownRepository`] when the requested repository is not registered.
    pub fn new(
        repository_id: impl Into<String>,
        registry: &'registry ProjectRegistry,
        lexical: &'indices mut LexicalRetriever<'registry>,
        structural: &'indices mut StructuralIndex<'registry>,
    ) -> Result<Self, RepoError> {
        let repository_id = repository_id.into();
        if registry.repository(&repository_id).is_none() {
            return Err(RepoError::UnknownRepository(repository_id));
        }
        Ok(Self {
            repository_id,
            registry,
            exact: ExactRetriever::new(registry),
            lexical,
            structural,
        })
    }

    fn ensure_repository(&self, repository_id: &str) -> Result<(), RepoError> {
        if repository_id == self.repository_id {
            return Ok(());
        }
        Err(RepoError::UnknownRepository(repository_id.to_owned()))
    }

    fn exact_diagnostics(&self) -> Result<(String, String), RepoError> {
        let snapshot = self.registry.snapshot(&self.repository_id)?;
        Ok((
            format!(
                "head={};branch={};dirty={}",
                snapshot.head.as_deref().unwrap_or("unborn"),
                snapshot.branch.as_deref().unwrap_or("detached"),
                snapshot.dirty_digest
            ),
            snapshot.dirty_digest,
        ))
    }

    fn structural_diagnostics(&self) -> Result<SourceDiagnostics, RepoError> {
        Ok(self.structural.snapshot()?.map_or(
            SourceDiagnostics {
                generation: None,
                snapshot: None,
                fingerprint: None,
            },
            |snapshot| SourceDiagnostics {
                generation: Some(snapshot.generation),
                snapshot: Some(format!("generation={}", snapshot.generation)),
                fingerprint: Some(format!(
                    "{}:{}:{}",
                    snapshot.source_manifest_digest,
                    snapshot.parser_fingerprint,
                    snapshot.schema_fingerprint
                )),
            },
        ))
    }
}

impl RetrievalBackend for RepositoryRetrievalBackend<'_, '_> {
    type Error = RepoError;

    fn current_diff(&mut self, repository_id: &str) -> Result<DiffResult, Self::Error> {
        self.ensure_repository(repository_id)?;
        let diff = self.exact.current_diff(repository_id)?;
        let (source_snapshot, source_fingerprint) = self.exact_diagnostics()?;
        let touched_paths = touched_paths_from_diff(&diff.content);
        let selected = if diff.content.is_empty() {
            Vec::new()
        } else {
            vec![EvidenceItem::from_diff(
                &diff,
                "authoritative current Git diff",
            )]
        };
        let candidate_ids = selected
            .iter()
            .map(|item| item.evidence_id.clone())
            .collect::<Vec<_>>();
        Ok(DiffResult {
            evidence: ChannelResult {
                candidates: selected.len(),
                candidate_ids,
                sufficient: !selected.is_empty(),
                selected,
                freshness_checked: true,
                stale_rejected: Some(0),
                source_refresh_count: 0,
                source_snapshot: Some(source_snapshot),
                source_fingerprint: Some(source_fingerprint),
                bound: None,
            },
            touched_paths,
        })
    }

    fn exact_path(
        &mut self,
        repository_id: &str,
        path: &Path,
    ) -> Result<ChannelResult, Self::Error> {
        self.ensure_repository(repository_id)?;
        let (source_snapshot, source_fingerprint) = self.exact_diagnostics()?;
        let evidence = match self.exact.read_path(repository_id, path, None) {
            Ok(evidence) => evidence,
            Err(RepoError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(ChannelResult {
                    source_snapshot: Some(source_snapshot),
                    source_fingerprint: Some(source_fingerprint),
                    ..ChannelResult::empty()
                });
            }
            Err(RepoError::NotRegularFile(_)) => {
                return Ok(ChannelResult {
                    source_snapshot: Some(source_snapshot),
                    source_fingerprint: Some(source_fingerprint),
                    ..ChannelResult::empty()
                });
            }
            Err(error) => return Err(error),
        };
        let item = EvidenceItem::from_exact_file(&evidence, "exact current path");
        Ok(ChannelResult {
            candidates: 1,
            candidate_ids: vec![item.evidence_id.clone()],
            selected: vec![item],
            sufficient: true,
            freshness_checked: true,
            stale_rejected: Some(0),
            source_refresh_count: 0,
            source_snapshot: Some(source_snapshot),
            source_fingerprint: Some(source_fingerprint),
            bound: None,
        })
    }

    fn exact_literal(
        &mut self,
        repository_id: &str,
        literal: &str,
    ) -> Result<ChannelResult, Self::Error> {
        self.ensure_repository(repository_id)?;
        let hits = self.exact.search_literal(
            repository_id,
            &ExactSearchQuery {
                text: literal,
                max_hits: MAX_EXACT_LITERAL_HITS,
                max_files: MAX_EXACT_SCAN_FILES,
                max_file_bytes: MAX_EXACT_FILE_BYTES,
                max_line_bytes: MAX_EXACT_LINE_BYTES,
            },
        )?;
        let (source_snapshot, source_fingerprint) = self.exact_diagnostics()?;
        let selected = hits
            .iter()
            .map(|hit| EvidenceItem::from_search_hit(hit, "bounded exact literal search"))
            .collect::<Vec<_>>();
        let candidate_ids = selected
            .iter()
            .map(|item| item.evidence_id.clone())
            .collect::<Vec<_>>();
        Ok(ChannelResult {
            candidates: selected.len(),
            candidate_ids,
            sufficient: !selected.is_empty(),
            selected,
            freshness_checked: true,
            stale_rejected: Some(0),
            source_refresh_count: 0,
            source_snapshot: Some(source_snapshot),
            source_fingerprint: Some(source_fingerprint),
            bound: None,
        })
    }

    fn lexical(&mut self, repository_id: &str, query: &str) -> Result<ChannelResult, Self::Error> {
        self.ensure_repository(repository_id)?;
        let before_generation = self.lexical.snapshot()?.map(|snapshot| snapshot.generation);
        let hits = self.lexical.search(&LexicalQuery {
            text: query,
            max_hits: MAX_LEXICAL_HITS,
        })?;
        let snapshot = self.lexical.snapshot()?;
        let after_generation = snapshot.as_ref().map(|value| value.generation);
        let refresh_count = generation_delta(before_generation, after_generation);
        let selected = hits.iter().map(lexical_item).collect::<Vec<_>>();
        let candidate_ids = selected
            .iter()
            .map(|item| item.evidence_id.clone())
            .collect::<Vec<_>>();
        Ok(ChannelResult {
            candidates: selected.len(),
            candidate_ids,
            sufficient: !selected.is_empty(),
            selected,
            freshness_checked: true,
            stale_rejected: None,
            source_refresh_count: refresh_count,
            source_snapshot: snapshot
                .as_ref()
                .map(|value| format!("generation={}", value.generation)),
            source_fingerprint: snapshot.map(|value| value.source_manifest_digest),
            bound: None,
        })
    }

    fn symbol(&mut self, repository_id: &str, symbol: &str) -> Result<ChannelResult, Self::Error> {
        self.ensure_repository(repository_id)?;
        let before = self.structural_diagnostics()?;
        let result = self
            .structural
            .definitions_bounded(symbol, MAX_SYMBOL_RESULTS)?;
        let records = result.rows;
        if records
            .iter()
            .any(|record| record.repository_id != repository_id)
        {
            return Err(RepoError::UnknownRepository(repository_id.to_owned()));
        }
        let after = self.structural_diagnostics()?;
        Ok(bounded_derived_result(
            records.iter().map(symbol_item).collect(),
            result.total,
            MAX_SYMBOL_RESULTS,
            "symbol_results",
            true,
            generation_delta(before.generation, after.generation),
            after,
        ))
    }

    fn symbols_for_path(
        &mut self,
        repository_id: &str,
        path: &Path,
    ) -> Result<ChannelResult, Self::Error> {
        self.ensure_repository(repository_id)?;
        let before = self.structural_diagnostics()?;
        let lookup = self
            .structural
            .structural_for_path_bounded(path, MAX_SYMBOL_RESULTS)?;
        let after = self.structural_diagnostics()?;
        let observed = lookup.total;
        let (freshness_checked, records) = match lookup.lookup {
            StructuralLookup::Indexed(records) => (true, records),
            StructuralLookup::UnsupportedLanguage { .. } => (false, Vec::new()),
        };
        if records
            .iter()
            .any(|record| record.repository_id != repository_id)
        {
            return Err(RepoError::UnknownRepository(repository_id.to_owned()));
        }
        Ok(bounded_derived_result(
            records.iter().map(symbol_item).collect(),
            observed,
            MAX_SYMBOL_RESULTS,
            "touched_path_symbol_results",
            freshness_checked,
            generation_delta(before.generation, after.generation),
            after,
        ))
    }

    fn structural(
        &mut self,
        repository_id: &str,
        anchor: &Path,
    ) -> Result<ChannelResult, Self::Error> {
        self.ensure_repository(repository_id)?;
        let before = self.structural_diagnostics()?;
        let outgoing = self
            .structural
            .import_neighborhood_bounded(anchor, MAX_STRUCTURAL_RESULTS)?;
        let inbound = self
            .structural
            .dependent_neighborhood_bounded(anchor, MAX_STRUCTURAL_RESULTS)?;
        let observed = outgoing.total.saturating_add(inbound.total);
        let mut edges = outgoing.rows;
        edges.extend(inbound.rows);
        edges.sort_by(|left, right| {
            (
                &left.source_path,
                &left.relation,
                &left.target,
                &left.source_digest,
            )
                .cmp(&(
                    &right.source_path,
                    &right.relation,
                    &right.target,
                    &right.source_digest,
                ))
        });
        edges.dedup_by(|left, right| {
            left.source_path == right.source_path
                && left.relation == right.relation
                && left.target == right.target
                && left.source_digest == right.source_digest
        });
        if edges.iter().any(|edge| edge.repository_id != repository_id) {
            return Err(RepoError::UnknownRepository(repository_id.to_owned()));
        }
        let after = self.structural_diagnostics()?;
        Ok(bounded_derived_result(
            edges.iter().map(dependency_item).collect(),
            observed,
            MAX_STRUCTURAL_RESULTS,
            "structural_neighborhood_results",
            true,
            generation_delta(before.generation, after.generation),
            after,
        ))
    }
}

fn bounded_derived_result(
    mut selected: Vec<EvidenceItem>,
    observed: usize,
    limit: usize,
    subject: &str,
    freshness_checked: bool,
    source_refresh_count: usize,
    diagnostics: SourceDiagnostics,
) -> ChannelResult {
    let truncated = observed > limit;
    selected.truncate(limit);
    let candidate_ids = selected
        .iter()
        .map(|item| item.evidence_id.clone())
        .collect::<Vec<_>>();
    ChannelResult {
        candidates: observed,
        candidate_ids,
        sufficient: !selected.is_empty(),
        selected,
        freshness_checked,
        stale_rejected: None,
        source_refresh_count,
        source_snapshot: diagnostics.snapshot,
        source_fingerprint: diagnostics.fingerprint,
        bound: Some(RouteBoundFact {
            subject: subject.to_owned(),
            observed,
            limit,
            truncated,
        }),
    }
}

/// Normalized episodic key. M4 can plug a persistent provider into this hook.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureHistoryKey {
    pub repository_id: String,
    pub normalized_signature: String,
    pub tool: String,
    pub symbol: Option<String>,
}

/// Optional history interface. M2 constructs the key but has no provider by default.
pub trait HistoryProvider {
    type Error;

    fn lookup_key(&mut self, key: &FailureHistoryKey) -> Result<ChannelResult, Self::Error>;
    fn lookup_text(
        &mut self,
        repository_id: &str,
        text: &str,
    ) -> Result<ChannelResult, Self::Error>;
}

/// Progressive context-level policy. C0 stays mandatory controller state; direct source is C1,
/// focused routed expansion is C2, and topology/history expansion is C3.
#[derive(Debug, Clone, Copy, Default)]
pub struct ContextLevelPolicy;

impl ContextLevelPolicy {
    #[must_use]
    pub const fn channel_level(channel: Channel, topology_primary: bool) -> ContextLevel {
        match channel {
            Channel::Diff | Channel::Exact => ContextLevel::C1,
            Channel::Structural if topology_primary => ContextLevel::C3,
            Channel::Lexical | Channel::Symbol | Channel::Structural => ContextLevel::C2,
            Channel::History | Channel::Semantic => ContextLevel::C3,
        }
    }

    #[must_use]
    pub const fn maximum_for(intent: &RetrievalIntent) -> ContextLevel {
        match intent {
            RetrievalIntent::KnownPath { .. }
            | RetrievalIntent::LiteralError { .. }
            | RetrievalIntent::KnownSymbol { .. }
            | RetrievalIntent::Behavior { .. } => ContextLevel::C2,
            RetrievalIntent::Impact { .. }
            | RetrievalIntent::Diff { .. }
            | RetrievalIntent::FailureHistory { .. }
            | RetrievalIntent::Fuzzy { .. } => ContextLevel::C3,
        }
    }
}

/// Complete deterministic trace for one route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetrievalTrace {
    pub trace_id: String,
    pub route: Vec<RouteStep>,
    pub candidate_count: usize,
    pub selected_count: usize,
    pub evidence_channels: Vec<EvidenceChannelLink>,
    pub freshness_checked: bool,
    pub stale_rejected: Option<usize>,
    pub source_refresh_count: usize,
    pub source_snapshot: Option<String>,
    pub source_fingerprint: Option<String>,
    pub expansion_count: usize,
    pub stop_reason: StopCondition,
    pub semantic_available: bool,
    pub semantic_unavailable_reason: Option<String>,
}

/// Selected evidence plus its trace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetrievalOutcome {
    pub evidence: Vec<EvidenceItem>,
    pub trace: RetrievalTrace,
}

/// Deterministic sequential router. It never fans out to all retrievers.
#[derive(Debug, Clone, Copy, Default)]
pub struct RetrievalRouter;

impl RetrievalRouter {
    /// Routes one intent with no history provider, which is the M2 default.
    pub fn route<B: RetrievalBackend>(
        &self,
        backend: &mut B,
        intent: &RetrievalIntent,
    ) -> Result<RetrievalOutcome, B::Error> {
        self.route_with_history::<B, NoHistory<B::Error>>(backend, intent, None)
    }

    /// Routes one intent with an optional M4-compatible history provider.
    pub fn route_with_history<B, H>(
        &self,
        backend: &mut B,
        intent: &RetrievalIntent,
        history: Option<&mut H>,
    ) -> Result<RetrievalOutcome, B::Error>
    where
        B: RetrievalBackend,
        H: HistoryProvider<Error = B::Error>,
    {
        let mut collector = TraceCollector::new(intent);
        match intent {
            RetrievalIntent::KnownPath {
                repository_id,
                path,
            } => {
                let result = backend.exact_path(repository_id, path)?;
                let sufficient = result.sufficient;
                collector.accept(
                    Channel::Exact,
                    "known path uses exact current source",
                    result,
                    false,
                    None,
                );
                collector.stop(if sufficient {
                    StopCondition::Satisfied
                } else {
                    StopCondition::InsufficientExact
                });
            }
            RetrievalIntent::LiteralError {
                repository_id,
                literal,
            } => {
                let exact = backend.exact_literal(repository_id, literal)?;
                let sufficient = exact.sufficient;
                collector.accept(
                    Channel::Exact,
                    "literal error starts with bounded exact search",
                    exact,
                    false,
                    None,
                );
                if sufficient {
                    collector.stop(StopCondition::Satisfied);
                } else {
                    let lexical = backend.lexical(repository_id, literal)?;
                    let lexical_sufficient = lexical.sufficient;
                    collector.accept(
                        Channel::Lexical,
                        "exact literal evidence was insufficient; bounded lexical fallback",
                        lexical,
                        false,
                        None,
                    );
                    collector.stop(if lexical_sufficient {
                        StopCondition::Satisfied
                    } else {
                        StopCondition::NoEvidence
                    });
                }
            }
            RetrievalIntent::KnownSymbol {
                repository_id,
                symbol,
            } => {
                let exact = backend.exact_literal(repository_id, symbol)?;
                collector.accept(
                    Channel::Exact,
                    "known symbol starts with exact symbol-name lookup",
                    exact,
                    false,
                    None,
                );
                let symbol_result = backend.symbol(repository_id, symbol)?;
                let sufficient = symbol_result.sufficient;
                collector.accept(
                    Channel::Symbol,
                    "known symbol resolves definitions without lexical FTS fanout",
                    symbol_result,
                    false,
                    None,
                );
                collector.stop(if sufficient {
                    StopCondition::Satisfied
                } else {
                    StopCondition::NoEvidence
                });
            }
            RetrievalIntent::Behavior {
                repository_id,
                query,
            } => {
                let lexical = backend.lexical(repository_id, query)?;
                let sufficient = lexical.sufficient;
                let anchor = lexical.selected.first().and_then(evidence_path);
                collector.accept(
                    Channel::Lexical,
                    "behavior query starts with bounded lexical retrieval",
                    lexical,
                    false,
                    None,
                );
                if sufficient {
                    collector.stop(StopCondition::Satisfied);
                } else if let Some(anchor) = anchor {
                    let structural = backend.structural(repository_id, &anchor)?;
                    collector.accept(
                        Channel::Structural,
                        "one structural anchor expansion after lexical gap",
                        structural,
                        false,
                        None,
                    );
                    collector.expansion_count = 1;
                    collector.stop(StopCondition::StructuralExpansionComplete);
                } else {
                    collector.stop(StopCondition::NoEvidence);
                }
            }
            RetrievalIntent::Impact {
                repository_id,
                anchor,
            } => {
                let result = backend.structural(repository_id, anchor)?;
                collector.accept(
                    Channel::Structural,
                    "impact/topology query uses structural graph as primary channel",
                    result,
                    true,
                    None,
                );
                collector.expansion_count = 1;
                collector.stop(StopCondition::StructuralExpansionComplete);
            }
            RetrievalIntent::Diff { repository_id } => {
                let diff = backend.current_diff(repository_id)?;
                let mut paths = diff.touched_paths;
                paths.sort();
                paths.dedup();
                let observed = paths.len();
                let truncated = observed > MAX_DIFF_TOUCHED_PATHS;
                paths.truncate(MAX_DIFF_TOUCHED_PATHS);
                let diff_sufficient = diff.evidence.sufficient;
                collector.accept(
                    Channel::Diff,
                    "current Git diff is the authoritative diff route source",
                    diff.evidence,
                    false,
                    Some(RouteBoundFact {
                        subject: "diff_touched_paths".to_owned(),
                        observed,
                        limit: MAX_DIFF_TOUCHED_PATHS,
                        truncated,
                    }),
                );
                for path in &paths {
                    let exact = backend.exact_path(repository_id, path)?;
                    collector.accept(
                        Channel::Exact,
                        "diff prioritizes exact current touched path",
                        exact,
                        false,
                        None,
                    );
                }
                for path in &paths {
                    let symbols = backend.symbols_for_path(repository_id, path)?;
                    collector.accept(
                        Channel::Symbol,
                        "diff prioritizes structural symbols from exact current touched path",
                        symbols,
                        false,
                        None,
                    );
                }
                for path in &paths {
                    let structural = backend.structural(repository_id, path)?;
                    collector.accept(
                        Channel::Structural,
                        "diff expands touched path through structural neighbors",
                        structural,
                        false,
                        None,
                    );
                    collector.expansion_count = collector.expansion_count.saturating_add(1);
                }
                collector.stop(if !diff_sufficient && paths.is_empty() {
                    StopCondition::NoEvidence
                } else {
                    StopCondition::StructuralExpansionComplete
                });
            }
            RetrievalIntent::FailureHistory {
                repository_id,
                normalized_signature,
                tool,
                symbol,
                text_fallback,
            } => {
                let Some(provider) = history else {
                    collector.note(Channel::History, "history provider absent until M4");
                    collector.stop(StopCondition::HistoryUnavailable);
                    return Ok(collector.finish());
                };
                let key = FailureHistoryKey {
                    repository_id: repository_id.clone(),
                    normalized_signature: normalized_signature.clone(),
                    tool: tool.clone(),
                    symbol: symbol.clone(),
                };
                let keyed = provider.lookup_key(&key)?;
                let sufficient = keyed.sufficient;
                collector.accept(
                    Channel::History,
                    "normalized signature/repo/tool/symbol lookup",
                    keyed,
                    true,
                    None,
                );
                if sufficient {
                    collector.stop(StopCondition::Satisfied);
                } else {
                    let text = provider.lookup_text(repository_id, text_fallback)?;
                    let text_sufficient = text.sufficient;
                    collector.accept(
                        Channel::History,
                        "provider text fallback after normalized key miss",
                        text,
                        true,
                        None,
                    );
                    collector.stop(if text_sufficient {
                        StopCondition::Satisfied
                    } else {
                        StopCondition::NoEvidence
                    });
                }
            }
            RetrievalIntent::Fuzzy {
                repository_id,
                query,
            } => {
                let lexical = backend.lexical(repository_id, query)?;
                let sufficient = lexical.sufficient;
                let anchor = lexical.selected.first().and_then(evidence_path);
                collector.accept(
                    Channel::Lexical,
                    "fuzzy query first attempts bounded lexical retrieval",
                    lexical,
                    false,
                    None,
                );
                if sufficient {
                    collector.stop(StopCondition::Satisfied);
                } else {
                    if let Some(anchor) = anchor {
                        let structural = backend.structural(repository_id, &anchor)?;
                        let structural_sufficient = structural.sufficient;
                        collector.accept(
                            Channel::Structural,
                            "one structural anchor expansion after lexical gap",
                            structural,
                            false,
                            None,
                        );
                        collector.expansion_count = 1;
                        if structural_sufficient {
                            collector.stop(StopCondition::StructuralExpansionComplete);
                            return Ok(collector.finish());
                        }
                    }
                    collector.note(
                        Channel::Semantic,
                        "lexical/structural gap remains; semantic retrieval is unavailable in M2",
                    );
                    collector.stop(StopCondition::SemanticUnavailable);
                }
            }
        }
        Ok(collector.finish())
    }
}

struct NoHistory<E>(PhantomData<E>);

impl<E> HistoryProvider for NoHistory<E> {
    type Error = E;

    fn lookup_key(&mut self, _key: &FailureHistoryKey) -> Result<ChannelResult, Self::Error> {
        unreachable!("M2 default route never constructs a history provider")
    }

    fn lookup_text(
        &mut self,
        _repository_id: &str,
        _text: &str,
    ) -> Result<ChannelResult, Self::Error> {
        unreachable!("M2 default route never constructs a history provider")
    }
}

struct TraceCollector {
    intent_digest: String,
    route: Vec<RouteStep>,
    evidence: Vec<EvidenceItem>,
    evidence_channels: Vec<EvidenceChannelLink>,
    candidate_count: usize,
    freshness_checked: bool,
    stale_rejected: Option<usize>,
    source_refresh_count: usize,
    source_snapshot: Option<String>,
    source_fingerprint: Option<String>,
    expansion_count: usize,
    stop_reason: StopCondition,
}

impl TraceCollector {
    fn new(intent: &RetrievalIntent) -> Self {
        let encoded = serde_json::to_vec(intent).unwrap_or_default();
        Self {
            intent_digest: sha256_prefixed(&encoded),
            route: Vec::new(),
            evidence: Vec::new(),
            evidence_channels: Vec::new(),
            candidate_count: 0,
            freshness_checked: false,
            stale_rejected: Some(0),
            source_refresh_count: 0,
            source_snapshot: None,
            source_fingerprint: None,
            expansion_count: 0,
            stop_reason: StopCondition::NoEvidence,
        }
    }

    fn accept(
        &mut self,
        channel: Channel,
        reason: &str,
        mut result: ChannelResult,
        topology_primary: bool,
        bound: Option<RouteBoundFact>,
    ) {
        let selected_ids = result
            .selected
            .iter()
            .map(|item| item.evidence_id.clone())
            .collect::<Vec<_>>();
        let route_bound = bound.or_else(|| result.bound.take());
        self.route.push(RouteStep {
            channel,
            reason: reason.to_owned(),
            candidate_count: result.candidates,
            selected_count: result.selected.len(),
            candidate_ids: result.candidate_ids.clone(),
            selected_ids,
            freshness_checked: result.freshness_checked,
            stale_rejected: result.stale_rejected,
            source_refresh_count: result.source_refresh_count,
            source_snapshot: result.source_snapshot.clone(),
            source_fingerprint: result.source_fingerprint.clone(),
            bound: route_bound,
        });
        self.candidate_count = self.candidate_count.saturating_add(result.candidates);
        self.freshness_checked |= result.freshness_checked;
        self.stale_rejected = match (self.stale_rejected, result.stale_rejected) {
            (Some(total), Some(step)) => Some(total.saturating_add(step)),
            _ => None,
        };
        self.source_refresh_count = self
            .source_refresh_count
            .saturating_add(result.source_refresh_count);
        if result.source_snapshot.is_some() {
            self.source_snapshot = result.source_snapshot.take();
        }
        if result.source_fingerprint.is_some() {
            self.source_fingerprint = result.source_fingerprint.take();
        }
        let level = ContextLevelPolicy::channel_level(channel, topology_primary);
        for mut item in result.selected {
            item.level = level;
            if level >= ContextLevel::C2 {
                item.section = PacketSection::RoutedExpansion;
            }
            self.evidence_channels.push(EvidenceChannelLink {
                evidence_id: item.evidence_id.clone(),
                channel,
                source_digest: item.source_digest.clone(),
                content_digest: item.content_digest.clone(),
            });
            self.evidence.push(item);
        }
    }

    fn note(&mut self, channel: Channel, reason: &str) {
        self.route.push(RouteStep {
            channel,
            reason: reason.to_owned(),
            candidate_count: 0,
            selected_count: 0,
            candidate_ids: Vec::new(),
            selected_ids: Vec::new(),
            freshness_checked: false,
            stale_rejected: None,
            source_refresh_count: 0,
            source_snapshot: None,
            source_fingerprint: None,
            bound: None,
        });
    }

    const fn stop(&mut self, reason: StopCondition) {
        self.stop_reason = reason;
    }

    fn finish(self) -> RetrievalOutcome {
        let selected_count = self.evidence.len();
        let mut trace_material = self.intent_digest.clone();
        for step in &self.route {
            trace_material.push('|');
            let _ = write!(trace_material, "{:?}", step.channel);
            trace_material.push(':');
            trace_material.push_str(&step.reason);
            let _ = write!(
                trace_material,
                ":candidates={}:selected={}:fresh={}:stale={:?}:refresh={}:snapshot={:?}:fingerprint={:?}:bound={:?}",
                step.candidate_count,
                step.selected_count,
                step.freshness_checked,
                step.stale_rejected,
                step.source_refresh_count,
                step.source_snapshot,
                step.source_fingerprint,
                step.bound
            );
            for candidate_id in &step.candidate_ids {
                trace_material.push_str(":candidate=");
                trace_material.push_str(candidate_id);
            }
            for selected_id in &step.selected_ids {
                trace_material.push_str(":selected_id=");
                trace_material.push_str(selected_id);
            }
        }
        for link in &self.evidence_channels {
            trace_material.push('|');
            trace_material.push_str(&link.evidence_id);
            trace_material.push(':');
            let _ = write!(trace_material, "{:?}", link.channel);
        }
        for item in &self.evidence {
            trace_material.push_str("|evidence_digest=");
            trace_material.push_str(&item.evidence_id);
            trace_material.push(':');
            trace_material.push_str(&item.source_digest);
            trace_material.push(':');
            trace_material.push_str(&item.content_digest);
        }
        let _ = write!(
            trace_material,
            "|candidates={}|selected={selected_count}|stale={:?}|refresh={}|snapshot={:?}|fingerprint={:?}|expansions={}|stop={:?}",
            self.candidate_count,
            self.stale_rejected,
            self.source_refresh_count,
            self.source_snapshot,
            self.source_fingerprint,
            self.expansion_count,
            self.stop_reason
        );
        let trace_id = format!("retrieval:{}", sha256_prefixed(trace_material.as_bytes()));
        RetrievalOutcome {
            evidence: self.evidence,
            trace: RetrievalTrace {
                trace_id,
                route: self.route,
                candidate_count: self.candidate_count,
                selected_count,
                evidence_channels: self.evidence_channels,
                freshness_checked: self.freshness_checked,
                stale_rejected: self.stale_rejected,
                source_refresh_count: self.source_refresh_count,
                source_snapshot: self.source_snapshot,
                source_fingerprint: self.source_fingerprint,
                expansion_count: self.expansion_count,
                stop_reason: self.stop_reason,
                semantic_available: false,
                semantic_unavailable_reason: Some(
                    "semantic retrieval is unavailable in M2".to_owned(),
                ),
            },
        }
    }
}

fn evidence_path(item: &EvidenceItem) -> Option<PathBuf> {
    item.locator
        .as_deref()
        .and_then(|locator| locator.strip_prefix("path:"))
        .map(PathBuf::from)
}

fn generation_delta(before: Option<u64>, after: Option<u64>) -> usize {
    let delta = match (before, after) {
        (Some(before), Some(after)) => after.saturating_sub(before),
        (None, Some(_)) => 1,
        _ => 0,
    };
    usize::try_from(delta).unwrap_or(usize::MAX)
}

fn touched_paths_from_diff(diff: &str) -> Vec<PathBuf> {
    let mut paths = BTreeSet::new();
    for line in diff.lines() {
        let raw = line
            .strip_prefix("+++ b/")
            .or_else(|| line.strip_prefix("--- a/"))
            .or_else(|| line.strip_prefix("rename from "))
            .or_else(|| line.strip_prefix("rename to "))
            .or_else(|| line.strip_prefix("copy from "))
            .or_else(|| line.strip_prefix("copy to "));
        let Some(raw) = raw else {
            continue;
        };
        if raw.is_empty() || raw == "/dev/null" {
            continue;
        }
        paths.insert(PathBuf::from(raw));
    }
    paths.into_iter().collect()
}

fn lexical_item(hit: &sovereign_repo::LexicalHit) -> EvidenceItem {
    EvidenceItem::new(
        format!(
            "lexical:{}:{}:{}",
            hit.repository_id,
            hit.relative_path.display(),
            hit.chunk_ordinal
        ),
        PacketSection::RoutedExpansion,
        ContextLevel::C2,
        EvidenceKind::SearchHit,
        format!(
            "repo://{}/{}",
            hit.repository_id,
            hit.relative_path.display()
        ),
        hit.source_digest.clone(),
        "fts5_bm25",
        TrustClass::Derived,
        "bounded lexical retrieval",
        hit.content.clone(),
    )
    .with_repository(hit.repository_id.clone())
    .with_locator(format!("path:{}", hit.relative_path.display()))
}

fn symbol_item(record: &sovereign_repo::SymbolRecord) -> EvidenceItem {
    EvidenceItem::new(
        format!(
            "symbol:{}:{}:{}:{}",
            record.repository_id,
            record.relative_path.display(),
            record.name,
            record.start_line
        ),
        PacketSection::RoutedExpansion,
        ContextLevel::C2,
        EvidenceKind::RoutedExpansion,
        format!(
            "repo://{}/{}",
            record.repository_id,
            record.relative_path.display()
        ),
        record.source_digest.clone(),
        format!(
            "structural_symbol:{}:{}",
            record.parser_fingerprint, record.schema_fingerprint
        ),
        TrustClass::Derived,
        "exact symbol definition index",
        format!(
            "{} {} at {}:{}-{}",
            record.kind,
            record.name,
            record.relative_path.display(),
            record.start_line,
            record.end_line
        ),
    )
    .with_repository(record.repository_id.clone())
    .with_locator(format!("path:{}", record.relative_path.display()))
}

fn dependency_item(edge: &sovereign_repo::DependencyEdge) -> EvidenceItem {
    EvidenceItem::new(
        format!(
            "structural:{}:{}:{}:{}",
            edge.repository_id,
            edge.source_path.display(),
            edge.relation,
            edge.target
        ),
        PacketSection::RoutedExpansion,
        ContextLevel::C2,
        EvidenceKind::RoutedExpansion,
        format!(
            "repo://{}/{}",
            edge.repository_id,
            edge.source_path.display()
        ),
        edge.source_digest.clone(),
        format!(
            "structural_graph:{}:{}",
            edge.parser_fingerprint, edge.schema_fingerprint
        ),
        TrustClass::Derived,
        "structural dependency neighborhood",
        format!(
            "{} {} -> {}",
            edge.source_path.display(),
            edge.relation,
            edge.target
        ),
    )
    .with_repository(edge.repository_id.clone())
    .with_locator(format!("path:{}", edge.source_path.display()))
}
