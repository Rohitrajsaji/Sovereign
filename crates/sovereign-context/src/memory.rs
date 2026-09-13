use crate::{
    ChannelResult, ContextLevel, EvidenceItem, EvidenceKind, ExpansionHandle, FailureHistoryKey,
    HistoryProvider, PacketSection, RouteBoundFact, TrustClass, sha256_prefixed,
};
use sovereign_memory::{
    FailureSignatureFilter, MemoryError, MemoryKind, MemoryManager, MemoryQuery,
    MemoryRetrievalResult, MemoryRetriever, MemorySynopsis,
};
use std::marker::PhantomData;

/// Production M4 history adapter. Persistent memory is projected into context
/// only as C3 derived evidence; it carries no permission, policy, or completion
/// authority.
pub struct MemoryHistoryProvider<'a, E, F>
where
    F: Fn(MemoryError) -> E,
{
    retriever: MemoryRetriever<'a>,
    project_id: String,
    agent_id: Option<String>,
    role_id: Option<String>,
    now_ms: i64,
    map_error: F,
    error: PhantomData<fn() -> E>,
}

impl<'a, E, F> MemoryHistoryProvider<'a, E, F>
where
    F: Fn(MemoryError) -> E,
{
    /// Binds one memory retriever to the caller's current project/agent/role
    /// visibility envelope. Repository scope remains supplied by each routed
    /// history request.
    pub fn new(
        manager: &'a mut MemoryManager,
        project_id: impl Into<String>,
        agent_id: Option<String>,
        role_id: Option<String>,
        now_ms: i64,
        map_error: F,
    ) -> Self {
        Self {
            retriever: MemoryRetriever::new(manager),
            project_id: project_id.into(),
            agent_id,
            role_id,
            now_ms,
            map_error,
            error: PhantomData,
        }
    }

    fn base_query(&self, repository_id: &str, text: &str) -> MemoryQuery {
        let mut query = MemoryQuery::ordinary(&self.project_id, text);
        query.repository_id = Some(repository_id.to_owned());
        query.agent_id.clone_from(&self.agent_id);
        query.role_id.clone_from(&self.role_id);
        query.kinds = vec![MemoryKind::Episodic];
        query.max_results = 8;
        query.max_tokens = 768;
        query
    }

    fn retrieve(&mut self, query: &MemoryQuery) -> Result<ChannelResult, E> {
        let result = self
            .retriever
            .retrieve(query, self.now_ms)
            .map_err(&self.map_error)?;
        Ok(channel_result(result))
    }
}

impl<E, F> HistoryProvider for MemoryHistoryProvider<'_, E, F>
where
    F: Fn(MemoryError) -> E,
{
    type Error = E;

    fn lookup_key(&mut self, key: &FailureHistoryKey) -> Result<ChannelResult, Self::Error> {
        let mut query = self.base_query(&key.repository_id, &key.normalized_signature);
        query.failure_signature = Some(FailureSignatureFilter {
            normalized_signature: key.normalized_signature.clone(),
            tool: key.tool.clone(),
            runtime_version: None,
            symbol: key.symbol.clone(),
            task_kind: None,
        });
        query.allow_lexical_fallback = false;
        self.retrieve(&query)
    }

    fn lookup_text(
        &mut self,
        repository_id: &str,
        text: &str,
    ) -> Result<ChannelResult, Self::Error> {
        let query = self.base_query(repository_id, text);
        self.retrieve(&query)
    }
}

fn channel_result(result: MemoryRetrievalResult) -> ChannelResult {
    let observed = result
        .synopses
        .len()
        .saturating_add(result.trace.excluded_noncurrent);
    let limit = result.trace.max_results;
    let mut selected = Vec::with_capacity(result.synopses.len());
    let mut fingerprint_parts = Vec::with_capacity(result.synopses.len());
    for synopsis in result.synopses {
        fingerprint_parts.push(format!(
            "{}:{}",
            synopsis.memory_id, synopsis.expansion.content_digest
        ));
        selected.push(evidence_item(synopsis));
    }
    let candidate_ids = selected
        .iter()
        .map(|item| item.evidence_id.clone())
        .collect::<Vec<_>>();
    let source_fingerprint = (!fingerprint_parts.is_empty()).then(|| {
        fingerprint_parts.sort();
        sha256_prefixed(fingerprint_parts.join("\n").as_bytes())
    });
    ChannelResult {
        candidates: observed,
        candidate_ids,
        sufficient: !selected.is_empty(),
        selected,
        freshness_checked: true,
        stale_rejected: Some(result.trace.excluded_noncurrent),
        source_refresh_count: 0,
        source_snapshot: None,
        source_fingerprint,
        bound: Some(RouteBoundFact {
            subject: "persistent_memory_history".to_owned(),
            observed,
            limit,
            truncated: observed > limit,
        }),
    }
}

fn evidence_item(synopsis: MemorySynopsis) -> EvidenceItem {
    let source_uri = format!("memory://{}", synopsis.memory_id);
    let mut item = EvidenceItem::new(
        format!("memory:{}", synopsis.memory_id),
        PacketSection::RoutedExpansion,
        ContextLevel::C3,
        EvidenceKind::FailureSynopsis,
        source_uri.clone(),
        synopsis.expansion.content_digest.clone(),
        format!(
            "persistent_memory;trust={:?};evidence_ids={:?}",
            synopsis.trust, synopsis.expansion.evidence_ids
        ),
        TrustClass::Derived,
        "persistent memory recall is derived evidence only",
        synopsis.rendered,
    )
    .with_locator(format!("memory_id:{}", synopsis.memory_id));
    if let Some(repository_id) = synopsis.repository_id {
        item = item.with_repository(repository_id);
    }
    if let Some(evidence_id) = synopsis.expansion.evidence_ids.first() {
        let retained_length = u64::try_from(item.text.len()).unwrap_or(u64::MAX);
        item = item.with_expansion_handle(ExpansionHandle {
            source_uri: format!("{source_uri}#evidence={evidence_id}"),
            source_digest: synopsis.expansion.content_digest,
            offset: 0,
            retained_length,
            total_length: retained_length,
        });
    }
    item
}
