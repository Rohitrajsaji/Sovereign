//! Test and e2e-fixtures only. Not compiled into the production binary.
//! Callers: `runner::advance_production_step` under `cfg(any(test, feature = "e2e-fixtures"))`.
//! API: `from_context` returns a `DeterministicFakeBackend` for e2e-fixtures or a state-dir marker.
//! Schema: none. The production `sovereign` binary must not contain this module.
//! User instruction: Continue from the current tree and finish the remaining consumer-product gaps you identified. CX-T10 HTTP execution uses `DeterministicFakeBackend`.

use serde_json::json;
use sovereign_model::{
    DeterministicFakeBackend, MODEL_SCHEMA_VERSION, ModelCapabilities, ModelFinishReason,
    ModelResponse, ModelUsage,
};
use std::path::Path;

/// Returns a compile fixture backend for the e2e binary or an explicit test marker.
#[must_use]
pub fn from_context(state: &Path) -> Option<DeterministicFakeBackend> {
    let marker = state
        .parent()
        .is_some_and(|dir| dir.join("USE_FIXTURE_BACKEND").is_file());
    if !cfg!(feature = "e2e-fixtures") && !marker {
        return None;
    }
    DeterministicFakeBackend::new(
        ModelCapabilities {
            schema_version: MODEL_SCHEMA_VERSION,
            model_id: "sovereign-fixture-backend".to_owned(),
            parameter_class: "4B".to_owned(),
            quantization: "Q4_K_M".to_owned(),
            max_context_tokens: 16_384,
            supports_tools: false,
            supports_json_schema: true,
            local: true,
        },
        vec![ModelResponse {
            schema_version: MODEL_SCHEMA_VERSION,
            request_id: "fixture-compile".to_owned(),
            content: json!({
                "tasks": [{
                    "title": "Inspect the local repository",
                    "objective": "Read the repository without mutating it.",
                    "rationale": "The queued goal is a bounded inspection.",
                    "files": [],
                    "symbols": [],
                    "evidence_queries": [],
                    "expected_change": "The Controller records a compiled plan."
                }]
            })
            .to_string(),
            structured: None,
            tool_calls: Vec::new(),
            finish_reason: ModelFinishReason::Stop,
            usage: ModelUsage::default(),
            elapsed_ms: 0,
            peak_rss_kb_during_call: None,
        }],
    )
    .ok()
}
