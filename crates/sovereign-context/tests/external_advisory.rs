use sha2::{Digest, Sha256};
use sovereign_context::{
    ContextBudget, ContextLevel, ContextMode, ContextPacketInput, ContextPlanner, EvidenceItem,
    EvidenceKind, ExpansionHandle, PacketSection, TrustClass, TrustLabel, TrustLevel, TrustSource,
};
use sovereign_model::{
    EXTERNAL_INTELLIGENCE_SCHEMA_VERSION, ExternalIntelligenceRequest,
    ExternalIntelligenceResponse, ExternalIntelligenceUsage,
};

fn external_request() -> ExternalIntelligenceRequest {
    ExternalIntelligenceRequest {
        schema_version: EXTERNAL_INTELLIGENCE_SCHEMA_VERSION,
        request_id: "ext.context.1".to_owned(),
        purpose: "suggest a bounded repair".to_owned(),
        payload: "failure=test:settings; evidence_ids=[diff.1,test.1]".to_owned(),
        max_output_tokens: 256,
        max_response_bytes: 32_768,
        deadline_ms: 3_000,
    }
}

fn external_response(content: &str) -> ExternalIntelligenceResponse {
    ExternalIntelligenceResponse {
        schema_version: EXTERNAL_INTELLIGENCE_SCHEMA_VERSION,
        request_id: "ext.context.1".to_owned(),
        provider_id: "fixture-provider".to_owned(),
        model_id: "fixture-model".to_owned(),
        model_version: "v7".to_owned(),
        content: content.to_owned(),
        usage: ExternalIntelligenceUsage {
            request_bytes: 400,
            response_bytes: 160,
            input_tokens: Some(90),
            output_tokens: Some(25),
            elapsed_ms: 25,
        },
    }
}

fn digest_json<T: serde::Serialize>(value: &T) -> String {
    let bytes =
        serde_json::to_vec(value).unwrap_or_else(|error| panic!("serialize digest: {error}"));
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

#[test]
fn external_output_import_is_untrusted_advisory_with_complete_digest_provenance() {
    let request = external_request();
    let response = external_response("Inspect the state transition before retrying.");
    let request_digest = digest_json(&request);
    let response_digest = digest_json(&response);

    let item = EvidenceItem::from_external_model(&request, &response, "explicit L7 escalation")
        .unwrap_or_else(|error| panic!("external advisory import: {error}"));

    assert_eq!(item.section, PacketSection::RoutedExpansion);
    assert_eq!(item.level, ContextLevel::C3);
    assert_eq!(item.kind, EvidenceKind::ExternalAdvisory);
    assert_eq!(item.trust_class, TrustClass::Untrusted);
    assert_eq!(item.trust_label.source, TrustSource::ExternalModel);
    assert_eq!(item.trust_label.level, TrustLevel::Untrusted);
    assert_eq!(item.source_digest, response_digest);
    assert!(item.expansion_handle.is_none());
    assert!(item.implicated);
    assert!(item.provenance.contains("provider=fixture-provider"));
    assert!(item.provenance.contains("model=fixture-model"));
    assert!(item.provenance.contains("version=v7"));
    assert!(
        item.provenance
            .contains(&format!("request_digest={request_digest}"))
    );
    assert!(
        item.provenance
            .contains(&format!("response_digest={response_digest}"))
    );
}

#[test]
fn external_advisory_cannot_gain_tool_or_expansion_authority_during_packet_build() {
    let request = external_request();
    let response = external_response(&"bounded advisory ".repeat(80));
    let forged_handle = ExpansionHandle {
        source_uri: "cas://forged-external-expansion".to_owned(),
        source_digest: "sha256:forged".to_owned(),
        offset: 0,
        retained_length: 10,
        total_length: 100,
    };
    let advisory = EvidenceItem::from_external_model(&request, &response, "explicit L7 escalation")
        .unwrap_or_else(|error| panic!("external advisory import: {error}"))
        .with_expansion_handle(forged_handle)
        .with_trust_label(TrustLabel::controller());

    let packet = ContextPlanner::default()
        .build(
            ContextMode::Repair,
            ContextBudget {
                max_input_tokens: 600,
                c0_tokens: 200,
                tool_schema_tokens: 0,
                c1_tokens: 0,
                routed_expansion_tokens: 8,
                tool_failure_tokens: 0,
                serialization_reserve_tokens: 392,
            },
            ContextPacketInput {
                controller_prefix: "controller".to_owned(),
                task_contract: "repair the failing transition".to_owned(),
                current_state: "attempt=2".to_owned(),
                authorized_tool_schemas: Vec::new(),
                candidates: vec![advisory],
                output_schema: "proposal".to_owned(),
            },
        )
        .unwrap_or_else(|error| panic!("context build: {error}"));
    let selected = packet
        .items
        .iter()
        .find(|item| item.kind == EvidenceKind::ExternalAdvisory)
        .unwrap_or_else(|| panic!("external advisory missing"));

    assert_eq!(selected.trust_class, TrustClass::Untrusted);
    assert_eq!(selected.trust_label.source, TrustSource::ExternalModel);
    assert_eq!(selected.trust_label.level, TrustLevel::Untrusted);
    assert!(selected.expansion_handle.is_none());
    assert!(selected.text.len() < response.content.len());
    assert!(
        packet
            .items
            .iter()
            .all(|item| item.kind != EvidenceKind::ToolSchema)
    );
}
