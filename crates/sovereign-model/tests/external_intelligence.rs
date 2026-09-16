use sovereign_model::{
    EXTERNAL_INTELLIGENCE_SCHEMA_VERSION, ExternalIntelligenceError, ExternalIntelligenceErrorKind,
    ExternalIntelligenceProvider, ExternalIntelligenceRequest, ExternalIntelligenceResponse,
    ExternalIntelligenceUsage,
};

struct FakeExternalProvider {
    provider_id: String,
    model_id: String,
    model_version: String,
}

impl Default for FakeExternalProvider {
    fn default() -> Self {
        Self {
            provider_id: "fixture-provider".to_owned(),
            model_id: "fixture-reasoner".to_owned(),
            model_version: "2026-09".to_owned(),
        }
    }
}

impl ExternalIntelligenceProvider for FakeExternalProvider {
    fn provider_id(&self) -> &str {
        &self.provider_id
    }

    fn model_id(&self) -> &str {
        &self.model_id
    }

    fn model_version(&self) -> &str {
        &self.model_version
    }

    fn complete_external(
        &self,
        request: &ExternalIntelligenceRequest,
    ) -> Result<ExternalIntelligenceResponse, ExternalIntelligenceError> {
        request.validate()?;
        Ok(ExternalIntelligenceResponse {
            schema_version: EXTERNAL_INTELLIGENCE_SCHEMA_VERSION,
            request_id: request.request_id.clone(),
            provider_id: self.provider_id().to_owned(),
            model_id: self.model_id().to_owned(),
            model_version: self.model_version().to_owned(),
            content: "Advisory: inspect the bounded failure evidence.".to_owned(),
            usage: ExternalIntelligenceUsage {
                request_bytes: 321,
                response_bytes: 123,
                input_tokens: Some(47),
                output_tokens: Some(11),
                elapsed_ms: 9,
            },
        })
    }
}

fn request() -> ExternalIntelligenceRequest {
    ExternalIntelligenceRequest {
        schema_version: EXTERNAL_INTELLIGENCE_SCHEMA_VERSION,
        request_id: "ext.fixture.1".to_owned(),
        purpose: "diagnose bounded test failure".to_owned(),
        payload: "evidence_id=test.failure; synopsis=assertion mismatch".to_owned(),
        max_output_tokens: 256,
        max_response_bytes: 16_384,
        deadline_ms: 2_000,
    }
}

#[test]
fn external_provider_contract_is_optional_tool_free_and_provider_neutral() {
    let no_provider: Option<&dyn ExternalIntelligenceProvider> = None;
    assert!(no_provider.is_none());

    let request = request();
    request
        .validate()
        .unwrap_or_else(|error| panic!("request validation: {error}"));
    let encoded =
        serde_json::to_value(&request).unwrap_or_else(|error| panic!("serialize request: {error}"));
    assert!(encoded.get("tools").is_none());
    assert!(encoded.get("tool_choice").is_none());
    assert!(encoded.get("credentials").is_none());
    assert!(encoded.get("approval").is_none());

    let provider = FakeExternalProvider::default();
    let response = provider
        .complete_external(&request)
        .unwrap_or_else(|error| panic!("fake external completion: {error}"));
    response
        .validate_for(&request)
        .unwrap_or_else(|error| panic!("response validation: {error}"));
    assert_eq!(response.provider_id, provider.provider_id());
    assert_eq!(response.model_id, provider.model_id());
    assert_eq!(response.model_version, provider.model_version());
    assert_eq!(response.usage.network_bytes(), 444);
}

#[test]
fn external_contract_rejects_identity_mismatch_and_preserves_failure_usage() {
    let request = request();
    let mismatched = ExternalIntelligenceResponse {
        schema_version: EXTERNAL_INTELLIGENCE_SCHEMA_VERSION,
        request_id: "different-request".to_owned(),
        provider_id: "fixture-provider".to_owned(),
        model_id: "fixture-reasoner".to_owned(),
        model_version: "2026-09".to_owned(),
        content: "advice".to_owned(),
        usage: ExternalIntelligenceUsage::default(),
    };
    let error = match mismatched.validate_for(&request) {
        Ok(()) => panic!("mismatched request id must fail closed"),
        Err(error) => error,
    };
    assert_eq!(error.kind, ExternalIntelligenceErrorKind::InvalidResponse);

    let partial_usage = ExternalIntelligenceUsage {
        request_bytes: 512,
        response_bytes: 17,
        input_tokens: None,
        output_tokens: None,
        elapsed_ms: 2_000,
    };
    let timeout = ExternalIntelligenceError::new(
        ExternalIntelligenceErrorKind::DeadlineExceeded,
        "provider deadline elapsed",
        partial_usage,
    );
    assert_eq!(timeout.usage.network_bytes(), 529);
    assert_eq!(timeout.usage.elapsed_ms, 2_000);
}
