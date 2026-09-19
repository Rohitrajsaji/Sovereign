use crate::schema::{EVAL_REPORT_SCHEMA_VERSION, EvalResourceSourceV1, LocalModelSmokeReportV1};
use serde_json::json;
use sovereign_model::{
    LlamaServerLaunch, LocalOpenAiBackend, LocalOpenAiConfig, MODEL_SCHEMA_VERSION, ModelBackend,
    ModelCapabilities, ModelLoadProfile, ModelMessage, ModelMessageRole, ModelOutputContract,
    ModelRequest, ModelResidencyProof,
};
use std::net::{IpAddr, Ipv4Addr, TcpListener};
use std::path::PathBuf;

/// Explicit physical local-model smoke configuration. The deterministic offline eval does not
/// require or implicitly run this smoke.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalModelSmokeConfig {
    pub runtime: PathBuf,
    pub model_path: PathBuf,
    pub model_id: String,
}

/// Runs one bounded local-model call and proves the owned model process is absent after unload.
///
/// # Errors
/// Returns a descriptive error for model startup, request, structured-output, or unload/residency
/// failure.
pub fn run_local_model_smoke(
    config: &LocalModelSmokeConfig,
) -> Result<LocalModelSmokeReportV1, String> {
    let port = free_loopback_port()?;
    let mut backend_config = LocalOpenAiConfig::with_defaults(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        port,
        &config.model_id,
        ModelCapabilities {
            schema_version: MODEL_SCHEMA_VERSION,
            model_id: config.model_id.clone(),
            parameter_class: "4B".to_owned(),
            quantization: "Q4_K_M".to_owned(),
            max_context_tokens: 16_384,
            supports_tools: true,
            supports_json_schema: true,
            local: true,
        },
    );
    backend_config.request_timeout_ms = 180_000;
    backend_config.launch = Some(LlamaServerLaunch {
        executable: config.runtime.clone(),
        model_path: config.model_path.clone(),
        extra_args: vec!["--reasoning".to_owned(), "off".to_owned()],
    });
    let backend = LocalOpenAiBackend::new(backend_config).map_err(|error| error.to_string())?;
    let lease = backend
        .load(ModelLoadProfile {
            context_tokens: 2_048,
            output_reserve_tokens: 512,
            startup_timeout_ms: 180_000,
            provider_call_timeout_ms: 180_000,
        })
        .map_err(|error| error.to_string())?;
    let request = ModelRequest {
        schema_version: MODEL_SCHEMA_VERSION,
        request_id: "m9-local-model-smoke-v1".to_owned(),
        messages: vec![ModelMessage {
            role: ModelMessageRole::User,
            content: "Return exactly the JSON object {\"ok\":true}. No prose.".to_owned(),
            tool_call_id: None,
        }],
        tools: Vec::new(),
        output_contract: ModelOutputContract::JsonSchema {
            name: "m9_local_model_smoke".to_owned(),
            schema: json!({
                "type": "object",
                "properties": {"ok": {"type": "boolean"}},
                "required": ["ok"],
                "additionalProperties": false
            }),
        },
        input_token_ceiling: 512,
        max_output_tokens: 128,
        deadline_ms: 180_000,
        temperature_milli: 0,
    };
    let response = backend.complete(&request).map_err(|error| {
        let _ = backend.unload();
        error.to_string()
    })?;
    if response
        .structured
        .as_ref()
        .and_then(|value| value.get("ok"))
        .and_then(serde_json::Value::as_bool)
        != Some(true)
    {
        let _ = backend.unload();
        return Err("local model smoke did not return structured ok=true".to_owned());
    }
    backend.unload().map_err(|error| error.to_string())?;
    let residency = backend
        .residency_proof()
        .map_err(|error| error.to_string())?;
    let process_absent_after_unload = matches!(residency, ModelResidencyProof::Absent);
    if !process_absent_after_unload {
        return Err(
            "local model smoke could not prove physical residency absent after unload".into(),
        );
    }
    Ok(LocalModelSmokeReportV1 {
        schema_version: EVAL_REPORT_SCHEMA_VERSION,
        model_id: config.model_id.clone(),
        input_tokens: response.usage.input_tokens,
        output_tokens: response.usage.output_tokens,
        startup_peak_rss_kib: lease.startup_peak_rss_kb,
        post_load_rss_kib: lease.post_load_rss_kb,
        call_peak_rss_kib: response.peak_rss_kb_during_call,
        process_id: lease.process_id,
        process_absent_after_unload,
        resource_source: EvalResourceSourceV1::PhysicalLocalModel,
    })
}

fn free_loopback_port() -> Result<u16, String> {
    let listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|error| error.to_string())?;
    listener
        .local_addr()
        .map(|address| address.port())
        .map_err(|error| error.to_string())
}
