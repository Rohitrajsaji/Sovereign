use sovereign_eval::{EvalResourceSourceV1, LocalModelSmokeConfig, run_local_model_smoke};
use std::path::PathBuf;

fn required_env(name: &str) -> PathBuf {
    std::env::var_os(name).map_or_else(
        || panic!("missing required environment {name}"),
        PathBuf::from,
    )
}

#[test]
#[ignore = "requires the local Qwen GGUF and managed llama.cpp runtime"]
fn local_model_smoke_records_usage_rss_and_unloads() {
    let report = run_local_model_smoke(&LocalModelSmokeConfig {
        runtime: required_env("SOVEREIGN_MODEL_RUNTIME"),
        model_path: required_env("SOVEREIGN_MODEL_PATH"),
        model_id: "Qwen3-4B-Q4_K_M".to_owned(),
    })
    .unwrap_or_else(|error| panic!("M9 local-model smoke: {error}"));
    assert!(report.input_tokens > 0);
    assert!(report.output_tokens > 0);
    assert!(
        report.startup_peak_rss_kib.is_some()
            || report.post_load_rss_kib.is_some()
            || report.call_peak_rss_kib.is_some(),
        "physical local-model smoke must capture at least one real RSS measurement"
    );
    assert!(report.process_absent_after_unload);
    assert_eq!(
        report.resource_source,
        EvalResourceSourceV1::PhysicalLocalModel
    );
}
