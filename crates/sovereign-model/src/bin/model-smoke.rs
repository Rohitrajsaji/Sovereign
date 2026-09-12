use serde_json::{Value, json};
use sovereign_model::{
    LlamaServerLaunch, LocalOpenAiBackend, LocalOpenAiConfig, MODEL_SCHEMA_VERSION, ModelBackend,
    ModelCapabilities, ModelLoadProfile, ModelMessage, ModelMessageRole, ModelOutputContract,
    ModelRequest, ModelToolDefinition,
};
use std::error::Error;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const CONTEXT_TIERS: [u32; 4] = [4_096, 8_192, 12_288, 16_384];

struct SmokeConfig {
    runtime: PathBuf,
    model_path: PathBuf,
    model_name: String,
    parameter_class: String,
    quantization: String,
    report_path: PathBuf,
    extra_args: Vec<String>,
}

impl SmokeConfig {
    fn from_env() -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            runtime: PathBuf::from(required_env("SOVEREIGN_MODEL_RUNTIME")?),
            model_path: PathBuf::from(required_env("SOVEREIGN_MODEL_PATH")?),
            model_name: required_env("SOVEREIGN_MODEL_NAME")?,
            parameter_class: required_env("SOVEREIGN_MODEL_PARAMETER_CLASS")?,
            quantization: required_env("SOVEREIGN_MODEL_QUANTIZATION")?,
            report_path: std::env::var_os("SOVEREIGN_MODEL_SMOKE_REPORT").map_or_else(
                || PathBuf::from("implementation/evidence/M1-T03-real-model-smoke.json"),
                PathBuf::from,
            ),
            extra_args: parse_extra_args()?,
        })
    }
}

struct TierOutcome {
    tier: Value,
    action: Option<Value>,
    throughput: Option<Value>,
    unload: Option<Value>,
}

struct ToolSmokeOutcome {
    action: Value,
    throughput: Value,
    peak_rss_kb: Option<u64>,
    raw_prompt_tokens: u32,
    admission: Value,
}

fn main() -> Result<(), Box<dyn Error>> {
    let config = SmokeConfig::from_env()?;
    let report = run_smoke(&config)?;
    if let Some(parent) = config.report_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&config.report_path, serde_json::to_vec_pretty(&report)?)?;
    println!("{}", config.report_path.display());
    Ok(())
}

fn run_smoke(config: &SmokeConfig) -> Result<Value, Box<dyn Error>> {
    let runtime_version = command_version(&config.runtime);
    let model_size = fs::metadata(&config.model_path)?.len();
    let host_before = host_observation();
    let mut tiers = Vec::new();
    let mut smoke_result = Value::Null;
    let mut token_throughput = Value::Null;
    let mut unload_residuals = Vec::new();
    for context_tokens in CONTEXT_TIERS {
        let outcome = run_context_tier(config, context_tokens)?;
        tiers.push(outcome.tier);
        if let Some(action) = outcome.action {
            smoke_result = action;
        }
        if let Some(throughput) = outcome.throughput {
            token_throughput = throughput;
        }
        if let Some(unload) = outcome.unload {
            unload_residuals.push(unload);
        }
    }
    let reload = reload_probe(
        &config.runtime,
        &config.model_path,
        &config.model_name,
        &config.parameter_class,
        &config.quantization,
        &config.extra_args,
    )?;
    let host_after = host_observation();
    let host_delta = host_observation_delta(&host_before, &host_after);
    let report = json!({
        "schema": "sovereign-m1-real-model-smoke-v1",
        "recorded_at_unix_ms": unix_millis()?,
        "target": {
            "hardware": "MacBook Air M1 / 8 GB profile",
            "architecture": std::env::consts::ARCH,
            "os": std::env::consts::OS,
        },
        "provider": "managed llama.cpp OpenAI-compatible loopback",
        "runtime": {
            "path": config.runtime,
            "version": runtime_version,
        },
        "model": {
            "name": config.model_name,
            "parameter_class": config.parameter_class,
            "quantization": config.quantization,
            "weight_path": config.model_path,
            "weight_artifact_size_bytes": model_size,
        },
        "configured_context_profile": {
            "normal_input_tokens": 8_192,
            "output_reserve_tokens": 1_536,
            "hard_m1_input_ceiling": 16_384,
        },
        "context_tiers": tiers,
        "task_action_result": smoke_result,
        "token_throughput": token_throughput,
        "unload_residuals": unload_residuals,
        "clean_reload": reload,
        "host_observation_before": host_before,
        "host_observation_after": host_after,
        "host_observation_delta": host_delta,
    });
    if report["task_action_result"]["passed"] != Value::Bool(true) {
        return Err(io::Error::other("8k real-model action smoke did not run successfully").into());
    }
    Ok(report)
}

fn run_context_tier(
    config: &SmokeConfig,
    context_tokens: u32,
) -> Result<TierOutcome, Box<dyn Error>> {
    let backend = smoke_backend(config)?;
    let profile = ModelLoadProfile {
        context_tokens,
        output_reserve_tokens: 1_536,
        startup_timeout_ms: 180_000,
        provider_call_timeout_ms: 180_000,
    };
    let host_before = host_observation();
    let lease = match backend.load(profile) {
        Ok(lease) => lease,
        Err(error) => {
            return Ok(TierOutcome {
                tier: json!({
                    "context_tokens": context_tokens,
                    "supported": false,
                    "error": error.to_string(),
                    "host_before": host_before,
                    "host_after": host_observation(),
                }),
                action: None,
                throughput: None,
                unload: None,
            });
        }
    };
    let mut tier = json!({
        "context_tokens": context_tokens,
        "supported": true,
        "process_id": lease.process_id,
        "startup_peak_rss_kb": lease.startup_peak_rss_kb,
        "post_load_steady_rss_kb": lease.post_load_rss_kb,
        "host_before": host_before,
    });
    let (action, throughput) = if context_tokens == 8_192 {
        let smoke = run_tool_smoke(&backend)?;
        tier["prefill_decode_peak_rss_kb"] = json!(smoke.peak_rss_kb);
        tier["raw_prompt_tokens"] = json!(smoke.raw_prompt_tokens);
        tier["request_token_admission"] = smoke.admission;
        (Some(smoke.action), Some(smoke.throughput))
    } else {
        (None, None)
    };
    let process_id = lease.process_id;
    backend.unload()?;
    let residual = process_id.and_then(process_rss_kb);
    tier["host_after_unload"] = host_observation();
    Ok(TierOutcome {
        tier,
        action,
        throughput,
        unload: Some(json!({
            "context_tokens": context_tokens,
            "process_rss_kb_after_unload": residual,
            "process_absent": residual.is_none(),
        })),
    })
}

fn run_tool_smoke(backend: &LocalOpenAiBackend) -> Result<ToolSmokeOutcome, Box<dyn Error>> {
    let prompt = "Call record_smoke exactly once with ok=true and message='local model ready'. Do not answer in prose.";
    let raw_prompt_tokens = backend.count_tokens(prompt)?;
    let request = smoke_request(prompt);
    let admission = backend.token_admission(&request)?;
    let response = backend.complete(&request)?;
    let call = response
        .tool_calls
        .iter()
        .find(|call| {
            call.name == "record_smoke"
                && call.arguments.get("ok").and_then(Value::as_bool) == Some(true)
        })
        .ok_or_else(|| {
            io::Error::other(format!(
                "real model did not produce required record_smoke tool call: {:?}",
                response.tool_calls
            ))
        })?;
    let throughput_milli = (response.elapsed_ms > 0)
        .then(|| response.usage.output_tokens.saturating_mul(1_000_000) / response.elapsed_ms);
    let action = json!({
        "passed": true,
        "tool_call_name": "record_smoke",
        "tool_call_arguments": call.arguments,
        "finish_reason": response.finish_reason,
        "input_tokens": response.usage.input_tokens,
        "output_tokens": response.usage.output_tokens,
        "elapsed_ms": response.elapsed_ms,
        "preflight": {
            "rendered_input_tokens": admission.rendered_input_tokens,
            "structured_output_tokens": admission.structured_output_tokens,
            "admitted_input_tokens": admission.admitted_input_tokens,
            "reserved_output_tokens": admission.reserved_output_tokens,
            "server_context_tokens": admission.server_context_tokens,
        },
    });
    let throughput = json!({
        "output_tokens_per_second_milli": throughput_milli,
        "output_tokens": response.usage.output_tokens,
        "elapsed_ms": response.elapsed_ms,
    });
    Ok(ToolSmokeOutcome {
        action,
        throughput,
        peak_rss_kb: response.peak_rss_kb_during_call,
        raw_prompt_tokens,
        admission: serde_json::to_value(admission)?,
    })
}

fn smoke_backend(config: &SmokeConfig) -> Result<LocalOpenAiBackend, Box<dyn Error>> {
    let port = free_loopback_port()?;
    let mut backend_config = LocalOpenAiConfig::with_defaults(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        port,
        &config.model_name,
        capabilities(
            &config.model_name,
            &config.parameter_class,
            &config.quantization,
            16_384,
        ),
    );
    backend_config.request_timeout_ms = 180_000;
    backend_config.launch = Some(LlamaServerLaunch {
        executable: config.runtime.clone(),
        model_path: config.model_path.clone(),
        extra_args: config.extra_args.clone(),
    });
    Ok(LocalOpenAiBackend::new(backend_config)?)
}

fn capabilities(
    model_name: &str,
    parameter_class: &str,
    quantization: &str,
    max_context_tokens: u32,
) -> ModelCapabilities {
    ModelCapabilities {
        schema_version: MODEL_SCHEMA_VERSION,
        model_id: model_name.to_owned(),
        parameter_class: parameter_class.to_owned(),
        quantization: quantization.to_owned(),
        max_context_tokens,
        supports_tools: true,
        supports_json_schema: true,
        local: true,
    }
}

fn smoke_request(prompt: &str) -> ModelRequest {
    ModelRequest {
        schema_version: MODEL_SCHEMA_VERSION,
        request_id: "m1.real-model-smoke.action".to_owned(),
        messages: vec![
            ModelMessage {
                role: ModelMessageRole::System,
                content: "You are a bounded local tool-use smoke test. Follow the user instruction exactly."
                    .to_owned(),
                tool_call_id: None,
            },
            ModelMessage {
                role: ModelMessageRole::User,
                content: prompt.to_owned(),
                tool_call_id: None,
            },
        ],
        tools: vec![ModelToolDefinition {
            name: "record_smoke".to_owned(),
            description: "Record that the bounded local tool-use smoke succeeded.".to_owned(),
            input_schema: json!({
                "type": "object",
                "required": ["ok", "message"],
                "additionalProperties": false,
                "properties": {
                    "ok": {"type": "boolean"},
                    "message": {"type": "string"}
                }
            }),
        }],
        output_contract: ModelOutputContract::Text,
        input_token_ceiling: 8_192,
        max_output_tokens: 256,
        deadline_ms: 180_000,
        temperature_milli: 0,
    }
}

fn reload_probe(
    runtime: &Path,
    model_path: &Path,
    model_name: &str,
    parameter_class: &str,
    quantization: &str,
    extra_args: &[String],
) -> Result<Value, Box<dyn Error>> {
    let port = free_loopback_port()?;
    let mut config = LocalOpenAiConfig::with_defaults(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        port,
        model_name,
        capabilities(model_name, parameter_class, quantization, 16_384),
    );
    config.request_timeout_ms = 180_000;
    config.launch = Some(LlamaServerLaunch {
        executable: runtime.to_path_buf(),
        model_path: model_path.to_path_buf(),
        extra_args: extra_args.to_vec(),
    });
    let backend = LocalOpenAiBackend::new(config)?;
    let profile = ModelLoadProfile {
        context_tokens: 8_192,
        output_reserve_tokens: 1_536,
        startup_timeout_ms: 180_000,
        provider_call_timeout_ms: 180_000,
    };
    let lease = backend.load(profile)?;
    let pid = lease.process_id;
    backend.unload()?;
    Ok(json!({
        "passed": pid.and_then(process_rss_kb).is_none(),
        "reload_post_load_rss_kb": lease.post_load_rss_kb,
        "reload_startup_peak_rss_kb": lease.startup_peak_rss_kb,
        "process_absent_after_second_unload": pid.and_then(process_rss_kb).is_none(),
    }))
}

fn parse_extra_args() -> Result<Vec<String>, Box<dyn Error>> {
    let Some(raw) = std::env::var_os("SOVEREIGN_MODEL_EXTRA_ARGS_JSON") else {
        return Ok(Vec::new());
    };
    let raw = raw
        .to_str()
        .ok_or_else(|| io::Error::other("SOVEREIGN_MODEL_EXTRA_ARGS_JSON is not UTF-8"))?;
    Ok(serde_json::from_str(raw)?)
}

fn required_env(name: &str) -> Result<String, io::Error> {
    std::env::var(name)
        .map_err(|_| io::Error::other(format!("missing required environment {name}")))
}

fn free_loopback_port() -> Result<u16, io::Error> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    Ok(listener.local_addr()?.port())
}

fn unix_millis() -> Result<u128, std::time::SystemTimeError> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())
}

fn command_version(runtime: &Path) -> String {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let Ok(output) = Command::new(runtime)
        .env_clear()
        .env("PATH", path)
        .arg("--version")
        .output()
    else {
        return "unknown".to_owned();
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let value = if stdout.trim().is_empty() {
        stderr
    } else {
        stdout
    };
    let value = value.trim();
    if value.is_empty() {
        "unknown".to_owned()
    } else {
        value.to_owned()
    }
}

fn process_rss_kb(pid: u32) -> Option<u64> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let output = Command::new("ps")
        .env_clear()
        .env("PATH", path)
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    std::str::from_utf8(&output.stdout)
        .ok()?
        .trim()
        .parse()
        .ok()
}

fn host_observation() -> Value {
    json!({
        "memory_pressure": command_text("memory_pressure", &["-Q"]),
        "vm_stat": command_text("vm_stat", &[]),
        "swapusage": command_text("sysctl", &["-n", "vm.swapusage"]),
    })
}

fn host_observation_delta(before: &Value, after: &Value) -> Value {
    let before_swap = before
        .get("swapusage")
        .and_then(Value::as_str)
        .and_then(parse_swap_used_kib);
    let after_swap = after
        .get("swapusage")
        .and_then(Value::as_str)
        .and_then(parse_swap_used_kib);
    let before_compressor = before
        .get("vm_stat")
        .and_then(Value::as_str)
        .and_then(parse_compressor_kib);
    let after_compressor = after
        .get("vm_stat")
        .and_then(Value::as_str)
        .and_then(parse_compressor_kib);
    json!({
        "swap_used_kib_before": before_swap,
        "swap_used_kib_after": after_swap,
        "swap_used_kib_delta": signed_delta(before_swap, after_swap),
        "compressor_kib_before": before_compressor,
        "compressor_kib_after": after_compressor,
        "compressor_kib_delta": signed_delta(before_compressor, after_compressor),
    })
}

fn signed_delta(before: Option<u64>, after: Option<u64>) -> Option<i128> {
    Some(i128::from(after?) - i128::from(before?))
}

fn parse_swap_used_kib(text: &str) -> Option<u64> {
    let used = text.split_whitespace().collect::<Vec<_>>();
    let index = used.iter().position(|part| *part == "used")?;
    let value = used.get(index + 2)?;
    parse_memory_to_kib(value)
}

fn parse_memory_to_kib(value: &str) -> Option<u64> {
    let unit = value.chars().last()?;
    let number = value.get(..value.len().checked_sub(1)?)?;
    let (whole, fraction) = number.split_once('.').unwrap_or((number, "0"));
    let whole = whole.parse::<u64>().ok()?;
    let fraction = fraction.chars().take(3).collect::<String>();
    let fraction = format!("{fraction:0<3}").parse::<u64>().ok()?;
    match unit {
        'K' => Some(whole.saturating_add(fraction / 1_000)),
        'M' => Some(
            whole
                .saturating_mul(1_024)
                .saturating_add(fraction.saturating_mul(1_024) / 1_000),
        ),
        'G' => Some(
            whole
                .saturating_mul(1_048_576)
                .saturating_add(fraction.saturating_mul(1_048_576) / 1_000),
        ),
        _ => None,
    }
}

fn parse_compressor_kib(text: &str) -> Option<u64> {
    let page_size = text
        .lines()
        .next()?
        .split_whitespace()
        .find_map(|word| word.trim_end_matches('.').parse::<u64>().ok())?;
    let pages = text.lines().find_map(|line| {
        line.strip_prefix("Pages occupied by compressor:")?
            .trim()
            .trim_end_matches('.')
            .parse::<u64>()
            .ok()
    })?;
    Some(pages.saturating_mul(page_size) / 1_024)
}

fn command_text(program: &str, args: &[&str]) -> Option<String> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let output = Command::new(program)
        .env_clear()
        .env("PATH", path)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout)
        .ok()
        .map(|value| value.trim().to_owned())
}
