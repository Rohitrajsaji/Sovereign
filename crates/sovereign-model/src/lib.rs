//! Provider-neutral model contracts plus the first local OpenAI-compatible backend.
//!
//! Sovereign deliberately keeps provider transport details behind [`ModelBackend`].
//! The M1 local implementation accepts loopback endpoints only, owns at most one
//! physical local-model lease per process, and never introduces a cloud/runtime
//! dependency into Plan IR or Controller semantics.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub const MODEL_SCHEMA_VERSION: u32 = 1;
pub const M1_HARD_INPUT_CONTEXT_TOKENS: u32 = 16_384;
const DEFAULT_MAX_HTTP_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;

static LEASE_SEQUENCE: AtomicU64 = AtomicU64::new(1);
static ACTIVE_LOCAL_MODEL: OnceLock<Mutex<Option<String>>> = OnceLock::new();

/// Provider-neutral capabilities advertised before a plan requests a model lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelCapabilities {
    pub schema_version: u32,
    pub model_id: String,
    pub parameter_class: String,
    pub quantization: String,
    pub max_context_tokens: u32,
    pub supports_tools: bool,
    pub supports_json_schema: bool,
    pub local: bool,
}

impl ModelCapabilities {
    /// Validates the stable v1 capability contract.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidContract`] for an unsupported version,
    /// empty identity fields, or a zero context limit.
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.schema_version != MODEL_SCHEMA_VERSION {
            return Err(ModelError::InvalidContract(format!(
                "unsupported ModelCapabilities schema version {}",
                self.schema_version
            )));
        }
        if self.model_id.trim().is_empty()
            || self.parameter_class.trim().is_empty()
            || self.quantization.trim().is_empty()
            || self.max_context_tokens == 0
        {
            return Err(ModelError::InvalidContract(
                "model capabilities require identity, parameter class, quantization and context"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

/// One bounded local-model residency profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelLoadProfile {
    pub context_tokens: u32,
    pub output_reserve_tokens: u32,
    pub startup_timeout_ms: u64,
    pub provider_call_timeout_ms: u64,
}

impl ModelLoadProfile {
    fn validate(&self, capabilities: &ModelCapabilities) -> Result<(), ModelError> {
        if self.context_tokens == 0 || self.context_tokens > M1_HARD_INPUT_CONTEXT_TOKENS {
            return Err(ModelError::InvalidContract(format!(
                "requested input allowance {} exceeds M1 input ceiling",
                self.context_tokens
            )));
        }
        if self.output_reserve_tokens == 0
            || self.startup_timeout_ms == 0
            || self.provider_call_timeout_ms == 0
        {
            return Err(ModelError::InvalidContract(
                "load profile budgets must be positive".to_owned(),
            ));
        }
        if self.server_context_tokens()? > capabilities.max_context_tokens {
            return Err(ModelError::InvalidContract(format!(
                "input allowance {} plus output reserve {} exceeds model context {}",
                self.context_tokens, self.output_reserve_tokens, capabilities.max_context_tokens
            )));
        }
        Ok(())
    }

    fn server_context_tokens(self) -> Result<u32, ModelError> {
        self.context_tokens
            .checked_add(self.output_reserve_tokens)
            .ok_or_else(|| ModelError::InvalidContract("model context budget overflow".to_owned()))
    }
}

/// Lease proving one physical local model is admitted and loaded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelLease {
    pub lease_id: String,
    pub model_id: String,
    pub context_tokens: u32,
    pub server_context_tokens: u32,
    pub process_id: Option<u32>,
    pub startup_peak_rss_kb: Option<u64>,
    pub post_load_rss_kb: Option<u64>,
}

/// Provider-neutral admission record for one completely rendered request.
///
/// `rendered_input_tokens` is the provider's exact chat-template prompt count.
/// `structured_output_tokens` is a conservative tokenizer charge for a typed
/// output contract when the provider enforces that schema outside the prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelTokenAdmission {
    pub rendered_input_tokens: u32,
    pub structured_output_tokens: u32,
    pub admitted_input_tokens: u32,
    pub reserved_output_tokens: u32,
    pub server_context_tokens: u32,
}

/// Stable role for one model-facing message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelMessageRole {
    System,
    User,
    Assistant,
    Tool,
}

impl ModelMessageRole {
    const fn as_openai(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::User => "user",
            Self::Assistant => "assistant",
            Self::Tool => "tool",
        }
    }
}

/// Provider-neutral message payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMessage {
    pub role: ModelMessageRole,
    pub content: String,
    pub tool_call_id: Option<String>,
}

/// Provider-neutral tool declaration. It carries schema, not executable authority.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

/// Output contract requested from a model call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ModelOutputContract {
    Text,
    JsonSchema { name: String, schema: Value },
}

/// Provider-neutral model request v1.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelRequest {
    pub schema_version: u32,
    pub request_id: String,
    pub messages: Vec<ModelMessage>,
    pub tools: Vec<ModelToolDefinition>,
    pub output_contract: ModelOutputContract,
    pub input_token_ceiling: u32,
    pub max_output_tokens: u32,
    pub deadline_ms: u64,
    pub temperature_milli: u16,
}

impl ModelRequest {
    fn validate(
        &self,
        capabilities: &ModelCapabilities,
        profile: ModelLoadProfile,
    ) -> Result<(), ModelError> {
        if self.schema_version != MODEL_SCHEMA_VERSION {
            return Err(ModelError::InvalidContract(format!(
                "unsupported ModelRequest schema version {}",
                self.schema_version
            )));
        }
        if self.request_id.trim().is_empty() || self.messages.is_empty() {
            return Err(ModelError::InvalidContract(
                "model request requires request_id and at least one message".to_owned(),
            ));
        }
        if self.input_token_ceiling == 0 || self.input_token_ceiling > profile.context_tokens {
            return Err(ModelError::InvalidContract(
                "request input-token ceiling exceeds active model lease".to_owned(),
            ));
        }
        if self.max_output_tokens == 0 || self.max_output_tokens > profile.output_reserve_tokens {
            return Err(ModelError::InvalidContract(
                "request output-token ceiling exceeds active output reserve".to_owned(),
            ));
        }
        if self.deadline_ms == 0 || self.temperature_milli > 2_000 {
            return Err(ModelError::InvalidContract(
                "request deadline must be positive and temperature <= 2.0".to_owned(),
            ));
        }
        if !self.tools.is_empty() && !capabilities.supports_tools {
            return Err(ModelError::InvalidContract(
                "request declares tools but model does not advertise tool support".to_owned(),
            ));
        }
        if matches!(self.output_contract, ModelOutputContract::JsonSchema { .. })
            && !capabilities.supports_json_schema
        {
            return Err(ModelError::InvalidContract(
                "request requires JSON schema but model does not advertise it".to_owned(),
            ));
        }
        Ok(())
    }
}

/// One provider-neutral model-proposed tool call. This is a proposal only; it
/// carries no Controller authorization.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelToolCall {
    pub call_id: String,
    pub name: String,
    pub arguments: Value,
}

/// Normalized model finish reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelFinishReason {
    Stop,
    Length,
    ToolCalls,
    Other(String),
}

/// Provider-neutral token-accounting data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ModelUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
}

/// Provider-neutral model response v1.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelResponse {
    pub schema_version: u32,
    pub request_id: String,
    pub content: String,
    pub structured: Option<Value>,
    pub tool_calls: Vec<ModelToolCall>,
    pub finish_reason: ModelFinishReason,
    pub usage: ModelUsage,
    pub elapsed_ms: u64,
    pub peak_rss_kb_during_call: Option<u64>,
}

/// Backend liveness and residency observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendHealth {
    pub reachable: bool,
    pub loaded: bool,
    pub detail: String,
}

/// Provider proof about physical model residency after load/unload transitions.
///
/// `Unknown` is deliberately distinct from `Absent`: externally managed providers may clear
/// local lease bookkeeping while the actual model server remains resident. Resource policy must
/// fail closed when physical absence is required and the backend cannot prove it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ModelResidencyProof {
    Resident { process_id: Option<u32> },
    Absent,
    Unknown,
}

/// Stable model/backend error classification.
#[derive(Debug)]
pub enum ModelError {
    Io(std::io::Error),
    Json(serde_json::Error),
    InvalidContract(String),
    InvalidResponse(String),
    NotLoaded,
    AlreadyLoaded,
    LeaseUnavailable(String),
    DeadlineExceeded(&'static str),
    HttpProtocol(String),
    ProviderStatus { status: u16, body: String },
    ProviderExited(Option<i32>),
    LockPoisoned(&'static str),
}

impl Display for ModelError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "model I/O error: {error}"),
            Self::Json(error) => write!(f, "model JSON error: {error}"),
            Self::InvalidContract(message) => write!(f, "invalid model contract: {message}"),
            Self::InvalidResponse(message) => write!(f, "invalid model response: {message}"),
            Self::NotLoaded => write!(f, "model backend is not loaded"),
            Self::AlreadyLoaded => write!(f, "model backend already has an active lease"),
            Self::LeaseUnavailable(lease) => {
                write!(f, "physical local-model lease is already held by {lease}")
            }
            Self::DeadlineExceeded(stage) => write!(f, "model {stage} deadline exceeded"),
            Self::HttpProtocol(message) => write!(f, "local model HTTP protocol error: {message}"),
            Self::ProviderStatus { status, body } => {
                write!(f, "local model provider returned HTTP {status}: {body}")
            }
            Self::ProviderExited(status) => {
                write!(f, "local model provider exited during startup: {status:?}")
            }
            Self::LockPoisoned(name) => write!(f, "model lock poisoned: {name}"),
        }
    }
}

impl Error for ModelError {}

impl From<std::io::Error> for ModelError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for ModelError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

/// Provider-independent model authority boundary.
pub trait ModelBackend: Send + Sync {
    fn capabilities(&self) -> ModelCapabilities;

    /// Acquires one bounded model residency lease.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError`] when profile validation, admission, provider
    /// startup, or health readiness fails.
    fn load(&self, profile: ModelLoadProfile) -> Result<ModelLease, ModelError>;

    /// Executes exactly one bounded provider call. Provider-internal recursive
    /// retries are intentionally absent in M1; outer Controller budgets own retry.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError`] for missing lease, invalid request, deadline,
    /// transport/provider error, or invalid structured output.
    fn complete(&self, request: &ModelRequest) -> Result<ModelResponse, ModelError>;

    /// Counts model tokens for bounded context construction.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError`] for missing lease or provider failure.
    fn count_tokens(&self, content: &str) -> Result<u32, ModelError>;

    /// Returns current provider health without changing authoritative state.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError`] on deadline, transport, or invalid provider response.
    fn health(&self) -> Result<BackendHealth, ModelError>;

    /// Returns a backend-specific proof of physical residency without mutating provider state.
    ///
    /// Backends that cannot distinguish local bookkeeping from real provider residency must
    /// return [`ModelResidencyProof::Unknown`]. This default is intentionally conservative.
    ///
    /// # Errors
    /// Returns [`ModelError`] when the backend cannot inspect its owned residency state.
    fn residency_proof(&self) -> Result<ModelResidencyProof, ModelError> {
        Ok(ModelResidencyProof::Unknown)
    }

    /// Unloads provider residency and releases the physical-model lease.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError`] when process cleanup or lease bookkeeping fails.
    fn unload(&self) -> Result<(), ModelError>;
}

/// Optional managed `llama-server` process settings. Arguments are always
/// passed as a structured vector; no shell is involved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LlamaServerLaunch {
    pub executable: PathBuf,
    pub model_path: PathBuf,
    pub extra_args: Vec<String>,
}

/// Loopback-only configuration for the first local provider.
#[derive(Debug, Clone)]
pub struct LocalOpenAiConfig {
    pub host: IpAddr,
    pub port: u16,
    pub model_name: String,
    pub capabilities: ModelCapabilities,
    pub request_timeout_ms: u64,
    pub max_http_response_bytes: u64,
    pub launch: Option<LlamaServerLaunch>,
}

impl LocalOpenAiConfig {
    #[must_use]
    pub fn with_defaults(
        host: IpAddr,
        port: u16,
        model_name: impl Into<String>,
        capabilities: ModelCapabilities,
    ) -> Self {
        Self {
            host,
            port,
            model_name: model_name.into(),
            capabilities,
            request_timeout_ms: 180_000,
            max_http_response_bytes: DEFAULT_MAX_HTTP_RESPONSE_BYTES,
            launch: None,
        }
    }
}

struct LocalState {
    lease: Option<ModelLease>,
    profile: Option<ModelLoadProfile>,
    child: Option<Child>,
}

/// First real local provider: a loopback OpenAI-compatible llama.cpp-style server.
pub struct LocalOpenAiBackend {
    config: LocalOpenAiConfig,
    state: Mutex<LocalState>,
}

impl LocalOpenAiBackend {
    /// Constructs a local backend. Non-loopback endpoints are rejected so this
    /// baseline provider cannot silently become a cloud dependency.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidContract`] for non-local endpoints or
    /// invalid capability/config values.
    pub fn new(config: LocalOpenAiConfig) -> Result<Self, ModelError> {
        config.capabilities.validate()?;
        if !config.host.is_loopback()
            || !config.capabilities.local
            || config.port == 0
            || config.model_name.trim().is_empty()
            || config.request_timeout_ms == 0
            || config.max_http_response_bytes == 0
        {
            return Err(ModelError::InvalidContract(
                "local provider requires loopback host, port, local capability, model name and positive limits"
                    .to_owned(),
            ));
        }
        Ok(Self {
            config,
            state: Mutex::new(LocalState {
                lease: None,
                profile: None,
                child: None,
            }),
        })
    }

    fn loaded_profile(&self) -> Result<ModelLoadProfile, ModelError> {
        let state = lock(&self.state, "local backend state")?;
        state.profile.ok_or(ModelError::NotLoaded)
    }

    fn provider_health(&self, timeout: Duration) -> Result<BackendHealth, ModelError> {
        let response = http_request(
            SocketAddr::new(self.config.host, self.config.port),
            "GET",
            "/health",
            None,
            timeout,
            self.config.max_http_response_bytes,
        )?;
        if !(200..300).contains(&response.status) {
            return Err(ModelError::ProviderStatus {
                status: response.status,
                body: String::from_utf8_lossy(&response.body).into_owned(),
            });
        }
        let loaded = lock(&self.state, "local backend state")?.lease.is_some();
        Ok(BackendHealth {
            reachable: true,
            loaded,
            detail: "loopback provider healthy".to_owned(),
        })
    }

    fn completion_body(&self, request: &ModelRequest) -> Value {
        let messages: Vec<Value> = request
            .messages
            .iter()
            .map(|message| {
                let mut value = json!({
                    "role": message.role.as_openai(),
                    "content": message.content,
                });
                if let Some(tool_call_id) = &message.tool_call_id {
                    value["tool_call_id"] = json!(tool_call_id);
                }
                value
            })
            .collect();
        let mut body = json!({
            "model": self.config.model_name,
            "messages": messages,
            "stream": false,
            "max_tokens": request.max_output_tokens,
            "temperature": f64::from(request.temperature_milli) / 1000.0,
        });
        if !request.tools.is_empty() {
            body["tools"] = Value::Array(
                request
                    .tools
                    .iter()
                    .map(|tool| {
                        json!({
                            "type": "function",
                            "function": {
                                "name": tool.name,
                                "description": tool.description,
                                "parameters": tool.input_schema,
                            }
                        })
                    })
                    .collect(),
            );
        }
        if let ModelOutputContract::JsonSchema { name, schema } = &request.output_contract {
            body["response_format"] = json!({
                "type": "json_schema",
                "json_schema": {
                    "name": name,
                    "schema": schema,
                    "strict": true
                }
            });
        }
        body
    }

    fn template_body(request: &ModelRequest) -> Value {
        let messages: Vec<Value> = request
            .messages
            .iter()
            .map(|message| {
                let mut value = json!({
                    "role": message.role.as_openai(),
                    "content": message.content,
                });
                if let Some(tool_call_id) = &message.tool_call_id {
                    value["tool_call_id"] = json!(tool_call_id);
                }
                value
            })
            .collect();
        let mut body = json!({
            "messages": messages,
            "add_generation_prompt": true,
        });
        if !request.tools.is_empty() {
            body["tools"] = Value::Array(
                request
                    .tools
                    .iter()
                    .map(|tool| {
                        json!({
                            "type": "function",
                            "function": {
                                "name": tool.name,
                                "description": tool.description,
                                "parameters": tool.input_schema,
                            }
                        })
                    })
                    .collect(),
            );
        }
        body
    }

    fn tokenize_until(&self, content: &str, deadline: Instant) -> Result<u32, ModelError> {
        let body = serde_json::to_vec(&json!({"content": content, "add_special": false}))?;
        let response = http_request_until(
            SocketAddr::new(self.config.host, self.config.port),
            "POST",
            "/tokenize",
            Some(&body),
            deadline,
            self.config.max_http_response_bytes,
        )?;
        if !(200..300).contains(&response.status) {
            return Err(ModelError::ProviderStatus {
                status: response.status,
                body: String::from_utf8_lossy(&response.body).into_owned(),
            });
        }
        token_count_from_response(&response.body)
    }

    fn token_admission_until(
        &self,
        request: &ModelRequest,
        profile: ModelLoadProfile,
        deadline: Instant,
    ) -> Result<ModelTokenAdmission, ModelError> {
        let template_body = serde_json::to_vec(&Self::template_body(request))?;
        let template_response = http_request_until(
            SocketAddr::new(self.config.host, self.config.port),
            "POST",
            "/apply-template",
            Some(&template_body),
            deadline,
            self.config.max_http_response_bytes,
        )?;
        if !(200..300).contains(&template_response.status) {
            return Err(ModelError::ProviderStatus {
                status: template_response.status,
                body: String::from_utf8_lossy(&template_response.body).into_owned(),
            });
        }
        let rendered: Value = serde_json::from_slice(&template_response.body)?;
        let prompt = rendered
            .get("prompt")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ModelError::InvalidResponse("apply-template response missing prompt".to_owned())
            })?;
        let rendered_input_tokens = self.tokenize_until(prompt, deadline)?;
        let structured_output_tokens = match &request.output_contract {
            ModelOutputContract::Text => 0,
            contract @ ModelOutputContract::JsonSchema { .. } => {
                let contract_json = serde_json::to_string(contract)?;
                self.tokenize_until(&contract_json, deadline)?
            }
        };
        let admitted_input_tokens = rendered_input_tokens
            .checked_add(structured_output_tokens)
            .ok_or_else(|| {
                ModelError::InvalidContract("request token count overflow".to_owned())
            })?;
        if admitted_input_tokens > request.input_token_ceiling
            || admitted_input_tokens > profile.context_tokens
        {
            return Err(ModelError::InvalidContract(format!(
                "fully rendered request requires {admitted_input_tokens} input tokens but ceiling is {}",
                request.input_token_ceiling.min(profile.context_tokens)
            )));
        }
        let server_context_tokens = profile.server_context_tokens()?;
        let required_total = admitted_input_tokens
            .checked_add(request.max_output_tokens)
            .ok_or_else(|| {
                ModelError::InvalidContract("request total token count overflow".to_owned())
            })?;
        if required_total > server_context_tokens {
            return Err(ModelError::InvalidContract(format!(
                "rendered input {admitted_input_tokens} plus output reserve {} exceeds server context {server_context_tokens}",
                request.max_output_tokens
            )));
        }
        Ok(ModelTokenAdmission {
            rendered_input_tokens,
            structured_output_tokens,
            admitted_input_tokens,
            reserved_output_tokens: request.max_output_tokens,
            server_context_tokens,
        })
    }

    /// Measures the exact provider-rendered request before inference and applies
    /// the same admission rules used by [`ModelBackend::complete`].
    ///
    /// # Errors
    /// Returns a contract, deadline, transport, or provider error when the fully
    /// rendered request cannot be safely admitted.
    pub fn token_admission(
        &self,
        request: &ModelRequest,
    ) -> Result<ModelTokenAdmission, ModelError> {
        let profile = self.loaded_profile()?;
        request.validate(&self.config.capabilities, profile)?;
        let timeout = Duration::from_millis(
            request
                .deadline_ms
                .min(profile.provider_call_timeout_ms)
                .min(self.config.request_timeout_ms),
        );
        let deadline = Instant::now() + timeout;
        self.token_admission_until(request, profile, deadline)
    }

    fn parse_completion(
        request: &ModelRequest,
        bytes: &[u8],
        elapsed_ms: u64,
        peak_rss_kb: Option<u64>,
    ) -> Result<ModelResponse, ModelError> {
        let root: Value = serde_json::from_slice(bytes)?;
        let choice = root
            .pointer("/choices/0")
            .ok_or_else(|| ModelError::InvalidResponse("missing choices[0]".to_owned()))?;
        let message = choice
            .get("message")
            .ok_or_else(|| ModelError::InvalidResponse("missing choice message".to_owned()))?;
        let content = message
            .get("content")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let mut tool_calls = Vec::new();
        if let Some(calls) = message.get("tool_calls").and_then(Value::as_array) {
            for call in calls {
                let call_id = call.get("id").and_then(Value::as_str).ok_or_else(|| {
                    ModelError::InvalidResponse("tool call missing id".to_owned())
                })?;
                let name = call
                    .pointer("/function/name")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        ModelError::InvalidResponse("tool call missing function name".to_owned())
                    })?;
                let arguments_text = call
                    .pointer("/function/arguments")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        ModelError::InvalidResponse("tool call missing arguments".to_owned())
                    })?;
                let arguments: Value = serde_json::from_str(arguments_text).map_err(|error| {
                    ModelError::InvalidResponse(format!("tool arguments are not JSON: {error}"))
                })?;
                tool_calls.push(ModelToolCall {
                    call_id: call_id.to_owned(),
                    name: name.to_owned(),
                    arguments,
                });
            }
        }

        let finish_reason = match choice
            .get("finish_reason")
            .and_then(Value::as_str)
            .unwrap_or("stop")
        {
            "stop" => ModelFinishReason::Stop,
            "length" => ModelFinishReason::Length,
            "tool_calls" => ModelFinishReason::ToolCalls,
            other => ModelFinishReason::Other(other.to_owned()),
        };
        let usage = ModelUsage {
            input_tokens: root
                .pointer("/usage/prompt_tokens")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            output_tokens: root
                .pointer("/usage/completion_tokens")
                .and_then(Value::as_u64)
                .unwrap_or(0),
        };
        let structured = validate_output_contract(&request.output_contract, &content)?;
        Ok(ModelResponse {
            schema_version: MODEL_SCHEMA_VERSION,
            request_id: request.request_id.clone(),
            content,
            structured,
            tool_calls,
            finish_reason,
            usage,
            elapsed_ms,
            peak_rss_kb_during_call: peak_rss_kb,
        })
    }

    fn launch_process(
        &self,
        launch: &LlamaServerLaunch,
        profile: ModelLoadProfile,
    ) -> Result<Child, ModelError> {
        let path = std::env::var_os("PATH").unwrap_or_default();
        let server_context_tokens = profile.server_context_tokens()?;
        let child = Command::new(&launch.executable)
            .env_clear()
            .env("PATH", path)
            .arg("-m")
            .arg(&launch.model_path)
            .arg("--host")
            .arg(self.config.host.to_string())
            .arg("--port")
            .arg(self.config.port.to_string())
            .arg("-c")
            .arg(server_context_tokens.to_string())
            .arg("--jinja")
            .args(&launch.extra_args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(ModelError::Io)?;
        Ok(child)
    }

    fn cleanup_state(state: &mut LocalState) -> Result<(), ModelError> {
        if let Some(child) = state.child.as_mut()
            && child.try_wait()?.is_none()
        {
            child.kill()?;
            let _ = child.wait()?;
        }
        state.child = None;
        state.profile = None;
        if let Some(lease) = state.lease.take() {
            release_global_lease(&lease.lease_id)?;
        }
        Ok(())
    }
}

impl ModelBackend for LocalOpenAiBackend {
    fn capabilities(&self) -> ModelCapabilities {
        self.config.capabilities.clone()
    }

    fn load(&self, profile: ModelLoadProfile) -> Result<ModelLease, ModelError> {
        self.config.capabilities.validate()?;
        profile.validate(&self.config.capabilities)?;
        {
            let state = lock(&self.state, "local backend state")?;
            if state.lease.is_some() {
                return Err(ModelError::AlreadyLoaded);
            }
        }

        let lease_id = acquire_global_lease(&self.config.model_name)?;
        let mut child = match &self.config.launch {
            Some(launch) => match self.launch_process(launch, profile) {
                Ok(child) => Some(child),
                Err(error) => {
                    release_global_lease(&lease_id)?;
                    return Err(error);
                }
            },
            None => None,
        };
        let process_id = child.as_ref().map(Child::id);
        let started = Instant::now();
        let startup_timeout = Duration::from_millis(profile.startup_timeout_ms);
        let request_timeout = Duration::from_millis(
            profile
                .provider_call_timeout_ms
                .min(self.config.request_timeout_ms),
        );
        let mut startup_peak_rss_kb = process_id.and_then(process_rss_kb);

        loop {
            if let Some(pid) = process_id
                && let Some(rss) = process_rss_kb(pid)
            {
                startup_peak_rss_kb = Some(startup_peak_rss_kb.map_or(rss, |peak| peak.max(rss)));
            }
            if let Some(process) = child.as_mut()
                && let Some(status) = process.try_wait()?
            {
                release_global_lease(&lease_id)?;
                return Err(ModelError::ProviderExited(status.code()));
            }
            if self.provider_health(request_timeout).is_ok() {
                break;
            }
            if started.elapsed() >= startup_timeout {
                if let Some(process) = child.as_mut() {
                    let _ = process.kill();
                    let _ = process.wait();
                }
                release_global_lease(&lease_id)?;
                return Err(ModelError::DeadlineExceeded("startup"));
            }
            thread::sleep(Duration::from_millis(50));
        }

        let lease = ModelLease {
            lease_id,
            model_id: self.config.capabilities.model_id.clone(),
            context_tokens: profile.context_tokens,
            server_context_tokens: profile.server_context_tokens()?,
            process_id,
            startup_peak_rss_kb,
            post_load_rss_kb: process_id.and_then(process_rss_kb),
        };
        let mut state = lock(&self.state, "local backend state")?;
        state.profile = Some(profile);
        state.child = child;
        state.lease = Some(lease.clone());
        Ok(lease)
    }

    fn complete(&self, request: &ModelRequest) -> Result<ModelResponse, ModelError> {
        let profile = self.loaded_profile()?;
        request.validate(&self.config.capabilities, profile)?;
        let process_id = lock(&self.state, "local backend state")?
            .lease
            .as_ref()
            .and_then(|lease| lease.process_id);
        let sampler = process_id.map(start_rss_sampler);
        let timeout = Duration::from_millis(
            request
                .deadline_ms
                .min(profile.provider_call_timeout_ms)
                .min(self.config.request_timeout_ms),
        );
        let started = Instant::now();
        let deadline = started + timeout;
        self.token_admission_until(request, profile, deadline)?;
        let body = serde_json::to_vec(&self.completion_body(request))?;
        let result = http_request_until(
            SocketAddr::new(self.config.host, self.config.port),
            "POST",
            "/v1/chat/completions",
            Some(&body),
            deadline,
            self.config.max_http_response_bytes,
        );
        let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let peak_rss_kb = sampler.and_then(RssSampler::stop);
        let response = result?;
        if !(200..300).contains(&response.status) {
            return Err(ModelError::ProviderStatus {
                status: response.status,
                body: String::from_utf8_lossy(&response.body).into_owned(),
            });
        }
        Self::parse_completion(request, &response.body, elapsed_ms, peak_rss_kb)
    }

    fn count_tokens(&self, content: &str) -> Result<u32, ModelError> {
        let profile = self.loaded_profile()?;
        let timeout = Duration::from_millis(
            profile
                .provider_call_timeout_ms
                .min(self.config.request_timeout_ms),
        );
        self.tokenize_until(content, Instant::now() + timeout)
    }

    fn health(&self) -> Result<BackendHealth, ModelError> {
        self.provider_health(Duration::from_millis(self.config.request_timeout_ms))
    }

    fn residency_proof(&self) -> Result<ModelResidencyProof, ModelError> {
        if self.config.launch.is_none() {
            return Ok(ModelResidencyProof::Unknown);
        }
        let state = lock(&self.state, "local backend state")?;
        Ok(state
            .lease
            .as_ref()
            .map_or(ModelResidencyProof::Absent, |lease| {
                ModelResidencyProof::Resident {
                    process_id: lease.process_id,
                }
            }))
    }

    fn unload(&self) -> Result<(), ModelError> {
        let mut state = lock(&self.state, "local backend state")?;
        Self::cleanup_state(&mut state)
    }
}

impl Drop for LocalOpenAiBackend {
    fn drop(&mut self) {
        if let Ok(state) = self.state.get_mut() {
            let _ = Self::cleanup_state(state);
        }
    }
}

struct FakeState {
    lease: Option<ModelLease>,
    profile: Option<ModelLoadProfile>,
    responses: VecDeque<ModelResponse>,
}

/// Deterministic fake backend used by Controller/unit tests. It never acquires
/// the physical local-model lease because it owns no model process.
pub struct DeterministicFakeBackend {
    capabilities: ModelCapabilities,
    state: Mutex<FakeState>,
}

impl DeterministicFakeBackend {
    /// Creates a deterministic fake with FIFO response templates.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError`] if the supplied capabilities are invalid.
    pub fn new(
        capabilities: ModelCapabilities,
        responses: Vec<ModelResponse>,
    ) -> Result<Self, ModelError> {
        capabilities.validate()?;
        Ok(Self {
            capabilities,
            state: Mutex::new(FakeState {
                lease: None,
                profile: None,
                responses: responses.into(),
            }),
        })
    }
}

impl ModelBackend for DeterministicFakeBackend {
    fn capabilities(&self) -> ModelCapabilities {
        self.capabilities.clone()
    }

    fn load(&self, profile: ModelLoadProfile) -> Result<ModelLease, ModelError> {
        profile.validate(&self.capabilities)?;
        let mut state = lock(&self.state, "fake backend state")?;
        if state.lease.is_some() {
            return Err(ModelError::AlreadyLoaded);
        }
        let lease = ModelLease {
            lease_id: format!(
                "fake-model-lease-{}",
                LEASE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ),
            model_id: self.capabilities.model_id.clone(),
            context_tokens: profile.context_tokens,
            server_context_tokens: profile.server_context_tokens()?,
            process_id: None,
            startup_peak_rss_kb: None,
            post_load_rss_kb: None,
        };
        state.profile = Some(profile);
        state.lease = Some(lease.clone());
        Ok(lease)
    }

    fn complete(&self, request: &ModelRequest) -> Result<ModelResponse, ModelError> {
        let mut state = lock(&self.state, "fake backend state")?;
        let profile = state.profile.ok_or(ModelError::NotLoaded)?;
        request.validate(&self.capabilities, profile)?;
        let mut response = state.responses.pop_front().ok_or_else(|| {
            ModelError::InvalidResponse("fake backend response queue exhausted".to_owned())
        })?;
        response.schema_version = MODEL_SCHEMA_VERSION;
        response.request_id.clone_from(&request.request_id);
        response.structured =
            validate_output_contract(&request.output_contract, &response.content)?;
        Ok(response)
    }

    fn count_tokens(&self, content: &str) -> Result<u32, ModelError> {
        if lock(&self.state, "fake backend state")?.lease.is_none() {
            return Err(ModelError::NotLoaded);
        }
        let bytes = content.len();
        let approximate = bytes.div_ceil(4).max(1);
        u32::try_from(approximate)
            .map_err(|_| ModelError::InvalidResponse("fake token count exceeds u32".to_owned()))
    }

    fn health(&self) -> Result<BackendHealth, ModelError> {
        let loaded = lock(&self.state, "fake backend state")?.lease.is_some();
        Ok(BackendHealth {
            reachable: true,
            loaded,
            detail: "deterministic fake backend".to_owned(),
        })
    }

    fn residency_proof(&self) -> Result<ModelResidencyProof, ModelError> {
        let loaded = lock(&self.state, "fake backend state")?.lease.is_some();
        Ok(if loaded {
            ModelResidencyProof::Resident { process_id: None }
        } else {
            ModelResidencyProof::Absent
        })
    }

    fn unload(&self) -> Result<(), ModelError> {
        let mut state = lock(&self.state, "fake backend state")?;
        state.lease = None;
        state.profile = None;
        Ok(())
    }
}

fn validate_output_contract(
    contract: &ModelOutputContract,
    content: &str,
) -> Result<Option<Value>, ModelError> {
    let ModelOutputContract::JsonSchema { schema, .. } = contract else {
        return Ok(None);
    };
    let value: Value = serde_json::from_str(content).map_err(|error| {
        ModelError::InvalidResponse(format!("structured output is not JSON: {error}"))
    })?;
    let validator = jsonschema::validator_for(schema).map_err(|error| {
        ModelError::InvalidContract(format!("response JSON schema is invalid: {error}"))
    })?;
    if let Some(error) = validator.iter_errors(&value).next() {
        return Err(ModelError::InvalidResponse(format!(
            "structured output violates JSON schema: {error}"
        )));
    }
    Ok(Some(value))
}

fn acquire_global_lease(owner: &str) -> Result<String, ModelError> {
    let registry = ACTIVE_LOCAL_MODEL.get_or_init(|| Mutex::new(None));
    let mut active = lock(registry, "global local-model lease")?;
    if let Some(existing) = active.as_ref() {
        return Err(ModelError::LeaseUnavailable(existing.clone()));
    }
    let lease_id = format!(
        "local-model-{}-{}",
        owner
            .chars()
            .map(|character| if character.is_ascii_alphanumeric() {
                character
            } else {
                '-'
            })
            .collect::<String>(),
        LEASE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    );
    *active = Some(lease_id.clone());
    Ok(lease_id)
}

fn release_global_lease(lease_id: &str) -> Result<(), ModelError> {
    let registry = ACTIVE_LOCAL_MODEL.get_or_init(|| Mutex::new(None));
    let mut active = lock(registry, "global local-model lease")?;
    if active.as_deref() == Some(lease_id) {
        *active = None;
    }
    Ok(())
}

fn lock<'a, T>(mutex: &'a Mutex<T>, name: &'static str) -> Result<MutexGuard<'a, T>, ModelError> {
    mutex.lock().map_err(|_| ModelError::LockPoisoned(name))
}

struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

fn http_request(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
    timeout: Duration,
    max_response_bytes: u64,
) -> Result<HttpResponse, ModelError> {
    http_request_until(
        address,
        method,
        path,
        body,
        Instant::now() + timeout,
        max_response_bytes,
    )
}

fn http_request_until(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
    deadline: Instant,
    max_response_bytes: u64,
) -> Result<HttpResponse, ModelError> {
    let mut stream =
        TcpStream::connect_timeout(&address, remaining(deadline)?).map_err(map_io_deadline)?;
    let payload = body.unwrap_or_default();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        payload.len()
    );
    stream
        .set_write_timeout(Some(remaining(deadline)?))
        .map_err(ModelError::Io)?;
    stream
        .write_all(request.as_bytes())
        .map_err(map_io_deadline)?;
    if !payload.is_empty() {
        stream
            .set_write_timeout(Some(remaining(deadline)?))
            .map_err(ModelError::Io)?;
        stream.write_all(payload).map_err(map_io_deadline)?;
    }
    stream
        .set_write_timeout(Some(remaining(deadline)?))
        .map_err(ModelError::Io)?;
    stream.flush().map_err(map_io_deadline)?;

    let read_cap = max_response_bytes.saturating_add(65_536);
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        stream
            .set_read_timeout(Some(remaining(deadline)?))
            .map_err(ModelError::Io)?;
        let count = stream.read(&mut buffer).map_err(map_io_deadline)?;
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..count]);
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > read_cap {
            return Err(ModelError::HttpProtocol(
                "provider response exceeds configured byte ceiling".to_owned(),
            ));
        }
    }
    parse_http_response(&bytes, max_response_bytes)
}

fn remaining(deadline: Instant) -> Result<Duration, ModelError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or(ModelError::DeadlineExceeded("wall"))
}

fn token_count_from_response(bytes: &[u8]) -> Result<u32, ModelError> {
    let root: Value = serde_json::from_slice(bytes)?;
    let tokens = root
        .get("tokens")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            ModelError::InvalidResponse("tokenize response missing tokens".to_owned())
        })?;
    u32::try_from(tokens.len())
        .map_err(|_| ModelError::InvalidResponse("token count exceeds u32".to_owned()))
}

fn parse_http_response(bytes: &[u8], max_body_bytes: u64) -> Result<HttpResponse, ModelError> {
    let header_end = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| ModelError::HttpProtocol("missing HTTP header terminator".to_owned()))?;
    let headers = std::str::from_utf8(&bytes[..header_end])
        .map_err(|_| ModelError::HttpProtocol("non-UTF-8 HTTP headers".to_owned()))?;
    let mut lines = headers.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| ModelError::HttpProtocol("missing HTTP status line".to_owned()))?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| ModelError::HttpProtocol("missing HTTP status code".to_owned()))?
        .parse::<u16>()
        .map_err(|_| ModelError::HttpProtocol("invalid HTTP status code".to_owned()))?;
    let chunked = lines.any(|line| {
        let lower = line.to_ascii_lowercase();
        lower.starts_with("transfer-encoding:") && lower.contains("chunked")
    });
    let raw_body = &bytes[header_end + 4..];
    let body = if chunked {
        decode_chunked(raw_body, max_body_bytes)?
    } else {
        if u64::try_from(raw_body.len()).unwrap_or(u64::MAX) > max_body_bytes {
            return Err(ModelError::HttpProtocol(
                "provider body exceeds configured byte ceiling".to_owned(),
            ));
        }
        raw_body.to_vec()
    };
    Ok(HttpResponse { status, body })
}

fn decode_chunked(bytes: &[u8], max_body_bytes: u64) -> Result<Vec<u8>, ModelError> {
    let mut offset = 0;
    let mut body = Vec::new();
    loop {
        let line_end = bytes[offset..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| ModelError::HttpProtocol("malformed chunk size".to_owned()))?
            + offset;
        let size_text = std::str::from_utf8(&bytes[offset..line_end])
            .map_err(|_| ModelError::HttpProtocol("non-UTF-8 chunk size".to_owned()))?;
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or_default(), 16)
            .map_err(|_| ModelError::HttpProtocol("invalid chunk size".to_owned()))?;
        offset = line_end + 2;
        if size == 0 {
            break;
        }
        let end = offset
            .checked_add(size)
            .ok_or_else(|| ModelError::HttpProtocol("chunk size overflow".to_owned()))?;
        if end + 2 > bytes.len() || &bytes[end..end + 2] != b"\r\n" {
            return Err(ModelError::HttpProtocol("truncated HTTP chunk".to_owned()));
        }
        body.extend_from_slice(&bytes[offset..end]);
        if u64::try_from(body.len()).unwrap_or(u64::MAX) > max_body_bytes {
            return Err(ModelError::HttpProtocol(
                "chunked provider body exceeds configured byte ceiling".to_owned(),
            ));
        }
        offset = end + 2;
    }
    Ok(body)
}

fn map_io_deadline(error: std::io::Error) -> ModelError {
    if matches!(
        error.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    ) {
        ModelError::DeadlineExceeded("transport")
    } else {
        ModelError::Io(error)
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

struct RssSampler {
    stop: Arc<AtomicBool>,
    handle: JoinHandle<Option<u64>>,
}

impl RssSampler {
    fn stop(self) -> Option<u64> {
        self.stop.store(true, Ordering::Release);
        self.handle.join().ok().flatten()
    }
}

fn start_rss_sampler(pid: u32) -> RssSampler {
    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = Arc::clone(&stop);
    let handle = thread::spawn(move || {
        let mut peak = process_rss_kb(pid);
        while !worker_stop.load(Ordering::Acquire) {
            if let Some(rss) = process_rss_kb(pid) {
                peak = Some(peak.map_or(rss, |current| current.max(rss)));
            }
            thread::sleep(Duration::from_millis(20));
        }
        peak
    });
    RssSampler { stop, handle }
}
