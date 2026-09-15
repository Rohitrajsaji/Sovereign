use serde_json::{Value, json};
use sovereign_model::{
    DeterministicFakeBackend, LocalOpenAiBackend, LocalOpenAiConfig, MODEL_SCHEMA_VERSION,
    ModelBackend, ModelCapabilities, ModelError, ModelFinishReason, ModelLoadProfile, ModelMessage,
    ModelMessageRole, ModelOutputContract, ModelRequest, ModelResponse, ModelUsage,
};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

static LOCAL_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn local_test_guard() -> MutexGuard<'static, ()> {
    LOCAL_TEST_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn capabilities() -> ModelCapabilities {
    ModelCapabilities {
        schema_version: MODEL_SCHEMA_VERSION,
        model_id: "fixture-3b-q4".to_owned(),
        parameter_class: "3B".to_owned(),
        quantization: "Q4".to_owned(),
        max_context_tokens: 16_384,
        supports_tools: true,
        supports_json_schema: true,
        local: true,
    }
}

fn profile() -> ModelLoadProfile {
    ModelLoadProfile {
        context_tokens: 4_096,
        output_reserve_tokens: 1_024,
        startup_timeout_ms: 1_000,
        provider_call_timeout_ms: 500,
    }
}

fn json_request(request_id: &str) -> ModelRequest {
    ModelRequest {
        schema_version: MODEL_SCHEMA_VERSION,
        request_id: request_id.to_owned(),
        messages: vec![ModelMessage {
            role: ModelMessageRole::User,
            content: "Return the requested JSON.".to_owned(),
            tool_call_id: None,
        }],
        tools: Vec::new(),
        output_contract: ModelOutputContract::JsonSchema {
            name: "fixture".to_owned(),
            schema: json!({
                "type": "object",
                "required": ["ok"],
                "additionalProperties": false,
                "properties": {"ok": {"type": "boolean"}}
            }),
        },
        input_token_ceiling: 4_096,
        max_output_tokens: 128,
        deadline_ms: 500,
        temperature_milli: 0,
    }
}

fn text_request(request_id: &str) -> ModelRequest {
    ModelRequest {
        schema_version: MODEL_SCHEMA_VERSION,
        request_id: request_id.to_owned(),
        messages: vec![ModelMessage {
            role: ModelMessageRole::User,
            content: "Use the declared tool if needed.".to_owned(),
            tool_call_id: None,
        }],
        tools: Vec::new(),
        output_contract: ModelOutputContract::Text,
        input_token_ceiling: 4_096,
        max_output_tokens: 128,
        deadline_ms: 500,
        temperature_milli: 0,
    }
}

fn template_reply() -> TestReply {
    TestReply::json(
        200,
        &json!({"prompt":"<|im_start|>user\nrendered fixture<|im_end|>\n<|im_start|>assistant\n"}),
    )
}

fn token_reply(count: usize) -> TestReply {
    TestReply::json(200, &json!({"tokens": vec![1_u32; count]}))
}

fn response_template(content: &str) -> ModelResponse {
    ModelResponse {
        schema_version: MODEL_SCHEMA_VERSION,
        request_id: "template".to_owned(),
        content: content.to_owned(),
        structured: None,
        tool_calls: Vec::new(),
        finish_reason: ModelFinishReason::Stop,
        usage: ModelUsage {
            input_tokens: 7,
            output_tokens: 3,
        },
        elapsed_ms: 1,
        peak_rss_kb_during_call: None,
    }
}

#[test]
fn fake_backend_contract_is_deterministic_and_reloadable() {
    let backend =
        DeterministicFakeBackend::new(capabilities(), vec![response_template("{\"ok\":true}")])
            .unwrap_or_else(|error| panic!("fake backend: {error}"));
    assert!(
        !backend
            .health()
            .unwrap_or_else(|error| panic!("health: {error}"))
            .loaded
    );

    let first = backend
        .load(profile())
        .unwrap_or_else(|error| panic!("load: {error}"));
    assert_eq!(first.context_tokens, 4_096);
    assert!(
        backend
            .health()
            .unwrap_or_else(|error| panic!("health: {error}"))
            .loaded
    );
    assert!(backend.count_tokens("hello model").unwrap_or(0) > 0);

    let response = backend
        .complete(&json_request("request.fake"))
        .unwrap_or_else(|error| panic!("complete: {error}"));
    assert_eq!(response.request_id, "request.fake");
    assert_eq!(response.structured, Some(json!({"ok": true})));

    backend
        .unload()
        .unwrap_or_else(|error| panic!("unload: {error}"));
    assert!(
        !backend
            .health()
            .unwrap_or_else(|error| panic!("health: {error}"))
            .loaded
    );
    backend
        .load(profile())
        .unwrap_or_else(|error| panic!("reload: {error}"));
    backend
        .unload()
        .unwrap_or_else(|error| panic!("second unload: {error}"));
}

#[test]
fn local_provider_maps_completion_and_token_count_without_provider_types_leaking() {
    let _guard = local_test_guard();
    let server = TestServer::spawn(6, |request| match request.path.as_str() {
        "/health" => TestReply::json(200, &json!({"status":"ok"})),
        "/apply-template" => {
            let body: Value = serde_json::from_slice(&request.body)
                .unwrap_or_else(|error| panic!("template request JSON: {error}"));
            assert!(body["messages"].is_array());
            template_reply()
        }
        "/v1/chat/completions" => {
            let body: Value = serde_json::from_slice(&request.body)
                .unwrap_or_else(|error| panic!("completion request JSON: {error}"));
            assert_eq!(body["model"], "fixture-model");
            assert!(body["messages"].is_array());
            TestReply::json(
                200,
                &json!({
                        "choices": [{
                            "message": {"content": "{\"ok\":true}"},
                            "finish_reason": "stop"
                    }],
                    "usage": {"prompt_tokens": 11, "completion_tokens": 4}
                }),
            )
        }
        "/tokenize" => {
            let body: Value = serde_json::from_slice(&request.body)
                .unwrap_or_else(|error| panic!("tokenize request JSON: {error}"));
            if body["content"] == "bounded context" {
                token_reply(4)
            } else {
                token_reply(11)
            }
        }
        _ => TestReply::json(404, &json!({"error":"not found"})),
    });
    let backend = attached_backend(server.address(), 500);
    backend
        .load(profile())
        .unwrap_or_else(|error| panic!("load local: {error}"));
    let response = backend
        .complete(&json_request("request.local"))
        .unwrap_or_else(|error| panic!("complete local: {error}"));
    assert_eq!(response.structured, Some(json!({"ok": true})));
    assert_eq!(response.usage.input_tokens, 11);
    assert_eq!(response.usage.output_tokens, 4);
    assert_eq!(backend.count_tokens("bounded context").unwrap_or(0), 4);
    backend
        .unload()
        .unwrap_or_else(|error| panic!("unload local: {error}"));
    server.finish();
}

#[test]
fn provider_health_obeys_transport_deadline() {
    let _guard = local_test_guard();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap_or_else(|error| panic!("bind timeout server: {error}"));
    let address = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("timeout server address: {error}"));
    let handle = thread::spawn(move || {
        let (_stream, _) = listener
            .accept()
            .unwrap_or_else(|error| panic!("accept timeout request: {error}"));
        thread::sleep(Duration::from_millis(150));
    });
    let backend = attached_backend(address, 30);
    assert!(matches!(
        backend.health(),
        Err(ModelError::DeadlineExceeded("transport"))
    ));
    handle
        .join()
        .unwrap_or_else(|_| panic!("timeout server thread panicked"));
}

#[test]
fn structured_response_validation_rejects_schema_violation() {
    let _guard = local_test_guard();
    let server = TestServer::spawn(5, |request| match request.path.as_str() {
        "/health" => TestReply::json(200, &json!({"status":"ok"})),
        "/apply-template" => template_reply(),
        "/tokenize" => token_reply(8),
        "/v1/chat/completions" => TestReply::json(
            200,
            &json!({
                "choices": [{
                    "message": {"content": "{\"ok\":\"not-a-boolean\"}"},
                    "finish_reason": "stop"
                }],
                "usage": {"prompt_tokens": 5, "completion_tokens": 3}
            }),
        ),
        _ => TestReply::json(404, &json!({"error":"not found"})),
    });
    let backend = attached_backend(server.address(), 500);
    backend
        .load(profile())
        .unwrap_or_else(|error| panic!("load: {error}"));
    assert!(matches!(
        backend.complete(&json_request("request.invalid")),
        Err(ModelError::InvalidResponse(_))
    ));
    backend
        .unload()
        .unwrap_or_else(|error| panic!("unload: {error}"));
    server.finish();
}

#[test]
fn rendered_request_admission_counts_template_tools_schema_and_output_reserve() {
    let _guard = local_test_guard();
    let server = TestServer::spawn(4, |request| match request.path.as_str() {
        "/health" => TestReply::json(200, &json!({"status":"ok"})),
        "/apply-template" => {
            let body: Value = serde_json::from_slice(&request.body)
                .unwrap_or_else(|error| panic!("template JSON: {error}"));
            assert!(body["messages"].is_array());
            template_reply()
        }
        "/tokenize" => {
            let body: Value = serde_json::from_slice(&request.body)
                .unwrap_or_else(|error| panic!("tokenize JSON: {error}"));
            let content = body["content"].as_str().unwrap_or_default();
            if content.contains("rendered fixture") {
                token_reply(100)
            } else {
                assert!(content.contains("json_schema"));
                token_reply(20)
            }
        }
        _ => TestReply::json(404, &json!({"error":"not found"})),
    });
    let backend = attached_backend(server.address(), 500);
    backend
        .load(profile())
        .unwrap_or_else(|error| panic!("load: {error}"));
    let admission = backend
        .token_admission(&json_request("request.accounting"))
        .unwrap_or_else(|error| panic!("admission: {error}"));
    assert_eq!(admission.rendered_input_tokens, 100);
    assert_eq!(admission.structured_output_tokens, 20);
    assert_eq!(admission.admitted_input_tokens, 120);
    assert_eq!(admission.reserved_output_tokens, 128);
    assert_eq!(admission.server_context_tokens, 5_120);
    backend
        .unload()
        .unwrap_or_else(|error| panic!("unload: {error}"));
    server.finish();
}

#[test]
fn oversized_fully_rendered_request_is_rejected_before_completion_dispatch() {
    let _guard = local_test_guard();
    let server = TestServer::spawn(3, |request| match request.path.as_str() {
        "/health" => TestReply::json(200, &json!({"status":"ok"})),
        "/apply-template" => template_reply(),
        "/tokenize" => token_reply(129),
        "/v1/chat/completions" => panic!("oversized request reached completion endpoint"),
        _ => TestReply::json(404, &json!({"error":"not found"})),
    });
    let backend = attached_backend(server.address(), 500);
    let small_profile = ModelLoadProfile {
        context_tokens: 128,
        output_reserve_tokens: 64,
        startup_timeout_ms: 1_000,
        provider_call_timeout_ms: 500,
    };
    backend
        .load(small_profile)
        .unwrap_or_else(|error| panic!("load: {error}"));
    let mut request = text_request("request.oversized");
    request.input_token_ceiling = 128;
    request.max_output_tokens = 32;
    assert!(matches!(
        backend.complete(&request),
        Err(ModelError::InvalidContract(_))
    ));
    backend
        .unload()
        .unwrap_or_else(|error| panic!("unload: {error}"));
    server.finish();
}

#[test]
fn completion_deadline_is_absolute_across_preflight_and_inference() {
    let _guard = local_test_guard();
    let server = TestServer::spawn(4, |request| match request.path.as_str() {
        "/health" => TestReply::json(200, &json!({"status":"ok"})),
        "/apply-template" => {
            thread::sleep(Duration::from_millis(25));
            template_reply()
        }
        "/tokenize" => {
            thread::sleep(Duration::from_millis(25));
            token_reply(8)
        }
        "/v1/chat/completions" => {
            thread::sleep(Duration::from_millis(25));
            TestReply::json(
                200,
                &json!({
                    "choices": [{"message": {"content":"ok"}, "finish_reason":"stop"}],
                    "usage": {"prompt_tokens":8,"completion_tokens":1}
                }),
            )
        }
        _ => TestReply::json(404, &json!({"error":"not found"})),
    });
    let backend = attached_backend(server.address(), 500);
    backend
        .load(profile())
        .unwrap_or_else(|error| panic!("load: {error}"));
    let mut request = text_request("request.absolute-deadline");
    request.deadline_ms = 65;
    let started = std::time::Instant::now();
    assert!(matches!(
        backend.complete(&request),
        Err(ModelError::DeadlineExceeded(_))
    ));
    assert!(started.elapsed() < Duration::from_millis(100));
    backend
        .unload()
        .unwrap_or_else(|error| panic!("unload: {error}"));
    server.finish();
}

#[test]
fn load_profile_reserves_server_context_for_generation() {
    let backend = DeterministicFakeBackend::new(capabilities(), Vec::new())
        .unwrap_or_else(|error| panic!("fake backend: {error}"));
    let too_large = ModelLoadProfile {
        context_tokens: 16_000,
        output_reserve_tokens: 1_000,
        startup_timeout_ms: 1_000,
        provider_call_timeout_ms: 500,
    };
    assert!(matches!(
        backend.load(too_large),
        Err(ModelError::InvalidContract(_))
    ));
}

#[test]
fn local_provider_unload_releases_lease_for_clean_reload() {
    let _guard = local_test_guard();
    let server = TestServer::spawn(2, |request| match request.path.as_str() {
        "/health" => TestReply::json(200, &json!({"status":"ok"})),
        _ => TestReply::json(404, &json!({"error":"not found"})),
    });
    let backend = attached_backend(server.address(), 500);
    let first = backend
        .load(profile())
        .unwrap_or_else(|error| panic!("first load: {error}"));
    backend
        .unload()
        .unwrap_or_else(|error| panic!("first unload: {error}"));
    let second = backend
        .load(profile())
        .unwrap_or_else(|error| panic!("second load: {error}"));
    assert_ne!(first.lease_id, second.lease_id);
    backend
        .unload()
        .unwrap_or_else(|error| panic!("second unload: {error}"));
    server.finish();
}

#[test]
fn unload_interrupts_in_flight_attached_completion() {
    let _guard = local_test_guard();
    let completion_started = Arc::new(AtomicBool::new(false));
    let release_response = Arc::new(AtomicBool::new(false));
    let handler_started = Arc::clone(&completion_started);
    let handler_release = Arc::clone(&release_response);
    let server = TestServer::spawn(4, move |request| match request.path.as_str() {
        "/health" => TestReply::json(200, &json!({"status":"ok"})),
        "/apply-template" => template_reply(),
        "/tokenize" => token_reply(8),
        "/v1/chat/completions" => {
            handler_started.store(true, Ordering::Release);
            while !handler_release.load(Ordering::Acquire) {
                thread::sleep(Duration::from_millis(1));
            }
            TestReply::json(
                200,
                &json!({
                    "choices": [{"message": {"content":"too late"}, "finish_reason":"stop"}],
                    "usage": {"prompt_tokens":8,"completion_tokens":1}
                }),
            )
        }
        _ => TestReply::json(404, &json!({"error":"not found"})),
    });
    let backend = Arc::new(attached_backend(server.address(), 1_500));
    let long_profile = ModelLoadProfile {
        provider_call_timeout_ms: 1_500,
        ..profile()
    };
    backend
        .load(long_profile)
        .unwrap_or_else(|error| panic!("load: {error}"));

    let worker_backend = Arc::clone(&backend);
    let completion = thread::spawn(move || {
        let mut request = text_request("request.cancelled");
        request.deadline_ms = 1_500;
        worker_backend.complete(&request)
    });
    let dispatch_wait = Instant::now();
    while !completion_started.load(Ordering::Acquire) {
        assert!(
            dispatch_wait.elapsed() < Duration::from_millis(500),
            "completion never reached provider"
        );
        thread::sleep(Duration::from_millis(1));
    }

    let cancellation_started = Instant::now();
    backend
        .unload()
        .unwrap_or_else(|error| panic!("unload: {error}"));
    let result = completion
        .join()
        .unwrap_or_else(|_| panic!("completion thread panicked"));
    assert!(
        result.is_err(),
        "cancelled completion unexpectedly succeeded"
    );
    assert!(
        cancellation_started.elapsed() < Duration::from_millis(250),
        "in-flight completion was not interrupted promptly"
    );

    release_response.store(true, Ordering::Release);
    server.finish();
}

#[test]
fn only_one_physical_local_model_lease_can_be_active() {
    let _guard = local_test_guard();
    let server = TestServer::spawn(2, |request| match request.path.as_str() {
        "/health" => TestReply::json(200, &json!({"status":"ok"})),
        _ => TestReply::json(404, &json!({"error":"not found"})),
    });
    let first = attached_backend(server.address(), 500);
    let second = attached_backend(server.address(), 500);
    first
        .load(profile())
        .unwrap_or_else(|error| panic!("load first: {error}"));
    assert!(matches!(
        second.load(profile()),
        Err(ModelError::LeaseUnavailable(_))
    ));
    first
        .unload()
        .unwrap_or_else(|error| panic!("unload first: {error}"));
    second
        .load(profile())
        .unwrap_or_else(|error| panic!("load second: {error}"));
    second
        .unload()
        .unwrap_or_else(|error| panic!("unload second: {error}"));
    server.finish();
}

fn attached_backend(address: SocketAddr, timeout_ms: u64) -> LocalOpenAiBackend {
    let mut config = LocalOpenAiConfig::with_defaults(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        address.port(),
        "fixture-model",
        capabilities(),
    );
    config.request_timeout_ms = timeout_ms;
    LocalOpenAiBackend::new(config).unwrap_or_else(|error| panic!("local backend: {error}"))
}

struct TestRequest {
    path: String,
    body: Vec<u8>,
}

struct TestReply {
    status: u16,
    body: Vec<u8>,
}

impl TestReply {
    fn json(status: u16, value: &Value) -> Self {
        Self {
            status,
            body: serde_json::to_vec(&value)
                .unwrap_or_else(|error| panic!("serialize test reply: {error}")),
        }
    }
}

struct TestServer {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: JoinHandle<()>,
}

impl TestServer {
    fn spawn(
        expected_requests: usize,
        handler: impl Fn(TestRequest) -> TestReply + Send + Sync + 'static,
    ) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap_or_else(|error| panic!("bind test server: {error}"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("test server address: {error}"));
        listener
            .set_nonblocking(true)
            .unwrap_or_else(|error| panic!("set test server nonblocking: {error}"));
        let handler = Arc::new(handler);
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            let mut served = 0;
            while served < expected_requests && !thread_stop.load(Ordering::Acquire) {
                let (mut stream, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    Err(error) => panic!("accept test request: {error}"),
                };
                stream
                    .set_nonblocking(false)
                    .unwrap_or_else(|error| panic!("set accepted stream blocking: {error}"));
                stream
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap_or_else(|error| panic!("set read timeout: {error}"));
                let request = read_request(&mut stream);
                let reply = handler(request);
                write_reply(&mut stream, &reply);
                served += 1;
            }
        });
        Self {
            address,
            stop,
            handle,
        }
    }

    const fn address(&self) -> SocketAddr {
        self.address
    }

    fn finish(self) {
        self.stop.store(true, Ordering::Release);
        self.handle
            .join()
            .unwrap_or_else(|_| panic!("test server thread panicked"));
    }
}

fn read_request(stream: &mut TcpStream) -> TestRequest {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4_096];
    let (header_end, content_length) = loop {
        let count = stream
            .read(&mut buffer)
            .unwrap_or_else(|error| panic!("read test request: {error}"));
        assert!(count > 0, "client closed before request headers completed");
        bytes.extend_from_slice(&buffer[..count]);
        if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            let header_end = position + 4;
            let headers = String::from_utf8_lossy(&bytes[..position]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    line.strip_prefix("Content-Length: ")
                        .and_then(|value| value.parse::<usize>().ok())
                })
                .unwrap_or(0);
            break (header_end, content_length);
        }
    };
    while bytes.len() < header_end + content_length {
        let count = stream
            .read(&mut buffer)
            .unwrap_or_else(|error| panic!("read test request body: {error}"));
        assert!(count > 0, "client closed before request body completed");
        bytes.extend_from_slice(&buffer[..count]);
    }
    let request_line_end = bytes
        .windows(2)
        .position(|window| window == b"\r\n")
        .unwrap_or_else(|| panic!("missing test request line"));
    let request_line = String::from_utf8_lossy(&bytes[..request_line_end]);
    let path = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or_else(|| panic!("missing request path"))
        .to_owned();
    TestRequest {
        path,
        body: bytes[header_end..header_end + content_length].to_vec(),
    }
}

fn write_reply(stream: &mut TcpStream, reply: &TestReply) {
    let reason = if reply.status == 200 { "OK" } else { "Error" };
    let headers = format!(
        "HTTP/1.1 {} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        reply.status,
        reply.body.len()
    );
    if stream.write_all(headers.as_bytes()).is_ok() {
        let _ = stream.write_all(&reply.body);
    }
}
