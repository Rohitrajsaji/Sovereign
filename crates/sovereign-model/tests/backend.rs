use serde_json::{Value, json};
use sovereign_model::{
    DeterministicFakeBackend, LocalOpenAiBackend, LocalOpenAiConfig, MODEL_SCHEMA_VERSION,
    ModelBackend, ModelCapabilities, ModelError, ModelFinishReason, ModelLoadProfile, ModelMessage,
    ModelMessageRole, ModelOutputContract, ModelRequest, ModelResponse, ModelUsage,
};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;

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
    let server = TestServer::spawn(3, |request| match request.path.as_str() {
        "/health" => TestReply::json(200, &json!({"status":"ok"})),
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
            assert_eq!(body["content"], "bounded context");
            TestReply::json(200, &json!({"tokens":[1,2,3,4]}))
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
    let server = TestServer::spawn(2, |request| match request.path.as_str() {
        "/health" => TestReply::json(200, &json!({"status":"ok"})),
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
        let handler = Arc::new(handler);
        let handle = thread::spawn(move || {
            for _ in 0..expected_requests {
                let (mut stream, _) = listener
                    .accept()
                    .unwrap_or_else(|error| panic!("accept test request: {error}"));
                stream
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap_or_else(|error| panic!("set read timeout: {error}"));
                let request = read_request(&mut stream);
                let reply = handler(request);
                write_reply(&mut stream, &reply);
            }
        });
        Self { address, handle }
    }

    const fn address(&self) -> SocketAddr {
        self.address
    }

    fn finish(self) {
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
    stream
        .write_all(headers.as_bytes())
        .unwrap_or_else(|error| panic!("write test headers: {error}"));
    stream
        .write_all(&reply.body)
        .unwrap_or_else(|error| panic!("write test body: {error}"));
}
