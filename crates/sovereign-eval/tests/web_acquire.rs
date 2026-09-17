use sha2::{Digest, Sha256};
use sovereign_policy::NetworkPolicy;
use sovereign_tools::{
    ScraplingStaticParser, ToolError, WEB_ACQUIRE_SCHEMA_VERSION, WebAcquireAdapter,
    WebAcquireRequestV1, WebDnsResolver, WebHtmlParser, WebHttpTransport, WebTransportRequestV1,
    WebTransportResponseV1,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

static PARSER_WORKER_TEST_NONCE: AtomicUsize = AtomicUsize::new(0);

fn ip(value: &str) -> IpAddr {
    value
        .parse()
        .unwrap_or_else(|error| panic!("parse test IP {value}: {error}"))
}

fn request(url: &str, parse_html: bool) -> WebAcquireRequestV1 {
    WebAcquireRequestV1 {
        schema_version: WEB_ACQUIRE_SCHEMA_VERSION,
        request_id: "request:m7-t02".to_owned(),
        url: url.to_owned(),
        max_response_bytes: 128 * 1024,
        max_redirects: 3,
        timeout_ms: 5_000,
        parse_html,
    }
}

#[derive(Default)]
struct FakeResolver {
    answers: BTreeMap<String, BTreeSet<IpAddr>>,
    calls: AtomicUsize,
}

impl FakeResolver {
    fn with(mut self, host: &str, addresses: impl IntoIterator<Item = IpAddr>) -> Self {
        self.answers
            .insert(host.to_owned(), addresses.into_iter().collect());
        self
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl WebDnsResolver for FakeResolver {
    fn resolve(
        &self,
        destination: &sovereign_policy::NetworkDestination,
    ) -> Result<BTreeSet<IpAddr>, ToolError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.answers.get(&destination.host).cloned().ok_or_else(|| {
            ToolError::Authority(format!("missing fake DNS answer for {}", destination.host))
        })
    }
}

struct FakeTransport {
    responses: BTreeMap<String, WebTransportResponseV1>,
    calls: AtomicUsize,
    requests: Mutex<Vec<WebTransportRequestV1>>,
}

impl FakeTransport {
    fn new(responses: impl IntoIterator<Item = (String, WebTransportResponseV1)>) -> Self {
        Self {
            responses: responses.into_iter().collect(),
            calls: AtomicUsize::new(0),
            requests: Mutex::new(Vec::new()),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl WebHttpTransport for FakeTransport {
    fn get(&self, request: &WebTransportRequestV1) -> Result<WebTransportResponseV1, ToolError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(request.clone());
        self.responses.get(&request.url).cloned().ok_or_else(|| {
            ToolError::Authority(format!("missing fake HTTP response for {}", request.url))
        })
    }
}

struct CrashTransport;

impl WebHttpTransport for CrashTransport {
    fn get(&self, _request: &WebTransportRequestV1) -> Result<WebTransportResponseV1, ToolError> {
        Err(ToolError::Authority(
            "simulated acquisition adapter crash".to_owned(),
        ))
    }
}

fn response(
    status_code: u16,
    peer: IpAddr,
    headers: BTreeMap<String, String>,
    body: &[u8],
) -> WebTransportResponseV1 {
    let mut raw_headers = format!("HTTP/1.1 {status_code} Test\r\n").into_bytes();
    for (name, value) in &headers {
        raw_headers.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    raw_headers.extend_from_slice(b"\r\n");
    WebTransportResponseV1 {
        status_code,
        connected_peer: peer,
        headers,
        raw_headers,
        body: body.to_vec(),
    }
}

fn allowed_policy(hosts: &[&str]) -> NetworkPolicy {
    let mut policy = NetworkPolicy::offline();
    for host in hosts {
        policy
            .allow("https", host, 443)
            .unwrap_or_else(|error| panic!("allow {host}: {error}"));
    }
    policy
}

#[test]
fn offline_is_denied_before_dns_or_transport() {
    let policy = NetworkPolicy::offline();
    let resolver = FakeResolver::default().with("example.com", [ip("93.184.216.34")]);
    let transport = FakeTransport::new([]);
    let adapter = WebAcquireAdapter::new(&policy, &resolver, &transport);

    let error = adapter
        .acquire(&request("https://example.com/", false))
        .err()
        .unwrap_or_else(|| panic!("offline acquisition must fail"));
    assert!(error.to_string().contains("offline"));
    assert_eq!(resolver.calls(), 0);
    assert_eq!(transport.calls(), 0);
}

#[test]
fn allowed_host_read_binds_dns_connected_peer_and_raw_response_evidence() {
    let policy = allowed_policy(&["example.com"]);
    let public_ip = ip("93.184.216.34");
    let resolver = FakeResolver::default().with("example.com", [public_ip]);
    let headers = BTreeMap::from([("content-type".to_owned(), "text/html".to_owned())]);
    let body = b"<html><body>Hello</body></html>";
    let transport = FakeTransport::new([(
        "https://example.com/data".to_owned(),
        response(200, public_ip, headers.clone(), body),
    )]);
    let adapter = WebAcquireAdapter::new(&policy, &resolver, &transport);

    let result = adapter
        .acquire(&request("https://EXAMPLE.com/data#ignored", false))
        .unwrap_or_else(|error| panic!("allowed acquisition: {error}"));
    assert_eq!(result.final_url, "https://example.com/data");
    assert_eq!(result.status_code, 200);
    assert_eq!(result.headers, headers);
    assert_eq!(result.body, body);
    assert_eq!(result.responses.len(), 1);
    let evidence = &result.responses[0];
    let mut hasher = Sha256::new();
    hasher.update(body);
    assert_eq!(
        evidence.body_sha256,
        format!("sha256:{:x}", hasher.finalize())
    );
    assert_eq!(evidence.body_bytes, body.len());
    assert_eq!(evidence.connected_peer, public_ip);
}

#[test]
fn idna_private_resolution_and_connected_peer_rebinding_fail_closed() {
    let idna_policy = allowed_policy(&["xn--xample-9ua.com"]);
    let idna_ip = ip("93.184.216.34");
    let idna_resolver = FakeResolver::default().with("xn--xample-9ua.com", [idna_ip]);
    let idna_transport = FakeTransport::new([(
        "https://xn--xample-9ua.com/".to_owned(),
        response(200, idna_ip, BTreeMap::new(), b"idna"),
    )]);
    let idna_adapter = WebAcquireAdapter::new(&idna_policy, &idna_resolver, &idna_transport);
    let idna_result = idna_adapter
        .acquire(&request("https://éxample.com/", false))
        .unwrap_or_else(|error| panic!("Unicode hostname should normalize to A-label: {error}"));
    assert_eq!(idna_result.final_url, "https://xn--xample-9ua.com/");
    assert_eq!(idna_resolver.calls(), 1);
    assert_eq!(idna_transport.calls(), 1);

    let policy = allowed_policy(&["safe.example"]);
    let unsafe_resolver = FakeResolver::default().with("safe.example", [ip("127.0.0.1")]);
    let never_transport = FakeTransport::new([]);
    let adapter = WebAcquireAdapter::new(&policy, &unsafe_resolver, &never_transport);
    assert!(
        adapter
            .acquire(&request("https://safe.example/", false))
            .is_err()
    );
    assert_eq!(never_transport.calls(), 0);

    let authorized = ip("93.184.216.34");
    let rebinding_peer = ip("1.1.1.1");
    let resolver = FakeResolver::default().with("safe.example", [authorized]);
    let transport = FakeTransport::new([(
        "https://safe.example/".to_owned(),
        response(200, rebinding_peer, BTreeMap::new(), b"unexpected"),
    )]);
    let adapter = WebAcquireAdapter::new(&policy, &resolver, &transport);
    let error = adapter
        .acquire(&request("https://safe.example/", false))
        .err()
        .unwrap_or_else(|| panic!("peer mismatch must fail"));
    assert!(error.to_string().contains("connected peer"));
}

#[test]
fn redirects_are_reauthorized_and_disallowed_target_never_reaches_transport() {
    let policy = allowed_policy(&["start.example"]);
    let start_ip = ip("93.184.216.34");
    let next_ip = ip("1.1.1.1");
    let resolver = FakeResolver::default()
        .with("start.example", [start_ip])
        .with("blocked.example", [next_ip]);
    let transport = FakeTransport::new([(
        "https://start.example/".to_owned(),
        response(
            302,
            start_ip,
            BTreeMap::from([(
                "location".to_owned(),
                "https://blocked.example/next".to_owned(),
            )]),
            b"",
        ),
    )]);
    let adapter = WebAcquireAdapter::new(&policy, &resolver, &transport);

    let error = adapter
        .acquire(&request("https://start.example/", false))
        .err()
        .unwrap_or_else(|| panic!("disallowed redirect must fail"));
    assert!(error.to_string().contains("not task-authorized"));
    assert_eq!(transport.calls(), 1);
    assert_eq!(resolver.calls(), 1);
}

#[test]
fn ambient_proxy_or_transport_cannot_bypass_controller_host_policy() {
    let policy = allowed_policy(&["allowed.example"]);
    let resolver = FakeResolver::default().with("denied.example", [ip("93.184.216.34")]);
    let transport = FakeTransport::new([]);
    let adapter = WebAcquireAdapter::new(&policy, &resolver, &transport);

    let error = adapter
        .acquire(&request("https://denied.example/", false))
        .err()
        .unwrap_or_else(|| panic!("host policy must deny before transport/proxy"));
    assert!(error.to_string().contains("not task-authorized"));
    assert_eq!(resolver.calls(), 0);
    assert_eq!(transport.calls(), 0);
}

#[test]
fn acquisition_adapter_crash_is_fail_closed() {
    let policy = allowed_policy(&["example.com"]);
    let resolver = FakeResolver::default().with("example.com", [ip("93.184.216.34")]);
    let adapter = WebAcquireAdapter::new(&policy, &resolver, &CrashTransport);
    let error = adapter
        .acquire(&request("https://example.com/", false))
        .err()
        .unwrap_or_else(|| panic!("crashing adapter must fail"));
    assert!(
        error
            .to_string()
            .contains("simulated acquisition adapter crash")
    );
}

#[test]
fn vendored_scrapling_static_parser_extracts_html_without_fetcher_or_browser_extras() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let vendor = root.join("research/tools/Scrapling");
    let worker = root.join("adapters/scrapling/parser_worker.py");
    let python = discover_scrapling_python(&vendor).unwrap_or_else(|| {
        panic!("no local Python runtime has the vendored Scrapling base-parser dependencies")
    });
    let parser = ScraplingStaticParser::new(&python, &worker, &vendor);
    let parsed = parser
        .parse(
            b"<html><head><title>Inventory</title></head><body><h1>Hello</h1><p>world</p><a href=\"/items\">Items</a></body></html>",
            5_000,
        )
        .unwrap_or_else(|error| panic!("static Scrapling parser: {error}"));

    assert_eq!(parsed.parser_name, "scrapling.parser.Selector");
    assert_eq!(parsed.parser_version, "0.4.15");
    assert_eq!(parsed.title.as_deref(), Some("Inventory"));
    assert!(parsed.text.contains("Hello"));
    assert!(parsed.text.contains("world"));
    assert_eq!(parsed.links, vec!["/items"]);

    let policy = allowed_policy(&["example.com"]);
    let public_ip = ip("93.184.216.34");
    let resolver = FakeResolver::default().with("example.com", [public_ip]);
    let html = b"<html><body><h1>Adapter parse</h1></body></html>";
    let transport = FakeTransport::new([(
        "https://example.com/".to_owned(),
        response(200, public_ip, BTreeMap::new(), html),
    )]);
    let adapter = WebAcquireAdapter::new(&policy, &resolver, &transport).with_parser(&parser);
    let result = adapter
        .acquire(&request("https://example.com/", true))
        .unwrap_or_else(|error| panic!("parsed acquisition: {error}"));
    let parsed = result
        .parsed
        .unwrap_or_else(|| panic!("parsed acquisition omitted parsed document"));
    assert!(parsed.text.contains("Adapter parse"));
}

#[test]
fn scrapling_worker_bounds_stdin_stdout_stderr_and_reaps_failures() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let vendor = root.join("research/tools/Scrapling");
    let python = discover_scrapling_python(&vendor).unwrap_or_else(|| {
        panic!("no local Python runtime has the vendored Scrapling base-parser dependencies")
    });
    let nonce = PARSER_WORKER_TEST_NONCE.fetch_add(1, Ordering::Relaxed);
    let test_root = std::env::temp_dir().join(format!(
        "sovereign-scrapling-bounds-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&test_root)
        .unwrap_or_else(|error| panic!("create parser bound-test root: {error}"));

    let timeout_pid = test_root.join("timeout.pid");
    let timeout_worker = write_test_worker(
        &test_root,
        "timeout.py",
        &format!(
            "from pathlib import Path\nimport os,time\nPath({:?}).write_text(str(os.getpid()))\ntime.sleep(5)\n",
            timeout_pid.to_string_lossy()
        ),
    );
    let timeout_parser = ScraplingStaticParser::new(&python, &timeout_worker, &vendor);
    let blocked_input = vec![b'x'; 8 * 1024 * 1024];
    let started = Instant::now();
    let timeout_error = timeout_parser
        .parse(&blocked_input, 250)
        .err()
        .unwrap_or_else(|| panic!("non-reading parser worker must time out"));
    assert!(
        timeout_error.to_string().contains("timed out"),
        "unexpected timeout error: {timeout_error}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "stdin backpressure escaped the parser deadline"
    );
    assert_reaped_pid(&timeout_pid);

    let stdout_pid = test_root.join("stdout.pid");
    let stdout_worker = write_test_worker(
        &test_root,
        "stdout_flood.py",
        &format!(
            "from pathlib import Path\nimport os,sys,time\nPath({:?}).write_text(str(os.getpid()))\nsys.stdin.buffer.read()\nsys.stdout.buffer.write(b'x' * (300 * 1024))\nsys.stdout.buffer.flush()\ntime.sleep(5)\n",
            stdout_pid.to_string_lossy()
        ),
    );
    let stdout_parser = ScraplingStaticParser::new(&python, &stdout_worker, &vendor);
    let stdout_error = stdout_parser
        .parse(b"<html></html>", 2_000)
        .err()
        .unwrap_or_else(|| panic!("stdout-flooding parser worker must fail"));
    assert!(
        stdout_error.to_string().contains("stdout exceeded bound"),
        "unexpected stdout overflow error: {stdout_error}"
    );
    assert_reaped_pid(&stdout_pid);

    let stderr_pid = test_root.join("stderr.pid");
    let stderr_worker = write_test_worker(
        &test_root,
        "stderr_flood.py",
        &format!(
            "from pathlib import Path\nimport os,sys,time\nPath({:?}).write_text(str(os.getpid()))\nsys.stdin.buffer.read()\nsys.stderr.buffer.write(b'e' * (300 * 1024))\nsys.stderr.buffer.flush()\ntime.sleep(5)\n",
            stderr_pid.to_string_lossy()
        ),
    );
    let stderr_parser = ScraplingStaticParser::new(&python, &stderr_worker, &vendor);
    let stderr_error = stderr_parser
        .parse(b"<html></html>", 2_000)
        .err()
        .unwrap_or_else(|| panic!("stderr-flooding parser worker must fail"));
    assert!(
        stderr_error.to_string().contains("stderr exceeded bound"),
        "unexpected stderr overflow error: {stderr_error}"
    );
    assert_reaped_pid(&stderr_pid);

    let crash_worker = write_test_worker(
        &test_root,
        "crash.py",
        "import sys\nsys.stdin.buffer.read()\nsys.stderr.write('controlled parser crash\\n')\nraise SystemExit(7)\n",
    );
    let crash_parser = ScraplingStaticParser::new(&python, &crash_worker, &vendor);
    let crash_error = crash_parser
        .parse(b"<html></html>", 2_000)
        .err()
        .unwrap_or_else(|| panic!("crashing parser worker must fail closed"));
    assert!(
        crash_error.to_string().contains("controlled parser crash"),
        "unexpected parser crash error: {crash_error}"
    );

    fs::remove_dir_all(&test_root)
        .unwrap_or_else(|error| panic!("remove parser bound-test root: {error}"));
}

fn write_test_worker(root: &Path, name: &str, source: &str) -> PathBuf {
    let worker = root.join(name);
    fs::write(&worker, source).unwrap_or_else(|error| panic!("write {name}: {error}"));
    worker
}

fn assert_reaped_pid(pid_path: &Path) {
    let pid = fs::read_to_string(pid_path)
        .unwrap_or_else(|error| panic!("read parser worker pid {}: {error}", pid_path.display()));
    let alive = Command::new("/bin/kill")
        .args(["-0", pid.trim()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    assert!(!alive, "parser worker PID {} was not reaped", pid.trim());
}

fn discover_scrapling_python(vendor: &Path) -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(path) = std::env::var_os("SOVEREIGN_SCRAPLING_PYTHON") {
        candidates.push(PathBuf::from(path));
    }
    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        candidates.push(home.join("genai-env/bin/python"));
        candidates.push(home.join("code-rag/.venv/bin/python"));
        candidates.push(home.join("free-claude-code/.venv/bin/python"));
        let desktop = home.join("Desktop");
        if let Ok(entries) = fs::read_dir(desktop) {
            for entry in entries.flatten() {
                candidates.push(entry.path().join(".venv/bin/python"));
            }
        }
    }
    candidates.into_iter().find(|candidate| {
        candidate.is_file() && python_supports_scrapling_base_parser(candidate, vendor)
    })
}

fn python_supports_scrapling_base_parser(python: &Path, vendor: &Path) -> bool {
    Command::new(python)
        .env_clear()
        .env("PYTHONPATH", vendor)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("PYTHONNOUSERSITE", "1")
        .args([
            "-s",
            "-c",
            "import lxml,cssselect,orjson,tld,w3lib,typing_extensions; from scrapling.parser import Selector; Selector('<h1>x</h1>', adaptive=False)",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}
