#![forbid(unsafe_code)]

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sovereign_context::{
    ContextBudget, ContextMode, ContextPacketInput, ContextPlanner, EvidenceItem,
};
use sovereign_controller::{
    BrowserResourceResidencyStateV1, BrowserResourceResidencyV1, BrowserTaskAuthorityV1,
    Controller, RecoveryManager, RoleId, RoleRegistry, browser_destination,
};
use sovereign_model::{
    DeterministicFakeBackend, MODEL_SCHEMA_VERSION, ModelBackend, ModelCapabilities,
    ModelFinishReason, ModelLoadProfile, ModelResponse, ModelUsage,
};
use sovereign_plan::{
    PLAN_COMPILATION_SCHEMA_VERSION, PlanCompilationInput, PlanCompilationRepository, PlanCompiler,
    PlanValidator, ValidationEnvironment,
};
use sovereign_policy::browser::{
    BROWSER_DOWNLOAD_POLICY_SCHEMA_VERSION, BROWSER_LOOPBACK_CAPABILITY_SCHEMA_VERSION,
    BrowserDownloadMode, BrowserDownloadPolicyV1, BrowserDownloadRetentionPolicyV1,
    BrowserDownloadRootAuthorityV1, BrowserLoopbackCapabilityV1, BrowserNavigationScheme,
    BrowserProfileAuthority, BrowserProfileMode, BrowserProfilePolicy,
    PERSISTENT_BROWSER_PROFILE_GRANT_SCHEMA_VERSION, PersistentBrowserProfileGrantV1,
    TASK_LOOPBACK_GRANT_SCHEMA_VERSION, TaskLoopbackGrantV1, TaskLoopbackScope,
    authorize_top_level_browser_url,
};
use sovereign_policy::{
    AdmissionStatus, ConditionalLeaseContextV1, HeavyLeaseClass, IsolatedCommand,
    M6ResourceGovernor, ModelCallBudget, NetworkDestination, OsMemoryPressure, PlanHeavyLeaseClass,
    ResourceLeaseOwnerV1, ResourceLeaseRequestV1, ResourcePressureSnapshotV1, TaskResourceBudgetV1,
    ThermalPressure,
};
use sovereign_repo::{ExactRetriever, ProjectRegistry, RepositoryIntelligence};
use sovereign_state::{NewJournalEvent, StateRecordUpdate, StateStore};
use sovereign_tools::browser::{
    BROWSER_SCHEMA_VERSION, BrowserAction, BrowserActionReceipt, BrowserAdapter,
    BrowserAdapterConfig, BrowserDocumentRequestDecision, BrowserError, BrowserLaunchOptions,
    BrowserLease, BrowserProfileRoot, BrowserSensitivePageReason, BrowserSensitivePageSignal,
    BrowserStateSynopsis, DownloadReceipt,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

static TEST_NONCE: AtomicU64 = AtomicU64::new(1);

struct TestDir(PathBuf);

impl TestDir {
    fn new(label: &str) -> Self {
        let nonce = TEST_NONCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "sovereign-eval-browser-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap_or_else(|error| panic!("create test root: {error}"));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("chmod test root: {error}"));
        Self(
            path.canonicalize()
                .unwrap_or_else(|error| panic!("canonical test root: {error}")),
        )
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _cleanup_result = fs::remove_dir_all(&self.0);
    }
}

fn sha256_binding(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn browser_lease(token: &str) -> BrowserLease {
    BrowserLease {
        schema_version: BROWSER_SCHEMA_VERSION,
        lease_id: "browser.eval.lease".to_owned(),
        task_id: "M7-T03".to_owned(),
        attempt_id: "browser.eval.attempt".to_owned(),
        execution_epoch: 7,
        token: token.to_owned(),
    }
}

fn chrome_path() -> Option<&'static Path> {
    let chrome = Path::new("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
    chrome.is_file().then_some(chrome)
}

fn spawn_browser(root: &Path, lease: &BrowserLease) -> Option<BrowserAdapter> {
    let chrome = chrome_path()?;
    let prepared = BrowserAdapter::prepare_launch(
        chrome,
        root,
        lease,
        BrowserAdapterConfig::default(),
        BrowserLaunchOptions::default(),
    )
    .unwrap_or_else(|error| panic!("prepare browser: {error}"));
    let mut args = vec![prepared.process_spec().executable.display().to_string()];
    args.extend(prepared.process_spec().args.iter().cloned());
    let wrapped = IsolatedCommand {
        executable: PathBuf::from("/usr/bin/env"),
        args,
    };
    Some(
        BrowserAdapter::spawn_preisolated(prepared, &wrapped)
            .unwrap_or_else(|error| panic!("spawn browser: {error}")),
    )
}

fn spawn_persistent_browser(
    root: &Path,
    profile: &Path,
    lease: &BrowserLease,
) -> Option<BrowserAdapter> {
    let chrome = chrome_path()?;
    let prepared = BrowserAdapter::prepare_launch(
        chrome,
        root,
        lease,
        BrowserAdapterConfig::default(),
        BrowserLaunchOptions {
            caller_chrome_args: vec!["--no-proxy-server".to_owned()],
            profile_root: BrowserProfileRoot::CallerOwnedPersistent(profile.to_path_buf()),
            ..BrowserLaunchOptions::default()
        },
    )
    .unwrap_or_else(|error| panic!("prepare persistent browser: {error}"));
    let mut args = vec![prepared.process_spec().executable.display().to_string()];
    args.extend(prepared.process_spec().args.iter().cloned());
    let wrapped = IsolatedCommand {
        executable: PathBuf::from("/usr/bin/env"),
        args,
    };
    Some(
        BrowserAdapter::spawn_preisolated(prepared, &wrapped)
            .unwrap_or_else(|error| panic!("spawn persistent browser: {error}")),
    )
}

fn navigate_local(adapter: &mut BrowserAdapter, lease: &BrowserLease, action_id: &str, url: &str) {
    let action = BrowserAction::Navigate {
        action_id: action_id.to_owned(),
        url: url.to_owned(),
    };
    adapter
        .dispatch_intercepted_action(lease, &action, None)
        .unwrap_or_else(|error| panic!("dispatch local navigation: {error}"));
    loop {
        let request = adapter
            .next_document_request(lease, 15_000)
            .unwrap_or_else(|error| panic!("observe local navigation request: {error}"));
        adapter
            .resolve_document_request(lease, &request, BrowserDocumentRequestDecision::Continue)
            .unwrap_or_else(|error| panic!("continue local navigation request: {error}"));
        match adapter.finish_dispatched_action(lease) {
            Ok(_) => return,
            Err(BrowserError::InvalidRequest(message))
                if message.contains("paused awaiting caller authorization") => {}
            Err(error) => panic!("finish local navigation: {error}"),
        }
    }
}

#[test]
fn probe_ephemeral_intercepted_local_navigation() {
    if chrome_path().is_none() {
        return;
    }
    let temp = TestDir::new("ephemeral-navigation-probe");
    let lease = browser_lease("ephemeral-navigation-probe-token");
    let (origin, stop_tx, server) = spawn_storage_server();
    let Some(mut adapter) = spawn_browser(&temp.0, &lease) else {
        let _ = stop_tx.send(());
        let _ = server.join();
        return;
    };
    navigate_local(
        &mut adapter,
        &lease,
        "ephemeral-navigation-probe",
        &format!("{origin}/seed"),
    );
    adapter
        .shutdown()
        .unwrap_or_else(|error| panic!("shutdown ephemeral probe: {error}"));
    let _ = stop_tx.send(());
    server
        .join()
        .unwrap_or_else(|_| panic!("ephemeral probe server panicked"));
}

fn read_storage_request(stream: &mut TcpStream) -> Option<String> {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut request = Vec::with_capacity(4096);
    loop {
        let mut chunk = [0_u8; 1024];
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(bytes) => {
                request.extend_from_slice(&chunk[..bytes]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(5));
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                break;
            }
            Err(error) => panic!("read storage fixture request: {error}"),
        }
    }
    (!request.is_empty()).then(|| String::from_utf8_lossy(&request).into_owned())
}

fn spawn_storage_server() -> (String, mpsc::Sender<()>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .unwrap_or_else(|error| panic!("bind storage fixture server: {error}"));
    listener
        .set_nonblocking(true)
        .unwrap_or_else(|error| panic!("set storage fixture server nonblocking: {error}"));
    let address = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("read storage fixture address: {error}"));
    let (stop_tx, stop_rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        loop {
            match stop_rx.try_recv() {
                Ok(()) | Err(mpsc::TryRecvError::Disconnected) => return,
                Err(mpsc::TryRecvError::Empty) => {}
            }
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false).unwrap_or_else(|error| {
                        panic!("set storage fixture stream blocking: {error}")
                    });
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap_or_else(|error| {
                            panic!("set storage fixture read timeout: {error}")
                        });
                    let Some(request) = read_storage_request(&mut stream) else {
                        continue;
                    };
                    let path = request
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or("/");
                    let body = match path {
                        "/seed" => {
                            r#"<!doctype html><meta charset="utf-8"><title>seed-start</title><script>
const cookieValue='cookie-'+'sentinel-'+'72f6';
const localValue='local-'+'sentinel-'+'4c31';
const sessionValue='session-old-'+'sentinel-'+'9a82';
document.cookie='sovereign_cookie='+cookieValue+'; Path=/; Max-Age=3600; SameSite=Lax';
localStorage.setItem('sovereign-local',localValue);
sessionStorage.setItem('sovereign-session',sessionValue);
const cookieOk=document.cookie.includes('sovereign_cookie='+cookieValue);
const localOk=localStorage.getItem('sovereign-local')===localValue;
const sessionOk=sessionStorage.getItem('sovereign-session')===sessionValue;
document.title=(cookieOk&&localOk&&sessionOk)?'storage-seeded':'storage-seed-failed';
</script><main>ordinary storage fixture</main>"#
                        }
                        "/check" => {
                            r#"<!doctype html><meta charset="utf-8"><title>check-start</title><script>
const cookieValue='cookie-'+'sentinel-'+'72f6';
const localValue='local-'+'sentinel-'+'4c31';
const newSessionValue='session-new-'+'sentinel-'+'d105';
const cookieOk=document.cookie.includes('sovereign_cookie='+cookieValue);
const localOk=localStorage.getItem('sovereign-local')===localValue;
const oldSessionAbsent=sessionStorage.getItem('sovereign-session')===null;
sessionStorage.setItem('sovereign-session',newSessionValue);
const newSessionOk=sessionStorage.getItem('sovereign-session')===newSessionValue;
document.title=(cookieOk&&localOk&&oldSessionAbsent&&newSessionOk)
  ?'storage-persisted'
  :'storage-check-'+Number(cookieOk)+Number(localOk)+Number(oldSessionAbsent)+Number(newSessionOk);
</script><main>ordinary storage fixture</main>"#
                        }
                        _ => "<!doctype html><title>not-found</title>",
                    };
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    stream
                        .write_all(response.as_bytes())
                        .unwrap_or_else(|error| panic!("write storage fixture response: {error}"));
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("accept storage fixture connection: {error}"),
            }
        }
    });
    (format!("http://{address}"), stop_tx, handle)
}

fn spawn_restart_server() -> (
    String,
    mpsc::Sender<()>,
    thread::JoinHandle<()>,
    Arc<AtomicU64>,
) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .unwrap_or_else(|error| panic!("bind restart fixture server: {error}"));
    listener
        .set_nonblocking(true)
        .unwrap_or_else(|error| panic!("set restart fixture server nonblocking: {error}"));
    let address = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("read restart fixture address: {error}"));
    let (stop_tx, stop_rx) = mpsc::channel();
    let submit_count = Arc::new(AtomicU64::new(0));
    let server_submit_count = Arc::clone(&submit_count);
    let handle = thread::spawn(move || {
        loop {
            match stop_rx.try_recv() {
                Ok(()) | Err(mpsc::TryRecvError::Disconnected) => return,
                Err(mpsc::TryRecvError::Empty) => {}
            }
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false).unwrap_or_else(|error| {
                        panic!("set restart fixture stream blocking: {error}")
                    });
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap_or_else(|error| {
                            panic!("set restart fixture read timeout: {error}")
                        });
                    let Some(request) = read_storage_request(&mut stream) else {
                        continue;
                    };
                    let mut request_parts = request
                        .lines()
                        .next()
                        .unwrap_or_default()
                        .split_whitespace();
                    let method = request_parts.next().unwrap_or_default();
                    let path = request_parts.next().unwrap_or("/");
                    let (body, hold_response) = match (method, path) {
                        ("GET", "/form") => (
                            r#"<!doctype html><meta charset="utf-8"><title>restart-form</title>
<form id="danger" action="/submitted" method="post"><input name="value" value="one"></form>
<main>restart form fixture</main>"#,
                            false,
                        ),
                        ("POST", "/submitted") => {
                            server_submit_count.fetch_add(1, Ordering::SeqCst);
                            (
                                "<!doctype html><title>submitted</title><main>submitted-once</main>",
                                true,
                            )
                        }
                        ("GET", "/recovered") => (
                            "<!doctype html><title>restart-recovered</title><main>fresh-run-ok</main>",
                            false,
                        ),
                        _ => ("<!doctype html><title>not-found</title>", false),
                    };
                    if hold_response {
                        thread::sleep(Duration::from_millis(750));
                    }
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    if hold_response {
                        let _ = stream.write_all(response.as_bytes());
                    } else {
                        stream
                            .write_all(response.as_bytes())
                            .unwrap_or_else(|error| {
                                panic!("write restart fixture response: {error}")
                            });
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("accept restart fixture connection: {error}"),
            }
        }
    });
    (format!("http://{address}"), stop_tx, handle, submit_count)
}

fn assert_storage_sentinels_absent(
    label: &str,
    synopsis: &BrowserStateSynopsis,
    receipt: &BrowserActionReceipt,
    sentinels: &[&str],
) {
    let receipt_bytes = receipt
        .to_bytes()
        .unwrap_or_else(|error| panic!("serialize {label} persistent receipt: {error}"));
    let receipt_text = String::from_utf8_lossy(&receipt_bytes);
    for sentinel in sentinels {
        for field in [
            synopsis.url.as_str(),
            synopsis.title.as_str(),
            synopsis.text.as_str(),
            synopsis.dom_excerpt.as_str(),
        ] {
            assert!(
                !field.contains(sentinel),
                "{label} synopsis leaked sentinel {sentinel}"
            );
        }
        assert!(
            !receipt_text.contains(sentinel),
            "{label} receipt leaked sentinel {sentinel}"
        );
    }
}

fn exact_authority() -> BrowserTaskAuthorityV1 {
    BrowserTaskAuthorityV1 {
        schema_version: 1,
        allowed_domains: BTreeSet::from([
            "example.com".to_owned(),
            "redirect.example.com".to_owned(),
            "127.0.0.1".to_owned(),
        ]),
        allowed_schemes: BTreeSet::from(["http".to_owned(), "https".to_owned()]),
        allowed_ports: BTreeSet::from([80, 443, 43_219]),
        allowed_methods: BTreeSet::from(["GET".to_owned(), "HEAD".to_owned()]),
        follow_redirects: true,
        max_redirects: 3,
        allow_task_loopback: true,
        max_tabs: 1,
        downloads_allowed: false,
        profile_mode: BrowserProfileMode::Isolated,
        download_root: None,
    }
}

#[test]
fn domain_scheme_redirect_and_loopback_authority_are_exact() {
    assert_eq!(
        authorize_top_level_browser_url("https://example.com/path")
            .unwrap_or_else(|error| panic!("https shape: {error}")),
        BrowserNavigationScheme::Https
    );
    for denied in [
        "file:///etc/passwd",
        "data:text/plain,secret",
        "chrome://settings",
        "javascript:alert(1)",
        "custom://example.com/path",
    ] {
        assert!(authorize_top_level_browser_url(denied).is_err(), "{denied}");
        assert!(browser_destination(denied).is_err(), "{denied}");
    }

    let authority = exact_authority();
    assert!(authority.permits_domain("EXAMPLE.COM"));
    assert!(!authority.permits_domain("sibling.example.com"));
    let policy = authority
        .public_network_policy()
        .unwrap_or_else(|error| panic!("public browser policy: {error}"));
    let primary = NetworkDestination {
        scheme: "https".to_owned(),
        host: "example.com".to_owned(),
        port: 443,
    };
    let public_ip = "93.184.216.34"
        .parse::<IpAddr>()
        .unwrap_or_else(|error| panic!("public IP fixture: {error}"));
    policy
        .authorize_resolved(&primary, [public_ip])
        .unwrap_or_else(|error| panic!("primary destination: {error}"));
    let redirect = NetworkDestination {
        host: "redirect.example.com".to_owned(),
        ..primary.clone()
    };
    policy
        .authorize_redirect(&redirect, [public_ip])
        .unwrap_or_else(|error| panic!("allowed redirect: {error}"));
    let denied_redirect = NetworkDestination {
        host: "other.example.com".to_owned(),
        ..primary
    };
    assert!(
        policy
            .authorize_redirect(&denied_redirect, [public_ip])
            .is_err()
    );

    let grant = TaskLoopbackGrantV1 {
        schema_version: TASK_LOOPBACK_GRANT_SCHEMA_VERSION,
        plan_id: "plan.browser.eval".to_owned(),
        plan_revision: 1,
        task_id: "task.browser.eval".to_owned(),
        task_contract_digest: sha256_binding(b"browser-task-contract"),
        resource_lease_id: "browser.resource.eval".to_owned(),
        execution_epoch: 7,
        scheme: "http".to_owned(),
        host: "127.0.0.1".to_owned(),
        port: 43_219,
        expires_at_ms: 10_000,
    };
    let scope = TaskLoopbackScope {
        plan_id: &grant.plan_id,
        plan_revision: grant.plan_revision,
        task_id: &grant.task_id,
        task_contract_digest: &grant.task_contract_digest,
        resource_lease_id: &grant.resource_lease_id,
        execution_epoch: grant.execution_epoch,
    };
    let loopback = NetworkDestination {
        scheme: "http".to_owned(),
        host: "127.0.0.1".to_owned(),
        port: 43_219,
    };
    assert!(policy.authorize_destination(&loopback).is_err());
    grant
        .authorize(&scope, &loopback, 9_999)
        .unwrap_or_else(|error| panic!("exact loopback grant: {error}"));
    let sibling_port = NetworkDestination {
        port: 43_220,
        ..loopback
    };
    assert!(grant.authorize(&scope, &sibling_port, 9_999).is_err());
}

#[test]
fn persistent_profile_requires_exact_explicit_grant() {
    let policy_digest = sha256_binding(b"browser-profile-policy");
    let policy = BrowserProfilePolicy::new("project.eval", "repo.eval", policy_digest.clone())
        .unwrap_or_else(|error| panic!("profile policy: {error}"));
    assert_eq!(
        policy
            .authorize(BrowserProfileMode::Isolated, None, None, 200)
            .unwrap_or_else(|error| panic!("isolated profile: {error}")),
        BrowserProfileAuthority::Isolated
    );
    assert!(
        policy
            .authorize(
                BrowserProfileMode::Persistent,
                Some("profile.eval"),
                None,
                200
            )
            .is_err()
    );
    let grant = PersistentBrowserProfileGrantV1 {
        schema_version: PERSISTENT_BROWSER_PROFILE_GRANT_SCHEMA_VERSION,
        grant_id: "grant.browser.eval".to_owned(),
        project_id: "project.eval".to_owned(),
        repository_id: "repo.eval".to_owned(),
        profile_id: "profile.eval".to_owned(),
        allowed_origins: BTreeSet::from(["https://example.com".to_owned()]),
        policy_digest,
        issued_at_ms: 100,
        expires_at_ms: 1_000,
    };
    assert_eq!(
        policy
            .authorize(
                BrowserProfileMode::Persistent,
                Some("profile.eval"),
                Some(&grant),
                200,
            )
            .unwrap_or_else(|error| panic!("persistent profile: {error}")),
        BrowserProfileAuthority::Persistent {
            grant_id: "grant.browser.eval".to_owned(),
            profile_id: "profile.eval".to_owned(),
        }
    );
    assert!(
        policy
            .authorize(
                BrowserProfileMode::Persistent,
                Some("profile.other"),
                Some(&grant),
                200,
            )
            .is_err()
    );
}

#[test]
fn download_root_and_sensitive_retention_are_fail_closed() {
    let temp = TestDir::new("downloads");
    let root = temp.0.join("downloads");
    fs::create_dir(&root).unwrap_or_else(|error| panic!("download root: {error}"));
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|error| panic!("chmod download root: {error}"));
    let root = root
        .canonicalize()
        .unwrap_or_else(|error| panic!("canonical download root: {error}"));
    let retention = BrowserDownloadRetentionPolicyV1 {
        max_file_bytes: 32,
        allowed_content_types: BTreeSet::from(["text/plain".to_owned()]),
    };
    let policy = BrowserDownloadPolicyV1 {
        schema_version: BROWSER_DOWNLOAD_POLICY_SCHEMA_VERSION,
        mode: BrowserDownloadMode::TaskScoped,
        root_authority: Some(BrowserDownloadRootAuthorityV1 {
            lease_id: "browser.eval.lease".to_owned(),
            execution_epoch: 7,
            root: root.clone(),
        }),
        retention: retention.clone(),
    };
    assert_eq!(
        policy
            .authorize_relative_path(Path::new("artifacts/result.txt"))
            .unwrap_or_else(|error| panic!("download relative path: {error}")),
        root.join("artifacts/result.txt")
    );
    assert!(
        policy
            .authorize_relative_path(Path::new("../escape"))
            .is_err()
    );
    retention
        .authorize(32, "text/plain", false)
        .unwrap_or_else(|error| panic!("retention boundary: {error}"));
    assert!(retention.authorize(33, "text/plain", false).is_err());
    assert!(retention.authorize(1, "text/plain", true).is_err());

    fs::write(root.join("result.txt"), b"bounded artifact")
        .unwrap_or_else(|error| panic!("download fixture: {error}"));
    let receipt = DownloadReceipt::from_confined_file(
        &browser_lease("download-eval-token"),
        &root,
        Path::new("result.txt"),
        "text/plain",
        32,
    )
    .unwrap_or_else(|error| panic!("download receipt: {error}"));
    assert!(!receipt.auto_opened_or_executed);
    assert!(receipt.sha256.starts_with("sha256:"));

    let sensitive = BrowserSensitivePageSignal {
        reasons: BTreeSet::from([
            BrowserSensitivePageReason::PasswordControl,
            BrowserSensitivePageReason::SensitiveAttribute,
        ]),
    };
    let synopsis = BrowserStateSynopsis {
        url: "https://example.com/login".to_owned(),
        title: String::new(),
        text: String::new(),
        dom_excerpt: String::new(),
        retained_text_bytes: 0,
        retained_dom_bytes: 0,
        text_truncated: false,
        dom_truncated: false,
        retained_dom_sha256: sha256_binding(b""),
        sensitive_page: sensitive,
    };
    assert!(synopsis.requires_visual_capture_suppression());
    assert!(
        synopsis
            .sensitive_page
            .contains(BrowserSensitivePageReason::PasswordControl)
    );
}

fn green_pressure(at_ms: i64) -> ResourcePressureSnapshotV1 {
    ResourcePressureSnapshotV1 {
        schema_version: 1,
        observed_at_ms: at_ms,
        controlled_working_set_mib: 512,
        host_headroom_mib: 6_000,
        swap_used_mib: None,
        swap_out_growth_mib_per_min: 0,
        compressor_growth_mib_per_min: 0,
        os_memory_pressure: OsMemoryPressure::Normal,
        recent_pressure_event: false,
        thermal_pressure: ThermalPressure::Normal,
        allocation_failure: false,
        repeated_resource_kill: false,
        uncontrolled_child_growth: false,
        host_free_disk_mib: Some(64 * 1_024),
    }
}

struct BrowserRecoveryFixture {
    temp: TestDir,
    registry: ProjectRegistry,
    state_path: PathBuf,
    task_id: String,
    plan_id: String,
    task_contract_digest: String,
    execution_epoch: i64,
    max_peak_rss_mib: u64,
    max_subprocesses: u32,
}

fn git_fixture(root: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .unwrap_or_else(|error| panic!("git {args:?}: {error}"));
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn compiler_response(content: String, input_tokens: u32) -> ModelResponse {
    ModelResponse {
        schema_version: MODEL_SCHEMA_VERSION,
        request_id: "browser-recovery-eval".to_owned(),
        content,
        structured: None,
        tool_calls: Vec::new(),
        finish_reason: ModelFinishReason::Stop,
        usage: ModelUsage {
            input_tokens: u64::from(input_tokens),
            output_tokens: 64,
        },
        elapsed_ms: 1,
        peak_rss_kb_during_call: None,
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "the governed recovery fixture is intentionally assembled in one explicit integration setup"
)]
fn controller_browser_recovery_fixture(max_network_bytes: u64) -> BrowserRecoveryFixture {
    const SOURCE: &str = "export const browserBudgetFixture = 'stable';\n";
    const WRITE_TOOL_DIGEST: &str =
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let temp = TestDir::new("controller-network-recovery");
    let repo = temp.0.join("repo");
    fs::create_dir(&repo).unwrap_or_else(|error| panic!("create recovery repo: {error}"));
    fs::write(repo.join("browser_budget.ts"), SOURCE)
        .unwrap_or_else(|error| panic!("write recovery source: {error}"));
    git_fixture(&repo, &["init", "-q"]);
    git_fixture(
        &repo,
        &["config", "user.email", "browser-eval@example.invalid"],
    );
    git_fixture(&repo, &["config", "user.name", "Browser Eval"]);
    git_fixture(&repo, &["add", "."]);
    git_fixture(&repo, &["commit", "-qm", "browser recovery fixture"]);

    let mut registry = ProjectRegistry::new();
    registry
        .register("repo.browser.eval", &repo)
        .unwrap_or_else(|error| panic!("register recovery repo: {error}"));
    let snapshot = registry
        .snapshot("repo.browser.eval")
        .unwrap_or_else(|error| panic!("snapshot recovery repo: {error}"));
    let exact = ExactRetriever::new(&registry)
        .read_path("repo.browser.eval", Path::new("browser_budget.ts"), None)
        .unwrap_or_else(|error| panic!("read recovery source: {error}"));
    let packet = ContextPlanner::default()
        .build(
            ContextMode::Implementation,
            ContextBudget::m1_8k(),
            ContextPacketInput {
                controller_prefix:
                    "Controller owns durable browser resource and budget accounting.".to_owned(),
                task_contract: "Keep the bounded browser budget fixture unchanged.".to_owned(),
                current_state: format!(
                    "repository=repo.browser.eval; dirty_digest={}",
                    snapshot.dirty_digest
                ),
                authorized_tool_schemas: Vec::new(),
                candidates: vec![EvidenceItem::from_exact_file(
                    &exact,
                    "exact browser budget recovery fixture",
                )],
                output_schema: "minimal-plan-proposal-v1".to_owned(),
            },
        )
        .unwrap_or_else(|error| panic!("build recovery context: {error}"));

    let role = RoleRegistry::canonical()
        .canonical_pin(RoleId::Implementer)
        .unwrap_or_else(|error| panic!("canonical implementer role: {error}"));
    let mut policy: Value = serde_json::from_str(include_str!("fixtures/scenario1/policy.json"))
        .unwrap_or_else(|error| panic!("parse browser recovery policy: {error}"));
    policy["capability_ceiling"]
        .as_array_mut()
        .unwrap_or_else(|| panic!("recovery capability ceiling must be an array"))
        .push(json!("external_intelligence"));
    policy["external_intelligence"]["allowed_providers"] =
        json!(["provider.browser-budget-fixture"]);
    policy["resources"]["heavy_leases"] = json!(["MODEL", "BROWSER"]);
    policy["resources"]["max_network_bytes"] = json!(max_network_bytes);
    let backend = DeterministicFakeBackend::new(
        ModelCapabilities {
            schema_version: MODEL_SCHEMA_VERSION,
            model_id: "fake-browser-recovery-model".to_owned(),
            parameter_class: "fixture".to_owned(),
            quantization: "fixture".to_owned(),
            max_context_tokens: 16_384,
            supports_tools: false,
            supports_json_schema: true,
            local: true,
        },
        vec![compiler_response(
            json!({
                "tasks": [{
                    "title": "Preserve browser budget fixture",
                    "objective": "Keep the exact browser budget fixture stable.",
                    "rationale": "The recovery regression needs one governed task budget.",
                    "files": ["browser_budget.ts"],
                    "symbols": ["browserBudgetFixture"],
                    "evidence_queries": [],
                    "expected_change": "No browser fixture behavior changes."
                }]
            })
            .to_string(),
            packet.metrics.final_serialized_input_tokens,
        )],
    )
    .unwrap_or_else(|error| panic!("construct recovery fake backend: {error}"));
    backend
        .load(ModelLoadProfile {
            context_tokens: 8_000,
            output_reserve_tokens: 1_024,
            startup_timeout_ms: 1_000,
            provider_call_timeout_ms: 1_000,
        })
        .unwrap_or_else(|error| panic!("load recovery fake backend: {error}"));
    let capability =
        |id: &str, digest: &str| json!({"id": id, "version": "1.0.0", "digest": digest});
    let input = PlanCompilationInput {
        schema_version: PLAN_COMPILATION_SCHEMA_VERSION,
        compilation_id: "compile.browser-recovery-eval".to_owned(),
        compiled_at: "2026-09-19T00:00:00Z".to_owned(),
        project_id: "project.browser-recovery-eval".to_owned(),
        project_name: "Browser recovery eval".to_owned(),
        workspace_roots: vec![snapshot.root.display().to_string()],
        goal_id: "goal.browser-recovery-eval".to_owned(),
        goal_statement: "Preserve the browser budget fixture.".to_owned(),
        goal_invariants: vec!["Browser accounting remains Controller-owned.".to_owned()],
        goal_non_goals: vec!["Do not change browser authority.".to_owned()],
        repository: PlanCompilationRepository {
            repository_id: snapshot.repository_id.clone(),
            root: snapshot.root.display().to_string(),
            head: snapshot.head.clone(),
            branch: snapshot.branch.clone(),
            dirty_digest: snapshot.dirty_digest.clone(),
            protected_changes_present: snapshot.protected_changes_present,
            languages: vec!["typescript".to_owned()],
        },
        policy,
        role: json!({"id": role.id, "version": role.version, "digest": role.digest}),
        skills: vec![capability(
            "skill.focused-edit",
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )],
        tools: vec![
            capability("tool.patch", WRITE_TOOL_DIGEST),
            capability(
                "tool.read",
                "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            ),
        ],
        write_tool_id: "tool.patch".to_owned(),
        read_tool_id: "tool.read".to_owned(),
        diff_evaluator: "builtin.diff.scope_and_literal.v1".to_owned(),
        rollback_diff_evaluator: "builtin.diff.controller_patch_absent.v1".to_owned(),
        context_packet: packet,
        m3: None,
        max_model_calls: 1,
        model_input_token_ceiling: 8_000,
        max_output_tokens: 512,
        model_deadline_ms: 1_000,
    };
    let validator = PlanValidator::new(ValidationEnvironment::default())
        .unwrap_or_else(|error| panic!("construct recovery validator: {error}"));
    let compiler = PlanCompiler::new(&backend, &validator, "browser-recovery-eval-v1")
        .unwrap_or_else(|error| panic!("construct recovery compiler: {error}"));
    let mut compiler_budget = ModelCallBudget::new(1, 1_000);
    let source_compilation = compiler
        .compile(&input, &mut compiler_budget)
        .unwrap_or_else(|error| panic!("compile recovery fixture: {error}"));
    let target_task_id = source_compilation.plan().as_value()["tasks"][0]["task_id"]
        .as_str()
        .unwrap_or_else(|| panic!("compiled recovery task id missing"))
        .to_owned();
    let compilation = source_compilation
        .bind_controller_external_intelligence(
            &validator,
            &target_task_id,
            "provider.browser-budget-fixture",
            &["source_slice".to_owned()],
            max_network_bytes,
        )
        .unwrap_or_else(|error| panic!("bind recovery task network budget: {error}"));
    backend
        .unload()
        .unwrap_or_else(|error| panic!("unload recovery fake backend: {error}"));

    let state_path = temp.0.join("state.sqlite3");
    let state = StateStore::open(&state_path)
        .unwrap_or_else(|error| panic!("open recovery state: {error}"));
    let mut controller = Controller::new(state);
    let activation = controller
        .activate(compilation, &registry)
        .unwrap_or_else(|error| panic!("activate recovery fixture: {error}"));
    let task_id = activation
        .task_ids
        .first()
        .cloned()
        .unwrap_or_else(|| panic!("recovery fixture activation omitted task"));
    let task_raw = controller
        .state()
        .get_state("controller.task", &task_id)
        .unwrap_or_else(|error| panic!("read recovery task runtime: {error}"))
        .unwrap_or_else(|| panic!("recovery task runtime missing"));
    let task: Value = serde_json::from_str(&task_raw)
        .unwrap_or_else(|error| panic!("decode recovery task runtime: {error}"));
    let active_raw = controller
        .state()
        .get_state("controller.plan", "active")
        .unwrap_or_else(|error| panic!("read recovery active plan: {error}"))
        .unwrap_or_else(|| panic!("recovery active plan missing"));
    let active: Value = serde_json::from_str(&active_raw)
        .unwrap_or_else(|error| panic!("decode recovery active plan: {error}"));
    let plan_id = active["plan_id"]
        .as_str()
        .unwrap_or_else(|| panic!("recovery plan id missing"))
        .to_owned();
    let task_contract_digest = task["task_contract_digest"]
        .as_str()
        .unwrap_or_else(|| panic!("recovery task contract digest missing"))
        .to_owned();
    let max_peak_rss_mib = task["task"]["resource_budget"]["max_peak_rss_mb"]
        .as_u64()
        .unwrap_or_else(|| panic!("recovery task max RSS missing"));
    let max_subprocesses = u32::try_from(
        task["task"]["resource_budget"]["max_subprocesses"]
            .as_u64()
            .unwrap_or_else(|| panic!("recovery task subprocess cap missing")),
    )
    .unwrap_or_else(|_| panic!("recovery task subprocess cap exceeds u32"));
    let execution_epoch = controller
        .state()
        .current_execution_epoch()
        .unwrap_or_else(|error| panic!("read recovery execution epoch: {error}"));
    drop(controller);
    BrowserRecoveryFixture {
        temp,
        registry,
        state_path,
        task_id,
        plan_id,
        task_contract_digest,
        execution_epoch,
        max_peak_rss_mib,
        max_subprocesses,
    }
}

fn resource_request(
    lease_id: &str,
    class: HeavyLeaseClass,
    plan_class: PlanHeavyLeaseClass,
) -> ResourceLeaseRequestV1 {
    ResourceLeaseRequestV1 {
        lease_id: lease_id.to_owned(),
        owner: ResourceLeaseOwnerV1 {
            plan_id: "plan.browser.resources".to_owned(),
            plan_revision: 1,
            task_id: format!("task.{lease_id}"),
        },
        class,
        calibrated: true,
        calibrated_p95_rss_mib: 512,
        evictable_idle_rss_mib: 0,
        task_budget: TaskResourceBudgetV1::new(5_500, 8, [plan_class]),
        conditional: ConditionalLeaseContextV1::default(),
        automatic_reload: false,
        disk_expanding: false,
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "the crash-state seed keeps one coherent durable browser recovery image explicit"
)]
fn seed_durable_browser_recovery_state(
    fixture: &BrowserRecoveryFixture,
    reserved_bytes: Option<u64>,
    residency_state: BrowserResourceResidencyStateV1,
) -> String {
    let lease_id = format!(
        "browser:{}:r1:{}:{}",
        fixture.plan_id, fixture.task_id, fixture.execution_epoch
    );
    let mut governor = M6ResourceGovernor::default();
    let pressure = governor.observe_pressure(green_pressure(1_000));
    let admission = governor.admit(
        &ResourceLeaseRequestV1 {
            lease_id: lease_id.clone(),
            owner: ResourceLeaseOwnerV1 {
                plan_id: fixture.plan_id.clone(),
                plan_revision: 1,
                task_id: fixture.task_id.clone(),
            },
            class: HeavyLeaseClass::CdpBrowser,
            calibrated: false,
            calibrated_p95_rss_mib: 1_536,
            evictable_idle_rss_mib: 0,
            task_budget: TaskResourceBudgetV1::new(
                fixture.max_peak_rss_mib,
                fixture.max_subprocesses,
                [PlanHeavyLeaseClass::Browser],
            ),
            conditional: ConditionalLeaseContextV1::default(),
            automatic_reload: false,
            disk_expanding: true,
        },
        &pressure,
    );
    assert_eq!(admission.status, AdmissionStatus::Admitted);
    let lease = admission
        .lease
        .unwrap_or_else(|| panic!("browser recovery admission omitted lease"));
    let governor_snapshot = governor.snapshot();
    let binding_digest = sha256_binding(b"browser-recovery-binding");
    let residency = BrowserResourceResidencyV1 {
        schema_version: 1,
        plan_id: fixture.plan_id.clone(),
        plan_revision: 1,
        task_id: fixture.task_id.clone(),
        task_contract_digest: fixture.task_contract_digest.clone(),
        execution_epoch: fixture.execution_epoch,
        policy_lease: lease.clone(),
        browser_lease_id: lease_id.clone(),
        browser_lease_binding_digest: binding_digest.clone(),
        loopback_capability: BrowserLoopbackCapabilityV1 {
            schema_version: BROWSER_LOOPBACK_CAPABILITY_SCHEMA_VERSION,
            lease_id: lease_id.clone(),
            execution_epoch: fixture.execution_epoch,
            localhost_port: 43_219,
            token_digest: sha256_binding(b"browser-recovery-loopback-token"),
            expires_at_ms: i64::MAX,
        },
        state: residency_state,
        process_group_id: None,
        process_group_leader_identity: None,
        private_parent: fixture.temp.0.clone(),
        profile_root: fixture.temp.0.join(".sovereign-browser-recovery-eval"),
        download_root: None,
        ephemeral_profile: true,
        updated_at_ms: 1,
    };
    let lease_json = serde_json::to_string(&lease)
        .unwrap_or_else(|error| panic!("encode recovery lease: {error}"));
    let governor_json = serde_json::to_string(&governor_snapshot)
        .unwrap_or_else(|error| panic!("encode recovery governor: {error}"));
    let residency_json = serde_json::to_string(&residency)
        .unwrap_or_else(|error| panic!("encode recovery residency: {error}"));
    let reservation_json = reserved_bytes.map(|bytes| {
        serde_json::to_string(&json!({
            "schema_version": 1,
            "plan_id": fixture.plan_id,
            "plan_revision": 1,
            "task_id": fixture.task_id,
            "task_contract_digest": fixture.task_contract_digest,
            "resource_lease_id": lease_id,
            "browser_lease_binding_digest": binding_digest,
            "execution_epoch": fixture.execution_epoch,
            "reserved_bytes": bytes,
            "state": "active",
            "settled_bytes": Value::Null,
            "settlement": Value::Null,
            "updated_at_ms": 1
        }))
        .unwrap_or_else(|error| panic!("encode recovery reservation: {error}"))
    });
    let mut post_images = BTreeMap::new();
    post_images.insert(
        format!("controller.resource_lease:{lease_id}"),
        sha256_binding(lease_json.as_bytes()),
    );
    post_images.insert(
        "controller.resource_governor:active".to_owned(),
        sha256_binding(governor_json.as_bytes()),
    );
    post_images.insert(
        "controller.resource_residency:cdp_browser".to_owned(),
        sha256_binding(residency_json.as_bytes()),
    );
    if let Some(reservation_json) = reservation_json.as_ref() {
        post_images.insert(
            format!("controller.browser_network_reservation:{lease_id}"),
            sha256_binding(reservation_json.as_bytes()),
        );
    }
    let event_payload = json!({
        "plan_id": fixture.plan_id,
        "plan_revision": 1,
        "post_image_digests": post_images,
    })
    .to_string();
    let mut state = StateStore::open(&fixture.state_path)
        .unwrap_or_else(|error| panic!("reopen recovery fixture state: {error}"));
    let mut updates = vec![
        StateRecordUpdate {
            namespace: "controller.resource_lease",
            key: &lease_id,
            value_json: &lease_json,
        },
        StateRecordUpdate {
            namespace: "controller.resource_governor",
            key: "active",
            value_json: &governor_json,
        },
        StateRecordUpdate {
            namespace: "controller.resource_residency",
            key: "cdp_browser",
            value_json: &residency_json,
        },
    ];
    if let Some(reservation_json) = reservation_json.as_ref() {
        updates.push(StateRecordUpdate {
            namespace: "controller.browser_network_reservation",
            key: &lease_id,
            value_json: reservation_json,
        });
    }
    state
        .put_state_records_with_events(
            &updates,
            &[NewJournalEvent {
                event_id: "eval.browser-network-recovery.crash-state",
                entity_type: "controller",
                entity_id: &fixture.task_id,
                event_kind: "resource_browser_recovery_fixture_seeded",
                payload_json: &event_payload,
            }],
        )
        .unwrap_or_else(|error| panic!("seed durable browser crash state: {error}"));
    lease_id
}

#[test]
fn controller_recovery_settles_active_browser_network_reservation_once_at_full_reserve() {
    const RESERVED_BYTES: u64 = 4_096;
    let fixture = controller_browser_recovery_fixture(RESERVED_BYTES);
    let lease_id = seed_durable_browser_recovery_state(
        &fixture,
        Some(RESERVED_BYTES),
        BrowserResourceResidencyStateV1::Absent,
    );

    let state = StateStore::open(&fixture.state_path)
        .unwrap_or_else(|error| panic!("open first recovery state: {error}"));
    let (recovered, _) = RecoveryManager::recover(state, &fixture.registry)
        .unwrap_or_else(|error| panic!("recover active browser reservation: {error}"));
    let reservation_raw = recovered
        .state()
        .get_state("controller.browser_network_reservation", &lease_id)
        .unwrap_or_else(|error| panic!("read settled browser reservation: {error}"))
        .unwrap_or_else(|| panic!("settled browser reservation disappeared"));
    let settled: Value = serde_json::from_str(&reservation_raw)
        .unwrap_or_else(|error| panic!("decode settled browser reservation: {error}"));
    assert_eq!(settled["state"], json!("settled"));
    assert_eq!(settled["settled_bytes"], json!(RESERVED_BYTES));
    assert_eq!(settled["settlement"], json!("recovery_full_reserve"));

    let charge_events = recovered
        .state()
        .journal()
        .unwrap_or_else(|error| panic!("read browser recovery journal: {error}"))
        .into_iter()
        .filter(|event| event.event_kind == "browser_network_budget_charged")
        .collect::<Vec<_>>();
    assert_eq!(charge_events.len(), 1);
    let charge: Value = serde_json::from_str(&charge_events[0].payload_json)
        .unwrap_or_else(|error| panic!("decode recovery browser charge: {error}"));
    assert_eq!(charge["bytes"], json!(RESERVED_BYTES));
    assert_eq!(charge["phase"], json!("recovery_full_reserve"));
    assert_eq!(
        charge["task_runtime"]["autonomy_budget"]["used_network_bytes"],
        json!(RESERVED_BYTES)
    );
    assert_eq!(
        charge["goal_autonomy_budget"]["used_network_bytes"],
        json!(RESERVED_BYTES)
    );
    drop(recovered);

    let state = StateStore::open(&fixture.state_path)
        .unwrap_or_else(|error| panic!("open second recovery state: {error}"));
    let (recovered_again, _) = RecoveryManager::recover(state, &fixture.registry)
        .unwrap_or_else(|error| panic!("recover settled browser reservation again: {error}"));
    let repeated_charges = recovered_again
        .state()
        .journal()
        .unwrap_or_else(|error| panic!("read second browser recovery journal: {error}"))
        .into_iter()
        .filter(|event| event.event_kind == "browser_network_budget_charged")
        .count();
    assert_eq!(
        repeated_charges, 1,
        "a settled recovery reservation must never be charged twice"
    );
    let task_raw = recovered_again
        .state()
        .get_state("controller.task", &fixture.task_id)
        .unwrap_or_else(|error| panic!("read task after second recovery: {error}"))
        .unwrap_or_else(|| panic!("task missing after second recovery"));
    let task: Value = serde_json::from_str(&task_raw)
        .unwrap_or_else(|error| panic!("decode task after second recovery: {error}"));
    assert_eq!(
        task["autonomy_budget"]["used_network_bytes"],
        json!(RESERVED_BYTES)
    );
}

#[test]
fn controller_recovery_refuses_post_admission_browser_state_without_network_reservation() {
    const NETWORK_BUDGET: u64 = 4_096;
    let fixture = controller_browser_recovery_fixture(NETWORK_BUDGET);
    let lease_id = seed_durable_browser_recovery_state(
        &fixture,
        None,
        BrowserResourceResidencyStateV1::Reserved,
    );
    let epoch_before = StateStore::open(&fixture.state_path)
        .unwrap_or_else(|error| panic!("open pre-recovery state: {error}"))
        .current_execution_epoch()
        .unwrap_or_else(|error| panic!("read pre-recovery epoch: {error}"));

    let state = StateStore::open(&fixture.state_path)
        .unwrap_or_else(|error| panic!("open missing-reservation recovery state: {error}"));
    let Err(error) = RecoveryManager::recover(state, &fixture.registry) else {
        panic!("recovery must not invent a browser network reservation after admission");
    };
    assert!(
        error
            .to_string()
            .contains("neither a durable network reservation nor a legacy full-reservation charge"),
        "unexpected missing-reservation recovery error: {error}"
    );

    let state = StateStore::open(&fixture.state_path)
        .unwrap_or_else(|error| panic!("reopen rejected recovery state: {error}"));
    assert!(
        state
            .get_state("controller.browser_network_reservation", &lease_id)
            .unwrap_or_else(|error| panic!("read missing reservation slot: {error}"))
            .is_none(),
        "recovery must not synthesize a network reservation"
    );
    assert_eq!(
        state
            .journal()
            .unwrap_or_else(|error| panic!("read rejected recovery journal: {error}"))
            .into_iter()
            .filter(|event| event.event_kind == "browser_network_budget_charged")
            .count(),
        0,
        "missing reservation must not be converted into a synthetic network charge"
    );
    let task_raw = state
        .get_state("controller.task", &fixture.task_id)
        .unwrap_or_else(|error| panic!("read task after rejected recovery: {error}"))
        .unwrap_or_else(|| panic!("task disappeared after rejected recovery"));
    let task: Value = serde_json::from_str(&task_raw)
        .unwrap_or_else(|error| panic!("decode task after rejected recovery: {error}"));
    assert_eq!(task["autonomy_budget"]["used_network_bytes"], json!(0));
    assert_eq!(
        state
            .current_execution_epoch()
            .unwrap_or_else(|error| panic!("read rejected recovery epoch: {error}")),
        epoch_before,
        "failed recovery must not advance the execution epoch"
    );
    let residency_raw = state
        .get_state("controller.resource_residency", "cdp_browser")
        .unwrap_or_else(|error| panic!("read rejected browser residency: {error}"))
        .unwrap_or_else(|| panic!("browser residency disappeared after rejected recovery"));
    let residency: BrowserResourceResidencyV1 = serde_json::from_str(&residency_raw)
        .unwrap_or_else(|error| panic!("decode rejected browser residency: {error}"));
    assert_eq!(residency.state, BrowserResourceResidencyStateV1::Reserved);
}

#[test]
fn browser_build_and_embedder_are_serialized_and_release_clears_logical_residency() {
    let mut governor = M6ResourceGovernor::default();
    let pressure = governor.observe_pressure(green_pressure(0));
    let browser = resource_request(
        "browser",
        HeavyLeaseClass::CdpBrowser,
        PlanHeavyLeaseClass::Browser,
    );
    assert_eq!(
        governor.admit(&browser, &pressure).status,
        AdmissionStatus::Admitted
    );
    let build = resource_request(
        "build",
        HeavyLeaseClass::BuildHeavy,
        PlanHeavyLeaseClass::BuildHeavy,
    );
    let embedder = resource_request(
        "embedder",
        HeavyLeaseClass::Embedder,
        PlanHeavyLeaseClass::Embedder,
    );
    assert_eq!(
        governor.admit(&build, &pressure).status,
        AdmissionStatus::Serialize
    );
    assert_eq!(
        governor.admit(&embedder, &pressure).status,
        AdmissionStatus::Serialize
    );
    assert_eq!(governor.active_leases().count(), 1);
    assert!(governor.release("browser").is_some());
    assert_eq!(governor.active_leases().count(), 0);
    assert_eq!(
        governor.admit(&build, &pressure).status,
        AdmissionStatus::Admitted
    );
}

fn process_group_exists(process_group_id: u32) -> bool {
    Command::new("/bin/kill")
        .arg("-0")
        .arg(format!("-{process_group_id}"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn process_group_rss_kib(process_group_id: u32) -> u64 {
    let output = Command::new("/bin/ps")
        .args(["-axo", "pgid=,rss="])
        .output()
        .unwrap_or_else(|error| panic!("sample browser process group RSS: {error}"));
    assert!(
        output.status.success(),
        "ps failed while sampling browser RSS"
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let pgid = fields.next()?.parse::<u32>().ok()?;
            let rss_kib = fields.next()?.parse::<u64>().ok()?;
            (pgid == process_group_id).then_some(rss_kib)
        })
        .sum()
}

#[test]
fn browser_is_demand_loaded_and_zero_resident_after_shutdown() {
    let temp = TestDir::new("zero-resident");
    let lease = browser_lease("zero-resident-token");
    let Some(adapter) = spawn_browser(&temp.0, &lease) else {
        return;
    };
    let process_group_id = adapter.process_group_id();
    let profile = adapter.profile_root().to_path_buf();
    assert!(process_group_exists(process_group_id));
    assert!(profile.is_dir());
    adapter
        .shutdown()
        .unwrap_or_else(|error| panic!("browser shutdown: {error}"));
    assert!(!process_group_exists(process_group_id));
    assert!(!profile.exists());
}

#[test]
fn browser_arm64_one_tab_resource_measurement_and_zero_resident() {
    let architecture = Command::new("/usr/bin/uname")
        .arg("-m")
        .output()
        .unwrap_or_else(|error| panic!("read host architecture: {error}"));
    assert!(architecture.status.success(), "uname -m failed");
    if String::from_utf8_lossy(&architecture.stdout).trim() != "arm64" {
        return;
    }
    let Some(chrome) = chrome_path() else {
        return;
    };
    let chrome_version = Command::new(chrome)
        .arg("--version")
        .output()
        .unwrap_or_else(|error| panic!("read Chrome version: {error}"));
    assert!(chrome_version.status.success(), "Chrome --version failed");

    let mut governor = M6ResourceGovernor::default();
    let pressure = governor.observe_pressure(green_pressure(0));
    let mut browser_request = resource_request(
        "browser-arm64-measured",
        HeavyLeaseClass::CdpBrowser,
        PlanHeavyLeaseClass::Browser,
    );
    browser_request.calibrated = false;
    browser_request.calibrated_p95_rss_mib = 1_536;
    assert_eq!(
        governor.admit(&browser_request, &pressure).status,
        AdmissionStatus::Admitted
    );
    assert_eq!(governor.active_leases().count(), 1);

    let temp = TestDir::new("arm64-resource-measurement");
    let lease = browser_lease("arm64-resource-measurement-token");
    let Some(mut adapter) = spawn_browser(&temp.0, &lease) else {
        return;
    };
    let process_group_id = adapter.process_group_id();
    let process_group_identity = adapter.process_group_identity().to_owned();
    let profile = adapter.profile_root().to_path_buf();
    assert!(process_group_exists(process_group_id));

    let mut samples_kib = Vec::with_capacity(17);
    samples_kib.push(process_group_rss_kib(process_group_id));
    for index in 0..16 {
        let receipt = adapter
            .execute(
                &lease,
                &BrowserAction::CaptureSynopsis {
                    action_id: format!("arm64-resource-synopsis-{index}"),
                },
            )
            .unwrap_or_else(|error| panic!("deterministic one-tab synopsis {index}: {error}"));
        assert_eq!(
            receipt.effect,
            sovereign_tools::browser::BrowserActionEffect::Observation
        );
        assert_eq!(
            receipt
                .synopsis
                .as_ref()
                .unwrap_or_else(|| panic!("resource synopsis omitted state"))
                .url,
            "about:blank"
        );
        samples_kib.push(process_group_rss_kib(process_group_id));
        thread::sleep(Duration::from_millis(25));
    }
    assert!(samples_kib.iter().all(|sample| *sample > 0));
    samples_kib.sort_unstable();
    let p95_index = (samples_kib.len() * 95).div_ceil(100).saturating_sub(1);
    let p95_rss_kib = samples_kib[p95_index];
    let peak_rss_kib = *samples_kib
        .last()
        .unwrap_or_else(|| panic!("browser RSS sample set unexpectedly empty"));

    eprintln!(
        "M7_T03_BROWSER_ARM64_RESOURCE_PROOF architecture=arm64 chrome_version={} process_group_id={} process_group_identity={} samples={} p95_rss_kib={} peak_rss_kib={} one_tab=true production_calibrated=false",
        String::from_utf8_lossy(&chrome_version.stdout).trim(),
        process_group_id,
        process_group_identity,
        samples_kib.len(),
        p95_rss_kib,
        peak_rss_kib,
    );

    adapter
        .shutdown()
        .unwrap_or_else(|error| panic!("browser shutdown after arm64 measurement: {error}"));
    assert!(!process_group_exists(process_group_id));
    assert!(!profile.exists());
    assert!(governor.release("browser-arm64-measured").is_some());
    assert_eq!(governor.active_leases().count(), 0);
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the transport-uncertainty regression keeps the kill, no-replay, and fresh-lease proof together"
)]
fn transport_uncertainty_cleanup_and_fresh_lease_restart_never_replays_submit() {
    if chrome_path().is_none() {
        return;
    }
    let temp = TestDir::new("unknown-no-resubmit");
    let (origin, stop_tx, server, submit_count) = spawn_restart_server();
    let lease = browser_lease("unknown-no-resubmit-token");
    let Some(mut adapter) = spawn_browser(&temp.0, &lease) else {
        let _ = stop_tx.send(());
        let _ = server.join();
        return;
    };
    navigate_local(
        &mut adapter,
        &lease,
        "unknown-submit-form-navigation",
        &format!("{origin}/form"),
    );

    let payload_digest = format!("sha256:{}", "a".repeat(64));
    let approved_form = adapter
        .inspect_form(&lease, "form#danger", &payload_digest)
        .unwrap_or_else(|error| panic!("inspect restart form: {error}"));
    let ambiguous_submit = BrowserAction::SubmitForm {
        action_id: "ambiguous-submit".to_owned(),
        selector: "form#danger".to_owned(),
        payload_digest,
    };
    let dispatched = adapter
        .dispatch_intercepted_action(&lease, &ambiguous_submit, Some(&approved_form))
        .unwrap_or_else(|error| panic!("dispatch restart submit: {error}"));
    assert!(dispatched.effect.is_side_effectful());
    assert_eq!(dispatched.action_id, ambiguous_submit.action_id());

    let submit_request = adapter
        .next_document_request(&lease, 15_000)
        .unwrap_or_else(|error| panic!("observe restart submit request: {error}"));
    assert_eq!(submit_request.method, "POST");
    assert_eq!(submit_request.url, format!("{origin}/submitted"));
    adapter
        .resolve_document_request(
            &lease,
            &submit_request,
            BrowserDocumentRequestDecision::Continue,
        )
        .unwrap_or_else(|error| panic!("continue restart submit request: {error}"));

    let submit_deadline = Instant::now() + Duration::from_secs(2);
    while submit_count.load(Ordering::SeqCst) == 0 && Instant::now() < submit_deadline {
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        submit_count.load(Ordering::SeqCst),
        1,
        "the fixture must observe the consequential submit before the browser is killed"
    );

    let killed_group = adapter.process_group_id();
    let killed_profile = adapter.profile_root().to_path_buf();
    let status = Command::new("/bin/kill")
        .arg("-KILL")
        .arg(format!("-{killed_group}"))
        .status()
        .unwrap_or_else(|error| panic!("kill browser group: {error}"));
    assert!(status.success());
    thread::sleep(Duration::from_millis(50));

    let Err(uncertain) = adapter.finish_dispatched_action(&lease) else {
        panic!("killed browser unexpectedly completed the ambiguous submit");
    };
    assert!(uncertain.is_transport_uncertain(), "{uncertain}");
    let submit_count_after_uncertainty = submit_count.load(Ordering::SeqCst);
    assert_eq!(submit_count_after_uncertainty, 1);

    let Err(replay) =
        adapter.dispatch_intercepted_action(&lease, &ambiguous_submit, Some(&approved_form))
    else {
        panic!("poisoned session unexpectedly re-dispatched the ambiguous submit");
    };
    match replay {
        BrowserError::InvalidRequest(message) => assert!(
            message.contains("another browser action is already dispatched"),
            "unexpected poisoned-session replay refusal: {message}"
        ),
        other => panic!("expected deterministic no-replay refusal, got {other}"),
    }
    assert_eq!(
        submit_count.load(Ordering::SeqCst),
        submit_count_after_uncertainty,
        "the poisoned session must not emit the consequential request again"
    );

    adapter
        .shutdown()
        .unwrap_or_else(|error| panic!("shutdown killed browser after uncertainty: {error}"));
    assert!(!process_group_exists(killed_group));
    assert!(!killed_profile.exists());

    let mut fresh_lease = browser_lease("restart-fresh-token");
    fresh_lease.lease_id = "browser.eval.lease.restart".to_owned();
    assert_eq!(fresh_lease.task_id, lease.task_id);
    assert_eq!(fresh_lease.attempt_id, lease.attempt_id);
    assert_eq!(fresh_lease.execution_epoch, lease.execution_epoch);
    assert_ne!(fresh_lease.lease_id, lease.lease_id);
    assert_ne!(fresh_lease.binding_digest(), lease.binding_digest());

    let Some(mut fresh_adapter) = spawn_browser(&temp.0, &fresh_lease) else {
        let _ = stop_tx.send(());
        let _ = server.join();
        return;
    };
    let recovered_url = format!("{origin}/recovered");
    navigate_local(
        &mut fresh_adapter,
        &fresh_lease,
        "fresh-session-navigation",
        &recovered_url,
    );
    let recovery_deadline = Instant::now() + Duration::from_secs(2);
    let mut capture_attempt = 0_u32;
    let synopsis = loop {
        let recovered = fresh_adapter
            .execute(
                &fresh_lease,
                &BrowserAction::CaptureSynopsis {
                    action_id: format!("fresh-session-synopsis-{capture_attempt}"),
                },
            )
            .unwrap_or_else(|error| panic!("capture fresh-session synopsis: {error}"));
        let synopsis = recovered
            .synopsis
            .unwrap_or_else(|| panic!("fresh-session capture omitted synopsis"));
        if synopsis.url == recovered_url
            && synopsis.title == "restart-recovered"
            && synopsis.text.contains("fresh-run-ok")
        {
            break synopsis;
        }
        assert!(
            Instant::now() < recovery_deadline,
            "fresh session never exposed recovered bounded state: {synopsis:?}"
        );
        capture_attempt = capture_attempt.saturating_add(1);
        thread::sleep(Duration::from_millis(25));
    };
    assert_eq!(synopsis.url, recovered_url);
    assert_eq!(synopsis.title, "restart-recovered");
    assert!(synopsis.text.contains("fresh-run-ok"));
    assert!(!synopsis.text_truncated);
    assert!(!synopsis.dom_truncated);
    assert_eq!(
        submit_count.load(Ordering::SeqCst),
        submit_count_after_uncertainty,
        "fresh lease/session startup and bounded observation must not replay the old submit"
    );

    let fresh_group = fresh_adapter.process_group_id();
    let fresh_profile = fresh_adapter.profile_root().to_path_buf();
    fresh_adapter
        .shutdown()
        .unwrap_or_else(|error| panic!("shutdown fresh browser: {error}"));
    assert!(!process_group_exists(fresh_group));
    assert!(!fresh_profile.exists());
    let _ = stop_tx.send(());
    server
        .join()
        .unwrap_or_else(|_| panic!("restart fixture server panicked"));
}

#[test]
fn persistent_profile_unrelated_storage_never_leaks_into_browser_evidence() {
    if chrome_path().is_none() {
        return;
    }
    let temp = TestDir::new("persistent-storage-non-leak");
    let profile = temp.0.join("persistent-profile");
    fs::create_dir(&profile).unwrap_or_else(|error| panic!("persistent profile: {error}"));
    fs::set_permissions(&profile, fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|error| panic!("chmod persistent profile: {error}"));
    let (origin, stop_tx, server) = spawn_storage_server();
    let sentinels = [
        "cookie-sentinel-72f6",
        "local-sentinel-4c31",
        "session-old-sentinel-9a82",
        "session-new-sentinel-d105",
    ];

    let first_lease = browser_lease("persistent-storage-token-1");
    let Some(mut first) = spawn_persistent_browser(&temp.0, &profile, &first_lease) else {
        let _ = stop_tx.send(());
        let _ = server.join();
        return;
    };
    navigate_local(
        &mut first,
        &first_lease,
        "persistent-storage-seed",
        &format!("{origin}/seed"),
    );
    let first_receipt = first
        .execute(
            &first_lease,
            &BrowserAction::CaptureSynopsis {
                action_id: "persistent-storage-seed-synopsis".to_owned(),
            },
        )
        .unwrap_or_else(|error| panic!("capture seeded persistent synopsis: {error}"));
    let first_synopsis = first_receipt
        .synopsis
        .as_ref()
        .unwrap_or_else(|| panic!("seeded persistent synopsis omitted state"));
    assert_eq!(first_synopsis.title, "storage-seeded");
    assert_storage_sentinels_absent("seeded", first_synopsis, &first_receipt, &sentinels);
    first
        .shutdown()
        .unwrap_or_else(|error| panic!("shutdown first persistent browser: {error}"));
    assert!(
        profile.is_dir(),
        "caller-owned persistent profile must survive shutdown"
    );

    let second_lease = browser_lease("persistent-storage-token-2");
    let Some(mut second) = spawn_persistent_browser(&temp.0, &profile, &second_lease) else {
        let _ = stop_tx.send(());
        let _ = server.join();
        return;
    };
    navigate_local(
        &mut second,
        &second_lease,
        "persistent-storage-check",
        &format!("{origin}/check"),
    );
    let second_receipt = second
        .execute(
            &second_lease,
            &BrowserAction::CaptureSynopsis {
                action_id: "persistent-storage-check-synopsis".to_owned(),
            },
        )
        .unwrap_or_else(|error| panic!("capture checked persistent synopsis: {error}"));
    let second_synopsis = second_receipt
        .synopsis
        .as_ref()
        .unwrap_or_else(|| panic!("checked persistent synopsis omitted state"));
    assert_eq!(second_synopsis.title, "storage-persisted");
    assert_storage_sentinels_absent("reloaded", second_synopsis, &second_receipt, &sentinels);
    second
        .shutdown()
        .unwrap_or_else(|error| panic!("shutdown second persistent browser: {error}"));
    assert!(
        profile.is_dir(),
        "persistent profile must remain caller-owned"
    );

    let _ = stop_tx.send(());
    server
        .join()
        .unwrap_or_else(|_| panic!("storage fixture server panicked"));
}

#[test]
fn persistent_profile_mechanics_do_not_delete_caller_owned_root() {
    let Some(chrome) = chrome_path() else {
        return;
    };
    let temp = TestDir::new("persistent-mechanics");
    let profile = temp.0.join("profile");
    fs::create_dir(&profile).unwrap_or_else(|error| panic!("persistent profile: {error}"));
    fs::set_permissions(&profile, fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|error| panic!("chmod persistent profile: {error}"));
    let prepared = BrowserAdapter::prepare_launch(
        chrome,
        &temp.0,
        &browser_lease("persistent-mechanics-token"),
        BrowserAdapterConfig::default(),
        BrowserLaunchOptions {
            profile_root: BrowserProfileRoot::CallerOwnedPersistent(profile.clone()),
            ..BrowserLaunchOptions::default()
        },
    )
    .unwrap_or_else(|error| panic!("prepare persistent mechanics: {error}"));
    assert!(prepared.profile_is_persistent());
    drop(prepared);
    assert!(profile.is_dir());
}
