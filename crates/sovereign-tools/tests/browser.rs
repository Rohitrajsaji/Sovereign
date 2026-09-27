#![forbid(unsafe_code)]

use sovereign_policy::IsolatedCommand;
use sovereign_tools::browser::{
    BROWSER_PROXY_AUTH_REALM, BROWSER_PROXY_AUTH_USERNAME, BROWSER_SCHEMA_VERSION, BrowserAction,
    BrowserActionEffect, BrowserActionReceipt, BrowserAdapter, BrowserAdapterConfig,
    BrowserDocumentRequestDecision, BrowserDownloadPolicy, BrowserLaunchOptions, BrowserLease,
    BrowserProfileRoot, BrowserProxyAuthBinding, BrowserSpawnState, DownloadReceipt,
};
use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

static TEST_NONCE: AtomicU64 = AtomicU64::new(1);

fn lease(token: &str) -> BrowserLease {
    BrowserLease {
        schema_version: BROWSER_SCHEMA_VERSION,
        lease_id: "browser-lease-test".to_owned(),
        task_id: "M7-T03".to_owned(),
        attempt_id: "attempt-browser-test".to_owned(),
        execution_epoch: 7,
        token: token.to_owned(),
    }
}

fn private_test_root(label: &str) -> PathBuf {
    let nonce = TEST_NONCE.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "sovereign-browser-test-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&path).unwrap_or_else(|error| panic!("create test root failed: {error}"));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|error| panic!("chmod test root failed: {error}"));
    path
}

fn remove_test_root(path: &Path) {
    match fs::remove_dir_all(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => panic!("test root cleanup failed: {error}"),
    }
}

fn wrapped_adapter(
    chrome: &Path,
    root: &Path,
    browser_lease: &BrowserLease,
    options: BrowserLaunchOptions,
) -> BrowserAdapter {
    wrapped_adapter_with_config(
        chrome,
        root,
        browser_lease,
        BrowserAdapterConfig::default(),
        options,
    )
}

fn wrapped_adapter_with_config(
    chrome: &Path,
    root: &Path,
    browser_lease: &BrowserLease,
    config: BrowserAdapterConfig,
    options: BrowserLaunchOptions,
) -> BrowserAdapter {
    let prepared = BrowserAdapter::prepare_launch(chrome, root, browser_lease, config, options)
        .unwrap_or_else(|error| panic!("Chrome pipe prepare failed: {error}"));
    let mut wrapped_args = vec![prepared.process_spec().executable.display().to_string()];
    wrapped_args.extend(prepared.process_spec().args.iter().cloned());
    let wrapped = IsolatedCommand {
        executable: PathBuf::from("/usr/bin/env"),
        args: wrapped_args,
    };
    BrowserAdapter::spawn_preisolated(prepared, &wrapped)
        .unwrap_or_else(|error| panic!("Chrome wrapped pipe launch failed: {error}"))
}

fn spawn_loopback_response_server(
    expected_path: &'static str,
    extra_headers: &'static str,
    body: &'static [u8],
) -> (std::net::SocketAddr, thread::JoinHandle<String>) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .unwrap_or_else(|error| panic!("bind loopback browser fixture failed: {error}"));
    listener
        .set_nonblocking(true)
        .unwrap_or_else(|error| panic!("set loopback fixture listener nonblocking: {error}"));
    let address = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("read loopback fixture address failed: {error}"));
    let handle = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            let (mut stream, _) = match listener.accept() {
                Ok(accepted) => accepted,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(error) => panic!("accept loopback browser request failed: {error}"),
            };
            stream
                .set_nonblocking(false)
                .unwrap_or_else(|error| panic!("set loopback fixture stream blocking: {error}"));
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap_or_else(|error| {
                    panic!("set loopback fixture read timeout failed: {error}")
                });
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
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) =>
                    {
                        break;
                    }
                    Err(error) => panic!("read loopback browser request failed: {error}"),
                }
            }
            let request = String::from_utf8_lossy(&request).into_owned();
            let expected_prefix = format!("GET {expected_path} ");
            if !request.starts_with(&expected_prefix) {
                continue;
            }
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n{extra_headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream
                .write_all(headers.as_bytes())
                .and_then(|()| stream.write_all(body))
                .and_then(|()| stream.flush())
                .unwrap_or_else(|error| panic!("write loopback browser response failed: {error}"));
            return request;
        }
        panic!("loopback browser fixture never received GET {expected_path}");
    });
    (address, handle)
}

fn spawn_browser_containment_server() -> (std::net::SocketAddr, thread::JoinHandle<Vec<String>>) {
    const FIXTURE_BODY: &[u8] = br#"<!doctype html><title>containment</title><script>
fetch('/safe-get').catch(() => {});
fetch('/safe-head', {method:'HEAD'}).catch(() => {});
fetch('/blocked-post', {method:'POST', body:'page-write'}).catch(() => {});
const workerSource = "fetch('/worker-get').catch(() => {}); fetch('/worker-post', {method:'POST', body:'worker-write'}).catch(() => {});";
const workerUrl = URL.createObjectURL(new Blob([workerSource], {type:'text/javascript'}));
new Worker(workerUrl);
</script>"#;
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .unwrap_or_else(|error| panic!("bind containment fixture failed: {error}"));
    listener
        .set_nonblocking(true)
        .unwrap_or_else(|error| panic!("set containment listener nonblocking failed: {error}"));
    let address = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("read containment fixture address failed: {error}"));
    let handle = thread::spawn(move || {
        let hard_deadline = Instant::now() + Duration::from_secs(15);
        let mut settle_deadline = None;
        let mut observed = Vec::new();
        while Instant::now() < hard_deadline
            && settle_deadline.is_none_or(|deadline| Instant::now() < deadline)
        {
            let (mut stream, _) = match listener.accept() {
                Ok(accepted) => accepted,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(error) => panic!("accept containment request failed: {error}"),
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap_or_else(|error| panic!("set containment read timeout failed: {error}"));
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
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) =>
                    {
                        break;
                    }
                    Err(error) => panic!("read containment request failed: {error}"),
                }
            }
            let request = String::from_utf8_lossy(&request);
            let Some(first_line) = request.lines().next().filter(|line| !line.is_empty()) else {
                continue;
            };
            observed.push(first_line.to_owned());
            let is_fixture = first_line.starts_with("GET /fixture ");
            let is_head = first_line.starts_with("HEAD ");
            let body = if is_fixture { FIXTURE_BODY } else { b"" };
            let status = if is_fixture {
                "HTTP/1.1 200 OK"
            } else {
                "HTTP/1.1 204 No Content"
            };
            let headers = format!(
                "{status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream
                .write_all(headers.as_bytes())
                .and_then(|()| {
                    if is_head {
                        Ok(())
                    } else {
                        stream.write_all(body)
                    }
                })
                .and_then(|()| stream.flush())
                .unwrap_or_else(|error| panic!("write containment response failed: {error}"));
            let safe_get = observed
                .iter()
                .any(|line| line.starts_with("GET /safe-get "));
            let safe_head = observed
                .iter()
                .any(|line| line.starts_with("HEAD /safe-head "));
            if safe_get && safe_head && settle_deadline.is_none() {
                settle_deadline = Some(Instant::now() + Duration::from_millis(750));
            }
        }
        observed
    });
    (address, handle)
}

fn navigate_intercepted(
    adapter: &mut BrowserAdapter,
    browser_lease: &BrowserLease,
    action_id: &str,
    url: &str,
) {
    let action = BrowserAction::Navigate {
        action_id: action_id.to_owned(),
        url: url.to_owned(),
    };
    adapter
        .dispatch_intercepted_action(browser_lease, &action, None)
        .unwrap_or_else(|error| panic!("dispatch intercepted navigation failed: {error}"));
    let observation = adapter
        .next_document_request(browser_lease, 15_000)
        .unwrap_or_else(|error| panic!("observe intercepted navigation request failed: {error}"));
    assert_eq!(observation.url, url);
    assert_eq!(observation.method, "GET");
    assert_eq!(observation.chain_index, 0);
    adapter
        .resolve_document_request(
            browser_lease,
            &observation,
            BrowserDocumentRequestDecision::Continue,
        )
        .unwrap_or_else(|error| panic!("continue intercepted navigation request failed: {error}"));
    adapter
        .finish_dispatched_action(browser_lease)
        .unwrap_or_else(|error| panic!("finish intercepted navigation failed: {error}"));
}

fn assert_bounded_png_screenshot(receipt: &BrowserActionReceipt, screenshot_bound: usize) {
    assert_eq!(receipt.effect, BrowserActionEffect::Observation);
    assert!(!receipt.screenshots_and_traces_suppressed);
    let synopsis = receipt
        .synopsis
        .as_ref()
        .unwrap_or_else(|| panic!("safe screenshot receipt omitted pre-capture synopsis"));
    assert!(!synopsis.sensitive_page.is_sensitive());
    let screenshot = receipt
        .screenshot
        .as_ref()
        .unwrap_or_else(|| panic!("safe screenshot receipt omitted PNG"));
    assert_eq!(screenshot.content_type, "image/png");
    assert_eq!(screenshot.encoding, "base64");
    assert!(screenshot.png_bytes > 0);
    assert!(screenshot.retained_base64_bytes > screenshot.png_bytes);
    assert!(screenshot.retained_base64_bytes <= screenshot_bound);
    assert_eq!(
        screenshot.retained_base64_bytes,
        screenshot.png_base64.len()
    );
    assert!(screenshot.png_base64.starts_with("iVBORw0KGgo"));
}

#[test]
fn action_shape_allows_http_https_without_destination_authorization() {
    let public = BrowserAction::Navigate {
        action_id: "nav-public".to_owned(),
        url: "https://example.com:8443/path?q=1".to_owned(),
    };
    let loopback = BrowserAction::Navigate {
        action_id: "nav-loopback".to_owned(),
        url: "http://127.0.0.1:49152/health".to_owned(),
    };
    let ipv6 = BrowserAction::Navigate {
        action_id: "nav-ipv6".to_owned(),
        url: "https://[::1]:8443/health".to_owned(),
    };
    assert!(public.validate_shape().is_ok());
    assert!(loopback.validate_shape().is_ok());
    assert!(ipv6.validate_shape().is_ok());
    assert_eq!(public.effect(), BrowserActionEffect::Navigation);

    for url in [
        "file:///etc/passwd",
        "javascript:alert(1)",
        "ftp://example.com/file",
        "https://user@example.com/",
        "https://",
        "https://example.com/a b",
        "https://example.com:abc/path",
        "https://example.com:99999/path",
        "https://example.com:0/path",
        "https://2001:db8::1/path",
        "https://[::1/path",
        "https://[nope]:443/path",
    ] {
        let action = BrowserAction::Navigate {
            action_id: "bad".to_owned(),
            url: url.to_owned(),
        };
        assert!(
            action.validate_shape().is_err(),
            "unexpectedly accepted {url}"
        );
    }
}

#[test]
fn form_submit_is_explicitly_consequential_and_digest_bound() {
    let submit = BrowserAction::SubmitForm {
        action_id: "submit-login".to_owned(),
        selector: "form#login".to_owned(),
        payload_digest: format!("sha256:{}", "a".repeat(64)),
    };
    let observe = BrowserAction::CaptureSynopsis {
        action_id: "observe-login".to_owned(),
    };
    assert!(submit.validate_shape().is_ok());
    assert_eq!(
        submit.effect(),
        BrowserActionEffect::ConsequentialFormSubmit
    );
    assert!(submit.effect().is_side_effectful());
    assert!(!observe.effect().is_side_effectful());
    assert_ne!(submit.digest(), observe.digest());
}

#[test]
fn lease_binding_digest_changes_with_epoch_or_token() {
    let first = lease("opaque-token-a");
    let mut second = first.clone();
    second.token = "opaque-token-b".to_owned();
    let mut third = first.clone();
    third.execution_epoch += 1;
    assert!(first.validate_shape().is_ok());
    assert_ne!(first.binding_digest(), second.binding_digest());
    assert_ne!(first.binding_digest(), third.binding_digest());
}

#[test]
fn download_receipt_is_bounded_and_never_marks_auto_open() {
    let root = private_test_root("download");
    fs::write(root.join("artifact.bin"), b"bounded-download")
        .unwrap_or_else(|error| panic!("write test download failed: {error}"));
    let receipt = DownloadReceipt::from_confined_file(
        &lease("download-token"),
        &root,
        Path::new("artifact.bin"),
        "application/octet-stream",
        1024,
    )
    .unwrap_or_else(|error| panic!("receipt creation failed: {error}"));
    assert_eq!(receipt.bytes, 16);
    assert!(receipt.sha256.starts_with("sha256:"));
    assert_eq!(receipt.content_type, "application/octet-stream");
    assert!(!receipt.auto_opened_or_executed);
    let bytes = receipt
        .to_bytes()
        .unwrap_or_else(|error| panic!("receipt serialization failed: {error}"));
    assert!(!String::from_utf8_lossy(&bytes).contains("download-token"));
    remove_test_root(&root);
}

#[test]
fn download_receipt_rejects_traversal_symlink_and_oversize() {
    let root = private_test_root("confinement");
    fs::create_dir(root.join("nested"))
        .unwrap_or_else(|error| panic!("create nested failed: {error}"));
    fs::write(root.join("nested/large.bin"), vec![0_u8; 32])
        .unwrap_or_else(|error| panic!("write large test file failed: {error}"));
    assert!(
        DownloadReceipt::from_confined_file(
            &lease("t"),
            &root,
            Path::new("nested/large.bin"),
            "application/octet-stream",
            8,
        )
        .is_err()
    );
    assert!(
        DownloadReceipt::from_confined_file(
            &lease("t"),
            &root,
            Path::new("../escape"),
            "application/octet-stream",
            1024,
        )
        .is_err()
    );

    let outside = private_test_root("outside");
    fs::write(outside.join("secret"), b"outside")
        .unwrap_or_else(|error| panic!("write outside file failed: {error}"));
    symlink(outside.join("secret"), root.join("link"))
        .unwrap_or_else(|error| panic!("symlink test setup failed: {error}"));
    assert!(
        DownloadReceipt::from_confined_file(
            &lease("t"),
            &root,
            Path::new("link"),
            "application/octet-stream",
            1024,
        )
        .is_err()
    );
    remove_test_root(&root);
    remove_test_root(&outside);
}

#[test]
fn prepared_launch_preserves_exact_caller_flags_and_cleans_when_unused() {
    let chrome = Path::new("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
    if !chrome.is_file() {
        return;
    }
    let root = private_test_root("prepare");
    let download_root = root.join("task-downloads");
    fs::create_dir(&download_root)
        .unwrap_or_else(|error| panic!("create task download root failed: {error}"));
    fs::set_permissions(&download_root, fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|error| panic!("chmod task download root failed: {error}"));
    let options = BrowserLaunchOptions {
        caller_chrome_args: vec![
            "--proxy-server=http://127.0.0.1:45678".to_owned(),
            "--proxy-bypass-list=<-loopback>".to_owned(),
        ],
        download_policy: BrowserDownloadPolicy::Allow,
        download_root: Some(download_root.clone()),
        profile_root: BrowserProfileRoot::Ephemeral,
        proxy_auth: None,
    };
    let prepared = BrowserAdapter::prepare_launch(
        chrome,
        &root,
        &lease("prepare-token"),
        BrowserAdapterConfig::default(),
        options.clone(),
    )
    .unwrap_or_else(|error| panic!("prepare launch failed: {error}"));
    assert_eq!(prepared.download_policy(), BrowserDownloadPolicy::Allow);
    let canonical_download_root = download_root
        .canonicalize()
        .unwrap_or_else(|error| panic!("canonicalize task download root failed: {error}"));
    assert_eq!(
        prepared.download_root(),
        Some(canonical_download_root.as_path())
    );
    assert!(!prepared.profile_root().starts_with(&download_root));
    assert!(!download_root.starts_with(prepared.profile_root()));
    assert_eq!(prepared.chrome_path(), chrome);
    assert!(
        prepared
            .chrome_args()
            .windows(options.caller_chrome_args.len())
            .any(|window| window == options.caller_chrome_args)
    );
    assert_eq!(prepared.process_spec().executable, Path::new("/bin/sh"));
    assert!(!prepared.process_spec().environment.contains_key("HOME"));
    assert_eq!(
        prepared.process_spec().environment.get("CFFIXED_USER_HOME"),
        Some(&prepared.profile_root().display().to_string())
    );
    assert_eq!(
        prepared.process_spec().environment.get("TMPDIR"),
        Some(&prepared.profile_root().display().to_string())
    );
    let profile = prepared.profile_root().to_path_buf();
    assert!(profile.is_dir());
    drop(prepared);
    assert!(!profile.exists());
    assert!(download_root.is_dir());
    remove_test_root(&root);
}

#[test]
fn proxy_auth_is_default_disabled_and_launch_shape_never_contains_token() {
    assert!(BrowserLaunchOptions::default().proxy_auth.is_none());
    let browser_lease = lease("proxy-auth-secret-token");
    let debug_lease = format!("{browser_lease:?}");
    assert!(!debug_lease.contains("proxy-auth-secret-token"));
    assert!(debug_lease.contains("[REDACTED]"));

    let chrome = Path::new("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
    if !chrome.is_file() {
        return;
    }
    let root = private_test_root("proxy-auth-launch-shape");
    let options = BrowserLaunchOptions {
        caller_chrome_args: vec![
            "--proxy-server=http://127.0.0.1:43123".to_owned(),
            "--proxy-bypass-list=<-loopback>".to_owned(),
        ],
        download_policy: BrowserDownloadPolicy::Deny,
        download_root: None,
        profile_root: BrowserProfileRoot::Ephemeral,
        proxy_auth: Some(BrowserProxyAuthBinding {
            origin: "http://127.0.0.1:43123".to_owned(),
            scheme: "basic".to_owned(),
            realm: BROWSER_PROXY_AUTH_REALM.to_owned(),
            username: BROWSER_PROXY_AUTH_USERNAME.to_owned(),
        }),
    };
    let prepared = BrowserAdapter::prepare_launch(
        chrome,
        &root,
        &browser_lease,
        BrowserAdapterConfig::default(),
        options,
    )
    .unwrap_or_else(|error| panic!("prepare proxy-auth launch failed: {error}"));
    let token = browser_lease.token.as_str();
    assert!(
        prepared
            .chrome_args()
            .iter()
            .all(|arg| !arg.contains(token))
    );
    assert!(
        prepared
            .process_spec()
            .environment
            .values()
            .all(|value| !value.contains(token))
    );
    assert!(!format!("{:?}", prepared.process_spec()).contains(token));
    assert!(!format!("{prepared:?}").contains(token));
    let profile = prepared.profile_root().to_path_buf();
    drop(prepared);
    assert!(!profile.exists());
    remove_test_root(&root);
}

#[test]
fn prepared_launch_method_ceiling_accepts_only_bounded_uppercase_methods() {
    let chrome = Path::new("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
    if !chrome.is_file() {
        return;
    }
    let root = private_test_root("method-ceiling");
    let mut prepared = BrowserAdapter::prepare_launch(
        chrome,
        &root,
        &lease("method-ceiling-token"),
        BrowserAdapterConfig::default(),
        BrowserLaunchOptions::default(),
    )
    .unwrap_or_else(|error| panic!("prepare method-ceiling launch failed: {error}"));

    prepared
        .set_request_method_ceiling(BTreeSet::from(["GET".to_owned(), "HEAD".to_owned()]))
        .unwrap_or_else(|error| panic!("exact method ceiling rejected: {error}"));
    assert!(
        prepared
            .set_request_method_ceiling(BTreeSet::new())
            .is_err()
    );
    assert!(
        prepared
            .set_request_method_ceiling(BTreeSet::from(["post".to_owned()]))
            .is_err()
    );

    let profile = prepared.profile_root().to_path_buf();
    drop(prepared);
    assert!(!profile.exists());
    remove_test_root(&root);
}

#[test]
fn prepared_launch_rejects_caller_override_of_adapter_owned_chrome_mechanics() {
    let chrome = Path::new("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
    if !chrome.is_file() {
        return;
    }
    let root = private_test_root("prepare-reserved");
    for flag in [
        "--remote-debugging-port=9222",
        "--remote-debugging-pipe",
        "--user-data-dir=/tmp/not-sovereign",
        "--profile-directory=Default",
    ] {
        let result = BrowserAdapter::prepare_launch(
            chrome,
            &root,
            &lease("reserved-token"),
            BrowserAdapterConfig::default(),
            BrowserLaunchOptions {
                caller_chrome_args: vec![flag.to_owned()],
                download_policy: BrowserDownloadPolicy::Deny,
                download_root: None,
                profile_root: BrowserProfileRoot::Ephemeral,
                proxy_auth: None,
            },
        );
        assert!(
            result.is_err(),
            "unexpectedly accepted reserved flag {flag}"
        );
    }
    remove_test_root(&root);
}

#[test]
fn caller_owned_persistent_profile_is_reused_and_never_cleaned_by_preparation() {
    let chrome = Path::new("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
    if !chrome.is_file() {
        return;
    }
    let root = private_test_root("persistent-profile");
    let profile = root.join("profile");
    fs::create_dir(&profile)
        .unwrap_or_else(|error| panic!("create persistent profile failed: {error}"));
    fs::set_permissions(&profile, fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|error| panic!("chmod persistent profile failed: {error}"));
    let options = BrowserLaunchOptions {
        caller_chrome_args: Vec::new(),
        download_policy: BrowserDownloadPolicy::Deny,
        download_root: None,
        profile_root: BrowserProfileRoot::CallerOwnedPersistent(profile.clone()),
        proxy_auth: None,
    };
    let browser_lease = lease("persistent-profile-token");
    let prepared = BrowserAdapter::prepare_launch(
        chrome,
        &root,
        &browser_lease,
        BrowserAdapterConfig::default(),
        options.clone(),
    )
    .unwrap_or_else(|error| panic!("prepare persistent profile failed: {error}"));
    assert!(prepared.profile_is_persistent());
    assert_eq!(
        prepared.profile_root(),
        profile
            .canonicalize()
            .unwrap_or_else(|error| panic!("canonicalize persistent profile failed: {error}"))
    );
    assert_eq!(prepared.download_root(), None);
    assert!(!profile.join("downloads").exists());
    drop(prepared);
    assert!(profile.is_dir());
    assert!(!profile.join("downloads").exists());

    let adapter = wrapped_adapter(chrome, &root, &browser_lease, options.clone());
    adapter
        .shutdown()
        .unwrap_or_else(|error| panic!("shutdown persistent browser failed: {error}"));
    assert!(profile.is_dir());

    let prepared_again = BrowserAdapter::prepare_launch(
        chrome,
        &root,
        &browser_lease,
        BrowserAdapterConfig::default(),
        options,
    )
    .unwrap_or_else(|error| panic!("reuse persistent profile failed: {error}"));
    assert_eq!(
        prepared_again.profile_root(),
        profile
            .canonicalize()
            .unwrap_or_else(|error| panic!("canonicalize reused profile failed: {error}"))
    );
    drop(prepared_again);
    assert!(profile.is_dir());
    assert!(!profile.join("downloads").exists());
    remove_test_root(&root);
}

#[test]
fn persistent_profile_no_proxy_first_navigation_is_intercepted() {
    let chrome = Path::new("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
    if !chrome.is_file() {
        return;
    }
    let root = private_test_root("persistent-no-proxy-navigation");
    let profile = root.join("profile");
    fs::create_dir(&profile)
        .unwrap_or_else(|error| panic!("create persistent navigation profile failed: {error}"));
    fs::set_permissions(&profile, fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|error| panic!("chmod persistent navigation profile failed: {error}"));

    let (address, server) = spawn_loopback_response_server(
        "/first",
        "",
        b"<!doctype html><title>persistent-navigation-ok</title><main>ok</main>",
    );

    let browser_lease = lease("persistent-no-proxy-navigation-token");
    let mut adapter = wrapped_adapter(
        chrome,
        &root,
        &browser_lease,
        BrowserLaunchOptions {
            caller_chrome_args: vec!["--no-proxy-server".to_owned()],
            profile_root: BrowserProfileRoot::CallerOwnedPersistent(profile.clone()),
            ..BrowserLaunchOptions::default()
        },
    );
    navigate_intercepted(
        &mut adapter,
        &browser_lease,
        "persistent-no-proxy-first-navigation",
        &format!("http://{address}/first"),
    );

    server
        .join()
        .unwrap_or_else(|_| panic!("persistent navigation fixture server panicked"));
    adapter
        .shutdown()
        .unwrap_or_else(|error| panic!("shutdown persistent navigation browser failed: {error}"));
    assert!(
        profile.is_dir(),
        "caller-owned persistent profile was deleted"
    );
    remove_test_root(&root);
}

#[test]
fn real_chrome_contains_page_js_writes_and_worker_network_before_execution() {
    let chrome = Path::new("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
    if !chrome.is_file() {
        return;
    }
    let root = private_test_root("subresource-worker-containment");
    let browser_lease = lease("subresource-worker-containment-token");
    let mut prepared = BrowserAdapter::prepare_launch(
        chrome,
        &root,
        &browser_lease,
        BrowserAdapterConfig::default(),
        BrowserLaunchOptions {
            caller_chrome_args: vec!["--no-proxy-server".to_owned()],
            ..BrowserLaunchOptions::default()
        },
    )
    .unwrap_or_else(|error| panic!("prepare containment browser failed: {error}"));
    prepared
        .set_request_method_ceiling(BTreeSet::from([
            "GET".to_owned(),
            "HEAD".to_owned(),
            "POST".to_owned(),
        ]))
        .unwrap_or_else(|error| panic!("install containment method ceiling failed: {error}"));
    let mut wrapped_args = vec![prepared.process_spec().executable.display().to_string()];
    wrapped_args.extend(prepared.process_spec().args.iter().cloned());
    let wrapped = IsolatedCommand {
        executable: PathBuf::from("/usr/bin/env"),
        args: wrapped_args,
    };
    let mut adapter = BrowserAdapter::spawn_preisolated(prepared, &wrapped)
        .unwrap_or_else(|error| panic!("spawn containment browser failed: {error}"));

    let (address, server) = spawn_browser_containment_server();
    navigate_intercepted(
        &mut adapter,
        &browser_lease,
        "subresource-worker-containment-nav",
        &format!("http://{address}/fixture"),
    );
    let observed = server
        .join()
        .unwrap_or_else(|_| panic!("containment server panicked"));
    assert!(
        observed
            .iter()
            .any(|line| line.starts_with("GET /safe-get ")),
        "safe GET subresource was not allowed: {observed:?}"
    );
    assert!(
        observed
            .iter()
            .any(|line| line.starts_with("HEAD /safe-head ")),
        "safe HEAD subresource was not allowed: {observed:?}"
    );
    for forbidden in [
        "POST /blocked-post ",
        "GET /worker-get ",
        "POST /worker-post ",
    ] {
        assert!(
            observed.iter().all(|line| !line.starts_with(forbidden)),
            "contained browser path reached the server as {forbidden:?}: {observed:?}"
        );
    }

    adapter
        .shutdown()
        .unwrap_or_else(|error| panic!("shutdown containment browser failed: {error}"));
    remove_test_root(&root);
}

#[test]
fn persistent_profile_cookie_survives_graceful_shutdown_and_relaunch() {
    let chrome = Path::new("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
    if !chrome.is_file() {
        return;
    }
    let root = private_test_root("persistent-cookie");
    let profile = root.join("profile");
    fs::create_dir(&profile)
        .unwrap_or_else(|error| panic!("create persistent cookie profile failed: {error}"));
    fs::set_permissions(&profile, fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|error| panic!("chmod persistent cookie profile failed: {error}"));
    let options = BrowserLaunchOptions {
        caller_chrome_args: vec!["--no-proxy-server".to_owned()],
        profile_root: BrowserProfileRoot::CallerOwnedPersistent(profile.clone()),
        ..BrowserLaunchOptions::default()
    };

    let first_lease = lease("persistent-cookie-token-1");
    let (seed_address, seed_server) = spawn_loopback_response_server(
        "/seed-cookie",
        "Set-Cookie: sovereign_persist=cookie-sentinel; Max-Age=3600; Path=/; SameSite=Lax\r\n",
        b"<!doctype html><title>cookie-seeded</title>",
    );
    let mut first = wrapped_adapter(chrome, &root, &first_lease, options.clone());
    navigate_intercepted(
        &mut first,
        &first_lease,
        "persistent-cookie-seed",
        &format!("http://{seed_address}/seed-cookie"),
    );
    let seed_request = seed_server
        .join()
        .unwrap_or_else(|_| panic!("persistent cookie seed server panicked"));
    assert!(!seed_request.contains("Cookie: sovereign_persist="));
    first
        .shutdown()
        .unwrap_or_else(|error| panic!("graceful persistent cookie shutdown failed: {error}"));
    assert!(profile.is_dir());

    let second_lease = lease("persistent-cookie-token-2");
    let (check_address, check_server) = spawn_loopback_response_server(
        "/check-cookie",
        "",
        b"<!doctype html><title>cookie-checked</title>",
    );
    let mut second = wrapped_adapter(chrome, &root, &second_lease, options);
    navigate_intercepted(
        &mut second,
        &second_lease,
        "persistent-cookie-check",
        &format!("http://{check_address}/check-cookie"),
    );
    let check_request = check_server
        .join()
        .unwrap_or_else(|_| panic!("persistent cookie check server panicked"));
    assert!(
        check_request
            .lines()
            .any(|line| line == "Cookie: sovereign_persist=cookie-sentinel"),
        "persistent cookie was not sent after graceful shutdown/relaunch: {check_request}"
    );
    second.shutdown().unwrap_or_else(|error| {
        panic!("shutdown second persistent cookie browser failed: {error}")
    });
    assert!(profile.is_dir());
    remove_test_root(&root);
}

#[test]
fn launch_download_root_is_explicit_caller_owned_and_disjoint_from_profile() {
    let chrome = Path::new("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
    if !chrome.is_file() {
        return;
    }
    let root = private_test_root("explicit-download-root");
    let download_root = root.join("task-downloads");
    fs::create_dir(&download_root)
        .unwrap_or_else(|error| panic!("create explicit download root failed: {error}"));
    fs::set_permissions(&download_root, fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|error| panic!("chmod explicit download root failed: {error}"));

    let prepared = BrowserAdapter::prepare_launch(
        chrome,
        &root,
        &lease("explicit-download-token"),
        BrowserAdapterConfig::default(),
        BrowserLaunchOptions {
            download_policy: BrowserDownloadPolicy::Allow,
            download_root: Some(download_root.clone()),
            ..BrowserLaunchOptions::default()
        },
    )
    .unwrap_or_else(|error| panic!("prepare explicit download root failed: {error}"));
    let profile_root = prepared.profile_root().to_path_buf();
    let canonical_download_root = download_root
        .canonicalize()
        .unwrap_or_else(|error| panic!("canonicalize explicit download root failed: {error}"));
    assert_eq!(
        prepared.download_root(),
        Some(canonical_download_root.as_path())
    );
    assert!(!profile_root.starts_with(&download_root));
    assert!(!download_root.starts_with(&profile_root));
    drop(prepared);
    assert!(!profile_root.exists());
    assert!(download_root.is_dir());

    let allowed_adapter = wrapped_adapter(
        chrome,
        &root,
        &lease("allow-and-name-download-token"),
        BrowserLaunchOptions {
            download_policy: BrowserDownloadPolicy::Allow,
            download_root: Some(download_root.clone()),
            ..BrowserLaunchOptions::default()
        },
    );
    assert!(allowed_adapter.downloads_enabled());
    assert_eq!(
        allowed_adapter.download_root(),
        Some(canonical_download_root.as_path())
    );
    allowed_adapter
        .shutdown()
        .unwrap_or_else(|error| panic!("shutdown allowAndName browser failed: {error}"));
    assert!(download_root.is_dir());

    let persistent_profile = root.join("persistent");
    fs::create_dir(&persistent_profile)
        .unwrap_or_else(|error| panic!("create persistent overlap fixture failed: {error}"));
    fs::set_permissions(&persistent_profile, fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|error| panic!("chmod persistent overlap fixture failed: {error}"));
    let nested_download = persistent_profile.join("downloads");
    fs::create_dir(&nested_download)
        .unwrap_or_else(|error| panic!("create nested download fixture failed: {error}"));
    fs::set_permissions(&nested_download, fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|error| panic!("chmod nested download fixture failed: {error}"));
    let overlap = BrowserAdapter::prepare_launch(
        chrome,
        &root,
        &lease("overlap-download-token"),
        BrowserAdapterConfig::default(),
        BrowserLaunchOptions {
            download_policy: BrowserDownloadPolicy::Allow,
            download_root: Some(nested_download),
            profile_root: BrowserProfileRoot::CallerOwnedPersistent(persistent_profile),
            ..BrowserLaunchOptions::default()
        },
    );
    assert!(overlap.is_err());
    remove_test_root(&root);
}

#[test]
fn spawn_failure_distinguishes_never_spawned_from_proven_absent() {
    let chrome = Path::new("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
    if !chrome.is_file() {
        return;
    }
    let root = private_test_root("typed-spawn-failure");
    let prepared = BrowserAdapter::prepare_launch(
        chrome,
        &root,
        &lease("never-spawned-token"),
        BrowserAdapterConfig::default(),
        BrowserLaunchOptions::default(),
    )
    .unwrap_or_else(|error| panic!("prepare never-spawned fixture failed: {error}"));
    let failure = match BrowserAdapter::spawn_preisolated(
        prepared,
        &IsolatedCommand {
            executable: root.join("missing-wrapper"),
            args: Vec::new(),
        },
    ) {
        Ok(adapter) => {
            let _ = adapter.shutdown();
            panic!("missing executable unexpectedly spawned")
        }
        Err(failure) => failure,
    };
    assert_eq!(failure.state(), &BrowserSpawnState::NeverSpawned);

    let prepared = BrowserAdapter::prepare_launch(
        chrome,
        &root,
        &lease("proven-absent-token"),
        BrowserAdapterConfig::default(),
        BrowserLaunchOptions::default(),
    )
    .unwrap_or_else(|error| panic!("prepare proven-absent fixture failed: {error}"));
    let failure = match BrowserAdapter::spawn_preisolated(
        prepared,
        &IsolatedCommand {
            executable: PathBuf::from("/usr/bin/false"),
            args: Vec::new(),
        },
    ) {
        Ok(adapter) => {
            let _ = adapter.shutdown();
            panic!("short-lived non-CDP process unexpectedly completed browser handshake")
        }
        Err(failure) => failure,
    };
    assert_eq!(failure.state(), &BrowserSpawnState::ProvenAbsent);
    remove_test_root(&root);
}

#[test]
fn real_chrome_pipe_smoke_gets_version_and_cleans_profile() {
    let chrome = Path::new("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
    if !chrome.is_file() {
        return;
    }
    let root = private_test_root("chrome-smoke");
    let config = BrowserAdapterConfig::default();
    let chrome_lease = lease("chrome-smoke-token");
    let prepared = BrowserAdapter::prepare_launch(
        chrome,
        &root,
        &chrome_lease,
        config,
        BrowserLaunchOptions::default(),
    )
    .unwrap_or_else(|error| panic!("Chrome pipe prepare failed: {error}"));
    let mut wrapped_args = vec![prepared.process_spec().executable.display().to_string()];
    wrapped_args.extend(prepared.process_spec().args.iter().cloned());
    let wrapped = IsolatedCommand {
        executable: PathBuf::from("/usr/bin/env"),
        args: wrapped_args,
    };
    let mut adapter = BrowserAdapter::spawn_preisolated(prepared, &wrapped)
        .unwrap_or_else(|error| panic!("Chrome wrapped pipe launch failed: {error}"));
    assert!(adapter.browser_version().product.starts_with("Chrome/"));
    assert!(!adapter.browser_version().protocol_version.is_empty());
    assert!(!adapter.browser_version().user_agent.is_empty());
    assert!(!adapter.target_id().is_empty());
    assert!(adapter.process_group_id() > 0);
    assert!(!adapter.process_group_identity().is_empty());
    assert!(adapter.screenshots_and_traces_suppressed());
    assert!(!adapter.downloads_enabled());
    let profile = adapter.profile_root().to_path_buf();
    let download_root = adapter.download_root().map(Path::to_path_buf);
    assert!(profile.is_dir());
    assert!(download_root.is_none());

    let synopsis_action = BrowserAction::CaptureSynopsis {
        action_id: "chrome-smoke-synopsis".to_owned(),
    };
    let receipt = adapter
        .execute(&chrome_lease, &synopsis_action)
        .unwrap_or_else(|error| panic!("about:blank synopsis failed: {error}"));
    assert_eq!(receipt.effect, BrowserActionEffect::Observation);
    assert!(receipt.screenshots_and_traces_suppressed);
    let synopsis = receipt
        .synopsis
        .as_ref()
        .unwrap_or_else(|| panic!("synopsis receipt omitted state"));
    assert_eq!(synopsis.url, "about:blank");
    assert!(synopsis.retained_text_bytes <= 64 * 1024);
    assert!(synopsis.retained_dom_bytes <= 128 * 1024);
    assert!(synopsis.retained_dom_sha256.starts_with("sha256:"));
    let receipt_bytes = receipt
        .to_bytes()
        .unwrap_or_else(|error| panic!("browser receipt serialization failed: {error}"));
    assert!(!String::from_utf8_lossy(&receipt_bytes).contains("chrome-smoke-token"));

    let mut stale_lease = chrome_lease.clone();
    stale_lease.token = "stale-token".to_owned();
    assert!(adapter.execute(&stale_lease, &synopsis_action).is_err());

    adapter
        .shutdown()
        .unwrap_or_else(|error| panic!("Chrome shutdown failed: {error}"));
    assert!(!profile.exists());
    remove_test_root(&root);
}

#[test]
fn real_chrome_screenshot_capture_is_bounded_and_sensitive_page_suppresses_raw_png() {
    let chrome = Path::new("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
    if !chrome.is_file() {
        return;
    }
    let root = private_test_root("chrome-screenshot");
    let chrome_lease = lease("chrome-screenshot-token");
    let config = BrowserAdapterConfig {
        suppress_screenshots_and_traces: false,
        ..BrowserAdapterConfig::default()
    };
    let screenshot_bound = config.max_cdp_frame_bytes;
    let mut adapter = wrapped_adapter_with_config(
        chrome,
        &root,
        &chrome_lease,
        config,
        BrowserLaunchOptions {
            caller_chrome_args: vec!["--no-proxy-server".to_owned()],
            ..BrowserLaunchOptions::default()
        },
    );

    let (safe_address, safe_server) = spawn_loopback_response_server(
        "/safe",
        "",
        b"<!doctype html><html><head><title>Safe screenshot page</title></head><body><h1>bounded screenshot fixture</h1></body></html>",
    );
    let safe_url = format!("http://{safe_address}/safe");
    navigate_intercepted(
        &mut adapter,
        &chrome_lease,
        "screenshot-safe-nav",
        &safe_url,
    );
    let safe_request = safe_server
        .join()
        .unwrap_or_else(|_| panic!("safe screenshot fixture server panicked"));
    assert!(safe_request.starts_with("GET /safe "));

    let safe_receipt = adapter
        .execute(
            &chrome_lease,
            &BrowserAction::CaptureScreenshot {
                action_id: "capture-safe-screenshot".to_owned(),
            },
        )
        .unwrap_or_else(|error| panic!("capture non-sensitive screenshot failed: {error}"));
    assert_bounded_png_screenshot(&safe_receipt, screenshot_bound);

    let (sensitive_address, sensitive_server) = spawn_loopback_response_server(
        "/credential",
        "",
        br#"<!doctype html><html><head><title>Credential screenshot page</title></head><body><form><label>Password<input type="password" value="raw-screenshot-secret"></label></form></body></html>"#,
    );
    let sensitive_url = format!("http://{sensitive_address}/credential");
    navigate_intercepted(
        &mut adapter,
        &chrome_lease,
        "screenshot-sensitive-nav",
        &sensitive_url,
    );
    let sensitive_request = sensitive_server
        .join()
        .unwrap_or_else(|_| panic!("sensitive screenshot fixture server panicked"));
    assert!(sensitive_request.starts_with("GET /credential "));

    let sensitive_receipt = adapter
        .execute(
            &chrome_lease,
            &BrowserAction::CaptureScreenshot {
                action_id: "capture-sensitive-screenshot".to_owned(),
            },
        )
        .unwrap_or_else(|error| panic!("capture sensitive screenshot suppression failed: {error}"));
    assert!(sensitive_receipt.screenshots_and_traces_suppressed);
    assert!(sensitive_receipt.screenshot.is_none());
    let sensitive_synopsis = sensitive_receipt
        .synopsis
        .as_ref()
        .unwrap_or_else(|| panic!("sensitive screenshot receipt omitted suppression synopsis"));
    assert!(sensitive_synopsis.sensitive_page.is_sensitive());
    assert!(sensitive_synopsis.title.is_empty());
    assert!(sensitive_synopsis.text.is_empty());
    assert!(sensitive_synopsis.dom_excerpt.is_empty());
    let sensitive_bytes = sensitive_receipt
        .to_bytes()
        .unwrap_or_else(|error| panic!("serialize sensitive screenshot receipt failed: {error}"));
    let sensitive_json = String::from_utf8_lossy(&sensitive_bytes);
    assert!(!sensitive_json.contains("raw-screenshot-secret"));
    assert!(!sensitive_json.contains("iVBORw0KGgo"));

    adapter
        .shutdown()
        .unwrap_or_else(|error| panic!("Chrome screenshot shutdown failed: {error}"));
    remove_test_root(&root);
}
