use sha2::{Digest, Sha256};
use sovereign_policy::browser::{
    BROWSER_DOWNLOAD_POLICY_SCHEMA_VERSION, BROWSER_LOOPBACK_CAPABILITY_SCHEMA_VERSION,
    BrowserDownloadMode, BrowserDownloadPolicyV1, BrowserDownloadRetentionPolicyV1,
    BrowserDownloadRootAuthorityV1, BrowserIsolationRequest, BrowserLoopbackCapabilityV1,
    BrowserNavigationScheme, BrowserPolicyError, BrowserProfileAuthority, BrowserProfileMode,
    BrowserProfilePolicy, LoopbackServerIsolationRequestV1, MacBrowserSandboxExecBackend,
    MacLoopbackServerSandboxExecBackend, PERSISTENT_BROWSER_PROFILE_GRANT_SCHEMA_VERSION,
    PersistentBrowserProfileGrantV1, TASK_LOOPBACK_GRANT_SCHEMA_VERSION, TaskLoopbackGrantV1,
    TaskLoopbackScope, authorize_top_level_browser_url,
};
use sovereign_policy::{NetworkDestination, NetworkPolicy};
use std::collections::BTreeSet;
use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

struct TestDir(PathBuf);

impl TestDir {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|error| panic!("clock: {error}"))
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "sovereign-policy-browser-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap_or_else(|error| panic!("test dir: {error}"));
        Self(
            path.canonicalize()
                .unwrap_or_else(|error| panic!("canonical test dir: {error}")),
        )
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn sha256_binding(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn loopback_capability(port: u16, token: &[u8]) -> BrowserLoopbackCapabilityV1 {
    BrowserLoopbackCapabilityV1 {
        schema_version: BROWSER_LOOPBACK_CAPABILITY_SCHEMA_VERSION,
        lease_id: "browser.lease.fixture".to_owned(),
        execution_epoch: 7,
        localhost_port: port,
        token_digest: sha256_binding(token),
        expires_at_ms: 10_000,
    }
}

fn task_loopback_grant() -> TaskLoopbackGrantV1 {
    TaskLoopbackGrantV1 {
        schema_version: TASK_LOOPBACK_GRANT_SCHEMA_VERSION,
        plan_id: "plan.fixture".to_owned(),
        plan_revision: 3,
        task_id: "task.fixture".to_owned(),
        task_contract_digest: sha256_binding(b"task-contract"),
        resource_lease_id: "browser.resource.fixture".to_owned(),
        execution_epoch: 7,
        scheme: "http".to_owned(),
        host: "127.0.0.1".to_owned(),
        port: 43_219,
        expires_at_ms: 10_000,
    }
}

fn task_loopback_scope(grant: &TaskLoopbackGrantV1) -> TaskLoopbackScope<'_> {
    TaskLoopbackScope {
        plan_id: &grant.plan_id,
        plan_revision: grant.plan_revision,
        task_id: &grant.task_id,
        task_contract_digest: &grant.task_contract_digest,
        resource_lease_id: &grant.resource_lease_id,
        execution_epoch: grant.execution_epoch,
    }
}

#[cfg(target_os = "macos")]
#[test]
#[expect(
    clippy::unwrap_used,
    reason = "the Seatbelt denial fixture uses unwrap only for setup and process status"
)]
fn managed_app_default_denies_local_database_and_other_outbound() {
    let root = TestDir::new("managed-local-database-denial");
    let repository_root = root.0.join("repo");
    let data_root = root.0.join("data");
    fs::create_dir(&repository_root).unwrap();
    fs::create_dir(&data_root).unwrap();
    let local_database = TcpListener::bind("127.0.0.1:0").unwrap();
    let database_socket_path = PathBuf::from(format!(
        "/tmp/sov-pg-{}-{}.sock",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _database_socket = std::os::unix::net::UnixListener::bind(&database_socket_path).unwrap();
    let neighboring_service = TcpListener::bind("127.0.0.1:0").unwrap();
    let app_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut grant = task_loopback_grant();
    grant.port = app_listener.local_addr().unwrap().port();
    grant.expires_at_ms = i64::MAX;
    let request = LoopbackServerIsolationRequestV1 {
        task_loopback_grant: grant,
        repository_root,
        data_root,
        user_home_root: root.0.clone(),
        extra_protected_read_roots: Vec::new(),
        postgres_broker_port: None,
        now_ms: 100,
    };
    let profile = MacLoopbackServerSandboxExecBackend::build_profile(&request).unwrap();
    let sandbox = Path::new("/usr/bin/sandbox-exec");
    let connect = |host: &str, port: u16| {
        Command::new(sandbox)
            .args(["-p", &profile, "/usr/bin/python3", "-B", "-c"])
            .arg("import socket,sys; s=socket.socket(); s.settimeout(0.2); s.connect((sys.argv[1],int(sys.argv[2]))); s.close()")
            .arg(host)
            .arg(port.to_string())
            .env_clear()
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    };
    assert!(
        !connect("127.0.0.1", local_database.local_addr().unwrap().port()),
        "default managed-app Seatbelt unexpectedly reached a local database endpoint"
    );
    assert!(!connect(
        "127.0.0.1",
        neighboring_service.local_addr().unwrap().port()
    ));
    assert!(!connect("8.8.8.8", 53));
    let unix_status = Command::new(sandbox)
        .args(["-p", &profile, "/usr/bin/python3", "-B", "-c"])
        .arg("import socket,sys; s=socket.socket(socket.AF_UNIX); s.settimeout(0.2); s.connect(sys.argv[1]); s.close()")
        .arg(&database_socket_path)
        .env_clear()
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(
        !unix_status.success(),
        "default managed-app Seatbelt reached a local database socket"
    );
    fs::remove_file(&database_socket_path).unwrap();
}

#[cfg(target_os = "macos")]
#[test]
#[expect(
    clippy::unwrap_used,
    reason = "the exact broker-port fixture uses unwrap only for setup and process status"
)]
fn managed_app_postgres_broker_grant_reaches_only_exact_controller_port() {
    let root = TestDir::new("managed-postgres-broker");
    let repository_root = root.0.join("repo");
    let data_root = root.0.join("data");
    fs::create_dir(&repository_root).unwrap();
    fs::create_dir(&data_root).unwrap();
    let broker = TcpListener::bind("127.0.0.1:0").unwrap();
    let neighbor = TcpListener::bind("127.0.0.1:0").unwrap();
    let app_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let direct_socket_path = PathBuf::from(format!(
        "/tmp/sov-pg-deny-{}-{}.sock",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _direct_socket = std::os::unix::net::UnixListener::bind(&direct_socket_path).unwrap();
    let mut grant = task_loopback_grant();
    grant.port = app_listener.local_addr().unwrap().port();
    grant.expires_at_ms = i64::MAX;
    let request = LoopbackServerIsolationRequestV1 {
        task_loopback_grant: grant,
        repository_root,
        data_root,
        user_home_root: root.0.clone(),
        extra_protected_read_roots: Vec::new(),
        postgres_broker_port: Some(broker.local_addr().unwrap().port()),
        now_ms: 100,
    };
    let profile = MacLoopbackServerSandboxExecBackend::build_profile(&request).unwrap();
    let connect = |port: u16| {
        Command::new("/usr/bin/sandbox-exec")
            .args(["-p", &profile, "/usr/bin/python3", "-B", "-c"])
            .arg("import socket,sys; s=socket.socket(); s.settimeout(0.2); s.connect(('127.0.0.1',int(sys.argv[1]))); s.close()")
            .arg(port.to_string())
            .env_clear()
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    };
    assert!(connect(broker.local_addr().unwrap().port()));
    assert!(!connect(neighbor.local_addr().unwrap().port()));
    assert!(!connect(5432));
    let outside = Command::new("/usr/bin/sandbox-exec")
        .args(["-p", &profile, "/usr/bin/python3", "-B", "-c"])
        .arg("import socket; s=socket.socket(); s.settimeout(0.2); s.connect(('8.8.8.8',53))")
        .env_clear()
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(!outside.success());
    let direct_socket = Command::new("/usr/bin/sandbox-exec")
        .args(["-p", &profile, "/usr/bin/python3", "-B", "-c"])
        .arg("import socket,sys; s=socket.socket(socket.AF_UNIX); s.settimeout(0.2); s.connect(sys.argv[1])")
        .arg(&direct_socket_path)
        .env_clear().stdout(Stdio::null()).stderr(Stdio::null()).status().unwrap();
    assert!(!direct_socket.success());
    fs::remove_file(&direct_socket_path).unwrap();
}

#[cfg(target_os = "macos")]
#[test]
fn loopback_server_seatbelt_profile_is_exact_and_self_tested() {
    let root = TestDir::new("loopback-server-seatbelt");
    let repository_root = root.0.join("repo");
    let data_root = root.0.join("data");
    fs::create_dir(&repository_root).unwrap_or_else(|error| panic!("create repo root: {error}"));
    fs::create_dir(&data_root).unwrap_or_else(|error| panic!("create data root: {error}"));
    let repository_root = repository_root
        .canonicalize()
        .unwrap_or_else(|error| panic!("canonical repo root: {error}"));
    let data_root = data_root
        .canonicalize()
        .unwrap_or_else(|error| panic!("canonical data root: {error}"));
    let protected_root = repository_root.join(".controller-protected");
    fs::create_dir(&protected_root)
        .unwrap_or_else(|error| panic!("create protected root: {error}"));
    let repository_file = repository_root.join("readable.txt");
    let data_file = data_root.join("readable.txt");
    let protected_file = protected_root.join("secret.txt");
    fs::write(&repository_file, b"repo")
        .unwrap_or_else(|error| panic!("repo read fixture: {error}"));
    fs::write(&data_file, b"data").unwrap_or_else(|error| panic!("data read fixture: {error}"));
    fs::write(&protected_file, b"secret")
        .unwrap_or_else(|error| panic!("protected read fixture: {error}"));
    let mut grant = task_loopback_grant();
    grant.port = 43_219;
    grant.expires_at_ms = i64::MAX;
    let request = LoopbackServerIsolationRequestV1 {
        task_loopback_grant: grant,
        repository_root: repository_root.clone(),
        data_root: data_root.clone(),
        user_home_root: root.0.clone(),
        extra_protected_read_roots: vec![protected_root.clone()],
        postgres_broker_port: None,
        now_ms: 100,
    };
    let profile = MacLoopbackServerSandboxExecBackend::build_profile(&request)
        .unwrap_or_else(|error| panic!("build loopback server profile: {error}"));
    assert!(profile.contains("(deny network*)"));
    assert!(profile.contains("(allow network-bind (local ip \"localhost:43219\"))"));
    assert!(profile.contains("(allow network-inbound (local ip \"localhost:43219\"))"));
    let home_deny = format!("(deny file-read* (subpath \"{}\"))", root.0.display());
    let repository_allow = format!(
        "(allow file-read* (subpath \"{}\"))",
        repository_root.display()
    );
    let data_allow = format!("(allow file-read* (subpath \"{}\"))", data_root.display());
    let protected_deny = format!(
        "(deny file-read* (subpath \"{}\"))",
        protected_root.display()
    );
    assert!(profile.contains(&home_deny));
    assert!(profile.contains(&repository_allow));
    assert!(profile.contains(&data_allow));
    assert!(profile.contains(&protected_deny));
    assert!(profile.find(&home_deny) < profile.find(&repository_allow));
    assert!(profile.find(&home_deny) < profile.find(&data_allow));
    assert!(profile.find(&repository_allow) < profile.find(&protected_deny));
    assert!(profile.contains("(deny file-write* (subpath \"/\"))"));
    assert!(profile.contains(&format!(
        "(allow file-write* (subpath \"{}\"))",
        data_root.display()
    )));
    assert!(!profile.contains(&format!(
        "(allow file-write* (subpath \"{}\"))",
        repository_root.display()
    )));

    let backend = MacLoopbackServerSandboxExecBackend::detect()
        .unwrap_or_else(|error| panic!("loopback server Seatbelt self-test: {error}"));
    assert!(sandbox_read_status(backend.sandbox_exec_path(), &profile, &repository_file).success());
    assert!(sandbox_read_status(backend.sandbox_exec_path(), &profile, &data_file).success());
    assert!(!sandbox_read_status(backend.sandbox_exec_path(), &profile, &protected_file).success());

    let mut broad_protected = request;
    broad_protected.extra_protected_read_roots = vec![root.0.clone()];
    assert!(broad_protected.validate().is_err());
}

#[test]
fn task_loopback_grant_is_exact_and_does_not_weaken_ordinary_network_policy() {
    let grant = task_loopback_grant();
    let scope = task_loopback_scope(&grant);
    let exact = NetworkDestination {
        scheme: "http".to_owned(),
        host: "127.0.0.1".to_owned(),
        port: 43_219,
    };
    grant
        .authorize(&scope, &exact, 9_999)
        .unwrap_or_else(|error| panic!("exact task loopback: {error}"));

    let mut ordinary = NetworkPolicy::offline();
    assert!(ordinary.allow("http", "127.0.0.1", 43_219).is_err());
    assert!(ordinary.authorize_destination(&exact).is_err());

    for mut denied in [
        NetworkDestination {
            port: 43_220,
            ..exact.clone()
        },
        NetworkDestination {
            scheme: "https".to_owned(),
            ..exact.clone()
        },
        NetworkDestination {
            host: "127.0.0.2".to_owned(),
            ..exact.clone()
        },
    ] {
        assert!(grant.authorize(&scope, &denied, 9_999).is_err());
        denied.host = "192.168.1.5".to_owned();
        assert!(grant.authorize(&scope, &denied, 9_999).is_err());
    }

    let mut stale_scope = scope;
    stale_scope.execution_epoch += 1;
    assert!(grant.authorize(&stale_scope, &exact, 9_999).is_err());

    let mut wrong_plan = task_loopback_scope(&grant);
    wrong_plan.plan_id = "plan.other";
    assert!(grant.authorize(&wrong_plan, &exact, 9_999).is_err());
    let mut wrong_revision = task_loopback_scope(&grant);
    wrong_revision.plan_revision += 1;
    assert!(grant.authorize(&wrong_revision, &exact, 9_999).is_err());
    let mut sibling = task_loopback_scope(&grant);
    sibling.task_id = "task.sibling";
    assert!(grant.authorize(&sibling, &exact, 9_999).is_err());
    let mut wrong_contract = task_loopback_scope(&grant);
    wrong_contract.task_contract_digest =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    assert!(grant.authorize(&wrong_contract, &exact, 9_999).is_err());
    let mut wrong_lease = task_loopback_scope(&grant);
    wrong_lease.resource_lease_id = "browser.resource.other";
    assert!(grant.authorize(&wrong_lease, &exact, 9_999).is_err());
}

#[test]
fn task_loopback_grant_rejects_dns_aliases_wildcards_and_noncanonical_literals() {
    for host in ["localhost", "127.0.0.0/8", "127.000.000.001", "::1"] {
        let mut grant = task_loopback_grant();
        grant.host = host.to_owned();
        assert!(grant.validate(100).is_err(), "{host}");
    }
    let mut ipv6 = task_loopback_grant();
    ipv6.host = "[::1]".to_owned();
    ipv6.validate(100)
        .unwrap_or_else(|error| panic!("canonical ipv6: {error}"));
}

#[test]
fn browser_loopback_capability_is_exact_port_epoch_lease_and_token_bound() {
    let token = b"capability-token";
    let capability = loopback_capability(43_219, token);
    capability
        .verify_token(token, 9_999)
        .unwrap_or_else(|error| panic!("exact capability: {error}"));
    assert!(capability.verify_token(b"other", 9_999).is_err());
    assert!(capability.validate(10_000).is_err());

    let mut invalid = capability.clone();
    invalid.localhost_port = 0;
    assert!(invalid.validate(0).is_err());
    invalid = capability.clone();
    invalid.execution_epoch = -1;
    assert!(invalid.validate(0).is_err());
    invalid = capability;
    invalid.lease_id.clear();
    assert!(invalid.validate(0).is_err());
}

#[test]
fn privileged_and_non_absolute_top_level_browser_schemes_are_denied() {
    assert_eq!(
        authorize_top_level_browser_url("https://example.test/path")
            .unwrap_or_else(|error| panic!("https: {error}")),
        BrowserNavigationScheme::Https
    );
    assert_eq!(
        authorize_top_level_browser_url("HTTP://example.test/")
            .unwrap_or_else(|error| panic!("http: {error}")),
        BrowserNavigationScheme::Http
    );
    for denied in [
        "file:///etc/passwd",
        "data:text/plain,hello",
        "chrome://settings",
        "javascript:alert(1)",
        "custom://authority/path",
        "https:relative",
        " https://example.test/",
    ] {
        assert!(authorize_top_level_browser_url(denied).is_err(), "{denied}");
    }
}

fn profile_grant(profile_id: &str) -> PersistentBrowserProfileGrantV1 {
    PersistentBrowserProfileGrantV1 {
        schema_version: PERSISTENT_BROWSER_PROFILE_GRANT_SCHEMA_VERSION,
        grant_id: "grant.fixture".to_owned(),
        project_id: "project.fixture".to_owned(),
        repository_id: "repo.fixture".to_owned(),
        profile_id: profile_id.to_owned(),
        allowed_origins: BTreeSet::from([
            "https://accounts.example.test".to_owned(),
            "https://app.example.test:8443".to_owned(),
        ]),
        policy_digest: sha256_binding(b"policy"),
        issued_at_ms: 100,
        expires_at_ms: 1_000,
    }
}

#[test]
fn isolated_profile_is_default_and_persistent_reuse_requires_exact_grant() {
    let policy =
        BrowserProfilePolicy::new("project.fixture", "repo.fixture", sha256_binding(b"policy"))
            .unwrap_or_else(|error| panic!("policy: {error}"));
    assert_eq!(
        policy
            .authorize(BrowserProfileMode::Isolated, None, None, 200)
            .unwrap_or_else(|error| panic!("isolated: {error}")),
        BrowserProfileAuthority::Isolated
    );
    assert!(
        policy
            .authorize(BrowserProfileMode::Persistent, Some("profile.a"), None, 200)
            .is_err()
    );
    let grant = profile_grant("profile.a");
    assert_eq!(
        policy
            .authorize(
                BrowserProfileMode::Persistent,
                Some("profile.a"),
                Some(&grant),
                200,
            )
            .unwrap_or_else(|error| panic!("persistent: {error}")),
        BrowserProfileAuthority::Persistent {
            grant_id: "grant.fixture".to_owned(),
            profile_id: "profile.a".to_owned(),
        }
    );
    assert!(
        policy
            .authorize(
                BrowserProfileMode::Persistent,
                Some("profile.b"),
                Some(&grant),
                200,
            )
            .is_err()
    );
    let mut wrong_repo = grant.clone();
    wrong_repo.repository_id = "repo.other".to_owned();
    assert!(
        policy
            .authorize(
                BrowserProfileMode::Persistent,
                Some("profile.a"),
                Some(&wrong_repo),
                200,
            )
            .is_err()
    );
    let mut stale_policy = grant;
    stale_policy.policy_digest = sha256_binding(b"other-policy");
    assert!(
        policy
            .authorize(
                BrowserProfileMode::Persistent,
                Some("profile.a"),
                Some(&stale_policy),
                200,
            )
            .is_err()
    );
}

#[test]
fn profile_grant_rejects_privileged_or_path_bearing_origin_metadata() {
    for origin in [
        "file://localhost",
        "https://example.test/path",
        "https://user@example.test",
        "https://example.test?query",
    ] {
        let mut grant = profile_grant("profile.a");
        grant.allowed_origins = BTreeSet::from([origin.to_owned()]);
        assert!(grant.validate(200).is_err(), "{origin}");
    }
}

fn download_policy(root: &Path) -> BrowserDownloadPolicyV1 {
    BrowserDownloadPolicyV1 {
        schema_version: BROWSER_DOWNLOAD_POLICY_SCHEMA_VERSION,
        mode: BrowserDownloadMode::TaskScoped,
        root_authority: Some(BrowserDownloadRootAuthorityV1 {
            lease_id: "browser.lease.fixture".to_owned(),
            execution_epoch: 7,
            root: root.to_path_buf(),
        }),
        retention: BrowserDownloadRetentionPolicyV1 {
            max_file_bytes: 4_096,
            allowed_content_types: BTreeSet::from([
                "application/pdf".to_owned(),
                "text/plain".to_owned(),
            ]),
        },
    }
}

#[test]
fn download_authority_is_task_root_relative_bounded_and_never_credential_retaining() {
    let temp = TestDir::new("download");
    let root = temp.0.join("downloads");
    fs::create_dir(&root).unwrap_or_else(|error| panic!("download root: {error}"));
    let root = root
        .canonicalize()
        .unwrap_or_else(|error| panic!("canonical download root: {error}"));
    let policy = download_policy(&root);
    assert_eq!(
        policy
            .authorize_relative_path(Path::new("reports/result.pdf"))
            .unwrap_or_else(|error| panic!("relative download: {error}")),
        root.join("reports/result.pdf")
    );
    for denied in ["../escape", "./alias", "/tmp/absolute"] {
        assert!(policy.authorize_relative_path(Path::new(denied)).is_err());
    }
    policy
        .retention
        .authorize(4_096, "application/pdf", false)
        .unwrap_or_else(|error| panic!("retention: {error}"));
    assert!(
        policy
            .retention
            .authorize(4_097, "application/pdf", false)
            .is_err()
    );
    assert!(
        policy
            .retention
            .authorize(1, "application/zip", false)
            .is_err()
    );
    assert!(policy.retention.authorize(1, "text/plain", true).is_err());

    let denied = BrowserDownloadPolicyV1 {
        schema_version: BROWSER_DOWNLOAD_POLICY_SCHEMA_VERSION,
        mode: BrowserDownloadMode::Deny,
        root_authority: None,
        retention: BrowserDownloadRetentionPolicyV1 {
            max_file_bytes: 1,
            allowed_content_types: BTreeSet::new(),
        },
    };
    assert!(
        denied
            .authorize_relative_path(Path::new("anything"))
            .is_err()
    );
}

#[test]
fn browser_isolation_request_rejects_symlink_writable_roots() {
    let temp = TestDir::new("roots");
    let profile = temp.0.join("profile");
    let target = temp.0.join("target");
    fs::create_dir(&profile).unwrap_or_else(|error| panic!("profile: {error}"));
    fs::create_dir(&target).unwrap_or_else(|error| panic!("target: {error}"));
    let profile = profile
        .canonicalize()
        .unwrap_or_else(|error| panic!("canonical profile: {error}"));
    let request = BrowserIsolationRequest {
        profile_root: profile,
        download_root: None,
        loopback_capability: loopback_capability(42_000, b"token"),
        now_ms: 100,
    };
    request
        .validate()
        .unwrap_or_else(|error| panic!("valid roots: {error}"));

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&target, temp.0.join("profile-link"))
            .unwrap_or_else(|error| panic!("symlink: {error}"));
        let mut symlinked = request;
        symlinked.profile_root = temp.0.join("profile-link");
        assert!(symlinked.validate().is_err());
    }
}

#[cfg(target_os = "macos")]
#[test]
fn mac_browser_sandbox_allows_only_exact_controller_loopback_port_and_roots() {
    let backend = MacBrowserSandboxExecBackend::detect()
        .unwrap_or_else(|error| panic!("browser sandbox detect: {error}"));
    let allowed_listener = TcpListener::bind("127.0.0.1:0")
        .unwrap_or_else(|error| panic!("allowed listener: {error}"));
    let denied_listener =
        TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("denied listener: {error}"));
    let allowed_port = allowed_listener
        .local_addr()
        .unwrap_or_else(|error| panic!("allowed addr: {error}"))
        .port();
    let denied_port = denied_listener
        .local_addr()
        .unwrap_or_else(|error| panic!("denied addr: {error}"))
        .port();
    assert_ne!(allowed_port, denied_port);

    let temp = TestDir::new("seatbelt");
    let profile_root = temp.0.join("profile");
    let download_root = temp.0.join("downloads");
    fs::create_dir(&profile_root).unwrap_or_else(|error| panic!("profile root: {error}"));
    fs::create_dir(&download_root).unwrap_or_else(|error| panic!("download root: {error}"));
    let request = BrowserIsolationRequest {
        profile_root: profile_root
            .canonicalize()
            .unwrap_or_else(|error| panic!("profile canonical: {error}")),
        download_root: Some(
            download_root
                .canonicalize()
                .unwrap_or_else(|error| panic!("download canonical: {error}")),
        ),
        loopback_capability: loopback_capability(allowed_port, b"seatbelt-token"),
        now_ms: 100,
    };
    let profile = MacBrowserSandboxExecBackend::build_profile(&request)
        .unwrap_or_else(|error| panic!("profile: {error}"));
    assert!(profile.contains("(deny network*)"));
    assert!(profile.contains(&format!(
        "(allow network-outbound (remote ip \"localhost:{allowed_port}\"))"
    )));
    assert!(!profile.contains(&format!("localhost:{denied_port}")));
    assert!(!profile.contains("(allow network*)"));
    assert!(!profile.contains("remote ip \"localhost\")"));
    assert!(profile.contains("(allow file-write* (literal \"/dev/null\"))"));
    assert!(profile.contains("com.google.Chrome."));
    assert!(profile.contains("(allow network-bind (prefix "));
    assert!(!profile.contains("(allow network-bind)"));

    let isolated = backend
        .isolate(Path::new("/usr/bin/true"), &[], &request)
        .unwrap_or_else(|error| panic!("isolate: {error}"));
    assert_eq!(isolated.executable, backend.sandbox_exec_path());
    assert_eq!(isolated.args.first().map(String::as_str), Some("-p"));

    let exact = sandbox_connect_status(
        backend.sandbox_exec_path(),
        &profile,
        "127.0.0.1",
        allowed_port,
    );
    let sibling = sandbox_connect_status(
        backend.sandbox_exec_path(),
        &profile,
        "127.0.0.1",
        denied_port,
    );
    let private = sandbox_connect_status(backend.sandbox_exec_path(), &profile, "192.168.0.1", 9);
    let public = sandbox_connect_status(backend.sandbox_exec_path(), &profile, "1.1.1.1", 80);
    assert!(exact.success());
    assert!(!sibling.success());
    assert!(!private.success());
    assert!(!public.success());

    let inside_profile = request.profile_root.join("profile-write");
    let inside_download = request
        .download_root
        .as_ref()
        .unwrap_or_else(|| panic!("download root"))
        .join("download-write");
    let outside = temp.0.join("outside-write");
    assert!(sandbox_touch_status(backend.sandbox_exec_path(), &profile, &inside_profile).success());
    assert!(
        sandbox_touch_status(backend.sandbox_exec_path(), &profile, &inside_download).success()
    );
    assert!(!sandbox_touch_status(backend.sandbox_exec_path(), &profile, &outside).success());
}

#[cfg(target_os = "macos")]
fn sandbox_connect_status(
    sandbox_exec: &Path,
    profile: &str,
    host: &str,
    port: u16,
) -> std::process::ExitStatus {
    let probe = format!(
        "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.settimeout(0.4); s.connect(({host:?},{port}))"
    );
    Command::new(sandbox_exec)
        .args(["-p", profile, "/usr/bin/python3", "-c", &probe])
        .env_clear()
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap_or_else(|error| panic!("network probe: {error}"))
}

#[cfg(target_os = "macos")]
fn sandbox_read_status(
    sandbox_exec: &Path,
    profile: &str,
    path: &Path,
) -> std::process::ExitStatus {
    Command::new(sandbox_exec)
        .args(["-p", profile, "/bin/cat"])
        .arg(path)
        .env_clear()
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap_or_else(|error| panic!("read probe: {error}"))
}

#[cfg(target_os = "macos")]
fn sandbox_touch_status(
    sandbox_exec: &Path,
    profile: &str,
    path: &Path,
) -> std::process::ExitStatus {
    Command::new(sandbox_exec)
        .args(["-p", profile, "/usr/bin/touch"])
        .arg(path)
        .env_clear()
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap_or_else(|error| panic!("touch probe: {error}"))
}

#[test]
fn browser_policy_error_is_human_readable_without_exposing_token_value() {
    let error = BrowserPolicyError::Denied("fixture".to_owned());
    assert_eq!(error.to_string(), "browser policy denied: fixture");
}
