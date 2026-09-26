use sovereign_policy::{
    Capability, CapabilityLayers, CapabilitySet, CheckpointIntegrityFloor, CommandMode,
    CommandPolicy, CommandRisk, CommandSpec, ExecutionIsolationBackend, HeavyLeaseClass,
    HostPressureSnapshot, IsolationRequest, M1ResourceGovernor, MacSandboxExecBackend,
    MinimalNetworkPolicy, MinimalResourceLeaseAuthority, ModelCallBudget, NetworkDestination,
    PathPolicy, PermissionDecision, PinnedExecutable, PolicyViolationDecision,
    PolicyViolationEvidence, PolicyViolationKind, PressureBand, ProtectedPolicyEffect,
    ResourceGovernor, TRUST_LABEL_SCHEMA_VERSION, TaskCapabilityGrant, TrustLabel, TrustLevel,
    TrustSource, sanitized_environment,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

struct TestDir(PathBuf);

impl TestDir {
    fn under(base: &Path, label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let path = base.join(format!(
            "sovereign-policy-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap_or_else(|error| panic!("create test dir: {error}"));
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn direct_spec(executable: impl Into<PathBuf>, args: &[&str]) -> CommandSpec {
    CommandSpec {
        executable: executable.into(),
        args: args.iter().map(|value| (*value).to_owned()).collect(),
        working_directory: std::env::current_dir().unwrap_or_else(|error| panic!("cwd: {error}")),
        environment: BTreeMap::new(),
        mode: CommandMode::Direct,
        declared_risk: CommandRisk::ReadOnly,
        timeout_ms: 1_000,
        output_limit_bytes: 16 * 1024,
        disk_write_limit_bytes: 16 * 1024,
        subprocess_limit: 2,
    }
}

fn test_digest(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

#[test]
fn canonical_plan_ir_capability_mapping_covers_all_twelve_values() {
    let expected = [
        (Capability::Read, "read"),
        (Capability::SandboxWrite, "sandbox_write"),
        (Capability::RepositoryWrite, "repo_write"),
        (Capability::ProcessExec, "process_exec"),
        (Capability::PackageInstall, "package_install"),
        (Capability::NetworkRead, "network_read"),
        (Capability::NetworkWrite, "network_write"),
        (Capability::BrowserInteractive, "browser_interactive"),
        (Capability::SecretUse, "secret_use"),
        (Capability::ExternalSideEffect, "external_side_effect"),
        (Capability::ExternalIntelligence, "external_intelligence"),
        (Capability::Destructive, "destructive"),
    ];
    assert_eq!(Capability::ALL.len(), expected.len());
    for (capability, wire_name) in expected {
        assert_eq!(capability.as_plan_ir_str(), wire_name);
        assert_eq!(Capability::from_plan_ir_str(wire_name), Some(capability));
    }
    assert_eq!(Capability::from_plan_ir_str("repository_write"), None);
}

#[test]
fn trust_labels_reject_self_promotion_and_violation_evidence_is_denial_only() {
    let source = TrustLabel::untrusted(TrustSource::Source)
        .unwrap_or_else(|error| panic!("source label: {error}"));
    assert!(source.is_untrusted());
    assert!(source.validate().is_ok());
    assert!(TrustLabel::untrusted(TrustSource::Controller).is_err());
    let forged = TrustLabel {
        schema_version: TRUST_LABEL_SCHEMA_VERSION,
        source: TrustSource::Source,
        level: TrustLevel::Governed,
    };
    assert!(forged.validate().is_err());

    let denial = PolicyViolationEvidence::denied(
        "violation.fixture",
        PolicyViolationKind::CapabilitySelfGrant,
        "evidence.fixture",
        test_digest('1'),
        source,
        ProtectedPolicyEffect::CapabilitySet,
        ["network_write".to_owned()],
        test_digest('2'),
        Some(test_digest('3')),
        "untrusted_source_cannot_grant_network",
    )
    .unwrap_or_else(|error| panic!("denial evidence: {error}"));
    assert_eq!(denial.decision, PolicyViolationDecision::Denied);
    assert!(denial.validate().is_ok());
    assert!(
        PolicyViolationEvidence::denied(
            "violation.unknown-capability",
            PolicyViolationKind::CapabilitySelfGrant,
            "evidence.fixture",
            test_digest('4'),
            source,
            ProtectedPolicyEffect::CapabilitySet,
            ["invented_superuser".to_owned()],
            test_digest('5'),
            None,
            "unknown_capability_rejected",
        )
        .is_err()
    );
}

#[test]
fn capability_set_and_permission_decision_digests_are_deterministic() {
    let first = CapabilitySet::new([
        Capability::ProcessExec,
        Capability::Read,
        Capability::RepositoryWrite,
    ]);
    let reordered = CapabilitySet::new([
        Capability::RepositoryWrite,
        Capability::ProcessExec,
        Capability::Read,
        Capability::Read,
    ]);
    assert_eq!(first, reordered);
    assert_eq!(first.digest(), reordered.digest());

    let layers = CapabilityLayers {
        global: CapabilitySet::all(),
        project: first.clone(),
        task: CapabilitySet::new([Capability::Read, Capability::RepositoryWrite]),
        role: CapabilitySet::all(),
        tool: CapabilitySet::new([
            Capability::Read,
            Capability::RepositoryWrite,
            Capability::ProcessExec,
        ]),
        user: CapabilitySet::all(),
    };
    let decision = PermissionDecision::new(
        "plan-a",
        7,
        "task-a",
        test_digest('a'),
        test_digest('b'),
        "tool-a",
        "1",
        test_digest('c'),
        layers.clone(),
    )
    .unwrap_or_else(|error| panic!("decision: {error}"));
    let same = PermissionDecision::new(
        "plan-a",
        7,
        "task-a",
        test_digest('a'),
        test_digest('b'),
        "tool-a",
        "1",
        test_digest('c'),
        layers,
    )
    .unwrap_or_else(|error| panic!("same decision: {error}"));
    assert_eq!(decision.digest(), same.digest());
    assert_eq!(
        decision.effective,
        CapabilitySet::new([Capability::Read, Capability::RepositoryWrite])
    );
}

#[test]
fn task_capability_grant_rejects_sibling_and_stale_task_scope() {
    let task_contract_digest = test_digest('d');
    let grant = TaskCapabilityGrant {
        plan_id: "plan-a".to_owned(),
        plan_revision: 3,
        task_id: "task-a".to_owned(),
        task_contract_digest: task_contract_digest.clone(),
        policy_digest: test_digest('f'),
        issued_by: "user:test".to_owned(),
        capabilities: CapabilitySet::new([Capability::NetworkRead]),
    };
    assert!(
        grant
            .capabilities_for_scope(
                "plan-a",
                3,
                "task-a",
                &task_contract_digest,
                &test_digest('f')
            )
            .is_ok()
    );
    assert!(
        grant
            .capabilities_for_scope(
                "plan-a",
                3,
                "task-b",
                &task_contract_digest,
                &test_digest('f')
            )
            .is_err()
    );
    assert!(
        grant
            .capabilities_for_scope(
                "plan-a",
                4,
                "task-a",
                &task_contract_digest,
                &test_digest('f')
            )
            .is_err()
    );
    assert!(
        grant
            .capabilities_for_scope("plan-a", 3, "task-a", &test_digest('e'), &test_digest('f'))
            .is_err()
    );
    assert!(
        grant
            .capabilities_for_scope(
                "plan-a",
                3,
                "task-a",
                &task_contract_digest,
                &test_digest('e')
            )
            .is_err()
    );
}

#[test]
fn path_traversal_symlink_escape_and_protected_roots_are_denied() {
    let temp = TestDir::under(&std::env::temp_dir(), "paths");
    let repo = temp.0.join("repo");
    let outside = temp.0.join("outside");
    fs::create_dir_all(repo.join("protected")).unwrap_or_else(|error| panic!("repo: {error}"));
    fs::create_dir_all(&outside).unwrap_or_else(|error| panic!("outside: {error}"));
    fs::write(repo.join("ok.txt"), b"ok").unwrap_or_else(|error| panic!("write ok: {error}"));
    fs::write(outside.join("secret"), b"secret")
        .unwrap_or_else(|error| panic!("write secret: {error}"));
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, repo.join("escape"))
        .unwrap_or_else(|error| panic!("symlink: {error}"));

    let policy = PathPolicy::new(&repo, [repo.join("protected")])
        .unwrap_or_else(|error| panic!("path policy: {error}"));
    assert!(policy.authorize_existing("ok.txt").is_ok());
    assert!(policy.authorize_existing("../outside/secret").is_err());
    #[cfg(unix)]
    assert!(policy.authorize_existing("escape/secret").is_err());
    assert!(policy.authorize_create("protected/new.txt").is_err());
}

#[test]
fn inherited_sensitive_environment_is_absent_unless_individually_authorized() {
    let requested = BTreeMap::from([
        ("PATH".to_owned(), "/usr/bin:/bin".to_owned()),
        ("HTTP_PROXY".to_owned(), "http://proxy.invalid".to_owned()),
        ("AWS_SECRET_ACCESS_KEY".to_owned(), "secret".to_owned()),
    ]);
    assert!(sanitized_environment(&requested, &BTreeSet::new()).is_err());

    let requested = BTreeMap::from([("LANG".to_owned(), "C".to_owned())]);
    let actual = sanitized_environment(&requested, &BTreeSet::new())
        .unwrap_or_else(|error| panic!("sanitize LANG: {error}"));
    assert_eq!(actual.len(), 1);
    assert!(!actual.contains_key("HOME"));
    assert!(!actual.contains_key("HTTP_PROXY"));
    assert!(
        sanitized_environment(
            &BTreeMap::from([("PATH".to_owned(), "/tmp/repo-shim".to_owned())]),
            &BTreeSet::new(),
        )
        .is_err()
    );
    assert!(
        sanitized_environment(
            &BTreeMap::from([("PATH".to_owned(), "/tmp/repo-shim".to_owned())]),
            &BTreeSet::from(["PATH".to_owned()]),
        )
        .is_err()
    );
}

#[test]
fn pinned_executable_cannot_be_replaced_by_path_or_repository_shim() {
    let echo = PinnedExecutable::from_path("/bin/echo", "macos-system")
        .unwrap_or_else(|error| panic!("pin echo: {error}"));
    let root = echo
        .path
        .parent()
        .unwrap_or_else(|| panic!("echo parent"))
        .to_path_buf();
    let policy = CommandPolicy::new([echo.clone()], [root])
        .unwrap_or_else(|error| panic!("command policy: {error}"));
    assert!(
        policy
            .authorize(&direct_spec(&echo.path, &["hello"]))
            .is_ok()
    );

    let temp = TestDir::under(&std::env::temp_dir(), "shim");
    let shim = temp.0.join("echo");
    fs::write(&shim, b"#!/bin/sh\necho shim\n").unwrap_or_else(|error| panic!("shim: {error}"));
    assert!(policy.authorize(&direct_spec(&shim, &["hello"])).is_err());
}

#[test]
fn shell_package_and_destructive_risk_floors_cannot_be_downgraded() {
    let sh = PinnedExecutable::from_path("/bin/sh", "macos-system")
        .unwrap_or_else(|error| panic!("pin sh: {error}"));
    let git = PinnedExecutable::from_path("/usr/bin/git", "macos-system")
        .unwrap_or_else(|error| panic!("pin git: {error}"));
    let policy = CommandPolicy::new(
        [sh.clone(), git.clone()],
        [
            sh.path
                .parent()
                .unwrap_or_else(|| panic!("sh parent"))
                .to_path_buf(),
            git.path
                .parent()
                .unwrap_or_else(|| panic!("git parent"))
                .to_path_buf(),
        ],
    )
    .unwrap_or_else(|error| panic!("policy: {error}"));

    assert!(
        policy
            .authorize(&direct_spec(&sh.path, &["-c", "echo ok; rm -rf /"]))
            .is_err()
    );
    assert!(
        policy
            .authorize(&direct_spec(&git.path, &["reset", "--hard", "HEAD"]))
            .is_err()
    );
}

#[test]
fn network_is_offline_by_default_and_exact_allowlist_is_enforced() {
    let mut policy = MinimalNetworkPolicy::offline();
    let allowed = NetworkDestination {
        scheme: "https".to_owned(),
        host: "example.com".to_owned(),
        port: 443,
    };
    assert!(policy.authorize(&allowed).is_err());
    policy
        .allow("HTTPS", "EXAMPLE.COM.", 443)
        .unwrap_or_else(|error| panic!("allow network: {error}"));
    assert!(policy.authorize(&allowed).is_ok());
    assert!(
        policy
            .authorize(&NetworkDestination {
                scheme: "https".to_owned(),
                host: "other.example".to_owned(),
                port: 443,
            })
            .is_err()
    );
}

#[test]
fn model_and_build_heavy_leases_serialize_and_second_model_is_denied() {
    let mut authority = MinimalResourceLeaseAuthority::default();
    let model = authority
        .acquire("model-a", HeavyLeaseClass::Model)
        .unwrap_or_else(|error| panic!("model lease: {error}"));
    assert!(
        authority
            .acquire("model-b", HeavyLeaseClass::Model)
            .is_err()
    );
    assert!(
        authority
            .acquire("build-a", HeavyLeaseClass::BuildHeavy)
            .is_err()
    );
    authority
        .release(&model)
        .unwrap_or_else(|error| panic!("release: {error}"));
    let build = authority
        .acquire("build-a", HeavyLeaseClass::BuildHeavy)
        .unwrap_or_else(|error| panic!("build lease: {error}"));
    assert_eq!(authority.active_count(), 1);
    authority
        .release(&build)
        .unwrap_or_else(|error| panic!("release: {error}"));
}

#[test]
fn live_pressure_overrides_nominal_heavy_lease_admission() {
    let green = HostPressureSnapshot {
        controlled_working_set_mib: 4_000,
        host_headroom_mib: 1_800,
        swap_out_growth_mib_per_min: 0,
        compressor_growth_mib_per_min: 0,
        os_pressure_warning: false,
        recent_pressure_event: false,
        thermal_serious: false,
    };
    assert_eq!(green.classify(), PressureBand::Green);

    let guarded = HostPressureSnapshot {
        swap_out_growth_mib_per_min: 64,
        ..green
    };
    assert_eq!(guarded.classify(), PressureBand::Guarded);

    let constrained = HostPressureSnapshot {
        swap_out_growth_mib_per_min: 300,
        ..green
    };
    assert_eq!(constrained.classify(), PressureBand::Constrained);

    let mut governor = M1ResourceGovernor::default();
    assert!(
        governor
            .acquire(
                "model-pressure-denied".to_owned(),
                HeavyLeaseClass::Model,
                constrained
            )
            .is_err()
    );
    let lease = governor
        .acquire("model-green".to_owned(), HeavyLeaseClass::Model, green)
        .unwrap_or_else(|error| panic!("green model lease: {error}"));
    assert!(
        governor
            .acquire(
                "build-overlap".to_owned(),
                HeavyLeaseClass::BuildHeavy,
                green,
            )
            .is_err()
    );
    governor
        .release(&lease)
        .unwrap_or_else(|error| panic!("release: {error}"));
}

#[test]
fn checkpoint_floor_blocks_action_journal_sequence_mismatch() {
    assert!(
        CheckpointIntegrityFloor {
            latest_valid_checkpoint_action_sequence: 9,
            authoritative_action_sequence: 9,
        }
        .admit_mutation()
        .is_ok()
    );
    assert!(
        CheckpointIntegrityFloor {
            latest_valid_checkpoint_action_sequence: 8,
            authoritative_action_sequence: 9,
        }
        .admit_mutation()
        .is_err()
    );
}

#[cfg(target_os = "macos")]
#[test]
fn mac_sandbox_denies_protected_home_read_and_offline_network() {
    let home = std::env::var_os("HOME").map_or_else(|| panic!("HOME"), PathBuf::from);
    let test_home = TestDir::under(&home, "seatbelt");
    let repo = test_home.0.join("repo");
    fs::create_dir_all(&repo).unwrap_or_else(|error| panic!("repo: {error}"));
    let repo_file = repo.join("inside.txt");
    let secret = test_home.0.join("secret.txt");
    let nested_protected = repo.join(".controller-secrets");
    fs::create_dir_all(&nested_protected)
        .unwrap_or_else(|error| panic!("nested protected: {error}"));
    let nested_secret = nested_protected.join("token.txt");
    fs::write(&repo_file, b"inside").unwrap_or_else(|error| panic!("inside: {error}"));
    fs::write(&secret, b"secret").unwrap_or_else(|error| panic!("secret: {error}"));
    fs::write(&nested_secret, b"nested-secret")
        .unwrap_or_else(|error| panic!("nested secret: {error}"));

    let backend =
        MacSandboxExecBackend::detect().unwrap_or_else(|error| panic!("sandbox: {error}"));
    let request = IsolationRequest {
        repository_root: repo.clone(),
        user_home_root: test_home.0.clone(),
        extra_protected_read_roots: vec![nested_protected.clone()],
        rust_toolchain: None,
        build_scratch_root: None,
        network_offline: true,
        allow_repository_write: true,
        require_full_filesystem_read_jail: false,
    };

    let inside = direct_spec(
        "/bin/cat",
        &[repo_file.to_str().unwrap_or_else(|| panic!("repo utf8"))],
    );
    let isolated = backend
        .isolate(&inside, &request)
        .unwrap_or_else(|error| panic!("isolate inside: {error}"));
    let status = Command::new(&isolated.executable)
        .args(&isolated.args)
        .status()
        .unwrap_or_else(|error| panic!("run inside: {error}"));
    assert!(status.success());

    let outside = direct_spec(
        "/bin/cat",
        &[secret.to_str().unwrap_or_else(|| panic!("secret utf8"))],
    );
    let isolated = backend
        .isolate(&outside, &request)
        .unwrap_or_else(|error| panic!("isolate secret: {error}"));
    let status = Command::new(&isolated.executable)
        .args(&isolated.args)
        .status()
        .unwrap_or_else(|error| panic!("run secret: {error}"));
    assert!(!status.success());

    let nested = direct_spec(
        "/bin/cat",
        &[nested_secret
            .to_str()
            .unwrap_or_else(|| panic!("nested secret utf8"))],
    );
    let isolated = backend
        .isolate(&nested, &request)
        .unwrap_or_else(|error| panic!("isolate nested secret: {error}"));
    let status = Command::new(&isolated.executable)
        .args(&isolated.args)
        .status()
        .unwrap_or_else(|error| panic!("run nested secret: {error}"));
    assert!(!status.success());

    let network = direct_spec(
        "/usr/bin/python3",
        &[
            "-c",
            "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(0.2); s.connect((\"1.1.1.1\", 53))",
        ],
    );
    let isolated = backend
        .isolate(&network, &request)
        .unwrap_or_else(|error| panic!("isolate network: {error}"));
    let status = Command::new(&isolated.executable)
        .args(&isolated.args)
        .status()
        .unwrap_or_else(|error| panic!("run network: {error}"));
    assert!(!status.success());

    let mut strict = request;
    strict.require_full_filesystem_read_jail = true;
    assert!(backend.isolate(&inside, &strict).is_err());

    let mut selective_network = strict;
    selective_network.require_full_filesystem_read_jail = false;
    selective_network.network_offline = false;
    assert!(backend.isolate(&inside, &selective_network).is_err());
}

#[cfg(target_os = "macos")]
#[test]
#[expect(
    clippy::expect_used,
    clippy::too_many_lines,
    reason = "security fixture checks each setup and output step explicitly"
)]
fn pinned_home_cargo_can_invoke_rustc_for_offline_verification() {
    let home = PathBuf::from(std::env::var_os("HOME").expect("HOME"));
    let rustup = home.join(".cargo/bin/rustup");
    if !rustup.is_file() {
        return;
    }
    let output = Command::new(&rustup)
        .args(["which", "cargo"])
        .output()
        .expect("resolve installed Cargo");
    assert!(output.status.success(), "installed Cargo is required");
    let cargo = PathBuf::from(
        String::from_utf8(output.stdout)
            .expect("Cargo path UTF-8")
            .trim(),
    )
    .canonicalize()
    .expect("canonical Cargo");
    if !cargo.starts_with(&home) {
        return;
    }
    let test_home = TestDir::under(&home, "cargo-seatbelt");
    let repo = test_home.0.join("repo");
    fs::create_dir_all(repo.join("src")).expect("create package");
    fs::write(
        repo.join("Cargo.toml"),
        "[package]\nname = \"seatbelt-probe\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .expect("manifest");
    fs::write(repo.join("src/lib.rs"), "pub fn ready() -> bool { true }\n").expect("source");
    let scratch = repo.join(".sovereign-build-test");
    fs::create_dir(&scratch).expect("build scratch");
    let lock_status = Command::new(&cargo)
        .args(["generate-lockfile", "--offline"])
        .current_dir(&repo)
        .status()
        .expect("generate fixture lockfile");
    assert!(
        lock_status.success(),
        "fixture lockfile must be prepared before sandboxing"
    );
    let lock_before = fs::read(repo.join("Cargo.lock")).expect("prepared lockfile");
    let backend = MacSandboxExecBackend::detect().expect("Seatbelt");
    let rustc = cargo.parent().expect("Cargo bin").join("rustc");
    let policy = CommandPolicy::new(
        [
            PinnedExecutable::from_path(&cargo, "test-cargo").expect("Cargo pin"),
            PinnedExecutable::from_path(&rustc, "test-rustc").expect("rustc pin"),
        ],
        [cargo.parent().expect("Cargo bin").to_path_buf()],
    )
    .expect("toolchain policy");
    let toolchain = sovereign_policy::RustToolchainAccess::from_policy(&policy, &cargo)
        .expect("exact Rust toolchain manifest");
    let request = IsolationRequest {
        repository_root: repo.clone(),
        user_home_root: home,
        extra_protected_read_roots: vec![],
        rust_toolchain: Some(toolchain),
        build_scratch_root: Some(scratch.clone()),
        network_offline: true,
        allow_repository_write: false,
        require_full_filesystem_read_jail: false,
    };
    let mut spec = direct_spec(&cargo, &["--offline", "test", "--no-run"]);
    spec.working_directory = repo.clone();
    let isolated = backend.isolate(&spec, &request).expect("isolate Cargo");
    let write_probe = Command::new(&isolated.executable)
        .args([
            "-p",
            &isolated.args[1],
            "/bin/sh",
            "-c",
            "printf ok > .sovereign-build-test/probe",
        ])
        .current_dir(&spec.working_directory)
        .output()
        .expect("probe isolated build output");
    assert!(
        write_probe.status.success(),
        "build output must be writable: {}",
        String::from_utf8_lossy(&write_probe.stderr)
    );
    let result = Command::new(&isolated.executable)
        .args(&isolated.args)
        .current_dir(&spec.working_directory)
        .env_clear()
        .env(
            "PATH",
            format!(
                "{}:/usr/bin:/bin",
                cargo.parent().expect("Cargo bin").display()
            ),
        )
        .env("CARGO_TARGET_DIR", &scratch)
        .env("TMPDIR", &scratch)
        .output()
        .expect("run isolated Cargo");
    assert!(
        result.status.success(),
        "offline Cargo verification must run pinned rustc: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        fs::read(repo.join("Cargo.lock")).expect("lockfile after Cargo"),
        lock_before
    );
    assert_eq!(
        fs::read(repo.join("src/lib.rs")).expect("source after Cargo"),
        b"pub fn ready() -> bool { true }\n"
    );
}

#[cfg(target_os = "macos")]
#[test]
#[expect(
    clippy::expect_used,
    clippy::too_many_lines,
    reason = "security fixture checks each setup and output step explicitly"
)]
fn rust_toolchain_access_rejects_drift_symlinks_and_unpinned_siblings() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let home = PathBuf::from(std::env::var_os("HOME").expect("HOME"));
    let fixture = TestDir::under(&home, "toolchain-security");
    let toolchain = fixture.0.join("toolchain");
    let bin = toolchain.join("bin");
    let lib = toolchain.join("lib");
    let repo = fixture.0.join("repo");
    fs::create_dir_all(&bin).expect("bin");
    fs::create_dir_all(&lib).expect("lib");
    fs::create_dir_all(&repo).expect("repo");
    let cargo = bin.join("cargo");
    let rustc = bin.join("rustc");
    let sibling = bin.join("rustdoc");
    for (path, contents) in [
        (&cargo, "#!/bin/sh\nexec /bin/sh \"$@\"\n"),
        (&rustc, "#!/bin/sh\nexit 0\n"),
        (&sibling, "#!/bin/sh\nexit 0\n"),
    ] {
        fs::write(path, contents).expect("test toolchain executable");
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("executable mode");
    }
    fs::write(lib.join("libstd.rlib"), b"checked library").expect("library");
    let secret = fixture.0.join("credentials.txt");
    fs::write(&secret, b"secret").expect("secret");

    let cargo_pin = PinnedExecutable::from_path(&cargo, "test-cargo").expect("Cargo pin");
    let missing_rustc = CommandPolicy::new([cargo_pin.clone()], [bin.clone()]).expect("policy");
    assert!(sovereign_policy::RustToolchainAccess::from_policy(&missing_rustc, &cargo).is_err());
    let policy = CommandPolicy::new(
        [
            cargo_pin,
            PinnedExecutable::from_path(&rustc, "test-rustc").expect("rustc pin"),
        ],
        [bin],
    )
    .expect("complete policy");
    let escape = lib.join("escape.rlib");
    symlink(&secret, &escape).expect("symlink escape fixture");
    assert!(sovereign_policy::RustToolchainAccess::from_policy(&policy, &cargo).is_err());
    fs::remove_file(&escape).expect("remove escape fixture");
    let access = sovereign_policy::RustToolchainAccess::from_policy(&policy, &cargo)
        .expect("exact manifest");
    let request = IsolationRequest {
        repository_root: repo.clone(),
        user_home_root: home.clone(),
        extra_protected_read_roots: vec![],
        rust_toolchain: Some(access.clone()),
        build_scratch_root: None,
        network_offline: true,
        allow_repository_write: false,
        require_full_filesystem_read_jail: false,
    };
    let backend = MacSandboxExecBackend::detect().expect("Seatbelt");
    for command in [
        sibling.display().to_string(),
        format!("/bin/cat {}", secret.display()),
        format!("/bin/ls {}", home.display()),
    ] {
        let mut spec = direct_spec(&cargo, &["-c", &command]);
        spec.working_directory = repo.clone();
        let isolated = backend
            .isolate(&spec, &request)
            .expect("isolate pinned Cargo");
        let result = Command::new(&isolated.executable)
            .args(&isolated.args)
            .current_dir(&repo)
            .output()
            .expect("execute denied operation");
        assert!(
            !result.status.success(),
            "toolchain sibling or protected home read escaped Seatbelt: {command}"
        );
    }
    let scratch = repo.join(".sovereign-build-test");
    fs::create_dir(&scratch).expect("exact build scratch");
    let source = repo.join("source.txt");
    fs::write(&source, b"source").expect("source fixture");
    let escape_link = scratch.join("escape.txt");
    symlink(&source, &escape_link).expect("scratch symlink escape");
    let mut scratch_request = request.clone();
    scratch_request.build_scratch_root = Some(scratch.clone());
    for unsafe_root in [&repo, &fixture.0] {
        let mut widened = scratch_request.clone();
        widened.build_scratch_root = Some(unsafe_root.clone());
        let mut spec = direct_spec(&cargo, &["-c", "true"]);
        spec.working_directory = repo.clone();
        assert!(
            backend.isolate(&spec, &widened).is_err(),
            "scratch root must not widen to {}",
            unsafe_root.display()
        );
    }
    for (command, permitted) in [
        (
            format!("printf ok > {}", scratch.join("output.txt").display()),
            true,
        ),
        (format!("printf no > {}", source.display()), false),
        (format!("printf no > {}", escape_link.display()), false),
    ] {
        let mut spec = direct_spec(&cargo, &["-c", &command]);
        spec.working_directory = repo.clone();
        let isolated = backend
            .isolate(&spec, &scratch_request)
            .expect("isolate scratch");
        let result = Command::new(&isolated.executable)
            .args(&isolated.args)
            .current_dir(&repo)
            .output()
            .expect("execute scratch probe");
        assert_eq!(
            result.status.success(),
            permitted,
            "scratch boundary: {command}; stderr={}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    assert_eq!(fs::read(&source).expect("source remains"), b"source");
    fs::write(lib.join("libstd.rlib"), b"changed library").expect("drift library");
    assert!(
        access.verify().is_err(),
        "library digest drift must fail closed"
    );
    let spec = direct_spec(&cargo, &["-c", "true"]);
    assert!(
        backend.isolate(&spec, &request).is_err(),
        "drift must fail before dispatch"
    );
}

#[test]
fn package_install_is_denied_without_task_grant() {
    let cargo_path = std::env::var_os("HOME")
        .map_or_else(|| panic!("HOME"), PathBuf::from)
        .join(".cargo/bin/cargo");
    let cargo = PinnedExecutable::from_path(&cargo_path, "test-toolchain")
        .unwrap_or_else(|error| panic!("pin cargo: {error}"));
    let root = cargo
        .path
        .parent()
        .unwrap_or_else(|| panic!("cargo parent"))
        .to_path_buf();
    let policy = CommandPolicy::new([cargo.clone()], [root])
        .unwrap_or_else(|error| panic!("command policy: {error}"));
    assert!(
        policy
            .authorize(&direct_spec(&cargo_path, &["install", "serde"]))
            .is_err()
    );
}

#[test]
fn model_timeout_consumes_outer_call_budget_without_hidden_retry() {
    let mut budget = ModelCallBudget::new(1, 5_000);
    budget
        .consume_call(5_000)
        .unwrap_or_else(|error| panic!("first call: {error}"));
    assert_eq!(budget.remaining_calls(), 0);
    assert!(budget.consume_call(5_000).is_err());
}
