#![cfg_attr(not(target_os = "macos"), allow(unused_imports, dead_code))]

use sovereign_policy::{
    Capability, CapabilitySet, CommandMode, CommandPolicy, CommandRisk, CommandSpec,
    ControllerSecretLocator, ExecutionIsolationBackend, FakeSecretProvider, IsolationCapability,
    IsolationRequest, MacOsKeychainProvider, MacSandboxExecBackend, PinnedExecutable,
    SECRET_REF_SCHEMA_VERSION, SecretBroker, SecretInjection, SecretProviderKind, SecretRef,
    SecretScope, sanitized_environment,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

struct TestDir(PathBuf);

impl TestDir {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "sovereign-secret-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap_or_else(|error| panic!("create temp: {error}"));
        Self(path)
    }

    #[cfg(target_os = "macos")]
    fn under_home(label: &str) -> Self {
        let home = std::env::var_os("HOME").map_or_else(|| panic!("HOME"), PathBuf::from);
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = home.join(format!(
            ".sovereign-secret-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap_or_else(|error| panic!("create home temp: {error}"));
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn digest(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

fn scope(action_id: &str) -> SecretScope {
    SecretScope {
        plan_id: "plan-secret".to_owned(),
        plan_revision: 7,
        task_id: "task-secret".to_owned(),
        task_contract_digest: digest('a'),
        action_id: action_id.to_owned(),
        permission_decision_digest: digest('b'),
        execution_epoch: 11,
    }
}

fn secret_ref(injection: SecretInjection) -> SecretRef {
    SecretRef {
        secret_ref_id: "secret.fixture.signing".to_owned(),
        provider: SecretProviderKind::ExternalBroker,
        purpose: "sign exact fixture payload".to_owned(),
        injection,
        target: "fixture-signer".to_owned(),
    }
}

fn broker_with_secret(injection: SecretInjection, value: &[u8]) -> (SecretBroker, SecretRef) {
    let secret_ref = secret_ref(injection);
    let mut broker = SecretBroker::new();
    broker
        .register_provider(Arc::new(FakeSecretProvider::new(
            SecretProviderKind::ExternalBroker,
            [("fixture-key".to_owned(), value.to_vec())],
        )))
        .unwrap_or_else(|error| panic!("register fake provider: {error}"));
    broker
        .register_secret(
            secret_ref.clone(),
            ControllerSecretLocator::FakeKey {
                provider: SecretProviderKind::ExternalBroker,
                key: "fixture-key".to_owned(),
            },
        )
        .unwrap_or_else(|error| panic!("register secret: {error}"));
    (broker, secret_ref)
}

#[test]
fn secret_ref_v1_serializes_handle_metadata_without_value_or_provider_locator() {
    let secret_ref = secret_ref(SecretInjection::AdapterHandle);
    assert_eq!(SECRET_REF_SCHEMA_VERSION, 1);
    let serialized = serde_json::to_value(&secret_ref)
        .unwrap_or_else(|error| panic!("serialize SecretRef: {error}"));
    assert_eq!(
        serialized,
        serde_json::json!({
            "secret_ref_id": "secret.fixture.signing",
            "provider": "external_broker",
            "purpose": "sign exact fixture payload",
            "injection": "adapter_handle",
            "target": "fixture-signer"
        })
    );
    let round_trip: SecretRef = serde_json::from_value(serialized)
        .unwrap_or_else(|error| panic!("deserialize frozen SecretRef shape: {error}"));
    assert_eq!(round_trip, secret_ref);
    let binding = secret_ref
        .binding_digest()
        .unwrap_or_else(|error| panic!("SecretRef binding digest: {error}"));
    assert!(binding.starts_with("sha256:"));
    for mutate in [
        |value: &mut SecretRef| value.secret_ref_id.push_str(".other"),
        |value: &mut SecretRef| value.provider = SecretProviderKind::Environment,
        |value: &mut SecretRef| value.purpose.push_str(" differently"),
        |value: &mut SecretRef| value.injection = SecretInjection::Stdin,
        |value: &mut SecretRef| value.target.push_str("-other"),
    ] {
        let mut changed = secret_ref.clone();
        mutate(&mut changed);
        assert_ne!(
            changed
                .binding_digest()
                .unwrap_or_else(|error| panic!("changed SecretRef binding: {error}")),
            binding
        );
    }
    assert!(
        serde_json::from_value::<SecretRef>(serde_json::json!({
            "schema_version": 1,
            "secret_ref_id": "secret.fixture.signing",
            "provider": "external_broker",
            "purpose": "sign exact fixture payload",
            "injection": "adapter_handle",
            "target": "fixture-signer"
        }))
        .is_err(),
        "frozen Plan IR secretRef forbids additional properties"
    );
}

#[test]
fn secret_unknown_repository_string_and_provider_lookup_cannot_resolve() {
    let (broker, registered) = broker_with_secret(SecretInjection::AdapterHandle, b"sentinel");
    let mut guessed = registered.clone();
    guessed.secret_ref_id = "repository-text-arbitrary-keychain-name".to_owned();
    assert!(
        broker
            .resolve(
                &guessed,
                scope("action-unknown"),
                &CapabilitySet::new([Capability::SecretUse]),
                100,
                200,
            )
            .is_err()
    );

    let mut mismatched = SecretBroker::new();
    mismatched
        .register_provider(Arc::new(MacOsKeychainProvider))
        .unwrap_or_else(|error| panic!("register keychain provider: {error}"));
    let mut keychain_ref = registered;
    keychain_ref.provider = SecretProviderKind::MacosKeychain;
    assert!(
        mismatched
            .register_secret(
                keychain_ref,
                ControllerSecretLocator::ExternalBrokerKey("repo-chosen-key".to_owned()),
            )
            .is_err()
    );
}

#[test]
fn secret_scope_expiry_and_secret_use_are_required_at_every_value_use() {
    let (broker, secret_ref) =
        broker_with_secret(SecretInjection::AdapterHandle, b"scope-sentinel");
    let exact_scope = scope("action-scope");
    assert!(
        broker
            .resolve(
                &secret_ref,
                exact_scope.clone(),
                &CapabilitySet::new([Capability::ProcessExec]),
                100,
                200,
            )
            .is_err()
    );
    assert!(
        broker
            .resolve(
                &secret_ref,
                exact_scope.clone(),
                &CapabilitySet::new([Capability::SecretUse]),
                200,
                200,
            )
            .is_err()
    );

    let mut lease = broker
        .resolve(
            &secret_ref,
            exact_scope.clone(),
            &CapabilitySet::new([Capability::SecretUse]),
            100,
            200,
        )
        .unwrap_or_else(|error| panic!("resolve: {error}"));
    let secret_use = CapabilitySet::new([Capability::SecretUse]);
    let no_secret_use = CapabilitySet::new([Capability::ProcessExec]);
    assert!(
        lease
            .with_value(&exact_scope, &no_secret_use, 150, |_| ())
            .is_err()
    );
    assert!(
        lease
            .with_value(&exact_scope, &secret_use, 150, |bytes| {
                bytes == b"scope-sentinel"
            })
            .unwrap_or(false)
    );
    let mut wrong_scope = exact_scope.clone();
    wrong_scope.action_id = "action-other".to_owned();
    assert!(
        lease
            .with_value(&wrong_scope, &secret_use, 150, |_| ())
            .is_err()
    );
    let mut stale_revision = exact_scope.clone();
    stale_revision.plan_revision += 1;
    assert!(
        lease
            .with_value(&stale_revision, &secret_use, 150, |_| ())
            .is_err()
    );
    let mut stale_contract = exact_scope.clone();
    stale_contract.task_contract_digest = digest('c');
    assert!(
        lease
            .with_value(&stale_contract, &secret_use, 150, |_| ())
            .is_err()
    );
    let mut stale_permission = exact_scope.clone();
    stale_permission.permission_decision_digest = digest('d');
    assert!(
        lease
            .with_value(&stale_permission, &secret_use, 150, |_| ())
            .is_err()
    );
    let mut stale_epoch = exact_scope.clone();
    stale_epoch.execution_epoch += 1;
    assert!(
        lease
            .with_value(&stale_epoch, &secret_use, 150, |_| ())
            .is_err()
    );
    assert!(
        lease
            .with_value(&exact_scope, &secret_use, 200, |_| ())
            .is_err()
    );
    lease
        .close(&exact_scope)
        .unwrap_or_else(|error| panic!("close expired lease safely: {error}"));
    assert!(lease.is_closed());
}

#[test]
fn secret_fake_resolve_debug_and_close_never_expose_or_reuse_value() {
    let sentinel = "never-print-this-secret";
    let (broker, secret_ref) =
        broker_with_secret(SecretInjection::AdapterHandle, sentinel.as_bytes());
    let exact_scope = scope("action-close");
    let mut lease = broker
        .resolve(
            &secret_ref,
            exact_scope.clone(),
            &CapabilitySet::new([Capability::SecretUse]),
            1_000,
            2_000,
        )
        .unwrap_or_else(|error| panic!("resolve: {error}"));
    assert!(!format!("{lease:?}").contains(sentinel));
    assert!(
        lease
            .with_value(
                &exact_scope,
                &CapabilitySet::new([Capability::SecretUse]),
                1_001,
                |bytes| bytes == sentinel.as_bytes(),
            )
            .unwrap_or(false)
    );
    lease
        .close(&exact_scope)
        .unwrap_or_else(|error| panic!("close: {error}"));
    assert!(
        lease
            .with_value(
                &exact_scope,
                &CapabilitySet::new([Capability::SecretUse]),
                1_002,
                |_| (),
            )
            .is_err()
    );
}

#[cfg(unix)]
#[test]
fn secret_temporary_file_is_private_task_action_scoped_and_absent_before_lease_close() {
    let temp = TestDir::new("temp-file");
    let private_root = temp.0.join("broker-private");
    let sentinel = b"temporary-secret-sentinel";
    let (broker, secret_ref) = broker_with_secret(SecretInjection::TemporaryFile, sentinel);
    let exact_scope = scope("action-temp");
    let mut lease = broker
        .resolve(
            &secret_ref,
            exact_scope.clone(),
            &CapabilitySet::new([Capability::SecretUse]),
            10,
            100,
        )
        .unwrap_or_else(|error| panic!("resolve: {error}"));
    let mut guard = lease
        .inject_temporary_file(
            &exact_scope,
            &CapabilitySet::new([Capability::SecretUse]),
            11,
            &private_root,
        )
        .unwrap_or_else(|error| panic!("inject temp: {error}"));
    let path = guard.path().to_path_buf();
    assert_eq!(fs::read(&path).unwrap_or_default(), sentinel);
    assert_eq!(
        fs::symlink_metadata(&path)
            .unwrap_or_else(|error| panic!("secret metadata: {error}"))
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        fs::symlink_metadata(path.parent().unwrap_or_else(|| panic!("secret parent")))
            .unwrap_or_else(|error| panic!("parent metadata: {error}"))
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let task_dir = path
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| panic!("task secret directory"));
    assert_eq!(
        fs::symlink_metadata(task_dir)
            .unwrap_or_else(|error| panic!("task metadata: {error}"))
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::symlink_metadata(&private_root)
            .unwrap_or_else(|error| panic!("private root metadata: {error}"))
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert!(lease.close(&exact_scope).is_err());
    guard
        .close()
        .unwrap_or_else(|error| panic!("explicit temp cleanup: {error}"));
    assert!(matches!(
        fs::symlink_metadata(&path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    ));
    lease
        .close(&exact_scope)
        .unwrap_or_else(|error| panic!("lease close after cleanup proof: {error}"));
}

#[test]
fn secret_ambient_credentials_remain_stripped_without_individual_authority() {
    for name in [
        "AWS_SECRET_ACCESS_KEY",
        "NPM_TOKEN",
        "SSH_AUTH_SOCK",
        "GIT_ASKPASS",
        "GOOGLE_APPLICATION_CREDENTIALS",
    ] {
        let requested = BTreeMap::from([(name.to_owned(), "ambient-secret".to_owned())]);
        assert!(
            sanitized_environment(&requested, &BTreeSet::new()).is_err(),
            "{name}"
        );
    }
}

#[cfg(target_os = "macos")]
#[test]
fn secret_generic_process_exec_cannot_invoke_security_directly_or_via_command_text() {
    let security = PinnedExecutable::from_path("/usr/bin/security", "macos-system")
        .unwrap_or_else(|error| panic!("pin security: {error}"));
    let security_root = security
        .path
        .parent()
        .unwrap_or_else(|| panic!("security parent"))
        .to_path_buf();
    let direct_policy = CommandPolicy::new([security.clone()], [security_root])
        .unwrap_or_else(|error| panic!("security policy: {error}"));
    assert!(
        direct_policy
            .authorize(&direct_spec(
                &security.path,
                &["find-generic-password", "-w", "-s", "repo-controlled"]
            ))
            .is_err()
    );

    let python = PinnedExecutable::from_path("/usr/bin/python3", "macos-system-python")
        .unwrap_or_else(|error| panic!("pin python: {error}"));
    let python_root = python
        .path
        .parent()
        .unwrap_or_else(|| panic!("python parent"))
        .to_path_buf();
    let transitive_policy = CommandPolicy::new([python.clone()], [python_root])
        .unwrap_or_else(|error| panic!("python policy: {error}"));
    let mut spec = direct_spec(
        &python.path,
        &[
            "-c",
            "import subprocess; subprocess.run(['/usr/bin/security','list-keychains'])",
        ],
    );
    spec.declared_risk = CommandRisk::UntrustedCode;
    assert!(transitive_policy.authorize(&spec).is_err());
}

#[cfg(target_os = "macos")]
#[test]
fn secret_macos_isolation_proves_security_process_and_securityd_lookup_denial() {
    let backend = MacSandboxExecBackend::detect()
        .unwrap_or_else(|error| panic!("secret-provider isolation proof: {error}"));
    assert!(
        backend
            .capabilities()
            .supports(IsolationCapability::SecretProviderDeny)
    );
    let temp = TestDir::under_home("seatbelt");
    let repo = temp.0.join("repo");
    fs::create_dir(&repo).unwrap_or_else(|error| panic!("repo: {error}"));
    let home = std::env::var_os("HOME").map_or_else(|| panic!("HOME"), PathBuf::from);
    let request = IsolationRequest {
        repository_root: repo.clone(),
        user_home_root: home,
        extra_protected_read_roots: Vec::new(),
        rust_toolchain: None,
        build_scratch_root: None,
        network_offline: true,
        allow_repository_write: false,
        require_full_filesystem_read_jail: false,
    };
    let spec = direct_spec(Path::new("/usr/bin/python3"), &["-c", "print('safe')"]);
    let isolated = backend
        .isolate(&spec, &request)
        .unwrap_or_else(|error| panic!("isolate: {error}"));
    let profile = isolated
        .args
        .get(1)
        .unwrap_or_else(|| panic!("sandbox profile"));
    assert!(profile.contains("deny process-exec"));
    assert!(profile.contains("/usr/bin/security"));
    assert!(profile.contains("deny mach-lookup"));
    assert!(profile.contains("com.apple.securityd"));
}

fn direct_spec(executable: &Path, args: &[&str]) -> CommandSpec {
    CommandSpec {
        executable: executable.to_path_buf(),
        args: args.iter().map(|value| (*value).to_owned()).collect(),
        working_directory: std::env::temp_dir(),
        environment: BTreeMap::new(),
        mode: CommandMode::Direct,
        declared_risk: CommandRisk::ReadOnly,
        timeout_ms: 1_000,
        output_limit_bytes: 4_096,
        disk_write_limit_bytes: 4_096,
        subprocess_limit: 0,
    }
}
