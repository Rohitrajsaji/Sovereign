use sovereign_policy::{
    ActiveRepositoryScope, CommandMode, CommandPolicy, CommandRisk, CommandSpec, GitConfigKeyClass,
    GitPolicy, NetworkDestination, NetworkPolicy, PathCommitMode, PathPolicy, PinnedExecutable,
    sanitized_environment,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

struct TestDir(PathBuf);

impl TestDir {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "sovereign-policy-security-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap_or_else(|error| panic!("create temp: {error}"));
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn command(executable: &Path, cwd: &Path, args: &[&str]) -> CommandSpec {
    CommandSpec {
        executable: executable.to_path_buf(),
        args: args.iter().map(|value| (*value).to_owned()).collect(),
        working_directory: cwd.to_path_buf(),
        environment: BTreeMap::new(),
        mode: CommandMode::Direct,
        declared_risk: CommandRisk::ReadOnly,
        timeout_ms: 1_000,
        output_limit_bytes: 16 * 1_024,
        disk_write_limit_bytes: 16 * 1_024,
        subprocess_limit: 2,
    }
}

#[test]
fn pinned_program_resolution_returns_unique_configured_basename() {
    let temp = TestDir::new("pinned-program-unique");
    let bin = temp.0.join("bin");
    fs::create_dir_all(&bin).unwrap_or_else(|error| panic!("bin: {error}"));
    let tool_path = bin.join("fixture-tool");
    fs::write(&tool_path, b"fixture executable").unwrap_or_else(|error| panic!("tool: {error}"));
    let pin = PinnedExecutable::from_path(&tool_path, "fixture-v1")
        .unwrap_or_else(|error| panic!("pin: {error}"));
    let expected_path = pin.path.clone();
    let expected_digest = pin.sha256.clone();
    let policy =
        CommandPolicy::new([pin], [bin]).unwrap_or_else(|error| panic!("command policy: {error}"));

    let resolved = policy
        .resolve_pinned_program("fixture-tool")
        .unwrap_or_else(|error| panic!("resolve: {error}"));
    assert_eq!(resolved.path, expected_path);
    assert_eq!(resolved.sha256, expected_digest);
}

#[test]
fn pinned_program_resolution_rejects_missing_basename() {
    let temp = TestDir::new("pinned-program-missing");
    let bin = temp.0.join("bin");
    fs::create_dir_all(&bin).unwrap_or_else(|error| panic!("bin: {error}"));
    let tool_path = bin.join("fixture-tool");
    fs::write(&tool_path, b"fixture executable").unwrap_or_else(|error| panic!("tool: {error}"));
    let pin = PinnedExecutable::from_path(&tool_path, "fixture-v1")
        .unwrap_or_else(|error| panic!("pin: {error}"));
    let policy =
        CommandPolicy::new([pin], [bin]).unwrap_or_else(|error| panic!("command policy: {error}"));

    assert!(policy.resolve_pinned_program("missing-tool").is_err());
    assert!(
        policy.resolve_pinned_program("sh").is_err(),
        "resolver must not fall back to ambient PATH"
    );
}

#[test]
fn pinned_program_resolution_rejects_ambiguous_basename() {
    let temp = TestDir::new("pinned-program-ambiguous");
    let left_bin = temp.0.join("left-bin");
    let right_bin = temp.0.join("right-bin");
    fs::create_dir_all(&left_bin).unwrap_or_else(|error| panic!("left bin: {error}"));
    fs::create_dir_all(&right_bin).unwrap_or_else(|error| panic!("right bin: {error}"));
    let left_path = left_bin.join("fixture-tool");
    let right_path = right_bin.join("fixture-tool");
    fs::write(&left_path, b"left executable").unwrap_or_else(|error| panic!("left tool: {error}"));
    fs::write(&right_path, b"right executable")
        .unwrap_or_else(|error| panic!("right tool: {error}"));
    let left = PinnedExecutable::from_path(&left_path, "left-v1")
        .unwrap_or_else(|error| panic!("left pin: {error}"));
    let right = PinnedExecutable::from_path(&right_path, "right-v1")
        .unwrap_or_else(|error| panic!("right pin: {error}"));
    let policy = CommandPolicy::new([left, right], [left_bin, right_bin])
        .unwrap_or_else(|error| panic!("command policy: {error}"));

    assert!(policy.resolve_pinned_program("fixture-tool").is_err());
}

#[test]
fn pinned_program_resolution_rejects_path_like_input() {
    let temp = TestDir::new("pinned-program-path-like");
    let bin = temp.0.join("bin");
    fs::create_dir_all(&bin).unwrap_or_else(|error| panic!("bin: {error}"));
    let tool_path = bin.join("fixture-tool");
    fs::write(&tool_path, b"fixture executable").unwrap_or_else(|error| panic!("tool: {error}"));
    let pin = PinnedExecutable::from_path(&tool_path, "fixture-v1")
        .unwrap_or_else(|error| panic!("pin: {error}"));
    let policy =
        CommandPolicy::new([pin], [bin]).unwrap_or_else(|error| panic!("command policy: {error}"));

    for program in [
        "./fixture-tool",
        "bin/fixture-tool",
        "bin\\fixture-tool",
        "C:fixture-tool",
        "/usr/bin/fixture-tool",
        ".",
        "..",
    ] {
        assert!(
            policy.resolve_pinned_program(program).is_err(),
            "path-like program must be denied: {program}"
        );
    }
}

#[test]
fn pinned_program_resolution_reverifies_digest_after_policy_construction() {
    let temp = TestDir::new("pinned-program-drift");
    let bin = temp.0.join("bin");
    fs::create_dir_all(&bin).unwrap_or_else(|error| panic!("bin: {error}"));
    let tool_path = bin.join("fixture-tool");
    fs::write(&tool_path, b"fixture executable").unwrap_or_else(|error| panic!("tool: {error}"));
    let pin = PinnedExecutable::from_path(&tool_path, "fixture-v1")
        .unwrap_or_else(|error| panic!("pin: {error}"));
    let policy =
        CommandPolicy::new([pin], [bin]).unwrap_or_else(|error| panic!("command policy: {error}"));

    fs::write(&tool_path, b"drifted executable")
        .unwrap_or_else(|error| panic!("drift tool: {error}"));
    assert!(policy.resolve_pinned_program("fixture-tool").is_err());
}

#[cfg(unix)]
#[test]
fn security_path_ticket_detects_swaps_and_hard_link_in_place_hazard() {
    use std::os::unix::fs::symlink;

    let temp = TestDir::new("path-ticket");
    let repo = temp.0.join("repo");
    let outside = temp.0.join("outside");
    fs::create_dir_all(repo.join("dir")).unwrap_or_else(|error| panic!("repo: {error}"));
    fs::create_dir_all(&outside).unwrap_or_else(|error| panic!("outside: {error}"));
    fs::write(repo.join("dir/file.txt"), b"inside")
        .unwrap_or_else(|error| panic!("inside: {error}"));
    fs::write(outside.join("secret.txt"), b"outside")
        .unwrap_or_else(|error| panic!("outside file: {error}"));

    let policy = PathPolicy::new(&repo, [repo.join(".controller")])
        .unwrap_or_else(|error| panic!("policy: {error}"));
    let ticket = policy
        .authorize_mutation("dir/file.txt")
        .unwrap_or_else(|error| panic!("ticket: {error}"));
    assert!(
        policy
            .revalidate_for_commit(&ticket, PathCommitMode::AtomicReplace)
            .is_ok()
    );

    fs::remove_file(repo.join("dir/file.txt")).unwrap_or_else(|error| panic!("remove: {error}"));
    symlink(outside.join("secret.txt"), repo.join("dir/file.txt"))
        .unwrap_or_else(|error| panic!("symlink swap: {error}"));
    assert!(
        policy
            .revalidate_for_commit(&ticket, PathCommitMode::AtomicReplace)
            .is_err()
    );

    fs::remove_file(repo.join("dir/file.txt"))
        .unwrap_or_else(|error| panic!("remove symlink: {error}"));
    fs::write(repo.join("dir/file.txt"), b"inside")
        .unwrap_or_else(|error| panic!("restore inside: {error}"));
    let parent_ticket = policy
        .authorize_mutation("dir/file.txt")
        .unwrap_or_else(|error| panic!("parent ticket: {error}"));
    fs::rename(repo.join("dir"), repo.join("dir-old"))
        .unwrap_or_else(|error| panic!("rename parent: {error}"));
    fs::create_dir(repo.join("dir")).unwrap_or_else(|error| panic!("new parent: {error}"));
    fs::write(repo.join("dir/file.txt"), b"replacement")
        .unwrap_or_else(|error| panic!("replacement: {error}"));
    assert!(
        policy
            .revalidate_for_commit(&parent_ticket, PathCommitMode::AtomicReplace)
            .is_err()
    );

    let hard_link = repo.join("hard.txt");
    fs::hard_link(outside.join("secret.txt"), &hard_link)
        .unwrap_or_else(|error| panic!("hard link: {error}"));
    let hard_ticket = policy
        .authorize_mutation("hard.txt")
        .unwrap_or_else(|error| panic!("hard ticket: {error}"));
    assert!(
        hard_ticket
            .target_link_count()
            .is_some_and(|count| count > 1)
    );
    assert!(
        policy
            .revalidate_for_commit(&hard_ticket, PathCommitMode::InPlace)
            .is_err()
    );
    let target = policy
        .revalidate_for_commit(&hard_ticket, PathCommitMode::AtomicReplace)
        .unwrap_or_else(|error| panic!("atomic replacement allowed: {error}"));
    let temporary = repo.join(".hard.tmp");
    fs::write(&temporary, b"new in-repo content")
        .unwrap_or_else(|error| panic!("temp write: {error}"));
    fs::rename(&temporary, &target).unwrap_or_else(|error| panic!("atomic rename: {error}"));
    assert_eq!(
        fs::read(outside.join("secret.txt"))
            .unwrap_or_else(|error| panic!("outside read: {error}")),
        b"outside"
    );
}

#[test]
fn security_repository_scope_denies_registered_sibling_outside_task_scope() {
    let scope = ActiveRepositoryScope::new(
        ["repo.primary".to_owned(), "repo.sibling".to_owned()],
        ["repo.primary".to_owned()],
    )
    .unwrap_or_else(|error| panic!("scope: {error}"));
    assert!(scope.authorize_write("repo.primary").is_ok());
    assert!(scope.authorize_write("repo.sibling").is_err());
    assert!(scope.authorize_write("repo.unknown").is_err());
}

#[test]
fn security_git_policy_denies_hidden_execution_remote_and_destructive_surfaces() {
    let policy = GitPolicy::deny_by_default();
    for key in [
        "core.hooksPath",
        "credential.helper",
        "core.fsmonitor",
        "filter.evil.smudge",
        "diff.evil.textconv",
        "alias.pwn",
        "remote.origin.url",
    ] {
        assert_ne!(
            GitPolicy::classify_local_config_key(key),
            GitConfigKeyClass::Safe,
            "{key}"
        );
        assert!(policy.authorize_local_config_key(key).is_err(), "{key}");
    }
    assert!(policy.authorize_local_config_key("core.ignorecase").is_ok());

    for args in [
        vec![
            "-c".to_owned(),
            "credential.helper=evil".to_owned(),
            "status".to_owned(),
        ],
        vec!["reset".to_owned(), "--hard".to_owned(), "HEAD".to_owned()],
        vec!["clean".to_owned(), "-fd".to_owned()],
        vec!["push".to_owned(), "--force".to_owned(), "origin".to_owned()],
        vec!["fetch".to_owned(), "origin".to_owned()],
        vec!["submodule".to_owned(), "update".to_owned()],
        vec!["lfs".to_owned(), "pull".to_owned()],
        vec!["credential".to_owned(), "fill".to_owned()],
        vec!["diff".to_owned(), "--ext-diff".to_owned()],
    ] {
        assert!(policy.authorize_args(&args).is_err(), "{args:?}");
    }
    assert!(
        policy
            .authorize_args(&["status".to_owned(), "--short".to_owned()])
            .is_ok()
    );
}

#[test]
fn security_environment_strips_git_ssh_loader_config_and_package_ambient_authority() {
    for name in [
        "GIT_ASKPASS",
        "SSH_ASKPASS",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_KEY_0",
        "GIT_CONFIG_VALUE_0",
        "HOME",
        "XDG_CONFIG_HOME",
        "LD_LIBRARY_PATH",
        "DYLD_FRAMEWORK_PATH",
        "NPM_CONFIG_USERCONFIG",
        "PIP_CONFIG_FILE",
        "CARGO_HOME",
        "GRADLE_USER_HOME",
    ] {
        let requested = BTreeMap::from([(name.to_owned(), "attacker".to_owned())]);
        assert!(
            sanitized_environment(&requested, &BTreeSet::new()).is_err(),
            "{name}"
        );
    }

    let path = BTreeMap::from([("PATH".to_owned(), "/tmp/repo-shim".to_owned())]);
    assert!(
        sanitized_environment(&path, &BTreeSet::from(["PATH".to_owned()])).is_err(),
        "PATH must remain Controller-owned even when individually requested"
    );

    let git_askpass = BTreeMap::from([("GIT_ASKPASS".to_owned(), "/safe/helper".to_owned())]);
    assert!(
        sanitized_environment(&git_askpass, &BTreeSet::from(["GIT_ASKPASS".to_owned()])).is_ok(),
        "non-PATH ambient channels may only return through exact individual authority"
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn security_package_policy_requires_local_target_denies_global_and_defaults_scripts_off() {
    let temp = TestDir::new("package");
    let project = temp.0.join("project");
    let bin = temp.0.join("bin");
    fs::create_dir_all(project.join("vendor")).unwrap_or_else(|error| panic!("project: {error}"));
    fs::create_dir_all(&bin).unwrap_or_else(|error| panic!("bin: {error}"));
    let npm_path = bin.join("npm");
    let pip_path = bin.join("pip");
    fs::write(&npm_path, b"npm fixture").unwrap_or_else(|error| panic!("npm: {error}"));
    fs::write(&pip_path, b"pip fixture").unwrap_or_else(|error| panic!("pip: {error}"));
    let npm = PinnedExecutable::from_path(&npm_path, "fixture")
        .unwrap_or_else(|error| panic!("pin npm: {error}"));
    let pip = PinnedExecutable::from_path(&pip_path, "fixture")
        .unwrap_or_else(|error| panic!("pin pip: {error}"));

    let mut policy = CommandPolicy::new([npm, pip], [bin])
        .unwrap_or_else(|error| panic!("command policy: {error}"));
    policy.allow_package_install = true;
    assert!(
        policy
            .authorize(&command(
                &npm_path,
                &project,
                &["install", "left-pad", "--ignore-scripts"]
            ))
            .is_err(),
        "package grant without explicit local root must fail closed"
    );

    policy
        .allow_project_local_package_install(&project)
        .unwrap_or_else(|error| panic!("local package root: {error}"));
    assert!(
        policy
            .authorize(&command(
                &npm_path,
                &project,
                &["install", "left-pad", "-g"]
            ))
            .is_err()
    );
    assert!(
        policy
            .authorize(&command(&npm_path, &project, &["install", "left-pad"]))
            .is_err(),
        "lifecycle scripts must be suppressed by default"
    );
    assert!(
        policy
            .authorize(&command(
                &npm_path,
                &project,
                &["install", "left-pad", "--ignore-scripts"],
            ))
            .is_ok()
    );
    assert!(
        policy
            .authorize(&command(
                &npm_path,
                &project,
                &[
                    "install",
                    "left-pad",
                    "--ignore-scripts",
                    "--prefix",
                    "../outside"
                ],
            ))
            .is_err(),
        "package-manager target flags cannot redirect outside the explicit project root"
    );
    assert!(
        policy
            .authorize(&command(
                &pip_path,
                &project,
                &[
                    "install",
                    "pkg",
                    "--target",
                    "../outside",
                    "--only-binary=:all:"
                ],
            ))
            .is_err(),
        "package target must stay under explicit project root"
    );
    assert!(
        policy
            .authorize(&command(
                &pip_path,
                &project,
                &[
                    "install",
                    "pkg",
                    "--target",
                    "vendor",
                    "--only-binary=:all:"
                ],
            ))
            .is_ok()
    );

    policy.allow_package_lifecycle_scripts = true;
    assert!(
        policy
            .authorize(&command(&npm_path, &project, &["install", "left-pad"]))
            .is_ok(),
        "explicit lifecycle authority changes policy only; execution remains a normal sandboxed command"
    );
}

#[test]
fn security_network_policy_rejects_private_rebinding_redirect_and_peer_mismatch() {
    let mut policy = NetworkPolicy::offline();
    policy
        .allow("https", "example.com", 443)
        .unwrap_or_else(|error| panic!("allow example: {error}"));
    policy
        .allow("https", "redirect.example", 443)
        .unwrap_or_else(|error| panic!("allow redirect: {error}"));
    let destination = NetworkDestination {
        scheme: "https".to_owned(),
        host: "example.com".to_owned(),
        port: 443,
    };
    let public = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
    let alternate = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 35));
    let authorization = policy
        .authorize_resolved(&destination, [public])
        .unwrap_or_else(|error| panic!("authorize public: {error}"));
    assert!(
        policy
            .authorize_connected_peer(&authorization, public)
            .is_ok()
    );
    assert!(
        policy
            .authorize_connected_peer(&authorization, alternate)
            .is_err(),
        "actual peer must match the authorized DNS set"
    );
    assert!(
        policy
            .authorize_resolved(&destination, [IpAddr::V4(Ipv4Addr::LOCALHOST)])
            .is_err()
    );
    assert!(
        policy
            .authorize_resolved(&destination, [IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))])
            .is_err()
    );
    assert!(
        policy
            .authorize_resolved(
                &destination,
                [IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))],
            )
            .is_err()
    );

    let redirect = NetworkDestination {
        scheme: "https".to_owned(),
        host: "redirect.example".to_owned(),
        port: 443,
    };
    assert!(
        policy
            .authorize_redirect(&redirect, [IpAddr::V4(Ipv4Addr::new(192, 168, 1, 4))])
            .is_err()
    );
    let not_allowlisted = NetworkDestination {
        scheme: "https".to_owned(),
        host: "other.example".to_owned(),
        port: 443,
    };
    assert!(
        policy
            .authorize_redirect(&not_allowlisted, [public])
            .is_err()
    );
    assert!(policy.allow("http", "127.0.0.1", 80).is_err());
    assert!(
        policy
            .allow("http", "metadata.google.internal", 80)
            .is_err()
    );
}
