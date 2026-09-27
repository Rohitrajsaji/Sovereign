//! Which build this is, and whether the running service or a source checkout is a different one.
//!
//! Callers: `serve` (records the running version), `launch_agent::open_ui` (restarts a service
//! left on another version), `sovereign app` (notices a source checkout with newer code), and
//! `/v2/session` (shows the version in Settings).
//! API: `BUILD_VERSION`, `write_service_version`, `service_needs_restart`,
//! `source_checkout_notice`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The commit this binary was built from, or `unknown` outside a Git checkout.
pub const BUILD_COMMIT: &str = env!("SOVEREIGN_BUILD_COMMIT");
/// The version shown to people and compared between the app and the service.
pub const BUILD_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    "+",
    env!("SOVEREIGN_BUILD_COMMIT")
);

const SERVICE_VERSION_FILE: &str = "service-version";
/// Written by `scripts/install-from-source.sh` under `~/.sovereign/`: the checkout it built.
const SOURCE_CHECKOUT_FILE: &str = "source-checkout";

/// Records the running service's version beside its session token.
///
/// # Errors
/// Returns when the file cannot be written.
pub fn write_service_version(app_data_root: &Path) -> io::Result<()> {
    fs::write(app_data_root.join(SERVICE_VERSION_FILE), BUILD_VERSION)
}

/// The version the running service recorded, if any. Services from before this file existed
/// record nothing.
#[must_use]
pub fn running_service_version(app_data_root: &Path) -> Option<String> {
    fs::read_to_string(app_data_root.join(SERVICE_VERSION_FILE))
        .ok()
        .map(|text| text.trim().to_owned())
        .filter(|text| !text.is_empty())
}

/// True when the service should be pointed at this binary: it runs a different (or unrecorded)
/// version, and this binary is the installed current one, so an old copy never downgrades it.
#[must_use]
pub fn service_needs_restart(running: Option<&str>, own: &str, is_current_install: bool) -> bool {
    is_current_install && running != Some(own)
}

/// True when `binary` is the installed current version under `home`.
#[must_use]
pub fn is_current_install(home: &Path, binary: &Path) -> bool {
    let current = home
        .join(".sovereign")
        .join("current")
        .join("bin")
        .join("sovereign");
    match (binary.canonicalize(), current.canonicalize()) {
        (Ok(binary), Ok(current)) => binary == current,
        _ => false,
    }
}

fn source_checkout(home: &Path) -> Option<PathBuf> {
    let path = fs::read_to_string(home.join(".sovereign").join(SOURCE_CHECKOUT_FILE)).ok()?;
    let path = PathBuf::from(path.trim());
    path.join(".git").exists().then_some(path)
}

fn checkout_commit(checkout: &Path) -> Option<String> {
    let output = Command::new("/usr/bin/git")
        .arg("-C")
        .arg(checkout)
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|commit| !commit.is_empty())
}

/// A plain notice when the checkout Sovereign was installed from now has different code.
#[must_use]
pub fn source_checkout_notice(home: &Path) -> Option<String> {
    let checkout = source_checkout(home)?;
    let commit = checkout_commit(&checkout)?;
    checkout_notice(&checkout, &commit, BUILD_COMMIT)
}

fn checkout_notice(checkout: &Path, checkout_commit: &str, built: &str) -> Option<String> {
    if built == "unknown"
        || checkout_commit.starts_with(built)
        || built.starts_with(checkout_commit)
    {
        return None;
    }
    Some(format!(
        "Your Sovereign folder has different code ({checkout_commit}) from the version that is running ({built}). To use it, run:\n  {}/scripts/install-from-source.sh",
        checkout.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_different_or_unrecorded_service_restarts_only_from_the_current_install() {
        assert!(service_needs_restart(Some("0.1.0+old"), "0.1.0+new", true));
        assert!(service_needs_restart(None, "0.1.0+new", true));
        assert!(!service_needs_restart(Some("0.1.0+new"), "0.1.0+new", true));
        // An old copy run by hand never restarts a newer service.
        assert!(!service_needs_restart(
            Some("0.1.0+new"),
            "0.1.0+old",
            false
        ));
    }

    #[test]
    fn a_checkout_on_other_code_says_how_to_install_it() {
        let checkout = Path::new("/Users/ana/Sovereign");
        let notice = checkout_notice(checkout, "05ad437", "65d07d9")
            .unwrap_or_else(|| panic!("a different commit needs a notice"));
        assert!(notice.contains("/Users/ana/Sovereign/scripts/install-from-source.sh"));
        assert!(checkout_notice(checkout, "65d07d9", "65d07d9").is_none());
        assert!(checkout_notice(checkout, "05ad437", "unknown").is_none());
    }

    #[test]
    fn the_service_version_round_trips() {
        let dir = std::env::temp_dir().join(format!(
            "sovereign-build-info-{}-{}",
            std::process::id(),
            crate::service_state::unix_millis()
        ));
        fs::create_dir_all(&dir).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(running_service_version(&dir), None);
        write_service_version(&dir).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            running_service_version(&dir).as_deref(),
            Some(BUILD_VERSION)
        );
        let _ = fs::remove_dir_all(dir);
    }
}
