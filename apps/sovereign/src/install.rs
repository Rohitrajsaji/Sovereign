//! Installing, updating, and removing Sovereign on a Mac.
//!
//! Callers: `main.rs` (`sovereign self-install`, `sovereign update`, `sovereign uninstall`),
//! `install.sh` (runs `self-install` from the version it unpacked).
//! API: `self_install`, `update`, `uninstall`, `InstallLayout`, `RELEASE_ASSET`.
//!
//! Layout, all under the person's home directory and never inside a project:
//! - `~/.sovereign/versions/<version>/` holds `bin/sovereign`, `libexec/llama/`, and `VERSION`;
//! - `~/.sovereign/current` points at the version in use, switched with an atomic rename;
//! - `~/.local/bin/sovereign` points at `~/.sovereign/current/bin/sovereign`;
//! - `~/Applications/Sovereign.app` opens Sovereign from Spotlight, Launchpad, or the Dock.
//!
//! Updates download the release tarball and its `SHA256SUMS` over HTTPS with `/usr/bin/curl`,
//! refuse a tarball whose checksum does not match, and hand over to the new version's own
//! `self-install`. Uninstall never deletes project folders.

use crate::app_data::AppData;
use crate::launch_agent;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{BufRead, Read, Write};
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const RELEASE_ASSET: &str = "sovereign-macos-arm64.tar.gz";
const RELEASE_ROOT_DIR: &str = "sovereign-macos-arm64";
const DEFAULT_RELEASE_BASE: &str =
    "https://github.com/Rohitrajsaji/Sovereign/releases/latest/download";
const RELEASE_BASE_ENV: &str = "SOVEREIGN_RELEASE_BASE_URL";
const KEEP_VERSIONS: usize = 2;

/// Where an installed Sovereign lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallLayout {
    pub home: PathBuf,
}

impl InstallLayout {
    /// The layout under `$HOME`.
    ///
    /// # Errors
    /// Returns when `HOME` is not set.
    pub fn from_env() -> Result<Self, String> {
        std::env::var_os("HOME")
            .map(|home| Self {
                home: PathBuf::from(home),
            })
            .ok_or_else(|| "HOME is not set".to_owned())
    }

    fn root(&self) -> PathBuf {
        self.home.join(".sovereign")
    }

    fn versions(&self) -> PathBuf {
        self.root().join("versions")
    }

    fn current(&self) -> PathBuf {
        self.root().join("current")
    }

    fn downloads(&self) -> PathBuf {
        self.root().join("downloads")
    }

    fn command_link(&self) -> PathBuf {
        self.home.join(".local").join("bin").join("sovereign")
    }

    fn current_binary(&self) -> PathBuf {
        self.current().join("bin").join("sovereign")
    }

    fn app_bundle(&self) -> PathBuf {
        self.home.join("Applications").join("Sovereign.app")
    }
}

const LAUNCHER_EXECUTABLE: &str = "sovereign-launcher";

fn launcher_info_plist(version: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>Sovereign</string>
  <key>CFBundleDisplayName</key><string>Sovereign</string>
  <key>CFBundleIdentifier</key><string>dev.sovereign.launcher</string>
  <key>CFBundleExecutable</key><string>{LAUNCHER_EXECUTABLE}</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>{version}</string>
  <key>LSMinimumSystemVersion</key><string>12.0</string>
  <key>LSUIElement</key><true/>
</dict>
</plist>
"#
    )
}

/// Writes `~/Applications/Sovereign.app`, which opens Sovereign with a fresh one-time link, so
/// nobody needs Terminal after installing. It is made on this Mac, so Gatekeeper never
/// quarantines it.
fn write_app_launcher(layout: &InstallLayout, version: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let contents = layout.app_bundle().join("Contents");
    let macos = contents.join("MacOS");
    fs::create_dir_all(&macos).map_err(|error| error.to_string())?;
    fs::write(contents.join("Info.plist"), launcher_info_plist(version))
        .map_err(|error| error.to_string())?;
    let launcher = macos.join(LAUNCHER_EXECUTABLE);
    fs::write(
        &launcher,
        format!(
            "#!/bin/sh\n# Opens Sovereign in the browser with a fresh one-time link.\nexec \"{}\" app\n",
            layout.current_binary().display()
        ),
    )
    .map_err(|error| error.to_string())?;
    fs::set_permissions(&launcher, fs::Permissions::from_mode(0o755))
        .map_err(|error| error.to_string())
}

fn valid_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= 64
        && !version.starts_with('.')
        && version
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
}

/// Points `link` at `target` by renaming a fresh symlink over it, so readers never see it missing.
fn replace_symlink(target: &Path, link: &Path) -> Result<(), String> {
    let parent = link
        .parent()
        .ok_or_else(|| format!("{} has no parent folder", link.display()))?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let file_name = link
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("{} has no name", link.display()))?;
    let temporary = parent.join(format!(".{file_name}.{}.tmp", std::process::id()));
    let _ = fs::remove_file(&temporary);
    symlink(target, &temporary).map_err(|error| error.to_string())?;
    fs::rename(&temporary, link).map_err(|error| {
        let _ = fs::remove_file(&temporary);
        error.to_string()
    })
}

/// The version folder this binary runs from, when it is an installed version.
fn own_version_dir(layout: &InstallLayout) -> Result<PathBuf, String> {
    let executable = std::env::current_exe()
        .and_then(|path| path.canonicalize())
        .map_err(|error| error.to_string())?;
    let version_dir = executable
        .parent()
        .and_then(Path::parent)
        .ok_or("the sovereign binary is not inside a version folder")?
        .to_path_buf();
    let versions = layout
        .versions()
        .canonicalize()
        .map_err(|_| "Sovereign is not installed under ~/.sovereign/versions".to_owned())?;
    if version_dir.parent() != Some(versions.as_path()) {
        return Err(format!(
            "self-install runs from ~/.sovereign/versions/<version>/bin/sovereign, not {}",
            executable.display()
        ));
    }
    Ok(version_dir)
}

/// Keeps the version in use and the one before it; removes older versions.
fn prune_versions(layout: &InstallLayout, keep: &Path) {
    let Ok(entries) = fs::read_dir(layout.versions()) else {
        return;
    };
    let mut versions = entries
        .flatten()
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .filter(|entry| !entry.file_name().to_string_lossy().starts_with('.'))
        .filter_map(|entry| {
            let modified = entry.metadata().ok()?.modified().ok()?;
            Some((modified, entry.path()))
        })
        .collect::<Vec<_>>();
    versions.sort();
    versions.reverse();
    let canonical_keep = keep.canonicalize().unwrap_or_else(|_| keep.to_path_buf());
    let mut kept = 0;
    for (_, path) in versions {
        let canonical = path.canonicalize().unwrap_or_else(|_| path.clone());
        if canonical == canonical_keep {
            continue;
        }
        kept += 1;
        if kept >= KEEP_VERSIONS {
            let _ = fs::remove_dir_all(&path);
        }
    }
}

fn path_hint(layout: &InstallLayout) -> Option<String> {
    let bin = layout.command_link().parent()?.to_path_buf();
    let on_path = std::env::var_os("PATH")
        .is_some_and(|path| std::env::split_paths(&path).any(|entry| entry == bin));
    (!on_path).then(|| {
        format!(
            "To use the `sovereign` command in new terminals, add this line to ~/.zprofile:\n  export PATH=\"{}:$PATH\"",
            bin.display()
        )
    })
}

/// Makes the version this binary runs from the one in use: switches `current`, links the
/// command, restarts the background service on it, and removes old versions.
///
/// # Errors
/// Returns when the binary is not an installed version or a step fails.
pub fn self_install(layout: &InstallLayout, data: &AppData) -> Result<String, String> {
    let version_dir = own_version_dir(layout)?;
    replace_symlink(&version_dir, &layout.current())?;
    replace_symlink(&layout.current_binary(), &layout.command_link())?;
    let service = launch_agent::install(
        data,
        &launch_agent::SystemLaunchctl,
        &layout.current_binary(),
        launch_agent::DEFAULT_BIND,
    )?;
    prune_versions(layout, &version_dir);
    let version = fs::read_to_string(version_dir.join("VERSION")).map_or_else(
        |_| env!("CARGO_PKG_VERSION").to_owned(),
        |text| text.trim().to_owned(),
    );
    let mut lines = vec![format!("Sovereign {version} is installed."), service];
    match write_app_launcher(layout, &version) {
        Ok(()) => lines.push(
            "Open Sovereign any time from Spotlight or Launchpad, or type `sovereign`.".to_owned(),
        ),
        Err(error) => lines.push(format!(
            "Could not add Sovereign to ~/Applications ({error}). Type `sovereign` to open it."
        )),
    }
    if let Some(hint) = path_hint(layout) {
        lines.push(hint);
    }
    Ok(lines.join("\n"))
}

fn release_base() -> String {
    std::env::var(RELEASE_BASE_ENV)
        .ok()
        .filter(|base| base.starts_with("https://"))
        .unwrap_or_else(|| DEFAULT_RELEASE_BASE.to_owned())
}

fn curl_to(url: &str, destination: &Path) -> Result<(), String> {
    let output = Command::new("/usr/bin/curl")
        .args([
            "--fail",
            "--location",
            "--silent",
            "--show-error",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--max-redirs",
            "10",
            "--connect-timeout",
            "30",
            "--output",
        ])
        .arg(destination)
        .arg(url)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("could not download {url}: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "could not download {url}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

/// The checksum listed for `asset` in a `SHA256SUMS` file.
fn listed_checksum(sums: &str, asset: &str) -> Option<String> {
    sums.lines().find_map(|line| {
        let mut parts = line.split_whitespace();
        let digest = parts.next()?;
        let name = parts.next()?.trim_start_matches('*');
        (name == asset && digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .then(|| digest.to_ascii_lowercase())
    })
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file = fs::File::open(path).map_err(|error| error.to_string())?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1 << 20];
    loop {
        let read = file.read(&mut buffer).map_err(|error| error.to_string())?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Unpacks a verified release tarball into `versions/<version>` and returns that folder.
fn unpack_release(layout: &InstallLayout, tarball: &Path) -> Result<(String, PathBuf), String> {
    let staging = layout
        .versions()
        .join(format!(".staging-{}", std::process::id()));
    let _ = fs::remove_dir_all(&staging);
    fs::create_dir_all(&staging).map_err(|error| error.to_string())?;
    let unpacked = Command::new("/usr/bin/tar")
        .arg("-xzf")
        .arg(tarball)
        .arg("-C")
        .arg(&staging)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| error.to_string())?;
    let root = staging.join(RELEASE_ROOT_DIR);
    let result = (|| {
        if !unpacked.status.success() || !root.join("bin").join("sovereign").is_file() {
            return Err("the downloaded release is incomplete".to_owned());
        }
        let version = fs::read_to_string(root.join("VERSION"))
            .map(|text| text.trim().to_owned())
            .map_err(|_| "the downloaded release has no VERSION".to_owned())?;
        if !valid_version(&version) {
            return Err("the downloaded release has an invalid version".to_owned());
        }
        let destination = layout.versions().join(&version);
        let _ = fs::remove_dir_all(&destination);
        fs::rename(&root, &destination).map_err(|error| error.to_string())?;
        Ok((version, destination))
    })();
    let _ = fs::remove_dir_all(&staging);
    result
}

/// Installs the newest release if it differs from the version in use.
///
/// # Errors
/// Returns when a download, the checksum, or the hand-over to the new version fails.
pub fn update(layout: &InstallLayout) -> Result<String, String> {
    if !cfg!(target_os = "macos") {
        return Err("`sovereign update` is available on macOS.".to_owned());
    }
    let base = release_base();
    let downloads = layout.downloads();
    fs::create_dir_all(&downloads).map_err(|error| error.to_string())?;
    let sums_path = downloads.join("SHA256SUMS");
    let tarball = downloads.join(RELEASE_ASSET);
    curl_to(&format!("{base}/SHA256SUMS"), &sums_path)?;
    let sums = fs::read_to_string(&sums_path).map_err(|error| error.to_string())?;
    let expected = listed_checksum(&sums, RELEASE_ASSET)
        .ok_or("the latest release does not list a checksum for this Mac")?;
    curl_to(&format!("{base}/{RELEASE_ASSET}"), &tarball)?;
    if sha256_file(&tarball)? != expected {
        let _ = fs::remove_file(&tarball);
        return Err(
            "the downloaded update did not match its checksum, so it was not installed. Try again."
                .to_owned(),
        );
    }
    let current_version = fs::read_to_string(layout.current().join("VERSION"))
        .map(|text| text.trim().to_owned())
        .unwrap_or_default();
    let (version, destination) = unpack_release(layout, &tarball)?;
    let _ = fs::remove_file(&tarball);
    if version == current_version {
        return Ok(format!(
            "Sovereign {version} is already the newest version."
        ));
    }
    let handed_over = Command::new(destination.join("bin").join("sovereign"))
        .arg("self-install")
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("could not start the new version: {error}"))?;
    if !handed_over.status.success() {
        return Err(format!(
            "the new version could not finish installing: {}",
            String::from_utf8_lossy(&handed_over.stderr).trim()
        ));
    }
    Ok(format!(
        "Updated to Sovereign {version}.\n{}",
        String::from_utf8_lossy(&handed_over.stdout).trim()
    ))
}

fn confirm(question: &str) -> bool {
    print!("{question} [y/N] ");
    let _ = std::io::stdout().flush();
    let mut answer = String::new();
    let _ = std::io::stdin().lock().read_line(&mut answer);
    matches!(answer.trim(), "y" | "Y" | "yes" | "Yes")
}

/// Removes the background service, the command, and the installed versions. Downloaded models
/// and Sovereign's records of projects are removed only with `--delete-data` or a yes. Project
/// folders are never touched.
///
/// # Errors
/// Returns when the service cannot be stopped or a folder cannot be removed.
pub fn uninstall(layout: &InstallLayout, args: &[String]) -> Result<String, String> {
    let delete_data = args.iter().any(|arg| arg == "--delete-data");
    let keep_data = args.iter().any(|arg| arg == "--keep-data");
    let mut lines = Vec::new();
    if cfg!(target_os = "macos") {
        lines.push(launch_agent::uninstall(&launch_agent::SystemLaunchctl)?);
    }
    let link = layout.command_link();
    if fs::read_link(&link).is_ok_and(|target| target.starts_with(layout.root())) {
        fs::remove_file(&link).map_err(|error| error.to_string())?;
    }
    if layout.root().exists() {
        fs::remove_dir_all(layout.root()).map_err(|error| error.to_string())?;
    }
    if layout.app_bundle().exists() {
        fs::remove_dir_all(layout.app_bundle()).map_err(|error| error.to_string())?;
    }
    lines.push("Removed the Sovereign app and its background service.".to_owned());
    let data_root = AppData::open_default()
        .ok()
        .map(|data| data.root().to_path_buf());
    if let Some(root) = data_root {
        let remove = delete_data
            || (!keep_data
                && confirm(
                    "Also delete downloaded models and Sovereign's records of your projects? Your project folders stay.",
                ));
        if remove {
            fs::remove_dir_all(&root).map_err(|error| error.to_string())?;
            lines.push("Deleted downloaded models and project records.".to_owned());
        } else {
            lines.push(format!(
                "Kept models and project records in {}.",
                root.display()
            ));
        }
    }
    lines.push("Your project folders were not changed.".to_owned());
    Ok(lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQUENCE: AtomicU64 = AtomicU64::new(1);

    fn temp_home(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sovereign-install-{label}-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap_or_else(|error| panic!("{error}"));
        dir
    }

    #[test]
    fn checksums_are_read_from_either_sha256sum_style() {
        let digest = "a".repeat(64);
        let sums = format!(
            "{digest}  {RELEASE_ASSET}\n{}  other.tar.gz\n",
            "b".repeat(64)
        );
        assert_eq!(listed_checksum(&sums, RELEASE_ASSET), Some(digest.clone()));
        let binary = format!("{digest} *{RELEASE_ASSET}\n");
        assert_eq!(listed_checksum(&binary, RELEASE_ASSET), Some(digest));
        assert_eq!(listed_checksum("nonsense", RELEASE_ASSET), None);
        assert_eq!(
            listed_checksum(&format!("xyz  {RELEASE_ASSET}"), RELEASE_ASSET),
            None
        );
    }

    #[test]
    fn the_app_launcher_opens_the_current_version() {
        let home = temp_home("launcher");
        let layout = InstallLayout { home: home.clone() };
        write_app_launcher(&layout, "0.2.0").unwrap_or_else(|error| panic!("{error}"));
        let contents = layout.app_bundle().join("Contents");
        let plist = fs::read_to_string(contents.join("Info.plist")).unwrap_or_default();
        assert!(plist.contains("<string>sovereign-launcher</string>"));
        assert!(plist.contains("<string>0.2.0</string>"));
        let script = fs::read_to_string(contents.join("MacOS").join(LAUNCHER_EXECUTABLE))
            .unwrap_or_default();
        assert!(
            script.contains(".sovereign/current/bin/sovereign\" app"),
            "{script}"
        );
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn versions_are_plain_names() {
        assert!(valid_version("0.2.0"));
        assert!(valid_version("0.2.0-rc.1"));
        assert!(!valid_version("../evil"));
        assert!(!valid_version(".hidden"));
        assert!(!valid_version(""));
    }

    #[test]
    fn symlinks_switch_atomically_and_point_at_the_new_version() {
        let home = temp_home("symlink");
        let layout = InstallLayout { home: home.clone() };
        let first = layout.versions().join("0.1.0");
        let second = layout.versions().join("0.2.0");
        fs::create_dir_all(first.join("bin")).unwrap_or_else(|error| panic!("{error}"));
        fs::create_dir_all(second.join("bin")).unwrap_or_else(|error| panic!("{error}"));
        replace_symlink(&first, &layout.current()).unwrap_or_else(|error| panic!("{error}"));
        replace_symlink(&second, &layout.current()).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(fs::read_link(layout.current()).ok(), Some(second));
        replace_symlink(&layout.current_binary(), &layout.command_link())
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            fs::read_link(layout.command_link()).ok(),
            Some(layout.current_binary())
        );
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn a_release_tarball_unpacks_into_its_version_folder() {
        let home = temp_home("unpack");
        let layout = InstallLayout { home: home.clone() };
        let bundle = home.join("bundle").join(RELEASE_ROOT_DIR);
        fs::create_dir_all(bundle.join("bin")).unwrap_or_else(|error| panic!("{error}"));
        fs::write(bundle.join("bin").join("sovereign"), b"binary")
            .unwrap_or_else(|error| panic!("{error}"));
        fs::write(bundle.join("VERSION"), "0.3.0\n").unwrap_or_else(|error| panic!("{error}"));
        let tarball = home.join(RELEASE_ASSET);
        let packed = Command::new("/usr/bin/tar")
            .arg("-czf")
            .arg(&tarball)
            .arg("-C")
            .arg(home.join("bundle"))
            .arg(RELEASE_ROOT_DIR)
            .status()
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(packed.success());
        fs::create_dir_all(layout.versions()).unwrap_or_else(|error| panic!("{error}"));
        let (version, destination) =
            unpack_release(&layout, &tarball).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(version, "0.3.0");
        assert_eq!(destination, layout.versions().join("0.3.0"));
        assert!(destination.join("bin").join("sovereign").is_file());
        let leftovers = fs::read_dir(layout.versions()).map_or(0, Iterator::count);
        assert_eq!(leftovers, 1, "no staging folder is left behind");
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn old_versions_are_pruned_but_the_one_in_use_and_one_before_stay() {
        let home = temp_home("prune");
        let layout = InstallLayout { home: home.clone() };
        for version in ["0.1.0", "0.2.0", "0.3.0"] {
            fs::create_dir_all(layout.versions().join(version))
                .unwrap_or_else(|error| panic!("{error}"));
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        prune_versions(&layout, &layout.versions().join("0.3.0"));
        assert!(layout.versions().join("0.3.0").is_dir());
        assert!(layout.versions().join("0.2.0").is_dir());
        assert!(!layout.versions().join("0.1.0").exists());
        let _ = fs::remove_dir_all(home);
    }
}
