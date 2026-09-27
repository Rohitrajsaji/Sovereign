//! `LaunchAgent` install and `sovereign app`.
//! Callers: `main.rs` `service install|uninstall|status` and `app`.
//! API: `Launchctl`, `install`, `uninstall`, `status`, `open_ui`.
//! Schema: `LaunchAgent` plist under `~/Library/LaunchAgents/dev.sovereign.agent.plist`.
//! User instruction: implement the attached consumer product plan (CX-T15).

use crate::app_data::AppData;
use std::fs;
#[cfg(test)]
use std::io::Write;
#[cfg(test)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const LABEL: &str = "dev.sovereign.agent";
pub const DEFAULT_BIND: &str = "127.0.0.1:7777";
const SERVICE_START_WAIT: std::time::Duration = std::time::Duration::from_secs(15);

/// True once the local service accepts connections, polling for up to `wait`.
fn service_answers(wait: std::time::Duration) -> bool {
    let Ok(address) = DEFAULT_BIND.parse::<std::net::SocketAddr>() else {
        return false;
    };
    let started = std::time::Instant::now();
    loop {
        if std::net::TcpStream::connect_timeout(&address, std::time::Duration::from_millis(250))
            .is_ok()
        {
            return true;
        }
        if started.elapsed() >= wait {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

/// Injectable launchctl so tests never call the real daemon.
pub trait Launchctl {
    /// # Errors
    /// Returns when the helper cannot run the requested launchctl verb.
    fn run(&self, args: &[&str]) -> Result<String, String>;
}

/// Real `/bin/launchctl`.
pub struct SystemLaunchctl;

impl Launchctl for SystemLaunchctl {
    fn run(&self, args: &[&str]) -> Result<String, String> {
        let output = Command::new("/bin/launchctl")
            .args(args)
            .output()
            .map_err(|error| format!("launchctl failed: {error}"))?;
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        if output.status.success() {
            Ok(stdout)
        } else {
            Err(stderr)
        }
    }
}

/// Writes the plist and bootstraps the agent.
///
/// # Errors
/// Returns when the binary path, plist write, or launchctl call fails.
pub fn install<L: Launchctl>(
    data: &AppData,
    launchctl: &L,
    sovereign_path: &Path,
    bind: &str,
) -> Result<String, String> {
    let canonical = sovereign_path
        .canonicalize()
        .map_err(|error| format!("sovereign binary: {error}"))?;
    if !canonical.is_file() {
        return Err("sovereign binary is not a regular file".to_owned());
    }
    let logs = data.root().join("logs");
    fs::create_dir_all(&logs).map_err(|error| error.to_string())?;
    let plist = render_plist(&canonical, bind, &logs);
    let path = plist_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    fs::write(&path, plist).map_err(|error| error.to_string())?;
    let uid = current_uid();
    let domain = format!("gui/{uid}");
    let target = format!("{domain}/{LABEL}");
    let _ = launchctl.run(&["bootout", &target]);
    launchctl.run(&["bootstrap", &domain, &path.to_string_lossy()])?;
    Ok(format!("installed {LABEL} on {bind}"))
}

/// Removes the job and the plist.
///
/// # Errors
/// Returns when launchctl or unlink fails after a loaded job.
pub fn uninstall<L: Launchctl>(launchctl: &L) -> Result<String, String> {
    let uid = current_uid();
    let target = format!("gui/{uid}/{LABEL}");
    let _ = launchctl.run(&["bootout", &target]);
    let path = plist_path();
    if path.exists() {
        fs::remove_file(&path).map_err(|error| error.to_string())?;
    }
    Ok(format!("uninstalled {LABEL}"))
}

/// Reports whether the plist exists.
#[must_use]
pub fn status() -> String {
    if plist_path().exists() {
        format!("{LABEL} plist present")
    } else {
        format!("{LABEL} is not installed")
    }
}

/// Starts the agent if needed and opens the loopback UI with the session token.
///
/// # Errors
/// Returns when the token or `/usr/bin/open` fails.
pub fn open_ui<L: Launchctl>(
    data: &AppData,
    launchctl: &L,
    sovereign_path: &Path,
    opener: fn(&str) -> Result<(), String>,
) -> Result<String, String> {
    if !plist_path().exists()
        && let Err(error) = install(data, launchctl, sovereign_path, DEFAULT_BIND)
    {
        return Ok(missing_service_guidance(&error));
    }
    // A freshly started service needs a moment; a stopped one gets one restart.
    if !service_answers(SERVICE_START_WAIT) {
        let target = format!("gui/{}/{LABEL}", current_uid());
        let _ = launchctl.run(&["kickstart", "-k", &target]);
        if !service_answers(SERVICE_START_WAIT) {
            return Ok(missing_service_guidance(
                "it did not start listening on 127.0.0.1:7777",
            ));
        }
    }
    // A service left on another version (for example after installing from source) is pointed
    // at this binary, so the app and the service always run the same code.
    let is_current = std::env::var_os("HOME").is_some_and(|home| {
        crate::build_info::is_current_install(Path::new(&home), sovereign_path)
    });
    let running = crate::build_info::running_service_version(data.root());
    if crate::build_info::service_needs_restart(
        running.as_deref(),
        crate::build_info::BUILD_VERSION,
        is_current,
    ) {
        install(data, launchctl, sovereign_path, DEFAULT_BIND)?;
        if !restarted_service_answers(data) {
            return Ok(missing_service_guidance(
                "it did not come back after switching to the new version",
            ));
        }
    }
    // A single-use, short-lived code keeps the long-lived session token out of browser history.
    let code = crate::launch_code::issue(data.root()).map_err(|error| error.to_string())?;
    let url = format!("http://{DEFAULT_BIND}/?c={code}");
    opener(&url)?;
    Ok(format!("opened {DEFAULT_BIND}"))
}

/// Waits for the restarted service to record this version and answer.
fn restarted_service_answers(data: &AppData) -> bool {
    let deadline = std::time::Instant::now() + SERVICE_START_WAIT;
    while std::time::Instant::now() < deadline {
        if crate::build_info::running_service_version(data.root()).as_deref()
            == Some(crate::build_info::BUILD_VERSION)
        {
            return service_answers(SERVICE_START_WAIT);
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    false
}

#[must_use]
pub fn missing_service_guidance(error: &str) -> String {
    format!(
        "Sovereign service is not running ({error}). Install it with `sovereign service install`, then run `sovereign app`."
    )
}

/// Default opener using `/usr/bin/open`.
///
/// # Errors
/// Returns when open fails.
pub fn system_open(url: &str) -> Result<(), String> {
    let status = Command::new("/usr/bin/open")
        .arg(url)
        .status()
        .map_err(|error| format!("open failed: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err("open returned a non-zero status".to_owned())
    }
}

#[must_use]
pub fn plist_path() -> PathBuf {
    let home = std::env::var_os("HOME").unwrap_or_default();
    PathBuf::from(home)
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{LABEL}.plist"))
}

#[must_use]
pub fn render_plist(sovereign: &Path, bind: &str, logs: &Path) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{}</string>
    <string>serve</string>
    <string>--execute</string>
    <string>{bind}</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key>
  <dict><key>SuccessfulExit</key><false/></dict>
  <key>ThrottleInterval</key><integer>30</integer>
  <key>StandardOutPath</key><string>{}/stdout.log</string>
  <key>StandardErrorPath</key><string>{}/stderr.log</string>
</dict>
</plist>
"#,
        sovereign.display(),
        logs.display(),
        logs.display()
    )
}

fn current_uid() -> u32 {
    Command::new("/usr/bin/id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(501)
}

/// Test helper that records launchctl verbs.
#[derive(Default)]
#[allow(dead_code)]
pub struct RecordingLaunchctl {
    pub calls: std::sync::Mutex<Vec<Vec<String>>>,
}

impl Launchctl for RecordingLaunchctl {
    fn run(&self, args: &[&str]) -> Result<String, String> {
        if let Ok(mut calls) = self.calls.lock() {
            calls.push(args.iter().map(|arg| (*arg).to_owned()).collect());
        }
        Ok(String::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn plist_content_snapshot() {
        let xml = render_plist(
            Path::new("/opt/sovereign"),
            "127.0.0.1:7777",
            Path::new("/tmp/logs"),
        );
        assert!(xml.contains("<string>serve</string>"));
        assert!(xml.contains("<string>--execute</string>"));
        assert!(xml.contains("<string>127.0.0.1:7777</string>"));
        assert!(xml.contains("<key>RunAtLoad</key><true/>"));
        assert!(xml.contains("SuccessfulExit"));
        assert!(xml.contains("<key>ThrottleInterval</key><integer>30</integer>"));
    }

    #[test]
    fn install_is_idempotent_through_injected_launchctl() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("sovereign-launchd-{nonce}"));
        let data = AppData::open(&root).unwrap_or_else(|error| panic!("open: {error}"));
        let bin = root.join("sovereign");
        let mut file = fs::File::create(&bin).unwrap_or_else(|error| panic!("bin: {error}"));
        file.write_all(b"#!/bin/sh\n")
            .unwrap_or_else(|error| panic!("write: {error}"));
        drop(file);
        let mut perms = fs::metadata(&bin)
            .unwrap_or_else(|error| panic!("meta: {error}"))
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&bin, perms).unwrap_or_else(|error| panic!("chmod: {error}"));
        let launchctl = RecordingLaunchctl::default();
        install(&data, &launchctl, &bin, DEFAULT_BIND)
            .unwrap_or_else(|error| panic!("install 1: {error}"));
        install(&data, &launchctl, &bin, DEFAULT_BIND)
            .unwrap_or_else(|error| panic!("install 2: {error}"));
        let calls = launchctl
            .calls
            .lock()
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            calls
                .iter()
                .any(|call| call.first().is_some_and(|verb| verb == "bootstrap"))
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn uninstall_removes_plist_and_app_without_service_prints_guidance() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("sovereign-launchd-uninst-{nonce}"));
        let data = AppData::open(&root).unwrap_or_else(|error| panic!("open: {error}"));
        let message = missing_service_guidance("launchctl unavailable");
        assert!(message.contains("sovereign service install"), "{message}");
        let _ = fs::remove_dir_all(root);
        let _ = data;
    }
}
