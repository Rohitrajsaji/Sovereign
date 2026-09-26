//! Single-use launch codes for opening the UI without putting the session token in a URL.
//!
//! Callers: `launch_agent::open_ui` (issues) and `control_api/server.rs` (redeems on `GET /?c=`).
//! API: `issue`, `redeem`, `LAUNCH_CODE_FILE`.
//!
//! `sovereign app` and the service are different processes, so the code travels through a mode
//! 0600 file in the app-data directory. The code expires after `LAUNCH_CODE_TTL_MS` and is
//! deleted when redeemed, so a URL left in browser history cannot open a session later.

use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub const LAUNCH_CODE_FILE: &str = "launch-code";
pub const LAUNCH_CODE_TTL_MS: i64 = 60_000;
const LAUNCH_CODE_SCHEMA_VERSION: u32 = 1;
const MAX_LAUNCH_CODE_FILE_BYTES: u64 = 4_096;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LaunchCodeV1 {
    schema_version: u32,
    code: String,
    expires_at_ms: i64,
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
        })
}

fn random_hex(bytes: usize) -> io::Result<String> {
    let mut buffer = vec![0_u8; bytes];
    fs::File::open("/dev/urandom")?.read_exact(&mut buffer)?;
    let mut text = String::with_capacity(bytes * 2);
    for byte in buffer {
        text.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
        text.push(char::from(b"0123456789abcdef"[usize::from(byte & 0x0f)]));
    }
    Ok(text)
}

/// Writes a new code to `<dir>/launch-code`, replacing any earlier one, and returns it.
///
/// # Errors
/// Returns an I/O error when the random device or the file cannot be used.
pub fn issue(dir: &Path) -> io::Result<String> {
    issue_at(dir, now_ms())
}

fn issue_at(dir: &Path, now: i64) -> io::Result<String> {
    let code = random_hex(32)?;
    let record = LaunchCodeV1 {
        schema_version: LAUNCH_CODE_SCHEMA_VERSION,
        code: code.clone(),
        expires_at_ms: now.saturating_add(LAUNCH_CODE_TTL_MS),
    };
    fs::create_dir_all(dir)?;
    let path = dir.join(LAUNCH_CODE_FILE);
    let temporary = dir.join(format!("{LAUNCH_CODE_FILE}.tmp"));
    let _ = fs::remove_file(&temporary);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(serde_json::to_string(&record)?.as_bytes())?;
    file.sync_all()?;
    fs::rename(&temporary, &path)?;
    Ok(code)
}

/// Returns true and deletes the stored code when `candidate` matches an unexpired code.
/// A wrong candidate leaves the stored code in place. An expired code is deleted.
#[must_use]
pub fn redeem(dir: &Path, candidate: &str) -> bool {
    redeem_at(dir, candidate, now_ms())
}

fn redeem_at(dir: &Path, candidate: &str, now: i64) -> bool {
    let path = dir.join(LAUNCH_CODE_FILE);
    let Ok(metadata) = fs::symlink_metadata(&path) else {
        return false;
    };
    if !metadata.file_type().is_file() || metadata.len() > MAX_LAUNCH_CODE_FILE_BYTES {
        return false;
    }
    let Ok(text) = fs::read_to_string(&path) else {
        return false;
    };
    let Ok(record) = serde_json::from_str::<LaunchCodeV1>(&text) else {
        let _ = fs::remove_file(&path);
        return false;
    };
    if record.schema_version != LAUNCH_CODE_SCHEMA_VERSION || now > record.expires_at_ms {
        let _ = fs::remove_file(&path);
        return false;
    }
    if !constant_time_eq(record.code.as_bytes(), candidate.as_bytes()) {
        return false;
    }
    // Only the request that removes the file wins, so a code cannot be redeemed twice.
    fs::remove_file(&path).is_ok()
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sovereign-launch-code-{label}-{}-{}",
            std::process::id(),
            now_ms()
        ));
        fs::create_dir_all(&dir).unwrap_or_else(|error| panic!("{error}"));
        dir
    }

    #[test]
    fn code_is_private_single_use_and_rejects_wrong_values() {
        let dir = temp_dir("single-use");
        let code = issue(&dir).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(code.len(), 64);
        let mode = fs::metadata(dir.join(LAUNCH_CODE_FILE))
            .map(|metadata| metadata.permissions().mode() & 0o777)
            .ok();
        assert_eq!(mode, Some(0o600));
        assert!(!redeem(&dir, "wrong"));
        let last_differs = if code.ends_with('0') { '1' } else { '0' };
        assert!(!redeem(&dir, &format!("{}{last_differs}", &code[..63])));
        assert!(redeem(&dir, &code));
        assert!(!redeem(&dir, &code), "a code must not be redeemable twice");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn expired_code_is_rejected_and_removed() {
        let dir = temp_dir("expired");
        let code = issue_at(&dir, 1_000).unwrap_or_else(|error| panic!("{error}"));
        assert!(!redeem_at(&dir, &code, 1_000 + LAUNCH_CODE_TTL_MS + 1));
        assert!(!dir.join(LAUNCH_CODE_FILE).exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn new_code_replaces_old_code() {
        let dir = temp_dir("replace");
        let first = issue(&dir).unwrap_or_else(|error| panic!("{error}"));
        let second = issue(&dir).unwrap_or_else(|error| panic!("{error}"));
        assert!(!redeem(&dir, &first));
        assert!(redeem(&dir, &second));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn symlinked_code_file_is_refused() {
        let dir = temp_dir("symlink");
        let outside = dir.join("outside");
        fs::write(
            &outside,
            format!(
                r#"{{"schema_version":1,"code":"abc","expires_at_ms":{}}}"#,
                i64::MAX
            ),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        std::os::unix::fs::symlink(&outside, dir.join(LAUNCH_CODE_FILE))
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(!redeem(&dir, "abc"));
        let _ = fs::remove_dir_all(dir);
    }
}
