//! Local machine checks for onboarding. Results are advisory; they do not grant capabilities.

use serde::Serialize;
use sovereign_policy::MacSandboxExecBackend;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DoctorCheck {
    pub id: String,
    pub status: String,
    pub detail: String,
    pub fix_hint: String,
}

/// Runs the consumer doctor checklist.
#[must_use]
pub fn doctor_checks(model_path: Option<&Path>, runtime_path: Option<&Path>) -> Vec<DoctorCheck> {
    let checks = vec![
        path_check(
            "git",
            Path::new("/usr/bin/git"),
            "fail",
            "Install the system Git at /usr/bin/git.",
        ),
        path_check(
            "python3",
            Path::new("/usr/bin/python3"),
            "fail",
            "Install the system Python at /usr/bin/python3.",
        ),
        sandbox_check(),
        optional_file(
            "model-runtime",
            runtime_path,
            "Choose the llama-server binary in Settings.",
        ),
        optional_file(
            "model-weights",
            model_path,
            "Choose the GGUF file in Settings.",
        ),
        path_check(
            "chrome",
            Path::new("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
            "warn",
            "Chrome is optional. Browser goals stay unavailable until it is installed.",
        ),
        path_check(
            "node",
            Path::new("/usr/local/bin/node"),
            "warn",
            "Node is optional. JavaScript verification stays unavailable until it is configured.",
        ),
        disk_check(),
        memory_check(),
        schema_check(),
        app_data_check(),
    ];
    checks
}

fn disk_check() -> DoctorCheck {
    let required = sovereign_policy::HardwareProfileV1::m1_8gb().minimum_host_free_disk_mib;
    match host_free_disk_mib() {
        Some(free) if free >= required => DoctorCheck {
            id: "disk".to_owned(),
            status: "pass".to_owned(),
            detail: format!("{free} MiB free"),
            fix_hint: String::new(),
        },
        Some(free) => DoctorCheck {
            id: "disk".to_owned(),
            status: "fail".to_owned(),
            detail: format!("{free} MiB free, need {required}"),
            fix_hint: "Free disk space on the startup volume.".to_owned(),
        },
        None => DoctorCheck {
            id: "disk".to_owned(),
            status: "warn".to_owned(),
            detail: "could not measure free disk".to_owned(),
            fix_hint: "Confirm /bin/df is available.".to_owned(),
        },
    }
}

fn memory_check() -> DoctorCheck {
    let required = sovereign_policy::HardwareProfileV1::m1_8gb().physical_memory_mib;
    match host_memory_mib() {
        Some(mem) if mem >= required => DoctorCheck {
            id: "memory".to_owned(),
            status: "pass".to_owned(),
            detail: format!("{mem} MiB physical memory"),
            fix_hint: String::new(),
        },
        Some(mem) => DoctorCheck {
            id: "memory".to_owned(),
            status: "warn".to_owned(),
            detail: format!("{mem} MiB physical memory, profile expects {required}"),
            fix_hint: "Sovereign is qualified for the M1/8 GB profile.".to_owned(),
        },
        None => DoctorCheck {
            id: "memory".to_owned(),
            status: "warn".to_owned(),
            detail: "could not measure physical memory".to_owned(),
            fix_hint: String::new(),
        },
    }
}

fn schema_check() -> DoctorCheck {
    DoctorCheck {
        id: "state-schema".to_owned(),
        status: "pass".to_owned(),
        detail: format!("state schema {}", sovereign_state::CURRENT_SCHEMA_VERSION),
        fix_hint: String::new(),
    }
}

fn app_data_check() -> DoctorCheck {
    match crate::app_data::AppData::open_default() {
        Ok(data) => DoctorCheck {
            id: "app-data".to_owned(),
            status: "pass".to_owned(),
            detail: format!("{}", data.root().display()),
            fix_hint: String::new(),
        },
        Err(error) => DoctorCheck {
            id: "app-data".to_owned(),
            status: "fail".to_owned(),
            detail: error.to_string(),
            fix_hint: "Create ~/Library/Application Support/Sovereign at mode 0700.".to_owned(),
        },
    }
}

fn host_free_disk_mib() -> Option<u64> {
    let output = std::process::Command::new("/bin/df")
        .args(["-k", "/"])
        .output()
        .ok()?;
    let text = String::from_utf8(output.stdout).ok()?;
    let line = text.lines().nth(1)?;
    let available_kib = line.split_whitespace().nth(3)?.parse::<u64>().ok()?;
    Some(available_kib / 1_024)
}

fn host_memory_mib() -> Option<u64> {
    let output = std::process::Command::new("/usr/sbin/sysctl")
        .args(["-n", "hw.memsize"])
        .output()
        .ok()?;
    let bytes = String::from_utf8(output.stdout)
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()?;
    Some(bytes / 1_048_576)
}

fn sandbox_check() -> DoctorCheck {
    match MacSandboxExecBackend::detect() {
        Ok(_) => DoctorCheck {
            id: "sandbox-exec".to_owned(),
            status: "pass".to_owned(),
            detail: "Seatbelt isolation self-test passed.".to_owned(),
            fix_hint: String::new(),
        },
        Err(error) => DoctorCheck {
            id: "sandbox-exec".to_owned(),
            status: "fail".to_owned(),
            detail: error.to_string(),
            fix_hint: "Sovereign requires /usr/bin/sandbox-exec on macOS.".to_owned(),
        },
    }
}

fn path_check(id: &str, path: &Path, missing_status: &str, hint: &str) -> DoctorCheck {
    if path.is_file() {
        DoctorCheck {
            id: id.to_owned(),
            status: "pass".to_owned(),
            detail: format!("{} is present", path.display()),
            fix_hint: String::new(),
        }
    } else {
        DoctorCheck {
            id: id.to_owned(),
            status: missing_status.to_owned(),
            detail: format!("{} is missing", path.display()),
            fix_hint: hint.to_owned(),
        }
    }
}

fn optional_file(id: &str, path: Option<&Path>, hint: &str) -> DoctorCheck {
    match path {
        Some(path) if path.is_file() => DoctorCheck {
            id: id.to_owned(),
            status: "pass".to_owned(),
            detail: format!("{} is present", path.display()),
            fix_hint: String::new(),
        },
        Some(path) => DoctorCheck {
            id: id.to_owned(),
            status: "fail".to_owned(),
            detail: format!("{} is missing", path.display()),
            fix_hint: hint.to_owned(),
        },
        None => DoctorCheck {
            id: id.to_owned(),
            status: "warn".to_owned(),
            detail: "not configured".to_owned(),
            fix_hint: hint.to_owned(),
        },
    }
}

/// Writes a 32-byte hex session token at mode 0600.
///
/// # Errors
/// Returns an I/O error when the random device or the token file cannot be used.
pub fn write_session_token(path: &Path) -> std::io::Result<String> {
    let mut bytes = [0_u8; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    let mut token = String::with_capacity(64);
    for byte in bytes {
        token.push(char::from(b"0123456789abcdef"[(byte >> 4) as usize]));
        token.push(char::from(b"0123456789abcdef"[(byte & 0x0f) as usize]));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(token.as_bytes())?;
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn session_token_is_mode_0600_and_missing_model_is_warned() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("sovereign-token-{nonce}"));
        std::fs::create_dir_all(&dir).unwrap_or_else(|error| panic!("{error}"));
        let path = dir.join("service-token");
        let token = write_session_token(&path).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(token.len(), 64);
        let mode = std::fs::metadata(&path)
            .unwrap_or_else(|error| panic!("{error}"))
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        let checks = doctor_checks(Some(Path::new("/missing/model.gguf")), None);
        assert!(
            checks
                .iter()
                .any(|check| check.id == "model-weights" && check.status == "fail")
        );
        assert!(
            checks
                .iter()
                .any(|check| check.id == "model-runtime" && check.status == "warn")
        );
        assert!(checks.iter().any(|check| check.id == "git"));
        assert!(checks.iter().any(|check| check.id == "python3"));
        assert!(checks.iter().any(|check| check.id == "sandbox-exec"));
        assert!(checks.iter().any(|check| check.id == "disk"));
        assert!(checks.iter().any(|check| check.id == "memory"));
        assert!(checks.iter().any(|check| check.id == "state-schema"));
        assert!(checks.iter().any(|check| check.id == "app-data"));
        let _ = std::fs::remove_dir_all(dir);
    }
}
