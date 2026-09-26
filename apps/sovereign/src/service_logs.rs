//! Size caps for the `LaunchAgent` log files.
//!
//! Callers: `run_serve` in `main.rs` (at start and on a background timer).
//! API: `rotate_if_needed`, `spawn_rotation`.
//!
//! launchd opens `stdout.log` and `stderr.log` in append mode before `sovereign` starts, so the
//! files cannot be renamed away from under it. When a file passes the cap, its newest tail is
//! copied to `<name>.1` and the file is truncated in place. Append-mode writes continue at the
//! new end of file.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

pub const LOG_FILE_NAMES: [&str; 2] = ["stdout.log", "stderr.log"];
/// Largest size of one live log file.
pub const LOG_CAP_BYTES: u64 = 10 * 1_024 * 1_024;
/// How much of the newest output is kept in `<name>.1`.
pub const LOG_KEEP_BYTES: u64 = 2 * 1_024 * 1_024;
const ROTATION_INTERVAL: Duration = Duration::from_secs(600);

/// Rotates every known log file in `dir` that is larger than `cap_bytes`.
/// Returns the files that were rotated. Missing files are skipped.
///
/// # Errors
/// Returns the first I/O error. A symlinked log file is refused.
pub fn rotate_if_needed(dir: &Path, cap_bytes: u64, keep_bytes: u64) -> io::Result<Vec<PathBuf>> {
    let mut rotated = Vec::new();
    for name in LOG_FILE_NAMES {
        let path = dir.join(name);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if !metadata.file_type().is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not a regular file", path.display()),
            ));
        }
        if metadata.len() <= cap_bytes {
            continue;
        }
        let mut source = File::open(&path)?;
        let keep = keep_bytes.min(metadata.len());
        source.seek(SeekFrom::End(-i64::try_from(keep).unwrap_or(i64::MAX)))?;
        let mut tail = Vec::new();
        source.take(keep).read_to_end(&mut tail)?;
        let backup = dir.join(format!("{name}.1"));
        let mut target = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&backup)?;
        target.write_all(&tail)?;
        target.sync_all()?;
        OpenOptions::new().write(true).open(&path)?.set_len(0)?;
        rotated.push(path);
    }
    Ok(rotated)
}

/// Rotates now and then every ten minutes on a detached thread.
pub fn spawn_rotation(dir: PathBuf) {
    let _ = rotate_if_needed(&dir, LOG_CAP_BYTES, LOG_KEEP_BYTES);
    let _ = thread::Builder::new()
        .name("sovereign-log-rotation".to_owned())
        .spawn(move || {
            loop {
                thread::sleep(ROTATION_INTERVAL);
                if let Err(error) = rotate_if_needed(&dir, LOG_CAP_BYTES, LOG_KEEP_BYTES) {
                    eprintln!("sovereign: log rotation failed: {error}");
                }
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sovereign-logs-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos())
        ));
        fs::create_dir_all(&dir).unwrap_or_else(|error| panic!("create dir: {error}"));
        dir
    }

    #[test]
    fn small_logs_are_left_alone_and_large_logs_keep_their_tail() {
        let dir = temp_dir("rotate");
        fs::write(dir.join("stdout.log"), b"short").unwrap_or_else(|error| panic!("{error}"));
        let mut large = vec![b'a'; 100];
        large.extend_from_slice(b"NEWEST");
        fs::write(dir.join("stderr.log"), &large).unwrap_or_else(|error| panic!("{error}"));

        let rotated = rotate_if_needed(&dir, 50, 6).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(rotated, vec![dir.join("stderr.log")]);
        assert_eq!(
            fs::read(dir.join("stdout.log")).ok(),
            Some(b"short".to_vec())
        );
        assert_eq!(fs::read(dir.join("stderr.log")).ok(), Some(Vec::new()));
        assert_eq!(
            fs::read(dir.join("stderr.log.1")).ok(),
            Some(b"NEWEST".to_vec())
        );
        assert!(!dir.join("stdout.log.1").exists());

        // Missing files are skipped.
        fs::remove_file(dir.join("stdout.log")).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(rotate_if_needed(&dir, 50, 6).ok(), Some(Vec::new()));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn append_mode_writer_continues_after_truncation() {
        let dir = temp_dir("append");
        let path = dir.join("stdout.log");
        let mut writer = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap_or_else(|error| panic!("{error}"));
        writer
            .write_all(&[b'x'; 64])
            .unwrap_or_else(|error| panic!("{error}"));
        rotate_if_needed(&dir, 10, 4).unwrap_or_else(|error| panic!("{error}"));
        writer
            .write_all(b"after")
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(fs::read(&path).ok(), Some(b"after".to_vec()));
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_log_is_refused() {
        let dir = temp_dir("symlink");
        let outside = dir.join("outside");
        fs::write(&outside, vec![b'z'; 100]).unwrap_or_else(|error| panic!("{error}"));
        std::os::unix::fs::symlink(&outside, dir.join("stdout.log"))
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(rotate_if_needed(&dir, 10, 4).is_err());
        assert_eq!(fs::read(&outside).ok().map(|bytes| bytes.len()), Some(100));
        let _ = fs::remove_dir_all(dir);
    }
}
