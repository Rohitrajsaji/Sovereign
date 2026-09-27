use std::ffi::OsString;
use std::fmt::{Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

#[derive(Debug)]
pub(crate) enum RunLockError {
    InvalidStatePath(String),
    UnsafeStatePath(String),
    UnsafeLockPath(String),
    Contended(PathBuf),
    Io(io::Error),
}

impl Display for RunLockError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidStatePath(message) => write!(f, "invalid state path: {message}"),
            Self::UnsafeStatePath(message) => write!(f, "unsafe state path: {message}"),
            Self::UnsafeLockPath(message) => write!(f, "unsafe run-lock path: {message}"),
            Self::Contended(path) => write!(
                f,
                "another sovereign run is active for this state database ({})",
                path.display()
            ),
            Self::Io(error) => write!(f, "run-lock I/O error: {error}"),
        }
    }
}

impl std::error::Error for RunLockError {}

impl From<io::Error> for RunLockError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Process-lifetime coordination for one canonical state database.
///
/// The sidecar file deliberately contains no owner/status data and is never durable Controller
/// truth. Only the kernel file lock held by `_file` has meaning; the sidecar remains after release.
pub(crate) struct RunLock {
    _file: File,
    #[cfg(test)]
    path: PathBuf,
}

impl RunLock {
    pub(crate) fn acquire(state_path: &Path) -> Result<Self, RunLockError> {
        let path = sidecar_path(state_path)?;
        validate_existing_sidecar(&path)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        options.mode(0o600);
        let file = options.open(&path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(RunLockError::UnsafeLockPath(format!(
                "{} is not a regular file",
                path.display()
            )));
        }
        match file.try_lock() {
            Ok(()) => Ok(Self {
                _file: file,
                #[cfg(test)]
                path,
            }),
            Err(std::fs::TryLockError::WouldBlock) => Err(RunLockError::Contended(path)),
            Err(std::fs::TryLockError::Error(error)) => Err(RunLockError::Io(error)),
        }
    }

    #[cfg(test)]
    fn path(&self) -> &Path {
        &self.path
    }
}

fn sidecar_path(state_path: &Path) -> Result<PathBuf, RunLockError> {
    let file_name = state_path.file_name().ok_or_else(|| {
        RunLockError::InvalidStatePath(format!("{} has no database filename", state_path.display()))
    })?;
    if file_name.is_empty() {
        return Err(RunLockError::InvalidStatePath(
            "state database filename is empty".to_owned(),
        ));
    }

    let parent = state_path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let canonical_parent = parent.canonicalize()?;
    let canonical_state_path = canonical_parent.join(file_name);
    validate_existing_state_path(&canonical_state_path)?;

    let mut sidecar_name = OsString::from(".");
    sidecar_name.push(file_name);
    sidecar_name.push(".sovereign-run.lock");
    Ok(canonical_parent.join(sidecar_name))
}

fn validate_existing_state_path(path: &Path) -> Result<(), RunLockError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() {
        return Err(RunLockError::UnsafeStatePath(format!(
            "{} is a symbolic link",
            path.display()
        )));
    }
    if !metadata.is_file() {
        return Err(RunLockError::UnsafeStatePath(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    #[cfg(unix)]
    if metadata.nlink() != 1 {
        return Err(RunLockError::UnsafeStatePath(format!(
            "{} has {} hard links; run-lock identity would be ambiguous",
            path.display(),
            metadata.nlink()
        )));
    }
    Ok(())
}

fn validate_existing_sidecar(path: &Path) -> Result<(), RunLockError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(RunLockError::UnsafeLockPath(format!(
            "{} must be a regular non-symlink file",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(label: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "sovereign-run-lock-{label}-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir_all(&path)
                .unwrap_or_else(|error| panic!("create run-lock test dir: {error}"));
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn same_state_contends_and_drop_reacquires_without_deleting_sidecar() {
        let temp = TestDir::new("contention");
        let state_path = temp.path().join("state.sqlite3");
        let first = RunLock::acquire(&state_path)
            .unwrap_or_else(|error| panic!("acquire first run lock: {error}"));
        assert!(first.path().is_file());
        let second = RunLock::acquire(&state_path);
        assert!(matches!(second, Err(RunLockError::Contended(_))));
        let sidecar = first.path().to_path_buf();
        drop(first);
        assert!(
            sidecar.is_file(),
            "run-lock sidecar should remain after release"
        );
        // Other tests in this binary spawn children with `pre_exec`, which forks. A child forked
        // while `first` was open shares its lock until the child execs and CLOEXEC closes it, so
        // a brief contention here is that child, not a lock that survived release.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let reacquired = loop {
            match RunLock::acquire(&state_path) {
                Err(RunLockError::Contended(_)) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                result => {
                    break result
                        .unwrap_or_else(|error| panic!("reacquire released run lock: {error}"));
                }
            }
        };
        assert_eq!(reacquired.path(), sidecar);
    }

    #[test]
    fn different_state_database_names_do_not_contend() {
        let temp = TestDir::new("different-state");
        let first = RunLock::acquire(&temp.path().join("first.sqlite3"))
            .unwrap_or_else(|error| panic!("acquire first state lock: {error}"));
        let second = RunLock::acquire(&temp.path().join("second.sqlite3"))
            .unwrap_or_else(|error| panic!("acquire second state lock: {error}"));
        assert_ne!(first.path(), second.path());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_parent_alias_contends_on_the_same_canonical_sidecar() {
        use std::os::unix::fs::symlink;

        let temp = TestDir::new("parent-alias");
        let real = temp.path().join("real");
        fs::create_dir_all(&real)
            .unwrap_or_else(|error| panic!("create real run-lock parent: {error}"));
        let alias = temp.path().join("alias");
        symlink(&real, &alias).unwrap_or_else(|error| panic!("create parent alias: {error}"));
        let first = RunLock::acquire(&real.join("state.sqlite3"))
            .unwrap_or_else(|error| panic!("acquire real-parent run lock: {error}"));
        let second = RunLock::acquire(&alias.join("state.sqlite3"));
        assert!(matches!(second, Err(RunLockError::Contended(_))));
        assert_eq!(
            first.path(),
            sidecar_path(&alias.join("state.sqlite3"))
                .unwrap_or_else(|error| panic!("resolve aliased sidecar: {error}"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn database_symlink_and_hardlink_aliases_are_rejected() {
        use std::os::unix::fs::symlink;

        let temp = TestDir::new("db-alias");
        let target = temp.path().join("target.sqlite3");
        File::create(&target).unwrap_or_else(|error| panic!("create target DB: {error}"));
        let symlinked = temp.path().join("symlink.sqlite3");
        symlink(&target, &symlinked).unwrap_or_else(|error| panic!("create DB symlink: {error}"));
        assert!(matches!(
            RunLock::acquire(&symlinked),
            Err(RunLockError::UnsafeStatePath(_))
        ));

        let hardlinked = temp.path().join("hardlink.sqlite3");
        fs::hard_link(&target, &hardlinked)
            .unwrap_or_else(|error| panic!("create DB hard link: {error}"));
        assert!(matches!(
            RunLock::acquire(&target),
            Err(RunLockError::UnsafeStatePath(_))
        ));
        assert!(matches!(
            RunLock::acquire(&hardlinked),
            Err(RunLockError::UnsafeStatePath(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_existing_sidecar_is_rejected() {
        use std::os::unix::fs::symlink;

        let temp = TestDir::new("unsafe-sidecar");
        let state_path = temp.path().join("state.sqlite3");
        let sidecar = sidecar_path(&state_path)
            .unwrap_or_else(|error| panic!("resolve sidecar path: {error}"));
        let target = temp.path().join("target.lock");
        File::create(&target).unwrap_or_else(|error| panic!("create target lock: {error}"));
        symlink(&target, &sidecar)
            .unwrap_or_else(|error| panic!("create sidecar symlink: {error}"));
        assert!(matches!(
            RunLock::acquire(&state_path),
            Err(RunLockError::UnsafeLockPath(_))
        ));
    }
}
