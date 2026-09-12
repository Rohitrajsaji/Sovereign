//! Immutable content-addressed artifact storage for Sovereign evidence.

use sha2::{Digest, Sha256};
use sovereign_state::{StateError, StateStore};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const SHA256_HEX_LEN: usize = 64;

/// Public metadata for one immutable CAS artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactMetadata {
    pub digest: String,
    pub size_bytes: u64,
}

/// Errors produced by the immutable artifact store.
#[derive(Debug)]
pub enum EvidenceError {
    Io(std::io::Error),
    State(StateError),
    InvalidDigest(String),
    DigestMismatch {
        expected: String,
        actual: String,
    },
    CorruptArtifact {
        expected: String,
        actual: String,
    },
    UnknownArtifact(String),
    RangeOutOfBounds {
        offset: u64,
        length: usize,
        size: u64,
    },
    SizeOverflow(usize),
    Clock(std::time::SystemTimeError),
}

impl Display for EvidenceError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "artifact I/O error: {error}"),
            Self::State(error) => write!(f, "artifact state error: {error}"),
            Self::InvalidDigest(digest) => write!(f, "invalid SHA-256 digest: {digest:?}"),
            Self::DigestMismatch { expected, actual } => {
                write!(
                    f,
                    "artifact digest mismatch: expected {expected}, got {actual}"
                )
            }
            Self::CorruptArtifact { expected, actual } => write!(
                f,
                "artifact corruption: path digest {expected}, bytes hash to {actual}"
            ),
            Self::UnknownArtifact(digest) => write!(f, "unknown artifact digest: {digest}"),
            Self::RangeOutOfBounds {
                offset,
                length,
                size,
            } => write!(
                f,
                "artifact range offset={offset} length={length} exceeds size={size}"
            ),
            Self::SizeOverflow(size) => {
                write!(
                    f,
                    "artifact byte length cannot fit durable size type: {size}"
                )
            }
            Self::Clock(error) => write!(f, "artifact clock error: {error}"),
        }
    }
}

impl Error for EvidenceError {}

impl From<std::io::Error> for EvidenceError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<StateError> for EvidenceError {
    fn from(value: StateError) -> Self {
        Self::State(value)
    }
}

impl From<std::time::SystemTimeError> for EvidenceError {
    fn from(value: std::time::SystemTimeError) -> Self {
        Self::Clock(value)
    }
}

/// Filesystem CAS whose durable object publication always precedes the
/// authoritative metadata commit.
#[derive(Debug, Clone)]
pub struct ArtifactStore {
    root: PathBuf,
}

impl ArtifactStore {
    /// Opens a CAS root without eagerly scanning existing objects.
    ///
    /// # Errors
    ///
    /// Returns [`EvidenceError`] if required CAS directories cannot be
    /// created.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, EvidenceError> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(root.join("sha256"))?;
        std::fs::create_dir_all(root.join("tmp"))?;
        Ok(Self { root })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Publishes bytes under their SHA-256 digest and then registers metadata
    /// in authoritative state.
    ///
    /// # Errors
    ///
    /// Returns [`EvidenceError`] when object publication, durability, size
    /// conversion, or metadata registration fails.
    pub fn put(
        &self,
        state: &mut StateStore,
        bytes: &[u8],
    ) -> Result<ArtifactMetadata, EvidenceError> {
        let digest = sha256_hex(bytes);
        self.put_expected(state, &digest, bytes)
    }

    /// Publishes bytes only when they match an expected SHA-256 digest.
    ///
    /// # Errors
    ///
    /// Returns [`EvidenceError::DigestMismatch`] before publication when the
    /// expected digest differs, or another store/state error.
    pub fn put_expected(
        &self,
        state: &mut StateStore,
        expected_digest: &str,
        bytes: &[u8],
    ) -> Result<ArtifactMetadata, EvidenceError> {
        validate_digest(expected_digest)?;
        let actual = sha256_hex(bytes);
        if actual != expected_digest {
            return Err(EvidenceError::DigestMismatch {
                expected: expected_digest.to_owned(),
                actual,
            });
        }

        let size_bytes =
            u64::try_from(bytes.len()).map_err(|_| EvidenceError::SizeOverflow(bytes.len()))?;
        let target = self.object_path(expected_digest)?;
        if target.exists() {
            Self::verify_file(&target, expected_digest)?;
        } else {
            self.publish_new(&target, expected_digest, bytes)?;
        }

        state.register_artifact(expected_digest, size_bytes)?;
        Ok(ArtifactMetadata {
            digest: expected_digest.to_owned(),
            size_bytes,
        })
    }

    /// Opens a known immutable object only after authoritative metadata and
    /// content digest verification succeed.
    ///
    /// # Errors
    ///
    /// Returns [`EvidenceError`] for unknown, missing, malformed, or corrupt
    /// artifacts.
    pub fn open_artifact(&self, state: &StateStore, digest: &str) -> Result<File, EvidenceError> {
        validate_digest(digest)?;
        if state.artifact_metadata(digest)?.is_none() {
            return Err(EvidenceError::UnknownArtifact(digest.to_owned()));
        }
        let path = self.object_path(digest)?;
        Self::verify_file(&path, digest)?;
        Ok(File::open(path)?)
    }

    /// Reads an exact byte range from a verified immutable object.
    ///
    /// # Errors
    ///
    /// Returns [`EvidenceError`] when the object is unknown/corrupt, the range
    /// exceeds its durable size, or I/O fails.
    pub fn range(
        &self,
        state: &StateStore,
        digest: &str,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, EvidenceError> {
        let metadata = state
            .artifact_metadata(digest)?
            .ok_or_else(|| EvidenceError::UnknownArtifact(digest.to_owned()))?;
        let length_u64 = u64::try_from(length).map_err(|_| EvidenceError::SizeOverflow(length))?;
        let end = offset
            .checked_add(length_u64)
            .ok_or(EvidenceError::RangeOutOfBounds {
                offset,
                length,
                size: metadata.size_bytes,
            })?;
        if end > metadata.size_bytes {
            return Err(EvidenceError::RangeOutOfBounds {
                offset,
                length,
                size: metadata.size_bytes,
            });
        }

        let mut file = self.open_artifact(state, digest)?;
        file.seek(SeekFrom::Start(offset))?;
        let mut result = vec![0_u8; length];
        file.read_exact(&mut result)?;
        Ok(result)
    }

    /// Selects unreferenced objects old enough to satisfy a caller-provided
    /// grace period. Selection never deletes bytes automatically.
    ///
    /// # Errors
    ///
    /// Returns [`EvidenceError`] on clock or state-query failure.
    pub fn gc_candidates(
        &self,
        state: &StateStore,
        grace_period: Duration,
    ) -> Result<Vec<ArtifactMetadata>, EvidenceError> {
        let now_ms = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())
            .unwrap_or(i64::MAX);
        let grace_ms = i64::try_from(grace_period.as_millis()).unwrap_or(i64::MAX);
        let cutoff = now_ms.saturating_sub(grace_ms);
        Ok(state
            .unreferenced_artifacts_before(cutoff)?
            .into_iter()
            .map(|metadata| ArtifactMetadata {
                digest: metadata.digest,
                size_bytes: metadata.size_bytes,
            })
            .collect())
    }

    fn publish_new(&self, target: &Path, digest: &str, bytes: &[u8]) -> Result<(), EvidenceError> {
        let parent = target.parent().ok_or_else(|| {
            EvidenceError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "CAS target has no parent",
            ))
        })?;
        std::fs::create_dir_all(parent)?;

        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let temp_path =
            self.root
                .join("tmp")
                .join(format!(".{digest}.{}.{}.tmp", std::process::id(), nonce));
        let mut temp = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp_path)?;
        if let Err(error) = (|| -> Result<(), std::io::Error> {
            temp.write_all(bytes)?;
            temp.sync_all()?;
            drop(temp);
            std::fs::rename(&temp_path, target)?;
            sync_directory(parent)?;
            Ok(())
        })() {
            let _ = std::fs::remove_file(&temp_path);
            return Err(EvidenceError::Io(error));
        }
        Self::verify_file(target, digest)
    }

    fn object_path(&self, digest: &str) -> Result<PathBuf, EvidenceError> {
        validate_digest(digest)?;
        Ok(self.root.join("sha256").join(&digest[..2]).join(digest))
    }

    fn verify_file(path: &Path, expected_digest: &str) -> Result<(), EvidenceError> {
        let mut file = File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0_u8; 64 * 1024];
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        let actual = format!("{:x}", hasher.finalize());
        if actual == expected_digest {
            Ok(())
        } else {
            Err(EvidenceError::CorruptArtifact {
                expected: expected_digest.to_owned(),
                actual,
            })
        }
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn validate_digest(digest: &str) -> Result<(), EvidenceError> {
    if digest.len() == SHA256_HEX_LEN
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(EvidenceError::InvalidDigest(digest.to_owned()))
    }
}

fn sync_directory(path: &Path) -> Result<(), std::io::Error> {
    File::open(path)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    struct TestContext {
        root: PathBuf,
        state: StateStore,
        store: ArtifactStore,
    }

    impl TestContext {
        fn new(label: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos());
            let root = std::env::temp_dir().join(format!(
                "sovereign-evidence-{label}-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir_all(&root).unwrap_or_else(|error| panic!("create root: {error}"));
            let state = StateStore::open(root.join("state.sqlite3"))
                .unwrap_or_else(|error| panic!("open state: {error}"));
            let store = ArtifactStore::open(root.join("cas"))
                .unwrap_or_else(|error| panic!("open CAS: {error}"));
            Self { root, state, store }
        }
    }

    impl Drop for TestContext {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn writes_are_deduplicated_and_survive_restart() {
        let mut ctx = TestContext::new("dedupe");
        let first = ctx
            .store
            .put(&mut ctx.state, b"same immutable bytes")
            .unwrap_or_else(|error| panic!("put first: {error}"));
        let second = ctx
            .store
            .put(&mut ctx.state, b"same immutable bytes")
            .unwrap_or_else(|error| panic!("put second: {error}"));
        assert_eq!(first, second);

        let object = ctx.store.object_path(&first.digest).unwrap_or_default();
        assert!(object.exists());
        let replacement = StateStore::open(ctx.root.join("replacement.sqlite3"))
            .unwrap_or_else(|error| panic!("temporary replacement: {error}"));
        let old_state = std::mem::replace(&mut ctx.state, replacement);
        drop(old_state);
        ctx.state = StateStore::open(ctx.root.join("state.sqlite3"))
            .unwrap_or_else(|error| panic!("reopen state: {error}"));
        let mut file = ctx
            .store
            .open_artifact(&ctx.state, &first.digest)
            .unwrap_or_else(|error| panic!("open object: {error}"));
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)
            .unwrap_or_else(|error| panic!("read object: {error}"));
        assert_eq!(contents, b"same immutable bytes");
    }

    #[test]
    fn interrupted_temp_write_is_never_published_or_registered() {
        let ctx = TestContext::new("interrupted");
        let digest = sha256_hex(b"intended complete bytes");
        let temp = ctx.store.root.join("tmp").join("interrupted.tmp");
        fs::write(&temp, b"partial").unwrap_or_else(|error| panic!("partial write: {error}"));

        assert!(!ctx.store.object_path(&digest).unwrap_or_default().exists());
        assert_eq!(
            ctx.state.artifact_metadata(&digest).unwrap_or_default(),
            None
        );
        assert!(temp.exists());
    }

    #[test]
    fn expected_digest_mismatch_is_rejected_without_publish() {
        let mut ctx = TestContext::new("mismatch");
        let expected = sha256_hex(b"expected bytes");
        let result = ctx
            .store
            .put_expected(&mut ctx.state, &expected, b"different bytes");
        assert!(matches!(result, Err(EvidenceError::DigestMismatch { .. })));
        assert_eq!(
            ctx.state.artifact_metadata(&expected).unwrap_or_default(),
            None
        );
    }

    #[test]
    fn range_reads_exact_bytes_and_rejects_overflow() {
        let mut ctx = TestContext::new("range");
        let metadata = ctx
            .store
            .put(&mut ctx.state, b"0123456789")
            .unwrap_or_else(|error| panic!("put: {error}"));
        let range = ctx
            .store
            .range(&ctx.state, &metadata.digest, 3, 4)
            .unwrap_or_else(|error| panic!("range: {error}"));
        assert_eq!(range, b"3456");
        assert!(matches!(
            ctx.store.range(&ctx.state, &metadata.digest, 9, 2),
            Err(EvidenceError::RangeOutOfBounds { .. })
        ));
    }

    #[test]
    fn gc_candidates_select_only_old_unreferenced_objects() {
        let mut ctx = TestContext::new("gc");
        let referenced = ctx
            .store
            .put(&mut ctx.state, b"referenced")
            .unwrap_or_else(|error| panic!("referenced: {error}"));
        let unreferenced = ctx
            .store
            .put(&mut ctx.state, b"unreferenced")
            .unwrap_or_else(|error| panic!("unreferenced: {error}"));
        ctx.state
            .add_artifact_reference("fixture-ref", &referenced.digest)
            .unwrap_or_else(|error| panic!("add reference: {error}"));

        let candidates = ctx
            .store
            .gc_candidates(&ctx.state, Duration::ZERO)
            .unwrap_or_else(|error| panic!("candidates: {error}"));
        assert!(
            candidates
                .iter()
                .any(|candidate| candidate.digest == unreferenced.digest)
        );
        assert!(
            candidates
                .iter()
                .all(|candidate| candidate.digest != referenced.digest)
        );
    }

    #[test]
    fn corrupted_published_object_is_rejected_on_read() {
        let mut ctx = TestContext::new("corrupt");
        let metadata = ctx
            .store
            .put(&mut ctx.state, b"correct")
            .unwrap_or_else(|error| panic!("put: {error}"));
        let path = ctx.store.object_path(&metadata.digest).unwrap_or_default();
        fs::write(path, b"tampered").unwrap_or_else(|error| panic!("tamper: {error}"));
        assert!(matches!(
            ctx.store.open_artifact(&ctx.state, &metadata.digest),
            Err(EvidenceError::CorruptArtifact { .. })
        ));
    }
}
