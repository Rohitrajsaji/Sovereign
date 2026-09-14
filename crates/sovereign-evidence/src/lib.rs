//! Immutable content-addressed artifact storage for Sovereign evidence.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sovereign_state::{StateError, StateStore};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const SHA256_HEX_LEN: usize = 64;
pub const REDACTION_EVENT_SCHEMA_V1: &str = "sovereign-redaction-event-v1";
pub const REDACTOR_VERSION_V1: u32 = 1;

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
    InvalidInput(String),
    NotRetained {
        offset: u64,
        length: usize,
    },
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
            Self::InvalidInput(message) => write!(f, "invalid evidence input: {message}"),
            Self::NotRetained { offset, length } => write!(
                f,
                "requested evidence range offset={offset} length={length} was not retained"
            ),
            Self::Clock(error) => write!(f, "artifact clock error: {error}"),
        }
    }
}

/// Versioned deterministic evidence kind used to select a synopsis strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Compiler,
    Test,
    Search,
    Log,
    Diff,
    Json,
}

/// One retained interval in the post-ingress/redacted raw artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetainedRange {
    pub offset: u64,
    pub length: u64,
}

impl RetainedRange {
    #[must_use]
    pub const fn end(self) -> u64 {
        self.offset.saturating_add(self.length)
    }
}

/// Stable normalized signature used by repair/circuit-breaker logic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureSignature(pub String);

/// Metadata describing one mandatory ingress-redaction event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionEvent {
    pub schema: String,
    pub redactor_version: u32,
    pub event_id: String,
    pub class: String,
    pub occurrences: u64,
}

/// Reusable deterministic ingress redactor. Exact secret values are supplied per invocation and
/// are never retained in this configuration object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Redactor {
    version: u32,
}

impl Default for Redactor {
    fn default() -> Self {
        Self::v1()
    }
}

impl Redactor {
    #[must_use]
    pub const fn v1() -> Self {
        Self {
            version: REDACTOR_VERSION_V1,
        }
    }

    #[must_use]
    pub const fn version(self) -> u32 {
        self.version
    }

    /// Redacts exact injected values and generic v1 credential shapes without persisting input.
    ///
    /// # Errors
    /// Returns an input error for an unsupported redactor version.
    pub fn redact(
        self,
        bytes: &[u8],
        exact_secret_values: &[&str],
    ) -> Result<RedactedIngress, EvidenceError> {
        let exact_secret_bytes = exact_secret_values
            .iter()
            .map(|value| value.as_bytes())
            .collect::<Vec<_>>();
        self.redact_bytes(bytes, &exact_secret_bytes)
    }

    /// Redacts exact byte sequences plus generic v1 credential shapes without UTF-8 conversion.
    ///
    /// This byte-exact entry point is intended for broker-resolved secret material that may not be
    /// valid UTF-8. Exact secret bytes are supplied per invocation and are never retained in the
    /// redactor configuration or redaction-event metadata.
    ///
    /// # Errors
    /// Returns an input error for an unsupported redactor version.
    pub fn redact_bytes(
        self,
        bytes: &[u8],
        exact_secret_values: &[&[u8]],
    ) -> Result<RedactedIngress, EvidenceError> {
        if self.version != REDACTOR_VERSION_V1 {
            return Err(EvidenceError::InvalidInput(format!(
                "unsupported redactor version: {}",
                self.version
            )));
        }
        Ok(redact_ingress_v1(bytes, exact_secret_values))
    }
}

/// Redacted bytes plus safe deterministic audit metadata, suitable for model/audit ingress before
/// any persistence occurs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactedIngress {
    pub bytes: Vec<u8>,
    pub events: Vec<RedactionEvent>,
}

/// Bounded immutable evidence derived from one retained post-ingress artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolEvidence {
    pub schema: String,
    pub action_id: String,
    pub tool: String,
    pub kind: EvidenceKind,
    pub compressor_id: String,
    pub compressor_version: u32,
    pub source_bytes_observed: u64,
    pub post_ingress_bytes: u64,
    pub retained_bytes: u64,
    pub retained_ranges: Vec<RetainedRange>,
    pub redaction_event_ids: Vec<String>,
    pub raw_complete: bool,
    pub truncation_reason: Option<String>,
    pub raw_artifact_digest: String,
    pub synopsis_artifact_digest: String,
    pub synopsis: String,
    pub failure_signature: Option<FailureSignature>,
}

/// Input to deterministic post-ingress evidence capture/compression.
#[derive(Debug, Clone)]
pub struct EvidenceCapture<'a> {
    pub action_id: &'a str,
    pub tool: &'a str,
    pub kind: EvidenceKind,
    pub bytes: &'a [u8],
    pub known_secret_values: &'a [&'a str],
    pub action_raw_spool_limit_bytes: u64,
    pub task_raw_spool_remaining_bytes: u64,
    pub synopsis_limit_bytes: usize,
}

/// Query used to expand already-retained evidence without rerunning a tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceExpandQuery {
    Range { offset: u64, length: usize },
    Query { text: String, max_bytes: usize },
}

/// Result of bounded evidence expansion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceExpansion {
    pub raw_artifact_digest: String,
    pub offset: u64,
    pub bytes: Vec<u8>,
    pub compressor_id: String,
    pub compressor_version: u32,
    pub not_retained: bool,
}

/// Deterministic M1 evidence compressor. It never executes tools.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceCompressor {
    id: String,
    version: u32,
}

impl EvidenceCompressor {
    #[must_use]
    pub fn new(id: impl Into<String>, version: u32) -> Self {
        Self {
            id: id.into(),
            version,
        }
    }

    /// Redacts ingress, publishes quota-bounded retained bytes, and publishes a bounded synopsis.
    ///
    /// # Errors
    /// Returns an evidence error for malformed budgets or CAS/state failures.
    pub fn capture(
        &self,
        store: &ArtifactStore,
        state: &mut StateStore,
        input: &EvidenceCapture<'_>,
    ) -> Result<ToolEvidence, EvidenceError> {
        if self.id.trim().is_empty()
            || self.version == 0
            || input.action_id.trim().is_empty()
            || input.tool.trim().is_empty()
            || input.action_raw_spool_limit_bytes == 0
            || input.synopsis_limit_bytes == 0
        {
            return Err(EvidenceError::InvalidInput(
                "compressor identity, evidence identity, action spool budget, and synopsis budget must be non-empty/positive"
                    .to_owned(),
            ));
        }
        let redacted_ingress = Redactor::v1().redact(input.bytes, input.known_secret_values)?;
        let redacted = redacted_ingress.bytes;
        let redactions = redacted_ingress.events;
        let effective_raw_limit = input
            .action_raw_spool_limit_bytes
            .min(input.task_raw_spool_remaining_bytes);
        let retain_limit = usize::try_from(effective_raw_limit).unwrap_or(usize::MAX);
        let retained_len = redacted.len().min(retain_limit);
        let retained = &redacted[..retained_len];
        let raw = store.put(state, retained)?;
        let raw_complete = retained_len == redacted.len();
        let retained_ranges = if retained_len == 0 {
            Vec::new()
        } else {
            vec![RetainedRange {
                offset: 0,
                length: u64::try_from(retained_len).unwrap_or(u64::MAX),
            }]
        };
        let failure_signature = failure_signature(input.kind, retained);
        let synopsis = build_synopsis(
            input.kind,
            retained,
            input.synopsis_limit_bytes,
            failure_signature.as_ref(),
        );
        let redaction_event_ids = redactions
            .iter()
            .map(|event| event.event_id.clone())
            .collect::<Vec<_>>();
        let mut evidence = ToolEvidence {
            schema: "sovereign-tool-evidence-v1".to_owned(),
            action_id: input.action_id.to_owned(),
            tool: input.tool.to_owned(),
            kind: input.kind,
            compressor_id: self.id.clone(),
            compressor_version: self.version,
            source_bytes_observed: u64::try_from(input.bytes.len()).unwrap_or(u64::MAX),
            post_ingress_bytes: u64::try_from(redacted.len()).unwrap_or(u64::MAX),
            retained_bytes: u64::try_from(retained_len).unwrap_or(u64::MAX),
            retained_ranges,
            redaction_event_ids,
            raw_complete,
            truncation_reason: (!raw_complete).then(|| {
                match input
                    .action_raw_spool_limit_bytes
                    .cmp(&input.task_raw_spool_remaining_bytes)
                {
                    std::cmp::Ordering::Less => "action_raw_spool_quota_exceeded",
                    std::cmp::Ordering::Greater => "task_raw_spool_quota_exceeded",
                    std::cmp::Ordering::Equal => "action_and_task_raw_spool_quota_exceeded",
                }
                .to_owned()
            }),
            raw_artifact_digest: raw.digest,
            synopsis_artifact_digest: String::new(),
            synopsis,
            failure_signature,
        };
        let synopsis_bytes = canonical_synopsis_bytes(&evidence)?;
        let synopsis_artifact = store.put(state, &synopsis_bytes)?;
        evidence.synopsis_artifact_digest = synopsis_artifact.digest;
        Ok(evidence)
    }

    /// Rebuilds a synopsis from immutable historical retained bytes without rewriting raw evidence.
    ///
    /// # Errors
    /// Returns an evidence error if the retained raw artifact cannot be read or republished.
    pub fn recompress(
        &self,
        store: &ArtifactStore,
        state: &mut StateStore,
        prior: &ToolEvidence,
        synopsis_limit_bytes: usize,
    ) -> Result<ToolEvidence, EvidenceError> {
        let retained_len = usize::try_from(prior.retained_bytes).map_err(|_| {
            EvidenceError::InvalidInput("retained byte count overflows usize".to_owned())
        })?;
        let retained = store.range(state, &prior.raw_artifact_digest, 0, retained_len)?;
        let failure_signature = failure_signature(prior.kind, &retained);
        let synopsis = build_synopsis(
            prior.kind,
            &retained,
            synopsis_limit_bytes,
            failure_signature.as_ref(),
        );
        let mut next = prior.clone();
        next.compressor_id.clone_from(&self.id);
        next.compressor_version = self.version;
        next.synopsis = synopsis;
        next.failure_signature = failure_signature;
        next.synopsis_artifact_digest.clear();
        let bytes = canonical_synopsis_bytes(&next)?;
        next.synopsis_artifact_digest = store.put(state, &bytes)?.digest;
        Ok(next)
    }

    /// Expands retained evidence by exact range or bounded textual query. No command is rerun.
    ///
    /// # Errors
    /// Returns an evidence error on malformed query/CAS failure. Requests beyond a truncated
    /// retained boundary return an explicit `not_retained` expansion rather than fabricated data.
    pub fn expand(
        &self,
        store: &ArtifactStore,
        state: &StateStore,
        evidence: &ToolEvidence,
        query: &EvidenceExpandQuery,
    ) -> Result<EvidenceExpansion, EvidenceError> {
        match query {
            EvidenceExpandQuery::Range { offset, length } => {
                let requested_end = offset
                    .checked_add(u64::try_from(*length).unwrap_or(u64::MAX))
                    .unwrap_or(u64::MAX);
                if !range_is_retained(&evidence.retained_ranges, *offset, requested_end) {
                    if evidence.raw_complete {
                        return Err(EvidenceError::RangeOutOfBounds {
                            offset: *offset,
                            length: *length,
                            size: evidence.retained_bytes,
                        });
                    }
                    return Ok(EvidenceExpansion {
                        raw_artifact_digest: evidence.raw_artifact_digest.clone(),
                        offset: *offset,
                        bytes: Vec::new(),
                        compressor_id: self.id.clone(),
                        compressor_version: self.version,
                        not_retained: true,
                    });
                }
                Ok(EvidenceExpansion {
                    raw_artifact_digest: evidence.raw_artifact_digest.clone(),
                    offset: *offset,
                    bytes: store.range(state, &evidence.raw_artifact_digest, *offset, *length)?,
                    compressor_id: self.id.clone(),
                    compressor_version: self.version,
                    not_retained: false,
                })
            }
            EvidenceExpandQuery::Query { text, max_bytes } => {
                if text.is_empty() || *max_bytes == 0 {
                    return Err(EvidenceError::InvalidInput(
                        "expansion query and max_bytes must be non-empty/positive".to_owned(),
                    ));
                }
                let retained_len = usize::try_from(evidence.retained_bytes).map_err(|_| {
                    EvidenceError::InvalidInput("retained byte count overflows usize".to_owned())
                })?;
                let bytes = store.range(state, &evidence.raw_artifact_digest, 0, retained_len)?;
                let haystack = String::from_utf8_lossy(&bytes);
                let Some(found) = haystack.find(text) else {
                    return Ok(EvidenceExpansion {
                        raw_artifact_digest: evidence.raw_artifact_digest.clone(),
                        offset: 0,
                        bytes: Vec::new(),
                        compressor_id: self.id.clone(),
                        compressor_version: self.version,
                        not_retained: !evidence.raw_complete,
                    });
                };
                let start = found.saturating_sub(*max_bytes / 4);
                let end = bytes.len().min(start.saturating_add(*max_bytes));
                Ok(EvidenceExpansion {
                    raw_artifact_digest: evidence.raw_artifact_digest.clone(),
                    offset: u64::try_from(start).unwrap_or(u64::MAX),
                    bytes: bytes[start..end].to_vec(),
                    compressor_id: self.id.clone(),
                    compressor_version: self.version,
                    not_retained: false,
                })
            }
        }
    }
}

fn canonical_synopsis_bytes(evidence: &ToolEvidence) -> Result<Vec<u8>, EvidenceError> {
    serde_json::to_vec(evidence)
        .map_err(|error| EvidenceError::InvalidInput(format!("synopsis serialization: {error}")))
}

fn range_is_retained(ranges: &[RetainedRange], start: u64, end: u64) -> bool {
    start <= end
        && ranges
            .iter()
            .any(|range| start >= range.offset && end <= range.end())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GenericCredentialShape {
    Bearer {
        class: &'static str,
        ordinal: usize,
    },
    Assignment {
        key: &'static [u8],
        class: &'static str,
        ordinal: usize,
    },
    Json {
        key: &'static [u8],
        class: &'static str,
        ordinal: usize,
    },
}

impl GenericCredentialShape {
    const fn class(self) -> &'static str {
        match self {
            Self::Bearer { class, .. }
            | Self::Assignment { class, .. }
            | Self::Json { class, .. } => class,
        }
    }

    const fn ordinal(self) -> usize {
        match self {
            Self::Bearer { ordinal, .. }
            | Self::Assignment { ordinal, .. }
            | Self::Json { ordinal, .. } => ordinal,
        }
    }
}

const GENERIC_CREDENTIAL_SHAPES_V1: [GenericCredentialShape; 19] = [
    GenericCredentialShape::Bearer {
        class: "bearer_token",
        ordinal: 0,
    },
    GenericCredentialShape::Assignment {
        key: b"npm_auth_token",
        class: "package_token",
        ordinal: 1,
    },
    GenericCredentialShape::Assignment {
        key: b"npm_token",
        class: "package_token",
        ordinal: 2,
    },
    GenericCredentialShape::Assignment {
        key: b"_authtoken",
        class: "package_token",
        ordinal: 3,
    },
    GenericCredentialShape::Assignment {
        key: b"access_token",
        class: "token",
        ordinal: 4,
    },
    GenericCredentialShape::Assignment {
        key: b"client_secret",
        class: "secret",
        ordinal: 5,
    },
    GenericCredentialShape::Assignment {
        key: b"api_key",
        class: "api_key",
        ordinal: 6,
    },
    GenericCredentialShape::Assignment {
        key: b"api-key",
        class: "api_key",
        ordinal: 7,
    },
    GenericCredentialShape::Assignment {
        key: b"apikey",
        class: "api_key",
        ordinal: 8,
    },
    GenericCredentialShape::Assignment {
        key: b"token",
        class: "token",
        ordinal: 9,
    },
    GenericCredentialShape::Assignment {
        key: b"password",
        class: "password",
        ordinal: 10,
    },
    GenericCredentialShape::Assignment {
        key: b"passwd",
        class: "password",
        ordinal: 11,
    },
    GenericCredentialShape::Assignment {
        key: b"secret",
        class: "secret",
        ordinal: 12,
    },
    GenericCredentialShape::Json {
        key: b"_authtoken",
        class: "json_package_token",
        ordinal: 13,
    },
    GenericCredentialShape::Json {
        key: b"api_key",
        class: "json_api_key",
        ordinal: 14,
    },
    GenericCredentialShape::Json {
        key: b"apikey",
        class: "json_api_key",
        ordinal: 15,
    },
    GenericCredentialShape::Json {
        key: b"token",
        class: "json_token",
        ordinal: 16,
    },
    GenericCredentialShape::Json {
        key: b"password",
        class: "json_password",
        ordinal: 17,
    },
    GenericCredentialShape::Json {
        key: b"secret",
        class: "json_secret",
        ordinal: 18,
    },
];

fn redact_ingress_v1(bytes: &[u8], known_secret_values: &[&[u8]]) -> RedactedIngress {
    let mut current = bytes.to_vec();
    let mut events = Vec::new();
    let mut exact_secrets = known_secret_values
        .iter()
        .copied()
        .filter(|secret| !secret.is_empty())
        .collect::<Vec<_>>();
    exact_secrets
        .sort_unstable_by(|left, right| right.len().cmp(&left.len()).then_with(|| left.cmp(right)));
    exact_secrets.dedup();
    for (index, secret) in exact_secrets.into_iter().enumerate() {
        let (next, count) = replace_all(&current, secret, b"[REDACTED]");
        current = next;
        if count > 0 {
            events.push(redaction_event("known_secret", index, count));
        }
    }

    for shape in GENERIC_CREDENTIAL_SHAPES_V1 {
        let (next, count) = redact_generic_shape(&current, shape);
        current = next;
        if count > 0 {
            events.push(redaction_event(shape.class(), shape.ordinal(), count));
        }
    }
    let (next, count) = redact_sk_tokens(&current);
    current = next;
    if count > 0 {
        events.push(redaction_event("api_token_shape", 0, count));
    }
    RedactedIngress {
        bytes: current,
        events,
    }
}

fn replace_all(source: &[u8], needle: &[u8], replacement: &[u8]) -> (Vec<u8>, usize) {
    if needle.is_empty() {
        return (source.to_vec(), 0);
    }
    let mut result = Vec::with_capacity(source.len());
    let mut cursor = 0;
    let mut count = 0;
    while cursor < source.len() {
        if source[cursor..].starts_with(needle) {
            result.extend_from_slice(replacement);
            cursor += needle.len();
            count += 1;
        } else {
            result.push(source[cursor]);
            cursor += 1;
        }
    }
    (result, count)
}

fn redact_generic_shape(source: &[u8], shape: GenericCredentialShape) -> (Vec<u8>, usize) {
    let mut result = Vec::with_capacity(source.len());
    let mut cursor = 0;
    let mut count = 0;
    while cursor < source.len() {
        if let Some(value) = match_generic_value(source, cursor, shape) {
            result.extend_from_slice(&source[cursor..value.start]);
            if value.end > value.start {
                result.extend_from_slice(b"[REDACTED]");
                count += 1;
            }
            cursor = value.end;
        } else {
            result.push(source[cursor]);
            cursor += 1;
        }
    }
    (result, count)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ValueSpan {
    start: usize,
    end: usize,
}

fn match_generic_value(
    source: &[u8],
    cursor: usize,
    shape: GenericCredentialShape,
) -> Option<ValueSpan> {
    match shape {
        GenericCredentialShape::Bearer { .. } => match_bearer_value(source, cursor),
        GenericCredentialShape::Assignment { key, .. } => {
            match_key_value(source, cursor, key, b'=')
        }
        GenericCredentialShape::Json { key, .. } => match_json_value(source, cursor, key),
    }
}

fn match_bearer_value(source: &[u8], cursor: usize) -> Option<ValueSpan> {
    let header = b"authorization";
    if !key_boundary_before(source, cursor)
        || !ascii_starts_with_ignore_case(&source[cursor..], header)
    {
        return None;
    }
    let mut index = cursor + header.len();
    index = skip_ascii_ows(source, index);
    if source.get(index) != Some(&b':') {
        return None;
    }
    index = skip_ascii_ows(source, index + 1);
    let scheme = b"bearer";
    if !ascii_starts_with_ignore_case(&source[index..], scheme) {
        return None;
    }
    index += scheme.len();
    let value_start = skip_ascii_ows(source, index);
    if value_start == index {
        return None;
    }
    quoted_or_bare_value_span(source, value_start)
}

fn match_key_value(source: &[u8], cursor: usize, key: &[u8], separator: u8) -> Option<ValueSpan> {
    if !key_boundary_before(source, cursor)
        || !ascii_starts_with_ignore_case(&source[cursor..], key)
        || !key_boundary_after(source, cursor + key.len())
    {
        return None;
    }
    let mut index = skip_ascii_ows(source, cursor + key.len());
    if source.get(index) != Some(&separator) {
        return None;
    }
    index = skip_ascii_ows(source, index + 1);
    quoted_or_bare_value_span(source, index)
}

fn match_json_value(source: &[u8], cursor: usize, key: &[u8]) -> Option<ValueSpan> {
    let quote = *source.get(cursor)?;
    if !matches!(quote, b'"' | b'\'') {
        return None;
    }
    let key_start = cursor + 1;
    if !ascii_starts_with_ignore_case(&source[key_start..], key)
        || source.get(key_start + key.len()) != Some(&quote)
    {
        return None;
    }
    let mut index = skip_ascii_ows(source, key_start + key.len() + 1);
    if source.get(index) != Some(&b':') {
        return None;
    }
    index = skip_ascii_ows(source, index + 1);
    quoted_or_bare_value_span(source, index)
}

fn quoted_or_bare_value_span(source: &[u8], start: usize) -> Option<ValueSpan> {
    let first = *source.get(start)?;
    if matches!(first, b'"' | b'\'') {
        let value_start = start + 1;
        let mut end = value_start;
        while end < source.len() && source[end] != first {
            end += 1;
        }
        return (end > value_start).then_some(ValueSpan {
            start: value_start,
            end,
        });
    }

    let mut end = start;
    while end < source.len()
        && !source[end].is_ascii_whitespace()
        && !matches!(source[end], b',' | b';' | b'}' | b']' | b'"' | b'\'')
    {
        end += 1;
    }
    (end > start).then_some(ValueSpan { start, end })
}

const fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}

fn key_boundary_before(source: &[u8], cursor: usize) -> bool {
    cursor == 0
        || source
            .get(cursor - 1)
            .is_none_or(|byte| !is_identifier_byte(*byte))
}

fn key_boundary_after(source: &[u8], cursor: usize) -> bool {
    source
        .get(cursor)
        .is_none_or(|byte| !is_identifier_byte(*byte))
}

fn skip_ascii_ows(source: &[u8], mut cursor: usize) -> usize {
    while matches!(source.get(cursor), Some(b' ' | b'\t')) {
        cursor += 1;
    }
    cursor
}

fn ascii_starts_with_ignore_case(source: &[u8], prefix: &[u8]) -> bool {
    source.len() >= prefix.len()
        && source[..prefix.len()]
            .iter()
            .zip(prefix)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

fn redact_sk_tokens(source: &[u8]) -> (Vec<u8>, usize) {
    let mut result = Vec::with_capacity(source.len());
    let mut cursor = 0;
    let mut count = 0;
    while cursor < source.len() {
        if ascii_starts_with_ignore_case(&source[cursor..], b"sk-") {
            let mut end = cursor + 3;
            while end < source.len()
                && (source[end].is_ascii_alphanumeric() || matches!(source[end], b'_' | b'-'))
            {
                end += 1;
            }
            if end.saturating_sub(cursor) >= 19 {
                result.extend_from_slice(b"[REDACTED]");
                cursor = end;
                count += 1;
                continue;
            }
        }
        result.push(source[cursor]);
        cursor += 1;
    }
    (result, count)
}

fn redaction_event(class: &str, ordinal: usize, count: usize) -> RedactionEvent {
    let seed =
        format!("{REDACTION_EVENT_SCHEMA_V1}:{REDACTOR_VERSION_V1}:{class}:{ordinal}:{count}");
    RedactionEvent {
        schema: REDACTION_EVENT_SCHEMA_V1.to_owned(),
        redactor_version: REDACTOR_VERSION_V1,
        event_id: format!("redact_{}", &sha256_hex(seed.as_bytes())[..16]),
        class: class.to_owned(),
        occurrences: u64::try_from(count).unwrap_or(u64::MAX),
    }
}

fn failure_signature(kind: EvidenceKind, bytes: &[u8]) -> Option<FailureSignature> {
    let text = String::from_utf8_lossy(bytes);
    let primary = primary_failure_line(kind, &text)?;
    let normalized = normalize_failure(&primary);
    let kind_name = evidence_kind_name(kind);
    let digest = sha256_hex(normalized.as_bytes());
    Some(FailureSignature(format!(
        "{kind_name}:{}:{}",
        compact_failure_label(&normalized),
        &digest[..16]
    )))
}

fn primary_failure_line(kind: EvidenceKind, text: &str) -> Option<String> {
    match kind {
        EvidenceKind::Compiler => text
            .lines()
            .find(|line| {
                let lower = line.to_ascii_lowercase();
                lower.contains("error[") || lower.trim_start().starts_with("error:")
            })
            .map(str::trim)
            .map(str::to_owned),
        EvidenceKind::Test => text
            .lines()
            .find(|line| {
                let lower = line.to_ascii_lowercase();
                lower.contains(" failed")
                    || lower.starts_with("failed ")
                    || lower.contains("failures:")
                    || lower.contains("assertion failed")
            })
            .map(str::trim)
            .map(str::to_owned),
        _ => text
            .lines()
            .find(|line| {
                let lower = line.to_ascii_lowercase();
                lower.contains("error") || lower.contains("failed") || lower.contains("panic")
            })
            .map(str::trim)
            .map(str::to_owned),
    }
}

fn normalize_failure(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    let mut in_digits = false;
    for character in value.chars() {
        if character.is_ascii_digit() {
            if !in_digits {
                result.push('#');
                in_digits = true;
            }
        } else {
            in_digits = false;
            if !character.is_whitespace() || !result.ends_with(' ') {
                result.push(if character.is_whitespace() {
                    ' '
                } else {
                    character
                });
            }
        }
    }
    result.trim().to_ascii_lowercase()
}

fn compact_failure_label(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
        .take(32)
        .collect::<String>()
}

const fn evidence_kind_name(kind: EvidenceKind) -> &'static str {
    match kind {
        EvidenceKind::Compiler => "compiler",
        EvidenceKind::Test => "test",
        EvidenceKind::Search => "search",
        EvidenceKind::Log => "log",
        EvidenceKind::Diff => "diff",
        EvidenceKind::Json => "json",
    }
}

fn build_synopsis(
    kind: EvidenceKind,
    bytes: &[u8],
    limit: usize,
    signature: Option<&FailureSignature>,
) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut lines = Vec::new();
    lines.push(format!("kind={}", evidence_kind_name(kind)));
    lines.push(format!("retained_bytes={}", bytes.len()));
    if let Some(signature) = signature {
        lines.push(format!("failure_signature={}", signature.0));
    }
    match kind {
        EvidenceKind::Compiler => compiler_synopsis(&text, &mut lines),
        EvidenceKind::Test => test_synopsis(&text, &mut lines),
        EvidenceKind::Search => search_synopsis(&text, &mut lines),
        EvidenceKind::Diff => diff_synopsis(&text, &mut lines),
        EvidenceKind::Json => json_synopsis(&text, &mut lines),
        EvidenceKind::Log => log_synopsis(&text, &mut lines),
    }
    bounded_lines(lines, limit)
}

fn compiler_synopsis(text: &str, output: &mut Vec<String>) {
    let errors = text
        .lines()
        .filter(|line| {
            let lower = line.to_ascii_lowercase();
            lower.contains("error[") || lower.trim_start().starts_with("error:")
        })
        .map(str::trim)
        .collect::<Vec<_>>();
    output.push(format!("error_count={}", errors.len()));
    if let Some(primary) = errors.first() {
        output.push(format!("primary_error={primary}"));
    }
    for line in text
        .lines()
        .filter(|line| line.contains("-->") || line.contains("warning:"))
        .take(6)
    {
        output.push(line.trim().to_owned());
    }
}

fn test_synopsis(text: &str, output: &mut Vec<String>) {
    let mut failures = BTreeSet::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(name) = trimmed
            .strip_prefix("test ")
            .and_then(|rest| rest.strip_suffix(" ... FAILED"))
        {
            failures.insert(name.to_owned());
        } else if let Some(name) = trimmed.strip_prefix("FAILED ") {
            failures.insert(name.to_owned());
        }
    }
    output.push(format!("failed_test_count={}", failures.len()));
    for failure in failures.into_iter().take(12) {
        output.push(format!("failed_test={failure}"));
    }
    for line in text
        .lines()
        .filter(|line| line.to_ascii_lowercase().contains("assertion"))
        .take(4)
    {
        output.push(line.trim().to_owned());
    }
}

fn search_synopsis(text: &str, output: &mut Vec<String>) {
    let mut per_file = BTreeMap::<String, usize>::new();
    for line in text.lines() {
        if let Some((file, _)) = line.split_once(':') {
            *per_file.entry(file.to_owned()).or_default() += 1;
        }
    }
    output.push(format!("matched_file_count={}", per_file.len()));
    for (file, count) in per_file.into_iter().take(12) {
        output.push(format!("match={file}:{count}"));
    }
}

fn diff_synopsis(text: &str, output: &mut Vec<String>) {
    let files = text
        .lines()
        .filter(|line| line.starts_with("diff --git "))
        .count();
    let additions = text
        .lines()
        .filter(|line| line.starts_with('+') && !line.starts_with("+++"))
        .count();
    let deletions = text
        .lines()
        .filter(|line| line.starts_with('-') && !line.starts_with("---"))
        .count();
    output.push(format!("changed_files={files}"));
    output.push(format!("additions={additions}"));
    output.push(format!("deletions={deletions}"));
    for line in text.lines().filter(|line| line.starts_with("@@")).take(8) {
        output.push(line.to_owned());
    }
}

fn json_synopsis(text: &str, output: &mut Vec<String>) {
    match serde_json::from_str::<serde_json::Value>(text) {
        Ok(serde_json::Value::Object(map)) => {
            output.push(format!("json_kind=object keys={}", map.len()));
            output.push(format!(
                "keys={}",
                map.keys().take(16).cloned().collect::<Vec<_>>().join(",")
            ));
        }
        Ok(serde_json::Value::Array(values)) => {
            output.push(format!("json_kind=array items={}", values.len()));
        }
        Ok(_) => output.push("json_kind=scalar".to_owned()),
        Err(_) => output.push("json_kind=invalid".to_owned()),
    }
}

fn log_synopsis(text: &str, output: &mut Vec<String>) {
    let all = text.lines().collect::<Vec<_>>();
    let error_count = all
        .iter()
        .filter(|line| line.to_ascii_lowercase().contains("error"))
        .count();
    let warning_count = all
        .iter()
        .filter(|line| line.to_ascii_lowercase().contains("warning"))
        .count();
    output.push(format!("line_count={}", all.len()));
    output.push(format!("error_lines={error_count}"));
    output.push(format!("warning_lines={warning_count}"));
    for line in all.iter().take(6) {
        output.push(format!("head={}", line.trim()));
    }
    for line in all
        .iter()
        .filter(|line| {
            let lower = line.to_ascii_lowercase();
            lower.contains("error") || lower.contains("warning") || lower.contains("panic")
        })
        .take(10)
    {
        output.push(format!("signal={}", line.trim()));
    }
    for line in all
        .iter()
        .rev()
        .take(6)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
    {
        output.push(format!("tail={}", line.trim()));
    }
}

fn bounded_lines(lines: Vec<String>, limit: usize) -> String {
    let mut result = String::new();
    for line in lines {
        let separator = usize::from(!result.is_empty());
        if result
            .len()
            .saturating_add(separator)
            .saturating_add(line.len())
            > limit
        {
            break;
        }
        if !result.is_empty() {
            result.push('\n');
        }
        result.push_str(&line);
    }
    if result.is_empty() && limit > 0 {
        "truncated".chars().take(limit).collect()
    } else {
        result
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
