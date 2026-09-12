use sovereign_evidence::{
    ArtifactStore, EvidenceCapture, EvidenceCompressor, EvidenceExpandQuery, EvidenceKind,
};
use sovereign_state::StateStore;
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

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
            "sovereign-evidence-compression-{label}-{}-{nonce}",
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

fn capture<'a>(
    action_id: &'a str,
    kind: EvidenceKind,
    bytes: &'a [u8],
    known_secret_values: &'a [&'a str],
    raw_limit: u64,
    synopsis_limit: usize,
) -> EvidenceCapture<'a> {
    EvidenceCapture {
        action_id,
        tool: "fixture.tool",
        kind,
        bytes,
        known_secret_values,
        action_raw_spool_limit_bytes: raw_limit,
        task_raw_spool_remaining_bytes: raw_limit,
        synopsis_limit_bytes: synopsis_limit,
    }
}

#[test]
fn ten_thousand_line_log_compresses_within_model_facing_budget() {
    let mut ctx = TestContext::new("large-log");
    let mut raw = String::new();
    for index in 0..10_000 {
        if index == 5_123 {
            raw.push_str("ERROR database fixture failed at item 5123\n");
        } else {
            writeln!(&mut raw, "INFO line {index} completed normally")
                .unwrap_or_else(|error| panic!("write fixture line: {error}"));
        }
    }
    let compressor = EvidenceCompressor::new("generic-log", 1);
    let evidence = compressor
        .capture(
            &ctx.store,
            &mut ctx.state,
            &capture(
                "act_large_log",
                EvidenceKind::Log,
                raw.as_bytes(),
                &[],
                2_000_000,
                1_024,
            ),
        )
        .unwrap_or_else(|error| panic!("capture: {error}"));
    assert!(evidence.synopsis.len() <= 1_024);
    assert!(evidence.synopsis.contains("line_count=10000"));
    assert!(evidence.synopsis.contains("ERROR database fixture failed"));
    assert!(evidence.retained_bytes > u64::try_from(evidence.synopsis.len()).unwrap_or(u64::MAX));
    eprintln!(
        "compression_fixture raw_bytes={} synopsis_bytes={}",
        evidence.retained_bytes,
        evidence.synopsis.len()
    );
}

#[test]
fn retained_post_ingress_bytes_are_byte_for_byte_recoverable() {
    let mut ctx = TestContext::new("recoverable");
    let raw = b"alpha\0beta\nplain bytes\xfftail";
    let compressor = EvidenceCompressor::new("raw-v1", 1);
    let evidence = compressor
        .capture(
            &ctx.store,
            &mut ctx.state,
            &capture("act_recoverable", EvidenceKind::Log, raw, &[], 4_096, 512),
        )
        .unwrap_or_else(|error| panic!("capture: {error}"));
    let expanded = compressor
        .expand(
            &ctx.store,
            &ctx.state,
            &evidence,
            &EvidenceExpandQuery::Range {
                offset: 0,
                length: raw.len(),
            },
        )
        .unwrap_or_else(|error| panic!("expand: {error}"));
    assert!(!expanded.not_retained);
    assert_eq!(expanded.bytes, raw);
}

#[test]
fn known_and_generic_credentials_are_redacted_before_cas_persistence() {
    let mut ctx = TestContext::new("redaction");
    let known = "known-secret-value";
    let raw = format!(
        "exact={known}\nAuthorization: Bearer bearer-value\nAPI_KEY=api-value\npassword=hunter2\nkey=sk-abcdefghijklmnopqrstuvwxyz123456\n{{\"token\":\"json-token-value\"}}\n"
    );
    let compressor = EvidenceCompressor::new("redaction-v1", 1);
    let evidence = compressor
        .capture(
            &ctx.store,
            &mut ctx.state,
            &capture(
                "act_redact",
                EvidenceKind::Log,
                raw.as_bytes(),
                &[known],
                16 * 1024,
                1_024,
            ),
        )
        .unwrap_or_else(|error| panic!("capture: {error}"));
    let retained = ctx
        .store
        .range(
            &ctx.state,
            &evidence.raw_artifact_digest,
            0,
            usize::try_from(evidence.retained_bytes).unwrap_or(usize::MAX),
        )
        .unwrap_or_else(|error| panic!("raw range: {error}"));
    let retained_text = String::from_utf8_lossy(&retained);
    for secret in [
        known,
        "bearer-value",
        "api-value",
        "hunter2",
        "sk-abcdefghijklmnopqrstuvwxyz123456",
        "json-token-value",
    ] {
        assert!(!retained_text.contains(secret), "secret leaked: {secret}");
    }
    assert!(retained_text.matches("[REDACTED]").count() >= 6);
    assert!(!evidence.redaction_event_ids.is_empty());
}

#[test]
fn spool_quota_exceedance_records_explicit_truncation_metadata() {
    let mut ctx = TestContext::new("quota");
    let raw = vec![b'x'; 4_096];
    let compressor = EvidenceCompressor::new("quota-v1", 1);
    let evidence = compressor
        .capture(
            &ctx.store,
            &mut ctx.state,
            &capture("act_quota", EvidenceKind::Log, &raw, &[], 1_024, 256),
        )
        .unwrap_or_else(|error| panic!("capture: {error}"));
    assert!(!evidence.raw_complete);
    assert_eq!(evidence.source_bytes_observed, 4_096);
    assert_eq!(evidence.post_ingress_bytes, 4_096);
    assert_eq!(evidence.retained_bytes, 1_024);
    assert_eq!(evidence.retained_ranges.len(), 1);
    assert_eq!(evidence.retained_ranges[0].offset, 0);
    assert_eq!(evidence.retained_ranges[0].length, 1_024);
    assert_eq!(
        evidence.truncation_reason.as_deref(),
        Some("action_and_task_raw_spool_quota_exceeded")
    );
}

#[test]
fn task_spool_remaining_budget_can_be_stricter_than_action_budget() {
    let mut ctx = TestContext::new("task-quota");
    let raw = vec![b'z'; 4_096];
    let compressor = EvidenceCompressor::new("quota-v1", 1);
    let input = EvidenceCapture {
        action_id: "act_task_quota",
        tool: "fixture.tool",
        kind: EvidenceKind::Log,
        bytes: &raw,
        known_secret_values: &[],
        action_raw_spool_limit_bytes: 2_048,
        task_raw_spool_remaining_bytes: 768,
        synopsis_limit_bytes: 256,
    };
    let evidence = compressor
        .capture(&ctx.store, &mut ctx.state, &input)
        .unwrap_or_else(|error| panic!("capture: {error}"));
    assert_eq!(evidence.retained_bytes, 768);
    assert_eq!(
        evidence.truncation_reason.as_deref(),
        Some("task_raw_spool_quota_exceeded")
    );
}

#[test]
fn exhausted_task_spool_budget_records_zero_retained_bytes() {
    let mut ctx = TestContext::new("task-quota-exhausted");
    let raw = b"later action output cannot exceed the task-wide retained-raw quota";
    let compressor = EvidenceCompressor::new("quota-v1", 1);
    let input = EvidenceCapture {
        action_id: "act_task_quota_exhausted",
        tool: "fixture.tool",
        kind: EvidenceKind::Log,
        bytes: raw,
        known_secret_values: &[],
        action_raw_spool_limit_bytes: 2_048,
        task_raw_spool_remaining_bytes: 0,
        synopsis_limit_bytes: 256,
    };
    let evidence = compressor
        .capture(&ctx.store, &mut ctx.state, &input)
        .unwrap_or_else(|error| panic!("capture: {error}"));
    assert_eq!(evidence.retained_bytes, 0);
    assert!(evidence.retained_ranges.is_empty());
    assert!(!evidence.raw_complete);
    assert_eq!(
        evidence.truncation_reason.as_deref(),
        Some("task_raw_spool_quota_exceeded")
    );
    assert_eq!(
        ctx.store
            .range(&ctx.state, &evidence.raw_artifact_digest, 0, 0)
            .unwrap_or_else(|error| panic!("read empty raw artifact: {error}")),
        Vec::<u8>::new()
    );
}

#[test]
fn expansion_reads_retained_artifact_without_rerunning_tool() {
    let mut ctx = TestContext::new("expand-range");
    let raw = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let compressor = EvidenceCompressor::new("expand-v1", 1);
    let evidence = compressor
        .capture(
            &ctx.store,
            &mut ctx.state,
            &capture("act_expand", EvidenceKind::Log, raw, &[], 4_096, 256),
        )
        .unwrap_or_else(|error| panic!("capture: {error}"));
    let expansion = compressor
        .expand(
            &ctx.store,
            &ctx.state,
            &evidence,
            &EvidenceExpandQuery::Range {
                offset: 10,
                length: 5,
            },
        )
        .unwrap_or_else(|error| panic!("expand: {error}"));
    assert_eq!(expansion.bytes, b"abcde");
    assert_eq!(expansion.raw_artifact_digest, evidence.raw_artifact_digest);
}

#[test]
fn expansion_beyond_truncated_range_returns_explicit_not_retained() {
    let mut ctx = TestContext::new("not-retained");
    let raw = vec![b'a'; 2_048];
    let compressor = EvidenceCompressor::new("expand-v1", 1);
    let evidence = compressor
        .capture(
            &ctx.store,
            &mut ctx.state,
            &capture("act_not_retained", EvidenceKind::Log, &raw, &[], 512, 256),
        )
        .unwrap_or_else(|error| panic!("capture: {error}"));
    let expansion = compressor
        .expand(
            &ctx.store,
            &ctx.state,
            &evidence,
            &EvidenceExpandQuery::Range {
                offset: 600,
                length: 10,
            },
        )
        .unwrap_or_else(|error| panic!("expand: {error}"));
    assert!(expansion.not_retained);
    assert!(expansion.bytes.is_empty());
}

#[test]
fn synopsis_records_required_provenance_and_digests() {
    let mut ctx = TestContext::new("provenance");
    let compressor = EvidenceCompressor::new("compiler-rust", 7);
    let secret = "provenance-secret";
    let raw =
        format!("error[E0382]: borrow of moved value `x`\n --> src/lib.rs:21:4\nsecret={secret}\n");
    let evidence = compressor
        .capture(
            &ctx.store,
            &mut ctx.state,
            &capture(
                "act_provenance",
                EvidenceKind::Compiler,
                raw.as_bytes(),
                &[secret],
                4_096,
                512,
            ),
        )
        .unwrap_or_else(|error| panic!("capture: {error}"));
    assert_eq!(evidence.compressor_id, "compiler-rust");
    assert_eq!(evidence.compressor_version, 7);
    assert!(!evidence.raw_artifact_digest.is_empty());
    assert!(!evidence.synopsis_artifact_digest.is_empty());
    assert!(!evidence.retained_ranges.is_empty());
    assert!(!evidence.redaction_event_ids.is_empty());
    assert!(evidence.raw_complete);
    assert!(evidence.truncation_reason.is_none());
}

#[test]
fn historical_raw_can_be_recompressed_without_rewriting_raw_artifact() {
    let mut ctx = TestContext::new("recompress");
    let raw = b"error: first stable compiler failure\n --> src/main.rs:10:2\n";
    let v1 = EvidenceCompressor::new("compiler", 1);
    let first = v1
        .capture(
            &ctx.store,
            &mut ctx.state,
            &capture(
                "act_recompress",
                EvidenceKind::Compiler,
                raw,
                &[],
                4_096,
                256,
            ),
        )
        .unwrap_or_else(|error| panic!("capture v1: {error}"));
    let v2 = EvidenceCompressor::new("compiler", 2);
    let second = v2
        .recompress(&ctx.store, &mut ctx.state, &first, 512)
        .unwrap_or_else(|error| panic!("recompress v2: {error}"));
    assert_eq!(first.raw_artifact_digest, second.raw_artifact_digest);
    assert_eq!(second.compressor_version, 2);
    assert_ne!(
        first.synopsis_artifact_digest,
        second.synopsis_artifact_digest
    );
    let recovered = ctx
        .store
        .range(&ctx.state, &second.raw_artifact_digest, 0, raw.len())
        .unwrap_or_else(|error| panic!("recover raw: {error}"));
    assert_eq!(recovered, raw);
}

#[test]
fn compiler_synopsis_extracts_primary_error() {
    let mut ctx = TestContext::new("compiler");
    let raw = b"warning: unused thing\nerror[E0382]: borrow of moved value `value`\n --> crates/app/src/lib.rs:44:9\nerror: aborting due to previous error\n";
    let compressor = EvidenceCompressor::new("compiler-rust", 1);
    let evidence = compressor
        .capture(
            &ctx.store,
            &mut ctx.state,
            &capture("act_compiler", EvidenceKind::Compiler, raw, &[], 4_096, 512),
        )
        .unwrap_or_else(|error| panic!("capture: {error}"));
    assert!(
        evidence
            .synopsis
            .contains("primary_error=error[E0382]: borrow of moved value `value`")
    );
    assert!(evidence.synopsis.contains("error_count=2"));
}

#[test]
fn test_synopsis_groups_failed_tests_deterministically() {
    let mut ctx = TestContext::new("tests");
    let raw = b"test alpha ... FAILED\ntest beta ... ok\ntest alpha ... FAILED\ntest gamma ... FAILED\nassertion failed: left == right\n";
    let compressor = EvidenceCompressor::new("tests", 1);
    let evidence = compressor
        .capture(
            &ctx.store,
            &mut ctx.state,
            &capture("act_tests", EvidenceKind::Test, raw, &[], 4_096, 512),
        )
        .unwrap_or_else(|error| panic!("capture: {error}"));
    assert!(evidence.synopsis.contains("failed_test_count=2"));
    assert_eq!(evidence.synopsis.matches("failed_test=alpha").count(), 1);
    assert_eq!(evidence.synopsis.matches("failed_test=gamma").count(), 1);
}

#[test]
fn failure_signature_is_stable_across_incidental_line_number_changes() {
    let mut ctx = TestContext::new("signature");
    let compressor = EvidenceCompressor::new("compiler-rust", 1);
    let first = compressor
        .capture(
            &ctx.store,
            &mut ctx.state,
            &capture(
                "act_sig_a",
                EvidenceKind::Compiler,
                b"error[E0382]: borrow of moved value `value` at line 41\n",
                &[],
                4_096,
                256,
            ),
        )
        .unwrap_or_else(|error| panic!("first: {error}"));
    let second = compressor
        .capture(
            &ctx.store,
            &mut ctx.state,
            &capture(
                "act_sig_b",
                EvidenceKind::Compiler,
                b"error[E0382]: borrow of moved value `value` at line 99\n",
                &[],
                4_096,
                256,
            ),
        )
        .unwrap_or_else(|error| panic!("second: {error}"));
    assert_eq!(first.failure_signature, second.failure_signature);
}
