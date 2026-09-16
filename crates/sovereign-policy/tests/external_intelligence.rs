use sovereign_policy::{
    EXTERNAL_ESCALATION_MANIFEST_SCHEMA_VERSION, EXTERNAL_PAYLOAD_POLICY_SCHEMA_VERSION,
    ExternalDataClass, ExternalEscalationManifest, ExternalEvidenceBinding, ExternalPayloadPolicy,
    ExternalRepositoryExport, ExternalSensitiveDataAccess, ExternalToolAuthority,
};
use std::collections::BTreeSet;

fn digest(byte: u8) -> String {
    format!("sha256:{}", format!("{byte:02x}").repeat(32))
}

fn policy() -> ExternalPayloadPolicy {
    ExternalPayloadPolicy {
        schema_version: EXTERNAL_PAYLOAD_POLICY_SCHEMA_VERSION,
        enabled: true,
        requires_explicit_grant: true,
        allowed_providers: BTreeSet::from(["fake.external".to_owned()]),
        allowed_data_classes: BTreeSet::from([
            ExternalDataClass::SourceSlice,
            ExternalDataClass::Verification,
        ]),
        resolved_secrets: ExternalSensitiveDataAccess::Deny,
        repository_export: ExternalRepositoryExport::Deny,
        raw_logs: ExternalSensitiveDataAccess::Deny,
        tool_authority: ExternalToolAuthority::None,
        max_payload_bytes: 4_096,
    }
}

fn manifest() -> ExternalEscalationManifest {
    ExternalEscalationManifest {
        schema_version: EXTERNAL_ESCALATION_MANIFEST_SCHEMA_VERSION,
        provider_id: "fake.external".to_owned(),
        model_id: "fake-advisor".to_owned(),
        model_version: "v1".to_owned(),
        purpose: "review a bounded source slice".to_owned(),
        plan_id: "plan.external".to_owned(),
        plan_revision: 1,
        task_id: "task.external".to_owned(),
        task_contract_digest: digest(1),
        policy_digest: digest(2),
        execution_epoch: 7,
        selected_evidence: vec![ExternalEvidenceBinding {
            evidence_id: "evidence.source.1".to_owned(),
            data_class: ExternalDataClass::SourceSlice,
            source_digest: digest(3),
            content_digest: digest(4),
            redacted_content_digest: digest(5),
        }],
        data_classes: BTreeSet::from([ExternalDataClass::SourceSlice]),
        redaction_event_ids: BTreeSet::from(["redact.credential.1".to_owned()]),
        redaction_result_digest: digest(6),
        payload_digest: digest(7),
        payload_bytes: 256,
        estimated_tokens: 64,
        deadline_ms: 1_000,
        expires_at_ms: 10_000,
        nonce: "nonce.external.1".to_owned(),
    }
}

#[test]
fn external_payload_policy_is_disabled_fail_closed_and_bounded_when_enabled() {
    let disabled = ExternalPayloadPolicy {
        schema_version: EXTERNAL_PAYLOAD_POLICY_SCHEMA_VERSION,
        enabled: false,
        requires_explicit_grant: true,
        allowed_providers: BTreeSet::new(),
        allowed_data_classes: BTreeSet::new(),
        resolved_secrets: ExternalSensitiveDataAccess::Deny,
        repository_export: ExternalRepositoryExport::Deny,
        raw_logs: ExternalSensitiveDataAccess::Deny,
        tool_authority: ExternalToolAuthority::None,
        max_payload_bytes: 0,
    };
    assert!(disabled.validate().is_ok());
    assert!(
        disabled
            .authorize_packet(
                "fake.external",
                &BTreeSet::from([ExternalDataClass::SourceSlice]),
                1,
            )
            .is_err()
    );

    let bounded = policy();
    assert!(bounded.validate().is_ok());
    assert!(
        bounded
            .authorize_packet(
                "fake.external",
                &BTreeSet::from([ExternalDataClass::SourceSlice]),
                512,
            )
            .is_ok()
    );
    assert!(
        bounded
            .authorize_packet(
                "undeclared.external",
                &BTreeSet::from([ExternalDataClass::SourceSlice]),
                512,
            )
            .is_err()
    );
    assert!(
        bounded
            .authorize_packet(
                "fake.external",
                &BTreeSet::from([ExternalDataClass::ArchitectureDoc]),
                512,
            )
            .is_err()
    );
    assert!(
        bounded
            .authorize_packet(
                "fake.external",
                &BTreeSet::from([ExternalDataClass::SourceSlice]),
                4_097,
            )
            .is_err()
    );
}

#[test]
fn external_payload_policy_rejects_unsafe_baseline_exports() {
    let mut unsafe_policy = policy();
    unsafe_policy.resolved_secrets = ExternalSensitiveDataAccess::Allow;
    assert!(unsafe_policy.validate().is_err());

    let mut unsafe_policy = policy();
    unsafe_policy.raw_logs = ExternalSensitiveDataAccess::Allow;
    assert!(unsafe_policy.validate().is_err());

    // The local profile deliberately has no enum variant that could grant tool authority.
}

#[test]
fn manifest_digest_is_exact_and_changes_with_authority_relevant_fields() {
    let original = manifest();
    let Ok(original_digest) = original.digest() else {
        panic!("manifest should validate");
    };

    let mut provider = original.clone();
    provider.provider_id = "other.external".to_owned();
    let Ok(provider_digest) = provider.digest() else {
        panic!("provider mutation should preserve manifest shape");
    };
    assert_ne!(original_digest, provider_digest);

    let mut purpose = original.clone();
    purpose.purpose = "different bounded purpose".to_owned();
    let Ok(purpose_digest) = purpose.digest() else {
        panic!("purpose mutation should preserve manifest shape");
    };
    assert_ne!(original_digest, purpose_digest);

    let mut payload = original.clone();
    payload.payload_digest = digest(9);
    let Ok(payload_digest) = payload.digest() else {
        panic!("payload mutation should preserve manifest shape");
    };
    assert_ne!(original_digest, payload_digest);
}

#[test]
fn manifest_rejects_inconsistent_or_noncanonical_evidence_bindings() {
    let mut inconsistent = manifest();
    inconsistent.data_classes = BTreeSet::from([ExternalDataClass::Verification]);
    assert!(inconsistent.validate().is_err());

    let mut duplicate = manifest();
    duplicate
        .selected_evidence
        .push(duplicate.selected_evidence[0].clone());
    assert!(duplicate.validate().is_err());
}
