use sovereign_context::{
    ContextBudget, ContextError, ContextLevel, ContextMode, ContextPacketInput, ContextPlanner,
    EvidenceItem, EvidenceKind, PacketSection, RepairPacketInput, TrustClass,
};
use sovereign_evidence::{
    EvidenceKind as ToolEvidenceKind, FailureSignature, RetainedRange, ToolEvidence,
};
use sovereign_repo::{ExactDiffEvidence, InstructionDocument};
use std::path::PathBuf;

fn required_input(candidates: Vec<EvidenceItem>) -> ContextPacketInput {
    ContextPacketInput {
        controller_prefix: "safe-controller-prefix".to_owned(),
        task_contract: "objective=edit settings; acceptance=focused test passes".to_owned(),
        current_state: "attempt=1; unknown_actions=0; diff=current".to_owned(),
        authorized_tool_schemas: Vec::new(),
        candidates,
        output_schema: "ModelProposal{action,evidence_ids}".to_owned(),
    }
}

fn candidate(id: &str, section: PacketSection, kind: EvidenceKind, text: &str) -> EvidenceItem {
    EvidenceItem::new(
        id,
        section,
        ContextLevel::C1,
        kind,
        format!("fixture://{id}"),
        format!("sha256:source-{id}"),
        "fixture",
        TrustClass::Repository,
        "focused fixture",
        text,
    )
}

fn roomy_budget() -> ContextBudget {
    ContextBudget {
        max_input_tokens: 2_000,
        c0_tokens: 400,
        tool_schema_tokens: 200,
        c1_tokens: 700,
        routed_expansion_tokens: 200,
        tool_failure_tokens: 200,
        serialization_reserve_tokens: 300,
    }
}

#[test]
fn c0_cannot_be_evicted_when_required_contract_exceeds_its_ceiling() {
    let planner = ContextPlanner::default();
    let budget = ContextBudget {
        max_input_tokens: 100,
        c0_tokens: 1,
        tool_schema_tokens: 0,
        c1_tokens: 0,
        routed_expansion_tokens: 0,
        tool_failure_tokens: 0,
        serialization_reserve_tokens: 99,
    };
    assert!(matches!(
        planner.build(
            ContextMode::Implementation,
            budget,
            required_input(Vec::new())
        ),
        Err(ContextError::RequiredC0TooLarge { .. })
    ));
}

#[test]
fn duplicate_evidence_is_removed_by_content_digest() {
    let planner = ContextPlanner::default();
    let first = candidate(
        "source-a",
        PacketSection::DirectEvidence,
        EvidenceKind::SourceSlice,
        "same source bytes",
    );
    let second = candidate(
        "source-b",
        PacketSection::DirectEvidence,
        EvidenceKind::SearchHit,
        "same source bytes",
    );
    let packet = planner
        .build(
            ContextMode::Implementation,
            roomy_budget(),
            required_input(vec![first, second]),
        )
        .unwrap_or_else(|error| panic!("build: {error}"));

    assert_eq!(
        packet
            .items
            .iter()
            .filter(|item| item.text == "same source bytes")
            .count(),
        1
    );
    assert!(packet.metrics.duplicate_tokens_removed > 0);
    assert!(
        packet.metrics.candidate_tokens_before_dedupe > packet.metrics.selected_tokens_after_dedupe
    );
}

#[test]
fn budget_truncation_produces_an_expansion_handle() {
    let planner = ContextPlanner::default();
    let long = "0123456789abcdef".repeat(40);
    let source = candidate(
        "large-source",
        PacketSection::DirectEvidence,
        EvidenceKind::SourceSlice,
        &long,
    );
    let budget = ContextBudget {
        max_input_tokens: 400,
        c0_tokens: 100,
        tool_schema_tokens: 0,
        c1_tokens: 8,
        routed_expansion_tokens: 0,
        tool_failure_tokens: 0,
        serialization_reserve_tokens: 292,
    };
    let packet = planner
        .build(
            ContextMode::Implementation,
            budget,
            required_input(vec![source]),
        )
        .unwrap_or_else(|error| panic!("build: {error}"));
    let selected = packet
        .items
        .iter()
        .find(|item| item.evidence_id == "large-source")
        .unwrap_or_else(|| panic!("large source missing"));
    let handle = selected
        .expansion_handle
        .as_ref()
        .unwrap_or_else(|| panic!("expansion handle missing"));
    assert!(selected.text.len() < long.len());
    assert!(handle.total_length > handle.retained_length);
}

#[test]
fn packet_uses_frozen_weak_model_section_order() {
    let planner = ContextPlanner::default();
    let tool = candidate(
        "tool-result",
        PacketSection::ToolEvidence,
        EvidenceKind::ToolSynopsis,
        "tests passed=3 failed=0",
    );
    let routed = candidate(
        "routed",
        PacketSection::RoutedExpansion,
        EvidenceKind::RoutedExpansion,
        "caller=save_settings",
    );
    let direct = candidate(
        "source",
        PacketSection::DirectEvidence,
        EvidenceKind::SourceSlice,
        "fn save_settings() {}",
    );
    let schema = candidate(
        "tool-schema",
        PacketSection::ControllerPrefix,
        EvidenceKind::ToolSchema,
        "patch{path,diff}",
    );
    let mut input = required_input(vec![tool, routed, direct]);
    input.authorized_tool_schemas.push(schema);
    let packet = planner
        .build(ContextMode::Implementation, ContextBudget::m1_8k(), input)
        .unwrap_or_else(|error| panic!("build: {error}"));

    let kinds = packet
        .items
        .iter()
        .map(|item| item.kind)
        .collect::<Vec<_>>();
    assert_eq!(kinds[0], EvidenceKind::ControllerPrefix);
    assert_eq!(kinds[1], EvidenceKind::ToolSchema);
    assert_eq!(kinds[2], EvidenceKind::TaskContract);
    assert_eq!(kinds[3], EvidenceKind::CurrentState);
    assert_eq!(kinds[4], EvidenceKind::SourceSlice);
    assert_eq!(kinds[5], EvidenceKind::RoutedExpansion);
    assert_eq!(kinds[6], EvidenceKind::ToolSynopsis);
    assert_eq!(kinds[7], EvidenceKind::OutputSchema);
    assert!(packet.metrics.final_serialized_input_tokens < 8_000);
    assert!(packet.metrics.tool_schema_tokens > 0);
}

#[test]
fn forbidden_bulk_context_is_absent_by_default() {
    let planner = ContextPlanner::default();
    let candidates = vec![
        candidate(
            "repo-dump",
            PacketSection::DirectEvidence,
            EvidenceKind::FullRepository,
            "entire repository tree and files",
        ),
        candidate(
            "chat",
            PacketSection::DirectEvidence,
            EvidenceKind::PriorAttemptTranscript,
            "full chat history",
        ),
        candidate(
            "raw-log",
            PacketSection::ToolEvidence,
            EvidenceKind::RawToolLog,
            "raw 10000 line log",
        ),
        candidate(
            "hidden",
            PacketSection::DirectEvidence,
            EvidenceKind::HiddenReasoning,
            "implementer private trajectory",
        ),
        candidate(
            "all-tool-schemas",
            PacketSection::ControllerPrefix,
            EvidenceKind::ToolSchema,
            "every tool schema",
        )
        .with_relevance(false),
        candidate(
            "generic-relevant-tool",
            PacketSection::ControllerPrefix,
            EvidenceKind::ToolSchema,
            "generic candidate cannot authorize patch tool",
        ),
    ];
    let authorized = candidate(
        "authorized-relevant-tool",
        PacketSection::ControllerPrefix,
        EvidenceKind::ToolSchema,
        "only authorized relevant patch tool",
    );
    let mut input = required_input(candidates);
    input.authorized_tool_schemas.push(authorized);
    let packet = planner
        .build(ContextMode::Implementation, roomy_budget(), input)
        .unwrap_or_else(|error| panic!("build: {error}"));

    let ids = packet
        .items
        .iter()
        .map(|item| item.evidence_id.as_str())
        .collect::<Vec<_>>();
    assert!(!ids.contains(&"repo-dump"));
    assert!(!ids.contains(&"chat"));
    assert!(!ids.contains(&"raw-log"));
    assert!(!ids.contains(&"hidden"));
    assert!(!ids.contains(&"all-tool-schemas"));
    assert!(!ids.contains(&"generic-relevant-tool"));
    assert!(ids.contains(&"authorized-relevant-tool"));
}

#[test]
fn authorized_tool_schema_lane_preserves_dedupe_order_and_budget() {
    let planner = ContextPlanner::default();
    let generic = candidate(
        "generic-schema",
        PacketSection::ControllerPrefix,
        EvidenceKind::ToolSchema,
        "generic schema must stay hidden",
    );
    let schema_text = "authorized-schema-body-is-longer-than-the-small-ceiling";
    let authorized_a = candidate(
        "authorized-a",
        PacketSection::ControllerPrefix,
        EvidenceKind::ToolSchema,
        schema_text,
    );
    let authorized_b = candidate(
        "authorized-b",
        PacketSection::ControllerPrefix,
        EvidenceKind::ToolSchema,
        schema_text,
    );
    let budget = ContextBudget {
        max_input_tokens: 1_000,
        c0_tokens: 400,
        tool_schema_tokens: 4,
        c1_tokens: 100,
        routed_expansion_tokens: 0,
        tool_failure_tokens: 0,
        serialization_reserve_tokens: 496,
    };
    let mut input = required_input(vec![generic]);
    input.authorized_tool_schemas = vec![authorized_b, authorized_a];

    let packet = planner
        .build(ContextMode::Implementation, budget, input)
        .unwrap_or_else(|error| panic!("build: {error}"));
    let schemas = packet
        .items
        .iter()
        .filter(|item| item.kind == EvidenceKind::ToolSchema)
        .collect::<Vec<_>>();

    assert_eq!(schemas.len(), 1);
    assert_eq!(schemas[0].evidence_id, "authorized-a");
    assert_eq!(packet.items[1].evidence_id, "authorized-a");
    assert!(schemas[0].text.len() < schema_text.len());
    assert!(schemas[0].expansion_handle.is_some());
    assert!(packet.metrics.tool_schema_tokens <= budget.tool_schema_tokens);
    assert_eq!(packet.metrics.tool_schema_tokens, schemas[0].token_cost);
    assert!(packet.metrics.duplicate_tokens_removed > 0);
    assert!(
        packet
            .items
            .iter()
            .all(|item| item.evidence_id != "generic-schema")
    );
}

#[test]
fn repair_reviewer_and_verifier_builders_only_admit_authorized_tool_schemas() {
    let planner = ContextPlanner::default();
    let generic = candidate(
        "generic-schema",
        PacketSection::ControllerPrefix,
        EvidenceKind::ToolSchema,
        "generic schema",
    );
    let authorized = candidate(
        "authorized-schema",
        PacketSection::ControllerPrefix,
        EvidenceKind::ToolSchema,
        "authorized schema",
    );

    let mut reviewer_input = required_input(vec![generic.clone()]);
    reviewer_input.authorized_tool_schemas = vec![authorized.clone()];
    let reviewer = planner
        .build_reviewer(roomy_budget(), reviewer_input)
        .unwrap_or_else(|error| panic!("reviewer: {error}"));

    let mut verifier_input = required_input(vec![generic.clone()]);
    verifier_input.authorized_tool_schemas = vec![authorized.clone()];
    let verifier = planner
        .build_verifier(roomy_budget(), verifier_input)
        .unwrap_or_else(|error| panic!("verifier: {error}"));

    let repair = planner
        .build_repair(
            roomy_budget(),
            RepairPacketInput {
                plan_id: "plan.fixture".to_owned(),
                plan_revision: 1,
                plan_digest: "sha256:plan".to_owned(),
                task_id: "task.fixture".to_owned(),
                task_contract_digest: "sha256:task".to_owned(),
                acceptance_contract_digest: "sha256:acceptance".to_owned(),
                prior_attempt_id: "attempt.fixture".to_owned(),
                failure_signature: "test:fixture:deadbeef".to_owned(),
                failure_record_digest: "sha256:failure".to_owned(),
                failure_evidence_refs: Vec::new(),
                controller_prefix: "safe-controller-prefix".to_owned(),
                task_contract: "objective=repair settings".to_owned(),
                current_state: "attempt=2; diff=current".to_owned(),
                authorized_tool_schemas: vec![authorized],
                candidates: vec![generic],
                output_schema: "ModelProposal{action,evidence_ids}".to_owned(),
            },
        )
        .unwrap_or_else(|error| panic!("repair: {error}"));

    for packet in [&reviewer, &verifier, &repair.context] {
        assert!(
            packet
                .items
                .iter()
                .any(|item| item.evidence_id == "authorized-schema")
        );
        assert!(
            packet
                .items
                .iter()
                .all(|item| item.evidence_id != "generic-schema")
        );
    }
}

#[test]
fn unused_budget_stays_empty_instead_of_backfilling_unrelated_evidence() {
    let planner = ContextPlanner::default();
    let relevant = candidate(
        "focused",
        PacketSection::DirectEvidence,
        EvidenceKind::SourceSlice,
        "focused source",
    );
    let unrelated = candidate(
        "unrelated",
        PacketSection::DirectEvidence,
        EvidenceKind::SourceSlice,
        "large unrelated module",
    )
    .with_relevance(false);
    let packet = planner
        .build(
            ContextMode::Implementation,
            roomy_budget(),
            required_input(vec![relevant, unrelated]),
        )
        .unwrap_or_else(|error| panic!("build: {error}"));

    assert!(
        packet
            .items
            .iter()
            .any(|item| item.evidence_id == "focused")
    );
    assert!(
        packet
            .items
            .iter()
            .all(|item| item.evidence_id != "unrelated")
    );
    assert!(packet.metrics.selected_tokens_after_dedupe < roomy_budget().max_input_tokens);
}

#[test]
fn repair_packet_excludes_prior_transcript_and_keeps_diff_failure_implicated_evidence() {
    let planner = ContextPlanner::default();
    let candidates = vec![
        candidate(
            "current-diff",
            PacketSection::DirectEvidence,
            EvidenceKind::Diff,
            "+ fixed line",
        ),
        candidate(
            "failure",
            PacketSection::ToolEvidence,
            EvidenceKind::FailureSynopsis,
            "assertion failed settings persisted",
        ),
        candidate(
            "implicated",
            PacketSection::DirectEvidence,
            EvidenceKind::SourceSlice,
            "fn persist_settings() {}",
        )
        .with_implicated(true),
        candidate(
            "unrelated-success",
            PacketSection::DirectEvidence,
            EvidenceKind::SourceSlice,
            "fn unrelated() {}",
        ),
        candidate(
            "prior-transcript",
            PacketSection::DirectEvidence,
            EvidenceKind::PriorAttemptTranscript,
            "all prior model prose",
        ),
    ];
    let packet = planner
        .build(
            ContextMode::Repair,
            roomy_budget(),
            required_input(candidates),
        )
        .unwrap_or_else(|error| panic!("build: {error}"));
    let ids = packet
        .items
        .iter()
        .map(|item| item.evidence_id.as_str())
        .collect::<Vec<_>>();
    assert!(ids.contains(&"current-diff"));
    assert!(ids.contains(&"failure"));
    assert!(ids.contains(&"implicated"));
    assert!(!ids.contains(&"unrelated-success"));
    assert!(!ids.contains(&"prior-transcript"));
}

#[test]
fn reviewer_packet_excludes_implementer_hidden_reasoning() {
    let planner = ContextPlanner::default();
    let candidates = vec![
        candidate(
            "final-diff",
            PacketSection::DirectEvidence,
            EvidenceKind::Diff,
            "+ final change",
        ),
        candidate(
            "verification",
            PacketSection::DirectEvidence,
            EvidenceKind::Verification,
            "focused tests pass",
        ),
        candidate(
            "hidden-reasoning",
            PacketSection::DirectEvidence,
            EvidenceKind::HiddenReasoning,
            "private implementer reasoning",
        ),
    ];
    let packet = planner
        .build(
            ContextMode::Reviewer,
            roomy_budget(),
            required_input(candidates),
        )
        .unwrap_or_else(|error| panic!("build: {error}"));

    assert!(
        packet
            .items
            .iter()
            .any(|item| item.evidence_id == "final-diff")
    );
    assert!(
        packet
            .items
            .iter()
            .any(|item| item.evidence_id == "verification")
    );
    assert!(
        packet
            .items
            .iter()
            .all(|item| item.evidence_id != "hidden-reasoning")
    );
}

#[test]
fn instruction_diff_and_compressed_tool_evidence_keep_provenance_and_handles() {
    let instruction = InstructionDocument {
        relative_path: PathBuf::from("src/AGENTS.md"),
        digest: "sha256:instruction-current".to_owned(),
        content: "preserve public behavior".to_owned(),
    };
    let instruction_item =
        EvidenceItem::from_instruction("repo.fixture", &instruction, "applies to edited source");
    assert_eq!(instruction_item.source_digest, "sha256:instruction-current");
    assert_eq!(instruction_item.kind, EvidenceKind::Instruction);

    let diff = ExactDiffEvidence {
        repository_id: "repo.fixture".to_owned(),
        digest: "sha256:diff-current".to_owned(),
        content: "+changed setting".to_owned(),
    };
    let diff_item = EvidenceItem::from_diff(&diff, "current controller diff");
    assert_eq!(diff_item.source_digest, "sha256:diff-current");
    assert!(diff_item.implicated);

    let tool = ToolEvidence {
        schema: "sovereign-tool-evidence-v1".to_owned(),
        action_id: "act.verify".to_owned(),
        tool: "cargo-test".to_owned(),
        kind: ToolEvidenceKind::Test,
        compressor_id: "tests".to_owned(),
        compressor_version: 1,
        source_bytes_observed: 20_000,
        post_ingress_bytes: 20_000,
        retained_bytes: 4_096,
        retained_ranges: vec![RetainedRange {
            offset: 0,
            length: 4_096,
        }],
        redaction_event_ids: vec!["redact_fixture".to_owned()],
        raw_complete: false,
        truncation_reason: Some("raw_spool_quota_exceeded".to_owned()),
        raw_artifact_digest: "raw-digest-fixture".to_owned(),
        synopsis_artifact_digest: "synopsis-digest-fixture".to_owned(),
        synopsis: "failed_test=settings_persists".to_owned(),
        failure_signature: Some(FailureSignature("test:settings:deadbeef".to_owned())),
    };
    let tool_item = EvidenceItem::from_tool_evidence(&tool, "current verification failure");
    assert_eq!(tool_item.kind, EvidenceKind::FailureSynopsis);
    assert_eq!(tool_item.text, tool.synopsis);
    let handle = tool_item
        .expansion_handle
        .unwrap_or_else(|| panic!("tool expansion handle missing"));
    assert_eq!(handle.source_digest, tool.raw_artifact_digest);
    assert_eq!(handle.retained_length, 4_096);
    assert_eq!(handle.total_length, 20_000);
}
