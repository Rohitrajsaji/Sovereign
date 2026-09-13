use serde_json::Value;
use sovereign_plan::{DepthClassifier, DepthFeatureInput, ExecutionDepth};

#[test]
fn depth_trivial_and_focused_inputs_classify_d0_d1() {
    let classifier = DepthClassifier;
    let direct = classifier.classify(&DepthFeatureInput::default());
    assert_eq!(direct.mode, ExecutionDepth::D0);

    let focused = classifier.classify(&DepthFeatureInput {
        expected_symbols: 4,
        verification_coverage_percent: 70,
        ..DepthFeatureInput::default()
    });
    assert_eq!(focused.mode, ExecutionDepth::D1);
}

#[test]
fn depth_multi_file_single_subsystem_classifies_d2() {
    let decision = DepthClassifier.classify(&DepthFeatureInput {
        expected_files: 4,
        expected_modules: 1,
        expected_symbols: 6,
        verification_coverage_percent: 70,
        ..DepthFeatureInput::default()
    });

    assert_eq!(decision.mode, ExecutionDepth::D2);
    assert!(decision.reason.contains("D2"));
}

#[test]
fn depth_authentication_change_is_hard_override_d4() {
    let decision = DepthClassifier.classify(&DepthFeatureInput {
        authentication_or_authorization: true,
        ..DepthFeatureInput::default()
    });

    assert_eq!(decision.mode, ExecutionDepth::D4);
    assert_eq!(
        decision.reason,
        "D4 hard override: authentication_or_authorization"
    );
}

#[test]
fn depth_multi_repo_migration_is_hard_override_d4() {
    let decision = DepthClassifier.classify(&DepthFeatureInput {
        repository_count: 2,
        schema_or_data_migration: true,
        ..DepthFeatureInput::default()
    });

    assert_eq!(decision.mode, ExecutionDepth::D4);
    assert_eq!(decision.reason, "D4 hard override: multi_repo_migration");
}

#[test]
fn depth_destructive_or_external_without_rollback_is_d4_regardless_of_score() {
    let destructive = DepthClassifier.classify(&DepthFeatureInput {
        destructive_effect: true,
        rollback_available: false,
        ..DepthFeatureInput::default()
    });
    assert_eq!(destructive.mode, ExecutionDepth::D4);

    let external = DepthClassifier.classify(&DepthFeatureInput {
        external_effect: true,
        rollback_available: false,
        ..DepthFeatureInput::default()
    });
    assert_eq!(external.mode, ExecutionDepth::D4);
    assert_eq!(
        external.reason,
        "D4 hard override: destructive_or_external_effect_without_rollback"
    );
}

#[test]
fn depth_security_migration_public_api_and_high_blast_have_d3_floor() {
    for input in [
        DepthFeatureInput {
            security_sensitive: true,
            ..DepthFeatureInput::default()
        },
        DepthFeatureInput {
            schema_or_data_migration: true,
            ..DepthFeatureInput::default()
        },
        DepthFeatureInput {
            public_api_or_protocol: true,
            ..DepthFeatureInput::default()
        },
        DepthFeatureInput {
            blast_radius_percent: 70,
            ..DepthFeatureInput::default()
        },
        DepthFeatureInput {
            expected_modules: 2,
            ..DepthFeatureInput::default()
        },
        DepthFeatureInput {
            architecture_uncertainty_percent: 50,
            ..DepthFeatureInput::default()
        },
    ] {
        assert!(DepthClassifier.classify(&input).mode >= ExecutionDepth::D3);
    }
}

#[test]
fn depth_decision_reason_and_scalar_features_are_deterministic_and_serializable() {
    let input = DepthFeatureInput {
        repository_count: 2,
        language_count: 3,
        expected_files: 5,
        expected_modules: 2,
        expected_symbols: 8,
        unknown_dependency: true,
        verification_coverage_percent: 61,
        architecture_uncertainty_percent: 42,
        dependency_centrality_percent: 58,
        prior_similar_failures: 2,
        ..DepthFeatureInput::default()
    };

    let first = DepthClassifier.classify(&input);
    let second = DepthClassifier.classify(&input);
    assert_eq!(first, second);

    let encoded = serde_json::to_value(&first).unwrap_or_else(|error| panic!("serialize: {error}"));
    assert_eq!(encoded["mode"], Value::String(format!("{:?}", first.mode)));
    assert_eq!(encoded["reason"], Value::String(first.reason.clone()));
    let features = encoded["features"]
        .as_object()
        .unwrap_or_else(|| panic!("features must serialize as an object"));
    assert!(features.values().all(Value::is_boolean_or_number));
    assert_eq!(features["repository_count"], 2);
    assert_eq!(features["verification_coverage_percent"], 61);
    assert_eq!(features["aggregate_score"], first.features.aggregate_score);
}

trait ScalarJsonValue {
    fn is_boolean_or_number(&self) -> bool;
}

impl ScalarJsonValue for Value {
    fn is_boolean_or_number(&self) -> bool {
        self.is_boolean() || self.is_number() || self.is_string()
    }
}
