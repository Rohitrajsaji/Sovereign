use serde::{Deserialize, Serialize};

/// Deterministic execution depth selected before rich plan compilation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ExecutionDepth {
    D0,
    D1,
    D2,
    D3,
    D4,
}

/// Typed observations supplied to the deterministic depth feature extractor.
///
/// Percent values are normalized to `0..=100` by [`DepthClassifier::extract`]
/// so the persisted feature vector is stable even if callers over-report them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct DepthFeatureInput {
    pub repository_count: u32,
    pub language_count: u32,
    pub expected_files: u32,
    pub expected_modules: u32,
    pub expected_symbols: u32,
    pub security_sensitive: bool,
    pub authentication_or_authorization: bool,
    pub secrets_sensitive: bool,
    pub schema_or_data_migration: bool,
    pub irreversible_migration: bool,
    pub public_api_or_protocol: bool,
    pub coordinated_multi_repo_protocol: bool,
    pub unknown_technology: bool,
    pub unknown_dependency: bool,
    pub verification_available: bool,
    pub verification_coverage_percent: u8,
    pub architecture_uncertainty_percent: u8,
    pub blast_radius_percent: u8,
    pub dependency_centrality_percent: u8,
    pub prior_similar_failures: u32,
    pub destructive_effect: bool,
    pub external_effect: bool,
    pub rollback_available: bool,
}

impl Default for DepthFeatureInput {
    fn default() -> Self {
        Self {
            repository_count: 1,
            language_count: 1,
            expected_files: 1,
            expected_modules: 1,
            expected_symbols: 1,
            security_sensitive: false,
            authentication_or_authorization: false,
            secrets_sensitive: false,
            schema_or_data_migration: false,
            irreversible_migration: false,
            public_api_or_protocol: false,
            coordinated_multi_repo_protocol: false,
            unknown_technology: false,
            unknown_dependency: false,
            verification_available: true,
            verification_coverage_percent: 100,
            architecture_uncertainty_percent: 0,
            blast_radius_percent: 0,
            dependency_centrality_percent: 0,
            prior_similar_failures: 0,
            destructive_effect: false,
            external_effect: false,
            rollback_available: true,
        }
    }
}

/// Persisted scalar feature vector compatible with Plan IR `depth.features`.
///
/// Every serialized field is a JSON scalar; no nested classifier state is
/// required to reproduce a decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct DepthFeatures {
    pub repository_count: u32,
    pub language_count: u32,
    pub expected_files: u32,
    pub expected_modules: u32,
    pub expected_symbols: u32,
    pub security_sensitive: bool,
    pub authentication_or_authorization: bool,
    pub secrets_sensitive: bool,
    pub schema_or_data_migration: bool,
    pub irreversible_migration: bool,
    pub public_api_or_protocol: bool,
    pub coordinated_multi_repo_protocol: bool,
    pub unknown_technology: bool,
    pub unknown_dependency: bool,
    pub verification_available: bool,
    pub verification_coverage_percent: u8,
    pub architecture_uncertainty_percent: u8,
    pub blast_radius_percent: u8,
    pub dependency_centrality_percent: u8,
    pub prior_similar_failures: u32,
    pub destructive_effect: bool,
    pub external_effect: bool,
    pub rollback_available: bool,
    pub aggregate_score: u32,
}

/// Persistable classifier output matching the Plan IR depth shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepthDecision {
    pub mode: ExecutionDepth,
    pub reason: String,
    pub features: DepthFeatures,
}

/// Stateless deterministic feature extractor and depth classifier.
#[derive(Debug, Clone, Copy, Default)]
pub struct DepthClassifier;

impl DepthClassifier {
    /// Normalizes the supplied observations and computes the stable scalar
    /// feature vector used by classification.
    #[must_use]
    pub fn extract(self, input: &DepthFeatureInput) -> DepthFeatures {
        let mut features = DepthFeatures {
            repository_count: input.repository_count.max(1),
            language_count: input.language_count.max(1),
            expected_files: input.expected_files,
            expected_modules: input.expected_modules,
            expected_symbols: input.expected_symbols,
            security_sensitive: input.security_sensitive,
            authentication_or_authorization: input.authentication_or_authorization,
            secrets_sensitive: input.secrets_sensitive,
            schema_or_data_migration: input.schema_or_data_migration,
            irreversible_migration: input.irreversible_migration,
            public_api_or_protocol: input.public_api_or_protocol,
            coordinated_multi_repo_protocol: input.coordinated_multi_repo_protocol,
            unknown_technology: input.unknown_technology,
            unknown_dependency: input.unknown_dependency,
            verification_available: input.verification_available,
            verification_coverage_percent: input.verification_coverage_percent.min(100),
            architecture_uncertainty_percent: input.architecture_uncertainty_percent.min(100),
            blast_radius_percent: input.blast_radius_percent.min(100),
            dependency_centrality_percent: input.dependency_centrality_percent.min(100),
            prior_similar_failures: input.prior_similar_failures,
            destructive_effect: input.destructive_effect,
            external_effect: input.external_effect,
            rollback_available: input.rollback_available,
            aggregate_score: 0,
        };
        features.aggregate_score = aggregate_score(&features);
        features
    }

    /// Classifies one feature input using stable score bands, explicit floors,
    /// and the architecture hard overrides.
    #[must_use]
    pub fn classify(self, input: &DepthFeatureInput) -> DepthDecision {
        let features = self.extract(input);

        if let Some(reason) = hard_override_reason(&features) {
            return DepthDecision {
                mode: ExecutionDepth::D4,
                reason: format!("D4 hard override: {reason}"),
                features,
            };
        }

        let score_depth = score_depth(&features);
        let (floor, floor_reason) = minimum_depth_floor(&features);
        let mode = score_depth.max(floor);
        let reason = match floor_reason {
            Some(reason) if floor > score_depth => format!(
                "{mode:?}: score={} would select {score_depth:?}; floor={floor:?} ({reason})",
                features.aggregate_score
            ),
            Some(reason) if floor == score_depth && floor >= ExecutionDepth::D3 => format!(
                "{mode:?}: score={} with matching floor {floor:?} ({reason})",
                features.aggregate_score
            ),
            _ => format!("{mode:?}: deterministic score={}", features.aggregate_score),
        };

        DepthDecision {
            mode,
            reason,
            features,
        }
    }
}

fn hard_override_reason(features: &DepthFeatures) -> Option<&'static str> {
    if features.irreversible_migration {
        return Some("irreversible_migration");
    }
    if features.authentication_or_authorization {
        return Some("authentication_or_authorization");
    }
    if features.secrets_sensitive {
        return Some("secrets_sensitive");
    }
    if features.repository_count > 1 && features.coordinated_multi_repo_protocol {
        return Some("coordinated_multi_repo_protocol");
    }
    if features.repository_count > 1 && features.schema_or_data_migration {
        return Some("multi_repo_migration");
    }
    if (features.destructive_effect || features.external_effect) && !features.rollback_available {
        return Some("destructive_or_external_effect_without_rollback");
    }
    None
}

fn minimum_depth_floor(features: &DepthFeatures) -> (ExecutionDepth, Option<&'static str>) {
    if features.security_sensitive {
        return (ExecutionDepth::D3, Some("security_sensitive"));
    }
    if features.schema_or_data_migration {
        return (ExecutionDepth::D3, Some("schema_or_data_migration"));
    }
    if features.public_api_or_protocol {
        return (ExecutionDepth::D3, Some("public_api_or_protocol"));
    }
    if features.blast_radius_percent >= 70 || features.dependency_centrality_percent >= 80 {
        return (
            ExecutionDepth::D3,
            Some("high_blast_radius_or_dependency_centrality"),
        );
    }
    if features.expected_modules >= 2 || features.architecture_uncertainty_percent >= 50 {
        return (
            ExecutionDepth::D3,
            Some("architectural_or_multi_module_scope"),
        );
    }
    if features.expected_files >= 3 {
        return (
            ExecutionDepth::D2,
            Some("multi_file_single_subsystem_scope"),
        );
    }
    (ExecutionDepth::D0, None)
}

fn score_depth(features: &DepthFeatures) -> ExecutionDepth {
    match features.aggregate_score {
        0..=1 if is_direct_scope(features) => ExecutionDepth::D0,
        0..=5 => ExecutionDepth::D1,
        6..=12 => ExecutionDepth::D2,
        13..=23 => ExecutionDepth::D3,
        _ => ExecutionDepth::D4,
    }
}

fn is_direct_scope(features: &DepthFeatures) -> bool {
    features.repository_count == 1
        && features.language_count == 1
        && features.expected_files <= 1
        && features.expected_modules <= 1
        && features.expected_symbols <= 2
        && features.prior_similar_failures == 0
}

fn aggregate_score(features: &DepthFeatures) -> u32 {
    let mut score = 0_u32;
    score = score.saturating_add(count_over_one_score(features.repository_count, 5, 10));
    score = score.saturating_add(count_over_one_score(features.language_count, 1, 4));
    score = score.saturating_add(scope_count_score(features.expected_files, 1, 3, 6, 1, 2, 4));
    score = score.saturating_add(scope_count_score(
        features.expected_modules,
        1,
        2,
        4,
        1,
        3,
        5,
    ));
    score = score.saturating_add(scope_count_score(
        features.expected_symbols,
        2,
        5,
        10,
        1,
        2,
        3,
    ));

    score = score.saturating_add(bool_score(features.security_sensitive, 6));
    score = score.saturating_add(bool_score(features.authentication_or_authorization, 10));
    score = score.saturating_add(bool_score(features.secrets_sensitive, 10));
    score = score.saturating_add(bool_score(features.schema_or_data_migration, 6));
    score = score.saturating_add(bool_score(features.irreversible_migration, 10));
    score = score.saturating_add(bool_score(features.public_api_or_protocol, 5));
    score = score.saturating_add(bool_score(features.coordinated_multi_repo_protocol, 5));
    score = score.saturating_add(bool_score(features.unknown_technology, 3));
    score = score.saturating_add(bool_score(features.unknown_dependency, 2));
    score = score.saturating_add(bool_score(!features.verification_available, 4));
    score = score.saturating_add(verification_gap_score(
        features.verification_coverage_percent,
    ));
    score = score.saturating_add(percent_risk_score(
        features.architecture_uncertainty_percent,
        1,
        3,
        5,
    ));
    score = score.saturating_add(percent_risk_score(features.blast_radius_percent, 2, 4, 6));
    score = score.saturating_add(percent_risk_score(
        features.dependency_centrality_percent,
        1,
        3,
        4,
    ));
    score = score.saturating_add(features.prior_similar_failures.min(5));
    score = score.saturating_add(bool_score(features.destructive_effect, 4));
    score = score.saturating_add(bool_score(features.external_effect, 3));
    score
}

const fn bool_score(enabled: bool, value: u32) -> u32 {
    if enabled { value } else { 0 }
}

fn count_over_one_score(value: u32, per_extra: u32, maximum: u32) -> u32 {
    value
        .saturating_sub(1)
        .saturating_mul(per_extra)
        .min(maximum)
}

const fn scope_count_score(
    value: u32,
    low_max: u32,
    medium_max: u32,
    high_max: u32,
    low_score: u32,
    medium_score: u32,
    high_score: u32,
) -> u32 {
    if value <= low_max {
        0
    } else if value <= medium_max {
        low_score
    } else if value <= high_max {
        medium_score
    } else {
        high_score
    }
}

const fn verification_gap_score(coverage: u8) -> u32 {
    if coverage < 25 {
        3
    } else if coverage < 60 {
        2
    } else if coverage < 80 {
        1
    } else {
        0
    }
}

const fn percent_risk_score(percent: u8, medium: u32, high: u32, very_high: u32) -> u32 {
    if percent >= 75 {
        very_high
    } else if percent >= 50 {
        high
    } else if percent >= 25 {
        medium
    } else {
        0
    }
}
