use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const COMPATIBILITY_SUITE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityCaseV1 {
    pub case_id: String,
    pub passed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationCompatibilitySuite {
    pub schema_version: u32,
    pub cases: Vec<CompatibilityCaseV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderConformanceSuite {
    pub schema_version: u32,
    pub cases: Vec<CompatibilityCaseV1>,
}

impl MigrationCompatibilitySuite {
    /// Validates deterministic migration-compatibility evidence without owning
    /// or mutating any execution state.
    ///
    /// # Errors
    /// Returns an error for an unsupported report version, empty/duplicate
    /// case IDs, an empty suite, or any failed case.
    pub fn validate(&self) -> Result<(), String> {
        validate_cases(self.schema_version, &self.cases, "migration")
    }
}

impl ProviderConformanceSuite {
    /// Validates deterministic provider-conformance evidence. Provider identity
    /// is intentionally outside this report: only normalized behavior belongs
    /// in the cases recorded by the caller.
    ///
    /// # Errors
    /// Returns an error for an unsupported report version, empty/duplicate
    /// case IDs, an empty suite, or any failed case.
    pub fn validate(&self) -> Result<(), String> {
        validate_cases(self.schema_version, &self.cases, "provider")
    }
}

fn validate_cases(
    schema_version: u32,
    cases: &[CompatibilityCaseV1],
    suite_kind: &str,
) -> Result<(), String> {
    if schema_version != COMPATIBILITY_SUITE_SCHEMA_VERSION {
        return Err(format!(
            "unsupported {suite_kind} compatibility suite schema {schema_version}"
        ));
    }
    if cases.is_empty() {
        return Err(format!("{suite_kind} compatibility suite is empty"));
    }
    let mut seen = BTreeSet::new();
    for case in cases {
        if case.case_id.trim().is_empty() {
            return Err(format!("{suite_kind} compatibility case id is empty"));
        }
        if !seen.insert(case.case_id.as_str()) {
            return Err(format!(
                "duplicate {suite_kind} compatibility case {}",
                case.case_id
            ));
        }
        if !case.passed {
            return Err(format!(
                "{suite_kind} compatibility case {} failed",
                case.case_id
            ));
        }
    }
    Ok(())
}
