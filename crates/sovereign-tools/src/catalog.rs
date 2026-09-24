use crate::{PermissionClass, ToolError, ToolManifest, ToolSchemaV1};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sovereign_policy::{CapabilitySet, CommandRisk, ReconciliationClass, ReconciliationPolicy};

pub const CANONICAL_PATCH_TOOL_ID: &str = "tool.patch";
pub const CANONICAL_READ_TOOL_ID: &str = "tool.read";
pub const CANONICAL_BROWSER_TOOL_ID: &str = "tool.browser";
pub const CANONICAL_PROCESS_TOOL_ID: &str = "tool.process";
pub const CANONICAL_TOOL_VERSION: &str = "1.0.0";

const PATCH_TOOL_NAME: &str = "repository_patch";
const PATCH_TOOL_DESCRIPTION: &str =
    "Propose one Controller-governed single-file repository create or update action.";
const READ_TOOL_NAME: &str = "repository_read";
const READ_TOOL_DESCRIPTION: &str =
    "Request one exact Controller-governed repository file read with an optional source digest.";

const PATCH_INPUT_SCHEMA_JSON: &str = r#"{
  "type": "object",
  "additionalProperties": false,
  "required": ["kind", "repository_id", "path", "content"],
  "properties": {
    "kind": {"enum": ["create_file", "update_file"]},
    "repository_id": {"type": "string", "minLength": 1},
    "path": {"type": "string", "minLength": 1},
    "expected_source_digest": {"type": ["string", "null"]},
    "content": {"type": "string"}
  },
  "allOf": [
    {
      "if": {"properties": {"kind": {"const": "update_file"}}},
      "then": {
        "required": ["expected_source_digest"],
        "properties": {
          "expected_source_digest": {
            "type": "string",
            "pattern": "^sha256:[0-9a-f]{64}$"
          }
        }
      }
    },
    {
      "if": {"properties": {"kind": {"const": "create_file"}}},
      "then": {"properties": {"expected_source_digest": {"type": "null"}}}
    }
  ]
}"#;

const READ_INPUT_SCHEMA_JSON: &str = r#"{
  "type": "object",
  "additionalProperties": false,
  "required": ["repository_id", "path"],
  "properties": {
    "repository_id": {"type": "string", "minLength": 1},
    "path": {"type": "string", "minLength": 1},
    "expected_source_digest": {
      "type": ["string", "null"],
      "pattern": "^sha256:[0-9a-f]{64}$"
    }
  }
}"#;

const PATCH_CAPABILITIES: [PermissionClass; 2] = [
    PermissionClass::ProcessExec,
    PermissionClass::RepositoryWrite,
];
const READ_CAPABILITIES: [PermissionClass; 2] =
    [PermissionClass::Read, PermissionClass::ProcessExec];
const READ_SCHEMA_CAPABILITIES: [PermissionClass; 1] = [PermissionClass::Read];
const BROWSER_CAPABILITIES: [PermissionClass; 3] = [
    PermissionClass::BrowserInteractive,
    PermissionClass::NetworkRead,
    PermissionClass::NetworkWrite,
];
const PROCESS_CAPABILITIES: [PermissionClass; 1] = [PermissionClass::ProcessExec];

struct CanonicalToolSpec {
    tool_id: &'static str,
    version: &'static str,
    name: &'static str,
    description: &'static str,
    permission_ceiling: &'static [PermissionClass],
    schema_capabilities: &'static [PermissionClass],
    risk: CommandRisk,
    reconciliation: ReconciliationPolicy,
    input_schema_json: &'static str,
}

const fn patch_spec() -> CanonicalToolSpec {
    CanonicalToolSpec {
        tool_id: CANONICAL_PATCH_TOOL_ID,
        version: CANONICAL_TOOL_VERSION,
        name: PATCH_TOOL_NAME,
        description: PATCH_TOOL_DESCRIPTION,
        permission_ceiling: &PATCH_CAPABILITIES,
        schema_capabilities: &PATCH_CAPABILITIES,
        risk: CommandRisk::RepositoryMutation,
        reconciliation: ReconciliationPolicy::proof_required_local(),
        input_schema_json: PATCH_INPUT_SCHEMA_JSON,
    }
}

const fn read_spec() -> CanonicalToolSpec {
    CanonicalToolSpec {
        tool_id: CANONICAL_READ_TOOL_ID,
        version: CANONICAL_TOOL_VERSION,
        name: READ_TOOL_NAME,
        description: READ_TOOL_DESCRIPTION,
        permission_ceiling: &READ_CAPABILITIES,
        schema_capabilities: &READ_SCHEMA_CAPABILITIES,
        risk: CommandRisk::ReadOnly,
        reconciliation: ReconciliationPolicy::idempotent_local(),
        input_schema_json: READ_INPUT_SCHEMA_JSON,
    }
}

const fn browser_spec() -> CanonicalToolSpec {
    CanonicalToolSpec {
        tool_id: CANONICAL_BROWSER_TOOL_ID,
        version: CANONICAL_TOOL_VERSION,
        name: "controller_browser_acceptance",
        description: "Execute typed Plan browser acceptance through Controller journals and receipts.",
        permission_ceiling: &BROWSER_CAPABILITIES,
        schema_capabilities: &BROWSER_CAPABILITIES,
        risk: CommandRisk::ReadOnly,
        reconciliation: ReconciliationPolicy::proof_required_local(),
        input_schema_json: r#"{"type":"object","additionalProperties":false}"#,
    }
}

const fn process_spec() -> CanonicalToolSpec {
    CanonicalToolSpec {
        tool_id: CANONICAL_PROCESS_TOOL_ID,
        version: CANONICAL_TOOL_VERSION,
        name: "controller_command_verification",
        description: "Frozen Controller-owned command verification using pinned executables.",
        permission_ceiling: &PROCESS_CAPABILITIES,
        schema_capabilities: &PROCESS_CAPABILITIES,
        risk: CommandRisk::UntrustedCode,
        reconciliation: ReconciliationPolicy::proof_required_local(),
        input_schema_json: "{}",
    }
}

/// Exact browser execution pin; browser actions are derived from typed Plan acceptance,
/// never exposed as a free-form model-callable tool.
#[must_use]
pub fn canonical_browser_tool_manifest() -> ToolManifest {
    let spec = browser_spec();
    ToolManifest {
        tool_id: spec.tool_id.to_owned(),
        version: spec.version.to_owned(),
        content_digest: canonical_tool_digest(&spec),
        permission_ceiling: spec.permission_ceiling.iter().copied().collect(),
        declared_risk_floor: spec.risk,
        reconciliation_policy: spec.reconciliation,
    }
}

#[must_use]
pub fn canonical_patch_tool_manifest() -> ToolManifest {
    let spec = patch_spec();
    ToolManifest {
        tool_id: spec.tool_id.to_owned(),
        version: spec.version.to_owned(),
        content_digest: canonical_tool_digest(&spec),
        permission_ceiling: spec.permission_ceiling.iter().copied().collect(),
        declared_risk_floor: spec.risk,
        reconciliation_policy: spec.reconciliation,
    }
}

/// Returns the model-visible schema bound to the exact canonical patch-tool identity.
///
/// # Errors
/// Returns an authority error if the frozen built-in JSON schema is malformed.
pub fn canonical_patch_tool_schema() -> Result<ToolSchemaV1, ToolError> {
    let spec = patch_spec();
    let manifest = canonical_patch_tool_manifest();
    let schema = ToolSchemaV1 {
        tool_id: manifest.tool_id.clone(),
        version: manifest.version.clone(),
        content_digest: manifest.content_digest.clone(),
        name: spec.name.to_owned(),
        description: spec.description.to_owned(),
        input_schema: parse_frozen_schema(spec.input_schema_json)?,
        required_capabilities: CapabilitySet::new(spec.schema_capabilities.iter().copied()),
    };
    schema.validate_against_manifest(&manifest)?;
    Ok(schema)
}

#[must_use]
pub fn canonical_read_tool_manifest() -> ToolManifest {
    let spec = read_spec();
    ToolManifest {
        tool_id: spec.tool_id.to_owned(),
        version: spec.version.to_owned(),
        content_digest: canonical_tool_digest(&spec),
        permission_ceiling: spec.permission_ceiling.iter().copied().collect(),
        declared_risk_floor: spec.risk,
        reconciliation_policy: spec.reconciliation,
    }
}

/// Pin for frozen command-verification steps. This is not a model-callable tool;
/// Controller still resolves each executable through its exact pinned policy.
#[must_use]
pub fn canonical_process_tool_manifest() -> ToolManifest {
    let spec = process_spec();
    ToolManifest {
        tool_id: spec.tool_id.to_owned(),
        version: spec.version.to_owned(),
        content_digest: canonical_tool_digest(&spec),
        permission_ceiling: spec.permission_ceiling.iter().copied().collect(),
        declared_risk_floor: spec.risk,
        reconciliation_policy: spec.reconciliation,
    }
}

/// Returns the model-visible schema bound to the exact canonical read-tool identity.
///
/// # Errors
/// Returns an authority error if the frozen built-in JSON schema is malformed.
pub fn canonical_read_tool_schema() -> Result<ToolSchemaV1, ToolError> {
    let spec = read_spec();
    let manifest = canonical_read_tool_manifest();
    let schema = ToolSchemaV1 {
        tool_id: manifest.tool_id.clone(),
        version: manifest.version.clone(),
        content_digest: manifest.content_digest.clone(),
        name: spec.name.to_owned(),
        description: spec.description.to_owned(),
        input_schema: parse_frozen_schema(spec.input_schema_json)?,
        required_capabilities: CapabilitySet::new(spec.schema_capabilities.iter().copied()),
    };
    schema.validate_against_manifest(&manifest)?;
    Ok(schema)
}

fn parse_frozen_schema(raw: &str) -> Result<Value, ToolError> {
    serde_json::from_str(raw).map_err(|error| {
        ToolError::Authority(format!("invalid frozen canonical tool schema: {error}"))
    })
}

fn canonical_tool_digest(spec: &CanonicalToolSpec) -> String {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, "sovereign-canonical-tool-v1");
    for value in [spec.tool_id, spec.version, spec.name, spec.description] {
        hash_field(&mut hasher, value);
    }
    hash_field(&mut hasher, "permission_ceiling");
    for capability in spec.permission_ceiling {
        hash_field(&mut hasher, capability.as_plan_ir_str());
    }
    hash_field(&mut hasher, "schema_capabilities");
    for capability in spec.schema_capabilities {
        hash_field(&mut hasher, capability.as_plan_ir_str());
    }
    hash_field(&mut hasher, command_risk_id(spec.risk));
    hash_field(
        &mut hasher,
        reconciliation_class_id(spec.reconciliation.class),
    );
    hash_field(&mut hasher, spec.input_schema_json);
    format!("sha256:{:x}", hasher.finalize())
}

fn hash_field(hasher: &mut Sha256, value: &str) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value.as_bytes());
}

const fn command_risk_id(risk: CommandRisk) -> &'static str {
    match risk {
        CommandRisk::ReadOnly => "read_only",
        CommandRisk::RepositoryMutation => "repository_mutation",
        CommandRisk::UntrustedCode => "untrusted_code",
        CommandRisk::PackageInstall => "package_install",
        CommandRisk::Destructive => "destructive",
        CommandRisk::Shell => "shell",
    }
}

const fn reconciliation_class_id(class: ReconciliationClass) -> &'static str {
    match class {
        ReconciliationClass::IdempotentLocal => "idempotent_local",
        ReconciliationClass::ProofRequiredLocal => "proof_required_local",
        ReconciliationClass::ConsequentialExternal => "consequential_external",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn canonical_tool_contracts_are_exact_and_self_consistent() {
        let patch_manifest = canonical_patch_tool_manifest();
        let patch_schema = canonical_patch_tool_schema()
            .unwrap_or_else(|error| panic!("canonical patch schema: {error}"));
        let read_manifest = canonical_read_tool_manifest();
        let read_schema = canonical_read_tool_schema()
            .unwrap_or_else(|error| panic!("canonical read schema: {error}"));

        assert_eq!(patch_manifest.tool_id, CANONICAL_PATCH_TOOL_ID);
        assert_eq!(read_manifest.tool_id, CANONICAL_READ_TOOL_ID);
        assert_eq!(patch_manifest.version, CANONICAL_TOOL_VERSION);
        assert_eq!(read_manifest.version, CANONICAL_TOOL_VERSION);
        assert!(patch_manifest.validate().is_ok());
        assert!(read_manifest.validate().is_ok());
        assert!(
            patch_schema
                .validate_against_manifest(&patch_manifest)
                .is_ok()
        );
        assert!(
            read_schema
                .validate_against_manifest(&read_manifest)
                .is_ok()
        );

        assert_eq!(
            patch_manifest.permission_ceiling,
            BTreeSet::from([
                PermissionClass::ProcessExec,
                PermissionClass::RepositoryWrite,
            ])
        );
        assert_eq!(
            read_manifest.permission_ceiling,
            BTreeSet::from([PermissionClass::Read, PermissionClass::ProcessExec])
        );
        assert_eq!(
            patch_manifest.declared_risk_floor,
            CommandRisk::RepositoryMutation
        );
        assert_eq!(read_manifest.declared_risk_floor, CommandRisk::ReadOnly);
        assert_eq!(
            patch_manifest.reconciliation_policy,
            ReconciliationPolicy::proof_required_local()
        );
        assert_eq!(
            read_manifest.reconciliation_policy,
            ReconciliationPolicy::idempotent_local()
        );
        assert_eq!(
            patch_schema.required_capabilities,
            CapabilitySet::new([
                PermissionClass::ProcessExec,
                PermissionClass::RepositoryWrite,
            ])
        );
        assert_eq!(
            read_schema.required_capabilities,
            CapabilitySet::new([PermissionClass::Read])
        );
    }

    #[test]
    fn canonical_tool_digests_are_frozen_and_not_eval_fixture_pins() {
        let patch = canonical_patch_tool_manifest();
        let read = canonical_read_tool_manifest();

        assert_eq!(
            patch.content_digest,
            "sha256:23e797d53255d25a366ef0c569f6b1dbadf9d8d45086d99e7d6fd277d291fb8b"
        );
        assert_eq!(
            read.content_digest,
            "sha256:6edba5a10ec9c424e573d5761878132d72698ada5462ca96277e220b8c92dcf9"
        );
        assert_ne!(
            patch.content_digest,
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        );
        assert_ne!(
            read.content_digest,
            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        );
    }
}
