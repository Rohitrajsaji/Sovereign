use serde_json::{Value, json};
use sovereign_policy::{Capability, PlanHeavyLeaseClass};

/// Returns the frozen local-autonomous Plan IR v1.2 policy envelope used for production
/// `PlanCompilationInput` construction.
///
/// This is the single production JSON owner for the Plan IR policy shape. Lower-level capability,
/// approval, resource, isolation, and reconciliation enforcement remains in `sovereign-policy`
/// and the Controller. The envelope grants only local read/repository-write/process authority;
/// network, package, browser, secret, destructive, external-side-effect, and external-intelligence
/// capabilities are not granted by this profile.
#[must_use]
pub fn local_autonomous_plan_policy() -> Value {
    let capability_ceiling = [
        Capability::Read.as_plan_ir_str(),
        Capability::RepositoryWrite.as_plan_ir_str(),
        Capability::ProcessExec.as_plan_ir_str(),
    ];
    let approval_required_permissions = [
        Capability::PackageInstall.as_plan_ir_str(),
        Capability::NetworkWrite.as_plan_ir_str(),
        Capability::ExternalSideEffect.as_plan_ir_str(),
        Capability::ExternalIntelligence.as_plan_ir_str(),
        Capability::Destructive.as_plan_ir_str(),
    ];
    let heavy_leases = [
        PlanHeavyLeaseClass::Model.as_plan_ir_str(),
        PlanHeavyLeaseClass::BuildHeavy.as_plan_ir_str(),
    ];

    json!({
        "capability_ceiling": capability_ceiling,
        "filesystem": filesystem_policy(),
        "process": process_policy(),
        "network": offline_network_policy(),
        "secrets": secret_policy(),
        "approval": approval_policy(approval_required_permissions),
        "browser": browser_policy(),
        "audit": audit_policy(),
        "external_intelligence": external_intelligence_policy(),
        "retry": retry_policy(),
        "escalation": ["L0", "L1", "L2", "L3", "L4"],
        "checkpoint": checkpoint_policy(),
        "resources": resource_policy(heavy_leases)
    })
}

fn filesystem_policy() -> Value {
    json!({
        "canonical_roots_required": true,
        "symlink_escape": "deny",
        "controller_state_protected": true,
        "atomic_replace_untrusted_targets": true,
        "revalidate_before_commit": true,
        "sibling_repo_requires_scope": true,
        "protected_path_classes": ["os_roots", "sovereign_internal"]
    })
}

fn process_policy() -> Value {
    json!({
        "structured_commands": true,
        "shell_mode": "disabled",
        "inherit_environment": false,
        "allowed_env_names": ["CI"],
        "deny_hidden_execution": true,
        "untrusted_code_isolation": "required_or_block",
        "executable_resolution": "pinned_manifest_or_approved_path",
        "strip_ambient_capabilities": true,
        "kill_process_tree_on_timeout": true,
        "default_max_subprocesses": 16
    })
}

fn offline_network_policy() -> Value {
    json!({
        "default": "offline",
        "allowed_hosts": [],
        "allowed_schemes": [],
        "allowed_ports": [],
        "allowed_methods": [],
        "follow_redirects": false,
        "max_redirects": 0,
        "allow_private_ranges": false,
        "dns_revalidation": true,
        "connected_peer_validation": true,
        "ambient_proxy": "deny",
        "allow_task_loopback": false
    })
}

fn secret_policy() -> Value {
    json!({
        "allowed_providers": ["macos_keychain"],
        "persist_values": false,
        "redact_evidence": true,
        "redact_model_context": true,
        "model_secret_values": "never",
        "ephemeral_resolution": true,
        "temporary_file_private": true
    })
}

fn approval_policy(required_permissions: [&str; 5]) -> Value {
    json!({
        "exact_action_binding": true,
        "reapprove_on_payload_change": true,
        "max_ttl_seconds": 900,
        "required_permissions": required_permissions
    })
}

fn browser_policy() -> Value {
    json!({
        "default_profile_mode": "isolated",
        "persistent_profile_requires_explicit_grant": true,
        "downloads": "deny",
        "clipboard": "deny",
        "notifications": "deny",
        "extensions": "deny_by_default",
        "disable_web_security": false,
        "trace_policy": "off",
        "auto_open_downloads": false,
        "local_file_navigation": "deny",
        "offline_telemetry": "deny"
    })
}

fn audit_policy() -> Value {
    json!({
        "append_only_events": true,
        "hash_chain": true,
        "record_policy_digest": true,
        "record_provenance": true,
        "on_corruption": "block_high_risk_until_reconciled"
    })
}

fn external_intelligence_policy() -> Value {
    json!({
        "enabled_by_default": false,
        "requires_explicit_grant": true,
        "allowed_providers": [],
        "allow_resolved_secrets": false,
        "raw_repository_export": "deny",
        "allow_raw_logs": false,
        "output_trust": "untrusted_external_model",
        "tool_authority": "none"
    })
}

fn retry_policy() -> Value {
    json!({
        "default_max_attempts": 3,
        "same_failure_limit": 2,
        "max_tasks_per_revision": 16,
        "max_plan_revisions": 4,
        "max_replans_per_scope": 2
    })
}

fn checkpoint_policy() -> Value {
    json!({
        "before_mutation": true,
        "after_mutation": true,
        "on_verification": true,
        "periodic_seconds": 60,
        "generation_required": true,
        "verify_references": true,
        "integrity": "hash_chain",
        "on_corruption": "fallback_last_valid_or_block"
    })
}

fn resource_policy(heavy_leases: [&str; 2]) -> Value {
    json!({
        "max_wall_seconds": 3600,
        "max_model_calls": 10,
        "max_model_call_seconds": 180,
        "max_tool_actions": 100,
        "max_single_tool_action_seconds": 300,
        "max_peak_rss_mb": 5500,
        "max_output_bytes": 33_554_432,
        "max_retained_raw_bytes": 33_554_432,
        "max_disk_write_mb": 512,
        "max_network_bytes": 0,
        "max_subprocesses": 16,
        "max_child_cpu_seconds": 1800,
        "heavy_leases": heavy_leases
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PlanIr, PlanValidator, ValidationEnvironment};
    use std::collections::BTreeSet;

    #[test]
    fn local_autonomous_policy_is_valid_plan_ir_policy() {
        let mut document: Value =
            serde_json::from_str(include_str!("../tests/fixtures/valid_trivial_plan.json"))
                .unwrap_or_else(|error| panic!("parse valid Plan IR fixture: {error}"));
        document["policy"] = local_autonomous_plan_policy();
        let validator = PlanValidator::new(ValidationEnvironment::default())
            .unwrap_or_else(|error| panic!("construct PlanValidator: {error}"));
        let diagnostics = validator.validate(&PlanIr::from_value(document));
        assert!(
            diagnostics.is_empty(),
            "production local policy must remain valid Plan IR: {diagnostics:?}"
        );
    }

    #[test]
    fn local_autonomous_policy_preserves_frozen_authority_and_resource_ceiling() {
        let policy = local_autonomous_plan_policy();
        let capabilities = policy["capability_ceiling"]
            .as_array()
            .unwrap_or_else(|| panic!("capability ceiling must be an array"))
            .iter()
            .filter_map(Value::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            capabilities,
            BTreeSet::from(["read", "repo_write", "process_exec"])
        );

        assert_eq!(policy["network"]["default"], "offline");
        assert_eq!(policy["network"]["allowed_hosts"], json!([]));
        assert_eq!(policy["network"]["allowed_schemes"], json!([]));
        assert_eq!(policy["network"]["allowed_ports"], json!([]));
        assert_eq!(policy["network"]["allowed_methods"], json!([]));
        assert_eq!(policy["network"]["allow_task_loopback"], false);
        assert_eq!(policy["resources"]["max_network_bytes"], 0);

        assert_eq!(policy["approval"]["exact_action_binding"], true);
        assert_eq!(policy["approval"]["reapprove_on_payload_change"], true);
        assert_eq!(policy["approval"]["max_ttl_seconds"], 900);
        let approval_permissions = policy["approval"]["required_permissions"]
            .as_array()
            .unwrap_or_else(|| panic!("approval required_permissions must be an array"))
            .iter()
            .filter_map(Value::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            approval_permissions,
            BTreeSet::from([
                "package_install",
                "network_write",
                "external_side_effect",
                "external_intelligence",
                "destructive",
            ])
        );

        assert_eq!(policy["resources"]["max_wall_seconds"], 3600);
        assert_eq!(policy["resources"]["max_model_calls"], 10);
        assert_eq!(policy["resources"]["max_model_call_seconds"], 180);
        assert_eq!(policy["resources"]["max_tool_actions"], 100);
        assert_eq!(policy["resources"]["max_single_tool_action_seconds"], 300);
        assert_eq!(policy["resources"]["max_peak_rss_mb"], 5500);
        assert_eq!(policy["resources"]["max_output_bytes"], 33_554_432);
        assert_eq!(policy["resources"]["max_retained_raw_bytes"], 33_554_432);
        assert_eq!(policy["resources"]["max_disk_write_mb"], 512);
        assert_eq!(policy["resources"]["max_subprocesses"], 16);
        assert_eq!(policy["resources"]["max_child_cpu_seconds"], 1800);
        assert_eq!(
            policy["resources"]["heavy_leases"],
            json!(["MODEL", "BUILD_HEAVY"])
        );
        assert_eq!(policy["external_intelligence"]["enabled_by_default"], false);
        assert_eq!(
            policy["external_intelligence"]["allowed_providers"],
            json!([])
        );
        assert_eq!(
            policy["external_intelligence"]["raw_repository_export"],
            "deny"
        );
    }
}
