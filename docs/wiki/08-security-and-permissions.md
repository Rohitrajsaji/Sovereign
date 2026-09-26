# Security and permissions

> Snapshot: HEAD `d266399` (2026-09-24) plus uncommitted work (+3440/−604 across 34 files, observed 2026-09-25).

Security is Controller-owned state. Model, repository, memory, web, tool, skill, role, package, and external-model content can propose actions. They cannot enlarge authority. The policy kernel is `crates/sovereign-policy`.

## Capability intersection

`Capability` has twelve variants. Wire names (`as_plan_ir_str`) are the Plan IR permission strings:

| Rust variant | Plan IR string |
| --- | --- |
| `Read` | `read` |
| `SandboxWrite` | `sandbox_write` |
| `RepositoryWrite` | `repo_write` |
| `ProcessExec` | `process_exec` |
| `PackageInstall` | `package_install` |
| `NetworkRead` | `network_read` |
| `NetworkWrite` | `network_write` |
| `BrowserInteractive` | `browser_interactive` |
| `SecretUse` | `secret_use` |
| `ExternalSideEffect` | `external_side_effect` |
| `ExternalIntelligence` | `external_intelligence` |
| `Destructive` | `destructive` |

Effective authority is the intersection of global policy, project policy, the active Plan IR task request, the role ceiling, the tool manifest ceiling, the isolation backend, and explicit persisted user grants. Text in a prompt, skill, or web page cannot add a capability. `process_exec` does not imply filesystem, network, secret, or sibling-repository access.

`PermissionClass` in `sovereign-tools` is an alias kept for older callers. New plan text should use the Plan IR strings.

Related schema versions, all `1`: `CAPABILITY_SET_SCHEMA_VERSION`, `PERMISSION_DECISION_SCHEMA_VERSION`, `APPROVAL_CLAIM_SCHEMA_VERSION`, `RECONCILIATION_POLICY_SCHEMA_VERSION`, `TRUST_LABEL_SCHEMA_VERSION`, `POLICY_VIOLATION_EVIDENCE_SCHEMA_VERSION`, `EXTERNAL_PAYLOAD_POLICY_SCHEMA_VERSION`, `EXTERNAL_ESCALATION_MANIFEST_SCHEMA_VERSION`.

Per-task grants are stored in `controller.task_capability_grant`.

## Approvals

`ApprovalClaim` binds the exact normalized payload. Changing the payload, executable, working root, destination, permission class, plan, task, revision, epoch, policy digest, nonce, or expiry invalidates the claim.

Durable rows:

- requests: `controller.approval_request` (`ApprovalRequestV1`, statuses `ApprovalRequestStatusV1`);
- claims: `controller.approval_claim` (`APPROVAL_CLAIM_NAMESPACE` in `sovereign-tools`);
- audit: `security_audit_events.approval_provenance_digest`.

CLI: `sovereign approvals` and `sovereign approval <id> <approve|deny> <principal>`. HTTP: `POST /v1/approvals/respond`. Both delegate to the Controller. Neither one dispatches a tool.

Explicit approval boundaries for the product profile (amendment v1.0): publication, spending, secret access, and destructive external actions.

## Budgets

`AutonomyBudgetV1` (`AUTONOMY_BUDGET_SCHEMA_VERSION` = 1) in `resources.rs` tracks wall, model, tool, byte, and subprocess ceilings plus used counters. Counters do not refill. Outer Controller budgets dominate inner library retries. Charges land in `controller.autonomy_action_charge`.

## Secrets

`SecretBroker` registers a provider and resolves a `SecretLease` only with `SecretUse`, scope, and expiry. `SecretValue`'s `Debug` impl redacts. Backends include macOS Keychain and a fake backend for tests. Private temp files are mode `0o700`. The only durable or model-visible form is a `SecretRef` (`SECRET_REF_SCHEMA_VERSION` = 1). Lifecycle rows: `controller.secret_action_lifecycle`. Ephemeral file handoff uses env `SOVEREIGN_SECRET_FILE`.

Ingress redaction is `sovereign-evidence::Redactor`, version 1, with 19 generic credential shapes, before any CAS write.

## Network

`NetworkPolicy` is offline by default with an exact allowlist. `canonicalize_idna_uts46` uses a small C helper built by `crates/sovereign-policy/build.rs` (`SOVEREIGN_IDNA_UTS46_HELPER`). Limits: 253 output bytes, 2 second helper timeout. `reject_unsafe_network_ip` rejects loopback, private, link-local, and metadata addresses for ordinary network. Browser loopback is a separate grant in `browser.rs`, not a general network allow.

On non-macOS the IDNA helper is empty and the policy denies. Do not stub it as allow.

## Commands and Git

`CommandSpec` is an executable plus an argument vector. Shell syntax is not inferred from a string. `CommandRisk` classifies `ReadOnly`, `RepositoryMutation`, `UntrustedCode`, `PackageInstall`, `Destructive`, and `Shell`.

`AMBIENT_DENY_NAMES` strips `PATH`, `HOME`, proxy variables, Git and SSH overrides, dynamic loader variables (`LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`), editors, pagers, and package-manager tokens unless policy reintroduces a specific variable.

Destructive Git substrings are denied by default: `reset --hard`, `clean -fd`, `clean -df`, `push --force`, `push -f`.

Repository code, package scripts, and build plugins are untrusted even when the executable is `cargo` or `python3`. Isolation must be a real `ExecutionIsolationBackend`. A best-effort wrapper must not be labeled a sandbox. On macOS that backend is `MacSandboxExecBackend` (`/usr/bin/sandbox-exec`). If it cannot prove the boundary, automatic execution is unavailable.

## Prompt injection

Repository content, web content, memories, skills, and tool output are untrusted data. Trust labels (`TrustLabel`, `TrustClass` in context) describe provenance. They do not grant permissions. Tests: `crates/sovereign-eval/tests/prompt_injection.rs`, `crates/sovereign-policy/tests/security.rs`.

## External intelligence

`ExternalIntelligenceGateway` may export a redacted packet under an explicit policy. The response re-enters as untrusted advisory evidence. It has no tool, approval, or completion authority. `EXTERNAL_MAX_OUTPUT_TOKENS` = 1024 and `EXTERNAL_MAX_EVIDENCE_ITEMS` = 16 in the controller. Provider absence must fail closed (`ExternalUnavailableDisposition`). Tests: `external_intelligence_policy.rs`.

## Audit before dispatch

Security-sensitive authorization, denial, approval, dispatch, and reconciliation events are durable before later state depends on them. Failure to persist the pre-dispatch record denies dispatch. Verify chains with `SecurityAuditLog::verify_chain`.
