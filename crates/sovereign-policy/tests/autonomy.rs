use sovereign_policy::{AUTONOMY_BUDGET_SCHEMA_VERSION, AutonomyBudgetV1};

fn budget() -> AutonomyBudgetV1 {
    AutonomyBudgetV1 {
        schema_version: AUTONOMY_BUDGET_SCHEMA_VERSION,
        max_wall_ms: 60_000,
        max_model_calls: 2,
        max_model_call_ms: 30_000,
        max_tool_actions: 3,
        max_single_tool_action_ms: 10_000,
        max_output_bytes: 4_096,
        max_disk_write_bytes: 2_048,
        max_network_bytes: 1_024,
        max_subprocesses: 2,
        max_child_cpu_ms: 20_000,
        used_wall_ms: 0,
        used_model_calls: 0,
        used_tool_actions: 0,
        used_output_bytes: 0,
        used_disk_write_bytes: 0,
        used_network_bytes: 0,
        used_subprocesses: 0,
        used_child_cpu_ms: 0,
    }
}

#[test]
fn autonomy_budget_v1_charges_outer_boundaries_without_refill() {
    let mut budget = budget();
    budget
        .validate()
        .unwrap_or_else(|error| panic!("valid budget: {error}"));

    budget
        .charge_model_call(30_000)
        .unwrap_or_else(|error| panic!("first model charge: {error}"));
    budget
        .charge_model_call(1)
        .unwrap_or_else(|error| panic!("second model charge: {error}"));
    assert!(budget.charge_model_call(1).is_err());
    assert_eq!(budget.used_model_calls, 2);

    budget
        .charge_tool_action(5_000)
        .unwrap_or_else(|error| panic!("tool charge: {error}"));
    budget
        .charge_browser_action(5_000)
        .unwrap_or_else(|error| panic!("browser charge: {error}"));
    assert_eq!(budget.used_tool_actions, 2);
    budget
        .charge_tool_action(1)
        .unwrap_or_else(|error| panic!("last tool charge: {error}"));
    assert!(budget.charge_browser_action(1).is_err());
    assert_eq!(budget.used_tool_actions, 3);

    for _ in 0..2 {
        budget
            .charge_process_spawn()
            .unwrap_or_else(|error| panic!("process charge: {error}"));
    }
    assert!(budget.charge_process_spawn().is_err());
    assert_eq!(budget.used_subprocesses, 2);
}

#[test]
fn autonomy_budget_v1_failed_charge_never_mutates_counter() {
    let mut budget = budget();
    assert!(budget.charge_model_call(30_001).is_err());
    assert_eq!(budget.used_model_calls, 0);
    assert!(budget.charge_tool_action(10_001).is_err());
    assert_eq!(budget.used_tool_actions, 0);

    budget
        .charge_output_bytes(4_000)
        .unwrap_or_else(|error| panic!("output charge: {error}"));
    let before = budget.used_output_bytes;
    assert!(budget.charge_output_bytes(97).is_err());
    assert_eq!(budget.used_output_bytes, before);

    budget
        .charge_wall_ms(59_000)
        .unwrap_or_else(|error| panic!("wall charge: {error}"));
    let before = budget.used_wall_ms;
    assert!(budget.charge_wall_ms(1_001).is_err());
    assert_eq!(budget.used_wall_ms, before);
}

#[test]
fn autonomy_budget_v1_restoration_rejects_reset_or_overrun_state() {
    let mut budget = budget();
    budget.used_model_calls = budget.max_model_calls;
    budget.used_network_bytes = budget.max_network_bytes;
    let encoded = serde_json::to_vec(&budget)
        .unwrap_or_else(|error| panic!("serialize autonomy budget: {error}"));
    let restored: AutonomyBudgetV1 = serde_json::from_slice(&encoded)
        .unwrap_or_else(|error| panic!("restore autonomy budget: {error}"));
    restored
        .validate()
        .unwrap_or_else(|error| panic!("restored budget valid: {error}"));

    let mut overrun = restored.clone();
    overrun.used_model_calls = overrun.max_model_calls.saturating_add(1);
    assert!(overrun.validate().is_err());

    let mut wrong_schema = restored;
    wrong_schema.schema_version = AUTONOMY_BUDGET_SCHEMA_VERSION.saturating_add(1);
    assert!(wrong_schema.validate().is_err());
}

#[test]
fn autonomy_budget_v1_byte_and_cpu_charges_are_fail_closed() {
    let mut budget = budget();
    budget
        .charge_disk_write_bytes(2_048)
        .unwrap_or_else(|error| panic!("disk charge: {error}"));
    budget
        .charge_network_bytes(1_024)
        .unwrap_or_else(|error| panic!("network charge: {error}"));
    budget
        .charge_child_cpu_ms(20_000)
        .unwrap_or_else(|error| panic!("cpu charge: {error}"));

    assert!(budget.charge_disk_write_bytes(1).is_err());
    assert!(budget.charge_network_bytes(1).is_err());
    assert!(budget.charge_child_cpu_ms(1).is_err());
    assert_eq!(budget.used_disk_write_bytes, 2_048);
    assert_eq!(budget.used_network_bytes, 1_024);
    assert_eq!(budget.used_child_cpu_ms, 20_000);
}
