use serde_json::Value;
use sovereign_policy::LeasePairRule::{Conditional as C, Forbidden as N, Serialize as S};
use sovereign_policy::{
    AdmissionStatus, ConditionalLeaseContextV1, HardwareProfileV1, HeavyLeaseClass, LeasePairRule,
    M6ResourceGovernor, OsMemoryPressure, PlanHeavyLeaseClass, PressureBand, ResourceLeaseOwnerV1,
    ResourceLeaseRequestV1, ResourcePolicyEventV1, ResourcePressureEventV1,
    ResourcePressureSnapshotV1, TaskResourceBudgetV1, ThermalPressure,
};

fn green_snapshot(observed_at_ms: i64) -> ResourcePressureSnapshotV1 {
    ResourcePressureSnapshotV1 {
        schema_version: 1,
        observed_at_ms,
        controlled_working_set_mib: 512,
        host_headroom_mib: 6_000,
        swap_used_mib: Some(9_728),
        swap_out_growth_mib_per_min: 0,
        compressor_growth_mib_per_min: 0,
        os_memory_pressure: OsMemoryPressure::Normal,
        recent_pressure_event: false,
        thermal_pressure: ThermalPressure::Normal,
        allocation_failure: false,
        repeated_resource_kill: false,
        uncontrolled_child_growth: false,
        host_free_disk_mib: Some(64 * 1_024),
    }
}

fn owner(task_id: &str) -> ResourceLeaseOwnerV1 {
    ResourceLeaseOwnerV1 {
        plan_id: "plan.resources".to_owned(),
        plan_revision: 1,
        task_id: task_id.to_owned(),
    }
}

fn budget(classes: impl IntoIterator<Item = PlanHeavyLeaseClass>) -> TaskResourceBudgetV1 {
    TaskResourceBudgetV1::new(5_500, 8, classes)
}

fn request(
    lease_id: &str,
    class: HeavyLeaseClass,
    calibrated: bool,
    p95_mib: u64,
) -> ResourceLeaseRequestV1 {
    ResourceLeaseRequestV1 {
        lease_id: lease_id.to_owned(),
        owner: owner(lease_id),
        class,
        calibrated,
        calibrated_p95_rss_mib: p95_mib,
        evictable_idle_rss_mib: 0,
        task_budget: budget([class.plan_ir_class()]),
        conditional: ConditionalLeaseContextV1::default(),
        automatic_reload: false,
        disk_expanding: false,
    }
}

fn observe_green(governor: &mut M6ResourceGovernor, at_ms: i64) -> ResourcePressureEventV1 {
    governor.observe_pressure(green_snapshot(at_ms))
}

#[test]
fn resources_m1_8gb_profile_materializes_frozen_limits_and_matrix() {
    let profile = HardwareProfileV1::m1_8gb();
    assert_eq!(profile.profile_id, "m1-8gb");
    assert_eq!(profile.physical_memory_mib, 8_192);
    assert_eq!(profile.normal_controlled_working_set_soft_mib, 4_864);
    assert_eq!(profile.normal_controlled_working_set_hard_mib, 5_632);
    assert_eq!(profile.minimum_launch_headroom_soft_mib, 1_536);
    assert_eq!(profile.minimum_launch_headroom_hard_mib, 1_280);
    assert_eq!(profile.heavy_lease_recovery_green_seconds, 120);
    assert_eq!(profile.heavy_lease_reload_cooldown_seconds, 30);
    assert_eq!(profile.heavy_lease_oscillation_window_seconds, 300);
    assert_eq!(profile.pair_rules.len(), 36);

    let expected = [
        [N, S, C, C, S, C, S, C],
        [S, N, S, S, S, C, S, S],
        [C, S, N, N, S, S, S, S],
        [C, S, N, N, S, S, S, S],
        [S, S, S, S, N, S, S, S],
        [C, C, S, S, S, N, S, S],
        [S, S, S, S, S, S, N, S],
        [C, S, S, S, S, S, S, N],
    ];
    for (active_index, active) in HeavyLeaseClass::KNOWN.iter().copied().enumerate() {
        for (requested_index, requested) in HeavyLeaseClass::KNOWN.iter().copied().enumerate() {
            assert_eq!(
                profile.pair_rule(active, requested),
                expected[active_index][requested_index],
                "matrix mismatch for {active:?} + {requested:?}"
            );
        }
    }
    assert_eq!(
        profile.pair_rule(HeavyLeaseClass::Unknown, HeavyLeaseClass::Model),
        LeasePairRule::Serialize
    );
}

macro_rules! bump_profile_field {
    ($name:ident, $field:ident) => {
        fn $name(profile: &mut HardwareProfileV1) {
            profile.$field = profile.$field.saturating_add(1);
        }
    };
}

bump_profile_field!(bump_schema_version, schema_version);
bump_profile_field!(bump_physical_memory_mib, physical_memory_mib);
bump_profile_field!(bump_logical_cpus, logical_cpus);
bump_profile_field!(bump_normal_model_slots, normal_model_slots);
bump_profile_field!(bump_mutating_task_slots, mutating_task_slots);
bump_profile_field!(bump_browser_slots, browser_slots);
bump_profile_field!(bump_embedder_slots, embedder_slots);
bump_profile_field!(bump_heavy_build_slots, heavy_build_slots);
bump_profile_field!(bump_heavy_index_slots, heavy_index_slots);
bump_profile_field!(bump_minimum_host_free_disk_mib, minimum_host_free_disk_mib);
bump_profile_field!(
    bump_sovereign_disk_soft_limit_mib,
    sovereign_disk_soft_limit_mib
);
bump_profile_field!(
    bump_sovereign_disk_hard_limit_mib,
    sovereign_disk_hard_limit_mib
);
bump_profile_field!(
    bump_normal_controlled_working_set_soft_mib,
    normal_controlled_working_set_soft_mib
);
bump_profile_field!(
    bump_normal_controlled_working_set_hard_mib,
    normal_controlled_working_set_hard_mib
);
bump_profile_field!(
    bump_minimum_launch_headroom_soft_mib,
    minimum_launch_headroom_soft_mib
);
bump_profile_field!(
    bump_minimum_launch_headroom_hard_mib,
    minimum_launch_headroom_hard_mib
);
bump_profile_field!(bump_default_model_input_tokens, default_model_input_tokens);
bump_profile_field!(
    bump_default_model_output_reserve_tokens,
    default_model_output_reserve_tokens
);
bump_profile_field!(
    bump_hard_model_input_tokens_without_profile_override,
    hard_model_input_tokens_without_profile_override
);
bump_profile_field!(bump_guarded_growth_mib_per_min, guarded_growth_mib_per_min);
bump_profile_field!(
    bump_constrained_growth_mib_per_min,
    constrained_growth_mib_per_min
);
bump_profile_field!(
    bump_constrained_controlled_working_set_mib,
    constrained_controlled_working_set_mib
);
bump_profile_field!(
    bump_heavy_lease_recovery_green_seconds,
    heavy_lease_recovery_green_seconds
);
bump_profile_field!(
    bump_heavy_lease_reload_cooldown_seconds,
    heavy_lease_reload_cooldown_seconds
);
bump_profile_field!(
    bump_heavy_lease_oscillation_window_seconds,
    heavy_lease_oscillation_window_seconds
);
bump_profile_field!(
    bump_max_completed_eviction_cycles_per_window,
    max_completed_eviction_cycles_per_window
);
bump_profile_field!(
    bump_unknown_heavy_admission_mib,
    unknown_heavy_admission_mib
);
bump_profile_field!(
    bump_unknown_heavy_first_run_max_jobs,
    unknown_heavy_first_run_max_jobs
);
bump_profile_field!(bump_calibrated_build_max_jobs, calibrated_build_max_jobs);
bump_profile_field!(
    bump_unknown_heavy_first_run_max_subprocesses,
    unknown_heavy_first_run_max_subprocesses
);

fn drift_profile_id(profile: &mut HardwareProfileV1) {
    profile.profile_id.push_str("-drift");
}

fn drift_pair_rules(profile: &mut HardwareProfileV1) {
    profile.pair_rules[0].rule = LeasePairRule::Safe;
}

type ProfileMutation = fn(&mut HardwareProfileV1);

const PROFILE_AUTHORITY_MUTATIONS: &[(&str, ProfileMutation)] = &[
    ("schema_version", bump_schema_version),
    ("profile_id", drift_profile_id),
    ("physical_memory_mib", bump_physical_memory_mib),
    ("logical_cpus", bump_logical_cpus),
    ("normal_model_slots", bump_normal_model_slots),
    ("mutating_task_slots", bump_mutating_task_slots),
    ("browser_slots", bump_browser_slots),
    ("embedder_slots", bump_embedder_slots),
    ("heavy_build_slots", bump_heavy_build_slots),
    ("heavy_index_slots", bump_heavy_index_slots),
    (
        "minimum_host_free_disk_mib",
        bump_minimum_host_free_disk_mib,
    ),
    (
        "sovereign_disk_soft_limit_mib",
        bump_sovereign_disk_soft_limit_mib,
    ),
    (
        "sovereign_disk_hard_limit_mib",
        bump_sovereign_disk_hard_limit_mib,
    ),
    (
        "normal_controlled_working_set_soft_mib",
        bump_normal_controlled_working_set_soft_mib,
    ),
    (
        "normal_controlled_working_set_hard_mib",
        bump_normal_controlled_working_set_hard_mib,
    ),
    (
        "minimum_launch_headroom_soft_mib",
        bump_minimum_launch_headroom_soft_mib,
    ),
    (
        "minimum_launch_headroom_hard_mib",
        bump_minimum_launch_headroom_hard_mib,
    ),
    (
        "default_model_input_tokens",
        bump_default_model_input_tokens,
    ),
    (
        "default_model_output_reserve_tokens",
        bump_default_model_output_reserve_tokens,
    ),
    (
        "hard_model_input_tokens_without_profile_override",
        bump_hard_model_input_tokens_without_profile_override,
    ),
    (
        "guarded_growth_mib_per_min",
        bump_guarded_growth_mib_per_min,
    ),
    (
        "constrained_growth_mib_per_min",
        bump_constrained_growth_mib_per_min,
    ),
    (
        "constrained_controlled_working_set_mib",
        bump_constrained_controlled_working_set_mib,
    ),
    (
        "heavy_lease_recovery_green_seconds",
        bump_heavy_lease_recovery_green_seconds,
    ),
    (
        "heavy_lease_reload_cooldown_seconds",
        bump_heavy_lease_reload_cooldown_seconds,
    ),
    (
        "heavy_lease_oscillation_window_seconds",
        bump_heavy_lease_oscillation_window_seconds,
    ),
    (
        "max_completed_eviction_cycles_per_window",
        bump_max_completed_eviction_cycles_per_window,
    ),
    (
        "unknown_heavy_admission_mib",
        bump_unknown_heavy_admission_mib,
    ),
    (
        "unknown_heavy_first_run_max_jobs",
        bump_unknown_heavy_first_run_max_jobs,
    ),
    ("calibrated_build_max_jobs", bump_calibrated_build_max_jobs),
    (
        "unknown_heavy_first_run_max_subprocesses",
        bump_unknown_heavy_first_run_max_subprocesses,
    ),
    ("pair_rules", drift_pair_rules),
];

#[test]
fn resources_hardware_profile_digest_binds_all_authority_fields_and_restore_rejects_drift() {
    let profile = HardwareProfileV1::m1_8gb();
    let baseline_digest = profile.digest();
    let snapshot = M6ResourceGovernor::new(profile.clone()).snapshot();

    for &(label, mutate) in PROFILE_AUTHORITY_MUTATIONS {
        let mut drifted = profile.clone();
        mutate(&mut drifted);
        assert_ne!(
            drifted.digest(),
            baseline_digest,
            "profile digest did not bind {label}"
        );
        assert!(
            M6ResourceGovernor::restore(drifted, &snapshot).is_err(),
            "snapshot restore accepted drift in {label}"
        );
    }
}

#[test]
fn resources_m1_8gb_profile_digest_commits_derived_idle_ttls() {
    let profile = HardwareProfileV1::m1_8gb();
    assert_eq!(
        profile.digest(),
        "sha256:21d7deb7354809400df510dd2b55a50f9b28af8069e2fd490e880c934967aadd"
    );
}

#[test]
fn resources_pressure_uses_growth_and_live_state_not_absolute_swap_occupancy() {
    let profile = HardwareProfileV1::m1_8gb();
    let high_stable_swap = green_snapshot(0);
    assert_eq!(high_stable_swap.classify(&profile), PressureBand::Green);

    let guarded_swap = ResourcePressureSnapshotV1 {
        swap_out_growth_mib_per_min: 64,
        ..high_stable_swap
    };
    assert_eq!(guarded_swap.classify(&profile), PressureBand::Guarded);

    let guarded_compressor = ResourcePressureSnapshotV1 {
        compressor_growth_mib_per_min: 64,
        ..high_stable_swap
    };
    assert_eq!(guarded_compressor.classify(&profile), PressureBand::Guarded);

    let constrained_swap = ResourcePressureSnapshotV1 {
        swap_out_growth_mib_per_min: 257,
        ..high_stable_swap
    };
    assert_eq!(
        constrained_swap.classify(&profile),
        PressureBand::Constrained
    );

    let constrained_warning = ResourcePressureSnapshotV1 {
        os_memory_pressure: OsMemoryPressure::Warning,
        ..high_stable_swap
    };
    assert_eq!(
        constrained_warning.classify(&profile),
        PressureBand::Constrained
    );

    let emergency = ResourcePressureSnapshotV1 {
        os_memory_pressure: OsMemoryPressure::Critical,
        ..high_stable_swap
    };
    assert_eq!(emergency.classify(&profile), PressureBand::Emergency);

    let unknown_live_signal = ResourcePressureSnapshotV1 {
        os_memory_pressure: OsMemoryPressure::Unknown,
        ..high_stable_swap
    };
    assert_eq!(
        unknown_live_signal.classify(&profile),
        PressureBand::Guarded
    );
}

#[test]
fn resources_projected_rss_task_budget_and_unknown_build_caps_are_enforced() {
    let mut governor = M6ResourceGovernor::default();
    let pressure = observe_green(&mut governor, 0);
    let mut denied = request("model-over-budget", HeavyLeaseClass::Model, true, 4_000);
    denied.task_budget.max_peak_rss_mib = 3_900;
    let decision = governor.admit(&denied, &pressure);
    assert_eq!(decision.status, AdmissionStatus::Denied);
    assert_eq!(decision.projected_controlled_rss_mib, 4_512);

    let calibrated_single = request("model-calibrated-fit", HeavyLeaseClass::Model, true, 4_400);
    assert_eq!(
        governor.admit(&calibrated_single, &pressure).status,
        AdmissionStatus::Admitted
    );
    let _ = governor.release("model-calibrated-fit");

    let mut unknown = request("unknown-build", HeavyLeaseClass::Unknown, false, 256);
    unknown.task_budget = budget([PlanHeavyLeaseClass::BuildHeavy]);
    let decision = governor.admit(&unknown, &pressure);
    assert_eq!(decision.status, AdmissionStatus::Admitted);
    let lease = decision.lease.unwrap_or_else(|| panic!("unknown lease"));
    assert_eq!(lease.admission_rss_mib, 3_072);
    assert_eq!(decision.parallel_job_cap, Some(2));
    assert_eq!(decision.subprocess_cap, 2);

    let _ = governor.release("unknown-build");
    let mut calibrated_build = request("calibrated-build", HeavyLeaseClass::BuildHeavy, true, 512);
    calibrated_build.task_budget = budget([PlanHeavyLeaseClass::BuildHeavy]);
    let calibrated = governor.admit(&calibrated_build, &pressure);
    assert_eq!(calibrated.status, AdmissionStatus::Admitted);
    assert_eq!(calibrated.parallel_job_cap, Some(4));
    assert_eq!(
        calibrated.subprocess_cap,
        calibrated_build.task_budget.max_subprocesses
    );
    let _ = governor.release("calibrated-build");

    let guarded_pressure = governor.observe_pressure(ResourcePressureSnapshotV1 {
        observed_at_ms: pressure.snapshot.observed_at_ms + 1,
        swap_out_growth_mib_per_min: 64,
        ..pressure.snapshot
    });
    let mut guarded_build = request(
        "calibrated-build-guarded",
        HeavyLeaseClass::BuildHeavy,
        true,
        512,
    );
    guarded_build.task_budget = budget([PlanHeavyLeaseClass::BuildHeavy]);
    let guarded = governor.admit(&guarded_build, &guarded_pressure);
    assert_eq!(guarded.status, AdmissionStatus::Admitted);
    assert_eq!(guarded.parallel_job_cap, Some(2));
}

#[test]
fn resources_pair_admission_enforces_one_model_serial_and_conditional_rules() {
    let mut governor = M6ResourceGovernor::default();
    let pressure = observe_green(&mut governor, 0);
    let model = request("model-a", HeavyLeaseClass::Model, true, 1_000);
    assert_eq!(
        governor.admit(&model, &pressure).status,
        AdmissionStatus::Admitted
    );

    let second_model = request("model-b", HeavyLeaseClass::Model, true, 1_000);
    assert_eq!(
        governor.admit(&second_model, &pressure).status,
        AdmissionStatus::Denied
    );

    let build = request("build-a", HeavyLeaseClass::BuildHeavy, true, 512);
    let build_decision = governor.admit(&build, &pressure);
    assert_eq!(build_decision.status, AdmissionStatus::Serialize);

    let browser = request("browser-a", HeavyLeaseClass::CdpBrowser, true, 512);
    assert_eq!(
        governor.admit(&browser, &pressure).status,
        AdmissionStatus::Admitted
    );

    let mut indexer = request("index-a", HeavyLeaseClass::Indexer, true, 256);
    assert_eq!(
        governor.admit(&indexer, &pressure).status,
        AdmissionStatus::Serialize
    );
    indexer.conditional.small_incremental_index = true;
    assert_eq!(
        governor.admit(&indexer, &pressure).status,
        AdmissionStatus::Serialize
    );
    assert!(matches!(
        governor
            .profile()
            .pair_rule(HeavyLeaseClass::CdpBrowser, HeavyLeaseClass::Indexer),
        LeasePairRule::Serialize
    ));
}

#[test]
fn resources_model_indexer_conditional_requires_calibration_green_and_small_batch() {
    let mut governor = M6ResourceGovernor::default();
    let pressure = observe_green(&mut governor, 0);
    assert_eq!(
        governor
            .admit(
                &request("model", HeavyLeaseClass::Model, true, 1_000),
                &pressure
            )
            .status,
        AdmissionStatus::Admitted
    );

    let mut indexer = request("index", HeavyLeaseClass::Indexer, true, 256);
    assert_eq!(
        governor.admit(&indexer, &pressure).status,
        AdmissionStatus::Serialize
    );
    indexer.conditional.small_incremental_index = true;
    assert_eq!(
        governor.admit(&indexer, &pressure).status,
        AdmissionStatus::Admitted
    );
}

#[test]
fn resources_guarded_serializes_overlap_and_constrained_or_emergency_defers() {
    let mut governor = M6ResourceGovernor::default();
    let initial = observe_green(&mut governor, 0);
    assert_eq!(
        governor
            .admit(
                &request("model", HeavyLeaseClass::Model, true, 1_000),
                &initial
            )
            .status,
        AdmissionStatus::Admitted
    );

    let guarded = governor.observe_pressure(ResourcePressureSnapshotV1 {
        observed_at_ms: 1_000,
        swap_out_growth_mib_per_min: 64,
        ..green_snapshot(1_000)
    });
    assert_eq!(guarded.effective_band, PressureBand::Guarded);
    assert_eq!(
        governor
            .admit(
                &request("browser", HeavyLeaseClass::CdpBrowser, true, 256),
                &guarded,
            )
            .status,
        AdmissionStatus::Serialize
    );

    let constrained = governor.observe_pressure(ResourcePressureSnapshotV1 {
        observed_at_ms: 2_000,
        compressor_growth_mib_per_min: 300,
        ..green_snapshot(2_000)
    });
    assert_eq!(
        governor
            .admit(
                &request("index", HeavyLeaseClass::Indexer, true, 128),
                &constrained,
            )
            .status,
        AdmissionStatus::Deferred
    );

    let emergency = governor.observe_pressure(ResourcePressureSnapshotV1 {
        observed_at_ms: 3_000,
        allocation_failure: true,
        ..green_snapshot(3_000)
    });
    assert_eq!(
        governor
            .admit(&request("lsp", HeavyLeaseClass::Lsp, true, 128), &emergency,)
            .status,
        AdmissionStatus::Deferred
    );
}

#[test]
fn resources_green_recovery_is_120_seconds_and_reload_cooldown_is_30_seconds() {
    let mut hysteresis = M6ResourceGovernor::default();
    let guarded = hysteresis.observe_pressure(ResourcePressureSnapshotV1 {
        observed_at_ms: 0,
        swap_out_growth_mib_per_min: 64,
        ..green_snapshot(0)
    });
    assert_eq!(guarded.effective_band, PressureBand::Guarded);
    let first_green = observe_green(&mut hysteresis, 1_000);
    assert_eq!(first_green.effective_band, PressureBand::Guarded);
    let almost = observe_green(&mut hysteresis, 120_999);
    assert_eq!(almost.effective_band, PressureBand::Guarded);
    let recovered = observe_green(&mut hysteresis, 121_000);
    assert_eq!(recovered.effective_band, PressureBand::Green);

    let mut cooldown = M6ResourceGovernor::default();
    let pressure = observe_green(&mut cooldown, 0);
    let mut initial_request = request("model", HeavyLeaseClass::Model, true, 1_000);
    // Caller intent cannot manufacture reload history. An initial admission remains an initial
    // admission even when a legacy caller labels it automatic_reload=true.
    initial_request.automatic_reload = true;
    assert_eq!(
        cooldown.admit(&initial_request, &pressure).status,
        AdmissionStatus::Admitted
    );
    assert!(cooldown.snapshot().capability_cycles.is_empty());
    let _ = cooldown.record_eviction("model", 0);
    let at_29 = observe_green(&mut cooldown, 29_000);
    let mut reload = request("model-reload-29", HeavyLeaseClass::Model, true, 1_000);
    assert!(!reload.automatic_reload);
    assert_eq!(
        cooldown.admit(&reload, &at_29).status,
        AdmissionStatus::Cooldown
    );
    let at_30 = observe_green(&mut cooldown, 30_000);
    reload.lease_id = "model-reload-30".to_owned();
    assert_eq!(
        cooldown.admit(&reload, &at_30).status,
        AdmissionStatus::Admitted
    );
    let cycle = cooldown
        .snapshot()
        .capability_cycles
        .into_iter()
        .find(|cycle| cycle.class == HeavyLeaseClass::Model)
        .unwrap_or_else(|| panic!("MODEL cycle history missing after reload"));
    assert_eq!(cycle.last_evicted_at_ms, Some(0));
    assert_eq!(cycle.last_reloaded_at_ms, Some(30_000));
}

#[test]
fn resources_second_evict_reload_evict_cycle_inside_five_minutes_defers() {
    let mut governor = M6ResourceGovernor::default();
    let initial = observe_green(&mut governor, 0);
    assert_eq!(
        governor
            .admit(
                &request("model-0", HeavyLeaseClass::Model, true, 1_000),
                &initial
            )
            .status,
        AdmissionStatus::Admitted
    );
    let _ = governor.record_eviction("model-0", 0);

    let first_reload_pressure = observe_green(&mut governor, 30_000);
    let first_reload = request("model-1", HeavyLeaseClass::Model, true, 1_000);
    assert!(!first_reload.automatic_reload);
    assert_eq!(
        governor.admit(&first_reload, &first_reload_pressure).status,
        AdmissionStatus::Admitted
    );
    assert!(matches!(
        governor.record_eviction("model-1", 40_000),
        Some(ResourcePolicyEventV1::Evict { .. })
    ));

    let second_reload_pressure = observe_green(&mut governor, 70_000);
    let second_reload = request("model-2", HeavyLeaseClass::Model, true, 1_000);
    assert_eq!(
        governor
            .admit(&second_reload, &second_reload_pressure)
            .status,
        AdmissionStatus::Admitted
    );
    assert!(matches!(
        governor.record_eviction("model-2", 80_000),
        Some(ResourcePolicyEventV1::Defer { .. })
    ));

    let blocked_pressure = observe_green(&mut governor, 110_000);
    let blocked_reload = request("model-3", HeavyLeaseClass::Model, true, 1_000);
    assert_eq!(
        governor.admit(&blocked_reload, &blocked_pressure).status,
        AdmissionStatus::Deferred
    );

    let expired_window_pressure = observe_green(&mut governor, 380_001);
    assert_eq!(
        governor
            .admit(&blocked_reload, &expired_window_pressure)
            .status,
        AdmissionStatus::Admitted
    );
}

#[test]
fn resources_governor_snapshot_restore_preserves_leases_hysteresis_and_oscillation() {
    let profile = HardwareProfileV1::m1_8gb();
    let mut governor = M6ResourceGovernor::new(profile.clone());
    let initial = observe_green(&mut governor, 0);
    assert_eq!(
        governor
            .admit(
                &request("model-0", HeavyLeaseClass::Model, true, 1_000),
                &initial,
            )
            .status,
        AdmissionStatus::Admitted
    );
    let _ = governor.record_eviction("model-0", 0);

    let at_30 = observe_green(&mut governor, 30_000);
    let mut reload = request("model-1", HeavyLeaseClass::Model, true, 1_000);
    assert_eq!(
        governor.admit(&reload, &at_30).status,
        AdmissionStatus::Admitted
    );
    assert!(matches!(
        governor.record_eviction("model-1", 40_000),
        Some(ResourcePolicyEventV1::Evict { .. })
    ));

    let at_70 = observe_green(&mut governor, 70_000);
    reload.lease_id = "model-2".to_owned();
    assert_eq!(
        governor.admit(&reload, &at_70).status,
        AdmissionStatus::Admitted
    );
    let _ = governor.observe_pressure(ResourcePressureSnapshotV1 {
        observed_at_ms: 80_000,
        swap_out_growth_mib_per_min: 64,
        ..green_snapshot(80_000)
    });
    let recovery = observe_green(&mut governor, 81_000);
    assert_eq!(recovery.effective_band, PressureBand::Guarded);

    let snapshot = governor.snapshot();
    let encoded =
        serde_json::to_string(&snapshot).unwrap_or_else(|error| panic!("snapshot json: {error}"));
    let decoded =
        serde_json::from_str(&encoded).unwrap_or_else(|error| panic!("snapshot decode: {error}"));
    let mut restored = M6ResourceGovernor::restore(profile, &decoded)
        .unwrap_or_else(|error| panic!("snapshot restore: {error}"));
    assert_eq!(restored.snapshot(), snapshot);
    assert_eq!(restored.active_leases().count(), 1);

    assert!(matches!(
        restored.record_eviction("model-2", 90_000),
        Some(ResourcePolicyEventV1::Defer { .. })
    ));
}

#[test]
fn resources_governor_restore_fails_closed_on_malformed_or_inconsistent_state() {
    let profile = HardwareProfileV1::m1_8gb();
    let mut governor = M6ResourceGovernor::new(profile.clone());
    let pressure = observe_green(&mut governor, 0);
    assert_eq!(
        governor
            .admit(
                &request("model", HeavyLeaseClass::Model, true, 1_000),
                &pressure,
            )
            .status,
        AdmissionStatus::Admitted
    );
    let snapshot = governor.snapshot();

    let mut wrong_profile = snapshot.clone();
    wrong_profile.profile_digest = "sha256:not-the-current-profile".to_owned();
    assert!(M6ResourceGovernor::restore(profile.clone(), &wrong_profile).is_err());

    let mut duplicate_lease = snapshot.clone();
    duplicate_lease
        .active_leases
        .push(duplicate_lease.active_leases[0].clone());
    assert!(M6ResourceGovernor::restore(profile.clone(), &duplicate_lease).is_err());

    let mut inconsistent_lease = snapshot.clone();
    inconsistent_lease.active_leases[0].profile_id = "other-profile".to_owned();
    assert!(M6ResourceGovernor::restore(profile.clone(), &inconsistent_lease).is_err());

    let mut inconsistent_pressure = snapshot.clone();
    inconsistent_pressure.effective_band = PressureBand::Constrained;
    assert!(M6ResourceGovernor::restore(profile.clone(), &inconsistent_pressure).is_err());

    let mut forbidden_pair = snapshot.clone();
    let mut embedder = forbidden_pair.active_leases[0].clone();
    embedder.lease_id = "embedder".to_owned();
    embedder.owner = owner("embedder");
    embedder.class = HeavyLeaseClass::Embedder;
    embedder.plan_ir_class = PlanHeavyLeaseClass::Embedder;
    embedder.idle_ttl_seconds = profile.idle_ttl_seconds(HeavyLeaseClass::Embedder);
    forbidden_pair.active_leases.push(embedder);
    assert!(M6ResourceGovernor::restore(profile.clone(), &forbidden_pair).is_err());

    let mut conditional_governor = M6ResourceGovernor::new(profile.clone());
    let conditional_pressure = observe_green(&mut conditional_governor, 20_000);
    assert_eq!(
        conditional_governor
            .admit(
                &request("conditional-model", HeavyLeaseClass::Model, true, 1_000),
                &conditional_pressure,
            )
            .status,
        AdmissionStatus::Admitted
    );
    assert_eq!(
        conditional_governor
            .admit(
                &request("conditional-lsp", HeavyLeaseClass::Lsp, true, 128),
                &conditional_pressure,
            )
            .status,
        AdmissionStatus::Admitted
    );
    assert!(
        M6ResourceGovernor::restore(profile.clone(), &conditional_governor.snapshot()).is_err(),
        "conditional active pair restored without durable live-predicate/pressure proof"
    );

    let _ = governor.record_eviction("model", 10_000);
    let mut duplicate_cycle = governor.snapshot();
    duplicate_cycle
        .capability_cycles
        .push(duplicate_cycle.capability_cycles[0].clone());
    assert!(M6ResourceGovernor::restore(profile, &duplicate_cycle).is_err());
}

#[test]
fn resources_idle_ttl_and_pressure_eviction_order_are_policy_only() {
    let mut governor = M6ResourceGovernor::default();
    let pressure = observe_green(&mut governor, 0);
    let embedder = request("embedder", HeavyLeaseClass::Embedder, true, 256);
    assert_eq!(
        governor.admit(&embedder, &pressure).status,
        AdmissionStatus::Admitted
    );
    let _ = governor.mark_idle("embedder", 0);
    assert!(governor.eviction_decisions(&pressure, 29_999).is_empty());
    let decisions = governor.eviction_decisions(&pressure, 30_000);
    assert!(matches!(
        decisions.as_slice(),
        [ResourcePolicyEventV1::Evict {
            lease_id,
            class: HeavyLeaseClass::Embedder
        }] if lease_id == "embedder"
    ));
    assert_eq!(governor.active_leases().count(), 1);
}

#[test]
fn resources_v1_schemas_accept_canonical_serialized_contracts() {
    let hardware_schema: Value =
        serde_json::from_str(include_str!("../../../schemas/hardware-profile-v1.json"))
            .unwrap_or_else(|error| panic!("hardware schema: {error}"));
    let lease_schema: Value =
        serde_json::from_str(include_str!("../../../schemas/resource-lease-v1.json"))
            .unwrap_or_else(|error| panic!("lease schema: {error}"));
    let pressure_schema: Value = serde_json::from_str(include_str!(
        "../../../schemas/resource-pressure-event-v1.json"
    ))
    .unwrap_or_else(|error| panic!("pressure schema: {error}"));

    let profile = HardwareProfileV1::m1_8gb();
    let profile_value =
        serde_json::to_value(&profile).unwrap_or_else(|error| panic!("profile json: {error}"));
    assert_schema_accepts(&hardware_schema, &profile_value);

    let mut governor = M6ResourceGovernor::new(profile);
    let pressure = observe_green(&mut governor, 0);
    let pressure_value = serde_json::to_value(&pressure)
        .unwrap_or_else(|error| panic!("pressure event json: {error}"));
    assert_schema_accepts(&pressure_schema, &pressure_value);

    let decision = governor.admit(
        &request("schema-model", HeavyLeaseClass::Model, true, 1_000),
        &pressure,
    );
    let lease = decision.lease.unwrap_or_else(|| panic!("schema lease"));
    let lease_value =
        serde_json::to_value(&lease).unwrap_or_else(|error| panic!("lease json: {error}"));
    assert_schema_accepts(&lease_schema, &lease_value);
}

fn assert_schema_accepts(schema: &Value, instance: &Value) {
    let validator =
        jsonschema::validator_for(schema).unwrap_or_else(|error| panic!("validator: {error}"));
    let errors = validator
        .iter_errors(instance)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    assert!(errors.is_empty(), "schema errors: {errors:?}");
}
