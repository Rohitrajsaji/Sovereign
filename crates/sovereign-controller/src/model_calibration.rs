//! Durable measured MODEL RSS calibration.
//!
//! Callers: MODEL admission and load in `lib.rs`, compilation in `production_driver.rs`, and the
//! composer in `apps/sovereign/src/runner.rs` (through `Controller` methods).
//! API: `Controller::set_model_calibration_identity`, `Controller::model_admission_estimate`,
//! `Controller::record_model_load_calibration`, `PeakRssRecorder`.
//! Schema: `ModelCalibrationV1` in `sovereign-policy`, namespace `controller.model_calibration`.
//!
//! Samples come only from Controller-owned loads and calls. They are telemetry, not authority:
//! a failed sample write never fails the task, and the post-load RSS budget check still applies.

use crate::{Controller, ControllerError, M1_MODEL_OUTPUT_TOKENS, sha256_prefixed};
use serde_json::json;
use sovereign_model::{
    BackendHealth, ModelBackend, ModelCapabilities, ModelError, ModelLease, ModelLoadProfile,
    ModelRequest, ModelResidencyProof, ModelResponse,
};
use sovereign_policy::{
    AdmissionStatus, ConditionalLeaseContextV1, HardwareProfileV1, HeavyLeaseClass,
    ModelCalibrationKeyV1, ModelCalibrationV1, PlanHeavyLeaseClass, ResourceLeaseOwnerV1,
    ResourceLeaseRequestV1, TaskResourceBudgetV1,
};
use sovereign_state::{NewJournalEvent, StateRecordCasMutation, StateStore};
use std::sync::Mutex;

pub(crate) const MODEL_CALIBRATION_NAMESPACE: &str = "controller.model_calibration";

/// The one server context the Controller loads on this profile. Samples from any other context
/// are not recorded under this key.
pub(crate) fn profile_server_context_tokens(profile: &HardwareProfileV1) -> u32 {
    profile.default_model_input_tokens.saturating_add(
        profile
            .default_model_output_reserve_tokens
            .max(M1_MODEL_OUTPUT_TOKENS),
    )
}

pub(crate) fn calibration_key(
    identity: &str,
    profile: &HardwareProfileV1,
) -> ModelCalibrationKeyV1 {
    ModelCalibrationKeyV1 {
        model_identity: identity.to_owned(),
        server_context_tokens: profile_server_context_tokens(profile),
        profile_id: profile.profile_id.clone(),
        profile_digest: profile.digest(),
    }
}

pub(crate) fn load_calibration(
    state: &StateStore,
    key: &ModelCalibrationKeyV1,
) -> Result<Option<(ModelCalibrationV1, i64)>, ControllerError> {
    let storage_key = key.storage_key();
    let Some(row) = state
        .state_records(MODEL_CALIBRATION_NAMESPACE)?
        .into_iter()
        .find(|row| row.key == storage_key)
    else {
        return Ok(None);
    };
    let calibration: ModelCalibrationV1 = serde_json::from_str(&row.value_json)?;
    if &calibration.key != key {
        return Err(ControllerError::InvalidPlan(
            "model calibration record does not match its storage key".to_owned(),
        ));
    }
    Ok(Some((calibration, row.version)))
}

/// Appends one measured sample with a compare-and-swap write and a journal event.
pub(crate) fn record_calibration_sample(
    state: &mut StateStore,
    key: &ModelCalibrationKeyV1,
    sample_mib: u64,
    observed_at_ms: i64,
) -> Result<(), ControllerError> {
    let existing = load_calibration(state, key)?;
    let (mut calibration, version) = match existing {
        Some((calibration, version)) => (calibration, Some(version)),
        None => (ModelCalibrationV1::new(key.clone(), observed_at_ms), None),
    };
    calibration
        .record_sample(key, sample_mib, observed_at_ms)
        .map_err(|error| ControllerError::InvalidPlan(error.to_string()))?;
    let storage_key = key.storage_key();
    let value_json = serde_json::to_string(&calibration)?;
    let payload_json = json!({
        "storage_key": storage_key,
        "sample_mib": sample_mib,
        "samples": calibration.samples_mib.len(),
        "admission_estimate_mib": calibration.admission_estimate_mib(),
    })
    .to_string();
    let seed = sha256_prefixed(
        format!(
            "{storage_key}\0{}\0{sample_mib}\0{observed_at_ms}",
            version.unwrap_or(0)
        )
        .as_bytes(),
    );
    let event_id = format!("controller.calibration.{}", &seed[7..27]);
    state.compare_and_apply_state_records_with_events(
        &[StateRecordCasMutation {
            namespace: MODEL_CALIBRATION_NAMESPACE,
            key: &storage_key,
            expected_version: version,
            value_json: Some(&value_json),
        }],
        &[NewJournalEvent {
            event_id: &event_id,
            entity_type: "controller",
            entity_id: &storage_key,
            event_kind: "model_calibration_sample_recorded",
            payload_json: &payload_json,
        }],
    )?;
    Ok(())
}

pub(crate) fn kib_to_mib(kib: u64) -> u64 {
    kib.div_ceil(1_024)
}

/// Largest RSS reported by a load, in MiB.
pub(crate) fn load_peak_mib(lease: &ModelLease) -> Option<u64> {
    lease
        .startup_peak_rss_kb
        .into_iter()
        .chain(lease.post_load_rss_kb)
        .max()
        .map(kib_to_mib)
}

/// Pass-through backend that remembers the largest `peak_rss_kb_during_call` it saw.
pub struct PeakRssRecorder<'a> {
    inner: &'a dyn ModelBackend,
    peak_kb: Mutex<Option<u64>>,
}

impl<'a> PeakRssRecorder<'a> {
    #[must_use]
    pub fn new(inner: &'a dyn ModelBackend) -> Self {
        Self {
            inner,
            peak_kb: Mutex::new(None),
        }
    }

    /// Largest observed call peak in MiB.
    #[must_use]
    pub fn peak_mib(&self) -> Option<u64> {
        self.peak_kb
            .lock()
            .ok()
            .and_then(|peak| *peak)
            .map(kib_to_mib)
    }
}

impl ModelBackend for PeakRssRecorder<'_> {
    fn capabilities(&self) -> ModelCapabilities {
        self.inner.capabilities()
    }
    fn load(&self, profile: ModelLoadProfile) -> Result<ModelLease, ModelError> {
        self.inner.load(profile)
    }
    fn complete(&self, request: &ModelRequest) -> Result<ModelResponse, ModelError> {
        let response = self.inner.complete(request)?;
        if let (Some(observed), Ok(mut peak)) =
            (response.peak_rss_kb_during_call, self.peak_kb.lock())
        {
            *peak = Some(peak.map_or(observed, |current| current.max(observed)));
        }
        Ok(response)
    }
    fn count_tokens(&self, content: &str) -> Result<u32, ModelError> {
        self.inner.count_tokens(content)
    }
    fn health(&self) -> Result<BackendHealth, ModelError> {
        self.inner.health()
    }
    fn residency_proof(&self) -> Result<ModelResidencyProof, ModelError> {
        self.inner.residency_proof()
    }
    fn unload(&self) -> Result<(), ModelError> {
        self.inner.unload()
    }
}

impl Controller {
    /// Asks the resource governor whether a MODEL lease of the current estimate would be admitted
    /// right now, before plan compilation loads the model. Compilation has no plan or task yet, so
    /// the probe lease is released immediately and nothing is persisted. The single-writer actor
    /// runs compilation synchronously, so no other heavy lease can start in between.
    ///
    /// Returns `None` when the load may proceed, or a user-facing reason to wait.
    ///
    /// # Errors
    /// Returns a state error or a corrupted calibration record. A failed pressure probe is a
    /// deferral, not an error, so compilation fails closed.
    pub fn compilation_model_admission(&mut self) -> Result<Option<String>, ControllerError> {
        let (calibrated, admission_mib) = self.model_admission_estimate()?;
        let snapshot = match self.resource_probe.sample() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                return Ok(Some(format!(
                    "memory pressure could not be measured, so the model was not started: {error}"
                )));
            }
        };
        let headroom_mib = snapshot.host_headroom_mib;
        let pressure = self.resources.observe_pressure(snapshot);
        let request = ResourceLeaseRequestV1 {
            lease_id: "compilation:model-admission-probe".to_owned(),
            owner: ResourceLeaseOwnerV1 {
                plan_id: "compilation".to_owned(),
                plan_revision: 0,
                task_id: "compile".to_owned(),
            },
            class: HeavyLeaseClass::Model,
            calibrated,
            calibrated_p95_rss_mib: admission_mib,
            evictable_idle_rss_mib: 0,
            task_budget: TaskResourceBudgetV1::new(admission_mib, 1, [PlanHeavyLeaseClass::Model]),
            conditional: ConditionalLeaseContextV1::default(),
            automatic_reload: false,
            disk_expanding: false,
        };
        let decision = self.resources.admit(&request, &pressure);
        if let Some(lease) = decision.lease.as_ref() {
            let _ = self.resources.release(&lease.lease_id);
        }
        if decision.status == AdmissionStatus::Admitted {
            return Ok(None);
        }
        let required_mib =
            admission_mib.saturating_add(self.resources.profile().minimum_launch_headroom_soft_mib);
        Ok(Some(format!(
            "waiting for memory: the model needs about {required_mib} MiB free and {headroom_mib} MiB is free ({} estimate, {:?})",
            if calibrated {
                "measured"
            } else {
                "uncalibrated"
            },
            decision.status
        )))
    }

    /// Sets the opaque identity of the configured model (weights, runtime, and name). `None`
    /// disables calibration, so MODEL admission uses the conservative uncalibrated estimate.
    pub fn set_model_calibration_identity(&mut self, identity: Option<String>) {
        self.model_calibration_identity = identity.filter(|value| !value.is_empty());
    }

    pub(crate) fn model_calibration_key(&self) -> Option<ModelCalibrationKeyV1> {
        self.model_calibration_identity
            .as_deref()
            .map(|identity| calibration_key(identity, self.resources.profile()))
    }

    /// Returns `(calibrated, admission_mib)` for the next MODEL lease.
    ///
    /// # Errors
    /// Returns a state error or a corrupted calibration record.
    pub fn model_admission_estimate(&self) -> Result<(bool, u64), ControllerError> {
        let calibrated = match self.model_calibration_key() {
            Some(key) => load_calibration(&self.state, &key)?
                .and_then(|(calibration, _)| calibration.admission_estimate_mib()),
            None => None,
        };
        Ok(
            calibrated.map_or((false, crate::M1_MODEL_UNCALIBRATED_ADMISSION_MIB), |mib| {
                (true, mib)
            }),
        )
    }

    /// Records the RSS of a load whose context matches the profile.
    /// Returns whether a sample was written.
    ///
    /// # Errors
    /// Returns a state error when the sample cannot be persisted.
    pub fn record_model_load_calibration(
        &mut self,
        lease: &ModelLease,
    ) -> Result<bool, ControllerError> {
        let Some(key) = self.model_calibration_key() else {
            return Ok(false);
        };
        if lease.server_context_tokens != key.server_context_tokens {
            return Ok(false);
        }
        let Some(sample) = load_peak_mib(lease) else {
            return Ok(false);
        };
        record_calibration_sample(&mut self.state, &key, sample, crate::unix_millis()?)?;
        Ok(true)
    }

    /// Records one call peak measured while the profile context was loaded.
    /// Returns whether a sample was written.
    ///
    /// # Errors
    /// Returns a state error when the sample cannot be persisted.
    pub fn record_model_call_calibration(
        &mut self,
        peak_mib: Option<u64>,
    ) -> Result<bool, ControllerError> {
        let (Some(key), Some(sample)) = (self.model_calibration_key(), peak_mib) else {
            return Ok(false);
        };
        record_calibration_sample(&mut self.state, &key, sample, crate::unix_millis()?)?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sovereign_policy::MODEL_CALIBRATION_MIN_SAMPLES;

    fn temp_state(label: &str) -> (std::path::PathBuf, StateStore) {
        let dir = std::env::temp_dir().join(format!(
            "sovereign-calibration-{label}-{}-{}",
            std::process::id(),
            crate::unix_millis().unwrap_or(0)
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("state.sqlite3");
        let state = StateStore::open(&path).unwrap_or_else(|error| panic!("open state: {error}"));
        (dir, state)
    }

    fn lease(context: u32, startup_kb: u64) -> ModelLease {
        ModelLease {
            lease_id: "lease".to_owned(),
            model_id: "model".to_owned(),
            context_tokens: 8_192,
            server_context_tokens: context,
            process_id: Some(1),
            startup_peak_rss_kb: Some(startup_kb),
            post_load_rss_kb: Some(startup_kb / 2),
        }
    }

    #[test]
    fn uncalibrated_until_enough_matching_samples_then_calibrated() {
        let (dir, state) = temp_state("admission");
        let mut controller = Controller::new(state);
        assert_eq!(
            controller.model_admission_estimate().ok(),
            Some((false, crate::M1_MODEL_UNCALIBRATED_ADMISSION_MIB))
        );
        // No identity: nothing is recorded.
        assert_eq!(
            controller
                .record_model_load_calibration(&lease(9_728, 3_120_624))
                .ok(),
            Some(false)
        );
        controller.set_model_calibration_identity(Some("sha256:model-a".to_owned()));
        let context = profile_server_context_tokens(controller.resources.profile());
        assert_eq!(context, 9_728);
        // A different context is never recorded under the profile key.
        assert_eq!(
            controller
                .record_model_load_calibration(&lease(4_096, 3_120_624))
                .ok(),
            Some(false)
        );
        assert_eq!(
            controller
                .record_model_load_calibration(&lease(context, 3_120_624))
                .ok(),
            Some(true)
        );
        for _ in 1..MODEL_CALIBRATION_MIN_SAMPLES - 1 {
            assert_eq!(
                controller.record_model_call_calibration(Some(3_130)).ok(),
                Some(true)
            );
        }
        assert_eq!(
            controller.model_admission_estimate().ok(),
            Some((false, crate::M1_MODEL_UNCALIBRATED_ADMISSION_MIB))
        );
        assert_eq!(
            controller.record_model_call_calibration(Some(3_130)).ok(),
            Some(true)
        );
        // Peak 3130 MiB (3_120_624 KiB rounds to 3048 MiB) plus 15 percent.
        assert_eq!(
            controller.model_admission_estimate().ok(),
            Some((true, 3_600))
        );
        // A different model identity starts uncalibrated again.
        controller.set_model_calibration_identity(Some("sha256:model-b".to_owned()));
        assert_eq!(
            controller.model_admission_estimate().ok(),
            Some((false, crate::M1_MODEL_UNCALIBRATED_ADMISSION_MIB))
        );
        let events = controller
            .state()
            .journal()
            .unwrap_or_default()
            .into_iter()
            .filter(|event| event.event_kind == "model_calibration_sample_recorded")
            .count();
        assert_eq!(events, MODEL_CALIBRATION_MIN_SAMPLES);
        let _ = std::fs::remove_dir_all(dir);
    }

    struct FixedProbe(u64);

    impl crate::ResourcePressureProbe for FixedProbe {
        fn sample(&mut self) -> std::io::Result<sovereign_policy::ResourcePressureSnapshotV1> {
            Ok(sovereign_policy::ResourcePressureSnapshotV1 {
                schema_version: 1,
                observed_at_ms: crate::unix_millis().map_err(std::io::Error::other)?,
                controlled_working_set_mib: 0,
                host_headroom_mib: self.0,
                swap_used_mib: Some(0),
                swap_out_growth_mib_per_min: 0,
                compressor_growth_mib_per_min: 0,
                os_memory_pressure: sovereign_policy::OsMemoryPressure::Normal,
                recent_pressure_event: false,
                thermal_pressure: sovereign_policy::ThermalPressure::Normal,
                allocation_failure: false,
                repeated_resource_kill: false,
                uncontrolled_child_growth: false,
                host_free_disk_mib: Some(100 * 1_024),
            })
        }
    }

    #[test]
    fn compilation_admission_uses_calibration_and_never_holds_a_lease() {
        let (dir, state) = temp_state("compile-admission");
        let mut controller = Controller::new(state);
        // CX-T25 host: 3686 MiB free. Uncalibrated 4096 MiB plus launch headroom cannot fit.
        controller.set_resource_pressure_probe(Box::new(FixedProbe(3_686)));
        let deferred = controller.compilation_model_admission().ok().flatten();
        assert!(
            deferred
                .as_deref()
                .is_some_and(|reason| reason.contains("uncalibrated")),
            "{deferred:?}"
        );
        // Plenty of memory: admitted, and the probe lease is not left behind.
        controller.set_resource_pressure_probe(Box::new(FixedProbe(7_000)));
        assert_eq!(controller.compilation_model_admission().ok(), Some(None));
        assert!(controller.resources.snapshot().active_leases.is_empty());
        // Measured calibration at about 3.1 GiB lowers the requirement for the same host.
        controller.set_model_calibration_identity(Some("sha256:model".to_owned()));
        for _ in 0..MODEL_CALIBRATION_MIN_SAMPLES {
            assert_eq!(
                controller.record_model_call_calibration(Some(3_130)).ok(),
                Some(true)
            );
        }
        controller.set_resource_pressure_probe(Box::new(FixedProbe(5_300)));
        assert_eq!(controller.compilation_model_admission().ok(), Some(None));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn peak_recorder_is_empty_without_calls() {
        let backend = sovereign_model::DeterministicFakeBackend::new(
            ModelCapabilities {
                schema_version: sovereign_model::MODEL_SCHEMA_VERSION,
                model_id: "fake".to_owned(),
                parameter_class: "4B".to_owned(),
                quantization: "Q4_K_M".to_owned(),
                max_context_tokens: 16_384,
                supports_tools: false,
                supports_json_schema: true,
                local: true,
            },
            Vec::new(),
        )
        .unwrap_or_else(|error| panic!("fake backend: {error}"));
        let recorder = PeakRssRecorder::new(&backend);
        assert_eq!(recorder.peak_mib(), None);
    }
}
