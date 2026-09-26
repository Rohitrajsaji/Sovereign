//! Measured model RSS calibration for MODEL lease admission.
//!
//! Callers: `sovereign-controller` (records samples after a Controller-owned load or call and
//! reads the estimate before admission).
//! API: `ModelCalibrationKeyV1`, `ModelCalibrationV1`.
//!
//! A calibration only replaces the conservative uncalibrated MODEL estimate. It never changes a
//! profile ceiling. The estimate is the largest measured sample plus a fixed margin, so a
//! larger measurement always raises it.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

pub const MODEL_CALIBRATION_SCHEMA_VERSION: u32 = 1;
/// Samples required before the estimate is trusted.
pub const MODEL_CALIBRATION_MIN_SAMPLES: usize = 3;
/// Samples kept per key. The oldest sample is dropped first.
pub const MODEL_CALIBRATION_MAX_SAMPLES: usize = 32;
/// Margin added on top of the largest sample, in percent.
pub const MODEL_CALIBRATION_MARGIN_PERCENT: u64 = 15;
/// Lowest estimate a calibration can produce, whatever was measured.
pub const MODEL_CALIBRATION_FLOOR_MIB: u64 = 1_024;
/// Samples above this are treated as measurement errors and rejected.
pub const MODEL_CALIBRATION_MAX_SAMPLE_MIB: u64 = 64 * 1_024;

/// Identity of one calibrated configuration. Any change starts a new calibration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelCalibrationKeyV1 {
    /// Opaque digest of the model weights, runtime, and model name, chosen by the composer.
    pub model_identity: String,
    pub server_context_tokens: u32,
    pub profile_id: String,
    pub profile_digest: String,
}

impl ModelCalibrationKeyV1 {
    /// Stable state-record key for this identity.
    #[must_use]
    pub fn storage_key(&self) -> String {
        let mut hasher = Sha256::new();
        for part in [
            self.model_identity.as_bytes(),
            &self.server_context_tokens.to_le_bytes(),
            self.profile_id.as_bytes(),
            self.profile_digest.as_bytes(),
        ] {
            hasher.update(u64::try_from(part.len()).unwrap_or(u64::MAX).to_le_bytes());
            hasher.update(part);
        }
        let digest = hasher.finalize();
        let mut key = String::from("model-calibration:");
        for byte in digest.iter().take(16) {
            let _ = write!(key, "{byte:02x}");
        }
        key
    }
}

/// Durable measured RSS samples for one key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelCalibrationV1 {
    pub schema_version: u32,
    pub key: ModelCalibrationKeyV1,
    pub samples_mib: Vec<u64>,
    pub updated_at_ms: i64,
}

/// Why a sample was not recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelCalibrationSampleError {
    Zero,
    Implausible(u64),
    KeyMismatch,
    UnsupportedSchema(u32),
}

impl std::fmt::Display for ModelCalibrationSampleError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Zero => formatter.write_str("model calibration sample is zero"),
            Self::Implausible(mib) => {
                write!(
                    formatter,
                    "model calibration sample {mib} MiB is implausible"
                )
            }
            Self::KeyMismatch => formatter.write_str("model calibration key does not match"),
            Self::UnsupportedSchema(version) => {
                write!(formatter, "unsupported model calibration schema {version}")
            }
        }
    }
}

impl std::error::Error for ModelCalibrationSampleError {}

impl ModelCalibrationV1 {
    #[must_use]
    pub fn new(key: ModelCalibrationKeyV1, updated_at_ms: i64) -> Self {
        Self {
            schema_version: MODEL_CALIBRATION_SCHEMA_VERSION,
            key,
            samples_mib: Vec::new(),
            updated_at_ms,
        }
    }

    /// Appends one measured peak RSS sample, keeping the newest
    /// [`MODEL_CALIBRATION_MAX_SAMPLES`].
    ///
    /// # Errors
    /// Rejects zero, implausible samples, a mismatched key, or an unsupported schema.
    pub fn record_sample(
        &mut self,
        key: &ModelCalibrationKeyV1,
        sample_mib: u64,
        observed_at_ms: i64,
    ) -> Result<(), ModelCalibrationSampleError> {
        if self.schema_version != MODEL_CALIBRATION_SCHEMA_VERSION {
            return Err(ModelCalibrationSampleError::UnsupportedSchema(
                self.schema_version,
            ));
        }
        if &self.key != key {
            return Err(ModelCalibrationSampleError::KeyMismatch);
        }
        if sample_mib == 0 {
            return Err(ModelCalibrationSampleError::Zero);
        }
        if sample_mib > MODEL_CALIBRATION_MAX_SAMPLE_MIB {
            return Err(ModelCalibrationSampleError::Implausible(sample_mib));
        }
        self.samples_mib.push(sample_mib);
        if self.samples_mib.len() > MODEL_CALIBRATION_MAX_SAMPLES {
            let excess = self.samples_mib.len() - MODEL_CALIBRATION_MAX_SAMPLES;
            self.samples_mib.drain(..excess);
        }
        self.updated_at_ms = self.updated_at_ms.max(observed_at_ms);
        Ok(())
    }

    /// Admission estimate in MiB, or `None` while there are too few samples or the record is
    /// not a supported schema.
    #[must_use]
    pub fn admission_estimate_mib(&self) -> Option<u64> {
        if self.schema_version != MODEL_CALIBRATION_SCHEMA_VERSION
            || self.samples_mib.len() < MODEL_CALIBRATION_MIN_SAMPLES
        {
            return None;
        }
        let peak = self.samples_mib.iter().copied().max()?;
        let with_margin = peak
            .saturating_mul(100 + MODEL_CALIBRATION_MARGIN_PERCENT)
            .div_ceil(100);
        Some(with_margin.max(MODEL_CALIBRATION_FLOOR_MIB))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> ModelCalibrationKeyV1 {
        ModelCalibrationKeyV1 {
            model_identity: "sha256:model".to_owned(),
            server_context_tokens: 9_728,
            profile_id: "m1-8gb".to_owned(),
            profile_digest: "sha256:profile".to_owned(),
        }
    }

    #[test]
    fn estimate_requires_min_samples_and_adds_margin_to_peak() {
        let mut calibration = ModelCalibrationV1::new(key(), 1);
        calibration.record_sample(&key(), 3_000, 2).ok();
        calibration.record_sample(&key(), 3_130, 3).ok();
        assert_eq!(calibration.admission_estimate_mib(), None);
        calibration.record_sample(&key(), 3_050, 4).ok();
        // 3130 * 1.15 = 3599.5, rounded up.
        assert_eq!(calibration.admission_estimate_mib(), Some(3_600));
        assert_eq!(calibration.updated_at_ms, 4);
    }

    #[test]
    fn larger_measurement_raises_estimate_and_floor_applies() {
        let mut calibration = ModelCalibrationV1::new(key(), 0);
        for sample in [100, 200, 300] {
            calibration.record_sample(&key(), sample, 1).ok();
        }
        assert_eq!(
            calibration.admission_estimate_mib(),
            Some(MODEL_CALIBRATION_FLOOR_MIB)
        );
        calibration.record_sample(&key(), 5_000, 2).ok();
        assert_eq!(calibration.admission_estimate_mib(), Some(5_750));
    }

    #[test]
    fn rejects_bad_samples_and_foreign_keys() {
        let mut calibration = ModelCalibrationV1::new(key(), 0);
        assert_eq!(
            calibration.record_sample(&key(), 0, 1),
            Err(ModelCalibrationSampleError::Zero)
        );
        assert!(matches!(
            calibration.record_sample(&key(), MODEL_CALIBRATION_MAX_SAMPLE_MIB + 1, 1),
            Err(ModelCalibrationSampleError::Implausible(_))
        ));
        let mut other = key();
        other.server_context_tokens = 4_096;
        assert_eq!(
            calibration.record_sample(&other, 3_000, 1),
            Err(ModelCalibrationSampleError::KeyMismatch)
        );
        assert!(calibration.samples_mib.is_empty());
        assert_ne!(key().storage_key(), other.storage_key());
    }

    #[test]
    fn sample_window_is_bounded() {
        let mut calibration = ModelCalibrationV1::new(key(), 0);
        for sample in 1..=u64::try_from(MODEL_CALIBRATION_MAX_SAMPLES + 5).unwrap_or(0) {
            calibration.record_sample(&key(), 2_000 + sample, 1).ok();
        }
        assert_eq!(calibration.samples_mib.len(), MODEL_CALIBRATION_MAX_SAMPLES);
        assert_eq!(calibration.samples_mib.first().copied(), Some(2_006));
    }

    #[test]
    fn unsupported_schema_yields_no_estimate() {
        let mut calibration = ModelCalibrationV1::new(key(), 0);
        for sample in [3_000, 3_000, 3_000] {
            calibration.record_sample(&key(), sample, 1).ok();
        }
        calibration.schema_version = 2;
        assert_eq!(calibration.admission_estimate_mib(), None);
    }
}
