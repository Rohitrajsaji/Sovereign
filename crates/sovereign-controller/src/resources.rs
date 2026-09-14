use serde::{Deserialize, Serialize};
use sovereign_model::ModelLease;
use sovereign_policy::{
    AdmissionStatus, HardwareProfileV1, HeavyLeaseClass, M6ResourceGovernor,
    M6ResourceGovernorSnapshotV1, OsMemoryPressure, ResourceAdmissionDecisionV1,
    ResourceGovernorRestoreError, ResourceLeaseRequestV1, ResourceLeaseV1, ResourcePolicyEventV1,
    ResourcePressureEventV1, ResourcePressureSnapshotV1, ThermalPressure,
};
use std::collections::BTreeSet;
use std::io;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) const RESOURCE_LEASE_NAMESPACE: &str = "controller.resource_lease";
pub(crate) const RESOURCE_PRESSURE_NAMESPACE: &str = "controller.resource_pressure";
pub(crate) const RESOURCE_RESIDENCY_NAMESPACE: &str = "controller.resource_residency";
pub(crate) const RESOURCE_GOVERNOR_NAMESPACE: &str = "controller.resource_governor";
pub(crate) const MODEL_RESIDENCY_KEY: &str = "model";
pub(crate) const RESOURCE_GOVERNOR_KEY: &str = "active";
pub(crate) const RESOURCE_RESIDENCY_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceResidencyStateV1 {
    Reserved,
    Resident,
    Unloading,
    Absent,
    Unknown,
}

/// Durable Controller binding between policy admission and one physical model lease.
///
/// `process_id=None` is intentionally not proof of physical absence: it means the provider is
/// not Controller-owned strongly enough to serialize it safely against a memory-heavy phase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceResidencyV1 {
    pub schema_version: u32,
    pub plan_id: String,
    pub plan_revision: u32,
    pub task_id: String,
    pub task_contract_digest: String,
    pub execution_epoch: i64,
    pub policy_lease: ResourceLeaseV1,
    pub model_lease: Option<ModelLease>,
    pub state: ResourceResidencyStateV1,
    pub updated_at_ms: i64,
}

impl ResourceResidencyV1 {
    #[must_use]
    pub fn owned_process_id(&self) -> Option<u32> {
        self.model_lease.as_ref().and_then(|lease| lease.process_id)
    }
}

/// Controller-side resource coordinator. The policy crate decides admission; this type owns the
/// runtime binding to physical residency but performs no persistence by itself.
#[derive(Debug, Clone, Default)]
pub(crate) struct ControllerResourceCoordinator {
    governor: M6ResourceGovernor,
    model_residency: Option<ResourceResidencyV1>,
}

impl ControllerResourceCoordinator {
    pub(crate) fn restore(
        snapshot: &M6ResourceGovernorSnapshotV1,
        model_residency: Option<ResourceResidencyV1>,
    ) -> Result<Self, ResourceGovernorRestoreError> {
        let governor = M6ResourceGovernor::restore(HardwareProfileV1::m1_8gb(), snapshot)?;
        let active_model_leases = governor
            .active_leases()
            .filter(|lease| lease.class == HeavyLeaseClass::Model)
            .cloned()
            .collect::<Vec<_>>();
        if active_model_leases.len() > 1 {
            return Err(ResourceGovernorRestoreError::InvalidLease {
                lease_id: active_model_leases
                    .first()
                    .map_or_else(|| "MODEL".to_owned(), |lease| lease.lease_id.clone()),
                reason: "more than one active MODEL lease survived durable restore".to_owned(),
            });
        }
        match model_residency.as_ref() {
            Some(residency) => {
                if residency.schema_version != RESOURCE_RESIDENCY_SCHEMA_VERSION {
                    return Err(ResourceGovernorRestoreError::InvalidLease {
                        lease_id: residency.policy_lease.lease_id.clone(),
                        reason: "unsupported Controller residency schema version".to_owned(),
                    });
                }
                if residency.policy_lease.class != HeavyLeaseClass::Model
                    || residency.policy_lease.owner.plan_id != residency.plan_id
                    || residency.policy_lease.owner.plan_revision != residency.plan_revision
                    || residency.policy_lease.owner.task_id != residency.task_id
                {
                    return Err(ResourceGovernorRestoreError::InvalidLease {
                        lease_id: residency.policy_lease.lease_id.clone(),
                        reason: "MODEL residency scope disagrees with its policy lease".to_owned(),
                    });
                }
                let active = active_model_leases
                    .iter()
                    .find(|lease| lease.lease_id == residency.policy_lease.lease_id);
                if residency.state != ResourceResidencyStateV1::Absent {
                    if active != Some(&residency.policy_lease) {
                        return Err(ResourceGovernorRestoreError::InvalidLease {
                            lease_id: residency.policy_lease.lease_id.clone(),
                            reason: "possibly-resident MODEL is not backed by the exact active logical lease"
                                .to_owned(),
                        });
                    }
                } else if let Some(active) = active
                    && active != &residency.policy_lease
                {
                    return Err(ResourceGovernorRestoreError::InvalidLease {
                        lease_id: residency.policy_lease.lease_id.clone(),
                        reason: "absent MODEL residency disagrees with active logical lease bytes"
                            .to_owned(),
                    });
                }
            }
            None if !active_model_leases.is_empty() => {
                return Err(ResourceGovernorRestoreError::InvalidLease {
                    lease_id: active_model_leases[0].lease_id.clone(),
                    reason: "active MODEL lease has no durable physical-residency record"
                        .to_owned(),
                });
            }
            None => {}
        }
        Ok(Self {
            governor,
            model_residency,
        })
    }

    #[must_use]
    pub(crate) fn snapshot(&self) -> M6ResourceGovernorSnapshotV1 {
        self.governor.snapshot()
    }

    pub(crate) fn observe_pressure(
        &mut self,
        snapshot: ResourcePressureSnapshotV1,
    ) -> ResourcePressureEventV1 {
        self.governor.observe_pressure(snapshot)
    }

    pub(crate) fn admit(
        &mut self,
        request: &ResourceLeaseRequestV1,
        pressure: &ResourcePressureEventV1,
    ) -> ResourceAdmissionDecisionV1 {
        self.governor.admit(request, pressure)
    }

    pub(crate) fn release(&mut self, lease_id: &str) -> Option<ResourcePolicyEventV1> {
        self.governor.release(lease_id)
    }

    pub(crate) fn record_eviction(
        &mut self,
        lease_id: &str,
        now_ms: i64,
    ) -> Option<ResourcePolicyEventV1> {
        self.governor.record_eviction(lease_id, now_ms)
    }

    #[must_use]
    pub(crate) fn model_residency(&self) -> Option<&ResourceResidencyV1> {
        self.model_residency.as_ref()
    }

    pub(crate) fn set_model_residency(&mut self, residency: ResourceResidencyV1) {
        self.model_residency = Some(residency);
    }

    pub(crate) fn clear_model_residency(&mut self) {
        self.model_residency = None;
    }

    #[must_use]
    pub(crate) fn profile(&self) -> &HardwareProfileV1 {
        self.governor.profile()
    }

    #[must_use]
    pub(crate) fn active_lease(&self, lease_id: &str) -> Option<ResourceLeaseV1> {
        self.governor
            .active_leases()
            .find(|lease| lease.lease_id == lease_id)
            .cloned()
    }

    #[must_use]
    pub(crate) fn admission_is_success(decision: &ResourceAdmissionDecisionV1) -> bool {
        decision.status == AdmissionStatus::Admitted && decision.lease.is_some()
    }
}

/// Live pressure source. Production uses [`MacOsResourceProbe`]; deterministic tests inject a
/// fixed/scripted implementation. Policy never shells out or owns platform probing.
pub trait ResourcePressureProbe {
    /// Returns one current typed host-pressure sample.
    ///
    /// # Errors
    /// Returns an I/O error if authoritative host signals cannot be sampled. Callers must fail
    /// closed rather than replacing an unavailable signal with synthetic Green pressure.
    fn sample(&mut self) -> io::Result<ResourcePressureSnapshotV1>;
}

#[derive(Debug, Clone, Copy)]
struct CounterSample {
    observed_at_ms: i64,
    swapouts: u64,
    compressor_pages: u64,
}

/// Read-only macOS pressure probe for the selected M1/8GB local profile.
#[derive(Debug, Default)]
pub struct MacOsResourceProbe {
    previous: Option<CounterSample>,
}

impl ResourcePressureProbe for MacOsResourceProbe {
    fn sample(&mut self) -> io::Result<ResourcePressureSnapshotV1> {
        #[cfg(not(target_os = "macos"))]
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "MacOsResourceProbe requires macOS",
            ));
        }
        #[cfg(target_os = "macos")]
        {
            let observed_at_ms = unix_time_ms()?;
            let vm = command_stdout("/usr/bin/vm_stat", &[])?;
            let page_size = parse_vm_page_size(&vm)?;
            let counters = parse_vm_counters(&vm)?;
            let memory_pressure = command_stdout("/usr/bin/memory_pressure", &["-Q"])?;
            let free_percent = parse_memory_free_percent(&memory_pressure)?;
            let swap = command_stdout("/usr/sbin/sysctl", &["vm.swapusage"])?;
            let swap_used_mib = parse_swap_used_mib(&swap);
            let thermal = command_stdout("/usr/bin/pmset", &["-g", "therm"])?;
            let controlled_working_set_mib = controlled_process_tree_rss_mib()?;
            let host_headroom_mib = u64::from(free_percent)
                .saturating_mul(HardwareProfileV1::m1_8gb().physical_memory_mib)
                / 100;
            let current = CounterSample {
                observed_at_ms,
                swapouts: counters.swapouts,
                compressor_pages: counters.compressor_pages,
            };
            let (swap_growth, compressor_growth, warmup_guard) =
                pressure_growth_signals(self.previous, current, page_size);
            self.previous = Some(current);
            Ok(ResourcePressureSnapshotV1 {
                schema_version: sovereign_policy::RESOURCE_PRESSURE_EVENT_SCHEMA_VERSION,
                observed_at_ms,
                controlled_working_set_mib,
                host_headroom_mib,
                swap_used_mib,
                swap_out_growth_mib_per_min: swap_growth,
                compressor_growth_mib_per_min: compressor_growth,
                os_memory_pressure: if free_percent <= 5 {
                    OsMemoryPressure::Critical
                } else if free_percent <= 10 {
                    OsMemoryPressure::Warning
                } else {
                    OsMemoryPressure::Normal
                },
                // A fresh process has no trustworthy delta basis yet. Treat the first sample as
                // guarded rather than manufacturing zero swap/compressor growth after restart.
                // The next real sample establishes a measured counter delta.
                recent_pressure_event: warmup_guard,
                thermal_pressure: parse_thermal_pressure(&thermal),
                allocation_failure: false,
                repeated_resource_kill: false,
                uncontrolled_child_growth: false,
                host_free_disk_mib: host_free_disk_mib(),
            })
        }
    }
}

#[cfg(target_os = "macos")]
fn pressure_growth_signals(
    previous: Option<CounterSample>,
    current: CounterSample,
    page_size: u64,
) -> (u64, u64, bool) {
    let Some(previous) = previous else {
        // Zero growth without a prior counter sample is unknown, not healthy evidence.
        return (0, 0, true);
    };
    (
        counter_growth_mib_per_min(
            previous.swapouts,
            current.swapouts,
            page_size,
            previous.observed_at_ms,
            current.observed_at_ms,
        ),
        counter_growth_mib_per_min(
            previous.compressor_pages,
            current.compressor_pages,
            page_size,
            previous.observed_at_ms,
            current.observed_at_ms,
        ),
        false,
    )
}

#[cfg(target_os = "macos")]
#[derive(Debug, Default)]
struct VmCounters {
    swapouts: u64,
    compressor_pages: u64,
}

#[cfg(target_os = "macos")]
fn command_stdout(program: &str, args: &[&str]) -> io::Result<String> {
    let output = Command::new(program).args(args).output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "resource probe command {program} failed with {}",
            output.status
        )));
    }
    String::from_utf8(output.stdout)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

#[cfg(target_os = "macos")]
fn parse_vm_page_size(text: &str) -> io::Result<u64> {
    let marker = "page size of ";
    let start = text
        .find(marker)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "vm_stat page size missing"))?
        + marker.len();
    let digits = text[start..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>();
    digits
        .parse()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

#[cfg(target_os = "macos")]
fn parse_vm_counters(text: &str) -> io::Result<VmCounters> {
    let mut counters = VmCounters::default();
    let mut seen_swapouts = false;
    let mut seen_compressor = false;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("Swapouts:") {
            counters.swapouts = parse_vm_counter(value)?;
            seen_swapouts = true;
        } else if let Some(value) = line.strip_prefix("Pages occupied by compressor:") {
            counters.compressor_pages = parse_vm_counter(value)?;
            seen_compressor = true;
        }
    }
    if !seen_swapouts || !seen_compressor {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "vm_stat pressure counters missing",
        ));
    }
    Ok(counters)
}

#[cfg(target_os = "macos")]
fn parse_vm_counter(value: &str) -> io::Result<u64> {
    value
        .trim()
        .trim_end_matches('.')
        .parse()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

#[cfg(target_os = "macos")]
fn parse_memory_free_percent(text: &str) -> io::Result<u32> {
    let marker = "System-wide memory free percentage:";
    let line = text
        .lines()
        .find(|line| line.contains(marker))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "memory pressure percentage missing",
            )
        })?;
    line.split(marker)
        .nth(1)
        .map(str::trim)
        .and_then(|value| value.strip_suffix('%'))
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid memory pressure percentage",
            )
        })
}

#[cfg(target_os = "macos")]
fn parse_swap_used_mib(text: &str) -> Option<u64> {
    let marker = "used = ";
    let start = text.find(marker)? + marker.len();
    let value = text[start..].split_whitespace().next()?;
    let numeric = value.trim_end_matches('M').parse::<f64>().ok()?;
    numeric.max(0.0).round().to_string().parse().ok()
}

#[cfg(target_os = "macos")]
fn parse_thermal_pressure(text: &str) -> ThermalPressure {
    let lower = text.to_ascii_lowercase();
    if lower.contains("critical") {
        ThermalPressure::Critical
    } else if lower.contains("serious") || lower.contains("warning level: 1") {
        ThermalPressure::Serious
    } else if lower.contains("no thermal warning") && lower.contains("no performance warning") {
        ThermalPressure::Normal
    } else {
        ThermalPressure::Unknown
    }
}

#[cfg(target_os = "macos")]
fn controlled_process_tree_rss_mib() -> io::Result<u64> {
    let output = command_stdout("/bin/ps", &["-axo", "pid=,ppid=,rss="])?;
    let mut rows = Vec::new();
    for line in output.lines() {
        let mut fields = line.split_whitespace();
        let Some(process_id) = fields.next().and_then(|value| value.parse::<u32>().ok()) else {
            continue;
        };
        let Some(parent_process_id) = fields.next().and_then(|value| value.parse::<u32>().ok())
        else {
            continue;
        };
        let Some(rss_kib) = fields.next().and_then(|value| value.parse::<u64>().ok()) else {
            continue;
        };
        rows.push((process_id, parent_process_id, rss_kib));
    }
    let root = std::process::id();
    let mut owned = BTreeSet::from([root]);
    loop {
        let before = owned.len();
        for (process_id, parent_process_id, _) in &rows {
            if owned.contains(parent_process_id) {
                owned.insert(*process_id);
            }
        }
        if owned.len() == before {
            break;
        }
    }
    let rss_kib = rows
        .iter()
        .filter(|(process_id, _, _)| owned.contains(process_id))
        .map(|(_, _, rss)| *rss)
        .sum::<u64>();
    Ok(rss_kib.div_ceil(1_024))
}

#[cfg(target_os = "macos")]
fn counter_growth_mib_per_min(
    previous: u64,
    current: u64,
    page_size: u64,
    previous_ms: i64,
    current_ms: i64,
) -> u64 {
    let elapsed = current_ms.saturating_sub(previous_ms);
    if elapsed <= 0 || current < previous {
        return 0;
    }
    let bytes = current.saturating_sub(previous).saturating_mul(page_size);
    let mib = bytes / (1_024 * 1_024);
    let elapsed_u64 = u64::try_from(elapsed).unwrap_or(u64::MAX).max(1);
    mib.saturating_mul(60_000).div_ceil(elapsed_u64)
}

#[cfg(target_os = "macos")]
fn host_free_disk_mib() -> Option<u64> {
    let output = command_stdout("/bin/df", &["-k", "/"]).ok()?;
    let line = output.lines().nth(1)?;
    let fields = line.split_whitespace().collect::<Vec<_>>();
    let available_kib = fields.get(3)?.parse::<u64>().ok()?;
    Some(available_kib / 1_024)
}

fn unix_time_ms() -> io::Result<i64> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_millis();
    i64::try_from(millis).map_err(io::Error::other)
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::{CounterSample, pressure_growth_signals};
    use sovereign_policy::{
        M6ResourceGovernor, OsMemoryPressure, PressureBand, RESOURCE_PRESSURE_EVENT_SCHEMA_VERSION,
        ResourcePressureSnapshotV1, ThermalPressure,
    };

    #[test]
    fn fresh_pressure_probe_counter_state_cannot_synthesize_green() {
        let current = CounterSample {
            observed_at_ms: 60_000,
            swapouts: 100,
            compressor_pages: 200,
        };
        let (swap_growth, compressor_growth, warmup_guard) =
            pressure_growth_signals(None, current, 4_096);
        assert_eq!(swap_growth, 0);
        assert_eq!(compressor_growth, 0);
        assert!(warmup_guard, "first sample must be conservatively guarded");

        let mut governor = M6ResourceGovernor::default();
        let event = governor.observe_pressure(ResourcePressureSnapshotV1 {
            schema_version: RESOURCE_PRESSURE_EVENT_SCHEMA_VERSION,
            observed_at_ms: current.observed_at_ms,
            controlled_working_set_mib: 512,
            host_headroom_mib: 6_144,
            swap_used_mib: Some(4_096),
            swap_out_growth_mib_per_min: swap_growth,
            compressor_growth_mib_per_min: compressor_growth,
            os_memory_pressure: OsMemoryPressure::Normal,
            recent_pressure_event: warmup_guard,
            thermal_pressure: ThermalPressure::Normal,
            allocation_failure: false,
            repeated_resource_kill: false,
            uncontrolled_child_growth: false,
            host_free_disk_mib: Some(32_768),
        });
        assert_ne!(event.raw_band, PressureBand::Green);
        assert_ne!(event.effective_band, PressureBand::Green);

        let (second_swap_growth, second_compressor_growth, second_sample_guard) =
            pressure_growth_signals(
                Some(CounterSample {
                    observed_at_ms: 0,
                    swapouts: 100,
                    compressor_pages: 200,
                }),
                current,
                4_096,
            );
        assert_eq!(second_swap_growth, 0);
        assert_eq!(second_compressor_growth, 0);
        assert!(
            !second_sample_guard,
            "only a real prior counter sample may clear the warm-up guard"
        );
    }
}

#[must_use]
pub(crate) fn resource_event_payload(
    pressure: &ResourcePressureEventV1,
    policy: &ResourcePolicyEventV1,
) -> serde_json::Value {
    serde_json::json!({
        "pressure_event_id": pressure.event_id,
        "raw_band": pressure.raw_band,
        "effective_band": pressure.effective_band,
        "policy_event": policy,
    })
}
