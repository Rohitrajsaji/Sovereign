//! Zero-setup local model: the machine check, the pinned model catalog, Apple's Command Line
//! Tools check, and a resumable, checksum-verified download of the runtime and the model.
//!
//! Callers: `dispatch.rs` (`/v2/setup`, `/v2/setup/model/download`, `/v2/setup/model/cancel`,
//! `/v2/setup/developer-tools/install`) through `ServiceShared::model_setup`.
//! API: `ModelSetup`, `SetupStatusV1`, `load_catalog`, `pick_model`, `evaluate_machine`.
//! Schema: `apps/sovereign/assets/model-manifest-v2.json`.
//!
//! Only pinned artifacts are fetched: every entry carries an exact HTTPS URL, size, and SHA-256,
//! and a file is moved into place only after its digest matches. Downloads use `/usr/bin/curl`
//! with HTTPS-only redirects and resume from a partial file. Nothing here starts the model.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

pub const CATALOG_JSON: &str = include_str!("../assets/model-manifest-v2.json");
const CATALOG_SCHEMA_VERSION: u32 = 2;
pub const SETUP_STATUS_SCHEMA_VERSION: u32 = 1;
const MIB: u64 = 1_048_576;
/// Free disk Sovereign keeps for projects and checks after the model is in place.
const WORKING_ROOM_MIB: u64 = 20 * 1_024;
const MIN_MEMORY_MIB: u64 = 8 * 1_024;
const DOWNLOAD_ATTEMPTS: u32 = 3;
const POLL_INTERVAL: Duration = Duration::from_millis(400);
const CURL: &str = "/usr/bin/curl";
const TAR: &str = "/usr/bin/tar";
const VERIFIED_SUFFIX: &str = ".verified.json";

/// The pinned llama.cpp server build.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeEntryV2 {
    pub id: String,
    pub archive_url: String,
    pub archive_sha256: String,
    pub archive_size_bytes: u64,
    pub executable_name: String,
    pub executable_sha256: String,
}

/// One pinned model. Entries without a complete pin are refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelEntryV2 {
    pub id: String,
    pub display_name: String,
    pub model_name: String,
    pub file_name: String,
    pub url: String,
    pub sha256: String,
    pub size_bytes: u64,
    /// Below this the model cannot run at all.
    pub min_memory_mib: u64,
    /// The largest model whose recommendation fits is picked by default.
    pub recommended_memory_mib: u64,
    /// MODEL admission estimate until this Mac has measured the model itself.
    pub starting_estimate_mib: u64,
    /// One plain sentence for the model switcher.
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelCatalogV2 {
    pub schema_version: u32,
    pub runtime: RuntimeEntryV2,
    pub models: Vec<ModelEntryV2>,
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_pinned_url(value: &str) -> bool {
    value.starts_with("https://") && !value.contains(char::is_whitespace)
}

fn is_plain_file_name(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('.')
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
}

/// Parses and checks the committed catalog. Any entry that is not fully pinned fails closed.
///
/// # Errors
/// Returns when the catalog is malformed or an entry is not pinned.
pub fn load_catalog() -> Result<ModelCatalogV2, String> {
    parse_catalog(CATALOG_JSON)
}

fn parse_catalog(json: &str) -> Result<ModelCatalogV2, String> {
    let catalog: ModelCatalogV2 =
        serde_json::from_str(json).map_err(|error| format!("model catalog: {error}"))?;
    if catalog.schema_version != CATALOG_SCHEMA_VERSION {
        return Err("unsupported model catalog version".to_owned());
    }
    let runtime = &catalog.runtime;
    if !is_pinned_url(&runtime.archive_url)
        || !is_sha256_hex(&runtime.archive_sha256)
        || !is_sha256_hex(&runtime.executable_sha256)
        || runtime.archive_size_bytes == 0
        || !is_plain_file_name(&runtime.executable_name)
        || !is_plain_file_name(&runtime.id)
    {
        return Err("the model runtime entry is not fully pinned".to_owned());
    }
    if catalog.models.is_empty() {
        return Err("the model catalog lists no models".to_owned());
    }
    for model in &catalog.models {
        if !is_pinned_url(&model.url)
            || !is_sha256_hex(&model.sha256)
            || model.size_bytes == 0
            || model.min_memory_mib == 0
            || model.recommended_memory_mib < model.min_memory_mib
            || model.starting_estimate_mib == 0
            || model.summary.trim().is_empty()
            || !is_plain_file_name(&model.file_name)
            || !is_plain_file_name(&model.id)
            || model.model_name.trim().is_empty()
        {
            return Err(format!("model {} is not fully pinned", model.id));
        }
    }
    let mut ids = catalog
        .models
        .iter()
        .map(|model| &model.id)
        .collect::<Vec<_>>();
    ids.sort();
    ids.dedup();
    if ids.len() != catalog.models.len() {
        return Err("the model catalog repeats a model id".to_owned());
    }
    Ok(catalog)
}

/// The model picked by default: the largest whose recommended memory this Mac has, or else the
/// smallest that runs at all.
#[must_use]
pub fn pick_model(catalog: &ModelCatalogV2, memory_mib: u64) -> Option<&ModelEntryV2> {
    catalog
        .models
        .iter()
        .filter(|model| model.recommended_memory_mib <= memory_mib)
        .max_by_key(|model| (model.recommended_memory_mib, model.size_bytes))
        .or_else(|| {
            catalog
                .models
                .iter()
                .filter(|model| model.min_memory_mib <= memory_mib)
                .min_by_key(|model| (model.recommended_memory_mib, model.size_bytes))
        })
}

/// The catalog entry whose downloaded file is `path`, matched by file name.
#[must_use]
pub fn entry_for_path<'a>(catalog: &'a ModelCatalogV2, path: &Path) -> Option<&'a ModelEntryV2> {
    let name = path.file_name()?.to_str()?;
    catalog.models.iter().find(|model| model.file_name == name)
}

/// The starting MODEL estimate for the model file in use, when it is a catalog model.
#[must_use]
pub fn starting_estimate_for(path: &Path) -> Option<u64> {
    let catalog = load_catalog().ok()?;
    entry_for_path(&catalog, path).map(|model| model.starting_estimate_mib)
}

/// What Sovereign found about this Mac.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MachineV1 {
    /// Sovereign can run here at all (Apple silicon, enough memory).
    pub supported: bool,
    pub apple_silicon: bool,
    pub memory_mib: Option<u64>,
    pub free_disk_mib: Option<u64>,
    /// Plain-language problems, each with what to do.
    pub problems: Vec<String>,
}

/// Judges the machine for a download of `still_needed_bytes`.
#[must_use]
pub fn evaluate_machine(
    apple_silicon: bool,
    memory_mib: Option<u64>,
    free_disk_mib: Option<u64>,
    still_needed_bytes: u64,
) -> MachineV1 {
    let mut problems = Vec::new();
    let mut supported = true;
    if !apple_silicon {
        supported = false;
        problems.push("Sovereign runs on Macs with Apple silicon (M1 or later).".to_owned());
    }
    if let Some(memory) = memory_mib
        && memory < MIN_MEMORY_MIB
    {
        supported = false;
        problems.push(format!(
            "Sovereign needs at least 8 GB of memory. This Mac has {} GB.",
            memory / 1_024
        ));
    }
    if let Some(free) = free_disk_mib {
        let needed = still_needed_bytes.div_ceil(MIB) + WORKING_ROOM_MIB;
        if free < needed {
            problems.push(format!(
                "Free up {} GB of disk space. Sovereign needs about {} GB free: room for the model plus 20 GB to work in.",
                (needed - free).div_ceil(1_024),
                needed.div_ceil(1_024)
            ));
        }
    }
    MachineV1 {
        supported,
        apple_silicon,
        memory_mib,
        free_disk_mib,
        problems,
    }
}

fn probe_apple_silicon() -> bool {
    cfg!(all(target_os = "macos", target_arch = "aarch64"))
}

fn probe_memory_mib() -> Option<u64> {
    let output = Command::new("/usr/sbin/sysctl")
        .args(["-n", "hw.memsize"])
        .output()
        .ok()?;
    let bytes = String::from_utf8(output.stdout)
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()?;
    Some(bytes / MIB)
}

fn probe_free_disk_mib(path: &Path) -> Option<u64> {
    let output = Command::new("/bin/df").arg("-k").arg(path).output().ok()?;
    let text = String::from_utf8(output.stdout).ok()?;
    let available_kib = text
        .lines()
        .nth(1)?
        .split_whitespace()
        .nth(3)?
        .parse::<u64>()
        .ok()?;
    Some(available_kib / 1_024)
}

/// Whether Apple's Command Line Tools (which provide `git` and `python3`) are installed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeveloperToolsV1 {
    pub installed: bool,
    pub detail: String,
}

/// Checks for Apple's Command Line Tools without running the `/usr/bin` stubs, which would pop
/// up Apple's installer on their own.
#[must_use]
pub fn probe_developer_tools() -> DeveloperToolsV1 {
    if !cfg!(target_os = "macos") {
        let installed =
            Path::new("/usr/bin/git").is_file() && Path::new("/usr/bin/python3").is_file();
        return DeveloperToolsV1 {
            installed,
            detail: if installed {
                "Git and Python are installed.".to_owned()
            } else {
                "Install Git and Python 3.".to_owned()
            },
        };
    }
    let developer_dir = Command::new("/usr/bin/xcode-select")
        .arg("-p")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|text| PathBuf::from(text.trim()));
    let installed = developer_dir.as_ref().is_some_and(|dir| {
        dir.join("usr/bin/git").is_file() && dir.join("usr/bin/python3").is_file()
    });
    DeveloperToolsV1 {
        installed,
        detail: if installed {
            "Apple's Command Line Tools are installed.".to_owned()
        } else {
            "Sovereign uses Apple's free Command Line Tools to save your project's history and check its work. Install them once, then choose Check again.".to_owned()
        },
    }
}

/// Opens Apple's installer for the Command Line Tools.
///
/// # Errors
/// Returns when the installer cannot be started.
pub fn install_developer_tools() -> Result<(), String> {
    if !cfg!(target_os = "macos") {
        return Err("Apple's Command Line Tools installer is available on macOS only.".to_owned());
    }
    let output = Command::new("/usr/bin/xcode-select")
        .arg("--install")
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("Could not open Apple's installer: {error}"))?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    // Already installed, or the installer is already open: both are fine.
    if output.status.success() || stderr.contains("already installed") || stderr.contains("already")
    {
        return Ok(());
    }
    Err(format!(
        "Could not open Apple's installer: {}",
        stderr.trim()
    ))
}

/// The model picked for this machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModelChoiceV1 {
    pub id: String,
    pub display_name: String,
    pub size_bytes: u64,
}

/// Download progress, polled by the UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DownloadProgressV1 {
    /// `idle`, `checking`, `downloading_runtime`, `downloading_model`, `verifying`, `done`,
    /// `failed`, or `cancelled`.
    pub phase: String,
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub percent: u8,
    pub detail: String,
    /// The catalog model this download is for.
    pub model_id: Option<String>,
}

impl Default for DownloadProgressV1 {
    fn default() -> Self {
        Self {
            phase: "idle".to_owned(),
            bytes_done: 0,
            bytes_total: 0,
            percent: 0,
            detail: String::new(),
            model_id: None,
        }
    }
}

impl DownloadProgressV1 {
    /// True while a download or its check is under way.
    #[must_use]
    pub fn running(&self) -> bool {
        matches!(
            self.phase.as_str(),
            "checking" | "downloading_runtime" | "downloading_model" | "verifying"
        )
    }
}

/// One card in the model switcher.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent facts shown together on one card"
)]
pub struct ModelOptionV1 {
    pub id: String,
    pub display_name: String,
    pub summary: String,
    pub size_bytes: u64,
    pub recommended_memory_mib: u64,
    /// Downloaded and verified.
    pub installed: bool,
    /// Used for new work now.
    pub selected: bool,
    /// Used once the current request finishes.
    pub queued: bool,
    /// This Mac has the memory the model is recommended for.
    pub fits: bool,
    /// Picked by default for this Mac.
    pub recommended: bool,
}

/// Everything onboarding needs to know.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SetupStatusV1 {
    pub schema_version: u32,
    pub machine: MachineV1,
    pub developer_tools: DeveloperToolsV1,
    /// The model in use, or the one setup will download.
    pub model: Option<ModelChoiceV1>,
    /// Every catalog model, for the switcher in Settings.
    pub models: Vec<ModelOptionV1>,
    pub runtime_ready: bool,
    pub model_ready: bool,
    pub download: DownloadProgressV1,
    /// Sovereign can take requests: machine, tools, runtime, and model are all ready.
    pub ready: bool,
}

fn hash_file(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|error| error.to_string())?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1 << 20];
    loop {
        let read = file.read(&mut buffer).map_err(|error| error.to_string())?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// A marker beside a verified file, so a 2.5 GB model is hashed once, not at every check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifiedMarkerV1 {
    sha256: String,
    size_bytes: u64,
    modified_ns: u128,
}

fn file_identity(path: &Path) -> Option<(u64, u128)> {
    let metadata = fs::metadata(path).ok()?;
    if !metadata.is_file() {
        return None;
    }
    let modified = metadata
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_nanos();
    Some((metadata.len(), modified))
}

fn marker_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(VERIFIED_SUFFIX);
    path.with_file_name(name)
}

fn verified_by_marker(path: &Path, sha256: &str) -> bool {
    let Some((size_bytes, modified_ns)) = file_identity(path) else {
        return false;
    };
    fs::read_to_string(marker_path(path))
        .ok()
        .and_then(|text| serde_json::from_str::<VerifiedMarkerV1>(&text).ok())
        .is_some_and(|marker| {
            marker.sha256 == sha256
                && marker.size_bytes == size_bytes
                && marker.modified_ns == modified_ns
        })
}

fn write_marker(path: &Path, sha256: &str) {
    if let Some((size_bytes, modified_ns)) = file_identity(path)
        && let Ok(text) = serde_json::to_string(&VerifiedMarkerV1 {
            sha256: sha256.to_owned(),
            size_bytes,
            modified_ns,
        })
    {
        let _ = fs::write(marker_path(path), text);
    }
}

/// Verifies `path` against its pin. With `remember`, a marker beside the file vouches for it
/// until the file changes; only Sovereign's own downloads get markers.
fn verify_pinned(path: &Path, sha256: &str, remember: bool) -> bool {
    if remember && verified_by_marker(path, sha256) {
        return true;
    }
    if hash_file(path).is_ok_and(|digest| digest == sha256) {
        if remember {
            write_marker(path, sha256);
        }
        return true;
    }
    false
}

/// How one pinned fetch ended.
#[derive(Debug, Clone, PartialEq, Eq)]
enum FetchOutcome {
    Done,
    Cancelled,
}

struct FetchRequest<'a> {
    url: &'a str,
    destination: &'a Path,
    sha256: &'a str,
    size_bytes: u64,
    /// `=https` in production. Tests allow `file`.
    protocols: &'a str,
}

fn partial_path(destination: &Path) -> PathBuf {
    let mut name = destination.file_name().unwrap_or_default().to_os_string();
    name.push(".partial");
    destination.with_file_name(name)
}

fn spawn_curl(request: &FetchRequest<'_>, partial: &Path) -> Result<Child, String> {
    Command::new(CURL)
        .args([
            "--fail",
            "--location",
            "--silent",
            "--show-error",
            "--proto",
            request.protocols,
            "--proto-redir",
            request.protocols,
            "--max-redirs",
            "10",
            "--connect-timeout",
            "30",
            "--speed-limit",
            "1024",
            "--speed-time",
            "60",
            "--continue-at",
            "-",
            "--output",
        ])
        .arg(partial)
        .arg(request.url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("could not start the download: {error}"))
}

/// Downloads one pinned file into place, resuming a partial file, reporting bytes through
/// `on_progress`, and moving it into place only when size and SHA-256 match.
fn fetch_pinned(
    request: &FetchRequest<'_>,
    cancel: &AtomicBool,
    on_progress: &dyn Fn(u64),
) -> Result<FetchOutcome, String> {
    if let Some(parent) = request.destination.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let partial = partial_path(request.destination);
    let mut last_error = String::new();
    for _ in 0..DOWNLOAD_ATTEMPTS {
        let already = fs::metadata(&partial).map_or(0, |metadata| metadata.len());
        if already > request.size_bytes {
            let _ = fs::remove_file(&partial);
        }
        if already != request.size_bytes {
            let mut child = spawn_curl(request, &partial)?;
            let status = loop {
                if cancel.load(Ordering::Relaxed) {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Ok(FetchOutcome::Cancelled);
                }
                on_progress(fs::metadata(&partial).map_or(0, |metadata| metadata.len()));
                match child.try_wait() {
                    Ok(Some(status)) => break status,
                    Ok(None) => std::thread::sleep(POLL_INTERVAL),
                    Err(error) => return Err(format!("the download stopped: {error}")),
                }
            };
            if !status.success() {
                let mut stderr = String::new();
                if let Some(mut pipe) = child.stderr.take() {
                    let _ = pipe.read_to_string(&mut stderr);
                }
                stderr.trim().clone_into(&mut last_error);
                // A server that cannot resume: start this file over.
                if status.code() == Some(33) {
                    let _ = fs::remove_file(&partial);
                }
                continue;
            }
        }
        on_progress(fs::metadata(&partial).map_or(0, |metadata| metadata.len()));
        let size = fs::metadata(&partial).map_or(0, |metadata| metadata.len());
        if size != request.size_bytes {
            last_error = format!(
                "the download ended at {size} of {} bytes",
                request.size_bytes
            );
            continue;
        }
        let digest = hash_file(&partial)?;
        if digest != request.sha256 {
            let _ = fs::remove_file(&partial);
            return Err(
                "the downloaded file did not match its published checksum, so it was deleted"
                    .to_owned(),
            );
        }
        fs::rename(&partial, request.destination).map_err(|error| error.to_string())?;
        write_marker(request.destination, request.sha256);
        return Ok(FetchOutcome::Done);
    }
    Err(if last_error.is_empty() {
        "the download did not finish".to_owned()
    } else {
        format!("the download did not finish: {last_error}")
    })
}

/// Finds the pinned executable inside an extracted runtime archive.
fn find_executable(root: &Path, name: &str, sha256: &str, depth: u32) -> Option<PathBuf> {
    let entries = fs::read_dir(root).ok()?;
    let mut directories = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_file()
            && path.file_name().and_then(|value| value.to_str()) == Some(name)
            && hash_file(&path).is_ok_and(|digest| digest == sha256)
        {
            return Some(path);
        }
        if file_type.is_dir() {
            directories.push(path);
        }
    }
    if depth == 0 {
        return None;
    }
    directories
        .iter()
        .find_map(|directory| find_executable(directory, name, sha256, depth - 1))
}

/// Where downloaded files live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupPaths {
    pub app_data: PathBuf,
}

impl SetupPaths {
    fn runtime_dir(&self, runtime: &RuntimeEntryV2) -> PathBuf {
        self.app_data.join("runtime").join(&runtime.id)
    }

    fn model_path(&self, model: &ModelEntryV2) -> PathBuf {
        self.app_data.join("models").join(&model.file_name)
    }

    fn downloads_dir(&self) -> PathBuf {
        self.app_data.join("downloads")
    }
}

/// A runtime shipped next to the installed `sovereign` binary (`../libexec/llama/`).
fn bundled_runtime(runtime: &RuntimeEntryV2) -> Option<PathBuf> {
    let executable = std::env::current_exe().ok()?.canonicalize().ok()?;
    let candidate = executable
        .parent()?
        .parent()?
        .join("libexec")
        .join("llama")
        .join(&runtime.executable_name);
    verify_pinned(&candidate, &runtime.executable_sha256, false).then_some(candidate)
}

/// The runtime to use: the configured one if it matches the pin, else a bundled or earlier
/// downloaded copy.
fn ready_runtime(
    paths: &SetupPaths,
    runtime: &RuntimeEntryV2,
    configured: Option<&Path>,
) -> Option<PathBuf> {
    if let Some(path) = configured
        && verify_pinned(path, &runtime.executable_sha256, false)
    {
        return Some(path.to_path_buf());
    }
    bundled_runtime(runtime).or_else(|| {
        find_executable(
            &paths.runtime_dir(runtime),
            &runtime.executable_name,
            &runtime.executable_sha256,
            3,
        )
    })
}

fn ready_model(
    paths: &SetupPaths,
    model: &ModelEntryV2,
    configured: Option<&Path>,
) -> Option<PathBuf> {
    if let Some(path) = configured
        && path.is_file()
    {
        // A model chosen in Advanced settings is the person's call.
        return Some(path.to_path_buf());
    }
    let path = paths.model_path(model);
    verify_pinned(&path, &model.sha256, true).then_some(path)
}

/// A catalog model's downloaded file, when it is in place and verified.
#[must_use]
pub fn installed_model_path(paths: &SetupPaths, model_id: &str) -> Option<(PathBuf, String)> {
    let catalog = load_catalog().ok()?;
    let model = catalog.models.iter().find(|model| model.id == model_id)?;
    let path = paths.model_path(model);
    verify_pinned(&path, &model.sha256, true).then(|| (path, model.model_name.clone()))
}

/// Deletes a downloaded catalog model, its verification marker, and any partial download.
///
/// # Errors
/// Returns a plain reason for an unknown model or a file that cannot be removed.
pub fn remove_model(paths: &SetupPaths, model_id: &str) -> Result<(), String> {
    let catalog = load_catalog()?;
    let model = catalog
        .models
        .iter()
        .find(|model| model.id == model_id)
        .ok_or_else(|| format!("Sovereign doesn't know a model called {model_id}."))?;
    let path = paths.model_path(model);
    for file in [marker_path(&path), partial_path(&path), path] {
        match fs::remove_file(&file) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("Could not remove {}: {error}", file.display())),
        }
    }
    Ok(())
}

/// What a finished setup run configures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledModel {
    pub runtime: PathBuf,
    pub model: PathBuf,
    pub model_name: String,
}

/// Runs onboarding's model setup in the background and reports progress.
pub struct ModelSetup {
    progress: Mutex<DownloadProgressV1>,
    cancel: AtomicBool,
    /// Set while a setup thread runs, so two starts never race.
    busy: AtomicBool,
}

impl Default for ModelSetup {
    fn default() -> Self {
        Self {
            progress: Mutex::new(DownloadProgressV1::default()),
            cancel: AtomicBool::new(false),
            busy: AtomicBool::new(false),
        }
    }
}

impl ModelSetup {
    #[must_use]
    pub fn progress(&self) -> DownloadProgressV1 {
        self.progress
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn set(&self, update: impl FnOnce(&mut DownloadProgressV1)) {
        update(&mut self.progress.lock().unwrap_or_else(PoisonError::into_inner));
    }

    /// Stops a running download. The partial file is kept so the next start resumes it.
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    /// The full onboarding picture for this machine.
    #[must_use]
    pub fn status(
        &self,
        paths: &SetupPaths,
        configured_runtime: Option<&Path>,
        configured_model: Option<&Path>,
        queued_model_id: Option<&str>,
    ) -> SetupStatusV1 {
        let catalog = load_catalog().ok();
        let memory_mib = probe_memory_mib();
        let memory = memory_mib.unwrap_or(MIN_MEMORY_MIB);
        let recommended = catalog
            .as_ref()
            .and_then(|catalog| pick_model(catalog, memory));
        let selected = catalog
            .as_ref()
            .zip(configured_model)
            .and_then(|(catalog, path)| entry_for_path(catalog, path));
        let chosen = selected.or(recommended);
        let models = catalog.as_ref().map_or_else(Vec::new, |catalog| {
            catalog
                .models
                .iter()
                .map(|model| ModelOptionV1 {
                    id: model.id.clone(),
                    display_name: model.display_name.clone(),
                    summary: model.summary.clone(),
                    size_bytes: model.size_bytes,
                    recommended_memory_mib: model.recommended_memory_mib,
                    installed: verify_pinned(&paths.model_path(model), &model.sha256, true),
                    selected: selected.is_some_and(|entry| entry.id == model.id),
                    queued: queued_model_id == Some(model.id.as_str()),
                    fits: model.recommended_memory_mib <= memory,
                    recommended: recommended.is_some_and(|entry| entry.id == model.id),
                })
                .collect()
        });
        let runtime_ready = catalog.as_ref().is_some_and(|catalog| {
            ready_runtime(paths, &catalog.runtime, configured_runtime).is_some()
        });
        let model_ready =
            chosen.is_some_and(|model| ready_model(paths, model, configured_model).is_some());
        let still_needed = if model_ready {
            0
        } else {
            chosen.map_or(0, |model| {
                let partial = fs::metadata(partial_path(&paths.model_path(model)))
                    .map_or(0, |metadata| metadata.len());
                model.size_bytes.saturating_sub(partial)
            })
        };
        let machine = evaluate_machine(
            probe_apple_silicon(),
            memory_mib,
            probe_free_disk_mib(&paths.app_data),
            still_needed,
        );
        let developer_tools = probe_developer_tools();
        let ready = machine.supported && developer_tools.installed && runtime_ready && model_ready;
        SetupStatusV1 {
            schema_version: SETUP_STATUS_SCHEMA_VERSION,
            model: chosen.map(|model| ModelChoiceV1 {
                id: model.id.clone(),
                display_name: model.display_name.clone(),
                size_bytes: model.size_bytes,
            }),
            models,
            machine,
            developer_tools,
            runtime_ready,
            model_ready,
            download: self.progress(),
            ready,
        }
    }

    /// Starts the download in the background unless one is running. `on_installed` runs once
    /// the runtime and model are in place, to save them in settings.
    ///
    /// # Errors
    /// Returns a plain-language reason when this machine cannot run Sovereign.
    pub fn start(
        self: &Arc<Self>,
        paths: SetupPaths,
        configured_runtime: Option<PathBuf>,
        model_id: Option<&str>,
        on_installed: impl FnOnce(&InstalledModel) + Send + 'static,
    ) -> Result<DownloadProgressV1, String> {
        let catalog = load_catalog()?;
        let memory_mib = probe_memory_mib();
        let model = match model_id {
            Some(id) => catalog
                .models
                .iter()
                .find(|model| model.id == id)
                .cloned()
                .ok_or_else(|| format!("Sovereign doesn't know a model called {id}."))?,
            None => pick_model(&catalog, memory_mib.unwrap_or(MIN_MEMORY_MIB))
                .cloned()
                .ok_or_else(|| "Sovereign needs at least 8 GB of memory.".to_owned())?,
        };
        if self.busy.load(Ordering::Acquire) {
            let current = self.progress();
            return if current.model_id.as_deref() == Some(model.id.as_str()) {
                Ok(current)
            } else {
                Err(
                    "Another download is running. Wait for it to finish, then try again."
                        .to_owned(),
                )
            };
        }
        let partial = fs::metadata(partial_path(&paths.model_path(&model)))
            .map_or(0, |metadata| metadata.len());
        let machine = evaluate_machine(
            probe_apple_silicon(),
            memory_mib,
            probe_free_disk_mib(&paths.app_data),
            model.size_bytes.saturating_sub(partial),
        );
        if let Some(problem) = machine.problems.first() {
            return Err(problem.clone());
        }
        if self
            .busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(self.progress());
        }
        self.cancel.store(false, Ordering::Relaxed);
        self.set(|progress| {
            *progress = DownloadProgressV1 {
                phase: "checking".to_owned(),
                detail: "Checking what is already downloaded.".to_owned(),
                model_id: Some(model.id.clone()),
                ..DownloadProgressV1::default()
            };
        });
        let setup = Arc::clone(self);
        std::thread::Builder::new()
            .name("sovereign-model-setup".to_owned())
            .spawn(move || {
                let result = setup.run(
                    &paths,
                    &catalog.runtime,
                    &model,
                    configured_runtime.as_deref(),
                    "=https",
                );
                match result {
                    Ok(Some(installed)) => {
                        on_installed(&installed);
                        setup.set(|progress| {
                            "done".clone_into(&mut progress.phase);
                            progress.percent = 100;
                            "The local model is ready.".clone_into(&mut progress.detail);
                        });
                    }
                    Ok(None) => setup.set(|progress| {
                        "cancelled".clone_into(&mut progress.phase);
                        "Download paused. Start it again to continue where it stopped.".clone_into(&mut progress.detail);
                    }),
                    Err(error) => setup.set(|progress| {
                        "failed".clone_into(&mut progress.phase);
                        progress.detail = format!(
                            "Sovereign couldn't finish the download ({error}). Check your internet connection and try again. It continues where it stopped."
                        );
                    }),
                }
                setup.busy.store(false, Ordering::Release);
            })
            .map_err(|error| {
                self.busy.store(false, Ordering::Release);
                format!("could not start the download: {error}")
            })?;
        Ok(self.progress())
    }

    /// Fetches whatever is missing. `Ok(None)` means cancelled.
    fn run(
        &self,
        paths: &SetupPaths,
        runtime: &RuntimeEntryV2,
        model: &ModelEntryV2,
        configured_runtime: Option<&Path>,
        protocols: &str,
    ) -> Result<Option<InstalledModel>, String> {
        let runtime_path = match ready_runtime(paths, runtime, configured_runtime) {
            Some(path) => path,
            None => match self.install_runtime(paths, runtime, protocols)? {
                Some(path) => path,
                None => return Ok(None),
            },
        };
        let model_path = paths.model_path(model);
        if !verify_pinned(&model_path, &model.sha256, true) {
            let total = model.size_bytes;
            self.set(|progress| {
                "downloading_model".clone_into(&mut progress.phase);
                progress.bytes_total = total;
                progress.detail = format!(
                    "Downloading {} ({} GB).",
                    model.display_name,
                    total.div_ceil(1 << 30)
                );
            });
            let outcome = fetch_pinned(
                &FetchRequest {
                    url: &model.url,
                    destination: &model_path,
                    sha256: &model.sha256,
                    size_bytes: total,
                    protocols,
                },
                &self.cancel,
                &|done| {
                    self.set(|progress| {
                        progress.bytes_done = done;
                        progress.percent = percent(done, total);
                        if done >= total {
                            "verifying".clone_into(&mut progress.phase);
                            "Checking the download.".clone_into(&mut progress.detail);
                        }
                    });
                },
            )?;
            if outcome == FetchOutcome::Cancelled {
                return Ok(None);
            }
        }
        Ok(Some(InstalledModel {
            runtime: runtime_path,
            model: model_path,
            model_name: model.model_name.clone(),
        }))
    }

    fn install_runtime(
        &self,
        paths: &SetupPaths,
        runtime: &RuntimeEntryV2,
        protocols: &str,
    ) -> Result<Option<PathBuf>, String> {
        let archive = paths.downloads_dir().join(format!("{}.tar.gz", runtime.id));
        let total = runtime.archive_size_bytes;
        self.set(|progress| {
            "downloading_runtime".clone_into(&mut progress.phase);
            progress.bytes_done = 0;
            progress.bytes_total = total;
            progress.percent = 0;
            "Downloading the model runner.".clone_into(&mut progress.detail);
        });
        if !verify_pinned(&archive, &runtime.archive_sha256, true) {
            let outcome = fetch_pinned(
                &FetchRequest {
                    url: &runtime.archive_url,
                    destination: &archive,
                    sha256: &runtime.archive_sha256,
                    size_bytes: total,
                    protocols,
                },
                &self.cancel,
                &|done| {
                    self.set(|progress| {
                        progress.bytes_done = done;
                        progress.percent = percent(done, total);
                    });
                },
            )?;
            if outcome == FetchOutcome::Cancelled {
                return Ok(None);
            }
        }
        let destination = paths.runtime_dir(runtime);
        let staging = destination.with_file_name(format!("{}.staging", runtime.id));
        let _ = fs::remove_dir_all(&staging);
        fs::create_dir_all(&staging).map_err(|error| error.to_string())?;
        let extracted = Command::new(TAR)
            .arg("-xzf")
            .arg(&archive)
            .arg("-C")
            .arg(&staging)
            .stdin(Stdio::null())
            .output()
            .map_err(|error| format!("could not unpack the model runner: {error}"))?;
        if !extracted.status.success() {
            let _ = fs::remove_dir_all(&staging);
            return Err("could not unpack the model runner".to_owned());
        }
        if find_executable(
            &staging,
            &runtime.executable_name,
            &runtime.executable_sha256,
            3,
        )
        .is_none()
        {
            let _ = fs::remove_dir_all(&staging);
            return Err("the model runner did not match its published checksum".to_owned());
        }
        let _ = fs::remove_dir_all(&destination);
        fs::rename(&staging, &destination).map_err(|error| error.to_string())?;
        find_executable(
            &destination,
            &runtime.executable_name,
            &runtime.executable_sha256,
            3,
        )
        .map(Some)
        .ok_or_else(|| "the model runner could not be found after unpacking".to_owned())
    }
}

fn percent(done: u64, total: u64) -> u8 {
    if total == 0 {
        return 0;
    }
    u8::try_from((done.min(total).saturating_mul(100)) / total).unwrap_or(100)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    static SEQUENCE: AtomicU64 = AtomicU64::new(1);

    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sovereign-model-setup-{label}-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap_or_else(|error| panic!("{error}"));
        dir
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    fn file_url(path: &Path) -> String {
        format!("file://{}", path.display())
    }

    #[test]
    fn committed_catalog_is_fully_pinned() {
        let catalog = load_catalog().unwrap_or_else(|error| panic!("{error}"));
        // 8 GB Macs start with the smaller model; the stronger one stays available.
        let small = pick_model(&catalog, 8 * 1_024).unwrap_or_else(|| panic!("an 8 GB pick"));
        assert_eq!(small.model_name, "Qwen3-1.7B-Q8_0");
        assert_eq!(small.size_bytes, 1_834_426_016);
        assert_eq!(
            small.sha256,
            "061b54daade076b5d3362dac252678d17da8c68f07560be70818cace6590cb1a"
        );
        assert!(
            small
                .url
                .contains("90862c4b9d2787eaed51d12237eafdfe7c5f6077")
        );
        let large = pick_model(&catalog, 16 * 1_024).unwrap_or_else(|| panic!("a 16 GB pick"));
        assert_eq!(large.model_name, "Qwen3-4B-Q4_K_M");
        assert_eq!(large.size_bytes, 2_497_280_256);
        assert!(
            large
                .url
                .contains("bc640142c66e1fdd12af0bd68f40445458f3869b")
        );
        assert!(
            catalog
                .models
                .iter()
                .all(|model| model.min_memory_mib <= 8 * 1_024)
        );
        assert!(pick_model(&catalog, 4 * 1_024).is_none());
    }

    fn two_model_catalog() -> ModelCatalogV2 {
        let mut catalog: serde_json::Value =
            serde_json::from_str(CATALOG_JSON).unwrap_or_else(|error| panic!("{error}"));
        // The committed 4B model plus a made-up smaller one.
        let large = catalog["models"]
            .as_array()
            .and_then(|models| models.iter().find(|model| model["id"] == "qwen3-4b-q4_k_m"))
            .cloned()
            .unwrap_or_else(|| panic!("the 4B entry"));
        catalog["models"] = serde_json::json!([large.clone()]);
        let mut small = large;
        small["id"] = serde_json::json!("small");
        small["file_name"] = serde_json::json!("small.gguf");
        small["size_bytes"] = serde_json::json!(1_000_000_000_u64);
        small["recommended_memory_mib"] = serde_json::json!(8_192);
        small["starting_estimate_mib"] = serde_json::json!(3_072);
        catalog["models"]
            .as_array_mut()
            .unwrap_or_else(|| panic!("models"))
            .push(small);
        parse_catalog(&catalog.to_string()).unwrap_or_else(|error| panic!("{error}"))
    }

    #[test]
    fn eight_gb_macs_get_the_smaller_model_and_larger_macs_the_best_fit() {
        let catalog = two_model_catalog();
        let pick = |memory| pick_model(&catalog, memory).map(|model| model.id.as_str());
        assert_eq!(pick(8 * 1_024), Some("small"));
        assert_eq!(pick(16 * 1_024), Some("qwen3-4b-q4_k_m"));
        assert_eq!(pick(24 * 1_024), Some("qwen3-4b-q4_k_m"));
        assert_eq!(pick(4 * 1_024), None);
        assert_eq!(
            entry_for_path(&catalog, Path::new("/x/models/small.gguf"))
                .map(|model| model.id.as_str()),
            Some("small")
        );
        assert!(entry_for_path(&catalog, Path::new("/x/models/own.gguf")).is_none());
    }

    #[test]
    fn one_download_at_a_time_and_asking_again_reports_it() {
        let setup = Arc::new(ModelSetup::default());
        setup.busy.store(true, Ordering::Release);
        setup.set(|progress| {
            "downloading_model".clone_into(&mut progress.phase);
            progress.model_id = Some("qwen3-4b-q4_k_m".to_owned());
        });
        let paths = SetupPaths {
            app_data: temp_dir("one-download"),
        };
        let same = setup.start(paths.clone(), None, Some("qwen3-4b-q4_k_m"), |_| {});
        assert_eq!(
            same.map(|progress| progress.phase),
            Ok("downloading_model".to_owned())
        );
        setup.set(|progress| progress.model_id = Some("another-model".to_owned()));
        let other = setup.start(paths.clone(), None, Some("qwen3-4b-q4_k_m"), |_| {});
        assert!(other.is_err_and(|reason| reason.starts_with("Another download is running")));
        assert!(
            setup
                .start(paths.clone(), None, Some("no-such-model"), |_| {})
                .is_err()
        );
        let _ = fs::remove_dir_all(paths.app_data);
    }

    #[test]
    fn a_repeated_model_id_fails_closed() {
        let mut catalog: serde_json::Value =
            serde_json::from_str(CATALOG_JSON).unwrap_or_else(|error| panic!("{error}"));
        let copy = catalog["models"][0].clone();
        catalog["models"]
            .as_array_mut()
            .unwrap_or_else(|| panic!("models"))
            .push(copy);
        assert!(parse_catalog(&catalog.to_string()).is_err());
    }

    #[test]
    fn removing_a_model_deletes_it_and_its_leftovers() {
        let dir = temp_dir("remove");
        let paths = SetupPaths {
            app_data: dir.clone(),
        };
        let catalog = load_catalog().unwrap_or_else(|error| panic!("{error}"));
        let model = &catalog.models[0];
        let path = paths.model_path(model);
        fs::create_dir_all(path.parent().unwrap_or(&dir)).unwrap_or_else(|error| panic!("{error}"));
        for file in [path.clone(), partial_path(&path), marker_path(&path)] {
            fs::write(&file, b"x").unwrap_or_else(|error| panic!("{error}"));
        }
        remove_model(&paths, &model.id).unwrap_or_else(|error| panic!("{error}"));
        assert!(!path.exists() && !partial_path(&path).exists() && !marker_path(&path).exists());
        // Removing again is fine; an unknown model is not.
        assert!(remove_model(&paths, &model.id).is_ok());
        assert!(remove_model(&paths, "no-such-model").is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn unpinned_entries_fail_closed() {
        let mut catalog: serde_json::Value =
            serde_json::from_str(CATALOG_JSON).unwrap_or_else(|error| panic!("{error}"));
        catalog["models"][0]["sha256"] = serde_json::json!("");
        assert!(parse_catalog(&catalog.to_string()).is_err());
        let mut catalog: serde_json::Value =
            serde_json::from_str(CATALOG_JSON).unwrap_or_else(|error| panic!("{error}"));
        catalog["models"][0]["url"] = serde_json::json!("http://example.invalid/model.gguf");
        assert!(parse_catalog(&catalog.to_string()).is_err());
        let mut catalog: serde_json::Value =
            serde_json::from_str(CATALOG_JSON).unwrap_or_else(|error| panic!("{error}"));
        catalog["models"][0]["recommended_memory_mib"] = serde_json::json!(1_024);
        assert!(parse_catalog(&catalog.to_string()).is_err());
    }

    #[test]
    fn machine_problems_say_what_to_do() {
        let fine = evaluate_machine(true, Some(16 * 1_024), Some(200 * 1_024), 2_497_280_256);
        assert!(fine.supported && fine.problems.is_empty());
        let intel = evaluate_machine(false, Some(16 * 1_024), Some(200 * 1_024), 0);
        assert!(!intel.supported);
        assert!(intel.problems[0].contains("Apple silicon"));
        let small = evaluate_machine(true, Some(4 * 1_024), Some(200 * 1_024), 0);
        assert!(!small.supported);
        let full = evaluate_machine(true, Some(8 * 1_024), Some(10 * 1_024), 2_497_280_256);
        assert!(full.supported, "a full disk is fixable, not unsupported");
        assert!(full.problems[0].starts_with("Free up"));
    }

    #[test]
    fn fetch_resumes_a_partial_file_and_verifies_it() {
        let dir = temp_dir("resume");
        let source = dir.join("source.bin");
        let content = (0..200_000_u32)
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        fs::write(&source, &content).unwrap_or_else(|error| panic!("{error}"));
        let destination = dir.join("models/model.gguf");
        fs::create_dir_all(dir.join("models")).unwrap_or_else(|error| panic!("{error}"));
        // Half of the file is already on disk from an earlier, interrupted download.
        fs::write(partial_path(&destination), &content[..content.len() / 2])
            .unwrap_or_else(|error| panic!("{error}"));
        let seen = AtomicU64::new(0);
        let url = file_url(&source);
        let outcome = fetch_pinned(
            &FetchRequest {
                url: &url,
                destination: &destination,
                sha256: &sha256_hex(&content),
                size_bytes: content.len() as u64,
                protocols: "=file",
            },
            &AtomicBool::new(false),
            &|done| {
                seen.fetch_max(done, Ordering::Relaxed);
            },
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(outcome, FetchOutcome::Done);
        assert_eq!(
            fs::read(&destination).ok().as_deref(),
            Some(content.as_slice())
        );
        assert_eq!(seen.load(Ordering::Relaxed), content.len() as u64);
        assert!(!partial_path(&destination).exists());
        assert!(verified_by_marker(&destination, &sha256_hex(&content)));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_file_that_does_not_match_its_pin_is_deleted() {
        let dir = temp_dir("mismatch");
        let source = dir.join("source.bin");
        fs::write(&source, b"not the model").unwrap_or_else(|error| panic!("{error}"));
        let destination = dir.join("model.gguf");
        let url = file_url(&source);
        let Err(error) = fetch_pinned(
            &FetchRequest {
                url: &url,
                destination: &destination,
                sha256: &sha256_hex(b"the real model"),
                size_bytes: 13,
                protocols: "=file",
            },
            &AtomicBool::new(false),
            &|_| {},
        ) else {
            panic!("a wrong digest must fail");
        };
        assert!(error.contains("checksum"), "{error}");
        assert!(!destination.exists());
        assert!(!partial_path(&destination).exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn https_only_refuses_other_protocols() {
        let dir = temp_dir("https-only");
        let source = dir.join("source.bin");
        fs::write(&source, b"data").unwrap_or_else(|error| panic!("{error}"));
        let url = file_url(&source);
        let result = fetch_pinned(
            &FetchRequest {
                url: &url,
                destination: &dir.join("out.bin"),
                sha256: &sha256_hex(b"data"),
                size_bytes: 4,
                protocols: "=https",
            },
            &AtomicBool::new(false),
            &|_| {},
        );
        assert!(result.is_err());
        assert!(!dir.join("out.bin").exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn runtime_archive_is_unpacked_and_its_executable_checked() {
        let dir = temp_dir("runtime");
        let bundle = dir.join("bundle/llama-b1");
        fs::create_dir_all(&bundle).unwrap_or_else(|error| panic!("{error}"));
        fs::write(bundle.join("llama-server"), b"#!/bin/sh\necho runner\n")
            .unwrap_or_else(|error| panic!("{error}"));
        fs::write(bundle.join("libllama.dylib"), b"lib").unwrap_or_else(|error| panic!("{error}"));
        let archive = dir.join("runtime.tar.gz");
        let packed = Command::new(TAR)
            .arg("-czf")
            .arg(&archive)
            .arg("-C")
            .arg(dir.join("bundle"))
            .arg("llama-b1")
            .status()
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(packed.success());
        let archive_bytes = fs::read(&archive).unwrap_or_else(|error| panic!("{error}"));
        let runtime = RuntimeEntryV2 {
            id: "llama-test".to_owned(),
            archive_url: file_url(&archive),
            archive_sha256: sha256_hex(&archive_bytes),
            archive_size_bytes: archive_bytes.len() as u64,
            executable_name: "llama-server".to_owned(),
            executable_sha256: sha256_hex(b"#!/bin/sh\necho runner\n"),
        };
        let paths = SetupPaths {
            app_data: dir.join("app"),
        };
        let setup = ModelSetup::default();
        let installed = setup
            .install_runtime(&paths, &runtime, "=file")
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("not cancelled"));
        assert!(installed.ends_with("llama-b1/llama-server"));
        assert!(installed.with_file_name("libllama.dylib").is_file());
        assert_eq!(ready_runtime(&paths, &runtime, None), Some(installed));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn percent_is_bounded() {
        assert_eq!(percent(0, 0), 0);
        assert_eq!(percent(50, 200), 25);
        assert_eq!(percent(500, 200), 100);
    }
}
