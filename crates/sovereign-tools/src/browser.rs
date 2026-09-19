#![forbid(unsafe_code)]

//! Authority-neutral browser mechanics for one ephemeral Chrome session.
//!
//! This module intentionally owns only browser/process mechanics. Network permission, browser
//! isolation admission, durable action authorization, and retry/reconciliation decisions remain
//! Controller/policy responsibilities. The adapter validates URL shape and local resource bounds,
//! but it never decides whether a destination is allowed.

use crate::process_group_leader_identity;
use sha2::{Digest, Sha256};
use sovereign_policy::IsolatedCommand;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

pub const BROWSER_SCHEMA_VERSION: u32 = 1;

const MAX_CDP_FRAME_BYTES_HARD: usize = 4 * 1024 * 1024;
const MAX_SYNOPSIS_BYTES_HARD: usize = 256 * 1024;
const MAX_DOM_BYTES_HARD: usize = 512 * 1024;
const MAX_DOWNLOAD_BYTES_HARD: u64 = 128 * 1024 * 1024;
const MAX_REQUEST_TIMEOUT_MS: u64 = 60_000;
const MAX_SELECTOR_BYTES: usize = 4 * 1024;
const MAX_CONTENT_TYPE_BYTES: usize = 512;
const MAX_FORM_STRUCTURE_BYTES: usize = 64 * 1024;
const MAX_CALLER_CHROME_ARGS: usize = 128;
const MAX_CALLER_CHROME_ARG_BYTES: usize = 64 * 1024;
const MAX_PROXY_AUTH_FIELD_BYTES: usize = 4 * 1024;
const MAX_TRACKED_DOWNLOADS: usize = 128;
const MAX_DOWNLOAD_GUID_BYTES: usize = 128;
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(10);
const PROCESS_TERM_GRACE: Duration = Duration::from_millis(250);
const PROCESS_KILL_GRACE: Duration = Duration::from_millis(750);
const PROCESS_BROWSER_CLOSE_GRACE: Duration = Duration::from_secs(1);

pub const BROWSER_PROXY_AUTH_REALM: &str = "sovereign-browser-gateway-v1";
pub const BROWSER_PROXY_AUTH_USERNAME: &str = "sovereign-browser";

static BROWSER_NONCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
pub enum BrowserError {
    InvalidRequest(String),
    ResourceLimit(String),
    Protocol(String),
    Process(String),
    TransportUncertain {
        request_id: u64,
        method: String,
        detail: String,
    },
    Io(std::io::Error),
}

impl BrowserError {
    #[must_use]
    pub const fn is_transport_uncertain(&self) -> bool {
        matches!(self, Self::TransportUncertain { .. })
    }
}

impl Display for BrowserError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRequest(message) => write!(f, "invalid browser request: {message}"),
            Self::ResourceLimit(message) => write!(f, "browser resource limit: {message}"),
            Self::Protocol(message) => write!(f, "browser protocol error: {message}"),
            Self::Process(message) => write!(f, "browser process error: {message}"),
            Self::TransportUncertain {
                request_id,
                method,
                detail,
            } => write!(
                f,
                "browser transport became uncertain after dispatch of {method} request {request_id}: {detail}"
            ),
            Self::Io(error) => write!(f, "browser I/O error: {error}"),
        }
    }
}

impl Error for BrowserError {}

impl From<std::io::Error> for BrowserError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

/// Controller-issued opaque lease binding used only to prevent stale browser mechanics from being
/// reused accidentally. Possession of this value is not an authorization decision.
#[derive(Clone, PartialEq, Eq)]
pub struct BrowserLease {
    pub schema_version: u32,
    pub lease_id: String,
    pub task_id: String,
    pub attempt_id: String,
    pub execution_epoch: i64,
    pub token: String,
}

impl std::fmt::Debug for BrowserLease {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrowserLease")
            .field("schema_version", &self.schema_version)
            .field("lease_id", &self.lease_id)
            .field("task_id", &self.task_id)
            .field("attempt_id", &self.attempt_id)
            .field("execution_epoch", &self.execution_epoch)
            .field("token", &"[REDACTED]")
            .finish()
    }
}

impl BrowserLease {
    /// Validates shape only. Controller policy remains responsible for issuing and admitting a
    /// current lease.
    ///
    /// # Errors
    /// Returns an invalid-request error for an unsupported schema, empty identity/token, negative
    /// epoch, or an unreasonably large opaque token.
    pub fn validate_shape(&self) -> Result<(), BrowserError> {
        if self.schema_version != BROWSER_SCHEMA_VERSION {
            return Err(BrowserError::InvalidRequest(
                "unsupported browser lease schema version".to_owned(),
            ));
        }
        if self.lease_id.trim().is_empty()
            || self.task_id.trim().is_empty()
            || self.attempt_id.trim().is_empty()
            || self.token.is_empty()
            || self.execution_epoch < 0
            || self.token.len() > 4 * 1024
        {
            return Err(BrowserError::InvalidRequest(
                "browser lease has incomplete or invalid binding fields".to_owned(),
            ));
        }
        Ok(())
    }

    /// Returns a non-secret digest suitable for receipts. The opaque token itself is never placed
    /// in a receipt.
    #[must_use]
    pub fn binding_digest(&self) -> String {
        let mut hasher = Sha256::new();
        digest_field(&mut hasher, "sovereign.browser_lease.v1");
        digest_field(&mut hasher, &self.lease_id);
        digest_field(&mut hasher, &self.task_id);
        digest_field(&mut hasher, &self.attempt_id);
        hasher.update(self.execution_epoch.to_be_bytes());
        digest_field(&mut hasher, &self.token);
        format!("sha256:{:x}", hasher.finalize())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserAdapterConfig {
    pub max_cdp_frame_bytes: usize,
    pub max_synopsis_bytes: usize,
    pub max_dom_bytes: usize,
    pub max_download_bytes: u64,
    pub request_timeout_ms: u64,
    /// When true, screenshot/trace capture remains suppressed. Screenshot actions return a typed
    /// suppression receipt without dispatching Page.captureScreenshot.
    pub suppress_screenshots_and_traces: bool,
}

impl Default for BrowserAdapterConfig {
    fn default() -> Self {
        Self {
            max_cdp_frame_bytes: 2 * 1024 * 1024,
            max_synopsis_bytes: 64 * 1024,
            max_dom_bytes: 128 * 1024,
            max_download_bytes: 64 * 1024 * 1024,
            request_timeout_ms: 15_000,
            suppress_screenshots_and_traces: true,
        }
    }
}

impl BrowserAdapterConfig {
    /// Validates bounded local mechanics. No permission decision is made here.
    ///
    /// # Errors
    /// Returns a resource-limit error for zero or oversized bounds, or when the CDP frame cap is too
    /// small to carry the configured bounded synopsis/DOM payload.
    pub fn validate(&self) -> Result<(), BrowserError> {
        if self.max_cdp_frame_bytes == 0
            || self.max_cdp_frame_bytes > MAX_CDP_FRAME_BYTES_HARD
            || self.max_synopsis_bytes == 0
            || self.max_synopsis_bytes > MAX_SYNOPSIS_BYTES_HARD
            || self.max_dom_bytes == 0
            || self.max_dom_bytes > MAX_DOM_BYTES_HARD
            || self.max_download_bytes == 0
            || self.max_download_bytes > MAX_DOWNLOAD_BYTES_HARD
            || self.request_timeout_ms == 0
            || self.request_timeout_ms > MAX_REQUEST_TIMEOUT_MS
        {
            return Err(BrowserError::ResourceLimit(
                "browser adapter configuration exceeds static bounds".to_owned(),
            ));
        }
        let synopsis_wire_bound = self
            .max_synopsis_bytes
            .saturating_add(self.max_dom_bytes)
            .saturating_mul(6)
            .saturating_add(64 * 1024);
        if synopsis_wire_bound > MAX_CDP_FRAME_BYTES_HARD
            || self.max_cdp_frame_bytes < synopsis_wire_bound
        {
            return Err(BrowserError::ResourceLimit(
                "CDP frame bound is too small for configured bounded synopsis/DOM capture"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

/// Caller-selected download behavior. This is a mechanics input reflecting an already-made policy
/// decision; the browser adapter does not decide whether downloads are authorized.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum BrowserDownloadPolicy {
    #[default]
    Deny,
    Allow,
}

/// Non-secret exact proxy-auth challenge binding supplied by the Controller. The opaque launch
/// token is retained separately in process memory and is never placed in Chrome argv/environment,
/// receipts, or durable launch options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserProxyAuthBinding {
    pub origin: String,
    pub scheme: String,
    pub realm: String,
    pub username: String,
}

impl BrowserProxyAuthBinding {
    fn validate(&self) -> Result<(), BrowserError> {
        for (label, value) in [
            ("origin", self.origin.as_str()),
            ("scheme", self.scheme.as_str()),
            ("realm", self.realm.as_str()),
            ("username", self.username.as_str()),
        ] {
            if value.trim().is_empty()
                || value.len() > MAX_PROXY_AUTH_FIELD_BYTES
                || value.bytes().any(|byte| byte.is_ascii_control())
            {
                return Err(BrowserError::InvalidRequest(format!(
                    "browser proxy-auth {label} is empty, oversized, or contains control bytes"
                )));
            }
        }
        if self.scheme != "basic" {
            return Err(BrowserError::InvalidRequest(
                "browser proxy-auth mechanics currently require exact lowercase basic scheme"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

/// Profile-root ownership mechanics selected by the caller after any authorization decision.
///
/// `CallerOwnedPersistent` requires an existing stable owner-only directory. The adapter validates
/// and uses the exact supplied root but never decides whether reuse is authorized and never removes
/// that persistent root during shutdown.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum BrowserProfileRoot {
    #[default]
    Ephemeral,
    CallerOwnedPersistent(PathBuf),
}

/// Caller-owned launch inputs that are preserved exactly after browser-local validation.
///
/// `caller_chrome_args` is intended for already-governed flags such as an exact forced proxy,
/// bypass list, or host-resolver rule. The adapter only rejects flags that would replace its own
/// profile/CDP pipe mechanics; it does not interpret them as network authority.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BrowserLaunchOptions {
    pub caller_chrome_args: Vec<String>,
    pub download_policy: BrowserDownloadPolicy,
    /// Exact caller-owned task download root. The adapter never derives this from the browser
    /// profile and never creates or removes it.
    pub download_root: Option<PathBuf>,
    pub profile_root: BrowserProfileRoot,
    pub proxy_auth: Option<BrowserProxyAuthBinding>,
}

/// Exact unisolated process shape prepared by the browser mechanics layer.
///
/// The Controller can convert this shape into its canonical `CommandSpec`, wrap it with Seatbelt or
/// another admitted isolation backend, then pass only the resulting `IsolatedCommand` back to
/// [`BrowserAdapter::spawn_preisolated`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserProcessSpec {
    pub executable: PathBuf,
    pub args: Vec<String>,
    pub environment: BTreeMap<String, String>,
    pub working_directory: PathBuf,
}

/// First phase of browser launch. It owns the exact ephemeral roots until successfully transferred
/// to a spawned [`BrowserAdapter`]. Dropping an unused preparation removes the ephemeral profile.
#[derive(Debug)]
pub struct PreparedBrowserLaunch {
    process_spec: BrowserProcessSpec,
    chrome_path: PathBuf,
    chrome_args: Vec<String>,
    private_parent: PathBuf,
    profile_root: PathBuf,
    download_root: Option<PathBuf>,
    lease: BrowserLease,
    config: BrowserAdapterConfig,
    launch_options: BrowserLaunchOptions,
    request_method_ceiling: Option<BTreeSet<String>>,
    cleanup_armed: bool,
    cleanup_profile_on_drop: bool,
}

impl PreparedBrowserLaunch {
    #[must_use]
    pub fn process_spec(&self) -> &BrowserProcessSpec {
        &self.process_spec
    }

    #[must_use]
    pub fn chrome_path(&self) -> &Path {
        &self.chrome_path
    }

    #[must_use]
    pub fn chrome_args(&self) -> &[String] {
        &self.chrome_args
    }

    #[must_use]
    pub fn profile_root(&self) -> &Path {
        &self.profile_root
    }

    #[must_use]
    pub fn download_root(&self) -> Option<&Path> {
        self.download_root.as_deref()
    }

    #[must_use]
    pub const fn download_policy(&self) -> BrowserDownloadPolicy {
        self.launch_options.download_policy
    }

    #[must_use]
    pub const fn profile_is_persistent(&self) -> bool {
        matches!(
            self.launch_options.profile_root,
            BrowserProfileRoot::CallerOwnedPersistent(_)
        )
    }

    /// Installs the exact caller-owned HTTP method ceiling that browser mechanics must enforce on
    /// every intercepted request before Chrome is allowed to continue it. This is a mechanical
    /// ceiling only; the adapter never derives policy authority from the set.
    ///
    /// # Errors
    /// Returns an invalid-request error for an empty or malformed method set.
    pub fn set_request_method_ceiling(
        &mut self,
        allowed_methods: BTreeSet<String>,
    ) -> Result<(), BrowserError> {
        if allowed_methods.is_empty()
            || allowed_methods
                .iter()
                .any(|method| !valid_http_method_ceiling_entry(method))
        {
            return Err(BrowserError::InvalidRequest(
                "browser request method ceiling must contain only bounded uppercase methods"
                    .to_owned(),
            ));
        }
        self.request_method_ceiling = Some(allowed_methods);
        Ok(())
    }
}

/// Exact process-group identity captured after a browser spawn crossed the OS process boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserSpawnBinding {
    pub process_group_id: u32,
    pub process_group_identity: String,
}

/// Physical browser-process state proven by a failed spawn attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserSpawnState {
    /// The OS process boundary was never crossed.
    NeverSpawned,
    /// A browser process was spawned, then exact process-group absence was proven.
    ProvenAbsent,
    /// Physical absence is unproven. A binding is included when exact identity was captured before
    /// cleanup became ambiguous so Controller recovery can retry exact reaping.
    Unknown {
        binding: Option<BrowserSpawnBinding>,
    },
}

/// Typed failed browser launch preserving whether physical absence is actually proven.
#[derive(Debug)]
pub struct BrowserSpawnFailure {
    error: BrowserError,
    state: BrowserSpawnState,
}

impl BrowserSpawnFailure {
    #[must_use]
    pub fn error(&self) -> &BrowserError {
        &self.error
    }

    #[must_use]
    pub fn state(&self) -> &BrowserSpawnState {
        &self.state
    }

    #[must_use]
    pub fn into_error(self) -> BrowserError {
        self.error
    }

    fn never_spawned(error: BrowserError) -> Self {
        Self {
            error,
            state: BrowserSpawnState::NeverSpawned,
        }
    }

    fn after_spawn(
        error: BrowserError,
        absence_proven: bool,
        binding: Option<BrowserSpawnBinding>,
    ) -> Self {
        let state = if absence_proven {
            BrowserSpawnState::ProvenAbsent
        } else {
            BrowserSpawnState::Unknown { binding }
        };
        Self { error, state }
    }
}

impl Display for BrowserSpawnFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{} ({:?})", self.error, self.state)
    }
}

impl Error for BrowserSpawnFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.error)
    }
}

impl Drop for PreparedBrowserLaunch {
    fn drop(&mut self) {
        if self.cleanup_armed && self.cleanup_profile_on_drop {
            let _ = fs::remove_dir_all(&self.profile_root);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserActionEffect {
    Observation,
    Navigation,
    ConsequentialFormSubmit,
}

impl BrowserActionEffect {
    #[must_use]
    pub const fn is_side_effectful(self) -> bool {
        matches!(self, Self::ConsequentialFormSubmit)
    }

    #[must_use]
    const fn as_str(self) -> &'static str {
        match self {
            Self::Observation => "observation",
            Self::Navigation => "navigation",
            Self::ConsequentialFormSubmit => "consequential_form_submit",
        }
    }
}

/// Typed browser action. `SubmitForm` is intentionally distinct so the Controller can journal it
/// under a no-blind-retry reconciliation policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserAction {
    Navigate {
        action_id: String,
        url: String,
    },
    CaptureSynopsis {
        action_id: String,
    },
    CaptureScreenshot {
        action_id: String,
    },
    SubmitForm {
        action_id: String,
        selector: String,
        payload_digest: String,
    },
}

impl BrowserAction {
    #[must_use]
    pub fn action_id(&self) -> &str {
        match self {
            Self::Navigate { action_id, .. }
            | Self::CaptureSynopsis { action_id }
            | Self::CaptureScreenshot { action_id }
            | Self::SubmitForm { action_id, .. } => action_id,
        }
    }

    #[must_use]
    pub const fn effect(&self) -> BrowserActionEffect {
        match self {
            Self::Navigate { .. } => BrowserActionEffect::Navigation,
            Self::CaptureSynopsis { .. } | Self::CaptureScreenshot { .. } => {
                BrowserActionEffect::Observation
            }
            Self::SubmitForm { .. } => BrowserActionEffect::ConsequentialFormSubmit,
        }
    }

    #[must_use]
    pub const fn kind_name(&self) -> &'static str {
        match self {
            Self::Navigate { .. } => "navigate",
            Self::CaptureSynopsis { .. } => "capture_synopsis",
            Self::CaptureScreenshot { .. } => "capture_screenshot",
            Self::SubmitForm { .. } => "submit_form",
        }
    }

    /// Validates browser-local action shape. In particular, URL validation permits any syntactically
    /// valid absolute HTTP(S) authority and performs no host/network allow-list decision.
    ///
    /// # Errors
    /// Returns an invalid-request/resource-limit error for malformed action ids, URL shape, or CSS
    /// selector size.
    pub fn validate_shape(&self) -> Result<(), BrowserError> {
        if self.action_id().trim().is_empty() {
            return Err(BrowserError::InvalidRequest(
                "browser action requires a non-empty action_id".to_owned(),
            ));
        }
        match self {
            Self::Navigate { url, .. } => validate_http_url_shape(url),
            Self::CaptureSynopsis { .. } | Self::CaptureScreenshot { .. } => Ok(()),
            Self::SubmitForm {
                selector,
                payload_digest,
                ..
            } => {
                if selector.trim().is_empty() {
                    return Err(BrowserError::InvalidRequest(
                        "form submission requires a non-empty selector".to_owned(),
                    ));
                }
                if selector.len() > MAX_SELECTOR_BYTES {
                    return Err(BrowserError::ResourceLimit(
                        "form selector exceeded browser adapter bound".to_owned(),
                    ));
                }
                validate_sha256_digest(payload_digest, "form payload digest")?;
                Ok(())
            }
        }
    }

    #[must_use]
    pub fn digest(&self) -> String {
        let mut hasher = Sha256::new();
        digest_field(&mut hasher, "sovereign.browser_action.v1");
        digest_field(&mut hasher, self.action_id());
        digest_field(&mut hasher, self.kind_name());
        match self {
            Self::Navigate { url, .. } => digest_field(&mut hasher, url),
            Self::CaptureSynopsis { .. } | Self::CaptureScreenshot { .. } => {}
            Self::SubmitForm {
                selector,
                payload_digest,
                ..
            } => {
                digest_field(&mut hasher, selector);
                digest_field(&mut hasher, payload_digest);
            }
        }
        format!("sha256:{:x}", hasher.finalize())
    }
}

/// Position of one paused top-level document request inside the currently dispatched navigation
/// chain. The adapter derives this mechanically from request order; it does not authorize either
/// initial destinations or redirects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserDocumentRequestKind {
    Initial,
    Redirect,
}

/// Typed observation emitted while Chrome has a top-level `Document` request paused in the Fetch
/// domain. The exact URL is intentionally exposed to the Controller so its policy layer can decide
/// whether that request may continue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserDocumentRequestObservation {
    pub schema_version: u32,
    pub interception_id: String,
    pub frame_id: String,
    pub url: String,
    pub method: String,
    pub kind: BrowserDocumentRequestKind,
    pub chain_index: u32,
}

impl BrowserDocumentRequestObservation {
    #[must_use]
    pub fn digest(&self) -> String {
        let mut hasher = Sha256::new();
        digest_field(&mut hasher, "sovereign.browser_document_request.v1");
        digest_field(&mut hasher, &self.interception_id);
        digest_field(&mut hasher, &self.frame_id);
        digest_field(&mut hasher, &self.url);
        digest_field(&mut hasher, &self.method);
        digest_field(
            &mut hasher,
            match self.kind {
                BrowserDocumentRequestKind::Initial => "initial",
                BrowserDocumentRequestKind::Redirect => "redirect",
            },
        );
        hasher.update(self.chain_index.to_be_bytes());
        format!("sha256:{:x}", hasher.finalize())
    }
}

/// Caller-owned continuation decision for one exact paused top-level document request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserDocumentRequestDecision {
    Continue,
    Abort,
}

/// Receipt that identifies an already-dispatched browser action whose completion is intentionally
/// split from top-level document authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserDispatchedAction {
    pub action_id: String,
    pub action_digest: String,
    pub effect: BrowserActionEffect,
    pub cdp_request_id: u64,
}

/// Conservative signal for pages whose retained visual/text evidence must be treated as sensitive.
/// A true signal is suitable for Controller-side screenshot/trace suppression.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BrowserSensitivePageReason {
    FormControl,
    PasswordControl,
    SensitiveAttribute,
    CredentialTextPattern,
    Unclassified,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BrowserSensitivePageSignal {
    pub reasons: BTreeSet<BrowserSensitivePageReason>,
}

impl BrowserSensitivePageSignal {
    #[must_use]
    pub fn is_sensitive(&self) -> bool {
        !self.reasons.is_empty()
    }

    #[must_use]
    pub fn contains(&self, reason: BrowserSensitivePageReason) -> bool {
        self.reasons.contains(&reason)
    }
}

/// Read-only form inspection bound to one exact selector/payload digest without retaining field
/// values. URL query/fragment components are omitted from retained strings; exact URL digests bind
/// the original values without disclosing them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserFormInspectionReceipt {
    pub schema_version: u32,
    pub selector_digest: String,
    pub payload_digest: String,
    pub current_page_url: String,
    pub current_page_url_digest: String,
    pub normalized_method: String,
    pub resolved_action_url: String,
    pub resolved_action_url_digest: String,
    pub structural_digest: String,
    pub sensitive_inputs_present: bool,
}

impl BrowserFormInspectionReceipt {
    #[must_use]
    pub fn binding_digest(&self) -> String {
        let mut hasher = Sha256::new();
        digest_field(&mut hasher, "sovereign.browser_form_inspection.v1");
        digest_field(&mut hasher, &self.selector_digest);
        digest_field(&mut hasher, &self.payload_digest);
        digest_field(&mut hasher, &self.current_page_url_digest);
        digest_field(&mut hasher, &self.normalized_method);
        digest_field(&mut hasher, &self.resolved_action_url_digest);
        digest_field(&mut hasher, &self.structural_digest);
        hasher.update([u8::from(self.sensitive_inputs_present)]);
        format!("sha256:{:x}", hasher.finalize())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserStateSynopsis {
    pub url: String,
    pub title: String,
    pub text: String,
    pub dom_excerpt: String,
    pub retained_text_bytes: usize,
    pub retained_dom_bytes: usize,
    pub text_truncated: bool,
    pub dom_truncated: bool,
    pub retained_dom_sha256: String,
    pub sensitive_page: BrowserSensitivePageSignal,
}

impl BrowserStateSynopsis {
    #[must_use]
    pub fn requires_visual_capture_suppression(&self) -> bool {
        self.sensitive_page.is_sensitive()
    }
}

/// One bounded PNG screenshot captured from the current single page target. The PNG remains base64
/// encoded exactly as returned by CDP so the adapter needs no secondary codec dependency. The
/// enclosing action receipt/CAS digest provides the durable content binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserScreenshot {
    pub content_type: String,
    pub encoding: String,
    pub png_base64: String,
    pub png_bytes: usize,
    pub retained_base64_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserVersion {
    pub product: String,
    pub protocol_version: String,
    pub user_agent: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserActionReceipt {
    pub schema_version: u32,
    pub action_id: String,
    pub action_digest: String,
    pub action_kind: String,
    pub effect: BrowserActionEffect,
    pub lease_id: String,
    pub lease_binding_digest: String,
    pub execution_epoch: i64,
    pub cdp_request_id: u64,
    pub requested_url: Option<String>,
    /// Mechanical `Page.navigate.isDownload` result for a dispatched Navigate action. This is not
    /// a retention decision and carries no filename/content-type authority.
    pub navigation_was_download: bool,
    /// Controller-populated metadata for an exact retained download. Browser mechanics always
    /// produce `None`; only the Controller may attach a receipt after its retention policy and
    /// durable accounting succeed.
    pub download: Option<DownloadReceipt>,
    pub synopsis: Option<BrowserStateSynopsis>,
    pub screenshot: Option<BrowserScreenshot>,
    pub screenshots_and_traces_suppressed: bool,
}

impl BrowserActionReceipt {
    /// Stable receipt encoding for Controller journaling/CAS publication.
    ///
    /// # Errors
    /// Returns a protocol error if JSON serialization fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, BrowserError> {
        let synopsis = self.synopsis.as_ref().map(|synopsis| {
            serde_json::json!({
                "url": synopsis.url,
                "title": synopsis.title,
                "text": synopsis.text,
                "dom_excerpt": synopsis.dom_excerpt,
                "retained_text_bytes": synopsis.retained_text_bytes,
                "retained_dom_bytes": synopsis.retained_dom_bytes,
                "text_truncated": synopsis.text_truncated,
                "dom_truncated": synopsis.dom_truncated,
                "retained_dom_sha256": synopsis.retained_dom_sha256,
                "sensitive_page": {
                    "sensitive": synopsis.sensitive_page.is_sensitive(),
                    "reasons": synopsis.sensitive_page.reasons.iter().map(|reason| match reason {
                        BrowserSensitivePageReason::FormControl => "form_control",
                        BrowserSensitivePageReason::PasswordControl => "password_control",
                        BrowserSensitivePageReason::SensitiveAttribute => "sensitive_attribute",
                        BrowserSensitivePageReason::CredentialTextPattern => "credential_text_pattern",
                        BrowserSensitivePageReason::Unclassified => "unclassified",
                    }).collect::<Vec<_>>(),
                },
            })
        });
        let screenshot = self.screenshot.as_ref().map(|screenshot| {
            serde_json::json!({
                "content_type": screenshot.content_type,
                "encoding": screenshot.encoding,
                "png_base64": screenshot.png_base64,
                "png_bytes": screenshot.png_bytes,
                "retained_base64_bytes": screenshot.retained_base64_bytes,
            })
        });
        let download = self.download.as_ref().map(|download| {
            serde_json::json!({
                "schema_version": download.schema_version,
                "lease_id": download.lease_id,
                "lease_binding_digest": download.lease_binding_digest,
                "execution_epoch": download.execution_epoch,
                "relative_path": download.relative_path.to_string_lossy(),
                "bytes": download.bytes,
                "sha256": download.sha256,
                "content_type": download.content_type,
                "auto_opened_or_executed": download.auto_opened_or_executed,
            })
        });
        serde_json::to_vec(&serde_json::json!({
            "schema_version": self.schema_version,
            "action_id": self.action_id,
            "action_digest": self.action_digest,
            "action_kind": self.action_kind,
            "effect": self.effect.as_str(),
            "lease_id": self.lease_id,
            "lease_binding_digest": self.lease_binding_digest,
            "execution_epoch": self.execution_epoch,
            "cdp_request_id": self.cdp_request_id,
            "requested_url": self.requested_url,
            "navigation_was_download": self.navigation_was_download,
            "download": download,
            "synopsis": synopsis,
            "screenshot": screenshot,
            "screenshots_and_traces_suppressed": self.screenshots_and_traces_suppressed,
        }))
        .map_err(|error| BrowserError::Protocol(format!("receipt serialization failed: {error}")))
    }
}

/// Receipt for one already-completed download file. The adapter never opens the file as a program
/// or document; it opens it only as bytes for bounded hashing after confinement checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadReceipt {
    pub schema_version: u32,
    pub lease_id: String,
    pub lease_binding_digest: String,
    pub execution_epoch: i64,
    pub relative_path: PathBuf,
    pub bytes: u64,
    pub sha256: String,
    pub content_type: String,
    pub auto_opened_or_executed: bool,
}

impl DownloadReceipt {
    /// Hashes one exact regular file confined below a canonical download root. All path components
    /// are checked for symlinks, the opened inode is matched to the pre-open inode before reading,
    /// and hard-linked files are rejected. This prevents traversal/symlink escape without granting
    /// any filesystem authority beyond the caller-supplied root.
    ///
    /// # Errors
    /// Returns an invalid-request/resource-limit/I/O error for malformed metadata, traversal,
    /// symlinks, hard links, non-regular files, identity races, or oversized downloads.
    pub fn from_confined_file(
        lease: &BrowserLease,
        download_root: &Path,
        relative_path: &Path,
        content_type: &str,
        max_bytes: u64,
    ) -> Result<Self, BrowserError> {
        lease.validate_shape()?;
        validate_content_type(content_type)?;
        if max_bytes == 0 || max_bytes > MAX_DOWNLOAD_BYTES_HARD {
            return Err(BrowserError::ResourceLimit(
                "download receipt byte bound is outside static limits".to_owned(),
            ));
        }
        validate_relative_path(relative_path)?;
        let root = canonical_private_directory(download_root, "download root")?;
        ensure_no_symlink_components(
            &root,
            relative_path.parent().unwrap_or_else(|| Path::new("")),
        )?;
        let candidate = root.join(relative_path);
        let path_metadata = fs::symlink_metadata(&candidate)?;
        if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
            return Err(BrowserError::InvalidRequest(
                "download receipt target must be a regular non-symlink file".to_owned(),
            ));
        }
        if path_metadata.nlink() != 1 {
            return Err(BrowserError::InvalidRequest(
                "download receipt refuses hard-linked files".to_owned(),
            ));
        }
        if path_metadata.len() > max_bytes {
            return Err(BrowserError::ResourceLimit(
                "download exceeded configured byte bound".to_owned(),
            ));
        }

        let mut file = File::open(&candidate)?;
        let opened_metadata = file.metadata()?;
        if opened_metadata.dev() != path_metadata.dev()
            || opened_metadata.ino() != path_metadata.ino()
            || opened_metadata.nlink() != 1
            || !opened_metadata.is_file()
        {
            return Err(BrowserError::InvalidRequest(
                "download target identity changed while opening".to_owned(),
            ));
        }

        let canonical_candidate = candidate.canonicalize()?;
        if !canonical_candidate.starts_with(&root) {
            return Err(BrowserError::InvalidRequest(
                "download target escaped configured root".to_owned(),
            ));
        }

        let mut hasher = Sha256::new();
        let mut total = 0_u64;
        let mut buffer = [0_u8; 16 * 1024];
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            total = total.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
            if total > max_bytes {
                return Err(BrowserError::ResourceLimit(
                    "download grew beyond configured byte bound while hashing".to_owned(),
                ));
            }
            hasher.update(&buffer[..read]);
        }
        let final_metadata = file.metadata()?;
        let final_path_metadata = fs::symlink_metadata(&candidate)?;
        if final_metadata.dev() != opened_metadata.dev()
            || final_metadata.ino() != opened_metadata.ino()
            || final_metadata.len() != total
            || final_path_metadata.dev() != opened_metadata.dev()
            || final_path_metadata.ino() != opened_metadata.ino()
            || final_path_metadata.file_type().is_symlink()
            || final_path_metadata.nlink() != 1
        {
            return Err(BrowserError::InvalidRequest(
                "download target changed while receipt was being produced".to_owned(),
            ));
        }

        Ok(Self {
            schema_version: BROWSER_SCHEMA_VERSION,
            lease_id: lease.lease_id.clone(),
            lease_binding_digest: lease.binding_digest(),
            execution_epoch: lease.execution_epoch,
            relative_path: relative_path.to_path_buf(),
            bytes: total,
            sha256: format!("sha256:{:x}", hasher.finalize()),
            content_type: content_type.to_owned(),
            auto_opened_or_executed: false,
        })
    }

    /// Stable metadata-only encoding for durable evidence.
    ///
    /// # Errors
    /// Returns a protocol error if JSON serialization fails or the relative path is not UTF-8.
    pub fn to_bytes(&self) -> Result<Vec<u8>, BrowserError> {
        let relative_path = self.relative_path.to_str().ok_or_else(|| {
            BrowserError::Protocol("download receipt path is not valid UTF-8".to_owned())
        })?;
        serde_json::to_vec(&serde_json::json!({
            "schema_version": self.schema_version,
            "lease_id": self.lease_id,
            "lease_binding_digest": self.lease_binding_digest,
            "execution_epoch": self.execution_epoch,
            "relative_path": relative_path,
            "bytes": self.bytes,
            "sha256": self.sha256,
            "content_type": self.content_type,
            "auto_opened_or_executed": self.auto_opened_or_executed,
        }))
        .map_err(|error| BrowserError::Protocol(format!("receipt serialization failed: {error}")))
    }
}

/// Mechanical terminal state reported by Chrome for one exact download GUID.
///
/// This type carries no retention or policy decision. The Controller remains responsible for
/// deciding whether a completed download may be retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserDownloadTerminalState {
    Completed,
    Canceled,
}

/// Authority-neutral observation of one terminal Chrome download event.
///
/// The relative path is derived only from Chrome's bounded download GUID while the adapter is using
/// `allowAndName`; `suggestedFilename` is never interpreted as a filesystem path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserDownloadTerminalObservation {
    pub schema_version: u32,
    pub lease_id: String,
    pub lease_binding_digest: String,
    pub execution_epoch: i64,
    pub guid: String,
    pub relative_path: PathBuf,
    pub state: BrowserDownloadTerminalState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct QueuedBrowserDownloadTerminal {
    guid: String,
    relative_path: PathBuf,
    state: BrowserDownloadTerminalState,
}

#[derive(Debug, Default)]
struct BrowserDownloadTracker {
    pending_guids: BTreeSet<String>,
    terminal_guids: BTreeSet<String>,
    terminals: VecDeque<QueuedBrowserDownloadTerminal>,
}

impl BrowserDownloadTracker {
    fn observe(
        &mut self,
        value: &serde_json::Value,
        policy: BrowserDownloadPolicy,
        download_root: Option<&Path>,
    ) -> Result<bool, BrowserError> {
        let Some(method) = value.get("method").and_then(serde_json::Value::as_str) else {
            return Ok(false);
        };
        match method {
            "Browser.downloadWillBegin" => {
                self.observe_will_begin(value, policy, download_root)?;
                Ok(true)
            }
            "Browser.downloadProgress" => {
                self.observe_progress(value, policy, download_root)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn observe_will_begin(
        &mut self,
        value: &serde_json::Value,
        policy: BrowserDownloadPolicy,
        download_root: Option<&Path>,
    ) -> Result<(), BrowserError> {
        let _root = require_enabled_download_event(policy, download_root)?;
        let params = value.get("params").ok_or_else(|| {
            BrowserError::Protocol("Browser.downloadWillBegin omitted params".to_owned())
        })?;
        let guid = required_value_string(params, "guid", "Browser.downloadWillBegin")?;
        validate_download_guid(&guid)?;
        if self.pending_guids.contains(&guid) || self.terminal_guids.contains(&guid) {
            return Err(BrowserError::Protocol(
                "Browser.downloadWillBegin repeated an already tracked download GUID".to_owned(),
            ));
        }
        if self
            .pending_guids
            .len()
            .saturating_add(self.terminal_guids.len())
            >= MAX_TRACKED_DOWNLOADS
        {
            return Err(BrowserError::ResourceLimit(
                "browser download tracker exceeded its static GUID bound".to_owned(),
            ));
        }
        self.pending_guids.insert(guid);
        Ok(())
    }

    fn observe_progress(
        &mut self,
        value: &serde_json::Value,
        policy: BrowserDownloadPolicy,
        download_root: Option<&Path>,
    ) -> Result<(), BrowserError> {
        let root = require_enabled_download_event(policy, download_root)?;
        let params = value.get("params").ok_or_else(|| {
            BrowserError::Protocol("Browser.downloadProgress omitted params".to_owned())
        })?;
        let guid = required_value_string(params, "guid", "Browser.downloadProgress")?;
        validate_download_guid(&guid)?;
        if self.terminal_guids.contains(&guid) {
            return Err(BrowserError::Protocol(
                "Browser.downloadProgress repeated a terminal download GUID".to_owned(),
            ));
        }
        if !self.pending_guids.contains(&guid) {
            return Err(BrowserError::Protocol(
                "Browser.downloadProgress referenced an unknown download GUID".to_owned(),
            ));
        }
        let state = required_value_string(params, "state", "Browser.downloadProgress")?;
        match state.as_str() {
            "inProgress" => Ok(()),
            "completed" => {
                if let Some(file_path) = params.get("filePath") {
                    let file_path = file_path.as_str().ok_or_else(|| {
                        BrowserError::Protocol(
                            "Browser.downloadProgress filePath must be a string when present"
                                .to_owned(),
                        )
                    })?;
                    validate_completed_download_file_path(root, &guid, file_path)?;
                }
                self.queue_terminal(guid, BrowserDownloadTerminalState::Completed)
            }
            "canceled" => self.queue_terminal(guid, BrowserDownloadTerminalState::Canceled),
            _ => Err(BrowserError::Protocol(
                "Browser.downloadProgress reported an unknown terminal state".to_owned(),
            )),
        }
    }

    fn queue_terminal(
        &mut self,
        guid: String,
        state: BrowserDownloadTerminalState,
    ) -> Result<(), BrowserError> {
        if self.terminals.len() >= MAX_TRACKED_DOWNLOADS {
            return Err(BrowserError::ResourceLimit(
                "browser download terminal queue exceeded its static bound".to_owned(),
            ));
        }
        if !self.pending_guids.remove(&guid) || !self.terminal_guids.insert(guid.clone()) {
            return Err(BrowserError::Protocol(
                "browser download terminal state conflicted with tracked GUID state".to_owned(),
            ));
        }
        self.terminals.push_back(QueuedBrowserDownloadTerminal {
            relative_path: PathBuf::from(&guid),
            guid,
            state,
        });
        Ok(())
    }

    fn pop_terminal(&mut self) -> Option<QueuedBrowserDownloadTerminal> {
        self.terminals.pop_front()
    }
}

/// One owned Chrome instance with an ephemeral profile and a single attached page target.
pub struct BrowserAdapter {
    child: Child,
    cdp_writer: Option<ChildStdin>,
    cdp_reader: Option<CdpFrameReader>,
    process_group_id: u32,
    process_group_identity: String,
    private_parent: PathBuf,
    profile_root: PathBuf,
    download_root: Option<PathBuf>,
    lease_id: String,
    lease_binding_digest: String,
    execution_epoch: i64,
    session_id: String,
    target_id: String,
    browser_version: BrowserVersion,
    config: BrowserAdapterConfig,
    download_policy: BrowserDownloadPolicy,
    cleanup_profile_on_shutdown: bool,
    next_request_id: u64,
    main_frame_id: String,
    pending_action: Option<PendingBrowserAction>,
    pending_responses: BTreeMap<u64, serde_json::Value>,
    internal_requests: BTreeMap<u64, String>,
    document_requests: VecDeque<BrowserDocumentRequestObservation>,
    paused_document_requests: BTreeMap<String, BrowserDocumentRequestObservation>,
    document_chain_index: u32,
    main_frame_load_state: MainFrameLoadState,
    unexpected_page_targets: BTreeSet<String>,
    download_tracker: BrowserDownloadTracker,
    proxy_auth: Option<BrowserProxyAuthState>,
    request_method_ceiling: Option<BTreeSet<String>>,
    transport_uncertain: bool,
    closed: bool,
}

struct BrowserProxyAuthState {
    binding: BrowserProxyAuthBinding,
    token: String,
    credentials_sent: bool,
}

#[derive(Debug, Clone)]
struct PendingBrowserAction {
    action: BrowserAction,
    cdp_request_id: u64,
    response_method: &'static str,
    requested_url: Option<String>,
    response: Option<serde_json::Value>,
}

enum FetchPausedRequest {
    TopLevel(BrowserDocumentRequestObservation),
    Other {
        interception_id: String,
        method: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AttachedTargetDisposition {
    CloseUnexpectedPage { target_id: String },
    CloseContainedChild { target_id: String },
    ResumeMainPage { session_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FetchAuthDecision {
    Provide { request_id: String },
    Cancel { request_id: String },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum MainFrameLoadState {
    #[default]
    Idle,
    Started,
    Stopped,
}

impl BrowserAdapter {
    /// Prepares the exact unisolated browser process shape and ephemeral roots without spawning.
    ///
    /// This is the production integration seam: the Controller can convert [`BrowserProcessSpec`]
    /// into its canonical command/isolation contract, wrap it (for example with Seatbelt), and then
    /// call [`Self::spawn_preisolated`] with only that already-wrapped command.
    ///
    /// Caller Chrome flags are preserved exactly after browser-local conflict/bounds checks. This
    /// module does not decide whether proxy/network settings are authorized.
    ///
    /// # Errors
    /// Returns an error for malformed lease/configuration, unstable paths, conflicting reserved
    /// Chrome flags, or resource-limit violation.
    pub fn prepare_launch(
        chrome_path: &Path,
        private_parent: &Path,
        lease: &BrowserLease,
        config: BrowserAdapterConfig,
        launch_options: BrowserLaunchOptions,
    ) -> Result<PreparedBrowserLaunch, BrowserError> {
        lease.validate_shape()?;
        config.validate()?;
        validate_caller_chrome_args(&launch_options.caller_chrome_args)?;
        if let Some(proxy_auth) = launch_options.proxy_auth.as_ref() {
            proxy_auth.validate()?;
        }
        match (
            launch_options.download_policy,
            launch_options.download_root.as_ref(),
        ) {
            (BrowserDownloadPolicy::Deny, None) | (BrowserDownloadPolicy::Allow, Some(_)) => {}
            (BrowserDownloadPolicy::Deny, Some(_)) => {
                return Err(BrowserError::InvalidRequest(
                    "denied browser downloads cannot carry a download root".to_owned(),
                ));
            }
            (BrowserDownloadPolicy::Allow, None) => {
                return Err(BrowserError::InvalidRequest(
                    "allowed browser downloads require an exact caller-owned download root"
                        .to_owned(),
                ));
            }
        }
        let chrome_path = canonical_executable(chrome_path)?;
        let private_parent = canonical_private_directory(private_parent, "browser private parent")?;
        let (profile_root, cleanup_profile_on_drop) = match &launch_options.profile_root {
            BrowserProfileRoot::Ephemeral => {
                (create_ephemeral_profile(&private_parent, lease)?, true)
            }
            BrowserProfileRoot::CallerOwnedPersistent(profile_root) => (
                canonical_private_directory(profile_root, "caller-owned browser profile root")?,
                false,
            ),
        };
        let download_root = match launch_options.download_root.as_ref() {
            Some(root) => {
                match canonical_private_directory(root, "caller-owned browser download root") {
                    Ok(root) if !paths_overlap(&profile_root, &root) => Some(root),
                    Ok(_) => {
                        if cleanup_profile_on_drop {
                            let _ = fs::remove_dir_all(&profile_root);
                        }
                        return Err(BrowserError::InvalidRequest(
                            "browser profile and caller-owned download root must be disjoint"
                                .to_owned(),
                        ));
                    }
                    Err(error) => {
                        if cleanup_profile_on_drop {
                            let _ = fs::remove_dir_all(&profile_root);
                        }
                        return Err(error);
                    }
                }
            }
            None => None,
        };

        let chrome_args = chrome_args(&profile_root, &launch_options.caller_chrome_args);
        let process_spec =
            browser_process_spec(&chrome_path, &chrome_args, &private_parent, &profile_root);
        Ok(PreparedBrowserLaunch {
            process_spec,
            chrome_path,
            chrome_args,
            private_parent,
            profile_root,
            download_root,
            lease: lease.clone(),
            config,
            launch_options,
            request_method_ceiling: None,
            cleanup_armed: true,
            cleanup_profile_on_drop,
        })
    }

    /// Spawns one browser from a previously prepared launch using only the caller-supplied already
    /// isolated/wrapped executable and argument vector. The adapter owns stdio/CDP wiring, the
    /// process group, exact cleanup identity, and prepared environment; it does not add or remove
    /// wrapper arguments.
    ///
    /// # Errors
    /// Returns for malformed wrapper shape, process identity failure, Chrome/CDP handshake failure,
    /// or resource-limit violation.
    pub fn spawn_preisolated(
        mut prepared: PreparedBrowserLaunch,
        isolated: &IsolatedCommand,
    ) -> Result<Self, BrowserSpawnFailure> {
        if !isolated.executable.is_absolute() || isolated.executable.as_os_str().is_empty() {
            return Err(BrowserSpawnFailure::never_spawned(
                BrowserError::InvalidRequest(
                    "pre-isolated browser executable must be an absolute path".to_owned(),
                ),
            ));
        }
        let result = Self::spawn_prepared_command(&prepared, isolated);
        match &result {
            Ok(_) => prepared.cleanup_armed = false,
            Err(failure) if matches!(failure.state(), BrowserSpawnState::Unknown { .. }) => {
                // A possibly-live Chrome process may still own this profile. Recovery must decide
                // when it is safe to remove it after exact process absence is established.
                prepared.cleanup_armed = false;
            }
            Err(_) => {}
        }
        result
    }

    /// Legacy direct launch retained for compatibility tests. Production callers should use
    /// [`Self::prepare_launch`] followed by Controller/policy wrapping and
    /// [`Self::spawn_preisolated`]. Downloads default to denied on this compatibility path.
    ///
    /// # Errors
    /// Returns the same errors as preparation/spawn/handshake.
    pub fn launch(
        chrome_path: &Path,
        private_parent: &Path,
        lease: &BrowserLease,
        config: BrowserAdapterConfig,
    ) -> Result<Self, BrowserError> {
        let prepared = Self::prepare_launch(
            chrome_path,
            private_parent,
            lease,
            config,
            BrowserLaunchOptions::default(),
        )?;
        let direct = IsolatedCommand {
            executable: prepared.process_spec.executable.clone(),
            args: prepared.process_spec.args.clone(),
        };
        Self::spawn_preisolated(prepared, &direct).map_err(BrowserSpawnFailure::into_error)
    }

    fn spawn_prepared_command(
        prepared: &PreparedBrowserLaunch,
        isolated: &IsolatedCommand,
    ) -> Result<Self, BrowserSpawnFailure> {
        let mut command = prepared_browser_command(prepared, isolated);
        let (mut child, process_group_id, process_group_identity) =
            spawn_browser_process(&mut command)?;
        let spawn_binding = BrowserSpawnBinding {
            process_group_id,
            process_group_identity: process_group_identity.clone(),
        };
        let Some(cdp_writer) = child.stdin.take() else {
            let cleanup = terminate_exact_process_group(
                &mut child,
                process_group_id,
                &process_group_identity,
            );
            return Err(BrowserSpawnFailure::after_spawn(
                BrowserError::Process("Chrome CDP pipe writer was unavailable".to_owned()),
                cleanup.is_ok(),
                Some(spawn_binding),
            ));
        };
        let Some(cdp_stdout) = child.stdout.take() else {
            let cleanup = terminate_exact_process_group(
                &mut child,
                process_group_id,
                &process_group_identity,
            );
            return Err(BrowserSpawnFailure::after_spawn(
                BrowserError::Process("Chrome CDP pipe reader was unavailable".to_owned()),
                cleanup.is_ok(),
                Some(spawn_binding),
            ));
        };
        let cdp_reader = CdpFrameReader::spawn(cdp_stdout, prepared.config.max_cdp_frame_bytes);
        let mut adapter = Self {
            child,
            cdp_writer: Some(cdp_writer),
            cdp_reader: Some(cdp_reader),
            process_group_id,
            process_group_identity,
            private_parent: prepared.private_parent.clone(),
            profile_root: prepared.profile_root.clone(),
            download_root: prepared.download_root.clone(),
            lease_id: prepared.lease.lease_id.clone(),
            lease_binding_digest: prepared.lease.binding_digest(),
            execution_epoch: prepared.lease.execution_epoch,
            session_id: String::new(),
            target_id: String::new(),
            browser_version: BrowserVersion {
                product: String::new(),
                protocol_version: String::new(),
                user_agent: String::new(),
            },
            config: prepared.config.clone(),
            download_policy: prepared.launch_options.download_policy,
            cleanup_profile_on_shutdown: prepared.cleanup_profile_on_drop,
            next_request_id: 1,
            main_frame_id: String::new(),
            pending_action: None,
            pending_responses: BTreeMap::new(),
            internal_requests: BTreeMap::new(),
            document_requests: VecDeque::new(),
            paused_document_requests: BTreeMap::new(),
            document_chain_index: 0,
            main_frame_load_state: MainFrameLoadState::Idle,
            unexpected_page_targets: BTreeSet::new(),
            download_tracker: BrowserDownloadTracker::default(),
            proxy_auth: prepared.launch_options.proxy_auth.clone().map(|binding| {
                BrowserProxyAuthState {
                    binding,
                    token: prepared.lease.token.clone(),
                    credentials_sent: false,
                }
            }),
            request_method_ceiling: prepared.request_method_ceiling.clone(),
            transport_uncertain: false,
            closed: false,
        };

        let handshake = adapter.initialize_cdp();
        if let Err(error) = handshake {
            adapter.cdp_writer.take();
            let cleanup = terminate_exact_process_group(
                &mut adapter.child,
                adapter.process_group_id,
                &adapter.process_group_identity,
            );
            adapter.cdp_reader.take();
            if cleanup.is_ok() {
                // PreparedBrowserLaunch still owns ephemeral-profile cleanup on this failure path.
                adapter.closed = true;
            }
            return Err(BrowserSpawnFailure::after_spawn(
                error,
                cleanup.is_ok(),
                Some(spawn_binding),
            ));
        }
        Ok(adapter)
    }

    #[must_use]
    pub fn browser_version(&self) -> &BrowserVersion {
        &self.browser_version
    }

    #[must_use]
    pub fn profile_root(&self) -> &Path {
        &self.profile_root
    }

    #[must_use]
    pub fn download_root(&self) -> Option<&Path> {
        self.download_root.as_deref()
    }

    #[must_use]
    pub const fn process_group_id(&self) -> u32 {
        self.process_group_id
    }

    #[must_use]
    pub fn process_group_identity(&self) -> &str {
        &self.process_group_identity
    }

    #[must_use]
    pub fn target_id(&self) -> &str {
        &self.target_id
    }

    #[must_use]
    pub fn screenshots_and_traces_suppressed(&self) -> bool {
        self.config.suppress_screenshots_and_traces
    }

    #[must_use]
    pub const fn downloads_enabled(&self) -> bool {
        matches!(self.download_policy, BrowserDownloadPolicy::Allow)
    }

    /// Executes one typed action exactly once. Once a CDP request write is attempted, a timeout,
    /// disconnect, framing failure, or write failure returns `TransportUncertain`; this method never
    /// resends that action. The Controller can therefore reconcile consequential form submission
    /// from durable state instead of receiving an adapter-level blind retry.
    ///
    /// # Errors
    /// Returns for stale/mismatched lease bindings, invalid action shape, protocol failure, local
    /// resource limits, or transport uncertainty after dispatch.
    pub fn execute(
        &mut self,
        lease: &BrowserLease,
        action: &BrowserAction,
    ) -> Result<BrowserActionReceipt, BrowserError> {
        self.verify_lease(lease)?;
        action.validate_shape()?;
        if !self.paused_document_requests.is_empty() || !self.document_requests.is_empty() {
            return Err(BrowserError::InvalidRequest(
                "top-level document authorization remains unresolved".to_owned(),
            ));
        }
        let (request_id, requested_url, synopsis, screenshot) = match action {
            BrowserAction::Navigate { .. } | BrowserAction::SubmitForm { .. } => {
                return Err(BrowserError::InvalidRequest(
                    "navigation-capable actions require dispatch_intercepted_action so every top-level document request can be caller-authorized before continuation"
                        .to_owned(),
                ));
            }
            BrowserAction::CaptureSynopsis { .. } => {
                let (request_id, synopsis) = self.capture_synopsis()?;
                self.enforce_single_page_target(request_id, action.kind_name())?;
                (request_id, None, Some(synopsis), None)
            }
            BrowserAction::CaptureScreenshot { .. }
                if self.config.suppress_screenshots_and_traces =>
            {
                (0, None, None, None)
            }
            BrowserAction::CaptureScreenshot { .. } => {
                let (synopsis_request_id, synopsis) = self.capture_synopsis()?;
                self.enforce_single_page_target(synopsis_request_id, action.kind_name())?;
                if synopsis.requires_visual_capture_suppression() {
                    (synopsis_request_id, None, Some(synopsis), None)
                } else {
                    let (screenshot_request_id, screenshot) = self.capture_screenshot()?;
                    self.enforce_single_page_target(screenshot_request_id, action.kind_name())?;
                    (
                        screenshot_request_id,
                        None,
                        Some(synopsis),
                        Some(screenshot),
                    )
                }
            }
        };
        let sensitive_page_requires_suppression = synopsis
            .as_ref()
            .is_some_and(BrowserStateSynopsis::requires_visual_capture_suppression);

        Ok(BrowserActionReceipt {
            schema_version: BROWSER_SCHEMA_VERSION,
            action_id: action.action_id().to_owned(),
            action_digest: action.digest(),
            action_kind: action.kind_name().to_owned(),
            effect: action.effect(),
            lease_id: self.lease_id.clone(),
            lease_binding_digest: self.lease_binding_digest.clone(),
            execution_epoch: self.execution_epoch,
            cdp_request_id: request_id,
            requested_url,
            navigation_was_download: false,
            download: None,
            synopsis,
            screenshot,
            screenshots_and_traces_suppressed: self.config.suppress_screenshots_and_traces
                || sensitive_page_requires_suppression,
        })
    }

    /// Performs a read-only bounded inspection of one form without retaining field values.
    ///
    /// The opaque `payload_digest` is supplied by the caller and becomes part of the approval
    /// binding. This adapter never interprets the payload or decides whether submission is allowed.
    ///
    /// # Errors
    /// Returns for stale lease bindings, malformed selector/payload digest, missing/non-form
    /// selector targets, protocol failure, or resource limits.
    pub fn inspect_form(
        &mut self,
        lease: &BrowserLease,
        selector: &str,
        payload_digest: &str,
    ) -> Result<BrowserFormInspectionReceipt, BrowserError> {
        self.verify_lease(lease)?;
        validate_selector(selector)?;
        validate_sha256_digest(payload_digest, "form payload digest")?;
        if self.pending_action.is_some() || !self.paused_document_requests.is_empty() {
            return Err(BrowserError::InvalidRequest(
                "form inspection requires no dispatched action or unresolved document authorization"
                    .to_owned(),
            ));
        }
        let selector_json = serde_json::to_string(selector).map_err(|error| {
            BrowserError::Protocol(format!("selector serialization failed: {error}"))
        })?;
        let expression = form_inspection_expression(&selector_json);
        let (_, response) = self.send_cdp(
            "Runtime.evaluate",
            serde_json::json!({
                "expression": expression,
                "returnByValue": true,
                "awaitPromise": false,
            }),
            Some(self.session_id.clone()),
        )?;
        let value = runtime_value(&response, "Runtime.evaluate")?;
        if value.get("found").and_then(serde_json::Value::as_bool) != Some(true) {
            return Err(BrowserError::InvalidRequest(
                "form selector did not resolve to an HTMLFormElement".to_owned(),
            ));
        }
        let page_url = required_value_string(value, "pageUrl", "form inspection")?;
        let action_url = required_value_string(value, "actionUrl", "form inspection")?;
        let method = required_value_string(value, "method", "form inspection")?;
        let structure = required_value_string(value, "structure", "form inspection")?;
        if structure.len() > MAX_FORM_STRUCTURE_BYTES {
            return Err(BrowserError::ResourceLimit(
                "form structure exceeded browser inspection bound".to_owned(),
            ));
        }
        let sensitive_inputs_present = value
            .get("sensitiveInputsPresent")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        Ok(BrowserFormInspectionReceipt {
            schema_version: BROWSER_SCHEMA_VERSION,
            selector_digest: digest_string("sovereign.browser_form_selector.v1", selector),
            payload_digest: payload_digest.to_owned(),
            current_page_url: strip_url_query_fragment(&page_url),
            current_page_url_digest: digest_string("sovereign.browser_exact_url.v1", &page_url),
            normalized_method: method,
            resolved_action_url: strip_url_query_fragment(&action_url),
            resolved_action_url_digest: digest_string(
                "sovereign.browser_exact_url.v1",
                &action_url,
            ),
            structural_digest: digest_string("sovereign.browser_form_structure.v1", &structure),
            sensitive_inputs_present,
        })
    }

    /// Dispatches one navigation-capable action exactly once while top-level `Document` requests
    /// remain paused until [`Self::resolve_document_request`] is called by the Controller.
    ///
    /// `SubmitForm` additionally requires the exact previously approved inspection binding. The
    /// adapter refreshes that read-only inspection immediately before dispatch and refuses a stale
    /// binding without making a policy decision.
    ///
    /// # Errors
    /// Returns before dispatch for invalid/stale bindings, overlapping actions, or unresolved
    /// document requests. Any transport failure after the CDP write returns `TransportUncertain`
    /// and poisons the session; the adapter never retries.
    pub fn dispatch_intercepted_action(
        &mut self,
        lease: &BrowserLease,
        action: &BrowserAction,
        approved_form: Option<&BrowserFormInspectionReceipt>,
    ) -> Result<BrowserDispatchedAction, BrowserError> {
        self.verify_lease(lease)?;
        action.validate_shape()?;
        if self.pending_action.is_some() {
            return Err(BrowserError::InvalidRequest(
                "another browser action is already dispatched".to_owned(),
            ));
        }
        if !self.paused_document_requests.is_empty() || !self.document_requests.is_empty() {
            return Err(BrowserError::InvalidRequest(
                "top-level document authorization remains unresolved".to_owned(),
            ));
        }

        if let BrowserAction::SubmitForm {
            selector,
            payload_digest,
            ..
        } = action
        {
            let approved = approved_form.ok_or_else(|| {
                BrowserError::InvalidRequest(
                    "SubmitForm requires an approved form inspection binding".to_owned(),
                )
            })?;
            let fresh = self.inspect_form(lease, selector, payload_digest)?;
            if fresh.binding_digest() != approved.binding_digest() {
                return Err(BrowserError::InvalidRequest(
                    "form inspection binding changed before submit dispatch".to_owned(),
                ));
            }
        } else if approved_form.is_some() {
            return Err(BrowserError::InvalidRequest(
                "form inspection binding is valid only for SubmitForm".to_owned(),
            ));
        }

        self.document_chain_index = 0;
        self.main_frame_load_state = MainFrameLoadState::Idle;
        let (method, params, requested_url) = match action {
            BrowserAction::Navigate { url, .. } => (
                "Page.navigate",
                serde_json::json!({"url": url}),
                Some(url.clone()),
            ),
            BrowserAction::SubmitForm { selector, .. } => {
                let selector_json = serde_json::to_string(selector).map_err(|error| {
                    BrowserError::Protocol(format!("selector serialization failed: {error}"))
                })?;
                (
                    "Runtime.evaluate",
                    serde_json::json!({
                        "expression": form_submit_expression(&selector_json),
                        "returnByValue": true,
                        "awaitPromise": false,
                    }),
                    None,
                )
            }
            BrowserAction::CaptureSynopsis { .. } | BrowserAction::CaptureScreenshot { .. } => {
                return Err(BrowserError::InvalidRequest(
                    "browser observation actions are not navigation-capable; use execute"
                        .to_owned(),
                ));
            }
        };
        let request_id =
            self.dispatch_cdp_request(method, params, Some(self.session_id.clone()))?;
        self.pending_action = Some(PendingBrowserAction {
            action: action.clone(),
            cdp_request_id: request_id,
            response_method: method,
            requested_url,
            response: None,
        });
        Ok(BrowserDispatchedAction {
            action_id: action.action_id().to_owned(),
            action_digest: action.digest(),
            effect: action.effect(),
            cdp_request_id: request_id,
        })
    }

    /// Waits for the next paused top-level document request. The request remains paused when this
    /// method returns; only the Controller's subsequent explicit resolution can continue or abort
    /// it.
    ///
    /// # Errors
    /// Returns for stale leases, invalid timeout bounds, protocol/process failure, or transport
    /// uncertainty while an already-dispatched action is in flight.
    pub fn next_document_request(
        &mut self,
        lease: &BrowserLease,
        timeout_ms: u64,
    ) -> Result<BrowserDocumentRequestObservation, BrowserError> {
        self.verify_lease(lease)?;
        if timeout_ms == 0 || timeout_ms > self.config.request_timeout_ms {
            return Err(BrowserError::InvalidRequest(
                "document observation timeout is outside configured browser bounds".to_owned(),
            ));
        }
        if let Some(observation) = self.document_requests.pop_front() {
            return Ok(observation);
        }
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        loop {
            if let Some(observation) = self.document_requests.pop_front() {
                return Ok(observation);
            }
            let (request_id, method) = self
                .pending_action
                .as_ref()
                .map_or((0, "Fetch.requestPaused"), |pending| {
                    (pending.cdp_request_id, pending.response_method)
                });
            if Instant::now() >= deadline {
                if request_id == 0 {
                    return Err(BrowserError::Protocol(
                        "timed out waiting for a paused top-level document request".to_owned(),
                    ));
                }
                return Err(self.mark_transport_uncertain(
                    request_id,
                    method,
                    "timed out while an intercepted browser action remained in flight".to_owned(),
                ));
            }
            self.receive_and_process_until(deadline, request_id, method)?;
        }
    }

    /// Resolves one exact paused top-level document request according to a caller-owned decision.
    /// The adapter performs no destination or policy evaluation.
    ///
    /// # Errors
    /// Returns for stale/mismatched observations or CDP/transport failure. Once the continuation or
    /// abort write is attempted, any uncertainty poisons the session and is never retried.
    pub fn resolve_document_request(
        &mut self,
        lease: &BrowserLease,
        observation: &BrowserDocumentRequestObservation,
        decision: BrowserDocumentRequestDecision,
    ) -> Result<(), BrowserError> {
        self.verify_lease(lease)?;
        let current = self
            .paused_document_requests
            .get(&observation.interception_id)
            .ok_or_else(|| {
                BrowserError::InvalidRequest(
                    "document interception id is not currently paused".to_owned(),
                )
            })?;
        if current.digest() != observation.digest() {
            return Err(BrowserError::InvalidRequest(
                "document request observation does not match the currently paused request"
                    .to_owned(),
            ));
        }
        if matches!(decision, BrowserDocumentRequestDecision::Continue)
            && !self.request_method_allowed(&observation.method)
        {
            return Err(BrowserError::InvalidRequest(format!(
                "browser request method {} exceeds the installed mechanical ceiling",
                observation.method.to_ascii_uppercase()
            )));
        }
        let (method, params) = match decision {
            BrowserDocumentRequestDecision::Continue => (
                "Fetch.continueRequest",
                serde_json::json!({"requestId": observation.interception_id}),
            ),
            BrowserDocumentRequestDecision::Abort => (
                "Fetch.failRequest",
                serde_json::json!({
                    "requestId": observation.interception_id,
                    "errorReason": "BlockedByClient",
                }),
            ),
        };
        let _ = self.send_cdp(method, params, Some(self.session_id.clone()))?;
        self.paused_document_requests
            .remove(&observation.interception_id);
        Ok(())
    }

    /// Finishes one previously dispatched action after all observed top-level document requests have
    /// been resolved. If another request/redirect is paused, this returns a deterministic
    /// precondition error without continuing it; the Controller should observe and resolve that
    /// request, then call this method again.
    ///
    /// # Errors
    /// Returns for unresolved document authorization, protocol failure, target invariant failure, or
    /// post-dispatch transport uncertainty. No action is retried.
    pub fn finish_dispatched_action(
        &mut self,
        lease: &BrowserLease,
    ) -> Result<BrowserActionReceipt, BrowserError> {
        self.verify_lease(lease)?;
        let deadline = Instant::now() + Duration::from_millis(self.config.request_timeout_ms);
        loop {
            if !self.document_requests.is_empty() || !self.paused_document_requests.is_empty() {
                return Err(BrowserError::InvalidRequest(
                    "top-level document request/redirect is paused awaiting caller authorization"
                        .to_owned(),
                ));
            }
            let Some(pending) = self.pending_action.as_ref() else {
                return Err(BrowserError::InvalidRequest(
                    "no dispatched browser action is awaiting completion".to_owned(),
                ));
            };
            let response_ready = pending.response.is_some();
            let loading_complete = match pending.action {
                BrowserAction::Navigate { .. } => {
                    pending
                        .response
                        .as_ref()
                        .map(navigation_response_is_download)
                        .transpose()?
                        .unwrap_or(false)
                        || self.main_frame_load_state == MainFrameLoadState::Stopped
                }
                BrowserAction::SubmitForm { .. } => {
                    (self.main_frame_load_state == MainFrameLoadState::Idle
                        && self.document_chain_index == 0)
                        || self.main_frame_load_state == MainFrameLoadState::Stopped
                }
                BrowserAction::CaptureSynopsis { .. } | BrowserAction::CaptureScreenshot { .. } => {
                    true
                }
            };
            if response_ready && loading_complete {
                break;
            }
            let request_id = pending.cdp_request_id;
            let response_method = pending.response_method;
            self.receive_and_process_until(deadline, request_id, response_method)?;
        }

        let pending = self.pending_action.clone().ok_or_else(|| {
            BrowserError::Protocol("pending browser action disappeared".to_owned())
        })?;
        let response = pending.response.as_ref().ok_or_else(|| {
            BrowserError::Protocol("pending browser action omitted its CDP response".to_owned())
        })?;
        let navigation_was_download = match &pending.action {
            BrowserAction::Navigate { .. } => {
                validate_navigation_response(response)?;
                navigation_response_is_download(response)?
            }
            BrowserAction::SubmitForm { .. } => {
                validate_submit_response(response)?;
                false
            }
            BrowserAction::CaptureSynopsis { .. } | BrowserAction::CaptureScreenshot { .. } => {
                return Err(BrowserError::Protocol(
                    "browser observation action cannot be a dispatched navigation action"
                        .to_owned(),
                ));
            }
        };
        self.enforce_single_page_target(pending.cdp_request_id, pending.action.kind_name())?;
        if !self.document_requests.is_empty() || !self.paused_document_requests.is_empty() {
            return Err(BrowserError::InvalidRequest(
                "top-level document redirect became paused while finalizing the browser action"
                    .to_owned(),
            ));
        }
        let receipt = BrowserActionReceipt {
            schema_version: BROWSER_SCHEMA_VERSION,
            action_id: pending.action.action_id().to_owned(),
            action_digest: pending.action.digest(),
            action_kind: pending.action.kind_name().to_owned(),
            effect: pending.action.effect(),
            lease_id: self.lease_id.clone(),
            lease_binding_digest: self.lease_binding_digest.clone(),
            execution_epoch: self.execution_epoch,
            cdp_request_id: pending.cdp_request_id,
            requested_url: pending.requested_url,
            navigation_was_download,
            download: None,
            synopsis: None,
            screenshot: None,
            screenshots_and_traces_suppressed: self.config.suppress_screenshots_and_traces,
        };
        self.pending_action = None;
        self.document_chain_index = 0;
        self.main_frame_load_state = MainFrameLoadState::Idle;
        Ok(receipt)
    }

    /// Produces a bounded receipt for one download file under this adapter's private download root.
    /// The caller supplies observed content-type metadata; this method never opens or executes the
    /// downloaded content beyond reading bytes for hashing.
    ///
    /// # Errors
    /// Returns for stale lease bindings or any confinement/size/identity failure described by
    /// [`DownloadReceipt::from_confined_file`].
    pub fn record_download(
        &self,
        lease: &BrowserLease,
        relative_path: &Path,
        content_type: &str,
    ) -> Result<DownloadReceipt, BrowserError> {
        self.verify_lease(lease)?;
        if self.download_policy != BrowserDownloadPolicy::Allow {
            return Err(BrowserError::InvalidRequest(
                "download receipt requested while caller policy denies browser downloads"
                    .to_owned(),
            ));
        }
        let download_root = self.download_root.as_deref().ok_or_else(|| {
            BrowserError::InvalidRequest(
                "download receipt requested without an exact caller-owned download root".to_owned(),
            )
        })?;
        DownloadReceipt::from_confined_file(
            lease,
            download_root,
            relative_path,
            content_type,
            self.config.max_download_bytes,
        )
    }

    /// Waits for one mechanically observed terminal Chrome download event.
    ///
    /// The adapter binds the observation to the exact live browser lease and derives the relative
    /// path only from Chrome's GUID under `allowAndName`. It performs no content-type, retention, or
    /// Controller policy decision.
    ///
    /// # Errors
    /// Returns for stale lease bindings, disabled downloads, invalid timeout bounds, malformed or
    /// conflicting download events, CDP transport failure, or timeout while awaiting a terminal.
    pub fn next_download_terminal(
        &mut self,
        lease: &BrowserLease,
        timeout_ms: u64,
    ) -> Result<BrowserDownloadTerminalObservation, BrowserError> {
        self.verify_lease(lease)?;
        if self.download_policy != BrowserDownloadPolicy::Allow || self.download_root.is_none() {
            return Err(BrowserError::InvalidRequest(
                "download terminal observation requested while browser downloads are disabled"
                    .to_owned(),
            ));
        }
        if timeout_ms == 0 || timeout_ms > self.config.request_timeout_ms {
            return Err(BrowserError::InvalidRequest(
                "download observation timeout is outside configured browser bounds".to_owned(),
            ));
        }
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        loop {
            if let Some(terminal) = self.download_tracker.pop_terminal() {
                return Ok(BrowserDownloadTerminalObservation {
                    schema_version: BROWSER_SCHEMA_VERSION,
                    lease_id: self.lease_id.clone(),
                    lease_binding_digest: self.lease_binding_digest.clone(),
                    execution_epoch: self.execution_epoch,
                    guid: terminal.guid,
                    relative_path: terminal.relative_path,
                    state: terminal.state,
                });
            }
            let (request_id, method) = self
                .pending_action
                .as_ref()
                .map_or((0, "Browser.downloadProgress"), |pending| {
                    (pending.cdp_request_id, pending.response_method)
                });
            self.receive_and_process_until(deadline, request_id, method)?;
        }
    }

    /// Terminates/reaps the exact owned process group and deletes only adapter-owned ephemeral
    /// profile roots. Caller-owned persistent roots are intentionally left intact.
    ///
    /// # Errors
    /// Returns fail-closed when the leader identity has changed, process-group absence cannot be
    /// proven, or profile cleanup fails.
    pub fn shutdown(mut self) -> Result<(), BrowserError> {
        self.shutdown_inner()
    }

    fn verify_lease(&self, lease: &BrowserLease) -> Result<(), BrowserError> {
        lease.validate_shape()?;
        if lease.lease_id != self.lease_id
            || lease.execution_epoch != self.execution_epoch
            || lease.binding_digest() != self.lease_binding_digest
        {
            return Err(BrowserError::InvalidRequest(
                "browser lease does not match the launched session binding".to_owned(),
            ));
        }
        Ok(())
    }

    fn initialize_cdp(&mut self) -> Result<(), BrowserError> {
        let (_, version_response) =
            self.send_cdp("Browser.getVersion", serde_json::json!({}), None)?;
        let version = cdp_result(&version_response, "Browser.getVersion")?;
        self.browser_version = BrowserVersion {
            product: required_string(version, "product", "Browser.getVersion")?,
            protocol_version: required_string(version, "protocolVersion", "Browser.getVersion")?,
            user_agent: required_string(version, "userAgent", "Browser.getVersion")?,
        };

        let (_, discover_response) = self.send_cdp(
            "Target.setDiscoverTargets",
            serde_json::json!({"discover": true}),
            None,
        )?;
        let _ = cdp_result(&discover_response, "Target.setDiscoverTargets")?;

        let (_, target_response) =
            self.send_cdp("Target.getTargets", serde_json::json!({}), None)?;
        let mut page_target_ids = page_target_ids(&target_response)?;
        if page_target_ids.is_empty() {
            let (_, create_response) = self.send_cdp(
                "Target.createTarget",
                serde_json::json!({"url": "about:blank"}),
                None,
            )?;
            let create_result = cdp_result(&create_response, "Target.createTarget")?;
            page_target_ids.push(required_string(
                create_result,
                "targetId",
                "Target.createTarget",
            )?);
        }
        if page_target_ids.len() != 1 {
            return Err(BrowserError::Protocol(format!(
                "browser session requires exactly one page target, observed {}",
                page_target_ids.len()
            )));
        }
        self.target_id.clone_from(&page_target_ids[0]);
        let (_, attach_response) = self.send_cdp(
            "Target.attachToTarget",
            serde_json::json!({"targetId": self.target_id, "flatten": true}),
            None,
        )?;
        let attach_result = cdp_result(&attach_response, "Target.attachToTarget")?;
        self.session_id = required_string(attach_result, "sessionId", "Target.attachToTarget")?;

        let session = Some(self.session_id.clone());
        let (_, auto_attach_response) = self.send_cdp(
            "Target.setAutoAttach",
            serde_json::json!({
                "autoAttach": true,
                "waitForDebuggerOnStart": true,
                "flatten": true,
            }),
            session.clone(),
        )?;
        let _ = cdp_result(&auto_attach_response, "Target.setAutoAttach")?;
        let (_, page_enable_response) =
            self.send_cdp("Page.enable", serde_json::json!({}), session)?;
        let _ = cdp_result(&page_enable_response, "Page.enable")?;
        let (_, frame_tree_response) = self.send_cdp(
            "Page.getFrameTree",
            serde_json::json!({}),
            Some(self.session_id.clone()),
        )?;
        self.main_frame_id = main_frame_id(&frame_tree_response)?;
        let (_, interception_response) = self.send_cdp(
            "Fetch.enable",
            serde_json::json!({
                "patterns": [{
                    "urlPattern": "*",
                    "requestStage": "Request",
                }],
                "handleAuthRequests": self.proxy_auth.is_some(),
            }),
            Some(self.session_id.clone()),
        )?;
        let _ = cdp_result(&interception_response, "Fetch.enable")?;
        let download_params = match self.download_policy {
            BrowserDownloadPolicy::Deny => serde_json::json!({
                "behavior": "deny",
                "eventsEnabled": true,
            }),
            BrowserDownloadPolicy::Allow => {
                let download_root = self.download_root.as_ref().ok_or_else(|| {
                    BrowserError::InvalidRequest(
                        "allowed browser downloads lost their caller-owned download root"
                            .to_owned(),
                    )
                })?;
                serde_json::json!({
                    "behavior": "allowAndName",
                    "downloadPath": download_root,
                    "eventsEnabled": true,
                })
            }
        };
        let (_, download_response) =
            self.send_cdp("Browser.setDownloadBehavior", download_params, None)?;
        let _ = cdp_result(&download_response, "Browser.setDownloadBehavior")?;
        Ok(())
    }

    fn enforce_single_page_target(
        &mut self,
        dispatched_request_id: u64,
        action_kind: &str,
    ) -> Result<(), BrowserError> {
        let (_, response) = self.send_cdp("Target.getTargets", serde_json::json!({}), None)?;
        let page_targets = page_target_ids(&response)?;
        let (expected_present, unexpected) = assess_single_tab_targets(
            &self.target_id,
            &page_targets,
            &self.unexpected_page_targets,
        );
        if unexpected.is_empty() && expected_present && page_targets.len() == 1 {
            return Ok(());
        }

        for target_id in unexpected
            .iter()
            .filter(|target_id| page_targets.contains(target_id))
        {
            let _ = self.send_cdp(
                "Target.closeTarget",
                serde_json::json!({"targetId": target_id}),
                None,
            )?;
        }
        self.unexpected_page_targets.clear();

        if !unexpected.is_empty() {
            let (_, verify_response) =
                self.send_cdp("Target.getTargets", serde_json::json!({}), None)?;
            let remaining = page_target_ids(&verify_response)?;
            if remaining.len() != 1 || remaining.first() != Some(&self.target_id) {
                return Err(self.mark_transport_uncertain(
                    dispatched_request_id,
                    action_kind,
                    format!(
                        "single-tab cleanup could not restore the original page target; remaining={remaining:?}"
                    ),
                ));
            }
            return Err(self.mark_transport_uncertain(
                dispatched_request_id,
                action_kind,
                format!(
                    "single-tab invariant violated after dispatch; closed unexpected page targets: {}",
                    unexpected.into_iter().collect::<Vec<_>>().join(",")
                ),
            ));
        }

        Err(self.mark_transport_uncertain(
            dispatched_request_id,
            action_kind,
            "original page target disappeared after dispatch".to_owned(),
        ))
    }

    fn capture_synopsis(&mut self) -> Result<(u64, BrowserStateSynopsis), BrowserError> {
        let expression =
            synopsis_expression(self.config.max_synopsis_bytes, self.config.max_dom_bytes);
        let (request_id, response) = self.send_cdp(
            "Runtime.evaluate",
            serde_json::json!({
                "expression": expression,
                "returnByValue": true,
                "awaitPromise": false,
            }),
            Some(self.session_id.clone()),
        )?;
        let value = runtime_value(&response, "Runtime.evaluate")?;
        let url = required_value_string(value, "url", "browser synopsis")?;
        let title = required_value_string(value, "title", "browser synopsis")?;
        let mut text = required_value_string(value, "text", "browser synopsis")?;
        let mut dom = required_value_string(value, "dom", "browser synopsis")?;
        let js_text_truncated = value
            .get("textTruncated")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let js_dom_truncated = value
            .get("domTruncated")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let mut sensitive_reasons = BTreeSet::new();
        if value
            .get("formControlsPresent")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true)
        {
            sensitive_reasons.insert(BrowserSensitivePageReason::FormControl);
        }
        if value
            .get("passwordControlPresent")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true)
        {
            sensitive_reasons.insert(BrowserSensitivePageReason::PasswordControl);
        }
        if value
            .get("sensitiveAttributePresent")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true)
        {
            sensitive_reasons.insert(BrowserSensitivePageReason::SensitiveAttribute);
        }
        if value
            .get("credentialTextPatternPresent")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true)
        {
            sensitive_reasons.insert(BrowserSensitivePageReason::CredentialTextPattern);
        }
        if value
            .get("sensitive")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true)
            && sensitive_reasons.is_empty()
        {
            sensitive_reasons.insert(BrowserSensitivePageReason::Unclassified);
        }
        let sensitive_page = BrowserSensitivePageSignal {
            reasons: sensitive_reasons,
        };
        let rust_text_truncated = truncate_utf8_bytes(&mut text, self.config.max_synopsis_bytes);
        let rust_dom_truncated = truncate_utf8_bytes(&mut dom, self.config.max_dom_bytes);
        let retained_text_bytes = text.len();
        let retained_dom_bytes = dom.len();
        let mut dom_hasher = Sha256::new();
        dom_hasher.update(dom.as_bytes());
        Ok((
            request_id,
            BrowserStateSynopsis {
                url,
                title,
                text,
                dom_excerpt: dom,
                retained_text_bytes,
                retained_dom_bytes,
                text_truncated: js_text_truncated || rust_text_truncated,
                dom_truncated: js_dom_truncated || rust_dom_truncated,
                retained_dom_sha256: format!("sha256:{:x}", dom_hasher.finalize()),
                sensitive_page,
            },
        ))
    }

    fn capture_screenshot(&mut self) -> Result<(u64, BrowserScreenshot), BrowserError> {
        let (request_id, response) = self.send_cdp(
            "Page.captureScreenshot",
            serde_json::json!({
                "format": "png",
                "fromSurface": true,
                "captureBeyondViewport": false,
                "optimizeForSpeed": true,
            }),
            Some(self.session_id.clone()),
        )?;
        let result = cdp_result(&response, "Page.captureScreenshot")?;
        let png_base64 = required_value_string(result, "data", "Page.captureScreenshot")?;
        let retained_base64_bytes = png_base64.len();
        if retained_base64_bytes > self.config.max_cdp_frame_bytes {
            return Err(BrowserError::ResourceLimit(
                "browser screenshot exceeded the configured CDP frame bound".to_owned(),
            ));
        }
        let png_bytes = decoded_base64_len(&png_base64).ok_or_else(|| {
            BrowserError::Protocol(
                "Page.captureScreenshot returned malformed standard base64".to_owned(),
            )
        })?;
        if png_bytes == 0 || !png_base64.starts_with("iVBORw0KGgo") {
            return Err(BrowserError::Protocol(
                "Page.captureScreenshot did not return a non-empty PNG payload".to_owned(),
            ));
        }
        Ok((
            request_id,
            BrowserScreenshot {
                content_type: "image/png".to_owned(),
                encoding: "base64".to_owned(),
                png_base64,
                png_bytes,
                retained_base64_bytes,
            },
        ))
    }

    fn send_cdp(
        &mut self,
        method: &str,
        params: serde_json::Value,
        session_id: Option<String>,
    ) -> Result<(u64, serde_json::Value), BrowserError> {
        let request_id = self.dispatch_cdp_request(method, params, session_id)?;
        let deadline = Instant::now() + Duration::from_millis(self.config.request_timeout_ms);
        loop {
            if let Some(response) = self.pending_responses.remove(&request_id) {
                return Ok((request_id, response));
            }
            self.receive_and_process_until(deadline, request_id, method)?;
        }
    }

    fn dispatch_cdp_request(
        &mut self,
        method: &str,
        params: serde_json::Value,
        session_id: Option<String>,
    ) -> Result<u64, BrowserError> {
        if self.transport_uncertain {
            return Err(BrowserError::TransportUncertain {
                request_id: 0,
                method: method.to_owned(),
                detail: "browser transport is poisoned after an earlier uncertain dispatch"
                    .to_owned(),
            });
        }
        let request_id = self.next_request_id;
        self.next_request_id = self.next_request_id.checked_add(1).ok_or_else(|| {
            BrowserError::ResourceLimit("CDP request id space exhausted".to_owned())
        })?;
        let mut request_object = serde_json::Map::new();
        request_object.insert("id".to_owned(), serde_json::Value::from(request_id));
        request_object.insert(
            "method".to_owned(),
            serde_json::Value::String(method.to_owned()),
        );
        request_object.insert("params".to_owned(), params);
        if let Some(session_id) = session_id {
            request_object.insert(
                "sessionId".to_owned(),
                serde_json::Value::String(session_id),
            );
        }
        let encoded =
            serde_json::to_vec(&serde_json::Value::Object(request_object)).map_err(|error| {
                BrowserError::Protocol(format!("CDP request serialization failed: {error}"))
            })?;
        if encoded.len().saturating_add(1) > self.config.max_cdp_frame_bytes {
            return Err(BrowserError::ResourceLimit(
                "CDP request exceeded configured frame bound".to_owned(),
            ));
        }
        let write_result = {
            let writer = self.cdp_writer.as_mut().ok_or_else(|| {
                BrowserError::Process("Chrome CDP writer is already closed".to_owned())
            })?;
            writer
                .write_all(&encoded)
                .and_then(|()| writer.write_all(&[0]))
                .and_then(|()| writer.flush())
        };
        if let Err(error) = write_result {
            return Err(self.mark_transport_uncertain(
                request_id,
                method,
                format!("CDP pipe write failed: {error}"),
            ));
        }
        Ok(request_id)
    }

    fn receive_and_process_until(
        &mut self,
        deadline: Instant,
        uncertainty_request_id: u64,
        uncertainty_method: &str,
    ) -> Result<(), BrowserError> {
        let now = Instant::now();
        if now >= deadline {
            return Err(self.mark_transport_uncertain(
                uncertainty_request_id,
                uncertainty_method,
                "timed out waiting for CDP activity after dispatch".to_owned(),
            ));
        }
        let remaining = deadline.saturating_duration_since(now);
        let frame = match self
            .cdp_reader
            .as_ref()
            .ok_or_else(|| BrowserError::Process("Chrome CDP reader is already closed".to_owned()))?
            .recv_timeout(remaining)
        {
            Ok(frame) => frame,
            Err(detail) => {
                return Err(self.mark_transport_uncertain(
                    uncertainty_request_id,
                    uncertainty_method,
                    detail,
                ));
            }
        };
        let value: serde_json::Value = serde_json::from_slice(&frame).map_err(|error| {
            self.mark_transport_uncertain(
                uncertainty_request_id,
                uncertainty_method,
                format!("received malformed CDP JSON after dispatch: {error}"),
            )
        })?;
        self.process_cdp_value(value, uncertainty_request_id, uncertainty_method)
    }

    fn process_cdp_value(
        &mut self,
        value: serde_json::Value,
        uncertainty_request_id: u64,
        uncertainty_method: &str,
    ) -> Result<(), BrowserError> {
        if let Some(response_id) = value.get("id").and_then(serde_json::Value::as_u64) {
            if let Some(internal_method) = self.internal_requests.remove(&response_id) {
                if value.get("error").is_some() {
                    return Err(self.mark_transport_uncertain(
                        response_id,
                        &internal_method,
                        "internal CDP continuation returned an error".to_owned(),
                    ));
                }
                return Ok(());
            }
            if let Some(pending) = self.pending_action.as_mut()
                && pending.cdp_request_id == response_id
            {
                pending.response = Some(value);
                return Ok(());
            }
            self.pending_responses.insert(response_id, value);
            return Ok(());
        }
        let download_event = self.download_tracker.observe(
            &value,
            self.download_policy,
            self.download_root.as_deref(),
        );
        match download_event {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(error) => {
                return Err(self.mark_transport_uncertain(
                    uncertainty_request_id,
                    uncertainty_method,
                    format!("invalid Browser download event: {error}"),
                ));
            }
        }
        if self.observe_attached_target_event(&value, uncertainty_request_id, uncertainty_method)? {
            return Ok(());
        }
        if self.observe_auth_event(&value, uncertainty_request_id, uncertainty_method)? {
            return Ok(());
        }
        self.observe_target_event(&value);
        self.observe_frame_event(&value);
        self.observe_interception_event(&value, uncertainty_request_id, uncertainty_method)
    }

    fn observe_auth_event(
        &mut self,
        value: &serde_json::Value,
        uncertainty_request_id: u64,
        uncertainty_method: &str,
    ) -> Result<bool, BrowserError> {
        let credentials_sent = self
            .proxy_auth
            .as_ref()
            .is_some_and(|state| state.credentials_sent);
        let decision = classify_fetch_auth_required(
            value,
            self.proxy_auth.as_ref().map(|state| &state.binding),
            credentials_sent,
        )
        .map_err(|error| {
            self.mark_transport_uncertain(
                uncertainty_request_id,
                uncertainty_method,
                format!("invalid Fetch.authRequired event: {error}"),
            )
        })?;
        let Some(decision) = decision else {
            return Ok(false);
        };
        let (request_id, auth_response) = match decision {
            FetchAuthDecision::Provide { request_id } => {
                if self.proxy_auth.is_none() {
                    return Err(self.mark_transport_uncertain(
                        uncertainty_request_id,
                        uncertainty_method,
                        "proxy credentials selected without configured auth binding".to_owned(),
                    ));
                }
                let state = self.proxy_auth.as_mut().ok_or_else(|| {
                    BrowserError::Protocol(
                        "proxy auth state disappeared after presence check".to_owned(),
                    )
                })?;
                state.credentials_sent = true;
                (
                    request_id,
                    serde_json::json!({
                        "response": "ProvideCredentials",
                        "username": state.binding.username,
                        "password": state.token,
                    }),
                )
            }
            FetchAuthDecision::Cancel { request_id } => {
                (request_id, serde_json::json!({"response": "CancelAuth"}))
            }
        };
        let internal_request_id = self.dispatch_cdp_request(
            "Fetch.continueWithAuth",
            serde_json::json!({
                "requestId": request_id,
                "authChallengeResponse": auth_response,
            }),
            Some(self.session_id.clone()),
        )?;
        self.internal_requests
            .insert(internal_request_id, "Fetch.continueWithAuth".to_owned());
        Ok(true)
    }

    fn observe_attached_target_event(
        &mut self,
        value: &serde_json::Value,
        uncertainty_request_id: u64,
        uncertainty_method: &str,
    ) -> Result<bool, BrowserError> {
        let disposition = classify_attached_target(value, &self.target_id).map_err(|error| {
            self.mark_transport_uncertain(
                uncertainty_request_id,
                uncertainty_method,
                format!("invalid Target.attachedToTarget event: {error}"),
            )
        })?;
        let Some(disposition) = disposition else {
            return Ok(false);
        };
        match disposition {
            AttachedTargetDisposition::CloseUnexpectedPage { target_id } => {
                self.unexpected_page_targets.insert(target_id.clone());
                let request_id = self.dispatch_cdp_request(
                    "Target.closeTarget",
                    serde_json::json!({"targetId": target_id}),
                    None,
                )?;
                self.internal_requests
                    .insert(request_id, "Target.closeTarget".to_owned());
            }
            AttachedTargetDisposition::CloseContainedChild { target_id } => {
                let request_id = self.dispatch_cdp_request(
                    "Target.closeTarget",
                    serde_json::json!({"targetId": target_id}),
                    None,
                )?;
                self.internal_requests
                    .insert(request_id, "Target.closeTarget".to_owned());
            }
            AttachedTargetDisposition::ResumeMainPage { session_id } => {
                let request_id = self.dispatch_cdp_request(
                    "Runtime.runIfWaitingForDebugger",
                    serde_json::json!({}),
                    Some(session_id),
                )?;
                self.internal_requests
                    .insert(request_id, "Runtime.runIfWaitingForDebugger".to_owned());
            }
        }
        Ok(true)
    }

    fn observe_target_event(&mut self, value: &serde_json::Value) {
        if self.target_id.is_empty() {
            return;
        }
        let Some(method) = value.get("method").and_then(serde_json::Value::as_str) else {
            return;
        };
        if !matches!(method, "Target.targetCreated" | "Target.targetInfoChanged") {
            return;
        }
        let Some(target_info) = value
            .get("params")
            .and_then(|params| params.get("targetInfo"))
        else {
            return;
        };
        if target_info.get("type").and_then(serde_json::Value::as_str) != Some("page") {
            return;
        }
        let Some(target_id) = target_info
            .get("targetId")
            .and_then(serde_json::Value::as_str)
        else {
            return;
        };
        if target_id != self.target_id {
            self.unexpected_page_targets.insert(target_id.to_owned());
        }
    }

    fn observe_frame_event(&mut self, value: &serde_json::Value) {
        let Some(method) = value.get("method").and_then(serde_json::Value::as_str) else {
            return;
        };
        if !matches!(
            method,
            "Page.frameStartedLoading" | "Page.frameStoppedLoading"
        ) {
            return;
        }
        let Some(frame_id) = value
            .get("params")
            .and_then(|params| params.get("frameId"))
            .and_then(serde_json::Value::as_str)
        else {
            return;
        };
        if frame_id != self.main_frame_id {
            return;
        }
        match method {
            "Page.frameStartedLoading" => self.main_frame_load_state = MainFrameLoadState::Started,
            "Page.frameStoppedLoading" => self.main_frame_load_state = MainFrameLoadState::Stopped,
            _ => {}
        }
    }

    fn observe_interception_event(
        &mut self,
        value: &serde_json::Value,
        uncertainty_request_id: u64,
        uncertainty_method: &str,
    ) -> Result<(), BrowserError> {
        let classified =
            classify_fetch_request_paused(value, &self.main_frame_id, self.document_chain_index)
                .map_err(|error| {
                    self.mark_transport_uncertain(
                        uncertainty_request_id,
                        uncertainty_method,
                        format!("invalid Fetch.requestPaused event: {error}"),
                    )
                })?;
        match classified {
            None => Ok(()),
            Some(FetchPausedRequest::Other {
                interception_id,
                method,
            }) => {
                if non_top_level_request_method_allowed(
                    self.request_method_ceiling.as_ref(),
                    &method,
                ) {
                    self.continue_intercepted_request_internally(&interception_id)
                } else {
                    self.fail_intercepted_request_internally(&interception_id)
                }
            }
            Some(FetchPausedRequest::TopLevel(observation)) => {
                if self
                    .paused_document_requests
                    .contains_key(&observation.interception_id)
                {
                    return Ok(());
                }
                self.document_chain_index = self.document_chain_index.saturating_add(1);
                self.paused_document_requests
                    .insert(observation.interception_id.clone(), observation.clone());
                self.document_requests.push_back(observation);
                Ok(())
            }
        }
    }

    fn continue_intercepted_request_internally(
        &mut self,
        interception_id: &str,
    ) -> Result<(), BrowserError> {
        let request_id = self.dispatch_cdp_request(
            "Fetch.continueRequest",
            serde_json::json!({"requestId": interception_id}),
            Some(self.session_id.clone()),
        )?;
        self.internal_requests
            .insert(request_id, "Fetch.continueRequest".to_owned());
        Ok(())
    }

    fn fail_intercepted_request_internally(
        &mut self,
        interception_id: &str,
    ) -> Result<(), BrowserError> {
        let request_id = self.dispatch_cdp_request(
            "Fetch.failRequest",
            serde_json::json!({
                "requestId": interception_id,
                "errorReason": "BlockedByClient",
            }),
            Some(self.session_id.clone()),
        )?;
        self.internal_requests
            .insert(request_id, "Fetch.failRequest".to_owned());
        Ok(())
    }

    fn request_method_allowed(&self, method: &str) -> bool {
        request_method_allowed_by_ceiling(self.request_method_ceiling.as_ref(), method)
    }

    fn mark_transport_uncertain(
        &mut self,
        request_id: u64,
        method: &str,
        detail: String,
    ) -> BrowserError {
        self.transport_uncertain = true;
        BrowserError::TransportUncertain {
            request_id,
            method: method.to_owned(),
            detail,
        }
    }

    fn shutdown_inner(&mut self) -> Result<(), BrowserError> {
        if self.closed {
            return Ok(());
        }
        let gracefully_closed = self.try_graceful_browser_close()?;
        self.cdp_writer.take();
        if !gracefully_closed {
            terminate_exact_process_group(
                &mut self.child,
                self.process_group_id,
                &self.process_group_identity,
            )?;
        }
        self.cdp_reader.take();
        if self.cleanup_profile_on_shutdown {
            if !self.profile_root.starts_with(&self.private_parent) {
                return Err(BrowserError::Process(
                    "ephemeral profile root no longer belongs to private parent".to_owned(),
                ));
            }
            match fs::remove_dir_all(&self.profile_root) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(BrowserError::Io(error)),
            }
        }
        self.closed = true;
        Ok(())
    }

    fn try_graceful_browser_close(&mut self) -> Result<bool, BrowserError> {
        if self.child.try_wait()?.is_some() {
            wait_for_group_absence(self.process_group_id, PROCESS_KILL_GRACE)?;
            return Ok(true);
        }
        if self.transport_uncertain || self.cdp_writer.is_none() {
            return Ok(false);
        }
        verify_current_group_identity(self.process_group_id, &self.process_group_identity)?;
        if self
            .dispatch_cdp_request("Browser.close", serde_json::json!({}), None)
            .is_err()
        {
            return Ok(false);
        }
        if !wait_child_until(&mut self.child, PROCESS_BROWSER_CLOSE_GRACE)? {
            return Ok(false);
        }
        let _ = self.child.wait()?;
        wait_for_group_absence(self.process_group_id, PROCESS_KILL_GRACE)?;
        Ok(true)
    }
}

impl Drop for BrowserAdapter {
    fn drop(&mut self) {
        let _ = self.shutdown_inner();
    }
}

struct CdpFrameReader {
    receiver: Receiver<ReaderMessage>,
    _thread: thread::JoinHandle<()>,
}

impl CdpFrameReader {
    fn spawn<R: Read + Send + 'static>(mut reader: R, max_frame_bytes: usize) -> Self {
        let (sender, receiver) = mpsc::channel();
        let handle = thread::spawn(move || {
            let mut frame = Vec::with_capacity(max_frame_bytes.min(16 * 1024));
            let mut chunk = [0_u8; 8 * 1024];
            let mut overflow = false;
            loop {
                let read = match reader.read(&mut chunk) {
                    Ok(0) => {
                        let _ = sender.send(ReaderMessage::Closed);
                        break;
                    }
                    Ok(read) => read,
                    Err(error) => {
                        let _ = sender.send(ReaderMessage::Io(error.to_string()));
                        break;
                    }
                };
                for byte in &chunk[..read] {
                    if *byte == 0 {
                        if overflow {
                            if sender.send(ReaderMessage::Overflow).is_err() {
                                return;
                            }
                            overflow = false;
                            frame.clear();
                        } else if !frame.is_empty() {
                            if sender
                                .send(ReaderMessage::Frame(std::mem::take(&mut frame)))
                                .is_err()
                            {
                                return;
                            }
                            frame = Vec::with_capacity(max_frame_bytes.min(16 * 1024));
                        }
                    } else if !overflow {
                        if frame.len() < max_frame_bytes {
                            frame.push(*byte);
                        } else {
                            overflow = true;
                            frame.clear();
                        }
                    }
                }
            }
        });
        Self {
            receiver,
            _thread: handle,
        }
    }

    fn recv_timeout(&self, timeout: Duration) -> Result<Vec<u8>, String> {
        match self.receiver.recv_timeout(timeout) {
            Ok(ReaderMessage::Frame(frame)) => Ok(frame),
            Ok(ReaderMessage::Overflow) => {
                Err("CDP response exceeded configured frame bound".into())
            }
            Ok(ReaderMessage::Io(detail)) => Err(format!("CDP reader failed: {detail}")),
            Ok(ReaderMessage::Closed) => Err("CDP response pipe closed".to_owned()),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                Err("timed out waiting for CDP frame".to_owned())
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                Err("CDP reader thread disconnected".to_owned())
            }
        }
    }
}

enum ReaderMessage {
    Frame(Vec<u8>),
    Overflow,
    Io(String),
    Closed,
}

fn chrome_args(profile_root: &Path, caller_chrome_args: &[String]) -> Vec<String> {
    let mut args = vec![
        "--headless=new".to_owned(),
        "--remote-debugging-pipe".to_owned(),
        "--no-first-run".to_owned(),
        "--no-default-browser-check".to_owned(),
        "--disable-background-networking".to_owned(),
        "--disable-component-update".to_owned(),
        "--disable-sync".to_owned(),
        "--metrics-recording-only".to_owned(),
        "--disable-breakpad".to_owned(),
    ];
    args.extend(caller_chrome_args.iter().cloned());
    args.push(format!("--user-data-dir={}", profile_root.display()));
    args.push("about:blank".to_owned());
    args
}

fn browser_process_spec(
    chrome_path: &Path,
    chrome_args: &[String],
    private_parent: &Path,
    profile_root: &Path,
) -> BrowserProcessSpec {
    let mut args = vec![
        "-c".to_owned(),
        "exec 3<&0 4>&1\nexec 0</dev/null 1>/dev/null\nexec \"$@\"".to_owned(),
        "sovereign-browser".to_owned(),
        chrome_path.display().to_string(),
    ];
    args.extend(chrome_args.iter().cloned());
    BrowserProcessSpec {
        executable: PathBuf::from("/bin/sh"),
        args,
        environment: BTreeMap::from([("TMPDIR".to_owned(), profile_root.display().to_string())]),
        working_directory: private_parent.to_path_buf(),
    }
}

fn validate_caller_chrome_args(args: &[String]) -> Result<(), BrowserError> {
    if args.len() > MAX_CALLER_CHROME_ARGS
        || args.iter().map(String::len).sum::<usize>() > MAX_CALLER_CHROME_ARG_BYTES
    {
        return Err(BrowserError::ResourceLimit(
            "caller Chrome arguments exceed static browser launch bounds".to_owned(),
        ));
    }
    for arg in args {
        if arg.is_empty()
            || !arg.starts_with("--")
            || arg.bytes().any(|byte| byte.is_ascii_control() || byte == 0)
        {
            return Err(BrowserError::InvalidRequest(
                "caller Chrome arguments must be non-empty flag arguments without control bytes"
                    .to_owned(),
            ));
        }
        let key = arg.split_once('=').map_or(arg.as_str(), |(key, _)| key);
        if matches!(
            key,
            "--remote-debugging-pipe"
                | "--remote-debugging-port"
                | "--user-data-dir"
                | "--profile-directory"
        ) {
            return Err(BrowserError::InvalidRequest(format!(
                "caller Chrome argument conflicts with adapter-owned browser mechanics: {key}"
            )));
        }
    }
    Ok(())
}

fn canonical_executable(path: &Path) -> Result<PathBuf, BrowserError> {
    if !path.is_absolute() {
        return Err(BrowserError::InvalidRequest(
            "Chrome executable path must be absolute".to_owned(),
        ));
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(BrowserError::InvalidRequest(
            "Chrome executable must be a regular non-symlink file".to_owned(),
        ));
    }
    path.canonicalize().map_err(BrowserError::Io)
}

fn canonical_private_directory(path: &Path, label: &str) -> Result<PathBuf, BrowserError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(BrowserError::InvalidRequest(format!(
            "{label} must be a stable directory"
        )));
    }
    let canonical = path.canonicalize()?;
    let canonical_metadata = fs::symlink_metadata(&canonical)?;
    if canonical_metadata.file_type().is_symlink()
        || !canonical_metadata.is_dir()
        || canonical_metadata.permissions().mode() & 0o077 != 0
    {
        return Err(BrowserError::InvalidRequest(format!(
            "{label} canonical path is not a stable owner-only directory"
        )));
    }
    Ok(canonical)
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

fn create_ephemeral_profile(
    private_parent: &Path,
    lease: &BrowserLease,
) -> Result<PathBuf, BrowserError> {
    let digest = lease.binding_digest();
    let suffix = digest
        .strip_prefix("sha256:")
        .unwrap_or(&digest)
        .chars()
        .take(12)
        .collect::<String>();
    for _ in 0..16 {
        let nonce = BROWSER_NONCE.fetch_add(1, Ordering::Relaxed);
        let candidate = private_parent.join(format!(
            ".sovereign-browser-{}-{nonce}-{suffix}",
            std::process::id()
        ));
        match create_private_directory(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(BrowserError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Err(BrowserError::ResourceLimit(
        "could not allocate a unique ephemeral browser profile".to_owned(),
    ))
}

fn create_private_directory(path: &Path) -> Result<(), BrowserError> {
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.permissions().mode() & 0o077 != 0
    {
        let _ = fs::remove_dir(path);
        return Err(BrowserError::InvalidRequest(
            "browser private directory is not owner-only".to_owned(),
        ));
    }
    Ok(())
}

fn observe_exact_group_identity(pgid: u32) -> Result<String, BrowserError> {
    let deadline = Instant::now() + Duration::from_millis(500);
    loop {
        match process_group_leader_identity(pgid)
            .map_err(|error| BrowserError::Process(error.to_string()))?
        {
            Some(identity) => return Ok(identity),
            None if Instant::now() < deadline => thread::sleep(PROCESS_POLL_INTERVAL),
            None => {
                return Err(BrowserError::Process(
                    "spawned Chrome process-group identity could not be observed".to_owned(),
                ));
            }
        }
    }
}

fn spawn_browser_process(
    command: &mut Command,
) -> Result<(Child, u32, String), BrowserSpawnFailure> {
    let mut child = command
        .spawn()
        .map_err(|error| BrowserSpawnFailure::never_spawned(BrowserError::Io(error)))?;
    let process_group_id = child.id();
    match observe_exact_group_identity(process_group_id) {
        Ok(identity) => Ok((child, process_group_id, identity)),
        Err(error) => {
            let absence_proven =
                prove_absence_without_identity(&mut child, process_group_id).is_ok();
            Err(BrowserSpawnFailure::after_spawn(
                error,
                absence_proven,
                None,
            ))
        }
    }
}

fn prepared_browser_command(
    prepared: &PreparedBrowserLaunch,
    isolated: &IsolatedCommand,
) -> Command {
    let mut command = Command::new(&isolated.executable);
    command
        .args(&isolated.args)
        .current_dir(&prepared.process_spec.working_directory)
        .env_clear()
        .envs(&prepared.process_spec.environment)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0);
    command
}

fn terminate_exact_process_group(
    child: &mut Child,
    pgid: u32,
    expected_identity: &str,
) -> Result<(), BrowserError> {
    if let Some(status) = child.try_wait()? {
        let _ = status;
        return wait_for_group_absence(pgid, PROCESS_KILL_GRACE);
    }
    verify_current_group_identity(pgid, expected_identity)?;
    signal_process_group(pgid, "-TERM")?;
    if wait_child_until(child, PROCESS_TERM_GRACE)? {
        child.wait()?;
        return wait_for_group_absence(pgid, PROCESS_KILL_GRACE);
    }
    verify_current_group_identity(pgid, expected_identity)?;
    signal_process_group(pgid, "-KILL")?;
    let _ = child.wait()?;
    wait_for_group_absence(pgid, PROCESS_KILL_GRACE)
}

fn prove_absence_without_identity(child: &mut Child, pgid: u32) -> Result<(), BrowserError> {
    if child.try_wait()?.is_some() {
        return wait_for_group_absence(pgid, PROCESS_KILL_GRACE);
    }
    child.kill()?;
    let _ = child.wait()?;
    wait_for_group_absence(pgid, PROCESS_KILL_GRACE)
}

fn verify_current_group_identity(pgid: u32, expected_identity: &str) -> Result<(), BrowserError> {
    match process_group_leader_identity(pgid)
        .map_err(|error| BrowserError::Process(error.to_string()))?
    {
        Some(current) if current == expected_identity => Ok(()),
        Some(_) => Err(BrowserError::Process(format!(
            "Chrome process-group leader identity changed for {pgid}; refusing signal"
        ))),
        None => Err(BrowserError::Process(format!(
            "Chrome process-group leader {pgid} disappeared before exact cleanup"
        ))),
    }
}

fn signal_process_group(pgid: u32, signal: &str) -> Result<(), BrowserError> {
    let status = Command::new("/bin/kill")
        .env_clear()
        .args([signal, "--", &format!("-{pgid}")])
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(BrowserError::Process(format!(
            "failed to send {signal} to Chrome process group {pgid}"
        )))
    }
}

fn wait_child_until(child: &mut Child, timeout: Duration) -> Result<bool, BrowserError> {
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait()?.is_some() {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        thread::sleep(PROCESS_POLL_INTERVAL);
    }
}

fn wait_for_group_absence(pgid: u32, timeout: Duration) -> Result<(), BrowserError> {
    let deadline = Instant::now() + timeout;
    loop {
        if !process_group_present(pgid)? {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(BrowserError::Process(format!(
                "Chrome process group {pgid} still has members after cleanup"
            )));
        }
        thread::sleep(PROCESS_POLL_INTERVAL);
    }
}

fn process_group_present(pgid: u32) -> Result<bool, BrowserError> {
    let output = Command::new("/bin/ps")
        .env_clear()
        .args(["-axo", "pgid="])
        .output()?;
    if !output.status.success() {
        return Err(BrowserError::Process(
            "cannot observe Chrome process-group membership".to_owned(),
        ));
    }
    let pgid = pgid.to_string();
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .any(|line| line.trim() == pgid))
}

fn page_target_ids(response: &serde_json::Value) -> Result<Vec<String>, BrowserError> {
    let result = cdp_result(response, "Target.getTargets")?;
    let targets = result
        .get("targetInfos")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            BrowserError::Protocol("Target.getTargets omitted targetInfos".to_owned())
        })?;
    targets
        .iter()
        .filter(|target| target.get("type").and_then(serde_json::Value::as_str) == Some("page"))
        .map(|target| required_value_string(target, "targetId", "Target.getTargets"))
        .collect()
}

fn assess_single_tab_targets(
    expected_target_id: &str,
    page_targets: &[String],
    event_targets: &BTreeSet<String>,
) -> (bool, BTreeSet<String>) {
    let expected_present = page_targets
        .iter()
        .any(|target_id| target_id == expected_target_id);
    let mut unexpected = event_targets.clone();
    unexpected.extend(
        page_targets
            .iter()
            .filter(|target_id| target_id.as_str() != expected_target_id)
            .cloned(),
    );
    (expected_present, unexpected)
}

fn classify_attached_target(
    value: &serde_json::Value,
    main_target_id: &str,
) -> Result<Option<AttachedTargetDisposition>, BrowserError> {
    if value.get("method").and_then(serde_json::Value::as_str) != Some("Target.attachedToTarget") {
        return Ok(None);
    }
    let params = value.get("params").ok_or_else(|| {
        BrowserError::Protocol("Target.attachedToTarget omitted params".to_owned())
    })?;
    let session_id = required_value_string(params, "sessionId", "Target.attachedToTarget")?;
    let target_info = params.get("targetInfo").ok_or_else(|| {
        BrowserError::Protocol("Target.attachedToTarget omitted targetInfo".to_owned())
    })?;
    let target_id = required_value_string(
        target_info,
        "targetId",
        "Target.attachedToTarget targetInfo",
    )?;
    let target_type =
        required_value_string(target_info, "type", "Target.attachedToTarget targetInfo")?;
    if target_type == "page" {
        if target_id != main_target_id {
            return Ok(Some(AttachedTargetDisposition::CloseUnexpectedPage {
                target_id,
            }));
        }
        return Ok(Some(AttachedTargetDisposition::ResumeMainPage {
            session_id,
        }));
    }
    Ok(Some(AttachedTargetDisposition::CloseContainedChild {
        target_id,
    }))
}

fn classify_fetch_request_paused(
    value: &serde_json::Value,
    main_frame_id: &str,
    chain_index: u32,
) -> Result<Option<FetchPausedRequest>, BrowserError> {
    if value.get("method").and_then(serde_json::Value::as_str) != Some("Fetch.requestPaused") {
        return Ok(None);
    }
    let params = value
        .get("params")
        .ok_or_else(|| BrowserError::Protocol("Fetch.requestPaused omitted params".to_owned()))?;
    let interception_id = required_value_string(params, "requestId", "Fetch.requestPaused")?;
    let request = params
        .get("request")
        .ok_or_else(|| BrowserError::Protocol("Fetch.requestPaused omitted request".to_owned()))?;
    let method = required_value_string(request, "method", "Fetch.requestPaused request")?;
    let resource_type = params
        .get("resourceType")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let frame_id = params
        .get("frameId")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_owned();
    if resource_type != "Document" || frame_id != main_frame_id {
        return Ok(Some(FetchPausedRequest::Other {
            interception_id,
            method,
        }));
    }
    Ok(Some(FetchPausedRequest::TopLevel(
        BrowserDocumentRequestObservation {
            schema_version: BROWSER_SCHEMA_VERSION,
            interception_id,
            frame_id,
            url: required_value_string(request, "url", "Fetch.requestPaused request")?,
            method,
            kind: if chain_index == 0 {
                BrowserDocumentRequestKind::Initial
            } else {
                BrowserDocumentRequestKind::Redirect
            },
            chain_index,
        },
    )))
}

fn classify_fetch_auth_required(
    value: &serde_json::Value,
    binding: Option<&BrowserProxyAuthBinding>,
    credentials_sent: bool,
) -> Result<Option<FetchAuthDecision>, BrowserError> {
    if value.get("method").and_then(serde_json::Value::as_str) != Some("Fetch.authRequired") {
        return Ok(None);
    }
    let params = value
        .get("params")
        .ok_or_else(|| BrowserError::Protocol("Fetch.authRequired omitted params".to_owned()))?;
    let request_id = required_value_string(params, "requestId", "Fetch.authRequired")?;
    let challenge = params.get("authChallenge").ok_or_else(|| {
        BrowserError::Protocol("Fetch.authRequired omitted authChallenge".to_owned())
    })?;
    let source = required_value_string(challenge, "source", "Fetch.authRequired challenge")?;
    let origin = required_value_string(challenge, "origin", "Fetch.authRequired challenge")?;
    let scheme = required_value_string(challenge, "scheme", "Fetch.authRequired challenge")?;
    let realm = challenge
        .get("realm")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");

    let exact_proxy_challenge = binding.is_some_and(|binding| {
        source == "Proxy"
            && origin == binding.origin
            && scheme.eq_ignore_ascii_case(&binding.scheme)
            && realm == binding.realm
    });
    if exact_proxy_challenge && !credentials_sent {
        return Ok(Some(FetchAuthDecision::Provide { request_id }));
    }
    Ok(Some(FetchAuthDecision::Cancel { request_id }))
}

fn valid_http_method_ceiling_entry(method: &str) -> bool {
    !method.is_empty()
        && method.len() <= 32
        && method
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
}

fn request_method_allowed_by_ceiling(ceiling: Option<&BTreeSet<String>>, method: &str) -> bool {
    ceiling.is_none_or(|ceiling| ceiling.contains(&method.to_ascii_uppercase()))
}

fn non_top_level_request_method_allowed(ceiling: Option<&BTreeSet<String>>, method: &str) -> bool {
    (method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD"))
        && request_method_allowed_by_ceiling(ceiling, method)
}

fn cdp_result<'a>(
    response: &'a serde_json::Value,
    method: &str,
) -> Result<&'a serde_json::Value, BrowserError> {
    if let Some(error) = response.get("error") {
        return Err(BrowserError::Protocol(format!(
            "{method} returned CDP error: {}",
            error.to_string().chars().take(1024).collect::<String>()
        )));
    }
    response
        .get("result")
        .ok_or_else(|| BrowserError::Protocol(format!("{method} omitted result")))
}

fn runtime_value<'a>(
    response: &'a serde_json::Value,
    method: &str,
) -> Result<&'a serde_json::Value, BrowserError> {
    let result = cdp_result(response, method)?;
    if let Some(exception) = result.get("exceptionDetails") {
        return Err(BrowserError::Protocol(format!(
            "{method} JavaScript exception: {}",
            exception.to_string().chars().take(1024).collect::<String>()
        )));
    }
    result
        .get("result")
        .and_then(|remote| remote.get("value"))
        .ok_or_else(|| BrowserError::Protocol(format!("{method} omitted returnByValue payload")))
}

fn required_string(
    object: &serde_json::Value,
    key: &str,
    method: &str,
) -> Result<String, BrowserError> {
    required_value_string(object, key, method)
}

fn required_value_string(
    object: &serde_json::Value,
    key: &str,
    context: &str,
) -> Result<String, BrowserError> {
    object
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| BrowserError::Protocol(format!("{context} omitted string field {key}")))
}

fn decoded_base64_len(encoded: &str) -> Option<usize> {
    let input = encoded.as_bytes();
    if input.is_empty() || !input.len().is_multiple_of(4) {
        return None;
    }
    let padding = if input.ends_with(b"==") {
        2
    } else {
        usize::from(input.ends_with(b"="))
    };
    let content_len = input.len().checked_sub(padding)?;
    if input[..content_len]
        .iter()
        .any(|byte| !matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/'))
        || input[content_len..].iter().any(|byte| *byte != b'=')
    {
        return None;
    }
    input
        .len()
        .checked_div(4)?
        .checked_mul(3)?
        .checked_sub(padding)
}

fn main_frame_id(response: &serde_json::Value) -> Result<String, BrowserError> {
    let result = cdp_result(response, "Page.getFrameTree")?;
    let frame = result
        .get("frameTree")
        .and_then(|tree| tree.get("frame"))
        .ok_or_else(|| BrowserError::Protocol("Page.getFrameTree omitted main frame".to_owned()))?;
    required_value_string(frame, "id", "Page.getFrameTree main frame")
}

fn navigation_response_is_download(response: &serde_json::Value) -> Result<bool, BrowserError> {
    let result = cdp_result(response, "Page.navigate")?;
    if result
        .get("isDownload")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        return Ok(true);
    }
    if let Some(error_text) = result
        .get("errorText")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
    {
        return Err(BrowserError::Protocol(format!(
            "Page.navigate reported failure: {error_text}"
        )));
    }
    Ok(false)
}

fn validate_navigation_response(response: &serde_json::Value) -> Result<(), BrowserError> {
    navigation_response_is_download(response).map(|_| ())
}

fn validate_submit_response(response: &serde_json::Value) -> Result<(), BrowserError> {
    let value = runtime_value(response, "Runtime.evaluate")?;
    if value.get("submitted").and_then(serde_json::Value::as_bool) == Some(true) {
        return Ok(());
    }
    let detail = value
        .get("error")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("form submission did not complete synchronously");
    Err(BrowserError::Protocol(detail.to_owned()))
}

fn form_submit_expression(selector_json: &str) -> String {
    format!(
        "(() => {{ const form = document.querySelector({selector_json}); if (!(form instanceof HTMLFormElement)) return {{submitted:false,error:'selector did not resolve to a form'}}; if (typeof form.requestSubmit === 'function') form.requestSubmit(); else form.submit(); return {{submitted:true}}; }})()"
    )
}

fn form_inspection_expression(selector_json: &str) -> String {
    format!(
        r"(() => {{
const form = document.querySelector({selector_json});
if (!(form instanceof HTMLFormElement)) return {{found:false}};
const credentialPattern = /(?:pass(?:word|wd)?|token|secret|credential|authorization|cookie|session|api[-_\s]?key|client[-_\s]?secret|access[-_\s]?token|one[-_\s]?time[-_\s]?code)/i;
const controls = Array.from(form.querySelectorAll('input,textarea,select,button'));
const sensitiveInputsPresent = controls.some((control) => {{
  const type = String(control.getAttribute('type') || '').toLowerCase();
  const autocomplete = String(control.getAttribute('autocomplete') || '').toLowerCase();
  const names = [control.getAttribute('name'), control.getAttribute('id'), control.getAttribute('aria-label')].filter(Boolean).join(' ');
  return type === 'password' || credentialPattern.test(autocomplete) || credentialPattern.test(names);
}});
const structuralParts = controls.map((control) => {{
  const tag = control.tagName.toLowerCase();
  const type = String(control.getAttribute('type') || '').toLowerCase();
  const name = String(control.getAttribute('name') || '');
  const autocomplete = String(control.getAttribute('autocomplete') || '').toLowerCase();
  return [tag, type, name, autocomplete, control.hasAttribute('required') ? 'required' : '', control.hasAttribute('disabled') ? 'disabled' : ''].join(':');
}});
const structure = `${{form.tagName.toLowerCase()}}|${{structuralParts.join('|')}}|count=${{controls.length}}`;
return {{found:true,pageUrl:location.href,method:String(form.method || 'get').toUpperCase(),actionUrl:form.action || location.href,structure,sensitiveInputsPresent}};
}})()"
    )
}

fn validate_selector(selector: &str) -> Result<(), BrowserError> {
    if selector.trim().is_empty() {
        return Err(BrowserError::InvalidRequest(
            "form selector must be non-empty".to_owned(),
        ));
    }
    if selector.len() > MAX_SELECTOR_BYTES {
        return Err(BrowserError::ResourceLimit(
            "form selector exceeded browser adapter bound".to_owned(),
        ));
    }
    Ok(())
}

fn validate_sha256_digest(value: &str, label: &str) -> Result<(), BrowserError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(BrowserError::InvalidRequest(format!(
            "{label} must use sha256:<64 lowercase hex>"
        )));
    };
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(BrowserError::InvalidRequest(format!(
            "{label} must use sha256:<64 lowercase hex>"
        )));
    }
    Ok(())
}

fn digest_string(namespace: &str, value: &str) -> String {
    let mut hasher = Sha256::new();
    digest_field(&mut hasher, namespace);
    digest_field(&mut hasher, value);
    format!("sha256:{:x}", hasher.finalize())
}

fn strip_url_query_fragment(url: &str) -> String {
    let without_fragment = url.split_once('#').map_or(url, |(head, _)| head);
    let without_query = without_fragment
        .split_once('?')
        .map_or(without_fragment, |(head, _)| head);
    if let Some((scheme, rest)) = without_query.split_once("://") {
        let (authority, suffix) = rest
            .split_once('/')
            .map_or((rest, ""), |(authority, suffix)| (authority, suffix));
        let safe_authority = authority
            .rsplit_once('@')
            .map_or(authority, |(_, host)| host);
        if suffix.is_empty() {
            format!("{scheme}://{safe_authority}")
        } else {
            format!("{scheme}://{safe_authority}/{suffix}")
        }
    } else {
        without_query.to_owned()
    }
}

fn synopsis_expression(max_text_bytes: usize, max_dom_bytes: usize) -> String {
    format!(
        r#"(() => {{
const enc = new TextEncoder();
const bound = (value, maxBytes) => {{
  const source = String(value ?? '');
  if (enc.encode(source).length <= maxBytes) return [source, false];
  let low = 0;
  let high = source.length;
  let best = 0;
  while (low <= high) {{
    const mid = Math.floor((low + high) / 2);
    if (enc.encode(source.slice(0, mid)).length <= maxBytes) {{ best = mid; low = mid + 1; }}
    else {{ high = mid - 1; }}
  }}
  return [source.slice(0, best), true];
}};
const credentialPattern = /(?:pass(?:word|wd)?|token|secret|credential|authorization|bearer|cookie|session|api[-_\s]?key|client[-_\s]?secret|access[-_\s]?token)/i;
const controls = Array.from(document.querySelectorAll('input,textarea,select'));
const formControlsPresent = controls.length > 0;
const passwordControlPresent = !!document.querySelector('input[type="password" i]');
let sensitiveAttributePresent = false;
for (const el of document.querySelectorAll('*')) {{
  for (const attr of Array.from(el.attributes || [])) {{
    if (attr.name.toLowerCase() === 'value' || credentialPattern.test(attr.name) || credentialPattern.test(attr.value || '')) {{
      sensitiveAttributePresent = true;
      break;
    }}
  }}
  if (sensitiveAttributePresent) break;
}}
const rawText = document.body ? document.body.innerText : '';
const credentialTextPatternPresent = credentialPattern.test(rawText);
const sensitive = formControlsPresent || passwordControlPresent || sensitiveAttributePresent || credentialTextPatternPresent;
let safeUrl = '';
try {{
  const parsed = new URL(location.href);
  if (parsed.protocol === 'http:' || parsed.protocol === 'https:') safeUrl = `${{parsed.protocol}}//${{parsed.host}}${{parsed.pathname}}`;
  else safeUrl = `${{parsed.protocol}}${{parsed.pathname}}`;
}} catch (_) {{ safeUrl = ''; }}
let safeText = '';
let safeDom = '';
let safeTitle = '';
if (!sensitive && document.documentElement) {{
  const clone = document.documentElement.cloneNode(true);
  for (const node of Array.from(clone.querySelectorAll('script,style,template,noscript,input,textarea,select'))) node.remove();
  for (const el of clone.querySelectorAll('*')) for (const attr of Array.from(el.attributes || [])) el.removeAttribute(attr.name);
  safeText = rawText;
  safeDom = clone.outerHTML;
  safeTitle = document.title || '';
}}
const text = bound(safeText, {max_text_bytes});
const dom = bound(safeDom, {max_dom_bytes});
return {{url: safeUrl, title: safeTitle, text: text[0], textTruncated: text[1], dom: dom[0], domTruncated: dom[1], sensitive, formControlsPresent, passwordControlPresent, sensitiveAttributePresent, credentialTextPatternPresent}};
}})()"#
    )
}

fn truncate_utf8_bytes(value: &mut String, max_bytes: usize) -> bool {
    if value.len() <= max_bytes {
        return false;
    }
    let mut boundary = max_bytes;
    while boundary > 0 && !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    value.truncate(boundary);
    true
}

fn validate_http_url_shape(url: &str) -> Result<(), BrowserError> {
    if url.is_empty()
        || url
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(BrowserError::InvalidRequest(
            "browser URL contains whitespace/control bytes or is empty".to_owned(),
        ));
    }
    let (scheme, rest) = url.split_once("://").ok_or_else(|| {
        BrowserError::InvalidRequest(
            "browser actions permit only absolute http/https URL shape".to_owned(),
        )
    })?;
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return Err(BrowserError::InvalidRequest(
            "browser actions permit only absolute http/https URL shape".to_owned(),
        ));
    }
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() || authority.contains('@') || authority.contains('\\') {
        return Err(BrowserError::InvalidRequest(
            "browser URL requires an authority and forbids userinfo".to_owned(),
        ));
    }
    if let Some(ipv6) = authority.strip_prefix('[') {
        let Some(close) = ipv6.find(']') else {
            return Err(BrowserError::InvalidRequest(
                "browser URL has malformed bracketed IPv6 authority".to_owned(),
            ));
        };
        let address = &ipv6[..close];
        let suffix = &ipv6[close + 1..];
        if address.is_empty() || address.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(BrowserError::InvalidRequest(
                "browser URL has malformed bracketed IPv6 authority".to_owned(),
            ));
        }
        if !suffix.is_empty() {
            let port = suffix.strip_prefix(':').ok_or_else(|| {
                BrowserError::InvalidRequest(
                    "browser URL has malformed IPv6 port suffix".to_owned(),
                )
            })?;
            validate_url_port(port)?;
        }
        return Ok(());
    }
    if authority.matches(':').count() > 1 {
        return Err(BrowserError::InvalidRequest(
            "browser URL requires bracket notation for IPv6 hosts".to_owned(),
        ));
    }
    let host = match authority.rsplit_once(':') {
        Some((host, port)) => {
            validate_url_port(port)?;
            host
        }
        None => authority,
    };
    if host.is_empty() {
        return Err(BrowserError::InvalidRequest(
            "browser URL authority has an invalid host/port shape".to_owned(),
        ));
    }
    Ok(())
}

fn validate_url_port(port: &str) -> Result<(), BrowserError> {
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(BrowserError::InvalidRequest(
            "browser URL port must be numeric".to_owned(),
        ));
    }
    let port = port.parse::<u16>().map_err(|_| {
        BrowserError::InvalidRequest("browser URL port is outside u16 range".to_owned())
    })?;
    if port == 0 {
        return Err(BrowserError::InvalidRequest(
            "browser URL port must be non-zero".to_owned(),
        ));
    }
    Ok(())
}

fn validate_relative_path(path: &Path) -> Result<(), BrowserError> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err(BrowserError::InvalidRequest(
            "download path must be non-empty and relative".to_owned(),
        ));
    }
    if path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err(BrowserError::InvalidRequest(
            "download path traversal is forbidden".to_owned(),
        ));
    }
    Ok(())
}

fn validate_download_guid(guid: &str) -> Result<(), BrowserError> {
    if guid.is_empty()
        || guid.len() > MAX_DOWNLOAD_GUID_BYTES
        || !guid
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(BrowserError::Protocol(
            "browser download GUID is empty, oversized, or not a safe filename component"
                .to_owned(),
        ));
    }
    Ok(())
}

fn require_enabled_download_event(
    policy: BrowserDownloadPolicy,
    download_root: Option<&Path>,
) -> Result<&Path, BrowserError> {
    if policy != BrowserDownloadPolicy::Allow {
        return Err(BrowserError::Protocol(
            "Chrome emitted a download event while caller policy denies downloads".to_owned(),
        ));
    }
    download_root.ok_or_else(|| {
        BrowserError::Protocol(
            "Chrome emitted a download event without an exact caller-owned download root"
                .to_owned(),
        )
    })
}

fn validate_completed_download_file_path(
    download_root: &Path,
    guid: &str,
    file_path: &str,
) -> Result<(), BrowserError> {
    if file_path.is_empty() {
        return Err(BrowserError::Protocol(
            "Browser.downloadProgress completed with an empty filePath".to_owned(),
        ));
    }
    let expected = download_root.join(guid);
    let reported = Path::new(file_path);
    if reported != expected {
        return Err(BrowserError::Protocol(
            "Browser.downloadProgress filePath disagrees with exact download-root/GUID path"
                .to_owned(),
        ));
    }
    if reported.canonicalize()? != expected {
        return Err(BrowserError::Protocol(
            "Browser.downloadProgress filePath does not resolve to exact download-root/GUID path"
                .to_owned(),
        ));
    }
    Ok(())
}

fn ensure_no_symlink_components(root: &Path, relative_parent: &Path) -> Result<(), BrowserError> {
    let mut cursor = root.to_path_buf();
    for component in relative_parent.components() {
        if matches!(component, Component::CurDir) {
            continue;
        }
        cursor.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&cursor)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(BrowserError::InvalidRequest(format!(
                "download parent component is not a stable directory: {}",
                cursor.display()
            )));
        }
    }
    Ok(())
}

fn validate_content_type(content_type: &str) -> Result<(), BrowserError> {
    if content_type.trim().is_empty()
        || content_type.len() > MAX_CONTENT_TYPE_BYTES
        || !content_type
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ' || byte == b'\t')
        || content_type.contains(['\r', '\n'])
    {
        return Err(BrowserError::InvalidRequest(
            "download content type is malformed or oversized".to_owned(),
        ));
    }
    Ok(())
}

fn digest_field(hasher: &mut Sha256, value: &str) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::{
        AttachedTargetDisposition, BROWSER_SCHEMA_VERSION, BrowserAction, BrowserAdapter,
        BrowserAdapterConfig, BrowserDocumentRequestKind, BrowserDownloadPolicy,
        BrowserDownloadTerminalState, BrowserDownloadTracker, BrowserError, BrowserLease,
        BrowserProxyAuthBinding, BrowserSensitivePageReason, BrowserSpawnBinding,
        BrowserSpawnFailure, BrowserSpawnState, FetchAuthDecision, FetchPausedRequest,
        assess_single_tab_targets, classify_attached_target, classify_fetch_auth_required,
        classify_fetch_request_paused, navigation_response_is_download,
        non_top_level_request_method_allowed, request_method_allowed_by_ceiling,
    };
    use serde_json::json;
    use std::collections::BTreeSet;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn spawn_failure_unknown_preserves_exact_binding() {
        let binding = BrowserSpawnBinding {
            process_group_id: 42,
            process_group_identity: "42:42:start".to_owned(),
        };
        let failure = BrowserSpawnFailure::after_spawn(
            BrowserError::Process("cleanup became ambiguous".to_owned()),
            false,
            Some(binding.clone()),
        );
        assert_eq!(
            failure.state(),
            &BrowserSpawnState::Unknown {
                binding: Some(binding)
            }
        );
    }

    #[test]
    fn download_tracker_uses_only_guid_path_and_preserves_terminal_order() {
        let root = Path::new("/tmp/sovereign-download-tracker");
        let mut tracker = BrowserDownloadTracker::default();
        let will_begin = json!({
            "method": "Browser.downloadWillBegin",
            "params": {
                "guid": "guid-safe-001",
                "url": "https://example.test/download",
                "suggestedFilename": "../../escape.bin"
            }
        });
        assert!(
            tracker
                .observe(&will_begin, BrowserDownloadPolicy::Allow, Some(root))
                .unwrap_or_else(|error| panic!("observe download start failed: {error}"))
        );
        let progress = json!({
            "method": "Browser.downloadProgress",
            "params": {"guid": "guid-safe-001", "state": "inProgress"}
        });
        tracker
            .observe(&progress, BrowserDownloadPolicy::Allow, Some(root))
            .unwrap_or_else(|error| panic!("observe download progress failed: {error}"));
        let completed = json!({
            "method": "Browser.downloadProgress",
            "params": {"guid": "guid-safe-001", "state": "completed"}
        });
        tracker
            .observe(&completed, BrowserDownloadPolicy::Allow, Some(root))
            .unwrap_or_else(|error| panic!("observe download completion failed: {error}"));
        let terminal = tracker
            .pop_terminal()
            .unwrap_or_else(|| panic!("completed download omitted terminal observation"));
        assert_eq!(terminal.guid, "guid-safe-001");
        assert_eq!(terminal.relative_path, Path::new("guid-safe-001"));
        assert_eq!(terminal.state, BrowserDownloadTerminalState::Completed);
        assert!(tracker.pop_terminal().is_none());
        assert!(
            tracker
                .observe(&completed, BrowserDownloadPolicy::Allow, Some(root))
                .is_err(),
            "duplicate terminal event must fail closed"
        );

        let second = json!({
            "method": "Browser.downloadWillBegin",
            "params": {"guid": "guid-safe-002", "suggestedFilename": "harmless.txt"}
        });
        tracker
            .observe(&second, BrowserDownloadPolicy::Allow, Some(root))
            .unwrap_or_else(|error| panic!("observe second download start failed: {error}"));
        let canceled = json!({
            "method": "Browser.downloadProgress",
            "params": {"guid": "guid-safe-002", "state": "canceled"}
        });
        tracker
            .observe(&canceled, BrowserDownloadPolicy::Allow, Some(root))
            .unwrap_or_else(|error| panic!("observe canceled download failed: {error}"));
        let terminal = tracker
            .pop_terminal()
            .unwrap_or_else(|| panic!("canceled download omitted terminal observation"));
        assert_eq!(terminal.relative_path, Path::new("guid-safe-002"));
        assert_eq!(terminal.state, BrowserDownloadTerminalState::Canceled);
    }

    #[test]
    fn download_tracker_fails_closed_for_untrusted_or_conflicting_events() {
        let root = Path::new("/tmp/sovereign-download-tracker");
        let start = json!({
            "method": "Browser.downloadWillBegin",
            "params": {"guid": "guid-safe-003", "suggestedFilename": "artifact.bin"}
        });
        let mut denied = BrowserDownloadTracker::default();
        assert!(
            denied
                .observe(&start, BrowserDownloadPolicy::Deny, None)
                .is_err()
        );

        let mut tracker = BrowserDownloadTracker::default();
        tracker
            .observe(&start, BrowserDownloadPolicy::Allow, Some(root))
            .unwrap_or_else(|error| panic!("observe tracked start failed: {error}"));
        assert!(
            tracker
                .observe(&start, BrowserDownloadPolicy::Allow, Some(root))
                .is_err()
        );
        let unknown = json!({
            "method": "Browser.downloadProgress",
            "params": {"guid": "guid-unknown", "state": "completed"}
        });
        assert!(
            tracker
                .observe(&unknown, BrowserDownloadPolicy::Allow, Some(root))
                .is_err()
        );
        let mismatch = json!({
            "method": "Browser.downloadProgress",
            "params": {
                "guid": "guid-safe-003",
                "state": "completed",
                "filePath": "/tmp/elsewhere/guid-safe-003"
            }
        });
        assert!(
            tracker
                .observe(&mismatch, BrowserDownloadPolicy::Allow, Some(root))
                .is_err()
        );
        let malformed = json!({
            "method": "Browser.downloadProgress",
            "params": {"guid": "../escape", "state": "completed"}
        });
        assert!(
            tracker
                .observe(&malformed, BrowserDownloadPolicy::Allow, Some(root))
                .is_err()
        );
        let unknown_state = json!({
            "method": "Browser.downloadProgress",
            "params": {"guid": "guid-safe-003", "state": "pausedForever"}
        });
        assert!(
            tracker
                .observe(&unknown_state, BrowserDownloadPolicy::Allow, Some(root))
                .is_err()
        );
    }

    #[test]
    fn download_tracker_accepts_only_exact_resolved_completed_file_path() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let root = std::env::temp_dir().join(format!(
            "sovereign-download-filepath-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir(&root)
            .unwrap_or_else(|error| panic!("create download filepath fixture failed: {error}"));
        let root = root.canonicalize().unwrap_or_else(|error| {
            panic!("canonicalize download filepath fixture failed: {error}")
        });
        let guid = "guid-safe-filepath";
        let expected = root.join(guid);
        fs::write(&expected, b"complete")
            .unwrap_or_else(|error| panic!("write download filepath fixture failed: {error}"));
        let mut tracker = BrowserDownloadTracker::default();
        tracker
            .observe(
                &json!({
                    "method": "Browser.downloadWillBegin",
                    "params": {"guid": guid, "suggestedFilename": "ignored.bin"}
                }),
                BrowserDownloadPolicy::Allow,
                Some(&root),
            )
            .unwrap_or_else(|error| panic!("observe filepath download start failed: {error}"));
        tracker
            .observe(
                &json!({
                    "method": "Browser.downloadProgress",
                    "params": {
                        "guid": guid,
                        "state": "completed",
                        "filePath": expected
                    }
                }),
                BrowserDownloadPolicy::Allow,
                Some(&root),
            )
            .unwrap_or_else(|error| panic!("observe exact filepath completion failed: {error}"));
        let terminal = tracker
            .pop_terminal()
            .unwrap_or_else(|| panic!("exact filepath completion omitted terminal"));
        assert_eq!(terminal.relative_path, Path::new(guid));
        fs::remove_dir_all(&root)
            .unwrap_or_else(|error| panic!("remove download filepath fixture failed: {error}"));
    }

    #[test]
    fn page_navigate_download_is_terminal_even_when_navigation_reports_abort() {
        let download = json!({
            "id": 7,
            "result": {
                "frameId": "frame-main",
                "isDownload": true,
                "errorText": "net::ERR_ABORTED"
            }
        });
        assert!(
            navigation_response_is_download(&download).unwrap_or_else(|error| panic!(
                "download navigation classification failed: {error}"
            ))
        );

        let failed = json!({
            "id": 8,
            "result": {"frameId": "frame-main", "errorText": "net::ERR_FAILED"}
        });
        assert!(navigation_response_is_download(&failed).is_err());
    }

    #[test]
    fn single_tab_target_assessment_detects_snapshot_and_event_only_popups() {
        let expected = "page-main";
        let healthy = vec![expected.to_owned()];
        let (present, unexpected) = assess_single_tab_targets(expected, &healthy, &BTreeSet::new());
        assert!(present);
        assert!(unexpected.is_empty());

        let popup_snapshot = vec![expected.to_owned(), "page-popup".to_owned()];
        let (present, unexpected) =
            assess_single_tab_targets(expected, &popup_snapshot, &BTreeSet::new());
        assert!(present);
        assert_eq!(unexpected, BTreeSet::from(["page-popup".to_owned()]));

        let event_only = BTreeSet::from(["page-transient".to_owned()]);
        let (present, unexpected) = assess_single_tab_targets(expected, &healthy, &event_only);
        assert!(present);
        assert_eq!(unexpected, event_only);

        let (present, unexpected) =
            assess_single_tab_targets(expected, &["page-replacement".to_owned()], &BTreeSet::new());
        assert!(!present);
        assert_eq!(unexpected, BTreeSet::from(["page-replacement".to_owned()]));
    }

    #[test]
    fn attached_target_classification_contains_popup_and_worker_but_resumes_duplicate_main() {
        let popup = json!({
            "method": "Target.attachedToTarget",
            "params": {
                "sessionId": "session-popup",
                "waitingForDebugger": true,
                "targetInfo": {
                    "targetId": "page-popup",
                    "type": "page",
                    "url": ""
                }
            }
        });
        assert_eq!(
            classify_attached_target(&popup, "page-main")
                .unwrap_or_else(|error| panic!("classify popup attach failed: {error}")),
            Some(AttachedTargetDisposition::CloseUnexpectedPage {
                target_id: "page-popup".to_owned(),
            })
        );

        let worker = json!({
            "method": "Target.attachedToTarget",
            "params": {
                "sessionId": "session-worker",
                "waitingForDebugger": true,
                "targetInfo": {
                    "targetId": "worker-child",
                    "type": "worker",
                    "url": "https://example.test/worker.js"
                }
            }
        });
        assert_eq!(
            classify_attached_target(&worker, "page-main")
                .unwrap_or_else(|error| panic!("classify worker attach failed: {error}")),
            Some(AttachedTargetDisposition::CloseContainedChild {
                target_id: "worker-child".to_owned(),
            })
        );

        let expected_page = json!({
            "method": "Target.attachedToTarget",
            "params": {
                "sessionId": "session-main-duplicate",
                "waitingForDebugger": true,
                "targetInfo": {
                    "targetId": "page-main",
                    "type": "page",
                    "url": "about:blank"
                }
            }
        });
        assert_eq!(
            classify_attached_target(&expected_page, "page-main")
                .unwrap_or_else(|error| panic!("classify main attach failed: {error}")),
            Some(AttachedTargetDisposition::ResumeMainPage {
                session_id: "session-main-duplicate".to_owned(),
            })
        );

        let malformed = json!({
            "method": "Target.attachedToTarget",
            "params": {
                "sessionId": "session-missing-target-info"
            }
        });
        assert!(classify_attached_target(&malformed, "page-main").is_err());
    }

    #[test]
    fn fetch_interception_classifies_initial_redirect_and_non_top_level_requests() {
        let main_frame = "frame-main";
        let initial = json!({
            "method": "Fetch.requestPaused",
            "params": {
                "requestId": "fetch-initial",
                "frameId": main_frame,
                "resourceType": "Document",
                "request": {"url": "https://example.test/start", "method": "GET"}
            }
        });
        let redirect = json!({
            "method": "Fetch.requestPaused",
            "params": {
                "requestId": "fetch-redirect",
                "frameId": main_frame,
                "resourceType": "Document",
                "request": {"url": "https://example.test/final?token=opaque", "method": "GET"}
            }
        });
        let subframe = json!({
            "method": "Fetch.requestPaused",
            "params": {
                "requestId": "fetch-subframe",
                "frameId": "frame-child",
                "resourceType": "Document",
                "request": {"url": "https://example.test/frame", "method": "GET"}
            }
        });

        match classify_fetch_request_paused(&initial, main_frame, 0)
            .unwrap_or_else(|error| panic!("classify initial request failed: {error}"))
        {
            Some(FetchPausedRequest::TopLevel(observation)) => {
                assert_eq!(observation.kind, BrowserDocumentRequestKind::Initial);
                assert_eq!(observation.chain_index, 0);
                assert_eq!(observation.url, "https://example.test/start");
            }
            _ => panic!("initial top-level document was not classified for caller authorization"),
        }
        match classify_fetch_request_paused(&redirect, main_frame, 1)
            .unwrap_or_else(|error| panic!("classify redirect request failed: {error}"))
        {
            Some(FetchPausedRequest::TopLevel(observation)) => {
                assert_eq!(observation.kind, BrowserDocumentRequestKind::Redirect);
                assert_eq!(observation.chain_index, 1);
                assert!(observation.url.ends_with("/final?token=opaque"));
            }
            _ => panic!("redirect document was not classified for caller authorization"),
        }
        match classify_fetch_request_paused(&subframe, main_frame, 0)
            .unwrap_or_else(|error| panic!("classify subframe request failed: {error}"))
        {
            Some(FetchPausedRequest::Other {
                interception_id,
                method,
            }) => {
                assert_eq!(interception_id, "fetch-subframe");
                assert_eq!(method, "GET");
            }
            _ => panic!("subframe document should be mechanically continued, not caller-gated"),
        }
    }

    #[test]
    fn request_method_ceiling_denies_https_subresource_write_before_continue() {
        let ceiling = BTreeSet::from(["GET".to_owned(), "HEAD".to_owned(), "POST".to_owned()]);
        let https_subresource = json!({
            "method": "Fetch.requestPaused",
            "params": {
                "requestId": "fetch-https-post",
                "frameId": "frame-main",
                "resourceType": "Fetch",
                "request": {
                    "url": "https://example.test/api/items",
                    "method": "POST"
                }
            }
        });

        match classify_fetch_request_paused(&https_subresource, "frame-main", 0)
            .unwrap_or_else(|error| panic!("classify HTTPS subresource failed: {error}"))
        {
            Some(FetchPausedRequest::Other {
                interception_id,
                method,
            }) => {
                assert_eq!(interception_id, "fetch-https-post");
                assert_eq!(method, "POST");
                assert!(request_method_allowed_by_ceiling(Some(&ceiling), &method));
                assert!(!non_top_level_request_method_allowed(
                    Some(&ceiling),
                    &method
                ));
            }
            _ => panic!("HTTPS subresource was not classified for mechanical gating"),
        }
        assert!(non_top_level_request_method_allowed(Some(&ceiling), "GET"));
        assert!(non_top_level_request_method_allowed(Some(&ceiling), "HEAD"));
        assert!(!non_top_level_request_method_allowed(Some(&ceiling), "PUT"));
        assert!(!non_top_level_request_method_allowed(None, "POST"));
        assert!(request_method_allowed_by_ceiling(None, "POST"));
    }

    #[test]
    fn fetch_proxy_auth_only_releases_credentials_to_the_exact_proxy_challenge_once() {
        let binding = BrowserProxyAuthBinding {
            origin: "http://127.0.0.1:49152".to_owned(),
            scheme: "basic".to_owned(),
            realm: "sovereign-browser-gateway-v1".to_owned(),
            username: "sovereign-browser".to_owned(),
        };
        let exact = json!({
            "method": "Fetch.authRequired",
            "params": {
                "requestId": "auth-1",
                "authChallenge": {
                    "source": "Proxy",
                    "origin": binding.origin,
                    "scheme": "Basic",
                    "realm": binding.realm,
                }
            }
        });
        assert_eq!(
            classify_fetch_auth_required(&exact, Some(&binding), false)
                .unwrap_or_else(|error| panic!("classify exact proxy auth failed: {error}")),
            Some(FetchAuthDecision::Provide {
                request_id: "auth-1".to_owned(),
            })
        );
        assert_eq!(
            classify_fetch_auth_required(&exact, Some(&binding), true)
                .unwrap_or_else(|error| panic!("classify repeated proxy auth failed: {error}")),
            Some(FetchAuthDecision::Cancel {
                request_id: "auth-1".to_owned(),
            })
        );

        let mut server = exact.clone();
        server["params"]["authChallenge"]["source"] = json!("Server");
        assert!(matches!(
            classify_fetch_auth_required(&server, Some(&binding), false)
                .unwrap_or_else(|error| panic!("classify server auth failed: {error}")),
            Some(FetchAuthDecision::Cancel { .. })
        ));

        let mut wrong_realm = exact.clone();
        wrong_realm["params"]["authChallenge"]["realm"] = json!("other-realm");
        assert!(matches!(
            classify_fetch_auth_required(&wrong_realm, Some(&binding), false)
                .unwrap_or_else(|error| panic!("classify wrong realm failed: {error}")),
            Some(FetchAuthDecision::Cancel { .. })
        ));

        let mut wrong_origin = exact.clone();
        wrong_origin["params"]["authChallenge"]["origin"] = json!("http://127.0.0.1:49153");
        assert!(matches!(
            classify_fetch_auth_required(&wrong_origin, Some(&binding), false)
                .unwrap_or_else(|error| panic!("classify wrong origin failed: {error}")),
            Some(FetchAuthDecision::Cancel { .. })
        ));

        let mut wrong_scheme = exact.clone();
        wrong_scheme["params"]["authChallenge"]["scheme"] = json!("Digest");
        assert!(matches!(
            classify_fetch_auth_required(&wrong_scheme, Some(&binding), false)
                .unwrap_or_else(|error| panic!("classify wrong scheme failed: {error}")),
            Some(FetchAuthDecision::Cancel { .. })
        ));

        let mut wrong_source_case = exact.clone();
        wrong_source_case["params"]["authChallenge"]["source"] = json!("proxy");
        assert!(matches!(
            classify_fetch_auth_required(&wrong_source_case, Some(&binding), false)
                .unwrap_or_else(|error| panic!("classify wrong source case failed: {error}")),
            Some(FetchAuthDecision::Cancel { .. })
        ));

        let mut origin_with_path = exact.clone();
        origin_with_path["params"]["authChallenge"]["origin"] = json!("http://127.0.0.1:49152/");
        assert!(matches!(
            classify_fetch_auth_required(&origin_with_path, Some(&binding), false)
                .unwrap_or_else(|error| panic!("classify origin with path failed: {error}")),
            Some(FetchAuthDecision::Cancel { .. })
        ));

        assert!(matches!(
            classify_fetch_auth_required(&exact, None, false)
                .unwrap_or_else(|error| panic!("classify unconfigured auth failed: {error}")),
            Some(FetchAuthDecision::Cancel { .. })
        ));

        let malformed = json!({
            "method": "Fetch.authRequired",
            "params": {"requestId": "auth-malformed"}
        });
        assert!(classify_fetch_auth_required(&malformed, Some(&binding), false).is_err());
    }

    fn assert_sensitive_receipt_is_redacted(receipt_json: &str) {
        for secret in [
            "alice",
            "hunter2",
            "textarea-secret",
            "option-secret",
            "attribute-secret",
            "body-secret",
            "action-secret",
        ] {
            assert!(!receipt_json.contains(secret));
        }
    }

    fn assert_sensitive_screenshot_is_suppressed(
        adapter: &mut BrowserAdapter,
        lease: &BrowserLease,
    ) {
        let screenshot_request_start = adapter.next_request_id;
        let screenshot_receipt = adapter
            .execute(
                lease,
                &BrowserAction::CaptureScreenshot {
                    action_id: "sensitive-screenshot".to_owned(),
                },
            )
            .unwrap_or_else(|error| panic!("suppress sensitive screenshot failed: {error}"));
        assert_eq!(
            adapter.next_request_id,
            screenshot_request_start + 2,
            "sensitive screenshot path must issue only the synopsis and one-tab check, never Page.captureScreenshot"
        );
        assert!(screenshot_receipt.screenshots_and_traces_suppressed);
        assert!(screenshot_receipt.screenshot.is_none());
        let screenshot_json = String::from_utf8_lossy(
            &screenshot_receipt
                .to_bytes()
                .unwrap_or_else(|error| panic!("serialize sensitive screenshot failed: {error}")),
        )
        .into_owned();
        assert_sensitive_receipt_is_redacted(&screenshot_json);
        assert!(!screenshot_json.contains("iVBORw0KGgo"));
    }

    #[test]
    fn real_chrome_sensitive_synopsis_redacts_values_and_form_inspection_is_value_free() {
        let chrome = Path::new("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
        if !chrome.is_file() {
            return;
        }
        let root = std::env::temp_dir().join(format!(
            "sovereign-browser-sensitive-unit-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root)
            .unwrap_or_else(|error| panic!("create sensitive browser test root failed: {error}"));
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("chmod sensitive browser test root failed: {error}"));
        let lease = BrowserLease {
            schema_version: BROWSER_SCHEMA_VERSION,
            lease_id: "sensitive-browser-test".to_owned(),
            task_id: "M7-T03".to_owned(),
            attempt_id: "sensitive-browser-attempt".to_owned(),
            execution_epoch: 1,
            token: "sensitive-browser-token".to_owned(),
        };
        let config = BrowserAdapterConfig {
            suppress_screenshots_and_traces: false,
            ..BrowserAdapterConfig::default()
        };
        let mut adapter = BrowserAdapter::launch(chrome, &root, &lease, config)
            .unwrap_or_else(|error| panic!("launch sensitive browser test failed: {error}"));
        let expression = r#"document.title='Credential token page';document.body.innerHTML='<form id="login" method="post" action="https://example.test/submit?token=action-secret"><input name="username" value="alice"><input type="password" name="password" value="hunter2"><textarea name="secret_note">textarea-secret</textarea><select name="credential_choice"><option selected>option-secret</option></select></form><div data-token="attribute-secret">visible token: body-secret</div>';({ok:true})"#;
        let (_, response) = adapter
            .send_cdp(
                "Runtime.evaluate",
                json!({"expression": expression, "returnByValue": true}),
                Some(adapter.session_id.clone()),
            )
            .unwrap_or_else(|error| panic!("inject sensitive DOM failed: {error}"));
        let _ = super::runtime_value(&response, "Runtime.evaluate")
            .unwrap_or_else(|error| panic!("sensitive DOM injection result failed: {error}"));

        let receipt = adapter
            .execute(
                &lease,
                &BrowserAction::CaptureSynopsis {
                    action_id: "sensitive-synopsis".to_owned(),
                },
            )
            .unwrap_or_else(|error| panic!("capture sensitive synopsis failed: {error}"));
        assert!(receipt.screenshots_and_traces_suppressed);
        let synopsis = receipt
            .synopsis
            .as_ref()
            .unwrap_or_else(|| panic!("sensitive synopsis missing"));
        assert!(synopsis.sensitive_page.is_sensitive());
        assert!(
            synopsis
                .sensitive_page
                .contains(BrowserSensitivePageReason::FormControl)
        );
        assert!(
            synopsis
                .sensitive_page
                .contains(BrowserSensitivePageReason::PasswordControl)
        );
        assert!(synopsis.text.is_empty());
        assert!(synopsis.dom_excerpt.is_empty());
        assert!(synopsis.title.is_empty());
        let receipt_json = String::from_utf8_lossy(
            &receipt
                .to_bytes()
                .unwrap_or_else(|error| panic!("serialize sensitive synopsis failed: {error}")),
        )
        .into_owned();
        assert_sensitive_receipt_is_redacted(&receipt_json);

        assert_sensitive_screenshot_is_suppressed(&mut adapter, &lease);

        let payload_digest = format!("sha256:{}", "b".repeat(64));
        let inspection = adapter
            .inspect_form(&lease, "form#login", &payload_digest)
            .unwrap_or_else(|error| panic!("inspect sensitive form failed: {error}"));
        assert_eq!(inspection.normalized_method, "POST");
        assert!(inspection.sensitive_inputs_present);
        assert_eq!(
            inspection.resolved_action_url,
            "https://example.test/submit"
        );
        assert!(!inspection.resolved_action_url.contains("action-secret"));
        assert_eq!(inspection.payload_digest, payload_digest);

        let submit = BrowserAction::SubmitForm {
            action_id: "submit-sensitive-form".to_owned(),
            selector: "form#login".to_owned(),
            payload_digest,
        };
        let mut stale = inspection.clone();
        stale.structural_digest = format!("sha256:{}", "c".repeat(64));
        assert!(
            adapter
                .dispatch_intercepted_action(&lease, &submit, Some(&stale))
                .is_err()
        );

        adapter
            .shutdown()
            .unwrap_or_else(|error| panic!("shutdown sensitive browser test failed: {error}"));
        let _ = fs::remove_dir_all(&root);
    }
}
