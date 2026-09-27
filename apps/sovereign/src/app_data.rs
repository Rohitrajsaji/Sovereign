//! Versioned settings and project index under the user's application-support directory.
//!
//! These files are operator configuration. They are not Controller execution authority.

use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub const SETTINGS_SCHEMA_VERSION: u32 = 1;
pub const PROJECTS_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsV1 {
    pub schema_version: u32,
    pub model_runtime: Option<String>,
    pub model_path: Option<String>,
    pub model_name: Option<String>,
    pub chrome_path: Option<String>,
    pub node_path: Option<String>,
    pub execute_on_start: bool,
    pub approval_principal: String,
    /// A catalog model chosen while a request was running. It replaces the model in use when
    /// the next request starts.
    /// Written only when set, so a settings file saved without a queued model still loads in
    /// versions from before this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queued_model_id: Option<String>,
}

impl Default for SettingsV1 {
    fn default() -> Self {
        Self {
            schema_version: SETTINGS_SCHEMA_VERSION,
            model_runtime: None,
            model_path: None,
            model_name: None,
            chrome_path: None,
            node_path: None,
            execute_on_start: false,
            approval_principal: "operator@ui".to_owned(),
            queued_model_id: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectRecordV1 {
    pub project_id: String,
    pub display_name: String,
    pub root: String,
    pub state_path: String,
    pub cas_root: String,
    pub created_at_ms: i64,
    /// True when Sovereign created or adopted the folder and keeps its history for the user.
    /// Managed projects get "Your edits" checkpoints; existing developer repositories do not.
    #[serde(default)]
    pub managed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectsV1 {
    pub schema_version: u32,
    pub active_project_id: Option<String>,
    pub projects: Vec<ProjectRecordV1>,
}

impl Default for ProjectsV1 {
    fn default() -> Self {
        Self {
            schema_version: PROJECTS_SCHEMA_VERSION,
            active_project_id: None,
            projects: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub struct AppData {
    root: PathBuf,
}

impl AppData {
    /// Resolves `~/Library/Application Support/Sovereign`, creating it at mode 0700.
    ///
    /// # Errors
    /// Returns an I/O error when the home directory is missing or the directory cannot be created.
    pub fn open_default() -> io::Result<Self> {
        let home = std::env::var_os("HOME").ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "HOME is required for app data")
        })?;
        let root = PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("Sovereign");
        Self::open(&root)
    }

    /// Opens an explicit app-data root. Tests pass a temporary directory.
    ///
    /// # Errors
    /// Returns an I/O error when the directory cannot be created or is a symlink.
    pub fn open(root: &Path) -> io::Result<Self> {
        if root.exists() {
            let meta = fs::symlink_metadata(root)?;
            if meta.file_type().is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "app data path must not be a symlink",
                ));
            }
        } else {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(root)?;
        }
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn token_path(&self) -> PathBuf {
        self.root.join("service-token")
    }

    /// # Errors
    /// Returns an I/O or JSON error when the file cannot be read or the schema is wrong.
    pub fn load_settings(&self) -> io::Result<SettingsV1> {
        load_json(
            &self.root.join("settings-v1.json"),
            SettingsV1::default(),
            |value| value.schema_version == SETTINGS_SCHEMA_VERSION,
        )
    }

    /// # Errors
    /// Returns an I/O error when the atomic write fails.
    pub fn save_settings(&self, settings: &SettingsV1) -> io::Result<()> {
        if settings.schema_version != SETTINGS_SCHEMA_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported settings schema",
            ));
        }
        write_private_json(&self.root.join("settings-v1.json"), settings)
    }

    /// # Errors
    /// Returns an I/O or JSON error when the file cannot be read or the schema is wrong.
    pub fn load_projects(&self) -> io::Result<ProjectsV1> {
        load_json(
            &self.root.join("projects-v1.json"),
            ProjectsV1::default(),
            |value| value.schema_version == PROJECTS_SCHEMA_VERSION,
        )
    }

    /// Environment variables override file settings. They are not execution authority.
    #[must_use]
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn settings_with_env(settings: SettingsV1) -> SettingsV1 {
        let mut merged = settings;
        if let Some(value) = std::env::var_os("SOVEREIGN_MODEL_RUNTIME") {
            merged.model_runtime = Some(PathBuf::from(value).display().to_string());
        }
        if let Some(value) = std::env::var_os("SOVEREIGN_MODEL_PATH") {
            merged.model_path = Some(PathBuf::from(value).display().to_string());
        }
        merged
    }

    /// # Errors
    /// Returns an I/O error when the atomic write fails.
    pub fn save_projects(&self, projects: &ProjectsV1) -> io::Result<()> {
        if projects.schema_version != PROJECTS_SCHEMA_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported projects schema",
            ));
        }
        write_private_json(&self.root.join("projects-v1.json"), projects)
    }
}

fn load_json<T, F>(path: &Path, default: T, schema_ok: F) -> io::Result<T>
where
    T: for<'de> Deserialize<'de>,
    F: Fn(&T) -> bool,
{
    if !path.exists() {
        return Ok(default);
    }
    let bytes = fs::read(path)?;
    let value: T = serde_json::from_slice(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if !schema_ok(&value) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported app-data schema",
        ));
    }
    Ok(value)
}

fn write_private_json<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    let parent = path.parent().unwrap_or(Path::new("."));
    let tmp = parent.join(format!(
        ".{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("file")
    ));
    let json = serde_json::to_vec_pretty(value)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(&json)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("sovereign-app-{label}-{nonce}"));
        let _ = fs::remove_dir_all(&path);
        path
    }

    #[test]
    fn settings_round_trip_and_unknown_field_rejected() {
        let root = temp_root("settings");
        let data = AppData::open(&root).unwrap_or_else(|error| panic!("open: {error}"));
        assert_eq!(
            data.load_settings()
                .unwrap_or_else(|error| panic!("default: {error}"))
                .schema_version,
            1
        );
        let settings = SettingsV1 {
            model_name: Some("Qwen3-4B".to_owned()),
            ..SettingsV1::default()
        };
        data.save_settings(&settings)
            .unwrap_or_else(|error| panic!("save: {error}"));
        assert_eq!(
            data.load_settings()
                .unwrap_or_else(|error| panic!("load: {error}"))
                .model_name
                .as_deref(),
            Some("Qwen3-4B")
        );
        fs::write(
            root.join("settings-v1.json"),
            b"{\"schema_version\":1,\"extra\":1}\n",
        )
        .unwrap_or_else(|error| panic!("write: {error}"));
        assert!(data.load_settings().is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn symlink_config_directory_is_rejected() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let target = std::env::temp_dir().join(format!("sovereign-app-link-target-{nonce}"));
        let link = std::env::temp_dir().join(format!("sovereign-app-link-{nonce}"));
        fs::create_dir_all(&target).unwrap_or_else(|error| panic!("{error}"));
        let _ = fs::remove_file(&link);
        std::os::unix::fs::symlink(&target, &link).unwrap_or_else(|error| panic!("{error}"));
        assert!(AppData::open(&link).is_err());
        let _ = fs::remove_file(link);
        let _ = fs::remove_dir_all(target);
    }

    #[test]
    fn environment_overrides_file_settings() {
        let settings = SettingsV1 {
            model_runtime: Some("/from-file".to_owned()),
            ..SettingsV1::default()
        };
        let merged = AppData::settings_with_env(settings.clone());
        if std::env::var_os("SOVEREIGN_MODEL_RUNTIME").is_some() {
            assert_ne!(merged.model_runtime.as_deref(), Some("/from-file"));
        } else {
            assert_eq!(merged.model_runtime.as_deref(), Some("/from-file"));
        }
    }
}
