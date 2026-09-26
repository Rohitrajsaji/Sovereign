//! Model asset manifest and path verification.
//! Callers: `/v2/setup/model/verify` and `doctor.rs`.
//! API: `load_manifest`, `verify_model_paths`.
//! Schema: `apps/sovereign/assets/model-manifest-v1.json`.
//! User instruction: implement the attached consumer product plan (CX-T14).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;

pub const MANIFEST_JSON: &str = include_str!("../assets/model-manifest-v1.json");

/// Versioned list of allowed local model files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelManifestV1 {
    pub schema_version: u32,
    pub download_enabled: bool,
    pub model: ManifestFileV1,
    pub runtime: ManifestFileV1,
}

/// One file pin. Download stays disabled when `url` is null.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestFileV1 {
    pub name: String,
    pub url: Option<String>,
    pub sha256: Option<String>,
    pub size_bytes: Option<u64>,
}

/// Result of hashing caller-chosen files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModelVerifyResultV1 {
    pub ok: bool,
    pub runtime_sha256: String,
    pub model_sha256: String,
    pub detail: String,
}

/// Parses the committed manifest.
///
/// # Errors
/// Returns when the committed JSON is not the expected schema.
pub fn load_manifest() -> Result<ModelManifestV1, String> {
    let manifest: ModelManifestV1 =
        serde_json::from_str(MANIFEST_JSON).map_err(|error| error.to_string())?;
    if manifest.schema_version != 1 {
        return Err("unsupported model manifest schema".to_owned());
    }
    Ok(manifest)
}

/// Hashes two existing files with bounded reads and compares optional pins.
///
/// # Errors
/// Returns when a path is missing or unreadable.
pub fn verify_model_paths(
    runtime_path: &Path,
    model_path: &Path,
) -> Result<ModelVerifyResultV1, String> {
    let manifest = load_manifest()?;
    if !runtime_path.is_file() || !model_path.is_file() {
        return Err("runtime and model paths must be regular files".to_owned());
    }
    let runtime_sha256 = hash_file(runtime_path)?;
    let model_sha256 = hash_file(model_path)?;
    if let Some(expected) = manifest.model.sha256.as_ref()
        && expected != &model_sha256
    {
        return Ok(ModelVerifyResultV1 {
            ok: false,
            runtime_sha256,
            model_sha256,
            detail: "model digest does not match the committed manifest".to_owned(),
        });
    }
    if let Some(expected) = manifest.runtime.sha256.as_ref()
        && expected != &runtime_sha256
    {
        return Ok(ModelVerifyResultV1 {
            ok: false,
            runtime_sha256,
            model_sha256,
            detail: "runtime digest does not match the committed manifest".to_owned(),
        });
    }
    Ok(ModelVerifyResultV1 {
        ok: true,
        runtime_sha256,
        model_sha256,
        detail: "files exist and match the manifest pins when present".to_owned(),
    })
}

fn hash_file(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|error| error.to_string())?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buf).map_err(|error| error.to_string())?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn manifest_parses_and_download_is_disabled_without_url() {
        let manifest = load_manifest().unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(manifest.schema_version, 1);
        assert!(!manifest.download_enabled);
        assert!(manifest.model.url.is_none());
    }

    #[test]
    fn verify_accepts_existing_files_without_pin() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("sovereign-model-{nonce}"));
        fs::create_dir_all(&dir).unwrap_or_else(|error| panic!("{error}"));
        let runtime = dir.join("llama-server");
        let model = dir.join("model.gguf");
        fs::write(&runtime, b"runtime").unwrap_or_else(|error| panic!("{error}"));
        fs::write(&model, b"weights").unwrap_or_else(|error| panic!("{error}"));
        let result = verify_model_paths(&runtime, &model).unwrap_or_else(|error| panic!("{error}"));
        assert!(result.ok);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn download_stays_disabled_without_manifest_url() {
        let manifest = load_manifest().unwrap_or_else(|error| panic!("{error}"));
        assert!(!manifest.download_enabled);
        assert!(manifest.model.url.is_none());
        assert!(manifest.runtime.url.is_none());
    }
}
