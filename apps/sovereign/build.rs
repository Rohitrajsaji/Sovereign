use sha2::{Digest, Sha256};
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=ui-dist");
    build_commit();

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap_or_else(|_| "target".to_owned()));
    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_owned()));
    let ui_dist = manifest_dir.join("ui-dist");

    let mut asset_entries = Vec::new();
    if ui_dist.is_dir() {
        collect_assets(&ui_dist, &ui_dist, &mut asset_entries);
    }

    let dest_path = out_dir.join("embedded_assets.rs");
    let code = if asset_entries.is_empty() {
        fallback_assets()
    } else {
        asset_table(&asset_entries)
    };
    if let Err(error) = fs::write(&dest_path, code) {
        println!("cargo:warning=failed to write embedded assets: {error}");
    }
}

fn fallback_assets() -> String {
    let fallback_html = b"<!doctype html><html><head><meta charset=\"utf-8\"><title>Sovereign</title></head><body><h1>Sovereign</h1><p>UI is not built. Run <code>npm --prefix apps/sovereign/ui run build</code>.</p></body></html>";
    let mut hasher = Sha256::new();
    hasher.update(fallback_html);
    let etag = format!("\"{:x}\"", hasher.finalize());
    format!(
        "pub struct EmbeddedAsset {{
    pub path: &'static str,
    pub bytes: &'static [u8],
    pub mime_type: &'static str,
    pub etag: &'static str,
}}

pub static ASSETS: &[EmbeddedAsset] = &[
    EmbeddedAsset {{
        path: \"/index.html\",
        bytes: {fallback_html:?},
        mime_type: \"text/html; charset=utf-8\",
        etag: {etag:?},
    }},
];
"
    )
}

fn asset_table(entries: &[(String, String, &'static str, String)]) -> String {
    let mut code = String::from(
        r"
pub struct EmbeddedAsset {
    pub path: &'static str,
    pub bytes: &'static [u8],
    pub mime_type: &'static str,
    pub etag: &'static str,
}

pub static ASSETS: &[EmbeddedAsset] = &[
",
    );
    for (rel_path, abs_path, mime_type, etag) in entries {
        let _ = write!(
            code,
            "    EmbeddedAsset {{\n        path: {rel_path:?},\n        bytes: include_bytes!({abs_path:?}),\n        mime_type: {mime_type:?},\n        etag: {etag:?},\n    }},\n"
        );
    }
    code.push_str("];\n");
    code
}

fn collect_assets(
    base: &Path,
    current: &Path,
    entries: &mut Vec<(String, String, &'static str, String)>,
) {
    let Ok(read_dir) = fs::read_dir(current) else {
        return;
    };
    for entry in read_dir.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_assets(base, &path, entries);
        } else if path.is_file() {
            let Ok(rel) = path.strip_prefix(base) else {
                continue;
            };
            let mut rel_str = rel.to_string_lossy().to_string();
            if !rel_str.starts_with('/') {
                rel_str = format!("/{rel_str}");
            }
            let Ok(bytes) = fs::read(&path) else {
                continue;
            };
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            let etag = format!("\"{:x}\"", hasher.finalize());
            let mime = mime_for_path(&path);
            let abs_str = path.to_string_lossy().to_string();
            entries.push((rel_str, abs_str, mime, etag));
        }
    }
}

fn mime_for_path(path: &Path) -> &'static str {
    match path.extension().and_then(|ext| ext.to_str()).unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "application/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        "wasm" => "application/wasm",
        _ => "application/octet-stream",
    }
}

/// Records the commit this binary is built from, so the app can tell builds apart.
fn build_commit() {
    // Only existing files: Cargo reruns the script on every build for a path that is missing.
    let git = Path::new("../../.git");
    let mut watched = vec![git.join("HEAD"), git.join("packed-refs")];
    if let Ok(head) = fs::read_to_string(git.join("HEAD"))
        && let Some(reference) = head.trim().strip_prefix("ref: ")
    {
        watched.push(git.join(reference));
    }
    for path in watched.iter().filter(|path| path.is_file()) {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    let commit = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|commit| !commit.is_empty() && commit.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .unwrap_or_else(|| "unknown".to_owned());
    println!("cargo:rustc-env=SOVEREIGN_BUILD_COMMIT={commit}");
}
