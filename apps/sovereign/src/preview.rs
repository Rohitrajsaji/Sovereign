//! Live preview and read-only file browsing for the active project.
//!
//! Callers: `main.rs` `serve` (starts the preview listener), `dispatch.rs` (`GET /v2/preview`,
//! `GET /v2/files`, `GET /v2/files/content`), `actor.rs` (binds the project root).
//! API: `start_preview`, `PreviewAddressV1`, `list_project_files`, `read_project_file`,
//! `resolve_project_path`.
//!
//! The preview serves the project's files at `http://localhost:<port>/p/<token>/`. That is a
//! different site from the app on `127.0.0.1`, so the app's session cookie is never sent to it
//! and the previewed page cannot script the app. The random path token keeps other websites
//! from loading project files. Responses allow no network access beyond the preview itself and
//! may be framed only by the app. Hidden paths (including `.git`), symlinks that leave the
//! folder, and anything outside it are never served. Nothing here writes to the folder.

use serde::Serialize;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

pub const PREVIEW_PORT: u16 = 7778;
const MAX_REQUEST_HEADER_BYTES: usize = 8 * 1024;
const MAX_SERVED_FILE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_CONNECTIONS: usize = 32;
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_LISTED_FILES: usize = 500;
const MAX_LISTED_FILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_VIEWED_FILE_BYTES: usize = 256 * 1024;

/// Where the preview answers, for the app.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PreviewAddressV1 {
    pub port: u16,
    pub token: String,
}

impl PreviewAddressV1 {
    #[must_use]
    pub fn origin(&self) -> String {
        format!("http://localhost:{}", self.port)
    }

    #[must_use]
    pub fn url(&self) -> String {
        format!("{}/p/{}/", self.origin(), self.token)
    }
}

/// The folder being previewed, switched when the service binds another project.
pub type PreviewRoot = Arc<RwLock<Option<PathBuf>>>;

fn random_token() -> std::io::Result<String> {
    let mut bytes = [0_u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes
        .iter()
        .fold(String::with_capacity(32), |mut text, byte| {
            text.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
            text.push(char::from(b"0123456789abcdef"[usize::from(byte & 0x0f)]));
            text
        }))
}

/// Resolves a project-relative path to a regular file inside `root`, refusing hidden
/// components, parent references, and symlinks that leave the folder.
///
/// # Errors
/// Returns a short reason when the path is not servable.
pub fn resolve_project_path(root: &Path, relative: &str) -> Result<PathBuf, &'static str> {
    let relative = relative.trim_start_matches('/');
    let mut path = root.to_path_buf();
    for component in Path::new(relative).components() {
        match component {
            Component::Normal(part) => {
                if part.to_string_lossy().starts_with('.') {
                    return Err("hidden");
                }
                path.push(part);
            }
            Component::CurDir => {}
            _ => return Err("outside"),
        }
    }
    if path.is_dir() {
        path.push("index.html");
    }
    let canonical_root = root.canonicalize().map_err(|_| "missing")?;
    let canonical = path.canonicalize().map_err(|_| "missing")?;
    if !canonical.starts_with(&canonical_root) {
        return Err("outside");
    }
    let metadata = fs::metadata(&canonical).map_err(|_| "missing")?;
    if !metadata.is_file() {
        return Err("missing");
    }
    Ok(canonical)
}

fn percent_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                let hex = text.get(index + 1..index + 3)?;
                decoded.push(u8::from_str_radix(hex, 16).ok()?);
                index += 3;
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(decoded).ok()
}

fn content_type(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("html" | "htm") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        Some("txt" | "md") => "text/plain; charset=utf-8",
        Some("woff2") => "font/woff2",
        Some("woff") => "font/woff",
        _ => "application/octet-stream",
    }
}

fn headers(app_origin: &str) -> String {
    format!(
        "Cache-Control: no-store\r\n\
X-Content-Type-Options: nosniff\r\n\
Referrer-Policy: no-referrer\r\n\
Cross-Origin-Resource-Policy: same-origin\r\n\
Content-Security-Policy: default-src 'self' 'unsafe-inline' data: blob:; connect-src 'self'; frame-ancestors {app_origin}; form-action 'self'; base-uri 'self'\r\n\
Connection: close\r\n"
    )
}

fn write_status(stream: &mut TcpStream, status: &str, app_origin: &str) {
    let body = format!("{status}\n");
    let _ = write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\n{}\r\n{body}",
        body.len(),
        headers(app_origin)
    );
}

fn serve_connection(
    stream: &mut TcpStream,
    root: &PreviewRoot,
    token: &str,
    app_origin: &str,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let mut request = Vec::with_capacity(1024);
    let mut buffer = [0_u8; 1024];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            return Ok(());
        }
        request.extend_from_slice(&buffer[..read]);
        if request.len() > MAX_REQUEST_HEADER_BYTES {
            write_status(stream, "431 Request Header Fields Too Large", app_origin);
            return Ok(());
        }
    }
    let text = String::from_utf8_lossy(&request);
    let mut parts = text.lines().next().unwrap_or_default().split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    if method != "GET" && method != "HEAD" {
        write_status(stream, "405 Method Not Allowed", app_origin);
        return Ok(());
    }
    let path = target.split(['?', '#']).next().unwrap_or_default();
    let prefix = format!("/p/{token}");
    let Some(rest) = path.strip_prefix(&prefix) else {
        write_status(stream, "404 Not Found", app_origin);
        return Ok(());
    };
    if rest.is_empty() {
        // Relative links need the trailing slash.
        let _ = write!(
            stream,
            "HTTP/1.1 308 Permanent Redirect\r\nLocation: {prefix}/\r\nContent-Length: 0\r\n{}\r\n",
            headers(app_origin)
        );
        return Ok(());
    }
    let Some(relative) = percent_decode(rest) else {
        write_status(stream, "400 Bad Request", app_origin);
        return Ok(());
    };
    let current_root = root.read().unwrap_or_else(PoisonError::into_inner).clone();
    let Some(current_root) = current_root else {
        write_status(stream, "404 Not Found", app_origin);
        return Ok(());
    };
    let file = match resolve_project_path(&current_root, &relative) {
        Ok(file) => file,
        Err("hidden" | "outside") => {
            write_status(stream, "403 Forbidden", app_origin);
            return Ok(());
        }
        Err(_) => {
            write_status(stream, "404 Not Found", app_origin);
            return Ok(());
        }
    };
    let length = fs::metadata(&file).map_or(0, |metadata| metadata.len());
    if length > MAX_SERVED_FILE_BYTES {
        write_status(stream, "413 Payload Too Large", app_origin);
        return Ok(());
    }
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {length}\r\n{}\r\n",
        content_type(&file),
        headers(app_origin)
    )?;
    if method == "GET" {
        std::io::copy(&mut File::open(&file)?.take(length), stream)?;
    }
    stream.flush()
}

fn accept_loop(
    listener: &TcpListener,
    root: &PreviewRoot,
    token: &Arc<str>,
    app_origin: &Arc<str>,
) {
    let active = Arc::new(AtomicUsize::new(0));
    for incoming in listener.incoming() {
        let Ok(mut stream) = incoming else { continue };
        if active.fetch_add(1, Ordering::AcqRel) >= MAX_CONNECTIONS {
            active.fetch_sub(1, Ordering::AcqRel);
            continue;
        }
        let root = Arc::clone(root);
        let token = Arc::clone(token);
        let app_origin = Arc::clone(app_origin);
        let finished = Arc::clone(&active);
        let spawned = std::thread::Builder::new()
            .name("sovereign-preview".to_owned())
            .spawn(move || {
                let _ = serve_connection(&mut stream, &root, &token, &app_origin);
                finished.fetch_sub(1, Ordering::AcqRel);
            });
        if spawned.is_err() {
            // The connection is dropped with the closure; free its slot.
            active.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

/// Starts the preview on `localhost` (IPv4 and, when free, IPv6) at `PREVIEW_PORT`, or at any
/// free port when that one is taken. `app_origin` is the only page allowed to frame it.
///
/// # Errors
/// Returns when no loopback port can be bound.
pub fn start_preview(root: &PreviewRoot, app_origin: &str) -> Result<PreviewAddressV1, String> {
    let token = random_token().map_err(|error| format!("preview token: {error}"))?;
    let v4 = TcpListener::bind(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        PREVIEW_PORT,
    ))
    .or_else(|_| TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)))
    .map_err(|error| format!("preview listener: {error}"))?;
    let port = v4
        .local_addr()
        .map_err(|error| format!("preview listener: {error}"))?
        .port();
    let v6 = TcpListener::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port)).ok();
    let token_shared: Arc<str> = Arc::from(token.as_str());
    let origin_shared: Arc<str> = Arc::from(app_origin);
    for listener in std::iter::once(v4).chain(v6) {
        let root = Arc::clone(root);
        let token = Arc::clone(&token_shared);
        let app_origin = Arc::clone(&origin_shared);
        std::thread::Builder::new()
            .name("sovereign-preview-accept".to_owned())
            .spawn(move || accept_loop(&listener, &root, &token, &app_origin))
            .map_err(|error| format!("preview listener: {error}"))?;
    }
    Ok(PreviewAddressV1 { port, token })
}

/// One file in the project, for the Files tab.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProjectFileV1 {
    pub path: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProjectFilesV1 {
    pub files: Vec<ProjectFileV1>,
    pub truncated: bool,
}

/// The project's visible files (tracked, or new and not ignored), without hidden paths.
///
/// # Errors
/// Returns a repository error.
pub fn list_project_files(root: &Path) -> Result<ProjectFilesV1, String> {
    let listed = sovereign_repo::project_text_files(root, MAX_LISTED_FILE_BYTES)
        .map_err(|error| error.to_string())?;
    let mut files = listed
        .into_iter()
        .filter(|path| {
            !path
                .components()
                .any(|component| component.as_os_str().to_string_lossy().starts_with('.'))
        })
        .filter_map(|path| {
            let size_bytes = fs::metadata(root.join(&path)).ok()?.len();
            Some(ProjectFileV1 {
                path: path.to_string_lossy().into_owned(),
                size_bytes,
            })
        })
        .collect::<Vec<_>>();
    let truncated = files.len() > MAX_LISTED_FILES;
    files.truncate(MAX_LISTED_FILES);
    Ok(ProjectFilesV1 { files, truncated })
}

/// One file's text, for the viewer. Binary files report no text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProjectFileContentV1 {
    pub path: String,
    pub size_bytes: u64,
    pub binary: bool,
    pub truncated: bool,
    pub text: String,
}

/// Reads up to 256 KiB of one project file as text.
///
/// # Errors
/// Returns a `not found:` error for a path that is missing, hidden, or outside the project.
pub fn read_project_file(root: &Path, relative: &str) -> Result<ProjectFileContentV1, String> {
    let path = resolve_project_path(root, relative)
        .map_err(|_| format!("not found: no file {relative} in this project"))?;
    let size_bytes = fs::metadata(&path).map_or(0, |metadata| metadata.len());
    let mut bytes = Vec::new();
    File::open(&path)
        .and_then(|file| {
            file.take(u64::try_from(MAX_VIEWED_FILE_BYTES).unwrap_or(u64::MAX))
                .read_to_end(&mut bytes)
        })
        .map_err(|error| error.to_string())?;
    let truncated = size_bytes > bytes.len() as u64;
    let (binary, text) = match String::from_utf8(bytes) {
        Ok(text) if !text.contains('\0') => (false, text),
        Err(error) if truncated && error.utf8_error().error_len().is_none() => {
            // Cut in the middle of a character at the limit: keep the valid prefix.
            let valid = error.utf8_error().valid_up_to();
            let mut bytes = error.into_bytes();
            bytes.truncate(valid);
            (false, String::from_utf8(bytes).unwrap_or_default())
        }
        _ => (true, String::new()),
    };
    Ok(ProjectFileContentV1 {
        path: relative.trim_start_matches('/').to_owned(),
        size_bytes,
        binary,
        truncated,
        text,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    static SEQUENCE: AtomicU64 = AtomicU64::new(1);

    fn project(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sovereign-preview-{label}-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("css")).unwrap_or_else(|error| panic!("{error}"));
        fs::write(dir.join("index.html"), "<title>Hi</title>")
            .unwrap_or_else(|error| panic!("{error}"));
        fs::write(dir.join("css/site.css"), "body{}").unwrap_or_else(|error| panic!("{error}"));
        fs::create_dir_all(dir.join(".git")).unwrap_or_else(|error| panic!("{error}"));
        fs::write(dir.join(".git/config"), "secret").unwrap_or_else(|error| panic!("{error}"));
        dir
    }

    fn get(address: &PreviewAddressV1, path: &str) -> String {
        let mut stream = TcpStream::connect(("127.0.0.1", address.port))
            .unwrap_or_else(|error| panic!("{error}"));
        write!(stream, "GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap_or_else(|error| panic!("{error}"));
        let mut response = String::new();
        let _ = stream.read_to_string(&mut response);
        response
    }

    #[test]
    fn paths_stay_inside_the_project_and_skip_hidden_files() {
        let root = project("resolve");
        assert!(resolve_project_path(&root, "").is_ok_and(|path| path.ends_with("index.html")));
        assert!(resolve_project_path(&root, "css/site.css").is_ok());
        assert_eq!(resolve_project_path(&root, ".git/config"), Err("hidden"));
        assert_eq!(resolve_project_path(&root, "../etc/passwd"), Err("outside"));
        assert_eq!(resolve_project_path(&root, "missing.js"), Err("missing"));
        std::os::unix::fs::symlink("/etc/hosts", root.join("escape"))
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(resolve_project_path(&root, "escape"), Err("outside"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn preview_serves_only_under_its_token_with_strict_headers() {
        let root = project("serve");
        let shared: PreviewRoot = Arc::new(RwLock::new(Some(root.clone())));
        let address = start_preview(&shared, "http://127.0.0.1:7777")
            .unwrap_or_else(|error| panic!("{error}"));
        let page = get(&address, &format!("/p/{}/", address.token));
        assert!(page.starts_with("HTTP/1.1 200 OK"), "{page}");
        assert!(page.contains("<title>Hi</title>"));
        assert!(page.contains("frame-ancestors http://127.0.0.1:7777"));
        assert!(page.contains("connect-src 'self'"));
        assert!(!page.to_ascii_lowercase().contains("set-cookie"));
        let css = get(&address, &format!("/p/{}/css/site.css", address.token));
        assert!(css.contains("text/css"), "{css}");
        assert!(get(&address, "/p/wrong-token/").starts_with("HTTP/1.1 404"));
        assert!(
            get(&address, &format!("/p/{}/.git/config", address.token)).starts_with("HTTP/1.1 403")
        );
        assert!(
            get(&address, &format!("/p/{}/%2e%2e/secret", address.token))
                .starts_with("HTTP/1.1 403")
        );
        assert!(get(&address, &format!("/p/{}", address.token)).starts_with("HTTP/1.1 308"));
        // Switching projects switches what the same address serves.
        *shared.write().unwrap_or_else(PoisonError::into_inner) = None;
        assert!(get(&address, &format!("/p/{}/", address.token)).starts_with("HTTP/1.1 404"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn file_viewer_reads_text_and_flags_binary() {
        let root = project("viewer");
        fs::write(root.join("logo.png"), [0_u8, 159, 146, 150])
            .unwrap_or_else(|error| panic!("{error}"));
        let page = read_project_file(&root, "index.html").unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(page.text, "<title>Hi</title>");
        assert!(!page.binary);
        let logo = read_project_file(&root, "logo.png").unwrap_or_else(|error| panic!("{error}"));
        assert!(logo.binary);
        assert!(logo.text.is_empty());
        assert!(
            read_project_file(&root, ".git/config")
                .is_err_and(|error| error.starts_with("not found"))
        );
        let _ = fs::remove_dir_all(root);
    }
}
