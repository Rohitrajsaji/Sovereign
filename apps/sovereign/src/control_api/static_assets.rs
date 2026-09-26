//! Embedded UI assets with `ETag` and SPA fallback.
//! Callers: `server.rs` for non-API GET requests.
//! API: `serve_static_asset`, `write_not_found`, `write_session_redirect`.
//! Schema: generated `OUT_DIR/embedded_assets.rs`.
//! User instruction: implement the attached consumer product plan (CX-T06).

use super::BASE_SECURITY_HEADERS;
use std::io::Write;
use std::net::TcpStream;

mod embedded {
    include!(concat!(env!("OUT_DIR"), "/embedded_assets.rs"));
}

pub(crate) fn serve_static_asset(
    stream: &mut TcpStream,
    path: &str,
    if_none_match: Option<&str>,
) -> Result<(), String> {
    let asset = embedded::ASSETS
        .iter()
        .find(|a| a.path == path)
        .or_else(|| embedded::ASSETS.iter().find(|a| a.path == "/index.html"));

    let Some(asset) = asset else {
        return write_not_found(stream);
    };

    if if_none_match.is_some_and(|etag| etag.trim() == asset.etag) {
        let headers = format!(
            "HTTP/1.1 304 Not Modified\r\nETag: {}\r\nConnection: close\r\n{BASE_SECURITY_HEADERS}\r\n",
            asset.etag
        );
        return stream
            .write_all(headers.as_bytes())
            .and_then(|()| stream.flush())
            .map_err(|e| e.to_string());
    }

    let cache_control = if asset.path.starts_with("/assets/") {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    };

    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nETag: {}\r\nCache-Control: {}\r\nConnection: close\r\n{BASE_SECURITY_HEADERS}\r\n",
        asset.mime_type,
        asset.bytes.len(),
        asset.etag,
        cache_control,
    );
    stream
        .write_all(headers.as_bytes())
        .and_then(|()| stream.write_all(asset.bytes))
        .and_then(|()| stream.flush())
        .map_err(|e| e.to_string())
}

pub(crate) fn write_not_found(stream: &mut TcpStream) -> Result<(), String> {
    let body = b"{\"error\":\"not found\"}";
    let headers = format!(
        "HTTP/1.1 404 Not Found\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n{BASE_SECURITY_HEADERS}\r\n",
        body.len()
    );
    stream
        .write_all(headers.as_bytes())
        .and_then(|()| stream.write_all(body))
        .and_then(|()| stream.flush())
        .map_err(|e| e.to_string())
}

pub(crate) fn write_session_redirect(stream: &mut TcpStream, token: &str) -> Result<(), String> {
    let headers = format!(
        "HTTP/1.1 302 Found\r\nLocation: /\r\nSet-Cookie: sovereign_session={token}; HttpOnly; SameSite=Strict; Path=/\r\nContent-Length: 0\r\nConnection: close\r\n{BASE_SECURITY_HEADERS}\r\n"
    );
    stream
        .write_all(headers.as_bytes())
        .and_then(|()| stream.flush())
        .map_err(|e| e.to_string())
}
