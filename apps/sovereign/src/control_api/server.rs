//! Threaded loopback HTTP server. Four workers, bounded bodies, fail-closed.
//! Callers: `main.rs` `serve` and unit tests.
//! API: `serve_listener`, `serve_one`.
//! Schema: none.
//! User instruction: implement the attached consumer product plan (CX-T03).

use super::parse::parse_http_envelope;
use super::routes::parse_control_request;
use super::sse::serve_event_stream;
use super::static_assets::{serve_static_asset, write_not_found, write_session_redirect};
use super::{ApiError, ApiStatus, BASE_SECURITY_HEADERS, ControlApiRequest, ServerConfig};
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

pub(crate) const MAX_HEADER_BYTES: usize = 16 * 1024;
pub(crate) const MAX_BODY_BYTES: usize = 64 * 1024;
pub(crate) const MAX_REQUEST_BYTES: usize = MAX_HEADER_BYTES + MAX_BODY_BYTES;
pub(crate) const READ_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const IDLE_CLOSE: Duration = Duration::from_secs(30);
const WORKER_COUNT: usize = 4;
const QUEUE_CAPACITY: usize = 32;

pub(crate) fn serve_listener<F>(
    listener: &TcpListener,
    handle: F,
    config: ServerConfig,
) -> Result<(), String>
where
    F: Fn(ControlApiRequest) -> Result<Value, String> + Send + Sync + 'static,
{
    let handle = Arc::new(handle);
    let config = Arc::new(config);
    let (tx, rx) = mpsc::sync_channel::<TcpStream>(QUEUE_CAPACITY);
    let rx = Arc::new(std::sync::Mutex::new(rx));

    let mut workers = Vec::with_capacity(WORKER_COUNT);
    for index in 0..WORKER_COUNT {
        let rx = Arc::clone(&rx);
        let handle = Arc::clone(&handle);
        let config = Arc::clone(&config);
        let worker = thread::Builder::new()
            .name(format!("sovereign-http-{index}"))
            .spawn(move || {
                loop {
                    let mut stream = {
                        let Ok(guard) = rx.lock() else { break };
                        match guard.recv() {
                            Ok(s) => s,
                            Err(_) => break,
                        }
                    };
                    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
                    let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT.max(IDLE_CLOSE)));
                    let _ = serve_stream(&mut stream, |req| handle(req), &config);
                }
            })
            .map_err(|error| error.to_string())?;
        workers.push(worker);
    }

    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                if tx.send(stream).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    drop(tx);
    for worker in workers {
        let _ = worker.join();
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn serve_one<F>(listener: &TcpListener, mut handle: F) -> Result<(), String>
where
    F: FnMut(ControlApiRequest) -> Result<Value, String>,
{
    let (mut stream, _) = listener.accept().map_err(|error| error.to_string())?;
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
    let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT.max(IDLE_CLOSE)));
    let config = ServerConfig::default();
    serve_stream(&mut stream, &mut handle, &config)
}

#[expect(
    clippy::too_many_lines,
    reason = "HTTP dispatch stays in one fail-closed function"
)]
fn serve_stream<F>(
    stream: &mut TcpStream,
    mut handle: F,
    config: &ServerConfig,
) -> Result<(), String>
where
    F: FnMut(ControlApiRequest) -> Result<Value, String>,
{
    let request_bytes = match read_request(stream) {
        Ok(bytes) => bytes,
        Err(error) => {
            return write_json_response(stream, error.status, &json!({"error": error.message}));
        }
    };

    let parsed_info = match parse_http_envelope(&request_bytes) {
        Ok(info) => info,
        Err(error) => {
            return write_json_response(stream, error.status, &json!({"error": error.message}));
        }
    };

    // Path traversal check
    if parsed_info.path.contains("..") || parsed_info.path.contains("%2e%2e") {
        return write_not_found(stream);
    }

    // Token query redirect on root GET /?t=<token>
    if parsed_info.path == "/"
        && let Some(token) = parsed_info.token_param.as_ref()
        && config
            .session_token
            .as_ref()
            .is_some_and(|expected| expected == token)
    {
        return write_session_redirect(stream, token);
    }

    // Single-use launch code from `sovereign app`: GET /?c=<code>. The long-lived session token
    // travels only in the HttpOnly cookie, never in a URL the browser keeps in history.
    if parsed_info.path == "/"
        && parsed_info.method == "GET"
        && let (Some(code), Some(dir), Some(token)) = (
            parsed_info.launch_code_param.as_ref(),
            config.launch_code_dir.as_ref(),
            config.session_token.as_ref(),
        )
        && crate::launch_code::redeem(dir, code)
    {
        return write_session_redirect(stream, token);
    }

    // Static asset serving: anything not under /v1/ or /v2/, including /dashboard SPA.
    if !parsed_info.path.starts_with("/v1/")
        && !parsed_info.path.starts_with("/v2/")
        && parsed_info.method == "GET"
    {
        let asset_path = if parsed_info.path == "/dashboard" {
            "/"
        } else {
            parsed_info.path.as_str()
        };
        return serve_static_asset(stream, asset_path, parsed_info.if_none_match.as_deref());
    }

    // v2 authentication & CSRF enforcement
    if parsed_info.path.starts_with("/v2/")
        && let Some(expected_token) = config.session_token.as_ref()
    {
        let authenticated = parsed_info
            .cookie_token
            .as_ref()
            .is_some_and(|cookie| cookie == expected_token)
            || parsed_info
                .auth_bearer
                .as_ref()
                .is_some_and(|bearer| bearer == expected_token);

        if !authenticated {
            return write_json_response(
                stream,
                ApiStatus::Unauthorized,
                &json!({"error": "unauthorized"}),
            );
        }

        if parsed_info.method == "POST" {
            let csrf_valid = parsed_info
                .csrf_header
                .as_ref()
                .is_some_and(|header| header == expected_token);
            if !csrf_valid {
                return write_json_response(
                    stream,
                    ApiStatus::Forbidden,
                    &json!({"error": "invalid CSRF token"}),
                );
            }
        }
    }

    if config.require_token_for_v1_post
        && parsed_info.path.starts_with("/v1/")
        && parsed_info.method == "POST"
    {
        let expected = config.session_token.as_ref();
        let authenticated = expected.is_some_and(|token| {
            parsed_info.cookie_token.as_ref() == Some(token)
                || parsed_info.auth_bearer.as_ref() == Some(token)
        });
        if !authenticated {
            return write_json_response(
                stream,
                ApiStatus::Unauthorized,
                &json!({"error": "unauthorized"}),
            );
        }
    }

    // Dispatch request to handler
    let request = match parse_control_request(&parsed_info, &request_bytes) {
        Ok(req) => req,
        Err(error) => {
            return write_json_response(stream, error.status, &json!({"error": error.message}));
        }
    };

    match request {
        ControlApiRequest::Dashboard => serve_static_asset(stream, "/", None),
        ControlApiRequest::EventStream { last_event_id } => {
            // A stream lasts as long as the page stays open, so it runs on its own thread and
            // never holds one of the request workers.
            let mut owned = stream.try_clone().map_err(|error| error.to_string())?;
            let config = config.clone();
            thread::Builder::new()
                .name("sovereign-events".to_owned())
                .spawn(move || {
                    let _ = serve_event_stream(&mut owned, &config, last_event_id);
                })
                .map(|_| ())
                .map_err(|error| error.to_string())
        }
        ControlApiRequest::Session => {
            let csrf_token = config.session_token.clone().unwrap_or_default();
            write_json_response(
                stream,
                ApiStatus::Ok,
                &json!({
                    "authenticated": true,
                    "csrf_token": csrf_token,
                    "version": crate::build_info::BUILD_VERSION,
                }),
            )
        }
        req => {
            let response = match handle(req) {
                Ok(body) => (ApiStatus::Ok, body),
                Err(message) if message.contains("timed out") => {
                    (ApiStatus::ServiceUnavailable, json!({"error": message}))
                }
                Err(message) if message.contains("not found") => {
                    (ApiStatus::NotFound, json!({"error": message}))
                }
                Err(message) => (ApiStatus::InternalServerError, json!({"error": message})),
            };
            write_json_response(stream, response.0, &response.1)
        }
    }
}

fn read_request(stream: &mut TcpStream) -> Result<Vec<u8>, ApiError> {
    let mut bytes = Vec::with_capacity(1024);
    let mut scratch = [0u8; 1024];
    let mut header_end = None;
    let mut content_length = None;

    loop {
        let read = stream.read(&mut scratch).map_err(|error| {
            ApiError::new(
                ApiStatus::BadRequest,
                format!("request read failed: {error}"),
            )
        })?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&scratch[..read]);
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(ApiError::new(
                ApiStatus::PayloadTooLarge,
                "request exceeds local control API size limit",
            ));
        }

        if header_end.is_none() {
            header_end = crate::control_api::parse::find_header_end(&bytes);
            if let Some(end) = header_end {
                if end > MAX_HEADER_BYTES {
                    return Err(ApiError::new(
                        ApiStatus::PayloadTooLarge,
                        "request headers exceed local control API size limit",
                    ));
                }
                content_length = Some(crate::control_api::parse::parse_content_length(
                    &bytes[..end],
                )?);
                if content_length.unwrap_or(0) > MAX_BODY_BYTES {
                    return Err(ApiError::new(
                        ApiStatus::PayloadTooLarge,
                        "request body exceeds local control API size limit",
                    ));
                }
            } else if bytes.len() > MAX_HEADER_BYTES {
                return Err(ApiError::new(
                    ApiStatus::PayloadTooLarge,
                    "request headers exceed local control API size limit",
                ));
            }
        }

        if let (Some(end), Some(length)) = (header_end, content_length)
            && bytes.len() >= end.saturating_add(length)
        {
            bytes.truncate(end + length);
            return Ok(bytes);
        }
    }

    let end = header_end
        .ok_or_else(|| ApiError::new(ApiStatus::BadRequest, "incomplete HTTP request headers"))?;
    let expected = content_length.unwrap_or(0);
    if bytes.len() != end.saturating_add(expected) {
        return Err(ApiError::new(
            ApiStatus::BadRequest,
            "incomplete HTTP request body",
        ));
    }
    Ok(bytes)
}

pub(crate) fn write_json_response(
    stream: &mut TcpStream,
    status: ApiStatus,
    body: &Value,
) -> Result<(), String> {
    let body = serde_json::to_vec(body).map_err(|error| error.to_string())?;
    let headers = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n{BASE_SECURITY_HEADERS}\r\n",
        status.code(),
        status.reason(),
        body.len()
    );
    stream
        .write_all(headers.as_bytes())
        .and_then(|()| stream.write_all(&body))
        .and_then(|()| stream.flush())
        .map_err(|error| error.to_string())
}
