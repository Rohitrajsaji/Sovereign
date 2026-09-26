//! HTTP envelope and fail-closed header/body parsing.
//! Callers: `server.rs` and `routes.rs`.
//! API: `HttpEnvelope`, `parse_http_envelope`, `parse_request`.
//! Schema: none. User instruction: implement the attached consumer product plan (CX-T03).

use super::{ApiError, ApiStatus, ControlApiRequest};
use serde_json::{Value, json};
use std::net::IpAddr;

pub(crate) struct HttpEnvelope {
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) header_end: usize,
    pub(crate) content_length: usize,
    pub(crate) if_none_match: Option<String>,
    pub(crate) token_param: Option<String>,
    pub(crate) launch_code_param: Option<String>,
    pub(crate) cookie_token: Option<String>,
    pub(crate) csrf_header: Option<String>,
    pub(crate) auth_bearer: Option<String>,
    pub(crate) last_event_id: Option<String>,
    pub(crate) query: String,
}

pub(crate) fn parse_http_envelope(bytes: &[u8]) -> Result<HttpEnvelope, ApiError> {
    let header_end = find_header_end(bytes)
        .ok_or_else(|| ApiError::new(ApiStatus::BadRequest, "missing HTTP header terminator"))?;
    let header_text = std::str::from_utf8(&bytes[..header_end])
        .map_err(|_| ApiError::new(ApiStatus::BadRequest, "request headers are not UTF-8"))?;
    let request_line = header_text
        .split("\r\n")
        .next()
        .ok_or_else(|| ApiError::new(ApiStatus::BadRequest, "missing request line"))?;

    let mut fields = request_line.split_ascii_whitespace();
    let method = fields
        .next()
        .ok_or_else(|| ApiError::new(ApiStatus::BadRequest, "missing HTTP method"))?
        .to_owned();
    let raw_path = fields
        .next()
        .ok_or_else(|| ApiError::new(ApiStatus::BadRequest, "missing request path"))?;
    let version = fields
        .next()
        .ok_or_else(|| ApiError::new(ApiStatus::BadRequest, "missing HTTP version"))?;

    if fields.next().is_some() || !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err(ApiError::new(
            ApiStatus::BadRequest,
            "unsupported HTTP request line",
        ));
    }

    validate_local_request_headers(header_text, version)?;

    let (path_str, query, token_param, launch_code_param) = match raw_path.split_once('?') {
        Some((p, query)) => {
            let mut tok = None;
            let mut code = None;
            for part in query.split('&') {
                if let Some(val) = part.strip_prefix("t=") {
                    tok = Some(val.to_owned());
                } else if let Some(val) = part.strip_prefix("c=") {
                    code = Some(val.to_owned());
                }
            }
            (p.to_owned(), query.to_owned(), tok, code)
        }
        None => (raw_path.to_owned(), String::new(), None, None),
    };

    let mut content_length = 0;
    let mut if_none_match = None;
    let mut cookie_token = None;
    let mut csrf_header = None;
    let mut auth_bearer = None;
    let mut last_event_id = None;

    for line in header_text.split("\r\n").skip(1) {
        if line.is_empty() {
            continue;
        }
        let Some((name, val)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let val = val.trim();

        if name.eq_ignore_ascii_case("content-length") {
            content_length = val
                .parse::<usize>()
                .map_err(|_| ApiError::new(ApiStatus::BadRequest, "invalid Content-Length"))?;
        } else if name.eq_ignore_ascii_case("if-none-match") {
            if_none_match = Some(val.to_owned());
        } else if name.eq_ignore_ascii_case("cookie") {
            for cookie in val.split(';') {
                let cookie = cookie.trim();
                if let Some(tok) = cookie.strip_prefix("sovereign_session=") {
                    cookie_token = Some(tok.to_owned());
                }
            }
        } else if name.eq_ignore_ascii_case("x-sovereign-csrf") {
            csrf_header = Some(val.to_owned());
        } else if name.eq_ignore_ascii_case("authorization")
            && let Some(bearer) = val.strip_prefix("Bearer ")
        {
            auth_bearer = Some(bearer.trim().to_owned());
        } else if name.eq_ignore_ascii_case("last-event-id") {
            last_event_id = Some(val.to_owned());
        }
    }

    Ok(HttpEnvelope {
        method,
        path: path_str,
        header_end,
        content_length,
        if_none_match,
        token_param,
        launch_code_param,
        cookie_token,
        csrf_header,
        auth_bearer,
        last_event_id,
        query,
    })
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn parse_request(bytes: &[u8]) -> Result<ControlApiRequest, ApiError> {
    let info = parse_http_envelope(bytes)?;
    crate::control_api::routes::parse_control_request(&info, bytes)
}

pub(crate) fn query_i64(query: &str, name: &str, default: i64) -> i64 {
    for part in query.split('&') {
        if let Some(value) = part.strip_prefix(&format!("{name}="))
            && let Ok(parsed) = value.parse::<i64>()
        {
            return parsed;
        }
    }
    default
}

/// A percent-decoded query value (`+` is a space), or `None` when absent or malformed.
pub(crate) fn query_string(query: &str, name: &str) -> Option<String> {
    let raw = query
        .split('&')
        .find_map(|part| part.strip_prefix(&format!("{name}=")))?;
    let bytes = raw.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                let hex = raw.get(index + 1..index + 3)?;
                decoded.push(u8::from_str_radix(hex, 16).ok()?);
                index += 3;
            }
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(decoded).ok()
}

pub(crate) fn query_usize(query: &str, name: &str, default: usize, max: usize) -> usize {
    let value = query_i64(query, name, i64::try_from(default).unwrap_or(0));
    let as_usize = usize::try_from(value).unwrap_or(default);
    as_usize.clamp(1, max)
}
pub(crate) fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

pub(crate) fn parse_content_length(headers: &[u8]) -> Result<usize, ApiError> {
    let text = std::str::from_utf8(headers)
        .map_err(|_| ApiError::new(ApiStatus::BadRequest, "request headers are not UTF-8"))?;
    let mut content_length = None;
    for line in text.split("\r\n").skip(1) {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(ApiError::new(
                ApiStatus::BadRequest,
                "malformed HTTP header",
            ));
        };
        let name = name.trim();
        let value = value.trim();
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(ApiError::new(
                ApiStatus::BadRequest,
                "Transfer-Encoding is not supported by the local control API",
            ));
        }
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(ApiError::new(
                    ApiStatus::BadRequest,
                    "duplicate Content-Length header",
                ));
            }
            content_length = Some(value.parse::<usize>().map_err(|_| {
                ApiError::new(ApiStatus::BadRequest, "invalid Content-Length header")
            })?);
        }
    }
    Ok(content_length.unwrap_or(0))
}

pub(crate) fn validate_local_request_headers(
    header_text: &str,
    version: &str,
) -> Result<(), ApiError> {
    let mut host = None;
    let mut origin = None;
    for line in header_text.split("\r\n").skip(1) {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(ApiError::new(
                ApiStatus::BadRequest,
                "malformed HTTP header",
            ));
        };
        let value = value.trim();
        if name.trim().eq_ignore_ascii_case("host") {
            if host.replace(value).is_some() {
                return Err(ApiError::new(
                    ApiStatus::BadRequest,
                    "duplicate Host header",
                ));
            }
        } else if name.trim().eq_ignore_ascii_case("origin") && origin.replace(value).is_some() {
            return Err(ApiError::new(
                ApiStatus::BadRequest,
                "duplicate Origin header",
            ));
        }
    }

    if version == "HTTP/1.1" && host.is_none() {
        return Err(ApiError::new(
            ApiStatus::BadRequest,
            "HTTP/1.1 local control requests require a Host header",
        ));
    }
    if host.is_some_and(|value| !is_loopback_authority(value)) {
        return Err(ApiError::new(
            ApiStatus::BadRequest,
            "local control Host must resolve syntactically to localhost or a loopback IP",
        ));
    }
    if origin.is_some_and(|value| !is_loopback_origin(value)) {
        return Err(ApiError::new(
            ApiStatus::BadRequest,
            "browser Origin must be the local control loopback origin",
        ));
    }
    Ok(())
}

pub(crate) fn is_loopback_origin(value: &str) -> bool {
    value
        .strip_prefix("http://")
        .filter(|authority| {
            !authority.is_empty()
                && !authority.contains('/')
                && !authority.contains('?')
                && !authority.contains('#')
        })
        .is_some_and(is_loopback_authority)
}

pub(crate) fn is_loopback_authority(value: &str) -> bool {
    let host = if let Some(bracketed) = value.strip_prefix('[') {
        let Some(close) = bracketed.find(']') else {
            return false;
        };
        let host = &bracketed[..close];
        let suffix = &bracketed[close + 1..];
        if !valid_optional_port(suffix) {
            return false;
        }
        host
    } else if let Some((host, port)) = value.rsplit_once(':') {
        if port.parse::<u16>().is_err() {
            return false;
        }
        host
    } else {
        value
    };

    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

pub(crate) fn valid_optional_port(suffix: &str) -> bool {
    suffix.is_empty()
        || suffix
            .strip_prefix(':')
            .is_some_and(|port| port.parse::<u16>().is_ok())
}

pub(crate) fn parse_optional_json_object(body: &[u8]) -> Result<Value, ApiError> {
    if body.is_empty() {
        Ok(json!({}))
    } else {
        parse_json_object(body)
    }
}

pub(crate) fn parse_json_object(body: &[u8]) -> Result<Value, ApiError> {
    let value: Value = serde_json::from_slice(body)
        .map_err(|error| ApiError::new(ApiStatus::BadRequest, format!("invalid JSON: {error}")))?;
    if !value.is_object() {
        return Err(ApiError::new(
            ApiStatus::BadRequest,
            "request JSON must be an object",
        ));
    }
    Ok(value)
}

pub(crate) fn required_string(value: &Value, field: &str) -> Result<String, ApiError> {
    let text = value
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .ok_or_else(|| {
            ApiError::new(
                ApiStatus::BadRequest,
                format!("request field {field:?} must be a non-empty string"),
            )
        })?;
    Ok(text.to_owned())
}

pub(crate) fn require_only_fields(value: &Value, allowed: &[&str]) -> Result<(), ApiError> {
    let object = value
        .as_object()
        .ok_or_else(|| ApiError::new(ApiStatus::BadRequest, "request JSON must be an object"))?;
    if let Some(field) = object
        .keys()
        .find(|field| !allowed.contains(&field.as_str()))
    {
        return Err(ApiError::new(
            ApiStatus::BadRequest,
            format!("unsupported request field {field:?}"),
        ));
    }
    Ok(())
}

pub(crate) fn optional_string(value: &Value, field: &str) -> Result<Option<String>, ApiError> {
    let Some(raw) = value.get(field) else {
        return Ok(None);
    };
    if raw.is_null() {
        return Ok(None);
    }
    let text = raw.as_str().ok_or_else(|| {
        ApiError::new(
            ApiStatus::BadRequest,
            format!("request field {field:?} must be a string or null"),
        )
    })?;
    let text = text.trim();
    Ok((!text.is_empty()).then(|| text.to_owned()))
}

pub(crate) fn require_empty_body(body: &[u8]) -> Result<(), ApiError> {
    if body.is_empty() {
        Ok(())
    } else {
        Err(ApiError::new(
            ApiStatus::BadRequest,
            "GET status does not accept a request body",
        ))
    }
}
