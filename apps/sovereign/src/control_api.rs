use serde_json::{Value, json};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};

const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_BODY_BYTES: usize = 64 * 1024;
const MAX_REQUEST_BYTES: usize = MAX_HEADER_BYTES + MAX_BODY_BYTES;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ControlApiRequest {
    ReadModel,
    SubmitGoal {
        goal: String,
    },
    Pause {
        reason: Option<String>,
    },
    Resume,
    RespondToApproval {
        request_id: String,
        decision: String,
        principal: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ApiStatus {
    Ok,
    BadRequest,
    NotFound,
    MethodNotAllowed,
    PayloadTooLarge,
    InternalServerError,
}

impl ApiStatus {
    const fn code(self) -> u16 {
        match self {
            Self::Ok => 200,
            Self::BadRequest => 400,
            Self::NotFound => 404,
            Self::MethodNotAllowed => 405,
            Self::PayloadTooLarge => 413,
            Self::InternalServerError => 500,
        }
    }

    const fn reason(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::BadRequest => "Bad Request",
            Self::NotFound => "Not Found",
            Self::MethodNotAllowed => "Method Not Allowed",
            Self::PayloadTooLarge => "Payload Too Large",
            Self::InternalServerError => "Internal Server Error",
        }
    }
}

#[derive(Debug)]
pub(crate) struct ApiError {
    pub(crate) status: ApiStatus,
    pub(crate) message: String,
}

impl ApiError {
    fn new(status: ApiStatus, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

pub(crate) fn validate_loopback_addr(address: SocketAddr) -> Result<(), String> {
    if !address.ip().is_loopback() {
        return Err(format!(
            "local control API must bind a loopback address, got {}",
            address.ip()
        ));
    }
    Ok(())
}

pub(crate) fn bind_loopback(address: SocketAddr) -> Result<TcpListener, String> {
    validate_loopback_addr(address)?;
    TcpListener::bind(address).map_err(|error| error.to_string())
}

pub(crate) fn serve_listener<F>(listener: &TcpListener, mut handle: F) -> Result<(), String>
where
    F: FnMut(ControlApiRequest) -> Result<Value, String>,
{
    for incoming in listener.incoming() {
        let mut stream = incoming.map_err(|error| error.to_string())?;
        serve_stream(&mut stream, &mut handle)?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn serve_one<F>(listener: &TcpListener, mut handle: F) -> Result<(), String>
where
    F: FnMut(ControlApiRequest) -> Result<Value, String>,
{
    let (mut stream, _) = listener.accept().map_err(|error| error.to_string())?;
    serve_stream(&mut stream, &mut handle)
}

fn serve_stream<F>(stream: &mut TcpStream, handle: &mut F) -> Result<(), String>
where
    F: FnMut(ControlApiRequest) -> Result<Value, String>,
{
    let response = match read_request(stream).and_then(|bytes| parse_request(&bytes)) {
        Ok(request) => match handle(request) {
            Ok(body) => (ApiStatus::Ok, body),
            Err(message) => (ApiStatus::InternalServerError, json!({"error": message})),
        },
        Err(error) => (error.status, json!({"error": error.message})),
    };
    write_response(stream, response.0, &response.1)
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
            header_end = find_header_end(&bytes);
            if let Some(end) = header_end {
                if end > MAX_HEADER_BYTES {
                    return Err(ApiError::new(
                        ApiStatus::PayloadTooLarge,
                        "request headers exceed local control API size limit",
                    ));
                }
                content_length = Some(parse_content_length(&bytes[..end])?);
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

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

fn parse_content_length(headers: &[u8]) -> Result<usize, ApiError> {
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

fn parse_request(bytes: &[u8]) -> Result<ControlApiRequest, ApiError> {
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
        .ok_or_else(|| ApiError::new(ApiStatus::BadRequest, "missing HTTP method"))?;
    let path = fields
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

    let body = &bytes[header_end..];
    match (method, path) {
        ("GET", "/v1/status") => {
            require_empty_body(body)?;
            Ok(ControlApiRequest::ReadModel)
        }
        ("POST", "/v1/goals") => {
            let value = parse_json_object(body)?;
            require_only_fields(&value, &["goal"])?;
            Ok(ControlApiRequest::SubmitGoal {
                goal: required_string(&value, "goal")?,
            })
        }
        ("POST", "/v1/control/pause") => {
            let value = parse_optional_json_object(body)?;
            require_only_fields(&value, &["reason"])?;
            let reason = optional_string(&value, "reason")?;
            Ok(ControlApiRequest::Pause { reason })
        }
        ("POST", "/v1/control/resume") => {
            if !body.is_empty() {
                let value = parse_json_object(body)?;
                if !value.as_object().is_some_and(serde_json::Map::is_empty) {
                    return Err(ApiError::new(
                        ApiStatus::BadRequest,
                        "resume accepts only an empty JSON object",
                    ));
                }
            }
            Ok(ControlApiRequest::Resume)
        }
        ("POST", "/v1/approvals/respond") => {
            let value = parse_json_object(body)?;
            require_only_fields(&value, &["request_id", "decision", "principal"])?;
            let decision = required_string(&value, "decision")?;
            if !matches!(decision.as_str(), "approve" | "deny") {
                return Err(ApiError::new(
                    ApiStatus::BadRequest,
                    "approval decision must be `approve` or `deny`",
                ));
            }
            Ok(ControlApiRequest::RespondToApproval {
                request_id: required_string(&value, "request_id")?,
                decision,
                principal: required_string(&value, "principal")?,
            })
        }
        ("GET" | "POST", _) => Err(ApiError::new(
            ApiStatus::NotFound,
            "unknown local control API route",
        )),
        _ => Err(ApiError::new(
            ApiStatus::MethodNotAllowed,
            "local control API supports only GET and POST",
        )),
    }
}

fn parse_optional_json_object(body: &[u8]) -> Result<Value, ApiError> {
    if body.is_empty() {
        Ok(json!({}))
    } else {
        parse_json_object(body)
    }
}

fn parse_json_object(body: &[u8]) -> Result<Value, ApiError> {
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

fn required_string(value: &Value, field: &str) -> Result<String, ApiError> {
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

fn require_only_fields(value: &Value, allowed: &[&str]) -> Result<(), ApiError> {
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

fn optional_string(value: &Value, field: &str) -> Result<Option<String>, ApiError> {
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

fn require_empty_body(body: &[u8]) -> Result<(), ApiError> {
    if body.is_empty() {
        Ok(())
    } else {
        Err(ApiError::new(
            ApiStatus::BadRequest,
            "GET status does not accept a request body",
        ))
    }
}

fn write_response(stream: &mut TcpStream, status: ApiStatus, body: &Value) -> Result<(), String> {
    let body = serde_json::to_vec(body).map_err(|error| error.to_string())?;
    let headers = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\n\r\n",
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

#[cfg(test)]
mod tests {
    use super::{ControlApiRequest, bind_loopback, parse_request, validate_loopback_addr};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    fn request(method: &str, path: &str, body: &str) -> Vec<u8> {
        format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    #[test]
    fn loopback_validation_rejects_nonlocal_bindings_before_bind() {
        let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0);
        assert!(validate_loopback_addr(v4).is_ok());
        assert!(validate_loopback_addr(v6).is_ok());
        assert!(bind_loopback(v4).is_ok());

        let wildcard = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 7777);
        assert!(validate_loopback_addr(wildcard).is_err());
        let public = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 7777);
        assert!(validate_loopback_addr(public).is_err());
    }

    #[test]
    fn parser_exposes_only_bounded_local_control_operations() {
        assert_eq!(
            parse_request(&request("GET", "/v1/status", ""))
                .unwrap_or_else(|error| panic!("read model parse: {}", error.message)),
            ControlApiRequest::ReadModel
        );
        assert_eq!(
            parse_request(&request(
                "POST",
                "/v1/goals",
                r#"{"goal":"Build inventory"}"#
            ))
            .unwrap_or_else(|error| panic!("goal parse: {}", error.message)),
            ControlApiRequest::SubmitGoal {
                goal: "Build inventory".to_owned()
            }
        );
        assert_eq!(
            parse_request(&request(
                "POST",
                "/v1/approvals/respond",
                r#"{"request_id":"request-1","decision":"approve","principal":"operator"}"#
            ))
            .unwrap_or_else(|error| panic!("approval parse: {}", error.message)),
            ControlApiRequest::RespondToApproval {
                request_id: "request-1".to_owned(),
                decision: "approve".to_owned(),
                principal: "operator".to_owned()
            }
        );

        assert!(parse_request(&request("POST", "/v1/state/controller.task", "{}")).is_err());
        assert!(parse_request(&request("POST", "/v1/actions/action-1/dispatch", "{}")).is_err());
        assert!(
            parse_request(&request(
                "POST",
                "/v1/approvals/respond",
                r#"{"request_id":"request-1","decision":"approve","principal":"operator","payload":"replacement"}"#
            ))
            .is_err()
        );
        assert!(parse_request(&request("DELETE", "/v1/status", "")).is_err());
    }
}
