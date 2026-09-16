use serde_json::{Value, json};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};

const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_BODY_BYTES: usize = 64 * 1024;
const MAX_REQUEST_BYTES: usize = MAX_HEADER_BYTES + MAX_BODY_BYTES;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ControlApiRequest {
    Dashboard,
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
    match read_request(stream).and_then(|bytes| parse_request(&bytes)) {
        Ok(ControlApiRequest::Dashboard) => write_dashboard_response(stream),
        Ok(request) => {
            let response = match handle(request) {
                Ok(body) => (ApiStatus::Ok, body),
                Err(message) => (ApiStatus::InternalServerError, json!({"error": message})),
            };
            write_json_response(stream, response.0, &response.1)
        }
        Err(error) => write_json_response(stream, error.status, &json!({"error": error.message})),
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
    validate_local_request_headers(header_text, version)?;

    let body = &bytes[header_end..];
    match (method, path) {
        ("GET", "/" | "/dashboard") => {
            require_empty_body(body)?;
            Ok(ControlApiRequest::Dashboard)
        }
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

fn validate_local_request_headers(header_text: &str, version: &str) -> Result<(), ApiError> {
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

fn is_loopback_origin(value: &str) -> bool {
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

fn is_loopback_authority(value: &str) -> bool {
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

fn valid_optional_port(suffix: &str) -> bool {
    suffix.is_empty()
        || suffix
            .strip_prefix(':')
            .is_some_and(|port| port.parse::<u16>().is_ok())
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

const DASHBOARD_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sovereign Local Dashboard</title>
<style>
:root{font-family:ui-sans-serif,system-ui,sans-serif;color-scheme:light dark}
body{max-width:1100px;margin:0 auto;padding:24px}
header{display:flex;justify-content:space-between;gap:16px;align-items:center}
section{border:1px solid #7776;border-radius:10px;padding:14px;margin:14px 0}
pre{white-space:pre-wrap;overflow-wrap:anywhere}
button,input{font:inherit;padding:8px;margin:4px}
button{cursor:pointer}
.row{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
.muted{opacity:.7}
.error{color:#c33}
.approval{border-top:1px solid #7776;padding:10px 0}
</style>
</head>
<body>
<header>
<div>
<h1>Sovereign Local Dashboard</h1>
<div class="muted">Read model from the same Controller/StateStore authority as the CLI.</div>
</div>
<button id="refresh">Refresh</button>
</header>
<section>
<h2>Controller</h2>
<div id="control"></div>
<div class="row">
<input id="pause-reason" placeholder="Pause reason (optional)">
<button id="pause">Pause</button>
<button id="resume">Resume</button>
</div>
<div id="message" class="muted"></div>
</section>
<section><h2>Goals</h2><pre id="goals"></pre></section>
<section><h2>Plan</h2><pre id="plan"></pre></section>
<section><h2>Tasks &amp; Progress</h2><pre id="progress"></pre></section>
<section><h2>Verification &amp; Evidence</h2><pre id="verification"></pre></section>
<section>
<h2>Blocked Approvals</h2>
<div class="row"><input id="principal" value="operator" aria-label="Approval principal"></div>
<div id="approvals"></div>
</section>
<section><h2>Recovery</h2><pre id="recovery"></pre></section>
<script>
const show=(id,value)=>document.getElementById(id).textContent=JSON.stringify(value,null,2);
async function request(path,options){
  const response=await fetch(path,options);
  const body=await response.json();
  if(!response.ok)throw new Error(body.error||`HTTP ${response.status}`);
  return body;
}
function message(text,error=false){
  const node=document.getElementById('message');
  node.textContent=text;
  node.className=error?'error':'muted';
}
async function refresh(){
  try{
    const view=await request('/v1/status');
    const status=view.status||{};
    document.getElementById('control').textContent=status.execution_control?.paused?'Paused':'Running';
    show('goals',status.goal_intents||[]);
    show('plan',{active_plan:status.active_plan||null,plan_revisions:view.plan_revisions||[]});
    show('progress',{tasks:status.tasks||[],attempts:status.attempts||[],actions:status.actions||[]});
    show('verification',{verifications:view.verifications||[],evidence:status.evidence||[]});
    show('recovery',view.recovery||{});
    renderApprovals(view.blocked_approvals||[]);
    message('State refreshed.');
  }catch(error){message(error.message,true);}
}
function renderApprovals(items){
  const root=document.getElementById('approvals');
  root.replaceChildren();
  if(items.length===0){root.textContent='No blocked approvals.';return;}
  for(const item of items){
    const row=document.createElement('div');
    row.className='approval';
    const details=document.createElement('pre');
    details.textContent=JSON.stringify(item,null,2);
    const approve=document.createElement('button');
    approve.textContent='Approve';
    approve.onclick=()=>respond(item.request_id,'approve');
    const deny=document.createElement('button');
    deny.textContent='Deny';
    deny.onclick=()=>respond(item.request_id,'deny');
    row.append(details,approve,deny);
    root.append(row);
  }
}
async function post(path,payload){
  return request(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
}
async function respond(requestId,decision){
  const principal=document.getElementById('principal').value.trim();
  if(!principal){message('Approval principal is required.',true);return;}
  try{
    await post('/v1/approvals/respond',{request_id:requestId,decision,principal});
    await refresh();
  }catch(error){message(error.message,true);}
}
document.getElementById('refresh').onclick=refresh;
document.getElementById('pause').onclick=async()=>{
  try{
    const reason=document.getElementById('pause-reason').value.trim();
    await post('/v1/control/pause',reason?{reason}:{});
    await refresh();
  }catch(error){message(error.message,true);}
};
document.getElementById('resume').onclick=async()=>{
  try{await post('/v1/control/resume',{});await refresh();}
  catch(error){message(error.message,true);}
};
refresh();
</script>
</body>
</html>
"#;

fn write_dashboard_response(stream: &mut TcpStream) -> Result<(), String> {
    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'\r\n\r\n",
        DASHBOARD_HTML.len()
    );
    stream
        .write_all(headers.as_bytes())
        .and_then(|()| stream.write_all(DASHBOARD_HTML.as_bytes()))
        .and_then(|()| stream.flush())
        .map_err(|error| error.to_string())
}

fn write_json_response(
    stream: &mut TcpStream,
    status: ApiStatus,
    body: &Value,
) -> Result<(), String> {
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
            parse_request(&request("GET", "/dashboard", ""))
                .unwrap_or_else(|error| panic!("dashboard parse: {}", error.message)),
            ControlApiRequest::Dashboard
        );
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

        assert!(
            parse_request(
                b"GET /dashboard HTTP/1.1\r\nHost: attacker.example\r\nContent-Length: 0\r\n\r\n"
            )
            .is_err()
        );
        assert!(
            parse_request(
                b"POST /v1/control/pause HTTP/1.1\r\nHost: 127.0.0.1:7777\r\nOrigin: https://attacker.example\r\nContent-Length: 2\r\n\r\n{}"
            )
            .is_err()
        );
        assert!(
            parse_request(
                b"POST /v1/control/pause HTTP/1.1\r\nHost: [::1]:7777\r\nOrigin: http://[::1]:7777\r\nContent-Length: 2\r\n\r\n{}"
            )
            .is_ok()
        );
    }
}
