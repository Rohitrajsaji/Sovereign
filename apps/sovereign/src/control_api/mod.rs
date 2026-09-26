//! Loopback Control API. The UI never writes `SQLite`; mutations go through the actor.
//! Callers: `main.rs` `serve`, CLI-era tests, and `e2e_server`.
//! API: `serve_listener`, `serve_one`, `parse_request`, `ControlApiRequest`.
//! Schema: `schemas/control-api-v2.json`.
//! User instruction: verify the consumer plan and execute only what is genuinely missing.

mod parse;
mod routes;
mod server;
mod sse;
mod static_assets;

#[allow(unused_imports)]
pub(crate) use parse::parse_request;
pub(crate) use server::serve_listener;
#[cfg(test)]
pub(crate) use server::{IDLE_CLOSE, MAX_BODY_BYTES, serve_one};

use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

pub(crate) const BASE_SECURITY_HEADERS: &str = "\
X-Content-Type-Options: nosniff\r\n\
Referrer-Policy: no-referrer\r\n\
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'\r\n";

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
    Session,
    Doctor,
    Overview,
    ListProjects,
    AddProject {
        root: String,
        display_name: String,
    },
    ActivateProject {
        project_id: String,
    },
    CreateProject {
        name: String,
    },
    /// Adopts a folder. Without `root`, the native folder picker asks the person.
    OpenFolder {
        root: Option<String>,
    },
    ListGoals,
    GetGoal {
        goal_id: String,
    },
    GetGoalActivity {
        goal_id: String,
    },
    CancelGoal {
        goal_id: String,
        principal: String,
    },
    UndoGoal {
        goal_id: String,
    },
    ApplyGoal {
        goal_id: String,
    },
    ListEvents {
        after: i64,
        limit: usize,
    },
    EventStream {
        last_event_id: i64,
    },
    GetArtifact {
        digest: String,
        offset: u64,
        length: usize,
    },
    GetTaskDiff {
        key: String,
    },
    GetApproval {
        request_id: String,
    },
    DownloadModel {
        confirmation: Option<String>,
    },
    SetupStatus,
    CancelModelDownload,
    InstallDeveloperTools,
    GetRecovery,
    VerifyModel {
        runtime_path: String,
        model_path: String,
    },
    GetSettings,
    SaveSettings {
        approval_principal: Option<String>,
        chrome_path: Option<String>,
        node_path: Option<String>,
        execute_on_start: Option<bool>,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct ServerConfig {
    pub(crate) session_token: Option<String>,
    pub(crate) require_token_for_v1_post: bool,
    pub(crate) state_path: Option<PathBuf>,
    pub(crate) sse_clients: Arc<AtomicUsize>,
    /// App-data directory holding the single-use `launch-code` file, when launch codes are on.
    pub(crate) launch_code_dir: Option<PathBuf>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            session_token: None,
            require_token_for_v1_post: false,
            state_path: None,
            sse_clients: Arc::new(AtomicUsize::new(0)),
            launch_code_dir: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ApiStatus {
    Ok,
    #[allow(dead_code)]
    Found,
    #[allow(dead_code)]
    NotModified,
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    MethodNotAllowed,
    PayloadTooLarge,
    ServiceUnavailable,
    InternalServerError,
}

impl ApiStatus {
    pub(crate) const fn code(self) -> u16 {
        match self {
            Self::Ok => 200,
            Self::Found => 302,
            Self::NotModified => 304,
            Self::BadRequest => 400,
            Self::Unauthorized => 401,
            Self::Forbidden => 403,
            Self::NotFound => 404,
            Self::MethodNotAllowed => 405,
            Self::PayloadTooLarge => 413,
            Self::ServiceUnavailable => 503,
            Self::InternalServerError => 500,
        }
    }

    pub(crate) const fn reason(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Found => "Found",
            Self::NotModified => "Not Modified",
            Self::BadRequest => "Bad Request",
            Self::Unauthorized => "Unauthorized",
            Self::Forbidden => "Forbidden",
            Self::NotFound => "Not Found",
            Self::MethodNotAllowed => "Method Not Allowed",
            Self::PayloadTooLarge => "Payload Too Large",
            Self::ServiceUnavailable => "Service Unavailable",
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
    pub(crate) fn new(status: ApiStatus, message: impl Into<String>) -> Self {
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
    TcpListener::bind(address).map_err(|error| bind_error_message(address, &error))
}

fn bind_error_message(address: SocketAddr, error: &std::io::Error) -> String {
    if error.kind() == std::io::ErrorKind::AddrInUse {
        format!(
            "{address} is already in use. Another Sovereign service may be running (check `sovereign service status`), or another app owns this port. Stop it or pass a different loopback address to `sovereign serve`."
        )
    } else {
        format!("cannot listen on {address}: {error}")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::similar_names, clippy::too_many_lines)]
mod tests {
    #[test]
    fn port_in_use_names_the_address_and_next_step() {
        let first = super::bind_loopback("127.0.0.1:0".parse().unwrap()).unwrap();
        let taken = first.local_addr().unwrap();
        let error = super::bind_loopback(taken).unwrap_err();
        assert!(error.contains("already in use"), "{error}");
        assert!(error.contains(&taken.to_string()), "{error}");
    }

    use super::{
        ControlApiRequest, IDLE_CLOSE, MAX_BODY_BYTES, ServerConfig, bind_loopback, parse_request,
        serve_listener, validate_loopback_addr,
    };
    use serde_json::json;
    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
    use std::thread;
    use std::time::{Duration, Instant};

    fn request(method: &str, path: &str, body: &str) -> Vec<u8> {
        format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    fn read_status(addr: SocketAddr, req: &str) -> String {
        let mut stream =
            TcpStream::connect(addr).unwrap_or_else(|error| panic!("connect: {error}"));
        stream
            .write_all(req.as_bytes())
            .unwrap_or_else(|error| panic!("write: {error}"));
        let mut buf = vec![0_u8; 2048];
        let n = stream
            .read(&mut buf)
            .unwrap_or_else(|error| panic!("read: {error}"));
        String::from_utf8_lossy(&buf[..n]).into_owned()
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
        assert_eq!(
            parse_request(&request("GET", "/v2/events?after=3&limit=10", ""))
                .unwrap_or_else(|error| panic!("events: {}", error.message)),
            ControlApiRequest::ListEvents {
                after: 3,
                limit: 10
            }
        );
        assert_eq!(
            parse_request(&request("GET", "/v2/events/stream", ""))
                .unwrap_or_else(|error| panic!("stream: {}", error.message)),
            ControlApiRequest::EventStream { last_event_id: 0 }
        );

        assert!(parse_request(&request("POST", "/v1/state/controller.task", "{}")).is_err());
        assert!(parse_request(&request("POST", "/v1/actions/action-1/dispatch", "{}")).is_err());
        assert!(parse_request(&request(
            "POST",
            "/v1/approvals/respond",
            r#"{"request_id":"request-1","decision":"approve","principal":"operator","payload":"replacement"}"#
        ))
        .is_err());
        assert!(parse_request(&request("DELETE", "/v1/status", "")).is_err());
        assert!(
            parse_request(
                b"GET /dashboard HTTP/1.1\r\nHost: attacker.example\r\nContent-Length: 0\r\n\r\n"
            )
            .is_err()
        );
        assert!(parse_request(
            b"POST /v1/control/pause HTTP/1.1\r\nHost: 127.0.0.1:7777\r\nOrigin: https://attacker.example\r\nContent-Length: 2\r\n\r\n{}"
        )
        .is_err());
        assert!(parse_request(
            b"POST /v1/control/pause HTTP/1.1\r\nHost: [::1]:7777\r\nOrigin: http://[::1]:7777\r\nContent-Length: 2\r\n\r\n{}"
        )
        .is_ok());
    }

    #[test]
    fn concurrent_requests_and_timeouts() {
        let listener = bind_loopback(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .unwrap_or_else(|error| panic!("bind: {error}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("addr: {error}"));
        thread::spawn(move || {
            let _ = serve_listener(
                &listener,
                |req| match req {
                    ControlApiRequest::ReadModel => Ok(json!({"status": "ok"})),
                    _ => Err("unsupported".to_owned()),
                },
                ServerConfig::default(),
            );
        });
        let mut handles = Vec::new();
        for _ in 0..50 {
            handles.push(thread::spawn(move || {
                let res = read_status(
                    addr,
                    "GET /v1/status HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
                );
                assert!(res.starts_with("HTTP/1.1 200 OK\r\n"));
            }));
        }
        for handle in handles {
            handle.join().unwrap_or_else(|_| panic!("worker panicked"));
        }
    }

    #[test]
    fn oversized_body_returns_413() {
        let listener = bind_loopback(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .unwrap_or_else(|error| panic!("bind: {error}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("addr: {error}"));
        thread::spawn(move || {
            let _ = serve_listener(&listener, |_| Ok(json!({})), ServerConfig::default());
        });
        let length = MAX_BODY_BYTES + 8;
        let body = "x".repeat(length);
        let req = format!(
            "POST /v1/goals HTTP/1.1\r\nHost: localhost\r\nContent-Length: {length}\r\n\r\n{body}"
        );
        let res = read_status(addr, &req);
        assert!(
            res.starts_with("HTTP/1.1 413 Payload Too Large\r\n"),
            "{res}"
        );
    }

    #[test]
    fn slow_client_does_not_block_other_workers() {
        let listener = bind_loopback(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .unwrap_or_else(|error| panic!("bind: {error}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("addr: {error}"));
        thread::spawn(move || {
            let _ = serve_listener(
                &listener,
                |req| match req {
                    ControlApiRequest::ReadModel => Ok(json!({"status": "ok"})),
                    _ => Err("unsupported".to_owned()),
                },
                ServerConfig::default(),
            );
        });
        let slow = thread::spawn(move || {
            let mut stream =
                TcpStream::connect(addr).unwrap_or_else(|error| panic!("slow connect: {error}"));
            let prefix = b"GET /v1/status HTTP/1.1\r\nHost: localhost\r\n";
            stream
                .write_all(prefix)
                .unwrap_or_else(|error| panic!("slow write: {error}"));
            thread::sleep(Duration::from_millis(400));
            stream
                .write_all(b"Content-Length: 0\r\n\r\n")
                .unwrap_or_else(|error| panic!("slow finish: {error}"));
        });
        let started = Instant::now();
        let res = read_status(
            addr,
            "GET /v1/status HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
        );
        assert!(res.starts_with("HTTP/1.1 200 OK\r\n"), "{res}");
        assert!(started.elapsed() < Duration::from_secs(1));
        slow.join().unwrap_or_else(|_| panic!("slow join"));
        assert_eq!(IDLE_CLOSE, Duration::from_secs(30));
    }

    #[test]
    fn v2_session_token_and_csrf_enforcement() {
        let listener = bind_loopback(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .unwrap_or_else(|error| panic!("bind: {error}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("addr: {error}"));
        let secret = "secret-token-1234567890".to_owned();
        let cfg = ServerConfig {
            session_token: Some(secret.clone()),
            require_token_for_v1_post: false,
            ..ServerConfig::default()
        };
        thread::spawn(move || {
            let _ = serve_listener(
                &listener,
                |req| match req {
                    ControlApiRequest::Overview => Ok(json!({"overview": "ok"})),
                    ControlApiRequest::Pause { .. } => Ok(json!({"paused": true})),
                    _ => Err("unsupported".to_owned()),
                },
                cfg,
            );
        });
        let missing = read_status(
            addr,
            "GET /v2/overview HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
        );
        assert!(missing.starts_with("HTTP/1.1 401 Unauthorized\r\n"));
        let cookie = format!(
            "GET /v2/overview HTTP/1.1\r\nHost: localhost\r\nCookie: sovereign_session={secret}\r\nContent-Length: 0\r\n\r\n"
        );
        assert!(read_status(addr, &cookie).starts_with("HTTP/1.1 200 OK\r\n"));
        let no_csrf = format!(
            "POST /v2/control/pause HTTP/1.1\r\nHost: localhost\r\nCookie: sovereign_session={secret}\r\nContent-Length: 2\r\n\r\n{{}}"
        );
        assert!(read_status(addr, &no_csrf).starts_with("HTTP/1.1 403 Forbidden\r\n"));
        let with_csrf = format!(
            "POST /v2/control/pause HTTP/1.1\r\nHost: localhost\r\nCookie: sovereign_session={secret}\r\nX-Sovereign-CSRF: {secret}\r\nContent-Length: 2\r\n\r\n{{}}"
        );
        assert!(read_status(addr, &with_csrf).starts_with("HTTP/1.1 200 OK\r\n"));
    }

    #[test]
    fn launch_code_sets_cookie_once_and_query_token_does_not_authenticate_v2() {
        let listener = bind_loopback(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .unwrap_or_else(|error| panic!("bind: {error}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("addr: {error}"));
        let dir = std::env::temp_dir().join(format!(
            "sovereign-launch-code-http-{}-{}",
            std::process::id(),
            addr.port()
        ));
        let code = crate::launch_code::issue(&dir).unwrap_or_else(|error| panic!("{error}"));
        let secret = "secret-token-launch-code".to_owned();
        let cfg = ServerConfig {
            session_token: Some(secret.clone()),
            launch_code_dir: Some(dir.clone()),
            ..ServerConfig::default()
        };
        thread::spawn(move || {
            let _ = serve_listener(
                &listener,
                |req| match req {
                    ControlApiRequest::Overview => Ok(json!({"overview": "ok"})),
                    _ => Err("unsupported".to_owned()),
                },
                cfg,
            );
        });
        let redeem =
            format!("GET /?c={code} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n");
        let first = read_status(addr, &redeem);
        assert!(first.starts_with("HTTP/1.1 302 Found\r\n"), "{first}");
        assert!(first.contains(&format!("sovereign_session={secret}; HttpOnly")));
        let replay = read_status(addr, &redeem);
        assert!(!replay.contains("Set-Cookie"), "{replay}");
        let query_token = format!(
            "GET /v2/overview?t={secret} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n"
        );
        assert!(read_status(addr, &query_token).starts_with("HTTP/1.1 401 Unauthorized\r\n"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn require_token_rejects_v1_post_without_session() {
        let listener = bind_loopback(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .unwrap_or_else(|error| panic!("bind: {error}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("addr: {error}"));
        let cfg = ServerConfig {
            session_token: Some("phase5-token".to_owned()),
            require_token_for_v1_post: true,
            ..ServerConfig::default()
        };
        thread::spawn(move || {
            let _ = serve_listener(&listener, |_| Ok(json!({})), cfg);
        });
        let res = read_status(
            addr,
            "POST /v1/control/resume HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{}",
        );
        assert!(res.starts_with("HTTP/1.1 401 Unauthorized\r\n"), "{res}");
    }

    #[test]
    fn static_asset_and_etag_behavior() {
        let listener = bind_loopback(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .unwrap_or_else(|error| panic!("bind: {error}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("addr: {error}"));
        thread::spawn(move || {
            let _ = serve_listener(
                &listener,
                |_| Err("not reached".to_owned()),
                ServerConfig::default(),
            );
        });
        let first = read_status(
            addr,
            "GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
        );
        assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(first.contains("ETag: "));
        let etag = first
            .lines()
            .find(|line| line.starts_with("ETag: "))
            .unwrap_or_else(|| panic!("missing etag"))
            .strip_prefix("ETag: ")
            .unwrap_or_default()
            .to_owned();
        let cached = read_status(
            addr,
            &format!(
                "GET / HTTP/1.1\r\nHost: localhost\r\nIf-None-Match: {etag}\r\nContent-Length: 0\r\n\r\n"
            ),
        );
        assert!(cached.starts_with("HTTP/1.1 304 Not Modified\r\n"));
        let traversal = read_status(
            addr,
            "GET /../secret HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
        );
        assert!(traversal.starts_with("HTTP/1.1 404 Not Found\r\n"));
        let dashboard = read_status(
            addr,
            "GET /dashboard HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
        );
        assert!(dashboard.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(!dashboard.contains("/v1/status"));
    }
}
