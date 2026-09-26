//! Live `sovereign serve` contract coverage (CX-T07).
//! Callers: `cargo test -p sovereign --test control_api_contract`.
//! API: `/v2` responses from the production binary on loopback.
//! Schema: `schemas/control-api-v2.json`.
//! User instruction: Continue from the current tree and finish the remaining consumer-product gaps you identified. Expand `control_api_contract.rs` to validate responses from real sovereign serve on loopback.

#![allow(
    clippy::unwrap_used,
    clippy::similar_names,
    clippy::if_not_else,
    clippy::too_many_lines,
    clippy::expect_used
)]

use jsonschema::Validator;
use serde_json::{Value, json};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn nonce() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

fn load_validator(def_name: &str) -> Validator {
    let schema_text = include_str!("../../../schemas/control-api-v2.json");
    let full_schema: Value = serde_json::from_str(schema_text).unwrap();
    let fragment = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": format!("#/definitions/{def_name}"),
        "definitions": full_schema["definitions"]
    });
    jsonschema::validator_for(&fragment).unwrap()
}

fn http(addr: &str, request: &str) -> (u16, Value) {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf);
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let body_pos = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let val: Value = serde_json::from_slice(&buf[body_pos..]).unwrap_or_else(|_| json!({}));
    (status, val)
}

#[test]
fn control_api_v2_live_serve_matches_frozen_schema() {
    let home = std::env::temp_dir().join(format!("sovereign-live-contract-{}", nonce()));
    fs::create_dir_all(home.join("Library/Application Support/Sovereign")).unwrap();
    let state = home.join("state.sqlite3");
    let bin = env!("CARGO_BIN_EXE_sovereign");
    let mut child = Command::new(bin)
        .args(["serve", "--no-require-token", "127.0.0.1:0"])
        .env("HOME", &home)
        .env("SOVEREIGN_STATE_DB", &state)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let started = Instant::now();
    let mut collected = String::new();
    let mut addr = None;
    while started.elapsed() < Duration::from_secs(8) {
        let mut buf = [0u8; 512];
        if let Ok(n) = stderr.read(&mut buf) {
            if n == 0 {
                break;
            }
            collected.push_str(&String::from_utf8_lossy(&buf[..n]));
            if let Some(start) = collected.find("http://") {
                let rest = &collected[start + 7..];
                let hostport = rest.split(['/', '\n', ' ']).next().unwrap_or_default();
                if hostport.contains(':') {
                    addr = Some(hostport.trim().to_owned());
                    break;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let addr = addr.unwrap_or_else(|| panic!("serve did not print bind address: {collected}"));
    let token_path = home.join("Library/Application Support/Sovereign/service-token");
    let token = wait_token(&token_path);
    let cookie = format!("Cookie: sovereign_session={token}\r\n");

    let (status, session) = http(
        &addr,
        &format!("GET /v2/session HTTP/1.1\r\nHost: 127.0.0.1\r\n{cookie}\r\n"),
    );
    assert_eq!(status, 200, "{session}");
    assert!(
        load_validator("SessionResponse").is_valid(&session),
        "{session}"
    );
    let csrf = session["csrf_token"].as_str().unwrap();

    for (path, def) in [
        ("/v2/overview", "OverviewResponse"),
        ("/v2/doctor", "DoctorResponse"),
        ("/v2/projects", "ProjectsResponse"),
        ("/v2/goals", "GoalsResponse"),
        ("/v2/events", "EventsResponse"),
        ("/v2/settings", "SettingsV1"),
    ] {
        let (status, body) = http(
            &addr,
            &format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{cookie}\r\n"),
        );
        assert_eq!(status, 200, "{path} {body}");
        assert!(
            load_validator(def).is_valid(&body),
            "{path} failed {def}: {body}"
        );
    }

    let (status, recovery) = http(
        &addr,
        &format!("GET /v2/recovery HTTP/1.1\r\nHost: 127.0.0.1\r\n{cookie}\r\n"),
    );
    assert_eq!(status, 200, "{recovery}");
    assert!(
        load_validator("RecoveryExplanation").is_valid(&recovery["explanation"]),
        "{recovery}"
    );

    let (status, unauthorized) = http(
        &addr,
        "GET /v2/overview HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
    );
    assert_eq!(status, 401);
    assert!(load_validator("ErrorResponse").is_valid(&unauthorized));

    let (status, forbidden) = http(
        &addr,
        &format!(
            "POST /v2/control/pause HTTP/1.1\r\nHost: 127.0.0.1\r\n{cookie}Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{{}}"
        ),
    );
    assert_eq!(status, 403, "{forbidden}");
    assert!(load_validator("ErrorResponse").is_valid(&forbidden));

    let body = json!({"goal": "Live contract goal"});
    let bytes = serde_json::to_vec(&body).unwrap();
    let (status, queued) = http(
        &addr,
        &format!(
            "POST /v2/goals HTTP/1.1\r\nHost: 127.0.0.1\r\n{cookie}X-Sovereign-CSRF: {csrf}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            bytes.len(),
            String::from_utf8(bytes).unwrap()
        ),
    );
    assert_eq!(status, 200, "{queued}");
    assert!(load_validator("GoalIntent").is_valid(&queued), "{queued}");

    let goal_id = queued["goal_id"].as_str().unwrap();
    let (status, detail) = http(
        &addr,
        &format!("GET /v2/goals/{goal_id} HTTP/1.1\r\nHost: 127.0.0.1\r\n{cookie}\r\n"),
    );
    assert_eq!(status, 200, "{detail}");
    assert!(load_validator("GoalDetail").is_valid(&detail), "{detail}");

    let post = |path: &str, body: &Value| {
        let bytes = serde_json::to_vec(body).unwrap();
        http(
            &addr,
            &format!(
                "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{cookie}X-Sovereign-CSRF: {csrf}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                bytes.len(),
                String::from_utf8(bytes).unwrap()
            ),
        )
    };
    let (status, created) = post("/v2/projects/create", &json!({"name": "Contract Demo"}));
    assert_eq!(status, 200, "{created}");
    assert!(
        load_validator("ProjectOpenResponse").is_valid(&created),
        "{created}"
    );
    assert_eq!(created["project"]["managed"], json!(true), "{created}");
    let created_root = PathBuf::from(created["project"]["root"].as_str().unwrap());
    assert!(created_root.starts_with(home.join("Sovereign Projects")));
    assert!(created_root.join("index.html").is_file());

    let plain = home.join("plain-folder");
    fs::create_dir_all(&plain).unwrap();
    fs::write(plain.join("notes.txt"), "hello").unwrap();
    let (status, opened) = post(
        "/v2/projects/open",
        &json!({"root": plain.to_string_lossy()}),
    );
    assert_eq!(status, 200, "{opened}");
    assert!(
        load_validator("ProjectOpenResponse").is_valid(&opened),
        "{opened}"
    );
    let (status, listed) = http(
        &addr,
        &format!("GET /v2/projects HTTP/1.1\r\nHost: 127.0.0.1\r\n{cookie}\r\n"),
    );
    assert_eq!(status, 200, "{listed}");
    assert!(
        load_validator("ProjectsResponse").is_valid(&listed),
        "{listed}"
    );
    assert_eq!(listed["projects"].as_array().map(Vec::len), Some(2));
    assert_eq!(listed["active_project_id"], opened["project"]["project_id"]);

    let (status, setup) = http(
        &addr,
        &format!("GET /v2/setup HTTP/1.1\r\nHost: 127.0.0.1\r\n{cookie}\r\n"),
    );
    assert_eq!(status, 200, "{setup}");
    assert!(load_validator("SetupStatus").is_valid(&setup), "{setup}");
    let (status, cancelled) = post("/v2/setup/model/cancel", &json!({}));
    assert_eq!(status, 200, "{cancelled}");
    assert!(
        load_validator("DownloadResponse").is_valid(&cancelled),
        "{cancelled}"
    );

    // Undo and Apply exist and explain, in words, why there is nothing to do yet.
    for action in ["undo", "apply"] {
        let (status, refused) = post(&format!("/v2/goals/{goal_id}/{action}"), &json!({}));
        assert!(
            status != 200 && status != 404,
            "{action}: {status} {refused}"
        );
        assert!(
            load_validator("ErrorResponse").is_valid(&refused),
            "{action}: {refused}"
        );
    }

    let _ = child.kill();
    let _ = child.wait();
    let _ = fs::remove_dir_all(&home);
}

fn wait_token(path: &PathBuf) -> String {
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(5) {
        if let Ok(token) = fs::read_to_string(path) {
            let token = token.trim().to_owned();
            if !token.is_empty() {
                return token;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("service-token was not written");
}

#[test]
fn production_binary_has_no_e2e_fixture_symbols() {
    let bytes = fs::read(env!("CARGO_BIN_EXE_sovereign")).unwrap();
    let hay = String::from_utf8_lossy(&bytes);
    assert!(!hay.contains("e2e-session-token"));
    assert!(!hay.contains("sovereign-e2e-server"));
    assert!(!hay.contains("SOVEREIGN_FIXTURE_BACKEND"));
}
