//! Ignored real-model consumer acceptance (CX-T25).
//! Callers: manual M1 run. API: /v2 over HTTP. Schema: control-api-v2.json.
//! User instruction: Continue from the current tree and finish the remaining consumer-product gaps you identified. CX-T25 ignored HTTP acceptance.

#![allow(
    clippy::expect_used,
    clippy::ignore_without_reason,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn env_or_skip() -> (PathBuf, PathBuf) {
    let runtime = std::env::var_os("SOVEREIGN_MODEL_RUNTIME")
        .map(PathBuf::from)
        .expect("set SOVEREIGN_MODEL_RUNTIME and SOVEREIGN_MODEL_PATH on the M1");
    let model = std::env::var_os("SOVEREIGN_MODEL_PATH")
        .map(PathBuf::from)
        .expect("set SOVEREIGN_MODEL_RUNTIME and SOVEREIGN_MODEL_PATH on the M1");
    (runtime, model)
}

fn http(addr: &str, request: &str) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    stream.write_all(request.as_bytes()).expect("write");
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

fn wait_addr(stderr: &mut impl Read) -> String {
    let started = Instant::now();
    let mut collected = String::new();
    while started.elapsed() < Duration::from_secs(20) {
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
                    return hostport.trim().to_owned();
                }
            }
        }
    }
    panic!("serve printed a bind address: {collected}");
}

fn wait_token(path: &PathBuf) -> String {
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(8) {
        if let Ok(value) = std::fs::read_to_string(path) {
            let token = value.trim().to_owned();
            if !token.is_empty() {
                return token;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("session token");
}

fn csrf_from(session: &str) -> String {
    session
        .split("csrf_token\":\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("csrf")
        .to_owned()
}

fn spawn_serve(
    bin: &PathBuf,
    root: &PathBuf,
    state: &PathBuf,
    runtime: &PathBuf,
    model: &PathBuf,
) -> std::process::Child {
    Command::new(bin)
        .args(["serve", "--execute", "--no-require-token", "127.0.0.1:0"])
        .env("HOME", root)
        .env("SOVEREIGN_STATE_DB", state)
        .env("SOVEREIGN_MODEL_RUNTIME", runtime)
        .env("SOVEREIGN_MODEL_PATH", model)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("spawn serve: {error}"))
}

#[test]
#[ignore = "needs real GGUF and llama-server on the M1"]
fn consumer_serve_execute_completes_bounded_goal_without_replay() {
    let (runtime, model) = env_or_skip();
    assert!(runtime.is_file(), "runtime must exist");
    assert!(model.is_file(), "model must exist");

    let bin = std::env::var_os("SOVEREIGN_BIN").map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/sovereign"),
        PathBuf::from,
    );
    assert!(
        bin.is_file(),
        "build sovereign and set SOVEREIGN_BIN if needed"
    );
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let root = std::env::temp_dir().join(format!("sovereign-cx-t25-{nonce}"));
    std::fs::create_dir_all(root.join("Library/Application Support/Sovereign"))
        .unwrap_or_else(|error| panic!("{error}"));
    let repo = root.join("fixture-repo");
    std::fs::create_dir_all(&repo).unwrap_or_else(|error| panic!("{error}"));
    let git = Command::new("/usr/bin/git")
        .args(["init", "-q"])
        .current_dir(&repo)
        .status()
        .expect("git init");
    assert!(git.success());
    let state = root.join("state.sqlite3");
    let mut child = spawn_serve(&bin, &root, &state, &runtime, &model);
    let mut stderr = child.stderr.take().expect("stderr");
    let addr = wait_addr(&mut stderr);
    let token = wait_token(&root.join("Library/Application Support/Sovereign/service-token"));
    let cookie = format!("Cookie: sovereign_session={token}\r\n");
    let session = http(
        &addr,
        &format!("GET /v2/session HTTP/1.1\r\nHost: 127.0.0.1\r\n{cookie}\r\n"),
    );
    let csrf = csrf_from(&session);
    let project = format!(
        r#"{{"root":"{}","display_name":"Acceptance"}}"#,
        repo.display()
    );
    let added = http(
        &addr,
        &format!(
            "POST /v2/projects HTTP/1.1\r\nHost: 127.0.0.1\r\n{cookie}X-Sovereign-CSRF: {csrf}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{project}",
            project.len()
        ),
    );
    assert!(
        added.contains("project_id") || added.contains("projects"),
        "{added}"
    );

    let body = r#"{"goal":"Create a settings-form comment in README"}"#;
    let queued = http(
        &addr,
        &format!(
            "POST /v2/goals HTTP/1.1\r\nHost: 127.0.0.1\r\n{cookie}X-Sovereign-CSRF: {csrf}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        ),
    );
    assert!(queued.contains("goal_id"), "{queued}");
    let goal_id = queued
        .split("goal_id\":\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("goal_id")
        .to_owned();

    std::thread::sleep(Duration::from_millis(800));
    let _ = child.kill();
    let _ = child.wait();

    let mut restarted = spawn_serve(&bin, &root, &state, &runtime, &model);
    let mut restart_err = restarted.stderr.take().expect("stderr");
    let addr = wait_addr(&mut restart_err);
    let token = wait_token(&root.join("Library/Application Support/Sovereign/service-token"));
    let cookie = format!("Cookie: sovereign_session={token}\r\n");
    let deadline = Instant::now() + Duration::from_secs(600);
    let mut last = String::new();
    let mut completed = false;
    while Instant::now() < deadline {
        last = http(
            &addr,
            &format!("GET /v2/goals/{goal_id} HTTP/1.1\r\nHost: 127.0.0.1\r\n{cookie}\r\n"),
        );
        if last.contains("\"completed\"")
            || last.contains("\"cancelled\"")
            || last.contains("\"failed\"")
        {
            completed = last.contains("\"completed\"");
            break;
        }
        std::thread::sleep(Duration::from_secs(5));
    }
    let recovery = http(
        &addr,
        &format!("GET /v2/recovery HTTP/1.1\r\nHost: 127.0.0.1\r\n{cookie}\r\n"),
    );
    assert!(
        !recovery.contains("unknown_action") || recovery.contains("\"mutation_blocked\":false"),
        "{recovery}"
    );
    assert!(completed, "goal did not complete: {last}");

    let evidence_dir =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../implementation/evidence");
    let _ = std::fs::create_dir_all(&evidence_dir);
    let rss = Command::new("/bin/ps")
        .args(["-o", "rss=", "-p", &restarted.id().to_string()])
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .unwrap_or_default();
    let payload = format!(
        "{{\"task\":\"CX-T25\",\"goal_id\":\"{goal_id}\",\"completed\":true,\"rss_kb\":\"{}\",\"source\":\"consumer_acceptance.rs\"}}",
        rss.trim()
    );
    std::fs::write(evidence_dir.join("CX-T25.json"), payload).expect("write evidence");
    let _ = restarted.kill();
    let _ = restarted.wait();
}
