use sovereign_state::StateStore;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

fn fixture_dir() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let path = std::env::temp_dir().join(format!(
        "sovereign-state-kill-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap_or_else(|error| panic!("create fixture: {error}"));
    path
}

#[test]
fn committed_wal_event_survives_forced_process_kill_and_reopen() {
    let dir = fixture_dir();
    let db = dir.join("state.sqlite3");
    let executable = env!("CARGO_BIN_EXE_state-fixture-writer");
    let mut child = Command::new(executable)
        .arg(&db)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("spawn writer: {error}"));

    let stdout = child
        .stdout
        .take()
        .unwrap_or_else(|| panic!("missing stdout"));
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .unwrap_or_else(|error| panic!("read writer: {error}"));
    assert_eq!(line.trim(), "COMMITTED");

    child
        .kill()
        .unwrap_or_else(|error| panic!("kill writer: {error}"));
    let _status = child
        .wait()
        .unwrap_or_else(|error| panic!("wait writer: {error}"));

    let store = StateStore::open(&db).unwrap_or_else(|error| panic!("reopen: {error}"));
    let events = store
        .journal()
        .unwrap_or_else(|error| panic!("journal: {error}"));
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_id, "event_committed_before_kill");
    assert_eq!(events[0].payload_json, "{\"durable\":true}");

    drop(store);
    let _ = fs::remove_dir_all(dir);
}
