use sovereign_state::{NewJournalEvent, StateStore};
use std::io::{self, Write};
use std::process::ExitCode;
use std::time::Duration;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("state fixture writer failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1).ok_or("missing database path")?;
    let mut store = StateStore::open(path)?;
    store.append_event(NewJournalEvent {
        event_id: "event_committed_before_kill",
        entity_type: "attempt",
        entity_id: "attempt_fixture",
        event_kind: "committed",
        payload_json: "{\"durable\":true}",
    })?;

    println!("COMMITTED");
    io::stdout().flush()?;
    loop {
        std::thread::sleep(Duration::from_secs(60));
    }
}
