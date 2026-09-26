//! Server-sent events over the journal tail.
//! Callers: `server.rs` for `GET /v2/events/stream`.
//! API: `serve_event_stream`.
//! Schema: `EventProjection` in `schemas/control-api-v2.json`.
//! User instruction: implement the attached consumer product plan (CX-T12).

use super::server::write_json_response;
use super::{ApiStatus, BASE_SECURITY_HEADERS, ServerConfig};
use crate::projections;
use serde_json::json;
use sovereign_state::StateStore;
use std::io::Write;
use std::net::TcpStream;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::{Duration, Instant};

const POLL: Duration = Duration::from_millis(500);
const HEARTBEAT: Duration = Duration::from_secs(15);
pub(crate) const MAX_SSE_CLIENTS: usize = 4;

/// Tails the journal and writes SSE frames. At most four clients.
///
/// # Errors
/// Returns when headers or frames cannot be written.
pub(crate) fn serve_event_stream(
    stream: &mut TcpStream,
    config: &ServerConfig,
    last_event_id: i64,
) -> Result<(), String> {
    let Some(state_path) = config.state_path.as_ref() else {
        return write_json_response(
            stream,
            ApiStatus::ServiceUnavailable,
            &json!({"error": "event stream requires a state path"}),
        );
    };
    let current = config.sse_clients.fetch_add(1, Ordering::SeqCst);
    if current >= MAX_SSE_CLIENTS {
        config.sse_clients.fetch_sub(1, Ordering::SeqCst);
        return write_json_response(
            stream,
            ApiStatus::ServiceUnavailable,
            &json!({"error": "event stream client limit reached"}),
        );
    }
    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\nCache-Control: no-store\r\nConnection: keep-alive\r\n{BASE_SECURITY_HEADERS}\r\n"
    );
    let result = (|| {
        stream
            .write_all(headers.as_bytes())
            .and_then(|()| stream.flush())
            .map_err(|error| error.to_string())?;
        let mut after = last_event_id;
        let mut last_beat = Instant::now();
        loop {
            let store = StateStore::open(state_path).map_err(|error| error.to_string())?;
            let events = store
                .journal_after(after)
                .map_err(|error| error.to_string())?;
            drop(store);
            let projected = projections::project_events(&events, after, 200);
            for event in &projected {
                let data = serde_json::to_string(event).map_err(|error| error.to_string())?;
                let frame = format!("id: {}\ndata: {}\n\n", event.sequence, data);
                stream
                    .write_all(frame.as_bytes())
                    .and_then(|()| stream.flush())
                    .map_err(|error| error.to_string())?;
                after = event.sequence;
                last_beat = Instant::now();
            }
            if last_beat.elapsed() >= HEARTBEAT {
                stream
                    .write_all(b": keepalive\n\n")
                    .and_then(|()| stream.flush())
                    .map_err(|error| error.to_string())?;
                last_beat = Instant::now();
            }
            thread::sleep(POLL);
        }
    })();
    config.sse_clients.fetch_sub(1, Ordering::SeqCst);
    result
}
