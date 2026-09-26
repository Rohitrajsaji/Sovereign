//! Fixture-only loopback server for Playwright.
//! Callers: `scripts/e2e.sh` and Phase 5 Playwright specs.
//! API: binary `sovereign-e2e-server` (feature `e2e-fixtures` only).
//! Schema: `schemas/control-api-v2.json`. Not reachable from the production binary.
//! User instruction: Continue from the current tree and finish the remaining consumer-product gaps you identified. Then complete Playwright/axe E2E.

#[path = "actor.rs"]
mod actor;
#[path = "app_data.rs"]
mod app_data;
#[path = "consumer_status.rs"]
mod consumer_status;
#[path = "control_api/mod.rs"]
mod control_api;
#[path = "dispatch.rs"]
mod dispatch;
#[path = "doctor.rs"]
mod doctor;
#[path = "execution.rs"]
mod execution;
#[path = "fixture_backend.rs"]
mod fixture_backend;
#[path = "launch_agent.rs"]
mod launch_agent;
#[path = "model_assets.rs"]
mod model_assets;
#[path = "projections.rs"]
mod projections;
#[path = "projects.rs"]
mod projects;
#[path = "run_lock.rs"]
mod run_lock;
#[path = "runner.rs"]
mod runner;

use actor::{ActorOptions, ControllerActorHandle};
use app_data::AppData;
use control_api::{ServerConfig, bind_loopback, serve_listener};
use dispatch::handle_actor_request;
use sovereign_state::StateStore;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

fn main() {
    if let Err(error) = run() {
        eprintln!("sovereign-e2e-server: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let dir = std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| {
        "HOME must be an isolated directory; scripts/e2e.sh exports one".to_owned()
    })?;
    if !dir
        .file_name()
        .is_some_and(|name| name.to_string_lossy().contains("sovereign-e2e"))
    {
        return Err(
            "refusing a non-isolated HOME; run scripts/e2e.sh so app data stays off the user profile"
                .to_owned(),
        );
    }
    std::fs::create_dir_all(&dir).map_err(|error| error.to_string())?;
    std::env::set_current_dir(&dir).map_err(|error| error.to_string())?;
    let repo = dir.join("fixture-repo");
    std::fs::create_dir_all(&repo).map_err(|error| error.to_string())?;
    let git = Command::new("/usr/bin/git")
        .args(["init", "-q"])
        .current_dir(&repo)
        .status()
        .map_err(|error| error.to_string())?;
    if !git.success() {
        return Err("git init failed".to_owned());
    }
    let data = AppData::open(&dir.join("Library/Application Support/Sovereign"))
        .map_err(|error| error.to_string())?;
    let _ = projects::register_project(&data, &repo, "Fixture");
    let state = std::env::var_os("SOVEREIGN_STATE_DB")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".sovereign/state.sqlite3"));
    if let Some(parent) = state.parent() {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let _store = StateStore::open(&state).map_err(|error| error.to_string())?;
    let _ = fixture_backend::from_context(&state);
    let (actor, _thread) = ControllerActorHandle::spawn_with(
        state.clone(),
        ActorOptions {
            execute: true,
            git_root: Some(repo),
        },
    )?;
    let listener = bind_loopback(SocketAddr::from(([127, 0, 0, 1], 0)))?;
    let addr = listener.local_addr().map_err(|error| error.to_string())?;
    println!("e2e-server {addr}");
    let actor_for_server = actor.clone();
    let config = ServerConfig {
        session_token: Some("e2e-session-token".to_owned()),
        require_token_for_v1_post: true,
        state_path: Some(PathBuf::from(&state)),
        sse_clients: Arc::new(AtomicUsize::new(0)),
    };
    serve_listener(
        &listener,
        move |request| handle_actor_request(&actor_for_server, request),
        config,
    )
}
