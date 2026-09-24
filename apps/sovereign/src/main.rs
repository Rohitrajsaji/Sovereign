mod control_api;
mod run_lock;
mod runner;

use control_api::{ControlApiRequest, bind_loopback, serve_listener};
use serde_json::Value;
use sovereign_controller::{ApprovalDecisionV1, LocalControl};
use sovereign_eval::{M1_8GB_PROFILE_ID, run_offline_profile, run_release_suite};
use sovereign_state::StateStore;
use sovereign_types::ErrorCode;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const STATE_DB_ENV: &str = "SOVEREIGN_STATE_DB";

fn main() -> ExitCode {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.first().is_some_and(|command| command == "run") {
        return render_result(runner::run_command(args.get(1..).unwrap_or_default()));
    }
    let state_path = std::env::var_os(STATE_DB_ENV)
        .map_or_else(|| PathBuf::from(".sovereign/state.sqlite3"), PathBuf::from);
    render_result(run(&args, &state_path))
}

fn render_result(result: Result<String, String>) -> ExitCode {
    match result {
        Ok(output) => {
            if !output.is_empty() {
                println!("{output}");
            }
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("{}: {message}", ErrorCode::InvalidState);
            ExitCode::from(2)
        }
    }
}

fn run(args: &[String], state_path: &Path) -> Result<String, String> {
    match args.first().map(String::as_str) {
        Some("--version" | "-V") => Ok(format!("sovereign {VERSION}")),
        Some("help" | "--help" | "-h") | None => Ok(help_text()),
        Some("doctor") => {
            let control = open_read_control(state_path)?;
            let read_model = control.read_model().map_err(|error| error.to_string())?;
            Ok(format!(
                "sovereign local control plane: ok\nstate={}\npaused={}",
                state_path.display(),
                read_model.status.execution_control.paused
            ))
        }
        Some("goal") => {
            let goal = args.get(1..).unwrap_or_default().join(" ");
            let mut control = open_read_control(state_path)?;
            let intent = control
                .submit_goal(&goal)
                .map_err(|error| error.to_string())?;
            Ok(format!(
                "goal_id={}\nstatus={}\nnote=queued durably for canonical PlanCompiler execution; no execution was bypassed",
                intent.goal_id, intent.status
            ))
        }
        Some("status") => {
            let control = open_read_control(state_path)?;
            let view = control.read_model().map_err(|error| error.to_string())?;
            serde_json::to_string_pretty(&view).map_err(|error| error.to_string())
        }
        Some("evidence") => {
            let control = open_read_control(state_path)?;
            let view = control.read_model().map_err(|error| error.to_string())?;
            serde_json::to_string_pretty(&view.status.evidence).map_err(|error| error.to_string())
        }
        Some("eval") => run_eval(args),
        Some("pause") => {
            let reason = args.get(1..).unwrap_or_default().join(" ");
            let mut local_control = open_local_control(state_path)?;
            let control = local_control
                .pause((!reason.trim().is_empty()).then_some(reason.as_str()))
                .map_err(|error| error.to_string())?;
            Ok(format!(
                "paused={}{}",
                control.paused,
                control
                    .reason
                    .as_deref()
                    .map_or_else(String::new, |reason| format!("\nreason={reason}"))
            ))
        }
        Some("resume") => {
            if args.len() != 1 {
                return Err("resume does not accept arguments".to_owned());
            }
            let mut local_control = open_local_control(state_path)?;
            let control = local_control.resume().map_err(|error| error.to_string())?;
            Ok(format!("paused={}", control.paused))
        }
        Some("approvals") => {
            let control = open_read_control(state_path)?;
            let view = control.read_model().map_err(|error| error.to_string())?;
            serde_json::to_string_pretty(&view.status.approval_requests)
                .map_err(|error| error.to_string())
        }
        Some("approval") => {
            if args.len() != 4 {
                return Err("approval requires <request-id> <approve|deny> <principal>".to_owned());
            }
            let decision = match args[2].as_str() {
                "approve" => ApprovalDecisionV1::Approve,
                "deny" => ApprovalDecisionV1::Deny,
                _ => return Err("approval decision must be `approve` or `deny`".to_owned()),
            };
            let mut control = open_local_control(state_path)?;
            let request = control
                .respond_to_approval(&args[1], decision, &args[3])
                .map_err(|error| error.to_string())?;
            serde_json::to_string_pretty(&request).map_err(|error| error.to_string())
        }
        Some("serve") => run_serve(args, state_path),
        Some("run") => Err("`run` must be dispatched by the production runner entrypoint".to_owned()),
        Some(command) => Err(format!(
            "unsupported command {command:?}; run `sovereign help` for the local CLI surface"
        )),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EvalInvocation {
    Corpus,
    Release,
}

fn parse_eval_invocation(args: &[String]) -> Result<EvalInvocation, String> {
    if args
        == [
            "eval".to_owned(),
            "--suite".to_owned(),
            "release".to_owned(),
            "--profile".to_owned(),
            M1_8GB_PROFILE_ID.to_owned(),
            "--offline".to_owned(),
        ]
    {
        return Ok(EvalInvocation::Release);
    }
    if args
        == [
            "eval".to_owned(),
            "--profile".to_owned(),
            M1_8GB_PROFILE_ID.to_owned(),
            "--offline".to_owned(),
        ]
    {
        return Ok(EvalInvocation::Corpus);
    }
    Err(
        "eval requires exactly either --profile m1-8gb --offline or --suite release --profile m1-8gb --offline for the frozen M9 local profile"
            .to_owned(),
    )
}

fn run_eval(args: &[String]) -> Result<String, String> {
    match parse_eval_invocation(args)? {
        EvalInvocation::Release => {
            let report = run_release_suite(M1_8GB_PROFILE_ID)?;
            serde_json::to_string_pretty(&report).map_err(|error| error.to_string())
        }
        EvalInvocation::Corpus => {
            let report = run_offline_profile(M1_8GB_PROFILE_ID)?;
            serde_json::to_string_pretty(&report).map_err(|error| error.to_string())
        }
    }
}

fn run_serve(args: &[String], state_path: &Path) -> Result<String, String> {
    if args.len() > 2 {
        return Err("serve accepts at most one loopback socket address".to_owned());
    }
    let address = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "127.0.0.1:7777".to_owned())
        .parse::<SocketAddr>()
        .map_err(|error| format!("invalid serve address: {error}"))?;
    let listener = bind_loopback(address)?;
    let local_address = listener.local_addr().map_err(|error| error.to_string())?;
    eprintln!("sovereign local dashboard listening on http://{local_address}/dashboard");
    let mut control = open_read_control(state_path)?;
    serve_listener(&listener, |request| {
        handle_control_request(&mut control, request)
    })?;
    Ok(String::new())
}

fn open_local_control(state_path: &Path) -> Result<LocalControl, String> {
    StateStore::open(state_path)
        .map_err(|error| error.to_string())
        .and_then(|state| LocalControl::reopen(state).map_err(|error| error.to_string()))
}

fn open_read_control(state_path: &Path) -> Result<LocalControl, String> {
    StateStore::open(state_path)
        .map(LocalControl::read_only)
        .map_err(|error| error.to_string())
}

fn handle_control_request(
    control: &mut LocalControl,
    request: ControlApiRequest,
) -> Result<Value, String> {
    match request {
        ControlApiRequest::Dashboard => {
            Err("dashboard route is served as static read-only content".to_owned())
        }
        ControlApiRequest::ReadModel => control
            .read_model()
            .and_then(|view| serde_json::to_value(view).map_err(Into::into))
            .map_err(|error| error.to_string()),
        ControlApiRequest::SubmitGoal { goal } => control
            .submit_goal(&goal)
            .and_then(|intent| serde_json::to_value(intent).map_err(Into::into))
            .map_err(|error| error.to_string()),
        ControlApiRequest::Pause { reason } => control
            .pause(reason.as_deref())
            .and_then(|control| serde_json::to_value(control).map_err(Into::into))
            .map_err(|error| error.to_string()),
        ControlApiRequest::Resume => control
            .resume()
            .and_then(|control| serde_json::to_value(control).map_err(Into::into))
            .map_err(|error| error.to_string()),
        ControlApiRequest::RespondToApproval {
            request_id,
            decision,
            principal,
        } => {
            let decision = match decision.as_str() {
                "approve" => ApprovalDecisionV1::Approve,
                "deny" => ApprovalDecisionV1::Deny,
                _ => return Err("approval decision must be `approve` or `deny`".to_owned()),
            };
            control
                .respond_to_approval(&request_id, decision, &principal)
                .and_then(|request| serde_json::to_value(request).map_err(Into::into))
                .map_err(|error| error.to_string())
        }
    }
}

fn help_text() -> String {
    [
        "Sovereign local Controller CLI",
        "",
        "Commands:",
        "  goal <natural-language goal>  Durably queue a Controller-owned goal intent",
        "  run [--once]                  Advance the Controller-owned production goal loop",
        "  status                        Inspect durable plan/task/attempt/control state",
        "  evidence                      Inspect durable verification evidence",
        "  eval --profile m1-8gb --offline  Run deterministic local M9 evaluation corpus",
        "  eval --suite release --profile m1-8gb --offline  Run final M1/8GB release soak report",
        "  pause [reason]                Pause Controller readiness/mutation",
        "  resume                         Resume Controller readiness/mutation",
        "  approvals                      Render durable approval-request facts",
        "  approval <id> <approve|deny> <principal>  Respond through Controller approval validation",
        "  serve [127.0.0.1:port]         Serve the loopback-only local dashboard and control API",
        "  doctor                         Check local state/control access",
        "  --version                      Print version",
        "",
        "State path defaults to .sovereign/state.sqlite3; override with SOVEREIGN_STATE_DB.",
    ]
    .join("\n")
}

#[cfg(test)]
mod tests {
    use super::{EvalInvocation, handle_control_request, parse_eval_invocation, run};
    use crate::control_api::{ControlApiRequest, bind_loopback, serve_one};
    use sovereign_controller::{Controller, LocalControl};
    use sovereign_state::StateStore;
    use std::fs;
    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
    use std::path::{Path, PathBuf};
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_state(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let root = std::env::temp_dir().join(format!("sovereign-cli-{name}-{unique}"));
        fs::create_dir_all(&root).unwrap_or_else(|error| panic!("temp dir: {error}"));
        root.join("state.sqlite3")
    }

    #[test]
    fn goal_submission_is_truthfully_queued_and_visible_in_status() {
        let state_path = temp_state("goal");
        let output = run(
            &[
                "goal".to_owned(),
                "Build".to_owned(),
                "inventory".to_owned(),
            ],
            &state_path,
        )
        .unwrap_or_else(|error| panic!("goal submission: {error}"));
        assert!(output.contains("queued durably for canonical PlanCompiler"));

        let status = run(&["status".to_owned()], &state_path)
            .unwrap_or_else(|error| panic!("status: {error}"));
        assert!(status.contains("Build inventory"));
        assert!(status.contains("queued_for_plan_compilation"));
    }

    #[test]
    fn offline_eval_cli_emits_versioned_m1_report() {
        let state_path = temp_state("eval");
        let output = run(
            &[
                "eval".to_owned(),
                "--profile".to_owned(),
                "m1-8gb".to_owned(),
                "--offline".to_owned(),
            ],
            &state_path,
        )
        .unwrap_or_else(|error| panic!("run eval: {error}"));
        let report: serde_json::Value = serde_json::from_str(&output)
            .unwrap_or_else(|error| panic!("parse eval report: {error}"));
        assert_eq!(report["schema_version"], 1);
        assert_eq!(report["profile_id"], "m1-8gb");
        assert_eq!(report["offline"], true);
        assert_eq!(report["aggregate"]["scenario_count"], 4);
        assert_eq!(report["aggregate"]["scenario_pass_count"], 4);
        assert_eq!(report["aggregate"]["false_completion_accepted"], 0);
    }

    #[test]
    fn release_eval_cli_shape_is_exact_without_running_the_release_matrix() {
        let exact = vec![
            "eval".to_owned(),
            "--suite".to_owned(),
            "release".to_owned(),
            "--profile".to_owned(),
            "m1-8gb".to_owned(),
            "--offline".to_owned(),
        ];
        assert_eq!(
            parse_eval_invocation(&exact)
                .unwrap_or_else(|error| panic!("parse exact release invocation: {error}")),
            EvalInvocation::Release
        );
        for invalid in [
            vec![
                "eval".to_owned(),
                "--suite".to_owned(),
                "release".to_owned(),
                "--profile".to_owned(),
                "m1-8gb".to_owned(),
            ],
            vec![
                "eval".to_owned(),
                "--profile".to_owned(),
                "m1-8gb".to_owned(),
                "--suite".to_owned(),
                "release".to_owned(),
                "--offline".to_owned(),
            ],
            vec![
                "eval".to_owned(),
                "--suite".to_owned(),
                "release".to_owned(),
                "--profile".to_owned(),
                "other".to_owned(),
                "--offline".to_owned(),
            ],
        ] {
            assert!(parse_eval_invocation(&invalid).is_err());
        }
    }

    #[test]
    fn offline_eval_cli_rejects_profile_or_authority_drift() {
        let state_path = temp_state("eval-reject");
        for args in [
            vec!["eval".to_owned()],
            vec![
                "eval".to_owned(),
                "--profile".to_owned(),
                "m1-8gb".to_owned(),
            ],
            vec![
                "eval".to_owned(),
                "--profile".to_owned(),
                "other".to_owned(),
                "--offline".to_owned(),
            ],
        ] {
            let error = run(&args, &state_path)
                .err()
                .unwrap_or_else(|| panic!("invalid eval invocation unexpectedly succeeded"));
            assert!(error.contains("eval requires exactly"));
        }
    }

    #[test]
    fn pause_resume_use_controller_owned_durable_state() {
        let state_path = temp_state("pause");
        run(
            &["pause".to_owned(), "operator requested".to_owned()],
            &state_path,
        )
        .unwrap_or_else(|error| panic!("pause: {error}"));

        let controller = Controller::new(
            StateStore::open(&state_path).unwrap_or_else(|error| panic!("state open: {error}")),
        );
        let paused = controller
            .execution_control()
            .unwrap_or_else(|error| panic!("control read: {error}"));
        assert!(paused.paused);
        assert_eq!(paused.reason.as_deref(), Some("operator requested"));

        run(&["resume".to_owned()], &state_path).unwrap_or_else(|error| panic!("resume: {error}"));
        let controller = Controller::new(
            StateStore::open(&state_path).unwrap_or_else(|error| panic!("state reopen: {error}")),
        );
        assert!(
            !controller
                .execution_control()
                .unwrap_or_else(|error| panic!("control reread: {error}"))
                .paused
        );
    }

    #[test]
    fn approval_rendering_is_read_only_and_empty_without_durable_requests() {
        let state_path = temp_state("approval");
        let output = run(&["approvals".to_owned()], &state_path)
            .unwrap_or_else(|error| panic!("approvals: {error}"));
        assert_eq!(output, "[]");
    }

    fn http_request(address: SocketAddr, request: &str) -> String {
        let mut stream = TcpStream::connect(address)
            .unwrap_or_else(|error| panic!("connect local control API: {error}"));
        stream
            .write_all(request.as_bytes())
            .unwrap_or_else(|error| panic!("write local control request: {error}"));
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .unwrap_or_else(|error| panic!("read local control response: {error}"));
        response
    }

    fn local_control_http_once(state_path: &Path, request: &str) -> String {
        let listener = bind_loopback(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .unwrap_or_else(|error| panic!("bind local control API: {error}"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("local control API address: {error}"));
        let path = state_path.to_path_buf();
        let server = thread::spawn(move || {
            let mut control = LocalControl::read_only(
                StateStore::open(&path).unwrap_or_else(|error| panic!("API state: {error}")),
            );
            serve_one(&listener, |api_request| {
                handle_control_request(&mut control, api_request)
            })
            .unwrap_or_else(|error| panic!("serve local control request: {error}"));
        });
        let response = http_request(address, request);
        server
            .join()
            .unwrap_or_else(|_| panic!("local control server thread panicked"));
        response
    }

    #[test]
    fn loopback_api_read_model_matches_controller_and_is_read_only() {
        let state_path = temp_state("api-read");
        run(
            &["goal".to_owned(), "Build inventory".to_owned()],
            &state_path,
        )
        .unwrap_or_else(|error| panic!("seed goal: {error}"));

        let before_store =
            StateStore::open(&state_path).unwrap_or_else(|error| panic!("state before: {error}"));
        let before_sequence = before_store
            .latest_journal_sequence()
            .unwrap_or_else(|error| panic!("journal before: {error}"));
        drop(before_store);

        let direct = LocalControl::read_only(
            StateStore::open(&state_path).unwrap_or_else(|error| panic!("direct state: {error}")),
        )
        .read_model()
        .unwrap_or_else(|error| panic!("direct status: {error}"));
        let direct_json =
            serde_json::to_value(direct).unwrap_or_else(|error| panic!("direct JSON: {error}"));

        let listener = bind_loopback(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .unwrap_or_else(|error| panic!("bind API: {error}"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("API local address: {error}"));
        let path = state_path.clone();
        let server = thread::spawn(move || {
            let mut control = LocalControl::read_only(
                StateStore::open(&path).unwrap_or_else(|error| panic!("API state: {error}")),
            );
            serve_one(&listener, |request| {
                handle_control_request(&mut control, request)
            })
            .unwrap_or_else(|error| panic!("serve one: {error}"));
        });
        let response = http_request(
            address,
            "GET /v1/status HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
        );
        server
            .join()
            .unwrap_or_else(|_| panic!("local control server thread panicked"));
        let (_, body) = response
            .split_once("\r\n\r\n")
            .unwrap_or_else(|| panic!("HTTP response missing body"));
        let api_json: serde_json::Value =
            serde_json::from_str(body).unwrap_or_else(|error| panic!("API JSON: {error}"));
        assert_eq!(api_json, direct_json);

        let after_store =
            StateStore::open(&state_path).unwrap_or_else(|error| panic!("state after: {error}"));
        assert_eq!(
            after_store
                .latest_journal_sequence()
                .unwrap_or_else(|error| panic!("journal after: {error}")),
            before_sequence
        );
    }

    #[test]
    fn local_control_requests_delegate_to_controller_mutations() {
        let state_path = temp_state("api-mutations");
        let mut control = LocalControl::reopen(
            StateStore::open(&state_path).unwrap_or_else(|error| panic!("state: {error}")),
        )
        .unwrap_or_else(|error| panic!("local control: {error}"));
        handle_control_request(
            &mut control,
            ControlApiRequest::SubmitGoal {
                goal: "Build inventory".to_owned(),
            },
        )
        .unwrap_or_else(|error| panic!("goal request: {error}"));
        handle_control_request(
            &mut control,
            ControlApiRequest::Pause {
                reason: Some("operator requested".to_owned()),
            },
        )
        .unwrap_or_else(|error| panic!("pause request: {error}"));

        let controller = Controller::new(
            StateStore::open(&state_path).unwrap_or_else(|error| panic!("observer state: {error}")),
        );
        assert!(
            controller
                .execution_control()
                .unwrap_or_else(|error| panic!("read control: {error}"))
                .paused
        );
        handle_control_request(&mut control, ControlApiRequest::Resume)
            .unwrap_or_else(|error| panic!("resume request: {error}"));
        let status = Controller::new(
            StateStore::open(&state_path)
                .unwrap_or_else(|error| panic!("observer state after resume: {error}")),
        )
        .durable_status()
        .unwrap_or_else(|error| panic!("status: {error}"));
        assert_eq!(status.goal_intents.len(), 1);
        assert!(!status.execution_control.paused);
    }

    #[test]
    fn socket_pause_resume_delegate_to_controller_owned_state() {
        let state_path = temp_state("api-socket-control");
        let pause_body = r#"{"reason":"dashboard operator"}"#;
        let pause = local_control_http_once(
            &state_path,
            &format!(
                "POST /v1/control/pause HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: http://127.0.0.1\r\nContent-Length: {}\r\n\r\n{pause_body}",
                pause_body.len()
            ),
        );
        assert!(pause.starts_with("HTTP/1.1 200 OK\r\n"));
        let paused = Controller::new(
            StateStore::open(&state_path).unwrap_or_else(|error| panic!("paused state: {error}")),
        )
        .execution_control()
        .unwrap_or_else(|error| panic!("paused control: {error}"));
        assert!(paused.paused);
        assert_eq!(paused.reason.as_deref(), Some("dashboard operator"));

        let resume = local_control_http_once(
            &state_path,
            "POST /v1/control/resume HTTP/1.1\r\nHost: localhost\r\nOrigin: http://localhost\r\nContent-Length: 2\r\n\r\n{}",
        );
        assert!(resume.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(
            !Controller::new(
                StateStore::open(&state_path)
                    .unwrap_or_else(|error| panic!("resumed state: {error}")),
            )
            .execution_control()
            .unwrap_or_else(|error| panic!("resumed control: {error}"))
            .paused
        );
    }

    #[test]
    fn rejected_raw_state_route_cannot_mutate_authoritative_journal() {
        let state_path = temp_state("api-deny-raw-state");
        let before_store =
            StateStore::open(&state_path).unwrap_or_else(|error| panic!("state before: {error}"));
        let before_sequence = before_store
            .latest_journal_sequence()
            .unwrap_or_else(|error| panic!("journal before: {error}"));
        drop(before_store);

        let listener = bind_loopback(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .unwrap_or_else(|error| panic!("bind API: {error}"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("API local address: {error}"));
        let path = state_path.clone();
        let server = thread::spawn(move || {
            let mut control = LocalControl::reopen(
                StateStore::open(&path).unwrap_or_else(|error| panic!("API state: {error}")),
            )
            .unwrap_or_else(|error| panic!("API local control: {error}"));
            serve_one(&listener, |request| {
                handle_control_request(&mut control, request)
            })
            .unwrap_or_else(|error| panic!("serve one: {error}"));
        });
        let response = http_request(
            address,
            "POST /v1/state/controller.task HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{}",
        );
        server
            .join()
            .unwrap_or_else(|_| panic!("local control server thread panicked"));
        assert!(response.starts_with("HTTP/1.1 404 Not Found\r\n"));

        let after_store =
            StateStore::open(&state_path).unwrap_or_else(|error| panic!("state after: {error}"));
        assert_eq!(
            after_store
                .latest_journal_sequence()
                .unwrap_or_else(|error| panic!("journal after: {error}")),
            before_sequence
        );
    }

    #[test]
    fn local_control_read_model_reconstructs_identically_after_restart() {
        let state_path = temp_state("api-restart");
        let mut first = LocalControl::reopen(
            StateStore::open(&state_path).unwrap_or_else(|error| panic!("first state: {error}")),
        )
        .unwrap_or_else(|error| panic!("first local control: {error}"));
        first
            .submit_goal("Build inventory")
            .unwrap_or_else(|error| panic!("submit goal: {error}"));
        first
            .pause(Some("restart fixture"))
            .unwrap_or_else(|error| panic!("pause: {error}"));
        let before = first
            .read_model()
            .unwrap_or_else(|error| panic!("read before restart: {error}"));
        drop(first);

        let after = LocalControl::reopen(
            StateStore::open(&state_path).unwrap_or_else(|error| panic!("reopen state: {error}")),
        )
        .and_then(|control| control.read_model())
        .unwrap_or_else(|error| panic!("read after restart: {error}"));
        assert_eq!(after, before);
    }

    #[test]
    fn dashboard_is_read_only_and_uses_only_local_control_routes() {
        let state_path = temp_state("dashboard");
        run(
            &["goal".to_owned(), "Build inventory".to_owned()],
            &state_path,
        )
        .unwrap_or_else(|error| panic!("seed goal: {error}"));

        let before_store =
            StateStore::open(&state_path).unwrap_or_else(|error| panic!("state before: {error}"));
        let before_sequence = before_store
            .latest_journal_sequence()
            .unwrap_or_else(|error| panic!("journal before: {error}"));
        drop(before_store);

        let listener = bind_loopback(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .unwrap_or_else(|error| panic!("bind dashboard: {error}"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("dashboard local address: {error}"));
        let server = thread::spawn(move || {
            serve_one(&listener, |request| {
                panic!("static dashboard must not reach Controller handler: {request:?}")
            })
            .unwrap_or_else(|error| panic!("serve dashboard: {error}"));
        });
        let response = http_request(
            address,
            "GET /dashboard HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
        );
        server
            .join()
            .unwrap_or_else(|_| panic!("dashboard server thread panicked"));

        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("Content-Type: text/html; charset=utf-8\r\n"));
        assert!(response.contains("Sovereign Local Dashboard"));
        assert!(response.contains("Goals"));
        assert!(response.contains("Tasks &amp; Progress"));
        assert!(response.contains("Verification &amp; Evidence"));
        assert!(response.contains("Blocked Approvals"));
        assert!(response.contains("/v1/status"));
        assert!(response.contains("/v1/control/pause"));
        assert!(response.contains("/v1/control/resume"));
        assert!(response.contains("/v1/approvals/respond"));
        assert!(!response.contains("/v1/actions"));
        assert!(!response.contains("/v1/state/"));

        let after_store =
            StateStore::open(&state_path).unwrap_or_else(|error| panic!("state after: {error}"));
        assert_eq!(
            after_store
                .latest_journal_sequence()
                .unwrap_or_else(|error| panic!("journal after: {error}")),
            before_sequence
        );
    }
}
