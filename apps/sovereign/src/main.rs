use sovereign_controller::Controller;
use sovereign_state::StateStore;
use sovereign_types::ErrorCode;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const STATE_DB_ENV: &str = "SOVEREIGN_STATE_DB";

fn main() -> ExitCode {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let state_path = std::env::var_os(STATE_DB_ENV)
        .map_or_else(|| PathBuf::from(".sovereign/state.sqlite3"), PathBuf::from);
    match run(&args, &state_path) {
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
            let state = StateStore::open(state_path).map_err(|error| error.to_string())?;
            let controller = Controller::new(state);
            let control = controller
                .execution_control()
                .map_err(|error| error.to_string())?;
            Ok(format!(
                "sovereign local control plane: ok\nstate={}\npaused={}",
                state_path.display(),
                control.paused
            ))
        }
        Some("goal") => {
            let goal = args.get(1..).unwrap_or_default().join(" ");
            let mut controller = open_controller(state_path)?;
            let intent = controller
                .submit_goal_intent(&goal)
                .map_err(|error| error.to_string())?;
            Ok(format!(
                "goal_id={}\nstatus={}\nnote=queued durably for canonical PlanCompiler execution; no execution was bypassed",
                intent.goal_id, intent.status
            ))
        }
        Some("status") => {
            let controller = open_controller(state_path)?;
            let view = controller
                .durable_status()
                .map_err(|error| error.to_string())?;
            serde_json::to_string_pretty(&view).map_err(|error| error.to_string())
        }
        Some("evidence") => {
            let controller = open_controller(state_path)?;
            let view = controller
                .durable_status()
                .map_err(|error| error.to_string())?;
            serde_json::to_string_pretty(&view.evidence).map_err(|error| error.to_string())
        }
        Some("pause") => {
            let reason = args.get(1..).unwrap_or_default().join(" ");
            let mut controller = open_controller(state_path)?;
            let control = controller
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
            let mut controller = open_controller(state_path)?;
            let control = controller.resume().map_err(|error| error.to_string())?;
            Ok(format!("paused={}", control.paused))
        }
        Some("approvals") => {
            let controller = open_controller(state_path)?;
            let view = controller
                .durable_status()
                .map_err(|error| error.to_string())?;
            serde_json::to_string_pretty(&view.approval_requests).map_err(|error| error.to_string())
        }
        Some(command) => Err(format!(
            "unsupported command {command:?}; run `sovereign help` for the local CLI surface"
        )),
    }
}

fn open_controller(state_path: &Path) -> Result<Controller, String> {
    StateStore::open(state_path)
        .map(Controller::new)
        .map_err(|error| error.to_string())
}

fn help_text() -> String {
    [
        "Sovereign local Controller CLI",
        "",
        "Commands:",
        "  goal <natural-language goal>  Durably queue a Controller-owned goal intent",
        "  status                        Inspect durable plan/task/attempt/control state",
        "  evidence                      Inspect durable verification evidence",
        "  pause [reason]                Pause Controller readiness/mutation",
        "  resume                         Resume Controller readiness/mutation",
        "  approvals                      Render durable approval-request facts",
        "  doctor                         Check local state/control access",
        "  --version                      Print version",
        "",
        "State path defaults to .sovereign/state.sqlite3; override with SOVEREIGN_STATE_DB.",
    ]
    .join("\n")
}

#[cfg(test)]
mod tests {
    use super::run;
    use sovereign_controller::Controller;
    use sovereign_state::StateStore;
    use std::fs;
    use std::path::PathBuf;
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
}
