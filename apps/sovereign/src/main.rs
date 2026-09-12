use sovereign_types::ErrorCode;
use std::process::ExitCode;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    match std::env::args().nth(1).as_deref() {
        Some("--version" | "-V") => {
            println!("sovereign {VERSION}");
            ExitCode::SUCCESS
        }
        Some("doctor") => {
            println!("sovereign foundation: ok");
            ExitCode::SUCCESS
        }
        Some(command) => {
            eprintln!(
                "{}: unsupported foundation command {command:?}; product behavior is not implemented yet",
                ErrorCode::InvalidState
            );
            ExitCode::from(2)
        }
        None => {
            println!("Sovereign engineering control plane (foundation)");
            ExitCode::SUCCESS
        }
    }
}
