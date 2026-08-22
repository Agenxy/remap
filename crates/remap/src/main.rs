//! Remap's human and machine-readable command-line interface.

mod app;
mod cli;
mod diagnostic;
#[cfg(target_os = "linux")]
mod linux_lifecycle;
mod output;
mod runtime;
mod runtime_health;

use std::env;
use std::ffi::OsString;
use std::io::{self, Write};
use std::process::ExitCode;

use crate::cli::ParseOutcome;

#[tokio::main]
async fn main() -> ExitCode {
    let arguments = env::args_os().collect::<Vec<OsString>>();
    match cli::parse(arguments) {
        ParseOutcome::Display(text) => write_display(&text),
        ParseOutcome::Failure { diagnostic, json } => write_failure(&diagnostic, json),
        ParseOutcome::Run(invocation) => {
            if let cli::Action::SystemLifecycle { command } = &invocation.action {
                return match runtime::run_native_lifecycle(*command, invocation.json) {
                    Ok(code) => ExitCode::from(code),
                    Err(diagnostic) => write_failure(&diagnostic, invocation.json),
                };
            }
            match runtime::execute(invocation.action, invocation.data_dir.as_deref()).await {
                Ok(Some(report)) => write_success(&report, invocation.json),
                Ok(None) => ExitCode::SUCCESS,
                Err(diagnostic) => write_failure(&diagnostic, invocation.json),
            }
        }
    }
}

fn write_display(text: &str) -> ExitCode {
    let mut stdout = io::stdout().lock();
    finish_write(write!(stdout, "{text}"), ExitCode::SUCCESS)
}

fn write_success(report: &app::Report, json: bool) -> ExitCode {
    let mut stdout = io::stdout().lock();
    finish_write(
        output::write_report(&mut stdout, report, json),
        ExitCode::SUCCESS,
    )
}

fn write_failure(diagnostic: &diagnostic::Diagnostic, json: bool) -> ExitCode {
    let result = if json {
        let mut stdout = io::stdout().lock();
        output::write_diagnostic(&mut stdout, diagnostic, true)
    } else {
        let mut stderr = io::stderr().lock();
        output::write_diagnostic(&mut stderr, diagnostic, false)
    };
    finish_write(result, ExitCode::from(diagnostic.exit_code()))
}

fn finish_write(result: io::Result<()>, success: ExitCode) -> ExitCode {
    match result {
        Ok(()) => success,
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(error) => {
            let mut stderr = io::stderr().lock();
            drop(writeln!(
                stderr,
                "remap: cannot write command output: {error}"
            ));
            ExitCode::FAILURE
        }
    }
}
