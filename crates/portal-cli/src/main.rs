//! Portal's human and machine-readable command-line interface.

mod app;
mod cli;
mod diagnostic;
mod output;

use std::env;
use std::ffi::OsString;
use std::io::{self, Write};
use std::process::ExitCode;

use crate::cli::ParseOutcome;

fn main() -> ExitCode {
    let arguments = env::args_os().collect::<Vec<OsString>>();
    match cli::parse(arguments) {
        ParseOutcome::Display(text) => write_display(&text),
        ParseOutcome::Failure { diagnostic, json } => write_failure(&diagnostic, json),
        ParseOutcome::Run(invocation) => match app::execute(invocation.action) {
            Ok(report) => write_success(&report, invocation.json),
            Err(diagnostic) => write_failure(&diagnostic, invocation.json),
        },
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
                "portal: cannot write command output: {error}"
            ));
            ExitCode::FAILURE
        }
    }
}
