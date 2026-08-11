//! Native repository-quality gates for Portal.

mod discover;
mod limits;
mod model;
mod rust_metrics;
mod scan;
mod toolchain;

use std::process::ExitCode;

use clap::{Arg, ArgAction, Command};
use serde_json::json;

use crate::model::Violation;

fn main() -> ExitCode {
    let matches = command().get_matches();
    let json = matches.get_flag("json");
    match matches.subcommand() {
        Some(("check", _)) => run_check(json),
        _ => ExitCode::FAILURE,
    }
}

fn command() -> Command {
    Command::new("portal-quality")
        .about("Runs Portal's native structural quality gates")
        .long_about(
            "Checks first-party source files without shelling out to language tools.\n\
             Diagnostics are deterministic and every finding fails the command.",
        )
        .subcommand_required(true)
        .arg_required_else_help(true)
        .arg(
            Arg::new("json")
                .long("json")
                .global(true)
                .action(ArgAction::SetTrue)
                .help("Emit a stable JSON result to standard output"),
        )
        .subcommand(Command::new("check").about("Checks all first-party source files"))
}

fn run_check(json_output: bool) -> ExitCode {
    let result = discover::workspace_root().and_then(|root| scan::workspace(&root));
    match result {
        Ok(violations) if violations.is_empty() => {
            render_success(json_output);
            ExitCode::SUCCESS
        }
        Ok(violations) => {
            render_violations(json_output, &violations);
            ExitCode::FAILURE
        }
        Err(error) => {
            render_failure(json_output, &error);
            ExitCode::FAILURE
        }
    }
}

fn render_success(json_output: bool) {
    if json_output {
        println!("{}", json!({"ok": true, "violations": []}));
    } else {
        println!("Portal quality: all structural gates passed");
    }
}

fn render_violations(json_output: bool, violations: &[Violation]) {
    if json_output {
        let diagnostics = violations
            .iter()
            .map(Violation::to_json)
            .collect::<Vec<_>>();
        println!("{}", json!({"ok": false, "violations": diagnostics}));
        return;
    }

    for violation in violations {
        let symbol = violation
            .symbol
            .as_deref()
            .map_or_else(String::new, |name| format!(" '{name}'"));
        eprintln!(
            "{}:{}: error[{}]: {}{} ({}; maximum {})",
            violation.path.display(),
            violation.line,
            violation.rule.code(),
            violation.rule.description(),
            symbol,
            violation.actual,
            violation.maximum
        );
        eprintln!("  help: {}", violation.rule.help());
    }
    eprintln!(
        "Portal quality: {} structural violation(s)",
        violations.len()
    );
}

fn render_failure(json_output: bool, error: &str) {
    if json_output {
        println!(
            "{}",
            json!({
                "ok": false,
                "error": {
                    "code": "quality-check-failed",
                    "message": error,
                }
            })
        );
    } else {
        eprintln!("portal-quality: {error}");
    }
}
