use std::env;
use std::process::ExitCode;
use std::str::FromStr;

use portal_core::{MappingTarget, NamePattern};

fn main() -> ExitCode {
    match run(env::args().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("portal: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(mut arguments: impl Iterator<Item = String>) -> Result<(), String> {
    match arguments.next().as_deref() {
        Some("validate") => {
            let pattern = arguments
                .next()
                .ok_or_else(|| "validate requires <name-pattern> <target>".to_owned())?;
            let target = arguments
                .next()
                .ok_or_else(|| "validate requires <name-pattern> <target>".to_owned())?;
            if arguments.next().is_some() {
                return Err("validate accepts exactly <name-pattern> <target>".to_owned());
            }

            let pattern = NamePattern::from_str(&pattern).map_err(|error| error.to_string())?;
            let target = MappingTarget::from_str(&target).map_err(|error| error.to_string())?;
            println!("{pattern} -> {target}");
            Ok(())
        }
        Some("help" | "--help" | "-h") | None => {
            println!("Portal\n\nUsage:\n  portal validate <name-pattern> <target>");
            Ok(())
        }
        Some(command) => Err(format!("unknown command '{command}'")),
    }
}
