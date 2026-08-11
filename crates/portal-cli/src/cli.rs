use std::ffi::OsString;

use clap::error::ErrorKind;
use clap::{Arg, ArgAction, Command};
use portal_core::HostHeaderPolicy;

use crate::diagnostic::Diagnostic;

const PATTERN: &str = "name-pattern";
const TARGET: &str = "target";
const HOST_HEADER: &str = "host-header";

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum Action {
    Doctor,
    Validate {
        pattern: String,
        target: String,
        host_header_policy: HostHeaderPolicy,
    },
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct Invocation {
    pub(crate) json: bool,
    pub(crate) action: Action,
}

pub(crate) enum ParseOutcome {
    Display(String),
    Failure { diagnostic: Diagnostic, json: bool },
    Run(Invocation),
}

pub(crate) fn parse(arguments: Vec<OsString>) -> ParseOutcome {
    let wants_json = arguments.iter().any(|argument| argument == "--json");
    let matches = match command().try_get_matches_from(arguments) {
        Ok(matches) => matches,
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            return ParseOutcome::Display(error.to_string());
        }
        Err(error) => {
            return ParseOutcome::Failure {
                diagnostic: Diagnostic::usage(&error.to_string()),
                json: wants_json,
            };
        }
    };

    let json = matches.get_flag("json");
    let action = match matches.subcommand() {
        Some(("doctor", _)) => Ok(Action::Doctor),
        Some(("validate", command)) => parse_validate(command),
        _ => Err(Diagnostic::internal(
            "the parsed command did not contain a recognized operation",
        )),
    };
    match action {
        Ok(action) => ParseOutcome::Run(Invocation { json, action }),
        Err(diagnostic) => ParseOutcome::Failure { diagnostic, json },
    }
}

pub(crate) fn command() -> Command {
    Command::new("portal")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Maps names to addresses and services on your own devices")
        .long_about(
            "Portal is a local-first name override and service-routing utility.\n\
             This build validates mappings and reports local capability; it does\n\
             not yet change DNS, install services, or modify trust.",
        )
        .subcommand_required(true)
        .arg_required_else_help(true)
        .arg(
            Arg::new("json")
                .long("json")
                .global(true)
                .action(ArgAction::SetTrue)
                .help("Emit a stable JSON envelope to standard output"),
        )
        .subcommand(
            Command::new("doctor")
                .about("Explains what this build can do and confirms it is local-only"),
        )
        .subcommand(
            Command::new("validate")
                .about("Validates and canonicalizes a mapping without changing the system")
                .arg(
                    Arg::new(PATTERN)
                        .required(true)
                        .value_name("NAME")
                        .help("Exact hostname or suffix wildcard, such as atlas or *.lab"),
                )
                .arg(
                    Arg::new(TARGET)
                        .required(true)
                        .value_name("TARGET")
                        .help("IP address, DNS alias, or http(s) upstream URL"),
                )
                .arg(
                    Arg::new(HOST_HEADER)
                        .long(HOST_HEADER)
                        .value_name("POLICY")
                        .value_parser(["preserve-client", "use-upstream"])
                        .default_value("preserve-client")
                        .help("HTTP Host and TLS SNI policy for the upstream"),
                ),
        )
        .after_help(
            "Examples:\n  \
             portal validate atlas http://127.0.0.1:5173\n  \
             portal validate '*.lab' 10.0.0.8\n  \
             portal --json doctor\n\n\
             Validation is offline. No command in this build changes system state.",
        )
}

fn parse_validate(matches: &clap::ArgMatches) -> Result<Action, Diagnostic> {
    let pattern = required_string(matches, PATTERN)?;
    let target = required_string(matches, TARGET)?;
    let policy = match required_string(matches, HOST_HEADER)?.as_str() {
        "preserve-client" => HostHeaderPolicy::PreserveClient,
        "use-upstream" => HostHeaderPolicy::UseUpstream,
        value => {
            return Err(Diagnostic::internal(format!(
                "the parsed host-header policy '{value}' is not implemented"
            )));
        }
    };
    Ok(Action::Validate {
        pattern,
        target,
        host_header_policy: policy,
    })
}

fn required_string(matches: &clap::ArgMatches, name: &str) -> Result<String, Diagnostic> {
    matches.get_one::<String>(name).cloned().ok_or_else(|| {
        Diagnostic::internal(format!(
            "the command parser did not provide required value '{name}'"
        ))
    })
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use portal_core::HostHeaderPolicy;

    use super::{Action, ParseOutcome, command, parse};

    fn arguments(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn command_definition_is_consistent() {
        command().debug_assert();
    }

    #[test]
    fn parses_explicit_host_policy() {
        let outcome = parse(arguments(&[
            "portal",
            "validate",
            "atlas",
            "https://example.com",
            "--host-header",
            "use-upstream",
        ]));
        assert!(matches!(
            outcome,
            ParseOutcome::Run(super::Invocation {
                action: Action::Validate {
                    host_header_policy: HostHeaderPolicy::UseUpstream,
                    ..
                },
                ..
            })
        ));
    }

    #[test]
    fn preserves_json_intent_for_usage_errors() {
        let outcome = parse(arguments(&["portal", "--json", "not-a-command"]));
        assert!(matches!(outcome, ParseOutcome::Failure { json: true, .. }));
    }
}
