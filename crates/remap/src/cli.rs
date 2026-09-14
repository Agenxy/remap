use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::PathBuf;

use clap::error::ErrorKind;
use clap::{Arg, ArgAction, Command};
use clap_complete::Shell;
use remap_core::HostHeaderPolicy;
use remap_protocol::MAX_MAPPING_PAGE_SIZE;

use crate::diagnostic::Diagnostic;

const PATTERN: &str = "name-pattern";
const TARGET: &str = "target";
const HOST_HEADER: &str = "host-header";
const DNS_LISTEN: &str = "dns-listen";
const DNS_UPSTREAM: &str = "dns-upstream";
const HTTP_LISTEN: &str = "http-listen";
const DOCTOR_GUIDANCE: &str = concat!(
    "Checks:\n",
    "  authority identity and registry status\n",
    "  authenticated UDP and TCP DNS listeners\n",
    "  authenticated HTTP gateway\n\n",
    "Doctor never changes system state. A collected report exits successfully even when a\n",
    "component is unavailable; automation should inspect the JSON readiness fields.\n\n",
    "Examples:\n",
    "  remap doctor\n",
    "  remap --json doctor",
);
const SET_GUIDANCE: &str = concat!(
    "Examples:\n",
    "  remap set remap.test http://127.0.0.1:4270\n",
    "  remap set '*.lab' https://example.com:9443 --host-header use-upstream\n",
    "  remap set atlas 127.0.0.1 --expect 12 --operation-id <UUID>\n\n",
    "Without explicit guards, Remap reads the current revision and creates an operation ID.\n",
    "If the response is lost after submission, the diagnostic preserves both values so the\n",
    "state can be inspected and the identical operation retried safely.",
);
const TOP_LEVEL_EXAMPLES: &str = concat!(
    "Examples:\n",
    "  remap validate atlas http://127.0.0.1:5173\n",
    "  remap list --all\n",
    "  remap set remap.test http://127.0.0.1:5173\n",
    "  remap doctor\n",
    "  remap daemon\n",
    "  remap mcp\n\n",
    "Names may be bare or dotted; .test is reserved for private testing.\n",
    "An installed Remap service owns the authority automatically.\n",
    "Use 'remap daemon' only for an explicit foreground development instance.\n",
    "Use --json for automation.",
);

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum Action {
    Completions {
        shell: Shell,
    },
    Doctor,
    Manpage,
    Manpages {
        directory: PathBuf,
    },
    Status,
    SystemLifecycle {
        command: SystemLifecycleCommand,
    },
    List {
        after: Option<String>,
        limit: u16,
        include_disabled: bool,
    },
    Get {
        pattern: String,
    },
    Resolve {
        name: String,
    },
    Preview {
        file: PathBuf,
    },
    Apply {
        file: PathBuf,
        expected_revision: u64,
        operation_id: String,
    },
    Set {
        pattern: String,
        target: String,
        host_header_policy: HostHeaderPolicy,
        enabled: Option<bool>,
        expected_revision: Option<u64>,
        operation_id: Option<String>,
    },
    Enable(MutationAction),
    Disable(MutationAction),
    Remove(MutationAction),
    Mcp {
        data_dir: Option<PathBuf>,
    },
    Daemon {
        data_dir: Option<PathBuf>,
        dns_listen: Option<SocketAddr>,
        dns_upstreams: Vec<SocketAddr>,
        http_listen: Option<SocketAddr>,
    },
    Validate {
        pattern: String,
        target: String,
        host_header_policy: HostHeaderPolicy,
    },
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum SystemLifecycleCommand {
    Recover,
    Status,
    Uninstall,
}

impl SystemLifecycleCommand {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Recover => "recover",
            Self::Status => "status",
            Self::Uninstall => "uninstall",
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct MutationAction {
    pub(crate) pattern: String,
    pub(crate) expected_revision: Option<u64>,
    pub(crate) operation_id: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct Invocation {
    pub(crate) json: bool,
    pub(crate) data_dir: Option<PathBuf>,
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
    let data_dir = matches.get_one::<PathBuf>("data-dir").cloned();
    let action = parse_action(&matches);
    match action {
        Ok(Action::Mcp { .. }) if json => ParseOutcome::Failure {
            diagnostic: Diagnostic::usage(
                "--json cannot be combined with 'mcp' because standard output carries MCP frames",
            ),
            json,
        },
        Ok(Action::SystemLifecycle { .. }) if data_dir.is_some() => ParseOutcome::Failure {
            diagnostic: Diagnostic::usage(
                "--data-dir controls a mapping registry and cannot be combined with 'system'",
            ),
            json,
        },
        Ok(action) => ParseOutcome::Run(Invocation {
            json,
            data_dir,
            action,
        }),
        Err(diagnostic) => ParseOutcome::Failure { diagnostic, json },
    }
}

fn parse_action(matches: &clap::ArgMatches) -> Result<Action, Diagnostic> {
    let Some((name, command)) = matches.subcommand() else {
        return Err(Diagnostic::internal(
            "the parsed command did not contain a recognized operation",
        ));
    };
    match name {
        "completions" | "doctor" | "manpage" | "manpages" | "validate" => {
            parse_offline_action(name, command)
        }
        "status" | "list" | "get" | "resolve" | "preview" => parse_read_action(name, command),
        "apply" | "set" | "enable" | "disable" | "remove" => parse_write_action(name, command),
        "mcp" | "daemon" => parse_service_action(name, command),
        "system" => parse_system_action(command),
        _ => Err(Diagnostic::internal(format!(
            "the parsed command '{name}' is not implemented"
        ))),
    }
}

fn parse_system_action(command: &clap::ArgMatches) -> Result<Action, Diagnostic> {
    let Some((name, _)) = command.subcommand() else {
        return Err(Diagnostic::internal(
            "the parsed system command did not contain an operation",
        ));
    };
    let command = match name {
        "recover" => SystemLifecycleCommand::Recover,
        "status" => SystemLifecycleCommand::Status,
        "uninstall" => SystemLifecycleCommand::Uninstall,
        _ => return Err(Diagnostic::internal("unknown system lifecycle command")),
    };
    Ok(Action::SystemLifecycle { command })
}

fn parse_offline_action(name: &str, command: &clap::ArgMatches) -> Result<Action, Diagnostic> {
    match name {
        "completions" => command
            .get_one::<Shell>("shell")
            .copied()
            .map(|shell| Action::Completions { shell })
            .ok_or_else(|| Diagnostic::internal("the parser did not provide a shell")),
        "doctor" => Ok(Action::Doctor),
        "manpage" => Ok(Action::Manpage),
        "manpages" => command
            .get_one::<PathBuf>("directory")
            .cloned()
            .map(|directory| Action::Manpages { directory })
            .ok_or_else(|| Diagnostic::internal("the parser did not provide a manpage directory")),
        "validate" => parse_validate(command),
        _ => Err(Diagnostic::internal("unknown offline command")),
    }
}

fn parse_read_action(name: &str, command: &clap::ArgMatches) -> Result<Action, Diagnostic> {
    match name {
        "status" => Ok(Action::Status),
        "list" => parse_list(command),
        "get" => required_string(command, PATTERN).map(|pattern| Action::Get { pattern }),
        "resolve" => required_string(command, "name").map(|name| Action::Resolve { name }),
        "preview" => parse_preview(command),
        _ => Err(Diagnostic::internal("unknown read command")),
    }
}

fn parse_write_action(name: &str, command: &clap::ArgMatches) -> Result<Action, Diagnostic> {
    match name {
        "apply" => parse_apply(command),
        "set" => parse_set(command),
        "enable" => parse_mutation(command).map(Action::Enable),
        "disable" => parse_mutation(command).map(Action::Disable),
        "remove" => parse_mutation(command).map(Action::Remove),
        _ => Err(Diagnostic::internal("unknown write command")),
    }
}

fn parse_service_action(name: &str, command: &clap::ArgMatches) -> Result<Action, Diagnostic> {
    let data_dir = command.get_one::<PathBuf>("data-dir").cloned();
    match name {
        "mcp" => Ok(Action::Mcp { data_dir }),
        "daemon" => {
            let dns_upstreams = command
                .get_many::<SocketAddr>(DNS_UPSTREAM)
                .map_or_else(Vec::new, |values| values.copied().collect());
            if dns_upstreams.len() > 4 {
                return Err(Diagnostic::usage(
                    "'daemon' accepts at most four --dns-upstream values",
                ));
            }
            Ok(Action::Daemon {
                data_dir,
                dns_listen: command.get_one::<SocketAddr>(DNS_LISTEN).copied(),
                dns_upstreams,
                http_listen: command.get_one::<SocketAddr>(HTTP_LISTEN).copied(),
            })
        }
        _ => Err(Diagnostic::internal("unknown service command")),
    }
}

pub(crate) fn command() -> Command {
    base_command()
        .subcommand(status_command())
        .subcommand(list_command())
        .subcommand(
            Command::new("get")
                .about("Reads one exact mapping pattern")
                .arg(pattern_argument()),
        )
        .subcommand(
            Command::new("resolve")
                .about("Explains exact and wildcard resolution for one name")
                .long_about(
                    "Resolves one canonical hostname against the authoritative mapping snapshot.\n\
                     The result identifies the exact or wildcard rule selected and does not perform\n\
                     DNS, connect to the destination, or change state.",
                )
                .arg(
                    Arg::new("name")
                        .required(true)
                        .value_name("NAME")
                        .help("Hostname to resolve without performing network I/O"),
                )
                .after_help("Example:\n  remap resolve service.lab"),
        )
        .subcommand(set_command())
        .subcommand(change_document_command(
            "preview",
            "Projects an ordered change set without changing state",
            false,
        ))
        .subcommand(change_document_command(
            "apply",
            "Commits an ordered change set atomically",
            true,
        ))
        .subcommand(mutation_command("enable", "Enables an existing mapping"))
        .subcommand(mutation_command(
            "disable",
            "Disables a mapping without deleting it",
        ))
        .subcommand(mutation_command("remove", "Deletes an existing mapping"))
        .subcommand(daemon_command())
        .subcommand(mcp_command())
        .subcommand(system_command())
        .subcommand(
            Command::new("validate")
                .about("Validates and canonicalizes a mapping without changing the system")
                .arg(pattern_argument())
                .arg(
                    Arg::new(TARGET)
                        .required(true)
                        .value_name("TARGET")
                        .help("IP address, DNS alias, http(s) upstream URL, or supgang://<peer>/<service>"),
                )
                .arg(host_policy_argument()),
        )
        .after_help(TOP_LEVEL_EXAMPLES)
}

fn system_command() -> Command {
    Command::new("system")
        .about("Manages the installed Remap service")
        .long_about(
            "Uses the native, locally signed lifecycle client installed with Remap.\n\
             Status is read-only. Recovery and uninstall show exact effects and require\n\
             a state-bound approval before the privileged service changes anything.",
        )
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("status")
                .about("Shows native installation and service state")
                .long_about(
                    "Shows the installed generation, native services, resolver state, and any\n\
                     interrupted lifecycle work. This command never changes system state.",
                ),
        )
        .subcommand(
            Command::new("recover")
                .about("Finishes an interrupted install, update, or uninstall")
                .long_about(
                    "Shows the exact unfinished work, then asks for a state-bound approval before\n\
                     the privileged Remap service repairs it. A stale or incorrect approval changes\n\
                     nothing.",
                ),
        )
        .subcommand(
            Command::new("uninstall")
                .about("Removes the installed Remap product after an exact preview")
                .long_about(
                    "Shows the services, resolver state, files, package receipt, and local authority\n\
                     covered by the uninstall. Remap restores the reviewed DNS state before removal\n\
                     and preserves the private mapping database and durable local signing identity.",
                ),
        )
        .after_help(
            "Examples:\n  remap system status\n  remap system recover\n  remap system uninstall",
        )
}

fn status_command() -> Command {
    Command::new("status")
        .about("Shows authoritative registry status")
        .long_about(
            "Reads the registry revision, mapping counts, schema, daemon version, and any\n\
             maintenance condition that currently blocks mutation. Use 'remap doctor' when\n\
             DNS and HTTP runtime identity also need to be proven.",
        )
}

fn base_command() -> Command {
    Command::new("remap")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Maps names to addresses and services on your own devices")
        .long_about(
            "Remap is a local-first name override and service-routing utility.\n\
             People use the typed CLI; agents use the MCP server. Both share the\n\
             same per-user daemon, revision order, and stable diagnostics.",
        )
        .subcommand_required(true)
        .disable_help_subcommand(true)
        .arg_required_else_help(true)
        .arg(
            Arg::new("json")
                .long("json")
                .global(true)
                .action(ArgAction::SetTrue)
                .help("Emit a stable JSON envelope to standard output"),
        )
        .arg(data_dir_argument().global(true))
        .subcommand(doctor_command())
        .subcommand(
            Command::new("completions")
                .about("Generates shell completions from the live command model")
                .arg(
                    Arg::new("shell")
                        .required(true)
                        .value_name("SHELL")
                        .value_parser(clap::value_parser!(Shell)),
                ),
        )
        .subcommand(Command::new("manpage").about("Generates the current remap(1) manpage"))
        .subcommand(
            Command::new("manpages")
                .about("Generates the complete remap(1) manual-page family")
                .arg(
                    Arg::new("directory")
                        .required(true)
                        .value_name("DIRECTORY")
                        .value_parser(clap::value_parser!(PathBuf)),
                ),
        )
}

fn doctor_command() -> Command {
    Command::new("doctor")
        .about("Checks whether the installed Remap system is ready")
        .long_about(
            "Collects a bounded, read-only diagnosis of the local Remap installation.\n\
             Listener readiness is accepted only when DNS and HTTP prove the same random\n\
             per-process identity returned by the authenticated authority.",
        )
        .after_help(DOCTOR_GUIDANCE)
}

fn daemon_command() -> Command {
    Command::new("daemon")
        .about("Runs the authoritative per-user daemon in the foreground")
        .long_about(
            "Runs the single-writer Remap authority until interrupted. The Unix socket\n\
             authenticates the local peer and the registry remains private to this user.\n\
             Native installers supply the production DNS configuration; explicit DNS\n\
             options are useful for foreground diagnostics and integration testing.",
        )
        .arg(
            Arg::new(DNS_LISTEN)
                .long(DNS_LISTEN)
                .value_name("LOOPBACK:PORT")
                .value_parser(clap::value_parser!(SocketAddr))
                .requires(DNS_UPSTREAM)
                .help("Listen for UDP and TCP DNS on an explicit loopback socket"),
        )
        .arg(
            Arg::new(DNS_UPSTREAM)
                .long(DNS_UPSTREAM)
                .value_name("ADDRESS:PORT")
                .value_parser(clap::value_parser!(SocketAddr))
                .action(ArgAction::Append)
                .requires(DNS_LISTEN)
                .help("Forward unmapped DNS to this resolver; repeat up to four times"),
        )
        .arg(
            Arg::new(HTTP_LISTEN)
                .long(HTTP_LISTEN)
                .value_name("LOOPBACK:PORT")
                .value_parser(clap::value_parser!(SocketAddr))
                .help("Route mapped HTTP names from an explicit loopback socket"),
        )
}

fn mcp_command() -> Command {
    Command::new("mcp")
        .about("Serves Remap's agent interface over MCP stdio")
        .long_about(
            "Serves MCP 2026-07-28 with compatibility for 2025-11-25. Standard output\n\
             is reserved for protocol frames; start the Remap daemon first.",
        )
}

fn data_dir_argument() -> Arg {
    Arg::new("data-dir")
        .long("data-dir")
        .value_name("PATH")
        .value_parser(clap::value_parser!(PathBuf))
        .help("Use an explicit private mapping directory; unavailable to 'system'")
}

fn pattern_argument() -> Arg {
    Arg::new(PATTERN)
        .required(true)
        .value_name("NAME")
        .help("Exact hostname or leading-label wildcard, such as atlas or *.lab")
}

fn host_policy_argument() -> Arg {
    Arg::new(HOST_HEADER)
        .long(HOST_HEADER)
        .value_name("POLICY")
        .value_parser(["preserve-client", "use-upstream"])
        .default_value("use-upstream")
        .help("Choose the HTTP Host header and TLS SNI sent to the upstream")
}

fn list_command() -> Command {
    Command::new("list")
        .about("Lists mappings in deterministic name order")
        .arg(
            Arg::new("after")
                .long("after")
                .value_name("CURSOR")
                .help("Continue lexically after a cursor from the preceding page"),
        )
        .arg(
            Arg::new("limit")
                .long("limit")
                .value_name("COUNT")
                .value_parser(clap::value_parser!(u16).range(1..=i64::from(MAX_MAPPING_PAGE_SIZE)))
                .default_value("100")
                .help("Return at most this many mappings"),
        )
        .arg(
            Arg::new("all")
                .long("all")
                .action(ArgAction::SetTrue)
                .help("Include disabled mappings"),
        )
}

fn set_command() -> Command {
    Command::new("set")
        .about("Creates or retargets one mapping atomically")
        .long_about(
            "Creates, retargets, or changes the enabled state of one mapping in a single\n\
             revision-checked transaction. Names may be bare, use arbitrary suffixes, or\n\
             intentionally shadow public hostnames on enrolled devices.",
        )
        .arg(pattern_argument())
        .arg(
            Arg::new(TARGET)
                .required(true)
                .value_name("TARGET")
                .help("IP address, DNS alias, http(s) upstream URL, or supgang://<peer>/<service>"),
        )
        .arg(host_policy_argument())
        .arg(
            Arg::new("disabled")
                .long("disabled")
                .action(ArgAction::SetTrue)
                .help("Create or leave the mapping disabled"),
        )
        .args(mutation_guards())
        .after_help(SET_GUIDANCE)
}

fn mutation_command(name: &'static str, about: &'static str) -> Command {
    Command::new(name)
        .about(about)
        .arg(pattern_argument())
        .args(mutation_guards())
}

fn change_document_command(name: &'static str, about: &'static str, mutating: bool) -> Command {
    let command = Command::new(name).about(about).arg(
        Arg::new("file")
            .value_name("FILE")
            .value_parser(clap::value_parser!(PathBuf))
            .default_value("-")
            .help("JSON array of changes; use '-' or omit FILE to read standard input"),
    );
    if mutating {
        command
            .arg(
                Arg::new("expect")
                    .long("expect")
                    .required(true)
                    .value_name("REVISION")
                    .value_parser(clap::value_parser!(u64))
                    .help("Require the revision on which this batch was reviewed"),
            )
            .arg(
                Arg::new("operation-id")
                    .long("operation-id")
                    .required(true)
                    .value_name("UUID")
                    .value_parser(clap::value_parser!(uuid::Uuid))
                    .help("UUIDv4 reused only to retry this exact batch"),
            )
            .after_help(
                "Example:\n  remap apply changes.json --expect 12 --operation-id <UUID>\n\n\
                 Apply commits all effects or none. Reuse both guards only for an identical retry.",
            )
    } else {
        command.after_help(
            "Example:\n  remap preview changes.json\n\n\
             Preview prints the ordered before/after effects and changes nothing.",
        )
    }
}

fn mutation_guards() -> [Arg; 2] {
    [
        Arg::new("expect")
            .long("expect")
            .value_name("REVISION")
            .value_parser(clap::value_parser!(u64))
            .help("Require this revision instead of reading it automatically"),
        Arg::new("operation-id")
            .long("operation-id")
            .value_name("UUID")
            .value_parser(clap::value_parser!(uuid::Uuid))
            .requires("expect")
            .help("Reuse a UUIDv4 only to retry the identical logical operation"),
    ]
}

fn parse_list(matches: &clap::ArgMatches) -> Result<Action, Diagnostic> {
    let limit = matches
        .get_one::<u16>("limit")
        .copied()
        .ok_or_else(|| Diagnostic::internal("the command parser did not provide the list limit"))?;
    Ok(Action::List {
        after: matches.get_one::<String>("after").cloned(),
        limit,
        include_disabled: matches.get_flag("all"),
    })
}

fn parse_set(matches: &clap::ArgMatches) -> Result<Action, Diagnostic> {
    Ok(Action::Set {
        pattern: required_string(matches, PATTERN)?,
        target: required_string(matches, TARGET)?,
        host_header_policy: parse_host_policy(matches)?,
        enabled: matches.get_flag("disabled").then_some(false),
        expected_revision: matches.get_one::<u64>("expect").copied(),
        operation_id: operation_id(matches),
    })
}

fn parse_mutation(matches: &clap::ArgMatches) -> Result<MutationAction, Diagnostic> {
    Ok(MutationAction {
        pattern: required_string(matches, PATTERN)?,
        expected_revision: matches.get_one::<u64>("expect").copied(),
        operation_id: operation_id(matches),
    })
}

fn parse_preview(matches: &clap::ArgMatches) -> Result<Action, Diagnostic> {
    Ok(Action::Preview {
        file: required_path(matches, "file")?,
    })
}

fn parse_apply(matches: &clap::ArgMatches) -> Result<Action, Diagnostic> {
    Ok(Action::Apply {
        file: required_path(matches, "file")?,
        expected_revision: matches.get_one::<u64>("expect").copied().ok_or_else(|| {
            Diagnostic::internal("the parser did not provide apply's required revision")
        })?,
        operation_id: operation_id(matches).ok_or_else(|| {
            Diagnostic::internal("the parser did not provide apply's required operation id")
        })?,
    })
}

fn operation_id(matches: &clap::ArgMatches) -> Option<String> {
    matches
        .get_one::<uuid::Uuid>("operation-id")
        .map(uuid::Uuid::to_string)
}

fn parse_validate(matches: &clap::ArgMatches) -> Result<Action, Diagnostic> {
    let pattern = required_string(matches, PATTERN)?;
    let target = required_string(matches, TARGET)?;
    let host_header_policy = parse_host_policy(matches)?;
    Ok(Action::Validate {
        pattern,
        target,
        host_header_policy,
    })
}

fn parse_host_policy(matches: &clap::ArgMatches) -> Result<HostHeaderPolicy, Diagnostic> {
    let policy = match required_string(matches, HOST_HEADER)?.as_str() {
        "preserve-client" => HostHeaderPolicy::PreserveClient,
        "use-upstream" => HostHeaderPolicy::UseUpstream,
        value => {
            return Err(Diagnostic::internal(format!(
                "the parsed host-header policy '{value}' is not implemented"
            )));
        }
    };
    Ok(policy)
}

fn required_string(matches: &clap::ArgMatches, name: &str) -> Result<String, Diagnostic> {
    matches.get_one::<String>(name).cloned().ok_or_else(|| {
        Diagnostic::internal(format!(
            "the command parser did not provide required value '{name}'"
        ))
    })
}

fn required_path(matches: &clap::ArgMatches, name: &str) -> Result<PathBuf, Diagnostic> {
    matches.get_one::<PathBuf>(name).cloned().ok_or_else(|| {
        Diagnostic::internal(format!(
            "the command parser did not provide required path '{name}'"
        ))
    })
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use remap_core::HostHeaderPolicy;

    use super::{Action, ParseOutcome, SystemLifecycleCommand, command, parse};

    fn arguments(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn command_definition_is_consistent() {
        command().debug_assert();
    }

    #[test]
    fn detailed_help_explains_doctor_and_mutation_recovery() {
        let doctor = parse(arguments(&["remap", "doctor", "--help"]));
        let set = parse(arguments(&["remap", "set", "--help"]));
        assert!(matches!(doctor, ParseOutcome::Display(text) if text.contains("readiness fields")));
        assert!(matches!(set, ParseOutcome::Display(text) if text.contains("identical operation")));
    }

    #[test]
    fn top_level_help_shows_bare_and_browser_ready_names() {
        let help = parse(arguments(&["remap", "--help"]));
        assert!(matches!(help, ParseOutcome::Display(text)
            if text.contains("remap validate atlas")
                && text.contains("remap set remap.test")
                && text.contains("remap doctor")
                && text.contains(".test is reserved for private testing")));
    }

    #[test]
    fn parses_explicit_host_policy() {
        let outcome = parse(arguments(&[
            "remap",
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
    fn defaults_http_routes_to_the_destination_host() {
        let outcome = parse(arguments(&[
            "remap",
            "set",
            "remap.test",
            "http://127.0.0.1:4270",
        ]));
        assert!(matches!(
            outcome,
            ParseOutcome::Run(super::Invocation {
                action: Action::Set {
                    host_header_policy: HostHeaderPolicy::UseUpstream,
                    ..
                },
                ..
            })
        ));
    }

    #[test]
    fn preserves_json_intent_for_usage_errors() {
        let outcome = parse(arguments(&["remap", "--json", "not-a-command"]));
        assert!(matches!(outcome, ParseOutcome::Failure { json: true, .. }));
    }

    #[test]
    fn operation_id_requires_a_fixed_revision() {
        let outcome = parse(arguments(&[
            "remap",
            "set",
            "atlas",
            "127.0.0.1",
            "--operation-id",
            "4df4bb55-93bb-4f99-9707-9761f6a69364",
        ]));
        assert!(matches!(outcome, ParseOutcome::Failure { .. }));
    }

    #[test]
    fn json_cannot_corrupt_the_mcp_stream() {
        let outcome = parse(arguments(&["remap", "--json", "mcp"]));
        assert!(matches!(outcome, ParseOutcome::Failure { json: true, .. }));
    }

    #[test]
    fn atomic_apply_requires_explicit_retry_guards() {
        let outcome = parse(arguments(&["remap", "apply", "changes.json"]));
        assert!(matches!(outcome, ParseOutcome::Failure { .. }));
    }

    #[test]
    fn daemon_dns_configuration_requires_both_sides() {
        let missing_upstream = parse(arguments(&[
            "remap",
            "daemon",
            "--dns-listen",
            "127.0.0.1:5353",
        ]));
        assert!(matches!(missing_upstream, ParseOutcome::Failure { .. }));
        let configured = parse(arguments(&[
            "remap",
            "daemon",
            "--dns-listen",
            "127.0.0.1:5353",
            "--dns-upstream",
            "1.1.1.1:53",
        ]));
        assert!(matches!(
            configured,
            ParseOutcome::Run(super::Invocation {
                action: Action::Daemon {
                    dns_listen: Some(_),
                    ref dns_upstreams,
                    ..
                },
                ..
            }) if dns_upstreams.len() == 1
        ));
    }

    #[test]
    fn parses_documentation_generators_from_the_same_command_model() {
        let completions = parse(arguments(&["remap", "completions", "zsh"]));
        assert!(matches!(
            completions,
            ParseOutcome::Run(super::Invocation {
                action: Action::Completions {
                    shell: clap_complete::Shell::Zsh
                },
                ..
            })
        ));
        let manpage = parse(arguments(&["remap", "manpage"]));
        assert!(matches!(
            manpage,
            ParseOutcome::Run(super::Invocation {
                action: Action::Manpage,
                ..
            })
        ));
        let manpages = parse(arguments(&["remap", "manpages", "manual"]));
        assert!(matches!(
            manpages,
            ParseOutcome::Run(super::Invocation {
                action: Action::Manpages { .. },
                ..
            })
        ));
    }

    #[test]
    fn parses_native_lifecycle_commands_without_hidden_approval_flags() {
        for (name, expected) in [
            ("status", SystemLifecycleCommand::Status),
            ("recover", SystemLifecycleCommand::Recover),
            ("uninstall", SystemLifecycleCommand::Uninstall),
        ] {
            let outcome = parse(arguments(&["remap", "system", name]));
            assert!(matches!(
                outcome,
                ParseOutcome::Run(super::Invocation {
                    action: Action::SystemLifecycle { command },
                    ..
                }) if command == expected
            ));
        }
        assert!(matches!(
            parse(arguments(&["remap", "system", "uninstall", "--yes"])),
            ParseOutcome::Failure { .. }
        ));
        assert!(matches!(
            parse(arguments(&[
                "remap",
                "system",
                "status",
                "--data-dir",
                "/tmp/remap"
            ])),
            ParseOutcome::Failure { .. }
        ));
    }
}
