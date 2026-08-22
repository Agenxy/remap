//! Authoritative per-user Remap daemon entry point.

use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::PathBuf;

use clap::error::ErrorKind;
use clap::{Arg, ArgAction, Command};
use remap_network::{DnsRuntimeConfig, GatewayRuntimeConfig};
use remap_protocol::{ControlPaths, Diagnostic};
use remapd::{DaemonConfig, RunAsUser};

fn main() -> std::process::ExitCode {
    match run(std::env::args_os().collect()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error[{}]: {}", error.code, error.message);
            if let Some(hint) = error.hint {
                eprintln!("hint: {hint}");
            }
            std::process::ExitCode::FAILURE
        }
    }
}

fn run(arguments: Vec<OsString>) -> Result<(), Diagnostic> {
    let Some(config) = parse_config(arguments)? else {
        return Ok(());
    };
    let daemon = remapd::bootstrap(config)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(runtime_error)?;
    eprintln!("Remap daemon starting; press Control-C to stop.");
    runtime.block_on(daemon.run())
}

fn parse_config(arguments: Vec<OsString>) -> Result<Option<DaemonConfig>, Diagnostic> {
    let matches = match command().try_get_matches_from(arguments) {
        Ok(matches) => matches,
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            print!("{error}");
            return Ok(None);
        }
        Err(error) => return Err(usage_error(error.to_string())),
    };
    let paths = matches
        .get_one::<PathBuf>("data-dir")
        .map_or_else(ControlPaths::discover, |path| Ok(ControlPaths::under(path)))?;
    let launchd_sockets = matches.get_flag("launchd-sockets");
    let systemd_sockets = matches.get_flag("systemd-sockets");
    let mut config = DaemonConfig::new(paths);
    if let Some(path) = matches.get_one::<PathBuf>("system-socket") {
        config.system_socket.clone_from(path);
    }
    if let Some(listen) = matches.get_one::<SocketAddr>("dns-listen").copied() {
        let upstreams = matches
            .get_many::<SocketAddr>("dns-upstream")
            .map_or_else(Vec::new, |values| values.copied().collect());
        if upstreams.len() > 4 {
            return Err(usage_error(
                "remapd accepts at most four --dns-upstream values",
            ));
        }
        if upstreams.is_empty() && !(launchd_sockets || systemd_sockets) {
            return Err(usage_error(
                "--dns-listen requires an upstream unless the native service manager supplies the supervisor",
            ));
        }
        config.dns = Some(DnsRuntimeConfig::new(listen, upstreams));
    }
    if let Some(listen) = matches.get_one::<SocketAddr>("http-listen").copied() {
        config.gateway = Some(GatewayRuntimeConfig::new(listen));
        if let Some(dns) = &mut config.dns {
            match listen.ip() {
                std::net::IpAddr::V4(_) => dns.policy.routed_ipv6 = None,
                std::net::IpAddr::V6(_) => dns.policy.routed_ipv4 = None,
            }
        }
    }
    config.launchd_sockets = launchd_sockets;
    config.systemd_sockets = systemd_sockets;
    config.run_as = matches
        .get_one::<String>("run-as-user")
        .cloned()
        .map(RunAsUser::new);
    Ok(Some(config))
}

fn command() -> Command {
    Command::new("remapd")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Runs the authoritative per-user Remap service")
        .long_about(
            "remapd owns the local mapping registry and serializes every mutation.\n\
             Native service managers can provide privileged sockets before the\n\
             process starts; request handling always runs as the selected user.",
        )
        .arg(data_dir_argument())
        .arg(dns_listener_argument())
        .arg(dns_upstream_argument())
        .arg(http_listener_argument())
        .arg(system_socket_argument())
        .arg(
            Arg::new("launchd-sockets")
                .long("launchd-sockets")
                .action(ArgAction::SetTrue)
                .requires("data-dir")
                .requires("system-socket")
                .conflicts_with("run-as-user")
                .help("Consume the native low-port sockets declared by launchd"),
        )
        .arg(
            Arg::new("systemd-sockets")
                .long("systemd-sockets")
                .action(ArgAction::SetTrue)
                .requires("data-dir")
                .requires("dns-listen")
                .requires("http-listen")
                .conflicts_with_all(["launchd-sockets", "run-as-user"])
                .help("Adopt the exact DNS and HTTP sockets supplied by systemd"),
        )
        .arg(
            Arg::new("run-as-user")
                .long("run-as-user")
                .value_name("ACCOUNT")
                .requires("data-dir")
                .conflicts_with("launchd-sockets")
                .help("Bind listeners as root, then discard privilege (Linux service mode)"),
        )
}

fn data_dir_argument() -> Arg {
    Arg::new("data-dir")
        .long("data-dir")
        .value_name("PATH")
        .value_parser(clap::value_parser!(PathBuf))
        .help("Use an explicit private data directory")
}

fn dns_listener_argument() -> Arg {
    Arg::new("dns-listen")
        .long("dns-listen")
        .value_name("LOOPBACK:PORT")
        .value_parser(clap::value_parser!(SocketAddr))
        .help("Listen for UDP and TCP DNS on an explicit loopback socket")
}

fn dns_upstream_argument() -> Arg {
    Arg::new("dns-upstream")
        .long("dns-upstream")
        .value_name("ADDRESS:PORT")
        .value_parser(clap::value_parser!(SocketAddr))
        .action(ArgAction::Append)
        .requires("dns-listen")
        .help("Forward unmapped DNS to this resolver; repeat up to four times")
}

fn http_listener_argument() -> Arg {
    Arg::new("http-listen")
        .long("http-listen")
        .value_name("LOOPBACK:PORT")
        .value_parser(clap::value_parser!(SocketAddr))
        .help("Route mapped HTTP names from an explicit loopback socket")
}

fn system_socket_argument() -> Arg {
    Arg::new("system-socket")
        .long("system-socket")
        .value_name("PATH")
        .value_parser(clap::value_parser!(PathBuf))
        .help("Adopt the native root-supervisor Unix socket at this path")
}

fn usage_error(message: impl Into<String>) -> Diagnostic {
    Diagnostic::new(
        "E_USAGE",
        message,
        Some("run 'remapd --help' for the supported options".to_owned()),
        false,
    )
}

fn runtime_error(_error: std::io::Error) -> Diagnostic {
    Diagnostic::new(
        "E_RUNTIME_START",
        "the asynchronous service runtime could not start",
        Some("check process resource limits and retry the native service".to_owned()),
        true,
    )
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::command;

    #[test]
    fn command_definition_is_consistent() {
        command().debug_assert();
    }

    #[test]
    fn systemd_mode_requires_the_complete_runtime_listener_contract() {
        let incomplete = command().try_get_matches_from(["remapd", "--systemd-sockets"]);
        assert!(incomplete.is_err());
        let complete = command().try_get_matches_from([
            "remapd",
            "--data-dir",
            "/var/lib/remap",
            "--dns-listen",
            "127.0.0.1:53",
            "--http-listen",
            "127.0.0.1:80",
            "--systemd-sockets",
        ]);
        assert!(complete.is_ok());
        if let Ok(matches) = complete {
            assert!(matches.get_flag("systemd-sockets"));
        }
        let ordinary = super::parse_config(
            [
                "remapd",
                "--dns-listen",
                "127.0.0.1:5353",
                "--http-listen",
                "127.0.0.1:8080",
            ]
            .into_iter()
            .map(OsString::from)
            .collect(),
        );
        assert!(ordinary.is_err());
    }

    #[test]
    fn launchd_mode_accepts_only_a_supervisor_published_initial_plan() {
        let parsed = super::parse_config(
            [
                "remapd",
                "--data-dir",
                "/Users/remap/Library/Application Support/org.Agenxy.Remap",
                "--dns-listen",
                "127.0.0.1:53",
                "--http-listen",
                "127.0.0.1:80",
                "--system-socket",
                "/var/run/org.agenxy.Remap.system.sock",
                "--launchd-sockets",
            ]
            .into_iter()
            .map(OsString::from)
            .collect(),
        );
        assert!(parsed.is_ok());
    }
}
