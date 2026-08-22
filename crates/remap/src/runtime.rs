use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
use std::process::{Command as ProcessCommand, Stdio};

use remap_core::HostHeaderPolicy;
use remap_network::{DnsRuntimeConfig, GatewayRuntimeConfig};
use remap_protocol::{
    Change, Command, CommandResult, ControlClient, ControlPaths, HostPolicy, Surface,
};
use remapd::DaemonConfig;

use crate::app::{self, Report};
use crate::cli::{Action, MutationAction, SystemLifecycleCommand};
use crate::diagnostic::Diagnostic;
use crate::runtime_health::{RuntimeHealth, installation_ready, valid_challenge, verify};

const MAX_CHANGE_DOCUMENT_BYTES: u64 = 512 * 1024;

#[cfg(target_os = "macos")]
const NATIVE_LIFECYCLE_CLIENT: &str =
    "/Library/Application Support/Agenxy/Remap/Install/current/libexec/remap-lifecycle";

pub(crate) fn run_native_lifecycle(
    command: SystemLifecycleCommand,
    json: bool,
) -> Result<u8, Diagnostic> {
    #[cfg(target_os = "macos")]
    {
        let mut process = ProcessCommand::new(NATIVE_LIFECYCLE_CLIENT);
        process
            .arg(command.as_str())
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        if json {
            process.arg("--json");
        }
        let status = process.status().map_err(|error| {
            Diagnostic::native_lifecycle(format!(
                "could not start the installed lifecycle client: {error}"
            ))
        })?;
        let code = status
            .code()
            .and_then(|value| u8::try_from(value).ok())
            .unwrap_or(70);
        Ok(code)
    }
    #[cfg(not(target_os = "macos"))]
    {
        #[cfg(target_os = "linux")]
        {
            crate::linux_lifecycle::run(command, json)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (command, json);
            Err(Diagnostic::native_lifecycle(
                "this Remap build has no installed native lifecycle client",
            ))
        }
    }
}

/// Executes commands that may require an asynchronous native service runtime.
pub(crate) async fn execute(
    action: Action,
    data_dir: Option<&Path>,
) -> Result<Option<Report>, Diagnostic> {
    match action {
        Action::Doctor => doctor(data_dir).await.map(Some),
        Action::Mcp {
            data_dir: action_dir,
        } => {
            run_mcp(action_dir.as_deref().or(data_dir)).await?;
            Ok(None)
        }
        Action::Daemon {
            data_dir: action_dir,
            dns_listen,
            dns_upstreams,
            http_listen,
        } => {
            run_daemon(
                action_dir.as_deref().or(data_dir),
                dns_listen,
                dns_upstreams,
                http_listen,
            )
            .await?;
            Ok(None)
        }
        Action::Status => authority(data_dir, "status", Command::Status).await,
        Action::List {
            after,
            limit,
            include_disabled,
        } => {
            authority(
                data_dir,
                "list",
                Command::List {
                    after,
                    limit,
                    include_disabled,
                },
            )
            .await
        }
        Action::Get { pattern } => authority(data_dir, "get", Command::Get { pattern }).await,
        Action::Resolve { name } => authority(data_dir, "resolve", Command::Resolve { name }).await,
        Action::Preview { file } => {
            let changes = read_change_document(&file)?;
            authority(data_dir, "preview", Command::Preview { changes }).await
        }
        Action::Apply {
            file,
            expected_revision,
            operation_id,
        } => {
            let changes = read_change_document(&file)?;
            mutation_authority(data_dir, "apply", expected_revision, operation_id, changes).await
        }
        Action::Set {
            pattern,
            target,
            host_header_policy,
            enabled,
            expected_revision,
            operation_id,
        } => {
            let change = Change::Set {
                pattern,
                target,
                host_policy: wire_policy(host_header_policy),
                enabled,
            };
            mutate(data_dir, "set", expected_revision, operation_id, change).await
        }
        Action::Enable(mutation) => {
            mutate_named(data_dir, "enable", mutation, |pattern| Change::Enable {
                pattern,
            })
            .await
        }
        Action::Disable(mutation) => {
            mutate_named(data_dir, "disable", mutation, |pattern| Change::Disable {
                pattern,
            })
            .await
        }
        Action::Remove(mutation) => {
            mutate_named(data_dir, "remove", mutation, |pattern| Change::Remove {
                pattern,
            })
            .await
        }
        Action::SystemLifecycle { .. } => Err(Diagnostic::internal(
            "a native lifecycle command bypassed its exact-path handoff",
        )),
        offline => app::execute(offline).map(Some),
    }
}

async fn doctor(data_dir: Option<&Path>) -> Result<Report, Diagnostic> {
    let (authority, revision, mapping_count, authority_ready, health) =
        inspect_runtime(data_dir).await;
    let native_install = installation_ready(authority_ready, &health);
    Ok(Report::Doctor(app::DoctorReport {
        version: env!("CARGO_PKG_VERSION"),
        operating_system: std::env::consts::OS,
        architecture: std::env::consts::ARCH,
        authority,
        revision,
        mapping_count,
        health,
        native_install,
    }))
}

async fn inspect_runtime(
    data_dir: Option<&Path>,
) -> (String, Option<u64>, Option<u64>, bool, RuntimeHealth) {
    let unavailable = RuntimeHealth {
        dns: false,
        forwarding: false,
        http: false,
    };
    let client = match client(data_dir) {
        Ok(client) => client,
        Err(error) => {
            return (
                format!("unavailable ({})", error.code()),
                None,
                None,
                false,
                unavailable,
            );
        }
    };
    let Some(nonce) = runtime_health_nonce() else {
        return (
            "unavailable (E_RUNTIME_IDENTITY)".to_owned(),
            None,
            None,
            false,
            unavailable,
        );
    };
    let challenge = match client
        .execute(Command::HealthChallenge {
            nonce: nonce.clone(),
        })
        .await
    {
        Ok(CommandResult::HealthChallenge(challenge))
            if valid_challenge(&challenge, env!("CARGO_PKG_VERSION")) =>
        {
            challenge
        }
        Ok(_) => {
            return (
                "returned an invalid runtime identity".to_owned(),
                None,
                None,
                false,
                unavailable,
            );
        }
        Err(error) => {
            return (
                format!("unavailable ({})", error.code),
                None,
                None,
                false,
                unavailable,
            );
        }
    };
    let status = match client.execute(Command::Status).await {
        Ok(CommandResult::Status(status)) => status,
        Ok(_) => {
            return (
                "returned an invalid status result".to_owned(),
                None,
                None,
                false,
                unavailable,
            );
        }
        Err(error) => {
            return (
                format!("unavailable ({})", error.code),
                None,
                None,
                false,
                unavailable,
            );
        }
    };
    let health = verify(
        &nonce,
        &challenge,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 80)),
    )
    .await;
    (
        "ready".to_owned(),
        Some(status.revision),
        Some(status.mapping_count),
        true,
        health,
    )
}

fn runtime_health_nonce() -> Option<String> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).ok()?;
    let mut encoded = [0_u8; 32];
    for (index, byte) in random.into_iter().enumerate() {
        encoded[index * 2] = HEX[usize::from(byte >> 4)];
        encoded[index * 2 + 1] = HEX[usize::from(byte & 0x0f)];
    }
    std::str::from_utf8(&encoded).ok().map(ToOwned::to_owned)
}

async fn run_mcp(data_dir: Option<&Path>) -> Result<(), Diagnostic> {
    let paths = control_paths(data_dir)?;
    let client = ControlClient::new(paths.socket(), Surface::Mcp, env!("CARGO_PKG_VERSION"));
    remap_mcp::serve_stdio(client)
        .await
        .map_err(Diagnostic::service)
}

async fn run_daemon(
    data_dir: Option<&Path>,
    dns_listen: Option<std::net::SocketAddr>,
    dns_upstreams: Vec<std::net::SocketAddr>,
    http_listen: Option<std::net::SocketAddr>,
) -> Result<(), Diagnostic> {
    let paths = control_paths(data_dir)?;
    let mut config = DaemonConfig::new(paths);
    if let Some(listen) = dns_listen {
        config.dns = Some(DnsRuntimeConfig::new(listen, dns_upstreams));
    }
    if let Some(listen) = http_listen {
        config.gateway = Some(GatewayRuntimeConfig::new(listen));
        if let Some(dns) = &mut config.dns {
            match listen.ip() {
                std::net::IpAddr::V4(_) => dns.policy.routed_ipv6 = None,
                std::net::IpAddr::V6(_) => dns.policy.routed_ipv4 = None,
            }
        }
    }
    eprintln!("Remap daemon starting; press Control-C to stop.");
    remapd::run(config).await.map_err(Diagnostic::service)
}

async fn authority(
    data_dir: Option<&Path>,
    command_name: &'static str,
    command: Command,
) -> Result<Option<Report>, Diagnostic> {
    let result = client(data_dir)?
        .execute(command)
        .await
        .map_err(Diagnostic::service)?;
    Ok(Some(Report::Authority {
        command: command_name,
        result,
    }))
}

async fn mutate_named(
    data_dir: Option<&Path>,
    command_name: &'static str,
    mutation: MutationAction,
    change: impl FnOnce(String) -> Change,
) -> Result<Option<Report>, Diagnostic> {
    mutate(
        data_dir,
        command_name,
        mutation.expected_revision,
        mutation.operation_id,
        change(mutation.pattern),
    )
    .await
}

async fn mutate(
    data_dir: Option<&Path>,
    command_name: &'static str,
    expected_revision: Option<u64>,
    operation_id: Option<String>,
    change: Change,
) -> Result<Option<Report>, Diagnostic> {
    let client = client(data_dir)?;
    let revision = match expected_revision {
        Some(revision) => revision,
        None => current_revision(&client).await?,
    };
    let operation_id = operation_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let result = client
        .execute(Command::Apply {
            expected_revision: revision,
            operation_id: operation_id.clone(),
            changes: vec![change],
        })
        .await
        .map_err(|error| Diagnostic::mutation_service(error, &operation_id, revision))?;
    Ok(Some(Report::Authority {
        command: command_name,
        result,
    }))
}

async fn mutation_authority(
    data_dir: Option<&Path>,
    command_name: &'static str,
    expected_revision: u64,
    operation_id: String,
    changes: Vec<Change>,
) -> Result<Option<Report>, Diagnostic> {
    let result = client(data_dir)?
        .execute(Command::Apply {
            expected_revision,
            operation_id: operation_id.clone(),
            changes,
        })
        .await
        .map_err(|error| Diagnostic::mutation_service(error, &operation_id, expected_revision))?;
    Ok(Some(Report::Authority {
        command: command_name,
        result,
    }))
}

async fn current_revision(client: &ControlClient) -> Result<u64, Diagnostic> {
    match client
        .execute(Command::Status)
        .await
        .map_err(Diagnostic::service)?
    {
        CommandResult::Status(status) => Ok(status.revision),
        _ => Err(Diagnostic::internal(
            "the daemon returned a non-status result while reading the revision",
        )),
    }
}

fn client(data_dir: Option<&Path>) -> Result<ControlClient, Diagnostic> {
    let paths = control_paths(data_dir)?;
    Ok(ControlClient::new(
        paths.socket(),
        Surface::Cli,
        env!("CARGO_PKG_VERSION"),
    ))
}

const fn wire_policy(policy: HostHeaderPolicy) -> HostPolicy {
    match policy {
        HostHeaderPolicy::PreserveClient => HostPolicy::PreserveClient,
        HostHeaderPolicy::UseUpstream => HostPolicy::UseUpstream,
    }
}

fn control_paths(data_dir: Option<&Path>) -> Result<ControlPaths, Diagnostic> {
    data_dir.map_or_else(
        || ControlPaths::discover().map_err(Diagnostic::service),
        |path| Ok(ControlPaths::under(PathBuf::from(path))),
    )
}

fn read_change_document(path: &Path) -> Result<Vec<Change>, Diagnostic> {
    let bytes = if path == Path::new("-") {
        read_bounded(std::io::stdin().lock())?
    } else {
        let file = std::fs::File::open(path).map_err(|error| {
            Diagnostic::change_document(format!("could not open the change document: {error}"))
        })?;
        read_bounded(file)?
    };
    serde_json::from_slice(&bytes).map_err(|error| {
        Diagnostic::change_document(format!(
            "invalid change JSON at line {}, column {}: {error}",
            error.line(),
            error.column()
        ))
    })
}

fn read_bounded(reader: impl Read) -> Result<Vec<u8>, Diagnostic> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_CHANGE_DOCUMENT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            Diagnostic::change_document(format!("could not read the change document: {error}"))
        })?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_CHANGE_DOCUMENT_BYTES {
        return Err(Diagnostic::change_document(format!(
            "the change document exceeds the {MAX_CHANGE_DOCUMENT_BYTES}-byte limit"
        )));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::io;
    use std::time::Duration;

    use remap_core::HostHeaderPolicy;
    use remap_protocol::{CommandResult, ControlPaths};
    use remapd::DaemonConfig;

    use super::execute;
    use crate::app::Report;
    use crate::cli::Action;

    #[tokio::test]
    async fn human_commands_share_the_authoritative_revision() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let paths = ControlPaths::under(directory.path().join("data"));
        let (stop_sender, stop_receiver) = tokio::sync::oneshot::channel();
        let daemon_paths = paths.clone();
        let daemon = tokio::spawn(async move {
            remapd::serve_until(DaemonConfig::new(daemon_paths), async {
                let _result = stop_receiver.await;
            })
            .await
        });
        wait_for_socket(paths.socket()).await?;

        let set = Action::Set {
            pattern: "atlas".to_owned(),
            target: "127.0.0.1".to_owned(),
            host_header_policy: HostHeaderPolicy::PreserveClient,
            enabled: None,
            expected_revision: None,
            operation_id: None,
        };
        let report = execute(set, Some(paths.data_dir()))
            .await?
            .ok_or_else(|| io::Error::other("set returned no report"))?;
        let Report::Authority {
            result: CommandResult::Apply(receipt),
            ..
        } = report
        else {
            return Err(io::Error::other("set returned the wrong report").into());
        };
        assert_eq!(receipt.revision, 1);

        let listed = execute(
            Action::List {
                after: None,
                limit: 10,
                include_disabled: true,
            },
            Some(paths.data_dir()),
        )
        .await?
        .ok_or_else(|| io::Error::other("list returned no report"))?;
        let Report::Authority {
            result: CommandResult::List(list),
            ..
        } = listed
        else {
            return Err(io::Error::other("list returned the wrong report").into());
        };
        assert_eq!(list.revision, 1);
        assert_eq!(list.mappings.len(), 1);
        assert_eq!(list.mappings[0].pattern, "atlas");

        let _result = stop_sender.send(());
        daemon.await??;
        Ok(())
    }

    #[tokio::test]
    async fn humans_can_preview_and_apply_the_same_atomic_document() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let paths = ControlPaths::under(directory.path().join("data"));
        let changes = directory.path().join("changes.json");
        std::fs::write(
            &changes,
            r#"[{"kind":"set","pattern":"atlas","target":"127.0.0.1","host_policy":"preserve-client"}]"#,
        )?;
        let (stop_sender, stop_receiver) = tokio::sync::oneshot::channel();
        let daemon_paths = paths.clone();
        let daemon = tokio::spawn(async move {
            remapd::serve_until(DaemonConfig::new(daemon_paths), async {
                let _result = stop_receiver.await;
            })
            .await
        });
        wait_for_socket(paths.socket()).await?;

        let preview = execute(
            Action::Preview {
                file: changes.clone(),
            },
            Some(paths.data_dir()),
        )
        .await?
        .ok_or_else(|| io::Error::other("preview returned no report"))?;
        assert!(matches!(
            preview,
            Report::Authority {
                result: CommandResult::Preview(_),
                ..
            }
        ));
        let applied = execute(
            Action::Apply {
                file: changes,
                expected_revision: 0,
                operation_id: "4df4bb55-93bb-4f99-9707-9761f6a69364".to_owned(),
            },
            Some(paths.data_dir()),
        )
        .await?
        .ok_or_else(|| io::Error::other("apply returned no report"))?;
        assert!(matches!(
            applied,
            Report::Authority {
                result: CommandResult::Apply(_),
                ..
            }
        ));

        let _sent = stop_sender.send(());
        daemon.await??;
        Ok(())
    }

    async fn wait_for_socket(path: &std::path::Path) -> Result<(), Box<dyn Error>> {
        for _attempt in 0..100 {
            if path.exists() {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Err(io::Error::other("daemon socket did not appear within one second").into())
    }
}
