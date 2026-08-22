//! Privileged Linux resolver lifecycle entry point.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

#[cfg(target_os = "linux")]
mod authority;
#[cfg(target_os = "linux")]
mod bootstrap_recovery;
#[cfg(target_os = "linux")]
mod channel;
#[cfg(target_os = "linux")]
mod cleanup;
#[cfg(target_os = "linux")]
mod digest;
#[cfg(target_os = "linux")]
mod generation;
#[cfg(target_os = "linux")]
mod generation_storage;
#[cfg(target_os = "linux")]
mod install_model;
#[cfg(target_os = "linux")]
mod installer;
#[cfg(target_os = "linux")]
mod lifecycle_approval;
#[cfg(target_os = "linux")]
mod lifecycle_contract;
#[cfg(target_os = "linux")]
mod lifecycle_effects;
#[cfg(target_os = "linux")]
mod lifecycle_install;
#[cfg(target_os = "linux")]
mod lifecycle_names;
#[cfg(target_os = "linux")]
mod lifecycle_observation;
#[cfg(target_os = "linux")]
mod lifecycle_recovery;
#[cfg(target_os = "linux")]
mod manager;
#[cfg(target_os = "linux")]
mod publications;
#[cfg(target_os = "linux")]
mod resolver_acceptance;
#[cfg(target_os = "linux")]
mod resolver_events;
#[cfg(target_os = "linux")]
mod resolver_generation;
#[cfg(target_os = "linux")]
mod resolver_stability;
#[cfg(target_os = "linux")]
mod resolver_upstreams;
#[cfg(target_os = "linux")]
mod resolver_worker;
#[cfg(target_os = "linux")]
mod rollback;
#[cfg(target_os = "linux")]
mod runtime_authority;
#[cfg(target_os = "linux")]
mod service_health;
#[cfg(target_os = "linux")]
mod socket_preflight;
#[cfg(target_os = "linux")]
mod source_io;
#[cfg(target_os = "linux")]
mod supervisor;
#[cfg(target_os = "linux")]
mod system_publication;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
#[cfg(target_os = "linux")]
use remap_linux::LinkIndex;

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Owns Remap's reversible native Linux resolver lifecycle"
)]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Reports typed installation, resolver, link, and service state.
    Status(InspectArguments),
    /// Inspects typed resolver candidates without mutating the host.
    Inspect(InspectArguments),
    /// Prepares an exact state-bound lifecycle plan without effects.
    Preview(PreviewArguments),
    /// Installs and activates one ownership-checked system generation.
    Install(CommitInstallArguments),
    /// Transactionally publishes a new generation with automatic rollback.
    Update(CommitInstallArguments),
    /// Restores resolver state and removes only the exact owned generation.
    Uninstall(CommitArguments),
    /// Runs one separately previewed interrupted-transaction recovery.
    Recover(RecoverArguments),
    /// Stabilizes and supervises one exact manager-bound resolver link.
    Serve(SupervisorArguments),
    /// Stabilizes, restores, and removes one exact manager-bound activation.
    Deactivate(SupervisorArguments),
    /// Authorizes one systemd start against exact generation and lease state.
    AuthorizeRuntime,
}

impl Command {
    const fn label(&self) -> &'static str {
        match self {
            Self::Status(_) => "status",
            Self::Inspect(_) => "inspect",
            Self::Preview(arguments) => match arguments.command {
                PreviewCommand::Recover(_) => "preview-recovery",
                PreviewCommand::Install(_)
                | PreviewCommand::Update(_)
                | PreviewCommand::Uninstall(_) => "preview",
            },
            Self::Install(_) => "install",
            Self::Update(_) => "update",
            Self::Uninstall(_) => "uninstall",
            Self::Recover(_) => "recover",
            Self::Serve(_) => "serve",
            Self::Deactivate(_) => "deactivate",
            Self::AuthorizeRuntime => "authorize-runtime",
        }
    }
}

#[derive(Debug, Clone, clap::Args)]
struct InspectArguments {
    /// Explicit link index to inspect; omitted status enumerates candidates.
    #[arg(long)]
    link: Option<u32>,
    /// Emits the bounded versioned lifecycle envelope.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Subcommand)]
enum PreviewCommand {
    /// Previews a first installation.
    Install(InstallArguments),
    /// Previews an installed generation replacement.
    Update(InstallArguments),
    /// Previews exact resolver restoration and owned publication removal.
    Uninstall(JsonArguments),
    /// Previews all pending interrupted lifecycle recovery.
    Recover(RecoverPreviewArguments),
}

#[derive(Debug, clap::Args)]
struct PreviewArguments {
    #[command(subcommand)]
    command: PreviewCommand,
}

#[derive(Debug, Clone, clap::Args)]
struct CommitInstallArguments {
    #[command(flatten)]
    install: InstallArguments,
    /// Exact 64-character token emitted by the matching preview.
    #[arg(long)]
    approval_token: String,
}

#[derive(Debug, Clone, clap::Args)]
struct CommitArguments {
    /// Exact 64-character token emitted by the matching preview.
    #[arg(long)]
    approval_token: String,
    /// Emits the bounded versioned lifecycle envelope.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, clap::Args)]
struct RecoverArguments {
    /// Recovers every pending Remap-owned lifecycle transaction.
    #[arg(long)]
    all: bool,
    /// Exact 64-character token emitted by `preview recover --all`.
    #[arg(long)]
    approval_token: String,
    /// Emits the bounded versioned lifecycle envelope.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, clap::Args)]
struct RecoverPreviewArguments {
    /// Previews every pending Remap-owned lifecycle transaction.
    #[arg(long)]
    all: bool,
    /// Emits the bounded versioned lifecycle envelope.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, clap::Args)]
struct JsonArguments {
    /// Emits the bounded versioned lifecycle envelope.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, clap::Args)]
struct InstallArguments {
    /// Built Linux remap ELF image to publish as the user-facing command.
    #[arg(long, value_name = "PATH")]
    remap_source: PathBuf,
    /// Built Linux remapd ELF image to copy into the immutable generation.
    #[arg(long, value_name = "PATH")]
    remapd_source: PathBuf,
    /// Built Linux supervisor ELF image to copy into the immutable generation.
    #[arg(long, value_name = "PATH")]
    system_source: PathBuf,
    /// Generated manuals, completions, LICENSE, and NOTICE payload directory.
    #[arg(long, value_name = "PATH")]
    assets_source: PathBuf,
    /// Canonical SHA-256 of every reviewed binary and asset source byte.
    #[arg(long, value_name = "64_HEX")]
    source_manifest_sha256: String,
    /// Existing non-root account that will run remapd.
    #[arg(long)]
    account: String,
    /// Existing non-root primary group for remapd.
    #[arg(long)]
    group: String,
    /// Interactive user represented by this host-wide activation.
    #[arg(long)]
    owner_uid: u32,
    /// Explicit systemd-resolved link index.
    #[arg(long)]
    link: u32,
    /// Emits the bounded versioned lifecycle envelope.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, clap::Args)]
struct SupervisorArguments {
    /// Explicit systemd-resolved link index; split scopes are never inferred.
    #[arg(long)]
    link: u32,
    /// Exact kernel interface name selected during approved installation.
    #[arg(long)]
    interface_name: Option<String>,
    /// Exact native manager selected during approved installation.
    #[arg(long, value_enum)]
    manager: Option<ResolverManagerArgument>,
    /// Interactive user represented by the host-wide activation.
    #[arg(long)]
    owner_uid: u32,
    /// Operating-system UID running remapd.
    #[arg(long)]
    daemon_uid: u32,
    /// Root-owned mode-0700 resolver transaction directory.
    #[arg(long, value_name = "PATH")]
    record_dir: PathBuf,
    /// Private root-authenticated remapd system-control socket.
    #[arg(long, value_name = "PATH")]
    system_socket: PathBuf,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum ResolverManagerArgument {
    SystemdResolved,
    SystemdNetworkd,
    NetworkManager,
}

impl From<ResolverManagerArgument> for remap_linux::ResolverLinkManager {
    fn from(value: ResolverManagerArgument) -> Self {
        match value {
            ResolverManagerArgument::SystemdResolved => Self::SystemdResolved,
            ResolverManagerArgument::SystemdNetworkd => Self::SystemdNetworkd,
            ResolverManagerArgument::NetworkManager => Self::NetworkManager,
        }
    }
}

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    let arguments = Arguments::parse();
    let command = arguments.command.label();
    match run(arguments) {
        Ok(output) => {
            println!("{output}");
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{}", error_envelope(command, &error));
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("error: remap-linux-system is available only on Linux");
    std::process::ExitCode::FAILURE
}

#[cfg(target_os = "linux")]
fn run(arguments: Arguments) -> std::io::Result<String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    match arguments.command {
        Command::Status(config) => {
            require_json(config.json)?;
            let link = config
                .link
                .map(LinkIndex::new)
                .transpose()
                .map_err(platform_error)?;
            let data = runtime.block_on(lifecycle_contract::status(link))?;
            success_envelope("status", &data)
        }
        Command::Inspect(config) => {
            require_json(config.json)?;
            let link = config
                .link
                .map(LinkIndex::new)
                .transpose()
                .map_err(platform_error)?;
            let data = runtime.block_on(lifecycle_contract::status(link))?;
            success_envelope("inspect", &data)
        }
        Command::Preview(config) => match config.command {
            PreviewCommand::Install(config) => {
                require_json(config.json)?;
                let request = config.try_into()?;
                let plan =
                    runtime.block_on(lifecycle_contract::prepare_install(&request, false))?;
                success_envelope("preview", &plan.preview)
            }
            PreviewCommand::Update(config) => {
                require_json(config.json)?;
                let request = config.try_into()?;
                let plan = runtime.block_on(lifecycle_contract::prepare_install(&request, true))?;
                success_envelope("preview", &plan.preview)
            }
            PreviewCommand::Uninstall(config) => {
                require_json(config.json)?;
                let plan = runtime.block_on(lifecycle_contract::prepare_uninstall())?;
                success_envelope("preview", &plan.preview)
            }
            PreviewCommand::Recover(config) => {
                require_json(config.json)?;
                require_all(config.all)?;
                let plan = runtime.block_on(lifecycle_contract::prepare_recovery())?;
                success_envelope("preview-recovery", &plan.preview)
            }
        },
        Command::Install(config) => {
            require_json(config.install.json)?;
            let request = config.install.try_into()?;
            runtime.block_on(installer::install(&request, false, &config.approval_token))?;
            success_envelope(
                "install",
                &runtime.block_on(lifecycle_contract::status(None))?,
            )
        }
        Command::Update(config) => {
            require_json(config.install.json)?;
            let request = config.install.try_into()?;
            runtime.block_on(installer::install(&request, true, &config.approval_token))?;
            success_envelope(
                "update",
                &runtime.block_on(lifecycle_contract::status(None))?,
            )
        }
        Command::Uninstall(config) => {
            require_json(config.json)?;
            runtime.block_on(installer::uninstall(&config.approval_token))?;
            success_envelope(
                "uninstall",
                &runtime.block_on(lifecycle_contract::status(None))?,
            )
        }
        Command::Recover(config) => {
            require_json(config.json)?;
            require_all(config.all)?;
            runtime.block_on(installer::recover_all(&config.approval_token))?;
            success_envelope(
                "recover",
                &runtime.block_on(lifecycle_contract::status(None))?,
            )
        }
        Command::Serve(config) => {
            runtime.block_on(supervisor::serve(
                config.try_into().map_err(platform_error)?,
            ))?;
            Ok(String::new())
        }
        Command::Deactivate(config) => {
            deactivate_command(&runtime, config)?;
            Ok(String::new())
        }
        Command::AuthorizeRuntime => {
            runtime_authority::authorize()?;
            Ok(String::new())
        }
    }
}

#[cfg(target_os = "linux")]
fn deactivate_command(
    runtime: &tokio::runtime::Runtime,
    config: SupervisorArguments,
) -> std::io::Result<()> {
    runtime.block_on(supervisor::deactivate(
        &config.try_into().map_err(platform_error)?,
    ))
}

#[cfg(target_os = "linux")]
fn success_envelope<T: serde::Serialize>(command: &str, data: &T) -> std::io::Result<String> {
    lifecycle_contract::encode_json(&serde_json::json!({
        "schemaVersion": 1,
        "ok": true,
        "command": command,
        "data": data,
    }))
}

#[cfg(target_os = "linux")]
fn error_envelope(command: &str, error: &std::io::Error) -> String {
    let category = match error.kind() {
        std::io::ErrorKind::PermissionDenied => "permission_denied",
        std::io::ErrorKind::AlreadyExists | std::io::ErrorKind::AddrInUse => "state_conflict",
        std::io::ErrorKind::InvalidData | std::io::ErrorKind::InvalidInput => "invalid_request",
        std::io::ErrorKind::Unsupported => "unsupported_platform",
        std::io::ErrorKind::TimedOut => "timeout",
        _ => "system_error",
    };
    let hint = match category {
        "permission_denied" => {
            "run the native lifecycle command as root with the required Linux capability and policy authorization"
        }
        "state_conflict" if error.kind() == std::io::ErrorKind::AddrInUse => {
            "free the reported loopback listener or choose which existing local service should own it"
        }
        "state_conflict" => "inspect status and use separately approved recovery when required",
        "unsupported_platform" if error.to_string() == lifecycle_contract::LEGACY_UPDATE_ERROR => {
            "run make uninstall, then make install to replace the legacy Linux resolver generation"
        }
        "unsupported_platform" => "inspect resolver candidates and select one supported exact link",
        "timeout" if error.to_string() == supervisor::NATIVE_MANAGER_STABILITY_TIMEOUT => {
            "inspect the selected link's native manager state and retry only after it is stably configured"
        }
        "timeout"
            if error.to_string() == resolver_acceptance::RESOLVER_PLAN_PUBLICATION_TIMEOUT =>
        {
            "inspect remapd and remap-resolver.service, then use separately approved recovery if typed status requires it"
        }
        _ => "inspect the typed status response before retrying",
    };
    lifecycle_contract::encode_json(&serde_json::json!({
        "schemaVersion": 1,
        "ok": false,
        "command": command,
        "error": {"category": category, "message": error.to_string(), "hint": hint},
    }))
    .unwrap_or_else(|_error| {
        "{\"schemaVersion\":1,\"ok\":false,\"command\":\"lifecycle\",\"error\":{\"category\":\"system_error\",\"message\":\"the bounded error response could not be encoded\",\"hint\":\"inspect native Linux state\"}}".to_owned()
    })
}

#[cfg(target_os = "linux")]
fn require_json(enabled: bool) -> std::io::Result<()> {
    if enabled {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "the Linux lifecycle contract requires --json",
        ))
    }
}

#[cfg(target_os = "linux")]
fn require_all(enabled: bool) -> std::io::Result<()> {
    if enabled {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "recovery requires the explicit --all scope",
        ))
    }
}

#[cfg(target_os = "linux")]
fn platform_error(_error: remap_linux::LinuxError) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "the explicit Linux link index is invalid",
    )
}

#[cfg(target_os = "linux")]
impl TryFrom<InstallArguments> for installer::InstallRequest {
    type Error = std::io::Error;

    fn try_from(value: InstallArguments) -> Result<Self, Self::Error> {
        Ok(Self {
            remap_source: value.remap_source,
            remapd_source: value.remapd_source,
            system_source: value.system_source,
            assets_source: value.assets_source,
            source_manifest_sha256: parse_sha256(&value.source_manifest_sha256)?,
            account: value.account,
            group: value.group,
            owner_uid: value.owner_uid,
            link: LinkIndex::new(value.link).map_err(platform_error)?,
        })
    }
}

fn parse_sha256(value: &str) -> std::io::Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "the reviewed source manifest SHA-256 must be 64 lowercase hexadecimal characters",
        ));
    }
    let mut digest = [0_u8; 32];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        digest[index] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
    }
    Ok(digest)
}

const fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => 0,
    }
}

#[cfg(target_os = "linux")]
impl TryFrom<SupervisorArguments> for supervisor::SupervisorConfig {
    type Error = remap_linux::LinuxError;

    fn try_from(value: SupervisorArguments) -> Result<Self, Self::Error> {
        Ok(Self {
            link: LinkIndex::new(value.link)?,
            interface_name: value.interface_name,
            manager: value.manager.map(Into::into),
            owner_uid: value.owner_uid,
            daemon_uid: value.daemon_uid,
            record_directory: value.record_dir,
            system_socket: value.system_socket,
        })
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::{Arguments, parse_sha256};

    #[cfg(target_os = "linux")]
    use super::error_envelope;

    #[test]
    fn command_definition_is_consistent() {
        Arguments::command().debug_assert();
    }

    #[test]
    fn supervisor_help_discloses_exact_manager_and_lease_authority() {
        let help = Arguments::command().render_long_help().to_string();
        assert!(help.contains("Stabilizes and supervises one exact manager-bound resolver link"));
        assert!(
            help.contains("Stabilizes, restores, and removes one exact manager-bound activation")
        );
        assert!(
            help.contains("Authorizes one systemd start against exact generation and lease state")
        );
    }

    #[test]
    fn source_manifest_digest_is_canonical_lowercase_hex() -> std::io::Result<()> {
        assert_eq!(parse_sha256(&"ab".repeat(32))?, [0xab; 32]);
        assert!(parse_sha256(&"AB".repeat(32)).is_err());
        assert!(parse_sha256(&"a".repeat(63)).is_err());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn legacy_update_error_has_an_exact_reinstall_action() -> std::io::Result<()> {
        let error = std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            crate::lifecycle_contract::LEGACY_UPDATE_ERROR,
        );
        let value: serde_json::Value = serde_json::from_str(&error_envelope("preview", &error))?;
        assert_eq!(
            value["error"]["hint"],
            "run make uninstall, then make install to replace the legacy Linux resolver generation"
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn resolver_stability_timeout_has_an_exact_manager_action() -> std::io::Result<()> {
        let error = std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            crate::supervisor::NATIVE_MANAGER_STABILITY_TIMEOUT,
        );
        let value: serde_json::Value = serde_json::from_str(&error_envelope("serve", &error))?;
        assert_eq!(
            value["error"]["hint"],
            "inspect the selected link's native manager state and retry only after it is stably configured"
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn resolver_plan_timeout_has_an_exact_service_action() -> std::io::Result<()> {
        let error = std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            crate::resolver_acceptance::RESOLVER_PLAN_PUBLICATION_TIMEOUT,
        );
        let value: serde_json::Value = serde_json::from_str(&error_envelope("update", &error))?;
        assert_eq!(
            value["error"]["hint"],
            "inspect remapd and remap-resolver.service, then use separately approved recovery if typed status requires it"
        );
        Ok(())
    }
}
