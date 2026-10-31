// SPDX-License-Identifier: GPL-3.0-or-later
use remap_core::{HostHeaderPolicy, MappingTarget, NamePattern};
use remap_protocol::CommandResult;

use crate::cli::Action;
use crate::diagnostic::Diagnostic;
use crate::runtime_health::RuntimeHealth;
use remap_mcp::system_lookup::SystemLookup;

const MANPAGE_DATE: &str = "2026-08-16";

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum Report {
    Document(DocumentReport),
    Doctor(DoctorReport),
    Validation(ValidationReport),
    Authority {
        command: &'static str,
        result: CommandResult,
    },
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct DocumentReport {
    pub(crate) command: &'static str,
    pub(crate) content: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct DoctorReport {
    pub(crate) version: &'static str,
    pub(crate) operating_system: &'static str,
    pub(crate) architecture: &'static str,
    pub(crate) authority: String,
    pub(crate) revision: Option<u64>,
    pub(crate) mapping_count: Option<u64>,
    pub(crate) health: RuntimeHealth,
    pub(crate) native_install: bool,
    pub(crate) system_lookup: SystemLookup,
    pub(crate) peer_machines: Option<remap_protocol::PeerMachineListeners>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct ValidationReport {
    pub(crate) warnings: Vec<String>,
    pub(crate) landing: Option<String>,
    pub(crate) pattern: String,
    pub(crate) target: String,
    pub(crate) target_kind: &'static str,
    pub(crate) host_header_policy: Option<&'static str>,
}

pub(crate) fn execute(action: Action) -> Result<Report, Diagnostic> {
    match action {
        Action::Completions { shell } => generate_completions(shell).map(Report::Document),
        Action::Manpage => generate_manpage().map(Report::Document),
        Action::Manpages { directory } => generate_manpages(&directory).map(Report::Document),
        Action::Validate {
            pattern,
            landing,
            target,
            host_header_policy,
        } => validate(&pattern, &target, host_header_policy, landing.as_deref())
            .map(Report::Validation),
        Action::Doctor
        | Action::Mcp { .. }
        | Action::Daemon { .. }
        | Action::Status
        | Action::SystemLifecycle { .. }
        | Action::List { .. }
        | Action::Get { .. }
        | Action::Resolve { .. }
        | Action::Preview { .. }
        | Action::Apply { .. }
        | Action::Set { .. }
        | Action::Enable(_)
        | Action::Disable(_)
        | Action::Remove(_) => Err(Diagnostic::internal(
            "a service command reached the offline command executor",
        )),
    }
}

fn generate_completions(shell: clap_complete::Shell) -> Result<DocumentReport, Diagnostic> {
    let mut bytes = Vec::new();
    clap_complete::generate(shell, &mut crate::cli::command(), "remap", &mut bytes);
    String::from_utf8(bytes)
        .map(|content| DocumentReport {
            command: "completions",
            content,
        })
        .map_err(|error| Diagnostic::internal(format!("completion output was not UTF-8: {error}")))
}

fn generate_manpage() -> Result<DocumentReport, Diagnostic> {
    render_manpage(crate::cli::command()).map(|content| DocumentReport {
        command: "manpage",
        content,
    })
}

fn generate_manpages(directory: &std::path::Path) -> Result<DocumentReport, Diagnostic> {
    std::fs::create_dir_all(directory).map_err(|error| {
        Diagnostic::internal(format!("could not create the manpage directory: {error}"))
    })?;
    let mut root = crate::cli::command();
    root.build();
    write_manpage_tree(&root, directory)?;
    Ok(DocumentReport {
        command: "manpages",
        content: format!(
            "Generated the complete remap(1) manual in {}.\n",
            directory.display()
        ),
    })
}

fn write_manpage_tree(
    command: &clap::Command,
    directory: &std::path::Path,
) -> Result<(), Diagnostic> {
    for child in command
        .get_subcommands()
        .filter(|child| !child.is_hide_set())
    {
        write_manpage_tree(child, directory)?;
    }
    let name = command
        .get_display_name()
        .unwrap_or_else(|| command.get_name());
    let path = directory.join(format!("{name}.1"));
    let content = render_manpage(command.clone())?;
    std::fs::write(&path, content).map_err(|error| {
        Diagnostic::internal(format!("could not write {}: {error}", path.display()))
    })
}

fn render_manpage(command: clap::Command) -> Result<String, Diagnostic> {
    let title = command
        .get_display_name()
        .unwrap_or_else(|| command.get_name())
        .to_uppercase();
    let mut bytes = Vec::new();
    clap_mangen::Man::new(command)
        .title(title)
        .date(MANPAGE_DATE)
        .source(format!("Remap {}", env!("CARGO_PKG_VERSION")))
        .manual("Remap Manual")
        .render(&mut bytes)
        .map_err(|error| {
            Diagnostic::internal(format!("could not generate the manpage: {error}"))
        })?;
    String::from_utf8(bytes)
        .map(|content| normalize_roff(&content))
        .map_err(|error| Diagnostic::internal(format!("manpage output was not UTF-8: {error}")))
}

fn normalize_roff(content: &str) -> String {
    let mut normalized = Vec::new();
    for line in content.lines().map(str::trim_end) {
        if line == ".br" {
            continue;
        }
        normalized.extend(wrap_roff_line(line));
    }
    normalized.join("\n") + "\n"
}

fn wrap_roff_line(line: &str) -> Vec<String> {
    const WIDTH: usize = 78;
    if line.len() <= WIDTH || line.starts_with('.') {
        return vec![line.to_owned()];
    }
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in line.split_whitespace() {
        if !current.is_empty() && current.len() + word.len() + 1 > WIDTH {
            lines.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

fn validate(
    pattern: &str,
    target: &str,
    host_header_policy: HostHeaderPolicy,
    landing: Option<&str>,
) -> Result<ValidationReport, Diagnostic> {
    let pattern = NamePattern::parse(pattern)
        .map_err(|error| Diagnostic::invalid_pattern(error.to_string()))?;
    let target = MappingTarget::parse_with_http_policy(target, host_header_policy)
        .map_err(|error| Diagnostic::invalid_target(error.to_string()))?;
    if let MappingTarget::Moved(moved) = &target {
        moved
            .validate_source(&pattern)
            .map_err(|error| Diagnostic::invalid_target(error.to_string()))?;
    }
    let landing = landing
        .map(|value| {
            let path = remap_core::LandingPath::parse(value)?;
            path.validate_target(&target)?;
            Ok::<_, remap_core::LandingPathError>(path.as_str().to_owned())
        })
        .transpose()
        .map_err(|error| Diagnostic::invalid_target(error.to_string()))?;
    let policy = match &target {
        MappingTarget::Http(upstream) => Some(upstream.host_header_policy().as_str()),
        MappingTarget::Peer(service) => Some(service.host_header_policy().as_str()),
        MappingTarget::Moved(_)
        | MappingTarget::DnsAddress(_)
        | MappingTarget::DnsAlias(_)
        | MappingTarget::PeerMachine(_) => None,
    };
    Ok(ValidationReport {
        warnings: remap_core::target_advisories(&target),
        landing,
        pattern: pattern.to_string(),
        target: target.to_string(),
        target_kind: target.kind().as_str(),
        host_header_policy: policy,
    })
}
