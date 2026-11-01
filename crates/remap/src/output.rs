// SPDX-License-Identifier: GPL-3.0-or-later
use std::borrow::Cow;
use std::fmt::Write as _;
use std::io::{self, Write};

use remap_protocol::{ChangeEffect, CommandResult, MappingView, RegistryStatus};
use serde_json::{Value, json};

use crate::app::{DoctorReport, Report, ValidationReport};
use crate::diagnostic::Diagnostic;
use crate::installed_package::InstalledPackage;
use remap_mcp::system_lookup::SystemLookup;

const SCHEMA: &str = "remap.cli/v1";

pub(crate) fn write_report(
    writer: &mut dyn Write,
    report: &Report,
    json_output: bool,
) -> io::Result<()> {
    if json_output {
        write_json(writer, &report_json(report))
    } else {
        write_human_report(writer, report)
    }
}

pub(crate) fn write_diagnostic(
    writer: &mut dyn Write,
    diagnostic: &Diagnostic,
    json_output: bool,
) -> io::Result<()> {
    if json_output {
        return write_json(
            writer,
            &json!({
                "schema": SCHEMA,
                "ok": false,
                "error": {
                    "code": diagnostic.code(),
                    "message": diagnostic.message(),
                    "detail": diagnostic.detail(),
                    "hint": diagnostic.hint(),
                    "retryable": diagnostic.retryable(),
                    "context": diagnostic.context(),
                }
            }),
        );
    }
    writeln!(
        writer,
        "error[{}]: {}",
        terminal_text(diagnostic.code()),
        terminal_text(diagnostic.message())
    )?;
    if !diagnostic.detail().is_empty() {
        write_indented_multiline(writer, diagnostic.detail())?;
    }
    writeln!(writer, "  help: {}", terminal_text(diagnostic.hint()))
}

fn write_indented_multiline(writer: &mut dyn Write, value: &str) -> io::Result<()> {
    for line in value.split('\n') {
        writeln!(writer, "  {}", terminal_line_text(line))?;
    }
    Ok(())
}

fn terminal_line_text(value: &str) -> Cow<'_, str> {
    if !value.chars().any(terminal_unsafe) {
        return Cow::Borrowed(value);
    }
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        push_terminal_character(&mut escaped, character);
    }
    Cow::Owned(escaped)
}

fn write_human_report(writer: &mut dyn Write, report: &Report) -> io::Result<()> {
    match report {
        Report::Document(report) => write!(writer, "{}", report.content),
        Report::Doctor(report) => write_doctor(writer, report),
        Report::Validation(report) => write_validation(writer, report),
        Report::Authority { result, .. } => write_authority(writer, result),
    }
}

fn write_doctor(writer: &mut dyn Write, report: &DoctorReport) -> io::Result<()> {
    writeln!(
        writer,
        "Remap {}: local diagnostics",
        terminal_text(report.version)
    )?;
    writeln!(writer)?;
    writeln!(
        writer,
        "  Platform   {}/{}",
        terminal_text(report.operating_system),
        terminal_text(report.architecture)
    )?;
    writeln!(writer, "  Validator  ready")?;
    writeln!(writer, "  Authority  {}", terminal_text(&report.authority))?;
    if let Some(revision) = report.revision {
        writeln!(writer, "  Revision   {revision}")?;
    }
    if let Some(mapping_count) = report.mapping_count {
        writeln!(writer, "  Mappings   {mapping_count}")?;
    }
    writeln!(writer, "  MCP        2026-07-28 + 2025-11-25")?;
    writeln!(writer, "  Native     {}", readiness(report.native_install))?;
    if let Some(package) = report.installed_package {
        writeln!(writer, "  Package    {}", package.description())?;
    }
    writeln!(writer, "  DNS        {}", readiness(report.health.dns))?;
    writeln!(
        writer,
        "  Forwarding {}",
        readiness(report.health.forwarding)
    )?;
    writeln!(writer, "  HTTP       {}", readiness(report.health.http))?;
    write_peer_machines(writer, report.peer_machines.as_ref())?;
    writeln!(
        writer,
        "  Lookup     {}",
        lookup_line(&report.system_lookup)
    )?;
    writeln!(writer, "  Telemetry  none")?;
    writeln!(writer)?;
    writeln!(
        writer,
        "Doctor itself changed nothing. Telemetry remains absent."
    )?;
    if matches!(
        report.system_lookup,
        SystemLookup::Bypassed { .. } | SystemLookup::Unresolved { .. }
    ) {
        writeln!(
            writer,
            "The system resolver is not returning Remap's answer. On macOS, `remap-system status` shows the recorded fallback reason."
        )?;
    }
    if report.revision.is_some()
        && report.health.dns
        && report.health.forwarding
        && report.health.http
    {
        writeln!(
            writer,
            "Remap's local authority and routing listeners are ready."
        )
    } else {
        writeln!(
            writer,
            "Recovery: install or restart the native Remap service."
        )
    }
}

fn lookup_line(lookup: &SystemLookup) -> String {
    let name = lookup.name().map(terminal_text).unwrap_or_default();
    match (lookup, lookup.answer()) {
        (SystemLookup::Matched { .. }, Some(answer)) => format!("ready ({name} → {answer})"),
        (SystemLookup::Bypassed { .. }, Some(answer)) => {
            format!("bypassed ({name} → {answer}; the system is not asking Remap)")
        }
        (SystemLookup::Unresolved { .. }, _) => {
            format!("unresolved ({name} did not resolve through the system)")
        }
        _ => "not checked (no enabled exact mapping to probe)".to_owned(),
    }
}

const fn readiness(ready: bool) -> &'static str {
    if ready { "ready" } else { "not detected" }
}

fn write_validation(writer: &mut dyn Write, report: &ValidationReport) -> io::Result<()> {
    writeln!(writer, "Valid mapping")?;
    writeln!(writer)?;
    writeln!(writer, "  Name       {}", terminal_text(&report.pattern))?;
    writeln!(writer, "  Target     {}", terminal_text(&report.target))?;
    writeln!(writer, "  Type       {}", terminal_text(report.target_kind))?;
    if let Some(policy) = report.host_header_policy {
        writeln!(writer, "  Host       {policy}")?;
    }
    write_peer_machine(writer, &report.target, None)?;
    write_landing(writer, report.landing.as_deref())?;
    write_warnings(writer, &report.warnings)?;
    writeln!(writer)?;
    writeln!(writer, "No system state changed.")
}

fn write_authority(writer: &mut dyn Write, result: &CommandResult) -> io::Result<()> {
    match result {
        CommandResult::Status(status) => write_status(writer, status),
        CommandResult::HealthChallenge(_) => writeln!(writer, "Runtime identity verified."),
        CommandResult::List(list) => {
            writeln!(writer, "Mappings at revision {}", list.revision)?;
            writeln!(writer)?;
            if list.mappings.is_empty() {
                writeln!(writer, "  No mappings.")?;
            } else {
                for mapping in &list.mappings {
                    write_mapping(writer, mapping)?;
                }
            }
            if let Some(cursor) = &list.next_cursor {
                writeln!(writer)?;
                writeln!(
                    writer,
                    "More: remap list --after '{}'",
                    terminal_text(cursor)
                )?;
            }
            Ok(())
        }
        CommandResult::Mapping(Some(mapping)) => write_mapping(writer, mapping),
        CommandResult::Mapping(None) => writeln!(writer, "No exact mapping found."),
        CommandResult::Resolution(resolution) => {
            writeln!(writer, "Resolution at revision {}", resolution.revision)?;
            writeln!(writer)?;
            if let Some(mapping) = &resolution.mapping {
                writeln!(writer, "  Name       {}", terminal_text(&resolution.name))?;
                write_mapping(writer, mapping)
            } else {
                writeln!(
                    writer,
                    "  No enabled mapping resolves {}.",
                    terminal_text(&resolution.name)
                )
            }
        }
        CommandResult::Validation(validation) => {
            writeln!(writer, "Valid mapping")?;
            writeln!(
                writer,
                "  Name       {}",
                terminal_text(&validation.pattern)
            )?;
            writeln!(writer, "  Target     {}", terminal_text(&validation.target))?;
            writeln!(
                writer,
                "  Type       {}",
                terminal_text(&validation.target_kind)
            )?;
            writeln!(writer, "  Host       {}", validation.host_policy.as_str())?;
            write_landing(writer, validation.landing.as_deref())?;
            write_warnings(writer, &validation.warnings)
        }
        CommandResult::Preview(preview) => {
            writeln!(writer, "Preview at revision {}", preview.base_revision)?;
            writeln!(writer, "  Would change  {}", preview.will_change)?;
            writeln!(writer, "  Effects       {}", preview.effects.len())?;
            write_effects(writer, &preview.effects)?;
            write_warnings(writer, &preview.warnings)
        }
        CommandResult::Apply(receipt) => {
            writeln!(writer, "Committed at revision {}", receipt.revision)?;
            writeln!(writer)?;
            writeln!(writer, "  Changed       {}", receipt.changed)?;
            writeln!(writer, "  Previous      {}", receipt.previous_revision)?;
            writeln!(writer, "  Effects       {}", receipt.effects.len())?;
            writeln!(
                writer,
                "  Operation     {}",
                terminal_text(&receipt.operation_id)
            )?;
            write_effects(writer, &receipt.effects)?;
            write_warnings(writer, &receipt.warnings)
        }
        CommandResult::Revision(notice) => {
            writeln!(
                writer,
                "Revision {} (changed: {})",
                notice.revision, notice.changed
            )
        }
    }
}

fn write_status(writer: &mut dyn Write, status: &RegistryStatus) -> io::Result<()> {
    writeln!(writer, "Remap authority at revision {}", status.revision)?;
    writeln!(writer)?;
    writeln!(writer, "  Mappings   {}", status.mapping_count)?;
    writeln!(writer, "  Active     {}", status.enabled_count)?;
    writeln!(writer, "  Schema     {}", status.schema_version)?;
    writeln!(
        writer,
        "  Daemon     {}",
        terminal_text(&status.daemon_version)
    )?;
    write_peer_machines(writer, status.peer_machine_listeners.as_ref())?;
    if let Some(error) = &status.maintenance {
        writeln!(writer, "  Mutations  blocked by maintenance")?;
        writeln!(writer, "  Reason     {}", terminal_text(&error.message))?;
        if let Some(hint) = &error.hint {
            writeln!(writer, "  Recovery   {}", terminal_text(hint))?;
        }
    } else {
        writeln!(writer, "  Mutations  ready")?;
    }
    Ok(())
}

/// Peer-machine listeners (ADR-0033): how many accept, and each one that
/// could not bind, with its cause.
fn write_peer_machines(
    writer: &mut dyn Write,
    listeners: Option<&remap_protocol::PeerMachineListeners>,
) -> io::Result<()> {
    let Some(listeners) = listeners else {
        return Ok(());
    };
    writeln!(
        writer,
        "  Peers      {} listening, {} not listening",
        listeners.listening, listeners.not_listening
    )?;
    for failure in &listeners.failures {
        writeln!(
            writer,
            "             {} {} at {}:{} not listening: {} ({})",
            terminal_text(&failure.pattern),
            terminal_text(&failure.service),
            terminal_text(&failure.address),
            failure.port,
            terminal_text(&failure.cause),
            terminal_text(&failure.detail)
        )?;
    }
    if !listeners.refusals.is_empty() {
        let counts: Vec<String> = listeners
            .refusals
            .iter()
            .map(|(cause, count)| format!("{} {count}", terminal_text(cause)))
            .collect();
        writeln!(
            writer,
            "             connections not carried since start: {}",
            counts.join(", ")
        )?;
    }
    Ok(())
}

fn write_effects(writer: &mut dyn Write, effects: &[ChangeEffect]) -> io::Result<()> {
    for effect in effects {
        writeln!(writer)?;
        writeln!(
            writer,
            "  {}  {}",
            terminal_text(&effect.action),
            terminal_text(&effect.pattern)
        )?;
        writeln!(
            writer,
            "    before  {}",
            mapping_effect(effect.before.as_ref())
        )?;
        writeln!(
            writer,
            "    after   {}",
            mapping_effect(effect.after.as_ref())
        )?;
    }
    Ok(())
}

fn mapping_effect(mapping: Option<&MappingView>) -> String {
    mapping.map_or_else(
        || "∅".to_owned(),
        |mapping| {
            format!(
                "{} → {} · {} · {} · {}{}",
                terminal_text(&mapping.pattern),
                terminal_text(&mapping.target),
                terminal_text(&mapping.target_kind),
                mapping.host_policy.as_str(),
                if mapping.enabled {
                    "active"
                } else {
                    "disabled"
                },
                mapping
                    .landing
                    .as_ref()
                    .map_or_else(String::new, |path| format!(
                        " · landing {}",
                        terminal_text(path)
                    )),
            ) + &mapping
                .peer_address
                .as_ref()
                .map_or_else(String::new, |address| {
                    format!(" · address {}", terminal_text(address))
                })
        },
    )
}

fn write_mapping(writer: &mut dyn Write, mapping: &MappingView) -> io::Result<()> {
    let state = if mapping.enabled {
        "active"
    } else {
        "disabled"
    };
    writeln!(
        writer,
        "  {}  →  {}  ({state})",
        terminal_text(&mapping.pattern),
        terminal_text(&mapping.target)
    )?;
    write_peer_machine(writer, &mapping.target, mapping.peer_address.as_deref())?;
    write_landing(writer, mapping.landing.as_deref())
}

/// Spells out a peer-machine target (ADR-0033): the address its name
/// answers, the peer that Supgang carries connections to, and each port.
/// An offline validation has no address yet, because the daemon allocates
/// it when the mapping is set.
fn write_peer_machine(
    writer: &mut dyn Write,
    target: &str,
    address: Option<&str>,
) -> io::Result<()> {
    let Ok(machine) = remap_core::PeerMachine::parse(target) else {
        return Ok(());
    };
    let shown = address.map_or("<address>", |address| address);
    writeln!(
        writer,
        "  Address    {}",
        address.map_or(
            Cow::Borrowed("allocated in 127.77.0.0/16 when set"),
            terminal_text
        )
    )?;
    writeln!(writer, "  Peer       {}", machine.selector())?;
    for service in machine.services() {
        writeln!(
            writer,
            "  Service    {} at {}:{} (TCP, through Supgang)",
            service.name(),
            terminal_text(shown),
            service.port()
        )?;
    }
    Ok(())
}

fn write_landing(writer: &mut dyn Write, landing: Option<&str>) -> io::Result<()> {
    if let Some(path) = landing {
        writeln!(writer, "  Landing    {}", terminal_text(path))?;
    }
    Ok(())
}

fn write_warnings(writer: &mut dyn Write, warnings: &[String]) -> io::Result<()> {
    for warning in warnings {
        writeln!(writer, "  Advisory   {}", terminal_text(warning))?;
    }
    Ok(())
}

fn terminal_text(value: &str) -> Cow<'_, str> {
    if !value.chars().any(terminal_unsafe) {
        return Cow::Borrowed(value);
    }
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        push_terminal_character(&mut escaped, character);
    }
    Cow::Owned(escaped)
}

fn push_terminal_character(output: &mut String, character: char) {
    match character {
        '\n' => output.push_str("\\n"),
        '\r' => output.push_str("\\r"),
        '\t' => output.push_str("\\t"),
        unsafe_character if terminal_unsafe(unsafe_character) => {
            let _result = write!(output, "\\u{{{:04X}}}", u32::from(unsafe_character));
        }
        safe => output.push(safe),
    }
}

const fn terminal_unsafe(character: char) -> bool {
    matches!(
        character,
        '\u{0000}'..='\u{001f}'
            | '\u{007f}'..='\u{009f}'
            | '\u{061c}'
            | '\u{200e}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
    )
}

fn report_json(report: &Report) -> Value {
    match report {
        Report::Document(report) => json!({
            "schema": SCHEMA,
            "ok": true,
            "command": report.command,
            "result": { "content": report.content },
        }),
        Report::Doctor(report) => json!({
            "schema": SCHEMA,
            "ok": true,
            "command": "doctor",
            "result": {
                "version": report.version,
                "platform": {
                    "os": report.operating_system,
                    "architecture": report.architecture,
                },
                "validator": "ready",
                "authority": report.authority,
                "revision": report.revision,
                "mapping_count": report.mapping_count,
                "mcp_versions": ["2026-07-28", "2025-11-25"],
                "native_install": report.native_install,
                "installed_package": report.installed_package.map(InstalledPackage::as_str),
                "dns_listener": report.health.dns,
                "dns_forwarding": report.health.forwarding,
                "http_gateway": report.health.http,
                "peer_machine_listeners": report.peer_machines,
                "system_lookup": {
                    "state": report.system_lookup.state(),
                    "name": report.system_lookup.name(),
                    "answer": report.system_lookup.answer().map(|answer| answer.to_string()),
                },
                "telemetry": "none",
            }
        }),
        Report::Validation(report) => json!({
            "schema": SCHEMA,
            "ok": true,
            "command": "validate",
            "result": {
                "name_pattern": report.pattern,
                "target": report.target,
                "target_kind": report.target_kind,
                "host_header_policy": report.host_header_policy,
                "landing": report.landing,
                "warnings": report.warnings,
                "system_state_changed": false,
            }
        }),
        Report::Authority { command, result } => json!({
            "schema": SCHEMA,
            "ok": true,
            "command": command,
            "result": result,
        }),
    }
}

fn write_json(writer: &mut dyn Write, value: &Value) -> io::Result<()> {
    serde_json::to_writer(&mut *writer, value).map_err(io::Error::other)?;
    writeln!(writer)
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use remap_protocol::{
        ChangeEffect, CommandResult, HostPolicy, MappingView, PreviewResult, RegistryStatus,
    };
    use serde_json::Value;

    use remap_mcp::system_lookup::SystemLookup;

    use super::{write_diagnostic, write_report};
    use crate::app::{DoctorReport, Report, ValidationReport};
    use crate::diagnostic::Diagnostic;
    use crate::installed_package::InstalledPackage;
    use crate::runtime_health::RuntimeHealth;

    fn doctor(installed_package: Option<InstalledPackage>) -> Report {
        Report::Doctor(DoctorReport {
            version: "0.2.0",
            operating_system: "macos",
            architecture: "aarch64",
            authority: "ready".to_owned(),
            revision: Some(3),
            mapping_count: Some(1),
            health: RuntimeHealth {
                dns: true,
                forwarding: true,
                http: true,
            },
            native_install: true,
            installed_package,
            system_lookup: SystemLookup::NotChecked,
        })
    }

    #[test]
    fn doctor_reports_a_rehearsal_install_as_one() -> Result<(), Box<dyn Error>> {
        let mut human = Vec::new();
        write_report(
            &mut human,
            &doctor(Some(InstalledPackage::Rehearsal)),
            false,
        )?;
        let text = String::from_utf8(human)?;
        assert!(text.contains("  Package    rehearsal install, not a release\n"));

        let mut machine = Vec::new();
        write_report(
            &mut machine,
            &doctor(Some(InstalledPackage::Rehearsal)),
            true,
        )?;
        let value: Value = serde_json::from_slice(&machine)?;
        assert_eq!(value["result"]["installed_package"], "rehearsal");

        let mut release = Vec::new();
        write_report(&mut release, &doctor(None), false)?;
        assert!(!String::from_utf8(release)?.contains("Package"));
        let mut release_json = Vec::new();
        write_report(&mut release_json, &doctor(None), true)?;
        let value: Value = serde_json::from_slice(&release_json)?;
        assert!(value["result"]["installed_package"].is_null());
        Ok(())
    }

    #[test]
    fn validation_json_has_stable_envelope() -> Result<(), Box<dyn Error>> {
        let report = Report::Validation(ValidationReport {
            warnings: Vec::new(),
            landing: None,
            pattern: "atlas".to_owned(),
            target: "http://127.0.0.1:5173/".to_owned(),
            target_kind: "http",
            host_header_policy: Some("preserve-client"),
        });
        let mut bytes = Vec::new();
        write_report(&mut bytes, &report, true)?;
        let value: Value = serde_json::from_slice(&bytes)?;
        assert_eq!(value["schema"], "remap.cli/v1");
        assert_eq!(value["ok"], true);
        assert_eq!(value["result"]["system_state_changed"], false);
        Ok(())
    }

    #[test]
    fn human_diagnostics_escape_terminal_controls_without_changing_json()
    -> Result<(), Box<dyn Error>> {
        let rejected = "bad\u{001b}[2J\u{202e}name";
        let diagnostic = Diagnostic::invalid_pattern(rejected.to_owned());
        let mut human = Vec::new();
        write_diagnostic(&mut human, &diagnostic, false)?;
        assert!(!human.contains(&0x1b));
        let displayed = String::from_utf8(human)?;
        assert!(displayed.contains("\\u{001B}[2J\\u{202E}name"));

        let mut machine = Vec::new();
        write_diagnostic(&mut machine, &diagnostic, true)?;
        let value: Value = serde_json::from_slice(&machine)?;
        assert_eq!(value["error"]["detail"], rejected);
        Ok(())
    }

    #[test]
    fn usage_diagnostics_preserve_layout_and_indent_without_terminal_controls()
    -> Result<(), Box<dyn Error>> {
        let diagnostic = Diagnostic::usage(
            "error: unknown command\r\n\nUsage:\tremap <COMMAND>\n  \u{001b}[31mbad",
        );
        let mut bytes = Vec::new();
        write_diagnostic(&mut bytes, &diagnostic, false)?;
        assert!(!bytes.contains(&0x1b));
        let displayed = String::from_utf8(bytes)?;
        assert!(displayed.contains("  error: unknown command\\r\n  \n"));
        assert!(displayed.contains("  Usage:\\tremap <COMMAND>\n"));
        assert!(displayed.contains("  \\u{001B}[31mbad\n"));
        assert!(!displayed.contains("\\n\\nUsage"));
        Ok(())
    }

    #[test]
    fn empty_diagnostic_detail_is_not_replaced_with_filler() -> Result<(), Box<dyn Error>> {
        let service = remap_protocol::Diagnostic::daemon_unavailable();
        let diagnostic = Diagnostic::service(service);
        let mut bytes = Vec::new();
        write_diagnostic(&mut bytes, &diagnostic, false)?;
        let displayed = String::from_utf8(bytes)?;
        assert!(!displayed.contains("No additional context"));
        assert_eq!(displayed.lines().count(), 2);
        Ok(())
    }

    #[test]
    fn human_preview_shows_the_exact_before_and_after_scope() -> Result<(), Box<dyn Error>> {
        let effect = ChangeEffect {
            pattern: "atlas".to_owned(),
            action: "update".to_owned(),
            before: Some(mapping("127.0.0.1:5173", HostPolicy::PreserveClient)),
            after: Some(mapping("127.0.0.1:6173", HostPolicy::UseUpstream)),
        };
        let report = Report::Authority {
            command: "preview",
            result: CommandResult::Preview(PreviewResult {
                warnings: Vec::new(),
                base_revision: 8,
                will_change: true,
                effects: vec![effect],
            }),
        };
        let mut bytes = Vec::new();
        write_report(&mut bytes, &report, false)?;
        let output = String::from_utf8(bytes)?;
        assert!(output.contains("update  atlas"));
        assert!(output.contains("127.0.0.1:5173 · socket · preserve-client · active"));
        assert!(output.contains("127.0.0.1:6173 · socket · use-upstream · active"));
        Ok(())
    }

    #[test]
    fn human_mapping_spells_out_a_peer_machine() -> Result<(), Box<dyn Error>> {
        let mut view = mapping("supgang://a8a37e32?ssh=22,k7=7443", HostPolicy::UseUpstream);
        view.target_kind = "peer-machine".to_owned();
        view.peer_address = Some("127.77.0.4".to_owned());
        let report = Report::Authority {
            command: "get",
            result: CommandResult::Mapping(Some(view.clone())),
        };
        let mut bytes = Vec::new();
        write_report(&mut bytes, &report, false)?;
        let output = String::from_utf8(bytes)?;
        assert!(output.contains("Address    127.77.0.4"), "{output}");
        assert!(output.contains("Peer       a8a37e32"), "{output}");
        assert!(output.contains("ssh at 127.77.0.4:22"), "{output}");
        assert!(output.contains("k7 at 127.77.0.4:7443"), "{output}");

        let mut bytes = Vec::new();
        write_report(&mut bytes, &report, true)?;
        let value: Value = serde_json::from_slice(&bytes)?;
        assert_eq!(value["result"]["value"]["peer_address"], "127.77.0.4");

        let effect = ChangeEffect {
            pattern: "atlas".to_owned(),
            action: "created".to_owned(),
            before: None,
            after: Some(view),
        };
        let preview = Report::Authority {
            command: "preview",
            result: CommandResult::Preview(PreviewResult {
                warnings: Vec::new(),
                base_revision: 1,
                will_change: true,
                effects: vec![effect],
            }),
        };
        let mut bytes = Vec::new();
        write_report(&mut bytes, &preview, false)?;
        assert!(String::from_utf8(bytes)?.contains("· address 127.77.0.4"));
        Ok(())
    }

    #[test]
    fn human_status_surfaces_blocked_retention_maintenance() -> Result<(), Box<dyn Error>> {
        let report = Report::Authority {
            command: "status",
            result: CommandResult::Status(RegistryStatus {
                revision: 8,
                mapping_count: 2,
                enabled_count: 1,
                schema_version: 1,
                daemon_version: "0.1.0".to_owned(),
                maintenance: Some(remap_protocol::Diagnostic::new(
                    "E_REGISTRY_CHECKPOINT",
                    "the private journal is awaiting retention maintenance",
                    Some("release the other registry reader".to_owned()),
                    true,
                )),
                peer_machine_listeners: None,
            }),
        };
        let mut bytes = Vec::new();
        write_report(&mut bytes, &report, false)?;
        let output = String::from_utf8(bytes)?;
        assert!(output.contains("Mutations  blocked by maintenance"));
        assert!(output.contains("private journal is awaiting retention maintenance"));
        assert!(output.contains("release the other registry reader"));
        Ok(())
    }

    #[test]
    fn human_status_names_each_peer_machine_listener_that_cannot_bind() -> Result<(), Box<dyn Error>>
    {
        let report = Report::Authority {
            command: "status",
            result: CommandResult::Status(RegistryStatus {
                revision: 8,
                mapping_count: 2,
                enabled_count: 2,
                schema_version: 4,
                daemon_version: "0.2.0".to_owned(),
                maintenance: None,
                peer_machine_listeners: Some(remap_protocol::PeerMachineListeners {
                    listening: 1,
                    not_listening: 1,
                    failures: vec![remap_protocol::PeerMachineListenerFailure {
                        pattern: "pro.test".to_owned(),
                        service: "ssh".to_owned(),
                        address: "127.77.0.1".to_owned(),
                        port: 22,
                        cause: "address-not-reserved".to_owned(),
                        detail: "this address is not reserved on this machine yet".to_owned(),
                    }],
                    refusals: [("refused".to_owned(), 3), ("unknown-peer".to_owned(), 1)]
                        .into_iter()
                        .collect(),
                }),
            }),
        };
        let mut bytes = Vec::new();
        write_report(&mut bytes, &report, false)?;
        let output = String::from_utf8(bytes)?;
        assert!(
            output.contains("Peers      1 listening, 1 not listening"),
            "{output}"
        );
        assert!(
            output.contains("pro.test ssh at 127.77.0.1:22 not listening: address-not-reserved"),
            "{output}"
        );
        assert!(
            output.contains("connections not carried since start: refused 3, unknown-peer 1"),
            "{output}"
        );
        Ok(())
    }

    #[test]
    fn human_status_confirms_mutation_readiness() -> Result<(), Box<dyn Error>> {
        let report = Report::Authority {
            command: "status",
            result: CommandResult::Status(RegistryStatus {
                revision: 8,
                mapping_count: 2,
                enabled_count: 1,
                schema_version: 1,
                daemon_version: "0.1.1".to_owned(),
                maintenance: None,
                peer_machine_listeners: None,
            }),
        };
        let mut bytes = Vec::new();
        write_report(&mut bytes, &report, false)?;
        let output = String::from_utf8(bytes)?;
        assert!(output.contains("Mutations  ready"));
        assert!(!output.contains("blocked"));
        Ok(())
    }

    fn mapping(target: &str, host_policy: HostPolicy) -> MappingView {
        MappingView {
            landing: None,
            pattern: "atlas".to_owned(),
            target: target.to_owned(),
            target_kind: "socket".to_owned(),
            host_policy,
            enabled: true,
            updated_revision: 8,
            peer_address: None,
        }
    }
}
