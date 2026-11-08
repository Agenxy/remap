// SPDX-License-Identifier: GPL-3.0-or-later
use std::error::Error;

use remap_protocol::{
    ChangeEffect, CommandResult, HostPolicy, MappingView, PreviewResult, RegistryStatus,
};
use serde_json::Value;

use remap_mcp::system_lookup::SystemLookup;

use super::{lookup_line, write_diagnostic, write_report};
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
        dns_upstream: None,
        dns_turned_off: None,
        peer_machines: None,
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
fn human_diagnostics_escape_terminal_controls_without_changing_json() -> Result<(), Box<dyn Error>>
{
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
    let diagnostic =
        Diagnostic::usage("error: unknown command\r\n\nUsage:\tremap <COMMAND>\n  \u{001b}[31mbad");
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
            dns_upstream: None,
            dns_turned_off: None,
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
fn human_status_names_each_peer_machine_listener_that_cannot_bind() -> Result<(), Box<dyn Error>> {
    let report = Report::Authority {
        command: "status",
        result: CommandResult::Status(RegistryStatus {
            revision: 8,
            mapping_count: 2,
            enabled_count: 2,
            schema_version: 4,
            daemon_version: "0.2.0".to_owned(),
            maintenance: None,
            dns_upstream: None,
            dns_turned_off: None,
            peer_machine_listeners: Some(Box::new(remap_protocol::PeerMachineListeners {
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
            })),
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
            dns_upstream: None,
            dns_turned_off: None,
            peer_machine_listeners: None,
        }),
    };
    let mut bytes = Vec::new();
    write_report(&mut bytes, &report, false)?;
    let output = String::from_utf8(bytes)?;
    assert!(output.contains("Mutations  ready"));
    assert!(!output.contains("blocked"));
    assert!(!output.contains("Upstream"));
    Ok(())
}

#[test]
fn human_status_says_dns_was_turned_off_on_purpose_and_how_to_undo_it() -> Result<(), Box<dyn Error>>
{
    let report = Report::Authority {
        command: "status",
        result: CommandResult::Status(RegistryStatus {
            revision: 8,
            mapping_count: 2,
            enabled_count: 1,
            schema_version: 1,
            daemon_version: "0.2.0".to_owned(),
            maintenance: None,
            dns_upstream: None,
            dns_turned_off: Some(Box::new(turned_off())),
            peer_machine_listeners: None,
        }),
    };
    let mut bytes = Vec::new();
    write_report(&mut bytes, &report, false)?;
    let output = String::from_utf8(bytes)?;
    assert!(output.contains(
        "DNS        turned off by the owner at 2026-10-31T01:20Z (`remap-system deactivate`)"
    ));
    assert!(output.contains("Turn on    sudo '/Library/"));
    Ok(())
}

#[test]
fn doctor_lookup_says_dns_is_off_on_purpose_instead_of_unresolved() {
    let unresolved = SystemLookup::Unresolved {
        name: "atlas.test".to_owned(),
    };
    assert!(lookup_line(&unresolved, None).starts_with("unresolved"));
    assert_eq!(
        lookup_line(&unresolved, Some(&turned_off())),
        "off (turned off by the owner at 2026-10-31T01:20Z (`remap-system deactivate`); \
         atlas.test uses ordinary DNS)"
    );
}

fn turned_off() -> remap_protocol::DnsTurnedOff {
    remap_protocol::DnsTurnedOff {
        turned_off_at: "2026-10-31T01:20Z".to_owned(),
        turned_off_at_ms: 1_793_409_600_000,
        command: "remap-system deactivate".to_owned(),
        turn_on:
            "sudo '/Library/Application Support/Agenxy/Remap/Install/current/libexec/remap-system' \
                  activate --owner-uid 501 --product-version 0.2.0 \
                  --system-socket /var/run/org.agenxy.Remap.system.sock"
                .to_owned(),
    }
}

#[test]
fn human_status_says_upstream_dns_is_not_answering_and_why() -> Result<(), Box<dyn Error>> {
    let failure = remap_protocol::UpstreamFailure {
        cause: remap_protocol::UpstreamFailureCause::TimedOut,
        unanswered_queries: 12,
        unanswered_for_ms: 9_000,
    };
    let report = Report::Authority {
        command: "status",
        result: CommandResult::Status(RegistryStatus {
            revision: 8,
            mapping_count: 2,
            enabled_count: 1,
            schema_version: 1,
            daemon_version: "0.2.0".to_owned(),
            maintenance: None,
            dns_upstream: Some(failure.diagnostic()),
            dns_turned_off: None,
            peer_machine_listeners: None,
        }),
    };
    let mut bytes = Vec::new();
    write_report(&mut bytes, &report, false)?;
    let output = String::from_utf8(bytes)?;
    assert!(output.contains("Upstream   DNS not answering"));
    assert!(output.contains(
        "Cause      every upstream resolver timed out for the last 12 queries over 9 seconds"
    ));
    assert!(output.contains("VPN"));
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
