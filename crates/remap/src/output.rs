use std::io::{self, Write};

use serde_json::{Value, json};

use crate::app::{DoctorReport, Report, ValidationReport};
use crate::diagnostic::Diagnostic;

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
                }
            }),
        );
    }
    writeln!(
        writer,
        "error[{}]: {}",
        diagnostic.code(),
        diagnostic.message()
    )?;
    writeln!(writer, "  {}", diagnostic.detail())?;
    writeln!(writer, "  help: {}", diagnostic.hint())
}

fn write_human_report(writer: &mut dyn Write, report: &Report) -> io::Result<()> {
    match report {
        Report::Doctor(report) => write_doctor(writer, report),
        Report::Validation(report) => write_validation(writer, report),
    }
}

fn write_doctor(writer: &mut dyn Write, report: &DoctorReport) -> io::Result<()> {
    writeln!(writer, "Remap {} — local diagnostics", report.version)?;
    writeln!(writer)?;
    writeln!(
        writer,
        "  Platform   {}/{}",
        report.operating_system, report.architecture
    )?;
    writeln!(writer, "  Validator  ready")?;
    writeln!(writer, "  Daemon     not included in this milestone")?;
    writeln!(writer, "  DNS        unchanged")?;
    writeln!(writer, "  Telemetry  none")?;
    writeln!(writer)?;
    writeln!(writer, "Nothing is installed or modified by this build.")?;
    writeln!(writer, "Try: remap validate atlas http://127.0.0.1:5173")
}

fn write_validation(writer: &mut dyn Write, report: &ValidationReport) -> io::Result<()> {
    writeln!(writer, "Valid mapping")?;
    writeln!(writer)?;
    writeln!(writer, "  Name       {}", report.pattern)?;
    writeln!(writer, "  Target     {}", report.target)?;
    writeln!(writer, "  Type       {}", report.target_kind)?;
    if let Some(policy) = report.host_header_policy {
        writeln!(writer, "  Host       {policy}")?;
    }
    writeln!(writer)?;
    writeln!(writer, "No system state changed.")
}

fn report_json(report: &Report) -> Value {
    match report {
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
                "daemon": "not-available-in-this-build",
                "dns": "unchanged",
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
                "system_state_changed": false,
            }
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

    use serde_json::Value;

    use super::write_report;
    use crate::app::{Report, ValidationReport};

    #[test]
    fn validation_json_has_stable_envelope() -> Result<(), Box<dyn Error>> {
        let report = Report::Validation(ValidationReport {
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
}
