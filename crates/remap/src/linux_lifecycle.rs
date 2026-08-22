use std::collections::BTreeSet;
use std::io::{self, IsTerminal, Read, Write};
use std::process::{Command as ProcessCommand, Stdio};

use serde_json::{Map, Value};

use crate::cli::SystemLifecycleCommand;
use crate::diagnostic::Diagnostic;

const SUDO: &str = "/usr/bin/sudo";
const NATIVE_HELPER: &str = "/usr/libexec/remap/current/remap-linux-system";
const MAXIMUM_RESPONSE_BYTES: usize = 64 * 1024;
const MAXIMUM_APPROVAL_BYTES: u64 = 97;
const APPROVAL_PREFIX_BYTES: usize = 12;

pub(crate) fn run(command: SystemLifecycleCommand, json: bool) -> Result<u8, Diagnostic> {
    match command {
        SystemLifecycleCommand::Status => status(json),
        SystemLifecycleCommand::Recover => mutate(command, json, true),
        SystemLifecycleCommand::Uninstall => mutate(command, json, false),
    }
}

fn status(json: bool) -> Result<u8, Diagnostic> {
    let response = invoke(&["status", "--json"])?;
    let document = decode_envelope(&response.stdout, "status")?;
    if !response.success {
        return emit_failure(&document, json, response.code);
    }
    emit_success(&document, "Linux native status", json)?;
    Ok(0)
}

fn mutate(command: SystemLifecycleCommand, json: bool, recovery: bool) -> Result<u8, Diagnostic> {
    let operation = command.as_str();
    let preview_arguments: &[&str] = if recovery {
        &["preview", "recover", "--all", "--json"]
    } else {
        &["preview", "uninstall", "--json"]
    };
    let expected_preview = if recovery {
        "preview-recovery"
    } else {
        "preview"
    };
    let preview = invoke(preview_arguments)?;
    let document = decode_envelope(&preview.stdout, expected_preview)?;
    if !preview.success {
        return emit_failure(&document, json, preview.code);
    }
    let approval = validated_preview(&document, expected_preview)?;
    emit_success(&document, &format!("Linux {operation} preview"), json)?;
    if !approval.has_effects {
        return Ok(0);
    }
    confirm_approval(&approval.token, operation)?;
    let commit_arguments = if recovery {
        vec![
            "recover",
            "--all",
            "--approval-token",
            approval.token.as_str(),
            "--json",
        ]
    } else {
        vec![
            "uninstall",
            "--approval-token",
            approval.token.as_str(),
            "--json",
        ]
    };
    let committed = invoke(&commit_arguments)?;
    let committed_document = decode_envelope(&committed.stdout, operation)?;
    if !committed.success {
        return emit_failure(&committed_document, json, committed.code);
    }
    emit_success(
        &committed_document,
        &format!("Linux {operation} complete"),
        json,
    )?;
    Ok(0)
}

struct HelperResponse {
    code: u8,
    stdout: Vec<u8>,
    success: bool,
}

fn invoke(arguments: &[&str]) -> Result<HelperResponse, Diagnostic> {
    let mut child = ProcessCommand::new(SUDO)
        .arg("--")
        .arg(NATIVE_HELPER)
        .args(arguments)
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| lifecycle_error("start the installed Linux helper", error))?;
    let mut stdout = child.stdout.take().ok_or_else(|| {
        Diagnostic::native_lifecycle("the installed Linux helper has no response channel")
    })?;
    let mut response = Vec::new();
    stdout
        .by_ref()
        .take((MAXIMUM_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut response)
        .map_err(|error| lifecycle_error("read the installed Linux helper", error))?;
    if response.len() > MAXIMUM_RESPONSE_BYTES {
        let _killed = child.kill();
        let _status = child.wait();
        return Err(Diagnostic::native_lifecycle(
            "the installed Linux helper exceeded its 64 KiB response bound",
        ));
    }
    let status = child
        .wait()
        .map_err(|error| lifecycle_error("wait for the installed Linux helper", error))?;
    let code = status
        .code()
        .and_then(|value| u8::try_from(value).ok())
        .unwrap_or(70);
    Ok(HelperResponse {
        code,
        stdout: response,
        success: status.success(),
    })
}

fn decode_envelope(bytes: &[u8], expected_command: &str) -> Result<Value, Diagnostic> {
    let document: Value = serde_json::from_slice(bytes).map_err(|_error| {
        Diagnostic::native_lifecycle("the installed Linux helper returned malformed JSON")
    })?;
    let values = document.as_object().ok_or_else(invalid_response)?;
    require_keys(
        values,
        &["schemaVersion", "ok", "command", envelope_payload(values)],
    )?;
    if values.get("schemaVersion") != Some(&Value::from(1))
        || values.get("command").and_then(Value::as_str) != Some(expected_command)
        || values.get("ok").and_then(Value::as_bool).is_none()
    {
        return Err(invalid_response());
    }
    Ok(document)
}

fn envelope_payload(values: &Map<String, Value>) -> &'static str {
    if values.get("ok").and_then(Value::as_bool) == Some(true) {
        "data"
    } else {
        "error"
    }
}

fn require_keys(values: &Map<String, Value>, expected: &[&str]) -> Result<(), Diagnostic> {
    let observed = values.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if observed == expected {
        Ok(())
    } else {
        Err(invalid_response())
    }
}

struct Approval {
    token: String,
    has_effects: bool,
}

fn validated_preview(document: &Value, command: &str) -> Result<Approval, Diagnostic> {
    let data = document
        .get("data")
        .and_then(Value::as_object)
        .ok_or_else(invalid_response)?;
    let token = data
        .get("approvalToken")
        .and_then(Value::as_str)
        .filter(|value| valid_token(value))
        .ok_or_else(invalid_response)?;
    let has_effects = data
        .get("hasEffects")
        .and_then(Value::as_bool)
        .ok_or_else(invalid_response)?;
    let effects = data
        .get("effects")
        .and_then(Value::as_array)
        .ok_or_else(invalid_response)?;
    if effects.len() > 128
        || effects
            .iter()
            .any(|effect| effect.as_str().is_none_or(|value| !safe_text(value, 512)))
        || command == "preview-recovery" && has_effects != !effects.is_empty()
    {
        return Err(invalid_response());
    }
    Ok(Approval {
        token: token.to_owned(),
        has_effects,
    })
}

fn confirm_approval(token: &str, operation: &str) -> Result<(), Diagnostic> {
    let interactive = io::stdin().is_terminal();
    let expected = if interactive {
        format!("approve {}", &token[..APPROVAL_PREFIX_BYTES])
    } else {
        token.to_owned()
    };
    let prompt = if interactive {
        format!("Type '{expected}' to approve this exact {operation} preview: ")
    } else {
        "Non-interactive approval requires the full 64-character token on standard input: "
            .to_owned()
    };
    let mut stderr = io::stderr().lock();
    stderr
        .write_all(prompt.as_bytes())
        .and_then(|()| stderr.flush())
        .map_err(|error| lifecycle_error("write the lifecycle approval prompt", error))?;
    let mut response = String::new();
    io::stdin()
        .lock()
        .take(MAXIMUM_APPROVAL_BYTES)
        .read_to_string(&mut response)
        .map_err(|error| lifecycle_error("read lifecycle approval", error))?;
    if response.trim_end_matches(['\r', '\n']) != expected {
        return Err(Diagnostic::native_lifecycle(format!(
            "approval was not confirmed; rerun 'remap system {operation}' for a fresh preview"
        )));
    }
    writeln!(
        stderr,
        "Approval confirmed. Applying only the reviewed state."
    )
    .map_err(|error| lifecycle_error("write the lifecycle approval result", error))?;
    Ok(())
}

fn emit_success(document: &Value, heading: &str, json: bool) -> Result<(), Diagnostic> {
    if json {
        return write_json(io::stdout().lock(), document);
    }
    let data = document.get("data").ok_or_else(invalid_response)?;
    let rendered = serde_json::to_string_pretty(data).map_err(|_error| invalid_response())?;
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{heading}\n{rendered}")
        .map_err(|error| lifecycle_error("write the Linux lifecycle response", error))
}

fn emit_failure(document: &Value, json: bool, code: u8) -> Result<u8, Diagnostic> {
    if json {
        write_json(io::stdout().lock(), document)?;
    } else {
        let error = document.get("error").ok_or_else(invalid_response)?;
        let rendered = serde_json::to_string_pretty(error).map_err(|_error| invalid_response())?;
        writeln!(io::stderr().lock(), "Linux lifecycle failed\n{rendered}").map_err(
            |write_error| lifecycle_error("write the Linux lifecycle failure", write_error),
        )?;
    }
    Ok(code)
}

fn write_json(mut output: impl Write, document: &Value) -> Result<(), Diagnostic> {
    serde_json::to_writer(&mut output, document).map_err(|_error| invalid_response())?;
    writeln!(output).map_err(|error| lifecycle_error("write the Linux lifecycle JSON", error))
}

fn valid_token(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || b'a' <= byte && byte <= b'f')
}

fn safe_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.chars().all(|character| !character.is_control())
}

fn invalid_response() -> Diagnostic {
    Diagnostic::native_lifecycle(
        "the installed Linux helper returned an invalid lifecycle envelope",
    )
}

fn lifecycle_error(operation: &str, error: io::Error) -> Diagnostic {
    Diagnostic::native_lifecycle(format!("could not {operation}: {error}"))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{decode_envelope, valid_token, validated_preview};

    #[test]
    fn preview_requires_a_bounded_state_bound_token_and_safe_effects() {
        let token = "a".repeat(64);
        let document = json!({
            "schemaVersion": 1,
            "ok": true,
            "command": "preview-recovery",
            "data": {
                "approvalToken": token,
                "hasEffects": true,
                "effects": ["restore exact resolver state"]
            }
        });
        let encoded = serde_json::to_vec(&document).unwrap_or_default();
        let decoded = decode_envelope(&encoded, "preview-recovery");
        assert!(decoded.is_ok());
        assert!(validated_preview(&document, "preview-recovery").is_ok());
        assert!(valid_token(&"f".repeat(64)));
        assert!(!valid_token(&"F".repeat(64)));
    }

    #[test]
    fn lifecycle_envelope_rejects_extra_or_mismatched_fields() {
        let extra = br#"{"schemaVersion":1,"ok":true,"command":"status","data":{},"extra":true}"#;
        assert!(decode_envelope(extra, "status").is_err());
        let mismatch = br#"{"schemaVersion":1,"ok":true,"command":"recover","data":{}}"#;
        assert!(decode_envelope(mismatch, "status").is_err());
    }
}
