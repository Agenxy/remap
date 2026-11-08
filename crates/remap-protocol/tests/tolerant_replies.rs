// SPDX-License-Identifier: GPL-3.0-or-later
//! A reply from a newer daemon decodes in an older client, and a request
//! with a field the daemon does not know is still refused.

use remap_protocol::{CommandResult, ControlRequest, ControlResponse};

#[test]
fn a_reply_with_unknown_fields_at_every_level_decodes() -> Result<(), Box<dyn std::error::Error>> {
    let reply = serde_json::json!({
        "protocol": "remap.control/v1",
        "request_id": "probe-1",
        "added_by_a_newer_daemon": true,
        "result": {"kind": "list", "value": {
            "revision": 3,
            "next_cursor": null,
            "page_hint": 1,
            "mappings": [{
                "pattern": "pro.test",
                "target": "supgang://a8a37e32?ssh=22",
                "target_kind": "peer-machine",
                "host_policy": "use-upstream",
                "enabled": true,
                "updated_revision": 3,
                "peer_address": "127.77.0.1",
                "peer_name": "a field from the future"
            }]
        }}
    });
    let response: ControlResponse = serde_json::from_value(reply)?;
    let Some(CommandResult::List(list)) = response.result else {
        return Err("the reply was not a list".into());
    };
    assert_eq!(list.mappings[0].peer_address.as_deref(), Some("127.77.0.1"));

    let status = serde_json::json!({
        "protocol": "remap.control/v1",
        "request_id": "probe-2",
        "result": {"kind": "status", "value": {
            "revision": 3, "mapping_count": 1, "enabled_count": 1,
            "schema_version": 9, "daemon_version": "9.0.0", "new_counter": 4,
            "peer_machine_listeners": {"listening": 0, "not_listening": 1, "held_by": "root",
                "failures": [{"pattern": "pro.test", "service": "ssh", "address": "127.77.0.1",
                    "port": 22, "cause": "awaiting-socket", "detail": "d", "since": 1}]}
        }},
    });
    let response: ControlResponse = serde_json::from_value(status)?;
    assert!(matches!(response.result, Some(CommandResult::Status(_))));

    let error = serde_json::json!({
        "protocol": "remap.control/v1",
        "request_id": "probe-3",
        "error": {"code": "E_X", "message": "m", "hint": null, "retryable": false,
            "context": {}, "documentation": "a field from the future"}
    });
    let response: ControlResponse = serde_json::from_value(error)?;
    assert_eq!(
        response.error.map(|error| error.code).as_deref(),
        Some("E_X")
    );
    Ok(())
}

#[test]
fn a_request_with_an_unknown_field_is_refused() {
    let request = serde_json::json!({
        "protocol": "remap.control/v1",
        "request_id": "probe-4",
        "surface": "probe",
        "client_version": "0.2.0",
        "command": {"kind": "status"},
        "act_on_this_too": true
    });
    assert!(serde_json::from_value::<ControlRequest>(request).is_err());
    let command = serde_json::json!({
        "protocol": "remap.control/v1",
        "request_id": "probe-5",
        "surface": "probe",
        "client_version": "0.2.0",
        "command": {"kind": "get", "pattern": "pro.test", "force": true}
    });
    assert!(serde_json::from_value::<ControlRequest>(command).is_err());
}
