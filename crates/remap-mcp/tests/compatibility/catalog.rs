use std::error::Error;
use std::io;

use serde_json::{Value, json};

pub(super) fn assert_modern_tool_catalog(
    tools: &rmcp::model::ListToolsResult,
) -> Result<(), Box<dyn Error>> {
    assert_eq!(tools.tools.len(), 11);
    assert_eq!(tools.ttl_ms, Some(3_600_000));
    assert_eq!(tools.cache_scope, Some(rmcp::model::CacheScope::Private));
    let names: Vec<&str> = tools.tools.iter().map(|tool| tool.name.as_ref()).collect();
    assert_eq!(names, expected_names());
    for tool in &tools.tools {
        assert!(
            tool.description
                .as_ref()
                .is_some_and(|text| !text.is_empty())
        );
        assert!(tool.output_schema.is_some());
        assert!(tool.annotations.is_some());
        assert!(ui_property(tool, "resourceUri").is_some());
        assert_tool_contract(tool)?;
    }
    assert_schema_bounds(tools)?;
    let status = tool_by_name(tools, "remap_status")?;
    assert!(
        ui_property(status, "resourceUri")
            .and_then(Value::as_str)
            .is_some_and(|uri| uri.starts_with("ui://remap/dashboard/"))
    );
    Ok(())
}

fn expected_names() -> [&'static str; 11] {
    [
        "remap_apply",
        "remap_disable",
        "remap_enable",
        "remap_get",
        "remap_list",
        "remap_preview",
        "remap_remove",
        "remap_resolve",
        "remap_set",
        "remap_status",
        "remap_validate",
    ]
}

fn assert_tool_contract(tool: &rmcp::model::Tool) -> Result<(), Box<dyn Error>> {
    let read_only = matches!(
        tool.name.as_ref(),
        "remap_get"
            | "remap_list"
            | "remap_preview"
            | "remap_resolve"
            | "remap_status"
            | "remap_validate"
    );
    let annotations = tool
        .annotations
        .as_ref()
        .ok_or_else(|| io::Error::other("tool had no safety annotations"))?;
    assert_eq!(annotations.read_only_hint, Some(read_only));
    assert_eq!(annotations.destructive_hint, Some(!read_only));
    assert_eq!(annotations.idempotent_hint, Some(true));
    assert_eq!(annotations.open_world_hint, Some(false));
    let expected_visibility = if matches!(tool.name.as_ref(), "remap_status" | "remap_list") {
        json!(["model", "app"])
    } else {
        json!(["model"])
    };
    assert_eq!(ui_property(tool, "visibility"), Some(&expected_visibility));
    assert_output_schema_contract(tool)?;
    Ok(())
}

fn assert_output_schema_contract(tool: &rmcp::model::Tool) -> Result<(), Box<dyn Error>> {
    let schema = Value::Object(
        tool.output_schema
            .as_ref()
            .ok_or_else(|| io::Error::other("tool had no output schema"))?
            .as_ref()
            .clone(),
    );
    assert_eq!(schema["type"], "object");
    let validator = jsonschema::validator_for(&schema)
        .map_err(|error| io::Error::other(format!("invalid {} schema: {error}", tool.name)))?;
    for instance in [sample_success(tool.name.as_ref()), sample_failure()] {
        validator.validate(&instance).map_err(|error| {
            io::Error::other(format!("{} output violates its schema: {error}", tool.name))
        })?;
    }
    if tool.name == "remap_get" {
        validator
            .validate(&json!({"summary": "No exact mapping.", "data": null}))
            .map_err(|error| {
                io::Error::other(format!("nullable lookup violated schema: {error}"))
            })?;
    }
    assert!(
        validator
            .validate(&json!({"summary": "Incomplete result."}))
            .is_err(),
        "{} output schema accepted an incomplete envelope",
        tool.name
    );
    if tool.name == "remap_status" {
        let mut invalid = sample_success(tool.name.as_ref());
        invalid["data"]["maintenance"]
            .as_object_mut()
            .ok_or_else(|| io::Error::other("status maintenance fixture was not an object"))?
            .remove("retryable");
        assert!(
            validator.validate(&invalid).is_err(),
            "status output schema accepted an incomplete maintenance diagnostic"
        );
    }
    Ok(())
}

fn sample_success(name: &str) -> Value {
    let mapping = json!({
        "pattern": "atlas",
        "target": "127.0.0.1",
        "target_kind": "ip",
        "host_policy": "preserve-client",
        "enabled": true,
        "updated_revision": 1
    });
    let data = match name {
        "remap_status" => json!({
            "revision": 1,
            "mapping_count": 1,
            "enabled_count": 1,
            "schema_version": 1,
            "daemon_version": "0.1.0",
            "maintenance": {
                "code": "E_REGISTRY_CHECKPOINT",
                "message": "retention checkpoint blocked",
                "hint": "release the other registry reader",
                "retryable": true
            }
        }),
        "remap_list" => json!({"revision": 1, "mappings": [mapping], "next_cursor": null}),
        "remap_get" => mapping,
        "remap_resolve" => json!({"name": "atlas", "revision": 1, "mapping": mapping}),
        "remap_validate" => json!({
            "pattern": "atlas",
            "target": "127.0.0.1",
            "target_kind": "ip",
            "host_policy": "preserve-client"
        }),
        "remap_preview" => json!({"base_revision": 1, "will_change": false, "effects": []}),
        _ => json!({
            "operation_id": "c77549cc-6f95-4dce-b74d-05cfd7f76c92",
            "previous_revision": 1,
            "revision": 1,
            "changed": false,
            "effects": []
        }),
    };
    json!({"summary": "Representative result.", "data": data})
}

fn sample_failure() -> Value {
    json!({
        "code": "E_EXAMPLE",
        "message": "Representative diagnostic.",
        "hint": "Correct the request, then retry.",
        "retryable": false,
        "context": {"field": "safe-value"}
    })
}

fn assert_schema_bounds(tools: &rmcp::model::ListToolsResult) -> Result<(), Box<dyn Error>> {
    let list = tool_by_name(tools, "remap_list")?;
    assert_eq!(schema_property(list, "limit")?["minimum"], 1);
    assert_eq!(schema_property(list, "limit")?["maximum"], 64);
    assert_eq!(schema_property(list, "after")?["maxLength"], 255);
    let status = tool_by_name(tools, "remap_status")?;
    assert_eq!(status.schema_as_json_value()["additionalProperties"], false);
    for name in ["remap_preview", "remap_apply"] {
        let changes = schema_property(tool_by_name(tools, name)?, "changes")?;
        assert_eq!(changes["minItems"], 1);
        assert_eq!(changes["maxItems"], 32);
    }
    let set = tool_by_name(tools, "remap_set")?;
    assert_eq!(schema_property(set, "pattern")?["maxLength"], 255);
    assert_eq!(schema_property(set, "target")?["maxLength"], 4_096);
    let operation_id = schema_property(set, "operation_id")?;
    assert_eq!(operation_id["minLength"], 36);
    assert_eq!(operation_id["maxLength"], 36);
    assert!(
        operation_id["pattern"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );
    assert_eq!(
        schema_property(tool_by_name(tools, "remap_resolve")?, "name")?["maxLength"],
        253
    );
    Ok(())
}

fn tool_by_name<'a>(
    tools: &'a rmcp::model::ListToolsResult,
    name: &str,
) -> Result<&'a rmcp::model::Tool, io::Error> {
    tools
        .tools
        .iter()
        .find(|tool| tool.name == name)
        .ok_or_else(|| io::Error::other(format!("{name} was not listed")))
}

fn schema_property<'a>(
    tool: &'a rmcp::model::Tool,
    property: &str,
) -> Result<&'a Value, io::Error> {
    tool.input_schema
        .get("properties")
        .and_then(Value::as_object)
        .and_then(|properties| properties.get(property))
        .ok_or_else(|| io::Error::other(format!("{} schema omitted {property}", tool.name)))
}

fn ui_property<'a>(tool: &'a rmcp::model::Tool, property: &str) -> Option<&'a Value> {
    tool.meta
        .as_ref()
        .and_then(|meta| meta.0.get("ui"))
        .and_then(|ui| ui.get(property))
}
