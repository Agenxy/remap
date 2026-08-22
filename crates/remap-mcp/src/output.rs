use std::borrow::Cow;

use remap_protocol::Diagnostic;
use rmcp::ErrorData;
use rmcp::handler::server::tool::IntoCallToolResult;
use rmcp::model::{CallToolResponse, CallToolResult, ContentBlock};
use schemars::JsonSchema;
use serde::Serialize;
use serde_json::{Map, Value};

const MAX_TOOL_RESULT_BYTES: usize = crate::transport::MAX_MCP_MESSAGE_BYTES - 16 * 1024;

/// Stable structured envelope returned by every successful Remap tool.
#[derive(Debug, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ToolOutput<T> {
    /// Concise human-readable outcome suitable for a transcript.
    pub summary: String,
    /// Typed machine-readable result.
    pub data: T,
}

/// Successful tool result with concise transcript text and typed structured content.
pub(crate) struct ToolSuccess<T>(ToolOutput<T>);

impl<T: JsonSchema> JsonSchema for ToolSuccess<T> {
    fn schema_name() -> Cow<'static, str> {
        ToolOutput::<T>::schema_name()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        let mut success = generator.subschema_for::<ToolOutput<T>>();
        success.insert(
            "required".to_owned(),
            serde_json::json!(["summary", "data"]),
        );
        schemars::json_schema!({
            "type": "object",
            "oneOf": [
                success,
                generator.subschema_for::<Diagnostic>()
            ]
        })
    }
}

impl<T: Serialize + JsonSchema + 'static> IntoCallToolResult for ToolSuccess<T> {
    fn into_call_tool_result(self) -> Result<CallToolResponse, ErrorData> {
        let summary = self.0.summary.clone();
        let value = serde_json::to_value(self.0).map_err(|error| {
            ErrorData::internal_error(
                format!("could not encode structured Remap result: {error}"),
                None,
            )
        })?;
        let detail = serde_json::to_string(&value["data"]).map_err(|error| {
            ErrorData::internal_error(
                format!("could not encode human-readable Remap result: {error}"),
                None,
            )
        })?;
        let transcript = format!("{summary}\n\n{detail}");
        let mut result = CallToolResult::success(vec![ContentBlock::text(transcript)]);
        result.structured_content = Some(value);
        if serde_json::to_vec(&result).is_ok_and(|encoded| encoded.len() > MAX_TOOL_RESULT_BYTES) {
            return Ok(failure(Diagnostic::new(
                "E_MCP_RESULT_LIMIT",
                "the complete tool result exceeded Remap's bounded MCP response budget",
                Some(
                    "request a smaller mapping page or split the change batch, then retry"
                        .to_owned(),
                ),
                false,
            ))
            .into());
        }
        Ok(result.into())
    }
}

/// Wraps one successful daemon result for both people and agents.
pub(crate) fn success<T>(summary: impl Into<String>, data: T) -> ToolSuccess<T> {
    ToolSuccess(ToolOutput {
        summary: summary.into(),
        data,
    })
}

/// Converts a stable daemon diagnostic into an MCP tool-level failure.
pub(crate) fn failure(diagnostic: Diagnostic) -> CallToolResult {
    let summary = diagnostic.to_string();
    let value = serde_json::to_value(diagnostic).unwrap_or_else(|error| {
        let mut object = Map::new();
        object.insert("code".to_owned(), Value::String("E_INTERNAL".to_owned()));
        object.insert(
            "message".to_owned(),
            Value::String(format!("could not encode diagnostic: {error}")),
        );
        object.insert("retryable".to_owned(), Value::Bool(false));
        Value::Object(object)
    });
    let detail = serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string());
    let mut result =
        CallToolResult::error(vec![ContentBlock::text(format!("{summary}\n\n{detail}"))]);
    result.structured_content = Some(value);
    result
}

/// Reports an impossible result variant without exposing internal state.
pub(crate) fn unexpected_result(expected: &str) -> CallToolResult {
    failure(Diagnostic::new(
        "E_INTERNAL",
        format!("the daemon returned a result other than {expected}"),
        Some("update the Remap client and daemon together, then retry".to_owned()),
        false,
    ))
}

#[cfg(test)]
mod tests {
    use remap_protocol::{
        ApplyResult, ChangeEffect, HostPolicy, ListResult, MAX_TARGET_BYTES, MappingView,
    };
    use rmcp::handler::server::tool::IntoCallToolResult;

    use super::{MAX_TOOL_RESULT_BYTES, success};

    #[test]
    fn maximum_mcp_pages_and_receipts_fit_the_bounded_result_budget()
    -> Result<(), Box<dyn std::error::Error>> {
        let mappings = (0..64).map(mapping).collect::<Vec<_>>();
        let page = ListResult {
            revision: 7,
            mappings,
            next_cursor: Some("name-063.example".to_owned()),
        };
        assert_result_fits(success("Read 64 mappings at revision 7.", page))?;

        let effects = (0..32)
            .map(|index| ChangeEffect {
                pattern: format!("name-{index:03}.example"),
                action: "update".to_owned(),
                before: Some(mapping(index)),
                after: Some(mapping(index + 64)),
            })
            .collect();
        let receipt = ApplyResult {
            operation_id: "dc83045e-9a23-40c8-aaf7-2e0753373c5d".to_owned(),
            previous_revision: 7,
            revision: 8,
            changed: true,
            effects,
        };
        assert_result_fits(success("Committed revision 8.", receipt))?;
        Ok(())
    }

    fn mapping(index: usize) -> MappingView {
        const PREFIX: &str = "https://example.com/";
        MappingView {
            pattern: format!("name-{index:03}.example"),
            target: format!("{PREFIX}{}", "x".repeat(MAX_TARGET_BYTES - PREFIX.len())),
            target_kind: "https".to_owned(),
            host_policy: HostPolicy::PreserveClient,
            enabled: true,
            updated_revision: 7,
        }
    }

    fn assert_result_fits<T>(value: super::ToolSuccess<T>) -> Result<(), Box<dyn std::error::Error>>
    where
        T: serde::Serialize + schemars::JsonSchema + 'static,
    {
        let response = value
            .into_call_tool_result()
            .map_err(|error| format!("tool result conversion failed: {error}"))?;
        let rmcp::model::CallToolResponse::Complete(result) = response else {
            return Err("Remap tool result did not complete inline".into());
        };
        let encoded = serde_json::to_vec(&result)?;
        assert!(encoded.len() <= MAX_TOOL_RESULT_BYTES);
        Ok(())
    }
}
