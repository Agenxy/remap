use std::sync::OnceLock;

use rmcp::model::MetaObject;
use serde_json::{Map, json};
use sha2::{Digest, Sha256};

const DASHBOARD_URI_BASE: &str = "ui://remap/dashboard";
const DASHBOARD_HTML: &str = include_str!(concat!(env!("OUT_DIR"), "/dashboard.html"));

/// MIME type required by MCP Apps hosts.
pub(crate) const APP_MIME_TYPE: &str = "text/html;profile=mcp-app";

/// Content-addressed MCP Apps resource URI for this dashboard build.
pub(crate) fn dashboard_uri() -> &'static str {
    static URI: OnceLock<String> = OnceLock::new();
    URI.get_or_init(|| format!("{DASHBOARD_URI_BASE}/{}", dashboard_build()))
}

/// Self-contained dashboard document carrying its visible build identifier.
pub(crate) fn dashboard_html() -> &'static str {
    DASHBOARD_HTML
}

fn dashboard_build() -> &'static str {
    static BUILD: OnceLock<String> = OnceLock::new();
    BUILD.get_or_init(|| short_digest(DASHBOARD_HTML))
}

fn short_digest(template: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(template.as_bytes());
    let mut output = String::with_capacity(12);
    for byte in &digest[..6] {
        output.push(char::from(HEX[usize::from(*byte >> 4)]));
        output.push(char::from(HEX[usize::from(*byte & 0x0f)]));
    }
    output
}

fn tool_meta(visibility: &[&str]) -> MetaObject {
    let mut object = Map::new();
    object.insert(
        "ui".to_owned(),
        json!({ "resourceUri": dashboard_uri(), "visibility": visibility }),
    );
    MetaObject(object)
}

/// Attaches the dashboard to a read tool callable by models and the App.
pub(crate) fn app_tool_meta() -> MetaObject {
    tool_meta(&["model", "app"])
}

/// Attaches the dashboard to a tool callable only by models.
pub(crate) fn model_tool_meta() -> MetaObject {
    tool_meta(&["model"])
}

/// Describes the dashboard resource to compatible hosts.
pub(crate) fn resource_meta() -> MetaObject {
    let mut object = Map::new();
    object.insert(
        "ui".to_owned(),
        json!({
            "prefersBorder": true,
            "csp": {
                "connectDomains": [],
                "resourceDomains": []
            }
        }),
    );
    object.insert(
        "openai/widgetDescription".to_owned(),
        json!(
            "Inspect the local Remap registry, exact tool results, and revision-checked changes."
        ),
    );
    MetaObject(object)
}

#[cfg(test)]
mod tests {
    use super::{
        DASHBOARD_HTML, DASHBOARD_URI_BASE, dashboard_build, dashboard_html, dashboard_uri,
        short_digest,
    };

    #[test]
    fn dashboard_identity_tracks_the_served_template() {
        let expected = short_digest(DASHBOARD_HTML);
        assert_eq!(dashboard_build(), expected);
        assert_eq!(dashboard_uri(), format!("{DASHBOARD_URI_BASE}/{expected}"));
        assert_eq!(dashboard_html(), DASHBOARD_HTML);
        assert!(dashboard_html().contains(&format!("panel {}", env!("CARGO_PKG_VERSION"))));
        assert!(!dashboard_html().contains("__REMAP_"));
        assert_ne!(dashboard_uri(), DASHBOARD_URI_BASE);
    }
}
