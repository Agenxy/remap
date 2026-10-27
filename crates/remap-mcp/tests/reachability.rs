// SPDX-License-Identifier: GPL-3.0-or-later
//! The MCP preview and committing tools carry the authority's reachability
//! advice for loopback HTTP targets, and still commit (ADR-0028).

use std::error::Error;
use std::io;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Duration;

use remap_mcp::RemapService;
use remap_protocol::{ControlClient, ControlPaths, Surface};
use remapd::DaemonConfig;
use rmcp::model::{CallToolRequestParams, ProtocolVersion};
use rmcp::{ClientLifecycleMode, ClientServiceExt, ServiceExt};
use serde_json::{Value, json};
use tokio::net::TcpListener;

type Client = rmcp::service::RunningService<rmcp::RoleClient, ()>;

async fn call(
    client: &Client,
    name: &'static str,
    arguments: Value,
) -> Result<Value, Box<dyn Error>> {
    let object = arguments
        .as_object()
        .cloned()
        .ok_or_else(|| io::Error::other("tool arguments must be an object"))?;
    let result = client
        .call_tool(CallToolRequestParams::new(name).with_arguments(object))
        .await?;
    assert_ne!(result.is_error, Some(true), "{name} failed: {result:?}");
    result
        .structured_content
        .ok_or_else(|| io::Error::other("tool returned no structured content").into())
}

fn refusals(data: &Value, pattern: &str) -> usize {
    data["warnings"].as_array().map_or(0, |warnings| {
        warnings
            .iter()
            .filter_map(Value::as_str)
            .filter(|warning| warning.starts_with(&format!("{pattern}: target refused connection")))
            .count()
    })
}

async fn wait_for_socket(path: &Path) -> Result<(), Box<dyn Error>> {
    for _attempt in 0..200 {
        if path.exists() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err(io::Error::other("daemon socket did not appear").into())
}

#[tokio::test]
async fn preview_set_and_apply_advise_on_a_refused_loopback_target() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let paths = ControlPaths::under(directory.path().join("data"));
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let daemon = tokio::spawn(remapd::serve_until(
        DaemonConfig::new(paths.clone()),
        async {
            let _done = stopped.await;
        },
    ));
    wait_for_socket(paths.socket()).await?;
    let reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let dead = format!("http://{}/", reservation.local_addr()?);
    drop(reservation);

    let (server_io, client_io) = tokio::io::duplex(128 * 1024);
    let server = RemapService::new(ControlClient::new(
        paths.socket(),
        Surface::Mcp,
        env!("CARGO_PKG_VERSION"),
    ));
    let server_task = tokio::spawn(async move { server.serve(server_io).await });
    let client = ()
        .serve_with_lifecycle(
            client_io,
            ClientLifecycleMode::Discover {
                preferred_versions: vec![ProtocolVersion::V_2026_07_28],
            },
        )
        .await?;
    let server_service = server_task.await??;

    let preview = call(
        &client,
        "remap_preview",
        json!({"changes": [{"kind": "set", "pattern": "api.test", "target": dead}]}),
    )
    .await?;
    assert_eq!(refusals(&preview["data"], "api.test"), 1, "{preview}");

    let set = call(
        &client,
        "remap_set",
        json!({
            "expected_revision": 0,
            "operation_id": uuid::Uuid::new_v4().to_string(),
            "pattern": "api.test",
            "target": dead
        }),
    )
    .await?;
    assert_eq!(set["data"]["changed"], true, "{set}");
    assert_eq!(set["data"]["revision"], 1);
    assert_eq!(refusals(&set["data"], "api.test"), 1, "{set}");

    let applied = call(
        &client,
        "remap_apply",
        json!({
            "expected_revision": 1,
            "operation_id": uuid::Uuid::new_v4().to_string(),
            "changes": [{"kind": "set", "pattern": "web.test", "target": dead}]
        }),
    )
    .await?;
    assert_eq!(applied["data"]["revision"], 2, "{applied}");
    assert_eq!(refusals(&applied["data"], "web.test"), 1, "{applied}");

    let fetched = call(&client, "remap_get", json!({"pattern": "web.test"})).await?;
    assert_eq!(fetched["data"]["target"], dead);

    client.cancel().await?;
    server_service.cancel().await?;
    let _sent = stop.send(());
    daemon.await??;
    Ok(())
}
