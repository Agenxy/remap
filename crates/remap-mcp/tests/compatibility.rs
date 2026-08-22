//! Official-SDK interoperability proofs for both supported MCP revisions.

#[path = "compatibility/catalog.rs"]
mod catalog;

use std::error::Error;
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use remap_mcp::{RemapService, SUPPORTED_PROTOCOL_VERSIONS};
use remap_protocol::{
    ApplyResult, Change, Command, CommandResult, ControlClient, ControlPaths, Diagnostic,
    HostPolicy, Surface,
};
use remapd::DaemonConfig;
use rmcp::model::{
    CallToolRequestParams, ClientCapabilities, ClientInfo, ClientJsonRpcMessage, ContentBlock,
    ErrorCode, ExtensionCapabilities, Implementation, ProtocolVersion, ReadResourceRequestParams,
    ResourceContents, ResourceUpdatedNotificationParam, ServerJsonRpcMessage, ServerNotification,
    SubscribeRequestParams, SubscriptionFilter, UnsubscribeRequestParams,
};
use rmcp::service::{NotificationContext, RoleClient, RoleServer, Service};
use rmcp::transport::{IntoTransport, Transport};
use rmcp::{ClientHandler, ClientLifecycleMode, ClientServiceExt, ServiceExt};
use serde_json::{Value, json};
use tokio::sync::Notify;

use catalog::assert_modern_tool_catalog;

#[derive(Debug, Clone, Default)]
struct TestClient {
    updates: Arc<AtomicUsize>,
    changed: Arc<Notify>,
    app_settings: Option<Value>,
}

impl TestClient {
    fn with_apps() -> Self {
        Self::with_app_settings(json!({
            "mimeTypes": ["text/html;profile=mcp-app"]
        }))
    }

    fn with_app_settings(settings: Value) -> Self {
        Self {
            app_settings: Some(settings),
            ..Self::default()
        }
    }
}

impl ClientHandler for TestClient {
    fn get_info(&self) -> ClientInfo {
        let mut extensions = ExtensionCapabilities::new();
        if let Some(settings) = &self.app_settings {
            extensions.insert(
                "io.modelcontextprotocol/ui".to_owned(),
                serde_json::from_value(settings.clone()).unwrap_or_default(),
            );
        }
        let capabilities = if extensions.is_empty() {
            ClientCapabilities::default()
        } else {
            ClientCapabilities::builder()
                .enable_extensions_with(extensions)
                .build()
        };
        ClientInfo::new(
            capabilities,
            Implementation::new("remap-compatibility-test", "1"),
        )
    }

    async fn on_resource_updated(
        &self,
        _params: ResourceUpdatedNotificationParam,
        _context: NotificationContext<RoleClient>,
    ) {
        self.updates.fetch_add(1, Ordering::Relaxed);
        self.changed.notify_one();
    }
}

#[test]
fn compatibility_policy_is_exact_and_ordered() {
    assert_eq!(
        SUPPORTED_PROTOCOL_VERSIONS,
        [ProtocolVersion::V_2026_07_28, ProtocolVersion::V_2025_11_25]
    );
}

#[tokio::test]
async fn legacy_initialize_cannot_negotiate_the_modern_revision() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let paths = ControlPaths::under(directory.path());
    let server = RemapService::new(ControlClient::new(
        paths.socket(),
        Surface::Mcp,
        env!("CARGO_PKG_VERSION"),
    ));
    let (server_io, client_io) = tokio::io::duplex(16 * 1024);
    let server_task = tokio::spawn(async move { server.serve(server_io).await });
    let mut client = IntoTransport::<RoleClient, _, _>::into_transport(client_io);
    let request: ClientJsonRpcMessage = serde_json::from_value(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2026-07-28",
            "capabilities": {},
            "clientInfo": {"name": "adversarial-client", "version": "1"}
        }
    }))?;
    client.send(request).await?;
    let response = tokio::time::timeout(Duration::from_secs(1), client.receive())
        .await?
        .ok_or_else(|| io::Error::other("server closed without rejecting initialize"))?;
    let ServerJsonRpcMessage::Error(error) = response else {
        return Err(io::Error::other("modern initialize was not rejected").into());
    };
    assert_eq!(error.error.code, ErrorCode::UNSUPPORTED_PROTOCOL_VERSION);
    drop(client);
    let result = server_task.await?;
    assert!(result.is_err());
    Ok(())
}

#[tokio::test]
async fn stateless_discover_cannot_select_the_legacy_revision() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let paths = ControlPaths::under(directory.path());
    let server = RemapService::new(ControlClient::new(
        paths.socket(),
        Surface::Mcp,
        env!("CARGO_PKG_VERSION"),
    ));
    let (server_io, client_io) = tokio::io::duplex(16 * 1024);
    let server_task = tokio::spawn(async move { server.serve(server_io).await });
    let mut client = IntoTransport::<RoleClient, _, _>::into_transport(client_io);
    let request: ClientJsonRpcMessage = serde_json::from_value(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "server/discover",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2025-11-25",
                "io.modelcontextprotocol/clientInfo": {
                    "name": "adversarial-client",
                    "version": "1"
                },
                "io.modelcontextprotocol/clientCapabilities": {}
            }
        }
    }))?;
    client.send(request).await?;
    let response = tokio::time::timeout(Duration::from_secs(1), client.receive())
        .await?
        .ok_or_else(|| io::Error::other("server closed without rejecting discover"))?;
    let ServerJsonRpcMessage::Error(error) = response else {
        return Err(io::Error::other("legacy stateless discovery was not rejected").into());
    };
    assert_eq!(error.error.code, ErrorCode::UNSUPPORTED_PROTOCOL_VERSION);
    drop(client);
    let service = server_task.await??;
    service.cancel().await?;
    Ok(())
}

#[tokio::test]
async fn legacy_apps_negotiates_ui_and_rejects_modern_discovery() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let paths = ControlPaths::under(directory.path());
    let server = mcp_for(&paths);
    let (server_io, client_io) = tokio::io::duplex(32 * 1024);
    let server_task = tokio::spawn(async move { server.serve(server_io).await });
    let mut client = IntoTransport::<RoleClient, _, _>::into_transport(client_io);
    let initialize: ClientJsonRpcMessage = serde_json::from_value(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {
                "extensions": {
                    "io.modelcontextprotocol/ui": {
                        "mimeTypes": ["text/html;profile=mcp-app"]
                    }
                }
            },
            "clientInfo": {"name": "legacy-apps-host", "version": "1"}
        }
    }))?;
    client.send(initialize).await?;
    let initialized = tokio::time::timeout(Duration::from_secs(1), client.receive())
        .await?
        .ok_or_else(|| io::Error::other("legacy initialize returned no response"))?;
    let encoded = serde_json::to_value(&initialized)?;
    assert_eq!(
        encoded["result"]["capabilities"]["extensions"]["io.modelcontextprotocol/ui"]["mimeTypes"],
        json!(["text/html;profile=mcp-app"])
    );
    let notification: ClientJsonRpcMessage = serde_json::from_value(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    }))?;
    client.send(notification).await?;
    let running = tokio::time::timeout(Duration::from_secs(1), server_task).await???;

    let list_tools: ClientJsonRpcMessage = serde_json::from_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    }))?;
    client.send(list_tools).await?;
    let listed = tokio::time::timeout(Duration::from_secs(1), client.receive())
        .await?
        .ok_or_else(|| io::Error::other("legacy tools/list returned no response"))?;
    let listed_value = serde_json::to_value(&listed)?;
    assert!(listed_value["result"].get("_meta").is_none());

    let discover: ClientJsonRpcMessage = serde_json::from_value(json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "server/discover",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2025-11-25"
            }
        }
    }))?;
    client.send(discover).await?;
    let response = tokio::time::timeout(Duration::from_secs(1), client.receive())
        .await?
        .ok_or_else(|| io::Error::other("cross-family discover returned no response"))?;
    let ServerJsonRpcMessage::Error(error) = response else {
        return Err(io::Error::other("legacy session accepted modern discovery").into());
    };
    assert_eq!(error.error.code, ErrorCode::METHOD_NOT_FOUND);
    drop(client);
    running.cancel().await?;
    Ok(())
}

#[tokio::test]
async fn modern_discovery_pins_stdio_against_a_late_legacy_initialize() -> Result<(), Box<dyn Error>>
{
    let directory = tempfile::tempdir()?;
    let paths = ControlPaths::under(directory.path());
    let server = mcp_for(&paths);
    let (server_io, client_io) = tokio::io::duplex(32 * 1024);
    let server_task = tokio::spawn(async move { server.serve(server_io).await });
    let mut client = IntoTransport::<RoleClient, _, _>::into_transport(client_io);
    let discover: ClientJsonRpcMessage = serde_json::from_value(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "server/discover",
        "params": modern_meta()
    }))?;
    client.send(discover).await?;
    let discovered = tokio::time::timeout(Duration::from_secs(1), client.receive())
        .await?
        .ok_or_else(|| io::Error::other("modern discovery returned no response"))?;
    assert!(matches!(discovered, ServerJsonRpcMessage::Response(_)));
    let running = tokio::time::timeout(Duration::from_secs(1), server_task).await???;

    let initialize: ClientJsonRpcMessage = serde_json::from_value(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "hybrid-client", "version": "1"}
        }
    }))?;
    client.send(initialize).await?;
    let response = tokio::time::timeout(Duration::from_secs(1), client.receive())
        .await?
        .ok_or_else(|| io::Error::other("late initialize returned no response"))?;
    let ServerJsonRpcMessage::Error(error) = response else {
        return Err(io::Error::other("modern connection accepted late initialize").into());
    };
    assert_eq!(error.error.code, ErrorCode::METHOD_NOT_FOUND);
    drop(client);
    running.cancel().await?;
    Ok(())
}

#[tokio::test]
async fn modern_discover_exposes_bounded_agent_contract() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let paths = ControlPaths::under(directory.path());
    let server = RemapService::new(ControlClient::new(
        paths.socket(),
        Surface::Mcp,
        env!("CARGO_PKG_VERSION"),
    ));
    assert_eq!(
        Service::<RoleServer>::supported_protocol_versions(&server).as_ref(),
        SUPPORTED_PROTOCOL_VERSIONS
    );

    let (server_io, client_io) = tokio::io::duplex(128 * 1024);
    let server_task = tokio::spawn(async move { server.serve(server_io).await });
    let client = TestClient::with_apps()
        .serve_with_lifecycle(
            client_io,
            ClientLifecycleMode::Discover {
                preferred_versions: vec![ProtocolVersion::V_2026_07_28],
            },
        )
        .await?;
    let server_service = server_task.await??;

    let peer = client
        .peer_info()
        .ok_or_else(|| io::Error::other("modern client retained no peer information"))?;
    assert_eq!(peer.protocol_version, ProtocolVersion::V_2026_07_28);
    let app_capability = peer
        .capabilities
        .extensions
        .as_ref()
        .and_then(|extensions| extensions.get("io.modelcontextprotocol/ui"))
        .ok_or_else(|| io::Error::other("server did not declare the MCP Apps extension"))?;
    assert_eq!(
        app_capability.get("mimeTypes"),
        Some(&json!(["text/html;profile=mcp-app"]))
    );
    let tools = client.list_tools(None).await?;
    assert_modern_tool_catalog(&tools)?;
    for _ in 0..40 {
        assert_modern_tool_catalog(&client.list_tools(None).await?)?;
    }
    let resources = client.list_resources(None).await?;
    assert_eq!(resources.resources.len(), 5);
    assert_eq!(resources.ttl_ms, Some(3_600_000));
    let dashboard_uri = resources
        .resources
        .iter()
        .find(|resource| resource.name == "dashboard")
        .map(|resource| resource.uri.clone())
        .ok_or_else(|| io::Error::other("dashboard resource was not listed"))?;
    let dashboard = client
        .read_resource(ReadResourceRequestParams::new(dashboard_uri))
        .await?;
    assert_eq!(dashboard.ttl_ms, Some(3_600_000));
    let Some(ResourceContents::TextResourceContents { meta, .. }) = dashboard.contents.first()
    else {
        return Err(io::Error::other("dashboard was not returned as text").into());
    };
    assert!(
        meta.as_ref()
            .and_then(|meta| meta.0.get("ui"))
            .and_then(|ui| ui.get("csp"))
            .is_some()
    );

    client.cancel().await?;
    server_service.cancel().await?;
    Ok(())
}

#[tokio::test]
async fn modern_apps_surface_requires_the_exact_negotiated_mime_type() -> Result<(), Box<dyn Error>>
{
    for (settings, expected) in [
        (None, false),
        (Some(json!({})), false),
        (Some(json!({"mimeTypes": ["text/plain"]})), false),
        (
            Some(json!({"mimeTypes": ["text/html;profile=mcp-app"]})),
            true,
        ),
    ] {
        assert_modern_apps_case(settings, expected).await?;
    }
    Ok(())
}

#[tokio::test]
#[allow(deprecated)]
async fn legacy_apps_surface_requires_the_exact_negotiated_mime_type() -> Result<(), Box<dyn Error>>
{
    for (settings, expected) in [
        (None, false),
        (Some(json!({})), false),
        (Some(json!({"mimeTypes": ["text/plain"]})), false),
        (
            Some(json!({"mimeTypes": ["text/html;profile=mcp-app"]})),
            true,
        ),
    ] {
        assert_legacy_apps_case(settings, expected).await?;
    }
    Ok(())
}

async fn assert_modern_apps_case(
    settings: Option<Value>,
    expected: bool,
) -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let paths = ControlPaths::under(directory.path());
    let server = mcp_for(&paths);
    let (server_io, client_io) = tokio::io::duplex(128 * 1024);
    let server_task = tokio::spawn(async move { server.serve(server_io).await });
    let handler = settings.map_or_else(TestClient::default, TestClient::with_app_settings);
    let client = handler
        .serve_with_lifecycle(
            client_io,
            ClientLifecycleMode::Discover {
                preferred_versions: vec![ProtocolVersion::V_2026_07_28],
            },
        )
        .await?;
    let server_service = server_task.await??;
    let peer = client
        .peer_info()
        .ok_or_else(|| io::Error::other("modern client retained no peer information"))?;
    assert_eq!(
        peer.capabilities
            .extensions
            .as_ref()
            .is_some_and(|extensions| extensions.contains_key("io.modelcontextprotocol/ui")),
        expected
    );
    let tools = client.list_tools(None).await?;
    assert_eq!(tools.cache_scope, Some(rmcp::model::CacheScope::Private));
    assert_eq!(tools.tools.iter().all(|tool| tool.meta.is_some()), expected);
    let resources = client.list_resources(None).await?;
    assert_eq!(resources.resources.len(), if expected { 5 } else { 4 });
    client.cancel().await?;
    server_service.cancel().await?;
    Ok(())
}

#[allow(deprecated)]
async fn assert_legacy_apps_case(
    settings: Option<Value>,
    expected: bool,
) -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let paths = ControlPaths::under(directory.path());
    let server = mcp_for(&paths);
    let (server_io, client_io) = tokio::io::duplex(128 * 1024);
    let server_task = tokio::spawn(async move { server.serve(server_io).await });
    let handler = settings.map_or_else(TestClient::default, TestClient::with_app_settings);
    let client = handler.serve(client_io).await?;
    let server_service = server_task.await??;
    let peer = client
        .peer_info()
        .ok_or_else(|| io::Error::other("legacy client retained no peer information"))?;
    assert_eq!(
        peer.capabilities
            .extensions
            .as_ref()
            .is_some_and(|extensions| extensions.contains_key("io.modelcontextprotocol/ui")),
        expected
    );
    let tools = client.list_tools(None).await?;
    assert_eq!(tools.tools.iter().all(|tool| tool.meta.is_some()), expected);
    let resources = client.list_resources(None).await?;
    assert_eq!(resources.resources.len(), if expected { 5 } else { 4 });
    client.cancel().await?;
    server_service.cancel().await?;
    Ok(())
}

#[tokio::test]
async fn both_revisions_share_one_revision_order() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let paths = ControlPaths::under(directory.path().join("data"));
    let (stop_sender, stop_receiver) = tokio::sync::oneshot::channel();
    let daemon_paths = paths.clone();
    let daemon = tokio::spawn(async move {
        remapd::serve_until(DaemonConfig::new(daemon_paths), async {
            let _result = stop_receiver.await;
        })
        .await
    });
    wait_for_socket(paths.socket()).await?;

    exercise_modern(&paths).await?;
    exercise_previous(&paths).await?;

    let _result = stop_sender.send(());
    daemon.await??;
    Ok(())
}

#[tokio::test]
async fn modern_subscription_capacity_rejects_a_flood() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let paths = ControlPaths::under(directory.path().join("data"));
    let (stop_sender, stop_receiver) = tokio::sync::oneshot::channel();
    let daemon_paths = paths.clone();
    let daemon = tokio::spawn(async move {
        remapd::serve_until(DaemonConfig::new(daemon_paths), async {
            let _result = stop_receiver.await;
        })
        .await
    });
    wait_for_socket(paths.socket()).await?;
    let (server_io, client_io) = tokio::io::duplex(128 * 1024);
    let server = mcp_for(&paths);
    let server_task = tokio::spawn(async move { server.serve(server_io).await });
    let client = TestClient::default()
        .serve_with_lifecycle(
            client_io,
            ClientLifecycleMode::Discover {
                preferred_versions: vec![ProtocolVersion::V_2026_07_28],
            },
        )
        .await?;
    let server_service = server_task.await??;
    let filter = || {
        SubscriptionFilter::builder()
            .resource_subscription("remap://status")
            .build()
    };
    let mut subscriptions = Vec::new();
    for _index in 0..4 {
        subscriptions.push(client.listen(filter()).await?);
    }
    let mut overflow = client.listen(filter()).await?;
    let overflow_result = tokio::time::timeout(Duration::from_secs(1), overflow.next()).await?;
    assert!(overflow_result.is_err());
    for mut subscription in subscriptions {
        subscription.cancel().await?;
    }
    client.cancel().await?;
    server_service.cancel().await?;
    let _sent = stop_sender.send(());
    daemon.await??;
    Ok(())
}

#[tokio::test]
async fn modern_subscription_recovers_after_a_daemon_restart() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let paths = ControlPaths::under(directory.path().join("data"));
    let (first_stop_sender, first_stop_receiver) = tokio::sync::oneshot::channel();
    let first_paths = paths.clone();
    let first_daemon = tokio::spawn(async move {
        remapd::serve_until(DaemonConfig::new(first_paths), async {
            let _result = first_stop_receiver.await;
        })
        .await
    });
    wait_for_socket(paths.socket()).await?;
    let (server_io, client_io) = tokio::io::duplex(128 * 1024);
    let server = mcp_for(&paths);
    let server_task = tokio::spawn(async move { server.serve(server_io).await });
    let client = TestClient::default()
        .serve_with_lifecycle(
            client_io,
            ClientLifecycleMode::Discover {
                preferred_versions: vec![ProtocolVersion::V_2026_07_28],
            },
        )
        .await?;
    let server_service = server_task.await??;
    let mut subscription = client
        .listen(
            SubscriptionFilter::builder()
                .resource_subscription("remap://status")
                .build(),
        )
        .await
        .map_err(|error| io::Error::other(format!("initial listen failed: {error}")))?;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let _sent = first_stop_sender.send(());
    tokio::time::timeout(Duration::from_secs(7), first_daemon).await???;
    let (second_stop_sender, second_stop_receiver) = tokio::sync::oneshot::channel();
    let second_paths = paths.clone();
    let second_daemon = tokio::spawn(async move {
        remapd::serve_until(DaemonConfig::new(second_paths), async {
            let _result = second_stop_receiver.await;
        })
        .await
    });
    wait_for_socket(paths.socket()).await?;
    ControlClient::new(paths.socket(), Surface::Probe, env!("CARGO_PKG_VERSION"))
        .execute(Command::Apply {
            expected_revision: 0,
            operation_id: uuid::Uuid::new_v4().to_string(),
            changes: vec![Change::Set {
                pattern: "restart-proof".to_owned(),
                target: "127.0.0.1".to_owned(),
                host_policy: HostPolicy::PreserveClient,
                enabled: None,
            }],
        })
        .await
        .map_err(|error| io::Error::other(format!("post-restart apply failed: {error}")))?;
    let update = tokio::time::timeout(Duration::from_secs(5), subscription.next())
        .await?
        .map_err(|error| io::Error::other(format!("post-restart subscription failed: {error}")))?;
    assert!(update.is_some());

    subscription.cancel().await?;
    client.cancel().await?;
    server_service.cancel().await?;
    let _sent = second_stop_sender.send(());
    second_daemon.await??;
    Ok(())
}

#[tokio::test]
#[allow(deprecated)]
async fn both_subscription_eras_observe_maintenance_recovery_without_a_new_revision()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let paths = ControlPaths::under(directory.path().join("data"));
    let (stop_sender, stop_receiver) = tokio::sync::oneshot::channel();
    let daemon_paths = paths.clone();
    let daemon = tokio::spawn(async move {
        remapd::serve_until(DaemonConfig::new(daemon_paths), async {
            let _result = stop_receiver.await;
        })
        .await
    });
    wait_for_socket(paths.socket()).await?;
    let control = ControlClient::new(paths.socket(), Surface::Probe, env!("CARGO_PKG_VERSION"));
    apply_mapping(&control, 0, "atlas", "127.0.0.1").await?;

    let (modern_io, modern_client_io) = tokio::io::duplex(128 * 1024);
    let modern_task = tokio::spawn({
        let server = mcp_for(&paths);
        async move { server.serve(modern_io).await }
    });
    let modern = TestClient::default()
        .serve_with_lifecycle(
            modern_client_io,
            ClientLifecycleMode::Discover {
                preferred_versions: vec![ProtocolVersion::V_2026_07_28],
            },
        )
        .await?;
    let modern_service = modern_task.await??;
    let mut modern_updates = modern
        .listen(
            SubscriptionFilter::builder()
                .resource_subscription("remap://status")
                .build(),
        )
        .await?;

    let (legacy_io, legacy_client_io) = tokio::io::duplex(128 * 1024);
    let legacy_task = tokio::spawn({
        let server = mcp_for(&paths);
        async move { server.serve(legacy_io).await }
    });
    let legacy_observer = TestClient::default();
    let legacy = legacy_observer.clone().serve(legacy_client_io).await?;
    let legacy_service = legacy_task.await??;
    legacy
        .subscribe(SubscribeRequestParams::new("remap://status"))
        .await?;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let updater = rusqlite::Connection::open(paths.database())?;
    updater.execute("UPDATE requests SET recorded_unix_ms = 0", [])?;
    let reader = rusqlite::Connection::open(paths.database())?;
    reader.execute_batch("BEGIN")?;
    let _count: i64 = reader.query_row("SELECT COUNT(*) FROM requests", [], |row| row.get(0))?;
    apply_mapping(&control, 1, "second", "127.0.0.2").await?;
    assert_modern_status_update(&mut modern_updates).await?;
    tokio::time::timeout(Duration::from_secs(2), legacy_observer.changed.notified()).await?;
    assert_eq!(legacy_observer.updates.load(Ordering::Relaxed), 1);
    assert!(current_maintenance(&control).await?.is_some());

    reader.execute_batch("ROLLBACK")?;
    drop(reader);
    let receipt = apply_mapping(&control, 2, "second", "127.0.0.2").await?;
    assert!(!receipt.changed);
    assert_eq!(receipt.revision, 2);
    assert!(current_maintenance(&control).await?.is_none());
    assert_modern_status_update(&mut modern_updates).await?;
    tokio::time::timeout(Duration::from_secs(7), legacy_observer.changed.notified()).await?;
    assert_eq!(legacy_observer.updates.load(Ordering::Relaxed), 2);

    modern_updates.cancel().await?;
    legacy
        .unsubscribe(UnsubscribeRequestParams::new("remap://status"))
        .await?;
    modern.cancel().await?;
    legacy.cancel().await?;
    modern_service.cancel().await?;
    legacy_service.cancel().await?;
    let _sent = stop_sender.send(());
    daemon.await??;
    Ok(())
}

async fn apply_mapping(
    client: &ControlClient,
    expected_revision: u64,
    pattern: &str,
    target: &str,
) -> Result<ApplyResult, Box<dyn Error>> {
    let result = client
        .execute(Command::Apply {
            expected_revision,
            operation_id: uuid::Uuid::new_v4().to_string(),
            changes: vec![Change::Set {
                pattern: pattern.to_owned(),
                target: target.to_owned(),
                host_policy: HostPolicy::PreserveClient,
                enabled: None,
            }],
        })
        .await?;
    let CommandResult::Apply(receipt) = result else {
        return Err(io::Error::other("control apply returned the wrong result").into());
    };
    Ok(receipt)
}

async fn current_maintenance(client: &ControlClient) -> Result<Option<Diagnostic>, Box<dyn Error>> {
    let result = client.execute(Command::Status).await?;
    let CommandResult::Status(status) = result else {
        return Err(io::Error::other("control status returned the wrong result").into());
    };
    Ok(status.maintenance)
}

async fn assert_modern_status_update(
    subscription: &mut rmcp::service::Subscription,
) -> Result<(), Box<dyn Error>> {
    let update = tokio::time::timeout(Duration::from_secs(7), subscription.next())
        .await??
        .ok_or_else(|| io::Error::other("modern status subscription ended without an update"))?;
    let ServerNotification::ResourceUpdatedNotification(update) = update else {
        return Err(io::Error::other("modern status subscription returned a wrong update").into());
    };
    assert_eq!(update.params.uri, "remap://status");
    Ok(())
}

async fn exercise_modern(paths: &ControlPaths) -> Result<(), Box<dyn Error>> {
    let (server_io, client_io) = tokio::io::duplex(128 * 1024);
    let server = mcp_for(paths);
    let server_task = tokio::spawn(async move { server.serve(server_io).await });
    let client = TestClient::default()
        .serve_with_lifecycle(
            client_io,
            ClientLifecycleMode::Discover {
                preferred_versions: vec![ProtocolVersion::V_2026_07_28],
            },
        )
        .await?;
    let server_service = server_task.await??;

    let status = call(&client, "remap_status", json!({})).await?;
    assert_eq!(structured(&status)?["data"]["revision"], 0);
    let Some(ContentBlock::Text(text)) = status.content.first() else {
        return Err(io::Error::other("status had no concise text fallback").into());
    };
    assert!(
        text.text
            .starts_with("Revision 0 contains 0 mappings; 0 are active.\n\n")
    );
    assert!(text.text.contains("\"revision\":0"));
    let mut subscription = client
        .listen(
            SubscriptionFilter::builder()
                .resource_subscription("remap://status")
                .build(),
        )
        .await?;
    let operation_id = uuid::Uuid::new_v4().to_string();
    let applied = call(
        &client,
        "remap_set",
        json!({
            "expected_revision": 0,
            "operation_id": operation_id.clone(),
            "pattern": "atlas",
            "target": "127.0.0.1"
        }),
    )
    .await?;
    assert_eq!(structured(&applied)?["data"]["revision"], 1);
    assert!(applied.result_type.is_some());

    let retried = call(
        &client,
        "remap_set",
        json!({
            "expected_revision": 0,
            "operation_id": operation_id.clone(),
            "pattern": "atlas",
            "target": "127.0.0.1"
        }),
    )
    .await?;
    assert_eq!(structured(&retried)?, structured(&applied)?);

    let conflicting_retry = call(
        &client,
        "remap_set",
        json!({
            "expected_revision": 0,
            "operation_id": operation_id,
            "pattern": "atlas",
            "target": "127.0.0.2"
        }),
    )
    .await?;
    assert_eq!(conflicting_retry.is_error, Some(true));
    assert_eq!(
        structured(&conflicting_retry)?["code"],
        "E_IDEMPOTENCY_CONFLICT"
    );

    assert_modern_input_validation(&client).await?;

    let update = tokio::time::timeout(Duration::from_secs(2), subscription.next())
        .await??
        .ok_or_else(|| io::Error::other("modern subscription ended without an update"))?;
    let ServerNotification::ResourceUpdatedNotification(update) = update else {
        return Err(io::Error::other("modern subscription returned the wrong notification").into());
    };
    assert_eq!(update.params.uri, "remap://status");
    subscription.cancel().await?;

    client.cancel().await?;
    server_service.cancel().await?;
    Ok(())
}

async fn assert_modern_input_validation(
    client: &rmcp::service::RunningService<rmcp::RoleClient, TestClient>,
) -> Result<(), Box<dyn Error>> {
    let invalid_limit = call(client, "remap_list", json!({"limit": 0})).await?;
    assert_eq!(invalid_limit.is_error, Some(true));
    assert_eq!(structured(&invalid_limit)?["code"], "E_LIST_LIMIT");
    let unknown_field = call(
        client,
        "remap_list",
        json!({"limit": 20, "unexpected": true}),
    )
    .await?;
    assert_eq!(unknown_field.is_error, Some(true));
    let missing_operation_id = call(
        client,
        "remap_set",
        json!({
            "expected_revision": 1,
            "pattern": "missing-operation-id",
            "target": "127.0.0.1"
        }),
    )
    .await?;
    assert_eq!(missing_operation_id.is_error, Some(true));
    let unexpected_status_argument = call(
        client,
        "remap_status",
        json!({"unexpected": "must be rejected"}),
    )
    .await?;
    assert_eq!(unexpected_status_argument.is_error, Some(true));
    Ok(())
}

#[allow(deprecated)]
async fn exercise_previous(paths: &ControlPaths) -> Result<(), Box<dyn Error>> {
    let (server_io, client_io) = tokio::io::duplex(128 * 1024);
    let server = mcp_for(paths);
    let server_task = tokio::spawn(async move { server.serve(server_io).await });
    let observer = TestClient::default();
    let client = observer.clone().serve(client_io).await?;
    let server_service = server_task.await??;

    let peer = client
        .peer_info()
        .ok_or_else(|| io::Error::other("legacy client retained no peer information"))?;
    assert_eq!(peer.protocol_version, ProtocolVersion::V_2025_11_25);
    assert!(peer.capabilities.extensions.is_none());
    let tools = client.list_tools(None).await?;
    assert_eq!(tools.ttl_ms, None);
    assert_eq!(tools.cache_scope, None);
    let resources = client.list_resources(None).await?;
    assert_eq!(resources.ttl_ms, None);
    assert_eq!(resources.cache_scope, None);
    let help = client
        .read_resource(ReadResourceRequestParams::new("remap://help"))
        .await?;
    assert_eq!(help.ttl_ms, None);
    assert_eq!(help.cache_scope, None);
    let listed = call(
        &client,
        "remap_list",
        json!({"limit": 20, "include_disabled": true}),
    )
    .await?;
    let data = &structured(&listed)?["data"];
    assert_eq!(data["revision"], 1);
    assert_eq!(data["mappings"][0]["pattern"], "atlas");

    client
        .subscribe(SubscribeRequestParams::new("remap://status"))
        .await?;
    let disabled = call(
        &client,
        "remap_disable",
        json!({
            "expected_revision": 1,
            "operation_id": uuid::Uuid::new_v4().to_string(),
            "pattern": "atlas"
        }),
    )
    .await?;
    assert_eq!(structured(&disabled)?["data"]["revision"], 2);
    tokio::time::timeout(Duration::from_secs(2), observer.changed.notified()).await?;
    assert_eq!(observer.updates.load(Ordering::Relaxed), 1);
    client
        .unsubscribe(UnsubscribeRequestParams::new("remap://status"))
        .await?;

    let stale = call(
        &client,
        "remap_remove",
        json!({
            "expected_revision": 0,
            "operation_id": uuid::Uuid::new_v4().to_string(),
            "pattern": "atlas"
        }),
    )
    .await?;
    assert_eq!(stale.is_error, Some(true));
    assert_eq!(structured(&stale)?["code"], "E_REVISION_CONFLICT");
    assert_eq!(structured(&stale)?["retryable"], false);

    client.cancel().await?;
    server_service.cancel().await?;
    Ok(())
}

fn mcp_for(paths: &ControlPaths) -> RemapService {
    RemapService::new(ControlClient::new(
        paths.socket(),
        Surface::Mcp,
        env!("CARGO_PKG_VERSION"),
    ))
}

fn modern_meta() -> Value {
    json!({
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientInfo": {
                "name": "modern-compatibility-test",
                "version": "1"
            },
            "io.modelcontextprotocol/clientCapabilities": {}
        }
    })
}

async fn call(
    client: &rmcp::service::RunningService<rmcp::RoleClient, TestClient>,
    name: &'static str,
    arguments: Value,
) -> Result<rmcp::model::CallToolResult, Box<dyn Error>> {
    let object = arguments
        .as_object()
        .cloned()
        .ok_or_else(|| io::Error::other("tool arguments must be an object"))?;
    let params = CallToolRequestParams::new(name).with_arguments(object);
    Ok(client.call_tool(params).await?)
}

fn structured(result: &rmcp::model::CallToolResult) -> Result<&Value, Box<dyn Error>> {
    result
        .structured_content
        .as_ref()
        .ok_or_else(|| io::Error::other("tool returned no structured content").into())
}

async fn wait_for_socket(path: &Path) -> Result<(), Box<dyn Error>> {
    for _attempt in 0..100 {
        if path.exists() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err(io::Error::other("daemon socket did not appear within one second").into())
}
