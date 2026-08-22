use remap_network::{DnsBindings, DnsRuntime, GatewayBindings, GatewayRuntime, SnapshotStore};
use remap_protocol::Diagnostic;

use crate::Engine;
use crate::server::{DaemonConfig, PreboundNetwork, PreparedNetwork, network_diagnostic};
use crate::system_control::SystemControlRuntime;

pub(crate) async fn prepare_network(
    config: &DaemonConfig,
    engine: &Engine,
    mut prebound: Option<PreboundNetwork>,
) -> Result<Option<PreparedNetwork>, Diagnostic> {
    if config.dns.is_none() && config.gateway.is_none() {
        return Ok(None);
    }
    let snapshots = SnapshotStore::empty();
    let identity = engine.runtime_identity();
    let initial = engine.snapshot().await?;
    let _published = snapshots.publish(initial);
    let dns = if let Some(config) = config.dns.clone() {
        Some(
            if let Some(bindings) = prebound.as_mut().and_then(|value| value.dns.take()) {
                if config.upstreams.is_empty() {
                    DnsRuntime::from_dormant_bindings_with_identity(
                        &config,
                        snapshots.clone(),
                        bindings,
                        identity.clone(),
                    )
                } else {
                    DnsRuntime::from_bindings_with_identity(
                        &config,
                        snapshots.clone(),
                        bindings,
                        identity.clone(),
                    )
                }
                .map_err(network_diagnostic)?
            } else {
                DnsRuntime::bind_with_identity(&config, snapshots.clone(), identity.clone())
                    .map_err(network_diagnostic)?
            },
        )
    } else {
        None
    };
    let gateway = if let Some(config) = config.gateway.clone() {
        Some(
            if let Some(bindings) = prebound.as_mut().and_then(|value| value.gateway.take()) {
                GatewayRuntime::from_bindings_with_identity(
                    config,
                    snapshots.clone(),
                    bindings,
                    identity.clone(),
                )
                .map_err(network_diagnostic)?
            } else {
                GatewayRuntime::bind_with_identity(config, snapshots.clone(), identity.clone())
                    .map_err(network_diagnostic)?
            },
        )
    } else {
        None
    };
    let system_control = if let Some(runtime) = dns.as_ref() {
        let plans = runtime.resolver_plans();
        Some(
            if let Some(listener) = prebound.and_then(|value| value.system_control) {
                SystemControlRuntime::adopt(listener, plans)?
            } else {
                SystemControlRuntime::bind(&config.system_socket, plans).await?
            },
        )
    } else {
        None
    };
    Ok(Some(PreparedNetwork {
        dns,
        gateway,
        system_control,
        snapshots,
    }))
}

pub(crate) fn bind_network(config: &DaemonConfig) -> Result<PreboundNetwork, Diagnostic> {
    let dns = config
        .dns
        .as_ref()
        .map(DnsBindings::bind)
        .transpose()
        .map_err(network_diagnostic)?;
    let gateway = config
        .gateway
        .as_ref()
        .map(GatewayBindings::bind)
        .transpose()
        .map_err(network_diagnostic)?;
    Ok(PreboundNetwork {
        dns,
        gateway,
        system_control: None,
    })
}
