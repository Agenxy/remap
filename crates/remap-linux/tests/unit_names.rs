// SPDX-License-Identifier: GPL-3.0-or-later
//! Every unit Remap installs names itself in `systemctl status` and the journal.

use remap_linux::{
    LinkIndex, LinuxError, LinuxErrorKind, LinuxResult, ResolverLinkManager,
    ResolverSupervisorIdentity, ResolverSupervisorLink, ServiceIdentity, SocketContract,
    SystemdUnitSet,
};

fn installable_units() -> LinuxResult<SystemdUnitSet> {
    let identity = ServiceIdentity::new("remap", "remap", "/usr/libexec/remap/remapd")?;
    let supervisor = ResolverSupervisorIdentity::new(
        "/usr/libexec/remap/remap-linux-system",
        ResolverSupervisorLink::new(
            LinkIndex::new(7)?,
            "eth0",
            ResolverLinkManager::SystemdResolved,
        )?,
        1000,
        1001,
        "/var/lib/remap-system",
        "/var/lib/remap/system.sock",
    )?;
    SystemdUnitSet::generate_installable(&identity, &supervisor, &SocketContract::remap())
}

#[test]
fn each_service_logs_under_its_own_unit_name() -> LinuxResult<()> {
    let units = installable_units()?;
    let resolver = units
        .resolver_service()
        .ok_or_else(|| LinuxError::new(LinuxErrorKind::InvalidState, "missing resolver unit"))?;
    assert!(units.service().contains("\nSyslogIdentifier=remapd\n"));
    assert!(resolver.contains("\nDescription=Remap DNS resolver supervisor\n"));
    // The supervisor's executable is remap-linux-system; the journal names the unit.
    assert!(resolver.contains("\nSyslogIdentifier=remap-resolver\n"));
    Ok(())
}

#[test]
fn each_socket_says_what_it_carries_and_where() -> LinuxResult<()> {
    let units = installable_units()?;
    let descriptions: Vec<_> = units
        .sockets()
        .values()
        .filter_map(|unit| unit.lines().find(|line| line.starts_with("Description=")))
        .collect();
    assert_eq!(
        descriptions,
        [
            "Description=Remap DNS over TCP on 127.0.0.1:53",
            "Description=Remap DNS over UDP on 127.0.0.1:53",
            "Description=Remap HTTP gateway on 127.0.0.1:80",
        ]
    );
    Ok(())
}
