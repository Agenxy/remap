// SPDX-License-Identifier: GPL-3.0-or-later
//! The peer-machine target names a Supgang machine by its identity and the
//! exposed services its name reaches (ADR-0033).

use std::error::Error;
use std::net::Ipv4Addr;
use std::str::FromStr;

use remap_core::{
    Mapping, MappingTarget, MappingTargetError, NamePattern, PeerMachineError, RegistrySnapshot,
    SnapshotError,
};

const NODE: &str = "3f1c0b9e7a2d4c5b8e6f1a0d9c8b7a6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a";

fn machine_error(input: &str) -> Result<PeerMachineError, Box<dyn Error>> {
    match MappingTarget::from_str(input) {
        Err(MappingTargetError::InvalidPeerMachine(error)) => Ok(error),
        other => Err(format!("{input} gave {other:?}").into()),
    }
}

#[test]
fn a_node_id_or_fingerprint_with_pairs_is_a_peer_machine() -> Result<(), Box<dyn Error>> {
    let input = format!("supgang://{NODE}?ssh=22,k7=7443");
    let target = MappingTarget::from_str(&input)?;
    let MappingTarget::PeerMachine(machine) = &target else {
        return Err("a supgang:// target without a path is a peer machine".into());
    };
    assert_eq!(machine.selector(), NODE);
    let pairs: Vec<(&str, u16)> = machine
        .services()
        .iter()
        .map(|service| (service.name(), service.port().get()))
        .collect();
    assert_eq!(pairs, vec![("ssh", 22), ("k7", 7443)]);
    assert_eq!(target.kind().as_str(), "peer-machine");
    assert_eq!(target.to_string(), input);
    assert_eq!(MappingTarget::from_str(&target.to_string())?, target);

    let fingerprint = MappingTarget::from_str("supgang://a8a37e32?ssh=22")?;
    assert_eq!(fingerprint.kind().as_str(), "peer-machine");
    // A path still selects a peer's advertised service, as before.
    assert_eq!(
        MappingTarget::from_str("supgang://a8a37e32/ssh")?
            .kind()
            .as_str(),
        "peer"
    );
    Ok(())
}

#[test]
fn display_is_canonical_and_round_trips() -> Result<(), Box<dyn Error>> {
    let target = MappingTarget::from_str("supgang://a8a37e32?ssh=0022,web=8080")?;
    assert_eq!(target.to_string(), "supgang://a8a37e32?ssh=22,web=8080");
    assert_eq!(MappingTarget::from_str(&target.to_string())?, target);
    Ok(())
}

#[test]
fn a_name_selector_is_refused_with_how_to_find_the_identity() -> Result<(), Box<dyn Error>> {
    for selector in ["MacSolis", "pro", "a8a37e3", &format!("{NODE}0")] {
        let error = machine_error(&format!("supgang://{selector}?ssh=22"))?;
        assert!(
            matches!(error, PeerMachineError::SelectorNotIdentity(_)),
            "{error:?}"
        );
        let message = error.to_string();
        assert!(message.contains("node ID"), "{message}");
        assert!(message.contains("fingerprint"), "{message}");
        assert!(message.contains("supgang resolve"), "{message}");
    }
    Ok(())
}

#[test]
fn uppercase_identities_are_refused() -> Result<(), Box<dyn Error>> {
    for selector in ["A8A37E32".to_owned(), NODE.to_ascii_uppercase()] {
        assert!(matches!(
            machine_error(&format!("supgang://{selector}?ssh=22"))?,
            PeerMachineError::SelectorNotLowercase(_)
        ));
    }
    Ok(())
}

#[test]
fn pairs_are_unique_bounded_and_well_formed() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        machine_error("supgang://a8a37e32?ssh=22,web=22")?,
        PeerMachineError::DuplicatePort(std::num::NonZeroU16::new(22).ok_or("zero")?)
    );
    assert_eq!(
        machine_error("supgang://a8a37e32?ssh=22,ssh=2222")?,
        PeerMachineError::DuplicateService("ssh".to_owned())
    );
    assert!(matches!(
        machine_error("supgang://a8a37e32?a-service-name-too-long=22")?,
        PeerMachineError::InvalidService(_)
    ));
    for port in ["0", "65536", "+22", "", "ssh", "0x16"] {
        assert!(
            matches!(
                machine_error(&format!("supgang://a8a37e32?ssh={port}"))?,
                PeerMachineError::InvalidPort { .. }
            ),
            "{port}"
        );
    }
    for pairs in ["ssh", "ssh=22,", ",ssh=22"] {
        assert!(matches!(
            machine_error(&format!("supgang://a8a37e32?{pairs}"))?,
            PeerMachineError::InvalidPair(_)
        ));
    }
    for name in ["SSH", "-ssh", "s s"] {
        assert!(matches!(
            machine_error(&format!("supgang://a8a37e32?{name}=22"))?,
            PeerMachineError::InvalidService(_)
        ));
    }
    Ok(())
}

#[test]
fn the_pair_list_holds_one_through_sixteen_services() -> Result<(), Box<dyn Error>> {
    for empty in ["supgang://a8a37e32", "supgang://a8a37e32?"] {
        assert_eq!(machine_error(empty)?, PeerMachineError::MissingServices);
    }
    let pairs = |count: u16| {
        (1..=count)
            .map(|index| format!("s{index}={}", 1000 + index))
            .collect::<Vec<_>>()
            .join(",")
    };
    assert!(MappingTarget::from_str(&format!("supgang://a8a37e32?{}", pairs(16))).is_ok());
    assert_eq!(
        machine_error(&format!("supgang://a8a37e32?{}", pairs(17)))?,
        PeerMachineError::TooManyServices(17)
    );
    Ok(())
}

#[test]
fn placeholders_are_refused() -> Result<(), Box<dyn Error>> {
    for input in ["supgang://{1}?ssh=22", "supgang://a8a37e32?{1}=22"] {
        let error = machine_error(input)?;
        assert_eq!(error, PeerMachineError::Template);
        assert!(error.to_string().contains("supgang://<peer>/<service>"));
    }
    Ok(())
}

#[test]
fn snapshots_require_one_unique_address_per_peer_machine() -> Result<(), Box<dyn Error>> {
    let machine = |pattern: &str, address: Option<Ipv4Addr>| -> Result<Mapping, Box<dyn Error>> {
        Ok(Mapping::new(
            NamePattern::parse(pattern)?,
            MappingTarget::from_str("supgang://a8a37e32?ssh=22")?,
        )
        .with_peer_address(address))
    };
    let first = Ipv4Addr::new(127, 77, 0, 1);
    let second = Ipv4Addr::new(127, 77, 0, 2);
    let snapshot = RegistrySnapshot::new(
        1,
        vec![
            machine("pro.test", Some(first))?,
            machine("old.test", Some(second))?.with_enabled(false),
        ],
    )?;
    assert_eq!(
        snapshot
            .peer_machine_addresses()
            .into_iter()
            .collect::<Vec<_>>(),
        vec![first]
    );
    assert!(matches!(
        RegistrySnapshot::new(1, vec![machine("pro.test", None)?]),
        Err(SnapshotError::PeerAddress(_))
    ));
    assert!(matches!(
        RegistrySnapshot::new(1, vec![machine("pro.test", Some(Ipv4Addr::LOCALHOST))?]),
        Err(SnapshotError::PeerAddress(_))
    ));
    assert!(matches!(
        RegistrySnapshot::new(
            1,
            vec![
                machine("pro.test", Some(first))?,
                machine("air.test", Some(first))?
            ]
        ),
        Err(SnapshotError::DuplicatePeerAddress(_))
    ));
    let address_on_http = Mapping::new(
        NamePattern::parse("web.test")?,
        MappingTarget::from_str("http://127.0.0.1:8080")?,
    )
    .with_peer_address(Some(first));
    assert!(matches!(
        RegistrySnapshot::new(1, vec![address_on_http]),
        Err(SnapshotError::PeerAddress(_))
    ));
    Ok(())
}
