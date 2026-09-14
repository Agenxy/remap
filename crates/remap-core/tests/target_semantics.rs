//! Executable specifications for typed mapping destinations.

use std::error::Error;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use remap_core::{
    HostHeaderPolicy, HttpScheme, HttpUpstream, MappingTarget, RemapName, UpstreamHost,
};

#[test]
fn infers_direct_dns_addresses() -> Result<(), Box<dyn Error>> {
    let target = MappingTarget::from_str("192.168.1.40")?;
    assert_eq!(
        target,
        MappingTarget::DnsAddress(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 40)))
    );
    Ok(())
}

#[test]
fn infers_canonical_dns_aliases() -> Result<(), Box<dyn Error>> {
    let target = MappingTarget::from_str("NAS.Home.")?;
    assert_eq!(
        target,
        MappingTarget::DnsAlias(RemapName::parse("nas.home")?)
    );
    Ok(())
}

#[test]
fn parses_http_routes_with_explicit_policy() -> Result<(), Box<dyn Error>> {
    let upstream = HttpUpstream::parse_with_policy(
        "https://Example.com:9443/base",
        HostHeaderPolicy::UseUpstream,
    )?;
    assert_eq!(upstream.scheme(), HttpScheme::Https);
    assert_eq!(
        upstream.host(),
        &UpstreamHost::Name(RemapName::parse("example.com")?)
    );
    assert_eq!(upstream.port().map(Into::into), Some(9443));
    assert_eq!(upstream.base_path(), "/base");
    assert_eq!(upstream.host_header_policy(), HostHeaderPolicy::UseUpstream);
    assert_eq!(upstream.to_string(), "https://example.com:9443/base");
    Ok(())
}

#[test]
fn http_routes_use_the_destination_host_by_default() -> Result<(), Box<dyn Error>> {
    let upstream = HttpUpstream::parse("http://127.0.0.1:4270")?;
    assert_eq!(upstream.host_header_policy(), HostHeaderPolicy::UseUpstream);
    Ok(())
}

#[test]
fn renders_bracketed_ipv6_upstreams() -> Result<(), Box<dyn Error>> {
    let upstream = HttpUpstream::parse("http://[2001:db8::1]:8080")?;
    assert_eq!(upstream.to_string(), "http://[2001:db8::1]:8080/");
    Ok(())
}

#[test]
fn rejects_credentials_queries_fragments_and_zero_ports() {
    assert!(HttpUpstream::parse("https://user@example.com").is_err());
    assert!(HttpUpstream::parse("https://example.com/?query=yes").is_err());
    assert!(HttpUpstream::parse("https://example.com/#fragment").is_err());
    assert!(HttpUpstream::parse("https://example.com:0").is_err());
    assert!(HttpUpstream::parse("https://example.com/a\r\nHost: evil").is_err());
    assert!(HttpUpstream::parse("https://example.com/a b").is_err());
}

#[test]
fn parses_supgang_peer_services_as_text() -> Result<(), Box<dyn Error>> {
    let target = MappingTarget::parse_with_http_policy(
        "supgang://MacSolis/dibs",
        HostHeaderPolicy::PreserveClient,
    )?;
    let MappingTarget::Peer(service) = &target else {
        return Err("a supgang:// target is a peer service".into());
    };
    assert_eq!(service.peer(), "MacSolis");
    assert_eq!(service.service(), "dibs");
    assert_eq!(
        service.host_header_policy(),
        HostHeaderPolicy::PreserveClient
    );
    assert_eq!(target.kind().as_str(), "peer");
    assert_eq!(target.to_string(), "supgang://MacSolis/dibs");
    // A fingerprint or a node id is a peer as much as a name is.
    assert!(MappingTarget::from_str("supgang://a8a37e32/remap").is_ok());
    assert!(MappingTarget::from_str(&format!("supgang://{}/dibs", "a".repeat(64))).is_ok());
    Ok(())
}

#[test]
fn rejects_supgang_targets_that_name_nothing_resolvable() {
    for invalid in [
        "supgang://",
        "supgang://MacSolis",
        "supgang:///dibs",
        "supgang://MacSolis/Dibs",
        "supgang://MacSolis/-dibs",
        "supgang://MacSolis/dibs/extra",
        "supgang://MacSolis/dibs?x",
        "supgang://--state-dir/dibs",
        "supgang://Mac Solis/dibs",
        "supgang://MacSolis/a-service-name-too-long",
    ] {
        assert!(
            MappingTarget::from_str(invalid).is_err(),
            "{invalid} was accepted"
        );
    }
}
