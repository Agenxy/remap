use std::error::Error;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use portal_core::{
    HostHeaderPolicy, HttpScheme, HttpUpstream, MappingTarget, PortalName, UpstreamHost,
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
        MappingTarget::DnsAlias(PortalName::parse("nas.home")?)
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
        &UpstreamHost::Name(PortalName::parse("example.com")?)
    );
    assert_eq!(upstream.port().map(Into::into), Some(9443));
    assert_eq!(upstream.base_path(), "/base");
    assert_eq!(upstream.host_header_policy(), HostHeaderPolicy::UseUpstream);
    assert_eq!(upstream.to_string(), "https://example.com:9443/base");
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
}
