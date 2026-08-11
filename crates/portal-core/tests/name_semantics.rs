use std::error::Error;

use portal_core::{NamePattern, PortalName, PortalNameError};

#[test]
fn accepts_single_label_arbitrary_suffix_and_public_names() -> Result<(), Box<dyn Error>> {
    assert_eq!(PortalName::parse("atlas")?.as_str(), "atlas");
    assert_eq!(PortalName::parse("api.whatever")?.as_str(), "api.whatever");
    assert_eq!(PortalName::parse("google.com")?.as_str(), "google.com");
    Ok(())
}

#[test]
fn canonicalizes_case_and_the_dns_root_dot() -> Result<(), Box<dyn Error>> {
    assert_eq!(PortalName::parse("Atlas.DEV.")?.as_str(), "atlas.dev");
    Ok(())
}

#[test]
fn rejects_address_literals_as_source_names() {
    assert!(matches!(
        PortalName::parse("127.0.0.1"),
        Err(PortalNameError::AddressLiteral(_))
    ));
    assert!(matches!(
        PortalName::parse("::1"),
        Err(PortalNameError::AddressLiteral(_))
    ));
}

#[test]
fn wildcard_matches_descendants_but_not_its_suffix() -> Result<(), Box<dyn Error>> {
    let pattern = NamePattern::parse("*.lab")?;
    assert!(pattern.matches(&PortalName::parse("api.lab")?));
    assert!(pattern.matches(&PortalName::parse("deep.api.lab")?));
    assert!(!pattern.matches(&PortalName::parse("lab")?));
    assert!(!pattern.matches(&PortalName::parse("notlab")?));
    Ok(())
}
