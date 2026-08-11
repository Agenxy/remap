//! Executable specifications for Remap lookup-name semantics.

use std::error::Error;

use remap_core::{NamePattern, RemapName, RemapNameError};

#[test]
fn accepts_single_label_arbitrary_suffix_and_public_names() -> Result<(), Box<dyn Error>> {
    assert_eq!(RemapName::parse("atlas")?.as_str(), "atlas");
    assert_eq!(RemapName::parse("api.whatever")?.as_str(), "api.whatever");
    assert_eq!(RemapName::parse("google.com")?.as_str(), "google.com");
    Ok(())
}

#[test]
fn canonicalizes_case_and_the_dns_root_dot() -> Result<(), Box<dyn Error>> {
    assert_eq!(RemapName::parse("Atlas.DEV.")?.as_str(), "atlas.dev");
    Ok(())
}

#[test]
fn rejects_address_literals_as_source_names() {
    assert!(matches!(
        RemapName::parse("127.0.0.1"),
        Err(RemapNameError::AddressLiteral(_))
    ));
    assert!(matches!(
        RemapName::parse("::1"),
        Err(RemapNameError::AddressLiteral(_))
    ));
}

#[test]
fn wildcard_matches_descendants_but_not_its_suffix() -> Result<(), Box<dyn Error>> {
    let pattern = NamePattern::parse("*.lab")?;
    assert!(pattern.matches(&RemapName::parse("api.lab")?));
    assert!(pattern.matches(&RemapName::parse("deep.api.lab")?));
    assert!(!pattern.matches(&RemapName::parse("lab")?));
    assert!(!pattern.matches(&RemapName::parse("notlab")?));
    Ok(())
}
