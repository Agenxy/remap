use std::error::Error;
use std::str::FromStr;

use portal_core::{Mapping, MappingTarget, NamePattern, PortalName, RegistrySnapshot};

fn mapping(pattern: &str, target: &str) -> Result<Mapping, Box<dyn Error>> {
    Ok(Mapping::new(
        NamePattern::parse(pattern)?,
        MappingTarget::from_str(target)?,
    ))
}

#[test]
fn exact_mapping_precedes_wildcards() -> Result<(), Box<dyn Error>> {
    let snapshot = RegistrySnapshot::new(
        7,
        vec![
            mapping("*.lab", "10.0.0.1")?,
            mapping("api.lab", "10.0.0.2")?,
        ],
    )?;
    let resolved = snapshot
        .resolve(&PortalName::parse("api.lab")?)
        .ok_or("api.lab should resolve")?;
    assert_eq!(resolved.target().to_string(), "10.0.0.2");
    Ok(())
}

#[test]
fn most_specific_wildcard_precedes_broader_suffix() -> Result<(), Box<dyn Error>> {
    let snapshot = RegistrySnapshot::new(
        8,
        vec![
            mapping("*.lab", "10.0.0.1")?,
            mapping("*.dev.lab", "10.0.0.2")?,
        ],
    )?;
    let resolved = snapshot
        .resolve(&PortalName::parse("api.dev.lab")?)
        .ok_or("api.dev.lab should resolve")?;
    assert_eq!(resolved.target().to_string(), "10.0.0.2");
    Ok(())
}

#[test]
fn disabled_mapping_does_not_claim_a_name() -> Result<(), Box<dyn Error>> {
    let snapshot =
        RegistrySnapshot::new(9, vec![mapping("atlas", "127.0.0.1")?.with_enabled(false)])?;
    assert!(snapshot.resolve(&PortalName::parse("atlas")?).is_none());
    Ok(())
}

#[test]
fn duplicate_patterns_are_rejected() -> Result<(), Box<dyn Error>> {
    let result = RegistrySnapshot::new(
        10,
        vec![
            mapping("atlas", "127.0.0.1")?,
            mapping("ATLAS", "127.0.0.2")?,
        ],
    );
    assert!(result.is_err());
    Ok(())
}
