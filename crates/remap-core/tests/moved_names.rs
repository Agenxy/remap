// SPDX-License-Identifier: GPL-3.0-or-later
//! Moved-name parsing, clock boundaries and immutable graph validation.

use remap_core::{Mapping, MappingTarget, MovedTarget, NamePattern, RegistrySnapshot, RemapName};

#[test]
fn review_default_resolve_observes_the_clock() -> Result<(), Box<dyn std::error::Error>> {
    let mapping = |name: &str, until: &str| -> Result<Mapping, Box<dyn std::error::Error>> {
        Ok(Mapping::new(
            NamePattern::parse(name)?,
            MappingTarget::Moved(MovedTarget::new("new.test", Some(until))?),
        ))
    };
    let snapshot = RegistrySnapshot::new(
        1,
        vec![
            mapping("active.test", "9999-12-31T23:59:59Z")?,
            mapping("expired.test", "2000-01-01T00:00:00Z")?,
        ],
    )?;
    let active = RemapName::parse("active.test")?;
    assert!(snapshot.resolve(&active).is_some());
    assert!(snapshot.resolve_at(&active, None).is_none());
    assert!(
        snapshot
            .resolve(&RemapName::parse("expired.test")?)
            .is_none()
    );
    Ok(())
}

#[test]
fn moved_expiry_is_exact_and_a_missing_clock_does_not_extend_it()
-> Result<(), Box<dyn std::error::Error>> {
    let moved = MovedTarget::new("New.TEST.", Some("1970-01-01T01:00:01+01:00"))?;
    assert_eq!(
        moved.to_string(),
        "moved://new.test?until=1970-01-01T00:00:01Z"
    );
    assert!(moved.active_at(Some(999_999_999)));
    assert!(!moved.active_at(Some(1_000_000_000)));
    assert!(!moved.active_at(None));
    let snapshot = RegistrySnapshot::new(
        1,
        vec![Mapping::new(
            NamePattern::parse("old.test")?,
            MappingTarget::Moved(moved),
        )],
    )?;
    let name = RemapName::parse("old.test")?;
    assert!(snapshot.resolve_at(&name, Some(999_999_999)).is_some());
    assert!(snapshot.resolve_at(&name, Some(1_000_000_000)).is_none());
    assert_eq!(snapshot.mappings().len(), 1);
    Ok(())
}

#[test]
fn moved_preserves_fractional_expiry_and_wide_rfc3339_dates()
-> Result<(), Box<dyn std::error::Error>> {
    let moved = MovedTarget::new("new.test", Some("1970-01-01T00:00:00.000000100Z"))?;
    assert!(moved.active_at(Some(99)));
    assert!(!moved.active_at(Some(100)));
    assert_eq!(
        moved.to_string(),
        "moved://new.test?until=1970-01-01T00:00:00.000000100Z"
    );
    let distant = MovedTarget::new("new.test", Some("9999-12-31T23:59:59Z"))?;
    assert!(distant.active_at(Some(253_402_300_798_999_999_999)));
    assert!(!distant.active_at(Some(253_402_300_799_000_000_000)));
    Ok(())
}

#[test]
fn moved_refuses_self_chains_and_invalid_inputs() -> Result<(), Box<dyn std::error::Error>> {
    for (name, until) in [
        ("//host", None),
        ("*.test", None),
        ("new.test", Some("tomorrow")),
        ("new.test", Some("2026-10-25T10:00:00")),
    ] {
        assert!(MovedTarget::new(name, until).is_err());
    }
    let mapping = |name: &str, target: &str| -> Result<Mapping, Box<dyn std::error::Error>> {
        Ok(Mapping::new(NamePattern::parse(name)?, target.parse()?))
    };
    assert!(RegistrySnapshot::new(1, vec![mapping("old.test", "moved://old.test")?]).is_err());
    assert!(
        RegistrySnapshot::new(
            1,
            vec![
                mapping("old.test", "moved://new.test")?,
                mapping("new.test", "moved://third.test")?
            ]
        )
        .is_err()
    );
    Ok(())
}
