// SPDX-License-Identifier: GPL-3.0-or-later
//! Executable specifications for peer targets that read labels from the
//! name a client asked for (ADR-0032).

use std::error::Error;

use remap_core::{
    HostHeaderPolicy, Mapping, MappingTarget, NamePattern, PeerService, PeerServiceError,
    RegistrySnapshot, RemapName, SnapshotError, TemplateNameError,
};

type TestResult = Result<(), Box<dyn Error>>;

fn mapping(pattern: &str, target: &str) -> Result<Mapping, Box<dyn Error>> {
    Ok(Mapping::new(
        NamePattern::parse(pattern)?,
        MappingTarget::parse_with_http_policy(target, HostHeaderPolicy::UseUpstream)?,
    ))
}

fn routed(mapping: &Mapping, name: &str) -> Result<String, Box<dyn Error>> {
    Ok(mapping.target_for(&RemapName::parse(name)?)?.to_string())
}

// `{1}` is the label nearest the wildcard's suffix and `{2}` the next one, so
// `<service>.<peer>.<suffix>` reads outward from the suffix like DNS does.
#[test]
fn a_template_reads_labels_outward_from_the_suffix() -> TestResult {
    let both = mapping("*.k7.internal", "supgang://{1}/{2}")?;
    assert_eq!(
        routed(&both, "preview.solis.k7.internal")?,
        "supgang://solis/preview"
    );
    assert_eq!(
        routed(&both, "Preview.SOLIS.k7.internal.")?,
        "supgang://solis/preview"
    );

    let service = mapping("*.solis.test", "supgang+http://solis/{1}")?;
    assert_eq!(
        routed(&service, "dibs.solis.test")?,
        "supgang+http://solis/dibs"
    );

    let peer = mapping("*.hub", "supgang://{1}/dibs")?;
    assert_eq!(routed(&peer, "solis.hub")?, "supgang://solis/dibs");
    Ok(())
}

// A template keeps its text, so it is stored and shown exactly as written,
// and a literal target routes every name to itself.
#[test]
fn a_template_is_stored_as_written_and_literals_are_unchanged() -> TestResult {
    let template = mapping("*.k7.internal", "supgang://{2}/{1}")?;
    assert_eq!(template.target().to_string(), "supgang://{2}/{1}");
    assert_eq!(template.target().template_arity(), Some(2));
    assert_eq!(
        routed(&template, "solis.preview.k7.internal")?,
        "supgang://solis/preview"
    );

    let literal = mapping("*.lab", "supgang://solis/preview")?;
    assert_eq!(literal.target().template_arity(), None);
    assert_eq!(routed(&literal, "a.b.c.lab")?, "supgang://solis/preview");
    Ok(())
}

// A name with another number of labels, or a label its field cannot hold, is
// refused with the reason; it is never shortened, padded, or routed elsewhere.
#[test]
fn a_name_that_cannot_fill_the_template_is_refused() -> TestResult {
    let both = mapping("*.k7.internal", "supgang://{1}/{2}")?;
    for (name, expected, found) in [
        ("solis.k7.internal", 2, 1),
        ("deep.preview.solis.k7.internal", 2, 3),
    ] {
        assert_eq!(
            both.target_for(&RemapName::parse(name)?),
            Err(TemplateNameError::LabelCount { expected, found }),
            "{name}"
        );
    }
    assert!(matches!(
        both.target_for(&RemapName::parse(
            "a-service-name-too-long.solis.k7.internal"
        )?),
        Err(TemplateNameError::Field(PeerServiceError::InvalidService(
            _
        )))
    ));
    Ok(())
}

// Only a whole `{1}` or `{2}` field is a placeholder, every capture a template
// reads must be used, and a brace is never part of a literal peer selector.
#[test]
fn only_whole_contiguous_placeholders_are_templates() {
    for target in [
        "supgang://{0}/preview",
        "supgang://{3}/preview",
        "supgang://{01}/preview",
        "supgang://{1/preview",
        "supgang://solis/{2}",
        "supgang://{2}/{2}",
        "supgang://so{1}/preview",
    ] {
        assert!(
            PeerService::parse_with_policy(target, HostHeaderPolicy::UseUpstream).is_err(),
            "{target}"
        );
    }
    assert!(matches!(
        PeerService::parse_with_policy("supgang://solis/x{1}", HostHeaderPolicy::UseUpstream),
        Err(PeerServiceError::InvalidService(_))
    ));
    assert!(
        PeerService::parse_with_policy("supgang://{1}/{1}", HostHeaderPolicy::UseUpstream).is_ok()
    );
}

// An exact name has no labels to fill a template, so a revision that pairs
// them is refused rather than routed to a literal `{1}`.
#[test]
fn a_template_on_an_exact_name_is_refused() -> TestResult {
    let exact = mapping("preview.test", "supgang://{1}/preview")?;
    assert_eq!(
        RegistrySnapshot::new(1, vec![exact]),
        Err(SnapshotError::TemplateNeedsWildcard(NamePattern::parse(
            "preview.test"
        )?))
    );
    Ok(())
}

// A template changes what a matched name routes to, never what it matches:
// exact names and more specific wildcards still win, and DNS still owns
// every descendant of the owner's suffix.
#[test]
fn a_template_does_not_change_precedence() -> TestResult {
    let snapshot = RegistrySnapshot::new(
        1,
        vec![
            mapping("*.k7.internal", "supgang://{1}/{2}")?,
            mapping("*.solis.k7.internal", "supgang://solis/{1}")?,
            mapping("docs.solis.k7.internal", "http://127.0.0.1:8080")?,
        ],
    )?;
    let resolve = |name: &str| -> Result<String, Box<dyn Error>> {
        let name = RemapName::parse(name)?;
        let mapping = snapshot.resolve(&name).ok_or("unmatched")?;
        Ok(mapping.target_for(&name)?.to_string())
    };
    assert_eq!(resolve("docs.solis.k7.internal")?, "http://127.0.0.1:8080/");
    assert_eq!(
        resolve("preview.solis.k7.internal")?,
        "supgang://solis/preview"
    );
    assert_eq!(
        resolve("preview.luna.k7.internal")?,
        "supgang://luna/preview"
    );
    let deep = RemapName::parse("a.b.c.k7.internal")?;
    assert!(
        snapshot.resolve(&deep).is_some(),
        "the wildcard still owns the name"
    );
    Ok(())
}
