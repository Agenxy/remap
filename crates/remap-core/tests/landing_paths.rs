// SPDX-License-Identifier: GPL-3.0-or-later
//! Adversarial same-origin redirect boundaries.

use remap_core::{LandingPath, MAX_LANDING_BYTES, MappingTarget};

#[test]
fn landing_rejects_ambiguous_and_encoded_redirects() {
    for path in [
        "",
        "/",
        "/?loop=1",
        "/./",
        "//host/page",
        "/\\host/page",
        "https://host/page",
        "/../page",
        "/%2e%2e/page",
        "/%2fhost/page",
        "/%5chost/page",
        "/page#fragment",
        "/page\r\nLocation:bad",
        "/%0d%0aheader",
        "/%",
        "/%xy",
        "/raw space",
        "/café",
    ] {
        assert!(LandingPath::parse(path).is_err(), "accepted {path:?}");
    }
    assert!(LandingPath::parse(&format!("/{}", "x".repeat(MAX_LANDING_BYTES))).is_err());
}

#[test]
fn landing_preserves_encoding_bounds_and_queries() -> Result<(), Box<dyn std::error::Error>> {
    let bound = format!("/{}", "x".repeat(MAX_LANDING_BYTES - 1));
    assert_eq!(LandingPath::parse(&bound)?.as_str(), bound);
    let path = LandingPath::parse("/caf%C3%A9/?view=all")?;
    assert_eq!(
        path.location(Some("q=a%2Fb&empty=")),
        "/caf%C3%A9/?view=all&q=a%2Fb&empty="
    );
    assert_eq!(path.location(None), path.as_str());
    assert!(
        path.validate_target(&"supgang://solis/preview".parse::<MappingTarget>()?)
            .is_ok()
    );
    assert!(
        path.validate_target(&"supgang+http://solis/preview".parse::<MappingTarget>()?)
            .is_ok()
    );
    Ok(())
}
