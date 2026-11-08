// SPDX-License-Identifier: GPL-3.0-or-later
//! Which kind of package the active native installation came from (ADR-0035).
//!
//! The macOS portable installer records a rehearsal or development kind in the installed
//! generation's manifest, never in the signed release manifest. A release, and a build from
//! source, record nothing, so `remap doctor` says nothing more about them.

#[cfg(target_os = "macos")]
use std::io::Read;

use serde_json::Value;

/// The world-readable manifest of the generation `current` points at.
#[cfg(target_os = "macos")]
const ACTIVE_MANIFEST: &str =
    "/Library/Application Support/Agenxy/Remap/Install/current/.remap-install-manifest.json";
/// Matches the installer's bound on a canonical install manifest.
#[cfg(target_os = "macos")]
const MAXIMUM_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum InstalledPackage {
    Development,
    Rehearsal,
}

impl InstalledPackage {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Development => "development",
            Self::Rehearsal => "rehearsal",
        }
    }

    pub(crate) const fn description(self) -> &'static str {
        match self {
            Self::Development => "development install, built and signed on its own Mac",
            Self::Rehearsal => "rehearsal install, not a release",
        }
    }

    /// The kind an install manifest records, if it records one this CLI knows.
    pub(crate) fn from_manifest(document: &[u8]) -> Option<Self> {
        let value: Value = serde_json::from_slice(document).ok()?;
        match value.get("packageKind")?.as_str()? {
            "development" => Some(Self::Development),
            "rehearsal" => Some(Self::Rehearsal),
            _ => None,
        }
    }
}

/// The active installation's package kind, or `None` for a release, a source build, no
/// installation, or a manifest this process cannot read.
pub(crate) fn active() -> Option<InstalledPackage> {
    active_manifest()
        .as_deref()
        .and_then(InstalledPackage::from_manifest)
}

#[cfg(target_os = "macos")]
fn active_manifest() -> Option<Vec<u8>> {
    let file = std::fs::File::open(ACTIVE_MANIFEST).ok()?;
    let mut document = Vec::new();
    file.take(MAXIMUM_MANIFEST_BYTES + 1)
        .read_to_end(&mut document)
        .ok()?;
    (u64::try_from(document.len()).ok()? <= MAXIMUM_MANIFEST_BYTES).then_some(document)
}

/// Only the macOS portable installer records a package kind.
#[cfg(not(target_os = "macos"))]
const fn active_manifest() -> Option<Vec<u8>> {
    None
}

#[cfg(test)]
mod tests {
    use super::InstalledPackage;

    #[test]
    fn a_manifest_names_a_rehearsal_or_development_install() {
        let rehearsal = br#"{"generationID":"0.2.0-a","packageKind":"rehearsal"}"#;
        let development = br#"{"generationID":"0.2.0-a","packageKind":"development"}"#;
        assert_eq!(
            InstalledPackage::from_manifest(rehearsal),
            Some(InstalledPackage::Rehearsal)
        );
        assert_eq!(
            InstalledPackage::from_manifest(development),
            Some(InstalledPackage::Development)
        );
        assert_eq!(
            InstalledPackage::Rehearsal.description(),
            "rehearsal install, not a release"
        );
    }

    #[test]
    fn a_release_or_unreadable_manifest_names_nothing() {
        for document in [
            br#"{"generationID":"0.2.0-a"}"#.as_slice(),
            br#"{"packageKind":"release"}"#,
            br#"{"packageKind":7}"#,
            b"not json",
            b"",
        ] {
            assert_eq!(InstalledPackage::from_manifest(document), None);
        }
    }
}
