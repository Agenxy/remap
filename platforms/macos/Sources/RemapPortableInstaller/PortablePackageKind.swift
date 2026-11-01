// SPDX-License-Identifier: GPL-3.0-or-later
import RemapInstallKit

/// The kind of package this installer was compiled for, and so the only kind it can install.
///
/// It is the same compile-time choice that selects the one pin in `PortableReleaseVerifier`, so
/// it cannot disagree with the key that verified the release. It is recorded in the installed
/// generation, never in the signed release manifest, whose format is unchanged (ADR-0035).
enum PortablePackageKind {
    #if REMAP_DEVELOPMENT_PACKAGE
        static let compiled: InstallPackageKind? = .development
    #elseif REMAP_REHEARSAL_PACKAGE
        static let compiled: InstallPackageKind? = .rehearsal
    #else
        static let compiled: InstallPackageKind? = nil
    #endif

    /// What the installer says before it changes anything, when this is not a release.
    static func announcement(for kind: InstallPackageKind?, productVersion: String) -> String? {
        switch kind {
        case .rehearsal:
            "This is a rehearsal of Remap \(productVersion), not a release. Do not keep it as a "
                + "release; a production release replaces it as an ordinary update"
        case .development:
            "This is a development package of Remap \(productVersion), built and signed on "
                + "its own Mac, not a release"
        case nil:
            nil
        }
    }

    /// The name the finished install is reported under.
    static func installedName(for kind: InstallPackageKind?, productVersion: String) -> String {
        switch kind {
        case .rehearsal: "Remap \(productVersion) (rehearsal, not a release)"
        case .development: "Remap \(productVersion) (development)"
        case nil: "Remap \(productVersion)"
        }
    }
}
