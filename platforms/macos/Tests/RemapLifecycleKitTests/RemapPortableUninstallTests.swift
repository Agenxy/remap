import Foundation
@testable import RemapInstallKit
@testable import RemapLifecycleKit
import Testing

@Test
func portableUninstallTokenBindsProductAndAuthorityState() throws {
    let first = try portablePreview(sourceDigest: String(repeating: "a", count: 64))
    let repeated = try portablePreview(sourceDigest: String(repeating: "a", count: 64))
    let changed = try portablePreview(sourceDigest: String(repeating: "b", count: 64))

    #expect(first == repeated)
    #expect(first.approvalToken != changed.approvalToken)
    #expect(first.effects.suffix(4) == [
        "Remove Remap's locally signed installer source package.",
        "Remove Remap's privileged lifecycle service and launchd registration.",
        "Remove Remap's private installer storage; keep its empty transaction lock.",
        "Remove Remap from macOS's installed-package records."
    ])
}

@Test
func portableUninstallPreviewRoundTripsCanonically() throws {
    let preview = try portablePreview(sourceDigest: String(repeating: "c", count: 64))
    let response = try RemapLifecycleResponse.success(
        action: .previewUninstall,
        uninstallPreview: preview
    )
    let encoded = try RemapLifecycleCoding.encodeResponse(response)
    #expect(try RemapLifecycleCoding.decodeResponse(encoded) == response)
}

private func portablePreview(sourceDigest: String) throws -> RemapLifecycleUninstallPreview {
    let digest = try InstallDigest(sourceDigest)
    let files = try MacOSPortableAuthorityFileState.specifications.map { path, mode in
        try MacOSPortableAuthorityFileState(
            path: InstallRelativePath(path),
            sha256: InstallDigest(String(repeating: path.contains("service-v1") ? "1" : "2", count: 64)),
            byteCount: 128,
            mode: mode
        )
    }
    let state = try MacOSPortableAuthorityCleanupState(
        sourcePackageRoot: InstallAbsolutePath(
            "/" + MacOSPortableAuthorityCleanupState.sourcesPathString + "/\(digest)"
        ),
        sourceManifestDigest: digest,
        files: files
    )
    let product = try MacOSInstallerPreview(
        schemaVersion: 2,
        operation: .uninstall,
        generationID: "generation-1",
        productVersion: "0.2.0",
        verifiedSourceEntries: 1,
        publicationChangeDetails: [],
        pendingRecoveryTransactions: [],
        effects: ["remove the installed Remap generation"],
        approvalState: MacOSInstallerApprovalState(
            manifestDigest: InstallDigest(String(repeating: "3", count: 64)),
            previousManifestDigest: nil,
            activeGenerationID: nil,
            installedGenerations: [],
            publicationStates: [],
            services: [],
            dns: MacOSInstallerDNSStatus(
                active: false,
                productVersion: nil,
                configuredServiceCount: 0,
                effectiveRemapServiceCount: 0
            )
        )
    )
    return try RemapLifecycleUninstallPreview(
        productPreview: product,
        authorityState: state
    )
}
