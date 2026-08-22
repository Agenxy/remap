import Foundation
@testable import RemapInstallKit
import Testing

@Test
func updatePreviewListsDeterministicCreateReplaceAndRemoveOwnership() throws {
    let previous = try previewManifest(
        generationID: "generation-1",
        previousGenerationID: nil,
        publications: [
            testPublication(path: "Public/removed", target: "/old/removed", generationID: "generation-1"),
            testPublication(path: "Public/shared", target: "/old/shared", generationID: "generation-1")
        ]
    )
    let current = try previewManifest(
        generationID: "generation-2",
        previousGenerationID: previous.generationID,
        publications: [
            testPublication(path: "Public/created", target: "/new/created", generationID: "generation-2"),
            testPublication(path: "Public/shared", target: "/new/shared", generationID: "generation-2")
        ]
    )
    let context = try InstallTransitionContext(operation: .update, current: current, previous: previous)
    let changes = try MacOSInstallerPublicationChange.changes(for: context)

    #expect(changes.map(\.path.description) == ["Public/created", "Public/removed", "Public/shared"])
    #expect(changes.map(\.action) == [.create, .remove, .replace])
    #expect(changes.map(\.previousGenerationID) == [nil, "generation-1", "generation-1"])
    #expect(changes.map(\.nextGenerationID) == ["generation-2", nil, "generation-2"])
}

@Test
func previewOmitsDirectoryPublicationsThatDoNotMutateTheFileSystem() throws {
    let previous = try previewManifest(
        generationID: "generation-1",
        previousGenerationID: nil,
        publications: [
            directoryPublication(path: "Public/owned", generationID: "generation-1"),
            directoryPublication(path: "Public/removed", generationID: "generation-1")
        ]
    )
    let current = try previewManifest(
        generationID: "generation-2",
        previousGenerationID: previous.generationID,
        publications: [
            directoryPublication(path: "Public/compatible", generationID: "generation-2"),
            directoryPublication(path: "Public/created", generationID: "generation-2"),
            directoryPublication(path: "Public/owned", generationID: "generation-2")
        ]
    )
    let context = try InstallTransitionContext(operation: .update, current: current, previous: previous)
    let changes = try MacOSInstallerPublicationChange.changes(for: context) {
        $0.path.description == "Public/compatible" ? .compatible : .missing
    }

    #expect(changes.map(\.path.description) == ["Public/created", "Public/removed"])
    #expect(changes.map(\.action) == [.create, .remove])
}

@Test
func previewRejectsMoreThanItsPublicationChangeBound() throws {
    let changes = try (0 ... MacOSInstallerPreview.maximumPublicationChanges).map { index in
        try MacOSInstallerPublicationChange(
            path: InstallRelativePath("Public/path-\(index)"),
            action: .create,
            previousGenerationID: nil,
            nextGenerationID: "generation-1"
        )
    }
    #expect(throws: InstallError.integrity("installer preview exceeds its deterministic bounds")) {
        try MacOSInstallerPreview(
            schemaVersion: 2,
            operation: .install,
            generationID: "generation-1",
            productVersion: "1.0.0",
            verifiedSourceEntries: 0,
            publicationChangeDetails: changes,
            pendingRecoveryTransactions: [],
            effects: ["publish"],
            approvalState: testApprovalState()
        )
    }
}

@Test
func approvalTokenIsCanonicalAndBindsEveryReviewedEffect() throws {
    let preview = try testApprovalPreview(effects: ["publish", "verify"])
    let repeated = try testApprovalPreview(effects: ["publish", "verify"])
    let changed = try testApprovalPreview(effects: ["publish", "restart"])
    let document = try #require(
        JSONSerialization.jsonObject(with: InstallCanonicalJSON.encoder.encode(preview)) as? [String: Any]
    )

    #expect(preview.approvalToken == repeated.approvalToken)
    #expect(preview.approvalToken != changed.approvalToken)
    #expect(document["approvalToken"] as? String == preview.approvalToken.description)
    // The expected value is a deterministic approval-token fixture.
    let expectedToken = "91ee8082ffe928af423dc25605e05477d6b59dafc7df57694a5c7e28d49f90b8" // gitleaks:allow
    #expect(preview.approvalToken.description == expectedToken)
}

@Test
func updatePreviewDisclosesTheExactPreviousGenerationPurge() {
    let effects = MacOSInstaller.previewEffects(previousGenerationID: "generation-1")

    #expect(effects.contains("purge previous generation generation-1"))
    #expect(effects.contains("keep ordinary internet DNS active while replacing Remap services"))
    #expect(effects.contains("preload and verify the new forwarding plan before reactivating Remap DNS"))
    #expect(!MacOSInstaller.previewEffects(previousGenerationID: nil).contains {
        $0.hasPrefix("purge previous generation ")
    })
}

private func previewManifest(
    generationID: String,
    previousGenerationID: String?,
    publications: [InstallPublication]
) throws -> InstallManifest {
    try InstallManifest(
        productIdentifier: "dev.agenxy.remap",
        generationID: generationID,
        productVersion: "1.0.0",
        previousGenerationID: previousGenerationID,
        entries: [],
        publications: publications
    )
}

private func directoryPublication(path: String, generationID: String) throws -> InstallPublication {
    try InstallPublication(
        path: InstallRelativePath(path),
        generationID: generationID,
        ownerUID: 0,
        groupGID: 0
    )
}

private func testApprovalPreview(effects: [String]) throws -> MacOSInstallerPreview {
    try MacOSInstallerPreview(
        schemaVersion: 2,
        operation: .install,
        generationID: "generation-1",
        productVersion: "1.0.0",
        verifiedSourceEntries: 1,
        publicationChangeDetails: [
            MacOSInstallerPublicationChange(
                path: InstallRelativePath("usr/local/bin/remap"),
                action: .create,
                previousGenerationID: nil,
                nextGenerationID: "generation-1"
            )
        ],
        pendingRecoveryTransactions: [],
        effects: effects,
        approvalState: testApprovalState()
    )
}

private func testApprovalState() throws -> MacOSInstallerApprovalState {
    try MacOSInstallerApprovalState(
        manifestDigest: InstallDigest(String(repeating: "1", count: 64)),
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
}
