import Foundation
import RemapInstallKit

public struct RemapLifecycleUninstallPreview: Codable, Equatable, Sendable {
    public let schemaVersion: UInt32
    public let generationID: String
    public let productPreview: MacOSInstallerPreview
    public let authorityState: MacOSPortableAuthorityCleanupState
    public let effects: [String]
    public let approvalToken: InstallApprovalToken

    public init(
        productPreview: MacOSInstallerPreview,
        authorityState: MacOSPortableAuthorityCleanupState
    ) throws {
        guard productPreview.operation == .uninstall,
              !productPreview.generationID.isEmpty
        else {
            throw InstallError.integrity("portable uninstall preview is malformed")
        }
        let effects = productPreview.effects + [
            "Remove Remap's locally signed installer source package.",
            "Remove Remap's privileged lifecycle service and launchd registration.",
            "Remove Remap's private installer storage; keep its empty transaction lock.",
            "Remove Remap from macOS's installed-package records."
        ]
        guard effects.count <= 20,
              effects.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 160 })
        else {
            throw InstallError.integrity("portable uninstall effects exceed their bound")
        }
        schemaVersion = 1
        generationID = productPreview.generationID
        self.productPreview = productPreview
        self.authorityState = authorityState
        self.effects = effects
        let payload = RemapLifecycleUninstallApprovalPayload(
            schemaVersion: 1,
            generationID: productPreview.generationID,
            productApprovalToken: productPreview.approvalToken,
            authorityState: authorityState,
            effects: effects
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        var data = Data("org.agenxy.remap.portable-uninstall-approval.v1\0".utf8)
        try data.append(encoder.encode(payload))
        approvalToken = try InstallApprovalToken(InstallDigest.hash(data).description)
    }

    public func validate() throws {
        let rebuilt = try Self(
            productPreview: productPreview,
            authorityState: authorityState
        )
        guard schemaVersion == 1, rebuilt == self else {
            throw InstallError.integrity("portable uninstall preview is not canonical")
        }
    }
}

private struct RemapLifecycleUninstallApprovalPayload: Codable {
    let schemaVersion: UInt32
    let generationID: String
    let productApprovalToken: InstallApprovalToken
    let authorityState: MacOSPortableAuthorityCleanupState
    let effects: [String]
}

protocol RemapPortableAuthorityLease: AnyObject, Sendable {}

private final class RemapPortableProductionLease: RemapPortableAuthorityLease, @unchecked Sendable {
    private let lock: MacOSPortableAuthorityLock

    init(_ lock: MacOSPortableAuthorityLock) {
        self.lock = lock
    }
}

struct RemapPortableUninstaller: Sendable {
    private let installer: MacOSInstaller
    private let configuration: RemapLifecycleServiceConfiguration
    private let cleanup: MacOSPortableAuthorityCleanup
    private let acquireLease: @Sendable () throws -> any RemapPortableAuthorityLease

    static func production(
        installer: MacOSInstaller,
        configuration: RemapLifecycleServiceConfiguration
    ) throws -> Self {
        try Self(
            installer: installer,
            configuration: configuration,
            cleanup: MacOSPortableAuthorityCleanup.production(),
            acquireLease: {
                try RemapPortableProductionLease(MacOSPortableAuthorityLock.acquire())
            }
        )
    }

    init(
        installer: MacOSInstaller,
        configuration: RemapLifecycleServiceConfiguration,
        cleanup: MacOSPortableAuthorityCleanup,
        acquireLease: @escaping @Sendable () throws -> any RemapPortableAuthorityLease
    ) {
        self.installer = installer
        self.configuration = configuration
        self.cleanup = cleanup
        self.acquireLease = acquireLease
    }

    func preview(generationID: String) throws -> RemapLifecycleUninstallPreview {
        try RemapLifecycleUninstallPreview(
            productPreview: installer.previewUninstall(generationID: generationID),
            authorityState: MacOSPortableAuthorityCleanupState.capture(
                sourcePackageRoot: configuration.sourcePackageRoot,
                sourceManifestDigest: configuration.sourceManifestDigest
            )
        )
    }

    func uninstall(
        transactionID: String,
        generationID: String,
        approvalToken: InstallApprovalToken
    ) async throws {
        let lease = try acquireLease()
        _ = lease
        let approved = try preview(generationID: generationID)
        guard approved.approvalToken == approvalToken else {
            throw InstallError.approval("the portable uninstall preview changed")
        }
        _ = try cleanup.reconcilePendingPlan()
        try cleanup.prepare(MacOSPortableAuthorityCleanupPlan(
            transactionID: transactionID,
            approvalToken: approvalToken,
            generationID: generationID,
            productApprovalToken: approved.productPreview.approvalToken,
            state: approved.authorityState
        ))
        do {
            try await installer.uninstall(
                transactionID: transactionID,
                generationID: generationID,
                approvalToken: approved.productPreview.approvalToken
            )
        } catch {
            if (try? cleanup.validatePendingPlan(expectedApprovalToken: approvalToken)) != nil {
                return
            }
            throw error
        }
    }
}

public struct RemapPortableAuthorityCleanupScheduler: Sendable {
    public init() {}

    public func schedule(approvalToken: InstallApprovalToken) {
        DispatchQueue.global(qos: .utility).async {
            do {
                try RemapPortableCleanupFinisher.launch(approvalToken: approvalToken)
            } catch {
                // The canonical plan is intentionally retained for exact recovery
                // by the next locally authenticated installer invocation.
            }
        }
    }
}
