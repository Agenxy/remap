import Foundation
import RemapInstallKit

public struct RemapLifecycleExecutor: Sendable {
    private let installer: MacOSInstaller
    private let bootstrapRecovery: MacOSBootstrapHelperRecovery
    private let configuredSource: RemapLifecycleConfiguredSource?
    private let portableUninstaller: RemapPortableUninstaller?

    public static func production() throws -> Self {
        try Self(
            installer: MacOSInstaller.production(),
            bootstrapRecovery: MacOSBootstrapHelperRecovery.production(),
            configuredSource: nil,
            portableUninstaller: nil
        )
    }

    public static func production(
        configuration: RemapLifecycleServiceConfiguration
    ) throws -> Self {
        let installer = try MacOSInstaller.production()
        return try Self(
            installer: installer,
            bootstrapRecovery: MacOSBootstrapHelperRecovery.production(),
            configuredSource: RemapLifecycleConfiguredSource(
                packageRoot: configuration.sourcePackageRoot,
                manifestDigest: configuration.sourceManifestDigest,
                sourceUID: 0
            ),
            portableUninstaller: RemapPortableUninstaller.production(
                installer: installer,
                configuration: configuration
            )
        )
    }

    public init(
        installer: MacOSInstaller,
        bootstrapRecovery: MacOSBootstrapHelperRecovery,
        configuredSource: RemapLifecycleConfiguredSource? = nil
    ) {
        self.installer = installer
        self.bootstrapRecovery = bootstrapRecovery
        self.configuredSource = configuredSource
        portableUninstaller = nil
    }

    init(
        installer: MacOSInstaller,
        bootstrapRecovery: MacOSBootstrapHelperRecovery,
        configuredSource: RemapLifecycleConfiguredSource?,
        portableUninstaller: RemapPortableUninstaller?
    ) {
        self.installer = installer
        self.bootstrapRecovery = bootstrapRecovery
        self.configuredSource = configuredSource
        self.portableUninstaller = portableUninstaller
    }

    public func execute(
        _ request: RemapLifecycleRequest,
        sourceUID: UInt32
    ) async -> RemapLifecycleResponse {
        do {
            try request.validate()
            return try await perform(request, sourceUID: sourceUID)
        } catch {
            return .failure(
                action: request.action,
                diagnostic: diagnostic(error)
            )
        }
    }

    private func perform(
        _ request: RemapLifecycleRequest,
        sourceUID: UInt32
    ) async throws -> RemapLifecycleResponse {
        switch request.action {
        case .status:
            return try .success(action: .status, status: installer.status())
        case .previewInstall:
            return try .success(
                action: .previewInstall,
                preview: preview(.install, request: request, sourceUID: sourceUID)
            )
        case .previewUpdate:
            return try .success(
                action: .previewUpdate,
                preview: preview(.update, request: request, sourceUID: sourceUID)
            )
        case .previewUninstall:
            if let portableUninstaller {
                return try .success(
                    action: .previewUninstall,
                    uninstallPreview: portableUninstaller.preview(
                        generationID: required(request.generationID, field: "generation ID")
                    )
                )
            }
            return try .success(
                action: .previewUninstall,
                preview: installer.previewUninstall(
                    generationID: required(request.generationID, field: "generation ID")
                )
            )
        case .previewRecover:
            return try .success(
                action: .previewRecover,
                recoveryPreview: installer.previewRecovery(transactionID: request.transactionID)
            )
        case .previewRecoverBootstrapHelpers:
            return try .success(
                action: .previewRecoverBootstrapHelpers,
                bootstrapRecoveryPreview: bootstrapRecovery.preview()
            )
        case .install, .update:
            let operation: InstallOperation = request.action == .install ? .install : .update
            let package = try sourcePackage(request, sourceUID: sourceUID)
            let transactionID = request.transactionID ?? generatedTransactionID(operation.rawValue)
            try await installer.installOrUpdate(
                operation: operation,
                transactionID: transactionID,
                manifest: package.manifest,
                source: package.source,
                approvalToken: required(request.approvalToken, field: "approval token")
            )
            return try .success(
                action: request.action,
                mutation: RemapLifecycleMutationResult(
                    generationID: package.manifest.generationID,
                    transactionID: transactionID
                )
            )
        case .uninstall:
            let generationID = try required(request.generationID, field: "generation ID")
            let transactionID = request.transactionID ?? generatedTransactionID("uninstall")
            let approvalToken = try required(request.approvalToken, field: "approval token")
            if let portableUninstaller {
                try await portableUninstaller.uninstall(
                    transactionID: transactionID,
                    generationID: generationID,
                    approvalToken: approvalToken
                )
            } else {
                try await installer.uninstall(
                    transactionID: transactionID,
                    generationID: generationID,
                    approvalToken: approvalToken
                )
            }
            return try .success(
                action: .uninstall,
                mutation: RemapLifecycleMutationResult(
                    generationID: generationID,
                    transactionID: transactionID,
                    authorityCleanupPending: portableUninstaller == nil ? nil : true
                )
            )
        case .recover:
            let token = try required(request.approvalToken, field: "approval token")
            if let transactionID = request.transactionID {
                try await installer.recover(
                    transactionID: transactionID,
                    approvalToken: token
                )
                return try .success(
                    action: .recover,
                    recovery: MacOSInstallerRecoveryResult(
                        schemaVersion: 1,
                        recoveredTransactions: [transactionID],
                        quarantinedOrphans: []
                    )
                )
            }
            return try await .success(
                action: .recover,
                recovery: installer.recoverAll(approvalToken: token)
            )
        case .recoverBootstrapHelpers:
            return try .success(
                action: .recoverBootstrapHelpers,
                bootstrapRecovery: bootstrapRecovery.recover(
                    approvalToken: required(request.approvalToken, field: "approval token")
                )
            )
        }
    }

    private func preview(
        _ operation: InstallOperation,
        request: RemapLifecycleRequest,
        sourceUID: UInt32
    ) throws -> MacOSInstallerPreview {
        let package = try sourcePackage(request, sourceUID: sourceUID)
        return try installer.preview(
            operation: operation,
            manifest: package.manifest,
            source: package.source
        )
    }

    private func sourcePackage(
        _ request: RemapLifecycleRequest,
        sourceUID: UInt32
    ) throws -> MacOSInstallSourcePackage {
        if let configuredSource {
            guard request.packageRoot == nil, request.manifestDigest == nil else {
                throw InstallError.approval(
                    "the application cannot replace the root-owned lifecycle source package"
                )
            }
            return try MacOSInstallSourcePackage(
                rootPath: configuredSource.packageRoot.description,
                expectedManifestDigest: configuredSource.manifestDigest.description,
                sourceUID: configuredSource.sourceUID
            )
        }
        return try MacOSInstallSourcePackage(
            rootPath: required(request.packageRoot, field: "package root"),
            expectedManifestDigest: required(
                request.manifestDigest,
                field: "manifest digest"
            ).description,
            sourceUID: sourceUID
        )
    }

    private func required<Value>(_ value: Value?, field: String) throws -> Value {
        guard let value else {
            throw InstallError.integrity("lifecycle request omitted its (field)")
        }
        return value
    }

    private func generatedTransactionID(_ prefix: String) -> String {
        "\(prefix)-\(UUID().uuidString.lowercased())"
    }

    private func diagnostic(_ error: any Error) -> RemapLifecycleDiagnostic {
        let category: RemapLifecycleDiagnosticCategory
        let hint: String
        let retryable: Bool
        switch error {
        case InstallError.notRoot:
            category = .authority
            hint = "Repair the native Remap installer service, then retry."
            retryable = false
        case InstallError.alreadyLocked:
            category = .busy
            hint = "Wait for the current lifecycle operation to finish, then refresh."
            retryable = true
        case InstallError.approval:
            category = .approval
            hint = "Refresh the exact preview before approving this operation."
            retryable = true
        case InstallError.collision:
            category = .conflict
            hint = "Inspect the conflicting path; Remap will not overwrite unowned state."
            retryable = false
        case InstallError.unsupported:
            category = .unsupported
            hint = "Update Remap before retrying this lifecycle operation."
            retryable = false
        case is InstallError:
            category = .integrity
            hint = "Run the approved Remap recovery flow before retrying."
            retryable = false
        default:
            category = .internalFailure
            hint = "Refresh Remap. If this persists, inspect the local diagnostic."
            retryable = true
        }
        return RemapLifecycleDiagnostic(
            category: category,
            message: String(describing: error),
            hint: hint,
            retryable: retryable
        )
    }
}

public struct RemapLifecycleConfiguredSource: Sendable {
    public let packageRoot: InstallAbsolutePath
    public let manifestDigest: InstallDigest
    public let sourceUID: UInt32

    public init(
        packageRoot: InstallAbsolutePath,
        manifestDigest: InstallDigest,
        sourceUID: UInt32
    ) {
        self.packageRoot = packageRoot
        self.manifestDigest = manifestDigest
        self.sourceUID = sourceUID
    }
}
