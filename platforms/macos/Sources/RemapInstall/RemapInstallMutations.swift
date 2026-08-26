import RemapInstallKit

extension RemapInstallCLI {
    static func executeRecoverAll(
        _ approvalToken: InstallApprovalToken
    ) async throws -> MacOSInstallerRecoveryResult {
        let installer = try MacOSInstaller.production()
        let preview = try installer.previewRecovery(transactionID: nil)
        try await RemapInstallUserPresence.authorize(
            reviewedToken: approvalToken,
            expectedToken: preview.approvalToken
        )
        return try await installer.recoverAll(approvalToken: approvalToken)
    }

    static func executeBootstrapRecovery(
        _ approvalToken: InstallApprovalToken
    ) async throws -> MacOSBootstrapHelperRecoveryResult {
        let recovery = try MacOSBootstrapHelperRecovery.production()
        let preview = try recovery.preview()
        try await RemapInstallUserPresence.authorize(
            reviewedToken: approvalToken,
            expectedToken: preview.approvalToken
        )
        return try recovery.recover(approvalToken: approvalToken)
    }

    static func executeRecovery(
        transactionID: String,
        approvalToken: InstallApprovalToken
    ) async throws {
        let installer = try MacOSInstaller.production()
        let preview = try installer.previewRecovery(transactionID: transactionID)
        try await RemapInstallUserPresence.authorize(
            reviewedToken: approvalToken,
            expectedToken: preview.approvalToken
        )
        try await installer.recover(
            transactionID: transactionID,
            approvalToken: approvalToken
        )
    }

    static func executeUninstall(
        transactionID: String,
        generationID: String,
        approvalToken: InstallApprovalToken
    ) async throws {
        let installer = try MacOSInstaller.production()
        let preview = try installer.previewUninstall(generationID: generationID)
        try await RemapInstallUserPresence.authorize(
            reviewedToken: approvalToken,
            expectedToken: preview.approvalToken
        )
        try await installer.uninstall(
            transactionID: transactionID,
            generationID: generationID,
            approvalToken: approvalToken
        )
    }
}
