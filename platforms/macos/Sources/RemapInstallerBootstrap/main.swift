import Foundation
import RemapInstallKit
import RemapLifecycleKit

@main
enum RemapInstallerBootstrapMain {
    static func main() async {
        do {
            try await run()
        } catch {
            let detail = if let installError = error as? InstallError {
                installError.description
            } else if let bootstrapError = error as? RemapInstallerBootstrapFailure {
                bootstrapError.description
            } else {
                String(reflecting: type(of: error))
            }
            FileHandle.standardError.write(
                Data("Remap installer bootstrap failed safely: \(detail)\n".utf8)
            )
            exit(EXIT_FAILURE)
        }
    }

    private static func run() async throws {
        guard geteuid() == 0 else {
            throw RemapInstallerBootstrapFailure.rootAuthorityRequired
        }
        let invocation = try RemapInstallerInvocation(
            arguments: CommandLine.arguments,
            environment: ProcessInfo.processInfo.environment
        )
        FileHandle.standardError.write(
            Data(
                "Remap installer invocation validated: script=\(invocation.script.rawValue) "
                    .appending("argumentCount=\(invocation.argumentCount)\n")
                    .utf8
            )
        )
        if invocation.script == .preinstall {
            try RemapLifecyclePackagePreflight.production().validateCleanInstall()
            return
        }
        let configuration = try RemapLifecycleServiceConfiguration.production()
        try RemapLifecycleBootstrapper.production(
            configuration: configuration
        ).bootstrap()
        report("lifecycle service verified and loaded")
        let executor = try RemapLifecycleExecutor.production(configuration: configuration)
        try await installOrUpdateConfiguredProduct(
            executor: executor,
            ownerUID: configuration.ownerUID
        )
    }

    private static func installOrUpdateConfiguredProduct(
        executor: RemapLifecycleExecutor,
        ownerUID: UInt32
    ) async throws {
        try await recoverConfiguredInstallerState(
            executor: executor,
            ownerUID: ownerUID
        )
        let status = try await successfulStatus(
            executor.execute(
                RemapLifecycleRequest(action: .status),
                sourceUID: ownerUID
            )
        )
        let operation: RemapLifecycleAction = status.activeGenerationID == nil ? .install : .update
        let previewAction: RemapLifecycleAction = operation == .install ? .previewInstall : .previewUpdate
        let preview = try await successfulPreview(
            executor.execute(
                RemapLifecycleRequest(action: previewAction),
                sourceUID: ownerUID
            ),
            action: previewAction
        )
        let transactionID = "package-\(operation.rawValue)-\(UUID().uuidString.lowercased())"
        let result = try await executor.execute(
            RemapLifecycleRequest(
                action: operation,
                transactionID: transactionID,
                approvalToken: preview.approvalToken
            ),
            sourceUID: ownerUID
        )
        guard result.outcome == .success,
              result.action == operation,
              result.mutation?.generationID == preview.generationID
        else {
            throw RemapInstallerBootstrapFailure.lifecycleFailure(result.diagnostic)
        }
        let finalStatus = try await successfulStatus(
            executor.execute(
                RemapLifecycleRequest(action: .status),
                sourceUID: ownerUID
            )
        )
        guard finalStatus.activeGenerationID == preview.generationID else {
            throw RemapInstallerBootstrapFailure.incompleteInstallation(
                "the committed generation is not active"
            )
        }
        guard finalStatus.transactions.allSatisfy({ !$0.recoveryRequired }) else {
            throw RemapInstallerBootstrapFailure.incompleteInstallation(
                "the committed transaction still requires recovery"
            )
        }
        guard finalStatus.services.allSatisfy(\.loaded) else {
            throw RemapInstallerBootstrapFailure.incompleteInstallation(
                "one or more native services are not loaded"
            )
        }
        guard finalStatus.dns.active,
              finalStatus.dns.effectiveRemapServiceCount > 0
        else {
            throw RemapInstallerBootstrapFailure.incompleteInstallation(
                "the native resolver is not effective"
            )
        }
    }

    private static func recoverConfiguredInstallerState(
        executor: RemapLifecycleExecutor,
        ownerUID: UInt32
    ) async throws {
        let preview = try await successfulRecoveryPreview(
            executor.execute(
                RemapLifecycleRequest(action: .previewRecover),
                sourceUID: ownerUID
            )
        )
        guard !preview.effects.isEmpty else {
            return
        }
        report("recovering a prior incomplete installer transaction")
        let response = try await executor.execute(
            RemapLifecycleRequest(
                action: .recover,
                approvalToken: preview.approvalToken
            ),
            sourceUID: ownerUID
        )
        guard response.outcome == .success,
              response.action == .recover,
              response.recovery != nil
        else {
            throw RemapInstallerBootstrapFailure.lifecycleFailure(response.diagnostic)
        }
        let converged = try await successfulRecoveryPreview(
            executor.execute(
                RemapLifecycleRequest(action: .previewRecover),
                sourceUID: ownerUID
            )
        )
        guard converged.effects.isEmpty else {
            throw RemapInstallerBootstrapFailure.incompleteInstallation(
                "the prior installer transaction did not recover completely"
            )
        }
        report("prior installer state recovered")
    }

    private static func successfulStatus(
        _ response: RemapLifecycleResponse
    ) throws -> MacOSInstallerStatus {
        guard response.outcome == .success,
              response.action == .status,
              let status = response.status
        else {
            throw RemapInstallerBootstrapFailure.lifecycleFailure(response.diagnostic)
        }
        return status
    }

    private static func successfulPreview(
        _ response: RemapLifecycleResponse,
        action: RemapLifecycleAction
    ) throws -> MacOSInstallerPreview {
        guard response.outcome == .success,
              response.action == action,
              let preview = response.preview
        else {
            throw RemapInstallerBootstrapFailure.lifecycleFailure(response.diagnostic)
        }
        return preview
    }

    private static func successfulRecoveryPreview(
        _ response: RemapLifecycleResponse
    ) throws -> MacOSInstallerRecoveryPreview {
        guard response.outcome == .success,
              response.action == .previewRecover,
              let preview = response.recoveryPreview
        else {
            throw RemapInstallerBootstrapFailure.lifecycleFailure(response.diagnostic)
        }
        return preview
    }

    private static func report(_ message: String) {
        FileHandle.standardError.write(Data("Remap installer: \(message).\n".utf8))
    }
}

private enum RemapInstallerBootstrapFailure: Error, CustomStringConvertible {
    case incompleteInstallation(String)
    case lifecycleFailure(RemapLifecycleDiagnostic?)
    case rootAuthorityRequired

    var description: String {
        switch self {
        case let .incompleteInstallation(detail):
            "the native installation did not reach complete readiness: \(detail)"
        case let .lifecycleFailure(diagnostic):
            if let diagnostic {
                "lifecycle \(diagnostic.category.rawValue) failure: "
                    + "\(diagnostic.message) Hint: \(diagnostic.hint)"
            } else {
                "the lifecycle operation failed without a typed diagnostic"
            }
        case .rootAuthorityRequired:
            "the Apple Installer script did not receive root authority"
        }
    }
}
