import Darwin
import Foundation
import LocalAuthentication
import RemapInstallKit
import RemapLifecycleKit

@main
enum RemapLifecycleCLIMain {
    static func main() async {
        let json = CommandLine.arguments.contains("--json")
        do {
            let command = try RemapLifecycleCLICommand.parse(CommandLine.arguments)
            try await execute(command, client: RemapLifecycleClient())
        } catch {
            report(error, json: json)
            exit(exitCode(error))
        }
    }

    private static func execute(
        _ command: RemapLifecycleCLICommand,
        client: RemapLifecycleClient
    ) async throws {
        switch command {
        case .help:
            write(RemapLifecycleCLIOutput.help + "\n", to: .standardOutput)
        case let .status(json):
            let response = try await client.execute(RemapLifecycleRequest(action: .status))
            if json {
                try writeJSON(response)
            } else if let status = response.status {
                write(RemapLifecycleCLIOutput.status(status) + "\n", to: .standardOutput)
            } else {
                throw RemapLifecycleCLIError.integrity("the lifecycle service returned no status")
            }
        case let .recover(json):
            try await recover(client: client, json: json)
        case let .uninstall(json):
            try await uninstall(client: client, json: json)
        }
    }

    private static func recover(client: RemapLifecycleClient, json: Bool) async throws {
        let lifecycle = try await client.execute(RemapLifecycleRequest(action: .previewRecover))
        guard let lifecyclePreview = lifecycle.recoveryPreview else {
            throw RemapLifecycleCLIError.integrity("the lifecycle service returned no recovery preview")
        }
        if !lifecyclePreview.effects.isEmpty {
            try await renderAndApprove(
                lifecycle,
                effects: lifecyclePreview.effects,
                json: json
            )
            let result = try await client.execute(RemapLifecycleRequest(
                action: .recover,
                approvalToken: lifecyclePreview.approvalToken
            ))
            try render(result, json: json, human: "Remap recovery completed.\n")
        } else if !json {
            write("Remap product recovery: no changes are needed.\n", to: .standardOutput)
        }

        let bootstrap = try await client.execute(
            RemapLifecycleRequest(action: .previewRecoverBootstrapHelpers)
        )
        guard let bootstrapPreview = bootstrap.bootstrapRecoveryPreview else {
            throw RemapLifecycleCLIError.integrity("the lifecycle service returned no bootstrap recovery preview")
        }
        if !bootstrapPreview.effects.isEmpty {
            try await renderAndApprove(
                bootstrap,
                effects: bootstrapPreview.effects,
                json: json
            )
            let result = try await client.execute(RemapLifecycleRequest(
                action: .recoverBootstrapHelpers,
                approvalToken: bootstrapPreview.approvalToken
            ))
            try render(result, json: json, human: "Remap installer cleanup completed.\n")
        } else if !json {
            write("Remap installer cleanup: no changes are needed.\n", to: .standardOutput)
        }

        let convergence = try await client.execute(RemapLifecycleRequest(action: .previewRecover))
        let bootstrapConvergence = try await client.execute(
            RemapLifecycleRequest(action: .previewRecoverBootstrapHelpers)
        )
        guard convergence.recoveryPreview?.effects.isEmpty == true,
              bootstrapConvergence.bootstrapRecoveryPreview?.effects.isEmpty == true
        else {
            throw RemapLifecycleCLIError.integrity("recovery did not converge to a clean state")
        }
        if json, lifecyclePreview.effects.isEmpty, bootstrapPreview.effects.isEmpty {
            try writeJSON(convergence)
            try writeJSON(bootstrapConvergence)
        }
    }

    private static func uninstall(client: RemapLifecycleClient, json: Bool) async throws {
        let statusResponse = try await client.execute(RemapLifecycleRequest(action: .status))
        guard let status = statusResponse.status else {
            throw RemapLifecycleCLIError.integrity("the lifecycle service returned no status")
        }
        guard let generationID = status.activeGenerationID else {
            if json {
                try writeJSON(statusResponse)
            } else {
                write("Remap is not installed.\n", to: .standardOutput)
            }
            return
        }
        let response = try await client.execute(RemapLifecycleRequest(
            action: .previewUninstall,
            generationID: generationID
        ))
        let effects: [String]
        let approvalToken: InstallApprovalToken
        if let portable = response.uninstallPreview {
            effects = portable.effects
            approvalToken = portable.approvalToken
        } else if let preview = response.preview {
            effects = preview.effects
            approvalToken = preview.approvalToken
        } else {
            throw RemapLifecycleCLIError.integrity("the lifecycle service returned no uninstall preview")
        }
        try await renderAndApprove(response, effects: effects, json: json)
        let mutation = try await client.execute(RemapLifecycleRequest(
            action: .uninstall,
            generationID: generationID,
            transactionID: UUID().uuidString.lowercased(),
            approvalToken: approvalToken
        ))
        if mutation.mutation?.authorityCleanupPending == true {
            try await waitForPortableAuthorityRemoval(client: client)
        }
        try render(mutation, json: json, human: "Remap was uninstalled.\n")
    }

    private static func waitForPortableAuthorityRemoval(
        client: RemapLifecycleClient
    ) async throws {
        let paths = [
            "/Library/PrivilegedHelperTools/org.agenxy.Remap.installer-service",
            "/Library/LaunchDaemons/org.agenxy.Remap.installer-service.plist",
            "/Library/Application Support/Agenxy/Remap/Installer"
        ]
        for _ in 0 ..< 100 {
            let filesAreGone = paths.allSatisfy { path in
                var status = stat()
                return lstat(path, &status) != 0 && errno == ENOENT
            }
            if filesAreGone {
                do {
                    _ = try await client.execute(RemapLifecycleRequest(action: .status))
                } catch {
                    return
                }
            }
            try await Task.sleep(for: .milliseconds(100))
        }
        throw RemapLifecycleCLIError.integrity(
            "the product was removed, but its local installer service did not finish cleanup"
        )
    }

    private static func renderAndApprove(
        _ response: RemapLifecycleResponse,
        effects: [String],
        json: Bool
    ) async throws {
        if json {
            try writeJSON(response)
        } else {
            write(
                RemapLifecycleCLIOutput.preview(title: "Review these changes", effects: effects) + "\n",
                to: .standardOutput
            )
        }
        let interactive = isatty(STDIN_FILENO) == 1
        try RemapLifecycleCLIApproval.requireInteractive(interactive)
        try await RemapLifecycleUserPresence.authorize()
    }

    private static func render(
        _ response: RemapLifecycleResponse,
        json: Bool,
        human: String
    ) throws {
        if json {
            try writeJSON(response)
        } else {
            write(human, to: .standardOutput)
        }
    }

    private static func writeJSON(_ response: RemapLifecycleResponse) throws {
        var data = try RemapLifecycleCoding.encodeResponse(response)
        data.append(0x0A)
        FileHandle.standardOutput.write(data)
    }

    private static func write(_ value: String, to handle: FileHandle) {
        handle.write(Data(value.utf8))
    }

    private static func report(_ error: any Error, json: Bool) {
        if json, let data = try? RemapLifecycleCLIErrorDocument.data(for: error) {
            FileHandle.standardOutput.write(data)
            return
        }
        let message: String
        let hint: String?
        if let remote = error as? RemapLifecycleRemoteError {
            message = remote.diagnostic.message
            hint = remote.diagnostic.hint
        } else if let local = error as? RemapLifecycleCLIError {
            switch local {
            case let .approval(value), let .integrity(value), let .usage(value):
                message = value
            }
            hint = local.usageHint
        } else if let install = error as? InstallError {
            message = install.description
            hint = nil
        } else {
            message = String(describing: error)
            hint = nil
        }
        write("remap: \(plain(message))\n", to: .standardError)
        if let hint {
            write("Next: \(plain(hint))\n", to: .standardError)
        }
    }

    private static func exitCode(_ error: any Error) -> Int32 {
        if case .usage = error as? RemapLifecycleCLIError {
            return 64
        }
        if case .approval = error as? RemapLifecycleCLIError {
            return 77
        }
        if let remote = error as? RemapLifecycleRemoteError {
            return switch remote.diagnostic.category {
            case .approval, .authority: 77
            case .busy, .conflict: 73
            case .unsupported: 69
            case .integrity, .internalFailure: 65
            }
        }
        return 65
    }
}

enum RemapLifecycleUserPresence {
    static func authorize(
        evaluate: @Sendable () async throws -> Bool = systemEvaluation
    ) async throws {
        do {
            guard try await evaluate() else {
                throw RemapLifecycleCLIError.approval(
                    "macOS user authentication did not approve this lifecycle change"
                )
            }
        } catch let error as RemapLifecycleCLIError {
            throw error
        } catch {
            throw RemapLifecycleCLIError.approval(
                "macOS user authentication did not approve this lifecycle change"
            )
        }
    }

    private static func systemEvaluation() async throws -> Bool {
        let context = LAContext()
        context.localizedCancelTitle = "Cancel"
        var evaluationError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &evaluationError) else {
            throw RemapLifecycleCLIError.approval(
                "macOS user authentication is unavailable for this lifecycle change"
            )
        }
        return try await context.evaluatePolicy(
            .deviceOwnerAuthentication,
            localizedReason: "Approve the reviewed Remap system changes"
        )
    }
}

private extension RemapLifecycleCLIError {
    var usageHint: String? {
        if case .usage = self {
            return "Run remap system --help."
        }
        return nil
    }
}
