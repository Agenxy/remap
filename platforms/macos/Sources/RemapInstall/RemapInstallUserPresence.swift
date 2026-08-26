import LocalAuthentication
import RemapInstallKit

enum RemapInstallUserPresence {
    static func authorize(
        reviewedToken: InstallApprovalToken,
        expectedToken: InstallApprovalToken,
        evaluate: @Sendable () async throws -> Bool = systemEvaluation
    ) async throws {
        guard reviewedToken == expectedToken else {
            throw InstallError.approval(
                "the approved preview is stale or does not match this operation"
            )
        }
        do {
            guard try await evaluate() else {
                throw InstallError.approval(
                    "macOS user authentication did not approve this installer change"
                )
            }
        } catch let error as InstallError {
            throw error
        } catch {
            throw InstallError.approval(
                "macOS user authentication did not approve this installer change"
            )
        }
    }

    private static func systemEvaluation() async throws -> Bool {
        let context = LAContext()
        context.localizedCancelTitle = "Cancel"
        var evaluationError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &evaluationError) else {
            throw InstallError.approval(
                "macOS user authentication is unavailable for this installer change"
            )
        }
        return try await context.evaluatePolicy(
            .deviceOwnerAuthentication,
            localizedReason: "Approve the reviewed Remap system changes"
        )
    }
}
