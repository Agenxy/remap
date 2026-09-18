import Darwin
import Foundation
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
        } catch let error as LAError {
            throw InstallError.approval(
                "macOS user authentication did not approve this installer change"
                    + " (\(reason(for: error)))"
            )
        } catch {
            throw InstallError.approval(
                "macOS user authentication did not approve this installer change"
            )
        }
    }

    /// Why the authentication dialog ended without approval, so the operator
    /// or an agent driving the lifecycle can tell a dismissed prompt from one
    /// that never appeared.
    static func reason(for error: LAError) -> String {
        switch error.code {
        case .userCancel:
            "the prompt was cancelled"
        case .systemCancel, .appCancel:
            "the prompt was cancelled by the system"
        case .userFallback:
            "the prompt asked for a password instead"
        case .authenticationFailed:
            "authentication failed"
        case .notInteractive:
            "no interactive session could show the prompt"
        case .passcodeNotSet:
            "no account password is set"
        case .biometryNotAvailable, .biometryNotEnrolled, .biometryLockout,
             .biometryDisconnected, .biometryNotPaired:
            "Touch ID is unavailable"
        default:
            "LAError \(error.code.rawValue)"
        }
    }

    /// The user whose presence a root helper under `sudo` must prove: the one
    /// who invoked it. macOS authenticates the calling process's own account,
    /// and asking root's would name "System Administrator" and never offer
    /// Touch ID.
    static func invokingUser(
        euid: uid_t = geteuid(),
        environment: [String: String] = ProcessInfo.processInfo.environment
    ) -> uid_t? {
        guard euid == 0,
              let value = environment["SUDO_UID"],
              let uid = uid_t(value),
              uid > 0
        else {
            return nil
        }
        return uid
    }

    private static func systemEvaluation() async throws -> Bool {
        if let uid = invokingUser() {
            return try await evaluateAsUser(uid)
        }
        return try await evaluateHere()
    }

    /// Ask macOS in this process, as whoever this process is.
    static func evaluateHere() async throws -> Bool {
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

    /// Ask macOS as the invoking user: this same executable, run as that user
    /// for the `presence` command alone, which does nothing but ask. Root
    /// needs no password to become a lesser user.
    private static func evaluateAsUser(_ uid: uid_t) async throws -> Bool {
        guard let executable = Bundle.main.executableURL?.resolvingSymlinksInPath().path else {
            throw InstallError.approval(
                "macOS user authentication is unavailable: the installer cannot find itself"
            )
        }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/sudo")
        process.arguments = ["-n", "-u", "#\(uid)", "--", executable, "presence", "--json"]
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        let errors = Pipe()
        process.standardError = errors
        try process.run()
        let said = errors.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        if process.terminationStatus == 0 {
            return true
        }
        throw InstallError.approval(childRefusal(said))
    }

    /// The child's own refusal, when it said one; otherwise the plain fact.
    private static func childRefusal(_ said: Data) -> String {
        let fallback = "macOS user authentication did not approve this installer change"
        guard let document = try? JSONSerialization.jsonObject(with: said) as? [String: Any],
              let error = document["error"] as? [String: Any],
              let message = error["message"] as? String,
              !message.isEmpty, message.utf8.count <= 512
        else {
            return fallback
        }
        return message
    }
}
