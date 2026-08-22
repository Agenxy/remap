import Foundation

/// Stateless, bounded client for the authenticated per-user Remap authority.
public struct RemapControlClient: Sendable {
    private static let metadataLimit = 64
    private static let proofLength = 64

    public let socketPath: String
    public let clientVersion: String

    public init(socketPath: String, clientVersion: String) {
        self.socketPath = socketPath
        self.clientVersion = clientVersion
    }

    /// Creates a client at the native per-user control socket.
    public static func discovered(clientVersion: String) throws -> Self {
        let home = FileManager.default.homeDirectoryForCurrentUser
        guard home.isFileURL, home.path.hasPrefix("/") else {
            throw transportDiagnostic(
                code: "E_DATA_PATH",
                message: "the current account has no absolute home directory",
                hint: "Run Remap from a normal signed-in user session.",
                retryable: false
            )
        }
        let socket = home
            .appending(path: "Library", directoryHint: .isDirectory)
            .appending(path: "Application Support", directoryHint: .isDirectory)
            .appending(path: "org.Agenxy.Remap", directoryHint: .isDirectory)
            .appending(path: "control.sock", directoryHint: .notDirectory)
        return Self(socketPath: socket.path, clientVersion: clientVersion)
    }

    /// Executes one request on a fresh local connection.
    public func execute(_ command: RemapControlCommand) async throws -> RemapCommandResult {
        try await execute(command, deadline: .command)
    }

    private func execute(
        _ command: RemapControlCommand,
        deadline: ControlDeadline
    ) async throws -> RemapCommandResult {
        let requestID = UUID().uuidString.lowercased()
        let request = ControlRequest(
            protocol: remapControlProtocolVersion,
            requestID: requestID,
            surface: "native-app",
            clientVersion: clientVersion,
            command: command
        )
        let frame = try ControlFrame.encode(request)
        let response = try await withThrowingTaskGroup(of: Data.self) { group in
            group.addTask {
                try await NetworkExchange(socketPath: socketPath).perform(frame: frame)
            }
            group.addTask {
                try await Task.sleep(for: deadline.duration)
                throw deadline.diagnostic()
            }
            guard let first = try await group.next() else {
                throw transportDiagnostic(
                    code: "E_CONTROL_TRANSPORT",
                    message: "the local-control exchange ended without a result",
                    retryable: true
                )
            }
            group.cancelAll()
            return first
        }
        return try validate(ControlFrame.decodeResponse(response), requestID: requestID)
    }

    /// Requests and validates one fresh runtime identity challenge.
    public func runtimeChallenge() async throws -> RemapRuntimeChallenge {
        let nonce = runtimeIdentityNonce()
        guard case let .healthChallenge(response) = try await execute(
            .healthChallenge(nonce: nonce),
            deadline: .runtimeIdentity
        ) else {
            throw runtimeIdentityDiagnostic("the daemon returned the wrong health result")
        }
        return try validateRuntimeChallenge(response, nonce: nonce)
    }

    private func runtimeIdentityNonce() -> String {
        let hexadecimal = Array("0123456789abcdef".utf8)
        var generator = SystemRandomNumberGenerator()
        var encoded: [UInt8] = []
        encoded.reserveCapacity(32)
        for _ in 0 ..< 16 {
            let byte = UInt8.random(in: .min ... .max, using: &generator)
            encoded.append(hexadecimal[Int(byte >> 4)])
            encoded.append(hexadecimal[Int(byte & 0x0F)])
        }
        return String(decoding: encoded, as: UTF8.self)
    }

    func validateRuntimeChallenge(
        _ response: RemapHealthChallengeResponse,
        nonce: String
    ) throws -> RemapRuntimeChallenge {
        guard validNonce(nonce),
              validMetadata(response.instanceID),
              validMetadata(response.daemonVersion),
              response.daemonVersion == clientVersion,
              validProof(response.dnsProof),
              validProof(response.httpProof),
              response.dnsProof != response.httpProof
        else {
            throw runtimeIdentityDiagnostic("the daemon returned an invalid runtime identity")
        }
        return RemapRuntimeChallenge(
            nonce: nonce,
            instanceID: response.instanceID,
            daemonVersion: response.daemonVersion,
            dnsProof: response.dnsProof,
            httpProof: response.httpProof
        )
    }

    private func validMetadata(_ value: String) -> Bool {
        !value.isEmpty
            && value.utf8.count <= Self.metadataLimit
            && value.utf8.allSatisfy { (32 ... 126).contains($0) }
    }

    private func validNonce(_ value: String) -> Bool {
        value.utf8.count == 32
            && value.utf8.allSatisfy { byte in
                (48 ... 57).contains(byte) || (97 ... 102).contains(byte)
            }
    }

    private func validProof(_ value: String) -> Bool {
        value.utf8.count == Self.proofLength
            && value.utf8.allSatisfy { byte in
                (48 ... 57).contains(byte) || (97 ... 102).contains(byte)
            }
    }

    private func runtimeIdentityDiagnostic(_ message: String) -> RemapDiagnostic {
        transportDiagnostic(
            code: "E_RUNTIME_IDENTITY",
            message: message,
            hint: "Update the Remap app and service together, then retry.",
            retryable: false
        )
    }

    private func validate(
        _ response: ControlResponse,
        requestID: String
    ) throws -> RemapCommandResult {
        guard response.protocol == remapControlProtocolVersion else {
            throw transportDiagnostic(
                code: "E_CONTROL_PROTOCOL",
                message: "the daemon answered with an unsupported control protocol",
                hint: "Update the Remap app and service together, then retry.",
                retryable: false
            )
        }
        guard response.requestID == requestID else {
            throw transportDiagnostic(
                code: "E_CONTROL_PROTOCOL",
                message: "the daemon response did not match the request",
                retryable: false
            )
        }
        switch (response.result, response.error) {
        case let (.some(result), .none):
            return result
        case let (.none, .some(error)):
            throw error
        case (.some, .some), (.none, .none):
            throw transportDiagnostic(
                code: "E_CONTROL_PROTOCOL",
                message: "the daemon response must contain exactly one result or error",
                retryable: false
            )
        }
    }
}

private enum ControlDeadline: Sendable {
    case command
    case runtimeIdentity

    var duration: Duration {
        switch self {
        case .command:
            .seconds(15)
        case .runtimeIdentity:
            .seconds(1)
        }
    }

    func diagnostic() -> RemapDiagnostic {
        switch self {
        case .command:
            transportDiagnostic(
                code: "E_DAEMON_TIMEOUT",
                message: "the Remap authority did not answer within 15 seconds",
                hint: "The request may have completed. Refresh authoritative state before retrying.",
                retryable: true,
                context: ["outcome": "unknown"]
            )
        case .runtimeIdentity:
            transportDiagnostic(
                code: "E_DAEMON_TIMEOUT",
                message: "the Remap authority did not answer the runtime identity challenge within one second",
                hint: "Start or repair the Remap service, then refresh.",
                retryable: true
            )
        }
    }
}
