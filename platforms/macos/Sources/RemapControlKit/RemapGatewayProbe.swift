import Foundation
@preconcurrency import Network
import Synchronization

/// Authenticated readiness probe for Remap's loopback HTTP gateway.
public enum RemapGatewayProbe {
    private static let timeout: Duration = .seconds(1)

    /// Challenges the local authority and compares its expected HTTP proof.
    public static func isReachable(port rawPort: UInt16 = 80) async -> Bool {
        guard let client = try? RemapControlClient.discovered(clientVersion: clientVersion()),
              let challenge = try? await client.runtimeChallenge()
        else {
            return false
        }
        return await verify(challenge: challenge, port: rawPort)
    }

    /// Verifies a specific challenge against one loopback HTTP port.
    public static func verify(
        challenge: RemapRuntimeChallenge,
        port rawPort: UInt16 = 80
    ) async -> Bool {
        guard let port = NWEndpoint.Port(rawValue: rawPort) else { return false }
        return await withTaskGroup(of: Bool.self) { group in
            group.addTask {
                await GatewayConnectionProbe(port: port, challenge: challenge).run()
            }
            group.addTask {
                try? await Task.sleep(for: timeout)
                return false
            }
            let first = await group.next() ?? false
            group.cancelAll()
            return first
        }
    }

    private static func clientVersion() -> String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String
            ?? "development"
    }
}

private final class GatewayConnectionProbe: @unchecked Sendable {
    private static let maximumResponseBytes = 4096

    private let challenge: RemapRuntimeChallenge
    private let connection: NWConnection
    private let queue = DispatchQueue(
        label: "org.agenxy.remap.gateway-probe",
        qos: .utility
    )
    private let state = Mutex(GatewayProbeState.idle)

    init(port: NWEndpoint.Port, challenge: RemapRuntimeChallenge) {
        self.challenge = challenge
        connection = NWConnection(host: "127.0.0.1", port: port, using: .tcp)
    }

    func run() async -> Bool {
        await withTaskCancellationHandler {
            defer {
                connection.stateUpdateHandler = nil
                connection.cancel()
            }
            guard await start(), await sendRequest() else { return false }
            return await receiveResponse()
        } onCancel: {
            self.completeStart(with: false)
            connection.cancel()
        }
    }

    private func start() async -> Bool {
        await withCheckedContinuation { continuation in
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    self.completeStart(with: true)
                case .failed, .waiting, .cancelled:
                    self.completeStart(with: false)
                case .setup, .preparing:
                    break
                @unknown default:
                    self.completeStart(with: false)
                }
            }
            if register(continuation) {
                connection.start(queue: queue)
            } else {
                connection.stateUpdateHandler = nil
                continuation.resume(returning: false)
            }
        }
    }

    private func sendRequest() async -> Bool {
        let request = Data(
            "GET /.well-known/remap/health/\(challenge.nonce) HTTP/1.1\r\n"
                .appending("Host: _health.remap.invalid\r\n")
                .appending("Connection: close\r\n\r\n")
                .utf8
        )
        return await withCheckedContinuation { continuation in
            connection.send(
                content: request,
                completion: .contentProcessed { error in
                    continuation.resume(returning: error == nil)
                }
            )
        }
    }

    private func receiveResponse() async -> Bool {
        var response = Data()
        while response.count <= Self.maximumResponseBytes {
            let remaining = Self.maximumResponseBytes + 1 - response.count
            let fragment = await receive(maximum: remaining)
            if let data = fragment.data {
                response.append(data)
            } else if !fragment.complete {
                return false
            }
            if response.count > Self.maximumResponseBytes {
                return false
            }
            if fragment.complete {
                return validHTTPResponse(response)
            }
        }
        return false
    }

    private func receive(maximum: Int) async -> GatewayFragment {
        await withCheckedContinuation { continuation in
            connection.receive(
                minimumIncompleteLength: 1,
                maximumLength: maximum
            ) { content, _, complete, error in
                continuation.resume(
                    returning: GatewayFragment(
                        data: error == nil ? content : nil,
                        complete: complete
                    )
                )
            }
        }
    }

    private func validHTTPResponse(_ response: Data) -> Bool {
        let separator = Data("\r\n\r\n".utf8)
        guard let range = response.range(of: separator),
              let headers = String(data: response[..<range.lowerBound], encoding: .utf8)
        else {
            return false
        }
        var lines = headers.components(separatedBy: "\r\n")[...]
        guard lines.popFirst() == "HTTP/1.1 200 OK" else { return false }
        var noStore: Bool?
        var plainText: Bool?
        for line in lines {
            let fields = line.split(separator: ":", maxSplits: 1).map(String.init)
            guard fields.count == 2 else { return false }
            let name = fields[0].lowercased()
            let value = fields[1].trimmingCharacters(in: .whitespaces)
            if name == "cache-control" {
                guard noStore == nil else { return false }
                noStore = value == "no-store"
            }
            if name == "content-type" {
                guard plainText == nil else { return false }
                plainText = value == "text/plain; charset=utf-8"
            }
            if name == "transfer-encoding" {
                return false
            }
        }
        let body = response[range.upperBound...]
        return noStore == true
            && plainText == true
            && body.elementsEqual(challenge.httpProof.utf8)
    }

    private func register(_ continuation: CheckedContinuation<Bool, Never>) -> Bool {
        state.withLock { state in
            guard case .idle = state else { return false }
            state = .waiting(continuation)
            return true
        }
    }

    private func completeStart(with result: Bool) {
        let continuation = state.withLock { state -> CheckedContinuation<Bool, Never>? in
            switch state {
            case .idle:
                state = .finished
                return nil
            case let .waiting(continuation):
                state = .finished
                return continuation
            case .finished:
                return nil
            }
        }
        continuation?.resume(returning: result)
    }
}

private struct GatewayFragment {
    let data: Data?
    let complete: Bool
}

private enum GatewayProbeState {
    case idle
    case waiting(CheckedContinuation<Bool, Never>)
    case finished
}
