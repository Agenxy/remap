import Foundation
@preconcurrency import Network
import Synchronization

final class NetworkExchange: @unchecked Sendable {
    private let connection: NWConnection
    private let queue: DispatchQueue
    private let startState = Mutex(ConnectionStartState.idle)

    init(socketPath: String) {
        connection = NWConnection(to: .unix(path: socketPath), using: .tcp)
        queue = DispatchQueue(label: "org.agenxy.remap.control", qos: .userInitiated)
    }

    func perform(frame: Data) async throws -> Data {
        try await withTaskCancellationHandler {
            defer { connection.cancel() }
            try await start()
            try await send(frame)
            let prefix = try await receiveExactly(MemoryLayout<UInt32>.size)
            let length = try ControlFrame.declaredLength(prefix)
            return try await receiveExactly(length)
        } onCancel: {
            self.completeStart(with: .failure(CancellationError()))
            connection.cancel()
        }
    }

    private func start() async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    self.completeStart(with: .success(()))
                case let .failed(error):
                    self.completeStart(with: .failure(self.connectionDiagnostic(error)))
                case .cancelled:
                    self.completeStart(with: .failure(CancellationError()))
                case let .waiting(error):
                    self.completeStart(with: .failure(self.connectionDiagnostic(error)))
                case .setup, .preparing:
                    break
                @unknown default:
                    self.completeStart(
                        with: .failure(transportDiagnostic(
                            code: "E_CONTROL_TRANSPORT",
                            message: "the daemon connection entered an unknown state",
                            retryable: true
                        ))
                    )
                }
            }
            if registerStart(continuation) {
                connection.start(queue: queue)
            } else {
                connection.stateUpdateHandler = nil
                continuation.resume(throwing: CancellationError())
            }
        }
    }

    private func registerStart(_ continuation: CheckedContinuation<Void, any Error>) -> Bool {
        startState.withLock { state in
            guard case .idle = state else { return false }
            state = .waiting(continuation)
            return true
        }
    }

    private func completeStart(with result: Result<Void, any Error>) {
        let continuation = startState.withLock { state -> CheckedContinuation<Void, any Error>? in
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
        connection.stateUpdateHandler = nil
        continuation?.resume(with: result)
    }

    private func send(_ frame: Data) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
            let completion = NWConnection.SendCompletion.contentProcessed { error in
                if let error {
                    continuation.resume(throwing: self.connectionDiagnostic(error))
                } else {
                    continuation.resume()
                }
            }
            connection.send(content: frame, completion: completion)
        }
    }

    private func receiveExactly(_ expected: Int) async throws -> Data {
        if expected == 0 {
            return Data()
        }
        var received = Data()
        while received.count < expected {
            let remaining = expected - received.count
            let fragment = try await receive(maximum: remaining)
            guard !fragment.isEmpty else {
                throw transportDiagnostic(
                    code: "E_CONTROL_TRANSPORT",
                    message: "the daemon closed the connection before answering",
                    hint: "The request may have completed. Refresh authoritative state before retrying.",
                    retryable: true,
                    context: ["outcome": "unknown", "phase": "receive"]
                )
            }
            received.append(fragment)
        }
        return received
    }

    private func receive(maximum: Int) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            connection.receive(minimumIncompleteLength: 1, maximumLength: maximum) { content, _, isComplete, error in
                if let error {
                    continuation.resume(throwing: self.connectionDiagnostic(error))
                } else if let content {
                    continuation.resume(returning: content)
                } else if isComplete {
                    continuation.resume(returning: Data())
                } else {
                    continuation.resume(
                        throwing: transportDiagnostic(
                            code: "E_CONTROL_TRANSPORT",
                            message: "the daemon returned no local-control data",
                            retryable: true
                        )
                    )
                }
            }
        }
    }

    private func connectionDiagnostic(_: NWError) -> RemapDiagnostic {
        transportDiagnostic(
            code: "E_DAEMON_UNAVAILABLE",
            message: "Remap's background service is not running",
            hint: "Reinstall Remap, then refresh. Your saved mappings are unchanged.",
            retryable: true
        )
    }
}

private enum ConnectionStartState {
    case idle
    case waiting(CheckedContinuation<Void, any Error>)
    case finished
}
