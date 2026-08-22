import Darwin
import Foundation
@preconcurrency import Network
@testable import RemapControlKit
import Testing

@Test
func cancellingControlReadAfterRequestWriteCompletesPromptly() async throws {
    let server = try HangingControlServer()
    try await server.start()
    defer { server.stop() }

    let client = RemapControlClient(socketPath: server.socketPath, clientVersion: "test")
    let request = Task { try await client.execute(.status) }
    await server.waitForRequests(1)
    let cancelledAt = monotonicTestTime()

    request.cancel()
    do {
        _ = try await request.value
        Issue.record("a cancelled control request unexpectedly answered")
    } catch is CancellationError {
        // Cancellation is the preferred result.
    } catch let diagnostic as RemapDiagnostic {
        #expect(diagnostic.code == "E_DAEMON_UNAVAILABLE")
    }

    #expect(monotonicTestElapsed(since: cancelledAt) < 500_000_000)
}

@Test
func runtimeIdentityChallengeHasOneSecondOverallDeadline() async throws {
    let server = try HangingControlServer()
    try await server.start()
    defer { server.stop() }

    let client = RemapControlClient(socketPath: server.socketPath, clientVersion: "0.1.0")
    let started = monotonicTestTime()
    do {
        _ = try await client.runtimeChallenge()
        Issue.record("a hanging runtime identity challenge unexpectedly answered")
    } catch let diagnostic as RemapDiagnostic {
        #expect(diagnostic.code == "E_DAEMON_TIMEOUT")
    }

    await server.waitForRequests(1)
    #expect(monotonicTestElapsed(since: started) < 1_250_000_000)
}

private final class HangingControlServer: @unchecked Sendable {
    let socketPath: String
    private let listener: NWListener
    private let queue = DispatchQueue(
        label: "org.agenxy.remap.tests.hanging-control",
        qos: .userInitiated
    )
    private let requests = RequestCounter()
    private var connections: [NWConnection] = []

    init() throws {
        socketPath = "/tmp/remap-\(UUID().uuidString.prefix(12).lowercased()).sock"
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .unix(path: socketPath)
        listener = try NWListener(using: parameters)
    }

    deinit {
        listener.cancel()
        unlink(socketPath)
    }

    func start() async throws {
        try await withCheckedThrowingContinuation { continuation in
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    self.listener.stateUpdateHandler = nil
                    continuation.resume()
                case let .failed(error), let .waiting(error):
                    self.listener.stateUpdateHandler = nil
                    continuation.resume(throwing: error)
                case .cancelled:
                    self.listener.stateUpdateHandler = nil
                    continuation.resume(throwing: CancellationError())
                case .setup:
                    break
                @unknown default:
                    self.listener.stateUpdateHandler = nil
                    continuation.resume(throwing: CancellationError())
                }
            }
            listener.newConnectionHandler = { connection in
                self.accept(connection)
            }
            listener.start(queue: queue)
        }
    }

    func waitForRequests(_ expected: Int) async {
        await requests.wait(until: expected)
    }

    func stop() {
        listener.stateUpdateHandler = nil
        listener.newConnectionHandler = nil
        listener.cancel()
        queue.sync {
            connections.forEach { $0.cancel() }
            connections.removeAll()
        }
        unlink(socketPath)
    }

    private func accept(_ connection: NWConnection) {
        connections.append(connection)
        connection.start(queue: queue)
        connection.receive(
            minimumIncompleteLength: 1,
            maximumLength: remapMaximumControlFrameBytes
        ) { content, _, _, _ in
            guard let content, !content.isEmpty else { return }
            Task { await self.requests.record() }
        }
    }
}

private actor RequestCounter {
    private var count = 0
    private var waiters: [RequestWaiter] = []

    func record() {
        count += 1
        let ready = waiters.filter { $0.expected <= count }
        waiters.removeAll { $0.expected <= count }
        ready.forEach { $0.continuation.resume() }
    }

    func wait(until expected: Int) async {
        guard count < expected else { return }
        await withCheckedContinuation { continuation in
            waiters.append(RequestWaiter(expected: expected, continuation: continuation))
        }
    }
}

private struct RequestWaiter {
    let expected: Int
    let continuation: CheckedContinuation<Void, Never>
}
