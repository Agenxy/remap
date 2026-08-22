import Darwin
import Foundation
@preconcurrency import Network
@testable import RemapControlKit
import Testing

@Test
func gatewayProbeAuthenticatesExpectedProofOnEphemeralLoopbackListener() async throws {
    let server = try HealthHTTPServer(body: challenge.httpProof)
    try await server.start()
    defer { server.stop() }

    #expect(await RemapGatewayProbe.verify(challenge: challenge, port: server.port))
}

@Test
func unrelatedLiveListenerCannotClaimGatewayReadiness() async throws {
    let listener = try LoopbackPortReservation(listening: true)
    let started = monotonicTestTime()

    let reachable = await RemapGatewayProbe.verify(challenge: challenge, port: listener.port)

    #expect(!reachable)
    #expect(monotonicTestElapsed(since: started) < 1_250_000_000)
}

@Test(arguments: ["c", String(repeating: "b", count: 4097)])
func gatewayProbeRejectsWrongOrOversizedProof(_ body: String) async throws {
    let server = try HealthHTTPServer(body: body)
    try await server.start()
    defer { server.stop() }

    #expect(await !(RemapGatewayProbe.verify(challenge: challenge, port: server.port)))
}

@Test(arguments: [
    "Cache-Control: no-store",
    "Cache-Control: private",
    "Content-Type: application/json",
    "Transfer-Encoding: identity"
])
func gatewayProbeRejectsAmbiguousHealthHeaders(_ extraHeader: String) async throws {
    let server = try HealthHTTPServer(
        body: challenge.httpProof,
        extraHeaders: [extraHeader]
    )
    try await server.start()
    defer { server.stop() }

    #expect(await !(RemapGatewayProbe.verify(challenge: challenge, port: server.port)))
}

@Test
func gatewayProbeRejectsReservedClosedLoopbackPortPromptly() async throws {
    let reservation = try LoopbackPortReservation(listening: false)
    let started = monotonicTestTime()

    let reachable = await RemapGatewayProbe.verify(challenge: challenge, port: reservation.port)

    #expect(!reachable)
    #expect(monotonicTestElapsed(since: started) < 1_250_000_000)
}

@Test
func cancelledGatewayProofsCompleteWithoutContinuationLeaks() async throws {
    let reservation = try LoopbackPortReservation(listening: false)
    let started = monotonicTestTime()
    let probes = (0 ..< 64).map { _ in
        Task { await RemapGatewayProbe.verify(challenge: challenge, port: reservation.port) }
    }

    probes.forEach { $0.cancel() }
    var results: [Bool] = []
    for probe in probes {
        let result = await probe.value
        results.append(result)
    }

    #expect(results.allSatisfy { !$0 })
    #expect(monotonicTestElapsed(since: started) < 1_000_000_000)
}

private let challenge = RemapRuntimeChallenge(
    nonce: "00112233445566778899aabbccddeeff",
    instanceID: "9f3e7a83-9ce8-4877-a50e-f1f4fc048b38",
    daemonVersion: "0.1.0",
    dnsProof: String(repeating: "a", count: 64),
    httpProof: String(repeating: "b", count: 64)
)

private final class HealthHTTPServer: @unchecked Sendable {
    private let body: String
    private let extraHeaders: [String]
    private let listener: NWListener
    private let queue = DispatchQueue(label: "org.agenxy.remap.tests.health-http")

    var port: UInt16 {
        listener.port?.rawValue ?? 0
    }

    init(body: String, extraHeaders: [String] = []) throws {
        self.body = body
        self.extraHeaders = extraHeaders
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        listener = try NWListener(using: parameters)
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

    func stop() {
        listener.stateUpdateHandler = nil
        listener.newConnectionHandler = nil
        listener.cancel()
    }

    private func accept(_ connection: NWConnection) {
        connection.start(queue: queue)
        connection.receive(minimumIncompleteLength: 1, maximumLength: 4096) { _, _, _, _ in
            let extraHeaders = self.extraHeaders.map { "\($0)\r\n" }.joined()
            let response = Data(
                "HTTP/1.1 200 OK\r\n"
                    .appending("Content-Type: text/plain; charset=utf-8\r\n")
                    .appending("Cache-Control: no-store\r\n")
                    .appending(extraHeaders)
                    .appending("Content-Length: \(self.body.utf8.count)\r\n")
                    .appending("Connection: close\r\n\r\n")
                    .appending(self.body)
                    .utf8
            )
            connection.send(content: response, contentContext: .finalMessage, isComplete: true, completion: .idempotent)
        }
    }
}

private final class LoopbackPortReservation: @unchecked Sendable {
    let port: UInt16
    private let descriptor: Int32

    init(listening: Bool) throws {
        let socketDescriptor = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        guard socketDescriptor >= 0 else {
            throw currentPOSIXError()
        }
        var succeeded = false
        defer {
            if !succeeded {
                Darwin.close(socketDescriptor)
            }
        }

        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = 0
        address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
        let bindResult = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { rebound in
                Darwin.bind(
                    socketDescriptor,
                    rebound,
                    socklen_t(MemoryLayout<sockaddr_in>.size)
                )
            }
        }
        guard bindResult == 0 else {
            throw currentPOSIXError()
        }
        if listening, Darwin.listen(socketDescriptor, 8) != 0 {
            throw currentPOSIXError()
        }

        var boundAddress = sockaddr_in()
        var boundLength = socklen_t(MemoryLayout<sockaddr_in>.size)
        let nameResult = withUnsafeMutablePointer(to: &boundAddress) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { rebound in
                Darwin.getsockname(socketDescriptor, rebound, &boundLength)
            }
        }
        guard nameResult == 0 else {
            throw currentPOSIXError()
        }

        descriptor = socketDescriptor
        port = UInt16(bigEndian: boundAddress.sin_port)
        succeeded = true
    }

    deinit {
        Darwin.close(descriptor)
    }
}

private func currentPOSIXError() -> POSIXError {
    let code = POSIXErrorCode(rawValue: errno) ?? .EIO
    return POSIXError(code)
}
