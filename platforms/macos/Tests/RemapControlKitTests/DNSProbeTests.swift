import Darwin
import Foundation
@preconcurrency import Network
@testable import RemapControlKit
import Testing

@Test
func dnsProbeAuthenticatesOneProofOverUDPAndTCP() async throws {
    let server = try HealthDNSServer(proof: dnsChallenge.dnsProof)
    try await server.start()
    defer { server.stop() }

    #expect(await RemapDNSProbe.verify(challenge: dnsChallenge, port: server.port))
}

@Test
func dnsProbeRejectsWrongProofOverBothTransports() async throws {
    let server = try HealthDNSServer(proof: String(repeating: "c", count: 64))
    try await server.start()
    defer { server.stop() }

    #expect(await !(RemapDNSProbe.verify(challenge: dnsChallenge, port: server.port)))
}

@Test
func dnsWireRejectsMalformedOrUnrelatedMessages() throws {
    let query = try #require(
        DNSHealthWire.query(nonce: dnsChallenge.nonce, identifier: 0x524D)
    )
    let valid = makeDNSResponse(query: query, proof: dnsChallenge.dnsProof)
    #expect(DNSHealthWire.valid(response: valid, query: query, expected: dnsChallenge.dnsProof))

    var unrelatedQuestion = valid
    unrelatedQuestion[13] = UInt8(ascii: "x")
    #expect(
        !DNSHealthWire.valid(
            response: unrelatedQuestion,
            query: query,
            expected: dnsChallenge.dnsProof
        )
    )

    var invalidPointer = valid
    invalidPointer[query.count] = 0xFF
    invalidPointer[query.count + 1] = 0xFF
    #expect(
        !DNSHealthWire.valid(
            response: invalidPointer,
            query: query,
            expected: dnsChallenge.dnsProof
        )
    )

    var trailingBytes = valid
    trailingBytes.append(0)
    #expect(
        !DNSHealthWire.valid(
            response: trailingBytes,
            query: query,
            expected: dnsChallenge.dnsProof
        )
    )
    #expect(DNSHealthWire.query(nonce: dnsChallenge.nonce.uppercased()) == nil)
}

@Test
func dnsProbeRejectsReservedClosedPortWithinStrictBound() async throws {
    let reservation = try DNSPortReservation()
    let started = monotonicTestTime()

    let ready = await RemapDNSProbe.verify(challenge: dnsChallenge, port: reservation.port)

    #expect(!ready)
    #expect(monotonicTestElapsed(since: started) < 1_250_000_000)
}

@Test
func cancelledDNSProofsCompleteWithoutContinuationLeaks() async throws {
    let reservation = try DNSPortReservation()
    let started = monotonicTestTime()
    let probes = (0 ..< 64).map { _ in
        Task { await RemapDNSProbe.verify(challenge: dnsChallenge, port: reservation.port) }
    }

    probes.forEach { $0.cancel() }
    var results: [Bool] = []
    for probe in probes {
        await results.append(probe.value)
    }

    #expect(results.allSatisfy { !$0 })
    #expect(monotonicTestElapsed(since: started) < 1_000_000_000)
}

@Test
func runtimeHealthNeverReportsPartialIdentityAsReady() {
    let partial = RemapRuntimeHealth(
        instanceID: dnsChallenge.instanceID,
        daemonVersion: dnsChallenge.daemonVersion,
        authority: true,
        dns: true,
        http: false
    )
    #expect(!partial.ready)
}

private let dnsChallenge = RemapRuntimeChallenge(
    nonce: "00112233445566778899aabbccddeeff",
    instanceID: "3fd30437-e1a8-4328-a1f8-a8afe31ef8e2",
    daemonVersion: "0.1.0",
    dnsProof: String(repeating: "a", count: 64),
    httpProof: String(repeating: "b", count: 64)
)

private final class HealthDNSServer: @unchecked Sendable {
    private let proof: String
    private let tcpListener: NWListener
    private let queue = DispatchQueue(label: "org.agenxy.remap.tests.health-dns")
    private var udpListener: NWListener?
    private var connections: [NWConnection] = []

    var port: UInt16 {
        tcpListener.port?.rawValue ?? 0
    }

    init(proof: String) throws {
        self.proof = proof
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        tcpListener = try NWListener(using: parameters)
    }

    deinit {
        stop()
    }

    func start() async throws {
        try await start(tcpListener) { connection in
            self.acceptTCP(connection)
        }
        guard let endpointPort = NWEndpoint.Port(rawValue: port) else {
            throw POSIXError(.EADDRNOTAVAIL)
        }
        let parameters = NWParameters.udp
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: endpointPort)
        let listener = try NWListener(using: parameters)
        udpListener = listener
        try await start(listener) { connection in
            self.acceptUDP(connection)
        }
    }

    func stop() {
        tcpListener.stateUpdateHandler = nil
        tcpListener.newConnectionHandler = nil
        tcpListener.cancel()
        udpListener?.stateUpdateHandler = nil
        udpListener?.newConnectionHandler = nil
        udpListener?.cancel()
        queue.sync {
            connections.forEach { $0.cancel() }
            connections.removeAll()
        }
    }

    private func start(
        _ listener: NWListener,
        handler: @escaping @Sendable (NWConnection) -> Void
    ) async throws {
        try await withCheckedThrowingContinuation { continuation in
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    listener.stateUpdateHandler = nil
                    continuation.resume()
                case let .failed(error), let .waiting(error):
                    listener.stateUpdateHandler = nil
                    continuation.resume(throwing: error)
                case .cancelled:
                    listener.stateUpdateHandler = nil
                    continuation.resume(throwing: CancellationError())
                case .setup:
                    break
                @unknown default:
                    listener.stateUpdateHandler = nil
                    continuation.resume(throwing: CancellationError())
                }
            }
            listener.newConnectionHandler = handler
            listener.start(queue: queue)
        }
    }

    private func acceptUDP(_ connection: NWConnection) {
        connections.append(connection)
        connection.start(queue: queue)
        connection.receiveMessage { content, _, _, error in
            guard error == nil, let query = content else { return }
            let response = makeDNSResponse(query: query, proof: self.proof)
            connection.send(
                content: response,
                contentContext: .finalMessage,
                isComplete: true,
                completion: .idempotent
            )
        }
    }

    private func acceptTCP(_ connection: NWConnection) {
        connections.append(connection)
        connection.start(queue: queue)
        receiveTCP(connection, buffered: Data())
    }

    private func receiveTCP(_ connection: NWConnection, buffered: Data) {
        connection.receive(
            minimumIncompleteLength: 1,
            maximumLength: 4096
        ) { content, _, complete, error in
            var received = buffered
            if let content {
                received.append(content)
            }
            guard received.count >= 2 else {
                if error == nil, !complete {
                    self.receiveTCP(connection, buffered: received)
                }
                return
            }
            let length = Int(received[0]) << 8 | Int(received[1])
            guard received.count >= length + 2 else {
                if error == nil, !complete {
                    self.receiveTCP(connection, buffered: received)
                }
                return
            }
            let query = received.subdata(in: 2 ..< length + 2)
            let response = makeDNSResponse(query: query, proof: self.proof)
            guard let size = UInt16(exactly: response.count) else { return }
            var frame = Data([UInt8(size >> 8), UInt8(size & 0xFF)])
            frame.append(response)
            connection.send(
                content: frame,
                contentContext: .finalMessage,
                isComplete: true,
                completion: .idempotent
            )
        }
    }
}

private final class DNSPortReservation: @unchecked Sendable {
    let port: UInt16
    private let tcpDescriptor: Int32
    private let udpDescriptor: Int32

    init() throws {
        let tcp = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        guard tcp >= 0 else { throw currentDNSError() }
        var address = loopbackAddress(port: 0)
        guard bindSocket(tcp, to: &address) == 0 else {
            Darwin.close(tcp)
            throw currentDNSError()
        }
        var bound = sockaddr_in()
        var boundLength = socklen_t(MemoryLayout<sockaddr_in>.size)
        let nameResult = withUnsafeMutablePointer(to: &bound) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { rebound in
                Darwin.getsockname(tcp, rebound, &boundLength)
            }
        }
        guard nameResult == 0 else {
            Darwin.close(tcp)
            throw currentDNSError()
        }
        let udp = Darwin.socket(AF_INET, SOCK_DGRAM, 0)
        guard udp >= 0 else {
            Darwin.close(tcp)
            throw currentDNSError()
        }
        var udpAddress = loopbackAddress(port: bound.sin_port)
        guard bindSocket(udp, to: &udpAddress) == 0 else {
            Darwin.close(udp)
            Darwin.close(tcp)
            throw currentDNSError()
        }
        tcpDescriptor = tcp
        udpDescriptor = udp
        port = UInt16(bigEndian: bound.sin_port)
    }

    deinit {
        Darwin.close(udpDescriptor)
        Darwin.close(tcpDescriptor)
    }
}

private func makeDNSResponse(query: Data, proof: String) -> Data {
    var response = query
    guard response.count >= 12 else { return Data() }
    response[2] = 0x81
    response[3] = 0x80
    response[6] = 0
    response[7] = 1
    response.append(contentsOf: [0xC0, 0x0C, 0, 16, 0, 1])
    response.append(contentsOf: [0, 0, 0, 0, 0, 65, 64])
    response.append(contentsOf: proof.utf8)
    return response
}

private func loopbackAddress(port: in_port_t) -> sockaddr_in {
    var address = sockaddr_in()
    address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    address.sin_family = sa_family_t(AF_INET)
    address.sin_port = port
    address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
    return address
}

private func bindSocket(_ descriptor: Int32, to address: inout sockaddr_in) -> Int32 {
    withUnsafePointer(to: &address) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { rebound in
            Darwin.bind(descriptor, rebound, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
    }
}

private func currentDNSError() -> POSIXError {
    POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
}
