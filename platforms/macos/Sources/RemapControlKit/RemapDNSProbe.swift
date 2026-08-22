import Foundation
@preconcurrency import Network
import Synchronization

/// Authenticated UDP-and-TCP readiness probe for Remap's DNS listener.
public enum RemapDNSProbe {
    private static let timeout: Duration = .seconds(1)

    /// Requires the daemon's keyed TXT proof over both DNS transports.
    public static func verify(
        challenge: RemapRuntimeChallenge,
        port rawPort: UInt16 = 53
    ) async -> Bool {
        guard let port = NWEndpoint.Port(rawValue: rawPort),
              let query = DNSHealthWire.query(nonce: challenge.nonce)
        else {
            return false
        }
        return await withTaskGroup(of: DNSProbeResult.self) { group in
            group.addTask {
                let response = await DNSConnectionProbe(port: port, transport: .udp).run(query)
                return .udp(
                    DNSHealthWire.valid(
                        response: response,
                        query: query,
                        expected: challenge.dnsProof
                    )
                )
            }
            group.addTask {
                let response = await DNSConnectionProbe(port: port, transport: .tcp).run(query)
                return .tcp(
                    DNSHealthWire.valid(
                        response: response,
                        query: query,
                        expected: challenge.dnsProof
                    )
                )
            }
            group.addTask {
                try? await Task.sleep(for: timeout)
                return .timeout
            }
            var udp = false
            var tcp = false
            while let result = await group.next() {
                switch result {
                case let .udp(valid):
                    guard valid else {
                        group.cancelAll()
                        return false
                    }
                    udp = valid
                case let .tcp(valid):
                    guard valid else {
                        group.cancelAll()
                        return false
                    }
                    tcp = valid
                case .timeout:
                    group.cancelAll()
                    return false
                }
                if udp, tcp {
                    group.cancelAll()
                    return true
                }
            }
            return false
        }
    }
}

enum DNSHealthWire {
    static let maximumResponseBytes = 4096

    static func query(nonce: String) -> Data? {
        var generator = SystemRandomNumberGenerator()
        let identifier = UInt16.random(in: .min ... .max, using: &generator)
        return query(nonce: nonce, identifier: identifier)
    }

    static func query(nonce: String, identifier: UInt16) -> Data? {
        guard nonce.utf8.count == 32,
              nonce.utf8.allSatisfy({ byte in
                  (48 ... 57).contains(byte) || (97 ... 102).contains(byte)
              })
        else {
            return nil
        }
        var data = Data()
        append(identifier, to: &data)
        append(0x0100, to: &data)
        append(1, to: &data)
        append(0, to: &data)
        append(0, to: &data)
        append(0, to: &data)
        for label in ["r\(nonce)", "_health", "remap", "invalid"] {
            guard let size = UInt8(exactly: label.utf8.count) else { return nil }
            data.append(size)
            data.append(contentsOf: label.utf8)
        }
        data.append(0)
        append(16, to: &data)
        append(1, to: &data)
        return data
    }

    static func valid(response: Data?, query: Data, expected: String) -> Bool {
        guard let response,
              response.count <= maximumResponseBytes,
              expected.utf8.count == 64,
              expected.utf8.allSatisfy({ byte in
                  (48 ... 57).contains(byte) || (97 ... 102).contains(byte)
              }),
              let queryHeader = DNSHeader(data: query),
              let header = DNSHeader(data: response),
              header.identifier == queryHeader.identifier,
              header.response,
              !header.truncated,
              header.operationCode == 0,
              header.responseCode == 0,
              header.questionCount == 1,
              header.answerCount == 1,
              header.authorityCount == 0,
              header.additionalCount == 0
        else {
            return false
        }
        var cursor = DNSCursor(data: response, offset: 12)
        guard cursor.skipName(),
              cursor.readUInt16() == 16,
              cursor.readUInt16() == 1,
              query.count == cursor.offset,
              response[12 ..< cursor.offset].elementsEqual(query[12...]),
              cursor.skipName(),
              cursor.readUInt16() == 16,
              cursor.readUInt16() == 1,
              cursor.readUInt32() == 0,
              cursor.readUInt16() == 65,
              cursor.readUInt8() == 64,
              cursor.read(count: 64)?.elementsEqual(expected.utf8) == true,
              cursor.offset == response.count
        else {
            return false
        }
        return true
    }

    private static func append(_ value: UInt16, to data: inout Data) {
        data.append(UInt8(value >> 8))
        data.append(UInt8(value & 0xFF))
    }
}

private struct DNSHeader {
    let identifier: UInt16
    let response: Bool
    let truncated: Bool
    let operationCode: UInt8
    let responseCode: UInt8
    let questionCount: UInt16
    let answerCount: UInt16
    let authorityCount: UInt16
    let additionalCount: UInt16

    init?(data: Data) {
        guard data.count >= 12 else { return nil }
        identifier = Self.readUInt16(data, at: 0)
        let flags = Self.readUInt16(data, at: 2)
        response = flags & 0x8000 != 0
        truncated = flags & 0x0200 != 0
        operationCode = UInt8((flags & 0x7800) >> 11)
        responseCode = UInt8(flags & 0x000F)
        questionCount = Self.readUInt16(data, at: 4)
        answerCount = Self.readUInt16(data, at: 6)
        authorityCount = Self.readUInt16(data, at: 8)
        additionalCount = Self.readUInt16(data, at: 10)
    }

    private static func readUInt16(_ data: Data, at offset: Int) -> UInt16 {
        UInt16(data[offset]) << 8 | UInt16(data[offset + 1])
    }
}

private struct DNSCursor {
    let data: Data
    var offset: Int

    mutating func skipName() -> Bool {
        for _ in 0 ..< 128 {
            guard let length = readUInt8() else { return false }
            if length == 0 {
                return true
            }
            if length & 0xC0 == 0xC0 {
                guard let low = readUInt8() else { return false }
                let pointer = Int(length & 0x3F) << 8 | Int(low)
                return pointer < data.count
            }
            if length & 0xC0 != 0 {
                return false
            }
            if length > 63 || !skip(Int(length)) {
                return false
            }
        }
        return false
    }

    mutating func readUInt8() -> UInt8? {
        guard offset < data.count else { return nil }
        defer { offset += 1 }
        return data[offset]
    }

    mutating func readUInt16() -> UInt16? {
        guard let high = readUInt8(), let low = readUInt8() else { return nil }
        return UInt16(high) << 8 | UInt16(low)
    }

    mutating func readUInt32() -> UInt32? {
        guard let high = readUInt16(), let low = readUInt16() else { return nil }
        return UInt32(high) << 16 | UInt32(low)
    }

    mutating func read(count: Int) -> Data? {
        guard count >= 0,
              offset <= data.count,
              count <= data.count - offset
        else {
            return nil
        }
        defer { offset += count }
        return data.subdata(in: offset ..< offset + count)
    }

    mutating func skip(_ count: Int) -> Bool {
        read(count: count) != nil
    }
}

private final class DNSConnectionProbe: @unchecked Sendable {
    private let connection: NWConnection
    private let queue = DispatchQueue(label: "org.agenxy.remap.dns-probe", qos: .utility)
    private let state = Mutex(DNSConnectionState.idle)
    private let transport: DNSProbeTransport

    init(port: NWEndpoint.Port, transport: DNSProbeTransport) {
        self.transport = transport
        connection = NWConnection(
            host: "127.0.0.1",
            port: port,
            using: transport == .udp ? .udp : .tcp
        )
    }

    func run(_ query: Data) async -> Data? {
        await withTaskCancellationHandler {
            defer {
                connection.stateUpdateHandler = nil
                connection.cancel()
            }
            guard await start() else { return nil }
            return switch transport {
            case .udp:
                await exchangeUDP(query)
            case .tcp:
                await exchangeTCP(query)
            }
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

    private func exchangeUDP(_ query: Data) async -> Data? {
        guard await send(query) else { return nil }
        return await withCheckedContinuation { continuation in
            connection.receiveMessage { content, _, _, error in
                continuation.resume(returning: error == nil ? content : nil)
            }
        }
    }

    private func exchangeTCP(_ query: Data) async -> Data? {
        guard let size = UInt16(exactly: query.count) else { return nil }
        var frame = Data([UInt8(size >> 8), UInt8(size & 0xFF)])
        frame.append(query)
        guard await send(frame), let prefix = await receiveExactly(2) else { return nil }
        let length = Int(prefix[0]) << 8 | Int(prefix[1])
        guard length <= DNSHealthWire.maximumResponseBytes else { return nil }
        return await receiveExactly(length)
    }

    private func send(_ data: Data) async -> Bool {
        await withCheckedContinuation { continuation in
            connection.send(
                content: data,
                completion: .contentProcessed { error in
                    continuation.resume(returning: error == nil)
                }
            )
        }
    }

    private func receiveExactly(_ expected: Int) async -> Data? {
        var received = Data()
        while received.count < expected {
            let maximum = expected - received.count
            let fragment: Data? = await withCheckedContinuation { continuation in
                connection.receive(
                    minimumIncompleteLength: 1,
                    maximumLength: maximum
                ) { content, _, _, error in
                    continuation.resume(returning: error == nil ? content : nil)
                }
            }
            guard let fragment, !fragment.isEmpty else { return nil }
            received.append(fragment)
        }
        return received
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

private enum DNSProbeResult {
    case udp(Bool)
    case tcp(Bool)
    case timeout
}

private enum DNSProbeTransport {
    case udp
    case tcp
}

private enum DNSConnectionState {
    case idle
    case waiting(CheckedContinuation<Bool, Never>)
    case finished
}
