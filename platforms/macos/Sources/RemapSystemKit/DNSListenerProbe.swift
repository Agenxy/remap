import Darwin
import Foundation

enum DNSListenerProbe {
    private static let headerLength = 12
    private static let timeoutSeconds = 2

    static func run() throws {
        let descriptor = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard descriptor >= 0 else {
            throw ResolverError.listenerUnavailable
        }
        defer { close(descriptor) }
        try configureTimeout(descriptor)
        try connectToLoopback(descriptor)

        let identifier = UInt16.random(in: 1 ... UInt16.max)
        let query = makeQuery(identifier: identifier, nonce: UUID().uuidString)
        let sent = query.withUnsafeBytes { buffer in
            send(descriptor, buffer.baseAddress, buffer.count, 0)
        }
        guard sent == query.count else {
            throw ResolverError.listenerUnavailable
        }

        var response = Data(count: 4096)
        let received = response.withUnsafeMutableBytes { buffer in
            recv(descriptor, buffer.baseAddress, buffer.count, 0)
        }
        guard received >= headerLength else {
            throw ResolverError.listenerUnavailable
        }
        response.removeSubrange(received ..< response.count)
        guard validates(response: response, identifier: identifier) else {
            throw ResolverError.listenerUnavailable
        }
    }

    static func makeQuery(identifier: UInt16, nonce: String) -> Data {
        var query = Data()
        append(identifier, to: &query)
        append(0x0100, to: &query)
        append(1, to: &query)
        append(0, to: &query)
        append(0, to: &query)
        append(0, to: &query)
        let label = "probe-\(nonce.prefix(32).lowercased())"
        appendLabel(label, to: &query)
        appendLabel("invalid", to: &query)
        query.append(0)
        append(1, to: &query)
        append(1, to: &query)
        return query
    }

    static func validates(response: Data, identifier: UInt16) -> Bool {
        guard response.count >= headerLength else {
            return false
        }
        let receivedIdentifier = UInt16(response[0]) << 8 | UInt16(response[1])
        let flags = UInt16(response[2]) << 8 | UInt16(response[3])
        let questionCount = UInt16(response[4]) << 8 | UInt16(response[5])
        return receivedIdentifier == identifier
            && flags & 0x8000 != 0
            && flags & 0x7800 == 0
            && questionCount == 1
    }

    private static func configureTimeout(_ descriptor: Int32) throws {
        var timeout = timeval(tv_sec: timeoutSeconds, tv_usec: 0)
        let result = withUnsafePointer(to: &timeout) { pointer in
            setsockopt(
                descriptor,
                SOL_SOCKET,
                SO_RCVTIMEO,
                pointer,
                socklen_t(MemoryLayout<timeval>.size)
            )
        }
        guard result == 0 else {
            throw ResolverError.listenerUnavailable
        }
    }

    private static func connectToLoopback(_ descriptor: Int32) throws {
        var address = sockaddr_in(
            sin_len: UInt8(MemoryLayout<sockaddr_in>.size),
            sin_family: sa_family_t(AF_INET),
            sin_port: UInt16(53).bigEndian,
            sin_addr: in_addr(s_addr: inet_addr("127.0.0.1")),
            sin_zero: (0, 0, 0, 0, 0, 0, 0, 0)
        )
        let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { socketAddress in
                connect(
                    descriptor,
                    socketAddress,
                    socklen_t(MemoryLayout<sockaddr_in>.size)
                )
            }
        }
        guard result == 0 else {
            throw ResolverError.listenerUnavailable
        }
    }

    private static func append(_ value: UInt16, to data: inout Data) {
        data.append(UInt8(value >> 8))
        data.append(UInt8(value & 0x00FF))
    }

    private static func appendLabel(_ value: String, to data: inout Data) {
        let bytes = Array(value.utf8.prefix(63))
        data.append(UInt8(bytes.count))
        data.append(contentsOf: bytes)
    }
}
