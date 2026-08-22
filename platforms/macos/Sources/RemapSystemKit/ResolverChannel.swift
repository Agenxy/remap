import Darwin
import Foundation

/// Resolver-only request contract accepted by the per-user Remap authority.
public struct ResolverSystemRequest: Encodable, Sendable {
    public let protocolVersion = "remap.system/v1"
    public let requestID: UUID
    public let command: ResolverSystemCommand

    enum CodingKeys: String, CodingKey {
        case protocolVersion = "protocol"
        case requestID = "request_id"
        case command
    }
}

/// Commands available to the privileged resolver supervisor.
public enum ResolverSystemCommand: Encodable, Sendable {
    case publish(activationID: UUID, generation: UInt64, upstreams: [String])
    case invalidate(activationID: UUID, generation: UInt64)
    case health

    enum CodingKeys: String, CodingKey {
        case kind
        case activationID = "activation_id"
        case generation
        case upstreams
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case let .publish(activationID, generation, upstreams):
            try container.encode("publish_resolver_plan", forKey: .kind)
            try container.encode(activationID, forKey: .activationID)
            try container.encode(generation, forKey: .generation)
            try container.encode(upstreams, forKey: .upstreams)
        case let .invalidate(activationID, generation):
            try container.encode("invalidate_resolver_plan", forKey: .kind)
            try container.encode(activationID, forKey: .activationID)
            try container.encode(generation, forKey: .generation)
        case .health:
            try container.encode("resolver_health", forKey: .kind)
        }
    }
}

/// Non-sensitive resolver state returned to the privileged supervisor.
public struct ResolverSystemResult: Decodable, Equatable, Sendable {
    public let activationID: UUID?
    public let activeGeneration: UInt64?

    enum CodingKeys: String, CodingKey {
        case activationID = "activation_id"
        case activeGeneration = "active_generation"
    }
}

/// Bounded response from the per-user authority.
public struct ResolverSystemResponse: Decodable, Sendable {
    public let protocolVersion: String
    public let requestID: UUID
    public let result: ResolverSystemResult?
    public let error: ResolverSystemDiagnostic?

    enum CodingKeys: String, CodingKey {
        case protocolVersion = "protocol"
        case requestID = "request_id"
        case result
        case error
    }
}

/// Sanitized resolver-channel failure returned by the daemon.
public struct ResolverSystemDiagnostic: Decodable, Error, Sendable {
    public let code: String
    public let message: String
    public let hint: String?
    public let retryable: Bool
}

/// A root-side Unix transport that authenticates the daemon's effective user.
public struct ResolverSystemChannel: Sendable {
    public let socketPath: String
    public let expectedPeerUID: uid_t

    public init(socketPath: String, expectedPeerUID: uid_t) {
        self.socketPath = socketPath
        self.expectedPeerUID = expectedPeerUID
    }

    public func exchange(_ command: ResolverSystemCommand) throws -> ResolverSystemResult {
        let request = ResolverSystemRequest(requestID: UUID(), command: command)
        let payload = try systemEncoder.encode(request)
        guard payload.count <= maximumSystemFrameBytes else {
            throw ResolverChannelError.frameTooLarge
        }
        let descriptor = try connectUnixSocket(path: socketPath)
        defer { close(descriptor) }
        try authenticatePeer(descriptor: descriptor, expectedUID: expectedPeerUID)
        let deadline = DispatchTime.now().uptimeNanoseconds + 250_000_000
        var length = UInt32(payload.count).bigEndian
        try withUnsafeBytes(of: &length) { try writeAll(descriptor, bytes: $0, deadline: deadline) }
        try payload.withUnsafeBytes { try writeAll(descriptor, bytes: $0, deadline: deadline) }
        let responseData = try readFrame(descriptor, deadline: deadline)
        let response = try systemDecoder.decode(ResolverSystemResponse.self, from: responseData)
        guard response.protocolVersion == request.protocolVersion,
              response.requestID == request.requestID
        else {
            throw ResolverChannelError.invalidResponse
        }
        if let error = response.error {
            throw error
        }
        guard let result = response.result else {
            throw ResolverChannelError.invalidResponse
        }
        return result
    }
}

/// Local resolver-channel failures that never expose paths or upstream addresses.
public enum ResolverChannelError: Error, CustomStringConvertible, Equatable {
    case frameTooLarge
    case invalidResponse
    case peerMismatch
    case transport

    public var description: String {
        switch self {
        case .frameTooLarge: "The resolver-supervisor frame exceeds its 16 KiB limit."
        case .invalidResponse: "The Remap authority returned an invalid resolver response."
        case .peerMismatch: "The resolver socket is not owned by the expected Remap account."
        case .transport: "The resolver supervisor could not reach the Remap authority."
        }
    }
}

private let maximumSystemFrameBytes = 16 * 1024
private let systemEncoder: JSONEncoder = {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    return encoder
}()

private let systemDecoder = JSONDecoder()

private func connectUnixSocket(path: String) throws -> Int32 {
    let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
    guard descriptor >= 0 else { throw ResolverChannelError.transport }
    do {
        guard fcntl(descriptor, F_SETFD, FD_CLOEXEC) == 0 else {
            throw ResolverChannelError.transport
        }
        var address = sockaddr_un()
        let bytes = Array(path.utf8CString)
        guard bytes.count <= MemoryLayout.size(ofValue: address.sun_path) else {
            throw ResolverChannelError.transport
        }
        guard let pathOffset = MemoryLayout.offset(of: \sockaddr_un.sun_path) else {
            throw ResolverChannelError.transport
        }
        let addressLength = pathOffset + bytes.count
        guard addressLength <= Int(UInt8.max) else {
            throw ResolverChannelError.transport
        }
        address.sun_len = UInt8(addressLength)
        address.sun_family = sa_family_t(AF_UNIX)
        let copied = withUnsafeMutableBytes(of: &address) { destination in
            guard let destinationBase = destination.baseAddress else {
                return false
            }
            return bytes.withUnsafeBytes { source in
                guard let sourceBase = source.baseAddress else {
                    return false
                }
                memcpy(destinationBase.advanced(by: pathOffset), sourceBase, bytes.count)
                return true
            }
        }
        guard copied else { throw ResolverChannelError.transport }
        let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(descriptor, $0, socklen_t(addressLength))
            }
        }
        guard result == 0 else { throw ResolverChannelError.transport }
        return descriptor
    } catch {
        close(descriptor)
        throw error
    }
}

private func authenticatePeer(descriptor: Int32, expectedUID: uid_t) throws {
    var userID: uid_t = 0
    var groupID: gid_t = 0
    guard getpeereid(descriptor, &userID, &groupID) == 0, userID == expectedUID else {
        throw ResolverChannelError.peerMismatch
    }
}

private func writeAll(
    _ descriptor: Int32,
    bytes: UnsafeRawBufferPointer,
    deadline: UInt64
) throws {
    var written = 0
    while written < bytes.count {
        try waitFor(descriptor: descriptor, event: Int16(POLLOUT), deadline: deadline)
        let count = Darwin.write(descriptor, bytes.baseAddress?.advanced(by: written), bytes.count - written)
        if count > 0 {
            written += count
        } else if count < 0, errno == EINTR || errno == EAGAIN {
            continue
        } else {
            throw ResolverChannelError.transport
        }
    }
}

private func readFrame(_ descriptor: Int32, deadline: UInt64) throws -> Data {
    var length = UInt32.zero
    try withUnsafeMutableBytes(of: &length) {
        try readExactly(descriptor, bytes: $0, deadline: deadline)
    }
    let count = Int(UInt32(bigEndian: length))
    guard count <= maximumSystemFrameBytes else {
        throw ResolverChannelError.frameTooLarge
    }
    var payload = Data(count: count)
    try payload.withUnsafeMutableBytes {
        try readExactly(descriptor, bytes: $0, deadline: deadline)
    }
    return payload
}

private func readExactly(
    _ descriptor: Int32,
    bytes: UnsafeMutableRawBufferPointer,
    deadline: UInt64
) throws {
    var readCount = 0
    while readCount < bytes.count {
        try waitFor(descriptor: descriptor, event: Int16(POLLIN), deadline: deadline)
        let count = Darwin.read(
            descriptor,
            bytes.baseAddress?.advanced(by: readCount),
            bytes.count - readCount
        )
        if count > 0 {
            readCount += count
        } else if count < 0, errno == EINTR || errno == EAGAIN {
            continue
        } else {
            throw ResolverChannelError.transport
        }
    }
}

private func waitFor(descriptor: Int32, event: Int16, deadline: UInt64) throws {
    var descriptorState = pollfd(fd: descriptor, events: event, revents: 0)
    while true {
        let now = DispatchTime.now().uptimeNanoseconds
        guard now < deadline else { throw ResolverChannelError.transport }
        let remainingMilliseconds = (deadline - now).dividedReportingOverflow(by: 1_000_000)
        let timeout = Int32(min(remainingMilliseconds.partialValue + 1, UInt64(Int32.max)))
        let result = poll(&descriptorState, 1, timeout)
        if result > 0, descriptorState.revents & event != 0 {
            return
        }
        if result < 0, errno == EINTR {
            continue
        }
        throw ResolverChannelError.transport
    }
}
