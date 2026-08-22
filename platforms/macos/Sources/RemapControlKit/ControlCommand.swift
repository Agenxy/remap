import Foundation

/// One atomic registry change submitted to the authority.
public enum RemapChange: Equatable, Sendable {
    case set(
        pattern: String,
        target: String,
        hostPolicy: RemapHostPolicy,
        enabled: Bool?
    )
    case enable(pattern: String)
    case disable(pattern: String)
    case remove(pattern: String)
}

extension RemapChange: Encodable {
    private enum CodingKeys: String, CodingKey {
        case kind
        case pattern
        case target
        case hostPolicy = "host_policy"
        case enabled
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case let .set(pattern, target, hostPolicy, enabled):
            try container.encode("set", forKey: .kind)
            try container.encode(pattern, forKey: .pattern)
            try container.encode(target, forKey: .target)
            try container.encode(hostPolicy, forKey: .hostPolicy)
            try container.encodeIfPresent(enabled, forKey: .enabled)
        case let .enable(pattern):
            try encodeNamed("enable", pattern: pattern, into: &container)
        case let .disable(pattern):
            try encodeNamed("disable", pattern: pattern, into: &container)
        case let .remove(pattern):
            try encodeNamed("remove", pattern: pattern, into: &container)
        }
    }

    private func encodeNamed(
        _ kind: String,
        pattern: String,
        into container: inout KeyedEncodingContainer<CodingKeys>
    ) throws {
        try container.encode(kind, forKey: .kind)
        try container.encode(pattern, forKey: .pattern)
    }
}

/// One typed command accepted by the Remap authority.
public enum RemapControlCommand: Equatable, Sendable {
    case status
    case healthChallenge(nonce: String)
    case list(after: String?, limit: UInt16, includeDisabled: Bool)
    case get(pattern: String)
    case resolve(name: String)
    case validate(pattern: String, target: String, hostPolicy: RemapHostPolicy)
    case preview(changes: [RemapChange])
    case apply(expectedRevision: UInt64, operationID: String, changes: [RemapChange])
    case waitForRevision(after: UInt64, timeoutMilliseconds: UInt32)
}

extension RemapControlCommand: Encodable {
    private enum CodingKeys: String, CodingKey {
        case kind
        case after
        case limit
        case includeDisabled = "include_disabled"
        case pattern
        case name
        case target
        case hostPolicy = "host_policy"
        case changes
        case expectedRevision = "expected_revision"
        case operationID = "operation_id"
        case timeoutMilliseconds = "timeout_ms"
        case nonce
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .status:
            try container.encode("status", forKey: .kind)
        case let .healthChallenge(nonce):
            try encodeSingle("health_challenge", key: .nonce, value: nonce, into: &container)
        case let .list(after, limit, includeDisabled):
            try container.encode("list", forKey: .kind)
            try container.encodeIfPresent(after, forKey: .after)
            try container.encode(limit, forKey: .limit)
            try container.encode(includeDisabled, forKey: .includeDisabled)
        case let .get(pattern):
            try encodeSingle("get", key: .pattern, value: pattern, into: &container)
        case let .resolve(name):
            try encodeSingle("resolve", key: .name, value: name, into: &container)
        case let .validate(pattern, target, hostPolicy):
            try container.encode("validate", forKey: .kind)
            try container.encode(pattern, forKey: .pattern)
            try container.encode(target, forKey: .target)
            try container.encode(hostPolicy, forKey: .hostPolicy)
        case let .preview(changes):
            try container.encode("preview", forKey: .kind)
            try container.encode(changes, forKey: .changes)
        case let .apply(expectedRevision, operationID, changes):
            try container.encode("apply", forKey: .kind)
            try container.encode(expectedRevision, forKey: .expectedRevision)
            try container.encode(operationID, forKey: .operationID)
            try container.encode(changes, forKey: .changes)
        case let .waitForRevision(after, timeoutMilliseconds):
            try container.encode("wait_for_revision", forKey: .kind)
            try container.encode(after, forKey: .after)
            try container.encode(timeoutMilliseconds, forKey: .timeoutMilliseconds)
        }
    }

    private func encodeSingle(
        _ kind: String,
        key: CodingKeys,
        value: String,
        into container: inout KeyedEncodingContainer<CodingKeys>
    ) throws {
        try container.encode(kind, forKey: .kind)
        try container.encode(value, forKey: key)
    }
}

struct ControlRequest: Encodable, Sendable {
    let `protocol`: String
    let requestID: String
    let surface: String
    let clientVersion: String
    let command: RemapControlCommand

    enum CodingKeys: String, CodingKey {
        case `protocol`
        case requestID = "request_id"
        case surface
        case clientVersion = "client_version"
        case command
    }
}

struct ControlResponse: Decodable, Sendable {
    let `protocol`: String
    let requestID: String
    let result: RemapCommandResult?
    let error: RemapDiagnostic?

    enum CodingKeys: String, CodingKey {
        case `protocol`
        case requestID = "request_id"
        case result
        case error
    }
}
