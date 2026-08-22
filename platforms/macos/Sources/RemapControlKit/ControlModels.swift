import Foundation

/// Stable local-control protocol understood by this client.
public let remapControlProtocolVersion = "remap.control/v1"

/// Maximum accepted local-control frame, including its JSON envelope.
public let remapMaximumControlFrameBytes = 1_048_576

/// Upstream Host and TLS SNI behavior for one routed mapping.
public enum RemapHostPolicy: String, Codable, CaseIterable, Sendable {
    case preserveClient = "preserve-client"
    case useUpstream = "use-upstream"
}

/// One mapping returned by the authority.
public struct RemapMapping: Codable, Equatable, Identifiable, Sendable {
    // The short property name is required by Identifiable.
    // swiftlint:disable:next identifier_name
    public var id: String {
        pattern
    }

    public let pattern: String
    public let target: String
    public let targetKind: String
    public let hostPolicy: RemapHostPolicy
    public let enabled: Bool
    public let updatedRevision: UInt64

    enum CodingKeys: String, CodingKey {
        case pattern
        case target
        case targetKind = "target_kind"
        case hostPolicy = "host_policy"
        case enabled
        case updatedRevision = "updated_revision"
    }
}

/// Current state of the authoritative registry.
public struct RemapRegistryStatus: Codable, Equatable, Sendable {
    public let revision: UInt64
    public let mappingCount: UInt64
    public let enabledCount: UInt64
    public let schemaVersion: UInt32
    public let daemonVersion: String
    public let maintenance: RemapDiagnostic?

    enum CodingKeys: String, CodingKey {
        case revision
        case mappingCount = "mapping_count"
        case enabledCount = "enabled_count"
        case schemaVersion = "schema_version"
        case daemonVersion = "daemon_version"
        case maintenance
    }
}

/// One bounded, revision-consistent registry page.
public struct RemapMappingPage: Codable, Equatable, Sendable {
    public let revision: UInt64
    public let mappings: [RemapMapping]
    public let nextCursor: String?

    enum CodingKeys: String, CodingKey {
        case revision
        case mappings
        case nextCursor = "next_cursor"
    }
}

/// Explanation of the mapping chosen for a queried name.
public struct RemapResolution: Codable, Equatable, Sendable {
    public let name: String
    public let revision: UInt64
    public let mapping: RemapMapping?
}

/// Canonical result of side-effect-free mapping validation.
public struct RemapValidation: Codable, Equatable, Sendable {
    public let pattern: String
    public let target: String
    public let targetKind: String
    public let hostPolicy: RemapHostPolicy

    enum CodingKeys: String, CodingKey {
        case pattern
        case target
        case targetKind = "target_kind"
        case hostPolicy = "host_policy"
    }
}

/// One exact before-and-after effect in a projected or committed operation.
public struct RemapChangeEffect: Codable, Equatable, Sendable {
    public let pattern: String
    public let action: String
    public let before: RemapMapping?
    public let after: RemapMapping?
}

/// Side-effect-free projection of a proposed operation.
public struct RemapPreview: Codable, Equatable, Sendable {
    public let baseRevision: UInt64
    public let willChange: Bool
    public let effects: [RemapChangeEffect]

    enum CodingKeys: String, CodingKey {
        case baseRevision = "base_revision"
        case willChange = "will_change"
        case effects
    }
}

/// Durable receipt for an idempotent committed operation.
public struct RemapApplyReceipt: Codable, Equatable, Sendable {
    public let operationID: String
    public let previousRevision: UInt64
    public let revision: UInt64
    public let changed: Bool
    public let effects: [RemapChangeEffect]

    enum CodingKeys: String, CodingKey {
        case operationID = "operation_id"
        case previousRevision = "previous_revision"
        case revision
        case changed
        case effects
    }
}

/// Bounded wait result used by revision subscribers.
public struct RemapRevisionNotice: Codable, Equatable, Sendable {
    public let revision: UInt64
    public let changed: Bool
}

/// Daemon-provided proof expectations for one fresh runtime challenge.
public struct RemapHealthChallengeResponse: Codable, Equatable, Sendable {
    public let instanceID: String
    public let daemonVersion: String
    public let dnsProof: String
    public let httpProof: String

    enum CodingKeys: String, CodingKey {
        case instanceID = "instance_id"
        case daemonVersion = "daemon_version"
        case dnsProof = "dns_proof"
        case httpProof = "http_proof"
    }
}

/// Validated runtime identity challenge retained only for its bounded probes.
public struct RemapRuntimeChallenge: Equatable, Sendable {
    public let nonce: String
    public let instanceID: String
    public let daemonVersion: String
    public let dnsProof: String
    public let httpProof: String
}

/// Stable diagnostic returned by the local authority or transport.
public struct RemapDiagnostic: Codable, Equatable, Error, Sendable {
    public let code: String
    public let message: String
    public let hint: String?
    public let retryable: Bool
    public let context: [String: String]

    public init(
        code: String,
        message: String,
        hint: String?,
        retryable: Bool,
        context: [String: String] = [:]
    ) {
        self.code = code
        self.message = message
        self.hint = hint
        self.retryable = retryable
        self.context = context
    }
}

/// Successful payload returned by one local-control command.
public enum RemapCommandResult: Equatable, Sendable {
    case status(RemapRegistryStatus)
    case healthChallenge(RemapHealthChallengeResponse)
    case list(RemapMappingPage)
    case mapping(RemapMapping?)
    case resolution(RemapResolution)
    case validation(RemapValidation)
    case preview(RemapPreview)
    case apply(RemapApplyReceipt)
    case revision(RemapRevisionNotice)
}

extension RemapCommandResult: Decodable {
    private enum CodingKeys: String, CodingKey {
        case kind
        case value
    }

    private enum Kind: String, Decodable {
        case status
        case healthChallenge = "health_challenge"
        case list
        case mapping
        case resolution
        case validation
        case preview
        case apply
        case revision
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(Kind.self, forKey: .kind) {
        case .status:
            self = try .status(container.decode(RemapRegistryStatus.self, forKey: .value))
        case .healthChallenge:
            self = try .healthChallenge(
                container.decode(RemapHealthChallengeResponse.self, forKey: .value)
            )
        case .list:
            self = try .list(container.decode(RemapMappingPage.self, forKey: .value))
        case .mapping:
            self = try .mapping(container.decodeIfPresent(RemapMapping.self, forKey: .value))
        case .resolution:
            self = try .resolution(container.decode(RemapResolution.self, forKey: .value))
        case .validation:
            self = try .validation(container.decode(RemapValidation.self, forKey: .value))
        case .preview:
            self = try .preview(container.decode(RemapPreview.self, forKey: .value))
        case .apply:
            self = try .apply(container.decode(RemapApplyReceipt.self, forKey: .value))
        case .revision:
            self = try .revision(container.decode(RemapRevisionNotice.self, forKey: .value))
        }
    }
}
