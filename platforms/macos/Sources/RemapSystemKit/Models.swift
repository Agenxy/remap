import CryptoKit
import Foundation

/// One enabled macOS network service and its effective upstream resolvers.
public struct DNSServicePlan: Codable, Equatable, Sendable {
    public let serviceID: String
    public let upstreams: [String]

    public init(serviceID: String, upstreams: [String]) {
        self.serviceID = serviceID
        self.upstreams = upstreams
    }
}

/// Read-only native DNS plan used before installation changes the system.
public struct DNSPlan: Codable, Equatable, Sendable {
    public let schemaVersion: UInt32
    public let services: [DNSServicePlan]
    public let upstreams: [String]

    public init(services: [DNSServicePlan]) {
        schemaVersion = 1
        self.services = services
        upstreams = stableUnique(services.flatMap(\.upstreams))
    }
}

func stableUnique(_ values: [String]) -> [String] {
    var seen: Set<String> = []
    return values.filter { seen.insert($0).inserted }
}

/// Read-only effective resolver state visible to an unprivileged management app.
public struct ResolverObservation: Codable, Equatable, Sendable {
    public let schemaVersion: UInt32
    public let activeServiceIDs: [String]
    public let remapServiceIDs: [String]

    public var isRemapActive: Bool {
        !remapServiceIDs.isEmpty
    }

    public init(activeServiceIDs: [String], remapServiceIDs: [String]) {
        schemaVersion = 1
        self.activeServiceIDs = activeServiceIDs.sorted()
        self.remapServiceIDs = remapServiceIDs.sorted()
    }
}

/// Reversible DNS state for one native network service.
public struct DNSServiceRecord: Codable, Equatable, Sendable {
    public let serviceID: String
    public let priorConfiguration: Data?
    /// Whether the stored DNS protocol entity was enabled before activation.
    /// Optionality preserves exact decoding and digest verification for records
    /// written by the first source-installer schema.
    public let priorEnabled: Bool?
    public let installedConfiguration: Data
    public let upstreams: [String]
    /// Native network signature captured with the upstream resolver set.
    /// Older activation records omit this field and therefore cannot reuse a
    /// captured resolver when no current provenance is available.
    public let networkSignature: Data?

    public init(
        serviceID: String,
        priorConfiguration: Data?,
        priorEnabled: Bool? = nil,
        installedConfiguration: Data,
        upstreams: [String],
        networkSignature: Data? = nil
    ) {
        self.serviceID = serviceID
        self.priorConfiguration = priorConfiguration
        self.priorEnabled = priorEnabled
        self.installedConfiguration = installedConfiguration
        self.upstreams = upstreams
        self.networkSignature = networkSignature
    }
}

/// Integrity-covered native activation payload.
public enum ActivationPhase: String, Codable, Equatable, Sendable {
    case prepared
    case active
}

/// Integrity-covered native activation payload.
public struct ActivationPayload: Codable, Equatable, Sendable {
    public let schemaVersion: UInt32
    public let ownerUID: UInt32
    public let createdAtMilliseconds: UInt64
    public let productVersion: String
    public let phase: ActivationPhase
    public let services: [DNSServiceRecord]

    public init(
        ownerUID: UInt32,
        createdAtMilliseconds: UInt64,
        productVersion: String,
        phase: ActivationPhase,
        services: [DNSServiceRecord]
    ) {
        schemaVersion = 1
        self.ownerUID = ownerUID
        self.createdAtMilliseconds = createdAtMilliseconds
        self.productVersion = productVersion
        self.phase = phase
        self.services = services
    }

    public func withPhase(_ phase: ActivationPhase) -> ActivationPayload {
        ActivationPayload(
            ownerUID: ownerUID,
            createdAtMilliseconds: createdAtMilliseconds,
            productVersion: productVersion,
            phase: phase,
            services: services
        )
    }
}

/// Root-owned activation record with a canonical SHA-256 integrity value.
public struct ActivationRecord: Codable, Equatable, Sendable {
    public let payload: ActivationPayload
    public let sha256: String

    public init(payload: ActivationPayload) throws {
        self.payload = payload
        sha256 = try Self.digest(payload)
    }

    public func verify() throws {
        let expected = try Self.digest(payload)
        guard sha256 == expected else {
            throw ResolverError.activationRecordIntegrity
        }
    }

    /// Stable activation identity derived from the verified record digest.
    public func activationIdentifier() throws -> UUID {
        try verify()
        // A prepared activation is deliberately published to the daemon before
        // SystemConfiguration points the Mac at loopback. Bind both phases to
        // the final active record so committing the phase cannot change the
        // daemon's authenticated activation identity.
        let identityDigest = if payload.phase == .prepared {
            try Self.digest(payload.withPhase(.active))
        } else {
            sha256
        }
        let compact = String(identityDigest.prefix(32))
        let parts = [8, 4, 4, 4, 12]
        var offset = compact.startIndex
        var segments: [Substring] = []
        for length in parts {
            let end = compact.index(offset, offsetBy: length)
            segments.append(compact[offset ..< end])
            offset = end
        }
        guard let identifier = UUID(uuidString: segments.joined(separator: "-")) else {
            throw ResolverError.invalidActivationRecord
        }
        return identifier
    }

    private static func digest(_ payload: ActivationPayload) throws -> String {
        let encoded = try CanonicalJSON.encoder.encode(payload)
        return SHA256.hash(data: encoded).map { String(format: "%02x", $0) }.joined()
    }
}

enum CanonicalJSON {
    static let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return encoder
    }()

    static let decoder = JSONDecoder()
}

/// Stable native integration failures returned by `remap-system`.
public enum ResolverError: Error, CustomStringConvertible, Equatable {
    case activationAlreadyExists
    case activationRecordIntegrity
    case activationRecordMissing
    case activeUserMismatch
    case configurationConflict([String])
    case invalidActivationRecord
    case listenerUnavailable
    case noEnabledDNSService
    case noUsableUpstream
    case notRoot
    case preferences(String)
    case secureStorage(String)
    case unsupportedResolverScope(Int)

    public var description: String {
        switch self {
        case .activationAlreadyExists:
            "Remap DNS is already activated; inspect status or deactivate it first."
        case .activationRecordIntegrity:
            "The native activation record failed its integrity check; do not change DNS automatically."
        case .activationRecordMissing:
            "No native Remap DNS activation record exists."
        case .activeUserMismatch:
            "The requested owner is not the active macOS console user."
        case let .configurationConflict(services):
            "DNS changed outside Remap for service IDs: \(services.joined(separator: ", "))."
        case .invalidActivationRecord:
            "The native activation record is malformed or unsupported."
        case .listenerUnavailable:
            "The local Remap DNS listener did not answer a valid loopback query."
        case .noEnabledDNSService:
            "No enabled macOS network service exposes a DNS protocol."
        case .noUsableUpstream:
            "No non-loopback upstream DNS server is currently available."
        case .notRoot:
            "Changing system DNS requires the native privileged installer."
        case let .preferences(operation):
            "SystemConfiguration could not \(operation)."
        case let .secureStorage(operation):
            "The root-owned activation store could not \(operation)."
        case let .unsupportedResolverScope(count):
            "Remap found \(count) active DNS service scopes; this source backend refuses to flatten split DNS."
        }
    }
}
