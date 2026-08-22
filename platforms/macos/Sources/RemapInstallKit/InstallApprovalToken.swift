import Foundation

/// A single-use approval capability bound to one exact installer preview and
/// the authoritative system state observed while producing it.
public struct InstallApprovalToken: Codable, CustomStringConvertible, Equatable, Hashable, Sendable {
    private static let domain = Data("org.agenxy.remap.install-approval.v1\0".utf8)

    private let digest: InstallDigest

    public var description: String {
        digest.description
    }

    public init(_ value: String) throws {
        digest = try InstallDigest(value)
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        do {
            try self.init(container.decode(String.self))
        } catch {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "Invalid installer approval token"
            )
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(description)
    }

    static func bind(to canonicalPayload: Data) -> Self {
        var bytes = Self.domain
        bytes.append(canonicalPayload)
        return Self(digest: InstallDigest.hash(bytes))
    }

    private init(digest: InstallDigest) {
        self.digest = digest
    }
}
