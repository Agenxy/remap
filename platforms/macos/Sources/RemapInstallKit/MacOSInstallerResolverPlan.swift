import Foundation

/// A bounded resolver plan suitable for the portable daemon's startup contract.
public struct MacOSInstallerResolverPlan: Encodable, Equatable, Sendable {
    public static let maximumUpstreamCount = 4

    public let schemaVersion = 1
    public let serviceCount: Int
    public let upstreams: [String]

    public init(serviceCount: Int, upstreamAddresses: [String]) throws {
        guard !upstreamAddresses.isEmpty else {
            throw InstallError.integrity("the native resolver plan has no upstreams")
        }
        guard upstreamAddresses.count <= Self.maximumUpstreamCount else {
            throw InstallError.integrity("the native resolver plan exceeds remapd's four-upstream limit")
        }
        self.serviceCount = serviceCount
        upstreams = try upstreamAddresses.map(Self.resolverEndpoint)
    }

    private static func resolverEndpoint(_ address: String) throws -> String {
        let endpoint = address.contains(":") ? "[\(address)]:53" : "\(address):53"
        guard endpoint.utf8.count <= 128 else {
            throw InstallError.integrity("the native resolver plan contains an oversized address")
        }
        return endpoint
    }
}
