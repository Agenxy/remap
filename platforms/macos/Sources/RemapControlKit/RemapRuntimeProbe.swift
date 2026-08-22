/// Authenticated status for one daemon instance and its network listeners.
public struct RemapRuntimeHealth: Equatable, Sendable {
    public let instanceID: String?
    public let daemonVersion: String?
    public let authority: Bool
    public let dns: Bool
    public let http: Bool

    public var ready: Bool {
        authority && dns && http
    }
}

public extension RemapRuntimeHealth {
    /// A fail-closed value used when no authenticated authority exists.
    static let unavailable = RemapRuntimeHealth(
        instanceID: nil,
        daemonVersion: nil,
        authority: false,
        dns: false,
        http: false
    )
}

/// Coordinates one control challenge across every local runtime listener.
public enum RemapRuntimeProbe {
    /// Returns fail-closed listener identity without throwing transport details.
    public static func verify(
        client: RemapControlClient,
        dnsPort: UInt16 = 53,
        httpPort: UInt16 = 80
    ) async -> RemapRuntimeHealth {
        guard let challenge = try? await client.runtimeChallenge() else {
            return .unavailable
        }
        async let dns = RemapDNSProbe.verify(challenge: challenge, port: dnsPort)
        async let http = RemapGatewayProbe.verify(challenge: challenge, port: httpPort)
        let (dnsReady, httpReady) = await (dns, http)
        return RemapRuntimeHealth(
            instanceID: challenge.instanceID,
            daemonVersion: challenge.daemonVersion,
            authority: true,
            dns: dnsReady,
            http: httpReady
        )
    }
}
