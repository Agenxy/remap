import Foundation

/// The single bounded message surface exported by Remap's privileged lifecycle
/// service. Requests and replies are validated Codable documents rather than
/// dynamically shaped Objective-C objects.
@objc public protocol RemapLifecycleXPCServiceProtocol {
    func perform(
        _ request: Data,
        withReply reply: @escaping (Data) -> Void
    )
}

public enum RemapLifecycleXPC {
    public static let machServiceName = "org.agenxy.Remap.installer-service"
    public static let maximumRequestByteCount = 65536
    public static let maximumResponseByteCount = 1_048_576
}
