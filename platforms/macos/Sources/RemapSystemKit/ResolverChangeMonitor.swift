import Foundation
import SystemConfiguration

/// Native change source consumed by the resolver supervisor.
public protocol ResolverChangeMonitoring: Sendable {
    var events: AsyncStream<Void> { get }

    func start() throws
}

/// Coalesced native network-change events for the root resolver supervisor.
public final class ResolverChangeMonitor: ResolverChangeMonitoring, @unchecked Sendable {
    public let events: AsyncStream<Void>

    private let continuation: AsyncStream<Void>.Continuation
    private let watchedSocketPath: String?
    private let queue = DispatchQueue(label: "org.agenxy.remap.resolver-monitor", qos: .utility)
    private var store: SCDynamicStore?
    private var callbackOwner: ResolverCallbackOwner?
    private var socketDirectoryDescriptor: Int32 = -1
    private var socketDirectorySource: DispatchSourceFileSystemObject?

    public init(watchedSocketPath: String? = nil) {
        let pair = AsyncStream.makeStream(of: Void.self, bufferingPolicy: .bufferingNewest(1))
        events = pair.stream
        continuation = pair.continuation
        self.watchedSocketPath = watchedSocketPath
    }

    deinit {
        if let store {
            SCDynamicStoreSetDispatchQueue(store, nil)
        }
        socketDirectorySource?.cancel()
        continuation.finish()
    }

    /// Starts one native dynamic-store session and its coalesced event stream.
    public func start() throws {
        guard store == nil else { return }
        let owner = ResolverCallbackOwner(continuation: continuation)
        var context = SCDynamicStoreContext(
            version: 0,
            info: Unmanaged.passUnretained(owner).toOpaque(),
            retain: nil,
            release: nil,
            copyDescription: nil
        )
        guard let dynamicStore = SCDynamicStoreCreate(
            nil,
            "Agenxy Remap Resolver Supervisor" as CFString,
            resolverChanged,
            &context
        ) else {
            throw ResolverMonitorError.unavailable
        }
        let keys = [
            "State:/Network/Global/IPv4",
            "State:/Network/Global/IPv6"
        ] as CFArray
        let patterns = [
            "State:/Network/Service/[^/]+/(DNS|IPv4|IPv6|Link)",
            "State:/Network/Interface/[^/]+/(IPv4|IPv6|Link)"
        ] as CFArray
        guard SCDynamicStoreSetNotificationKeys(dynamicStore, keys, patterns),
              SCDynamicStoreSetDispatchQueue(dynamicStore, queue)
        else {
            throw ResolverMonitorError.unavailable
        }
        callbackOwner = owner
        store = dynamicStore
        try startSocketDirectoryMonitor()
    }

    private func startSocketDirectoryMonitor() throws {
        guard let watchedSocketPath else { return }
        let directory = URL(fileURLWithPath: watchedSocketPath).deletingLastPathComponent().path
        let descriptor = open(directory, O_EVTONLY | O_CLOEXEC | O_NOFOLLOW)
        guard descriptor >= 0 else { throw ResolverMonitorError.unavailable }
        let source = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: descriptor,
            eventMask: [.delete, .rename, .write],
            queue: queue
        )
        let continuation = continuation
        source.setEventHandler {
            _ = continuation.yield(())
        }
        source.setCancelHandler {
            close(descriptor)
        }
        socketDirectoryDescriptor = descriptor
        socketDirectorySource = source
        source.resume()
    }
}

/// Native monitor startup failures intentionally omit service and interface names.
public enum ResolverMonitorError: Error, CustomStringConvertible {
    case unavailable

    public var description: String {
        "The native network-change monitor could not start."
    }
}

private final class ResolverCallbackOwner: @unchecked Sendable {
    let continuation: AsyncStream<Void>.Continuation

    init(continuation: AsyncStream<Void>.Continuation) {
        self.continuation = continuation
    }
}

private func resolverChanged(
    _: SCDynamicStore,
    _: CFArray,
    info: UnsafeMutableRawPointer?
) {
    guard let info else { return }
    let owner = Unmanaged<ResolverCallbackOwner>.fromOpaque(info).takeUnretainedValue()
    _ = owner.continuation.yield(())
}
