import Darwin
import Foundation

/// Stable boundaries where tests can model abrupt I/O failure without production runtime switches.
public enum InstallCheckpoint: String, CaseIterable, Sendable {
    case afterCopyData
    case beforeCreateDirectory
    case beforeCreateFile
    case beforeDirectorySync
    case beforeFileSync
    case beforeJournalAppend
    case beforeMetadata
    case beforeOpenComponent
    case beforeRemove
    case beforeRename
}

/// An injected fault source. Production uses `NoInstallFaultInjector` directly.
public protocol InstallFaultInjecting: Sendable {
    func check(_ checkpoint: InstallCheckpoint) throws
}

/// Production fault policy, with no environment-variable or command-line override.
public struct NoInstallFaultInjector: InstallFaultInjecting {
    public init() {}

    public func check(_: InstallCheckpoint) throws {}
}

/// A durability boundary that permits deterministic fault tests.
public protocol InstallDurability: Sendable {
    func syncDirectory(_ descriptor: Int32, operation: String) throws
    func syncFile(_ descriptor: Int32, operation: String) throws
}

/// Production macOS durability using full file sync and directory sync.
public struct FullInstallDurability: InstallDurability {
    public init() {}

    public func syncDirectory(_ descriptor: Int32, operation: String) throws {
        guard fsync(descriptor) == 0 else {
            throw InstallError.durability(operation, errno)
        }
    }

    public func syncFile(_ descriptor: Int32, operation: String) throws {
        guard fcntl(descriptor, F_FULLFSYNC) == 0 else {
            throw InstallError.durability(operation, errno)
        }
    }
}
