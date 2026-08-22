import Darwin
import Foundation

/// Stable, actionable failures produced by the native installer foundation.
public enum InstallError: Error, CustomStringConvertible, Equatable, Sendable {
    case alreadyLocked
    case approval(String)
    case collision(String)
    case durability(String, Int32)
    case faultInjected(String)
    case integrity(String)
    case invalidManifest(String)
    case invalidPath(String)
    case journal(String)
    case metadata(String)
    case notRoot
    case operatingSystem(String, Int32)
    case transaction(primary: String, recovery: String)
    case unsupported(String)

    public var description: String {
        switch self {
        case .alreadyLocked:
            "Another Remap install, update, uninstall, or recovery transaction is already running."
        case let .approval(detail):
            "Installer approval validation failed: \(detail)"
        case let .collision(path):
            "Remap will not replace an unmanaged or mismatched object at \(path)."
        case let .durability(operation, code):
            "Remap could not durably persist \(operation): \(systemMessage(code))."
        case let .faultInjected(checkpoint):
            "The test fault injector stopped the installer at \(checkpoint)."
        case let .integrity(detail):
            "Installer integrity validation failed: \(detail)"
        case let .invalidManifest(detail):
            "The install manifest is invalid: \(detail)"
        case let .invalidPath(path):
            "The installer rejected an unsafe path: \(path)"
        case let .journal(detail):
            "The install journal is invalid: \(detail)"
        case let .metadata(detail):
            "Installer metadata validation failed: \(detail)"
        case .notRoot:
            "The native installer requires root authority."
        case let .operatingSystem(operation, code):
            "The operating system could not \(operation): \(systemMessage(code))."
        case let .transaction(primary, recovery):
            "The transaction failed (\(primary)); its immediate recovery also failed (\(recovery))."
        case let .unsupported(detail):
            "This installer operation is not available: \(detail)"
        }
    }
}

private func systemMessage(_ code: Int32) -> String {
    String(cString: strerror(code))
}
