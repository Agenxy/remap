import Foundation
import RemapInstallKit

public enum RemapInstallerScript: String, Equatable, Sendable {
    case postinstall
    case preinstall
}

public struct RemapInstallerInvocation: Equatable, Sendable {
    public static let packageIdentifier = "org.agenxy.Remap.InstallerBootstrap"
    public static let maximumArgumentCount = 8
    public static let maximumArgumentByteCount = 4096

    public let script: RemapInstallerScript
    public let argumentCount: Int

    public init(arguments: [String], environment: [String: String]) throws {
        guard !arguments.isEmpty,
              arguments.count <= Self.maximumArgumentCount,
              arguments.allSatisfy(Self.isBounded),
              let scriptName = arguments.first.map({
                  URL(fileURLWithPath: $0).lastPathComponent
              }),
              let script = RemapInstallerScript(rawValue: scriptName),
              environment["SCRIPT_NAME"] == script.rawValue,
              environment["INSTALL_PKG_SESSION_ID"] == Self.packageIdentifier,
              environment["DSTROOT"] == "/",
              environment["DSTVOLUME"] == "/",
              let packagePath = environment["PACKAGE_PATH"],
              Self.isCanonicalAbsolutePath(packagePath)
        else {
            throw InstallError.integrity("the native package invocation is malformed")
        }
        self.script = script
        argumentCount = arguments.count
    }

    private static func isBounded(_ value: String) -> Bool {
        !value.contains("\0") && value.utf8.count <= maximumArgumentByteCount
    }

    private static func isCanonicalAbsolutePath(_ value: String) -> Bool {
        guard isBounded(value), value.hasPrefix("/") else {
            return false
        }
        return URL(fileURLWithPath: value).standardizedFileURL.path == value
    }
}
