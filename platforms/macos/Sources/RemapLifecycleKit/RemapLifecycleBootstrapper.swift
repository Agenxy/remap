import Darwin
import Foundation
import RemapInstallKit

public struct RemapLifecycleBootstrapper: Sendable {
    private static let maximumPlistByteCount = 65536

    private let authority: FileSystemAuthority
    private let authenticator: RemapLifecycleCallerAuthenticator

    public static func production() throws -> Self {
        let configuration = try RemapLifecycleServiceConfiguration.production()
        return try production(configuration: configuration)
    }

    public static func production(
        configuration: RemapLifecycleServiceConfiguration
    ) throws -> Self {
        try Self(
            authority: FileSystemAuthority(systemRootPath: "/"),
            authenticator: RemapLifecycleCallerAuthenticator(
                configuration: configuration
            )
        )
    }

    init(
        authority: FileSystemAuthority,
        authenticator: RemapLifecycleCallerAuthenticator
    ) {
        self.authority = authority
        self.authenticator = authenticator
    }

    public func bootstrap() throws {
        try authenticator.authorizeBootstrap()
        try validateInstalledAuthority()
        try MacOSInstallerServiceLaunchd.bootstrap()
    }

    public func validateInstalledAuthority() throws {
        try validateInstalledHelper()
        try validateLaunchdPlist()
    }

    private func validateInstalledHelper() throws {
        let helperPath = try InstallRelativePath(
            "Library/PrivilegedHelperTools/org.agenxy.Remap.installer-service"
        )
        let descriptor = try authority.openUniqueRegularFile(at: helperPath)
        defer { close(descriptor) }
        var status = stat()
        guard fstat(descriptor, &status) == 0,
              status.st_mode & S_IFMT == S_IFREG,
              status.st_uid == 0,
              status.st_gid == 0,
              status.st_mode & 0o777 == 0o555,
              status.st_nlink == 1,
              status.st_size > 0,
              UInt64(status.st_size) <= 134_217_728,
              status.st_flags == 0
        else {
            throw InstallError.metadata("the installed lifecycle helper has unsafe metadata")
        }
        try authority.validateNoUnexpectedExtendedMetadata(descriptor)
        try authenticator.authorizeHelper(fileDescriptor: descriptor)
    }

    private func validateLaunchdPlist() throws {
        let plistPath = try InstallRelativePath(
            "Library/LaunchDaemons/org.agenxy.Remap.installer-service.plist"
        )
        guard let metadata = try authority.metadata(at: plistPath),
              metadata.kind == .regularFile,
              metadata.ownerUID == 0,
              metadata.groupGID == 0,
              metadata.mode == 0o644,
              metadata.linkCount == 1,
              metadata.byteCount <= UInt64(Self.maximumPlistByteCount),
              !metadata.hasACL,
              metadata.flags == 0
        else {
            throw InstallError.metadata("the lifecycle launchd plist has unsafe metadata")
        }
        let descriptor = try authority.openUniqueRegularFile(at: plistPath)
        defer { close(descriptor) }
        try authority.validateNoUnexpectedExtendedMetadata(descriptor)
        let data = try authority.readUniqueFile(
            at: plistPath,
            maximumByteCount: Self.maximumPlistByteCount
        )
        let value = try PropertyListSerialization.propertyList(
            from: data,
            options: [],
            format: nil
        )
        guard let document = value as? [String: Any],
              NSDictionary(dictionary: document).isEqual(to: Self.launchdDocument)
        else {
            throw InstallError.integrity("the lifecycle launchd plist is not exact")
        }
    }

    public static var launchdDocument: [String: Any] {
        [
            "HardResourceLimits": ["Core": 0, "NumberOfFiles": 128],
            "Label": MacOSInstallerServiceLaunchd.label,
            "MachServices": [MacOSInstallerServiceLaunchd.label: true],
            "ProcessType": "Interactive",
            "ProgramArguments": [MacOSInstallerServiceLaunchd.programPath],
            "SoftResourceLimits": ["NumberOfFiles": 128],
            "StandardErrorPath": "/dev/null",
            "StandardOutPath": "/dev/null",
            "ThrottleInterval": 5,
            "Umask": 0o077
        ]
    }
}
