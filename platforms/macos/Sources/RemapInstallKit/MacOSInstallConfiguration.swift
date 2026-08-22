import Foundation

/// Manifest-bound native settings stored inside every immutable macOS generation.
public struct MacOSInstallConfiguration: Codable, Equatable, Sendable {
    public static let entryName = ".remap-macos-install-v2.json"

    public let schemaVersion: UInt32
    public let ownerUID: UInt32
    public let dataDirectory: InstallAbsolutePath
    public let controlSocket: InstallAbsolutePath
    public let dnsPort: UInt16
    public let httpPort: UInt16
    public let signingCertificateSHA256: InstallDigest

    var systemSocketPath: String {
        "/var/run/org.agenxy.Remap.system.sock"
    }

    public init(
        ownerUID: UInt32,
        dataDirectory: InstallAbsolutePath,
        controlSocket: InstallAbsolutePath,
        signingCertificateSHA256: InstallDigest,
        dnsPort: UInt16 = 53,
        httpPort: UInt16 = 80
    ) throws {
        guard ownerUID != 0 else {
            throw InstallError.invalidManifest("the native daemon must not run as root")
        }
        guard dnsPort != 0, httpPort != 0, dnsPort != httpPort else {
            throw InstallError.invalidManifest("native listener ports must be distinct and nonzero")
        }
        guard controlSocket.value == dataDirectory.value + "/control.sock" else {
            throw InstallError.invalidManifest("the control socket must be inside the native data directory")
        }
        guard controlSocket.value.utf8.count < 104 else {
            throw InstallError.invalidManifest("the native control socket path exceeds the macOS Unix-socket limit")
        }
        schemaVersion = 2
        self.ownerUID = ownerUID
        self.dataDirectory = dataDirectory
        self.controlSocket = controlSocket
        self.dnsPort = dnsPort
        self.httpPort = httpPort
        self.signingCertificateSHA256 = signingCertificateSHA256
    }

    public func validate(for manifest: InstallManifest) throws {
        try validate(for: manifest, installOwnerUID: 0, installGroupGID: 0)
    }

    func validate(
        for manifest: InstallManifest,
        installOwnerUID: UInt32,
        installGroupGID: UInt32
    ) throws {
        guard manifest.productIdentifier == "org.agenxy.Remap" else {
            throw InstallError.invalidManifest("the native package has the wrong product identity")
        }
        let reconstructed = try MacOSInstallConfiguration(
            ownerUID: ownerUID,
            dataDirectory: dataDirectory,
            controlSocket: controlSocket,
            signingCertificateSHA256: signingCertificateSHA256,
            dnsPort: dnsPort,
            httpPort: httpPort
        )
        guard schemaVersion == 2, reconstructed == self else {
            throw InstallError.invalidManifest("native install configuration schema validation failed")
        }
        let entryPath = try InstallRelativePath(Self.entryName)
        guard let configuration = manifest.entries.first(where: { $0.path == entryPath }),
              configuration.kind == .regularFile,
              configuration.role == .support,
              configuration.ownerUID == installOwnerUID,
              configuration.groupGID == installGroupGID,
              configuration.mode == 0o444
        else {
            throw InstallError.invalidManifest("the native install configuration is not manifest-bound")
        }
        let account = try MacOSAccountLookup.account(for: ownerUID)
        let expectedDirectory = account.homeDirectory.value
            + "/Library/Application Support/org.Agenxy.Remap"
        guard dataDirectory.value == expectedDirectory else {
            throw InstallError.invalidManifest("the native data directory does not belong to the daemon account")
        }
        try validateInstallerEntry(
            in: manifest,
            installOwnerUID: installOwnerUID,
            installGroupGID: installGroupGID
        )
        try validateCurrentPublication(in: manifest)
        try MacOSLaunchdServiceKind.allCases.forEach { service in
            try service.validateEntries(
                in: manifest,
                installOwnerUID: installOwnerUID,
                installGroupGID: installGroupGID
            )
        }
    }

    private func validateInstallerEntry(
        in manifest: InstallManifest,
        installOwnerUID: UInt32,
        installGroupGID: UInt32
    ) throws {
        let path = try InstallRelativePath("libexec/remap-install")
        guard let entry = manifest.entries.first(where: { $0.path == path }),
              entry.kind == .regularFile,
              entry.role == .support,
              entry.ownerUID == installOwnerUID,
              entry.groupGID == installGroupGID,
              entry.mode == 0o555
        else {
            throw InstallError.invalidManifest("the immutable generation has no trusted recovery installer")
        }
    }

    private func validateCurrentPublication(in manifest: InstallManifest) throws {
        let path = try InstallRelativePath("\(MacOSInstallLayout.installerBase)/current")
        let target = try InstallSymlinkTarget(
            "/\(MacOSInstallLayout.installerBase)/Generations/\(manifest.generationID)"
        )
        guard manifest.publications.contains(where: {
            $0.path == path
                && $0.kind == .symbolicLink
                && $0.target == target
                && $0.generationID == manifest.generationID
        }) else {
            throw InstallError.invalidManifest("the native package has no exact current-generation publication")
        }
    }
}

enum MacOSLaunchdServiceKind: String, CaseIterable, Sendable {
    case daemon
    case resolver

    var label: String {
        "org.agenxy.Remap.\(rawValue)"
    }

    var plistEntry: String {
        "launchd/\(label).plist"
    }

    var programEntry: String {
        switch self {
        case .daemon:
            "libexec/remapd"
        case .resolver:
            "libexec/remap-resolver"
        }
    }

    func validateEntries(
        in manifest: InstallManifest,
        installOwnerUID: UInt32,
        installGroupGID: UInt32
    ) throws {
        let plistPath = try InstallRelativePath(plistEntry)
        let programPath = try InstallRelativePath(programEntry)
        let plist = manifest.entries.first { $0.path == plistPath }
        let program = manifest.entries.first { $0.path == programPath }
        guard plist?.kind == .regularFile,
              plist?.role == .support,
              plist?.ownerUID == installOwnerUID,
              plist?.groupGID == installGroupGID,
              plist?.mode == 0o444,
              program?.kind == .regularFile,
              program?.ownerUID == installOwnerUID,
              program?.groupGID == installGroupGID,
              program?.mode == 0o555,
              serviceRoleIsValid(program?.role)
        else {
            throw InstallError.invalidManifest("\(label) paths are not bound to immutable root-owned files")
        }
        try validatePublication(
            manifest,
            plist: plist,
            installOwnerUID: installOwnerUID,
            installGroupGID: installGroupGID
        )
    }

    private func validatePublication(
        _ manifest: InstallManifest,
        plist: InstallEntry?,
        installOwnerUID: UInt32,
        installGroupGID: UInt32
    ) throws {
        let publicationPath = try InstallRelativePath("Library/LaunchDaemons/\(label).plist")
        let expectedSource = try InstallRelativePath(
            "\(MacOSInstallLayout.installerBase)/Generations/\(manifest.generationID)/\(plistEntry)"
        )
        let publication = manifest.publications.first { $0.path == publicationPath }
        guard publication?.kind == .regularFile,
              publication?.source == expectedSource,
              publication?.sha256 == plist?.sha256,
              publication?.byteCount == plist?.byteCount,
              publication?.ownerUID == installOwnerUID,
              publication?.groupGID == installGroupGID,
              publication?.mode == 0o444
        else {
            throw InstallError.invalidManifest("\(label) has no exact persistent LaunchDaemon publication")
        }
    }

    private func serviceRoleIsValid(_ role: InstallEntryRole?) -> Bool {
        switch self {
        case .daemon:
            role == .daemon
        case .resolver:
            role == .daemon || role == .support
        }
    }
}
