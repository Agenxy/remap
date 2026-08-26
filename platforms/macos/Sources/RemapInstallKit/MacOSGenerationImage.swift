import Foundation

struct MacOSLaunchdServiceImage: Equatable, Sendable {
    let kind: MacOSLaunchdServiceKind
    let plistPath: InstallAbsolutePath
    let programPath: InstallAbsolutePath
}

struct MacOSGenerationImage: Equatable, Sendable {
    let configuration: MacOSInstallConfiguration
    let services: [MacOSLaunchdServiceImage]
}

protocol MacOSGenerationImageLoading: Sendable {
    func load(_ manifest: InstallManifest) throws -> MacOSGenerationImage
}

struct MacOSGenerationImageStore: MacOSGenerationImageLoading, Sendable {
    private static let maximumConfigurationSize = 65536
    private static let maximumPropertyListSize = 1_048_576

    let layout: MacOSInstallLayout

    func load(_ manifest: InstallManifest) throws -> MacOSGenerationImage {
        guard case .owned = try layout.generations.classify(manifest) else {
            throw InstallError.integrity("the native generation is not exactly manifest-owned")
        }
        let generation = try layout.generationPath(manifest.generationID)
        return try load(
            manifest,
            authority: layout.authority,
            entryRoot: generation,
            imageRoot: layout.absoluteGenerationPath(manifest.generationID),
            installOwnerUID: layout.installOwnerUID,
            installGroupGID: layout.installGroupGID,
            allowInstalledCompatibility: true
        )
    }

    func validateSource(
        _ manifest: InstallManifest,
        authority: FileSystemAuthority
    ) throws -> MacOSGenerationImage {
        try load(
            manifest,
            authority: authority,
            entryRoot: nil,
            imageRoot: layout.absoluteGenerationPath(manifest.generationID),
            installOwnerUID: layout.installOwnerUID,
            installGroupGID: layout.installGroupGID,
            allowInstalledCompatibility: false
        )
    }

    func validateProductionSource(
        _ manifest: InstallManifest,
        authority: FileSystemAuthority
    ) throws -> MacOSGenerationImage {
        try load(
            manifest,
            authority: authority,
            entryRoot: nil,
            imageRoot: InstallAbsolutePath(
                "/\(MacOSInstallLayout.installerBase)/Generations/\(manifest.generationID)"
            ),
            installOwnerUID: 0,
            installGroupGID: 0,
            allowInstalledCompatibility: false
        )
    }

    private func load(
        _ manifest: InstallManifest,
        authority: FileSystemAuthority,
        entryRoot: InstallRelativePath?,
        imageRoot: InstallAbsolutePath,
        installOwnerUID: UInt32,
        installGroupGID: UInt32,
        allowInstalledCompatibility: Bool
    ) throws -> MacOSGenerationImage {
        let configuration = try loadConfiguration(
            manifest: manifest,
            authority: authority,
            entryRoot: entryRoot,
            installOwnerUID: installOwnerUID,
            installGroupGID: installGroupGID
        )
        if installOwnerUID == 0 {
            try validateCodeIdentities(
                manifest: manifest,
                configuration: configuration,
                authority: authority,
                entryRoot: entryRoot
            )
        }
        let account = try MacOSAccountLookup.account(for: configuration.ownerUID)
        let services = try loadServices(
            authority: authority,
            entryRoot: entryRoot,
            root: imageRoot,
            configuration: configuration,
            account: account,
            allowInstalledCompatibility: allowInstalledCompatibility
        )
        return MacOSGenerationImage(configuration: configuration, services: services)
    }

    private func loadServices(
        authority: FileSystemAuthority,
        entryRoot: InstallRelativePath?,
        root: InstallAbsolutePath,
        configuration: MacOSInstallConfiguration,
        account: MacOSAccount,
        allowInstalledCompatibility: Bool
    ) throws -> [MacOSLaunchdServiceImage] {
        do {
            return try loadServices(
                authority: authority,
                entryRoot: entryRoot,
                root: root,
                configuration: configuration,
                account: account,
                contract: .launchdOwnedSystemSocket
            )
        } catch where allowInstalledCompatibility {
            return try loadServices(
                authority: authority,
                entryRoot: entryRoot,
                root: root,
                configuration: configuration,
                account: account,
                contract: .legacyDataDirectorySystemSocket
            )
        }
    }

    private func loadServices(
        authority: FileSystemAuthority,
        entryRoot: InstallRelativePath?,
        root: InstallAbsolutePath,
        configuration: MacOSInstallConfiguration,
        account: MacOSAccount,
        contract: MacOSLaunchdAuthorityContract
    ) throws -> [MacOSLaunchdServiceImage] {
        try MacOSLaunchdServiceKind.allCases.map { kind in
            try loadService(
                kind,
                authority: authority,
                entryRoot: entryRoot,
                root: root,
                configuration: configuration,
                account: account,
                contract: contract
            )
        }
    }

    private func validateCodeIdentities(
        manifest: InstallManifest,
        configuration: MacOSInstallConfiguration,
        authority: FileSystemAuthority,
        entryRoot: InstallRelativePath?
    ) throws {
        var expected = [
            ("bin/remap", "org.agenxy.Remap.cli"),
            ("libexec/remap-install", MacOSBootstrapHelperStore.codeIdentifier),
            ("libexec/remap-resolver", "org.agenxy.Remap.resolver"),
            ("libexec/remap-system", "org.agenxy.Remap.system"),
            ("libexec/remapd", "org.agenxy.Remap.daemon")
        ]
        let lifecyclePath = try InstallRelativePath("libexec/remap-lifecycle")
        if manifest.entries.contains(where: { $0.path == lifecyclePath }) {
            expected.append(("libexec/remap-lifecycle", "org.agenxy.Remap.lifecycle-cli"))
        }
        let checker = NativeMacOSProductCodeIdentityChecker()
        for (pathValue, identifier) in expected {
            let path = try InstallRelativePath(pathValue)
            guard let entry = manifest.entries.first(where: { $0.path == path }),
                  entry.kind == .regularFile,
                  entry.mode == 0o555
            else {
                throw InstallError.invalidManifest("the native product has an incomplete executable set")
            }
            let descriptor = try authority.openRegularFile(
                entryPath(path, root: entryRoot),
                rejectHardLinks: true
            )
            defer { close(descriptor) }
            let identity = try checker.identity(fileDescriptor: descriptor)
            guard identity.identifier == identifier,
                  identity.signingCertificateSHA256 == configuration.signingCertificateSHA256
            else {
                throw InstallError.integrity("a native product executable has the wrong local signing identity")
            }
        }
        try validateApplicationBundle(
            manifest: manifest,
            configuration: configuration,
            authority: authority,
            entryRoot: entryRoot
        )
    }

    private func validateApplicationBundle(
        manifest: InstallManifest,
        configuration: MacOSInstallConfiguration,
        authority: FileSystemAuthority,
        entryRoot: InstallRelativePath?
    ) throws {
        let path = try InstallRelativePath("app/Remap.app")
        guard let entry = manifest.entries.first(where: { $0.path == path }),
              entry.kind == .directory,
              entry.mode == 0o555
        else {
            throw InstallError.invalidManifest("the native product has no application bundle")
        }
        let bundlePath = if let entryRoot {
            try entryRoot.appending(path)
        } else {
            path
        }
        let descriptor = try authority.openDirectory(at: bundlePath)
        defer { close(descriptor) }
        let identity = try NativeMacOSProductCodeIdentityChecker().bundleIdentity(
            directoryDescriptor: descriptor
        )
        try requireIdentity(
            identity,
            identifier: "org.agenxy.Remap",
            configuration: configuration
        )
    }

    private func requireIdentity(
        _ identity: MacOSProductCodeIdentity,
        identifier: String,
        configuration: MacOSInstallConfiguration
    ) throws {
        guard identity.identifier == identifier,
              identity.signingCertificateSHA256 == configuration.signingCertificateSHA256
        else {
            throw InstallError.integrity("a native product executable has the wrong local signing identity")
        }
    }

    private func loadConfiguration(
        manifest: InstallManifest,
        authority: FileSystemAuthority,
        entryRoot: InstallRelativePath?,
        installOwnerUID: UInt32,
        installGroupGID: UInt32
    ) throws -> MacOSInstallConfiguration {
        let path = try entryPath(MacOSInstallConfiguration.entryName, root: entryRoot)
        let data = try authority.readFile(at: path, maximumByteCount: Self.maximumConfigurationSize)
        let configuration: MacOSInstallConfiguration
        do {
            configuration = try InstallCanonicalJSON.decoder.decode(MacOSInstallConfiguration.self, from: data)
        } catch {
            throw InstallError.invalidManifest("the native install configuration is malformed")
        }
        try configuration.validate(
            for: manifest,
            installOwnerUID: installOwnerUID,
            installGroupGID: installGroupGID
        )
        return configuration
    }

    private func loadService(
        _ kind: MacOSLaunchdServiceKind,
        authority: FileSystemAuthority,
        entryRoot: InstallRelativePath?,
        root: InstallAbsolutePath,
        configuration: MacOSInstallConfiguration,
        account: MacOSAccount,
        contract: MacOSLaunchdAuthorityContract
    ) throws -> MacOSLaunchdServiceImage {
        let plistEntry = try InstallRelativePath(kind.plistEntry)
        let programEntry = try InstallRelativePath(kind.programEntry)
        let plistPath = try append(plistEntry, to: root)
        let programPath = try append(programEntry, to: root)
        let data = try authority.readFile(
            at: entryPath(plistEntry, root: entryRoot),
            maximumByteCount: Self.maximumPropertyListSize
        )
        try MacOSLaunchdPropertyList.validate(
            data,
            kind: kind,
            configuration: configuration,
            account: account,
            programPath: programPath,
            contract: contract
        )
        return MacOSLaunchdServiceImage(kind: kind, plistPath: plistPath, programPath: programPath)
    }

    private func entryPath(
        _ path: String,
        root: InstallRelativePath?
    ) throws -> InstallRelativePath {
        try entryPath(InstallRelativePath(path), root: root)
    }

    private func entryPath(
        _ path: InstallRelativePath,
        root: InstallRelativePath?
    ) throws -> InstallRelativePath {
        if let root {
            return try root.appending(path)
        }
        return path
    }

    private func append(
        _ path: InstallRelativePath,
        to root: InstallAbsolutePath
    ) throws -> InstallAbsolutePath {
        try InstallAbsolutePath(root.value + "/" + path.description)
    }
}
