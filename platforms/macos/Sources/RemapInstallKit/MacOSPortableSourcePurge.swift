import Foundation

/// Removes one root-owned portable source package by its canonical manifest.
/// The manifest is retained until every payload entry is gone, so an
/// interrupted purge can validate and resume without recursive deletion.
public struct MacOSPortableSourcePurge: Sendable {
    private static let directoryMode: UInt16 = 0o700
    private static let manifestLimit = 1_048_576
    private static let maximumSourcePackages = 32

    private let authority: FileSystemAuthority
    private let packagePath: InstallRelativePath
    private let expectedDigest: InstallDigest
    private let ownerUID: UInt32
    private let groupGID: UInt32

    public init(rootPath: String, expectedManifestDigest: InstallDigest) throws {
        let prefix = "/Library/Application Support/Agenxy/Remap/Installer/Sources/"
        guard rootPath == prefix + expectedManifestDigest.description else {
            throw InstallError.invalidPath(rootPath)
        }
        try self.init(
            authority: FileSystemAuthority(systemRootPath: "/"),
            packagePath: InstallRelativePath(String(rootPath.dropFirst())),
            expectedManifestDigest: expectedManifestDigest,
            ownerUID: 0,
            groupGID: 0
        )
    }

    public static func purgeDetachedSources(retaining digests: Set<InstallDigest>) throws {
        try purgeDetachedSources(
            authority: FileSystemAuthority(systemRootPath: "/"),
            sourcesPath: InstallRelativePath(
                MacOSPortableAuthorityCleanupState.sourcesPathString
            ),
            retaining: digests,
            ownerUID: 0,
            groupGID: 0
        )
    }

    static func purgeDetachedSources(
        authority: FileSystemAuthority,
        sourcesPath: InstallRelativePath,
        retaining digests: Set<InstallDigest>,
        ownerUID: UInt32,
        groupGID: UInt32
    ) throws {
        guard try authority.metadata(at: sourcesPath) != nil else { return }
        try authority.verifyOwnedDirectory(
            at: sourcesPath,
            ownerUID: ownerUID,
            groupGID: groupGID,
            permittedModes: [directoryMode]
        )
        let names = try authority.listDirectory(at: sourcesPath)
        guard names.count <= maximumSourcePackages else {
            throw InstallError.integrity("too many portable source packages")
        }
        let candidates = try names.compactMap { name -> MacOSPortableSourcePurge? in
            let digest = try InstallDigest(name)
            guard !digests.contains(digest) else { return nil }
            let packagePath = try sourcesPath.appending(InstallRelativePath(name))
            let purge = try MacOSPortableSourcePurge(
                authority: authority,
                packagePath: packagePath,
                expectedManifestDigest: digest,
                ownerUID: ownerUID,
                groupGID: groupGID
            )
            try purge.validate()
            return purge
        }
        for candidate in candidates {
            try candidate.purge()
        }
    }

    init(
        authority: FileSystemAuthority,
        packagePath: InstallRelativePath,
        expectedManifestDigest: InstallDigest,
        ownerUID: UInt32,
        groupGID: UInt32
    ) throws {
        guard !packagePath.components.isEmpty else {
            throw InstallError.invalidPath(packagePath.description)
        }
        self.authority = authority
        self.packagePath = packagePath
        expectedDigest = expectedManifestDigest
        self.ownerUID = ownerUID
        self.groupGID = groupGID
    }

    public func purge() throws {
        guard try authority.metadata(at: packagePath) != nil else { return }
        let manifestPath = try packagePath.appending(InstallRelativePath("manifest.json"))
        let data = try authority.readUniqueFile(
            at: manifestPath,
            maximumByteCount: Self.manifestLimit
        )
        let manifest = try InstallManifest.decodeCanonical(data, expectedDigest: expectedDigest)
        let payloadPath = try packagePath.appending(InstallRelativePath("payload"))
        try preflight(manifest, payloadPath: payloadPath, manifestPath: manifestPath)
        try prepareDirectories(manifest, payloadPath: payloadPath)
        try removeFiles(manifest, payloadPath: payloadPath)
        try removeDirectories(manifest, payloadPath: payloadPath)
        if try authority.metadata(at: payloadPath) != nil {
            try authority.verifyOwnedDirectory(
                at: payloadPath,
                ownerUID: ownerUID,
                groupGID: groupGID,
                permittedModes: [Self.directoryMode]
            )
            try authority.removeEmptyDirectory(at: payloadPath)
        }
        if try authority.metadata(at: manifestPath) != nil {
            let manifestEntry = try InstallEntry(
                path: InstallRelativePath("manifest.json"),
                kind: .regularFile,
                role: .support,
                sha256: expectedDigest,
                byteCount: UInt64(data.count),
                ownerUID: ownerUID,
                groupGID: groupGID,
                mode: 0o400
            )
            try authority.unlinkRegularFile(at: manifestPath, expected: manifestEntry)
        }
        try authority.verifyOwnedDirectory(
            at: packagePath,
            ownerUID: ownerUID,
            groupGID: groupGID,
            permittedModes: [Self.directoryMode]
        )
        try authority.removeEmptyDirectory(at: packagePath)
    }

    public func validate() throws {
        let manifestPath = try packagePath.appending(InstallRelativePath("manifest.json"))
        let data = try authority.readUniqueFile(
            at: manifestPath,
            maximumByteCount: Self.manifestLimit
        )
        let manifest = try InstallManifest.decodeCanonical(data, expectedDigest: expectedDigest)
        let payloadPath = try packagePath.appending(InstallRelativePath("payload"))
        try preflight(manifest, payloadPath: payloadPath, manifestPath: manifestPath)
    }

    private func preflight(
        _ manifest: InstallManifest,
        payloadPath: InstallRelativePath,
        manifestPath: InstallRelativePath
    ) throws {
        try authority.verifyOwnedDirectory(
            at: packagePath,
            ownerUID: ownerUID,
            groupGID: groupGID,
            permittedModes: [0o700]
        )
        if try authority.metadata(at: payloadPath) != nil {
            try authority.verifyOwnedDirectory(
                at: payloadPath,
                ownerUID: ownerUID,
                groupGID: groupGID,
                permittedModes: [0o500, Self.directoryMode]
            )
        }
        let manifestEntry = try InstallEntry(
            path: InstallRelativePath("manifest.json"),
            kind: .regularFile,
            role: .support,
            sha256: expectedDigest,
            byteCount: UInt64(authority.readUniqueFile(
                at: manifestPath,
                maximumByteCount: Self.manifestLimit
            ).count),
            ownerUID: ownerUID,
            groupGID: groupGID,
            mode: 0o400
        )
        try authority.verify(manifestEntry, at: manifestPath)
        for entry in manifest.entries {
            let path = try payloadPath.appending(entry.path)
            guard try authority.metadata(at: path) != nil else { continue }
            if entry.kind == .directory {
                try authority.verifyOwnedDirectory(
                    at: path,
                    ownerUID: ownerUID,
                    groupGID: groupGID,
                    permittedModes: [0o500, Self.directoryMode]
                )
            } else {
                try authority.verify(sourceEntry(for: entry), at: path)
            }
        }
        try verifyListings(manifest, payloadPath: payloadPath)
    }

    private func prepareDirectories(
        _ manifest: InstallManifest,
        payloadPath: InstallRelativePath
    ) throws {
        try authority.transitionOwnedDirectoryMode(
            at: packagePath,
            ownerUID: ownerUID,
            groupGID: groupGID,
            permittedModes: [Self.directoryMode],
            mode: Self.directoryMode
        )
        if try authority.metadata(at: payloadPath) != nil {
            try authority.transitionOwnedDirectoryMode(
                at: payloadPath,
                ownerUID: ownerUID,
                groupGID: groupGID,
                permittedModes: [0o500, Self.directoryMode],
                mode: Self.directoryMode
            )
        }
        let directories = manifest.entries
            .filter { $0.kind == .directory }
            .sorted(by: { $0.path.components.count < $1.path.components.count })
        for entry in directories {
            let path = try payloadPath.appending(entry.path)
            if try authority.metadata(at: path) != nil {
                try authority.transitionOwnedDirectoryMode(
                    at: path,
                    ownerUID: ownerUID,
                    groupGID: groupGID,
                    permittedModes: [0o500, Self.directoryMode],
                    mode: Self.directoryMode
                )
            }
        }
    }

    private func removeFiles(
        _ manifest: InstallManifest,
        payloadPath: InstallRelativePath
    ) throws {
        for entry in manifest.entries where entry.kind == .regularFile {
            let path = try payloadPath.appending(entry.path)
            if try authority.metadata(at: path) != nil {
                try authority.unlinkRegularFile(at: path, expected: sourceEntry(for: entry))
            }
        }
    }

    private func removeDirectories(
        _ manifest: InstallManifest,
        payloadPath: InstallRelativePath
    ) throws {
        let directories = manifest.entries
            .filter { $0.kind == .directory }
            .sorted(by: { $0.path.components.count > $1.path.components.count })
        for entry in directories {
            let path = try payloadPath.appending(entry.path)
            if try authority.metadata(at: path) != nil {
                try authority.verifyOwnedDirectory(
                    at: path,
                    ownerUID: ownerUID,
                    groupGID: groupGID,
                    permittedModes: [Self.directoryMode]
                )
                try authority.removeEmptyDirectory(at: path)
            }
        }
    }

    private func sourceEntry(for entry: InstallEntry) throws -> InstallEntry {
        guard entry.kind == .regularFile else {
            throw InstallError.invalidManifest("portable source file entry is not regular")
        }
        return try InstallEntry(
            path: entry.path,
            kind: .regularFile,
            role: entry.role,
            sha256: entry.sha256,
            byteCount: entry.byteCount,
            ownerUID: ownerUID,
            groupGID: groupGID,
            mode: entry.mode & 0o111 == 0 ? 0o400 : 0o500
        )
    }

    private func verifyListings(
        _ manifest: InstallManifest,
        payloadPath: InstallRelativePath
    ) throws {
        var expected: [String: Set<String>] = ["": []]
        for entry in manifest.entries {
            let components = entry.path.components
            let parent = components.dropLast().joined(separator: "/")
            expected[parent, default: []].insert(components.last ?? "")
            if entry.kind == .directory {
                expected[entry.path.description, default: []] = expected[entry.path.description, default: []]
            }
        }
        if try authority.metadata(at: payloadPath) != nil {
            for (relative, names) in expected {
                let path = relative.isEmpty
                    ? payloadPath
                    : try payloadPath.appending(InstallRelativePath(relative))
                guard try authority.metadata(at: path) != nil else { continue }
                let observed = try Set(authority.listDirectory(at: path))
                guard observed.isSubset(of: names) else {
                    throw InstallError.collision(path.description)
                }
            }
        }
        let rootNames = try Set(authority.listDirectory(at: packagePath))
        guard rootNames.isSubset(of: ["manifest.json", "payload"]),
              rootNames.contains("manifest.json")
        else {
            throw InstallError.collision(packagePath.description)
        }
    }
}
