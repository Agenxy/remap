import Foundation

/// Manifest-verified, crash-resumable deletion for one journal-bound generation.
struct GenerationPurgeStore: Sendable {
    private static let purgeDirectoryMode: UInt16 = 0o700

    private let authority: FileSystemAuthority
    private let generationsPath: InstallRelativePath
    private let ownerUID: UInt32
    private let groupGID: UInt32

    init(
        authority: FileSystemAuthority,
        generationsPath: InstallRelativePath,
        ownerUID: UInt32,
        groupGID: UInt32
    ) {
        self.authority = authority
        self.generationsPath = generationsPath
        self.ownerUID = ownerUID
        self.groupGID = groupGID
    }

    func requirePurgeable(generationID: String, transactionID: String) throws {
        let paths = try purgePaths(generationID: generationID, transactionID: transactionID)
        let liveExists = try authority.metadata(at: paths.live) != nil
        let retiredExists = try authority.metadata(at: paths.retired) != nil
        guard liveExists != retiredExists else {
            if liveExists {
                throw InstallError.collision(paths.live.description)
            }
            throw InstallError.integrity("the journal-bound purge generation is missing")
        }
        let path = liveExists ? paths.live : paths.retired
        _ = try fullyOwnedManifest(at: path, generationID: generationID)
    }

    func purgeContents(generationID: String, transactionID: String) throws {
        let paths = try purgePaths(generationID: generationID, transactionID: transactionID)
        if try authority.metadata(at: paths.live) != nil {
            guard try authority.metadata(at: paths.retired) == nil else {
                throw InstallError.collision(paths.retired.description)
            }
            _ = try fullyOwnedManifest(at: paths.live, generationID: generationID)
            try authority.renameExclusive(from: paths.live, to: paths.retired)
        }
        guard try authority.metadata(at: paths.retired) != nil else {
            return
        }
        let manifest = try purgeManifest(at: paths.retired, generationID: generationID)
        try verifyPurgeSubset(manifest, at: paths.retired)
        try prepareDirectoriesForPurge(manifest, at: paths.retired)
        try removeRegularFiles(manifest, at: paths.retired)
        try removeDirectories(manifest, at: paths.retired)
        guard try authority.listDirectory(at: paths.retired) == [GenerationStore.manifestName] else {
            throw InstallError.collision(paths.retired.description)
        }
    }

    func finishPurge(generationID: String, transactionID: String) throws {
        let retired = try purgePaths(generationID: generationID, transactionID: transactionID).retired
        guard try authority.metadata(at: retired) != nil else {
            return
        }
        try authority.verifyOwnedDirectory(
            at: retired,
            ownerUID: ownerUID,
            groupGID: groupGID,
            permittedModes: [Self.purgeDirectoryMode]
        )
        let names = try authority.listDirectory(at: retired)
        guard names.isEmpty || names == [GenerationStore.manifestName] else {
            throw InstallError.collision(retired.description)
        }
        if !names.isEmpty {
            let manifest = try purgeManifest(at: retired, generationID: generationID)
            try authority.unlinkRegularFile(
                at: retired.appending(component: GenerationStore.manifestName),
                expected: manifestEntry(manifest)
            )
        }
        try authority.removeEmptyDirectory(at: retired)
    }

    /// Removes one installer-quarantined generation after verifying every remaining
    /// manifest entry. The hidden path itself is selected only by `GenerationStore`
    /// from the protected Generations directory.
    func purgeDetached(at path: InstallRelativePath) throws {
        guard try authority.metadata(at: path) != nil else {
            return
        }
        let names = try authority.listDirectory(at: path)
        if names.isEmpty {
            try authority.verifyOwnedDirectory(
                at: path,
                ownerUID: ownerUID,
                groupGID: groupGID,
                permittedModes: [Self.purgeDirectoryMode]
            )
            try authority.removeEmptyDirectory(at: path)
            return
        }
        let manifest = try purgeManifest(at: path, generationID: nil)
        try verifyPurgeSubset(manifest, at: path)
        try prepareDirectoriesForPurge(manifest, at: path)
        try removeRegularFiles(manifest, at: path)
        try removeDirectories(manifest, at: path)
        guard try authority.listDirectory(at: path) == [GenerationStore.manifestName] else {
            throw InstallError.collision(path.description)
        }
        try authority.unlinkRegularFile(
            at: path.appending(component: GenerationStore.manifestName),
            expected: manifestEntry(manifest)
        )
        try authority.removeEmptyDirectory(at: path)
    }

    private func fullyOwnedManifest(
        at path: InstallRelativePath,
        generationID: String
    ) throws -> InstallManifest {
        let manifest = try purgeManifest(at: path, generationID: generationID)
        try authority.verify(rootEntry(), at: path)
        try authority.verify(manifestEntry(manifest), at: path.appending(component: GenerationStore.manifestName))
        for entry in manifest.entries {
            try authority.verify(entry, at: path.appending(entry.path))
        }
        try verifyListings(manifest, at: path, permitsMissingEntries: false)
        return manifest
    }

    private func verifyPurgeSubset(_ manifest: InstallManifest, at path: InstallRelativePath) throws {
        try authority.verifyOwnedDirectory(
            at: path,
            ownerUID: ownerUID,
            groupGID: groupGID,
            permittedModes: [GenerationStore.generationRootMode, Self.purgeDirectoryMode]
        )
        try authority.verify(manifestEntry(manifest), at: path.appending(component: GenerationStore.manifestName))
        for entry in manifest.entries {
            let entryPath = try path.appending(entry.path)
            guard try authority.metadata(at: entryPath) != nil else {
                continue
            }
            if entry.kind == .directory {
                try authority.verifyOwnedDirectory(
                    at: entryPath,
                    ownerUID: entry.ownerUID,
                    groupGID: entry.groupGID,
                    permittedModes: [entry.mode, Self.purgeDirectoryMode]
                )
            } else {
                try authority.verify(entry, at: entryPath)
            }
        }
        try verifyListings(manifest, at: path, permitsMissingEntries: true)
    }

    private func prepareDirectoriesForPurge(_ manifest: InstallManifest, at path: InstallRelativePath) throws {
        try authority.transitionOwnedDirectoryMode(
            at: path,
            ownerUID: ownerUID,
            groupGID: groupGID,
            permittedModes: [GenerationStore.generationRootMode, Self.purgeDirectoryMode],
            mode: Self.purgeDirectoryMode
        )
        let directories = manifest.entries
            .filter { $0.kind == .directory }
            .sorted { $0.path.components.count < $1.path.components.count }
        for entry in directories {
            let entryPath = try path.appending(entry.path)
            if try authority.metadata(at: entryPath) != nil {
                try authority.transitionOwnedDirectoryMode(
                    at: entryPath,
                    ownerUID: entry.ownerUID,
                    groupGID: entry.groupGID,
                    permittedModes: [entry.mode, Self.purgeDirectoryMode],
                    mode: Self.purgeDirectoryMode
                )
            }
        }
    }

    private func removeRegularFiles(_ manifest: InstallManifest, at path: InstallRelativePath) throws {
        for entry in manifest.entries where entry.kind == .regularFile {
            let entryPath = try path.appending(entry.path)
            if try authority.metadata(at: entryPath) != nil {
                try authority.unlinkRegularFile(at: entryPath, expected: entry)
            }
        }
    }

    private func removeDirectories(_ manifest: InstallManifest, at path: InstallRelativePath) throws {
        let directories = manifest.entries
            .filter { $0.kind == .directory }
            .sorted { $0.path.components.count > $1.path.components.count }
        for entry in directories {
            let entryPath = try path.appending(entry.path)
            if try authority.metadata(at: entryPath) != nil {
                try authority.verifyOwnedDirectory(
                    at: entryPath,
                    ownerUID: entry.ownerUID,
                    groupGID: entry.groupGID,
                    permittedModes: [Self.purgeDirectoryMode]
                )
                try authority.removeEmptyDirectory(at: entryPath)
            }
        }
    }

    private func verifyListings(
        _ manifest: InstallManifest,
        at path: InstallRelativePath,
        permitsMissingEntries: Bool
    ) throws {
        let expected = expectedListings(manifest)
        for (relative, expectedNames) in expected {
            let directory = relative.isEmpty ? path : try path.appending(InstallRelativePath(relative))
            guard try authority.metadata(at: directory) != nil else {
                guard permitsMissingEntries else {
                    throw InstallError.integrity("generation directory \(relative) is missing")
                }
                continue
            }
            let names = try Set(authority.listDirectory(at: directory))
            let valid = permitsMissingEntries ? names.isSubset(of: expectedNames) : names == expectedNames
            guard valid else {
                throw InstallError.collision(directory.description)
            }
        }
    }

    private func expectedListings(_ manifest: InstallManifest) -> [String: Set<String>] {
        var expected: [String: Set<String>] = ["": [GenerationStore.manifestName]]
        for entry in manifest.entries {
            let parent = entry.path.components.dropLast().joined(separator: "/")
            if let leaf = entry.path.components.last {
                expected[parent, default: []].insert(leaf)
            }
            if entry.kind == .directory, expected[entry.path.description] == nil {
                expected[entry.path.description] = []
            }
        }
        return expected
    }

    private func purgeManifest(
        at path: InstallRelativePath,
        generationID: String?
    ) throws -> InstallManifest {
        let data = try authority.readFile(
            at: path.appending(component: GenerationStore.manifestName),
            maximumByteCount: 1_048_576
        )
        let manifest: InstallManifest
        do {
            manifest = try InstallCanonicalJSON.decoder.decode(InstallManifest.self, from: data)
        } catch {
            throw InstallError.integrity("generation purge manifest is malformed")
        }
        try manifest.validate()
        guard generationID == nil || manifest.generationID == generationID else {
            throw InstallError.integrity("generation purge identity differs from its journal")
        }
        return manifest
    }

    private func manifestEntry(_ manifest: InstallManifest) throws -> InstallEntry {
        let data = try manifest.canonicalData()
        return try InstallEntry(
            path: InstallRelativePath(GenerationStore.manifestName),
            kind: .regularFile,
            role: .support,
            sha256: InstallDigest.hash(data),
            byteCount: UInt64(data.count),
            ownerUID: ownerUID,
            groupGID: groupGID,
            mode: 0o444
        )
    }

    private func rootEntry() throws -> InstallEntry {
        try InstallEntry(
            path: InstallRelativePath("generation-root"),
            kind: .directory,
            role: .support,
            sha256: nil,
            byteCount: nil,
            ownerUID: ownerUID,
            groupGID: groupGID,
            mode: GenerationStore.generationRootMode
        )
    }

    private func purgePaths(
        generationID: String,
        transactionID: String
    ) throws -> (live: InstallRelativePath, retired: InstallRelativePath) {
        try InstallManifest.validateIdentifier(generationID, field: "generation ID")
        try InstallManifest.validateIdentifier(transactionID, field: "transaction ID")
        let live = try generationsPath.appending(component: generationID)
        let identity = InstallDigest.hash(Data("\(generationID)\0\(transactionID)".utf8)).value
        let retired = try generationsPath.appending(component: ".retired-\(identity)")
        return (live, retired)
    }
}
