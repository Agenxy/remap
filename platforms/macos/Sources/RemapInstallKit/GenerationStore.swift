import Foundation

/// Ownership classification for a generation destination.
public enum GenerationClassification: Equatable, Sendable {
    case missing
    case owned(InstallDigest)
    case unmanaged
}

/// Stages and atomically publishes immutable, manifest-bound generations.
public struct GenerationStore: Sendable {
    static let manifestName = ".remap-install-manifest.json"
    static let generationRootMode: UInt16 = 0o511
    static let generationsMode: UInt16 = 0o711
    static let maximumDetachedGenerations = 64

    private let authority: FileSystemAuthority
    private let generationsPath: InstallRelativePath
    private let ownerUID: UInt32
    private let groupGID: UInt32
    private let purgeStore: GenerationPurgeStore

    public init(
        authority: FileSystemAuthority,
        generationsPath: InstallRelativePath,
        ownerUID: UInt32 = 0,
        groupGID: UInt32 = 0
    ) {
        self.authority = authority
        self.generationsPath = generationsPath
        self.ownerUID = ownerUID
        self.groupGID = groupGID
        purgeStore = GenerationPurgeStore(
            authority: authority,
            generationsPath: generationsPath,
            ownerUID: ownerUID,
            groupGID: groupGID
        )
    }

    public func classify(_ manifest: InstallManifest) throws -> GenerationClassification {
        let path = try generationsPath.appending(component: manifest.generationID)
        return try classify(manifest, at: path)
    }

    public func classifyStaging(
        _ manifest: InstallManifest,
        transactionID: String
    ) throws -> GenerationClassification {
        try classify(manifest, at: stagingPath(transactionID: transactionID))
    }

    public func classifyRetired(
        _ manifest: InstallManifest,
        transactionID: String
    ) throws -> GenerationClassification {
        try classify(manifest, at: retiredPath(manifest: manifest, transactionID: transactionID))
    }

    public func classifyAbandoned(
        _ manifest: InstallManifest,
        transactionID: String
    ) throws -> GenerationClassification {
        try classify(manifest, at: abandonedPath(manifest: manifest, transactionID: transactionID))
    }

    public func retire(_ manifest: InstallManifest, transactionID: String) throws {
        try manifest.validate()
        try InstallManifest.validateIdentifier(transactionID, field: "transaction ID")
        let live = try generationPath(manifest)
        let retired = try retiredPath(manifest: manifest, transactionID: transactionID)
        switch try classify(manifest, at: live) {
        case .owned:
            guard case .missing = try classify(manifest, at: retired) else {
                throw InstallError.collision(retired.description)
            }
            try authority.renameExclusive(from: live, to: retired)
        case .missing:
            guard case .owned = try classify(manifest, at: retired) else {
                throw InstallError.integrity("owned generation is missing from both live and retired locations")
            }
        case .unmanaged:
            throw InstallError.collision(live.description)
        }
        guard case .owned = try classify(manifest, at: retired) else {
            throw InstallError.integrity("retired generation failed exact manifest verification")
        }
    }

    public func quarantineStaging(_ manifest: InstallManifest, transactionID: String) throws {
        try manifest.validate()
        let staging = try stagingPath(transactionID: transactionID)
        let abandoned = try abandonedPath(manifest: manifest, transactionID: transactionID)
        switch try classify(manifest, at: staging) {
        case .owned:
            guard case .missing = try classify(manifest, at: abandoned) else {
                throw InstallError.collision(abandoned.description)
            }
            try authority.renameExclusive(from: staging, to: abandoned)
        case .missing:
            switch try classify(manifest, at: abandoned) {
            case .owned:
                return
            case .missing:
                throw InstallError.integrity("staged generation is missing from active and abandoned locations")
            case .unmanaged:
                throw InstallError.collision(abandoned.description)
            }
        case .unmanaged:
            throw InstallError.collision(staging.description)
        }
    }

    func retireStaging(_ manifest: InstallManifest, transactionID: String) throws {
        try manifest.validate()
        let staging = try stagingPath(transactionID: transactionID)
        let retired = try retiredPath(manifest: manifest, transactionID: transactionID)
        switch try classify(manifest, at: staging) {
        case .owned:
            guard case .missing = try classify(manifest, at: retired) else {
                throw InstallError.collision(retired.description)
            }
            try authority.renameExclusive(from: staging, to: retired)
        case .missing:
            guard case .owned = try classify(manifest, at: retired) else {
                throw InstallError.integrity("prepared generation is missing from staging and retirement")
            }
        case .unmanaged:
            throw InstallError.collision(staging.description)
        }
    }

    public func loadManifestForRecovery(
        generationID: String,
        transactionID: String
    ) throws -> InstallManifest {
        try InstallManifest.validateIdentifier(generationID, field: "generation ID")
        let live = try generationsPath.appending(component: generationID)
        if try authority.metadata(at: live) != nil {
            let manifest = try loadManifest(for: generationID)
            try verifyGeneration(manifest, at: live)
            return manifest
        }
        let staging = try stagingPath(transactionID: transactionID)
        if try authority.metadata(at: staging) != nil {
            return try validatedRecoveryManifest(at: staging, generationID: generationID)
        }
        let identity = try recoveryIdentity(generationID: generationID, transactionID: transactionID)
        let retired = try generationsPath.appending(component: ".retired-\(identity)")
        if try authority.metadata(at: retired) != nil {
            return try validatedRecoveryManifest(at: retired, generationID: generationID)
        }
        let abandoned = try generationsPath.appending(component: ".abandoned-\(identity)")
        return try validatedRecoveryManifest(at: abandoned, generationID: generationID)
    }

    func loadManifestForPurgeRecovery(
        generationID: String,
        transactionID: String
    ) throws -> InstallManifest? {
        try InstallManifest.validateIdentifier(generationID, field: "generation ID")
        let live = try generationsPath.appending(component: generationID)
        let identity = try recoveryIdentity(
            generationID: generationID,
            transactionID: transactionID
        )
        let retired = try generationsPath.appending(component: ".retired-\(identity)")
        let liveExists = try authority.metadata(at: live) != nil
        let retiredExists = try authority.metadata(at: retired) != nil
        guard liveExists == false || retiredExists == false else {
            throw InstallError.collision(live.description)
        }
        guard liveExists || retiredExists else {
            return nil
        }
        let manifest = try loadManifest(at: liveExists ? live : retired)
        try manifest.validate()
        guard manifest.generationID == generationID else {
            throw InstallError.integrity("purge generation and manifest identity differ")
        }
        return manifest
    }

    private func validatedRecoveryManifest(
        at path: InstallRelativePath,
        generationID: String
    ) throws -> InstallManifest {
        let manifest = try loadManifest(at: path)
        try manifest.validate()
        guard manifest.generationID == generationID else {
            throw InstallError.integrity("recovery generation and manifest identity differ")
        }
        try verifyGeneration(manifest, at: path)
        return manifest
    }

    private func classify(
        _ manifest: InstallManifest,
        at path: InstallRelativePath
    ) throws -> GenerationClassification {
        guard let metadata = try authority.metadata(at: path) else {
            return .missing
        }
        guard metadata.kind == .directory else {
            return .unmanaged
        }
        do {
            let existing = try loadManifest(at: path)
            try existing.validate()
            guard existing == manifest else {
                return .unmanaged
            }
            try verifyGeneration(manifest, at: path)
            return try .owned(existing.digest())
        } catch {
            return .unmanaged
        }
    }

    public func stage(
        _ manifest: InstallManifest,
        from source: FileSystemAuthority,
        transactionID: String
    ) throws -> InstallRelativePath {
        try manifest.validate()
        try InstallManifest.validateIdentifier(transactionID, field: "transaction ID")
        try authority.ensureOwnedDirectory(
            at: generationsPath,
            ownerUID: ownerUID,
            groupGID: groupGID,
            mode: Self.generationsMode
        )
        let staging = try stagingPath(transactionID: transactionID)
        guard try authority.metadata(at: staging) == nil else {
            throw InstallError.collision(staging.description)
        }
        try authority.createDirectory(at: staging, ownerUID: ownerUID, groupGID: groupGID, mode: 0o700)
        try stageDirectories(manifest, at: staging)
        try stageFiles(manifest, from: source, at: staging)
        try writeManifest(manifest, at: staging)
        try sealDirectories(manifest, at: staging)
        try authority.createDirectory(
            at: staging,
            ownerUID: ownerUID,
            groupGID: groupGID,
            mode: Self.generationRootMode
        )
        return staging
    }

    public func publish(_ staging: InstallRelativePath, manifest: InstallManifest) throws {
        guard case .missing = try classify(manifest) else {
            throw try InstallError.collision(generationPath(manifest).description)
        }
        try authority.renameExclusive(from: staging, to: generationPath(manifest))
    }

    public func loadManifest(for generationID: String) throws -> InstallManifest {
        try InstallManifest.validateIdentifier(generationID, field: "generation ID")
        let generation = try generationsPath.appending(component: generationID)
        let manifest = try loadManifest(at: generation)
        try manifest.validate()
        guard manifest.generationID == generationID else {
            throw InstallError.integrity("generation directory and manifest identity differ")
        }
        return manifest
    }

    public func ownedManifests() throws -> [InstallManifest] {
        guard let metadata = try authority.metadata(at: generationsPath) else {
            return []
        }
        guard metadata.kind == .directory else {
            throw InstallError.collision(generationsPath.description)
        }
        var manifests: [InstallManifest] = []
        for name in try authority.listDirectory(at: generationsPath) where !name.hasPrefix(".") {
            let manifest = try loadManifest(for: name)
            guard case .owned = try classify(manifest) else {
                throw try InstallError.collision(generationsPath.appending(component: name).description)
            }
            manifests.append(manifest)
        }
        return manifests.sorted { $0.generationID < $1.generationID }
    }

    func requirePurgeable(generationID: String, transactionID: String) throws {
        try purgeStore.requirePurgeable(generationID: generationID, transactionID: transactionID)
    }

    func purgeContents(generationID: String, transactionID: String) throws {
        try purgeStore.purgeContents(generationID: generationID, transactionID: transactionID)
    }

    func finishPurge(generationID: String, transactionID: String) throws {
        try purgeStore.finishPurge(generationID: generationID, transactionID: transactionID)
    }

    public func quarantineOrphanedStaging(knownTransactionIDs: Set<String>) throws -> [String] {
        let transactionIDs = try orphanedStagingTransactionIDs(
            knownTransactionIDs: knownTransactionIDs
        )
        var recovered: [String] = []
        for transactionID in transactionIDs {
            let staging = try stagingPath(transactionID: transactionID)
            let manifest = try loadManifest(at: staging)
            try quarantineStaging(manifest, transactionID: transactionID)
            recovered.append(transactionID)
        }
        return recovered.sorted()
    }

    func orphanedStagingTransactionIDs(
        knownTransactionIDs: Set<String>
    ) throws -> [String] {
        guard let metadata = try authority.metadata(at: generationsPath) else {
            return []
        }
        guard metadata.kind == .directory else {
            throw InstallError.collision(generationsPath.description)
        }
        var transactionIDs: [String] = []
        for name in try authority.listDirectory(at: generationsPath) where name.hasPrefix(".staging-") {
            let transactionID = String(name.dropFirst(".staging-".count))
            try InstallManifest.validateIdentifier(transactionID, field: "orphan transaction ID")
            guard !knownTransactionIDs.contains(transactionID) else {
                continue
            }
            let staging = try stagingPath(transactionID: transactionID)
            let manifest = try loadManifest(at: staging)
            try manifest.validate()
            try verifyGeneration(manifest, at: staging)
            transactionIDs.append(transactionID)
        }
        return transactionIDs.sorted()
    }

    /// Purges only exact installer quarantine names from the protected Generations
    /// namespace. Every non-empty tree remains bound to its canonical manifest.
    func purgeDetachedGenerations() throws -> [String] {
        let candidates = try detachedGenerationNames()
        for name in candidates {
            try purgeStore.purgeDetached(at: generationsPath.appending(component: name))
        }
        return candidates
    }

    func detachedGenerationNames() throws -> [String] {
        guard let metadata = try authority.metadata(at: generationsPath) else {
            return []
        }
        guard metadata.kind == .directory else {
            throw InstallError.collision(generationsPath.description)
        }
        let names = try authority.listDirectory(at: generationsPath)
        let candidates = try names.filter { name in
            guard Self.isDetachedPrefix(name) else {
                return false
            }
            guard Self.isDetachedName(name) else {
                throw try InstallError.collision(
                    generationsPath.appending(component: name).description
                )
            }
            return true
        }
        guard candidates.count <= Self.maximumDetachedGenerations else {
            throw InstallError.integrity("too many detached generations require recovery")
        }
        return candidates.sorted()
    }

    private static func isDetachedName(_ name: String) -> Bool {
        let prefixes = [".abandoned-", ".retired-"]
        guard let prefix = prefixes.first(where: name.hasPrefix) else {
            return false
        }
        let identity = name.dropFirst(prefix.count)
        return identity.count == 64 && identity.allSatisfy { $0.isHexDigit && !$0.isUppercase }
    }

    private static func isDetachedPrefix(_ name: String) -> Bool {
        name.hasPrefix(".abandoned-") || name.hasPrefix(".retired-")
    }

    private func stageDirectories(_ manifest: InstallManifest, at staging: InstallRelativePath) throws {
        let directories = manifest.entries
            .filter { $0.kind == .directory }
            .sorted { $0.path.components.count < $1.path.components.count }
        for entry in directories {
            try authority.createDirectory(
                at: staging.appending(entry.path),
                ownerUID: entry.ownerUID,
                groupGID: entry.groupGID,
                mode: 0o700
            )
        }
    }

    private func stageFiles(
        _ manifest: InstallManifest,
        from source: FileSystemAuthority,
        at staging: InstallRelativePath
    ) throws {
        for entry in manifest.entries where entry.kind == .regularFile {
            try authority.copyRegularFile(
                from: source,
                sourcePath: entry.path,
                destinationPath: staging.appending(entry.path),
                entry: entry
            )
        }
    }

    private func writeManifest(_ manifest: InstallManifest, at staging: InstallRelativePath) throws {
        let path = try staging.appending(component: Self.manifestName)
        try authority.writeFile(
            manifest.canonicalData(),
            at: path,
            ownerUID: ownerUID,
            groupGID: groupGID,
            mode: 0o444
        )
    }

    private func sealDirectories(_ manifest: InstallManifest, at staging: InstallRelativePath) throws {
        let directories = manifest.entries
            .filter { $0.kind == .directory }
            .sorted { $0.path.components.count > $1.path.components.count }
        for entry in directories {
            try authority.createDirectory(
                at: staging.appending(entry.path),
                ownerUID: entry.ownerUID,
                groupGID: entry.groupGID,
                mode: entry.mode
            )
        }
    }

    private func generationPath(_ manifest: InstallManifest) throws -> InstallRelativePath {
        try generationsPath.appending(component: manifest.generationID)
    }

    private func stagingPath(transactionID: String) throws -> InstallRelativePath {
        try InstallManifest.validateIdentifier(transactionID, field: "transaction ID")
        return try generationsPath.appending(component: ".staging-\(transactionID)")
    }

    private func retiredPath(
        manifest: InstallManifest,
        transactionID: String
    ) throws -> InstallRelativePath {
        let identity = try recoveryIdentity(generationID: manifest.generationID, transactionID: transactionID)
        return try generationsPath.appending(component: ".retired-\(identity)")
    }

    private func abandonedPath(
        manifest: InstallManifest,
        transactionID: String
    ) throws -> InstallRelativePath {
        let identity = try recoveryIdentity(generationID: manifest.generationID, transactionID: transactionID)
        return try generationsPath.appending(component: ".abandoned-\(identity)")
    }

    private func recoveryIdentity(generationID: String, transactionID: String) throws -> String {
        try InstallManifest.validateIdentifier(generationID, field: "generation ID")
        try InstallManifest.validateIdentifier(transactionID, field: "transaction ID")
        return InstallDigest.hash(Data("\(generationID)\0\(transactionID)".utf8)).value
    }

    private func loadManifest(at generation: InstallRelativePath) throws -> InstallManifest {
        let path = try generation.appending(component: Self.manifestName)
        let data = try authority.readFile(at: path, maximumByteCount: 1_048_576)
        do {
            return try InstallCanonicalJSON.decoder.decode(InstallManifest.self, from: data)
        } catch {
            throw InstallError.integrity("generation manifest is malformed")
        }
    }

    private func verifyGeneration(_ manifest: InstallManifest, at generation: InstallRelativePath) throws {
        let rootEntry = try InstallEntry(
            path: InstallRelativePath("generation-root"),
            kind: .directory,
            role: .support,
            sha256: nil,
            byteCount: nil,
            ownerUID: ownerUID,
            groupGID: groupGID,
            mode: Self.generationRootMode
        )
        try authority.verify(rootEntry, at: generation)
        for entry in manifest.entries {
            try authority.verify(entry, at: generation.appending(entry.path))
        }
        let manifestData = try manifest.canonicalData()
        let manifestEntry = try InstallEntry(
            path: InstallRelativePath(Self.manifestName),
            kind: .regularFile,
            role: .support,
            sha256: InstallDigest.hash(manifestData),
            byteCount: UInt64(manifestData.count),
            ownerUID: ownerUID,
            groupGID: groupGID,
            mode: 0o444
        )
        try authority.verify(manifestEntry, at: generation.appending(component: Self.manifestName))
        try verifyDirectoryListings(manifest, at: generation)
    }

    private func verifyDirectoryListings(_ manifest: InstallManifest, at generation: InstallRelativePath) throws {
        var expected: [String: Set<String>] = ["": [Self.manifestName]]
        for entry in manifest.entries {
            let parent = entry.path.components.dropLast().joined(separator: "/")
            guard let leaf = entry.path.components.last else {
                throw InstallError.invalidPath(entry.path.description)
            }
            expected[parent, default: []].insert(leaf)
            if entry.kind == .directory, expected[entry.path.description] == nil {
                expected[entry.path.description] = []
            }
        }
        for (relative, names) in expected {
            let directory = relative.isEmpty
                ? generation
                : try generation.appending(InstallRelativePath(relative))
            guard try Set(authority.listDirectory(at: directory)) == names else {
                throw InstallError.integrity("generation directory \(relative) contains unmanifested entries")
            }
        }
    }
}
