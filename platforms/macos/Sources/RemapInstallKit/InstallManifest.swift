import Foundation

/// The semantic role of an immutable generation entry.
public enum InstallEntryRole: String, Codable, Equatable, Sendable {
    case application
    case commandLineTool
    case daemon
    case support
}

/// The on-disk type of an immutable generation entry.
public enum InstallEntryKind: String, Codable, Equatable, Sendable {
    case directory
    case regularFile
}

/// A manifest-bound immutable file or directory.
public struct InstallEntry: Codable, Equatable, Sendable {
    public let path: InstallRelativePath
    public let kind: InstallEntryKind
    public let role: InstallEntryRole
    public let sha256: InstallDigest?
    public let byteCount: UInt64?
    public let ownerUID: UInt32
    public let groupGID: UInt32
    public let mode: UInt16

    public init(
        path: InstallRelativePath,
        kind: InstallEntryKind,
        role: InstallEntryRole,
        sha256: InstallDigest?,
        byteCount: UInt64?,
        ownerUID: UInt32 = 0,
        groupGID: UInt32 = 0,
        mode: UInt16
    ) throws {
        try Self.validate(kind: kind, sha256: sha256, byteCount: byteCount, mode: mode)
        self.path = path
        self.kind = kind
        self.role = role
        self.sha256 = sha256
        self.byteCount = byteCount
        self.ownerUID = ownerUID
        self.groupGID = groupGID
        self.mode = mode
    }

    private static func validate(
        kind: InstallEntryKind,
        sha256: InstallDigest?,
        byteCount: UInt64?,
        mode: UInt16
    ) throws {
        guard mode <= 0o777, mode & 0o222 == 0 else {
            throw InstallError.invalidManifest("immutable generation entries must not be writable")
        }
        switch kind {
        case .directory where sha256 == nil && byteCount == nil && mode & 0o500 == 0o500:
            return
        case .regularFile where sha256 != nil && byteCount != nil && mode & 0o400 == 0o400:
            return
        default:
            throw InstallError.invalidManifest("entry digest, size, kind, and mode are inconsistent")
        }
    }

    func validate() throws {
        let reconstructed = try InstallEntry(
            path: path,
            kind: kind,
            role: role,
            sha256: sha256,
            byteCount: byteCount,
            ownerUID: ownerUID,
            groupGID: groupGID,
            mode: mode
        )
        guard reconstructed == self else {
            throw InstallError.invalidManifest("entry validation failed")
        }
    }
}

/// The publication primitive used for a stable public install path.
public enum InstallPublicationKind: String, Codable, Equatable, Sendable {
    case directory
    case regularFile
    case symbolicLink
}

/// A stable path whose target is bound to one immutable generation.
public struct InstallPublication: Codable, Equatable, Sendable {
    public let path: InstallRelativePath
    public let kind: InstallPublicationKind
    public let target: InstallSymlinkTarget?
    public let source: InstallRelativePath?
    public let sha256: InstallDigest?
    public let byteCount: UInt64?
    public let ownerUID: UInt32?
    public let groupGID: UInt32?
    public let mode: UInt16?
    public let generationID: String

    private enum CodingKeys: String, CodingKey {
        case byteCount
        case generationID
        case groupGID
        case kind
        case mode
        case ownerUID
        case path
        case sha256
        case source
        case target
    }

    public init(
        path: InstallRelativePath,
        target: InstallSymlinkTarget,
        generationID: String
    ) throws {
        try InstallManifest.validateIdentifier(generationID, field: "publication generation ID")
        self.path = path
        kind = .symbolicLink
        self.target = target
        source = nil
        sha256 = nil
        byteCount = nil
        ownerUID = nil
        groupGID = nil
        mode = nil
        self.generationID = generationID
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let kind = try container.decode(InstallPublicationKind.self, forKey: .kind)
        let path = try container.decode(InstallRelativePath.self, forKey: .path)
        let generationID = try container.decode(String.self, forKey: .generationID)
        switch kind {
        case .directory:
            try self.init(
                path: path,
                generationID: generationID,
                ownerUID: container.decode(UInt32.self, forKey: .ownerUID),
                groupGID: container.decode(UInt32.self, forKey: .groupGID),
                mode: container.decode(UInt16.self, forKey: .mode)
            )
        case .symbolicLink:
            try self.init(
                path: path,
                target: container.decode(InstallSymlinkTarget.self, forKey: .target),
                generationID: generationID
            )
        case .regularFile:
            try self.init(
                path: path,
                source: container.decode(InstallRelativePath.self, forKey: .source),
                sha256: container.decode(InstallDigest.self, forKey: .sha256),
                byteCount: container.decode(UInt64.self, forKey: .byteCount),
                generationID: generationID,
                ownerUID: container.decode(UInt32.self, forKey: .ownerUID),
                groupGID: container.decode(UInt32.self, forKey: .groupGID),
                mode: container.decode(UInt16.self, forKey: .mode)
            )
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(generationID, forKey: .generationID)
        try container.encode(kind, forKey: .kind)
        try container.encode(path, forKey: .path)
        switch kind {
        case .directory:
            guard let ownerUID, let groupGID, let mode else {
                throw InstallError.invalidManifest("a directory publication has incomplete ownership")
            }
            try container.encode(ownerUID, forKey: .ownerUID)
            try container.encode(groupGID, forKey: .groupGID)
            try container.encode(mode, forKey: .mode)
        case .symbolicLink:
            guard let target else {
                throw InstallError.invalidManifest("a symbolic-link publication has no target")
            }
            try container.encode(target, forKey: .target)
        case .regularFile:
            guard let source, let sha256, let byteCount, let ownerUID, let groupGID, let mode else {
                throw InstallError.invalidManifest("a regular publication has incomplete content identity")
            }
            try container.encode(source, forKey: .source)
            try container.encode(sha256, forKey: .sha256)
            try container.encode(byteCount, forKey: .byteCount)
            try container.encode(ownerUID, forKey: .ownerUID)
            try container.encode(groupGID, forKey: .groupGID)
            try container.encode(mode, forKey: .mode)
        }
    }

    public init(
        path: InstallRelativePath,
        generationID: String,
        ownerUID: UInt32 = 0,
        groupGID: UInt32 = 0,
        mode: UInt16 = 0o755
    ) throws {
        try InstallManifest.validateIdentifier(generationID, field: "publication generation ID")
        guard mode == 0o755 else {
            throw InstallError.invalidManifest("public directory publications must have mode 755")
        }
        self.path = path
        kind = .directory
        target = nil
        source = nil
        sha256 = nil
        byteCount = nil
        self.ownerUID = ownerUID
        self.groupGID = groupGID
        self.mode = mode
        self.generationID = generationID
    }

    public init(
        path: InstallRelativePath,
        source: InstallRelativePath,
        sha256: InstallDigest,
        byteCount: UInt64,
        generationID: String,
        ownerUID: UInt32 = 0,
        groupGID: UInt32 = 0,
        mode: UInt16 = 0o444
    ) throws {
        try InstallManifest.validateIdentifier(generationID, field: "publication generation ID")
        guard source.components.contains(generationID) else {
            throw InstallError.invalidManifest("a regular publication source must name its immutable generation")
        }
        let sourceEntry = try InstallEntry(
            path: source,
            kind: .regularFile,
            role: .support,
            sha256: sha256,
            byteCount: byteCount,
            ownerUID: ownerUID,
            groupGID: groupGID,
            mode: mode
        )
        guard sourceEntry.mode == 0o444
        else {
            throw InstallError.invalidManifest("regular publications must be read-only")
        }
        self.path = path
        kind = .regularFile
        target = nil
        self.source = source
        self.sha256 = sha256
        self.byteCount = byteCount
        self.ownerUID = ownerUID
        self.groupGID = groupGID
        self.mode = mode
        self.generationID = generationID
    }

    func validate() throws {
        let reconstructed: InstallPublication
        switch kind {
        case .directory:
            guard let ownerUID, let groupGID, let mode else {
                throw InstallError.invalidManifest("a directory publication has incomplete ownership")
            }
            reconstructed = try InstallPublication(
                path: path,
                generationID: generationID,
                ownerUID: ownerUID,
                groupGID: groupGID,
                mode: mode
            )
        case .symbolicLink:
            guard let target else {
                throw InstallError.invalidManifest("a symbolic-link publication has no target")
            }
            reconstructed = try InstallPublication(path: path, target: target, generationID: generationID)
        case .regularFile:
            guard let source, let sha256, let byteCount, let ownerUID, let groupGID, let mode else {
                throw InstallError.invalidManifest("a regular-file publication has incomplete content identity")
            }
            reconstructed = try InstallPublication(
                path: path,
                source: source,
                sha256: sha256,
                byteCount: byteCount,
                generationID: generationID,
                ownerUID: ownerUID,
                groupGID: groupGID,
                mode: mode
            )
        }
        guard reconstructed == self else {
            throw InstallError.invalidManifest("publication validation failed")
        }
    }

    func regularFileEntry() throws -> InstallEntry {
        guard kind == .regularFile,
              let source,
              let sha256,
              let byteCount,
              let ownerUID,
              let groupGID,
              let mode
        else {
            throw InstallError.invalidManifest("regular publication metadata is unavailable")
        }
        return try InstallEntry(
            path: source,
            kind: .regularFile,
            role: .support,
            sha256: sha256,
            byteCount: byteCount,
            ownerUID: ownerUID,
            groupGID: groupGID,
            mode: mode
        )
    }
}

/// Canonical integrity boundary for one immutable Remap installation generation.
public struct InstallManifest: Codable, Equatable, Sendable {
    public let schemaVersion: UInt32
    public let productIdentifier: String
    public let generationID: String
    public let productVersion: String
    public let previousGenerationID: String?
    public let entries: [InstallEntry]
    public let publications: [InstallPublication]

    public init(
        productIdentifier: String,
        generationID: String,
        productVersion: String,
        previousGenerationID: String?,
        entries: [InstallEntry],
        publications: [InstallPublication]
    ) throws {
        try Self.validateIdentifier(productIdentifier, field: "product identifier")
        try Self.validateIdentifier(generationID, field: "generation ID")
        try Self.validateIdentifier(productVersion, field: "product version")
        if let previousGenerationID {
            try Self.validateIdentifier(previousGenerationID, field: "previous generation ID")
        }
        try entries.forEach { try $0.validate() }
        try publications.forEach { try $0.validate() }
        let orderedEntries = entries.sorted { $0.path < $1.path }
        let orderedPublications = publications.sorted { $0.path < $1.path }
        try Self.validateUnique(orderedEntries.map(\.path), field: "entry")
        try Self.validateUnique(orderedPublications.map(\.path), field: "publication")
        try Self.validateParents(orderedEntries)
        guard orderedPublications.allSatisfy({ $0.generationID == generationID }) else {
            throw InstallError.invalidManifest("every publication must name this generation")
        }
        schemaVersion = 1
        self.productIdentifier = productIdentifier
        self.generationID = generationID
        self.productVersion = productVersion
        self.previousGenerationID = previousGenerationID
        self.entries = orderedEntries
        self.publications = orderedPublications
    }

    public func canonicalData() throws -> Data {
        try InstallCanonicalJSON.encoder.encode(self)
    }

    public func digest() throws -> InstallDigest {
        try InstallDigest.hash(canonicalData())
    }

    public func verify(digest expected: InstallDigest) throws {
        try validate()
        let actual = try digest()
        guard actual == expected else {
            throw InstallError.integrity("manifest digest \(actual) does not match \(expected)")
        }
    }

    public static func decodeCanonical(_ data: Data, expectedDigest: InstallDigest? = nil) throws -> InstallManifest {
        let manifest: InstallManifest
        do {
            manifest = try InstallCanonicalJSON.decoder.decode(InstallManifest.self, from: data)
        } catch {
            throw InstallError.invalidManifest("the canonical manifest is malformed")
        }
        try manifest.validate()
        guard try manifest.canonicalData() == data else {
            throw InstallError.invalidManifest("the manifest is not canonical sorted JSON")
        }
        if let expectedDigest {
            try manifest.verify(digest: expectedDigest)
        }
        return manifest
    }

    public func validate() throws {
        let reconstructed = try InstallManifest(
            productIdentifier: productIdentifier,
            generationID: generationID,
            productVersion: productVersion,
            previousGenerationID: previousGenerationID,
            entries: entries,
            publications: publications
        )
        guard schemaVersion == 1, self == reconstructed else {
            throw InstallError.invalidManifest("canonical ordering or schema validation failed")
        }
    }

    static func validateIdentifier(_ value: String, field: String) throws {
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: ".-_+"))
        guard !value.isEmpty,
              value.utf8.count <= 128,
              !value.contains("\0"),
              value.unicodeScalars.allSatisfy(allowed.contains)
        else {
            throw InstallError.invalidManifest("\(field) contains unsupported characters")
        }
    }

    private static func validateUnique(_ paths: [InstallRelativePath], field: String) throws {
        guard Set(paths).count == paths.count else {
            throw InstallError.invalidManifest("duplicate \(field) paths")
        }
    }

    private static func validateParents(_ entries: [InstallEntry]) throws {
        let directories = Set(entries.filter { $0.kind == .directory }.map(\.path))
        for entry in entries where entry.path.components.count > 1 {
            let parentValue = entry.path.components.dropLast().joined(separator: "/")
            let parent = try InstallRelativePath(parentValue)
            guard directories.contains(parent) else {
                throw InstallError.invalidManifest("entry \(entry.path) has no manifest-bound parent directory")
            }
        }
    }
}
