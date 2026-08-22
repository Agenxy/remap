import Foundation

/// Exact ownership classification for a stable public path.
public enum PublicationClassification: Equatable, Sendable {
    case compatible
    case missing
    case owned
    case unmanaged
}

/// Atomically publishes manifest-bound symbolic links and root-owned regular files.
public struct PublicationStore: Sendable {
    private let authority: FileSystemAuthority

    public init(authority: FileSystemAuthority) {
        self.authority = authority
    }

    public func classify(_ publication: InstallPublication) throws -> PublicationClassification {
        try classifyAt(publication, path: publication.path)
    }

    public func publish(
        _ publication: InstallPublication,
        replacing previous: InstallPublication?,
        transactionID: String
    ) throws {
        try InstallManifest.validateIdentifier(transactionID, field: "transaction ID")
        if publication.kind == .directory {
            try publishDirectory(publication)
            return
        }
        switch try classify(publication) {
        case .compatible, .owned:
            return
        case .missing:
            guard previous == nil else {
                throw InstallError.collision(publication.path.description)
            }
            try publishMissing(publication, transactionID: transactionID)
        case .unmanaged:
            guard let previous,
                  previous.path == publication.path,
                  previous.kind == publication.kind,
                  try classify(previous) == .owned
            else {
                throw InstallError.collision(publication.path.description)
            }
            try exchange(publication, previous: previous, transactionID: transactionID)
        }
    }

    public func unpublish(_ publication: InstallPublication) throws {
        if publication.kind == .directory {
            try unpublishDirectory(publication)
            return
        }
        switch try classify(publication) {
        case .compatible:
            throw InstallError.integrity("a non-directory publication cannot be compatible")
        case .missing:
            return
        case .owned:
            try removeOwned(publication, at: publication.path)
        case .unmanaged:
            throw InstallError.collision(publication.path.description)
        }
    }

    private func publishMissing(_ publication: InstallPublication, transactionID: String) throws {
        let temporary = try temporaryPath(for: publication.path, transactionID: transactionID)
        guard try authority.metadata(at: temporary) == nil else {
            throw InstallError.collision(temporary.description)
        }
        try create(publication, at: temporary)
        do {
            try authority.renameExclusive(from: temporary, to: publication.path)
        } catch {
            try? removeOwned(publication, at: temporary)
            throw error
        }
    }

    private func exchange(
        _ publication: InstallPublication,
        previous: InstallPublication,
        transactionID: String
    ) throws {
        let temporary = try temporaryPath(for: publication.path, transactionID: transactionID)
        guard try authority.metadata(at: temporary) == nil else {
            throw InstallError.collision(temporary.description)
        }
        try create(publication, at: temporary)
        do {
            try authority.renameSwap(temporary, publication.path)
            try verifyExchange(temporary, publication: publication, previous: previous)
        } catch {
            try? restoreAfterFailedExchange(temporary, publication: publication, previous: previous)
            throw error
        }
    }

    private func verifyExchange(
        _ temporary: InstallRelativePath,
        publication: InstallPublication,
        previous: InstallPublication
    ) throws {
        guard try classifyAt(publication, path: publication.path) == .owned,
              try classifyAt(previous, path: temporary) == .owned
        else {
            throw InstallError.collision(publication.path.description)
        }
        try removeOwned(previous, at: temporary)
    }

    private func restoreAfterFailedExchange(
        _ temporary: InstallRelativePath,
        publication: InstallPublication,
        previous: InstallPublication
    ) throws {
        let publicationIsCurrent = try classifyAt(publication, path: publication.path) == .owned
        let temporaryIsPrevious = try classifyAt(previous, path: temporary) == .owned
        if publicationIsCurrent, temporaryIsPrevious {
            try authority.renameSwap(temporary, publication.path)
        }
        if try classifyAt(publication, path: temporary) == .owned {
            try removeOwned(publication, at: temporary)
        }
    }

    private func create(_ publication: InstallPublication, at path: InstallRelativePath) throws {
        switch publication.kind {
        case .directory:
            throw InstallError.integrity("directory publications are not exchanged")
        case .symbolicLink:
            guard let target = publication.target else {
                throw InstallError.invalidManifest("a symbolic-link publication has no target")
            }
            try authority.createSymbolicLink(target, at: path, createParents: false)
        case .regularFile:
            guard let source = publication.source else {
                throw InstallError.invalidManifest("a regular-file publication has no source")
            }
            try authority.copyRegularFile(
                from: authority,
                sourcePath: source,
                destinationPath: path,
                entry: publication.regularFileEntry(),
                createParents: false
            )
        }
    }

    private func removeOwned(_ publication: InstallPublication, at path: InstallRelativePath) throws {
        switch publication.kind {
        case .directory:
            throw InstallError.integrity("directory publications use provenance-aware removal")
        case .symbolicLink:
            guard let target = publication.target else {
                throw InstallError.invalidManifest("a symbolic-link publication has no target")
            }
            try authority.unlinkSymbolicLink(at: path, expectedTarget: target)
        case .regularFile:
            try authority.unlinkRegularFile(at: path, expected: publication.regularFileEntry())
        }
    }

    private func classifyAt(
        _ publication: InstallPublication,
        path: InstallRelativePath
    ) throws -> PublicationClassification {
        guard let metadata = try authority.metadata(at: path) else {
            return .missing
        }
        switch publication.kind {
        case .directory:
            return try classifyDirectory(publication)
        case .symbolicLink:
            guard metadata.kind == .symbolicLink, let target = publication.target else {
                return .unmanaged
            }
            return try authority.readSymbolicLink(at: path) == target.value ? .owned : .unmanaged
        case .regularFile:
            guard metadata.kind == .regularFile else {
                return .unmanaged
            }
            do {
                try authority.verify(publication.regularFileEntry(), at: path)
                return .owned
            } catch {
                return .unmanaged
            }
        }
    }

    private func temporaryPath(
        for path: InstallRelativePath,
        transactionID: String
    ) throws -> InstallRelativePath {
        let parent = path.components.dropLast().joined(separator: "/")
        guard let leaf = path.components.last else {
            throw InstallError.invalidPath(path.description)
        }
        let temporaryLeaf = ".\(leaf).remap-\(transactionID)"
        return try parent.isEmpty
            ? InstallRelativePath(temporaryLeaf)
            : InstallRelativePath("\(parent)/\(temporaryLeaf)")
    }

    private func publishDirectory(_ publication: InstallPublication) throws {
        switch try directoryState(publication) {
        case .compatible, .ownedPresent:
            return
        case .missing:
            try stageDirectory(publication)
            try publishStagedDirectory(publication)
        case .incompleteStaging:
            try discardStagedDirectory(publication, permitsMissingMarker: true)
            try stageDirectory(publication)
            try publishStagedDirectory(publication)
        case .staged:
            try publishStagedDirectory(publication)
        case .retired:
            try purgeRetiredDirectory(publication)
            try stageDirectory(publication)
            try publishStagedDirectory(publication)
        case .raceCompatible:
            try discardStagedDirectory(publication, permitsMissingMarker: false)
        case .unmanaged:
            throw InstallError.collision(publication.path.description)
        }
    }

    private func unpublishDirectory(_ publication: InstallPublication) throws {
        switch try directoryState(publication) {
        case .compatible, .missing:
            return
        case .incompleteStaging:
            try discardStagedDirectory(publication, permitsMissingMarker: true)
        case .staged:
            try discardStagedDirectory(publication, permitsMissingMarker: false)
        case .retired:
            try purgeRetiredDirectory(publication)
        case .raceCompatible:
            try discardStagedDirectory(publication, permitsMissingMarker: false)
        case .ownedPresent:
            let marker = Self.ownershipMarkerName
            guard try authority.listDirectory(at: publication.path) == [marker] else {
                try removeOwnershipMarker(publication, from: publication.path)
                return
            }
            try authority.renameExclusive(
                from: publication.path,
                to: retiredPath(publication)
            )
            try purgeRetiredDirectory(publication)
        case .unmanaged:
            throw InstallError.collision(publication.path.description)
        }
    }

    private func classifyDirectory(_ publication: InstallPublication) throws -> PublicationClassification {
        switch try directoryState(publication) {
        case .compatible:
            .compatible
        case .missing:
            .missing
        case .incompleteStaging, .ownedPresent, .retired, .staged:
            .owned
        case .raceCompatible:
            .compatible
        case .unmanaged:
            .unmanaged
        }
    }

    private func directoryState(_ publication: InstallPublication) throws -> DirectoryPublicationState {
        guard let mode = publication.mode else {
            throw InstallError.invalidManifest("directory publication metadata is unavailable")
        }
        let staging = try stagedDirectoryState(publication)
        let retired = try retiredDirectoryState(publication)
        if retired {
            guard staging == .missing else {
                return .unmanaged
            }
            return .retired
        }
        guard let metadata = try authority.metadata(at: publication.path) else {
            return staging
        }
        guard metadata.kind == .directory,
              try exactDirectory(
                  publication,
                  at: publication.path,
                  permittedModes: [mode],
                  permitPlatformFlags: true
              )
        else {
            return .unmanaged
        }
        let markerPath = try publication.path.appending(component: Self.ownershipMarkerName)
        if try authority.metadata(at: markerPath) != nil {
            guard try exactDirectory(
                publication,
                at: publication.path,
                permittedModes: [mode],
                permitPlatformFlags: false
            ), try exactMarker(publication, at: markerPath), staging == .missing else {
                return .unmanaged
            }
            return .ownedPresent
        }
        switch staging {
        case .missing:
            return .compatible
        case .incompleteStaging, .staged:
            return .raceCompatible
        default:
            return .unmanaged
        }
    }

    private func stagedDirectoryState(_ publication: InstallPublication) throws -> DirectoryPublicationState {
        let path = try stagingPath(publication)
        guard let metadata = try authority.metadata(at: path) else {
            return .missing
        }
        guard metadata.kind == .directory,
              try exactDirectory(publication, at: path, permittedModes: [0o700, 0o755])
        else {
            return .unmanaged
        }
        let names = try authority.listDirectory(at: path)
        if names.isEmpty, metadata.mode == 0o700 {
            return .incompleteStaging
        }
        let markerPath = try path.appending(component: Self.ownershipMarkerName)
        return try names == [Self.ownershipMarkerName] && exactMarker(publication, at: markerPath)
            ? .staged
            : .unmanaged
    }

    private func retiredDirectoryState(_ publication: InstallPublication) throws -> Bool {
        let path = try retiredPath(publication)
        guard try authority.metadata(at: path) != nil else {
            return false
        }
        guard try exactDirectory(publication, at: path, permittedModes: [0o755]) else {
            throw InstallError.collision(path.description)
        }
        let names = try authority.listDirectory(at: path)
        guard try names.isEmpty ||
            (names == [Self.ownershipMarkerName] && exactMarker(
                publication,
                at: path.appending(component: Self.ownershipMarkerName)
            ))
        else {
            throw InstallError.collision(path.description)
        }
        return true
    }

    private func stageDirectory(_ publication: InstallPublication) throws {
        guard let ownerUID = publication.ownerUID,
              let groupGID = publication.groupGID,
              let mode = publication.mode
        else {
            throw InstallError.invalidManifest("directory publication metadata is unavailable")
        }
        try authority.ensureOwnedDirectory(
            at: stagingPath(publication),
            ownerUID: ownerUID,
            groupGID: groupGID,
            mode: 0o700
        )
        let staging = try stagingPath(publication)
        try authority.writeFile(
            ownershipData(publication),
            at: staging.appending(component: Self.ownershipMarkerName),
            ownerUID: ownerUID,
            groupGID: groupGID,
            mode: 0o400
        )
        try authority.transitionOwnedDirectoryMode(
            at: staging,
            ownerUID: ownerUID,
            groupGID: groupGID,
            permittedModes: [0o700],
            mode: mode
        )
    }

    private func publishStagedDirectory(_ publication: InstallPublication) throws {
        guard let ownerUID = publication.ownerUID,
              let groupGID = publication.groupGID,
              let mode = publication.mode
        else {
            throw InstallError.invalidManifest("directory publication metadata is unavailable")
        }
        try authority.transitionOwnedDirectoryMode(
            at: stagingPath(publication),
            ownerUID: ownerUID,
            groupGID: groupGID,
            permittedModes: [0o700, mode],
            mode: mode
        )
        do {
            try authority.renameExclusive(from: stagingPath(publication), to: publication.path)
        } catch let InstallError.operatingSystem(_, code) where code == EEXIST {
            let state = try directoryState(publication)
            guard state == .raceCompatible else {
                throw InstallError.collision(publication.path.description)
            }
            try discardStagedDirectory(publication, permitsMissingMarker: false)
        }
    }

    private func discardStagedDirectory(
        _ publication: InstallPublication,
        permitsMissingMarker: Bool
    ) throws {
        let path = try stagingPath(publication)
        let names = try authority.listDirectory(at: path)
        if names == [Self.ownershipMarkerName] {
            try removeOwnershipMarker(publication, from: path)
        } else if !permitsMissingMarker || !names.isEmpty {
            throw InstallError.collision(path.description)
        }
        try authority.removeEmptyDirectory(at: path)
    }

    private func purgeRetiredDirectory(_ publication: InstallPublication) throws {
        let path = try retiredPath(publication)
        if try authority.metadata(at: path.appending(component: Self.ownershipMarkerName)) != nil {
            try removeOwnershipMarker(publication, from: path)
        }
        try authority.removeEmptyDirectory(at: path)
    }

    private func removeOwnershipMarker(
        _ publication: InstallPublication,
        from directory: InstallRelativePath
    ) throws {
        try authority.unlinkRegularFile(
            at: directory.appending(component: Self.ownershipMarkerName),
            expected: ownershipMarkerEntry(publication)
        )
    }

    private func exactDirectory(
        _ publication: InstallPublication,
        at path: InstallRelativePath,
        permittedModes: Set<UInt16>,
        permitPlatformFlags: Bool = false
    ) throws -> Bool {
        guard let ownerUID = publication.ownerUID, let groupGID = publication.groupGID else {
            throw InstallError.invalidManifest("directory publication metadata is unavailable")
        }
        do {
            try authority.verifyOwnedDirectory(
                at: path,
                ownerUID: ownerUID,
                groupGID: groupGID,
                permittedModes: permittedModes,
                permitPlatformFlags: permitPlatformFlags
            )
            return true
        } catch {
            return false
        }
    }

    private func exactMarker(_ publication: InstallPublication, at path: InstallRelativePath) throws -> Bool {
        do {
            try authority.verify(ownershipMarkerEntry(publication), at: path)
            return true
        } catch {
            return false
        }
    }

    private func ownershipMarkerEntry(_ publication: InstallPublication) throws -> InstallEntry {
        let data = ownershipData(publication)
        return try InstallEntry(
            path: InstallRelativePath("publication-ownership.json"),
            kind: .regularFile,
            role: .support,
            sha256: InstallDigest.hash(data),
            byteCount: UInt64(data.count),
            ownerUID: publication.ownerUID ?? 0,
            groupGID: publication.groupGID ?? 0,
            mode: 0o400
        )
    }

    private func ownershipData(_ publication: InstallPublication) -> Data {
        Data("org.agenxy.Remap\0\(publication.path.description)".utf8)
    }

    private func ownershipIdentity(_ publication: InstallPublication) -> String {
        InstallDigest.hash(ownershipData(publication)).value
    }

    private func stagingPath(_ publication: InstallPublication) throws -> InstallRelativePath {
        try siblingPath(publication, prefix: ".remap-directory-staging-")
    }

    private func retiredPath(_ publication: InstallPublication) throws -> InstallRelativePath {
        try siblingPath(publication, prefix: ".remap-directory-retired-")
    }

    private func siblingPath(_ publication: InstallPublication, prefix: String) throws -> InstallRelativePath {
        let parent = publication.path.components.dropLast().joined(separator: "/")
        let leaf = prefix + ownershipIdentity(publication)
        return try parent.isEmpty
            ? InstallRelativePath(leaf)
            : InstallRelativePath("\(parent)/\(leaf)")
    }

    private static let ownershipMarkerName = ".remap-owned-directory"
}

private enum DirectoryPublicationState: Equatable {
    case compatible
    case incompleteStaging
    case missing
    case ownedPresent
    case raceCompatible
    case retired
    case staged
    case unmanaged
}
