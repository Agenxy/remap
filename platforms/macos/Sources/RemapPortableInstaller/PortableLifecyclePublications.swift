import Darwin
import Foundation
import RemapInstallKit

enum PortableAuthorityCheckpoint: String, Sendable {
    case journalPrepared
    case helperStaged
    case configurationStaged
    case plistStaged
    case stagingRecorded
    case helperPublishedBeforeJournal
    case configurationPublishedBeforeJournal
    case plistPublishedBeforeJournal
    case previousHelperRemoved
    case previousConfigurationRemoved
    case previousPlistRemoved
    case previousSourceRemoved
}

struct PortableAuthorityFaults: Sendable {
    private let handler: @Sendable (PortableAuthorityCheckpoint) throws -> Void

    init(handler: @escaping @Sendable (PortableAuthorityCheckpoint) throws -> Void = { _ in }) {
        self.handler = handler
    }

    func check(_ checkpoint: PortableAuthorityCheckpoint) throws {
        try handler(checkpoint)
    }
}

struct PortableAuthorityPublicationStore: Sendable {
    private let files: PortableAuthorityFiles
    private let journalStore: PortableLifecycleJournalStore
    private let faults: PortableAuthorityFaults
    private let sourcePurge: @Sendable (String, InstallDigest) throws -> Void

    init(
        files: PortableAuthorityFiles = .production(),
        faults: PortableAuthorityFaults = PortableAuthorityFaults(),
        sourcePurge: @escaping @Sendable (String, InstallDigest) throws -> Void = { root, digest in
            try MacOSPortableSourcePurge(
                rootPath: root,
                expectedManifestDigest: digest
            ).purge()
        }
    ) {
        self.files = files
        journalStore = PortableLifecycleJournalStore(files: files)
        self.faults = faults
        self.sourcePurge = sourcePurge
    }

    func prepare(
        transactionID: String,
        generationID: String,
        previousServiceWasLoaded: Bool,
        previousSourceRoot: String? = nil,
        previousSourceManifestDigest: InstallDigest? = nil,
        contents: [Data]
    ) throws -> PortableAuthorityJournal {
        let expected = PortableLifecyclePaths.orderedPublications
        guard contents.count == expected.count else {
            throw InstallError.integrity("the lifecycle authority publication set is incomplete")
        }
        var publications: [PortableAuthorityJournalPublication] = []
        for (index, specification) in expected.enumerated() {
            let data = contents[index]
            guard !data.isEmpty, data.count <= PortableAuthorityFiles.maximumByteCount else {
                throw InstallError.integrity("lifecycle authority data exceeds its byte bound")
            }
            let stagedPath = stagedPath(
                finalPath: specification.path,
                transactionID: transactionID,
                index: index
            )
            guard !files.exists(stagedPath) else {
                throw InstallError.collision(stagedPath)
            }
            let previous = try files.inspect(
                specification.path,
                expectedMode: specification.mode
            )
            try publications.append(
                PortableAuthorityJournalPublication(
                    finalPath: specification.path,
                    stagedPath: stagedPath,
                    hadPrevious: previous != nil,
                    newDigest: InstallDigest.hash(data),
                    newByteCount: data.count,
                    previousDigest: previous?.digest,
                    previousByteCount: previous?.byteCount,
                    mode: specification.mode
                )
            )
        }
        var journal = try PortableAuthorityJournal(
            transactionID: transactionID,
            phase: .prepared,
            generationID: generationID,
            previousServiceWasLoaded: previousServiceWasLoaded,
            previousSourceRoot: previousSourceRoot,
            previousSourceManifestDigest: previousSourceManifestDigest,
            publications: publications
        )
        try journalStore.save(journal)
        try faults.check(.journalPrepared)
        let stagedCheckpoints: [PortableAuthorityCheckpoint] = [
            .helperStaged,
            .configurationStaged,
            .plistStaged
        ]
        for (index, pair) in zip(publications, contents).enumerated() {
            let (publication, data) = pair
            try files.writeNew(data, to: publication.stagedPath, finalMode: publication.mode)
            _ = try requireNew(publication, at: publication.stagedPath)
            try faults.check(stagedCheckpoints[index])
        }
        journal = try journal.withPhase(.staged)
        try journalStore.save(journal)
        try faults.check(.stagingRecorded)
        return journal
    }

    func publish(
        _ journal: PortableAuthorityJournal,
        index: Int,
        phase: PortableAuthorityPhase
    ) throws -> PortableAuthorityJournal {
        guard journal.phase >= .staged,
              journal.phase < phase,
              journal.publications.indices.contains(index)
        else {
            throw InstallError.journal("the lifecycle authority publication order is invalid")
        }
        let publication = journal.publications[index]
        let staged = try requireNew(publication, at: publication.stagedPath)
        if publication.hadPrevious {
            let current = try requirePrevious(publication, at: publication.finalPath)
            try files.exchange(
                publication.stagedPath,
                expectedLeft: staged,
                with: publication.finalPath,
                expectedRight: current
            )
        } else {
            guard try files.inspect(
                publication.finalPath,
                allowedModes: [publication.mode]
            ) == nil
            else {
                throw InstallError.collision(publication.finalPath)
            }
            try files.moveNoReplace(
                publication.stagedPath,
                expectedSource: staged,
                to: publication.finalPath
            )
        }
        _ = try requireNew(publication, at: publication.finalPath)
        let checkpoints: [PortableAuthorityCheckpoint] = [
            .helperPublishedBeforeJournal,
            .configurationPublishedBeforeJournal,
            .plistPublishedBeforeJournal
        ]
        try faults.check(checkpoints[index])
        let advanced = try journal.withPhase(phase)
        try journalStore.save(advanced)
        return advanced
    }

    func rollback(_ journal: PortableAuthorityJournal) throws {
        try validateRollback(journal)
        for publication in journal.publications.reversed() {
            try rollback(publication)
        }
    }

    func finishRollback() throws {
        try journalStore.remove()
    }

    func commit(_ journal: PortableAuthorityJournal) throws {
        guard journal.phase == .productCommitted else {
            throw InstallError.journal("the lifecycle authority was not product-committed")
        }
        try validateCommit(journal)
        let checkpoints: [PortableAuthorityCheckpoint] = [
            .previousHelperRemoved,
            .previousConfigurationRemoved,
            .previousPlistRemoved
        ]
        for (index, publication) in journal.publications.enumerated() {
            _ = try requireNew(publication, at: publication.finalPath)
            guard publication.hadPrevious else {
                guard try files.inspect(
                    publication.stagedPath,
                    allowedModes: [0o600, publication.mode]
                ) == nil
                else {
                    throw InstallError.collision(publication.stagedPath)
                }
                continue
            }
            if let staged = try files.inspect(
                publication.stagedPath,
                allowedModes: [publication.mode]
            ) {
                guard isPrevious(staged, publication) else {
                    throw InstallError.collision(publication.stagedPath)
                }
                try files.removeExact(publication.stagedPath, expected: staged)
            }
            try faults.check(checkpoints[index])
        }
        let previousSource = journal.previousSourceRoot.flatMap { root in
            journal.previousSourceManifestDigest.map { (root, $0) }
        }
        if let previousSource {
            try sourcePurge(previousSource.0, previousSource.1)
            try faults.check(.previousSourceRemoved)
        }
        try journalStore.remove()
    }

    func advance(
        _ journal: PortableAuthorityJournal,
        to phase: PortableAuthorityPhase
    ) throws -> PortableAuthorityJournal {
        let advanced = try journal.withPhase(phase)
        try journalStore.save(advanced)
        return advanced
    }

    func load() throws -> PortableAuthorityJournal? {
        try journalStore.load()
    }

    func validateRollback(_ journal: PortableAuthorityJournal) throws {
        for publication in journal.publications {
            _ = try rollbackAction(publication)
        }
    }

    func validateCommit(_ journal: PortableAuthorityJournal) throws {
        for publication in journal.publications {
            _ = try requireNew(publication, at: publication.finalPath)
            let staged = try files.inspect(
                publication.stagedPath,
                allowedModes: [0o600, publication.mode],
                maximumByteCount: max(
                    publication.newByteCount,
                    publication.previousByteCount ?? 0
                )
            )
            if publication.hadPrevious {
                guard staged.map({ isPrevious($0, publication) }) ?? true else {
                    throw InstallError.collision(publication.stagedPath)
                }
            } else if staged != nil {
                throw InstallError.collision(publication.stagedPath)
            }
        }
    }

    private func rollback(_ publication: PortableAuthorityJournalPublication) throws {
        switch try rollbackAction(publication) {
        case let .exchange(final, staged):
            try files.exchange(
                publication.stagedPath,
                expectedLeft: staged,
                with: publication.finalPath,
                expectedRight: final
            )
            let displacedNew = try requireNew(publication, at: publication.stagedPath)
            try files.removeExact(publication.stagedPath, expected: displacedNew)
        case let .removeFinal(final):
            try files.removeExact(publication.finalPath, expected: final)
        case let .removeStaged(staged):
            try files.removeExact(publication.stagedPath, expected: staged)
        case .none:
            return
        }
    }

    private func rollbackAction(
        _ publication: PortableAuthorityJournalPublication
    ) throws -> PortableAuthorityRollbackAction {
        let final = try files.inspect(
            publication.finalPath,
            allowedModes: [publication.mode]
        )
        let staged = try files.inspect(
            publication.stagedPath,
            allowedModes: [0o600, publication.mode],
            maximumByteCount: max(
                publication.newByteCount,
                publication.previousByteCount ?? 0
            )
        )
        if publication.hadPrevious {
            if let final, isNew(final, publication) {
                guard let staged, isPrevious(staged, publication) else {
                    throw InstallError.collision(publication.stagedPath)
                }
                return .exchange(final: final, staged: staged)
            }
            guard let final, isPrevious(final, publication) else {
                throw InstallError.collision(publication.finalPath)
            }
            _ = final
            if let staged {
                guard isNew(staged, publication) || isSafePartial(staged, publication) else {
                    throw InstallError.collision(publication.stagedPath)
                }
                return .removeStaged(staged)
            }
            return .none
        }
        if let final {
            guard isNew(final, publication), staged == nil else {
                throw InstallError.collision(publication.finalPath)
            }
            return .removeFinal(final)
        }
        if let staged {
            guard isNew(staged, publication) || isSafePartial(staged, publication) else {
                throw InstallError.collision(publication.stagedPath)
            }
            return .removeStaged(staged)
        }
        return .none
    }

    private func requireNew(
        _ publication: PortableAuthorityJournalPublication,
        at path: String
    ) throws -> PortableAuthorityFileSnapshot {
        guard let snapshot = try files.inspect(path, expectedMode: publication.mode),
              isNew(snapshot, publication)
        else {
            throw InstallError.integrity("the new lifecycle authority bytes are not exact")
        }
        return snapshot
    }

    private func requirePrevious(
        _ publication: PortableAuthorityJournalPublication,
        at path: String
    ) throws -> PortableAuthorityFileSnapshot {
        guard let snapshot = try files.inspect(path, expectedMode: publication.mode),
              isPrevious(snapshot, publication)
        else {
            throw InstallError.integrity("the prior lifecycle authority bytes are not exact")
        }
        return snapshot
    }

    private func isNew(
        _ snapshot: PortableAuthorityFileSnapshot,
        _ publication: PortableAuthorityJournalPublication
    ) -> Bool {
        snapshot.mode == publication.mode
            && snapshot.digest == publication.newDigest
            && snapshot.byteCount == publication.newByteCount
    }

    private func isPrevious(
        _ snapshot: PortableAuthorityFileSnapshot,
        _ publication: PortableAuthorityJournalPublication
    ) -> Bool {
        snapshot.mode == publication.mode
            && snapshot.digest == publication.previousDigest
            && snapshot.byteCount == publication.previousByteCount
    }

    private func isSafePartial(
        _ snapshot: PortableAuthorityFileSnapshot,
        _ publication: PortableAuthorityJournalPublication
    ) -> Bool {
        snapshot.mode == 0o600 && snapshot.byteCount <= publication.newByteCount
    }

    private func stagedPath(
        finalPath: String,
        transactionID: String,
        index: Int
    ) -> String {
        let final = URL(fileURLWithPath: finalPath)
        return final.deletingLastPathComponent().appendingPathComponent(
            ".remap-portable-\(transactionID)-\(index)"
        ).path
    }
}

private enum PortableAuthorityRollbackAction {
    case exchange(
        final: PortableAuthorityFileSnapshot,
        staged: PortableAuthorityFileSnapshot
    )
    case removeFinal(PortableAuthorityFileSnapshot)
    case removeStaged(PortableAuthorityFileSnapshot)
    case none
}

enum PortableAuthoritySourceReader {
    static func read(_ path: String) throws -> Data {
        let descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else {
            throw InstallError.operatingSystem("open the signed lifecycle helper", errno)
        }
        defer { close(descriptor) }
        var before = stat()
        guard fstat(descriptor, &before) == 0,
              before.st_mode & S_IFMT == S_IFREG,
              before.st_uid == 0,
              before.st_gid == 0,
              before.st_mode & 0o777 == 0o500,
              before.st_nlink == 1,
              before.st_size > 0,
              before.st_size <= PortableAuthorityFiles.maximumByteCount,
              before.st_flags == 0,
              try Set(attributeNames(descriptor)).isSubset(of: ["com.apple.provenance"]),
              try !hasACL(descriptor)
        else {
            throw InstallError.metadata("the signed lifecycle helper has unsafe metadata")
        }
        var data = Data()
        var offset: off_t = 0
        var buffer = [UInt8](repeating: 0, count: 65536)
        while offset < before.st_size {
            let count = pread(
                descriptor,
                &buffer,
                min(buffer.count, Int(before.st_size - offset)),
                offset
            )
            guard count > 0 else {
                throw InstallError.integrity("the signed lifecycle helper changed while read")
            }
            data.append(contentsOf: buffer.prefix(count))
            offset += off_t(count)
        }
        var finalByte: UInt8 = 0
        var after = stat()
        guard pread(descriptor, &finalByte, 1, offset) == 0,
              fstat(descriptor, &after) == 0,
              before.st_dev == after.st_dev,
              before.st_ino == after.st_ino,
              before.st_size == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec,
              before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec
        else {
            throw InstallError.integrity("the signed lifecycle helper changed while read")
        }
        return data
    }

    private static func attributeNames(_ descriptor: Int32) throws -> [String] {
        let size = flistxattr(descriptor, nil, 0, 0)
        guard size >= 0 else {
            throw InstallError.operatingSystem("inspect lifecycle helper attributes", errno)
        }
        guard size > 0 else { return [] }
        var bytes = [CChar](repeating: 0, count: size)
        guard flistxattr(descriptor, &bytes, size, 0) == size else {
            throw InstallError.operatingSystem("read lifecycle helper attributes", errno)
        }
        return bytes.split(separator: 0).map {
            String(decoding: $0.map(UInt8.init(bitPattern:)), as: UTF8.self)
        }.sorted()
    }

    private static func hasACL(_ descriptor: Int32) throws -> Bool {
        guard let list = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else {
            if errno == ENOENT {
                return false
            }
            throw InstallError.operatingSystem("inspect lifecycle helper ACL", errno)
        }
        defer { acl_free(UnsafeMutableRawPointer(list)) }
        var entry: acl_entry_t?
        let result = acl_get_entry(list, Int32(ACL_FIRST_ENTRY.rawValue), &entry)
        guard result >= 0 else {
            throw InstallError.operatingSystem("read lifecycle helper ACL", errno)
        }
        return result == 0
    }
}
