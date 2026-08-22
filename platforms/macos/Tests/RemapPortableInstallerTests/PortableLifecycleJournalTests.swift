import Darwin
import Foundation
import RemapInstallKit
@testable import RemapPortableInstaller
import Testing

@Test
func portableAuthorityRollbackConvergesFromEveryStagingCheckpoint() throws {
    for checkpoint in [
        PortableAuthorityCheckpoint.journalPrepared,
        .helperStaged,
        .configurationStaged,
        .plistStaged,
        .stagingRecorded
    ] {
        let fixture = try PortableAuthorityFixture()
        defer { fixture.remove() }
        let store = fixture.store(failingAt: checkpoint)
        #expect(throws: InstallError.self) {
            _ = try store.prepare(
                transactionID: "staging-\(checkpoint.rawValue)",
                generationID: "generation-next",
                previousServiceWasLoaded: true,
                contents: fixture.newContents
            )
        }
        let recovery = fixture.store()
        let journal = try #require(try recovery.load())
        try recovery.rollback(journal)
        try recovery.finishRollback()
        try fixture.requireOldAuthority()
        #expect(try recovery.load() == nil)
    }
}

@Test
func portableAuthorityRollbackInfersEachUnrecordedPublication() throws {
    let checkpoints: [PortableAuthorityCheckpoint] = [
        .helperPublishedBeforeJournal,
        .configurationPublishedBeforeJournal,
        .plistPublishedBeforeJournal
    ]
    for (targetIndex, checkpoint) in checkpoints.enumerated() {
        let fixture = try PortableAuthorityFixture()
        defer { fixture.remove() }
        let store = fixture.store(failingAt: checkpoint)
        var journal = try store.prepare(
            transactionID: "publish-\(targetIndex)",
            generationID: "generation-next",
            previousServiceWasLoaded: true,
            contents: fixture.newContents
        )
        for index in 0 ... targetIndex {
            let phase: PortableAuthorityPhase = switch index {
            case 0: .helperPublished
            case 1: .configurationPublished
            default: .plistPublished
            }
            if index == targetIndex {
                #expect(throws: InstallError.self) {
                    _ = try store.publish(journal, index: index, phase: phase)
                }
            } else {
                journal = try store.publish(journal, index: index, phase: phase)
            }
        }
        let recovery = fixture.store()
        let persisted = try #require(try recovery.load())
        try recovery.rollback(persisted)
        try recovery.finishRollback()
        try fixture.requireOldAuthority()
    }
}

@Test
func portableAuthorityRollbackRemovesTrackedPartialStage() throws {
    let fixture = try PortableAuthorityFixture()
    defer { fixture.remove() }
    let store = fixture.store(failingAt: .journalPrepared)
    #expect(throws: InstallError.self) {
        _ = try store.prepare(
            transactionID: "partial-stage",
            generationID: "generation-next",
            previousServiceWasLoaded: true,
            contents: fixture.newContents
        )
    }
    let recovery = fixture.store()
    let journal = try #require(try recovery.load())
    let staged = journal.publications[0].stagedPath
    let stagedPath = try fixture.files.resolve(staged)
    try Data("partial".utf8).write(to: URL(fileURLWithPath: stagedPath))
    #expect(chmod(stagedPath, 0o600) == 0)
    try recovery.rollback(journal)
    try recovery.finishRollback()
    try fixture.requireOldAuthority()
    #expect(!fixture.files.exists(staged))
}

@Test
func portableAuthorityCommitRecoversAfterEachBackupRemoval() throws {
    for checkpoint in [
        PortableAuthorityCheckpoint.previousHelperRemoved,
        .previousConfigurationRemoved,
        .previousPlistRemoved
    ] {
        let fixture = try PortableAuthorityFixture()
        defer { fixture.remove() }
        let store = fixture.store(failingAt: checkpoint)
        var journal = try fixture.publishAll(using: store)
        journal = try store.advance(journal, to: .serviceLoaded)
        journal = try store.advance(journal, to: .productCommitted)
        #expect(throws: InstallError.self) {
            try store.commit(journal)
        }
        let recovery = fixture.store()
        let persisted = try #require(try recovery.load())
        try recovery.commit(persisted)
        try fixture.requireNewAuthority()
        #expect(try recovery.load() == nil)
    }
}

@Test
func portableAuthorityFirstInstallCommitsWithoutBackups() throws {
    let fixture = try PortableAuthorityFixture(includeOldAuthority: false)
    defer { fixture.remove() }
    let store = fixture.store()
    var journal = try fixture.publishAll(using: store)
    journal = try store.advance(journal, to: .serviceLoaded)
    journal = try store.advance(journal, to: .productCommitted)
    try store.commit(journal)
    try fixture.requireNewAuthority()
    #expect(try store.load() == nil)
}

@Test
func portableAuthorityCommitResumesPriorSourceCollection() throws {
    let fixture = try PortableAuthorityFixture()
    defer { fixture.remove() }
    let digest = try InstallDigest(String(repeating: "d", count: 64))
    let sourceRoot = PortableInstallTopology.sourcesPath + "/\(digest.description)"
    let recorder = SourcePurgeRecorder()
    let failing = PortableAuthorityPublicationStore(
        files: fixture.files,
        faults: PortableAuthorityFaults { checkpoint in
            if checkpoint == .previousSourceRemoved {
                throw InstallError.faultInjected(checkpoint.rawValue)
            }
        },
        sourcePurge: recorder.record
    )
    var journal = try failing.prepare(
        transactionID: "source-collection",
        generationID: "generation-next",
        previousServiceWasLoaded: true,
        previousSourceRoot: sourceRoot,
        previousSourceManifestDigest: digest,
        contents: fixture.newContents
    )
    journal = try failing.publish(journal, index: 0, phase: .helperPublished)
    journal = try failing.publish(journal, index: 1, phase: .configurationPublished)
    journal = try failing.publish(journal, index: 2, phase: .plistPublished)
    journal = try failing.advance(journal, to: .serviceLoaded)
    journal = try failing.advance(journal, to: .productCommitted)
    #expect(throws: InstallError.self) {
        try failing.commit(journal)
    }

    let recovery = PortableAuthorityPublicationStore(
        files: fixture.files,
        sourcePurge: recorder.record
    )
    try recovery.commit(#require(try recovery.load()))
    #expect(recorder.values == [sourceRoot, sourceRoot])
    #expect(try recovery.load() == nil)
}

@Test
func portableAuthorityRollbackPreflightsEveryPublicationBeforeMutation() throws {
    let fixture = try PortableAuthorityFixture()
    defer { fixture.remove() }
    let store = fixture.store()
    let journal = try fixture.publishAll(using: store)
    try fixture.overwrite(
        journal.publications[2].stagedPath,
        with: Data("foreign-previous-plist".utf8)
    )
    #expect(throws: InstallError.self) {
        try store.rollback(journal)
    }
    try fixture.requireNewAuthority()
    for publication in journal.publications {
        #expect(try fixture.files.inspect(
            publication.stagedPath,
            expectedMode: publication.mode
        ) != nil)
    }
}

@Test
func portableAuthorityCommitPreflightsEveryPublicationBeforeMutation() throws {
    let fixture = try PortableAuthorityFixture()
    defer { fixture.remove() }
    let store = fixture.store()
    var journal = try fixture.publishAll(using: store)
    journal = try store.advance(journal, to: .serviceLoaded)
    journal = try store.advance(journal, to: .productCommitted)
    try fixture.overwrite(
        journal.publications[2].stagedPath,
        with: Data("foreign-previous-plist".utf8)
    )
    #expect(throws: InstallError.self) {
        try store.commit(journal)
    }
    try fixture.requireNewAuthority()
    for publication in journal.publications {
        #expect(try fixture.files.inspect(
            publication.stagedPath,
            expectedMode: publication.mode
        ) != nil)
    }
}

@Test
func portableAuthorityJournalRepairsOnlyAnIncompleteTail() throws {
    let fixture = try PortableAuthorityFixture()
    defer { fixture.remove() }
    let store = fixture.store()
    let prepared = try store.prepare(
        transactionID: "journal-tail",
        generationID: "generation-next",
        previousServiceWasLoaded: true,
        contents: fixture.newContents
    )
    let journalPath = try fixture.files.resolve(PortableLifecyclePaths.journal)
    let handle = try FileHandle(forWritingTo: URL(fileURLWithPath: journalPath))
    try handle.seekToEnd()
    try handle.write(contentsOf: Data("{\"partial\":".utf8))
    try handle.synchronize()
    try handle.close()
    #expect(try store.load() == prepared)
    let repaired = try Data(contentsOf: URL(fileURLWithPath: journalPath))
    #expect(repaired.last == 0x0A)
}

@Test
func portableAuthorityJournalClearsAnEmptyFirstFrame() throws {
    let fixture = try PortableAuthorityFixture()
    defer { fixture.remove() }
    let journalPath = try fixture.files.resolve(PortableLifecyclePaths.journal)
    #expect(FileManager.default.createFile(atPath: journalPath, contents: Data()))
    #expect(chmod(journalPath, 0o600) == 0)
    let store = fixture.store()
    #expect(try store.load() == nil)
    #expect(!fixture.files.exists(PortableLifecyclePaths.journal))
}

@Test
func portableAuthorityJournalRejectsACompleteForeignFrame() throws {
    let fixture = try PortableAuthorityFixture()
    defer { fixture.remove() }
    let store = fixture.store()
    _ = try store.prepare(
        transactionID: "journal-tamper",
        generationID: "generation-next",
        previousServiceWasLoaded: true,
        contents: fixture.newContents
    )
    let journalPath = try fixture.files.resolve(PortableLifecyclePaths.journal)
    let handle = try FileHandle(forWritingTo: URL(fileURLWithPath: journalPath))
    try handle.seekToEnd()
    try handle.write(contentsOf: Data("{}\n".utf8))
    try handle.synchronize()
    try handle.close()
    #expect(throws: Error.self) {
        _ = try store.load()
    }
}

@Test
func portableAuthorityLockUsesOneStableInode() throws {
    let fixture = try PortableAuthorityFixture()
    defer { fixture.remove() }
    let first = try PortableAuthorityLock.acquire(files: fixture.files)
    _ = first
    #expect(throws: InstallError.self) {
        _ = try PortableAuthorityLock.acquire(files: fixture.files)
    }
}

private struct PortableAuthorityFixture {
    let root: URL
    let files: PortableAuthorityFiles
    let oldContents = [
        Data("old-helper".utf8),
        Data("old-configuration".utf8),
        Data("old-plist".utf8)
    ]
    let newContents = [
        Data("new-helper".utf8),
        Data("new-configuration".utf8),
        Data("new-plist".utf8)
    ]

    init(includeOldAuthority: Bool = true) throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent(
            "remap-portable-authority-\(UUID().uuidString.lowercased())",
            isDirectory: true
        )
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        files = PortableAuthorityFiles(
            rootPrefix: root.path,
            expectedUID: getuid(),
            expectedGID: getgid()
        )
        let parents = Set(
            (PortableLifecyclePaths.orderedPublications.map(\.path) + [
                PortableLifecyclePaths.journal,
                PortableLifecyclePaths.lock
            ]).map {
                URL(fileURLWithPath: root.path + $0).deletingLastPathComponent().path
            }
        )
        for parent in parents.sorted() {
            try FileManager.default.createDirectory(
                atPath: parent,
                withIntermediateDirectories: true
            )
        }
        if includeOldAuthority {
            for (index, publication) in PortableLifecyclePaths.orderedPublications.enumerated() {
                try files.writeNew(
                    oldContents[index],
                    to: publication.path,
                    finalMode: publication.mode
                )
            }
        }
    }

    func store(
        failingAt checkpoint: PortableAuthorityCheckpoint? = nil
    ) -> PortableAuthorityPublicationStore {
        PortableAuthorityPublicationStore(
            files: files,
            faults: PortableAuthorityFaults { observed in
                if observed == checkpoint {
                    throw InstallError.faultInjected(observed.rawValue)
                }
            }
        )
    }

    func publishAll(
        using store: PortableAuthorityPublicationStore
    ) throws -> PortableAuthorityJournal {
        var journal = try store.prepare(
            transactionID: "complete-transaction",
            generationID: "generation-next",
            previousServiceWasLoaded: true,
            contents: newContents
        )
        journal = try store.publish(journal, index: 0, phase: .helperPublished)
        journal = try store.publish(journal, index: 1, phase: .configurationPublished)
        return try store.publish(journal, index: 2, phase: .plistPublished)
    }

    func requireOldAuthority() throws {
        try requireContents(oldContents)
    }

    func requireNewAuthority() throws {
        try requireContents(newContents)
    }

    func remove() {
        try? FileManager.default.removeItem(at: root)
    }

    func overwrite(_ logicalPath: String, with data: Data) throws {
        let path = try files.resolve(logicalPath)
        let handle = try FileHandle(forWritingTo: URL(fileURLWithPath: path))
        try handle.truncate(atOffset: 0)
        try handle.write(contentsOf: data)
        try handle.synchronize()
        try handle.close()
    }

    private func requireContents(_ contents: [Data]) throws {
        for (index, publication) in PortableLifecyclePaths.orderedPublications.enumerated() {
            let snapshot = try #require(
                try files.inspect(publication.path, expectedMode: publication.mode)
            )
            #expect(snapshot.digest == InstallDigest.hash(contents[index]))
            #expect(snapshot.byteCount == contents[index].count)
        }
    }
}

private final class SourcePurgeRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var recorded: [String] = []

    var values: [String] {
        lock.withLock { recorded }
    }

    func record(root: String, digest _: InstallDigest) {
        lock.withLock { recorded.append(root) }
    }
}
