import Foundation
@testable import RemapInstallKit
import Testing

@Test
func tornJournalRecordFailsClosed() throws {
    #expect(throws: InstallError.journal("a record is torn or malformed")) {
        try InstallJournalChain.decode([Data("{\"schemaVersion\":".utf8)])
    }
}

@Test
func replayedJournalRecordIsRejected() throws {
    let first = try journalRecord(sequence: 1, phase: .prepared, previousDigest: nil)
    let replay = try journalRecord(sequence: 1, phase: .prepared, previousDigest: nil)
    #expect(throws: InstallError.self) {
        try InstallJournalChain.validate([first, replay])
    }
}

@Test
func diskFullBeforeJournalAppendLeavesNoPartialRecord() throws {
    let tree = try TemporaryInstallTree()
    let root = try tree.directory("root")
    let authority = try testAuthority(at: root)
    let store = try InstallJournalStore(
        authority: authority,
        journalsPath: InstallRelativePath("Journal"),
        ownerUID: UInt32(geteuid()),
        groupGID: UInt32(getegid()),
        faultInjector: CheckpointFaultInjector(checkpoint: .beforeJournalAppend)
    )
    let record = try journalRecord(sequence: 1, phase: .prepared, previousDigest: nil)
    #expect(throws: InstallError.faultInjected("beforeJournalAppend")) {
        try store.append(record)
    }
    #expect(try store.load(transactionID: record.transactionID).isEmpty)
}

@Test
func transactionLockRejectsConcurrentOwner() throws {
    let tree = try TemporaryInstallTree()
    let root = try tree.directory("root")
    let firstAuthority = try testAuthority(at: root)
    let secondAuthority = try testAuthority(at: root)
    let path = try InstallRelativePath("install.lock")
    let first = try InstallTransactionLock.acquire(authority: firstAuthority, at: path)
    _ = withExtendedLifetime(first) {
        #expect(throws: InstallError.alreadyLocked) {
            try InstallTransactionLock.acquire(authority: secondAuthority, at: path)
        }
    }
}

@Test
func directoryAuthorityLockRejectsConcurrentOwnerWithoutAPersistentLockFile() throws {
    let tree = try TemporaryInstallTree()
    let root = try tree.directory("root")
    let firstAuthority = try testAuthority(at: root)
    let secondAuthority = try testAuthority(at: root)
    let path = try InstallRelativePath("Agenxy")
    try firstAuthority.ensureOwnedDirectory(
        at: path,
        ownerUID: UInt32(geteuid()),
        groupGID: UInt32(getegid()),
        mode: 0o755
    )
    let first = try InstallTransactionLock.acquireDirectory(
        authority: firstAuthority,
        at: path,
        ownerUID: UInt32(geteuid()),
        groupGID: UInt32(getegid()),
        mode: 0o755
    )
    _ = withExtendedLifetime(first) {
        #expect(throws: InstallError.alreadyLocked) {
            try InstallTransactionLock.acquireDirectory(
                authority: secondAuthority,
                at: path,
                ownerUID: UInt32(geteuid()),
                groupGID: UInt32(getegid()),
                mode: 0o755
            )
        }
    }
}

@Test
func interruptedTerminalJournalCollectionResumesFromTheProtectedNamespace() throws {
    let harness = try InstallTransactionHarness()
    let data = Data("terminal-journal".utf8)
    let manifest = try harness.manifest(
        generationID: "terminal-journal",
        previousGenerationID: nil,
        data: data
    )
    let context = try InstallTransitionContext(operation: .install, current: manifest, previous: nil)
    let journal = harness.journal()
    try appendTerminalInstallJournal(
        store: journal,
        transactionID: "terminal-journal",
        context: context
    )

    let faultingAuthority = try testAuthority(
        at: harness.root,
        faultInjector: CheckpointFaultInjector(checkpoint: .beforeRemove)
    )
    let faulting = InstallJournalStore(
        authority: faultingAuthority,
        journalsPath: harness.journalPath,
        ownerUID: UInt32(geteuid()),
        groupGID: UInt32(getegid())
    )
    #expect(throws: InstallError.faultInjected("beforeRemove")) {
        try faulting.collectTerminalTransactions()
    }
    #expect(try faulting.transactionIDs().isEmpty)
    let healthy = harness.journal()
    try healthy.purgeCompletedTransactions()
    #expect(try healthy.transactionIDs().isEmpty)
    #expect(try harness.authority.listDirectory(at: harness.journalPath).isEmpty)
}

@Test
func lifecycleCommitCollectsOnlyItsOwnTerminalJournal() throws {
    let harness = try InstallTransactionHarness()
    let data = Data("terminal-journal-scope".utf8)
    let manifest = try harness.manifest(
        generationID: "terminal-journal-scope",
        previousGenerationID: nil,
        data: data
    )
    let context = try InstallTransitionContext(operation: .install, current: manifest, previous: nil)
    let journal = harness.journal()
    try appendTerminalInstallJournal(
        store: journal,
        transactionID: "current-transaction",
        context: context
    )
    try appendTerminalInstallJournal(
        store: journal,
        transactionID: "foreign-transaction",
        context: context
    )

    try journal.collectTerminalTransaction(transactionID: "current-transaction")

    #expect(try journal.transactionIDs() == ["foreign-transaction"])
    #expect(try journal.completedTransactionNames().isEmpty)
    #expect(try journal.load(transactionID: "foreign-transaction").last?.phase == .committed)
}

@Test
func narrowTerminalJournalCollectionRecoversAcrossRenameAndRemovalFaults() throws {
    let harness = try InstallTransactionHarness()
    let data = Data("narrow-terminal-journal".utf8)
    let manifest = try harness.manifest(
        generationID: "narrow-terminal-journal",
        previousGenerationID: nil,
        data: data
    )
    let context = try InstallTransitionContext(operation: .install, current: manifest, previous: nil)
    let healthy = harness.journal()
    try appendTerminalInstallJournal(
        store: healthy,
        transactionID: "narrow-terminal-journal",
        context: context
    )
    let renameFault = try InstallJournalStore(
        authority: testAuthority(
            at: harness.root,
            faultInjector: CheckpointFaultInjector(checkpoint: .beforeRename)
        ),
        journalsPath: harness.journalPath,
        ownerUID: UInt32(geteuid()),
        groupGID: UInt32(getegid())
    )
    #expect(throws: InstallError.faultInjected("beforeRename")) {
        try renameFault.collectTerminalTransaction(transactionID: "narrow-terminal-journal")
    }
    #expect(try healthy.transactionIDs() == ["narrow-terminal-journal"])
    #expect(try healthy.completedTransactionNames().isEmpty)

    let removeFault = try InstallJournalStore(
        authority: testAuthority(
            at: harness.root,
            faultInjector: CheckpointFaultInjector(checkpoint: .beforeRemove)
        ),
        journalsPath: harness.journalPath,
        ownerUID: UInt32(geteuid()),
        groupGID: UInt32(getegid())
    )
    #expect(throws: InstallError.faultInjected("beforeRemove")) {
        try removeFault.collectTerminalTransaction(transactionID: "narrow-terminal-journal")
    }
    #expect(try healthy.transactionIDs().isEmpty)
    #expect(try healthy.completedTransactionNames().count == 1)

    try healthy.purgeCompletedTransactions()
    #expect(try healthy.completedTransactionNames().isEmpty)
}

@Test
func narrowTerminalJournalCollectionPreservesForeignCompletedRecoveryState() throws {
    let harness = try InstallTransactionHarness()
    let data = Data("foreign-completed-journal".utf8)
    let manifest = try harness.manifest(
        generationID: "foreign-completed-journal",
        previousGenerationID: nil,
        data: data
    )
    let context = try InstallTransitionContext(operation: .install, current: manifest, previous: nil)
    let healthy = harness.journal()
    for transactionID in ["foreign-completed", "current-terminal"] {
        try appendTerminalInstallJournal(
            store: healthy,
            transactionID: transactionID,
            context: context
        )
    }
    let faulting = try InstallJournalStore(
        authority: testAuthority(
            at: harness.root,
            faultInjector: CheckpointFaultInjector(checkpoint: .beforeRemove)
        ),
        journalsPath: harness.journalPath,
        ownerUID: UInt32(geteuid()),
        groupGID: UInt32(getegid())
    )
    #expect(throws: InstallError.faultInjected("beforeRemove")) {
        try faulting.collectTerminalTransaction(transactionID: "foreign-completed")
    }
    let foreignCompleted = try healthy.completedTransactionNames()
    #expect(foreignCompleted.count == 1)

    try healthy.collectTerminalTransaction(transactionID: "current-terminal")

    #expect(try healthy.transactionIDs().isEmpty)
    #expect(try healthy.completedTransactionNames() == foreignCompleted)
    try healthy.purgeCompletedTransactions()
}

@Test
func committedUpdateSelectsPostCommitGenerationPurge() throws {
    let prepared = try journalRecord(sequence: 1, phase: .prepared, previousDigest: nil)
    let generation = try journalRecord(
        sequence: 2,
        phase: .generationPublished,
        previousDigest: prepared.digest()
    )
    let service = try journalRecord(sequence: 3, phase: .serviceStarted, previousDigest: generation.digest())
    let dns = try journalRecord(sequence: 4, phase: .dnsActive, previousDigest: service.digest())
    let application = try journalRecord(
        sequence: 5,
        phase: .applicationPublished,
        previousDigest: dns.digest()
    )
    let accepted = try journalRecord(sequence: 6, phase: .accepted, previousDigest: application.digest())
    let committed = try journalRecord(sequence: 7, phase: .committed, previousDigest: accepted.digest())
    let chain = [prepared, generation, service, dns, application, accepted, committed]
    let action = InstallRecoveryAction.resumeGenerationPurge(
        from: .committed,
        generationID: "generation-0"
    )
    #expect(try InstallRecoveryStateMachine.nextAction(for: chain) == action)
    #expect(try InstallRecoveryStateMachine.nextAction(for: chain) == action)
}

@Test
func incompleteUpdateSelectsVersionCorrectRollback() throws {
    let prepared = try journalRecord(sequence: 1, phase: .prepared, previousDigest: nil)
    let generation = try journalRecord(
        sequence: 2,
        phase: .generationPublished,
        previousDigest: prepared.digest()
    )
    #expect(
        try InstallRecoveryStateMachine.nextAction(for: [prepared, generation])
            == .rollbackInstall(from: .generationPublished, previousGenerationID: "generation-0")
    )
}

private func appendTerminalInstallJournal(
    store: InstallJournalStore,
    transactionID: String,
    context: InstallTransitionContext
) throws {
    let writer = InstallJournalWriter(store: store)
    try writer.appendInitial(
        transactionID: transactionID,
        context: context,
        phase: .prepared
    )
    for phase in [
        InstallPhase.generationPublished,
        .serviceStarted,
        .dnsActive,
        .applicationPublished,
        .accepted,
        .committed
    ] {
        try writer.appendNext(transactionID: transactionID, phase: phase)
    }
}

func journalRecord(
    sequence: UInt64,
    phase: InstallPhase,
    previousDigest: InstallDigest?
) throws -> InstallJournalRecord {
    try InstallJournalRecord(
        transactionID: "transaction-1",
        sequence: sequence,
        operation: .update,
        phase: phase,
        generationID: "generation-1",
        previousGenerationID: "generation-0",
        previousRecordDigest: previousDigest
    )
}
