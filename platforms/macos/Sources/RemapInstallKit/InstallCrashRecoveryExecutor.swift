import Foundation

/// Reconciles one interrupted transaction from its verified append-only journal.
public struct InstallCrashRecoveryExecutor: Sendable {
    private let lockConfiguration: InstallLockConfiguration
    private let generations: GenerationStore
    private let journalStore: InstallJournalStore
    private let steps: InstallTransactionSteps

    public init(
        lockAuthority: FileSystemAuthority,
        lockPath: InstallRelativePath,
        generations: GenerationStore,
        publications: PublicationStore,
        journal: InstallJournalStore,
        effects: any InstallSystemEffectAdapting
    ) {
        self.init(
            lockConfiguration: InstallLockConfiguration(
                authority: lockAuthority,
                path: lockPath,
                kind: .privateFile
            ),
            generations: generations,
            publications: publications,
            journal: journal,
            effects: effects
        )
    }

    init(
        lockConfiguration: InstallLockConfiguration,
        generations: GenerationStore,
        publications: PublicationStore,
        journal: InstallJournalStore,
        effects: any InstallSystemEffectAdapting
    ) {
        let journalWriter = InstallJournalWriter(store: journal)
        self.lockConfiguration = lockConfiguration
        self.generations = generations
        journalStore = journal
        steps = InstallTransactionSteps(
            generations: generations,
            publications: PublicationReconciler(store: publications),
            journal: journalWriter,
            effects: effects
        )
    }

    func recover(transactionID: String) async throws {
        try InstallManifest.validateIdentifier(transactionID, field: "transaction ID")
        let lock = try lockConfiguration.acquire()
        defer { _ = lock }
        try await recoverLocked(transactionID: transactionID)
    }

    func recoverLocked(transactionID: String) async throws {
        try InstallManifest.validateIdentifier(transactionID, field: "transaction ID")
        let records = try journalStore.load(transactionID: transactionID)
        let action = try InstallRecoveryStateMachine.nextAction(for: records)
        guard let latest = records.last else {
            return
        }
        switch action {
        case .none:
            return
        case .discardPreparedGeneration:
            let context = try loadContext(record: latest)
            try steps.discardPreparedGeneration(
                transactionID: transactionID,
                context: context
            )
        case .resumeRollback, .rollbackInstall:
            let context = try loadContext(record: latest)
            try await steps.rollBackInstall(
                transactionID: transactionID,
                context: context,
                completedPhase: latest.phase
            )
        case let .resumeGenerationPurge(completedPhase, generationID):
            guard let generationID else {
                throw InstallError.journal("generation purge has no target identity")
            }
            try steps.runCommittedPurge(
                transactionID: transactionID,
                generationID: generationID,
                completedPhase: completedPhase
            )
        case .resumeUninstall:
            let context = try loadContext(record: latest)
            try await steps.runUninstall(
                transactionID: transactionID,
                context: context,
                completedPhase: latest.phase
            )
        }
    }

    private func loadContext(record: InstallJournalRecord) throws -> InstallTransitionContext {
        guard let generationID = record.generationID else {
            throw InstallError.journal("recovery transaction has no generation identity")
        }
        let current = try generations.loadManifestForRecovery(
            generationID: generationID,
            transactionID: record.transactionID
        )
        let previous: InstallManifest?
        if let previousGenerationID = record.previousGenerationID {
            previous = try generations.loadManifest(for: previousGenerationID)
            guard let previous, case .owned = try generations.classify(previous) else {
                throw InstallError.collision("previous generation \(previousGenerationID)")
            }
        } else {
            previous = nil
        }
        return try InstallTransitionContext(
            operation: record.operation,
            current: current,
            previous: previous
        )
    }
}
