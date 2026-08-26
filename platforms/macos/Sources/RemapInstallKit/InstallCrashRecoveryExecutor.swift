import Foundation

/// Reconciles one interrupted transaction from its verified append-only journal.
public struct InstallCrashRecoveryExecutor: Sendable {
    private let lockConfiguration: InstallLockConfiguration
    private let generations: GenerationStore
    private let journalStore: InstallJournalStore
    private let steps: InstallTransactionSteps
    private let validateManifest: @Sendable (InstallManifest) throws -> Void

    public init(
        lockAuthority: FileSystemAuthority,
        lockPath: InstallRelativePath,
        generations: GenerationStore,
        publications: PublicationStore,
        journal: InstallJournalStore,
        effects: any InstallSystemEffectAdapting,
        validateManifest: @escaping @Sendable (InstallManifest) throws -> Void = { _ in }
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
            effects: effects,
            validateManifest: validateManifest
        )
    }

    init(
        lockConfiguration: InstallLockConfiguration,
        generations: GenerationStore,
        publications: PublicationStore,
        journal: InstallJournalStore,
        effects: any InstallSystemEffectAdapting,
        validateManifest: @escaping @Sendable (InstallManifest) throws -> Void = { _ in }
    ) {
        let journalWriter = InstallJournalWriter(store: journal)
        self.lockConfiguration = lockConfiguration
        self.generations = generations
        journalStore = journal
        self.validateManifest = validateManifest
        steps = InstallTransactionSteps(
            generations: generations,
            publications: PublicationReconciler(
                store: publications,
                validateManifest: validateManifest
            ),
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
            try validatePurgeContext(
                record: latest,
                generationID: generationID,
                completedPhase: completedPhase
            )
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
        try validateManifest(current)
        let previous: InstallManifest?
        if let previousGenerationID = record.previousGenerationID {
            previous = try generations.loadManifest(for: previousGenerationID)
            guard let previous, case .owned = try generations.classify(previous) else {
                throw InstallError.collision("previous generation \(previousGenerationID)")
            }
            try validateManifest(previous)
        } else {
            previous = nil
        }
        return try InstallTransitionContext(
            operation: record.operation,
            current: current,
            previous: previous
        )
    }

    private func validatePurgeContext(
        record: InstallJournalRecord,
        generationID: String,
        completedPhase: InstallPhase
    ) throws {
        let identities = [record.generationID, record.previousGenerationID].compactMap(\.self)
        var validated: Set<String> = []
        for identity in identities where validated.insert(identity).inserted {
            if identity == generationID {
                let manifest = try generations.loadManifestForPurgeRecovery(
                    generationID: identity,
                    transactionID: record.transactionID
                )
                if let manifest {
                    try validateManifest(manifest)
                } else if completedPhase != .generationContentsPurged {
                    throw InstallError.integrity(
                        "the journal-bound purge generation is missing"
                    )
                }
            } else {
                let manifest = try generations.loadManifest(for: identity)
                guard case .owned = try generations.classify(manifest) else {
                    throw InstallError.collision("generation \(identity)")
                }
                try validateManifest(manifest)
            }
        }
    }
}
