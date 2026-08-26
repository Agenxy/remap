import Foundation

/// Executes fresh install, update, and uninstall transactions under one exclusive native lock.
public struct InstallTransactionCoordinator: Sendable {
    private let lockConfiguration: InstallLockConfiguration
    private let generations: GenerationStore
    private let publications: PublicationReconciler
    private let journal: InstallJournalWriter
    private let steps: InstallTransactionSteps
    private let approvalVerifier: any InstallApprovalVerifying
    private let prepareStorage: @Sendable () throws -> Void

    public init(
        lockAuthority: FileSystemAuthority,
        lockPath: InstallRelativePath,
        generations: GenerationStore,
        publications: PublicationStore,
        journal: InstallJournalStore,
        effects: any InstallSystemEffectAdapting,
        approvalVerifier: any InstallApprovalVerifying,
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
            approvalVerifier: approvalVerifier,
            prepareStorage: {},
            validateManifest: validateManifest
        )
    }

    init(
        lockConfiguration: InstallLockConfiguration,
        generations: GenerationStore,
        publications: PublicationStore,
        journal: InstallJournalStore,
        effects: any InstallSystemEffectAdapting,
        approvalVerifier: any InstallApprovalVerifying,
        prepareStorage: @escaping @Sendable () throws -> Void = {},
        validateManifest: @escaping @Sendable (InstallManifest) throws -> Void = { _ in }
    ) {
        let publicationReconciler = PublicationReconciler(
            store: publications,
            validateManifest: validateManifest
        )
        let journalWriter = InstallJournalWriter(store: journal)
        self.lockConfiguration = lockConfiguration
        self.generations = generations
        self.publications = publicationReconciler
        self.journal = journalWriter
        self.approvalVerifier = approvalVerifier
        self.prepareStorage = prepareStorage
        steps = InstallTransactionSteps(
            generations: generations,
            publications: publicationReconciler,
            journal: journalWriter,
            effects: effects
        )
    }

    func installOrUpdate(_ request: InstallTransactionRequest) async throws {
        let lock = try lockConfiguration.acquire()
        defer { _ = lock }
        try approvalVerifier.verify(request.context)
        try prepareStorage()
        try journal.requireUnused(transactionID: request.transactionID)
        try requireInstallPreconditions(request.context)
        let staging = try generations.stage(
            request.context.current,
            from: request.source,
            transactionID: request.transactionID
        )
        guard case .owned = try generations.classifyStaging(
            request.context.current,
            transactionID: request.transactionID
        ) else {
            throw InstallError.integrity("staged generation failed exact manifest verification")
        }
        do {
            try journal.appendInitial(
                transactionID: request.transactionID,
                context: request.context,
                phase: .prepared
            )
        } catch let primaryError {
            do {
                try generations.quarantineStaging(
                    request.context.current,
                    transactionID: request.transactionID
                )
            } catch let recoveryError {
                throw InstallError.transaction(
                    primary: String(describing: primaryError),
                    recovery: String(describing: recoveryError)
                )
            }
            throw primaryError
        }
        try await commitInstall(request, staging: staging)
        if let previous = request.context.previous {
            try steps.runCommittedPurge(
                transactionID: request.transactionID,
                generationID: previous.generationID,
                completedPhase: .committed
            )
        }
        try journal.collectTerminal(transactionID: request.transactionID)
    }

    private func commitInstall(
        _ request: InstallTransactionRequest,
        staging: InstallRelativePath
    ) async throws {
        var completedPhase = InstallPhase.prepared
        do {
            try generations.publish(staging, manifest: request.context.current)
            guard case .owned = try generations.classify(request.context.current) else {
                throw InstallError.integrity("published generation failed exact manifest verification")
            }
            try journal.appendNext(transactionID: request.transactionID, phase: .generationPublished)
            completedPhase = .generationPublished
            try await steps.reconcile(.serviceRunning, context: request.context)
            try journal.appendNext(transactionID: request.transactionID, phase: .serviceStarted)
            completedPhase = .serviceStarted
            try await steps.reconcile(.dnsActive, context: request.context)
            try journal.appendNext(transactionID: request.transactionID, phase: .dnsActive)
            completedPhase = .dnsActive
            try publications.install(request.context, transactionID: request.transactionID)
            try journal.appendNext(transactionID: request.transactionID, phase: .applicationPublished)
            completedPhase = .applicationPublished
            try await steps.reconcile(.installationAccepted, context: request.context)
            try journal.appendNext(transactionID: request.transactionID, phase: .accepted)
            completedPhase = .accepted
            try journal.appendNext(transactionID: request.transactionID, phase: .committed)
        } catch let primaryError {
            try await recoverFailedInstall(
                request,
                completedPhase: completedPhase,
                primaryError: primaryError
            )
        }
    }

    private func recoverFailedInstall(
        _ request: InstallTransactionRequest,
        completedPhase: InstallPhase,
        primaryError: any Error
    ) async throws -> Never {
        do {
            if completedPhase == .prepared {
                try steps.discardPreparedGeneration(
                    transactionID: request.transactionID,
                    context: request.context
                )
            } else {
                try await steps.rollBackInstall(
                    transactionID: request.transactionID,
                    context: request.context,
                    completedPhase: completedPhase
                )
            }
            try journal.collectTerminal(transactionID: request.transactionID)
        } catch let recoveryError {
            throw InstallError.transaction(
                primary: String(describing: primaryError),
                recovery: String(describing: recoveryError)
            )
        }
        throw primaryError
    }

    func uninstall(transactionID: String, manifest: InstallManifest) async throws {
        try InstallManifest.validateIdentifier(transactionID, field: "transaction ID")
        let context = try InstallTransitionContext(operation: .uninstall, current: manifest, previous: nil)
        let lock = try lockConfiguration.acquire()
        defer { _ = lock }
        try approvalVerifier.verify(context)
        try journal.requireUnused(transactionID: transactionID)
        guard case .owned = try generations.classify(manifest) else {
            throw InstallError.collision("generation \(manifest.generationID)")
        }
        try publications.requireCurrentOwned(context)
        try journal.appendInitial(
            transactionID: transactionID,
            context: context,
            phase: .uninstallPrepared
        )
        try await steps.runUninstall(
            transactionID: transactionID,
            context: context,
            completedPhase: .uninstallPrepared
        )
    }

    private func requireInstallPreconditions(_ context: InstallTransitionContext) throws {
        guard case .missing = try generations.classify(context.current) else {
            throw InstallError.collision("generation \(context.current.generationID)")
        }
        if let previous = context.previous {
            guard case .owned = try generations.classify(previous) else {
                throw InstallError.collision("previous generation \(previous.generationID)")
            }
        }
        try publications.requireInstallable(context)
    }
}
