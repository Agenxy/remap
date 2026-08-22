import Foundation

struct InstallTransactionSteps: Sendable {
    let generations: GenerationStore
    let publications: PublicationReconciler
    let journal: InstallJournalWriter
    let effects: any InstallSystemEffectAdapting

    func runUninstall(
        transactionID: String,
        context: InstallTransitionContext,
        completedPhase: InstallPhase
    ) async throws {
        try await reconcile(.dnsRestored, context: context)
        if !uninstallPhase(completedPhase, includes: .dnsRestored) {
            try journal.appendNext(transactionID: transactionID, phase: .dnsRestored)
        }
        try await reconcile(.serviceStopped, context: context)
        if !uninstallPhase(completedPhase, includes: .serviceStopped) {
            try journal.appendNext(transactionID: transactionID, phase: .serviceStopped)
        }
        try publications.removeCurrent(context)
        if !uninstallPhase(completedPhase, includes: .publicationsRemoved) {
            try journal.appendNext(transactionID: transactionID, phase: .publicationsRemoved)
        }
        try generations.retire(context.current, transactionID: transactionID)
        if !uninstallPhase(completedPhase, includes: .generationRetired) {
            try journal.appendNext(transactionID: transactionID, phase: .generationRetired)
        }
        if !uninstallPhase(completedPhase, includes: .uninstallCommitted) {
            try journal.appendNext(transactionID: transactionID, phase: .uninstallCommitted)
        }
        try runCommittedPurge(
            transactionID: transactionID,
            generationID: context.current.generationID,
            completedPhase: completedPhase == .uninstallPrepared ? .uninstallCommitted : completedPhase
        )
    }

    func runCommittedPurge(
        transactionID: String,
        generationID: String,
        completedPhase: InstallPhase
    ) throws {
        if !purgePhase(completedPhase, includes: .generationPurgePrepared) {
            try generations.requirePurgeable(generationID: generationID, transactionID: transactionID)
            try journal.appendNext(transactionID: transactionID, phase: .generationPurgePrepared)
        }
        if !purgePhase(completedPhase, includes: .generationContentsPurged) {
            try generations.purgeContents(generationID: generationID, transactionID: transactionID)
            try journal.appendNext(transactionID: transactionID, phase: .generationContentsPurged)
        }
        try generations.finishPurge(generationID: generationID, transactionID: transactionID)
        if !purgePhase(completedPhase, includes: .generationPurged) {
            try journal.appendNext(transactionID: transactionID, phase: .generationPurged)
        }
    }

    func rollBackInstall(
        transactionID: String,
        context: InstallTransitionContext,
        completedPhase: InstallPhase
    ) async throws {
        if completedPhase != .rollingBack {
            try journal.appendNext(transactionID: transactionID, phase: .rollingBack)
        }
        try publications.restorePrevious(context, transactionID: transactionID)
        try await reconcile(.priorServiceRestored, context: context)
        try await reconcile(.dnsRestored, context: context)
        try disposeCurrent(context.current, transactionID: transactionID)
        try journal.appendNext(transactionID: transactionID, phase: .rolledBack)
        try runCommittedPurge(
            transactionID: transactionID,
            generationID: context.current.generationID,
            completedPhase: .rolledBack
        )
    }

    func discardPreparedGeneration(
        transactionID: String,
        context: InstallTransitionContext
    ) throws {
        try journal.appendNext(transactionID: transactionID, phase: .rollingBack)
        try disposeCurrent(context.current, transactionID: transactionID)
        try journal.appendNext(transactionID: transactionID, phase: .rolledBack)
        try runCommittedPurge(
            transactionID: transactionID,
            generationID: context.current.generationID,
            completedPhase: .rolledBack
        )
    }

    func reconcile(_ effect: InstallSystemEffect, context: InstallTransitionContext) async throws {
        try await effects.reconcile(effect, context: context)
        try await effects.verify(effect, context: context)
    }

    private func disposeCurrent(_ manifest: InstallManifest, transactionID: String) throws {
        switch try generations.classify(manifest) {
        case .owned:
            try generations.retire(manifest, transactionID: transactionID)
        case .unmanaged:
            throw InstallError.collision("live generation \(manifest.generationID)")
        case .missing:
            try disposeNonLive(manifest, transactionID: transactionID)
        }
    }

    private func disposeNonLive(_ manifest: InstallManifest, transactionID: String) throws {
        switch try generations.classifyRetired(manifest, transactionID: transactionID) {
        case .owned:
            return
        case .unmanaged:
            throw InstallError.collision("retired generation \(manifest.generationID)")
        case .missing:
            try generations.retireStaging(manifest, transactionID: transactionID)
        }
    }

    private func uninstallPhase(_ completed: InstallPhase, includes candidate: InstallPhase) -> Bool {
        guard let completedIndex = Self.uninstallOrder.firstIndex(of: completed),
              let candidateIndex = Self.uninstallOrder.firstIndex(of: candidate)
        else {
            return false
        }
        return completedIndex >= candidateIndex
    }

    private func purgePhase(_ completed: InstallPhase, includes candidate: InstallPhase) -> Bool {
        guard let completedIndex = Self.purgeOrder.firstIndex(of: completed),
              let candidateIndex = Self.purgeOrder.firstIndex(of: candidate)
        else {
            return false
        }
        return completedIndex >= candidateIndex
    }

    private static let uninstallOrder: [InstallPhase] = [
        .uninstallPrepared,
        .dnsRestored,
        .serviceStopped,
        .publicationsRemoved,
        .generationRetired,
        .uninstallCommitted,
        .generationPurgePrepared,
        .generationContentsPurged,
        .generationPurged
    ]

    private static let purgeOrder: [InstallPhase] = [
        .generationPurgePrepared,
        .generationContentsPurged,
        .generationPurged
    ]
}
