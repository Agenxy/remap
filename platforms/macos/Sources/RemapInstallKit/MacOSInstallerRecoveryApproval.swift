import Foundation

public struct MacOSInstallerRecoveryTransaction: Codable, Equatable, Sendable {
    public let transactionID: String
    public let operation: InstallOperation
    public let phase: InstallPhase
    public let generationID: String
    public let previousGenerationID: String?
    public let recordCount: Int
    public let journalHeadDigest: InstallDigest
    public let recoveryRequired: Bool

    init(records: [InstallJournalRecord]) throws {
        try InstallJournalChain.validate(records)
        guard let latest = records.last,
              let generationID = latest.generationID
        else {
            throw InstallError.journal("a recovery preview requires a nonempty journal")
        }
        transactionID = latest.transactionID
        operation = latest.operation
        phase = latest.phase
        self.generationID = generationID
        previousGenerationID = latest.previousGenerationID
        recordCount = records.count
        journalHeadDigest = try latest.digest()
        recoveryRequired = try InstallRecoveryStateMachine.nextAction(for: records) != .none
    }
}

public struct MacOSInstallerRecoveryPreview: Codable, Equatable, Sendable {
    public static let maximumTransactions = 4096
    public static let maximumDetachedGenerations = 64

    public let schemaVersion: UInt32
    public let requestedTransactionID: String?
    public let selectedTransactionIDs: [String]
    public let transactions: [MacOSInstallerRecoveryTransaction]
    public let orphanedStagingTransactionIDs: [String]
    public let detachedGenerationNames: [String]
    public let effects: [String]
    public let approvalToken: InstallApprovalToken

    init(
        requestedTransactionID: String?,
        selectedTransactionIDs: [String],
        transactions: [MacOSInstallerRecoveryTransaction],
        orphanedStagingTransactionIDs: [String],
        detachedGenerationNames: [String],
        effects: [String]
    ) throws {
        let selected = selectedTransactionIDs.sorted()
        let orderedTransactions = transactions.sorted { $0.transactionID < $1.transactionID }
        let orphans = orphanedStagingTransactionIDs.sorted()
        let detached = detachedGenerationNames.sorted()
        let available = Set(orderedTransactions.map(\.transactionID))
        if let requestedTransactionID {
            try InstallManifest.validateIdentifier(requestedTransactionID, field: "recovery transaction ID")
        }
        guard orderedTransactions.count <= Self.maximumTransactions,
              orphans.count <= Self.maximumTransactions,
              detached.count <= Self.maximumDetachedGenerations,
              Set(selected).count == selected.count,
              Set(orderedTransactions.map(\.transactionID)).count == orderedTransactions.count,
              Set(orphans).count == orphans.count,
              Set(detached).count == detached.count,
              Set(selected).isSubset(of: available),
              effects.count <= Self.maximumTransactions * 2 + Self.maximumDetachedGenerations + 2,
              effects.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 192 })
        else {
            throw InstallError.integrity("recovery approval exceeds its deterministic bounds")
        }
        schemaVersion = 1
        self.requestedTransactionID = requestedTransactionID
        self.selectedTransactionIDs = selected
        self.transactions = orderedTransactions
        self.orphanedStagingTransactionIDs = orphans
        self.detachedGenerationNames = detached
        self.effects = effects
        let payload = MacOSInstallerRecoveryApprovalPayload(
            schemaVersion: schemaVersion,
            requestedTransactionID: requestedTransactionID,
            selectedTransactionIDs: selected,
            transactions: orderedTransactions,
            orphanedStagingTransactionIDs: orphans,
            detachedGenerationNames: detached,
            effects: effects
        )
        approvalToken = try InstallApprovalToken.bind(
            to: InstallCanonicalJSON.encoder.encode(payload)
        )
    }
}

private struct MacOSInstallerRecoveryApprovalPayload: Encodable {
    let schemaVersion: UInt32
    let requestedTransactionID: String?
    let selectedTransactionIDs: [String]
    let transactions: [MacOSInstallerRecoveryTransaction]
    let orphanedStagingTransactionIDs: [String]
    let detachedGenerationNames: [String]
    let effects: [String]
}
