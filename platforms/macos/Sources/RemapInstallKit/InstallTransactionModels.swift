import Foundation

/// Desired native system states. Adapters must reconcile each state idempotently before verifying it.
public enum InstallSystemEffect: String, Equatable, Sendable {
    case dnsActive
    case dnsRestored
    case installationAccepted
    case priorServiceRestored
    case serviceRunning
    case serviceStopped
}

/// Complete immutable context for one install, update, uninstall, or recovery transaction.
public struct InstallTransitionContext: Equatable, Sendable {
    public let operation: InstallOperation
    public let current: InstallManifest
    public let previous: InstallManifest?

    public init(
        operation: InstallOperation,
        current: InstallManifest,
        previous: InstallManifest?
    ) throws {
        try current.validate()
        if let previous {
            try previous.validate()
            guard previous.productIdentifier == current.productIdentifier else {
                throw InstallError.invalidManifest("update generations identify different products")
            }
        }
        try Self.validateIdentity(operation: operation, current: current, previous: previous)
        self.operation = operation
        self.current = current
        self.previous = previous
    }

    private static func validateIdentity(
        operation: InstallOperation,
        current: InstallManifest,
        previous: InstallManifest?
    ) throws {
        switch operation {
        case .install where previous == nil && current.previousGenerationID == nil:
            return
        case .update where previous != nil && current.previousGenerationID == previous?.generationID:
            return
        case .uninstall where previous == nil:
            return
        default:
            throw InstallError.invalidManifest("generation lineage does not match the requested operation")
        }
    }
}

/// Typed input for a fresh install or update transaction.
public struct InstallTransactionRequest: Sendable {
    public let transactionID: String
    public let context: InstallTransitionContext
    public let source: FileSystemAuthority

    public init(
        transactionID: String,
        context: InstallTransitionContext,
        source: FileSystemAuthority
    ) throws {
        try InstallManifest.validateIdentifier(transactionID, field: "transaction ID")
        guard context.operation != .uninstall else {
            throw InstallError.unsupported("an uninstall transaction has no staged source")
        }
        self.transactionID = transactionID
        self.context = context
        self.source = source
    }
}

/// Native side-effect boundary. Reconciliation and verification are deliberately separate.
public protocol InstallSystemEffectAdapting: Sendable {
    /// Idempotently drives the machine toward the requested state.
    func reconcile(_ effect: InstallSystemEffect, context: InstallTransitionContext) async throws

    /// Independently proves the requested state before its journal phase may be appended.
    func verify(_ effect: InstallSystemEffect, context: InstallTransitionContext) async throws
}

struct InstallJournalWriter: Sendable {
    let store: InstallJournalStore

    func requireUnused(transactionID: String) throws {
        guard try store.load(transactionID: transactionID).isEmpty else {
            throw InstallError.collision("journal transaction \(transactionID)")
        }
    }

    func appendInitial(
        transactionID: String,
        context: InstallTransitionContext,
        phase: InstallPhase
    ) throws {
        let record = try InstallJournalRecord(
            transactionID: transactionID,
            sequence: 1,
            operation: context.operation,
            phase: phase,
            generationID: context.current.generationID,
            previousGenerationID: context.previous?.generationID,
            previousRecordDigest: nil
        )
        try store.append(record)
    }

    func appendNext(transactionID: String, phase: InstallPhase) throws {
        let records = try store.load(transactionID: transactionID)
        guard let previous = records.last else {
            throw InstallError.journal("cannot append a phase to an unknown transaction")
        }
        let record = try InstallJournalRecord(
            transactionID: transactionID,
            sequence: previous.sequence + 1,
            operation: previous.operation,
            phase: phase,
            generationID: previous.generationID,
            previousGenerationID: previous.previousGenerationID,
            previousRecordDigest: previous.digest()
        )
        try store.append(record)
    }

    func collectTerminal(transactionID: String) throws {
        try store.collectTerminalTransaction(transactionID: transactionID)
    }
}
