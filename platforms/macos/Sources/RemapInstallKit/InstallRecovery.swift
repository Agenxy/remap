import Foundation

/// A deterministic next step derived only from a validated durable journal chain.
public enum InstallRecoveryAction: Equatable, Sendable {
    case discardPreparedGeneration(generationID: String?)
    case none
    case resumeRollback(from: InstallPhase, previousGenerationID: String?)
    case resumeGenerationPurge(from: InstallPhase, generationID: String?)
    case resumeUninstall(from: InstallPhase, generationID: String?)
    case rollbackInstall(from: InstallPhase, previousGenerationID: String?)
}

/// Pure recovery decision engine. Effectful privileged adapters execute the returned action.
public enum InstallRecoveryStateMachine {
    public static func nextAction(
        for records: [InstallJournalRecord]
    ) throws -> InstallRecoveryAction {
        try InstallJournalChain.validate(records)
        guard let record = records.last else {
            return .none
        }
        switch record.operation {
        case .install, .update:
            return installAction(records)
        case .uninstall:
            return uninstallAction(record)
        }
    }

    private static func installAction(_ records: [InstallJournalRecord]) -> InstallRecoveryAction {
        guard let record = records.last else {
            return .none
        }
        let committedUpdate = record.operation == .update && records.contains { $0.phase == .committed }
        switch record.phase {
        case .generationContentsPurged, .generationPurgePrepared, .generationPurged:
            if record.phase == .generationPurged {
                return .none
            }
            let target = committedUpdate ? record.previousGenerationID : record.generationID
            return .resumeGenerationPurge(from: record.phase, generationID: target)
        case .committed where record.operation == .update:
            return .resumeGenerationPurge(from: record.phase, generationID: record.previousGenerationID)
        case .rolledBack:
            return .resumeGenerationPurge(from: record.phase, generationID: record.generationID)
        default:
            break
        }
        return switch record.phase {
        case .committed, .rolledBack:
            .none
        case .prepared:
            .discardPreparedGeneration(generationID: record.generationID)
        case .rollingBack:
            .resumeRollback(from: record.phase, previousGenerationID: record.previousGenerationID)
        default:
            .rollbackInstall(from: record.phase, previousGenerationID: record.previousGenerationID)
        }
    }

    private static func uninstallAction(_ record: InstallJournalRecord) -> InstallRecoveryAction {
        switch record.phase {
        case .generationPurged:
            .none
        case .generationContentsPurged, .generationPurgePrepared, .uninstallCommitted:
            .resumeGenerationPurge(from: record.phase, generationID: record.generationID)
        default:
            .resumeUninstall(from: record.phase, generationID: record.generationID)
        }
    }
}
