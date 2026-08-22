import Foundation

public enum MacOSInstallerPublicationAction: String, Codable, Equatable, Sendable {
    case create
    case remove
    case replace
}

public struct MacOSInstallerPublicationChange: Codable, Equatable, Sendable {
    public let path: InstallRelativePath
    public let action: MacOSInstallerPublicationAction
    public let previousGenerationID: String?
    public let nextGenerationID: String?

    init(
        path: InstallRelativePath,
        action: MacOSInstallerPublicationAction,
        previousGenerationID: String?,
        nextGenerationID: String?
    ) throws {
        if let previousGenerationID {
            try InstallManifest.validateIdentifier(previousGenerationID, field: "previous publication generation")
        }
        if let nextGenerationID {
            try InstallManifest.validateIdentifier(nextGenerationID, field: "next publication generation")
        }
        let validIdentity = switch action {
        case .create:
            previousGenerationID == nil && nextGenerationID != nil
        case .remove:
            previousGenerationID != nil && nextGenerationID == nil
        case .replace:
            previousGenerationID != nil && nextGenerationID != nil
        }
        guard validIdentity else {
            throw InstallError.integrity("preview publication ownership is incomplete")
        }
        self.path = path
        self.action = action
        self.previousGenerationID = previousGenerationID
        self.nextGenerationID = nextGenerationID
    }

    static func changes(
        for context: InstallTransitionContext,
        classifyDirectory: (InstallPublication) throws -> PublicationClassification = { _ in .missing }
    ) throws -> [Self] {
        let previous = Dictionary(uniqueKeysWithValues: (context.previous?.publications ?? []).map { ($0.path, $0) })
        let current = Dictionary(uniqueKeysWithValues: context.current.publications.map { ($0.path, $0) })
        let paths = Set(previous.keys).union(current.keys).sorted()
        return try paths.compactMap { path in
            switch (previous[path], current[path]) {
            case let (old?, new?):
                if old.kind == .directory, new.kind == .directory {
                    return nil
                }
                return try Self(
                    path: path,
                    action: .replace,
                    previousGenerationID: old.generationID,
                    nextGenerationID: new.generationID
                )
            case let (old?, nil):
                if try isCompatibleDirectory(old, classify: classifyDirectory) {
                    return nil
                }
                return try Self(
                    path: path,
                    action: .remove,
                    previousGenerationID: old.generationID,
                    nextGenerationID: nil
                )
            case let (nil, new?):
                if try isCompatibleDirectory(new, classify: classifyDirectory) {
                    return nil
                }
                return try Self(
                    path: path,
                    action: .create,
                    previousGenerationID: nil,
                    nextGenerationID: new.generationID
                )
            case (nil, nil):
                throw InstallError.integrity("preview publication path has no ownership")
            }
        }
    }

    static func removals(for publications: [InstallPublication]) throws -> [Self] {
        try publications.map {
            try Self(
                path: $0.path,
                action: .remove,
                previousGenerationID: $0.generationID,
                nextGenerationID: nil
            )
        }.sorted { $0.path < $1.path }
    }

    private static func isCompatibleDirectory(
        _ publication: InstallPublication,
        classify: (InstallPublication) throws -> PublicationClassification
    ) throws -> Bool {
        guard publication.kind == .directory else {
            return false
        }
        return try classify(publication) == .compatible
    }
}

public struct MacOSInstallerPreview: Codable, Equatable, Sendable {
    public static let maximumPublicationChanges = 256

    public let schemaVersion: UInt32
    public let operation: InstallOperation
    public let generationID: String
    public let productVersion: String
    public let verifiedSourceEntries: Int
    public let publicationChanges: Int
    public let publicationChangeDetails: [MacOSInstallerPublicationChange]
    public let pendingRecoveryTransactions: [String]
    public let effects: [String]
    public let approvalState: MacOSInstallerApprovalState
    public let approvalToken: InstallApprovalToken

    public init(
        schemaVersion: UInt32,
        operation: InstallOperation,
        generationID: String,
        productVersion: String,
        verifiedSourceEntries: Int,
        publicationChangeDetails: [MacOSInstallerPublicationChange],
        pendingRecoveryTransactions: [String],
        effects: [String],
        approvalState: MacOSInstallerApprovalState
    ) throws {
        try InstallManifest.validateIdentifier(generationID, field: "preview generation ID")
        guard schemaVersion == 2,
              verifiedSourceEntries >= 0,
              publicationChangeDetails.count <= Self.maximumPublicationChanges,
              publicationChangeDetails.map(\.path) == publicationChangeDetails.map(\.path).sorted(),
              Set(publicationChangeDetails.map(\.path)).count == publicationChangeDetails.count,
              pendingRecoveryTransactions.count <= 4096,
              1 ... 16 ~= effects.count,
              effects.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 160 })
        else {
            throw InstallError.integrity("installer preview exceeds its deterministic bounds")
        }
        self.schemaVersion = schemaVersion
        self.operation = operation
        self.generationID = generationID
        self.productVersion = productVersion
        self.verifiedSourceEntries = verifiedSourceEntries
        publicationChanges = publicationChangeDetails.count
        self.publicationChangeDetails = publicationChangeDetails
        let orderedRecoveryTransactions = pendingRecoveryTransactions.sorted()
        self.pendingRecoveryTransactions = orderedRecoveryTransactions
        self.effects = effects
        self.approvalState = approvalState
        let payload = MacOSInstallerApprovalPayload(
            schemaVersion: schemaVersion,
            operation: operation,
            generationID: generationID,
            productVersion: productVersion,
            verifiedSourceEntries: verifiedSourceEntries,
            publicationChangeDetails: publicationChangeDetails,
            pendingRecoveryTransactions: orderedRecoveryTransactions,
            effects: effects,
            approvalState: approvalState
        )
        approvalToken = try InstallApprovalToken.bind(
            to: InstallCanonicalJSON.encoder.encode(payload)
        )
    }
}

public struct MacOSInstallerGenerationStatus: Codable, Equatable, Sendable {
    public let generationID: String
    public let productVersion: String
}

public struct MacOSInstallerTransactionStatus: Codable, Equatable, Sendable {
    public let transactionID: String
    public let operation: InstallOperation
    public let phase: InstallPhase
    public let recoveryRequired: Bool
}

public struct MacOSInstallerServiceStatus: Codable, Equatable, Sendable {
    public let label: String
    public let loaded: Bool
    public let plistPath: String?
    public let programPath: String?
}

public struct MacOSInstallerDNSStatus: Codable, Equatable, Sendable {
    public let active: Bool
    public let productVersion: String?
    public let configuredServiceCount: Int
    public let effectiveRemapServiceCount: Int
}

public struct MacOSInstallerStatus: Codable, Equatable, Sendable {
    public let schemaVersion: UInt32
    public let activeGenerationID: String?
    public let generations: [MacOSInstallerGenerationStatus]
    public let transactions: [MacOSInstallerTransactionStatus]
    public let services: [MacOSInstallerServiceStatus]
    public let dns: MacOSInstallerDNSStatus
}

public struct MacOSInstallerRecoveryResult: Codable, Equatable, Sendable {
    public let schemaVersion: UInt32
    public let recoveredTransactions: [String]
    public let quarantinedOrphans: [String]

    public init(
        schemaVersion: UInt32,
        recoveredTransactions: [String],
        quarantinedOrphans: [String]
    ) {
        self.schemaVersion = schemaVersion
        self.recoveredTransactions = recoveredTransactions
        self.quarantinedOrphans = quarantinedOrphans
    }
}
