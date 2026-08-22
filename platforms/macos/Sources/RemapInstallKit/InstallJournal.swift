import Foundation

/// The transaction whose recovery semantics are journaled.
public enum InstallOperation: String, Codable, Equatable, Sendable {
    case install
    case uninstall
    case update
}

/// Durable milestones. A milestone means the named effect completed and was verified.
public enum InstallPhase: String, Codable, Equatable, Sendable {
    case accepted
    case applicationPublished
    case committed
    case dnsActive
    case dnsRestored
    case generationPublished
    case generationPurgePrepared
    case generationContentsPurged
    case generationPurged
    case generationRetired
    case prepared
    case publicationsRemoved
    case rolledBack
    case rollingBack
    case serviceStarted
    case serviceStopped
    case uninstallCommitted
    case uninstallPrepared
}

/// One canonical append-only journal record bound to its predecessor's digest.
public struct InstallJournalRecord: Codable, Equatable, Sendable {
    public let schemaVersion: UInt32
    public let transactionID: String
    public let sequence: UInt64
    public let operation: InstallOperation
    public let phase: InstallPhase
    public let generationID: String?
    public let previousGenerationID: String?
    public let previousRecordDigest: InstallDigest?

    public init(
        transactionID: String,
        sequence: UInt64,
        operation: InstallOperation,
        phase: InstallPhase,
        generationID: String?,
        previousGenerationID: String?,
        previousRecordDigest: InstallDigest?
    ) throws {
        try InstallManifest.validateIdentifier(transactionID, field: "transaction ID")
        guard sequence > 0 else {
            throw InstallError.journal("sequence numbers start at one")
        }
        if let generationID {
            try InstallManifest.validateIdentifier(generationID, field: "generation ID")
        }
        if let previousGenerationID {
            try InstallManifest.validateIdentifier(previousGenerationID, field: "previous generation ID")
        }
        try Self.validateIdentities(
            operation: operation,
            generationID: generationID,
            previousGenerationID: previousGenerationID
        )
        schemaVersion = 1
        self.transactionID = transactionID
        self.sequence = sequence
        self.operation = operation
        self.phase = phase
        self.generationID = generationID
        self.previousGenerationID = previousGenerationID
        self.previousRecordDigest = previousRecordDigest
    }

    public func canonicalData() throws -> Data {
        try InstallCanonicalJSON.encoder.encode(self)
    }

    public func digest() throws -> InstallDigest {
        try InstallDigest.hash(canonicalData())
    }

    public func validate() throws {
        let reconstructed = try InstallJournalRecord(
            transactionID: transactionID,
            sequence: sequence,
            operation: operation,
            phase: phase,
            generationID: generationID,
            previousGenerationID: previousGenerationID,
            previousRecordDigest: previousRecordDigest
        )
        guard schemaVersion == 1, reconstructed == self else {
            throw InstallError.journal("record schema validation failed")
        }
    }

    private static func validateIdentities(
        operation: InstallOperation,
        generationID: String?,
        previousGenerationID: String?
    ) throws {
        guard let generationID else {
            throw InstallError.journal("every transaction must bind an installed generation")
        }
        switch operation {
        case .install where previousGenerationID == nil:
            return
        case .update where previousGenerationID != nil && previousGenerationID != generationID:
            return
        case .uninstall where previousGenerationID == nil:
            return
        default:
            throw InstallError.journal("generation identities do not match the transaction operation")
        }
    }
}

/// Validates complete chains, rejecting replays, gaps, identity drift, and invalid phase transitions.
public enum InstallJournalChain {
    public static let maximumRecordCount = 4096

    public static func decode(_ payloads: [Data]) throws -> [InstallJournalRecord] {
        guard payloads.count <= maximumRecordCount else {
            throw InstallError.journal("record count exceeds the recovery bound")
        }
        let records = try payloads.map { payload in
            do {
                return try InstallCanonicalJSON.decoder.decode(InstallJournalRecord.self, from: payload)
            } catch {
                throw InstallError.journal("a record is torn or malformed")
            }
        }
        try validate(records)
        return records
    }

    public static func validate(_ records: [InstallJournalRecord]) throws {
        guard records.count <= maximumRecordCount else {
            throw InstallError.journal("record count exceeds the recovery bound")
        }
        guard let first = records.first else {
            return
        }
        try first.validate()
        guard first.sequence == 1, first.previousRecordDigest == nil else {
            throw InstallError.journal("the first record is not an unchained sequence-one record")
        }
        guard validInitialPhase(first.phase, operation: first.operation) else {
            throw InstallError.journal("the initial phase does not match the operation")
        }
        var previous = first
        for record in records.dropFirst() {
            try record.validate()
            try validateIdentity(record, previous: previous)
            let expectedDigest = try previous.digest()
            guard record.sequence == previous.sequence + 1,
                  record.previousRecordDigest == expectedDigest
            else {
                throw InstallError.journal("the record sequence or digest chain is discontinuous")
            }
            guard validTransition(from: previous.phase, to: record.phase, operation: record.operation) else {
                throw InstallError
                    .journal("invalid transition from \(previous.phase.rawValue) to \(record.phase.rawValue)")
            }
            previous = record
        }
    }

    private static func validateIdentity(
        _ record: InstallJournalRecord,
        previous: InstallJournalRecord
    ) throws {
        guard record.transactionID == previous.transactionID,
              record.operation == previous.operation,
              record.generationID == previous.generationID,
              record.previousGenerationID == previous.previousGenerationID
        else {
            throw InstallError.journal("transaction identity changed within the chain")
        }
    }

    private static func validInitialPhase(_ phase: InstallPhase, operation: InstallOperation) -> Bool {
        switch operation {
        case .install, .update:
            phase == .prepared
        case .uninstall:
            phase == .uninstallPrepared
        }
    }

    private static func validTransition(
        from: InstallPhase,
        to nextPhase: InstallPhase,
        operation: InstallOperation
    ) -> Bool {
        if operation == .uninstall {
            return uninstallTransition(from: from, to: nextPhase)
        }
        let permitsCommittedPurge = operation == .update || from != .committed
        let isCommittedPurge = committedPurgeTransition(from: from, to: nextPhase)
        if operation != .uninstall, isCommittedPurge, permitsCommittedPurge {
            return true
        }
        if nextPhase == .rollingBack {
            return installMayRollBack(from)
        }
        return installTransition(from: from, to: nextPhase)
    }

    private static func installTransition(from: InstallPhase, to nextPhase: InstallPhase) -> Bool {
        switch (from, nextPhase) {
        case (.prepared, .generationPublished),
             (.generationPublished, .serviceStarted),
             (.serviceStarted, .dnsActive),
             (.dnsActive, .applicationPublished),
             (.applicationPublished, .accepted),
             (.accepted, .committed),
             (.rollingBack, .rolledBack):
            true
        default:
            false
        }
    }

    private static func installMayRollBack(_ phase: InstallPhase) -> Bool {
        switch phase {
        case .accepted, .applicationPublished, .dnsActive, .generationPublished, .prepared, .serviceStarted:
            true
        default:
            false
        }
    }

    private static func uninstallTransition(from: InstallPhase, to nextPhase: InstallPhase) -> Bool {
        switch (from, nextPhase) {
        case (.uninstallPrepared, .dnsRestored),
             (.dnsRestored, .serviceStopped),
             (.serviceStopped, .publicationsRemoved),
             (.publicationsRemoved, .generationRetired),
             (.generationRetired, .uninstallCommitted),
             (.uninstallCommitted, .generationPurgePrepared),
             (.generationPurgePrepared, .generationContentsPurged),
             (.generationContentsPurged, .generationPurged):
            true
        default:
            false
        }
    }

    private static func committedPurgeTransition(from: InstallPhase, to nextPhase: InstallPhase) -> Bool {
        switch (from, nextPhase) {
        case (.committed, .generationPurgePrepared),
             (.rolledBack, .generationPurgePrepared),
             (.generationPurgePrepared, .generationContentsPurged),
             (.generationContentsPurged, .generationPurged):
            true
        default:
            false
        }
    }
}

/// Descriptor-rooted append-only storage; every record is a separately durable file.
public struct InstallJournalStore: Sendable {
    private static let completedPrefix = ".completed-"
    private static let maximumTransactionCount = 4096

    private let authority: FileSystemAuthority
    private let journalsPath: InstallRelativePath
    private let ownerUID: UInt32
    private let groupGID: UInt32
    private let faultInjector: any InstallFaultInjecting

    public init(
        authority: FileSystemAuthority,
        journalsPath: InstallRelativePath,
        ownerUID: UInt32 = 0,
        groupGID: UInt32 = 0,
        faultInjector: any InstallFaultInjecting = NoInstallFaultInjector()
    ) {
        self.authority = authority
        self.journalsPath = journalsPath
        self.ownerUID = ownerUID
        self.groupGID = groupGID
        self.faultInjector = faultInjector
    }

    public func append(_ record: InstallJournalRecord) throws {
        try record.validate()
        let existing = try load(transactionID: record.transactionID)
        try InstallJournalChain.validate(existing + [record])
        try faultInjector.check(.beforeJournalAppend)
        try ensureTransactionDirectory(record.transactionID)
        try authority.writeFile(
            record.canonicalData(),
            at: recordPath(transactionID: record.transactionID, sequence: record.sequence),
            ownerUID: ownerUID,
            groupGID: groupGID,
            mode: 0o400
        )
    }

    public func load(transactionID: String) throws -> [InstallJournalRecord] {
        try InstallManifest.validateIdentifier(transactionID, field: "transaction ID")
        let directory = try transactionPath(transactionID)
        guard let metadata = try authority.metadata(at: directory) else {
            return []
        }
        guard metadata.kind == .directory else {
            throw InstallError.journal("the transaction journal path is not a directory")
        }
        let names = try authority.listDirectory(at: directory)
        guard names.count <= InstallJournalChain.maximumRecordCount,
              names.allSatisfy(validRecordName)
        else {
            throw InstallError.journal("the transaction journal contains unexpected entries")
        }
        let orderedNames = names.sorted()
        let payloads = try orderedNames.map { name in
            try authority.readFile(at: directory.appending(component: name), maximumByteCount: 65536)
        }
        let records = try InstallJournalChain.decode(payloads)
        guard zip(orderedNames, records).allSatisfy({ name, record in
            name == recordFileName(sequence: record.sequence)
        }) else {
            throw InstallError.journal("record filenames do not match their sequence numbers")
        }
        return records
    }

    public func transactionIDs() throws -> [String] {
        guard let metadata = try authority.metadata(at: journalsPath) else {
            return []
        }
        guard metadata.kind == .directory else {
            throw InstallError.journal("the journal root is not a directory")
        }
        let names = try authority.listDirectory(at: journalsPath)
        guard names.count <= Self.maximumTransactionCount else {
            throw InstallError.journal("the journal root exceeds its transaction bound")
        }
        var transactions: [String] = []
        for name in names {
            if name.hasPrefix(Self.completedPrefix) {
                guard Self.validCompletedName(name) else {
                    throw InstallError.journal("the journal root contains an invalid completed transaction")
                }
                continue
            }
            do {
                try InstallManifest.validateIdentifier(name, field: "transaction ID")
            } catch {
                throw InstallError.journal("the journal root contains an invalid transaction name")
            }
            let path = try journalsPath.appending(component: name)
            guard try authority.metadata(at: path)?.kind == .directory else {
                throw InstallError.journal("a transaction journal is not a directory")
            }
            transactions.append(name)
        }
        return transactions.sorted()
    }

    /// Returns durable post-commit journal directories left by an interrupted
    /// collection. Names carry the terminal record digest and are therefore
    /// suitable for exact recovery approval without exposing journal contents.
    func completedTransactionNames() throws -> [String] {
        guard let metadata = try authority.metadata(at: journalsPath) else {
            return []
        }
        guard metadata.kind == .directory else {
            throw InstallError.journal("the journal root is not a directory")
        }
        let names = try authority.listDirectory(at: journalsPath)
        guard names.count <= Self.maximumTransactionCount else {
            throw InstallError.journal("the journal root exceeds its transaction bound")
        }
        let completed = names.filter { $0.hasPrefix(Self.completedPrefix) }
        guard completed.allSatisfy(Self.validCompletedName) else {
            throw InstallError.journal("the journal root contains an invalid completed transaction")
        }
        return completed.sorted()
    }

    /// Atomically moves terminal journals out of the active namespace, then removes
    /// each canonical record individually. An interrupted removal resumes by scanning
    /// the digest-named completed namespace.
    func collectTerminalTransactions() throws -> [String] {
        var completed: [String] = []
        for transactionID in try transactionIDs() {
            let records = try load(transactionID: transactionID)
            guard let tail = records.last,
                  try InstallRecoveryStateMachine.nextAction(for: records) == .none
            else {
                continue
            }
            let name = try Self.completedPrefix + tail.digest().value
            let destination = try journalsPath.appending(component: name)
            guard try authority.metadata(at: destination) == nil else {
                throw InstallError.collision(destination.description)
            }
            try authority.renameExclusive(
                from: transactionPath(transactionID),
                to: destination
            )
            completed.append(transactionID)
        }
        try purgeCompletedTransactions()
        return completed.sorted()
    }

    /// Collects only the named terminal transaction. A lifecycle commit uses
    /// this narrow boundary so it never consumes unrelated recovery state.
    func collectTerminalTransaction(transactionID: String) throws {
        try InstallManifest.validateIdentifier(transactionID, field: "transaction ID")
        let records = try load(transactionID: transactionID)
        guard let tail = records.last else {
            throw InstallError.journal("cannot collect an unknown transaction")
        }
        guard try InstallRecoveryStateMachine.nextAction(for: records) == .none else {
            throw InstallError.journal("cannot collect a transaction that requires recovery")
        }
        let name = try Self.completedPrefix + tail.digest().value
        let destination = try journalsPath.appending(component: name)
        guard try authority.metadata(at: destination) == nil else {
            throw InstallError.collision(destination.description)
        }
        try authority.renameExclusive(
            from: transactionPath(transactionID),
            to: destination
        )
        try purgeCompletedTransaction(at: destination)
    }

    func purgeCompletedTransactions() throws {
        guard try authority.metadata(at: journalsPath) != nil else {
            return
        }
        try authority.verifyOwnedDirectory(
            at: journalsPath,
            ownerUID: ownerUID,
            groupGID: groupGID,
            permittedModes: [0o700]
        )
        for name in try authority.listDirectory(at: journalsPath) where name.hasPrefix(Self.completedPrefix) {
            guard Self.validCompletedName(name) else {
                throw InstallError.journal("the journal root contains an invalid completed transaction")
            }
            try purgeCompletedTransaction(at: journalsPath.appending(component: name))
        }
    }

    private func ensureTransactionDirectory(_ transactionID: String) throws {
        try authority.createDirectory(
            at: journalsPath,
            ownerUID: ownerUID,
            groupGID: groupGID,
            mode: 0o700
        )
        try authority.createDirectory(
            at: transactionPath(transactionID),
            ownerUID: ownerUID,
            groupGID: groupGID,
            mode: 0o700
        )
    }

    private func transactionPath(_ transactionID: String) throws -> InstallRelativePath {
        try journalsPath.appending(component: transactionID)
    }

    private func recordPath(transactionID: String, sequence: UInt64) throws -> InstallRelativePath {
        try transactionPath(transactionID).appending(component: recordFileName(sequence: sequence))
    }

    private func validRecordName(_ name: String) -> Bool {
        guard name.count == 25, name.hasSuffix(".json") else {
            return false
        }
        return name.prefix(20).unicodeScalars.allSatisfy { (48 ... 57).contains($0.value) }
    }

    private func recordFileName(sequence: UInt64) -> String {
        String(format: "%020llu.json", sequence)
    }

    private func purgeCompletedTransaction(at directory: InstallRelativePath) throws {
        try authority.verifyOwnedDirectory(
            at: directory,
            ownerUID: ownerUID,
            groupGID: groupGID,
            permittedModes: [0o700]
        )
        let names = try authority.listDirectory(at: directory)
        guard names.count <= InstallJournalChain.maximumRecordCount,
              names.allSatisfy(validRecordName)
        else {
            throw InstallError.journal("a completed transaction contains unexpected entries")
        }
        for name in names.sorted().reversed() {
            let path = try directory.appending(component: name)
            let payload = try authority.readUniqueFile(at: path, maximumByteCount: 65536)
            let record: InstallJournalRecord
            do {
                record = try InstallCanonicalJSON.decoder.decode(InstallJournalRecord.self, from: payload)
            } catch {
                throw InstallError.journal("a completed transaction record is malformed")
            }
            try record.validate()
            guard try payload == (record.canonicalData()),
                  name == recordFileName(sequence: record.sequence)
            else {
                throw InstallError.journal("a completed transaction record is not canonical")
            }
            let entry = try InstallEntry(
                path: InstallRelativePath(name),
                kind: .regularFile,
                role: .support,
                sha256: InstallDigest.hash(payload),
                byteCount: UInt64(payload.count),
                ownerUID: ownerUID,
                groupGID: groupGID,
                mode: 0o400
            )
            try authority.unlinkRegularFile(at: path, expected: entry)
        }
        try authority.removeEmptyDirectory(at: directory)
    }

    private static func validCompletedName(_ name: String) -> Bool {
        let identity = name.dropFirst(completedPrefix.count)
        return identity.count == 64 && identity.allSatisfy { $0.isHexDigit && !$0.isUppercase }
    }
}
