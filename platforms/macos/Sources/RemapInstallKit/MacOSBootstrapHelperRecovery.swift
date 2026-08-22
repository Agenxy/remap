import Foundation

public enum MacOSBootstrapHelperActivity: String, Codable, Equatable, Sendable {
    case active
    case current
    case inactive
}

public enum MacOSBootstrapCodeValidity: String, Codable, Equatable, Sendable {
    case invalid
    case verified
}

public struct MacOSBootstrapHelperCandidate: Codable, Equatable, Sendable {
    public let path: InstallAbsolutePath
    public let codeValidity: MacOSBootstrapCodeValidity
    public let codeIdentifier: String?
    public let cdHash: String?
    public let sha256: String
    let fileIdentity: MacOSBootstrapFileIdentity
    public let ownerUID: UInt32
    public let groupGID: UInt32
    public let mode: UInt16
    public let byteCount: UInt64
    public let linkCount: UInt64
    public let flags: UInt32
    public let extendedAttributeNames: [String]
    public let activity: MacOSBootstrapHelperActivity
}

public struct MacOSBootstrapStagedFileCandidate: Codable, Equatable, Sendable {
    public let path: InstallAbsolutePath
    let fileIdentity: MacOSBootstrapFileIdentity
    public let ownerUID: UInt32
    public let groupGID: UInt32
    public let mode: UInt16
    public let byteCount: UInt64
    public let linkCount: UInt64
    public let flags: UInt32
    public let extendedAttributeNames: [String]
    public let sha256: String
}

public struct MacOSBootstrapStageCandidate: Codable, Equatable, Sendable {
    public let path: InstallAbsolutePath
    let fileIdentity: MacOSBootstrapFileIdentity
    public let ownerUID: UInt32
    public let groupGID: UInt32
    public let mode: UInt16
    public let linkCount: UInt64
    public let flags: UInt32
    public let extendedAttributeNames: [String]
    public let stagedFile: MacOSBootstrapStagedFileCandidate?
}

protocol MacOSBootstrapStageStoring: Sendable {
    func candidates() throws -> [MacOSBootstrapStageCandidate]
    func remove(_ candidate: MacOSBootstrapStageCandidate) throws
}

struct EmptyMacOSBootstrapStageStore: MacOSBootstrapStageStoring {
    func candidates() -> [MacOSBootstrapStageCandidate] {
        []
    }

    func remove(_: MacOSBootstrapStageCandidate) {}
}

public struct MacOSBootstrapHelperRecoveryPreview: Codable, Equatable, Sendable {
    public let schemaVersion: UInt32
    public let candidates: [MacOSBootstrapHelperCandidate]
    public let stagingCandidates: [MacOSBootstrapStageCandidate]
    public let effects: [String]
    public let approvalToken: InstallApprovalToken

    init(
        candidates: [MacOSBootstrapHelperCandidate],
        stagingCandidates: [MacOSBootstrapStageCandidate]
    ) throws {
        let ordered = candidates.sorted { $0.path.value < $1.path.value }
        let orderedStages = stagingCandidates.sorted { $0.path.value < $1.path.value }
        guard ordered.count + orderedStages.count <= MacOSBootstrapHelperStore.maximumCandidates,
              Set(ordered.map(\.path)).count == ordered.count,
              Set(orderedStages.map(\.path)).count == orderedStages.count
        else {
            throw InstallError.integrity("bootstrap recovery preview exceeds its deterministic bound")
        }
        schemaVersion = 3
        self.candidates = ordered
        self.stagingCandidates = orderedStages
        let helperEffects = ordered.compactMap { candidate in
            candidate.activity == .inactive
                ? "remove inactive orphan bootstrap helper \(candidate.path.value)"
                : nil
        }
        effects = helperEffects + orderedStages.map {
            "remove private orphan bootstrap stage \($0.path.value)"
        }
        let payload = MacOSBootstrapHelperRecoveryApprovalPayload(
            schemaVersion: schemaVersion,
            candidates: ordered,
            stagingCandidates: orderedStages,
            effects: effects
        )
        approvalToken = try InstallApprovalToken.bind(to: InstallCanonicalJSON.encoder.encode(payload))
    }
}

public struct MacOSBootstrapHelperRecoveryResult: Codable, Equatable, Sendable {
    public let schemaVersion: UInt32
    public let removedPaths: [InstallAbsolutePath]

    init(removedPaths: [InstallAbsolutePath]) {
        schemaVersion = 1
        self.removedPaths = removedPaths.sorted { $0.value < $1.value }
    }
}

public struct MacOSBootstrapHelperRecovery: Sendable {
    private let lockConfiguration: InstallLockConfiguration
    private let store: any MacOSBootstrapHelperStoring
    private let stagingStore: any MacOSBootstrapStageStoring

    public static func production() throws -> MacOSBootstrapHelperRecovery {
        let layout = try MacOSInstallLayout.production()
        let store = try MacOSBootstrapHelperStore(
            authority: layout.authority,
            ownerUID: 0,
            groupGID: 0,
            identityChecker: NativeMacOSBootstrapCodeIdentityChecker(),
            currentExecutableIdentity: MacOSBootstrapHelperActivityLease.currentIdentity()
        )
        let stagingStore = MacOSBootstrapStageStore(
            authority: layout.authority,
            ownerUID: 0,
            groupGID: 0
        )
        return MacOSBootstrapHelperRecovery(
            lockConfiguration: layout.lockConfiguration,
            store: store,
            stagingStore: stagingStore
        )
    }

    init(
        lockConfiguration: InstallLockConfiguration,
        store: any MacOSBootstrapHelperStoring,
        stagingStore: any MacOSBootstrapStageStoring = EmptyMacOSBootstrapStageStore()
    ) {
        self.lockConfiguration = lockConfiguration
        self.store = store
        self.stagingStore = stagingStore
    }

    public func preview() throws -> MacOSBootstrapHelperRecoveryPreview {
        let lock = try lockConfiguration.acquire()
        defer { _ = lock }
        return try previewLocked()
    }

    public func recover(
        approvalToken: InstallApprovalToken
    ) throws -> MacOSBootstrapHelperRecoveryResult {
        let approved = try preview()
        try requireApproval(approvalToken, matches: approved)
        let lock = try lockConfiguration.acquire()
        defer { _ = lock }
        let locked = try previewLocked()
        try requireApproval(approvalToken, matches: locked)
        var removed: [InstallAbsolutePath] = []
        for candidate in locked.candidates where candidate.activity == .inactive {
            try store.remove(candidate)
            removed.append(candidate.path)
        }
        for candidate in locked.stagingCandidates {
            try stagingStore.remove(candidate)
            removed.append(candidate.path)
        }
        return MacOSBootstrapHelperRecoveryResult(removedPaths: removed)
    }

    private func previewLocked() throws -> MacOSBootstrapHelperRecoveryPreview {
        try MacOSBootstrapHelperRecoveryPreview(
            candidates: store.candidates(),
            stagingCandidates: stagingStore.candidates()
        )
    }

    private func requireApproval(
        _ supplied: InstallApprovalToken,
        matches preview: MacOSBootstrapHelperRecoveryPreview
    ) throws {
        guard supplied == preview.approvalToken else {
            throw InstallError.approval("the approved bootstrap recovery preview is stale or does not match")
        }
    }
}

private struct MacOSBootstrapHelperRecoveryApprovalPayload: Encodable {
    let schemaVersion: UInt32
    let candidates: [MacOSBootstrapHelperCandidate]
    let stagingCandidates: [MacOSBootstrapStageCandidate]
    let effects: [String]
}
