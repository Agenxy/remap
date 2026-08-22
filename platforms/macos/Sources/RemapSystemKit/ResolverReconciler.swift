import Foundation
import Network

/// Narrow transport seam used by resolver reconciliation and deterministic tests.
public protocol ResolverSystemExchanging: Sendable {
    func exchange(_ command: ResolverSystemCommand) throws -> ResolverSystemResult
}

extension ResolverSystemChannel: ResolverSystemExchanging {}

/// Serializes complete resolver generations into the per-user daemon.
public actor ResolverReconciler {
    private let channel: any ResolverSystemExchanging
    private let loadRecord: @Sendable () throws -> ActivationRecord?
    private let makePlan: @Sendable (ActivationRecord) throws -> DNSPlan
    private let restoreSystemDNS: @Sendable () throws -> Void
    private let commitPreparedDNS: @Sendable (ActivationRecord) throws -> Void
    private var activationID: UUID?
    private var activeGeneration: UInt64?
    private var highestGeneration: UInt64 = 0
    private var lastUpstreams: [String]?

    public init(
        resolver: SystemResolver = SystemResolver(),
        activationStore: ActivationStore = .standard,
        channel: any ResolverSystemExchanging,
        reactivatePreparedDNS: Bool = false
    ) {
        self.channel = channel
        loadRecord = { try resolver.activeRecord(store: activationStore) }
        makePlan = { try resolver.reconciliationPlan(record: $0) }
        restoreSystemDNS = {
            if activationStore.exists() {
                try resolver.suspend(store: activationStore)
            }
        }
        commitPreparedDNS = { record in
            guard reactivatePreparedDNS else { return }
            switch record.payload.phase {
            case .prepared:
                _ = try resolver.commitPreparedActivation(store: activationStore)
            case .active:
                let observation = try resolver.observe()
                guard systemDNSNeedsReactivation(
                    record: record,
                    remapServiceIDs: observation.remapServiceIDs
                ) else { return }

                // The daemon may become unavailable while launchd exchanges a
                // generation. Safe bypass deliberately restores ordinary DNS
                // first and retains the activation as prepared. A concurrent
                // installer can commit the record again before this supervisor
                // observes that transition, leaving an active record while the
                // effective resolver still bypasses Remap. Move that exact
                // owned record back through the prepared phase and reapply it;
                // an external configuration change fails closed in suspend().
                try resolver.suspend(store: activationStore)
                _ = try resolver.commitPreparedActivation(store: activationStore)
            }
        }
    }

    init(
        channel: any ResolverSystemExchanging,
        loadRecord: @escaping @Sendable () throws -> ActivationRecord?,
        makePlan: @escaping @Sendable (ActivationRecord) throws -> DNSPlan,
        restoreSystemDNS: @escaping @Sendable () throws -> Void = {},
        commitPreparedDNS: @escaping @Sendable (ActivationRecord) throws -> Void = { _ in }
    ) {
        self.channel = channel
        self.loadRecord = loadRecord
        self.makePlan = makePlan
        self.restoreSystemDNS = restoreSystemDNS
        self.commitPreparedDNS = commitPreparedDNS
    }

    /// Reconciles daemon generation state after startup or a native network change.
    public func reconcile() throws {
        let health = try channel.exchange(.health)
        if let generation = health.activeGeneration {
            highestGeneration = max(highestGeneration, generation)
        }
        guard let record = try loadRecord() else {
            try invalidateIfNeeded(health: health)
            return
        }
        let identifier = try record.activationIdentifier()
        if let bound = health.activationID, bound != identifier {
            throw ResolverReconciliationError.activationMismatch
        }
        let plan: DNSPlan
        do {
            plan = try makePlan(record)
        } catch {
            // A network handoff may briefly expose no usable upstream. Keep the
            // last complete generation active so a transient observation cannot
            // turn ordinary DNS into an immediate SERVFAIL outage.
            throw error
        }
        let unchangedPublishedPlan = health.activationID == identifier
            && health.activeGeneration == activeGeneration
            && lastUpstreams == plan.upstreams
        if unchangedPublishedPlan {
            activationID = identifier
            activeGeneration = health.activeGeneration
            try commitPreparedDNS(record)
            return
        }
        let generation = try nextGeneration(after: health.activeGeneration)
        let result = try channel.exchange(
            .publish(
                activationID: identifier,
                generation: generation,
                upstreams: resolverEndpoints(plan.upstreams)
            )
        )
        guard result.activationID == identifier, result.activeGeneration == generation else {
            throw ResolverReconciliationError.invalidPublication
        }
        activationID = identifier
        activeGeneration = generation
        highestGeneration = max(highestGeneration, generation)
        lastUpstreams = plan.upstreams
        try commitPreparedDNS(record)
    }

    /// Restores ordinary system DNS after a sustained reconciliation failure.
    ///
    /// Public connectivity is restored before the daemon plan is invalidated.
    /// A channel failure after restoration therefore cannot put the Mac back on
    /// the local listener.
    public func enterSafeBypass() throws {
        try restoreSystemDNS()
        guard let health = try? channel.exchange(.health) else { return }
        try? invalidateIfNeeded(health: health)
    }

    private func invalidateIfNeeded(
        health: ResolverSystemResult,
        activationID preferredID: UUID? = nil
    ) throws {
        guard let generation = health.activeGeneration ?? activeGeneration,
              let identifier = health.activationID ?? preferredID ?? activationID
        else {
            lastUpstreams = nil
            return
        }
        let result = try channel.exchange(
            .invalidate(activationID: identifier, generation: generation)
        )
        guard result.activeGeneration == nil else {
            throw ResolverReconciliationError.invalidInvalidation
        }
        activeGeneration = nil
        activationID = nil
        lastUpstreams = nil
    }

    private func nextGeneration(after daemonGeneration: UInt64?) throws -> UInt64 {
        let greatest = max(daemonGeneration ?? 0, highestGeneration)
        guard greatest < UInt64.max else {
            throw ResolverReconciliationError.generationExhausted
        }
        return greatest + 1
    }
}

func systemDNSNeedsReactivation(
    record: ActivationRecord,
    remapServiceIDs: [String]
) -> Bool {
    let expected = record.payload.services.map(\.serviceID).sorted()
    return remapServiceIDs.sorted() != expected
}

/// Fail-closed resolver publication failures with no upstream-address context.
public enum ResolverReconciliationError: Error, CustomStringConvertible, Equatable {
    case activationMismatch
    case generationExhausted
    case invalidInvalidation
    case invalidPublication
    case invalidUpstream

    public var description: String {
        switch self {
        case .activationMismatch: "The daemon is bound to another native DNS activation."
        case .generationExhausted: "The resolver generation counter is exhausted."
        case .invalidInvalidation: "The daemon did not invalidate the requested resolver generation."
        case .invalidPublication: "The daemon did not acknowledge the complete resolver generation."
        case .invalidUpstream: "The native resolver plan contains an unsupported address."
        }
    }
}

private func resolverEndpoints(_ upstreams: [String]) throws -> [String] {
    try upstreams.map { value in
        guard isUsableUpstream(value) else {
            throw ResolverReconciliationError.invalidUpstream
        }
        if IPv6Address(value) != nil {
            return "[\(value)]:53"
        }
        guard IPv4Address(value) != nil else {
            throw ResolverReconciliationError.invalidUpstream
        }
        return "\(value):53"
    }
}
