// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
import Network

/// Narrow transport seam used by resolver reconciliation and deterministic tests.
public protocol ResolverSystemExchanging: Sendable {
    func exchange(_ command: ResolverSystemCommand) throws -> ResolverSystemResult
}

extension ResolverSystemChannel: ResolverSystemExchanging {}

/// Follows a different single service that now carries DNS, publishing
/// through `publish` before any service points at loopback, and returns the
/// published plan; nil means the recorded service is the one to reconcile.
typealias ResolverHandOff = @Sendable (
    _ record: ActivationRecord,
    _ publish: (DNSPlan) throws -> Void
) throws -> DNSPlan?

/// Serializes complete resolver generations into the per-user daemon.
public actor ResolverReconciler {
    private let channel: any ResolverSystemExchanging
    private let loadRecord: @Sendable () throws -> ActivationRecord?
    private let makePlan: @Sendable (ActivationRecord) throws -> DNSPlan
    private let restoreSystemDNS: @Sendable () throws -> Void
    private let commitPreparedDNS: @Sendable (ActivationRecord) throws -> Void
    private let recordedOrphan: @Sendable () -> UUID?
    /// ADR-0024 handoff, present only in the root supervisor.
    private let handOff: ResolverHandOff?
    private var activationID: UUID?
    private var activeGeneration: UInt64?
    private var highestGeneration: UInt64 = 0
    private var lastUpstreams: [String]?
    /// Activation a safe bypass meant to release from the daemon but could
    /// not. Only this exact identity may be released on a later mismatch.
    private var orphanedActivationID: UUID?

    public init(
        resolver: SystemResolver = SystemResolver(),
        activationStore: ActivationStore = .standard,
        channel: any ResolverSystemExchanging,
        reactivatePreparedDNS: Bool = false
    ) {
        self.channel = channel
        let bypassStore = ResolverBypassStore(directory: activationStore.directory)
        // A supervisor restart or a separate `remap-system activate` has no
        // memory of an earlier failed release, so the durable bypass record
        // carries that one identity across processes.
        recordedOrphan = { (try? bypassStore.read())?.payload.outstandingOrphan }
        // Only the root supervisor changes SystemConfiguration after activation.
        if reactivatePreparedDNS {
            handOff = { (record: ActivationRecord, publish: (DNSPlan) throws -> Void) throws -> DNSPlan? in
                try resolver.handOffIfNeeded(record: record, store: activationStore, publish: publish)
            }
        } else {
            handOff = nil
        }
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
        commitPreparedDNS: @escaping @Sendable (ActivationRecord) throws -> Void = { _ in },
        recordedOrphan: @escaping @Sendable () -> UUID? = { nil },
        handOff: ResolverHandOff? = nil
    ) {
        self.channel = channel
        self.handOff = handOff
        self.loadRecord = loadRecord
        self.makePlan = makePlan
        self.restoreSystemDNS = restoreSystemDNS
        self.commitPreparedDNS = commitPreparedDNS
        self.recordedOrphan = recordedOrphan
    }

    /// Reconciles daemon generation state after startup or a native network change.
    public func reconcile() throws {
        var health = try channel.exchange(.health)
        observeGenerations(health)
        guard let record = try loadRecord() else {
            try invalidateIfNeeded(health: health)
            return
        }
        let identifier = try record.activationIdentifier()
        var orphan: (activationID: UUID, generation: UInt64)?
        if let bound = health.activationID, bound != identifier {
            orphan = try releasableOrphan(bound: bound, health: health)
        }
        if let handOff {
            let handedOff = try handOff(record) { plan in
                if let orphan {
                    health = try release(orphan.activationID, generation: orphan.generation)
                }
                try publish(plan, identifier: identifier, after: health.activeGeneration)
            }
            if handedOff != nil {
                return
            }
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
        if let orphan {
            // Released only once a complete replacement plan exists.
            health = try release(orphan.activationID, generation: orphan.generation)
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
        try publish(plan, identifier: identifier, after: health.activeGeneration)
        try commitPreparedDNS(record)
    }

    /// Asks the daemon for its health and changes nothing: no publication,
    /// no invalidation, and no SystemConfiguration change. While bypassed, the
    /// supervisor uses it to measure continuous daemon health before it
    /// re-arms (ADR-0030); only the generations the daemon reports are kept.
    public func probe() throws {
        try observeGenerations(channel.exchange(.health))
    }

    /// Publishes one complete generation above every generation seen and
    /// verifies the daemon bound it to this activation.
    private func publish(_ plan: DNSPlan, identifier: UUID, after daemonGeneration: UInt64?) throws {
        let generation = try nextGeneration(after: daemonGeneration)
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
        orphanedActivationID = nil
    }

    /// Restores ordinary system DNS after a sustained reconciliation failure.
    ///
    /// Public connectivity is restored before the daemon plan is invalidated.
    /// A channel failure after restoration therefore cannot put the Mac back on
    /// the local listener.
    ///
    /// Only a failure to restore ordinary DNS throws. A failure to release the
    /// daemon's plan afterwards is returned, and the activation it may still
    /// hold is remembered so a later reconciliation can release exactly that
    /// identity instead of reporting an activation mismatch forever.
    public func enterSafeBypass() throws -> ResolverBypassRelease {
        try restoreSystemDNS()
        var observed: ResolverSystemResult?
        do {
            let health = try channel.exchange(.health)
            observed = health
            observeGenerations(health)
            try invalidateIfNeeded(health: health)
            orphanedActivationID = nil
            return .released
        } catch {
            let orphan = ownOrphan(observed: observed)
            orphanedActivationID = orphan
            return .pending(activationID: orphan)
        }
    }

    /// Only an activation this host bound can become its orphan. The daemon's
    /// report corroborates one of those identities and never supplies its own:
    /// a binding made by another controller is never adopted, so it can never
    /// be released by a later reconciliation.
    private func ownOrphan(observed: ResolverSystemResult?) -> UUID? {
        let own = [activationID, orphanedActivationID, recordedOrphan()].compactMap(\.self)
        guard let observed else {
            return own.first
        }
        guard let bound = observed.activationID, own.contains(bound) else {
            return nil
        }
        return bound
    }

    /// Accepts a foreign daemon binding only when it is the one this host's own
    /// failed bypass left behind. Any other bound activation is still a
    /// mismatch: that check is what keeps two controllers from fighting over
    /// one daemon.
    private func releasableOrphan(
        bound: UUID,
        health: ResolverSystemResult
    ) throws -> (activationID: UUID, generation: UInt64) {
        guard bound == (orphanedActivationID ?? recordedOrphan()),
              let generation = health.activeGeneration
        else {
            throw ResolverReconciliationError.activationMismatch
        }
        return (bound, generation)
    }

    private func release(_ orphan: UUID, generation: UInt64) throws -> ResolverSystemResult {
        let released = try channel.exchange(
            .invalidate(activationID: orphan, generation: generation)
        )
        guard released.activationID == nil, released.activeGeneration == nil else {
            throw ResolverReconciliationError.invalidInvalidation
        }
        observeGenerations(released)
        highestGeneration = max(highestGeneration, generation)
        orphanedActivationID = nil
        activationID = nil
        activeGeneration = nil
        lastUpstreams = nil
        return released
    }

    private func observeGenerations(_ result: ResolverSystemResult) {
        highestGeneration = max(
            highestGeneration,
            result.activeGeneration ?? 0,
            result.highestAcceptedGeneration ?? 0
        )
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
        observeGenerations(result)
        activeGeneration = nil
        activationID = nil
        lastUpstreams = nil
        orphanedActivationID = nil
    }

    /// The daemon refuses any generation at or below the highest it has
    /// accepted, including after invalidation clears its active plan, so the
    /// next generation exceeds the active generation, the daemon's reported
    /// high-water (ADR-0025), and every generation this reconciler has seen.
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

/// Whether a safe bypass also released the daemon's resolver plan.
public enum ResolverBypassRelease: Equatable, Sendable {
    case released
    /// The daemon may still be bound to this activation, when it is known.
    case pending(activationID: UUID?)
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
