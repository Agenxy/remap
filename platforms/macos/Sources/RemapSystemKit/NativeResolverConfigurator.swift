import Foundation

/// What the current network asks of an activation (ADR-0024).
enum ResolverNetworkDecision: Equatable, Sendable {
    /// The recorded service alone carries DNS; reconcile as before.
    case recorded
    /// Exactly one other service carries DNS; hand the activation over to it.
    case handoff(serviceID: String, upstreams: [String])
}

/// Follows the single service that carries DNS and restores every service
/// Remap changed, using only compare-and-set SystemConfiguration effects.
struct NativeResolverConfigurator: Sendable {
    let network: any NativeNetworkConfiguring
    let store: any ActivationRecordStoring
    var verificationTimeout: TimeInterval = 3
    var verificationInterval: TimeInterval = 0.05

    /// Counts the services with a usable resolver. None is an unobserved
    /// network, more than one is refused as split DNS, and one is either the
    /// recorded service or the target of a handoff.
    func decide(record: ActivationRecord) throws -> ResolverNetworkDecision {
        try record.verify()
        let snapshot = try network.snapshot()
        let usable = try usableServices(snapshot: snapshot, record: record)
        guard let only = usable.first else {
            throw ResolverError.noUsableUpstream
        }
        guard usable.count == 1 else {
            throw ResolverError.unsupportedResolverScope(usable.count)
        }
        let recordedIDs = record.payload.services.map(\.serviceID)
        if recordedIDs == [only.serviceID], record.payload.handoffTargetServiceID == nil {
            return .recorded
        }
        return .handoff(serviceID: only.serviceID, upstreams: only.upstreams)
    }

    /// Moves the activation to `target`, which must be the single usable
    /// service. Each step is durable before the next begins, and every step
    /// can be repeated, so an interruption anywhere is completed by the next
    /// reconciliation:
    ///
    /// 1. every owned service is checked for a user change, before anything;
    /// 2. the target's prior configuration is captured into the record, which
    ///    now lists the service being left and the target;
    /// 3. the daemon accepts the target's complete plan (`publish`);
    /// 4. in one commit the service being left returns to its captured prior
    ///    state and the target is pointed at loopback;
    /// 5. the effective configuration is verified; and
    /// 6. the record converges to the target alone.
    func handOff(
        record: ActivationRecord,
        to target: String,
        upstreams: [String],
        publish: (DNSPlan) throws -> Void
    ) throws -> ActivationRecord {
        try record.verify()
        let identity = try record.activationIdentifier()
        let snapshot = try network.snapshot()
        guard let observedTarget = snapshot.service(target) else {
            throw ResolverError.noUsableUpstream
        }
        let services = try handoffServices(
            record: record,
            target: observedTarget,
            upstreams: upstreams,
            snapshot: snapshot
        )
        let plan = try validatedPlan([DNSServicePlan(serviceID: target, upstreams: upstreams)])
        let handoff = try ActivationRecord(payload: record.payload.replacing(
            services: services,
            phase: .active,
            activationID: identity,
            handoffTargetServiceID: target
        ))
        if handoff != record {
            try store.replace(handoff)
        }
        try publish(plan)
        try network.preflightLoopback(ownerUID: record.payload.ownerUID)
        try network.commit(handoffChanges(services: services, target: target, snapshot: snapshot))
        try awaitConfiguration { current in
            try handoffApplied(services: services, target: target, snapshot: current)
        }
        guard let targetRecord = services.first(where: { $0.serviceID == target }) else {
            throw ResolverError.invalidActivationRecord
        }
        let converged = try ActivationRecord(payload: record.payload.replacing(
            services: [targetRecord],
            phase: .active,
            activationID: identity,
            handoffTargetServiceID: nil
        ))
        try store.replace(converged)
        return converged
    }

    /// The recorded service's plan from one snapshot, as `reconciliationPlan`
    /// derives it from live SystemConfiguration reads.
    func recordedPlan(record: ActivationRecord) throws -> DNSPlan {
        try record.verify()
        let snapshot = try network.snapshot()
        let usable = try usableServices(snapshot: snapshot, record: record)
        let services = try record.payload.services.map { service in
            guard let upstreams = usable.first(where: { $0.serviceID == service.serviceID })?.upstreams
            else {
                throw ResolverError.noUsableUpstream
            }
            return DNSServicePlan(serviceID: service.serviceID, upstreams: upstreams)
        }
        return try validatedPlan(services)
    }

    /// Hands the activation over when a different single service now carries
    /// DNS, and returns the plan it published; nil otherwise. The record is
    /// the one the caller reconciled, so its identity is the one published.
    func handOffIfNeeded(
        record: ActivationRecord,
        publish: (DNSPlan) throws -> Void
    ) throws -> DNSPlan? {
        guard case let .handoff(target, upstreams) = try decide(record: record) else {
            return nil
        }
        _ = try handOff(record: record, to: target, upstreams: upstreams, publish: publish)
        return DNSPlan(services: [DNSServicePlan(serviceID: target, upstreams: upstreams)])
    }

    /// Restores every owned service that still holds Remap's configuration,
    /// refusing all restoration when any owned service was changed by the
    /// user, then retains the activation as prepared or removes it.
    func restoreOrdinaryDNS(retainPreparedRecord: Bool) throws {
        let record = try store.read()
        if record.payload.phase == .prepared {
            if !retainPreparedRecord {
                try store.remove()
            }
            return
        }
        let services = record.payload.services
        let snapshot = try network.snapshot()
        let conflicts = try conflictingServices(services, snapshot: snapshot)
        guard conflicts.isEmpty else {
            throw ResolverError.configurationConflict(conflicts.sorted())
        }
        let changes = try services.compactMap { service -> ServiceConfigurationChange? in
            guard let current = snapshot.service(service.serviceID),
                  try holdsInstalledConfiguration(current, record: service)
            else {
                return nil
            }
            return restoration(service, from: current)
        }
        try network.commit(changes)
        try awaitConfiguration { current in
            try restorationApplied(services: services, snapshot: current)
        }
        if retainPreparedRecord {
            try store.replace(ActivationRecord(payload: record.payload.withPhase(.prepared)))
        } else {
            try store.remove()
        }
    }

    private func usableServices(
        snapshot: NetworkSnapshot,
        record: ActivationRecord
    ) throws -> [(serviceID: String, upstreams: [String])] {
        let recorded = Dictionary(uniqueKeysWithValues: record.payload.services.map {
            ($0.serviceID, $0)
        })
        return snapshot.services.compactMap { service in
            let upstreams = if let owned = recorded[service.serviceID] {
                resolverUpstreams(
                    effectiveServers: service.effectiveServers,
                    dhcpServers: service.dhcpServers,
                    capturedUpstreams: owned.upstreams,
                    capturedNetworkSignature: owned.networkSignature,
                    currentNetworkSignature: service.networkSignature
                )
            } else {
                stableUnique((service.effectiveServers ?? []).filter(isUsableUpstream))
            }
            return upstreams.isEmpty ? nil : (service.serviceID, upstreams)
        }
    }

    /// The owned services for a handoff record, with the target captured
    /// fresh unless it already holds Remap's configuration, whose captured
    /// prior state is then the one to keep.
    private func handoffServices(
        record: ActivationRecord,
        target: ObservedNetworkService,
        upstreams: [String],
        snapshot: NetworkSnapshot
    ) throws -> [DNSServiceRecord] {
        var services = record.payload.services
        let leaving = services.filter { $0.serviceID != target.serviceID }
        // A service Remap may have changed but cannot now see could still
        // point at loopback, so it is never dropped from the record unseen.
        let unseen = leaving.map(\.serviceID).filter { snapshot.service($0) == nil }
        let conflicts = try conflictingServices(leaving, snapshot: snapshot) + unseen
        guard conflicts.isEmpty else {
            throw ResolverError.configurationConflict(conflicts.sorted())
        }
        if let index = services.firstIndex(where: { $0.serviceID == target.serviceID }) {
            if try !holdsInstalledConfiguration(target, record: services[index]) {
                services[index] = try capturedService(target, upstreams: upstreams)
            }
        } else {
            guard services.count < maximumOwnedServices else {
                throw ResolverError.invalidActivationRecord
            }
            try services.append(capturedService(target, upstreams: upstreams))
        }
        return services
    }

    private func handoffChanges(
        services: [DNSServiceRecord],
        target: String,
        snapshot: NetworkSnapshot
    ) throws -> [ServiceConfigurationChange] {
        try services.compactMap { service in
            guard let current = snapshot.service(service.serviceID) else {
                return nil
            }
            let installed = try holdsInstalledConfiguration(current, record: service)
            if service.serviceID == target {
                return installed ? nil : ServiceConfigurationChange(
                    serviceID: service.serviceID,
                    expectedConfiguration: current.configuration,
                    expectedEnabled: current.enabled,
                    configuration: service.installedConfiguration,
                    enabled: true
                )
            }
            return installed ? restoration(service, from: current) : nil
        }
    }

    private func handoffApplied(
        services: [DNSServiceRecord],
        target: String,
        snapshot: NetworkSnapshot
    ) throws -> Bool {
        guard snapshot.globalServers == [loopbackResolver] else { return false }
        return try services.allSatisfy { service in
            guard let current = snapshot.service(service.serviceID) else {
                return service.serviceID != target
            }
            return service.serviceID == target
                ? try holdsInstalledConfiguration(current, record: service)
                : try !holdsInstalledConfiguration(current, record: service)
        }
    }

    private func restorationApplied(
        services: [DNSServiceRecord],
        snapshot: NetworkSnapshot
    ) throws -> Bool {
        let restored = try services.allSatisfy { service in
            guard let current = snapshot.service(service.serviceID) else { return false }
            return try holdsPriorConfiguration(current, record: service)
        }
        guard restored else { return false }
        // Only a service that is up can be expected in the global resolver.
        let liveRecords = services.filter {
            snapshot.service($0.serviceID)?.effectiveServers != nil
        }
        return try restoredEffectiveServersMatch(liveRecords, effective: snapshot.globalServers)
    }

    private func conflictingServices(
        _ services: [DNSServiceRecord],
        snapshot: NetworkSnapshot
    ) throws -> [String] {
        try services.compactMap { service in
            guard let current = snapshot.service(service.serviceID) else { return nil }
            let installed = try holdsInstalledConfiguration(current, record: service)
            let prior = try holdsPriorConfiguration(current, record: service)
            return installed || prior ? nil : service.serviceID
        }
    }

    private func restoration(
        _ service: DNSServiceRecord,
        from current: ObservedNetworkService
    ) -> ServiceConfigurationChange {
        ServiceConfigurationChange(
            serviceID: service.serviceID,
            expectedConfiguration: current.configuration,
            expectedEnabled: current.enabled,
            configuration: service.priorConfiguration,
            enabled: service.priorEnabled ?? true
        )
    }

    private func awaitConfiguration(_ applied: (NetworkSnapshot) throws -> Bool) throws {
        let deadline = Date().addingTimeInterval(verificationTimeout)
        while true {
            if try applied(network.snapshot()) {
                return
            }
            guard Date() < deadline else {
                throw ResolverError.preferences("verify the effective DNS configuration")
            }
            Thread.sleep(forTimeInterval: verificationInterval)
        }
    }
}

/// Captures a service's exact current DNS state before Remap changes it.
/// A configuration that already points at loopback is not a prior state
/// Remap may restore, so it is refused rather than recorded.
func capturedService(
    _ service: ObservedNetworkService,
    upstreams: [String]
) throws -> DNSServiceRecord {
    let prior = try service.configuration.map(PropertyLists.decode)
    if serverAddresses(from: prior ?? [:]).contains(where: { !isUsableUpstream($0) }) {
        throw ResolverError.configurationConflict([service.serviceID])
    }
    return try DNSServiceRecord(
        serviceID: service.serviceID,
        priorConfiguration: service.configuration,
        priorEnabled: service.enabled,
        installedConfiguration: PropertyLists.encode(installedConfiguration(from: prior)),
        upstreams: upstreams,
        networkSignature: service.networkSignature
    )
}

let loopbackResolver = "127.0.0.1"
