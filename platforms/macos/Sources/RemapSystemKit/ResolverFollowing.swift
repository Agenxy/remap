// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation

/// Which resolver macOS actually uses for names no supplemental resolver
/// claims, as one snapshot shows it (ADR-0036).
enum ResolverCarrier: Equatable, Sendable {
    /// The global resolver is Remap's loopback listener.
    case remap
    /// The global resolver is exactly this service's effective resolver.
    case service(String)
    /// macOS ranks primary a service that exists only in the dynamic store,
    /// as a VPN's tunnel commonly does. Remap cannot configure it.
    case outsidePreferences
    /// No single service accounts for the global resolver.
    case unattributed
}

/// The resolver macOS uses: loopback is Remap; otherwise the one service
/// whose effective servers are exactly the global servers, with macOS's own
/// primary ranking breaking a tie between services on the same resolver.
func resolverCarrier(_ snapshot: NetworkSnapshot) -> ResolverCarrier {
    if snapshot.globalServers == [loopbackResolver] {
        return .remap
    }
    let global = Set(snapshot.globalServers.filter(isUsableUpstream))
    guard !global.isEmpty else {
        return .unattributed
    }
    if let primary = snapshot.primaryServiceID, snapshot.service(primary) == nil {
        return .outsidePreferences
    }
    let matches = snapshot.services.filter { service in
        guard let effective = service.effectiveServers else { return false }
        return Set(effective.filter(isUsableUpstream)) == global
    }.map(\.serviceID)
    if matches.count == 1 {
        return .service(matches[0])
    }
    if let primary = snapshot.primaryServiceID, matches.contains(primary) {
        return .service(primary)
    }
    return .unattributed
}

/// What reconciliation should do about the resolver macOS uses.
enum ResolverFollowing: Equatable, Sendable {
    /// The recorded service carries DNS; reconcile it as before.
    case recorded
    /// The activation moved to the service that now carries DNS, whose plan
    /// was published before it pointed at loopback.
    case handedOff(DNSPlan)
    /// Another agent holds the resolver macOS uses. Remap writes nothing,
    /// publishes the servers macOS uses when there are any, and waits.
    case deferred(ResolverDeferral, adopted: DNSPlan?)
}

/// Remap stays out of the way of another agent's DNS and says why. Ordinary
/// DNS through that agent's resolver is already what macOS uses, so failing
/// open needs no write at all, and none is made (ADR-0036).
public enum ResolverDeferral: Error, CustomStringConvertible, Equatable, Sendable {
    /// Another agent replaced the DNS configuration of a service Remap
    /// owns. Remap answers again when that agent puts Remap's back.
    case dnsChangedElsewhere(serviceID: String)
    /// Remap's configuration is in place, but macOS resolves through another
    /// agent's DNS that takes precedence over it, such as a VPN's.
    case resolverHeldElsewhere

    /// The stable code the supervisor reports and logs.
    public var code: String {
        switch self {
        case .dnsChangedElsewhere: "E_RESOLVER_DNS_CHANGED_ELSEWHERE"
        case .resolverHeldElsewhere: "E_RESOLVER_HELD_ELSEWHERE"
        }
    }

    public var description: String {
        switch self {
        case let .dnsChangedElsewhere(serviceID):
            "Another agent changed the DNS servers of service \(serviceID); Remap leaves them in place "
                + "and answers its names again when that agent restores Remap's configuration."
        case .resolverHeldElsewhere:
            "Another agent, such as a VPN, holds the resolver macOS uses; Remap writes nothing and "
                + "answers its names again when that agent lets go."
        }
    }
}

/// Every upstream the daemon forwards to has stopped answering, so Remap
/// must not stay the resolver macOS uses (ADR-0036).
public struct ResolverUpstreamsUnanswered: Error, CustomStringConvertible, Equatable, Sendable {
    public let failure: ResolverUpstreamFailure

    public var description: String {
        "Upstream DNS is not answering: every upstream resolver \(causePhrase) for the last "
            + "\(failure.unansweredQueries) queries."
    }

    private var causePhrase: String {
        switch failure.cause {
        case "timed_out": "timed out"
        case "refused": "refused the queries"
        case "unreachable": "was unreachable"
        default: "failed"
        }
    }
}

extension NativeResolverConfigurator {
    /// Whether another agent's DNS keeps Remap's active, single-service
    /// record off the path, and if so which deferral applies. Nil means the
    /// ADR-0024 rules decide, which includes following a service that now
    /// carries DNS and Remap can configure.
    func foreignHold(
        record: ActivationRecord,
        snapshot: NetworkSnapshot,
        carrier: ResolverCarrier
    ) throws -> ResolverFollowing? {
        guard record.payload.phase == .active,
              record.payload.handoffTargetServiceID == nil,
              record.payload.services.count == 1,
              let owned = record.payload.services.first,
              let current = snapshot.service(owned.serviceID),
              current.effectiveServers != nil
        else {
            return nil
        }
        let installed = try holdsInstalledConfiguration(current, record: owned)
        if !installed, try !holdsPriorConfiguration(current, record: owned) {
            return .deferred(
                .dnsChangedElsewhere(serviceID: owned.serviceID),
                adopted: adoptedPlan(snapshot: snapshot, serviceID: owned.serviceID)
            )
        }
        guard installed else {
            // Remap's own restore under an active record: reconciliation
            // commits it again, which writes over nothing but Remap's state.
            return nil
        }
        switch carrier {
        case .service(owned.serviceID), .outsidePreferences:
            return .deferred(
                .resolverHeldElsewhere,
                adopted: adoptedPlan(snapshot: snapshot, serviceID: owned.serviceID)
            )
        case .remap, .service, .unattributed:
            return nil
        }
    }

    /// The servers macOS uses, as a plan under the owned service, so a
    /// lookup that still reaches Remap goes where every other lookup goes.
    private func adoptedPlan(snapshot: NetworkSnapshot, serviceID: String) -> DNSPlan? {
        var adopted = stableUnique(snapshot.globalServers.filter(isUsableUpstream))
        if adopted.isEmpty {
            adopted = stableUnique((snapshot.service(serviceID)?.effectiveServers ?? []).filter(isUsableUpstream))
        }
        guard !adopted.isEmpty else { return nil }
        return DNSPlan(services: [DNSServicePlan(serviceID: serviceID, upstreams: Array(adopted.prefix(4)))])
    }

    /// An active record that macOS does not use. When Remap's own restore
    /// left an owned service at its prior state, as a safe bypass racing an
    /// installer does, the record goes back through prepared and is committed
    /// again: that writes over nothing but Remap's own state. When every owned
    /// service already holds Remap's configuration, another resolver wins
    /// over it, and writing again would only start a write war, so nothing is
    /// written and the deferral says why.
    func reassertActive(record: ActivationRecord) throws {
        let snapshot = try network.snapshot()
        guard snapshot.globalServers != [loopbackResolver] else { return }
        let restoredByRemap = try record.payload.services.contains { service in
            guard let current = snapshot.service(service.serviceID) else { return false }
            return try holdsPriorConfiguration(current, record: service)
                && !holdsInstalledConfiguration(current, record: service)
        }
        guard restoredByRemap else {
            throw ResolverDeferral.resolverHeldElsewhere
        }
        try restoreOrdinaryDNS(retainPreparedRecord: true)
        _ = try commitPrepared()
    }

    /// After a commit whose verification failed, whether Remap's
    /// configuration is in place on every owned service and only another
    /// agent's DNS, layered above it, keeps macOS from using it. Then the
    /// record stays active over that configuration and nothing is restored:
    /// a restore would be a write against the agent that holds the resolver.
    func heldAfterCommit(services: [DNSServiceRecord]) throws -> Bool {
        let snapshot = try network.snapshot()
        let allInstalled = try services.allSatisfy { service in
            guard let current = snapshot.service(service.serviceID) else { return false }
            return try holdsInstalledConfiguration(current, record: service)
        }
        guard allInstalled else { return false }
        switch resolverCarrier(snapshot) {
        case let .service(serviceID):
            return services.contains { $0.serviceID == serviceID }
        case .outsidePreferences:
            return true
        case .remap, .unattributed:
            return false
        }
    }
}
