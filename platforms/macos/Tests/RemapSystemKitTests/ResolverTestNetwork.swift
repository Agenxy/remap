import Foundation
@testable import RemapSystemKit
import Synchronization

/// A model of the SystemConfiguration behavior handoff relies on. Each
/// service has a persisted DNS protocol and the configuration configd last
/// applied. A service that is up resolves through its applied server
/// addresses, or its DHCP resolvers when it sets none, and the first service
/// that is up in service order supplies the global resolver.
final class ResolverTestNetwork: NativeNetworkConfiguring, Sendable {
    enum Fault: Equatable, Sendable {
        case preflight
        case commitRefused
        case applyFailed
        case verificationStale
    }

    struct Service: Sendable {
        let serviceID: String
        var persisted: Data?
        var enabled = true
        var applied: Data?
        var connected: Bool
        var dhcp: [String]
    }

    struct State: Sendable {
        var services: [Service]
        var faults: Set<Fault> = []
        var commits = 0
        var commitAttempts = 0
        /// 1-based commit attempts refused before any change, as a stale
        /// preferences session or a lost authorization would be.
        var refusedCommitAttempts: Set<Int> = []
    }

    private let state: Mutex<State>

    init(_ services: [Service]) {
        state = Mutex(State(services: services))
    }

    func update(_ change: (inout State) -> Void) {
        state.withLock { change(&$0) }
    }

    func service(_ serviceID: String) -> Service? {
        state.withLock { $0.services.first { $0.serviceID == serviceID } }
    }

    /// Refuses the given 1-based future commit attempt without changing anything.
    func refuseCommit(_ ordinal: Int) {
        update { state in _ = state.refusedCommitAttempts.insert(state.commitAttempts + ordinal) }
    }

    /// Commits that changed the persisted configuration.
    var commitCount: Int {
        state.withLock(\.commits)
    }

    func setUp(_ serviceID: String, _ connected: Bool) {
        update { state in
            guard let index = state.services.firstIndex(where: { $0.serviceID == serviceID }) else { return }
            state.services[index].connected = connected
        }
    }

    /// The user edits a service's DNS outside Remap; configd applies it.
    func userSets(_ serviceID: String, servers: [String]) throws {
        let data = try PropertyLists.encode(["ServerAddresses": servers])
        update { state in
            guard let index = state.services.firstIndex(where: { $0.serviceID == serviceID }) else { return }
            state.services[index].persisted = data
            state.services[index].applied = data
        }
    }

    /// Services whose persisted DNS points at the loopback listener.
    func loopbackServiceIDs() throws -> [String] {
        try state.withLock { $0.services }.filter { service in
            guard let persisted = service.persisted else { return false }
            return try serverAddresses(from: PropertyLists.decode(persisted)) == [loopbackResolver]
        }.map(\.serviceID)
    }

    func snapshot() throws -> NetworkSnapshot {
        let current = state.withLock { $0 }
        let services = try current.services.map { service in
            try ObservedNetworkService(
                serviceID: service.serviceID,
                configuration: service.persisted,
                enabled: service.enabled,
                effectiveServers: service.connected ? effectiveServers(service) : nil,
                dhcpServers: service.connected ? service.dhcp : [],
                networkSignature: Data(service.serviceID.utf8)
            )
        }
        var global = try current.services.first(where: \.connected).map(effectiveServers) ?? []
        if current.faults.contains(.verificationStale) {
            global = ["198.51.100.1"]
        }
        return NetworkSnapshot(services: services, globalServers: global)
    }

    func commit(_ changes: [ServiceConfigurationChange]) throws {
        try state.withLock { state in
            state.commitAttempts += 1
            let refused = state.refusedCommitAttempts.contains(state.commitAttempts)
            if refused || state.faults.contains(.commitRefused) {
                throw ResolverError.preferences("commit and apply DNS preferences")
            }
            for change in changes {
                guard let service = state.services.first(where: { $0.serviceID == change.serviceID }),
                      service.persisted == change.expectedConfiguration,
                      service.enabled == change.expectedEnabled
                else {
                    throw ResolverError.configurationConflict([change.serviceID])
                }
            }
            for change in changes {
                guard let index = state.services.firstIndex(where: { $0.serviceID == change.serviceID }) else {
                    continue
                }
                state.services[index].persisted = change.configuration
                state.services[index].enabled = change.enabled
            }
            state.commits += 1
            if state.faults.contains(.applyFailed) {
                throw ResolverError.preferences("commit and apply DNS preferences")
            }
            for index in state.services.indices {
                state.services[index].applied = state.services[index].persisted
            }
        }
    }

    func preflightLoopback(ownerUID _: UInt32) throws {
        if state.withLock({ $0.faults.contains(.preflight) }) {
            throw ResolverError.listenerUnavailable
        }
    }

    private func effectiveServers(_ service: Service) throws -> [String] {
        let configured = try service.applied.map { try serverAddresses(from: PropertyLists.decode($0)) } ?? []
        return configured.isEmpty ? service.dhcp : configured
    }
}

/// An activation record store that can fail chosen writes, as a crash would.
final class ResolverTestRecordStore: ActivationRecordStoring, Sendable {
    private struct State {
        var record: ActivationRecord?
        var writes = 0
        var failingWrites: Set<Int> = []
    }

    private let state: Mutex<State>

    init(_ record: ActivationRecord?) {
        state = Mutex(State(record: record))
    }

    /// Makes the given 1-based future write fail without changing the record.
    func failWrite(_ ordinal: Int) {
        state.withLock { state in _ = state.failingWrites.insert(state.writes + ordinal) }
    }

    func clearFailures() {
        state.withLock { $0.failingWrites = [] }
    }

    var current: ActivationRecord? {
        state.withLock(\.record)
    }

    func read() throws -> ActivationRecord {
        guard let record = state.withLock(\.record) else {
            throw ResolverError.activationRecordMissing
        }
        return record
    }

    func replace(_ record: ActivationRecord) throws {
        try state.withLock { state in
            state.writes += 1
            if state.failingWrites.contains(state.writes) {
                throw ResolverError.secureStorage("replace the activation record atomically")
            }
            state.record = record
        }
    }

    func remove() throws {
        state.withLock { $0.record = nil }
    }
}
