// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation

/// One enabled network service with a DNS protocol, as SystemConfiguration
/// reports it at one moment.
struct ObservedNetworkService: Equatable, Sendable {
    let serviceID: String
    /// Persisted DNS protocol configuration, property-list encoded; nil when absent.
    let configuration: Data?
    /// Whether the persisted DNS protocol is enabled.
    let enabled: Bool
    /// Effective DNS server addresses; nil when the service has no effective
    /// DNS entry because its interface is down, asleep, or not yet configured.
    let effectiveServers: [String]?
    /// Usable IPv4 resolvers from the service's DHCP option 6, in lease order.
    let dhcpServers: [String]
    let networkSignature: Data?
}

/// A consistent reading of the services and the global resolver.
struct NetworkSnapshot: Equatable, Sendable {
    let services: [ObservedNetworkService]
    let globalServers: [String]

    func service(_ serviceID: String) -> ObservedNetworkService? {
        services.first { $0.serviceID == serviceID }
    }
}

/// One compare-and-set change to a service's persisted DNS protocol.
struct ServiceConfigurationChange: Equatable, Sendable {
    let serviceID: String
    let expectedConfiguration: Data?
    let expectedEnabled: Bool
    let configuration: Data?
    let enabled: Bool
}

/// The SystemConfiguration effects resolver handoff and restoration need.
/// The product adapter is `SystemNetworkConfiguration`; tests use a model.
protocol NativeNetworkConfiguring: Sendable {
    func snapshot() throws -> NetworkSnapshot
    /// Applies every change in one authorized preferences session, refusing
    /// all of them with `configurationConflict` when any service no longer
    /// holds its expected configuration, then commits and applies.
    func commit(_ changes: [ServiceConfigurationChange]) throws
    /// Proves the activation's owner is the console user and the loopback
    /// listener answers before any service is pointed at it.
    func preflightLoopback(ownerUID: UInt32) throws
}

/// The durable activation record, as handoff and restoration use it.
protocol ActivationRecordStoring: Sendable {
    func read() throws -> ActivationRecord
    func replace(_ record: ActivationRecord) throws
    func remove() throws
}

extension ActivationStore: ActivationRecordStoring {}

/// Whether the persisted DNS protocol matches an encoded configuration,
/// ignoring dictionary order, and is enabled as expected.
func persistedMatches(
    _ service: ObservedNetworkService,
    configuration: Data?,
    enabled: Bool
) throws -> Bool {
    guard service.enabled == enabled else { return false }
    switch (service.configuration, configuration) {
    case (nil, nil):
        return true
    case let (current?, expected?):
        return try PropertyLists.equal(PropertyLists.decode(current), encoded: expected)
    case (.some, nil), (nil, .some):
        return false
    }
}

func holdsInstalledConfiguration(
    _ service: ObservedNetworkService,
    record: DNSServiceRecord
) throws -> Bool {
    try persistedMatches(service, configuration: record.installedConfiguration, enabled: true)
}

func holdsPriorConfiguration(
    _ service: ObservedNetworkService,
    record: DNSServiceRecord
) throws -> Bool {
    try persistedMatches(
        service,
        configuration: record.priorConfiguration,
        enabled: record.priorEnabled ?? true
    )
}
