// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
import SystemConfiguration

/// The product's SystemConfiguration adapter for handoff and restoration.
struct SystemNetworkConfiguration: NativeNetworkConfiguring {
    func snapshot() throws -> NetworkSnapshot {
        let preferences = try makePreferences()
        let dynamicStore = try makeDynamicStore()
        let services = try allServiceHandles(preferences: preferences).map { handle in
            let key = "State:/Network/Service/\(handle.serviceID)/DNS" as CFString
            let effective = SCDynamicStoreCopyValue(dynamicStore, key) as? [String: Any]
            return try ObservedNetworkService(
                serviceID: handle.serviceID,
                configuration: handle.configuration.map(PropertyLists.encode),
                enabled: handle.enabled,
                effectiveServers: effective.map(serverAddresses),
                dhcpServers: dhcpResolverData(serviceID: handle.serviceID).map(dhcpIPv4Servers) ?? [],
                networkSignature: networkSignature(from: ipv4Configuration(
                    dynamicStore: dynamicStore,
                    serviceID: handle.serviceID
                ))
            )
        }
        return NetworkSnapshot(
            services: services,
            globalServers: effectiveGlobalServerAddresses(dynamicStore: dynamicStore),
            primaryServiceID: primaryServiceID(dynamicStore: dynamicStore)
        )
    }

    func commit(_ changes: [ServiceConfigurationChange]) throws {
        let session = try makeAuthorizedPreferences()
        let preferences = session.preferences
        let handles = try Dictionary(uniqueKeysWithValues: allServiceHandles(preferences: preferences).map {
            ($0.serviceID, $0)
        })
        // Every expectation is checked in this session before any value is
        // staged, and CommitChanges refuses a stale session, so a concurrent
        // user change is reported rather than overwritten.
        let conflicts = try changes.compactMap { change -> String? in
            guard let handle = handles[change.serviceID] else { return change.serviceID }
            let current = try ObservedNetworkService(
                serviceID: handle.serviceID,
                configuration: handle.configuration.map(PropertyLists.encode),
                enabled: handle.enabled,
                effectiveServers: nil,
                dhcpServers: [],
                networkSignature: nil
            )
            let unchanged = try persistedMatches(
                current,
                configuration: change.expectedConfiguration,
                enabled: change.expectedEnabled
            )
            return unchanged ? nil : change.serviceID
        }
        guard conflicts.isEmpty else {
            throw ResolverError.configurationConflict(conflicts.sorted())
        }
        for change in changes {
            try setProtocolPreference(
                preferences: preferences,
                serviceID: change.serviceID,
                configuration: change.configuration.map(PropertyLists.decode),
                enabled: change.enabled,
                operation: "stage a DNS configuration"
            )
        }
        try commitPreferences(preferences)
    }

    private func primaryServiceID(dynamicStore: SCDynamicStore) -> String? {
        let key = "State:/Network/Global/IPv4" as CFString
        let value = SCDynamicStoreCopyValue(dynamicStore, key) as? [String: Any]
        return value?[kSCDynamicStorePropNetPrimaryService as String] as? String
    }

    func preflightLoopback(ownerUID: UInt32) throws {
        try requireActiveConsoleUser(ownerUID)
        try DNSListenerProbe.run()
    }
}
