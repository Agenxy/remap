import Darwin
import Foundation
import Network
import Security
import SystemConfiguration
import SystemConfiguration.SCDynamicStoreCopyDHCPInfo

/// Native, reversible macOS DNS configuration adapter.
public struct SystemResolver: Sendable {
    public init() {}

    public func observe() throws -> ResolverObservation {
        let preferences = try makePreferences()
        let dynamicStore = try makeDynamicStore()
        let services = try activeServerAddresses(
            preferences: preferences,
            dynamicStore: dynamicStore
        )
        let configured = try Dictionary(uniqueKeysWithValues: allServiceHandles(
            preferences: preferences
        ).map { handle in
            (handle.serviceID, serverAddresses(from: handle.configuration ?? [:]))
        })
        let remapServices = effectiveRemapServiceIDs(
            activeServiceIDs: Array(services.keys),
            configuredServerAddresses: configured,
            effectiveServerAddresses: effectiveGlobalServerAddresses(dynamicStore: dynamicStore)
        )
        return ResolverObservation(
            activeServiceIDs: Array(services.keys).sorted(),
            remapServiceIDs: remapServices
        )
    }

    public func plan() throws -> DNSPlan {
        let preferences = try makePreferences()
        let dynamicStore = try makeDynamicStore()
        let handles = try serviceHandles(preferences: preferences, dynamicStore: dynamicStore)
        let services = handles.compactMap { handle -> DNSServicePlan? in
            guard !handle.upstreams.isEmpty else {
                return nil
            }
            return DNSServicePlan(serviceID: handle.serviceID, upstreams: handle.upstreams)
        }
        guard !services.isEmpty else {
            throw ResolverError.noEnabledDNSService
        }
        let plan = try validatedPlan(services)
        guard !plan.upstreams.isEmpty else {
            throw ResolverError.noUsableUpstream
        }
        return plan
    }

    public func activate(
        ownerUID: UInt32,
        productVersion: String,
        systemSocketPath: String,
        store: ActivationStore = .standard
    ) async throws -> ActivationRecord {
        let prepared = try prepareActivation(
            ownerUID: ownerUID,
            productVersion: productVersion,
            store: store
        )
        let channel = ResolverSystemChannel(
            socketPath: systemSocketPath,
            expectedPeerUID: ownerUID
        )
        let reconciler = ResolverReconciler(
            resolver: self,
            activationStore: store,
            channel: channel
        )
        try await reconciler.reconcile()
        let health = try channel.exchange(.health)
        let activationID = try prepared.activationIdentifier()
        guard health.activationID == activationID,
              health.activeGeneration != nil
        else {
            throw ResolverReconciliationError.invalidPublication
        }
        return try commitPreparedActivation(store: store)
    }

    /// Captures a complete, integrity-covered resolver restoration point without
    /// changing the Mac's effective DNS configuration.
    public func prepareActivation(
        ownerUID: UInt32,
        productVersion: String,
        store: ActivationStore = .standard
    ) throws -> ActivationRecord {
        try requireRoot()
        try requireActiveConsoleUser(ownerUID)
        guard !store.exists() else {
            throw ResolverError.activationAlreadyExists
        }
        try DNSListenerProbe.run()
        let handles = try serviceHandles(
            preferences: makePreferences(),
            dynamicStore: makeDynamicStore()
        ).filter { !$0.upstreams.isEmpty }
        guard !handles.isEmpty else {
            throw ResolverError.noUsableUpstream
        }
        guard handles.count == 1 else {
            throw ResolverError.unsupportedResolverScope(handles.count)
        }
        let payload = try ActivationPayload(
            ownerUID: ownerUID,
            createdAtMilliseconds: UInt64(Date().timeIntervalSince1970 * 1000),
            productVersion: productVersion,
            phase: .prepared,
            services: handles.map(makeServiceRecord)
        )
        let record = try ActivationRecord(payload: payload)
        try store.create(record)
        return record
    }

    /// Applies a previously prepared activation after the daemon has accepted
    /// the matching forwarding plan. A failure leaves a recoverable prepared
    /// record and restores ordinary DNS whenever the installed configuration
    /// may have reached SystemConfiguration.
    public func commitPreparedActivation(
        store: ActivationStore = .standard
    ) throws -> ActivationRecord {
        try requireRoot()
        let prepared = try store.read()
        guard prepared.payload.phase == .prepared else {
            throw ResolverError.invalidActivationRecord
        }
        try requireActiveConsoleUser(prepared.payload.ownerUID)
        try DNSListenerProbe.run()
        let preferencesSession = try makeAuthorizedPreferences()
        let preferences = preferencesSession.preferences
        let records = prepared.payload.services
        do {
            let handles = try allServiceHandles(preferences: preferences)
            let indexed = Dictionary(uniqueKeysWithValues: handles.map { ($0.serviceID, $0) })
            guard records.allSatisfy({ indexed[$0.serviceID] != nil }) else {
                throw ResolverError.invalidActivationRecord
            }
            let conflicts = try conflictingServices(records, handles: indexed)
            guard conflicts.isEmpty else {
                throw ResolverError.configurationConflict(conflicts.sorted())
            }
            let selected = records.compactMap { indexed[$0.serviceID] }
            try applyInstalledConfigurations(
                preferences: preferences,
                handles: selected,
                records: records
            )
            // CommitChanges obtains the SystemConfiguration lock itself and
            // rejects a stale preferences snapshot instead of overwriting it.
            try commit(preferences)
            try verifyEffectiveConfigurations(records)
            let active = try ActivationRecord(payload: prepared.payload.withPhase(.active))
            try store.replace(active)
            return active
        } catch {
            try? restoreFailedActivation(records)
            throw error
        }
    }

    public func deactivate(store: ActivationStore = .standard) throws {
        try restoreOrdinaryDNS(store: store, retainPreparedRecord: false)
    }

    /// Restores ordinary DNS while retaining the integrity-covered activation
    /// as prepared state. The resolver supervisor uses this fail-safe state to
    /// retry daemon publication without directing system traffic back to Remap
    /// until the complete plan has been accepted again.
    public func suspend(store: ActivationStore = .standard) throws {
        try restoreOrdinaryDNS(store: store, retainPreparedRecord: true)
    }

    private func restoreOrdinaryDNS(
        store: ActivationStore,
        retainPreparedRecord: Bool
    ) throws {
        try requireRoot()
        let record = try store.read()
        if record.payload.phase == .prepared {
            if !retainPreparedRecord {
                try store.remove()
            }
            return
        }
        let preferencesSession = try makeAuthorizedPreferences()
        let preferences = preferencesSession.preferences
        let handles = try allServiceHandles(preferences: preferences)
        let indexed = Dictionary(uniqueKeysWithValues: handles.map { ($0.serviceID, $0) })
        let conflicts = try conflictingServices(record.payload.services, handles: indexed)
        guard conflicts.isEmpty else {
            throw ResolverError.configurationConflict(conflicts.sorted())
        }
        let restorable = record.payload.services.compactMap { service -> ServiceHandle? in
            guard let handle = indexed[service.serviceID],
                  handle.enabled,
                  (try? PropertyLists.equal(
                      handle.configuration,
                      encoded: service.installedConfiguration
                  )) == true
            else {
                return nil
            }
            return handle
        }
        let records = restorable.compactMap { handle in
            record.payload.services.first { $0.serviceID == handle.serviceID }
        }
        try restoreConfigurations(
            preferences: preferences,
            handles: restorable,
            records: records
        )
        try commit(preferences)
        try verifyEffectiveConfigurations(record.payload.services, restoring: true)
        if retainPreparedRecord {
            let prepared = try ActivationRecord(payload: record.payload.withPhase(.prepared))
            try store.replace(prepared)
        } else {
            try store.remove()
        }
    }

    public func activeRecord(store: ActivationStore = .standard) throws -> ActivationRecord? {
        guard store.exists() else {
            return nil
        }
        return try store.read()
    }

    /// Recomputes the supported ordinary resolver scope while loopback DNS is active.
    ///
    /// The current effective service state or DHCP lease takes precedence so a network
    /// transition cannot keep forwarding to the prior network. The integrity-covered
    /// pre-activation snapshot is used only while the same service is still present and
    /// macOS exposes no usable current upstream.
    public func reconciliationPlan(record: ActivationRecord) throws -> DNSPlan {
        let dynamicStore = try makeDynamicStore()
        let capturedUpstreams = Dictionary(
            uniqueKeysWithValues: record.payload.services.map { ($0.serviceID, $0.upstreams) }
        )
        return try reconciliationPlan(record: record) { serviceID in
            let dnsKey = "State:/Network/Service/\(serviceID)/DNS" as CFString
            let ipv4Key = "State:/Network/Service/\(serviceID)/IPv4" as CFString
            let effective = SCDynamicStoreCopyValue(dynamicStore, dnsKey) as? [String: Any]
            let ipv4 = SCDynamicStoreCopyValue(dynamicStore, ipv4Key) as? [String: Any]
            let service = record.payload.services.first { $0.serviceID == serviceID }
            return dynamicResolverUpstreams(
                effectiveConfiguration: effective,
                dhcpData: dhcpResolverData(serviceID: serviceID),
                capturedUpstreams: capturedUpstreams[serviceID] ?? [],
                capturedNetworkSignature: service?.networkSignature,
                currentNetworkSignature: networkSignature(from: ipv4)
            )
        }
    }

    func reconciliationPlan(
        record: ActivationRecord,
        dhcpData: (String) -> Data?
    ) throws -> DNSPlan {
        try reconciliationPlan(record: record) { serviceID in
            guard let data = dhcpData(serviceID) else { return [] }
            return dhcpIPv4Servers(data)
        }
    }

    func reconciliationPlan(
        record: ActivationRecord,
        dynamicUpstreams: (String) throws -> [String]
    ) throws -> DNSPlan {
        try record.verify()
        guard record.payload.phase == .prepared || record.payload.phase == .active else {
            throw ResolverError.invalidActivationRecord
        }
        let services = try record.payload.services.map { service in
            let upstreams = try reconciliationUpstreams(
                service: service,
                dynamicUpstreams: dynamicUpstreams
            )
            guard !upstreams.isEmpty else {
                throw ResolverError.noUsableUpstream
            }
            return DNSServicePlan(serviceID: service.serviceID, upstreams: upstreams)
        }
        let plan = try validatedPlan(services)
        guard !plan.upstreams.isEmpty else {
            throw ResolverError.noUsableUpstream
        }
        return plan
    }
}

/// Resolves a dynamic service without treating Remap's own loopback setting as
/// an upstream. The effective-service entry must still exist: this prevents a
/// captured resolver from being reused after the original service disappears.
/// When the service is unchanged but its upstream mechanism is not exposed as
/// DHCP option 6, a captured plan is accepted only while the native network
/// signature still exactly matches the activation snapshot.
func dynamicResolverUpstreams(
    effectiveConfiguration: [String: Any]?,
    dhcpData: Data?,
    capturedUpstreams: [String],
    capturedNetworkSignature: Data?,
    currentNetworkSignature: Data?
) -> [String] {
    guard let effectiveConfiguration else { return [] }
    let live = upstreams(from: effectiveConfiguration)
    if !live.isEmpty {
        return live
    }
    if let dhcpData {
        let dhcp = dhcpIPv4Servers(dhcpData)
        if !dhcp.isEmpty {
            return dhcp
        }
    }
    guard let capturedNetworkSignature,
          capturedNetworkSignature == currentNetworkSignature
    else {
        return []
    }
    return stableUnique(capturedUpstreams.filter(isUsableUpstream))
}

private func reconciliationUpstreams(
    service: DNSServiceRecord,
    dynamicUpstreams: (String) throws -> [String]
) throws -> [String] {
    let current = try dynamicUpstreams(service.serviceID).filter(isUsableUpstream)
    if !current.isEmpty {
        return current
    }
    return []
}

func networkSignature(from configuration: [String: Any]?) -> Data? {
    configuration?["NetworkSignatureHash"] as? Data
}

private func dhcpResolverData(serviceID: String) -> Data? {
    guard let information = SCDynamicStoreCopyDHCPInfo(nil, serviceID as CFString),
          let data = DHCPInfoGetOptionData(information, 6)
    else {
        return nil
    }
    return data as Data
}

func dhcpIPv4Servers(_ data: Data) -> [String] {
    guard !data.isEmpty, data.count.isMultiple(of: 4) else {
        return []
    }
    return stableUnique(stride(from: 0, to: data.count, by: 4).compactMap { offset in
        let bytes = data[offset ..< offset + 4]
        guard let address = IPv4Address(Data(bytes)) else {
            return nil
        }
        let value = address.debugDescription
        return isUsableUpstream(value) ? value : nil
    })
}

func validatedPlan(_ services: [DNSServicePlan]) throws -> DNSPlan {
    guard services.count == 1 else {
        throw ResolverError.unsupportedResolverScope(services.count)
    }
    return DNSPlan(services: services)
}

private struct ServiceHandle {
    let serviceID: String
    let dnsProtocol: SCNetworkProtocol
    let configuration: [String: Any]?
    let enabled: Bool
    let upstreams: [String]
    let networkSignature: Data?
}

private func makePreferences() throws -> SCPreferences {
    guard let preferences = SCPreferencesCreate(nil, "Agenxy Remap" as CFString, nil) else {
        throw ResolverError.preferences("open DNS preferences")
    }
    return preferences
}

private final class AuthorizedPreferencesSession {
    let preferences: SCPreferences
    private let authorization: AuthorizationRef

    init(preferences: SCPreferences, authorization: AuthorizationRef) {
        self.preferences = preferences
        self.authorization = authorization
    }

    deinit {
        _ = AuthorizationFree(authorization, [.destroyRights])
    }
}

private func makeAuthorizedPreferences() throws -> AuthorizedPreferencesSession {
    var authorization: AuthorizationRef?
    let status = "system.preferences.network".withCString { rightName in
        var item = AuthorizationItem(
            name: rightName,
            valueLength: 0,
            value: nil,
            flags: 0
        )
        return withUnsafeMutablePointer(to: &item) { itemPointer in
            var rights = AuthorizationRights(count: 1, items: itemPointer)
            return AuthorizationCreate(
                &rights,
                nil,
                [.extendRights],
                &authorization
            )
        }
    }
    guard status == errAuthorizationSuccess, let authorization else {
        throw ResolverError.preferences("authorize DNS preferences")
    }
    guard let preferences = SCPreferencesCreateWithAuthorization(
        nil,
        "Agenxy Remap" as CFString,
        nil,
        authorization
    ) else {
        _ = AuthorizationFree(authorization, [.destroyRights])
        throw ResolverError.preferences("open authorized DNS preferences")
    }
    return AuthorizedPreferencesSession(
        preferences: preferences,
        authorization: authorization
    )
}

private func makeDynamicStore() throws -> SCDynamicStore {
    guard let store = SCDynamicStoreCreate(nil, "Agenxy Remap" as CFString, nil, nil) else {
        throw ResolverError.preferences("open the dynamic network store")
    }
    return store
}

private func serviceHandles(
    preferences: SCPreferences,
    dynamicStore: SCDynamicStore
) throws -> [ServiceHandle] {
    try allServiceHandles(preferences: preferences).filter { handle in
        let key = "State:/Network/Service/\(handle.serviceID)/DNS" as CFString
        guard let effective = SCDynamicStoreCopyValue(dynamicStore, key) as? [String: Any] else {
            return false
        }
        return !upstreams(from: effective).isEmpty
    }.map { handle in
        let key = "State:/Network/Service/\(handle.serviceID)/DNS" as CFString
        let effective = SCDynamicStoreCopyValue(dynamicStore, key) as? [String: Any]
        return ServiceHandle(
            serviceID: handle.serviceID,
            dnsProtocol: handle.dnsProtocol,
            configuration: handle.configuration,
            enabled: handle.enabled,
            upstreams: upstreams(from: effective ?? [:]),
            networkSignature: networkSignature(from: ipv4Configuration(
                dynamicStore: dynamicStore,
                serviceID: handle.serviceID
            ))
        )
    }
}

private func activeServerAddresses(
    preferences: SCPreferences,
    dynamicStore: SCDynamicStore
) throws -> [String: [String]] {
    let handles = try allServiceHandles(preferences: preferences)
    return Dictionary(uniqueKeysWithValues: handles.compactMap { handle in
        let key = "State:/Network/Service/\(handle.serviceID)/DNS" as CFString
        guard let effective = SCDynamicStoreCopyValue(dynamicStore, key) as? [String: Any] else {
            return nil
        }
        let addresses = serverAddresses(from: effective)
        return addresses.isEmpty ? nil : (handle.serviceID, addresses)
    })
}

private func allServiceHandles(preferences: SCPreferences) throws -> [ServiceHandle] {
    guard let services = SCNetworkServiceCopyAll(preferences) as? [SCNetworkService] else {
        throw ResolverError.preferences("enumerate network services")
    }
    return services.compactMap { service in
        guard SCNetworkServiceGetEnabled(service),
              let serviceID = SCNetworkServiceGetServiceID(service) as String?,
              let dnsProtocol = SCNetworkServiceCopyProtocol(service, kSCNetworkProtocolTypeDNS)
        else {
            return nil
        }
        return ServiceHandle(
            serviceID: serviceID,
            dnsProtocol: dnsProtocol,
            configuration: SCNetworkProtocolGetConfiguration(dnsProtocol) as? [String: Any],
            enabled: SCNetworkProtocolGetEnabled(dnsProtocol),
            upstreams: [],
            networkSignature: nil
        )
    }
}

private func upstreams(from configuration: [String: Any]) -> [String] {
    serverAddresses(from: configuration).filter(isUsableUpstream)
}

func serverAddresses(from configuration: [String: Any]) -> [String] {
    let serverKey = kSCPropNetDNSServerAddresses as String
    let addresses = configuration[serverKey] as? [String] ?? []
    return stableUnique(addresses)
}

func effectiveRemapServiceIDs(
    activeServiceIDs: [String],
    configuredServerAddresses: [String: [String]],
    effectiveServerAddresses: [String]
) -> [String] {
    guard effectiveServerAddresses == ["127.0.0.1"] else {
        return []
    }
    return activeServiceIDs.filter { serviceID in
        configuredServerAddresses[serviceID] == ["127.0.0.1"]
    }.sorted()
}

func isUsableUpstream(_ value: String) -> Bool {
    if let address = IPv4Address(value) {
        return address.rawValue.first != 127
    }
    if let address = IPv6Address(value) {
        let loopback = Data(repeating: 0, count: 15) + Data([1])
        return address.rawValue != loopback
    }
    return false
}

private func makeServiceRecord(_ handle: ServiceHandle) throws -> DNSServiceRecord {
    let installed = installedConfiguration(from: handle.configuration)
    return try DNSServiceRecord(
        serviceID: handle.serviceID,
        priorConfiguration: handle.configuration.map(PropertyLists.encode),
        priorEnabled: handle.enabled,
        installedConfiguration: PropertyLists.encode(installed),
        upstreams: handle.upstreams,
        networkSignature: handle.networkSignature
    )
}

private func ipv4Configuration(
    dynamicStore: SCDynamicStore,
    serviceID: String
) -> [String: Any]? {
    let key = "State:/Network/Service/\(serviceID)/IPv4" as CFString
    return SCDynamicStoreCopyValue(dynamicStore, key) as? [String: Any]
}

private func installedConfiguration(from prior: [String: Any]?) -> [String: Any] {
    var configuration = prior ?? [:]
    configuration[kSCPropNetDNSServerAddresses as String] = ["127.0.0.1"]
    return configuration
}

private func applyInstalledConfigurations(
    preferences: SCPreferences,
    handles: [ServiceHandle],
    records: [DNSServiceRecord]
) throws {
    let indexed = Dictionary(uniqueKeysWithValues: records.map { ($0.serviceID, $0) })
    for handle in handles {
        guard let record = indexed[handle.serviceID] else {
            throw ResolverError.invalidActivationRecord
        }
        let configuration = try PropertyLists.decode(record.installedConfiguration)
        try setProtocolPreference(
            preferences: preferences,
            serviceID: handle.serviceID,
            configuration: configuration,
            enabled: true,
            operation: "stage the Remap DNS configuration"
        )
    }
}

private func restoreConfigurations(
    preferences: SCPreferences,
    handles: [ServiceHandle],
    records: [DNSServiceRecord]
) throws {
    let indexed = Dictionary(uniqueKeysWithValues: records.map { ($0.serviceID, $0) })
    for handle in handles {
        guard let record = indexed[handle.serviceID] else {
            throw ResolverError.invalidActivationRecord
        }
        let restored = try record.priorConfiguration.map(PropertyLists.decode)
        try setProtocolPreference(
            preferences: preferences,
            serviceID: handle.serviceID,
            configuration: restored,
            enabled: record.priorEnabled ?? true,
            operation: "stage the prior DNS configuration"
        )
    }
}

func protocolPreferenceValue(
    configuration: [String: Any]?,
    enabled: Bool
) -> [String: Any]? {
    guard configuration != nil || enabled else {
        return nil
    }
    var value = configuration ?? [:]
    if enabled {
        value.removeValue(forKey: "__INACTIVE__")
    } else {
        value["__INACTIVE__"] = 1
    }
    return value
}

private func setProtocolPreference(
    preferences: SCPreferences,
    serviceID: String,
    configuration: [String: Any]?,
    enabled: Bool,
    operation: String
) throws {
    let path = "/NetworkServices/\(serviceID)/DNS" as CFString
    if let value = protocolPreferenceValue(configuration: configuration, enabled: enabled) {
        guard SCPreferencesPathSetValue(preferences, path, value as CFDictionary) else {
            throw ResolverError.preferences(operation)
        }
    } else if SCPreferencesPathGetValue(preferences, path) != nil {
        guard SCPreferencesPathRemoveValue(preferences, path) else {
            throw ResolverError.preferences(operation)
        }
    }
}

private func conflictingServices(
    _ records: [DNSServiceRecord],
    handles: [String: ServiceHandle]
) throws -> [String] {
    try records.compactMap { record in
        guard let handle = handles[record.serviceID] else {
            return nil
        }
        let installedConfigurationMatches = try PropertyLists.equal(
            handle.configuration,
            encoded: record.installedConfiguration
        )
        let priorConfigurationMatches = try configurationsEqual(
            handle.configuration,
            prior: record.priorConfiguration
        )
        let installed = handle.enabled && installedConfigurationMatches
        let prior = handle.enabled == (record.priorEnabled ?? true)
            && priorConfigurationMatches
        return installed || prior ? nil : record.serviceID
    }
}

private func configurationsEqual(_ current: [String: Any]?, prior: Data?) throws -> Bool {
    switch (current, prior) {
    case (nil, nil):
        true
    case let (current?, prior?):
        try PropertyLists.equal(current, encoded: prior)
    case (.some, nil), (nil, .some):
        false
    }
}

private func commit(_ preferences: SCPreferences) throws {
    guard SCPreferencesCommitChanges(preferences), SCPreferencesApplyChanges(preferences) else {
        throw ResolverError.preferences("commit and apply DNS preferences")
    }
}

private func restoreFailedActivation(_ records: [DNSServiceRecord]) throws {
    let preferencesSession = try makeAuthorizedPreferences()
    let preferences = preferencesSession.preferences
    let handles = try allServiceHandles(preferences: preferences)
    let indexed = Dictionary(uniqueKeysWithValues: handles.map { ($0.serviceID, $0) })
    let conflicts = try conflictingServices(records, handles: indexed)
    guard conflicts.isEmpty else {
        throw ResolverError.configurationConflict(conflicts.sorted())
    }
    let restorable = records.compactMap { record -> ServiceHandle? in
        guard let handle = indexed[record.serviceID],
              handle.enabled,
              (try? PropertyLists.equal(
                  handle.configuration,
                  encoded: record.installedConfiguration
              )) == true
        else {
            return nil
        }
        return handle
    }
    let restorableRecords = restorable.compactMap { handle in
        records.first { $0.serviceID == handle.serviceID }
    }
    try restoreConfigurations(
        preferences: preferences,
        handles: restorable,
        records: restorableRecords
    )
    try commit(preferences)
}

private func verifyEffectiveConfigurations(
    _ records: [DNSServiceRecord],
    restoring: Bool = false
) throws {
    let deadline = Date().addingTimeInterval(3)
    repeat {
        let preferences = try makePreferences()
        let store = try makeDynamicStore()
        let effective = effectiveGlobalServerAddresses(dynamicStore: store)
        let effectiveMatches = if restoring {
            try restoredEffectiveServersMatch(records, effective: effective)
        } else {
            effective == ["127.0.0.1"]
        }
        if try persistedConfigurationsMatch(
            records,
            preferences: preferences,
            restoring: restoring
        ), effectiveMatches {
            return
        }
        usleep(50000)
    } while Date() < deadline
    throw ResolverError.preferences("verify the effective DNS configuration")
}

func restoredEffectiveServersMatch(
    _ records: [DNSServiceRecord],
    effective: [String]
) throws -> Bool {
    let configured = try records.flatMap { record -> [String] in
        guard let prior = record.priorConfiguration else { return [] }
        return try upstreams(from: PropertyLists.decode(prior))
    }
    if !configured.isEmpty {
        return effective.sorted() == stableUnique(configured).sorted()
    }
    return !effective.isEmpty && effective.allSatisfy(isUsableUpstream)
}

private func effectiveGlobalServerAddresses(dynamicStore: SCDynamicStore) -> [String] {
    let key = "State:/Network/Global/DNS" as CFString
    let value = SCDynamicStoreCopyValue(dynamicStore, key) as? [String: Any]
    return serverAddresses(from: value ?? [:])
}

private func persistedConfigurationsMatch(
    _ records: [DNSServiceRecord],
    preferences: SCPreferences,
    restoring: Bool
) throws -> Bool {
    let handles = try allServiceHandles(preferences: preferences)
    let indexed = Dictionary(uniqueKeysWithValues: handles.map { ($0.serviceID, $0) })
    return try records.allSatisfy { record in
        guard let handle = indexed[record.serviceID] else {
            return false
        }
        if restoring {
            return try handle.enabled == (record.priorEnabled ?? true)
                && configurationsEqual(
                    handle.configuration,
                    prior: record.priorConfiguration
                )
        }
        return try handle.enabled
            && (PropertyLists.equal(
                handle.configuration,
                encoded: record.installedConfiguration
            ))
    }
}

private func requireActiveConsoleUser(_ expectedUID: UInt32) throws {
    var userID: uid_t = 0
    var groupID: gid_t = 0
    guard SCDynamicStoreCopyConsoleUser(nil, &userID, &groupID) != nil,
          userID == expectedUID,
          userID != 0
    else {
        throw ResolverError.activeUserMismatch
    }
}
