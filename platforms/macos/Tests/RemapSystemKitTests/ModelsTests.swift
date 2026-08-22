import Foundation
@testable import RemapSystemKit
import SystemConfiguration
import Testing

@Test
func dhcpOptionSixParsesOrderedSafeIpv4Servers() {
    let data = Data([
        192, 0, 2, 1,
        127, 0, 0, 1,
        192, 0, 2, 2,
        192, 0, 2, 1
    ])
    #expect(dhcpIPv4Servers(data) == ["192.0.2.1", "192.0.2.2"])
    #expect(dhcpIPv4Servers(Data([192, 0, 2])).isEmpty)
}

@Test
func reconciliationRejectsSavedStaticResolversWithoutCurrentNetworkProvenance() throws {
    let configuration = [kSCPropNetDNSServerAddresses as String: ["192.0.2.8", "192.0.2.9"]]
    let service = try DNSServiceRecord(
        serviceID: "service-a",
        priorConfiguration: PropertyLists.encode(configuration),
        installedConfiguration: PropertyLists.encode(configuration),
        upstreams: ["192.0.2.8", "192.0.2.9"]
    )
    let record = try activeRecord(service: service)
    #expect(throws: ResolverError.noUsableUpstream) {
        try SystemResolver().reconciliationPlan(record: record) { _ in nil }
    }
}

@Test
func reconciliationReplacesSavedResolversAfterANetworkTransition() throws {
    let configuration = [kSCPropNetDNSServerAddresses as String: ["192.168.5.2"]]
    let service = try DNSServiceRecord(
        serviceID: "service-a",
        priorConfiguration: PropertyLists.encode(configuration),
        installedConfiguration: PropertyLists.encode(configuration),
        upstreams: ["192.168.5.2"]
    )
    let record = try activeRecord(service: service)
    let plan = try SystemResolver().reconciliationPlan(record: record) { _ in
        ["192.168.1.254", "2600:1700:2f70:ce40::1"]
    }
    #expect(plan.upstreams == ["192.168.1.254", "2600:1700:2f70:ce40::1"])
}

@Test
func reconciliationUsesDhcpv4AndRejectsUnsupportedDynamicScopes() throws {
    let service = try DNSServiceRecord(
        serviceID: "service-a",
        priorConfiguration: nil,
        installedConfiguration: PropertyLists.encode([:]),
        upstreams: ["192.0.2.1"]
    )
    let record = try activeRecord(service: service)
    let plan = try SystemResolver().reconciliationPlan(record: record) { _ in
        Data([198, 51, 100, 7])
    }
    #expect(plan.upstreams == ["198.51.100.7"])
    #expect(throws: ResolverError.noUsableUpstream) {
        try SystemResolver().reconciliationPlan(record: record) { _ in nil }
    }
}

@Test
func reconciliationUsesTheCompleteLiveDynamicResolverSet() throws {
    let service = try DNSServiceRecord(
        serviceID: "service-a",
        priorConfiguration: nil,
        installedConfiguration: PropertyLists.encode([:]),
        upstreams: ["192.0.2.1"]
    )
    let record = try activeRecord(service: service)
    let plan = try SystemResolver().reconciliationPlan(record: record) { _ in
        ["192.0.2.53", "2001:db8::53"]
    }
    #expect(plan.upstreams == ["192.0.2.53", "2001:db8::53"])
}

@Test
func dynamicResolverFallbackRequiresTheOriginalEffectiveService() {
    let loopback = [kSCPropNetDNSServerAddresses as String: ["127.0.0.1"]]
    let captured = ["17.7.7.207", "17.8.8.208"]
    let originalSignature = Data([1, 2, 3])
    let changedSignature = Data([4, 5, 6])

    #expect(dynamicResolverUpstreams(
        effectiveConfiguration: loopback,
        dhcpData: nil,
        capturedUpstreams: captured,
        capturedNetworkSignature: originalSignature,
        currentNetworkSignature: originalSignature
    ) == captured)
    #expect(dynamicResolverUpstreams(
        effectiveConfiguration: loopback,
        dhcpData: nil,
        capturedUpstreams: captured,
        capturedNetworkSignature: originalSignature,
        currentNetworkSignature: changedSignature
    ).isEmpty)
    #expect(dynamicResolverUpstreams(
        effectiveConfiguration: loopback,
        dhcpData: Data([192, 0, 2, 53]),
        capturedUpstreams: captured,
        capturedNetworkSignature: originalSignature,
        currentNetworkSignature: changedSignature
    ) == ["192.0.2.53"])
    #expect(dynamicResolverUpstreams(
        effectiveConfiguration: [
            kSCPropNetDNSServerAddresses as String: ["198.51.100.53"]
        ],
        dhcpData: nil,
        capturedUpstreams: captured,
        capturedNetworkSignature: originalSignature,
        currentNetworkSignature: changedSignature
    ) == ["198.51.100.53"])
    #expect(dynamicResolverUpstreams(
        effectiveConfiguration: nil,
        dhcpData: nil,
        capturedUpstreams: captured,
        capturedNetworkSignature: originalSignature,
        currentNetworkSignature: originalSignature
    ).isEmpty)
}

@Test
func preparedActivationPublishesTheFinalIdentityAndCompletePlan() throws {
    let configuration = [kSCPropNetDNSServerAddresses as String: ["192.0.2.53"]]
    let service = try DNSServiceRecord(
        serviceID: "service-a",
        priorConfiguration: PropertyLists.encode(configuration),
        installedConfiguration: PropertyLists.encode([
            kSCPropNetDNSServerAddresses as String: ["127.0.0.1"]
        ]),
        upstreams: ["192.0.2.53"]
    )
    let prepared = try ActivationRecord(payload: ActivationPayload(
        ownerUID: 501,
        createdAtMilliseconds: 1,
        productVersion: "0.1.1",
        phase: .prepared,
        services: [service]
    ))
    let active = try ActivationRecord(payload: prepared.payload.withPhase(.active))

    #expect(try prepared.activationIdentifier() == active.activationIdentifier())
    #expect(try SystemResolver().reconciliationPlan(record: prepared) { _ in
        ["192.0.2.53"]
    }.upstreams == ["192.0.2.53"])
}

@Test
func dynamicRestorationAcceptsTheCurrentNonLoopbackNetworkResolvers() throws {
    let dynamic = try DNSServiceRecord(
        serviceID: "service-a",
        priorConfiguration: nil,
        installedConfiguration: PropertyLists.encode([
            kSCPropNetDNSServerAddresses as String: ["127.0.0.1"]
        ]),
        upstreams: ["10.103.0.1"]
    )
    #expect(try restoredEffectiveServersMatch(
        [dynamic],
        effective: ["192.168.1.254", "2600:1700:2f70:ce40::1"]
    ))
    #expect(try !restoredEffectiveServersMatch([dynamic], effective: ["127.0.0.1"]))
    #expect(try !restoredEffectiveServersMatch([dynamic], effective: []))
}

@Test
func activationStorageKeepsPublicProductAncestorsTraversable() {
    #expect(activationDirectoryPermissions(URL(
        fileURLWithPath: "/Library/Application Support/Agenxy",
        isDirectory: true
    )) == 0o755)
    #expect(activationDirectoryPermissions(URL(
        fileURLWithPath: "/Library/Application Support/Agenxy/Remap",
        isDirectory: true
    )) == 0o711)
    #expect(activationDirectoryPermissions(URL(
        fileURLWithPath: "/Library/Application Support/Agenxy/Other",
        isDirectory: true
    )) == 0o700)
}

private func activeRecord(service: DNSServiceRecord) throws -> ActivationRecord {
    let payload = ActivationPayload(
        ownerUID: 501,
        createdAtMilliseconds: 1,
        productVersion: "0.1.0",
        phase: .active,
        services: [service]
    )
    return try ActivationRecord(payload: payload)
}

@Test
func activationIntegrityCoversEveryRecoveryField() throws {
    let service = DNSServiceRecord(
        serviceID: "service-1",
        priorConfiguration: Data([1, 2, 3]),
        priorEnabled: false,
        installedConfiguration: Data([4, 5, 6]),
        upstreams: ["192.0.2.53"]
    )
    let payload = ActivationPayload(
        ownerUID: 501,
        createdAtMilliseconds: 1_786_000_000_000,
        productVersion: "0.1.0",
        phase: .prepared,
        services: [service]
    )
    let record = try ActivationRecord(payload: payload)
    try record.verify()
    let active = try ActivationRecord(payload: payload.withPhase(.active))
    #expect(record.sha256 != active.sha256)
    #expect(active.payload.phase == .active)
    let enabled = DNSServiceRecord(
        serviceID: service.serviceID,
        priorConfiguration: service.priorConfiguration,
        priorEnabled: true,
        installedConfiguration: service.installedConfiguration,
        upstreams: service.upstreams
    )
    let enabledRecord = try activeRecord(service: enabled)
    #expect(enabledRecord.sha256 != active.sha256)
}

@Test
func propertyListComparisonIgnoresDictionaryOrdering() throws {
    let first: [String: Any] = ["ServerAddresses": ["127.0.0.1"], "SearchDomains": ["test"]]
    let second: [String: Any] = ["SearchDomains": ["test"], "ServerAddresses": ["127.0.0.1"]]
    let encoded = try PropertyLists.encode(second)
    #expect(try PropertyLists.equal(first, encoded: encoded))
}

@Test
func protocolPreferencePreservesTheEnabledStateExplicitly() {
    let configuration: [String: Any] = ["ServerAddresses": ["127.0.0.1"]]
    let active = protocolPreferenceValue(configuration: configuration, enabled: true)
    #expect(active?["__INACTIVE__"] == nil)
    #expect(active?["ServerAddresses"] as? [String] == ["127.0.0.1"])

    let inactive = protocolPreferenceValue(configuration: configuration, enabled: false)
    #expect(inactive?["__INACTIVE__"] as? Int == 1)
    #expect(protocolPreferenceValue(configuration: nil, enabled: false) == nil)
    #expect(protocolPreferenceValue(configuration: nil, enabled: true)?.isEmpty == true)
}

@Test
func planDeduplicatesAndPreservesUpstreamPreference() {
    let plan = DNSPlan(services: [
        DNSServicePlan(serviceID: "b", upstreams: ["203.0.113.2", "203.0.113.1"]),
        DNSServicePlan(serviceID: "a", upstreams: ["203.0.113.1"])
    ])
    #expect(plan.upstreams == ["203.0.113.2", "203.0.113.1"])
}

@Test
func serverAddressesPreserveResolverPreference() {
    let configuration: [String: Any] = [
        "ServerAddresses": ["203.0.113.2", "203.0.113.1", "203.0.113.2"]
    ]
    #expect(serverAddresses(from: configuration) == ["203.0.113.2", "203.0.113.1"])
}

@Test
func sourceBackendRejectsFlattenedSplitDnsScopes() throws {
    let one = DNSServicePlan(serviceID: "wifi", upstreams: ["192.0.2.53"])
    #expect(try validatedPlan([one]) == DNSPlan(services: [one]))
    #expect(throws: ResolverError.unsupportedResolverScope(2)) {
        try validatedPlan([
            one,
            DNSServicePlan(serviceID: "vpn", upstreams: ["198.51.100.53"])
        ])
    }
}

@Test
func effectiveConfigurationVerificationRetainsLoopbackServers() {
    let configuration: [String: Any] = ["ServerAddresses": ["127.0.0.1"]]
    #expect(serverAddresses(from: configuration) == ["127.0.0.1"])
}

@Test
func effectiveRemapServiceRequiresBothPersistedAndGlobalLoopbackState() {
    let configured = [
        "wifi": ["127.0.0.1"],
        "ethernet": ["192.0.2.53"]
    ]
    #expect(effectiveRemapServiceIDs(
        activeServiceIDs: ["ethernet", "wifi"],
        configuredServerAddresses: configured,
        effectiveServerAddresses: ["127.0.0.1"]
    ) == ["wifi"])
    #expect(effectiveRemapServiceIDs(
        activeServiceIDs: ["wifi"],
        configuredServerAddresses: configured,
        effectiveServerAddresses: ["10.103.0.1"]
    ).isEmpty)
    #expect(effectiveRemapServiceIDs(
        activeServiceIDs: ["wifi"],
        configuredServerAddresses: ["wifi": ["10.103.0.1"]],
        effectiveServerAddresses: ["127.0.0.1"]
    ).isEmpty)
}

@Test
func listenerProbeUsesBoundedDnsWireFormat() {
    let identifier: UInt16 = 0xBEEF
    let query = DNSListenerProbe.makeQuery(identifier: identifier, nonce: "abc123")
    #expect(query.count < 512)
    #expect(query[0] == 0xBE)
    #expect(query[1] == 0xEF)
    #expect(query.suffix(4) == Data([0, 1, 0, 1]))
}

@Test
func listenerProbeValidatesIdentityAndResponseShape() {
    let identifier: UInt16 = 0x1234
    let response = Data([
        0x12, 0x34, 0x81, 0x83, 0, 1, 0, 0, 0, 0, 0, 0
    ])
    #expect(DNSListenerProbe.validates(response: response, identifier: identifier))
    #expect(!DNSListenerProbe.validates(response: response, identifier: 0x4321))
    #expect(!DNSListenerProbe.validates(response: response.dropLast(), identifier: identifier))
}
