// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
@testable import RemapSystemKit
import Synchronization
import Testing

private let wifi = "wifi"
private let tether = "iphone-usb"
private let wifiResolver = "192.168.1.1"
private let tetherResolver = "172.20.10.1"

@Test
func remapFollowsWiFiToATetheredServiceAndKeepsItsActivation() async throws {
    let mac = try ActivatedMac()
    mac.network.setUp(wifi, false)
    mac.network.setUp(tether, true)

    try await mac.reconciler().reconcile()

    try mac.expectActive(on: tether, resolver: tetherResolver, generation: 2)
    #expect(try mac.network.snapshot().globalServers == [loopbackResolver])
}

@Test
func remapFollowsATetheredServiceBackToWiFi() async throws {
    let mac = try ActivatedMac()
    mac.network.setUp(wifi, false)
    mac.network.setUp(tether, true)
    let reconciler = mac.reconciler()
    try await reconciler.reconcile()

    mac.network.setUp(tether, false)
    mac.network.setUp(wifi, true)
    try await reconciler.reconcile()

    try mac.expectActive(on: wifi, resolver: wifiResolver, generation: 3)
}

@Test
func twoServicesWithUsableDNSAreRefusedAndNothingChanges() async throws {
    let mac = try ActivatedMac()
    mac.network.setUp(tether, true)
    let before = mac.store.current

    await #expect(throws: ResolverError.unsupportedResolverScope(2)) {
        try await mac.reconciler().reconcile()
    }
    #expect(mac.store.current == before)
    #expect(try mac.network.loopbackServiceIDs() == [wifi])
    #expect(mac.daemon.snapshot().publications == [1])
}

@Test
func twoUsableServicesBypassPromptlyAndRecordWhy() async throws {
    let mac = try ActivatedMac()
    mac.network.setUp(tether, true)
    let log = HandoffBypassLog()
    let monitor = QuietResolverMonitor()
    let supervisor = ResolverSupervisor(
        reconciler: mac.reconciler(),
        monitor: monitor,
        interval: .milliseconds(5),
        retryInterval: .milliseconds(1),
        failureGrace: .seconds(3600),
        bypassLog: log
    )
    let task = Task { await supervisor.run() }
    try await eventually { !log.payloads().isEmpty }
    task.cancel()
    await task.value
    monitor.finish()

    #expect(log.payloads().first?.reasonCode == "E_RESOLVER_PLAN")
    #expect(log.payloads().first?.outcomeCode == "E_RESOLVER_SAFE_BYPASS")
    #expect(try mac.network.loopbackServiceIDs().isEmpty)
    #expect(mac.store.current?.payload.phase == .prepared)
}

@Test
func aUserChangeToTheServiceBeingLeftIsReportedAndNotOverwritten() async throws {
    let mac = try ActivatedMac()
    try mac.network.userSets(wifi, servers: ["9.9.9.9"])
    mac.network.setUp(wifi, false)
    mac.network.setUp(tether, true)
    let before = mac.store.current

    await #expect(throws: ResolverError.configurationConflict([wifi])) {
        try await mac.reconciler().reconcile()
    }
    let edited = try #require(mac.network.service(wifi)?.persisted)
    #expect(try serverAddresses(from: PropertyLists.decode(edited)) == ["9.9.9.9"])
    #expect(mac.network.service(tether)?.persisted == nil)
    #expect(mac.store.current == before)
    #expect(mac.daemon.snapshot().publications == [1])
}

@Test
func deactivatingAfterAHandoffRestoresBothServices() async throws {
    let mac = try ActivatedMac()
    mac.network.setUp(wifi, false)
    mac.network.setUp(tether, true)
    try await mac.reconciler().reconcile()

    try mac.configurator.restoreOrdinaryDNS(retainPreparedRecord: false)

    #expect(mac.network.service(wifi)?.persisted == nil)
    #expect(mac.network.service(tether)?.persisted == nil)
    #expect(mac.store.current == nil)
}

@Test
func deactivatingInTheMiddleOfAHandoffRestoresEveryServiceRemapChanged() async throws {
    for fault in [ResolverTestNetwork.Fault.preflight, .applyFailed] {
        let mac = try ActivatedMac()
        mac.network.setUp(wifi, false)
        mac.network.setUp(tether, true)
        mac.network.update { $0.faults = [fault] }
        await #expect(throws: (any Error).self) { try await mac.reconciler().reconcile() }
        #expect(mac.store.current?.payload.services.count == 2)
        mac.network.update { $0.faults = [] }

        try mac.configurator.restoreOrdinaryDNS(retainPreparedRecord: false)

        #expect(try mac.network.loopbackServiceIDs().isEmpty)
        #expect(mac.network.service(wifi)?.persisted == nil)
        #expect(mac.network.service(tether)?.persisted == nil)
        #expect(mac.store.current == nil)
    }
}

/// Every step of the handoff is interrupted in turn. Afterwards exactly one
/// service, the one being left or the target, points at loopback, the
/// daemon holds a published plan, and the record lists that service. A
/// restarted reconciler then completes the handoff.
@Test(arguments: HandoffInterruption.allCases)
func anInterruptedHandoffLeavesOneArmedServiceAndCompletesOnTheNextReconcile(
    _ interruption: HandoffInterruption
) async throws {
    let mac = try ActivatedMac()
    mac.network.setUp(wifi, false)
    mac.network.setUp(tether, true)
    interruption.inject(into: mac)

    await #expect(throws: (any Error).self) { try await mac.reconciler().reconcile() }

    let armed = try mac.network.loopbackServiceIDs()
    #expect(armed == [interruption.armedService])
    #expect(mac.daemon.snapshot().activeGeneration != nil)
    #expect(mac.daemon.snapshot().activationID == mac.identity)
    // The tethered service never points at loopback before its own plan is
    // published; Wi-Fi, which is down, may already be serving the new plan.
    let served = mac.daemon.snapshot().publishedUpstreams
    if armed == [tether] {
        #expect(served == ["\(tetherResolver):53"])
    } else {
        #expect(served == ["\(wifiResolver):53"] || served == ["\(tetherResolver):53"])
    }
    let owned = mac.store.current?.payload.services.map(\.serviceID) ?? []
    #expect(armed.allSatisfy(owned.contains))

    mac.clearFaults()
    try await mac.reconciler().reconcile()
    try mac.expectActive(on: tether, resolver: tetherResolver)
}

@Test
func aRecordFromBeforeStableIdentityKeepsItsIdentityAcrossAHandoff() async throws {
    let mac = try ActivatedMac(stableIdentity: false)
    let derived = mac.identity
    #expect(mac.store.current?.payload.activationID == nil)
    mac.network.setUp(wifi, false)
    mac.network.setUp(tether, true)

    try await mac.reconciler().reconcile()

    #expect(mac.store.current?.payload.activationID == derived)
    #expect(try mac.store.current?.activationIdentifier() == derived)
    #expect(mac.daemon.snapshot().activationID == derived)
}

@Test
func activationIdentityIsStableAcrossServicesAndPhasesWhenRecorded() throws {
    let identity = UUID()
    let first = try healingRecord(createdAt: 1)
    let carried = try ActivationRecord(payload: ActivationPayload(
        ownerUID: 501,
        createdAtMilliseconds: 1,
        productVersion: "0.2.0",
        phase: .prepared,
        services: first.payload.services,
        activationID: identity
    ))
    let moved = try ActivationRecord(payload: carried.payload.replacing(
        services: [DNSServiceRecord(
            serviceID: "another",
            priorConfiguration: nil,
            installedConfiguration: Data(),
            upstreams: ["198.51.100.53"]
        )],
        phase: .active,
        activationID: identity,
        handoffTargetServiceID: nil
    ))
    #expect(try carried.activationIdentifier() == identity)
    #expect(try moved.activationIdentifier() == identity)
    #expect(moved.sha256 != carried.sha256)
    // An older record has no identity field, so its digest and its derived
    // identity are exactly what they were before the field existed.
    let encoded = try String(data: CanonicalJSON.encoder.encode(first.payload), encoding: .utf8)
    #expect(encoded?.contains("activationID") == false)
    #expect(encoded?.contains("handoffTargetServiceID") == false)
    #expect(try first.activationIdentifier() != identity)
}

@Test
func aHandoffMarkerOutsideAnActiveTwoServiceRecordIsRejected() throws {
    let base = try healingRecord(phase: .prepared)
    let stray = try ActivationRecord(payload: ActivationPayload(
        ownerUID: 501,
        createdAtMilliseconds: 1,
        productVersion: "0.2.0",
        phase: .prepared,
        services: base.payload.services,
        activationID: UUID(),
        handoffTargetServiceID: "service-a"
    ))
    #expect(throws: ResolverError.invalidActivationRecord) { try stray.verify() }
    let unknown = try ActivationRecord(payload: base.payload.withPhase(.active).replacing(
        services: base.payload.services,
        phase: .active,
        activationID: UUID(),
        handoffTargetServiceID: "absent"
    ))
    #expect(throws: ResolverError.invalidActivationRecord) { try unknown.verify() }
}

@Test
func aServiceAlreadyPointingAtLoopbackIsNeverCapturedAsAPriorState() throws {
    let service = try ObservedNetworkService(
        serviceID: tether,
        configuration: PropertyLists.encode(["ServerAddresses": [loopbackResolver]]),
        enabled: true,
        effectiveServers: [loopbackResolver],
        dhcpServers: [tetherResolver],
        networkSignature: nil
    )
    #expect(throws: ResolverError.configurationConflict([tether])) {
        try capturedService(service, upstreams: [tetherResolver])
    }
}

enum HandoffInterruption: CaseIterable, CustomTestStringConvertible, Sendable {
    case recordCapture
    case publication
    case loopbackPreflight
    case commitRefused
    case applyFailed
    case verification
    case recordConvergence

    var testDescription: String {
        String(describing: self)
    }

    /// The one service that may point at loopback after this interruption.
    var armedService: String {
        switch self {
        case .recordCapture, .publication, .loopbackPreflight, .commitRefused:
            wifi
        case .applyFailed, .verification, .recordConvergence:
            tether
        }
    }

    func inject(into mac: ActivatedMac) {
        switch self {
        case .recordCapture:
            mac.store.failWrite(1)
        case .publication:
            mac.daemon.update { $0.refusesPublication = true }
        case .loopbackPreflight:
            mac.network.update { $0.faults = [.preflight] }
        case .commitRefused:
            mac.network.update { $0.faults = [.commitRefused] }
        case .applyFailed:
            mac.network.update { $0.faults = [.applyFailed] }
        case .verification:
            mac.network.update { $0.faults = [.verificationStale] }
        case .recordConvergence:
            mac.store.failWrite(2)
        }
    }
}

/// A Mac whose Wi-Fi was activated through Remap: Wi-Fi points at loopback,
/// the daemon holds generation one for the activation, and the iPhone USB
/// service exists but is not connected.
final class ActivatedMac: Sendable {
    let network: ResolverTestNetwork
    let store: ResolverTestRecordStore
    let daemon: ResolverTestDaemon
    let identity: UUID

    var configurator: NativeResolverConfigurator {
        NativeResolverConfigurator(
            network: network,
            store: store,
            verificationTimeout: 0,
            verificationInterval: 0
        )
    }

    init(stableIdentity: Bool = true) throws {
        network = ResolverTestNetwork([
            .init(serviceID: wifi, connected: true, dhcp: [wifiResolver]),
            .init(serviceID: tether, connected: false, dhcp: [tetherResolver])
        ])
        guard let observed = try network.snapshot().service(wifi) else {
            throw ResolverError.noUsableUpstream
        }
        let captured = try capturedService(observed, upstreams: [wifiResolver])
        let record = try ActivationRecord(payload: ActivationPayload(
            ownerUID: 501,
            createdAtMilliseconds: 1,
            productVersion: "0.2.0",
            phase: .active,
            services: [captured],
            activationID: stableIdentity ? UUID() : nil
        ))
        identity = try record.activationIdentifier()
        store = ResolverTestRecordStore(record)
        daemon = ResolverTestDaemon(ResolverTestDaemon.State(
            activationID: identity,
            activeGeneration: 1,
            highestGeneration: 1,
            publications: [1],
            publishedUpstreams: ["\(wifiResolver):53"]
        ))
        let installed = captured.installedConfiguration
        network.update { state in
            state.services[0].persisted = installed
            state.services[0].applied = installed
        }
    }

    func reconciler() -> ResolverReconciler {
        let configurator = configurator
        return ResolverReconciler(
            channel: daemon,
            loadRecord: { [store] in store.current },
            makePlan: { record in try configurator.recordedPlan(record: record) },
            restoreSystemDNS: {
                if (try? configurator.store.read()) != nil {
                    try configurator.restoreOrdinaryDNS(retainPreparedRecord: true)
                }
            },
            handOff: { record, publish in
                try configurator.handOffIfNeeded(record: record, publish: publish)
            }
        )
    }

    func clearFaults() {
        store.clearFailures()
        network.update { $0.faults = [] }
        daemon.update { $0.refusesPublication = false }
    }

    func expectActive(on serviceID: String, resolver: String, generation: UInt64? = nil) throws {
        let record = try #require(store.current)
        #expect(record.payload.phase == .active)
        #expect(record.payload.services.map(\.serviceID) == [serviceID])
        #expect(record.payload.handoffTargetServiceID == nil)
        #expect(try record.activationIdentifier() == identity)
        #expect(try network.loopbackServiceIDs() == [serviceID])
        let other = serviceID == wifi ? tether : wifi
        #expect(network.service(other)?.persisted == nil)
        #expect(daemon.snapshot().activationID == identity)
        #expect(daemon.snapshot().publishedUpstreams == ["\(resolver):53"])
        if let generation {
            #expect(daemon.snapshot().activeGeneration == generation)
        }
    }
}

final class HandoffBypassLog: ResolverBypassRecording, Sendable {
    private let recorded = Mutex<[ResolverBypassPayload]>([])

    func record(_ payload: ResolverBypassPayload) {
        recorded.withLock { $0.append(payload) }
    }

    func lastBypass() -> ResolverBypassPayload? {
        recorded.withLock(\.last)
    }

    func payloads() -> [ResolverBypassPayload] {
        recorded.withLock { $0 }
    }
}
