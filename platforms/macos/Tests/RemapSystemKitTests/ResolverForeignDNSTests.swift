// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
@testable import RemapSystemKit
import Synchronization
import Testing

// ADR-0036. A VPN or another agent changes DNS while Remap is active. Remap
// follows the resolver macOS actually uses, never writes over a value it did
// not write, and when it cannot be on the path it writes nothing and says why.

private let wifi = "wifi"
private let vpn = "vpn-tunnel"
private let routerResolver = "192.168.1.1"
private let vpnResolver = "10.0.0.243"

@Test
func aVPNsDNSOnAServiceRemapOwnsBecomesTheUpstreamWithoutAWrite() async throws {
    let mac = try ActivatedMac()
    // The VPN publishes its resolver for Wi-Fi in the dynamic store; Remap's
    // persisted loopback still decides the resolver macOS uses.
    mac.network.update { $0.overridePrecedence = .persisted }
    mac.network.agentOverrides(wifi, servers: [vpnResolver])
    let reconciler = mac.supervisingReconciler()

    try await reconciler.reconcile()

    #expect(mac.daemon.snapshot().publishedUpstreams == ["\(vpnResolver):53"])
    #expect(try mac.network.snapshot().globalServers == [loopbackResolver])
    // The VPN re-asserts its DNS again and again: Remap never answers with a write.
    for servers in [[vpnResolver], [vpnResolver, "10.0.0.242"], [vpnResolver]] {
        mac.network.agentOverrides(wifi, servers: servers)
        try await reconciler.reconcile()
    }
    #expect(mac.network.commitCount == 0)
    #expect(mac.daemon.snapshot().publishedUpstreams == ["\(vpnResolver):53"])

    // Disconnecting withdraws the VPN's DNS and Remap follows the router again.
    mac.network.agentOverrides(wifi, servers: nil)
    try await reconciler.reconcile()

    #expect(mac.daemon.snapshot().publishedUpstreams == ["\(routerResolver):53"])
    #expect(mac.network.commitCount == 0)
    #expect(try mac.network.loopbackServiceIDs() == [wifi])
}

@Test
func aVPNWhoseDNSOutranksRemapsIsDeferredToWithoutAWriteWar() async throws {
    let mac = try ActivatedMac()
    let before = mac.store.current
    mac.network.agentOverrides(wifi, servers: [vpnResolver])
    let reconciler = mac.supervisingReconciler()

    await #expect(throws: ResolverDeferral.resolverHeldElsewhere) { try await reconciler.reconcile() }

    // Every other lookup already goes to the VPN's resolver; one that still
    // reaches Remap goes there too.
    #expect(mac.daemon.snapshot().publishedUpstreams == ["\(vpnResolver):53"])
    for _ in 0 ..< 10 {
        mac.network.agentOverrides(wifi, servers: [vpnResolver])
        await #expect(throws: ResolverDeferral.resolverHeldElsewhere) { try await reconciler.reconcile() }
    }
    #expect(mac.network.commitCount == 0)
    #expect(mac.store.current == before)
    #expect(try mac.network.loopbackServiceIDs() == [wifi])

    mac.network.agentOverrides(wifi, servers: nil)
    try await reconciler.reconcile()

    #expect(try mac.network.snapshot().globalServers == [loopbackResolver])
    #expect(mac.daemon.snapshot().publishedUpstreams == ["\(routerResolver):53"])
    #expect(mac.network.commitCount == 0)
}

@Test
func theSupervisorDefersToAVPNWithoutABypassAndReturnsWhenItLetsGo() async throws {
    let mac = try ActivatedMac()
    mac.network.agentOverrides(wifi, servers: [vpnResolver])
    let run = SupervisedMac(mac)

    try await eventually { run.states().contains(.deferred(code: "E_RESOLVER_HELD_ELSEWHERE")) }
    mac.network.agentOverrides(wifi, servers: nil)
    try await eventually { run.states().last == .ready }
    await run.stop()

    #expect(run.states() == [.deferred(code: "E_RESOLVER_HELD_ELSEWHERE"), .ready])
    #expect(run.log.payloads().isEmpty)
    #expect(mac.network.commitCount == 0)
}

@Test
func remapFollowsAVPNsOwnServiceWhenMacOSUsesItAndFollowsItBack() async throws {
    let mac = try ActivatedMac()
    // The VPN's service is first in service order, so macOS resolves through
    // it; Wi-Fi keeps its own usable resolver beside it.
    mac.network.update { state in
        state.services.insert(.init(serviceID: vpn, connected: true, dhcp: [vpnResolver]), at: 0)
    }
    let reconciler = mac.supervisingReconciler()

    try await reconciler.reconcile()

    #expect(mac.store.current?.payload.services.map(\.serviceID) == [vpn])
    #expect(try mac.network.loopbackServiceIDs() == [vpn])
    #expect(mac.network.service(wifi)?.persisted == nil)
    #expect(mac.daemon.snapshot().publishedUpstreams == ["\(vpnResolver):53"])
    #expect(try mac.network.snapshot().globalServers == [loopbackResolver])
    let settled = (mac.network.commitCount, mac.daemon.snapshot().publications)
    try await reconciler.reconcile()
    #expect((mac.network.commitCount, mac.daemon.snapshot().publications) == settled)

    mac.network.setUp(vpn, false)
    try await reconciler.reconcile()

    #expect(mac.store.current?.payload.services.map(\.serviceID) == [wifi])
    #expect(try mac.network.loopbackServiceIDs() == [wifi])
    #expect(mac.network.service(vpn)?.persisted == nil)
    #expect(mac.daemon.snapshot().publishedUpstreams == ["\(routerResolver):53"])
    #expect(try mac.store.current?.activationIdentifier() == mac.identity)

    try mac.configurator.restoreOrdinaryDNS(retainPreparedRecord: false)
    #expect(try mac.network.loopbackServiceIDs().isEmpty)
}

@Test
func aSecondServiceBesideTheResolverRemapHoldsIsNotSplitDNS() async throws {
    let mac = try ActivatedMac()
    mac.network.setUp("iphone-usb", true)
    let before = mac.store.current

    try await mac.supervisingReconciler().reconcile()

    #expect(mac.store.current == before)
    #expect(try mac.network.loopbackServiceIDs() == [wifi])
    #expect(mac.network.commitCount == 0)
}

@Test
func aVPNTunnelOutsideThePreferencesIsDeferredToActiveOrBypassed() async throws {
    let mac = try ActivatedMac()
    mac.network.update { $0.outsideService = (serviceID: "utun-vpn", servers: [vpnResolver]) }

    await #expect(throws: ResolverDeferral.resolverHeldElsewhere) {
        try await mac.supervisingReconciler().reconcile()
    }
    #expect(mac.network.commitCount == 0)
    #expect(mac.daemon.snapshot().publishedUpstreams == ["\(vpnResolver):53"])

    // Bypassed, Remap does not re-arm under a resolver it cannot configure.
    try mac.configurator.restoreOrdinaryDNS(retainPreparedRecord: true)
    let restored = mac.network.commitCount
    await #expect(throws: ResolverDeferral.resolverHeldElsewhere) {
        try await mac.supervisingReconciler().reconcile()
    }
    #expect(mac.network.commitCount == restored)
    #expect(mac.store.current?.payload.phase == .prepared)

    mac.network.update { $0.outsideService = nil }
    try await mac.supervisingReconciler().reconcile()
    #expect(mac.store.current?.payload.phase == .active)
    #expect(try mac.network.loopbackServiceIDs() == [wifi])
}

@Test
func aForeignChangeToAServiceRemapOwnsIsLeftInPlaceUntilItsAgentRestoresRemaps() async throws {
    let mac = try ActivatedMac()
    let installed = try #require(mac.network.service(wifi)?.persisted)
    // The VPN rewrites Wi-Fi's persisted DNS, saving what it replaced.
    try mac.network.userSets(wifi, servers: [vpnResolver])
    let run = SupervisedMac(mac)

    try await eventually { run.states().contains(.deferred(code: "E_RESOLVER_DNS_CHANGED_ELSEWHERE")) }
    #expect(mac.daemon.snapshot().publishedUpstreams == ["\(vpnResolver):53"])
    #expect(run.log.payloads().isEmpty)
    #expect(mac.network.commitCount == 0)

    // Disconnecting, the VPN restores the configuration it saved: Remap's.
    mac.network.update { state in
        state.services[0].persisted = installed
        state.services[0].applied = installed
    }
    try await eventually { run.states().last == .ready }
    await run.stop()

    #expect(mac.daemon.snapshot().publishedUpstreams == ["\(routerResolver):53"])
    #expect(mac.network.commitCount == 0)
    #expect(run.log.payloads().isEmpty)
}

@Test
func reArmingUnderAVPNsDynamicDNSWritesOnceAndThenWaits() async throws {
    let mac = try ActivatedMac()
    try mac.configurator.restoreOrdinaryDNS(retainPreparedRecord: true)
    mac.network.agentOverrides(wifi, servers: [vpnResolver])
    let reconciler = mac.supervisingReconciler()

    await #expect(throws: ResolverDeferral.resolverHeldElsewhere) { try await reconciler.reconcile() }
    let afterCommit = mac.network.commitCount
    for _ in 0 ..< 5 {
        await #expect(throws: ResolverDeferral.resolverHeldElsewhere) { try await reconciler.reconcile() }
    }

    // One commit re-armed Wi-Fi; nothing restored it against the VPN, and
    // nothing was written again while the VPN held the resolver.
    #expect(afterCommit == 2)
    #expect(mac.network.commitCount == afterCommit)
    #expect(mac.store.current?.payload.phase == .active)
    #expect(try mac.network.loopbackServiceIDs() == [wifi])

    mac.network.agentOverrides(wifi, servers: nil)
    try await reconciler.reconcile()
    #expect(try mac.network.snapshot().globalServers == [loopbackResolver])
    #expect(mac.network.commitCount == afterCommit)
}

// Part three of ADR-0036: the prior configuration was captured before the VPN
// connected, and the VPN changed it while Remap was active.

@Test
func restoringNeverOverwritesAVPNsChangeMadeWhileRemapWasActive() throws {
    let mac = try ActivatedMac()
    let installed = try #require(mac.network.service(wifi)?.persisted)
    try mac.network.userSets(wifi, servers: [vpnResolver])
    let vpnConfiguration = mac.network.service(wifi)?.persisted

    #expect(throws: ResolverError.configurationConflict([wifi])) {
        try mac.configurator.restoreOrdinaryDNS(retainPreparedRecord: false)
    }
    #expect(throws: ResolverError.configurationConflict([wifi])) {
        try mac.configurator.restoreOrdinaryDNS(retainPreparedRecord: true)
    }
    #expect(mac.network.service(wifi)?.persisted == vpnConfiguration)
    #expect(mac.network.commitCount == 0)
    #expect(mac.store.current?.payload.phase == .active)

    // Once the VPN disconnects and restores what it saved, Remap's own
    // configuration, deactivation restores the original capture, not the VPN's.
    mac.network.update { state in
        state.services[0].persisted = installed
        state.services[0].applied = installed
    }
    try mac.configurator.restoreOrdinaryDNS(retainPreparedRecord: false)

    #expect(mac.network.service(wifi)?.persisted == nil)
    #expect(try mac.network.snapshot().globalServers == [routerResolver])
    #expect(mac.store.current == nil)
}

@Test
func restoringLeavesAVPNsDynamicDNSInPlace() throws {
    let mac = try ActivatedMac()
    mac.network.agentOverrides(wifi, servers: [vpnResolver])

    try mac.configurator.restoreOrdinaryDNS(retainPreparedRecord: false)

    #expect(mac.network.service(wifi)?.persisted == nil)
    #expect(mac.network.service(wifi)?.override == [vpnResolver])
    #expect(try mac.network.snapshot().globalServers == [vpnResolver])
    #expect(mac.store.current == nil)
}

@Test
func theResolverMacOSUsesIsAttributedToExactlyOneService() {
    func service(_ serviceID: String, _ servers: [String]?) -> ObservedNetworkService {
        ObservedNetworkService(
            serviceID: serviceID,
            configuration: nil,
            enabled: true,
            effectiveServers: servers,
            dhcpServers: [],
            networkSignature: nil
        )
    }
    let twoOnOneRouter = [service("a", [routerResolver]), service("b", [routerResolver])]
    #expect(resolverCarrier(NetworkSnapshot(services: twoOnOneRouter, globalServers: [loopbackResolver])) == .remap)
    #expect(resolverCarrier(NetworkSnapshot(
        services: twoOnOneRouter, globalServers: [routerResolver], primaryServiceID: "b"
    )) == .service("b"))
    #expect(resolverCarrier(NetworkSnapshot(services: twoOnOneRouter, globalServers: [routerResolver]))
        == .unattributed)
    #expect(resolverCarrier(NetworkSnapshot(
        services: twoOnOneRouter, globalServers: [vpnResolver], primaryServiceID: "utun"
    )) == .outsidePreferences)
    #expect(resolverCarrier(NetworkSnapshot(services: [service("a", nil)], globalServers: [])) == .unattributed)
}

extension ActivatedMac {
    /// The root supervisor's reconciler: it hands off, defers, and commits a
    /// prepared record back to SystemConfiguration when it re-arms.
    func supervisingReconciler() -> ResolverReconciler {
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
            commitPreparedDNS: { record in
                if record.payload.phase == .prepared {
                    _ = try configurator.commitPrepared()
                }
            },
            handOff: { record, publish in
                try configurator.handOffIfNeeded(record: record, publish: publish)
            }
        )
    }
}

/// A running root supervisor over an `ActivatedMac`, recording every state
/// and every bypass.
final class SupervisedMac: Sendable {
    let log: HandoffBypassLog
    private let recorder: SupervisorStateRecorder
    private let monitor: QuietResolverMonitor
    private let task: Task<Void, Never>

    init(_ mac: ActivatedMac, failureGrace: Duration = .seconds(3600)) {
        let log = HandoffBypassLog()
        let recorder = SupervisorStateRecorder()
        let monitor = QuietResolverMonitor()
        let supervisor = ResolverSupervisor(
            reconciler: mac.supervisingReconciler(),
            monitor: monitor,
            interval: .milliseconds(2),
            retryInterval: .milliseconds(1),
            failureGrace: failureGrace,
            rearmDamping: promptRearm,
            bypassLog: log,
            observe: { state in recorder.append(state) }
        )
        self.log = log
        self.recorder = recorder
        self.monitor = monitor
        task = Task { await supervisor.run() }
    }

    func states() -> [ResolverSupervisorState] {
        recorder.states()
    }

    func stop() async {
        task.cancel()
        await task.value
        monitor.finish()
    }
}

final class SupervisorStateRecorder: Sendable {
    private let recorded = Mutex<[ResolverSupervisorState]>([])

    func append(_ state: ResolverSupervisorState) {
        recorded.withLock { $0.append(state) }
    }

    func states() -> [ResolverSupervisorState] {
        recorded.withLock { $0 }
    }
}

@Test
func anActiveRecordRestoredByRemapIsCommittedAgainButAForeignResolverIsNotFought() throws {
    // A safe bypass restored Wi-Fi while an installer recorded the activation
    // active again: only Remap's own state is in the way, so it is re-applied.
    let raced = try ActivatedMac()
    let active = try #require(raced.store.current)
    try raced.configurator.restoreOrdinaryDNS(retainPreparedRecord: true)
    try raced.store.replace(active)
    try raced.configurator.reassertActive(record: active)
    #expect(try raced.network.loopbackServiceIDs() == [wifi])
    #expect(try raced.network.snapshot().globalServers == [loopbackResolver])

    // Remap's configuration is in place and macOS still uses a resolver no
    // service accounts for: writing again could only fight it.
    let held = try ActivatedMac()
    held.network.update { $0.unattributedGlobal = [vpnResolver] }
    #expect(throws: ResolverDeferral.resolverHeldElsewhere) {
        try held.configurator.reassertActive(record: #require(held.store.current))
    }
    #expect(held.network.commitCount == 0)
}
