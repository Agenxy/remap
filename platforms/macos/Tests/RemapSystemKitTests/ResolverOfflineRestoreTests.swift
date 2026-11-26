// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
@testable import RemapSystemKit
import Testing

private let wifi = "wifi"

@Test
func restoringWithNoConnectedServiceSucceedsOnceTheCapturedConfigurationIsBack() throws {
    let mac = try ActivatedMac()
    mac.network.setUp(wifi, false)
    #expect(try mac.network.snapshot().globalServers.isEmpty)

    try mac.configurator.restoreOrdinaryDNS(retainPreparedRecord: true)

    #expect(mac.network.service(wifi)?.persisted == nil)
    #expect(try mac.network.loopbackServiceIDs().isEmpty)
    #expect(mac.store.current?.payload.phase == .prepared)
}

@Test
func aSafeBypassWhileFullyOfflineIsReportedAsABypassNotAFailure() async throws {
    let mac = try ActivatedMac()
    mac.network.setUp(wifi, false)
    let log = HandoffBypassLog()
    let monitor = QuietResolverMonitor()
    let supervisor = ResolverSupervisor(
        reconciler: mac.reconciler(),
        monitor: monitor,
        interval: .milliseconds(5),
        retryInterval: .milliseconds(1),
        failureGrace: .zero,
        bypassLog: log
    )
    let task = Task { await supervisor.run() }
    try await eventually { !log.payloads().isEmpty }
    task.cancel()
    await task.value
    monitor.finish()

    #expect(log.payloads().first?.reasonCode == "E_RESOLVER_NETWORK_UNOBSERVED")
    #expect(log.payloads().first?.outcomeCode == "E_RESOLVER_SAFE_BYPASS")
    #expect(try mac.network.loopbackServiceIDs().isEmpty)
    #expect(mac.store.current?.payload.phase == .prepared)
}

/// The offline allowance covers only an empty global resolver with nothing
/// connected. Loopback in the global view, or an empty view while an owned
/// service is up, is still not a restored state.
@Test
func theOfflineAllowanceDoesNotAcceptAnyOtherGlobalResolver() throws {
    let prior = try PropertyLists.encode(["ServerAddresses": ["9.9.9.9"]])
    let record = try DNSServiceRecord(
        serviceID: wifi,
        priorConfiguration: prior,
        priorEnabled: true,
        installedConfiguration: PropertyLists.encode(["ServerAddresses": [loopbackResolver]]),
        upstreams: ["9.9.9.9"]
    )
    func snapshot(connected: Bool, global: [String]) -> NetworkSnapshot {
        NetworkSnapshot(
            services: [ObservedNetworkService(
                serviceID: wifi,
                configuration: prior,
                enabled: true,
                effectiveServers: connected ? ["9.9.9.9"] : nil,
                dhcpServers: [],
                networkSignature: nil
            )],
            globalServers: global
        )
    }
    #expect(try restoredGlobalResolverMatches([record], snapshot: snapshot(connected: false, global: [])))
    #expect(try !restoredGlobalResolverMatches(
        [record],
        snapshot: snapshot(connected: false, global: [loopbackResolver])
    ))
    #expect(try !restoredGlobalResolverMatches([record], snapshot: snapshot(connected: true, global: [])))
    #expect(try restoredGlobalResolverMatches([record], snapshot: snapshot(connected: true, global: ["9.9.9.9"])))
}
