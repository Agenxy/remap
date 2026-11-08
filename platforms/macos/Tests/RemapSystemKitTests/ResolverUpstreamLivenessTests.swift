// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
@testable import RemapSystemKit
import Testing

// ADR-0036. When the daemon reports that every upstream it forwards to has
// stopped answering, Remap restores ordinary DNS at once, never reports ready
// over those upstreams, and re-arms only once they, or a different set, answer.

private let wifi = "wifi"
private let routerResolver = "192.168.1.1"
private let routerUpstream = "\(routerResolver):53"

@Test
func upstreamsThatStopAnsweringRestoreOrdinaryDNSAtOnce() async throws {
    let mac = try ActivatedMac()
    mac.daemon.update { $0.unansweredUpstreams = [routerUpstream] }
    // An hour of grace would hold an unobserved network; this is a fault.
    let run = SupervisedMac(mac, failureGrace: .seconds(3600))

    try await eventually { !run.log.payloads().isEmpty }
    await run.stop()

    let bypass = try #require(run.log.payloads().first)
    #expect(bypass.reasonCode == "E_RESOLVER_UPSTREAM_UNANSWERED")
    #expect(bypass.outcomeCode == "E_RESOLVER_SAFE_BYPASS")
    #expect(try mac.network.loopbackServiceIDs().isEmpty)
    #expect(mac.store.current?.payload.phase == .prepared)
    #expect(!run.states().contains(.ready))
    #expect(run.states().prefix(2) == [
        .degraded(code: "E_RESOLVER_UPSTREAM_UNANSWERED"),
        .bypassed(code: "E_RESOLVER_SAFE_BYPASS")
    ])
}

@Test
func remapReArmsOnlyOnceTheUpstreamsAnswerAgain() async throws {
    let mac = try ActivatedMac()
    mac.daemon.update { $0.unansweredUpstreams = [routerUpstream] }
    let run = SupervisedMac(mac)
    try await eventually { !run.log.payloads().isEmpty }
    let commits = mac.network.commitCount
    let publications = mac.daemon.snapshot().publications.count

    // Many healthy probes and re-arm attempts pass; each republishes the same
    // set, sees the verdict, and commits nothing.
    try await eventually { mac.daemon.snapshot().publications.count >= publications + 5 }
    #expect(mac.network.commitCount == commits)
    #expect(try mac.network.loopbackServiceIDs().isEmpty)
    #expect(mac.store.current?.payload.phase == .prepared)

    mac.daemon.update { $0.unansweredUpstreams = nil }
    try await eventually { run.states().last == .ready }
    await run.stop()

    #expect(try mac.network.loopbackServiceIDs() == [wifi])
    #expect(mac.store.current?.payload.phase == .active)
    #expect(run.log.payloads().last?.rearmedAtMilliseconds != nil)
}

@Test
func aDifferentUpstreamSetIsNotHeldToTheVerdictOfTheOldOne() async throws {
    let mac = try ActivatedMac()
    mac.daemon.update { $0.unansweredUpstreams = [routerUpstream] }
    let run = SupervisedMac(mac)
    try await eventually { !run.log.payloads().isEmpty }

    // Wi-Fi's lease now names another resolver, as a different network does.
    mac.network.update { $0.services[0].dhcp = ["192.168.50.1"] }
    try await eventually { run.states().last == .ready }
    await run.stop()

    #expect(mac.daemon.snapshot().publishedUpstreams == ["192.168.50.1:53"])
    #expect(try mac.network.loopbackServiceIDs() == [wifi])
}

@Test
func reconcilingOverUnansweredUpstreamsNeverCommitsAPreparedActivation() async throws {
    let mac = try ActivatedMac()
    try mac.configurator.restoreOrdinaryDNS(retainPreparedRecord: true)
    mac.daemon.update { $0.unansweredUpstreams = [routerUpstream] }
    let commits = mac.network.commitCount

    await #expect(throws: ResolverUpstreamsUnanswered.self) {
        try await mac.supervisingReconciler().reconcile()
    }

    #expect(mac.network.commitCount == commits)
    #expect(mac.store.current?.payload.phase == .prepared)
}

@Test
func theUpstreamVerdictDecodesAndIsAbsentFromAnOlderDaemon() throws {
    let older = try JSONDecoder().decode(
        ResolverSystemResult.self,
        from: Data(#"{"activation_id":null,"active_generation":3}"#.utf8)
    )
    #expect(older.upstreamFailure == nil)
    let current = try JSONDecoder().decode(
        ResolverSystemResult.self,
        from: Data(#"""
        {"activation_id":null,"active_generation":3,
         "upstream_failure":{"cause":"refused","unanswered_queries":5,"unanswered_for_ms":4000}}
        """#.utf8)
    )
    #expect(current.upstreamFailure == ResolverUpstreamFailure(
        cause: "refused",
        unansweredQueries: 5,
        unansweredForMilliseconds: 4000
    ))
    let unanswered = try ResolverUpstreamsUnanswered(failure: #require(current.upstreamFailure))
    #expect(unanswered.description.contains("refused the queries"))
}

@Test
func statusExplainsAFallbackForUnansweredUpstreams() {
    let bypass = ResolverBypassPayload(
        reasonCode: "E_RESOLVER_UPSTREAM_UNANSWERED",
        outcomeCode: "E_RESOLVER_SAFE_BYPASS",
        failingSinceMilliseconds: 1_793_000_000_000,
        bypassedAtMilliseconds: 1_793_000_000_100,
        releasePending: false,
        unreleasedActivationID: nil
    )
    let lines = NativeResolverStatus(record: nil, bypass: bypass, bypassError: nil).bypassLines()
    #expect(lines.contains { $0.contains("Meaning     upstream DNS not answering") })
    #expect(lines.contains { $0.contains("VPN") })
}
