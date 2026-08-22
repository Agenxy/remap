import Foundation
@testable import RemapSystemKit
import Synchronization
import Testing

@Test
func supervisorPollsDaemonHealthAndReportsStateTransitionsOnce() async throws {
    let record = try supervisorRecord()
    let channel = CountingHealthChannel()
    let monitor = TestResolverMonitor()
    let states = Mutex<[ResolverSupervisorState]>([])
    let reconciler = ResolverReconciler(
        channel: channel,
        loadRecord: { record },
        makePlan: { _ in
            DNSPlan(services: [
                DNSServicePlan(serviceID: "service-a", upstreams: ["192.0.2.53"])
            ])
        }
    )
    let supervisor = ResolverSupervisor(
        reconciler: reconciler,
        monitor: monitor,
        interval: .milliseconds(10),
        observe: { state in states.withLock { $0.append(state) } }
    )

    let task = Task { await supervisor.run() }
    try await Task.sleep(for: .milliseconds(35))
    task.cancel()
    await task.value
    monitor.finish()

    #expect(channel.healthCount() >= 2)
    #expect(states.withLock { $0 } == [.ready])
}

@Test
func supervisorKeepsMonitorFailureVisibleWhilePolling() async throws {
    let record = try supervisorRecord()
    let channel = CountingHealthChannel()
    let monitor = TestResolverMonitor(startError: ResolverMonitorError.unavailable)
    let states = Mutex<[ResolverSupervisorState]>([])
    let reconciler = ResolverReconciler(
        channel: channel,
        loadRecord: { record },
        makePlan: { _ in
            DNSPlan(services: [
                DNSServicePlan(serviceID: "service-a", upstreams: ["192.0.2.53"])
            ])
        }
    )
    let supervisor = ResolverSupervisor(
        reconciler: reconciler,
        monitor: monitor,
        interval: .milliseconds(10),
        observe: { state in states.withLock { $0.append(state) } }
    )

    let task = Task { await supervisor.run() }
    try await Task.sleep(for: .milliseconds(25))
    task.cancel()
    await task.value
    monitor.finish()

    #expect(states.withLock { $0 } == [.degraded(code: "E_RESOLVER_MONITOR")])
}

@Test
func supervisorRestoresOrdinaryDNSAfterSustainedChannelFailure() async throws {
    let record = try supervisorRecord()
    let monitor = TestResolverMonitor()
    let states = Mutex<[ResolverSupervisorState]>([])
    let restoreCount = Mutex(0)
    let reconciler = ResolverReconciler(
        channel: FailingResolverChannel(),
        loadRecord: { record },
        makePlan: { _ in
            DNSPlan(services: [
                DNSServicePlan(serviceID: "service-a", upstreams: ["192.0.2.53"])
            ])
        },
        restoreSystemDNS: { restoreCount.withLock { $0 += 1 } }
    )
    let supervisor = ResolverSupervisor(
        reconciler: reconciler,
        monitor: monitor,
        interval: .seconds(60),
        retryInterval: .milliseconds(1),
        maximumConsecutiveFailures: 3,
        observe: { state in states.withLock { $0.append(state) } }
    )

    let task = Task { await supervisor.run() }
    for _ in 0 ..< 100 where !states.withLock({ $0.contains(.bypassed(code: "E_RESOLVER_SAFE_BYPASS")) }) {
        try await Task.sleep(for: .milliseconds(1))
    }
    task.cancel()
    await task.value
    monitor.finish()

    #expect(restoreCount.withLock { $0 } == 1)
    #expect(states.withLock { $0 } == [
        .degraded(code: "E_RESOLVER_CHANNEL"),
        .bypassed(code: "E_RESOLVER_SAFE_BYPASS")
    ])
}

@Test
func supervisorDefaultsToImmediatePublicDnsFallback() async throws {
    let record = try supervisorRecord()
    let monitor = TestResolverMonitor()
    let states = Mutex<[ResolverSupervisorState]>([])
    let restoreCount = Mutex(0)
    let reconciler = ResolverReconciler(
        channel: FailingResolverChannel(),
        loadRecord: { record },
        makePlan: { _ in
            DNSPlan(services: [
                DNSServicePlan(serviceID: "service-a", upstreams: ["192.0.2.53"])
            ])
        },
        restoreSystemDNS: { restoreCount.withLock { $0 += 1 } }
    )
    let supervisor = ResolverSupervisor(
        reconciler: reconciler,
        monitor: monitor,
        interval: .seconds(60),
        retryInterval: .milliseconds(1),
        observe: { state in states.withLock { $0.append(state) } }
    )

    let task = Task { await supervisor.run() }
    for _ in 0 ..< 100 where restoreCount.withLock({ $0 }) == 0 {
        try await Task.sleep(for: .milliseconds(1))
    }
    task.cancel()
    await task.value
    monitor.finish()

    #expect(restoreCount.withLock { $0 } == 1)
    #expect(states.withLock { $0 } == [
        .degraded(code: "E_RESOLVER_CHANNEL"),
        .bypassed(code: "E_RESOLVER_SAFE_BYPASS")
    ])
}

@Test
func supervisorReenrolsOnlyAfterTheRecoveredDaemonAcceptsACompletePlan() async throws {
    let initial = try supervisorRecord()
    let record = Mutex(initial)
    let monitor = TestResolverMonitor()
    let states = Mutex<[ResolverSupervisorState]>([])
    let restoreCount = Mutex(0)
    let commitCount = Mutex(0)
    let channel = RecoveringResolverChannel(failureCount: 3)
    let reconciler = ResolverReconciler(
        channel: channel,
        loadRecord: { record.withLock { $0 } },
        makePlan: { _ in
            DNSPlan(services: [
                DNSServicePlan(serviceID: "service-a", upstreams: ["192.0.2.53"])
            ])
        },
        restoreSystemDNS: {
            try record.withLock { value in
                value = try ActivationRecord(payload: value.payload.withPhase(.prepared))
            }
            restoreCount.withLock { $0 += 1 }
        },
        commitPreparedDNS: { prepared in
            #expect(prepared.payload.phase == .prepared)
            try record.withLock { value in
                value = try ActivationRecord(payload: value.payload.withPhase(.active))
            }
            commitCount.withLock { $0 += 1 }
        }
    )
    let supervisor = ResolverSupervisor(
        reconciler: reconciler,
        monitor: monitor,
        interval: .seconds(60),
        retryInterval: .milliseconds(1),
        maximumConsecutiveFailures: 3,
        observe: { state in states.withLock { $0.append(state) } }
    )

    let task = Task { await supervisor.run() }
    for _ in 0 ..< 100 where commitCount.withLock({ $0 }) == 0 {
        try await Task.sleep(for: .milliseconds(1))
    }
    task.cancel()
    await task.value
    monitor.finish()

    #expect(restoreCount.withLock { $0 } == 1)
    #expect(commitCount.withLock { $0 } == 1)
    #expect(record.withLock { $0.payload.phase } == .active)
    #expect(channel.publishedUpstreams() == ["192.0.2.53:53"])
    #expect(states.withLock { $0 } == [
        .degraded(code: "E_RESOLVER_CHANNEL"),
        .bypassed(code: "E_RESOLVER_SAFE_BYPASS"),
        .ready
    ])
}

@Test
func activeRecordRequiresReactivationWhenEffectiveDNSBypassesRemap() throws {
    let record = try supervisorRecord()
    #expect(!systemDNSNeedsReactivation(
        record: record,
        remapServiceIDs: ["service-a"]
    ))
    #expect(systemDNSNeedsReactivation(record: record, remapServiceIDs: []))
    #expect(systemDNSNeedsReactivation(
        record: record,
        remapServiceIDs: ["another-service"]
    ))
}

private final class TestResolverMonitor: ResolverChangeMonitoring, Sendable {
    let events: AsyncStream<Void>

    private let continuation: AsyncStream<Void>.Continuation
    private let startError: (any Error)?

    init(startError: (any Error)? = nil) {
        let pair = AsyncStream.makeStream(of: Void.self, bufferingPolicy: .bufferingNewest(1))
        events = pair.stream
        continuation = pair.continuation
        self.startError = startError
    }

    func start() throws {
        if let startError {
            throw startError
        }
    }

    func finish() {
        continuation.finish()
    }
}

private struct CountingHealthState {
    var activationID: UUID?
    var generation: UInt64?
    var healthCount = 0
}

private final class CountingHealthChannel: ResolverSystemExchanging, Sendable {
    private let state = Mutex(CountingHealthState())

    func exchange(_ command: ResolverSystemCommand) throws -> ResolverSystemResult {
        state.withLock { state in
            switch command {
            case .health:
                state.healthCount += 1
            case let .publish(activationID, generation, _):
                state.activationID = activationID
                state.generation = generation
            case .invalidate:
                state.generation = nil
            }
            return ResolverSystemResult(
                activationID: state.activationID,
                activeGeneration: state.generation
            )
        }
    }

    func healthCount() -> Int {
        state.withLock(\.healthCount)
    }
}

private struct FailingResolverChannel: ResolverSystemExchanging {
    func exchange(_: ResolverSystemCommand) throws -> ResolverSystemResult {
        throw ResolverChannelError.transport
    }
}

private struct RecoveringResolverChannelState {
    var activationID: UUID?
    var failuresRemaining: Int
    var generation: UInt64?
    var upstreams: [String] = []
}

private final class RecoveringResolverChannel: ResolverSystemExchanging, Sendable {
    private let state: Mutex<RecoveringResolverChannelState>

    init(failureCount: Int) {
        state = Mutex(RecoveringResolverChannelState(failuresRemaining: failureCount))
    }

    func exchange(_ command: ResolverSystemCommand) throws -> ResolverSystemResult {
        try state.withLock { state in
            if state.failuresRemaining > 0 {
                state.failuresRemaining -= 1
                throw ResolverChannelError.transport
            }
            switch command {
            case .health:
                break
            case let .invalidate(_, generation):
                if state.generation == generation {
                    state.activationID = nil
                    state.generation = nil
                    state.upstreams = []
                }
            case let .publish(activationID, generation, upstreams):
                state.activationID = activationID
                state.generation = generation
                state.upstreams = upstreams
            }
            return ResolverSystemResult(
                activationID: state.activationID,
                activeGeneration: state.generation
            )
        }
    }

    func publishedUpstreams() -> [String] {
        state.withLock(\.upstreams)
    }
}

private func supervisorRecord() throws -> ActivationRecord {
    let service = DNSServiceRecord(
        serviceID: "service-a",
        priorConfiguration: nil,
        installedConfiguration: Data(),
        upstreams: ["192.0.2.53"]
    )
    return try ActivationRecord(payload: ActivationPayload(
        ownerUID: 501,
        createdAtMilliseconds: 1,
        productVersion: "0.1.0",
        phase: .active,
        services: [service]
    ))
}
