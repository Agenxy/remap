import Foundation
@testable import RemapSystemKit
import Synchronization
import Testing

// Regression tests for the 13 October 2026 fallback that never re-armed.
// They use only interfaces that existed before the fix, so each one can be
// run against the earlier sources to show that it fails there.

@Test
func reconcilerReleasesItsOwnBindingAfterABypassCouldNotReachTheDaemon() async throws {
    let first = try healingRecord(createdAt: 1)
    let second = try healingRecord(createdAt: 2)
    let current = Mutex(first)
    let daemon = ResolverTestDaemon()
    let reconciler = ResolverReconciler(
        channel: daemon,
        loadRecord: { current.withLock { $0 } },
        makePlan: { _ in singleServicePlan() }
    )
    try await reconciler.reconcile()

    daemon.update { $0.refusesEverything = true }
    _ = try await reconciler.enterSafeBypass()
    daemon.update { $0.refusesEverything = false }
    #expect(try daemon.snapshot().activationID == first.activationIdentifier())

    current.withLock { $0 = second }
    try await reconciler.reconcile()

    let state = daemon.snapshot()
    #expect(try state.invalidations == [first.activationIdentifier()])
    #expect(try state.activationID == second.activationIdentifier())
    #expect(state.activeGeneration == 2)
}

@Test
func reconcilerReleasesItsOwnBindingAfterTheBypassInvalidationFailed() async throws {
    let first = try healingRecord(createdAt: 1)
    let second = try healingRecord(createdAt: 2)
    let current = Mutex(first)
    let daemon = ResolverTestDaemon()
    let reconciler = ResolverReconciler(
        channel: daemon,
        loadRecord: { current.withLock { $0 } },
        makePlan: { _ in singleServicePlan() }
    )
    try await reconciler.reconcile()

    daemon.update { $0.refusesInvalidation = true }
    _ = try await reconciler.enterSafeBypass()
    daemon.update { $0.refusesInvalidation = false }

    current.withLock { $0 = second }
    try await reconciler.reconcile()

    #expect(try daemon.snapshot().activationID == second.activationIdentifier())
    #expect(daemon.snapshot().activeGeneration == 2)
}

@Test
func aBindingThatNoBypassOrphanedIsStillAnActivationMismatch() async throws {
    let first = try healingRecord(createdAt: 1)
    let foreign = UUID()
    let daemon = ResolverTestDaemon(ResolverTestDaemon.State(
        activationID: foreign,
        activeGeneration: 4,
        highestGeneration: 4
    ))
    let reconciler = ResolverReconciler(
        channel: daemon,
        loadRecord: { first },
        makePlan: { _ in singleServicePlan() }
    )
    daemon.update { $0.refusesEverything = true }
    _ = try await reconciler.enterSafeBypass()
    daemon.update { $0.refusesEverything = false }

    await #expect(throws: ResolverReconciliationError.activationMismatch) {
        try await reconciler.reconcile()
    }
    #expect(daemon.snapshot().activationID == foreign)
    #expect(daemon.snapshot().invalidations.isEmpty)
}

@Test
func aFreshReconcilerPublishesAboveTheDaemonHighWaterAfterAFallback() async throws {
    let record = try healingRecord()
    let daemon = ResolverTestDaemon()
    let upstream = Mutex("192.0.2.53")
    let supervisorReconciler = ResolverReconciler(
        channel: daemon,
        loadRecord: { record },
        makePlan: { _ in singleServicePlan(upstream.withLock { $0 }) }
    )
    for address in ["192.0.2.53", "192.0.2.54", "192.0.2.55"] {
        upstream.withLock { $0 = address }
        try await supervisorReconciler.reconcile()
    }
    _ = try await supervisorReconciler.enterSafeBypass()
    #expect(daemon.snapshot().activeGeneration == nil)
    #expect(daemon.snapshot().highestGeneration == 3)

    // `remap-system activate` and a restarted supervisor both start here,
    // with no memory of the generations the daemon has already accepted.
    let activation = ResolverReconciler(
        channel: daemon,
        loadRecord: { record },
        makePlan: { _ in singleServicePlan() }
    )
    try await activation.reconcile()

    #expect(daemon.snapshot().publications == [1, 2, 3, 4])
    #expect(try daemon.snapshot().activationID == record.activationIdentifier())
    #expect(daemon.snapshot().activeGeneration == 4)
}

@Test
func anUnobservedNetworkShorterThanTheDefaultGraceKeepsRemapArmed() async throws {
    let record = try healingRecord()
    let daemon = ResolverTestDaemon()
    let observations = Mutex(0)
    let restoreCount = Mutex(0)
    let states = Mutex<[ResolverSupervisorState]>([])
    let monitor = QuietResolverMonitor()
    let reconciler = ResolverReconciler(
        channel: daemon,
        loadRecord: { record },
        makePlan: { _ in
            let attempt = observations.withLock { value -> Int in
                value += 1
                return value
            }
            // Attempts two to four see Wi-Fi rejoining after sleep.
            guard attempt == 1 || attempt > 4 else {
                throw ResolverError.noUsableUpstream
            }
            return singleServicePlan()
        },
        restoreSystemDNS: { restoreCount.withLock { $0 += 1 } }
    )
    let supervisor = ResolverSupervisor(
        reconciler: reconciler,
        monitor: monitor,
        interval: .milliseconds(5),
        retryInterval: .milliseconds(1),
        observe: { state in states.withLock { $0.append(state) } }
    )

    let task = Task { await supervisor.run() }
    try await eventually { states.withLock { $0.count >= 3 } || restoreCount.withLock { $0 } > 0 }
    task.cancel()
    await task.value
    monitor.finish()

    #expect(restoreCount.withLock { $0 } == 0)
    #expect(daemon.snapshot().invalidations.isEmpty)
    #expect(daemon.snapshot().publications == [1])
    #expect(daemon.snapshot().activeGeneration == 1)
    #expect(states.withLock { $0 } == [
        .ready,
        .degraded(code: "E_RESOLVER_NETWORK_UNOBSERVED"),
        .ready
    ])
}
