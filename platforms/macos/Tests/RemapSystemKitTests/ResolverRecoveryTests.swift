import Darwin
import Foundation
@testable import RemapSystemKit
import Synchronization
import Testing

@Test
func resultDecodingToleratesADaemonThatPredatesTheHighWater() throws {
    let old = try JSONDecoder().decode(
        ResolverSystemResult.self,
        from: Data(#"{"activation_id":null,"active_generation":7}"#.utf8)
    )
    #expect(old == ResolverSystemResult(activationID: nil, activeGeneration: 7))
    #expect(old.highestAcceptedGeneration == nil)
    let current = try JSONDecoder().decode(
        ResolverSystemResult.self,
        from: Data(#"{"activation_id":null,"active_generation":null,"highest_accepted_generation":9}"#.utf8)
    )
    #expect(current.highestAcceptedGeneration == 9)
}

@Test
func aDaemonWithoutTheHighWaterStillReceivesTheNextLocalGeneration() async throws {
    let record = try healingRecord()
    let daemon = ResolverTestDaemon(ResolverTestDaemon.State(reportsHighWater: false))
    let reconciler = ResolverReconciler(
        channel: daemon,
        loadRecord: { record },
        makePlan: { _ in singleServicePlan() }
    )
    try await reconciler.reconcile()
    _ = try await reconciler.enterSafeBypass()
    try await reconciler.reconcile()
    #expect(daemon.snapshot().publications == [1, 2])
}

@Test
func aRestartedReconcilerReleasesTheOrphanNamedByTheDurableBypassRecord() async throws {
    let orphan = try healingRecord(createdAt: 1).activationIdentifier()
    let current = try healingRecord(createdAt: 2)
    let daemon = ResolverTestDaemon(ResolverTestDaemon.State(
        activationID: orphan,
        activeGeneration: 5,
        highestGeneration: 5
    ))
    let reconciler = ResolverReconciler(
        channel: daemon,
        loadRecord: { current },
        makePlan: { _ in singleServicePlan() },
        recordedOrphan: { orphan }
    )
    try await reconciler.reconcile()
    #expect(daemon.snapshot().invalidations == [orphan])
    #expect(try daemon.snapshot().activationID == current.activationIdentifier())
    #expect(daemon.snapshot().activeGeneration == 6)
}

@Test
func anOrphanIsReleasedOnlyOnceACompleteReplacementPlanExists() async throws {
    let orphan = try healingRecord(createdAt: 1).activationIdentifier()
    let current = try healingRecord(createdAt: 2)
    let observable = Mutex(false)
    let daemon = ResolverTestDaemon(ResolverTestDaemon.State(
        activationID: orphan,
        activeGeneration: 5,
        highestGeneration: 5
    ))
    let reconciler = ResolverReconciler(
        channel: daemon,
        loadRecord: { current },
        makePlan: { _ in
            guard observable.withLock({ $0 }) else { throw ResolverError.noUsableUpstream }
            return singleServicePlan()
        },
        recordedOrphan: { orphan }
    )
    await #expect(throws: ResolverError.noUsableUpstream) {
        try await reconciler.reconcile()
    }
    #expect(daemon.snapshot().activationID == orphan)
    #expect(daemon.snapshot().invalidations.isEmpty)

    observable.withLock { $0 = true }
    try await reconciler.reconcile()
    #expect(daemon.snapshot().invalidations == [orphan])
    #expect(daemon.snapshot().activeGeneration == 6)
}

@Test
func safeBypassReportsTheActivationItCouldNotRelease() async throws {
    let record = try healingRecord()
    let daemon = ResolverTestDaemon()
    let reconciler = ResolverReconciler(
        channel: daemon,
        loadRecord: { record },
        makePlan: { _ in singleServicePlan() }
    )
    try await reconciler.reconcile()
    daemon.update { $0.refusesEverything = true }
    #expect(try await reconciler.enterSafeBypass() == .pending(
        activationID: record.activationIdentifier()
    ))
    daemon.update { $0.refusesEverything = false }
    #expect(try await reconciler.enterSafeBypass() == .released)
    #expect(daemon.snapshot().activeGeneration == nil)
}

@Test
func anUnobservedNetworkBeyondTheGraceBypassesRecordsWhyAndReArms() async throws {
    let fixture = try SupervisorFixture()
    let networkDown = Mutex(false)
    let reconciler = fixture.reconciler { _ in
        if networkDown.withLock({ $0 }) {
            throw ResolverError.noUsableUpstream
        }
        return singleServicePlan()
    } onRestore: {
        // Wi-Fi rejoins only after ordinary DNS was restored.
        networkDown.withLock { $0 = false }
    }
    let supervisor = fixture.supervisor(reconciler, failureGrace: .milliseconds(30))

    let task = Task { await supervisor.run() }
    try await eventually { fixture.states() == [.ready] }
    networkDown.withLock { $0 = true }
    try await eventually { fixture.log.payloads().count >= 2 }
    task.cancel()
    await task.value
    fixture.monitor.finish()

    #expect(fixture.states() == [
        .ready,
        .degraded(code: "E_RESOLVER_NETWORK_UNOBSERVED"),
        .bypassed(code: "E_RESOLVER_SAFE_BYPASS"),
        .ready
    ])
    #expect(fixture.restoreCount() == 1)
    #expect(fixture.daemon.snapshot().publications == [1, 2])
    let payloads = fixture.log.payloads()
    #expect(payloads.count == 2)
    let bypass = try #require(payloads.first)
    #expect(bypass.reasonCode == "E_RESOLVER_NETWORK_UNOBSERVED")
    #expect(bypass.outcomeCode == "E_RESOLVER_SAFE_BYPASS")
    #expect(!bypass.releasePending)
    #expect(bypass.rearmedAtMilliseconds == nil)
    #expect(bypass.failingSinceMilliseconds <= bypass.bypassedAtMilliseconds)
    let rearmed = try #require(payloads.last)
    #expect(rearmed.reasonCode == bypass.reasonCode)
    #expect(try #require(rearmed.rearmedAtMilliseconds) >= bypass.bypassedAtMilliseconds)
}

@Test
func aDaemonRefusalBypassesAtOnceDespiteALongGraceAndRecordsItsCode() async throws {
    let fixture = try SupervisorFixture()
    fixture.daemon.update { $0.refusesPublication = true }
    let reconciler = fixture.reconciler { _ in singleServicePlan() }
    let supervisor = fixture.supervisor(reconciler, failureGrace: .seconds(3600))

    let clock = ContinuousClock()
    let started = clock.now
    let task = Task { await supervisor.run() }
    try await eventually { !fixture.log.payloads().isEmpty }
    let elapsed = started.duration(to: clock.now)
    task.cancel()
    await task.value
    fixture.monitor.finish()

    #expect(elapsed < .seconds(5))
    #expect(fixture.restoreCount() == 1)
    #expect(Array(fixture.states().prefix(2)) == [
        .degraded(code: "E_RESOLVER_ACTIVATION"),
        .bypassed(code: "E_RESOLVER_SAFE_BYPASS")
    ])
    #expect(fixture.log.payloads().first?.reasonCode == "E_RESOLVER_ACTIVATION")
}

@Test
func aBypassThatCannotReleaseTheDaemonRecordsThePendingRelease() async throws {
    let fixture = try SupervisorFixture()
    let reconciler = fixture.reconciler { _ in singleServicePlan() }
    let supervisor = fixture.supervisor(reconciler, failureGrace: .zero)
    let task = Task { await supervisor.run() }
    try await eventually { fixture.states() == [.ready] }
    fixture.daemon.update { $0.refusesEverything = true }
    try await eventually { !fixture.log.payloads().isEmpty }
    task.cancel()
    await task.value
    fixture.monitor.finish()

    let payload = try #require(fixture.log.payloads().first)
    #expect(payload.reasonCode == "E_RESOLVER_CHANNEL")
    #expect(payload.releasePending)
    #expect(try payload.unreleasedActivationID == fixture.record.activationIdentifier())
    #expect(try payload.outstandingOrphan == fixture.record.activationIdentifier())
    #expect(payload.rearmed(atMilliseconds: 1).outstandingOrphan == nil)
}

@Test
func daemonRefusalCodesAreAcceptedOnlyInStableForm() {
    #expect(isStableErrorCode("E_RESOLVER_PLAN"))
    #expect(!isStableErrorCode("E_resolver"))
    #expect(!isStableErrorCode("E_PLAN example.test"))
    #expect(!isStableErrorCode("RESOLVER_PLAN"))
    #expect(!isStableErrorCode("E_" + String(repeating: "A", count: 63)))
}

@Test
func bypassStoreRoundTripsAndRejectsTamperingAndLoosePermissions() throws {
    let directory = try privateTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = ResolverBypassStore(directory: directory, ownerUID: geteuid())
    #expect(try store.read() == nil)

    let payload = ResolverBypassPayload(
        reasonCode: "E_RESOLVER_CHANNEL",
        outcomeCode: "E_RESOLVER_SAFE_BYPASS",
        failingSinceMilliseconds: 10,
        bypassedAtMilliseconds: 20,
        releasePending: true,
        unreleasedActivationID: UUID()
    )
    try store.write(payload)
    #expect(try store.read()?.payload == payload)
    try store.write(payload.rearmed(atMilliseconds: 30))
    #expect(try store.read()?.payload.rearmedAtMilliseconds == 30)
    #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path) == [
        "resolver-bypass-v1.json"
    ])

    let text = try String(contentsOf: store.recordURL, encoding: .utf8)
    try Data(text.replacingOccurrences(of: "E_RESOLVER_CHANNEL", with: "E_RESOLVER_PLANET").utf8)
        .write(to: store.recordURL)
    #expect(chmod(store.recordURL.path, 0o600) == 0)
    #expect(throws: ResolverError.invalidBypassRecord) { try store.read() }

    #expect(chmod(store.recordURL.path, 0o644) == 0)
    #expect(throws: ResolverError.secureStorage("verify the root-owned resolver bypass record")) {
        try store.read()
    }
    #expect(throws: ResolverError.secureStorage("verify the root-owned resolver bypass record")) {
        try store.write(payload)
    }
}

@Test
func bypassStoreRefusesASymlinkAndAWritableDirectory() throws {
    let directory = try privateTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = ResolverBypassStore(directory: directory, ownerUID: geteuid())
    let target = directory.appendingPathComponent("elsewhere.json")
    try Data("{}".utf8).write(to: target)
    #expect(symlink(target.path, store.recordURL.path) == 0)
    #expect(throws: ResolverError.secureStorage("verify the root-owned resolver bypass record")) {
        try store.read()
    }
    #expect(unlink(store.recordURL.path) == 0)

    #expect(chmod(directory.path, 0o777) == 0)
    #expect(throws: ResolverError.secureStorage("verify the root-owned activation directory")) {
        try store.write(ResolverBypassPayload(
            reasonCode: "E_RESOLVER_CHANNEL",
            outcomeCode: "E_RESOLVER_SAFE_BYPASS",
            failingSinceMilliseconds: 1,
            bypassedAtMilliseconds: 2,
            releasePending: false,
            unreleasedActivationID: nil
        ))
    }
    #expect(throws: ResolverError.notRoot) {
        try ResolverBypassStore(directory: directory, ownerUID: geteuid() &+ 1).write(
            ResolverBypassPayload(
                reasonCode: "E_RESOLVER_CHANNEL",
                outcomeCode: "E_RESOLVER_SAFE_BYPASS",
                failingSinceMilliseconds: 1,
                bypassedAtMilliseconds: 2,
                releasePending: false,
                unreleasedActivationID: nil
            )
        )
    }
}

@Test
func statusKeepsTheActivationKeysAndAddsTheLastBypass() throws {
    let record = try healingRecord()
    let bypass = ResolverBypassPayload(
        reasonCode: "E_RESOLVER_NETWORK_UNOBSERVED",
        outcomeCode: "E_RESOLVER_SAFE_BYPASS",
        failingSinceMilliseconds: 1_760_000_000_000,
        bypassedAtMilliseconds: 1_760_000_020_000,
        releasePending: false,
        unreleasedActivationID: nil
    )
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    let inactive = NativeResolverStatus(record: nil, bypass: nil, bypassError: nil)
    #expect(try String(data: encoder.encode(inactive), encoding: .utf8) == "null")
    #expect(inactive.bypassLines().isEmpty)

    let status = NativeResolverStatus(record: record, bypass: bypass, bypassError: nil)
    let object = try #require(
        JSONSerialization.jsonObject(with: encoder.encode(status)) as? [String: Any]
    )
    #expect(Set(object.keys) == ["payload", "sha256", "lastResolverBypass"])
    #expect(object["sha256"] as? String == record.sha256)
    let lines = status.bypassLines()
    #expect(lines.count == 3)
    #expect(lines[0].contains("E_RESOLVER_SAFE_BYPASS"))
    #expect(lines[1].contains("E_RESOLVER_NETWORK_UNOBSERVED"))
    #expect(lines[2].contains("not yet"))

    let unreadable = NativeResolverStatus(record: nil, bypass: nil, bypassError: "damaged")
    #expect(unreadable.bypassLines() == ["  Last fallback record unreadable: damaged"])
}

private func privateTemporaryDirectory() throws -> URL {
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("remap-bypass-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(
        at: directory,
        withIntermediateDirectories: false,
        attributes: [.posixPermissions: 0o700]
    )
    return directory
}

private final class RecordingBypassLog: ResolverBypassRecording, Sendable {
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

/// One supervised activation whose restore and commit move the record
/// between phases as `SystemResolver` does.
private final class SupervisorFixture: Sendable {
    let record: ActivationRecord
    let daemon = ResolverTestDaemon()
    let monitor = QuietResolverMonitor()
    let log = RecordingBypassLog()
    private let current: Mutex<ActivationRecord>
    private let observed = Mutex<[ResolverSupervisorState]>([])
    private let restores = Mutex(0)

    init() throws {
        record = try healingRecord()
        current = Mutex(record)
    }

    func states() -> [ResolverSupervisorState] {
        observed.withLock { $0 }
    }

    func restoreCount() -> Int {
        restores.withLock { $0 }
    }

    func reconciler(
        plan: @escaping @Sendable (ActivationRecord) throws -> DNSPlan,
        onRestore: @escaping @Sendable () -> Void = {}
    ) -> ResolverReconciler {
        ResolverReconciler(
            channel: daemon,
            loadRecord: { self.current.withLock { $0 } },
            makePlan: plan,
            restoreSystemDNS: {
                try self.moveRecord(to: .prepared)
                self.restores.withLock { $0 += 1 }
                onRestore()
            },
            commitPreparedDNS: { prepared in
                guard prepared.payload.phase == .prepared else { return }
                try self.moveRecord(to: .active)
            }
        )
    }

    func supervisor(_ reconciler: ResolverReconciler, failureGrace: Duration) -> ResolverSupervisor {
        ResolverSupervisor(
            reconciler: reconciler,
            monitor: monitor,
            interval: .milliseconds(5),
            retryInterval: .milliseconds(1),
            failureGrace: failureGrace,
            bypassLog: log,
            observe: { state in self.observed.withLock { $0.append(state) } }
        )
    }

    private func moveRecord(to phase: ActivationPhase) throws {
        try current.withLock { value in
            value = try ActivationRecord(payload: value.payload.withPhase(phase))
        }
    }
}
