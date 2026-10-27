import CryptoKit
import Foundation
@testable import RemapSystemKit
import Synchronization
import Testing

// ADR-0030. Every test runs the supervisor on a stepped clock whose awake time
// advances only when the supervisor waits, so minutes of damping take
// milliseconds and every instant is exact: a bypass at `t` is first probed at
// `t + 250 ms`, and a period of `p` re-arms at `t + 250 ms + p`.

@Test
func oneSuccessfulExchangeAfterAChannelFaultDoesNotReArm() async throws {
    // The channel fails from the start, answers exactly one probe at 0.25 s,
    // then fails again until 3 s, as it did on the loaded Mac.
    let fixture = try DampingFixture { now in now != .milliseconds(250) && now < .seconds(3) }
    let task = Task { await fixture.supervisor().run() }
    try await eventually(within: generousWait) { fixture.events().rearms.count == 1 }
    await fixture.stop(task)

    let events = fixture.events()
    #expect(events.bypasses == [.zero])
    // The single answer at 0.25 s re-armed nothing; health from 3 s did,
    // after the base period.
    #expect(events.rearms == [.seconds(8)])
    #expect(fixture.daemon.snapshot().publications == [1])
    #expect(events.states == [
        .degraded(code: "E_RESOLVER_CHANNEL"),
        .bypassed(code: "E_RESOLVER_SAFE_BYPASS"),
        .ready
    ])
}

@Test
func aSustainedHealthyPeriodReArms() async throws {
    let fixture = try DampingFixture { now in now == .zero }
    let task = Task { await fixture.supervisor().run() }
    try await eventually(within: generousWait) { fixture.events().rearms.count == 1 }
    await fixture.stop(task)

    let events = fixture.events()
    #expect(events.bypasses == [.zero])
    #expect(events.rearms == [.milliseconds(5250)])
    #expect(events.payloads.first?.rearmAfterHealthyMilliseconds == 5000)
    #expect(events.payloads.last?.rearmedAtMilliseconds != nil)
    #expect(fixture.daemon.snapshot().publications == [1])
}

@Test
func repeatedBypassesDoubleTheRequiredPeriodUpToTheCap() async throws {
    let fixture = try DampingFixture(faultsAfterRearm: 7) { now in now == .zero }
    let task = Task { await fixture.supervisor().run() }
    try await eventually(within: generousWait) { fixture.events().rearms.count == 8 }
    await fixture.stop(task)

    let events = fixture.events()
    let expected = [5, 10, 20, 40, 80, 160, 300, 300].map { Duration.seconds($0) }
    #expect(events.requiredPeriods() == expected)
    let recorded = events.payloads
        .filter { $0.rearmedAtMilliseconds == nil }
        .compactMap(\.rearmAfterHealthyMilliseconds)
    #expect(recorded == [5000, 10000, 20000, 40000, 80000, 160_000, 300_000, 300_000])
}

@Test
func aLongHealthyRunResetsTheDamping() async throws {
    let fixture = try DampingFixture(faultsAfterRearm: 2) { now in now == .zero }
    let task = Task { await fixture.supervisor().run() }
    try await eventually(within: generousWait) { fixture.rearmedPayloadCount() == 3 }
    // Armed for the full reset period, then one more fault, and one right
    // after the re-arm that follows it.
    fixture.clock.advance(by: .seconds(300))
    fixture.faultNextExchange(thenAfterRearms: 1)
    try await eventually(within: generousWait) { fixture.events().rearms.count == 5 }
    await fixture.stop(task)

    let events = fixture.events()
    #expect(events.requiredPeriods() == [5, 10, 20, 5, 10].map { Duration.seconds($0) })
    #expect(events.bypasses[3] == events.rearms[2] + .seconds(300))
}

@Test
func anArmedRunShorterThanTheResetPeriodStillDoubles() {
    let policy = ResolverRearmDamping.standard
    var backoff = ResolverRearmBackoff(policy)
    backoff.noteBypass(at: .zero, policy: policy)
    #expect(backoff.required == .seconds(5))
    backoff.noteArmed(at: .seconds(10))
    backoff.noteArmed(at: .seconds(200))
    backoff.noteBypass(at: .seconds(309), policy: policy)
    #expect(backoff.required == .seconds(10))
    // A bypass that could not restore ordinary DNS is retried as the same fault.
    backoff.noteBypass(at: .seconds(310), policy: policy)
    #expect(backoff.required == .seconds(10))
    backoff.noteArmed(at: .seconds(320))
    backoff.noteBypass(at: .seconds(620), policy: policy)
    #expect(backoff.required == .seconds(5))
}

@Test
func statusSaysHowMuchHealthTheNextReArmNeeds() {
    let waiting = ResolverBypassPayload(
        reasonCode: "E_RESOLVER_CHANNEL",
        outcomeCode: "E_RESOLVER_SAFE_BYPASS",
        failingSinceMilliseconds: 1_760_000_000_000,
        bypassedAtMilliseconds: 1_760_000_000_000,
        releasePending: false,
        unreleasedActivationID: nil,
        rearmAfterHealthyMilliseconds: 20000
    )
    let lines = NativeResolverStatus(record: nil, bypass: waiting, bypassError: nil).bypassLines()
    #expect(lines.contains("    Next try    after 20 seconds of continuous daemon health"))

    let rearmed = waiting.rearmed(atMilliseconds: 1_760_000_030_000)
    #expect(rearmed.rearmAfterHealthyMilliseconds == 20000)
    let after = NativeResolverStatus(record: nil, bypass: rearmed, bypassError: nil).bypassLines()
    #expect(!after.contains { $0.contains("Next try") })
}

@Test
func aBypassRecordFromAnEarlierBuildStillVerifies() throws {
    // The canonical payload a 0.2.0 supervisor hashed, before the period existed.
    let earlier = #"{"bypassedAtMilliseconds":20,"failingSinceMilliseconds":10,"#
        + #""outcomeCode":"E_RESOLVER_SAFE_BYPASS","reasonCode":"E_RESOLVER_CHANNEL","#
        + #""releasePending":false,"schemaVersion":1}"#
    let earlierDigest = SHA256.hash(data: Data(earlier.utf8)).map { String(format: "%02x", $0) }.joined()
    let stored = #"{"payload":"# + earlier + #","sha256":""# + earlierDigest + #""}"#
    let record = try CanonicalJSON.decoder.decode(ResolverBypassRecord.self, from: Data(stored.utf8))
    try record.verify()
    #expect(record.payload.rearmAfterHealthyMilliseconds == nil)
    #expect(try String(decoding: CanonicalJSON.encoder.encode(record.payload), as: UTF8.self) == earlier)
}

/// The stepped run covers at most a few thousand probes; this bounds the
/// wall-clock wait on a heavily loaded machine, not the behaviour under test.
private let generousWait = Duration.seconds(300)

/// Awake time that advances only when the supervisor waits.
private final class SteppedSupervisorClock: ResolverSupervisorClock, Sendable {
    private let elapsed = Mutex(Duration.zero)

    var now: Duration {
        elapsed.withLock { $0 }
    }

    func sleep(for duration: Duration) async throws {
        try Task.checkCancellation()
        elapsed.withLock { $0 += duration }
        await Task.yield()
    }

    func advance(by duration: Duration) {
        elapsed.withLock { $0 += duration }
    }
}

private struct DampingEvents {
    var bypasses: [Duration] = []
    var rearms: [Duration] = []
    var payloads: [ResolverBypassPayload] = []
    var states: [ResolverSupervisorState] = []
    var faultNext = false
    var faultsAfterRearm = 0

    /// The continuous health each bypass waited for before its re-arm.
    func requiredPeriods() -> [Duration] {
        zip(bypasses, rearms).map { bypass, rearm in rearm - bypass - .milliseconds(250) }
    }
}

/// One supervised activation behind a channel that fails while `down` says
/// so at the current awake time, and once after each of the first
/// `faultsAfterRearm` re-arms. Restore and commit move the record between
/// phases as `SystemResolver` does and note when they happened.
private final class DampingFixture: ResolverSystemExchanging, ResolverBypassRecording, Sendable {
    let clock = SteppedSupervisorClock()
    let daemon = ResolverTestDaemon()
    let monitor = QuietResolverMonitor()
    private let current: Mutex<ActivationRecord>
    private let recorded: Mutex<DampingEvents>
    private let down: @Sendable (Duration) -> Bool

    init(faultsAfterRearm: Int = 0, down: @escaping @Sendable (Duration) -> Bool) throws {
        current = try Mutex(healingRecord())
        recorded = Mutex(DampingEvents(faultsAfterRearm: faultsAfterRearm))
        self.down = down
    }

    func events() -> DampingEvents {
        recorded.withLock { $0 }
    }

    func rearmedPayloadCount() -> Int {
        recorded.withLock { events in
            events.payloads.count { payload in payload.rearmedAtMilliseconds != nil }
        }
    }

    func faultNextExchange(thenAfterRearms count: Int) {
        recorded.withLock { events in
            events.faultNext = true
            events.faultsAfterRearm = count
        }
    }

    func supervisor() -> ResolverSupervisor {
        let reconciler = ResolverReconciler(
            channel: self,
            loadRecord: { self.current.withLock { $0 } },
            makePlan: { _ in singleServicePlan() },
            restoreSystemDNS: {
                try self.moveRecord(to: .prepared)
                let now = self.clock.now
                self.recorded.withLock { $0.bypasses.append(now) }
            },
            commitPreparedDNS: { prepared in
                guard prepared.payload.phase == .prepared else { return }
                try self.moveRecord(to: .active)
                let now = self.clock.now
                self.recorded.withLock { events in
                    events.rearms.append(now)
                    if events.faultsAfterRearm > 0 {
                        events.faultsAfterRearm -= 1
                        events.faultNext = true
                    }
                }
            }
        )
        return ResolverSupervisor(
            reconciler: reconciler,
            monitor: monitor,
            timing: ResolverSupervisorTiming(interval: .milliseconds(1), clock: clock),
            bypassLog: self,
            observe: { state in self.recorded.withLock { $0.states.append(state) } }
        )
    }

    func stop(_ task: Task<Void, Never>) async {
        task.cancel()
        await task.value
        monitor.finish()
    }

    func exchange(_ command: ResolverSystemCommand) throws -> ResolverSystemResult {
        let faulted = recorded.withLock { events in
            defer { events.faultNext = false }
            return events.faultNext
        }
        if faulted || down(clock.now) {
            throw ResolverChannelError.transport
        }
        return try daemon.exchange(command)
    }

    func record(_ payload: ResolverBypassPayload) {
        recorded.withLock { $0.payloads.append(payload) }
    }

    func lastBypass() -> ResolverBypassPayload? {
        nil
    }

    private func moveRecord(to phase: ActivationPhase) throws {
        try current.withLock { value in
            value = try ActivationRecord(payload: value.payload.withPhase(phase))
        }
    }
}
