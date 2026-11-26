// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation

/// How eagerly the supervisor returns to Remap DNS after a bypass (ADR-0030).
///
/// A fault still restores ordinary DNS at once. Re-arming waits until the
/// daemon has answered continuously for `base` of awake time. A bypass that
/// follows a re-arm within `resetAfter` doubles the wait, up to `cap`; an
/// armed run of at least `resetAfter` forgets the earlier bypasses.
public struct ResolverRearmDamping: Equatable, Sendable {
    public let base: Duration
    public let cap: Duration
    public let resetAfter: Duration

    public static let standard = ResolverRearmDamping(
        base: .seconds(5),
        cap: .seconds(300),
        resetAfter: .seconds(300)
    )

    public init(base: Duration, cap: Duration, resetAfter: Duration) {
        precondition(base >= .zero)
        precondition(cap >= base)
        precondition(resetAfter > .zero)
        self.base = base
        self.cap = cap
        self.resetAfter = resetAfter
    }
}

/// The supervisor's memory of recent bypasses, in awake time.
struct ResolverRearmBackoff: Equatable {
    /// Continuous daemon health the current bypass requires before re-arming.
    private(set) var required: Duration
    /// When Remap DNS was last re-armed after a bypass; nil before the first
    /// re-arm and while bypassed.
    private var armedSince: Duration?
    private var bypassed = false

    init(_ policy: ResolverRearmDamping) {
        required = policy.base
    }

    /// Called for every bypass attempt. A retry of a bypass that could not
    /// restore ordinary DNS is the same fault and changes nothing.
    mutating func noteBypass(at now: Duration, policy: ResolverRearmDamping) {
        guard !bypassed else { return }
        bypassed = true
        if let armedSince, now - armedSince < policy.resetAfter {
            required = min(required * 2, policy.cap)
        } else {
            required = policy.base
        }
        armedSince = nil
    }

    /// Called whenever Remap DNS is known to be armed; only the first call
    /// after a bypass starts the armed run.
    mutating func noteArmed(at now: Duration) {
        guard bypassed else { return }
        bypassed = false
        armedSince = now
    }
}

/// Awake time and waiting for the supervisor. Production measures the
/// suspending clock, so hours of system sleep never count toward a window;
/// tests advance time without waiting for it.
protocol ResolverSupervisorClock: Sendable {
    /// Awake time since a fixed, arbitrary origin.
    var now: Duration { get }
    func sleep(for duration: Duration) async throws
}

struct AwakeSupervisorClock: ResolverSupervisorClock {
    private let clock = SuspendingClock()
    private let origin: SuspendingClock.Instant

    init() {
        origin = clock.now
    }

    var now: Duration {
        origin.duration(to: clock.now)
    }

    func sleep(for duration: Duration) async throws {
        try await Task.sleep(for: duration)
    }
}

/// Every duration the supervisor waits on, and the clock that measures them.
struct ResolverSupervisorTiming: Sendable {
    var interval: Duration = .seconds(5)
    var retryInterval: Duration = .milliseconds(250)
    var failureGrace: Duration = .seconds(20)
    var rearmDamping: ResolverRearmDamping = .standard
    var clock: any ResolverSupervisorClock = AwakeSupervisorClock()
}

/// Whole milliseconds of a non-negative awake duration.
func awakeMilliseconds(_ duration: Duration) -> UInt64 {
    let components = duration.components
    guard components.seconds >= 0 else { return 0 }
    return UInt64(components.seconds) * 1000 + UInt64(components.attoseconds / 1_000_000_000_000_000)
}
