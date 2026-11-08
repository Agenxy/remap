// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation

/// Privacy-safe health state for the root resolver supervisor.
public enum ResolverSupervisorState: Equatable, Sendable {
    case bypassed(code: String)
    case degraded(code: String)
    /// Another agent's DNS holds the resolver macOS uses. Remap wrote
    /// nothing, ordinary DNS through that agent is in effect, and the code
    /// says why (ADR-0036).
    case deferred(code: String)
    case ready
}

/// Reconciles native resolver changes and daemon restarts without holding user data.
///
/// ADR-0006: "a transient incomplete network observation preserves the last
/// complete generation". When the recorded service exposes no usable upstream
/// (sleep, Wi-Fi rejoining, an interface down), the daemon keeps its last
/// complete plan for up to `failureGrace` of awake time while the supervisor
/// re-observes. Every other failure, such as a channel refusal, an activation
/// mismatch, or a configuration conflict, is a fault and restores ordinary DNS
/// at once. Every bypass records its reason durably.
///
/// ADR-0030: returning is damped. After a bypass the daemon must answer
/// continuously for the period `rearmDamping` sets before Remap re-arms, so
/// one lucky exchange on a loaded Mac cannot flip DNS back and forth.
///
/// ADR-0036: upstreams that stopped answering are a fault, so ordinary DNS
/// is restored at once; another agent holding the resolver macOS uses is
/// not, so nothing is written and nothing is bypassed until it lets go.
public final class ResolverSupervisor: Sendable {
    private let reconciler: ResolverReconciler
    private let monitor: any ResolverChangeMonitoring
    private let timing: ResolverSupervisorTiming
    private let bypassLog: any ResolverBypassRecording
    private let observe: @Sendable (ResolverSupervisorState) -> Void

    private var clock: any ResolverSupervisorClock {
        timing.clock
    }

    public convenience init(
        reconciler: ResolverReconciler,
        monitor: any ResolverChangeMonitoring = ResolverChangeMonitor(),
        interval: Duration = .seconds(5),
        retryInterval: Duration = .milliseconds(250),
        failureGrace: Duration = .seconds(20),
        rearmDamping: ResolverRearmDamping = .standard,
        bypassLog: any ResolverBypassRecording = DiscardedResolverBypassLog(),
        observe: @escaping @Sendable (ResolverSupervisorState) -> Void = { _ in }
    ) {
        self.init(
            reconciler: reconciler,
            monitor: monitor,
            timing: ResolverSupervisorTiming(
                interval: interval,
                retryInterval: retryInterval,
                failureGrace: failureGrace,
                rearmDamping: rearmDamping
            ),
            bypassLog: bypassLog,
            observe: observe
        )
    }

    init(
        reconciler: ResolverReconciler,
        monitor: any ResolverChangeMonitoring,
        timing: ResolverSupervisorTiming,
        bypassLog: any ResolverBypassRecording = DiscardedResolverBypassLog(),
        observe: @escaping @Sendable (ResolverSupervisorState) -> Void = { _ in }
    ) {
        precondition(timing.failureGrace >= .zero)
        precondition(timing.retryInterval > .zero)
        self.reconciler = reconciler
        self.monitor = monitor
        self.timing = timing
        self.bypassLog = bypassLog
        self.observe = observe
    }

    /// Runs until its task is cancelled, coalescing native events with periodic health checks.
    public func run() async {
        var progress = SupervisorProgress(
            bypass: bypassLog.lastBypass(),
            backoff: ResolverRearmBackoff(timing.rearmDamping)
        )
        let monitorAvailable: Bool
        do {
            try monitor.start()
            monitorAvailable = true
        } catch {
            monitorAvailable = false
        }
        guard await cycle(monitorAvailable: monitorAvailable, progress: &progress) else { return }
        for await _ in triggerStream(changes: monitor.events, interval: timing.interval) {
            guard !Task.isCancelled,
                  await cycle(monitorAvailable: monitorAvailable, progress: &progress) else { return }
        }
    }

    /// Returns false once the supervisor has been cancelled.
    private func cycle(
        monitorAvailable: Bool,
        progress: inout SupervisorProgress
    ) async -> Bool {
        guard await reconcileOrBypass(monitorAvailable: monitorAvailable, progress: &progress) else {
            return !Task.isCancelled
        }
        return await recoverFromBypass(monitorAvailable: monitorAvailable, progress: &progress)
    }

    /// Returns true after ordinary DNS has been restored and Remap is bypassed.
    private func reconcileOrBypass(
        monitorAvailable: Bool,
        progress: inout SupervisorProgress
    ) async -> Bool {
        while true {
            let state = await reconcile(monitorAvailable: monitorAvailable)
            report(state, progress: &progress)
            if case .deferred = state {
                // Ordinary DNS through another agent is already in effect.
                progress.failure = nil
                return false
            }
            guard case let .degraded(code) = state, code != monitorDegradedCode else {
                progress.failure = nil
                noteRearmed(progress: &progress)
                return false
            }
            let failure = progress.failure.map { $0.withCode(code) }
                ?? FailureWindow(start: clock.now, startDate: Date(), code: code)
            progress.failure = failure
            // Only an incomplete network observation is held: the daemon still
            // has a complete plan and nothing has been refused. Any other
            // failure is a fault, and ordinary DNS is restored now.
            guard code == networkUnobservedCode else {
                break
            }
            let remaining = timing.failureGrace - (clock.now - failure.start)
            if remaining <= .zero {
                break
            }
            guard !Task.isCancelled else {
                return false
            }
            do {
                try await clock.sleep(for: min(timing.retryInterval, remaining))
            } catch {
                return false
            }
        }
        return await bypass(progress: &progress)
    }

    private func bypass(progress: inout SupervisorProgress) async -> Bool {
        let failure = progress.failure ?? FailureWindow(
            start: clock.now,
            startDate: Date(),
            code: "E_RESOLVER_INTERNAL"
        )
        let code: String
        var release = ResolverBypassRelease.released
        do {
            release = try await reconciler.enterSafeBypass()
            code = "E_RESOLVER_SAFE_BYPASS"
        } catch {
            code = "E_RESOLVER_SAFE_BYPASS_FAILED"
        }
        let unreleased: UUID? = if case let .pending(activationID) = release {
            activationID
        } else {
            nil
        }
        progress.backoff.noteBypass(at: clock.now, policy: timing.rearmDamping)
        let payload = ResolverBypassPayload(
            reasonCode: failure.code,
            outcomeCode: code,
            failingSinceMilliseconds: unixMilliseconds(failure.startDate),
            bypassedAtMilliseconds: unixMilliseconds(Date()),
            releasePending: release != .released,
            unreleasedActivationID: unreleased,
            rearmAfterHealthyMilliseconds: awakeMilliseconds(progress.backoff.required)
        )
        bypassLog.record(payload)
        progress.bypass = payload
        report(.bypassed(code: code), progress: &progress)
        guard code == "E_RESOLVER_SAFE_BYPASS" else {
            // Ordinary DNS may still point at Remap. Keep the expired window
            // so the next failed reconciliation retries the bypass at once.
            return false
        }
        progress.failure = nil
        return true
    }

    /// Keeps ordinary DNS active while probing for a healthy daemon. Only
    /// once the daemon has answered every probe for the period the backoff
    /// requires does the reconciler publish and verify a complete generation
    /// and commit the retained prepared activation back to SystemConfiguration.
    /// Any failed probe, or a failed reconciliation at the end of the period,
    /// starts the period again; neither counts as a further bypass.
    private func recoverFromBypass(
        monitorAvailable: Bool,
        progress: inout SupervisorProgress
    ) async -> Bool {
        var healthySince: Duration?
        while !Task.isCancelled {
            do {
                try await clock.sleep(for: timing.retryInterval)
            } catch {
                return false
            }
            guard await daemonAnswers() else {
                healthySince = nil
                continue
            }
            let since = healthySince ?? clock.now
            healthySince = since
            guard clock.now - since >= progress.backoff.required else {
                continue
            }
            let state = await reconcile(monitorAvailable: monitorAvailable)
            guard state == .ready || state == .degraded(code: monitorDegradedCode) else {
                if case .deferred = state {
                    report(state, progress: &progress)
                }
                healthySince = nil
                continue
            }
            report(state, progress: &progress)
            noteRearmed(progress: &progress)
            return true
        }
        return false
    }

    /// Whether the daemon answered a health probe that changes nothing.
    private func daemonAnswers() async -> Bool {
        do {
            try await reconciler.probe()
            return true
        } catch {
            return false
        }
    }

    private func reconcile(monitorAvailable: Bool) async -> ResolverSupervisorState {
        do {
            try await reconciler.reconcile()
            return monitorAvailable ? .ready : .degraded(code: monitorDegradedCode)
        } catch let deferral as ResolverDeferral {
            return .deferred(code: deferral.code)
        } catch {
            return .degraded(code: supervisorErrorCode(error))
        }
    }

    private func noteRearmed(progress: inout SupervisorProgress) {
        progress.backoff.noteArmed(at: clock.now)
        guard let bypass = progress.bypass, bypass.rearmedAtMilliseconds == nil else { return }
        let rearmed = bypass.rearmed(atMilliseconds: unixMilliseconds(Date()))
        bypassLog.record(rearmed)
        progress.bypass = rearmed
    }

    private func report(
        _ state: ResolverSupervisorState,
        progress: inout SupervisorProgress
    ) {
        guard progress.previous != state else { return }
        progress.previous = state
        observe(state)
    }
}

private let monitorDegradedCode = "E_RESOLVER_MONITOR"
let upstreamUnansweredCode = "E_RESOLVER_UPSTREAM_UNANSWERED"
private let networkUnobservedCode = "E_RESOLVER_NETWORK_UNOBSERVED"

/// The supervisor loop's own memory between reconciliations.
private struct SupervisorProgress {
    var previous: ResolverSupervisorState?
    var failure: FailureWindow?
    var bypass: ResolverBypassPayload?
    var backoff: ResolverRearmBackoff
}

/// The first failure of an unbroken run, in the supervisor clock's awake time.
private struct FailureWindow {
    let start: Duration
    let startDate: Date
    let code: String

    func withCode(_ code: String) -> FailureWindow {
        FailureWindow(start: start, startDate: startDate, code: code)
    }
}

private func triggerStream(
    changes: AsyncStream<Void>,
    interval: Duration
) -> AsyncStream<Void> {
    AsyncStream(bufferingPolicy: .bufferingNewest(1)) { continuation in
        let changeTask = Task {
            for await _ in changes {
                guard !Task.isCancelled else { return }
                continuation.yield(())
            }
        }
        let timerTask = Task {
            while !Task.isCancelled {
                do {
                    try await Task.sleep(for: interval)
                } catch {
                    return
                }
                continuation.yield(())
            }
        }
        continuation.onTermination = { @Sendable _ in
            changeTask.cancel()
            timerTask.cancel()
        }
    }
}

/// Accepts only `E_` codes of uppercase letters, digits, and underscores, so a
/// refusal can never place free text in the log or the durable bypass record.
func isStableErrorCode(_ code: String) -> Bool {
    code.utf8.count <= 64
        && code.hasPrefix("E_")
        && code.utf8.allSatisfy { byte in
            (byte >= 65 && byte <= 90) || (byte >= 48 && byte <= 57) || byte == 95
        }
}

private func supervisorErrorCode(_ error: Error) -> String {
    switch error {
    case is ResolverChannelError:
        "E_RESOLVER_CHANNEL"
    case is ResolverUpstreamsUnanswered:
        upstreamUnansweredCode
    case let refusal as ResolverSystemDiagnostic:
        // The authenticated daemon's own stable code says why it refused.
        isStableErrorCode(refusal.code) ? refusal.code : "E_RESOLVER_DAEMON_REFUSED"
    case is ResolverReconciliationError:
        "E_RESOLVER_RECONCILIATION"
    case let error as ResolverError where error.isIncompleteNetworkObservation:
        networkUnobservedCode
    case is ResolverError:
        "E_RESOLVER_PLAN"
    default:
        "E_RESOLVER_INTERNAL"
    }
}
