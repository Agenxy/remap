import Foundation

/// Privacy-safe health state for the root resolver supervisor.
public enum ResolverSupervisorState: Equatable, Sendable {
    case bypassed(code: String)
    case degraded(code: String)
    case ready
}

/// Reconciles native resolver changes and daemon restarts without holding user data.
public final class ResolverSupervisor: Sendable {
    private let reconciler: ResolverReconciler
    private let monitor: any ResolverChangeMonitoring
    private let interval: Duration
    private let retryInterval: Duration
    private let maximumConsecutiveFailures: Int
    private let observe: @Sendable (ResolverSupervisorState) -> Void

    public init(
        reconciler: ResolverReconciler,
        monitor: any ResolverChangeMonitoring = ResolverChangeMonitor(),
        interval: Duration = .seconds(5),
        retryInterval: Duration = .milliseconds(250),
        maximumConsecutiveFailures: Int = 1,
        observe: @escaping @Sendable (ResolverSupervisorState) -> Void = { _ in }
    ) {
        precondition(maximumConsecutiveFailures > 0)
        self.reconciler = reconciler
        self.monitor = monitor
        self.interval = interval
        self.retryInterval = retryInterval
        self.maximumConsecutiveFailures = maximumConsecutiveFailures
        self.observe = observe
    }

    /// Runs until its task is cancelled, coalescing native events with periodic health checks.
    public func run() async {
        var previousState: ResolverSupervisorState?
        let monitorAvailable: Bool
        do {
            try monitor.start()
            monitorAvailable = true
        } catch {
            monitorAvailable = false
        }
        if await reconcileOrBypass(monitorAvailable: monitorAvailable, previous: &previousState) {
            guard await recoverFromBypass(
                monitorAvailable: monitorAvailable,
                previous: &previousState
            ) else { return }
        }
        for await _ in triggerStream(changes: monitor.events, interval: interval) {
            guard !Task.isCancelled else { return }
            if await reconcileOrBypass(monitorAvailable: monitorAvailable, previous: &previousState) {
                guard await recoverFromBypass(
                    monitorAvailable: monitorAvailable,
                    previous: &previousState
                ) else { return }
            }
        }
    }

    /// Returns true after ordinary DNS has been restored and Remap is bypassed.
    private func reconcileOrBypass(
        monitorAvailable: Bool,
        previous: inout ResolverSupervisorState?
    ) async -> Bool {
        for attempt in 1 ... maximumConsecutiveFailures {
            let state = await reconcile(monitorAvailable: monitorAvailable)
            report(state, previous: &previous)
            if case .ready = state {
                return false
            }
            if state == .degraded(code: "E_RESOLVER_MONITOR") {
                return false
            }
            if attempt == maximumConsecutiveFailures {
                break
            }
            guard !Task.isCancelled else {
                return false
            }
            do {
                try await Task.sleep(for: retryInterval)
            } catch {
                return false
            }
        }
        let code: String
        do {
            try await reconciler.enterSafeBypass()
            code = "E_RESOLVER_SAFE_BYPASS"
        } catch {
            code = "E_RESOLVER_SAFE_BYPASS_FAILED"
        }
        report(.bypassed(code: code), previous: &previous)
        return code == "E_RESOLVER_SAFE_BYPASS"
    }

    /// Keeps ordinary DNS active while probing for a healthy daemon. The
    /// reconciler publishes and verifies a complete generation before it
    /// commits the retained prepared activation back to SystemConfiguration.
    private func recoverFromBypass(
        monitorAvailable: Bool,
        previous: inout ResolverSupervisorState?
    ) async -> Bool {
        while !Task.isCancelled {
            do {
                try await Task.sleep(for: retryInterval)
            } catch {
                return false
            }
            let state = await reconcile(monitorAvailable: monitorAvailable)
            if case .ready = state {
                report(state, previous: &previous)
                return true
            }
        }
        return false
    }

    private func reconcile(monitorAvailable: Bool) async -> ResolverSupervisorState {
        do {
            try await reconciler.reconcile()
            return monitorAvailable ? .ready : .degraded(code: "E_RESOLVER_MONITOR")
        } catch {
            return .degraded(code: supervisorErrorCode(error))
        }
    }

    private func report(
        _ state: ResolverSupervisorState,
        previous: inout ResolverSupervisorState?
    ) {
        guard previous != state else { return }
        previous = state
        observe(state)
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

private func supervisorErrorCode(_ error: Error) -> String {
    switch error {
    case is ResolverChannelError:
        "E_RESOLVER_CHANNEL"
    case is ResolverReconciliationError:
        "E_RESOLVER_RECONCILIATION"
    case is ResolverError:
        "E_RESOLVER_PLAN"
    default:
        "E_RESOLVER_INTERNAL"
    }
}
