// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
@testable import RemapSystemKit
import Synchronization

/// A resolver channel that keeps `remapd`'s plan-store rules: a generation at
/// or below the highest ever accepted is refused, invalidation clears the
/// active plan but never the high-water, and one activation is bound at a time.
///
/// Results are decoded from the daemon's JSON wire form, so the reconciler
/// sees exactly what `ResolverSystemChannel` would decode.
final class ResolverTestDaemon: ResolverSystemExchanging, Sendable {
    struct State {
        var activationID: UUID?
        var activeGeneration: UInt64?
        var highestGeneration: UInt64 = 0
        var reportsHighWater = true
        var refusesEverything = false
        var refusesInvalidation = false
        var refusesPublication = false
        var publications: [UInt64] = []
        var publishedUpstreams: [String] = []
        var invalidations: [UUID] = []
        /// An upstream set the daemon judges unanswered (ADR-0036). Like
        /// `remapd`, it reports the verdict while that exact set, in any
        /// order, is the last one published, including after invalidation.
        var unansweredUpstreams: [String]?
        var loopbackReservations: [String] = []
        var unheldListeners: [LoopbackListener] = []
        var adoptedDescriptorCounts: [Int] = []
    }

    private let state: Mutex<State>

    init(_ initial: State = State()) {
        state = Mutex(initial)
    }

    func update(_ change: (inout State) -> Void) {
        state.withLock { change(&$0) }
    }

    func snapshot() -> State {
        state.withLock { $0 }
    }

    func exchange(_ command: ResolverSystemCommand) throws -> ResolverSystemResult {
        try exchange(command, passing: [])
    }

    func exchange(
        _ command: ResolverSystemCommand,
        passing descriptors: [Int32]
    ) throws -> ResolverSystemResult {
        let encoded = try state.withLock { state in
            if state.refusesEverything {
                throw ResolverChannelError.transport
            }
            switch command {
            case .health:
                break
            case let .publish(activationID, generation, upstreams):
                try publish(&state, activationID: activationID, generation: generation)
                state.publishedUpstreams = upstreams
            case let .invalidate(activationID, generation):
                try invalidate(&state, activationID: activationID, generation: generation)
            case .loopbackReservations:
                return try wireResult(state, loopbackReservations: state.loopbackReservations)
            case let .adoptListeners(listeners):
                // remapd adopts one descriptor per listener, in order, or none.
                guard listeners.count == descriptors.count else {
                    throw try daemonDiagnostic("E_SYSTEM_DESCRIPTORS")
                }
                state.adoptedDescriptorCounts.append(descriptors.count)
                state.unheldListeners.removeAll(where: listeners.contains)
                return try wireResult(state, loopbackReservations: state.loopbackReservations)
            }
            return try wireResult(state)
        }
        return try JSONDecoder().decode(ResolverSystemResult.self, from: encoded)
    }

    private func publish(_ state: inout State, activationID: UUID, generation: UInt64) throws {
        if state.refusesPublication {
            throw try daemonDiagnostic("E_RESOLVER_ACTIVATION")
        }
        if let bound = state.activationID, bound != activationID {
            throw try daemonDiagnostic("E_RESOLVER_ACTIVATION")
        }
        guard generation > state.highestGeneration else {
            throw try daemonDiagnostic("E_RESOLVER_PLAN")
        }
        state.highestGeneration = generation
        state.activationID = activationID
        state.activeGeneration = generation
        state.publications.append(generation)
    }

    private func invalidate(_ state: inout State, activationID: UUID, generation: UInt64) throws {
        if state.refusesInvalidation {
            throw ResolverChannelError.transport
        }
        if state.activationID == nil, state.activeGeneration == nil {
            return
        }
        guard state.activationID == activationID else {
            throw try daemonDiagnostic("E_RESOLVER_ACTIVATION")
        }
        guard state.activeGeneration == generation else {
            throw try daemonDiagnostic("E_RESOLVER_GENERATION")
        }
        state.activationID = nil
        state.activeGeneration = nil
        state.invalidations.append(activationID)
    }

    private func wireResult(_ state: State, loopbackReservations: [String]? = nil) throws -> Data {
        var object: [String: Any] = [
            "activation_id": state.activationID.map { $0.uuidString.lowercased() } ?? NSNull(),
            "active_generation": state.activeGeneration.map { NSNumber(value: $0) } ?? NSNull()
        ]
        let exceedsActive = state.highestGeneration > (state.activeGeneration ?? 0)
        if state.reportsHighWater, state.highestGeneration > 0, exceedsActive {
            object["highest_accepted_generation"] = NSNumber(value: state.highestGeneration)
        }
        if let unanswered = state.unansweredUpstreams, unanswered.sorted() == state.publishedUpstreams.sorted() {
            object["upstream_failure"] = [
                "cause": "timed_out",
                "unanswered_queries": 12,
                "unanswered_for_ms": 9000
            ]
        }
        if let loopbackReservations {
            object["loopback_reservations"] = loopbackReservations
            object["unheld_listeners"] = state.unheldListeners.map { ["address": $0.address, "port": Int($0.port)] }
        }
        return try JSONSerialization.data(withJSONObject: object)
    }
}

func daemonDiagnostic(_ code: String) throws -> ResolverSystemDiagnostic {
    let json = #"{"code":"\#(code)","message":"refused","hint":null,"retryable":false}"#
    return try JSONDecoder().decode(ResolverSystemDiagnostic.self, from: Data(json.utf8))
}

func healingRecord(createdAt: UInt64 = 1, phase: ActivationPhase = .active) throws -> ActivationRecord {
    let service = DNSServiceRecord(
        serviceID: "service-a",
        priorConfiguration: nil,
        installedConfiguration: Data(),
        upstreams: ["192.0.2.53"]
    )
    return try ActivationRecord(payload: ActivationPayload(
        ownerUID: 501,
        createdAtMilliseconds: createdAt,
        productVersion: "0.2.0",
        phase: phase,
        services: [service]
    ))
}

/// Re-arms on the first healthy probe, as supervisors did before ADR-0030,
/// for tests whose subject is something other than re-arm damping.
let promptRearm = ResolverRearmDamping(base: .zero, cap: .zero, resetAfter: .seconds(1))

func singleServicePlan(_ upstream: String = "192.0.2.53") -> DNSPlan {
    DNSPlan(services: [DNSServicePlan(serviceID: "service-a", upstreams: [upstream])])
}

/// Change monitor that never reports a change; triggers come from the interval.
final class QuietResolverMonitor: ResolverChangeMonitoring, Sendable {
    let events: AsyncStream<Void>
    private let continuation: AsyncStream<Void>.Continuation

    init() {
        let pair = AsyncStream.makeStream(of: Void.self, bufferingPolicy: .bufferingNewest(1))
        events = pair.stream
        continuation = pair.continuation
    }

    func start() throws {}

    func finish() {
        continuation.finish()
    }
}

/// Polls a condition for up to `limit`, so a test waits for behavior rather than a fixed time.
func eventually(
    within limit: Duration = .seconds(5),
    _ condition: @Sendable () -> Bool
) async throws {
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: limit)
    while !condition(), clock.now < deadline {
        try await Task.sleep(for: .milliseconds(1))
    }
}
