import Foundation
@testable import RemapSystemKit
import Synchronization
import Testing

@Test
func resolverReconcilerPublishesOneCompleteInitialGeneration() async throws {
    let record = try makeActiveRecord()
    let channel = RecordingResolverChannel()
    let reconciler = ResolverReconciler(
        channel: channel,
        loadRecord: { record },
        makePlan: { _ in
            DNSPlan(services: [
                DNSServicePlan(
                    serviceID: "service-a",
                    upstreams: ["192.0.2.53", "2001:db8::53"]
                )
            ])
        }
    )

    try await reconciler.reconcile()

    let expectedID = try record.activationIdentifier()
    #expect(channel.snapshot().events == [
        .health,
        .publish(
            activationID: expectedID,
            generation: 1,
            upstreams: ["192.0.2.53:53", "[2001:db8::53]:53"]
        )
    ])
}

@Test
func resolverReconcilerSkipsAnUnchangedPublishedPlan() async throws {
    let record = try makeActiveRecord()
    let channel = RecordingResolverChannel()
    let plan = DNSPlan(services: [
        DNSServicePlan(serviceID: "service-a", upstreams: ["192.0.2.53"])
    ])
    let reconciler = ResolverReconciler(
        channel: channel,
        loadRecord: { record },
        makePlan: { _ in plan }
    )

    try await reconciler.reconcile()
    try await reconciler.reconcile()

    #expect(channel.snapshot().events.filter(\.isPublish).count == 1)
    #expect(channel.snapshot().events.filter(\.isHealth).count == 2)
}

@Test
func resolverReconcilerKeepsTheLastPlanAcrossATransientNetworkGap() async throws {
    let record = try makeActiveRecord()
    let channel = RecordingResolverChannel()
    let currentPlan = Mutex<DNSPlan?>(DNSPlan(services: [
        DNSServicePlan(serviceID: "service-a", upstreams: ["192.0.2.53"])
    ]))
    let reconciler = ResolverReconciler(
        channel: channel,
        loadRecord: { record },
        makePlan: { _ in
            guard let plan = currentPlan.withLock({ $0 }) else {
                throw ResolverError.noUsableUpstream
            }
            return plan
        }
    )

    try await reconciler.reconcile()
    currentPlan.withLock { $0 = nil }
    await #expect(throws: ResolverError.noUsableUpstream) {
        try await reconciler.reconcile()
    }
    #expect(channel.snapshot().activeGeneration == 1)
    #expect(channel.snapshot().events.filter(\.isInvalidate).isEmpty)

    currentPlan.withLock {
        $0 = DNSPlan(services: [
            DNSServicePlan(serviceID: "service-a", upstreams: ["198.51.100.53"])
        ])
    }
    try await reconciler.reconcile()
    #expect(channel.snapshot().activeGeneration == 2)
    #expect(try channel.snapshot().events.last == .publish(
        activationID: record.activationIdentifier(),
        generation: 2,
        upstreams: ["198.51.100.53:53"]
    ))
}

@Test
func resolverReconcilerRepublishesAfterDaemonRestartEvenWhenAddressesMatch() async throws {
    let record = try makeActiveRecord()
    let channel = RecordingResolverChannel()
    let plan = DNSPlan(services: [
        DNSServicePlan(serviceID: "service-a", upstreams: ["192.0.2.53"])
    ])
    let reconciler = ResolverReconciler(
        channel: channel,
        loadRecord: { record },
        makePlan: { _ in plan }
    )

    try await reconciler.reconcile()
    channel.restartWithAnonymousStartupPlan()
    try await reconciler.reconcile()

    #expect(try channel.snapshot().events.last == .publish(
        activationID: record.activationIdentifier(),
        generation: 2,
        upstreams: ["192.0.2.53:53"]
    ))
}

@Test
func resolverReconcilerInvalidatesWhenActivationDisappears() async throws {
    let record = try makeActiveRecord()
    let currentRecord = Mutex<ActivationRecord?>(record)
    let channel = RecordingResolverChannel()
    let reconciler = ResolverReconciler(
        channel: channel,
        loadRecord: { currentRecord.withLock { $0 } },
        makePlan: { _ in
            DNSPlan(services: [
                DNSServicePlan(serviceID: "service-a", upstreams: ["192.0.2.53"])
            ])
        }
    )

    try await reconciler.reconcile()
    currentRecord.withLock { $0 = nil }
    try await reconciler.reconcile()

    let expectedID = try record.activationIdentifier()
    #expect(channel.snapshot().events.last == .invalidate(
        activationID: expectedID,
        generation: 1
    ))
    #expect(channel.snapshot().activeGeneration == nil)

    currentRecord.withLock { $0 = record }
    try await reconciler.reconcile()
    #expect(channel.snapshot().events.last == .publish(
        activationID: expectedID,
        generation: 2,
        upstreams: ["192.0.2.53:53"]
    ))
}

@Test
func resolverReconcilerRejectsAnActivationMismatch() async throws {
    let record = try makeActiveRecord()
    let channel = RecordingResolverChannel(
        activationID: UUID(),
        activeGeneration: 7
    )
    let reconciler = ResolverReconciler(
        channel: channel,
        loadRecord: { record },
        makePlan: { _ in
            DNSPlan(services: [
                DNSServicePlan(serviceID: "service-a", upstreams: ["192.0.2.53"])
            ])
        }
    )

    await #expect(throws: ResolverReconciliationError.activationMismatch) {
        try await reconciler.reconcile()
    }
    #expect(channel.snapshot().events == [.health])
}

@Test
func resolverReconcilerRejectsUnsafeAndMalformedUpstreams() async throws {
    let record = try makeActiveRecord()
    for upstream in ["127.0.0.1", "::1", "not-an-address", "[2001:db8::1]"] {
        let reconciler = ResolverReconciler(
            channel: RecordingResolverChannel(),
            loadRecord: { record },
            makePlan: { _ in
                DNSPlan(services: [
                    DNSServicePlan(serviceID: "service-a", upstreams: [upstream])
                ])
            }
        )
        await #expect(throws: ResolverReconciliationError.invalidUpstream) {
            try await reconciler.reconcile()
        }
    }
}

private enum RecordedResolverEvent: Equatable {
    case health
    case invalidate(activationID: UUID, generation: UInt64)
    case publish(activationID: UUID, generation: UInt64, upstreams: [String])

    var isHealth: Bool {
        if case .health = self {
            return true
        }
        return false
    }

    var isPublish: Bool {
        if case .publish = self {
            return true
        }
        return false
    }

    var isInvalidate: Bool {
        if case .invalidate = self {
            return true
        }
        return false
    }
}

private struct RecordingResolverState {
    var activationID: UUID?
    var activeGeneration: UInt64?
    var events: [RecordedResolverEvent] = []
}

private final class RecordingResolverChannel: ResolverSystemExchanging, Sendable {
    private let state: Mutex<RecordingResolverState>

    init(activationID: UUID? = nil, activeGeneration: UInt64? = nil) {
        state = Mutex(RecordingResolverState(
            activationID: activationID,
            activeGeneration: activeGeneration
        ))
    }

    func exchange(_ command: ResolverSystemCommand) throws -> ResolverSystemResult {
        state.withLock { state in
            switch command {
            case .health:
                state.events.append(.health)
            case let .invalidate(activationID, generation):
                state.events.append(.invalidate(
                    activationID: activationID,
                    generation: generation
                ))
                state.activeGeneration = nil
            case let .publish(activationID, generation, upstreams):
                state.events.append(.publish(
                    activationID: activationID,
                    generation: generation,
                    upstreams: upstreams
                ))
                state.activationID = activationID
                state.activeGeneration = generation
            }
            return ResolverSystemResult(
                activationID: state.activationID,
                activeGeneration: state.activeGeneration
            )
        }
    }

    func snapshot() -> RecordingResolverState {
        state.withLock { $0 }
    }

    func restartWithAnonymousStartupPlan() {
        state.withLock { state in
            state.activationID = nil
            state.activeGeneration = 1
        }
    }
}

private func makeActiveRecord() throws -> ActivationRecord {
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
