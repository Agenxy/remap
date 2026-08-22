import Foundation
@testable import RemapApp
@testable import RemapControlKit
import RemapSystemKit
import Testing

@Test @MainActor
func coldStartNeverInventsAnEmptyRegistryOrListenerReadiness() async {
    let store = RemapStore(
        executeCommand: { _ in throw unavailableDiagnostic() },
        observeResolver: { throw TestObservationError.unavailable },
        verifyRuntime: { .unavailable }
    )

    await store.refresh()

    #expect(store.authorityState == .unavailable)
    #expect(store.status == nil)
    #expect(store.mappings.isEmpty)
    #expect(store.resolverState == .unavailable)
    #expect(store.dnsState == .unavailable)
    #expect(store.gatewayState == .unavailable)
    #expect(!store.isSystemReady)
    #expect(!store.canMutateMappings)
}

@Test @MainActor
func healthySnapshotRequiresResolverAndEveryAuthenticatedRuntimeSurface() async {
    let mapping = testMapping(pattern: "remap.test", revision: 4)
    let store = RemapStore(
        executeCommand: stableExecutor(revision: 4, mappings: [mapping]),
        observeResolver: {
            ResolverObservation(activeServiceIDs: ["service-a"], remapServiceIDs: ["service-a"])
        },
        verifyRuntime: { healthyRuntime() }
    )

    await store.refresh()

    #expect(store.authorityState == .ready)
    #expect(store.status?.revision == 4)
    #expect(store.mappings == [mapping])
    #expect(store.dnsState == .authenticated)
    #expect(store.gatewayState == .authenticated)
    #expect(store.isSystemReady)
    #expect(store.canMutateMappings)
}

@Test @MainActor
func partialRuntimeIdentityKeepsMappingsUsableButNeverClaimsSystemReadiness() async {
    let store = RemapStore(
        executeCommand: stableExecutor(revision: 2, mappings: []),
        observeResolver: {
            ResolverObservation(activeServiceIDs: ["service-a"], remapServiceIDs: ["service-a"])
        },
        verifyRuntime: {
            RemapRuntimeHealth(
                instanceID: "instance-a",
                daemonVersion: "0.1.0",
                authority: true,
                dns: false,
                http: true
            )
        }
    )

    await store.refresh()

    #expect(store.authorityState == .ready)
    #expect(store.canMutateMappings)
    #expect(store.dnsState == .unavailable)
    #expect(store.gatewayState == .authenticated)
    #expect(!store.isSystemReady)
}

@Test @MainActor
func refreshRetriesUntilStatusAndEveryPageShareOneRevision() async {
    let authority = RevisionChangingAuthority()
    let store = RemapStore(
        executeCommand: { command in try await authority.execute(command) },
        observeResolver: {
            ResolverObservation(activeServiceIDs: ["service-a"], remapServiceIDs: ["service-a"])
        },
        verifyRuntime: { healthyRuntime() }
    )

    await store.refresh()

    #expect(store.status?.revision == 2)
    #expect(store.mappings.map(\.updatedRevision) == [2])
    #expect(await authority.statusReads() == 4)
    #expect(store.isSystemReady)
}

private actor RevisionChangingAuthority {
    private var statusReadCount = 0
    private var listReadCount = 0

    func execute(_ command: RemapControlCommand) throws -> RemapCommandResult {
        switch command {
        case .status:
            statusReadCount += 1
            let revision: UInt64 = statusReadCount == 1 ? 1 : 2
            return .status(testStatus(revision: revision, count: 1))
        case .list:
            listReadCount += 1
            let revision: UInt64 = listReadCount == 1 ? 1 : 2
            return .list(RemapMappingPage(
                revision: revision,
                mappings: [testMapping(pattern: "remap.test", revision: revision)],
                nextCursor: nil
            ))
        default:
            throw unavailableDiagnostic()
        }
    }

    func statusReads() -> Int {
        statusReadCount
    }
}

private func stableExecutor(
    revision: UInt64,
    mappings: [RemapMapping]
) -> RemapStore.CommandExecutor {
    { command in
        switch command {
        case .status:
            .status(testStatus(revision: revision, count: UInt64(mappings.count)))
        case .list:
            .list(RemapMappingPage(
                revision: revision,
                mappings: mappings,
                nextCursor: nil
            ))
        default:
            throw unavailableDiagnostic()
        }
    }
}

private func testStatus(revision: UInt64, count: UInt64) -> RemapRegistryStatus {
    RemapRegistryStatus(
        revision: revision,
        mappingCount: count,
        enabledCount: count,
        schemaVersion: 1,
        daemonVersion: "0.1.0",
        maintenance: nil
    )
}

private func testMapping(pattern: String, revision: UInt64) -> RemapMapping {
    RemapMapping(
        pattern: pattern,
        target: "http://127.0.0.1:4270/",
        targetKind: "http",
        hostPolicy: .useUpstream,
        enabled: true,
        updatedRevision: revision
    )
}

private func healthyRuntime() -> RemapRuntimeHealth {
    RemapRuntimeHealth(
        instanceID: "instance-a",
        daemonVersion: "0.1.0",
        authority: true,
        dns: true,
        http: true
    )
}

private func unavailableDiagnostic() -> RemapDiagnostic {
    RemapDiagnostic(
        code: "E_DAEMON_UNAVAILABLE",
        message: "authority unavailable",
        hint: nil,
        retryable: true
    )
}

private enum TestObservationError: Error {
    case unavailable
}
