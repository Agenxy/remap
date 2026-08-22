@testable import RemapInstallKit
import Synchronization
import Testing

@Test
func resolverReadinessRequiresConsecutiveExactSystemObservations() async throws {
    let observations = Mutex([true, false, true, true])
    let count = Mutex(0)
    let verifier = MacOSResolverReadinessVerifier(
        timeout: .seconds(10),
        retryDelay: .milliseconds(1),
        requiredConsecutiveObservations: 2
    )

    try await verifier.wait {
        count.withLock { $0 += 1 }
        return observations.withLock { values in values.removeFirst() }
    }

    #expect(count.withLock { $0 } == 4)
}

@Test
func resolverReadinessRejectsListenerHealthWithoutSystemDNS() async {
    let verifier = MacOSResolverReadinessVerifier(
        timeout: .milliseconds(10),
        retryDelay: .milliseconds(1),
        requiredConsecutiveObservations: 2
    )

    await #expect(throws: InstallError.self) {
        try await verifier.wait { false }
    }
}
