@testable import RemapPortableInstaller
import Synchronization
import Testing

@Test
func portableReadinessWaitsForTwoStableCompleteObservations() async throws {
    let observations = Mutex([false, true, false, true, true])
    let count = Mutex(0)
    let verifier = PortableInstalledReadinessVerifier(
        timeout: .seconds(1),
        retryDelay: .milliseconds(1),
        requiredConsecutiveObservations: 2
    )

    try await verifier.wait {
        count.withLock { $0 += 1 }
        return observations.withLock { values in values.removeFirst() }
    }

    #expect(count.withLock { $0 } == 5)
}

@Test
func portableReadinessRejectsAListenerThatNeverSettles() async {
    let verifier = PortableInstalledReadinessVerifier(
        timeout: .milliseconds(10),
        retryDelay: .milliseconds(1),
        requiredConsecutiveObservations: 2
    )

    await #expect(throws: Error.self) {
        try await verifier.wait { false }
    }
}
