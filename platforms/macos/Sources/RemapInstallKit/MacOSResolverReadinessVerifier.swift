import Foundation

/// Waits for macOS's effective resolver state to converge and remain exact.
/// Runtime listener health is intentionally outside this verifier.
struct MacOSResolverReadinessVerifier: Sendable {
    private let timeout: Duration
    private let retryDelay: Duration
    private let requiredConsecutiveObservations: Int

    init(
        timeout: Duration = .seconds(15),
        retryDelay: Duration = .milliseconds(250),
        requiredConsecutiveObservations: Int = 2
    ) {
        precondition(requiredConsecutiveObservations > 1)
        self.timeout = timeout
        self.retryDelay = retryDelay
        self.requiredConsecutiveObservations = requiredConsecutiveObservations
    }

    func wait(observation: () throws -> Bool) async throws {
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: timeout)
        var consecutive = 0
        repeat {
            if try observation() {
                consecutive += 1
                if consecutive == requiredConsecutiveObservations {
                    return
                }
            } else {
                consecutive = 0
            }
            guard clock.now < deadline else { break }
            try await Task.sleep(for: retryDelay)
        } while clock.now < deadline
        throw InstallError.integrity(
            "system DNS did not settle on the intended Remap generation"
        )
    }
}
