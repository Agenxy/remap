import Foundation
import RemapInstallKit

/// Requires complete installed state to remain true across more than one
/// observation. launchd and SystemConfiguration settle independently, so a
/// single successful listener probe is not a safe package-commit boundary.
struct PortableInstalledReadinessVerifier {
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

    func wait(
        observation: () async throws -> Bool
    ) async throws {
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: timeout)
        var consecutive = 0
        repeat {
            if try await observation() {
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
            "Remap's services did not settle into a complete ready state"
        )
    }
}
