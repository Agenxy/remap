import Foundation
import RemapControlKit

struct MacOSRuntimeHealth: Equatable, Sendable {
    let daemonVersion: String?
    let authority: Bool
    let dns: Bool
    let http: Bool
}

enum MacOSRuntimeRequirement: Sendable {
    case authority
    case dns
    case ready
    case unavailable
}

protocol MacOSRuntimeHealthChecking: Sendable {
    func wait(
        configuration: MacOSInstallConfiguration,
        productVersion: String,
        requirement: MacOSRuntimeRequirement
    ) async throws -> MacOSRuntimeHealth
}

struct NativeMacOSRuntimeHealthChecker: MacOSRuntimeHealthChecking, Sendable {
    // The admitted launchd definitions use a five-second throttle interval.
    // Allow one complete throttle window plus the bounded authenticated control,
    // DNS, and HTTP challenge before declaring startup unhealthy.
    private static let timeout = Duration.seconds(10)
    private static let retryDelay = Duration.milliseconds(100)

    func wait(
        configuration: MacOSInstallConfiguration,
        productVersion: String,
        requirement: MacOSRuntimeRequirement
    ) async throws -> MacOSRuntimeHealth {
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: Self.timeout)
        var latest = MacOSRuntimeHealth(daemonVersion: nil, authority: false, dns: false, http: false)
        repeat {
            let client = RemapControlClient(
                socketPath: configuration.controlSocket.value,
                clientVersion: productVersion
            )
            let status = await RemapRuntimeProbe.verify(
                client: client,
                dnsPort: configuration.dnsPort,
                httpPort: configuration.httpPort
            )
            latest = MacOSRuntimeHealth(
                daemonVersion: status.daemonVersion,
                authority: status.authority,
                dns: status.dns,
                http: status.http
            )
            if satisfies(latest, requirement: requirement, productVersion: productVersion) {
                return latest
            }
            if clock.now < deadline {
                try await Task.sleep(for: Self.retryDelay)
            }
        } while clock.now < deadline
        throw InstallError
            .integrity("the authenticated Remap runtime did not reach the required state within ten seconds")
    }

    private func satisfies(
        _ health: MacOSRuntimeHealth,
        requirement: MacOSRuntimeRequirement,
        productVersion: String
    ) -> Bool {
        switch requirement {
        case .authority:
            health.authority && health.daemonVersion == productVersion
        case .dns:
            health.authority && health.dns && health.daemonVersion == productVersion
        case .ready:
            health.authority && health.dns && health.http && health.daemonVersion == productVersion
        case .unavailable:
            !health.authority && !health.dns && !health.http
        }
    }
}
