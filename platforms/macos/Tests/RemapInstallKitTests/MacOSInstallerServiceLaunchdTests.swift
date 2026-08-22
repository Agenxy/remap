import Foundation
@testable import RemapInstallKit
import Testing

@Test
func lifecycleBootstrapLoadsAMissingExactJob() throws {
    let controller = InstallerServiceLaunchdControllerFake(observation: .missing)

    try MacOSInstallerServiceLaunchd.bootstrap(controller: controller)

    #expect(controller.bootstrapCount == 1)
    #expect(controller.kickstartCount == 0)
}

@Test
func lifecycleBootstrapRestartsAnAlreadyLoadedExactJob() throws {
    let controller = try InstallerServiceLaunchdControllerFake(observation: expectedObservation())

    try MacOSInstallerServiceLaunchd.bootstrap(controller: controller)

    #expect(controller.bootstrapCount == 0)
    #expect(controller.kickstartCount == 1)
}

@Test
func lifecycleBootstrapRejectsAForeignLoadedJobWithoutEffects() throws {
    let foreign = try MacOSLaunchdObservation.loaded(
        plistPath: InstallAbsolutePath("/Library/LaunchDaemons/foreign.plist"),
        programPath: InstallAbsolutePath("/Library/PrivilegedHelperTools/foreign")
    )
    let controller = InstallerServiceLaunchdControllerFake(observation: foreign)

    #expect(throws: InstallError.self) {
        try MacOSInstallerServiceLaunchd.bootstrap(controller: controller)
    }
    #expect(controller.bootstrapCount == 0)
    #expect(controller.kickstartCount == 0)
}

private func expectedObservation() throws -> MacOSLaunchdObservation {
    try .loaded(
        plistPath: InstallAbsolutePath(MacOSInstallerServiceLaunchd.plistPath),
        programPath: InstallAbsolutePath(MacOSInstallerServiceLaunchd.programPath)
    )
}

private final class InstallerServiceLaunchdControllerFake: @unchecked Sendable, MacOSLaunchdControlling {
    private let lock = NSLock()
    private var currentObservation: MacOSLaunchdObservation
    private var recordedBootstrapCount = 0
    private var recordedKickstartCount = 0

    var bootstrapCount: Int {
        lock.withLock { recordedBootstrapCount }
    }

    var kickstartCount: Int {
        lock.withLock { recordedKickstartCount }
    }

    init(observation: MacOSLaunchdObservation) {
        currentObservation = observation
    }

    func observation(label _: String) throws -> MacOSLaunchdObservation {
        lock.withLock { currentObservation }
    }

    func bootstrap(plistPath _: InstallAbsolutePath) throws {
        let expected = try expectedObservation()
        lock.withLock {
            recordedBootstrapCount += 1
            currentObservation = expected
        }
    }

    func bootout(label _: String) throws {}

    func enable(label _: String) throws {}

    func kickstart(label _: String) throws {
        lock.withLock { recordedKickstartCount += 1 }
    }
}
