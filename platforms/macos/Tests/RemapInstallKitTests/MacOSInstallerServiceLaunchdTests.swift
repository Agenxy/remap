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

@Test
func launchdObservationReadsTheServiceFieldsNotANestedSocketPath() throws {
    // As `launchctl print` renders a daemon whose Sockets include a Unix socket:
    // the service's own `path` and `program` sit one tab deep, the socket's
    // `path` three.
    let output = """
    system/org.agenxy.Remap.daemon = {
    \tactive count = 0
    \tpath = /Library/LaunchDaemons/org.agenxy.Remap.daemon.plist
    \ttype = LaunchDaemon
    \tstate = spawn scheduled

    \tprogram = /Library/Application Support/Agenxy/Remap/Install/Generations/g/libexec/remapd
    \targuments = {
    \t\t/Library/Application Support/Agenxy/Remap/Install/Generations/g/libexec/remapd
    \t}
    \tstdout path = /dev/null
    \tsockets = {
    \t\t"remap-system" = {
    \t\t\ttype = stream
    \t\t\tpath = /var/run/org.agenxy.Remap.system.sock
    \t\t}
    \t}
    }
    """
    let controller = NativeMacOSLaunchdController(
        runner: FixedLaunchctlRunner(result: LaunchctlResult(exitStatus: 0, output: output))
    )
    let observation = try controller.observation(label: "org.agenxy.Remap.daemon")
    let expected = try MacOSLaunchdObservation.loaded(
        plistPath: InstallAbsolutePath("/Library/LaunchDaemons/org.agenxy.Remap.daemon.plist"),
        programPath: InstallAbsolutePath(
            "/Library/Application Support/Agenxy/Remap/Install/Generations/g/libexec/remapd"
        )
    )
    #expect(observation == expected)
}

private struct FixedLaunchctlRunner: LaunchctlRunning {
    let result: LaunchctlResult

    func run(_: LaunchctlCommand) throws -> LaunchctlResult {
        result
    }
}
