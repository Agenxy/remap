import Foundation
@testable import RemapInstallKit
import Testing

@Test
func launchdBootoutWaitsForSIGTERMedToDisappearBeforeReturning() throws {
    let runner = TeardownRunner(results: [loadedJob(), success(), loadedJob(), missingJob()])
    try NativeMacOSLaunchdController(runner: runner).bootout(label: "org.agenxy.Remap.daemon", expected: expectedJob())
    #expect(runner.commands == [
        .print(label: "org.agenxy.Remap.daemon"),
        .bootout(label: "org.agenxy.Remap.daemon"),
        .print(label: "org.agenxy.Remap.daemon"),
        .print(label: "org.agenxy.Remap.daemon")
    ])
}

@Test
func launchdBootoutNamesTheJobWhenTeardownTimesOut() throws {
    let runner = TeardownRunner(results: [loadedJob(), success(), loadedJob()])
    #expect(throws: InstallError.integrity(
        "launchd did not unload org.agenxy.Remap.daemon before the teardown deadline"
    )) {
        try NativeMacOSLaunchdController(runner: runner, unloadTimeout: .zero)
            .bootout(label: "org.agenxy.Remap.daemon", expected: expectedJob())
    }
}

@Test
func launchdBootoutRefusesAReplacementJobDuringTeardown() throws {
    let runner = TeardownRunner(results: [loadedJob(), success(), loadedJob(program: "/foreign/remapd")])
    #expect(throws: InstallError.collision("launchd service org.agenxy.Remap.daemon")) {
        try NativeMacOSLaunchdController(runner: runner).bootout(
            label: "org.agenxy.Remap.daemon",
            expected: expectedJob()
        )
    }
    #expect(runner.commands.count == 3)
}

@Test
func launchdBootoutRefusesAReplacedJobBeforeAnyMutation() throws {
    let runner = TeardownRunner(results: [loadedJob(program: "/foreign/remapd")])
    #expect(throws: InstallError.collision("launchd service org.agenxy.Remap.daemon")) {
        try NativeMacOSLaunchdController(runner: runner)
            .bootout(label: "org.agenxy.Remap.daemon", expected: expectedJob())
    }
    #expect(runner.commands == [.print(label: "org.agenxy.Remap.daemon")])
}

private func expectedJob() throws -> MacOSLaunchdObservation {
    try .loaded(
        plistPath: InstallAbsolutePath("/Library/LaunchDaemons/org.agenxy.Remap.daemon.plist"),
        programPath: InstallAbsolutePath("/generation/libexec/remapd")
    )
}

@Test
func launchdBootoutOfAnAbsentJobHasNoMutation() throws {
    let runner = TeardownRunner(results: [missingJob()])
    try NativeMacOSLaunchdController(runner: runner).bootout(label: "org.agenxy.Remap.daemon", expected: expectedJob())
    #expect(runner.commands == [.print(label: "org.agenxy.Remap.daemon")])
}

private func loadedJob(program: String = "/generation/libexec/remapd") -> LaunchctlResult {
    LaunchctlResult(exitStatus: 0, output: """
    system/org.agenxy.Remap.daemon = {
    \tpath = /Library/LaunchDaemons/org.agenxy.Remap.daemon.plist
    \tprogram = \(program)
    \tstate = SIGTERMed
    }
    """)
}

private func success() -> LaunchctlResult {
    LaunchctlResult(exitStatus: 0, output: "")
}

private func missingJob() -> LaunchctlResult {
    LaunchctlResult(exitStatus: 113, output: "Could not find service")
}

private final class TeardownRunner: @unchecked Sendable, LaunchctlRunning {
    private let lock = NSLock()
    private var results: [LaunchctlResult]
    private var recorded: [LaunchctlCommand] = []

    var commands: [LaunchctlCommand] {
        lock.withLock { recorded }
    }

    init(results: [LaunchctlResult]) {
        self.results = results
    }

    func run(_ command: LaunchctlCommand) throws -> LaunchctlResult {
        try lock.withLock {
            guard !results.isEmpty else { throw InstallError.integrity("unexpected launchctl call") }
            recorded.append(command)
            return results.removeFirst()
        }
    }
}
