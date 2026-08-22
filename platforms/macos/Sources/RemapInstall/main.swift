import Darwin
import RemapInstallKit

do {
    let activityLease = try MacOSBootstrapHelperActivityLease.acquireForCurrentExecutable()
    let status = await RemapInstallCLI.run(arguments: Array(CommandLine.arguments.dropFirst()))
    withExtendedLifetime(activityLease) {}
    exit(status)
} catch {
    RemapInstallOutput.failure(error, json: CommandLine.arguments.contains("--json"))
    exit(RemapInstallOutput.exitStatus(for: error))
}
