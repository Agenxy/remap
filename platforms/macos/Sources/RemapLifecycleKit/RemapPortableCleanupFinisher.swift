import Darwin
import Foundation
import RemapInstallKit

public enum RemapPortableCleanupFinisher {
    public static let argument = "--finish-portable-uninstall"

    public static func launch(approvalToken: InstallApprovalToken) throws {
        let cleanup = try MacOSPortableAuthorityCleanup.production()
        _ = try cleanup.validatePendingPlan(expectedApprovalToken: approvalToken)
        try spawn(approvalToken: approvalToken)
    }

    public static func finish(approvalToken: InstallApprovalToken) throws {
        let lease = try MacOSPortableAuthorityLock.acquire()
        _ = lease
        try MacOSPortableAuthorityCleanup.production().perform(
            expectedApprovalToken: approvalToken,
            beforeRemovingHelper: MacOSInstallerServiceLaunchd.bootoutIfLoaded
        )
    }

    public static func finish(approvalTokenString: String) throws {
        try finish(approvalToken: InstallApprovalToken(approvalTokenString))
    }

    private static func spawn(approvalToken: InstallApprovalToken) throws {
        let executable = MacOSInstallerServiceLaunchd.programPath
        var actions: posix_spawn_file_actions_t?
        var attributes: posix_spawnattr_t?
        guard posix_spawn_file_actions_init(&actions) == 0,
              posix_spawnattr_init(&attributes) == 0
        else {
            throw InstallError.operatingSystem("initialize the portable cleanup finisher", errno)
        }
        defer {
            posix_spawn_file_actions_destroy(&actions)
            posix_spawnattr_destroy(&attributes)
        }
        let opens = [
            posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0),
            posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0),
            posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0)
        ]
        guard opens.allSatisfy({ $0 == 0 }) else {
            throw InstallError.operatingSystem("isolate the portable cleanup finisher", errno)
        }
        let flags = Int16(POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_CLOEXEC_DEFAULT)
        guard posix_spawnattr_setflags(&attributes, flags) == 0,
              posix_spawnattr_setpgroup(&attributes, 0) == 0
        else {
            throw InstallError.operatingSystem("isolate the portable cleanup process group", errno)
        }
        let arguments = [executable, argument, approvalToken.description]
        let environment = [
            "HOME=/var/root",
            "LANG=C",
            "LC_ALL=C",
            "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
            "TMPDIR=/private/var/tmp"
        ]
        var processID: pid_t = 0
        let status = withCStringArray(arguments) { argumentValues in
            withCStringArray(environment) { environmentValues in
                posix_spawn(
                    &processID,
                    executable,
                    &actions,
                    &attributes,
                    argumentValues,
                    environmentValues
                )
            }
        }
        guard status == 0, processID > 1 else {
            throw InstallError.operatingSystem("start the portable cleanup finisher", status)
        }
    }

    private static func withCStringArray<T>(
        _ values: [String],
        _ body: ([UnsafeMutablePointer<CChar>?]) throws -> T
    ) rethrows -> T {
        let allocated = values.map { strdup($0) }
        defer { allocated.forEach { free($0) } }
        return try body(allocated + [nil])
    }
}
