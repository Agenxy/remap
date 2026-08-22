import Darwin
import Foundation
import RemapInstallKit

enum PortableInstallTopology {
    static let installerPath = "/Library/Application Support/Agenxy/Remap/Installer"
    static let sourcesPath = installerPath + "/Sources"

    static func ensureSourceDirectory() throws {
        guard geteuid() == 0 else {
            throw InstallError.notRoot
        }
        try ensure(
            parent: "/Library/Application Support",
            component: "Agenxy",
            mode: 0o755
        )
        try ensure(
            parent: "/Library/Application Support/Agenxy",
            component: "Remap",
            mode: 0o711
        )
        try ensure(
            parent: "/Library/Application Support/Agenxy/Remap",
            component: "Installer",
            mode: 0o700
        )
        try ensure(parent: installerPath, component: "Sources", mode: 0o700)
    }

    private static func ensure(parent: String, component: String, mode: mode_t) throws {
        let parentDescriptor = open(parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parentDescriptor >= 0 else {
            throw InstallError.operatingSystem("open portable installer storage", errno)
        }
        defer { close(parentDescriptor) }
        var status = stat()
        if fstatat(parentDescriptor, component, &status, AT_SYMLINK_NOFOLLOW) != 0 {
            guard errno == ENOENT,
                  mkdirat(parentDescriptor, component, mode) == 0,
                  fchownat(parentDescriptor, component, 0, 0, AT_SYMLINK_NOFOLLOW) == 0
            else {
                throw InstallError.operatingSystem("create portable installer storage", errno)
            }
            guard fsync(parentDescriptor) == 0 else {
                throw InstallError.operatingSystem("persist portable installer storage", errno)
            }
        }
        guard fstatat(parentDescriptor, component, &status, AT_SYMLINK_NOFOLLOW) == 0,
              status.st_mode & S_IFMT == S_IFDIR,
              status.st_uid == 0,
              status.st_gid == 0,
              status.st_mode & 0o777 == mode,
              status.st_flags == 0
        else {
            throw InstallError.metadata("portable installer storage has unsafe metadata")
        }
    }
}
