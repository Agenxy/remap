import Darwin
import Foundation

extension FileSystemAuthority {
    func validateSystemTraversalFlags(
        _ descriptor: Int32,
        relativePath: String
    ) throws {
        guard policy.systemFlags else {
            return
        }
        var status = stat()
        guard fstat(descriptor, &status) == 0 else {
            throw InstallError.operatingSystem("inspect system directory flags", errno)
        }
        guard InstallSystemNodeFlagPolicy.permitsTraversalFlags(
            status.st_flags,
            relativePath: relativePath
        ) else {
            throw InstallError.metadata("system directory \(relativePath) has unexpected flags")
        }
    }

    func permittedFlags(
        _ flags: UInt32,
        relativePath: String,
        permitsPlatformFlags: Bool
    ) -> Bool {
        guard policy.systemFlags else {
            return flags == 0
        }
        if permitsPlatformFlags {
            return InstallSystemNodeFlagPolicy.permitsCompatibleDirectoryFlags(
                flags,
                relativePath: relativePath
            )
        }
        return flags == 0
    }

    func permittedRootFlags(_ flags: UInt32) -> Bool {
        guard policy.systemFlags else {
            return flags == 0
        }
        return InstallSystemNodeFlagPolicy.permitsTraversalFlags(flags, relativePath: "")
    }
}
