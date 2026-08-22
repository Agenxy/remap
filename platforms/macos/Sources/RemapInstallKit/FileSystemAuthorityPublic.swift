import Foundation

public extension FileSystemAuthority {
    /// Opens and pins one non-symlink, single-link regular file below this
    /// authority. The caller owns the returned descriptor and must close it.
    func openUniqueRegularFile(at path: InstallRelativePath) throws -> Int32 {
        try openRegularFile(path, rejectHardLinks: true)
    }

    /// Migrates one previously verified authority-owned directory between an
    /// explicitly bounded set of historical modes. No symlink, foreign owner,
    /// ACL, flag, or unexpected extended attribute is accepted.
    func transitionExactOwnedDirectoryMode(
        at path: InstallRelativePath,
        ownerUID: UInt32,
        groupGID: UInt32,
        permittedModes: Set<UInt16>,
        mode: UInt16
    ) throws {
        try transitionOwnedDirectoryMode(
            at: path,
            ownerUID: ownerUID,
            groupGID: groupGID,
            permittedModes: permittedModes,
            mode: mode
        )
    }
}
