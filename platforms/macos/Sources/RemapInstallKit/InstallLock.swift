import Darwin
import Foundation

enum InstallLockKind: Sendable {
    case ownedDirectory(ownerUID: UInt32, groupGID: UInt32, mode: UInt16)
    case privateFile
}

struct InstallLockConfiguration: Sendable {
    let authority: FileSystemAuthority
    let path: InstallRelativePath
    let kind: InstallLockKind

    func acquire() throws -> InstallTransactionLock {
        switch kind {
        case let .ownedDirectory(ownerUID, groupGID, mode):
            try InstallTransactionLock.acquireDirectory(
                authority: authority,
                at: path,
                ownerUID: ownerUID,
                groupGID: groupGID,
                mode: mode
            )
        case .privateFile:
            try InstallTransactionLock.acquire(authority: authority, at: path)
        }
    }
}

/// Exclusive process lock for install, update, uninstall, and recovery transactions.
public final class InstallTransactionLock: @unchecked Sendable {
    private let descriptor: Int32

    private init(descriptor: Int32) {
        self.descriptor = descriptor
    }

    deinit {
        _ = flock(descriptor, LOCK_UN)
        close(descriptor)
    }

    public static func acquire(
        authority: FileSystemAuthority,
        at path: InstallRelativePath
    ) throws -> InstallTransactionLock {
        let descriptor = try authority.openLockFile(at: path)
        return try acquire(descriptor: descriptor)
    }

    static func acquireDirectory(
        authority: FileSystemAuthority,
        at path: InstallRelativePath,
        ownerUID: UInt32,
        groupGID: UInt32,
        mode: UInt16
    ) throws -> InstallTransactionLock {
        try authority.ensureOwnedDirectory(
            at: path,
            ownerUID: ownerUID,
            groupGID: groupGID,
            mode: mode
        )
        let descriptor = try authority.openDirectoryLock(
            at: path,
            ownerUID: ownerUID,
            groupGID: groupGID,
            mode: mode
        )
        return try acquire(descriptor: descriptor)
    }

    private static func acquire(descriptor: Int32) throws -> InstallTransactionLock {
        guard flock(descriptor, LOCK_EX | LOCK_NB) == 0 else {
            let code = errno
            close(descriptor)
            if code == EWOULDBLOCK {
                throw InstallError.alreadyLocked
            }
            throw InstallError.operatingSystem("acquire installer transaction lock", code)
        }
        return InstallTransactionLock(descriptor: descriptor)
    }
}
