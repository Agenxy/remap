import CryptoKit
import Darwin
import Foundation

public extension FileSystemAuthority {
    /// Verifies one exact authority file whose public mode may be writable by root.
    func verifyAuthorityFile(
        at path: InstallRelativePath,
        expectedDigest: InstallDigest,
        expectedByteCount: UInt64,
        ownerUID: UInt32,
        groupGID: UInt32,
        mode: UInt16
    ) throws {
        let descriptor = try openRegularFile(path, rejectHardLinks: true)
        defer { close(descriptor) }
        _ = try validateAuthorityFile(
            descriptor,
            path: path,
            expectedDigest: expectedDigest,
            expectedByteCount: expectedByteCount,
            ownerUID: ownerUID,
            groupGID: groupGID,
            mode: mode
        )
    }

    /// Unlinks the same pinned inode that was fully verified above.
    func unlinkAuthorityFile(
        at path: InstallRelativePath,
        expectedDigest: InstallDigest,
        expectedByteCount: UInt64,
        ownerUID: UInt32,
        groupGID: UInt32,
        mode: UInt16
    ) throws {
        try requireMutable()
        let descriptor = try openRegularFile(path, rejectHardLinks: true)
        defer { close(descriptor) }
        let opened = try validateAuthorityFile(
            descriptor,
            path: path,
            expectedDigest: expectedDigest,
            expectedByteCount: expectedByteCount,
            ownerUID: ownerUID,
            groupGID: groupGID,
            mode: mode
        )
        let location = try parentAndLeaf(path)
        defer { close(location.parent) }
        var current = stat()
        let inspected = location.leaf.withCString {
            fstatat(location.parent, $0, &current, AT_SYMLINK_NOFOLLOW)
        }
        guard inspected == 0,
              current.st_dev == opened.status.st_dev,
              current.st_ino == opened.status.st_ino,
              current.st_nlink == 1
        else {
            throw InstallError.collision(path.description)
        }
        try faultInjector.check(.beforeRemove)
        guard location.leaf.withCString({ unlinkat(location.parent, $0, 0) }) == 0 else {
            throw InstallError.operatingSystem("unlink authority file \(path)", errno)
        }
        try syncDirectory(location.parent, operation: "parent of \(path)")
    }

    /// Reads and verifies one authority file through the same pinned descriptor.
    func readAuthorityFile(
        at path: InstallRelativePath,
        expectedDigest: InstallDigest,
        expectedByteCount: UInt64,
        ownerUID: UInt32,
        groupGID: UInt32,
        mode: UInt16
    ) throws -> Data {
        let descriptor = try openRegularFile(path, rejectHardLinks: true)
        defer { close(descriptor) }
        return try validateAuthorityFile(
            descriptor,
            path: path,
            expectedDigest: expectedDigest,
            expectedByteCount: expectedByteCount,
            ownerUID: ownerUID,
            groupGID: groupGID,
            mode: mode
        ).data
    }

    private func validateAuthorityFile(
        _ descriptor: Int32,
        path: InstallRelativePath,
        expectedDigest: InstallDigest,
        expectedByteCount: UInt64,
        ownerUID: UInt32,
        groupGID: UInt32,
        mode: UInt16
    ) throws -> (status: stat, data: Data) {
        guard mode <= 0o777, expectedByteCount <= 134_217_728 else {
            throw InstallError.integrity("authority file expectation exceeds its bound")
        }
        var opened = stat()
        guard fstat(descriptor, &opened) == 0,
              opened.st_mode & S_IFMT == S_IFREG,
              opened.st_uid == ownerUID,
              opened.st_gid == groupGID,
              UInt16(opened.st_mode & 0o777) == mode,
              opened.st_nlink == 1,
              opened.st_flags == 0,
              UInt64(opened.st_size) == expectedByteCount
        else {
            throw InstallError.metadata("authority file metadata changed")
        }
        try validateNoUnexpectedExtendedMetadata(descriptor)
        var hasher = SHA256()
        var total: UInt64 = 0
        var data = Data()
        data.reserveCapacity(Int(expectedByteCount))
        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let count = try readChunk(descriptor, into: &buffer, operation: "verify authority file \(path)")
            if count == 0 {
                break
            }
            guard UInt64(count) <= expectedByteCount,
                  total <= expectedByteCount - UInt64(count)
            else {
                throw InstallError.integrity("authority file exceeds its expected size")
            }
            total += UInt64(count)
            let chunk = Data(buffer.prefix(count))
            data.append(chunk)
            hasher.update(data: chunk)
        }
        let observedDigest = try InstallDigest(
            hasher.finalize().map { String(format: "%02x", $0) }.joined()
        )
        guard total == expectedByteCount, observedDigest == expectedDigest else {
            throw InstallError.integrity("authority file content changed")
        }
        var settled = stat()
        guard fstat(descriptor, &settled) == 0,
              settled.st_dev == opened.st_dev,
              settled.st_ino == opened.st_ino,
              settled.st_nlink == opened.st_nlink,
              settled.st_size == opened.st_size,
              settled.st_mtimespec.tv_sec == opened.st_mtimespec.tv_sec,
              settled.st_mtimespec.tv_nsec == opened.st_mtimespec.tv_nsec,
              settled.st_ctimespec.tv_sec == opened.st_ctimespec.tv_sec,
              settled.st_ctimespec.tv_nsec == opened.st_ctimespec.tv_nsec
        else {
            throw InstallError.integrity("authority file changed while it was read")
        }
        return (opened, data)
    }
}
