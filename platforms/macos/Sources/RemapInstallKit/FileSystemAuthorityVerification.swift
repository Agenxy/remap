import CryptoKit
import Darwin
import Foundation

extension FileSystemAuthority {
    public func verifySource(_ entry: InstallEntry, at path: InstallRelativePath) throws {
        try entry.validate()
        switch entry.kind {
        case .directory:
            let descriptor = try openDirectory(at: path)
            close(descriptor)
        case .regularFile:
            guard let expectedDigest = entry.sha256, let expectedByteCount = entry.byteCount else {
                throw InstallError.invalidManifest("source verification requires a digest and size")
            }
            let descriptor = try openRegularFile(path, rejectHardLinks: true)
            defer { close(descriptor) }
            let content = try digest(descriptor, operation: "verify source file \(path)")
            guard content.digest == expectedDigest, content.byteCount == expectedByteCount else {
                throw InstallError.integrity("source file \(path) does not match its manifest digest")
            }
        }
    }

    public func verify(_ entry: InstallEntry, at path: InstallRelativePath) throws {
        try entry.validate()
        switch entry.kind {
        case .directory:
            try verifyDirectory(entry, at: path)
        case .regularFile:
            try verifyRegularFile(entry, at: path)
        }
    }

    private func verifyDirectory(_ entry: InstallEntry, at path: InstallRelativePath) throws {
        let descriptor = try openDirectory(at: path)
        defer { close(descriptor) }
        var status = stat()
        guard fstat(descriptor, &status) == 0 else {
            throw InstallError.operatingSystem("inspect generation directory \(path)", errno)
        }
        guard status.st_mode & S_IFMT == S_IFDIR,
              status.st_uid == entry.ownerUID,
              status.st_gid == entry.groupGID,
              UInt16(status.st_mode & 0o777) == entry.mode,
              status.st_flags == 0
        else {
            throw InstallError.metadata("generation directory \(path) does not match its manifest")
        }
        try validateNoUnexpectedExtendedMetadata(descriptor)
    }

    private func verifyRegularFile(_ entry: InstallEntry, at path: InstallRelativePath) throws {
        guard let expectedDigest = entry.sha256, let expectedByteCount = entry.byteCount else {
            throw InstallError.invalidManifest("regular file verification requires a digest and size")
        }
        let descriptor = try openRegularFile(path, rejectHardLinks: true)
        defer { close(descriptor) }
        try validateRegularFile(descriptor, entry: entry)
        let content = try digest(descriptor, operation: "verify generation file \(path)")
        guard content.digest == expectedDigest, content.byteCount == expectedByteCount else {
            throw InstallError.integrity("generation file \(path) does not match its manifest digest")
        }
    }

    private func digest(
        _ descriptor: Int32,
        operation: String
    ) throws -> (digest: InstallDigest, byteCount: UInt64) {
        var hasher = SHA256()
        var total: UInt64 = 0
        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let count = try readChunk(descriptor, into: &buffer, operation: operation)
            if count == 0 {
                let value = hasher.finalize().map { String(format: "%02x", $0) }.joined()
                return try (InstallDigest(value), total)
            }
            hasher.update(data: Data(buffer.prefix(count)))
            let addition = total.addingReportingOverflow(UInt64(count))
            guard !addition.overflow else {
                throw InstallError.integrity("generation file exceeds the supported size")
            }
            total = addition.partialValue
        }
    }
}
