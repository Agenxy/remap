import Darwin
import Foundation

/// The file that holds a Secure Enclave key's `dataRepresentation`.
///
/// The blob is not the private key. It is that key wrapped by this Mac's Secure Enclave, and
/// only this Mac's Secure Enclave can use it, so copying the file elsewhere yields nothing that
/// can sign. It is still kept owner-only, because on this Mac it is what selects the key.
enum ReleaseKeyFile {
    static let maximumByteCount = 4096

    /// Creates the file before any key exists, so an existing file is refused without the
    /// Secure Enclave ever being asked for a key that would then be thrown away.
    static func createExclusively(at path: String) throws -> Int32 {
        let descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else {
            let code = errno
            if code == EEXIST {
                throw ReleaseKeyError.keyFile("\(path) already exists; a release key is never overwritten")
            }
            throw ReleaseKeyError.keyFile("cannot create \(path): \(String(cString: strerror(code)))")
        }
        guard fchmod(descriptor, 0o600) == 0 else {
            let code = errno
            close(descriptor)
            unlink(path)
            throw ReleaseKeyError.keyFile("cannot seal \(path): \(String(cString: strerror(code)))")
        }
        return descriptor
    }

    static func write(_ data: Data, to descriptor: Int32, path: String) throws {
        defer { close(descriptor) }
        let written = data.withUnsafeBytes { bytes in
            Darwin.write(descriptor, bytes.baseAddress, bytes.count)
        }
        guard written == data.count, fsync(descriptor) == 0 else {
            unlink(path)
            throw ReleaseKeyError.keyFile("cannot write \(path)")
        }
    }

    static func abandon(_ descriptor: Int32, path: String) {
        close(descriptor)
        unlink(path)
    }

    /// Reads one owner-only regular file, refusing links and anything larger than a key blob.
    static func read(at path: String) throws -> Data {
        let descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else {
            throw ReleaseKeyError.keyFile("cannot open \(path): \(String(cString: strerror(errno)))")
        }
        defer { close(descriptor) }
        var status = stat()
        guard fstat(descriptor, &status) == 0,
              status.st_mode & S_IFMT == S_IFREG,
              status.st_nlink == 1,
              status.st_uid == geteuid(),
              status.st_mode & 0o077 == 0,
              status.st_size > 0,
              status.st_size <= maximumByteCount
        else {
            throw ReleaseKeyError.keyFile(
                "\(path) must be one owner-only regular file of at most \(maximumByteCount) bytes"
            )
        }
        var data = Data(count: Int(status.st_size))
        let count = data.withUnsafeMutableBytes { bytes in
            Darwin.read(descriptor, bytes.baseAddress, bytes.count)
        }
        guard count == Int(status.st_size) else {
            throw ReleaseKeyError.keyFile("cannot read \(path) completely")
        }
        return data
    }
}
