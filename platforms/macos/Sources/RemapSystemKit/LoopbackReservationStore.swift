// SPDX-License-Identifier: GPL-3.0-or-later
import Darwin
import Foundation

/// The aliases this supervisor added, kept beside the activation record so
/// that a restart, a crash or an uninstall removes exactly those and nothing
/// another tool placed in the range.
public struct LoopbackReservationStore: Sendable {
    public static let standard = LoopbackReservationStore(directory: ActivationStore.standard.directory)

    public let directory: URL
    let ownerUID: uid_t

    public init(directory: URL) {
        self.init(directory: directory, ownerUID: 0)
    }

    /// Tests use their own account; the product always requires root.
    init(directory: URL, ownerUID: uid_t) {
        self.directory = directory.standardizedFileURL
        self.ownerUID = ownerUID
    }

    public var recordURL: URL {
        directory.appendingPathComponent("loopback-reservations-v1.json", isDirectory: false)
    }

    /// Returns the owned reservations, empty when none were ever added.
    public func read() throws -> Set<LoopbackReservation> {
        var information = stat()
        guard lstat(recordURL.path, &information) == 0 else {
            guard errno == ENOENT else { throw LoopbackReservationError.invalidRecord }
            return []
        }
        guard (information.st_mode & S_IFMT) == S_IFREG,
              information.st_uid == ownerUID,
              information.st_mode & 0o777 == 0o600,
              information.st_size <= maximumRecordBytes
        else {
            throw LoopbackReservationError.invalidRecord
        }
        let data = try Data(contentsOf: recordURL)
        guard let record = try? CanonicalJSON.decoder.decode(LoopbackReservationRecord.self, from: data),
              record.version == 1,
              record.reservations.count <= maximumLoopbackReservations
        else {
            throw LoopbackReservationError.invalidRecord
        }
        // Aliases do not survive a restart. Entries from an earlier boot name
        // nothing this supervisor added, so they are dropped, never adopted.
        guard record.boot == bootSession() else { return [] }
        let owned = record.reservations.compactMap(LoopbackReservation.init)
        guard owned.count == record.reservations.count else {
            throw LoopbackReservationError.invalidRecord
        }
        return Set(owned)
    }

    /// Replaces the record atomically; an empty set removes it.
    public func write(_ owned: Set<LoopbackReservation>) throws {
        guard geteuid() == ownerUID else { throw ResolverError.notRoot }
        if owned.isEmpty {
            guard unlink(recordURL.path) == 0 || errno == ENOENT else {
                throw ResolverError.secureStorage("remove the loopback reservation record")
            }
            return
        }
        let record = LoopbackReservationRecord(
            version: 1,
            boot: bootSession(),
            reservations: owned.sorted().map(\.description)
        )
        let data = try CanonicalJSON.encoder.encode(record)
        let temporary = directory.appendingPathComponent(
            ".loopback-reservations-\(UUID().uuidString.lowercased()).tmp",
            isDirectory: false
        )
        let descriptor = open(temporary.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard descriptor >= 0 else {
            throw ResolverError.secureStorage("create a temporary loopback reservation record")
        }
        do {
            let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
            guard fchmod(descriptor, 0o600) == 0 else {
                throw ResolverError.secureStorage("secure the loopback reservation record")
            }
            try handle.write(contentsOf: data)
            try handle.synchronize()
            try handle.close()
            guard rename(temporary.path, recordURL.path) == 0 else {
                throw ResolverError.secureStorage("replace the loopback reservation record atomically")
            }
        } catch {
            _ = unlink(temporary.path)
            throw error
        }
    }

    /// Runs `body` holding an exclusive lock beside the record, so the keeper
    /// and deactivation, which run in different processes, never interleave.
    func withLock<Result>(_ body: () throws -> Result) throws -> Result {
        let lock = directory.appendingPathComponent(".loopback-reservations.lock", isDirectory: false)
        let descriptor = open(lock.path, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else {
            throw ResolverError.secureStorage("open the loopback reservation lock")
        }
        defer { close(descriptor) }
        var information = stat()
        guard fstat(descriptor, &information) == 0,
              information.st_uid == ownerUID,
              (information.st_mode & S_IFMT) == S_IFREG,
              flock(descriptor, LOCK_EX) == 0
        else {
            throw ResolverError.secureStorage("lock the loopback reservation record")
        }
        return try body()
    }
}

private struct LoopbackReservationRecord: Codable {
    let version: Int
    let boot: String
    let reservations: [String]
}

/// This boot's session identifier, which changes at every restart.
func bootSession() -> String {
    var size = 0
    guard sysctlbyname("kern.bootsessionuuid", nil, &size, nil, 0) == 0, size > 0 else { return "" }
    var buffer = [CChar](repeating: 0, count: size)
    guard sysctlbyname("kern.bootsessionuuid", &buffer, &size, nil, 0) == 0 else { return "" }
    return String(decoding: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
}

private let maximumRecordBytes: off_t = 16 * 1024
