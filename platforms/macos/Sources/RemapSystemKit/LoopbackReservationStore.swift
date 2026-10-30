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
        let record = LoopbackReservationRecord(version: 1, reservations: owned.sorted().map(\.description))
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
}

private struct LoopbackReservationRecord: Codable {
    let version: Int
    let reservations: [String]
}

private let maximumRecordBytes: off_t = 16 * 1024
