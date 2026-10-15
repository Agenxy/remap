import CryptoKit
import Darwin
import Foundation

/// Why and when the resolver supervisor last restored ordinary DNS.
///
/// The payload holds stable codes, times, and at most one activation
/// identifier. It never holds names, upstream addresses, or traffic.
public struct ResolverBypassPayload: Codable, Equatable, Sendable {
    public let schemaVersion: UInt32
    /// Degraded code of the last reconciliation that failed before the bypass.
    public let reasonCode: String
    /// `E_RESOLVER_SAFE_BYPASS`, or `E_RESOLVER_SAFE_BYPASS_FAILED` when
    /// ordinary DNS could not be restored.
    public let outcomeCode: String
    /// Wall-clock time of the first failure in the grace window.
    public let failingSinceMilliseconds: UInt64
    public let bypassedAtMilliseconds: UInt64
    /// True when the daemon could not be told to release its plan, so it may
    /// still be bound to `unreleasedActivationID`.
    public let releasePending: Bool
    public let unreleasedActivationID: UUID?
    /// Wall-clock time a later complete generation re-armed Remap DNS.
    public let rearmedAtMilliseconds: UInt64?

    public init(
        reasonCode: String,
        outcomeCode: String,
        failingSinceMilliseconds: UInt64,
        bypassedAtMilliseconds: UInt64,
        releasePending: Bool,
        unreleasedActivationID: UUID?,
        rearmedAtMilliseconds: UInt64? = nil
    ) {
        schemaVersion = 1
        self.reasonCode = reasonCode
        self.outcomeCode = outcomeCode
        self.failingSinceMilliseconds = failingSinceMilliseconds
        self.bypassedAtMilliseconds = bypassedAtMilliseconds
        self.releasePending = releasePending
        self.unreleasedActivationID = unreleasedActivationID
        self.rearmedAtMilliseconds = rearmedAtMilliseconds
    }

    public func rearmed(atMilliseconds time: UInt64) -> ResolverBypassPayload {
        ResolverBypassPayload(
            reasonCode: reasonCode,
            outcomeCode: outcomeCode,
            failingSinceMilliseconds: failingSinceMilliseconds,
            bypassedAtMilliseconds: bypassedAtMilliseconds,
            releasePending: releasePending,
            unreleasedActivationID: unreleasedActivationID,
            rearmedAtMilliseconds: time
        )
    }

    /// The activation a failed release may have left bound in the daemon,
    /// while no later generation has re-armed Remap DNS.
    public var outstandingOrphan: UUID? {
        guard releasePending, rearmedAtMilliseconds == nil else { return nil }
        return unreleasedActivationID
    }
}

/// Integrity-covered bypass record, stored beside the activation record.
public struct ResolverBypassRecord: Codable, Equatable, Sendable {
    public let payload: ResolverBypassPayload
    public let sha256: String

    public init(payload: ResolverBypassPayload) throws {
        self.payload = payload
        sha256 = try Self.digest(payload)
    }

    public func verify() throws {
        guard try sha256 == Self.digest(payload) else {
            throw ResolverError.invalidBypassRecord
        }
    }

    private static func digest(_ payload: ResolverBypassPayload) throws -> String {
        let encoded = try CanonicalJSON.encoder.encode(payload)
        return SHA256.hash(data: encoded).map { String(format: "%02x", $0) }.joined()
    }
}

/// Receives the supervisor's durable bypass evidence. Recording never
/// changes resolver behavior, so implementations report their own failures.
public protocol ResolverBypassRecording: Sendable {
    func record(_ payload: ResolverBypassPayload)
    /// The last recorded bypass, so a restarted supervisor can still mark it re-armed.
    func lastBypass() -> ResolverBypassPayload?
}

/// Discards bypass evidence, for supervisors that have nowhere to keep it.
public struct DiscardedResolverBypassLog: ResolverBypassRecording {
    public init() {}

    public func record(_: ResolverBypassPayload) {}

    public func lastBypass() -> ResolverBypassPayload? {
        nil
    }
}

/// Root-owned, symlink-resistant storage for the last resolver bypass. It
/// follows `ActivationStore`: a 0600 regular file owned by root, written by
/// exclusive temporary file and atomic rename, and verified by digest.
public struct ResolverBypassStore: Sendable {
    public static let standard = ResolverBypassStore(directory: ActivationStore.standard.directory)

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
        directory.appendingPathComponent("resolver-bypass-v1.json", isDirectory: false)
    }

    /// Returns the last bypass, or nil when Remap has never bypassed.
    public func read() throws -> ResolverBypassRecord? {
        guard try verifyRecordFile(allowMissing: true) else { return nil }
        let descriptor = open(recordURL.path, O_RDONLY | O_NOFOLLOW)
        guard descriptor >= 0 else {
            throw ResolverError.secureStorage("open the resolver bypass record")
        }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        let data = try handle.read(upToCount: maximumBypassRecordBytes + 1) ?? Data()
        guard data.count <= maximumBypassRecordBytes else {
            throw ResolverError.invalidBypassRecord
        }
        let record: ResolverBypassRecord
        do {
            record = try CanonicalJSON.decoder.decode(ResolverBypassRecord.self, from: data)
        } catch {
            throw ResolverError.invalidBypassRecord
        }
        try record.verify()
        return record
    }

    /// Replaces the last bypass record. The activation directory must already
    /// exist and be root-owned; this store never creates the directory tree.
    public func write(_ payload: ResolverBypassPayload) throws {
        guard geteuid() == ownerUID else { throw ResolverError.notRoot }
        try verifyDirectory()
        _ = try verifyRecordFile(allowMissing: true)
        let data = try CanonicalJSON.encoder.encode(ResolverBypassRecord(payload: payload))
        guard data.count <= maximumBypassRecordBytes else {
            throw ResolverError.invalidBypassRecord
        }
        let temporary = directory.appendingPathComponent(
            ".resolver-bypass-\(UUID().uuidString.lowercased()).tmp",
            isDirectory: false
        )
        let descriptor = open(temporary.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard descriptor >= 0 else {
            throw ResolverError.secureStorage("create a temporary resolver bypass record")
        }
        do {
            let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
            guard fchmod(descriptor, 0o600) == 0 else {
                throw ResolverError.secureStorage("secure the resolver bypass record")
            }
            try handle.write(contentsOf: data)
            try handle.synchronize()
            try handle.close()
            guard rename(temporary.path, recordURL.path) == 0 else {
                throw ResolverError.secureStorage("replace the resolver bypass record atomically")
            }
            try synchronizeDirectory()
        } catch {
            _ = unlink(temporary.path)
            throw error
        }
    }

    private func verifyDirectory() throws {
        var information = stat()
        guard lstat(directory.path, &information) == 0,
              (information.st_mode & S_IFMT) == S_IFDIR,
              information.st_uid == ownerUID,
              information.st_mode & 0o022 == 0
        else {
            throw ResolverError.secureStorage("verify the root-owned activation directory")
        }
    }

    /// Returns false only when the record is absent and absence is allowed.
    private func verifyRecordFile(allowMissing: Bool) throws -> Bool {
        var information = stat()
        guard lstat(recordURL.path, &information) == 0 else {
            if errno == ENOENT, allowMissing {
                return false
            }
            throw ResolverError.secureStorage("inspect the resolver bypass record")
        }
        guard (information.st_mode & S_IFMT) == S_IFREG,
              information.st_uid == ownerUID,
              information.st_mode & 0o777 == 0o600
        else {
            throw ResolverError.secureStorage("verify the root-owned resolver bypass record")
        }
        return true
    }

    private func synchronizeDirectory() throws {
        let descriptor = open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
        guard descriptor >= 0 else {
            throw ResolverError.secureStorage("open the activation directory")
        }
        defer { close(descriptor) }
        guard fsync(descriptor) == 0 else {
            throw ResolverError.secureStorage("synchronize the activation directory")
        }
    }
}

private let maximumBypassRecordBytes = 64 * 1024

func unixMilliseconds(_ date: Date) -> UInt64 {
    UInt64(max(0, date.timeIntervalSince1970 * 1000))
}
