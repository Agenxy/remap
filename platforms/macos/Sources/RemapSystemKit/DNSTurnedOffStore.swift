// SPDX-License-Identifier: GPL-3.0-or-later
import CryptoKit
import Darwin
import Foundation

/// The owner turned Remap DNS off on purpose (ADR-0036). It is distinct from
/// a supervisor fallback, which keeps its prepared activation and its own
/// bypass record, and from DNS that was never activated, which has neither.
///
/// The payload holds a time, the command that was run, and what turning DNS
/// back on needs: the activation's owner and product version. It never holds
/// a name, an address, or traffic.
public struct DNSTurnedOffPayload: Codable, Equatable, Sendable {
    public let schemaVersion: UInt32
    public let turnedOffAtMilliseconds: UInt64
    /// One of `DNSTurnedOffPayload.commands`.
    public let command: String
    public let ownerUID: UInt32
    public let productVersion: String

    /// The operator commands that turn Remap DNS off.
    public static let commands: Set<String> = [remapSystemDeactivateCommand]

    public init(
        turnedOffAtMilliseconds: UInt64,
        command: String,
        ownerUID: UInt32,
        productVersion: String
    ) {
        schemaVersion = 1
        self.turnedOffAtMilliseconds = turnedOffAtMilliseconds
        self.command = command
        self.ownerUID = ownerUID
        self.productVersion = productVersion
    }

    func validate() throws {
        let versionCharacters = CharacterSet(charactersIn: "0123456789abcdefghijklmnopqrstuvwxyz"
            + "ABCDEFGHIJKLMNOPQRSTUVWXYZ.+-")
        guard schemaVersion == 1,
              Self.commands.contains(command),
              ownerUID != 0,
              !productVersion.isEmpty,
              productVersion.utf8.count <= 64,
              productVersion.unicodeScalars.allSatisfy(versionCharacters.contains)
        else {
            throw ResolverError.invalidTurnedOffRecord
        }
    }

    /// The exact root command that turns Remap DNS back on for this owner.
    public var turnOnCommand: String {
        "sudo '\(installedRemapSystemPath)' activate --owner-uid \(ownerUID) "
            + "--product-version \(productVersion) --system-socket \(installedSystemSocketPath)"
    }

    /// One line for status output: when, how, and how to undo it.
    public var statusLine: String {
        "turned off by the owner at \(statusMinute(turnedOffAtMilliseconds)) (`\(command)`)"
    }
}

public let remapSystemDeactivateCommand = "remap-system deactivate"
let installedRemapSystemPath = "/Library/Application Support/Agenxy/Remap/Install/current/libexec/remap-system"
let installedSystemSocketPath = "/var/run/org.agenxy.Remap.system.sock"

/// UTC to the minute, as `2026-10-31T01:20Z`.
func statusMinute(_ milliseconds: UInt64) -> String {
    let formatter = DateFormatter()
    formatter.locale = Locale(identifier: "en_US_POSIX")
    formatter.timeZone = TimeZone(identifier: "UTC")
    formatter.dateFormat = "yyyy-MM-dd'T'HH:mm'Z'"
    return formatter.string(from: Date(timeIntervalSince1970: TimeInterval(milliseconds) / 1000))
}

/// Integrity-covered turned-off record, stored beside the activation record.
public struct DNSTurnedOffRecord: Codable, Equatable, Sendable {
    public let payload: DNSTurnedOffPayload
    public let sha256: String

    public init(payload: DNSTurnedOffPayload) throws {
        try payload.validate()
        self.payload = payload
        sha256 = try Self.digest(payload)
    }

    public func verify() throws {
        try payload.validate()
        guard try sha256 == Self.digest(payload) else {
            throw ResolverError.invalidTurnedOffRecord
        }
    }

    private static func digest(_ payload: DNSTurnedOffPayload) throws -> String {
        let encoded = try CanonicalJSON.encoder.encode(payload)
        return SHA256.hash(data: encoded).map { String(format: "%02x", $0) }.joined()
    }
}

/// Root-owned, symlink-resistant storage for the turned-off record. It
/// follows `ResolverBypassStore`: written by exclusive temporary file and
/// atomic rename, and verified by digest. Unlike that record it is 0644, so
/// the owner's unprivileged `remapd` and CLI can say DNS is off on purpose;
/// it holds nothing a person chose.
public struct DNSTurnedOffStore: Sendable {
    public static let standard = DNSTurnedOffStore(directory: ActivationStore.standard.directory)

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
        directory.appendingPathComponent("dns-turned-off-v1.json", isDirectory: false)
    }

    /// The turned-off record, or nil when DNS was not turned off on purpose.
    public func read() throws -> DNSTurnedOffRecord? {
        guard try verifyRecordFile() else { return nil }
        let descriptor = open(recordURL.path, O_RDONLY | O_NOFOLLOW)
        guard descriptor >= 0 else {
            throw ResolverError.secureStorage("open the DNS turned-off record")
        }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        let data = try handle.read(upToCount: maximumTurnedOffRecordBytes + 1) ?? Data()
        guard data.count <= maximumTurnedOffRecordBytes else {
            throw ResolverError.invalidTurnedOffRecord
        }
        let record: DNSTurnedOffRecord
        do {
            record = try CanonicalJSON.decoder.decode(DNSTurnedOffRecord.self, from: data)
        } catch {
            throw ResolverError.invalidTurnedOffRecord
        }
        try record.verify()
        return record
    }

    public func write(_ payload: DNSTurnedOffPayload) throws {
        guard geteuid() == ownerUID else { throw ResolverError.notRoot }
        try verifyDirectory()
        _ = try verifyRecordFile()
        let data = try CanonicalJSON.encoder.encode(DNSTurnedOffRecord(payload: payload))
        let temporary = directory.appendingPathComponent(
            ".dns-turned-off-\(UUID().uuidString.lowercased()).tmp",
            isDirectory: false
        )
        let descriptor = open(temporary.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard descriptor >= 0 else {
            throw ResolverError.secureStorage("create a temporary DNS turned-off record")
        }
        do {
            let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
            guard fchmod(descriptor, 0o644) == 0 else {
                throw ResolverError.secureStorage("set the DNS turned-off record's mode")
            }
            try handle.write(contentsOf: data)
            try handle.synchronize()
            try handle.close()
            guard rename(temporary.path, recordURL.path) == 0 else {
                throw ResolverError.secureStorage("replace the DNS turned-off record atomically")
            }
            try synchronizeDirectory()
        } catch {
            _ = unlink(temporary.path)
            throw error
        }
    }

    /// Removes the record when it exists, as activation and the installer do.
    public func clear() throws {
        guard try verifyRecordFile() else { return }
        guard geteuid() == ownerUID else { throw ResolverError.notRoot }
        guard unlink(recordURL.path) == 0 else {
            throw ResolverError.secureStorage("remove the DNS turned-off record")
        }
        try synchronizeDirectory()
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

    /// False only when the record is absent.
    private func verifyRecordFile() throws -> Bool {
        var information = stat()
        guard lstat(recordURL.path, &information) == 0 else {
            if errno == ENOENT {
                return false
            }
            throw ResolverError.secureStorage("inspect the DNS turned-off record")
        }
        guard (information.st_mode & S_IFMT) == S_IFREG,
              information.st_uid == ownerUID,
              information.st_mode & 0o777 == 0o644
        else {
            throw ResolverError.secureStorage("verify the root-owned DNS turned-off record")
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

private let maximumTurnedOffRecordBytes = 4 * 1024

/// What turning DNS off recorded.
public struct DNSTurnOff: Sendable {
    public let payload: DNSTurnedOffPayload
    /// Why the record could not be written, when it could not.
    public let recordError: String?
}

/// Records the owner's turn-off of `activation` in `store`.
func recordTurnOff(
    command: String,
    activation: ActivationRecord,
    at date: Date,
    store: DNSTurnedOffStore
) -> DNSTurnOff {
    let payload = DNSTurnedOffPayload(
        turnedOffAtMilliseconds: unixMilliseconds(date),
        command: command,
        ownerUID: activation.payload.ownerUID,
        productVersion: activation.payload.productVersion
    )
    do {
        try store.write(payload)
        return DNSTurnOff(payload: payload, recordError: nil)
    } catch {
        return DNSTurnOff(payload: payload, recordError: String(describing: error))
    }
}
