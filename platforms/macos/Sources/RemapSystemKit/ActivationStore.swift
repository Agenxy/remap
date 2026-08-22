import Darwin
import Foundation

/// Root-owned, symlink-resistant storage for native resolver activation state.
public struct ActivationStore: Sendable {
    public static let standard = ActivationStore(
        directory: URL(fileURLWithPath: "/Library/Application Support/Agenxy/Remap", isDirectory: true)
    )

    public let directory: URL

    public init(directory: URL) {
        self.directory = directory.standardizedFileURL
    }

    public var recordURL: URL {
        directory.appendingPathComponent("dns-activation-v1.json", isDirectory: false)
    }

    public func exists() -> Bool {
        var information = stat()
        return lstat(recordURL.path, &information) == 0
    }

    public func read() throws -> ActivationRecord {
        try verifyRecordFile()
        let descriptor = open(recordURL.path, O_RDONLY | O_NOFOLLOW)
        guard descriptor >= 0 else {
            throw ResolverError.secureStorage("open the activation record")
        }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        let data = try handle.readToEnd() ?? Data()
        guard data.count <= 1_048_576 else {
            throw ResolverError.invalidActivationRecord
        }
        let record = try CanonicalJSON.decoder.decode(ActivationRecord.self, from: data)
        try record.verify()
        return record
    }

    public func create(_ record: ActivationRecord) throws {
        try requireRoot()
        guard !exists() else {
            throw ResolverError.activationAlreadyExists
        }
        try ensureDirectoryTree()
        try write(record, replacing: false)
    }

    public func replace(_ record: ActivationRecord) throws {
        try requireRoot()
        try verifyRecordFile()
        try write(record, replacing: true)
    }

    private func write(_ record: ActivationRecord, replacing: Bool) throws {
        let data = try CanonicalJSON.encoder.encode(record)
        guard data.count <= 1_048_576 else {
            throw ResolverError.invalidActivationRecord
        }
        let temporary = directory.appendingPathComponent(
            ".dns-activation-\(UUID().uuidString.lowercased()).tmp",
            isDirectory: false
        )
        let descriptor = open(temporary.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard descriptor >= 0 else {
            throw ResolverError.secureStorage("create a temporary activation record")
        }
        do {
            let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
            try handle.write(contentsOf: data)
            try handle.synchronize()
            try handle.close()
            if replacing {
                guard rename(temporary.path, recordURL.path) == 0 else {
                    throw ResolverError.secureStorage("replace the activation record atomically")
                }
            } else {
                guard link(temporary.path, recordURL.path) == 0 else {
                    throw ResolverError.secureStorage("publish the activation record atomically")
                }
                guard unlink(temporary.path) == 0 else {
                    throw ResolverError.secureStorage("retire the temporary activation record")
                }
            }
            try synchronizeDirectory()
        } catch {
            _ = unlink(temporary.path)
            throw error
        }
    }

    public func remove() throws {
        try requireRoot()
        try verifyRecordFile()
        guard unlink(recordURL.path) == 0 else {
            throw ResolverError.secureStorage("remove the activation record")
        }
        try synchronizeDirectory()
    }

    private func ensureDirectoryTree() throws {
        let applicationSupport = URL(
            fileURLWithPath: "/Library/Application Support",
            isDirectory: true
        )
        guard directory.path.hasPrefix(applicationSupport.path + "/") else {
            throw ResolverError.secureStorage("use the native activation directory")
        }
        try verifyDirectory(applicationSupport, create: false, permissions: 0)
        var current = applicationSupport
        let relative = directory.path.dropFirst(applicationSupport.path.count + 1)
        for component in relative.split(separator: "/") {
            current.appendPathComponent(String(component), isDirectory: true)
            try verifyDirectory(
                current,
                create: true,
                permissions: activationDirectoryPermissions(current)
            )
        }
    }

    private func verifyDirectory(_ url: URL, create: Bool, permissions: mode_t) throws {
        var information = stat()
        if lstat(url.path, &information) != 0, create, errno == ENOENT {
            guard mkdir(url.path, permissions) == 0 || errno == EEXIST else {
                throw ResolverError.secureStorage("create the activation directory")
            }
            guard lstat(url.path, &information) == 0 else {
                throw ResolverError.secureStorage("inspect the activation directory")
            }
        }
        guard (information.st_mode & S_IFMT) == S_IFDIR, information.st_uid == 0 else {
            throw ResolverError.secureStorage("verify root-owned activation directories")
        }
        if permissions != 0, information.st_mode & 0o777 != permissions {
            guard chmod(url.path, permissions) == 0 else {
                throw ResolverError.secureStorage("secure the activation directory")
            }
        }
    }

    private func verifyRecordFile() throws {
        var information = stat()
        guard lstat(recordURL.path, &information) == 0 else {
            if errno == ENOENT {
                throw ResolverError.activationRecordMissing
            }
            throw ResolverError.secureStorage("inspect the activation record")
        }
        guard (information.st_mode & S_IFMT) == S_IFREG,
              information.st_uid == 0,
              information.st_mode & 0o777 == 0o600
        else {
            throw ResolverError.secureStorage("verify the root-owned activation record")
        }
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

func activationDirectoryPermissions(_ directory: URL) -> mode_t {
    switch directory.standardizedFileURL.path {
    case "/Library/Application Support/Agenxy":
        0o755
    case "/Library/Application Support/Agenxy/Remap":
        0o711
    default:
        0o700
    }
}

func requireRoot() throws {
    guard geteuid() == 0 else {
        throw ResolverError.notRoot
    }
}
