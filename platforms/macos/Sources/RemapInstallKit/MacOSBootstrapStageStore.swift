import CryptoKit
import Darwin
import Foundation

/// Reviews and removes root-private, possibly partial bootstrap staging bytes.
final class MacOSBootstrapStageStore: @unchecked Sendable, MacOSBootstrapStageStoring {
    static let prefix = "org.agenxy.Remap.install-stage."
    static let childName = "candidate"

    private let authority: FileSystemAuthority
    private let ownerUID: UInt32
    private let groupGID: UInt32
    private let durability: any InstallDurability

    init(
        authority: FileSystemAuthority,
        ownerUID: UInt32,
        groupGID: UInt32,
        durability: any InstallDurability = FullInstallDurability()
    ) {
        self.authority = authority
        self.ownerUID = ownerUID
        self.groupGID = groupGID
        self.durability = durability
    }

    func candidates() throws -> [MacOSBootstrapStageCandidate] {
        guard try authority.metadata(at: Self.directory()) != nil else { return [] }
        let parent = try openVerifiedParent()
        defer { close(parent) }
        let names = try directoryNames(parent).filter { $0.hasPrefix(Self.prefix) }.sorted()
        guard names.count <= MacOSBootstrapHelperStore.maximumCandidates else {
            throw InstallError.integrity("too many private bootstrap stages require recovery")
        }
        return try names.map { name in
            try validateName(name)
            let descriptor = try openStage(name: name, parent: parent)
            defer { close(descriptor) }
            return try snapshot(name: name, descriptor: descriptor)
        }
    }

    func remove(_ candidate: MacOSBootstrapStageCandidate) throws {
        let name = try candidateName(candidate.path)
        let parent = try openVerifiedParent()
        defer { close(parent) }
        let stage = try openStage(name: name, parent: parent)
        defer { close(stage) }
        guard flock(stage, LOCK_EX | LOCK_NB) == 0 else {
            throw InstallError.approval("a private bootstrap stage became active after preview")
        }
        guard try snapshot(name: name, descriptor: stage) == candidate else {
            throw InstallError.approval("a private bootstrap stage changed after preview")
        }
        if let file = candidate.stagedFile {
            try removeStagedFile(file, directory: stage)
            try durability.syncDirectory(stage, operation: "private bootstrap stage")
        }
        try requireSameNode(name: name, descriptor: stage, parent: parent, directory: true)
        let result = name.withCString { unlinkat(parent, $0, AT_REMOVEDIR) }
        guard result == 0 else {
            throw InstallError.operatingSystem("remove private bootstrap stage", errno)
        }
        try durability.syncDirectory(parent, operation: "privileged bootstrap helper directory")
    }

    private func snapshot(name: String, descriptor: Int32) throws -> MacOSBootstrapStageCandidate {
        var status = stat()
        guard fstat(descriptor, &status) == 0 else {
            throw InstallError.operatingSystem("inspect private bootstrap stage", errno)
        }
        let attributes = try attributeNames(descriptor)
        guard status.st_mode & S_IFMT == S_IFDIR,
              status.st_uid == ownerUID,
              status.st_gid == groupGID,
              (1 ... 3).contains(status.st_nlink),
              [mode_t(0o700), mode_t(0o711)].contains(status.st_mode & 0o777),
              status.st_flags == 0,
              try !hasACL(descriptor),
              Set(attributes).isSubset(of: ["com.apple.provenance"])
        else {
            throw InstallError.metadata("a private bootstrap stage has unsafe metadata")
        }
        let names = try directoryNames(descriptor)
        guard names.isEmpty || names == [Self.childName] else {
            throw InstallError.metadata("a private bootstrap stage has unexpected children")
        }
        return try MacOSBootstrapStageCandidate(
            path: InstallAbsolutePath("\(MacOSBootstrapHelperStore.absoluteDirectory)/\(name)"),
            fileIdentity: identity(status),
            ownerUID: UInt32(status.st_uid),
            groupGID: UInt32(status.st_gid),
            mode: UInt16(status.st_mode & 0o777),
            linkCount: UInt64(status.st_nlink),
            flags: status.st_flags,
            extendedAttributeNames: attributes,
            stagedFile: names.isEmpty ? nil : stagedFile(name: name, directory: descriptor)
        )
    }

    private func stagedFile(
        name: String,
        directory: Int32
    ) throws -> MacOSBootstrapStagedFileCandidate {
        let descriptor = Self.childName.withCString {
            openat(directory, $0, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        }
        guard descriptor >= 0 else {
            throw InstallError.operatingSystem("open private bootstrap staged file", errno)
        }
        defer { close(descriptor) }
        var status = stat()
        guard fstat(descriptor, &status) == 0 else {
            throw InstallError.operatingSystem("inspect private bootstrap staged file", errno)
        }
        let attributes = try attributeNames(descriptor)
        let mode = UInt16(status.st_mode & 0o777)
        guard status.st_mode & S_IFMT == S_IFREG,
              status.st_uid == ownerUID,
              status.st_gid == groupGID,
              status.st_nlink == 1,
              [UInt16(0o600), UInt16(0o400), UInt16(0o555)].contains(mode),
              status.st_size >= 0,
              UInt64(status.st_size) <= MacOSBootstrapHelperStore.maximumByteCount,
              status.st_flags == 0,
              try !hasACL(descriptor),
              Set(attributes).isSubset(of: ["com.apple.provenance"])
        else {
            throw InstallError.metadata("a private bootstrap staged file has unsafe metadata")
        }
        let path = MacOSBootstrapHelperStore.absoluteDirectory + "/" + name + "/" + Self.childName
        return try MacOSBootstrapStagedFileCandidate(
            path: InstallAbsolutePath(path),
            fileIdentity: identity(status),
            ownerUID: UInt32(status.st_uid),
            groupGID: UInt32(status.st_gid),
            mode: mode,
            byteCount: UInt64(status.st_size),
            linkCount: UInt64(status.st_nlink),
            flags: status.st_flags,
            extendedAttributeNames: attributes,
            sha256: digest(descriptor)
        )
    }

    private func removeStagedFile(
        _ candidate: MacOSBootstrapStagedFileCandidate,
        directory: Int32
    ) throws {
        let descriptor = Self.childName.withCString {
            openat(directory, $0, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        }
        guard descriptor >= 0 else {
            throw InstallError.operatingSystem("reopen private bootstrap staged file", errno)
        }
        defer { close(descriptor) }
        try requireSameNode(
            name: Self.childName,
            descriptor: descriptor,
            parent: directory,
            directory: false
        )
        guard try stagedSnapshot(descriptor, path: candidate.path) == candidate else {
            throw InstallError.approval("private bootstrap staged bytes changed before removal")
        }
        let result = Self.childName.withCString { unlinkat(directory, $0, 0) }
        guard result == 0 else {
            throw InstallError.operatingSystem("remove private bootstrap staged file", errno)
        }
    }

    private func stagedSnapshot(
        _ descriptor: Int32,
        path: InstallAbsolutePath
    ) throws -> MacOSBootstrapStagedFileCandidate {
        var status = stat()
        guard fstat(descriptor, &status) == 0 else {
            throw InstallError.operatingSystem("reinspect private bootstrap staged file", errno)
        }
        return try MacOSBootstrapStagedFileCandidate(
            path: path,
            fileIdentity: identity(status),
            ownerUID: UInt32(status.st_uid),
            groupGID: UInt32(status.st_gid),
            mode: UInt16(status.st_mode & 0o777),
            byteCount: UInt64(max(status.st_size, 0)),
            linkCount: UInt64(status.st_nlink),
            flags: status.st_flags,
            extendedAttributeNames: attributeNames(descriptor),
            sha256: digest(descriptor)
        )
    }

    private func openVerifiedParent() throws -> Int32 {
        let descriptor = try authority.openDirectory(at: Self.directory())
        do {
            var status = stat()
            guard fstat(descriptor, &status) == 0,
                  status.st_mode & S_IFMT == S_IFDIR,
                  status.st_uid == ownerUID,
                  status.st_gid == groupGID,
                  status.st_mode & 0o022 == 0,
                  status.st_flags == 0,
                  try !hasACL(descriptor),
                  try Set(attributeNames(descriptor)).isSubset(of: ["com.apple.provenance"])
            else {
                throw InstallError.metadata("the privileged helper directory has unsafe metadata")
            }
            return descriptor
        } catch {
            close(descriptor)
            throw error
        }
    }

    private func openStage(name: String, parent: Int32) throws -> Int32 {
        let descriptor = name.withCString {
            openat(parent, $0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        }
        guard descriptor >= 0 else {
            throw InstallError.operatingSystem("open private bootstrap stage", errno)
        }
        return descriptor
    }

    private func requireSameNode(
        name: String,
        descriptor: Int32,
        parent: Int32,
        directory: Bool
    ) throws {
        var opened = stat()
        var current = stat()
        let expectedType = directory ? S_IFDIR : S_IFREG
        guard fstat(descriptor, &opened) == 0,
              name.withCString({ fstatat(parent, $0, &current, AT_SYMLINK_NOFOLLOW) }) == 0,
              identity(opened) == identity(current),
              current.st_mode & S_IFMT == expectedType
        else {
            throw InstallError.collision(name)
        }
    }

    private func directoryNames(_ descriptor: Int32) throws -> [String] {
        let duplicate = fcntl(descriptor, F_DUPFD_CLOEXEC, 0)
        guard duplicate >= 0, let stream = fdopendir(duplicate) else {
            if duplicate >= 0 {
                close(duplicate)
            }
            throw InstallError.operatingSystem("enumerate private bootstrap stage", errno)
        }
        defer { closedir(stream) }
        var names: [String] = []
        errno = 0
        while let pointer = readdir(stream) {
            var entry = pointer.pointee
            let name = withUnsafeBytes(of: &entry.d_name) { bytes -> String in
                let values = bytes.bindMemory(to: UInt8.self)
                let end = values.firstIndex(of: 0) ?? values.endIndex
                return String(decoding: values[..<end], as: UTF8.self)
            }
            if name != ".", name != ".." {
                names.append(name)
            }
        }
        guard errno == 0 else {
            throw InstallError.operatingSystem("enumerate private bootstrap stage", errno)
        }
        return names.sorted()
    }

    private func validateName(_ name: String) throws {
        let suffix = name.dropFirst(Self.prefix.count)
        guard suffix.count == 32,
              suffix.allSatisfy({ $0.isHexDigit && !$0.isUppercase })
        else {
            throw InstallError.integrity("a private bootstrap stage has an invalid name")
        }
    }

    private func candidateName(_ path: InstallAbsolutePath) throws -> String {
        let prefix = MacOSBootstrapHelperStore.absoluteDirectory + "/"
        guard path.value.hasPrefix(prefix) else { throw InstallError.invalidPath(path.value) }
        let name = String(path.value.dropFirst(prefix.count))
        try validateName(name)
        return name
    }

    private func digest(_ descriptor: Int32) throws -> String {
        var hasher = SHA256()
        var offset: off_t = 0
        var buffer = [UInt8](repeating: 0, count: 65536)
        while true {
            let count = pread(descriptor, &buffer, buffer.count, offset)
            guard count >= 0 else {
                throw InstallError.operatingSystem("hash private bootstrap staged file", errno)
            }
            if count == 0 {
                return hasher.finalize().map { String(format: "%02x", $0) }.joined()
            }
            hasher.update(data: Data(buffer.prefix(count)))
            offset += off_t(count)
            guard offset <= off_t(MacOSBootstrapHelperStore.maximumByteCount) else {
                throw InstallError.integrity("a private bootstrap staged file exceeds its size bound")
            }
        }
    }

    private func attributeNames(_ descriptor: Int32) throws -> [String] {
        let size = flistxattr(descriptor, nil, 0, 0)
        guard size >= 0 else {
            throw InstallError.operatingSystem("inspect private bootstrap extended attributes", errno)
        }
        guard size > 0 else { return [] }
        var bytes = [CChar](repeating: 0, count: size)
        guard flistxattr(descriptor, &bytes, size, 0) == size else {
            throw InstallError.operatingSystem("read private bootstrap extended attributes", errno)
        }
        return bytes.split(separator: 0).map {
            String(decoding: $0.map(UInt8.init(bitPattern:)), as: UTF8.self)
        }.sorted()
    }

    private func hasACL(_ descriptor: Int32) throws -> Bool {
        guard let list = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else {
            if errno == ENOENT {
                return false
            }
            throw InstallError.operatingSystem("inspect private bootstrap ACL", errno)
        }
        defer { acl_free(UnsafeMutableRawPointer(list)) }
        var entry: acl_entry_t?
        let result = acl_get_entry(list, Int32(ACL_FIRST_ENTRY.rawValue), &entry)
        guard result >= 0 else {
            throw InstallError.operatingSystem("read private bootstrap ACL", errno)
        }
        return result == 0
    }

    private func identity(_ status: stat) -> MacOSBootstrapFileIdentity {
        MacOSBootstrapFileIdentity(deviceID: UInt64(status.st_dev), fileID: UInt64(status.st_ino))
    }

    private static func directory() throws -> InstallRelativePath {
        try InstallRelativePath("Library/PrivilegedHelperTools")
    }
}
