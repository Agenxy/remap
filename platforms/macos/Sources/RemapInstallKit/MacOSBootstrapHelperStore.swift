import CryptoKit
import Darwin
import Foundation
import Security

struct MacOSBootstrapCodeIdentity: Equatable, Sendable {
    let identifier: String
    let cdHash: String
}

protocol MacOSBootstrapCodeIdentityChecking: Sendable {
    func identity(fileDescriptor: Int32) throws -> MacOSBootstrapCodeIdentity
}

struct NativeMacOSBootstrapCodeIdentityChecker: MacOSBootstrapCodeIdentityChecking {
    func identity(fileDescriptor: Int32) throws -> MacOSBootstrapCodeIdentity {
        let descriptorPath = URL(fileURLWithPath: "/dev/fd/\(fileDescriptor)") as CFURL
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(descriptorPath, [], &code) == errSecSuccess,
              let code,
              SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), nil) == errSecSuccess
        else {
            throw InstallError.integrity("a bootstrap helper has an invalid code signature")
        }
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &information)
            == errSecSuccess,
            let values = information as? [CFString: Any],
            let identifier = values[kSecCodeInfoIdentifier] as? String,
            let unique = values[kSecCodeInfoUnique] as? Data
        else {
            throw InstallError.integrity("a bootstrap helper has no stable code identity")
        }
        return MacOSBootstrapCodeIdentity(identifier: identifier, cdHash: unique.hexadecimal)
    }
}

struct MacOSBootstrapFileIdentity: Codable, Equatable, Sendable {
    let deviceID: UInt64
    let fileID: UInt64
}

protocol MacOSBootstrapHelperStoring: Sendable {
    func candidates() throws -> [MacOSBootstrapHelperCandidate]
    func remove(_ candidate: MacOSBootstrapHelperCandidate) throws
}

final class MacOSBootstrapHelperStore: @unchecked Sendable, MacOSBootstrapHelperStoring {
    static let absoluteDirectory = "/Library/PrivilegedHelperTools"
    static let prefix = "org.agenxy.Remap.install."
    static let codeIdentifier = "org.agenxy.Remap.install-bootstrap"
    static let maximumCandidates = 32
    static let maximumByteCount: UInt64 = 134_217_728

    private let authority: FileSystemAuthority
    private let ownerUID: UInt32
    private let groupGID: UInt32
    private let identityChecker: any MacOSBootstrapCodeIdentityChecking
    private let currentExecutableIdentity: MacOSBootstrapFileIdentity?
    private let durability: any InstallDurability
    private let faultInjector: any InstallFaultInjecting

    init(
        authority: FileSystemAuthority,
        ownerUID: UInt32,
        groupGID: UInt32,
        identityChecker: any MacOSBootstrapCodeIdentityChecking,
        currentExecutableIdentity: MacOSBootstrapFileIdentity?,
        durability: any InstallDurability = FullInstallDurability(),
        faultInjector: any InstallFaultInjecting = NoInstallFaultInjector()
    ) {
        self.authority = authority
        self.ownerUID = ownerUID
        self.groupGID = groupGID
        self.identityChecker = identityChecker
        self.currentExecutableIdentity = currentExecutableIdentity
        self.durability = durability
        self.faultInjector = faultInjector
    }

    func candidates() throws -> [MacOSBootstrapHelperCandidate] {
        guard try authority.metadata(at: Self.directory()) != nil else {
            return []
        }
        let directory = try openVerifiedDirectory()
        defer { close(directory) }
        let names = try directoryNames(directory).filter { $0.hasPrefix(Self.prefix) }.sorted()
        guard names.count <= Self.maximumCandidates else {
            throw InstallError.integrity("too many bootstrap helpers require recovery")
        }
        return try names.map { name in
            try validateCandidateName(name)
            return try inspect(name: name, directory: directory)
        }
    }

    func remove(_ candidate: MacOSBootstrapHelperCandidate) throws {
        let name = try candidateName(for: candidate.path)
        let directory = try openVerifiedDirectory()
        defer { close(directory) }
        let descriptor = try openCandidate(name: name, directory: directory)
        defer { close(descriptor) }
        guard flock(descriptor, LOCK_EX | LOCK_NB) == 0 else {
            if errno == EWOULDBLOCK {
                throw InstallError.approval("a bootstrap helper became active after preview")
            }
            throw InstallError.operatingSystem("lock bootstrap helper for recovery", errno)
        }
        let inspected = try snapshot(name: name, descriptor: descriptor, activity: .inactive)
        guard inspected == candidate,
              inspected.fileIdentity != currentExecutableIdentity
        else {
            throw InstallError.approval("bootstrap helper identity changed after preview")
        }
        try faultInjector.check(.beforeRemove)
        let revalidated = try snapshot(name: name, descriptor: descriptor, activity: .inactive)
        guard revalidated == candidate else {
            throw InstallError.approval("bootstrap helper metadata or code identity changed before removal")
        }
        try requireSameNode(name: name, descriptor: descriptor, directory: directory)
        let result = name.withCString { unlinkat(directory, $0, 0) }
        guard result == 0 else {
            throw InstallError.operatingSystem("remove approved bootstrap helper", errno)
        }
        try durability.syncDirectory(directory, operation: "privileged bootstrap helper directory")
    }

    private func inspect(name: String, directory: Int32) throws -> MacOSBootstrapHelperCandidate {
        let descriptor = try openCandidate(name: name, directory: directory)
        defer { close(descriptor) }
        let fileIdentity = try identity(descriptor)
        if fileIdentity == currentExecutableIdentity {
            return try snapshot(name: name, descriptor: descriptor, activity: .current)
        }
        if flock(descriptor, LOCK_EX | LOCK_NB) == 0 {
            return try snapshot(name: name, descriptor: descriptor, activity: .inactive)
        }
        guard errno == EWOULDBLOCK else {
            throw InstallError.operatingSystem("inspect bootstrap helper activity", errno)
        }
        return try snapshot(name: name, descriptor: descriptor, activity: .active)
    }

    private func snapshot(
        name: String,
        descriptor: Int32,
        activity: MacOSBootstrapHelperActivity
    ) throws -> MacOSBootstrapHelperCandidate {
        var status = stat()
        guard fstat(descriptor, &status) == 0 else {
            throw InstallError.operatingSystem("inspect bootstrap helper", errno)
        }
        let extendedAttributes = try attributeNames(descriptor)
        guard status.st_mode & S_IFMT == S_IFREG,
              status.st_uid == ownerUID,
              status.st_gid == groupGID,
              status.st_nlink == 1,
              status.st_mode & 0o777 == 0o555,
              status.st_size >= 0,
              UInt64(status.st_size) <= Self.maximumByteCount,
              status.st_flags == 0,
              try !hasACL(descriptor),
              Set(extendedAttributes).isSubset(of: ["com.apple.provenance"])
        else {
            throw InstallError.metadata("a bootstrap helper has unsafe metadata")
        }
        let inspectedCodeIdentity = try? identityChecker.identity(fileDescriptor: descriptor)
        let codeIdentity = inspectedCodeIdentity.flatMap { identity in
            identity.identifier == Self.codeIdentifier && Self.validCDHash(identity.cdHash)
                ? identity
                : nil
        }
        return try MacOSBootstrapHelperCandidate(
            path: InstallAbsolutePath("\(Self.absoluteDirectory)/\(name)"),
            codeValidity: codeIdentity == nil ? .invalid : .verified,
            codeIdentifier: codeIdentity?.identifier,
            cdHash: codeIdentity?.cdHash,
            sha256: digest(descriptor),
            fileIdentity: identity(status),
            ownerUID: UInt32(status.st_uid),
            groupGID: UInt32(status.st_gid),
            mode: UInt16(status.st_mode & 0o777),
            byteCount: UInt64(status.st_size),
            linkCount: UInt64(status.st_nlink),
            flags: status.st_flags,
            extendedAttributeNames: extendedAttributes,
            activity: activity
        )
    }

    private func openVerifiedDirectory() throws -> Int32 {
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

    private func openCandidate(name: String, directory: Int32) throws -> Int32 {
        let descriptor = name.withCString {
            openat(directory, $0, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        }
        guard descriptor >= 0 else {
            throw InstallError.operatingSystem("open bootstrap helper candidate", errno)
        }
        return descriptor
    }

    private func requireSameNode(name: String, descriptor: Int32, directory: Int32) throws {
        var opened = stat()
        var current = stat()
        let inspected = fstat(descriptor, &opened)
        let resolved = name.withCString { fstatat(directory, $0, &current, AT_SYMLINK_NOFOLLOW) }
        guard inspected == 0,
              resolved == 0,
              identity(opened) == identity(current),
              current.st_mode & S_IFMT == S_IFREG
        else {
            throw InstallError.collision("\(Self.absoluteDirectory)/\(name)")
        }
    }

    private func directoryNames(_ descriptor: Int32) throws -> [String] {
        let duplicate = fcntl(descriptor, F_DUPFD_CLOEXEC, 0)
        guard duplicate >= 0, let stream = fdopendir(duplicate) else {
            if duplicate >= 0 {
                close(duplicate)
            }
            throw InstallError.operatingSystem("enumerate privileged helper directory", errno)
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
            throw InstallError.operatingSystem("enumerate privileged helper directory", errno)
        }
        return names
    }

    private func validateCandidateName(_ name: String) throws {
        let suffix = name.dropFirst(Self.prefix.count)
        guard suffix.count == 32,
              suffix.allSatisfy({ $0.isHexDigit && !$0.isUppercase })
        else {
            throw InstallError.integrity("a bootstrap helper candidate has an invalid name")
        }
    }

    private func candidateName(for path: InstallAbsolutePath) throws -> String {
        let prefix = Self.absoluteDirectory + "/"
        guard path.value.hasPrefix(prefix) else {
            throw InstallError.invalidPath(path.value)
        }
        let name = String(path.value.dropFirst(prefix.count))
        try validateCandidateName(name)
        return name
    }

    private func attributeNames(_ descriptor: Int32) throws -> [String] {
        let size = flistxattr(descriptor, nil, 0, 0)
        guard size >= 0 else {
            throw InstallError.operatingSystem("inspect bootstrap extended attributes", errno)
        }
        guard size > 0 else { return [] }
        var bytes = [CChar](repeating: 0, count: size)
        guard flistxattr(descriptor, &bytes, size, 0) == size else {
            throw InstallError.operatingSystem("read bootstrap extended attributes", errno)
        }
        return bytes.split(separator: 0).map { String(decoding: $0.map(UInt8.init(bitPattern:)), as: UTF8.self) }
            .sorted()
    }

    private func hasACL(_ descriptor: Int32) throws -> Bool {
        guard let list = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else {
            if errno == ENOENT {
                return false
            }
            throw InstallError.operatingSystem("inspect bootstrap helper ACL", errno)
        }
        defer { acl_free(UnsafeMutableRawPointer(list)) }
        var entry: acl_entry_t?
        let result = acl_get_entry(list, Int32(ACL_FIRST_ENTRY.rawValue), &entry)
        guard result >= 0 else {
            throw InstallError.operatingSystem("read bootstrap helper ACL", errno)
        }
        return result == 0
    }

    private func identity(_ descriptor: Int32) throws -> MacOSBootstrapFileIdentity {
        var status = stat()
        guard fstat(descriptor, &status) == 0 else {
            throw InstallError.operatingSystem("inspect bootstrap helper identity", errno)
        }
        return identity(status)
    }

    private func identity(_ status: stat) -> MacOSBootstrapFileIdentity {
        MacOSBootstrapFileIdentity(deviceID: UInt64(status.st_dev), fileID: UInt64(status.st_ino))
    }

    private static func validCDHash(_ value: String) -> Bool {
        (40 ... 64).contains(value.count)
            && value.count.isMultiple(of: 2)
            && value.allSatisfy { $0.isHexDigit && !$0.isUppercase }
    }

    private func digest(_ descriptor: Int32) throws -> String {
        var digest = SHA256()
        var offset: off_t = 0
        var buffer = [UInt8](repeating: 0, count: 1_048_576)
        while true {
            let count = pread(descriptor, &buffer, buffer.count, offset)
            guard count >= 0 else {
                throw InstallError.operatingSystem("hash bootstrap helper", errno)
            }
            guard count > 0 else {
                return digest.finalize().map { String(format: "%02x", $0) }.joined()
            }
            digest.update(data: buffer.prefix(count))
            offset += off_t(count)
            guard UInt64(offset) <= Self.maximumByteCount else {
                throw InstallError.integrity("a bootstrap helper exceeds its size bound")
            }
        }
    }

    private static func directory() throws -> InstallRelativePath {
        try InstallRelativePath("Library/PrivilegedHelperTools")
    }
}

public final class MacOSBootstrapHelperActivityLease: @unchecked Sendable {
    private let descriptor: Int32

    private init(descriptor: Int32) {
        self.descriptor = descriptor
    }

    deinit {
        close(descriptor)
    }

    public static func acquireForCurrentExecutable() throws -> MacOSBootstrapHelperActivityLease? {
        guard let path = currentExecutablePath(), isBootstrapPath(path) else {
            return nil
        }
        let descriptor = path.withCString { open($0, O_RDONLY | O_NOFOLLOW | O_CLOEXEC) }
        guard descriptor >= 0 else {
            throw InstallError.operatingSystem("open current bootstrap helper", errno)
        }
        guard flock(descriptor, LOCK_SH | LOCK_NB) == 0 else {
            let code = errno
            close(descriptor)
            if code == EWOULDBLOCK {
                throw InstallError.approval("the current bootstrap helper is being recovered")
            }
            throw InstallError.operatingSystem("mark current bootstrap helper active", code)
        }
        return MacOSBootstrapHelperActivityLease(descriptor: descriptor)
    }

    static func currentIdentity() throws -> MacOSBootstrapFileIdentity? {
        guard let path = currentExecutablePath(), isBootstrapPath(path) else {
            return nil
        }
        var status = stat()
        guard lstat(path, &status) == 0, status.st_mode & S_IFMT == S_IFREG else {
            throw InstallError.integrity("the current bootstrap helper path changed identity")
        }
        return MacOSBootstrapFileIdentity(deviceID: UInt64(status.st_dev), fileID: UInt64(status.st_ino))
    }

    private static func currentExecutablePath() -> String? {
        guard let executable = Bundle.main.executableURL?.resolvingSymlinksInPath().path else {
            return nil
        }
        return executable
    }

    private static func isBootstrapPath(_ path: String) -> Bool {
        let prefix = MacOSBootstrapHelperStore.absoluteDirectory + "/" + MacOSBootstrapHelperStore.prefix
        guard path.hasPrefix(prefix) else { return false }
        let name = String(path.dropFirst((MacOSBootstrapHelperStore.absoluteDirectory + "/").count))
        let suffix = name.dropFirst(MacOSBootstrapHelperStore.prefix.count)
        return suffix.count == 32 && suffix.allSatisfy { $0.isHexDigit && !$0.isUppercase }
    }
}

private extension Data {
    var hexadecimal: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
