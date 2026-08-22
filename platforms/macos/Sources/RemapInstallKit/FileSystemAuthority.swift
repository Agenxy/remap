import CryptoKit
import Darwin
import Foundation

/// A descriptor-rooted filesystem authority. Every descendant traversal rejects symbolic links.
public final class FileSystemAuthority: @unchecked Sendable {
    let root: InstallDescriptor
    let policy: InstallAuthorityPolicy
    private let durability: any InstallDurability
    let faultInjector: any InstallFaultInjecting

    public convenience init(
        systemRootPath: String,
        durability: any InstallDurability = FullInstallDurability(),
        faultInjector: any InstallFaultInjecting = NoInstallFaultInjector()
    ) throws {
        try self.init(
            rootPath: systemRootPath,
            policy: .system,
            durability: durability,
            faultInjector: faultInjector
        )
    }

    /// Opens an immutable package built by an unprivileged caller.
    ///
    /// This authority can only read. It requires an exact private source root and validates
    /// every opened descendant against the declared owner without following symbolic links.
    public convenience init(
        sourcePackageRootPath: String,
        ownerUID: UInt32,
        durability: any InstallDurability = FullInstallDurability(),
        faultInjector: any InstallFaultInjecting = NoInstallFaultInjector()
    ) throws {
        try self.init(
            rootPath: sourcePackageRootPath,
            policy: .sourcePackage(ownerUID: uid_t(ownerUID), requiresRoot: true),
            durability: durability,
            faultInjector: faultInjector
        )
    }

    convenience init(
        testingRootPath: String,
        durability: any InstallDurability = FullInstallDurability(),
        faultInjector: any InstallFaultInjecting = NoInstallFaultInjector()
    ) throws {
        try self.init(
            rootPath: testingRootPath,
            policy: InstallAuthorityPolicy(
                ownerUID: geteuid(),
                groupGID: getegid(),
                requiresRoot: false,
                sourceOnly: false,
                requiredRootMode: nil,
                systemFlags: false
            ),
            durability: durability,
            faultInjector: faultInjector
        )
    }

    convenience init(
        testingSourcePackageRootPath: String,
        ownerUID: UInt32,
        durability: any InstallDurability = FullInstallDurability(),
        faultInjector: any InstallFaultInjecting = NoInstallFaultInjector()
    ) throws {
        try self.init(
            rootPath: testingSourcePackageRootPath,
            policy: .sourcePackage(ownerUID: uid_t(ownerUID), requiresRoot: false),
            durability: durability,
            faultInjector: faultInjector
        )
    }

    private convenience init(
        rootPath: String,
        policy: InstallAuthorityPolicy,
        durability: any InstallDurability,
        faultInjector: any InstallFaultInjecting
    ) throws {
        if policy.requiresRoot, geteuid() != 0 {
            throw InstallError.notRoot
        }
        let descriptor = rootPath.withCString { open($0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) }
        guard descriptor >= 0 else {
            throw InstallError.operatingSystem("open installer authority root", errno)
        }
        try self.init(
            rootDescriptor: descriptor,
            policy: policy,
            durability: durability,
            faultInjector: faultInjector
        )
    }

    private init(
        rootDescriptor: Int32,
        policy: InstallAuthorityPolicy,
        durability: any InstallDurability,
        faultInjector: any InstallFaultInjecting
    ) throws {
        root = InstallDescriptor(rootDescriptor)
        self.policy = policy
        self.durability = durability
        self.faultInjector = faultInjector
        try validateRoot()
    }

    /// Derives a read-only descendant authority without resolving an absolute path again.
    public func sourceSubdirectory(at path: InstallRelativePath) throws -> FileSystemAuthority {
        guard policy.sourceOnly else {
            throw InstallError.integrity("only a source package authority can derive a source subdirectory")
        }
        let descriptor = try openDirectory(at: path)
        let childPolicy = InstallAuthorityPolicy(
            ownerUID: policy.ownerUID,
            groupGID: policy.groupGID,
            requiresRoot: policy.requiresRoot,
            sourceOnly: true,
            requiredRootMode: 0o500,
            systemFlags: false
        )
        return try FileSystemAuthority(
            rootDescriptor: descriptor,
            policy: childPolicy,
            durability: durability,
            faultInjector: faultInjector
        )
    }

    public func metadata(at path: InstallRelativePath) throws -> InstallNodeMetadata? {
        let location: (parent: Int32, leaf: String)
        do {
            location = try parentAndLeaf(path)
        } catch let InstallError.operatingSystem(_, code) where code == ENOENT {
            return nil
        }
        defer { close(location.parent) }
        var status = stat()
        let result = location.leaf.withCString {
            fstatat(location.parent, $0, &status, AT_SYMLINK_NOFOLLOW)
        }
        if result != 0, errno == ENOENT {
            return nil
        }
        guard result == 0 else {
            throw InstallError.operatingSystem("inspect \(path)", errno)
        }
        return try metadata(status: status, parent: location.parent, leaf: location.leaf)
    }

    public func createDirectory(
        at path: InstallRelativePath,
        ownerUID: UInt32,
        groupGID: UInt32,
        mode: UInt16
    ) throws {
        try requireMutable()
        let location = try parentAndLeaf(path, createParents: true)
        defer { close(location.parent) }
        try faultInjector.check(.beforeCreateDirectory)
        let result = location.leaf.withCString { mkdirat(location.parent, $0, 0o700) }
        if result != 0, errno != EEXIST {
            throw InstallError.operatingSystem("create directory \(path)", errno)
        }
        let descriptor = try openDirectoryComponent(
            location.leaf,
            from: location.parent,
            relativePath: path.description
        )
        defer { close(descriptor) }
        try applyMetadata(descriptor, ownerUID: ownerUID, groupGID: groupGID, mode: mode)
        try syncDirectory(descriptor, operation: "directory \(path)")
        try syncDirectory(location.parent, operation: "parent of \(path)")
    }

    /// Creates one authority-owned directory or verifies an existing exact directory.
    ///
    /// Unlike `createDirectory`, this never changes metadata on a pre-existing node and
    /// never creates implicit parents. It is the collision-safe primitive for fixed
    /// privileged storage topology.
    public func ensureOwnedDirectory(
        at path: InstallRelativePath,
        ownerUID: UInt32,
        groupGID: UInt32,
        mode: UInt16
    ) throws {
        try requireMutable()
        let location = try parentAndLeaf(path)
        defer { close(location.parent) }
        try faultInjector.check(.beforeCreateDirectory)
        let result = location.leaf.withCString { mkdirat(location.parent, $0, 0o700) }
        let created = result == 0
        guard created || errno == EEXIST else {
            throw InstallError.operatingSystem("create owned directory \(path)", errno)
        }
        let descriptor = try openDirectoryComponent(
            location.leaf,
            from: location.parent,
            relativePath: path.description
        )
        defer { close(descriptor) }
        if created {
            try applyMetadata(descriptor, ownerUID: ownerUID, groupGID: groupGID, mode: mode)
        } else {
            try verifyOwnedDirectory(
                descriptor,
                path: path,
                ownerUID: ownerUID,
                groupGID: groupGID,
                permittedModes: [mode]
            )
        }
        try syncDirectory(descriptor, operation: "owned directory \(path)")
        if created {
            try syncDirectory(location.parent, operation: "parent of \(path)")
        }
    }

    func transitionOwnedDirectoryMode(
        at path: InstallRelativePath,
        ownerUID: UInt32,
        groupGID: UInt32,
        permittedModes: Set<UInt16>,
        mode: UInt16
    ) throws {
        try requireMutable()
        let descriptor = try openDirectory(at: path)
        defer { close(descriptor) }
        try verifyOwnedDirectory(
            descriptor,
            path: path,
            ownerUID: ownerUID,
            groupGID: groupGID,
            permittedModes: permittedModes
        )
        try applyMetadata(descriptor, ownerUID: ownerUID, groupGID: groupGID, mode: mode)
        try syncDirectory(descriptor, operation: "transitioned directory \(path)")
    }

    func verifyOwnedDirectory(
        at path: InstallRelativePath,
        ownerUID: UInt32,
        groupGID: UInt32,
        permittedModes: Set<UInt16>,
        permitPlatformFlags: Bool = false
    ) throws {
        let descriptor = try openDirectory(at: path)
        defer { close(descriptor) }
        try verifyOwnedDirectory(
            descriptor,
            path: path,
            ownerUID: ownerUID,
            groupGID: groupGID,
            permittedModes: permittedModes,
            permitPlatformFlags: permitPlatformFlags
        )
    }

    public func writeFile(
        _ data: Data,
        at path: InstallRelativePath,
        ownerUID: UInt32,
        groupGID: UInt32,
        mode: UInt16
    ) throws {
        try requireMutable()
        let location = try parentAndLeaf(path, createParents: true)
        defer { close(location.parent) }
        try faultInjector.check(.beforeCreateFile)
        let descriptor = try createRegularFile(location.leaf, parent: location.parent)
        do {
            try writeAll(data, to: descriptor, operation: "write \(path)")
            try applyMetadata(descriptor, ownerUID: ownerUID, groupGID: groupGID, mode: mode)
            try syncFile(descriptor, operation: "file \(path)")
            close(descriptor)
            try syncDirectory(location.parent, operation: "parent of \(path)")
        } catch {
            close(descriptor)
            unlinkLeaf(location.leaf, parent: location.parent)
            throw error
        }
    }

    public func copyRegularFile(
        from source: FileSystemAuthority,
        sourcePath: InstallRelativePath,
        destinationPath: InstallRelativePath,
        entry: InstallEntry,
        createParents: Bool = true
    ) throws {
        try requireMutable()
        guard entry.kind == .regularFile, let digest = entry.sha256, let byteCount = entry.byteCount else {
            throw InstallError.invalidManifest("copy requires a regular-file entry")
        }
        let sourceDescriptor = try source.openRegularFile(sourcePath, rejectHardLinks: true)
        defer { close(sourceDescriptor) }
        let location = try parentAndLeaf(destinationPath, createParents: createParents)
        defer { close(location.parent) }
        try faultInjector.check(.beforeCreateFile)
        let destination = try createRegularFile(location.leaf, parent: location.parent)
        do {
            let copied = try copyAndHash(from: sourceDescriptor, to: destination)
            guard copied.digest == digest, copied.byteCount == byteCount else {
                throw InstallError.integrity("copied bytes for \(sourcePath) do not match the manifest")
            }
            try faultInjector.check(.afterCopyData)
            try applyMetadata(
                destination,
                ownerUID: entry.ownerUID,
                groupGID: entry.groupGID,
                mode: entry.mode
            )
            try validateRegularFile(destination, entry: entry)
            try syncFile(destination, operation: "copied file \(destinationPath)")
            close(destination)
            try syncDirectory(location.parent, operation: "parent of \(destinationPath)")
        } catch {
            close(destination)
            unlinkLeaf(location.leaf, parent: location.parent)
            throw error
        }
    }

    public func readFile(at path: InstallRelativePath, maximumByteCount: Int) throws -> Data {
        guard maximumByteCount >= 0 else {
            throw InstallError.integrity("file read bound cannot be negative")
        }
        let descriptor = try openRegularFile(path, rejectHardLinks: false)
        defer { close(descriptor) }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 16384)
        while true {
            let count = try readChunk(descriptor, into: &buffer, operation: "read \(path)")
            if count == 0 {
                return data
            }
            guard data.count <= maximumByteCount - count else {
                throw InstallError.integrity("\(path) exceeds the permitted size")
            }
            data.append(buffer, count: count)
        }
    }

    public func readUniqueFile(at path: InstallRelativePath, maximumByteCount: Int) throws -> Data {
        guard maximumByteCount >= 0 else {
            throw InstallError.integrity("file read bound cannot be negative")
        }
        let descriptor = try openRegularFile(path, rejectHardLinks: true)
        defer { close(descriptor) }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 16384)
        while true {
            let count = try readChunk(descriptor, into: &buffer, operation: "read unique file \(path)")
            if count == 0 {
                return data
            }
            guard data.count <= maximumByteCount - count else {
                throw InstallError.integrity("\(path) exceeds the permitted size")
            }
            data.append(buffer, count: count)
        }
    }

    public func createSymbolicLink(
        _ target: InstallSymlinkTarget,
        at path: InstallRelativePath,
        createParents: Bool = true
    ) throws {
        try requireMutable()
        let location = try parentAndLeaf(path, createParents: createParents)
        defer { close(location.parent) }
        let result = target.value.withCString { targetPointer in
            location.leaf.withCString { symlinkat(targetPointer, location.parent, $0) }
        }
        guard result == 0 else {
            throw InstallError.operatingSystem("create symbolic link \(path)", errno)
        }
        try syncDirectory(location.parent, operation: "parent of \(path)")
    }

    public func readSymbolicLink(at path: InstallRelativePath) throws -> String {
        let location = try parentAndLeaf(path)
        defer { close(location.parent) }
        var buffer = [CChar](repeating: 0, count: 4097)
        let count = location.leaf.withCString {
            readlinkat(location.parent, $0, &buffer, buffer.count - 1)
        }
        guard count >= 0, count < buffer.count - 1 else {
            throw InstallError.operatingSystem("read symbolic link \(path)", errno)
        }
        return String(decoding: buffer.prefix(count).map(UInt8.init(bitPattern:)), as: UTF8.self)
    }

    public func renameExclusive(
        from source: InstallRelativePath,
        to destination: InstallRelativePath
    ) throws {
        try requireMutable()
        try rename(from: source, to: destination, flags: UInt32(RENAME_EXCL))
    }

    public func renameSwap(_ first: InstallRelativePath, _ second: InstallRelativePath) throws {
        try requireMutable()
        try rename(from: first, to: second, flags: UInt32(RENAME_SWAP))
    }

    public func unlinkSymbolicLink(at path: InstallRelativePath, expectedTarget: InstallSymlinkTarget) throws {
        try requireMutable()
        guard try readSymbolicLink(at: path) == expectedTarget.value else {
            throw InstallError.collision(path.description)
        }
        let location = try parentAndLeaf(path)
        defer { close(location.parent) }
        try faultInjector.check(.beforeRemove)
        let result = location.leaf.withCString { unlinkat(location.parent, $0, 0) }
        guard result == 0 else {
            throw InstallError.operatingSystem("unlink symbolic link \(path)", errno)
        }
        try syncDirectory(location.parent, operation: "parent of \(path)")
    }

    public func unlinkRegularFile(at path: InstallRelativePath, expected: InstallEntry) throws {
        try requireMutable()
        try verify(expected, at: path)
        let location = try parentAndLeaf(path)
        defer { close(location.parent) }
        try faultInjector.check(.beforeRemove)
        let result = location.leaf.withCString { unlinkat(location.parent, $0, 0) }
        guard result == 0 else {
            throw InstallError.operatingSystem("unlink regular file \(path)", errno)
        }
        try syncDirectory(location.parent, operation: "parent of \(path)")
    }

    public func syncRoot() throws {
        try syncDirectory(root.rawValue, operation: "installer authority root")
    }

    public func listDirectory(at path: InstallRelativePath) throws -> [String] {
        let descriptor = try openDirectory(at: path)
        guard let stream = fdopendir(descriptor) else {
            close(descriptor)
            throw InstallError.operatingSystem("open directory stream \(path)", errno)
        }
        defer { closedir(stream) }
        var names: [String] = []
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
        return names.sorted()
    }

    func openDirectory(at path: InstallRelativePath) throws -> Int32 {
        try walk(path.components, create: false)
    }

    func removeEmptyDirectory(at path: InstallRelativePath) throws {
        try requireMutable()
        let location = try parentAndLeaf(path)
        defer { close(location.parent) }
        try faultInjector.check(.beforeRemove)
        let result = location.leaf.withCString { unlinkat(location.parent, $0, AT_REMOVEDIR) }
        guard result == 0 else {
            throw InstallError.operatingSystem("remove empty directory \(path)", errno)
        }
        try syncDirectory(location.parent, operation: "parent of \(path)")
    }

    func openLockFile(at path: InstallRelativePath) throws -> Int32 {
        try requireMutable()
        let location = try parentAndLeaf(path, createParents: true)
        defer { close(location.parent) }
        let descriptor = location.leaf.withCString {
            openat(location.parent, $0, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
        }
        guard descriptor >= 0 else {
            throw InstallError.operatingSystem("open transaction lock \(path)", errno)
        }
        do {
            var status = stat()
            guard fstat(descriptor, &status) == 0 else {
                throw InstallError.operatingSystem("inspect transaction lock \(path)", errno)
            }
            guard status.st_mode & S_IFMT == S_IFREG,
                  status.st_uid == policy.ownerUID,
                  status.st_gid == policy.groupGID,
                  status.st_nlink == 1,
                  status.st_mode & 0o077 == 0
            else {
                throw InstallError.metadata("transaction lock is not an authority-owned private regular file")
            }
            try applyMetadata(
                descriptor,
                ownerUID: UInt32(policy.ownerUID),
                groupGID: UInt32(policy.groupGID),
                mode: 0o600
            )
            return descriptor
        } catch {
            close(descriptor)
            throw error
        }
    }

    func openDirectoryLock(
        at path: InstallRelativePath,
        ownerUID: UInt32,
        groupGID: UInt32,
        mode: UInt16
    ) throws -> Int32 {
        let descriptor = try openDirectory(at: path)
        do {
            try verifyOwnedDirectory(
                descriptor,
                path: path,
                ownerUID: ownerUID,
                groupGID: groupGID,
                permittedModes: [mode]
            )
            return descriptor
        } catch {
            close(descriptor)
            throw error
        }
    }
}

extension FileSystemAuthority {
    private func validateRoot() throws {
        var status = stat()
        guard fstat(root.rawValue, &status) == 0 else {
            throw InstallError.operatingSystem("inspect installer authority root", errno)
        }
        guard status.st_mode & S_IFMT == S_IFDIR,
              status.st_uid == policy.ownerUID,
              status.st_mode & 0o022 == 0,
              permittedRootFlags(status.st_flags)
        else {
            throw InstallError.metadata("authority root must be owned by its authority and not group/world writable")
        }
        if let requiredMode = policy.requiredRootMode, UInt16(status.st_mode & 0o777) != requiredMode {
            throw InstallError.metadata(
                "source authority root must have mode \(String(requiredMode, radix: 8))"
            )
        }
        try validateAuthorityMetadata(root.rawValue)
    }

    func parentAndLeaf(
        _ path: InstallRelativePath,
        createParents: Bool = false
    ) throws -> (parent: Int32, leaf: String) {
        guard let leaf = path.components.last else {
            throw InstallError.invalidPath(path.description)
        }
        let parent = try walk(Array(path.components.dropLast()), create: createParents)
        return (parent, leaf)
    }

    private func walk(_ components: [String], create: Bool) throws -> Int32 {
        let duplicated = fcntl(root.rawValue, F_DUPFD_CLOEXEC, 0)
        guard duplicated >= 0 else {
            throw InstallError.operatingSystem("duplicate installer authority descriptor", errno)
        }
        var current = duplicated
        do {
            var traversed: [String] = []
            for component in components {
                try faultInjector.check(.beforeOpenComponent)
                if create {
                    try ensureDirectoryComponent(component, parent: current)
                }
                traversed.append(component)
                let next = try openDirectoryComponent(
                    component,
                    from: current,
                    relativePath: traversed.joined(separator: "/")
                )
                close(current)
                current = next
            }
            return current
        } catch {
            close(current)
            throw error
        }
    }

    private func ensureDirectoryComponent(_ component: String, parent: Int32) throws {
        try faultInjector.check(.beforeCreateDirectory)
        let result = component.withCString { mkdirat(parent, $0, 0o700) }
        guard result == 0 || errno == EEXIST else {
            throw InstallError.operatingSystem("create directory component \(component)", errno)
        }
    }

    private func openDirectoryComponent(
        _ component: String,
        from parent: Int32,
        relativePath: String
    ) throws -> Int32 {
        let descriptor = component.withCString {
            openat(parent, $0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        }
        guard descriptor >= 0 else {
            throw InstallError.operatingSystem("open directory component \(component)", errno)
        }
        do {
            try validateSourceNode(descriptor, kind: .directory, label: component)
            try validateSystemTraversalFlags(descriptor, relativePath: relativePath)
            return descriptor
        } catch {
            close(descriptor)
            throw error
        }
    }

    func openRegularFile(_ path: InstallRelativePath, rejectHardLinks: Bool) throws -> Int32 {
        let location = try parentAndLeaf(path)
        defer { close(location.parent) }
        let descriptor = location.leaf.withCString {
            openat(location.parent, $0, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        }
        guard descriptor >= 0 else {
            throw InstallError.operatingSystem("open regular file \(path)", errno)
        }
        do {
            var status = stat()
            guard fstat(descriptor, &status) == 0 else {
                throw InstallError.operatingSystem("inspect regular file \(path)", errno)
            }
            guard status.st_mode & S_IFMT == S_IFREG else {
                throw InstallError.metadata("\(path) is not a regular file")
            }
            if rejectHardLinks || policy.sourceOnly, status.st_nlink != 1 {
                throw InstallError.metadata("\(path) is hard-linked")
            }
            try validateSourceNode(descriptor, kind: .regularFile, label: path.description)
            return descriptor
        } catch {
            close(descriptor)
            throw error
        }
    }

    private func createRegularFile(_ leaf: String, parent: Int32) throws -> Int32 {
        let descriptor = leaf.withCString {
            openat(parent, $0, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        }
        guard descriptor >= 0 else {
            throw InstallError.operatingSystem("create regular file \(leaf)", errno)
        }
        return descriptor
    }

    func requireMutable() throws {
        guard !policy.sourceOnly else {
            throw InstallError.integrity("source package authority is read-only")
        }
    }

    private func validateSourceNode(
        _ descriptor: Int32,
        kind: InstallNodeKind,
        label: String
    ) throws {
        guard policy.sourceOnly else {
            return
        }
        var status = stat()
        guard fstat(descriptor, &status) == 0 else {
            throw InstallError.operatingSystem("inspect source package node", errno)
        }
        let mode = UInt16(status.st_mode & 0o777)
        let validMode: Bool = switch kind {
        case .directory:
            mode == 0o500 || mode == 0o700
        case .regularFile:
            mode == 0o400 || mode == 0o500
        case .symbolicLink:
            false
        }
        guard status.st_uid == policy.ownerUID,
              status.st_flags == 0,
              validMode
        else {
            throw InstallError.metadata(
                "source package node \(label) must be an owner-only, immutable file or directory"
            )
        }
        try validateAuthorityMetadata(descriptor)
    }

    private func validateAuthorityMetadata(_ descriptor: Int32) throws {
        if policy.sourceOnly {
            let unexpected = try extendedAttributeNames(descriptor).filter { $0 != "com.apple.provenance" }
            guard try !hasACL(descriptor), unexpected.isEmpty else {
                throw InstallError.metadata("source package nodes have an ACL or unexpected extended attribute")
            }
        } else {
            try validateNoUnexpectedExtendedMetadata(descriptor)
        }
    }

    private func copyAndHash(
        from source: Int32,
        to destination: Int32
    ) throws -> (digest: InstallDigest, byteCount: UInt64) {
        var hasher = SHA256()
        var total: UInt64 = 0
        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let count = try readChunk(source, into: &buffer, operation: "read staged source")
            if count == 0 {
                let digest = hasher.finalize().map { String(format: "%02x", $0) }.joined()
                return try (InstallDigest(digest), total)
            }
            let data = Data(buffer.prefix(count))
            hasher.update(data: data)
            try writeAll(data, to: destination, operation: "copy staged source")
            let addition = total.addingReportingOverflow(UInt64(count))
            guard !addition.overflow else {
                throw InstallError.integrity("staged source exceeds supported file size")
            }
            total = addition.partialValue
        }
    }

    private func writeAll(_ data: Data, to descriptor: Int32, operation: String) throws {
        try data.withUnsafeBytes { rawBuffer in
            guard var pointer = rawBuffer.baseAddress else {
                return
            }
            var remaining = rawBuffer.count
            while remaining > 0 {
                let count = write(descriptor, pointer, remaining)
                if count < 0, errno == EINTR {
                    continue
                }
                guard count > 0 else {
                    let code = count == 0 ? EIO : errno
                    throw InstallError.operatingSystem(operation, code)
                }
                remaining -= count
                pointer = pointer.advanced(by: count)
            }
        }
    }

    func readChunk(
        _ descriptor: Int32,
        into buffer: inout [UInt8],
        operation: String
    ) throws -> Int {
        while true {
            let count = read(descriptor, &buffer, buffer.count)
            if count >= 0 {
                return count
            }
            guard errno == EINTR else {
                throw InstallError.operatingSystem(operation, errno)
            }
        }
    }

    private func applyMetadata(
        _ descriptor: Int32,
        ownerUID: UInt32,
        groupGID: UInt32,
        mode: UInt16
    ) throws {
        try faultInjector.check(.beforeMetadata)
        guard ownerUID == policy.ownerUID, groupGID == policy.groupGID else {
            throw InstallError.metadata("manifest ownership exceeds this filesystem authority")
        }
        guard fchown(descriptor, uid_t(ownerUID), gid_t(groupGID)) == 0,
              fchmod(descriptor, mode_t(mode)) == 0,
              fchflags(descriptor, 0) == 0
        else {
            throw InstallError.operatingSystem("apply owned immutable metadata", errno)
        }
        try clearACL(descriptor)
        try clearExtendedAttributes(descriptor)
        try validateNoUnexpectedExtendedMetadata(descriptor)
    }

    private func verifyOwnedDirectory(
        _ descriptor: Int32,
        path: InstallRelativePath,
        ownerUID: UInt32,
        groupGID: UInt32,
        permittedModes: Set<UInt16>,
        permitPlatformFlags: Bool = false
    ) throws {
        var status = stat()
        guard fstat(descriptor, &status) == 0 else {
            throw InstallError.operatingSystem("inspect owned directory \(path)", errno)
        }
        guard status.st_mode & S_IFMT == S_IFDIR,
              status.st_uid == ownerUID,
              status.st_gid == groupGID,
              permittedModes.contains(UInt16(status.st_mode & 0o777)),
              permittedFlags(
                  status.st_flags,
                  relativePath: path.description,
                  permitsPlatformFlags: permitPlatformFlags
              )
        else {
            throw InstallError.collision(path.description)
        }
        do {
            try validateNoUnexpectedExtendedMetadata(descriptor)
        } catch {
            throw InstallError.collision(path.description)
        }
    }

    func validateRegularFile(_ descriptor: Int32, entry: InstallEntry) throws {
        var status = stat()
        guard fstat(descriptor, &status) == 0 else {
            throw InstallError.operatingSystem("validate copied file", errno)
        }
        guard status.st_mode & S_IFMT == S_IFREG,
              status.st_uid == entry.ownerUID,
              status.st_gid == entry.groupGID,
              UInt16(status.st_mode & 0o777) == entry.mode,
              status.st_nlink == 1,
              status.st_flags == 0,
              UInt64(status.st_size) == entry.byteCount
        else {
            throw InstallError.metadata("copied file metadata does not match the manifest")
        }
        try validateNoUnexpectedExtendedMetadata(descriptor)
    }

    public func validateNoUnexpectedExtendedMetadata(_ descriptor: Int32) throws {
        guard try !hasACL(descriptor) else {
            throw InstallError.metadata("extended ACL remained after sanitization")
        }
        let unexpected = try extendedAttributeNames(descriptor).filter { $0 != "com.apple.provenance" }
        guard unexpected.isEmpty else {
            throw InstallError.metadata("unexpected extended attributes remained after sanitization")
        }
    }

    private func clearExtendedAttributes(_ descriptor: Int32) throws {
        for name in try extendedAttributeNames(descriptor) where name != "com.apple.provenance" {
            let result = name.withCString { fremovexattr(descriptor, $0, 0) }
            guard result == 0 else {
                throw InstallError.operatingSystem("remove extended attribute \(name)", errno)
            }
        }
    }

    private func extendedAttributeNames(_ descriptor: Int32) throws -> [String] {
        let byteCount = flistxattr(descriptor, nil, 0, 0)
        guard byteCount >= 0 else {
            throw InstallError.operatingSystem("inspect extended attributes", errno)
        }
        if byteCount == 0 {
            return []
        }
        guard byteCount <= 65536 else {
            throw InstallError.metadata("extended attribute name list exceeds its safety bound")
        }
        var bytes = [UInt8](repeating: 0, count: byteCount)
        let readCount = flistxattr(descriptor, &bytes, bytes.count, 0)
        guard readCount == byteCount else {
            throw InstallError.operatingSystem("read extended attribute names", errno)
        }
        return try decodeExtendedAttributeNames(bytes)
    }

    private func decodeExtendedAttributeNames(_ bytes: [UInt8]) throws -> [String] {
        var names: [String] = []
        var start = bytes.startIndex
        for index in bytes.indices where bytes[index] == 0 {
            guard index > start else {
                throw InstallError.metadata("extended attribute name list is malformed")
            }
            let name = String(decoding: bytes[start ..< index], as: UTF8.self)
            guard Array(name.utf8) == Array(bytes[start ..< index]) else {
                throw InstallError.metadata("extended attribute name is not valid UTF-8")
            }
            names.append(name)
            start = bytes.index(after: index)
        }
        guard start == bytes.endIndex else {
            throw InstallError.metadata("extended attribute name list is unterminated")
        }
        return names
    }

    private func metadata(status: stat, parent: Int32, leaf: String) throws -> InstallNodeMetadata {
        let kind = try nodeKind(status.st_mode)
        var hasExtendedACL = false
        var hasAttributes = false
        if kind != .symbolicLink {
            let flags = kind == .directory ? O_DIRECTORY : 0
            let descriptor = leaf.withCString {
                openat(parent, $0, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | flags)
            }
            guard descriptor >= 0 else {
                throw InstallError.operatingSystem("open node metadata \(leaf)", errno)
            }
            defer { close(descriptor) }
            hasExtendedACL = try hasACL(descriptor)
            let count = flistxattr(descriptor, nil, 0, 0)
            guard count >= 0 else {
                throw InstallError.operatingSystem("inspect node extended attributes", errno)
            }
            hasAttributes = count > 0
        }
        return InstallNodeMetadata(
            kind: kind,
            ownerUID: status.st_uid,
            groupGID: status.st_gid,
            mode: UInt16(status.st_mode & 0o777),
            byteCount: UInt64(status.st_size),
            linkCount: UInt64(status.st_nlink),
            hasACL: hasExtendedACL,
            hasExtendedAttributes: hasAttributes,
            flags: status.st_flags
        )
    }

    private func nodeKind(_ mode: mode_t) throws -> InstallNodeKind {
        switch mode & S_IFMT {
        case S_IFDIR:
            return .directory
        case S_IFREG:
            return .regularFile
        case S_IFLNK:
            return .symbolicLink
        default:
            throw InstallError.metadata("unsupported filesystem node type")
        }
    }

    private func hasACL(_ descriptor: Int32) throws -> Bool {
        guard let accessControlList = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else {
            if errno == ENOENT {
                return false
            }
            throw InstallError.operatingSystem("inspect extended ACL", errno)
        }
        defer { acl_free(UnsafeMutableRawPointer(accessControlList)) }
        var entry: acl_entry_t?
        let result = acl_get_entry(accessControlList, Int32(ACL_FIRST_ENTRY.rawValue), &entry)
        guard result >= 0 else {
            throw InstallError.operatingSystem("read extended ACL", errno)
        }
        return result == 0
    }

    private func clearACL(_ descriptor: Int32) throws {
        guard let emptyACL = acl_init(0) else {
            throw InstallError.operatingSystem("allocate empty extended ACL", errno)
        }
        defer { acl_free(UnsafeMutableRawPointer(emptyACL)) }
        guard acl_set_fd_np(descriptor, emptyACL, ACL_TYPE_EXTENDED) == 0 else {
            throw InstallError.operatingSystem("remove extended ACL", errno)
        }
    }

    func rename(
        from sourcePath: InstallRelativePath,
        to destinationPath: InstallRelativePath,
        flags: UInt32
    ) throws {
        let source = try parentAndLeaf(sourcePath)
        defer { close(source.parent) }
        let destination = try parentAndLeaf(destinationPath)
        defer { close(destination.parent) }
        try faultInjector.check(.beforeRename)
        let result = source.leaf.withCString { sourcePointer in
            destination.leaf.withCString {
                renameatx_np(source.parent, sourcePointer, destination.parent, $0, flags)
            }
        }
        guard result == 0 else {
            throw InstallError.operatingSystem(
                "atomically rename \(sourcePath) to \(destinationPath)",
                errno
            )
        }
        try syncDirectory(source.parent, operation: "source parent of \(sourcePath)")
        if source.parent != destination.parent {
            try syncDirectory(
                destination.parent,
                operation: "destination parent of \(destinationPath)"
            )
        }
    }

    private func syncFile(_ descriptor: Int32, operation: String) throws {
        try faultInjector.check(.beforeFileSync)
        try durability.syncFile(descriptor, operation: operation)
    }

    func syncDirectory(_ descriptor: Int32, operation: String) throws {
        try faultInjector.check(.beforeDirectorySync)
        try durability.syncDirectory(descriptor, operation: operation)
    }

    private func unlinkLeaf(_ leaf: String, parent: Int32) {
        _ = leaf.withCString { unlinkat(parent, $0, 0) }
    }
}
