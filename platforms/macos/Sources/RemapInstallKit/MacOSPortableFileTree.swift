import Darwin
import Foundation

enum MacOSPortableFileTree {
    private static let maximumFileBytes: UInt64 = 268_435_456
    private static let maximumTotalBytes: UInt64 = 805_306_368

    static func copyProduct(
        from sourcePath: String,
        to payloadPath: String,
        ownerUID: uid_t,
        groupGID: gid_t
    ) throws {
        let source = URL(fileURLWithPath: sourcePath, isDirectory: true)
        let destination = URL(fileURLWithPath: payloadPath, isDirectory: true)
        try requireDirectory(
            source,
            mode: 0o500,
            ownerUID: ownerUID,
            groupGID: groupGID
        )
        try FileManager.default.createDirectory(
            at: destination,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        var seenFiles = Set<String>()
        var seenDirectories = Set<String>()
        var totalBytes: UInt64 = 0
        try copyDirectory(
            source,
            destination,
            relative: "",
            seenFiles: &seenFiles,
            seenDirectories: &seenDirectories,
            totalBytes: &totalBytes,
            ownerUID: ownerUID,
            groupGID: groupGID
        )
        let requiredFiles = MacOSPortableProductContract.requiredFiles.union([
            "app/Remap.app/Contents/Info.plist",
            "app/Remap.app/Contents/MacOS/Remap"
        ])
        guard requiredFiles.isSubset(of: seenFiles),
              MacOSPortableProductContract.requiredDirectories.isSubset(of: seenDirectories)
        else {
            throw InstallError.invalidManifest("the portable product omits a required native asset")
        }
    }

    static func sealPackage(rootPath: String) throws {
        let root = URL(fileURLWithPath: rootPath, isDirectory: true)
        try walk(root) { url, metadata in
            if metadata.kind == .directory {
                try setMode(url, url == root ? 0o700 : 0o500)
            } else {
                let executable = metadata.mode & 0o111 != 0
                try setMode(url, executable ? 0o500 : 0o400)
            }
            try clearFlags(url)
        }
    }

    static func entries(payloadPath: String) throws -> [InstallEntry] {
        let root = URL(fileURLWithPath: payloadPath, isDirectory: true)
        var entries: [InstallEntry] = []
        try walkEntries(root, relative: "") { url, relative, metadata in
            let path = try InstallRelativePath(relative)
            if metadata.kind == .directory {
                try entries.append(
                    InstallEntry(
                        path: path,
                        kind: .directory,
                        role: role(relative),
                        sha256: nil,
                        byteCount: nil,
                        mode: 0o555
                    )
                )
                return
            }
            let data = try Data(contentsOf: url, options: [.mappedIfSafe])
            try entries.append(
                InstallEntry(
                    path: path,
                    kind: .regularFile,
                    role: role(relative),
                    sha256: InstallDigest.hash(data),
                    byteCount: UInt64(data.count),
                    mode: metadata.mode & 0o111 == 0 ? 0o444 : 0o555
                )
            )
        }
        return entries.sorted { $0.path < $1.path }
    }

    private static func walkEntries(
        _ root: URL,
        relative: String,
        visit: (URL, String, NodeMetadata) throws -> Void
    ) throws {
        let children = try FileManager.default.contentsOfDirectory(
            at: root,
            includingPropertiesForKeys: nil
        ).sorted { $0.lastPathComponent < $1.lastPathComponent }
        for child in children {
            let childRelative = relative.isEmpty
                ? child.lastPathComponent
                : relative + "/" + child.lastPathComponent
            let metadata = try nodeMetadata(child)
            try visit(child, childRelative, metadata)
            if metadata.kind == .directory {
                try walkEntries(child, relative: childRelative, visit: visit)
            }
        }
    }

    private static func copyDirectory(
        _ source: URL,
        _ destination: URL,
        relative: String,
        seenFiles: inout Set<String>,
        seenDirectories: inout Set<String>,
        totalBytes: inout UInt64,
        ownerUID: uid_t,
        groupGID: gid_t
    ) throws {
        let children = try FileManager.default.contentsOfDirectory(
            at: source,
            includingPropertiesForKeys: nil
        ).sorted { $0.lastPathComponent < $1.lastPathComponent }
        for child in children {
            let childRelative = relative.isEmpty
                ? child.lastPathComponent
                : relative + "/" + child.lastPathComponent
            guard allowed(childRelative) else {
                throw InstallError.invalidManifest("the portable product contains an unexpected asset")
            }
            let metadata = try nodeMetadata(child)
            guard metadata.ownerUID == ownerUID,
                  metadata.groupGID == groupGID,
                  metadata.flags == 0,
                  allowedMode(metadata)
            else {
                throw InstallError.metadata("a portable product node has unsafe ownership")
            }
            let target = destination.appendingPathComponent(child.lastPathComponent)
            switch metadata.kind {
            case .directory:
                _ = seenDirectories.insert(childRelative)
                try FileManager.default.createDirectory(
                    at: target,
                    withIntermediateDirectories: false,
                    attributes: [.posixPermissions: 0o700]
                )
                try copyDirectory(
                    child,
                    target,
                    relative: childRelative,
                    seenFiles: &seenFiles,
                    seenDirectories: &seenDirectories,
                    totalBytes: &totalBytes,
                    ownerUID: ownerUID,
                    groupGID: groupGID
                )
            case .regularFile:
                guard metadata.linkCount == 1,
                      metadata.byteCount <= maximumFileBytes,
                      totalBytes <= maximumTotalBytes - metadata.byteCount
                else {
                    throw InstallError.metadata("a portable product file exceeds its integrity bound")
                }
                totalBytes += metadata.byteCount
                let data = try Data(contentsOf: child, options: [.mappedIfSafe])
                guard UInt64(data.count) == metadata.byteCount else {
                    throw InstallError.integrity("a portable product file changed while it was copied")
                }
                try data.write(to: target, options: [.withoutOverwriting])
                try setMode(target, metadata.mode & 0o111 == 0 ? 0o400 : 0o500)
                _ = seenFiles.insert(childRelative)
            case .symbolicLink:
                throw InstallError.metadata("the portable product contains a symbolic link")
            }
        }
    }

    private static func allowed(_ relative: String) -> Bool {
        if relative == "app/Remap.app" || relative.hasPrefix("app/Remap.app/") {
            return true
        }
        return MacOSPortableProductContract.requiredFiles.contains(relative)
            || MacOSPortableProductContract.requiredDirectories.contains(relative)
    }

    private static func role(_ path: String) -> InstallEntryRole {
        switch path {
        case "bin/remap":
            .commandLineTool
        case "libexec/remapd", "libexec/remap-resolver":
            .daemon
        default:
            path.hasPrefix("app/") ? .application : .support
        }
    }

    private static func allowedMode(_ metadata: NodeMetadata) -> Bool {
        switch metadata.kind {
        case .directory:
            metadata.mode == 0o500
        case .regularFile:
            metadata.mode == 0o400 || metadata.mode == 0o500
        case .symbolicLink:
            false
        }
    }

    private static func requireDirectory(
        _ url: URL,
        mode: UInt16,
        ownerUID: uid_t,
        groupGID: gid_t
    ) throws {
        let metadata = try nodeMetadata(url)
        guard metadata.kind == .directory,
              metadata.ownerUID == ownerUID,
              metadata.groupGID == groupGID,
              metadata.mode == mode,
              metadata.flags == 0
        else {
            throw InstallError.metadata("the portable product root has unsafe metadata")
        }
    }

    private static func walk(
        _ root: URL,
        includeRoot: Bool = true,
        visit: (URL, NodeMetadata) throws -> Void
    ) throws {
        if includeRoot {
            try visit(root, nodeMetadata(root))
        }
        let children = try FileManager.default.contentsOfDirectory(
            at: root,
            includingPropertiesForKeys: nil
        ).sorted { $0.lastPathComponent < $1.lastPathComponent }
        for child in children {
            let metadata = try nodeMetadata(child)
            try visit(child, metadata)
            if metadata.kind == .directory {
                try walk(child, includeRoot: false, visit: visit)
            }
        }
    }

    private static func nodeMetadata(_ url: URL) throws -> NodeMetadata {
        var status = stat()
        guard lstat(url.path, &status) == 0 else {
            throw InstallError.operatingSystem("inspect portable product", errno)
        }
        let kind: InstallNodeKind
        switch status.st_mode & S_IFMT {
        case S_IFDIR:
            kind = .directory
        case S_IFREG:
            kind = .regularFile
        case S_IFLNK:
            kind = .symbolicLink
        default:
            throw InstallError.metadata("the portable product contains a special file")
        }
        guard status.st_size >= 0 else {
            throw InstallError.metadata("a portable product file has an invalid size")
        }
        return NodeMetadata(
            kind: kind,
            ownerUID: status.st_uid,
            groupGID: status.st_gid,
            mode: UInt16(status.st_mode & 0o777),
            byteCount: UInt64(status.st_size),
            linkCount: UInt64(status.st_nlink),
            flags: status.st_flags
        )
    }

    private static func setMode(_ url: URL, _ mode: mode_t) throws {
        guard chmod(url.path, mode) == 0 else {
            throw InstallError.operatingSystem("seal portable product mode", errno)
        }
    }

    private static func clearFlags(_ url: URL) throws {
        guard chflags(url.path, 0) == 0 else {
            throw InstallError.operatingSystem("clear portable product flags", errno)
        }
    }

    private struct NodeMetadata {
        let kind: InstallNodeKind
        let ownerUID: uid_t
        let groupGID: gid_t
        let mode: UInt16
        let byteCount: UInt64
        let linkCount: UInt64
        let flags: UInt32
    }
}
