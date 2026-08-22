import Darwin
import Foundation
@testable import RemapInstallKit
import Testing

@Test
func liveMacOSSystemFlagsMatchThePinnedAuthorityPolicy() throws {
    for (absolutePath, relativePath) in [("/", ""), ("/Library", "Library"), ("/usr", "usr")] {
        var status = stat()
        guard lstat(absolutePath, &status) == 0 else {
            throw InstallError.operatingSystem("inspect live system flag fixture", errno)
        }
        #expect(InstallSystemNodeFlagPolicy.permitsTraversalFlags(
            status.st_flags,
            relativePath: relativePath
        ))
    }
    var local = stat()
    if lstat("/usr/local", &local) == 0 {
        #expect(InstallSystemNodeFlagPolicy.permitsTraversalFlags(
            local.st_flags,
            relativePath: "usr/local"
        ))
        #expect(InstallSystemNodeFlagPolicy.permitsCompatibleDirectoryFlags(
            local.st_flags,
            relativePath: "usr/local"
        ))
    } else {
        #expect(errno == ENOENT)
    }
}

@Test
func systemFlagPolicyRejectsEveryUnpinnedOrAdditionalFlag() {
    #expect(!InstallSystemNodeFlagPolicy.permitsTraversalFlags(
        UInt32(SF_NOUNLINK | UF_HIDDEN),
        relativePath: "Library"
    ))
    #expect(!InstallSystemNodeFlagPolicy.permitsTraversalFlags(
        UInt32(SF_NOUNLINK),
        relativePath: "Library/Application Support"
    ))
    #expect(!InstallSystemNodeFlagPolicy.permitsCompatibleDirectoryFlags(
        UInt32(SF_NOUNLINK | UF_IMMUTABLE),
        relativePath: "usr/local"
    ))
}

@Test
func descriptorTraversalRejectsIntermediateSymbolicLinks() throws {
    let tree = try TemporaryInstallTree()
    let root = try tree.directory("root")
    let outside = try tree.directory("outside")
    try writeTestFile(Data("foreign".utf8), to: outside.appending(path: "payload"))
    let linkPath = root.appending(path: "escape").path
    guard symlink(outside.path, linkPath) == 0 else {
        throw InstallError.operatingSystem("create test symbolic link", errno)
    }
    let authority = try testAuthority(at: root)
    #expect(throws: InstallError.self) {
        try authority.metadata(at: InstallRelativePath("escape/payload"))
    }
}

@Test
func copyRejectsHardLinkedSources() throws {
    let tree = try TemporaryInstallTree()
    let sourceURL = try tree.directory("source")
    let destinationURL = try tree.directory("destination")
    let data = Data("hard-link".utf8)
    let sourceFile = sourceURL.appending(path: "tool")
    try writeTestFile(data, to: sourceFile)
    guard link(sourceFile.path, sourceURL.appending(path: "alias").path) == 0 else {
        throw InstallError.operatingSystem("create test hard link", errno)
    }
    let source = try testAuthority(at: sourceURL)
    let destination = try testAuthority(at: destinationURL)
    let entry = try testEntry(path: "tool", data: data)
    #expect(throws: InstallError.metadata("tool is hard-linked")) {
        try destination.copyRegularFile(
            from: source,
            sourcePath: entry.path,
            destinationPath: entry.path,
            entry: entry
        )
    }
    #expect(try destination.metadata(at: entry.path) == nil)
}

@Test
func copyDoesNotPreserveSourceACL() throws {
    let tree = try TemporaryInstallTree()
    let sourceURL = try tree.directory("source")
    let destinationURL = try tree.directory("destination")
    let data = Data("acl".utf8)
    let sourceFile = sourceURL.appending(path: "tool")
    try writeTestFile(data, to: sourceFile)
    try addExtendedACL(to: sourceFile)
    let source = try testAuthority(at: sourceURL)
    let destination = try testAuthority(at: destinationURL)
    let entry = try testEntry(path: "tool", data: data)
    try destination.copyRegularFile(
        from: source,
        sourcePath: entry.path,
        destinationPath: entry.path,
        entry: entry
    )
    let sourceMetadata = try source.metadata(at: entry.path)
    let destinationMetadata = try destination.metadata(at: entry.path)
    #expect(sourceMetadata?.hasACL == true)
    #expect(destinationMetadata?.hasACL == false)
    #expect(destinationMetadata?.linkCount == 1)
    #expect(destinationMetadata?.mode == 0o444)
}

@Test
func rootAuthorityCannotBeOpenedByAnUnprivilegedProcess() throws {
    if geteuid() == 0 {
        return
    }
    let tree = try TemporaryInstallTree()
    let root = try tree.directory("root")
    #expect(throws: InstallError.notRoot) {
        try FileSystemAuthority(systemRootPath: root.path)
    }
}

@Test
func sourcePackageAuthorityIsPrivateOwnerBoundAndReadOnly() throws {
    let tree = try TemporaryInstallTree()
    let root = try tree.directory("source-package")
    let file = root.appending(path: "manifest.json")
    try writeTestFile(Data("manifest".utf8), to: file)
    try removeTestProvenance(from: file)
    guard chmod(file.path, 0o400) == 0 else {
        throw InstallError.operatingSystem("seal source package file", errno)
    }
    try removeTestProvenance(from: root)
    let authority = try testSourcePackageAuthority(at: root)
    #expect(try authority.readUniqueFile(
        at: InstallRelativePath("manifest.json"),
        maximumByteCount: 32
    ) == Data("manifest".utf8))
    #expect(throws: InstallError.integrity("source package authority is read-only")) {
        try authority.writeFile(
            Data("replacement".utf8),
            at: InstallRelativePath("replacement"),
            ownerUID: UInt32(geteuid()),
            groupGID: UInt32(getegid()),
            mode: 0o400
        )
    }
    #expect(throws: InstallError.metadata(
        "authority root must be owned by its authority and not group/world writable"
    )) {
        try testSourcePackageAuthority(at: root, ownerUID: UInt32(geteuid()) &+ 1)
    }
}

@Test
func sourcePackageAuthorityRejectsLooseRootsAndExtendedMetadata() throws {
    let tree = try TemporaryInstallTree()
    let looseRoot = try tree.directory("loose-source")
    guard chmod(looseRoot.path, 0o755) == 0 else {
        throw InstallError.operatingSystem("loosen source package root", errno)
    }
    #expect(throws: InstallError.metadata("source authority root must have mode 700")) {
        try testSourcePackageAuthority(at: looseRoot)
    }

    let aclRoot = try tree.directory("acl-source")
    let file = aclRoot.appending(path: "manifest.json")
    try writeTestFile(Data("manifest".utf8), to: file)
    try addExtendedACL(to: file)
    try removeTestProvenance(from: file)
    guard chmod(file.path, 0o400) == 0 else {
        throw InstallError.operatingSystem("seal ACL source file", errno)
    }
    try removeTestProvenance(from: aclRoot)
    let authority = try testSourcePackageAuthority(at: aclRoot)
    #expect(throws: InstallError.metadata("source package nodes have an ACL or unexpected extended attribute")) {
        try authority.readUniqueFile(at: InstallRelativePath("manifest.json"), maximumByteCount: 32)
    }
}

private func removeTestProvenance(from url: URL) throws {
    let result = url.path.withCString { path in
        "com.apple.provenance".withCString { name in
            removexattr(path, name, XATTR_NOFOLLOW)
        }
    }
    guard result == 0 || errno == ENOATTR else {
        throw InstallError.operatingSystem("remove test provenance", errno)
    }
}
