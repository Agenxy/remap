import Darwin
import Foundation
@testable import RemapInstallKit
@testable import RemapPortableInstaller
import Testing

@_silgen_name("mbr_uid_to_uuid")
private func portableTestMbrUIDToUUID(
    _ userID: uid_t,
    _ identifier: UnsafeMutablePointer<UInt8>
) -> Int32

@Test
func portableReleaseTreeUsesDescriptorRootedExactEntries() throws {
    let fixture = try PortableReleaseTreeFixture()
    defer { fixture.remove() }
    let entries = try PortableReleaseVerifier.entries(
        authority: fixture.authority(),
        payloadPath: InstallRelativePath("payload"),
        expectedOwnerUID: geteuid()
    )
    #expect(entries.map(\.path.description) == ["product", "product/bin", "product/bin/remap"])
    #expect(entries.last?.sha256 == InstallDigest.hash(fixture.fileData))
}

@Test
func portableReleaseTreeRejectsSymbolicLinksAndHardLinks() throws {
    do {
        let fixture = try PortableReleaseTreeFixture()
        defer { fixture.remove() }
        let linkPath = fixture.product.appendingPathComponent("linked")
        #expect(symlink("bin/remap", linkPath.path) == 0)
        #expect(throws: Error.self) {
            _ = try PortableReleaseVerifier.entries(
                authority: fixture.authority(),
                payloadPath: InstallRelativePath("payload"),
                expectedOwnerUID: geteuid()
            )
        }
    }
    do {
        let fixture = try PortableReleaseTreeFixture()
        defer { fixture.remove() }
        let hardLink = fixture.bin.appendingPathComponent("remap-copy")
        #expect(link(fixture.file.path, hardLink.path) == 0)
        #expect(throws: Error.self) {
            _ = try PortableReleaseVerifier.entries(
                authority: fixture.authority(),
                payloadPath: InstallRelativePath("payload"),
                expectedOwnerUID: geteuid()
            )
        }
    }
}

@Test
func portableReleaseTreeRejectsUnexpectedDirectoryMetadata() throws {
    do {
        let fixture = try PortableReleaseTreeFixture()
        defer { fixture.remove() }
        try addPortableTestACL(to: fixture.product)
        #expect(throws: Error.self) {
            _ = try PortableReleaseVerifier.entries(
                authority: fixture.authority(),
                payloadPath: InstallRelativePath("payload"),
                expectedOwnerUID: geteuid()
            )
        }
    }
    do {
        let fixture = try PortableReleaseTreeFixture()
        defer { fixture.remove() }
        let value = Data("unexpected".utf8)
        let result = value.withUnsafeBytes { bytes in
            setxattr(
                fixture.product.path,
                "org.agenxy.remap.test",
                bytes.baseAddress,
                bytes.count,
                0,
                0
            )
        }
        #expect(result == 0)
        #expect(throws: Error.self) {
            _ = try PortableReleaseVerifier.entries(
                authority: fixture.authority(),
                payloadPath: InstallRelativePath("payload"),
                expectedOwnerUID: geteuid()
            )
        }
    }
}

private struct PortableReleaseTreeFixture {
    let root: URL
    let payload: URL
    let product: URL
    let bin: URL
    let file: URL
    let fileData = Data("portable-remap".utf8)

    init() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent(
            "remap-release-tree-\(UUID().uuidString.lowercased())",
            isDirectory: true
        )
        payload = root.appendingPathComponent("payload", isDirectory: true)
        product = payload.appendingPathComponent("product", isDirectory: true)
        bin = product.appendingPathComponent("bin", isDirectory: true)
        file = bin.appendingPathComponent("remap")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        try FileManager.default.createDirectory(at: payload, withIntermediateDirectories: false)
        try FileManager.default.createDirectory(at: product, withIntermediateDirectories: false)
        try FileManager.default.createDirectory(at: bin, withIntermediateDirectories: false)
        try fileData.write(to: file, options: .withoutOverwriting)
        for directory in [root, payload, product, bin] {
            guard chmod(directory.path, 0o700) == 0 else {
                throw InstallError.operatingSystem("seal a test release directory", errno)
            }
        }
        guard chmod(file.path, 0o500) == 0 else {
            throw InstallError.operatingSystem("seal a test release file", errno)
        }
    }

    func authority() throws -> FileSystemAuthority {
        try FileSystemAuthority(
            testingSourcePackageRootPath: root.path,
            ownerUID: UInt32(geteuid())
        )
    }

    func remove() {
        try? FileManager.default.removeItem(at: root)
    }
}

private func addPortableTestACL(to url: URL) throws {
    var accessControlList = acl_init(1)
    guard accessControlList != nil else {
        throw InstallError.operatingSystem("allocate a test ACL", errno)
    }
    defer {
        if let accessControlList {
            acl_free(UnsafeMutableRawPointer(accessControlList))
        }
    }
    var entry: acl_entry_t?
    guard acl_create_entry(&accessControlList, &entry) == 0, let entry,
          acl_set_tag_type(entry, ACL_EXTENDED_DENY) == 0
    else {
        throw InstallError.operatingSystem("create a test ACL entry", errno)
    }
    var identifier = [UInt8](repeating: 0, count: 16)
    guard portableTestMbrUIDToUUID(geteuid(), &identifier) == 0 else {
        throw InstallError.operatingSystem("resolve a test ACL identity", errno)
    }
    guard identifier.withUnsafeBytes({ acl_set_qualifier(entry, $0.baseAddress) }) == 0 else {
        throw InstallError.operatingSystem("set a test ACL identity", errno)
    }
    var permissions: acl_permset_t?
    var flags: acl_flagset_t?
    guard acl_get_permset(entry, &permissions) == 0, let permissions,
          acl_clear_perms(permissions) == 0,
          acl_add_perm(permissions, ACL_WRITE_DATA) == 0,
          acl_set_permset(entry, permissions) == 0,
          acl_get_flagset_np(UnsafeMutableRawPointer(entry), &flags) == 0,
          let flags,
          acl_clear_flags_np(flags) == 0,
          acl_set_flagset_np(UnsafeMutableRawPointer(entry), flags) == 0,
          let accessControlList,
          acl_valid(accessControlList) == 0,
          acl_set_file(url.path, ACL_TYPE_EXTENDED, accessControlList) == 0
    else {
        throw InstallError.operatingSystem("apply a test ACL", errno)
    }
}
