// SPDX-License-Identifier: GPL-3.0-or-later
import Darwin
import Foundation
@testable import RemapInstallKit
import Testing

@Test(arguments: [false, true])
func definitionReplacementIsAtomicAndLeavesTheCorrectModeWithoutTemporaryFiles(failRename: Bool) throws {
    let tree = try TemporaryInstallTree()
    let root = try tree.directory("definition-publication")
    let authority = try testAuthority(at: root)
    let publicDirectory = try InstallRelativePath("LaunchDaemons")
    try authority.ensureOwnedDirectory(
        at: publicDirectory,
        ownerUID: UInt32(geteuid()),
        groupGID: UInt32(getegid()),
        mode: 0o755
    )
    let oldBytes = Data("<plist><dict><key>Label</key><string>old</string></dict></plist>".utf8)
    let newBytes = Data("<plist><dict><key>Label</key><string>new</string></dict></plist>".utf8)
    let previous = try definitionPublication(authority: authority, generation: "old", bytes: oldBytes)
    let next = try definitionPublication(authority: authority, generation: "new", bytes: newBytes)
    let store = PublicationStore(authority: authority)
    try store.publish(previous, replacing: nil, transactionID: "first")
    if failRename {
        let failing = try PublicationStore(authority: testAuthority(
            at: root,
            faultInjector: CheckpointFaultInjector(checkpoint: .beforeRename)
        ))
        #expect(throws: InstallError.faultInjected("beforeRename")) {
            try failing.publish(next, replacing: previous, transactionID: "replacement")
        }
    } else {
        try store.publish(next, replacing: previous, transactionID: "replacement")
    }
    #expect(try authority.readFile(at: next.path, maximumByteCount: 1024) == (failRename ? oldBytes : newBytes))
    #expect(try authority.metadata(at: next.path)?.mode == 0o444)
    #expect(try authority.listDirectory(at: publicDirectory) == ["remap.plist"])
}

private func definitionPublication(
    authority: FileSystemAuthority,
    generation: String,
    bytes: Data
) throws -> InstallPublication {
    let source = try InstallRelativePath("Generations/\(generation)/remap.plist")
    try authority.writeFile(
        bytes,
        at: source,
        ownerUID: UInt32(geteuid()),
        groupGID: UInt32(getegid()),
        mode: 0o444
    )
    return try InstallPublication(
        path: InstallRelativePath("LaunchDaemons/remap.plist"),
        source: source,
        sha256: InstallDigest.hash(bytes),
        byteCount: UInt64(bytes.count),
        generationID: generation,
        ownerUID: UInt32(geteuid()),
        groupGID: UInt32(getegid()),
        mode: 0o444
    )
}
