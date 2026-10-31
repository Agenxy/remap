// SPDX-License-Identifier: GPL-3.0-or-later
import Darwin
import Foundation
@testable import RemapInstallKit
import Testing

// ADR-0036. A complete uninstall leaves `Library/Application Support/Agenxy/Remap`
// exactly as empty as before Remap, after a supervisor fallback and after the
// owner turned DNS off on purpose, and never removes anything it cannot vouch for.

let remapProductDirectory = "Library/Application Support/Agenxy/Remap"

/// Writes one resolver record the way its root writer does, at its exact mode.
func writeResolverRecord(_ name: String, mode: mode_t, in product: URL) throws {
    let url = product.appendingPathComponent(name)
    try Data(#"{"payload":{},"sha256":""}"#.utf8).write(to: url, options: .withoutOverwriting)
    guard chmod(url.path, mode) == 0 else {
        throw InstallError.operatingSystem("set a test record's mode", errno)
    }
}

/// After a fallback: the bypass record. After a deliberate turn-off: that
/// record as well, since a fallback may have preceded it.
let resolverRecordCases: [[(name: String, mode: mode_t)]] = [
    [("resolver-bypass-v1.json", 0o600)],
    [("dns-turned-off-v1.json", 0o644), ("resolver-bypass-v1.json", 0o600)],
    [("loopback-reservations-v1.json", 0o600), (".loopback-reservations.lock", 0o600)]
]

@Test(arguments: resolverRecordCases.indices)
func aSourceUninstallLeavesTheProductDirectoryEmptyAfterResolverRecords(_ index: Int) async throws {
    let fixture = try MacOSInstallerFixture()
    try await fixture.install(transactionID: "install-resolver-records-\(index)")
    let product = fixture.rootURL.appending(path: remapProductDirectory)
    for record in resolverRecordCases[index] {
        try writeResolverRecord(record.name, mode: record.mode, in: product)
    }
    let preview = try fixture.installer.previewUninstall(generationID: fixture.manifest.generationID)

    try await fixture.installer.uninstall(
        transactionID: "uninstall-resolver-records-\(index)",
        generationID: fixture.manifest.generationID,
        approvalToken: preview.approvalToken
    )

    #expect(!fixture.exists(remapProductDirectory))
    #expect(fixture.exists("Library/Application Support/Agenxy"))
}

@Test
func aSourceUninstallRefusesARecordItCannotVouchFor() async throws {
    let fixture = try MacOSInstallerFixture()
    try await fixture.install(transactionID: "install-untrusted-record")
    let product = fixture.rootURL.appending(path: remapProductDirectory)
    let elsewhere = fixture.rootURL.appending(path: "elsewhere.json")
    try Data("keep".utf8).write(to: elsewhere)
    try FileManager.default.createSymbolicLink(
        at: product.appendingPathComponent("resolver-bypass-v1.json"),
        withDestinationURL: elsewhere
    )
    let preview = try fixture.installer.previewUninstall(generationID: fixture.manifest.generationID)

    await #expect(throws: InstallError.collision("\(remapProductDirectory)/resolver-bypass-v1.json")) {
        try await fixture.installer.uninstall(
            transactionID: "uninstall-untrusted-record",
            generationID: fixture.manifest.generationID,
            approvalToken: preview.approvalToken
        )
    }
    #expect(try Data(contentsOf: elsewhere) == Data("keep".utf8))
    #expect(fixture.exists("\(remapProductDirectory)/resolver-bypass-v1.json"))
}

@Test
func aRecordWithAnotherModeIsNotRemoved() throws {
    let tree = try TemporaryInstallTree()
    let product = tree.url.appending(path: remapProductDirectory)
    try FileManager.default.createDirectory(at: product, withIntermediateDirectories: true)
    try writeResolverRecord("dns-turned-off-v1.json", mode: 0o666, in: product)
    let authority = try FileSystemAuthority(testingRootPath: tree.url.path)

    #expect(throws: InstallError.collision("\(remapProductDirectory)/dns-turned-off-v1.json")) {
        try MacOSResolverRecords.remove(
            from: InstallRelativePath(remapProductDirectory),
            authority: authority,
            ownerUID: UInt32(geteuid())
        )
    }
    #expect(FileManager.default.fileExists(atPath: product.appendingPathComponent("dns-turned-off-v1.json").path))
}
