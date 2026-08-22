import Darwin
import Foundation
@testable import RemapInstallKit
import Testing

@Test
func digestIsCanonicalLowercaseSha256() throws {
    let digest = InstallDigest.hash(Data("remap".utf8))
    #expect(digest.value.count == 64)
    #expect(digest.value == digest.value.lowercased())
    #expect(throws: InstallError.self) {
        try InstallDigest(digest.value.uppercased())
    }
}

@Test
func regularPublicationCanonicalShapeOmitsSymlinkFields() throws {
    let digest = InstallDigest.hash(Data("plist".utf8))
    let publication = try InstallPublication(
        path: InstallRelativePath("Library/LaunchDaemons/org.agenxy.Remap.daemon.plist"),
        source: InstallRelativePath(
            "Library/Application Support/Agenxy/Remap/Install/Generations/generation-1/launchd/daemon.plist"
        ),
        sha256: digest,
        byteCount: 5,
        generationID: "generation-1"
    )
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    let data = try encoder.encode(publication)
    let object = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
    #expect(object["path"] as? String == "Library/LaunchDaemons/org.agenxy.Remap.daemon.plist")
    #expect(object["source"] is String)
    #expect(object["byteCount"] as? Int == 5)
    #expect(object["target"] == nil)
    #expect(try JSONDecoder().decode(InstallPublication.self, from: data) == publication)
}

@Test
func directoryPublicationCanonicalShapeContainsOnlyOwnershipIdentity() throws {
    let publication = try InstallPublication(
        path: InstallRelativePath("usr/local/share/man"),
        generationID: "generation-1"
    )
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    let data = try encoder.encode(publication)
    let object = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])

    #expect(object["kind"] as? String == "directory")
    #expect(object["mode"] as? Int == 0o755)
    #expect(object["ownerUID"] as? Int == 0)
    #expect(object["groupGID"] as? Int == 0)
    #expect(object["source"] == nil)
    #expect(object["target"] == nil)
    #expect(object["sha256"] == nil)
    #expect(object["byteCount"] == nil)
    #expect(try JSONDecoder().decode(InstallPublication.self, from: data) == publication)
}

@Test
func manifestCanonicalizationIgnoresCallerOrdering() throws {
    let firstData = Data("first".utf8)
    let secondData = Data("second".utf8)
    let firstEntry = try testEntry(path: "a", data: firstData)
    let secondEntry = try testEntry(path: "b", data: secondData)
    let forward = try testManifest(entries: [firstEntry, secondEntry])
    let reverse = try testManifest(entries: [secondEntry, firstEntry])
    #expect(try forward.canonicalData() == reverse.canonicalData())
    #expect(try forward.digest() == reverse.digest())
}

@Test
func manifestRejectsTraversalDuplicatePathsAndWritableEntries() throws {
    #expect(throws: InstallError.self) {
        try InstallRelativePath("../escape")
    }
    let data = Data("duplicate".utf8)
    let entry = try testEntry(path: "tool", data: data)
    #expect(throws: InstallError.self) {
        try testManifest(entries: [entry, entry])
    }
    #expect(throws: InstallError.self) {
        try InstallEntry(
            path: InstallRelativePath("writable"),
            kind: .regularFile,
            role: .support,
            sha256: InstallDigest.hash(data),
            byteCount: UInt64(data.count),
            ownerUID: UInt32(geteuid()),
            groupGID: UInt32(getegid()),
            mode: 0o755
        )
    }
}
