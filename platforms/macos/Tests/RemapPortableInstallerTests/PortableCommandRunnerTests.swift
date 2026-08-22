import Darwin
import Foundation
import RemapInstallKit
@testable import RemapPortableInstaller
import Testing

@Test
func commandRunnerRejectsRelativeExecutables() throws {
    #expect(throws: Error.self) {
        _ = try PortableCommandRunner().run(
            executable: "security",
            arguments: ["help"]
        )
    }
}

@Test
func commandRunnerCapturesBoundedAppleToolOutput() throws {
    let result = try PortableCommandRunner().run(
        executable: "/usr/bin/printf",
        arguments: ["%s", "plain-output"]
    )
    #expect(result.exitStatus == 0)
    #expect(result.output == Data("plain-output".utf8))
}

@Test
func commandRunnerKillsDescendantsThatKeepOutputOpen() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(
        "remap-runner-descendant-\(UUID().uuidString.lowercased())",
        isDirectory: true
    )
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
    defer { try? FileManager.default.removeItem(at: directory) }
    let processIDPath = directory.appendingPathComponent("pid").path
    let started = ContinuousClock.now
    #expect(throws: InstallError.self) {
        _ = try PortableCommandRunner().run(
            executable: "/bin/sh",
            arguments: ["-c", "sleep 30 & echo $! > \(processIDPath)"],
            timeoutSeconds: 1
        )
    }
    #expect(started.duration(to: .now) < .seconds(3))
    let value = try String(contentsOfFile: processIDPath, encoding: .utf8)
        .trimmingCharacters(in: .whitespacesAndNewlines)
    let processID = try #require(pid_t(value))
    let deadline = ContinuousClock.now + .seconds(1)
    while kill(processID, 0) == 0, ContinuousClock.now < deadline {
        usleep(10000)
    }
    #expect(kill(processID, 0) == -1)
    #expect(errno == ESRCH)
}

@Test
func commandRunnerStopsUnboundedOutput() throws {
    let started = ContinuousClock.now
    #expect(throws: InstallError.self) {
        _ = try PortableCommandRunner().run(
            executable: "/usr/bin/yes",
            arguments: [],
            timeoutSeconds: 5
        )
    }
    #expect(started.duration(to: .now) < .seconds(3))
}

@Test
func signingIdentityParsersRequireOneExactFingerprint() throws {
    let identities = try PortableCodeSigningIdentityStore.identityFingerprints(
        "  1) AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA \"Remap Local Codesign\"\n"
            + "     1 valid identities found\n"
    )
    #expect(identities == [String(repeating: "a", count: 40)])
    let certificates = try PortableCodeSigningIdentityStore.certificateFingerprints(
        "SHA-1 hash: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
            + "SHA-256 hash: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n"
    )
    #expect(certificates.count == 1)
    #expect(certificates[0].sha1 == String(repeating: "a", count: 40))
    #expect(certificates[0].sha256 == String(repeating: "b", count: 64))
}

@Test
func portableReleaseManifestHasOneCanonicalEncoding() throws {
    let entries = try [
        PortableReleaseEntry(
            path: InstallRelativePath("product"),
            kind: .directory,
            sha256: nil,
            byteCount: nil,
            mode: 0o700
        ),
        PortableReleaseEntry(
            path: InstallRelativePath("product/bin/remap"),
            kind: .regularFile,
            sha256: InstallDigest(String(repeating: "a", count: 64)),
            byteCount: 7,
            mode: 0o500
        )
    ]
    let manifest = try PortableReleaseManifest(
        productVersion: "0.2.0",
        architecture: "arm64",
        minimumMacOSVersion: "15.0",
        entries: entries
    )
    let data = try manifest.canonicalData()
    #expect(try PortableReleaseManifest.decodeCanonical(data) == manifest)
    var nonCanonical = data
    nonCanonical.append(0x0A)
    #expect(throws: Error.self) {
        _ = try PortableReleaseManifest.decodeCanonical(nonCanonical)
    }
}
