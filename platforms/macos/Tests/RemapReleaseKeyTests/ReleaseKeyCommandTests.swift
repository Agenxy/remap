// SPDX-License-Identifier: GPL-3.0-or-later
import Darwin
import Foundation
@testable import RemapReleaseKey
import Testing

@Suite("remap-release-key command surface")
struct ReleaseKeyCommandTests {
    @Test("parses exactly the three subcommands")
    func parsesSubcommands() throws {
        #expect(
            try ReleaseKeyCommand.parse(["create", "--key", "/private/key"])
                == .create(key: "/private/key", kind: .release)
        )
        #expect(
            try ReleaseKeyCommand.parse(["public-key", "--key", "/private/key"])
                == .publicKey(key: "/private/key", kind: .release, comment: "remap-release-v2")
        )
        #expect(
            try ReleaseKeyCommand.parse(["public-key", "--comment", "remap-release-v3", "--key", "/private/key"])
                == .publicKey(key: "/private/key", kind: .release, comment: "remap-release-v3")
        )
        #expect(
            try ReleaseKeyCommand.parse(["sign", "--key", "/private/key", "-n", "remap-package-v1"])
                == .sign(key: "/private/key", kind: .release, namespace: "remap-package-v1")
        )
    }

    @Test("a rehearsal key is asked for by name, and its path says so")
    func parsesTheRehearsalKind() throws {
        let path = "/private/keys/remap-rehearsal.enclave-key"
        #expect(
            try ReleaseKeyCommand.parse(["create", "--kind", "rehearsal", "--key", path])
                == .create(key: path, kind: .rehearsal)
        )
        #expect(
            try ReleaseKeyCommand.parse(["public-key", "--kind", "rehearsal", "--key", path])
                == .publicKey(key: path, kind: .rehearsal, comment: "remap-release-rehearsal-only")
        )
        #expect(
            try ReleaseKeyCommand.parse(["sign", "--key", path, "--kind", "rehearsal", "-n", "remap-release"])
                == .sign(key: path, kind: .rehearsal, namespace: "remap-release")
        )
        #expect(
            try ReleaseKeyCommand.parse(["sign", "--kind", "release", "--key", "/private/release.key", "-n", "ns"])
                == .sign(key: "/private/release.key", kind: .release, namespace: "ns")
        )
    }

    @Test("neither kind is created, read, or used at the other kind's path")
    func refusesTheOtherKindsPath() {
        let crossed: [[String]] = [
            ["create", "--kind", "rehearsal", "--key", "/private/keys/remap-release.key"],
            ["create", "--key", "/private/keys/remap-rehearsal.key"],
            ["create", "--kind", "release", "--key", "/private/keys/Remap-Rehearsal.key"],
            ["public-key", "--kind", "rehearsal", "--key", "/private/rehearsal/release.key"],
            ["public-key", "--key", "/private/keys/rehearsal.key"],
            ["sign", "--key", "/private/keys/remap-rehearsal.key", "-n", "remap-release"],
            ["sign", "--kind", "rehearsal", "--key", "/private/keys/release.key", "-n", "remap-release"],
            ["create", "--kind", "development", "--key", "/private/keys/development.key"],
            ["create", "--kind", "", "--key", "/private/keys/release.key"]
        ]
        for arguments in crossed {
            #expect(throws: ReleaseKeyError.self, "\(arguments)") {
                try ReleaseKeyCommand.parse(arguments)
            }
        }
    }

    @Test("only the release key asks for the owner, and each kind names itself")
    func kindsDifferInPresenceAndName() {
        #expect(ReleaseKeyKind.release.accessControlFlags.contains(.userPresence))
        #expect(ReleaseKeyKind.release.accessControlFlags.contains(.privateKeyUsage))
        #expect(!ReleaseKeyKind.rehearsal.accessControlFlags.contains(.userPresence))
        #expect(ReleaseKeyKind.rehearsal.accessControlFlags.contains(.privateKeyUsage))
        #expect(
            ReleaseKeyKind.rehearsal.signingReason(namespace: "remap-package-v1")
                == "sign a Remap rehearsal installer package"
        )
        #expect(ReleaseKeyKind.rehearsal.creationNotice.contains("rehearsal signing key"))
        #expect(ReleaseKeyKind.rehearsal.creationNotice.contains("without Touch ID"))
        #expect(ReleaseKeyKind.release.creationNotice.contains("release signing key"))
        #expect(ReleaseKeyKind.release.defaultComment == "remap-release-v2")
        #expect(ReleaseKeyKind.rehearsal.defaultComment == "remap-release-rehearsal-only")
    }

    @Test("a blob is labelled with its kind, and neither kind loads the other's")
    func blobsAreLabelledByKind() throws {
        let representation = Data([0x30, 0x81, 0x02, 0x03])
        let release = ReleaseKeyBlob.wrap(representation, kind: .release)
        let rehearsal = ReleaseKeyBlob.wrap(representation, kind: .rehearsal)
        // A release blob is the Enclave's representation alone, as ADR-0029 wrote it.
        #expect(release == representation)
        #expect(rehearsal.starts(with: Data("remap-release-rehearsal-key-v1\n".utf8)))
        #expect(try ReleaseKeyBlob.unwrap(release, kind: .release, path: "/k") == representation)
        #expect(try ReleaseKeyBlob.unwrap(rehearsal, kind: .rehearsal, path: "/k") == representation)
        #expect(throws: ReleaseKeyError.self) {
            try ReleaseKeyBlob.unwrap(rehearsal, kind: .release, path: "/k")
        }
        #expect(throws: ReleaseKeyError.self) {
            try ReleaseKeyBlob.unwrap(release, kind: .rehearsal, path: "/k")
        }
    }

    @Test("a key is never read from the other kind's blob")
    func loadingRefusesTheOtherKindsBlob() throws {
        let fixture = try SSHToolFixture()
        defer { fixture.remove() }
        let release = try fixture.write(Data([0x30, 0x81]), named: "remap-release.key")
        #expect(chmod(release.path, 0o600) == 0)
        let rehearsal = try fixture.write(
            ReleaseKeyBlob.wrap(Data([0x30, 0x81]), kind: .rehearsal),
            named: "remap-rehearsal.key"
        )
        #expect(chmod(rehearsal.path, 0o600) == 0)
        #expect(throws: ReleaseKeyError.self) {
            try ReleaseKeyBlob.unwrap(ReleaseKeyFile.read(at: rehearsal.path), kind: .release, path: rehearsal.path)
        }
        #expect(throws: ReleaseKeyError.self) {
            try ReleaseKeyBlob.unwrap(ReleaseKeyFile.read(at: release.path), kind: .rehearsal, path: release.path)
        }
    }

    @Test("refuses malformed invocations before touching a key")
    func refusesMalformedInvocations() {
        let invalid: [[String]] = [
            [],
            ["export", "--key", "/private/key"],
            ["create"],
            ["create", "--key", "relative/key"],
            ["create", "--key", "/private/../key"],
            ["create", "--key", "/private//key"],
            ["create", "--key", "/private/key/"],
            ["create", "--key", "/"],
            ["create", "--key", "/private/key", "--key", "/private/other"],
            ["create", "--key", "/private/key", "--comment", "extra"],
            ["sign", "--key", "/private/key"],
            ["sign", "--key", "/private/key", "-n", ""],
            ["sign", "--key", "/private/key", "-n", "two words"],
            ["sign", "--key", "/private/key", "-n", "line\nbreak"],
            ["sign", "--key", "/private/key", "-n", String(repeating: "a", count: 65)],
            ["public-key", "--key", "/private/key", "--comment"]
        ]
        for arguments in invalid {
            #expect(throws: ReleaseKeyError.self, "\(arguments)") {
                try ReleaseKeyCommand.parse(arguments)
            }
        }
    }

    @Test("create refuses to overwrite and leaves the existing file untouched")
    func createRefusesOverwrite() throws {
        let fixture = try SSHToolFixture()
        defer { fixture.remove() }
        let existing = try fixture.write(Data("earlier key".utf8), named: "release.key")
        #expect(throws: ReleaseKeyError.self) {
            try ReleaseKeyTool.run(.create(key: existing.path, kind: .release))
        }
        #expect(try Data(contentsOf: existing) == Data("earlier key".utf8))
        let rehearsal = try fixture.write(Data("earlier key".utf8), named: "remap-rehearsal.key")
        #expect(throws: ReleaseKeyError
            .keyFile("\(rehearsal.path) already exists; a rehearsal key is never overwritten"))
        {
            try ReleaseKeyTool.run(.create(key: rehearsal.path, kind: .rehearsal))
        }
        #expect(try Data(contentsOf: rehearsal) == Data("earlier key".utf8))
        // An existing file under macOS's /private aliases is still a canonical path.
        #expect(ReleaseKeyCommand.isCanonicalPath("/private/tmp"))
        #expect(ReleaseKeyCommand.isCanonicalPath(existing.path))
    }

    @Test("a key blob must be one small owner-only regular file")
    func keyFileMetadataIsChecked() throws {
        let fixture = try SSHToolFixture()
        defer { fixture.remove() }
        let blob = try fixture.write(Data("blob".utf8), named: "blob")
        #expect(chmod(blob.path, 0o600) == 0)
        #expect(try ReleaseKeyFile.read(at: blob.path) == Data("blob".utf8))

        #expect(chmod(blob.path, 0o644) == 0)
        #expect(throws: ReleaseKeyError.self) { try ReleaseKeyFile.read(at: blob.path) }
        #expect(chmod(blob.path, 0o600) == 0)

        let link = fixture.directory.appendingPathComponent("link")
        #expect(symlink(blob.path, link.path) == 0)
        #expect(throws: ReleaseKeyError.self) { try ReleaseKeyFile.read(at: link.path) }

        let large = try fixture.write(Data(count: ReleaseKeyFile.maximumByteCount + 1), named: "large")
        #expect(chmod(large.path, 0o600) == 0)
        #expect(throws: ReleaseKeyError.self) { try ReleaseKeyFile.read(at: large.path) }
    }

    @Test("the message is bounded and never empty")
    func messageIsBounded() throws {
        func digest(_ bytes: Int, bound: Int) throws {
            let pipe = Pipe()
            try pipe.fileHandleForWriting.write(contentsOf: Data(count: bytes))
            try pipe.fileHandleForWriting.close()
            _ = try SSHSignature.digest(of: pipe.fileHandleForReading, maximumByteCount: bound, chunkByteCount: 3)
        }
        try digest(8, bound: 8)
        #expect(throws: ReleaseKeyError.self) { try digest(9, bound: 8) }
        #expect(throws: ReleaseKeyError.self) { try digest(0, bound: 8) }
    }

    @Test("each signature's prompt says which one the owner is approving")
    func signingReasonsCompleteTheSystemSentence() {
        let namespaces = ["remap-release", "remap-package-v1", "other"]
        let reasons = ReleaseKeyKind.allCases.flatMap { kind in
            namespaces.map { kind.signingReason(namespace: $0) }
        }
        #expect(reasons[0] == "sign the manifest of a Remap release")
        #expect(reasons[1] == "sign a Remap installer package")
        #expect(reasons[3] == "sign the manifest of a Remap rehearsal")
        #expect(Set(reasons).count == reasons.count)
        for reason in reasons {
            #expect(reason.first?.isLowercase == true && !reason.hasSuffix("."))
        }
    }
}
