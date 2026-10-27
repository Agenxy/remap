import Darwin
import Foundation
@testable import RemapReleaseKey
import Testing

@Suite("remap-release-key command surface")
struct ReleaseKeyCommandTests {
    @Test("parses exactly the three subcommands")
    func parsesSubcommands() throws {
        #expect(try ReleaseKeyCommand.parse(["create", "--key", "/private/key"]) == .create(key: "/private/key"))
        #expect(
            try ReleaseKeyCommand.parse(["public-key", "--key", "/private/key"])
                == .publicKey(key: "/private/key", comment: "remap-release-v2")
        )
        #expect(
            try ReleaseKeyCommand.parse(["public-key", "--comment", "remap-release-v3", "--key", "/private/key"])
                == .publicKey(key: "/private/key", comment: "remap-release-v3")
        )
        #expect(
            try ReleaseKeyCommand.parse(["sign", "--key", "/private/key", "-n", "remap-package-v1"])
                == .sign(key: "/private/key", namespace: "remap-package-v1")
        )
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
            try ReleaseKeyTool.run(.create(key: existing.path))
        }
        #expect(try Data(contentsOf: existing) == Data("earlier key".utf8))
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
}
