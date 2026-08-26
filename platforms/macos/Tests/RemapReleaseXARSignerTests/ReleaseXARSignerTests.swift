import Foundation
@testable import RemapReleaseXARSigner
import Testing

@Suite("Release XAR signer")
struct ReleaseXARSignerTests {
    @Test("accepts only canonical certificate digests")
    func validatesDigest() {
        #expect(ReleaseXARSigner.isCanonicalDigest(String(repeating: "A", count: 64)))
        #expect(ReleaseXARSigner.isCanonicalDigest(String(repeating: "9", count: 64)))
        #expect(!ReleaseXARSigner.isCanonicalDigest(String(repeating: "a", count: 64)))
        #expect(!ReleaseXARSigner.isCanonicalDigest(String(repeating: "A", count: 63)))
        #expect(!ReleaseXARSigner.isCanonicalDigest(String(repeating: "G", count: 64)))
        #expect(!ReleaseXARSigner.isCanonicalDigest(String(repeating: "９", count: 64)))
        #expect(
            ReleaseXARSigner.isCanonicalKeychainPath(
                "/Users/example/Library/Keychains/login.keychain-db"
            )
        )
        #expect(!ReleaseXARSigner.isCanonicalKeychainPath("login.keychain-db"))
        #expect(!ReleaseXARSigner.isCanonicalKeychainPath("/tmp/../login.keychain-db"))
    }

    @Test("rejects invalid arguments before keychain access")
    func rejectsArguments() throws {
        let input = Pipe()
        let output = Pipe()
        try input.fileHandleForWriting.write(contentsOf: Data("table".utf8))
        try input.fileHandleForWriting.close()

        #expect(throws: ReleaseXARSigningError.self) {
            try ReleaseXARSigner.run(
                arguments: [],
                input: input.fileHandleForReading,
                output: output.fileHandleForWriting
            )
        }
    }
}
