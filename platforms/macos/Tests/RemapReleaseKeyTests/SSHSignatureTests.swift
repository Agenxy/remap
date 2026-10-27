import CryptoKit
import Foundation
@testable import RemapReleaseKey
import Testing

@Suite("SSHSIG encoder for a P-256 release key")
struct SSHSignatureTests {
    private static let namespace = "remap-package-v1"

    private static func sign(_ message: Data, namespace: String, key: some ReleaseSigningKey) throws -> Data {
        try SSHSignature.sign(messageDigest: SHA512.hash(data: message), namespace: namespace, key: key)
    }

    @Test("ssh-keygen accepts the signature, and only for its namespace and message")
    func sshKeygenVerifies() throws {
        let fixture = try SSHToolFixture()
        defer { fixture.remove() }
        let key = P256.Signing.PrivateKey()
        let line = SSHSignature.publicKeyLine(key.publicKey, comment: "remap-release-v2")
        let message = Data("exact package bytes".utf8)
        let signature = try Self.sign(message, namespace: Self.namespace, key: key)

        #expect(try fixture.verifies(
            signature: signature,
            message: message,
            namespace: Self.namespace,
            publicKeyLine: line
        ))
        #expect(try !fixture.verifies(
            signature: signature,
            message: message,
            namespace: "remap-release",
            publicKeyLine: line
        ))
        #expect(try !fixture.verifies(
            signature: signature,
            message: Data("changed package bytes".utf8),
            namespace: Self.namespace,
            publicKeyLine: line
        ))
        let stranger = SSHSignature.publicKeyLine(P256.Signing.PrivateKey().publicKey, comment: "other")
        #expect(try !fixture.verifies(
            signature: signature,
            message: message,
            namespace: Self.namespace,
            publicKeyLine: stranger
        ))
    }

    @Test("the armour is byte-identical to ssh-keygen's for the same key and signature")
    func armourMatchesSSHKeygen() throws {
        let fixture = try SSHToolFixture()
        defer { fixture.remove() }
        let keyPath = fixture.directory.appendingPathComponent("ecdsa").path
        try fixture.sshKeygen(["-q", "-t", "ecdsa", "-b", "256", "-N", "", "-C", "remap-release-v2", "-f", keyPath])
        // Long enough that the armour wraps over several 70-column lines.
        let message = try fixture.write(Data(repeating: 0x5A, count: 4099), named: "message")
        let produced = try fixture.sshKeygen(["-Y", "sign", "-f", keyPath, "-n", Self.namespace], input: message)
        #expect(produced.status == 0)

        var outer = try SSHReader(armoredBlob(produced.output))
        #expect(try outer.bytes(6) == SSHSignature.magic)
        #expect(try outer.uint32() == SSHSignature.version)
        var publicBlob = try SSHReader(outer.string())
        #expect(try publicBlob.string() == Data(SSHSignature.keyType.utf8))
        #expect(try publicBlob.string() == Data(SSHSignature.curveName.utf8))
        let publicKey = try P256.Signing.PublicKey(x963Representation: publicBlob.string())
        #expect(try outer.string() == Data(Self.namespace.utf8))
        #expect(try outer.string().isEmpty)
        #expect(try outer.string() == Data(SSHSignature.hashAlgorithm.utf8))
        var signatureBlob = try SSHReader(outer.string())
        #expect(try signatureBlob.string() == Data(SSHSignature.keyType.utf8))
        var scalars = try SSHReader(signatureBlob.string())
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: scalars.scalar() + scalars.scalar())
        #expect(outer.isEmpty && signatureBlob.isEmpty && scalars.isEmpty)

        let encoded = SSHSignature.armor(publicKey: publicKey, namespace: Self.namespace, signature: signature)
        #expect(encoded == produced.output)
        let digest = try SHA512.hash(data: Data(contentsOf: message))
        #expect(publicKey.isValidSignature(
            signature,
            for: SSHSignature.signedData(namespace: Self.namespace, messageDigest: digest)
        ))
        let publicLine = try String(contentsOfFile: keyPath + ".pub", encoding: .utf8)
        #expect(SSHSignature.publicKeyLine(publicKey, comment: "remap-release-v2") + "\n" == publicLine)
    }

    @Test("the OpenSSH public key round-trips through ssh-keygen")
    func publicKeyRoundTrips() throws {
        let fixture = try SSHToolFixture()
        defer { fixture.remove() }
        let key = P256.Signing.PrivateKey().publicKey
        let line = SSHSignature.publicKeyLine(key, comment: "remap-release-v2")
        let file = try fixture.write(Data((line + "\n").utf8), named: "release.pub")

        let fingerprint = try fixture.sshKeygen(["-l", "-E", "sha256", "-f", file.path])
        let expected = "SHA256:" + Data(SHA256.hash(data: SSHSignature.publicKeyBlob(key)))
            .base64EncodedString()
            .replacingOccurrences(of: "=", with: "")
        #expect(fingerprint.status == 0)
        #expect(String(decoding: fingerprint.output, as: UTF8.self) == "256 \(expected) remap-release-v2 (ECDSA)\n")

        let exported = try fixture.sshKeygen(["-e", "-m", "PKCS8", "-f", file.path])
        #expect(exported.status == 0)
        let decoded = try P256.Signing.PublicKey(pemRepresentation: String(decoding: exported.output, as: UTF8.self))
        #expect(decoded.x963Representation == key.x963Representation)
    }

    @Test("an mpint is minimal and never negative")
    func mpintEncoding() {
        #expect(SSHWire.mpint(Data()) == Data([0, 0, 0, 0]))
        #expect(SSHWire.mpint(Data([0, 0, 0x7F])) == Data([0, 0, 0, 1, 0x7F]))
        #expect(SSHWire.mpint(Data([0x80, 1])) == Data([0, 0, 0, 3, 0, 0x80, 1]))
    }
}
