import CryptoKit
import Foundation

/// A P-256 signing key whose private half the encoder never sees.
///
/// The release key is a Secure Enclave key, which hosted CI does not have, so the encoder is
/// written against this protocol and tested with a software key of the same curve.
protocol ReleaseSigningKey {
    var publicKey: P256.Signing.PublicKey { get }
    func signature(for data: some DataProtocol) throws -> P256.Signing.ECDSASignature
}

extension P256.Signing.PrivateKey: ReleaseSigningKey {}
extension SecureEnclave.P256.Signing.PrivateKey: ReleaseSigningKey {}

/// The SSH wire primitives that RFC 4251 and OpenSSH's PROTOCOL.sshsig use.
enum SSHWire {
    static func uint32(_ value: UInt32) -> Data {
        Data([
            UInt8(truncatingIfNeeded: value >> 24),
            UInt8(truncatingIfNeeded: value >> 16),
            UInt8(truncatingIfNeeded: value >> 8),
            UInt8(truncatingIfNeeded: value)
        ])
    }

    static func string(_ bytes: Data) -> Data {
        uint32(UInt32(bytes.count)) + bytes
    }

    static func string(_ text: String) -> Data {
        string(Data(text.utf8))
    }

    /// A non-negative integer from its unsigned big-endian magnitude, in the minimal
    /// two's-complement form an `mpint` requires.
    static func mpint(_ magnitude: Data) -> Data {
        var value = Data(magnitude.drop { $0 == 0 })
        if let first = value.first, first & 0x80 != 0 {
            value.insert(0, at: 0)
        }
        return string(value)
    }
}

/// OpenSSH's SSHSIG format for one `ecdsa-sha2-nistp256` key, byte-compatible with
/// `ssh-keygen -Y sign` so that every existing `ssh-keygen -Y verify` keeps working.
enum SSHSignature {
    static let keyType = "ecdsa-sha2-nistp256"
    static let curveName = "nistp256"
    static let hashAlgorithm = "sha512"
    static let magic = Data("SSHSIG".utf8)
    static let version: UInt32 = 1
    static let lineLength = 70
    static let beginLine = "-----BEGIN SSH SIGNATURE-----"
    static let endLine = "-----END SSH SIGNATURE-----"

    static func publicKeyBlob(_ key: P256.Signing.PublicKey) -> Data {
        SSHWire.string(keyType) + SSHWire.string(curveName) + SSHWire.string(key.x963Representation)
    }

    static func publicKeyLine(_ key: P256.Signing.PublicKey, comment: String) -> String {
        keyType + " " + publicKeyBlob(key).base64EncodedString() + " " + comment
    }

    /// The exact bytes the key signs: never the message itself, always its SHA-512 digest
    /// bound to the namespace, so a signature cannot be replayed under another purpose.
    static func signedData(namespace: String, messageDigest: SHA512Digest) -> Data {
        magic
            + SSHWire.string(namespace)
            + SSHWire.string(Data())
            + SSHWire.string(hashAlgorithm)
            + SSHWire.string(Data(messageDigest))
    }

    static func sign(
        messageDigest: SHA512Digest,
        namespace: String,
        key: some ReleaseSigningKey
    ) throws -> Data {
        let signature = try key.signature(
            for: signedData(namespace: namespace, messageDigest: messageDigest)
        )
        return armor(publicKey: key.publicKey, namespace: namespace, signature: signature)
    }

    static func armor(
        publicKey: P256.Signing.PublicKey,
        namespace: String,
        signature: P256.Signing.ECDSASignature
    ) -> Data {
        let raw = signature.rawRepresentation
        let half = raw.count / 2
        let ecdsa = SSHWire.mpint(raw.prefix(half)) + SSHWire.mpint(raw.suffix(half))
        let blob = magic
            + SSHWire.uint32(version)
            + SSHWire.string(publicKeyBlob(publicKey))
            + SSHWire.string(namespace)
            + SSHWire.string(Data())
            + SSHWire.string(hashAlgorithm)
            + SSHWire.string(SSHWire.string(keyType) + SSHWire.string(ecdsa))
        let encoded = Array(blob.base64EncodedString())
        let lines = stride(from: 0, to: encoded.count, by: lineLength).map {
            String(encoded[$0 ..< min($0 + lineLength, encoded.count)])
        }
        let text = ([beginLine] + lines + [endLine]).joined(separator: "\n") + "\n"
        return Data(text.utf8)
    }

    /// Streams at most `maximumByteCount` bytes into SHA-512 without holding the message.
    static func digest(
        of input: FileHandle,
        maximumByteCount: Int,
        chunkByteCount: Int = 1_048_576
    ) throws -> SHA512Digest {
        var hasher = SHA512()
        var total = 0
        while let chunk = try input.read(upToCount: chunkByteCount), !chunk.isEmpty {
            total += chunk.count
            guard total <= maximumByteCount else {
                throw ReleaseKeyError.input("the message exceeds \(maximumByteCount) bytes")
            }
            hasher.update(data: chunk)
        }
        guard total > 0 else {
            throw ReleaseKeyError.input("the message on standard input is empty")
        }
        return hasher.finalize()
    }
}
