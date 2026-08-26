import CryptoKit
import Darwin
import Foundation
import Security

enum ReleaseXARSigningError: Error, LocalizedError {
    case input
    case identity
    case key(OSStatus)
    case signature(String)

    var errorDescription: String? {
        switch self {
        case .input:
            "expected one 64-character uppercase certificate SHA-256 digest and bounded stdin"
        case .identity:
            "expected exactly one matching login-keychain signing identity"
        case let .key(status):
            "could not access the release signing key (OSStatus \(status))"
        case let .signature(message):
            "could not sign the canonical XAR table: \(message)"
        }
    }
}

enum ReleaseXARSigner {
    static let maximumInputBytes = 16_777_216
    private static let maximumIdentities = 64

    static func run(
        arguments: [String],
        input: FileHandle = .standardInput,
        output: FileHandle = .standardOutput
    ) throws {
        guard arguments.count == 2,
              isCanonicalDigest(arguments[0]),
              isCanonicalKeychainPath(arguments[1])
        else {
            throw ReleaseXARSigningError.input
        }
        let message = try boundedInput(input)
        let signature = try sign(
            message,
            certificateSHA256: arguments[0],
            keychainPath: arguments[1]
        )
        try output.write(contentsOf: signature)
    }

    static func isCanonicalDigest(_ value: String) -> Bool {
        value.utf8.count == 64 && value.utf8.allSatisfy { byte in
            (48 ... 57).contains(byte) || (65 ... 70).contains(byte)
        }
    }

    static func isCanonicalKeychainPath(_ value: String) -> Bool {
        value.hasPrefix("/")
            && URL(fileURLWithPath: value).standardizedFileURL.path == value
            && value.hasSuffix(".keychain-db")
    }

    private static func boundedInput(_ input: FileHandle) throws -> Data {
        let message = try input.read(upToCount: maximumInputBytes + 1) ?? Data()
        guard !message.isEmpty, message.count <= maximumInputBytes else {
            throw ReleaseXARSigningError.input
        }
        return message
    }

    private static func sign(
        _ message: Data,
        certificateSHA256: String,
        keychainPath: String
    ) throws -> Data {
        let matching = try identities(keychainPath: keychainPath).filter {
            try digest($0) == certificateSHA256
        }
        guard matching.count == 1 else {
            throw ReleaseXARSigningError.identity
        }
        var key: SecKey?
        let status = SecIdentityCopyPrivateKey(matching[0], &key)
        guard status == errSecSuccess, let key else {
            throw ReleaseXARSigningError.key(status)
        }
        guard SecKeyGetBlockSize(key) == 384 else {
            throw ReleaseXARSigningError.identity
        }
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            key,
            .rsaSignatureMessagePKCS1v15SHA1,
            message as CFData,
            &error
        ) as Data? else {
            let message = error?.takeRetainedValue().localizedDescription ?? "unknown failure"
            throw ReleaseXARSigningError.signature(message)
        }
        guard signature.count == SecKeyGetBlockSize(key) else {
            throw ReleaseXARSigningError.signature("unexpected RSA signature size")
        }
        return signature
    }

    private static func identities(keychainPath: String) throws -> [SecIdentity] {
        var keychain: SecKeychain?
        let openStatus = keychainPath.withCString {
            remapReleaseSecKeychainOpen($0, &keychain)
        }
        guard openStatus == errSecSuccess, let keychain else {
            throw ReleaseXARSigningError.key(openStatus)
        }
        let query: [CFString: Any] = [
            kSecClass: kSecClassIdentity,
            kSecMatchLimit: kSecMatchLimitAll,
            kSecMatchSearchList: [keychain],
            kSecReturnRef: true,
            kSecUseDataProtectionKeychain: false
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return []
        }
        guard status == errSecSuccess,
              let identities = result as? [SecIdentity],
              identities.count <= maximumIdentities
        else {
            throw ReleaseXARSigningError.key(status)
        }
        return identities
    }

    private static func digest(_ identity: SecIdentity) throws -> String {
        var certificate: SecCertificate?
        let status = SecIdentityCopyCertificate(identity, &certificate)
        guard status == errSecSuccess, let certificate else {
            throw ReleaseXARSigningError.key(status)
        }
        return SHA256.hash(data: SecCertificateCopyData(certificate) as Data)
            .map { String(format: "%02X", $0) }
            .joined()
    }
}

@_silgen_name("SecKeychainOpen")
private func remapReleaseSecKeychainOpen(
    _ pathName: UnsafePointer<CChar>,
    _ keychain: UnsafeMutablePointer<SecKeychain?>
) -> OSStatus

do {
    try ReleaseXARSigner.run(arguments: Array(CommandLine.arguments.dropFirst()))
} catch {
    let message = "remap-release-xar-signer: \(error.localizedDescription)\n"
    try? FileHandle.standardError.write(contentsOf: Data(message.utf8))
    exit(2)
}
