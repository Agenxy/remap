// SPDX-License-Identifier: GPL-3.0-or-later
import CryptoKit
import Foundation
import LocalAuthentication
import Security

enum ReleaseKeyError: Error, Equatable, LocalizedError {
    case usage(String)
    case unavailable
    case keyFile(String)
    case input(String)
    case enclave(String)

    var errorDescription: String? {
        switch self {
        case let .usage(message):
            message + "\n" + ReleaseKeyCommand.usage
        case .unavailable:
            "this Mac has no Secure Enclave, so it cannot hold a Remap release key"
        case let .keyFile(message), let .input(message), let .enclave(message):
            message
        }
    }
}

enum ReleaseKeyCommand: Equatable {
    case create(key: String)
    case publicKey(key: String, comment: String)
    case sign(key: String, namespace: String)

    static let defaultComment = "remap-release-v2"
    /// The largest package is about 30 MB. This is the same bound the package verifier puts
    /// on a package, so anything the verifier would read can be signed and nothing larger.
    static let maximumMessageByteCount = 268_435_456
    static let usage = """
    usage: remap-release-key create --key <path>
           remap-release-key public-key --key <path> [--comment <comment>]
           remap-release-key sign --key <path> -n <namespace>  < message > signature
    """

    static func parse(_ arguments: [String]) throws -> Self {
        guard let subcommand = arguments.first else {
            throw ReleaseKeyError.usage("a subcommand is required")
        }
        let options = try options(Array(arguments.dropFirst()))
        let allowed: Set<String> = switch subcommand {
        case "create": ["--key"]
        case "public-key": ["--key", "--comment"]
        case "sign": ["--key", "-n"]
        default: throw ReleaseKeyError.usage("unknown subcommand \(subcommand)")
        }
        guard Set(options.keys).isSubset(of: allowed), let key = options["--key"] else {
            throw ReleaseKeyError.usage("\(subcommand) takes exactly \(allowed.sorted().joined(separator: ", "))")
        }
        guard isCanonicalPath(key) else {
            throw ReleaseKeyError.usage("--key must be an absolute, canonical path")
        }
        switch subcommand {
        case "create":
            return .create(key: key)
        case "public-key":
            return try .publicKey(key: key, comment: label(options["--comment"] ?? defaultComment))
        default:
            guard let namespace = options["-n"] else {
                throw ReleaseKeyError.usage("sign requires -n <namespace>")
            }
            return try .sign(key: key, namespace: label(namespace))
        }
    }

    /// Lexical, not filesystem, canonicality: Foundation's `standardizedFileURL` rewrites an
    /// existing `/private/tmp` path to `/tmp`, which would refuse a key it had just created.
    static func isCanonicalPath(_ value: String) -> Bool {
        let components = value.split(separator: "/", omittingEmptySubsequences: false).dropFirst()
        return value.hasPrefix("/")
            && !value.utf8.contains(0)
            && !components.isEmpty
            && components.allSatisfy { !$0.isEmpty && $0 != "." && $0 != ".." }
    }

    private static func options(_ arguments: [String]) throws -> [String: String] {
        guard arguments.count.isMultiple(of: 2) else {
            throw ReleaseKeyError.usage("every option takes one value")
        }
        var values: [String: String] = [:]
        for index in stride(from: 0, to: arguments.count, by: 2) {
            let name = arguments[index]
            guard name.hasPrefix("-"), values.updateValue(arguments[index + 1], forKey: name) == nil else {
                throw ReleaseKeyError.usage("\(name) is not an option, or is given twice")
            }
        }
        return values
    }

    /// Namespaces and comments are short printable labels, so neither can smuggle a newline
    /// into a signature's signed data or into the line a verifier pins.
    private static func label(_ value: String) throws -> String {
        let permitted = value.utf8.allSatisfy { byte in
            (48 ... 57).contains(byte) || (65 ... 90).contains(byte) || (97 ... 122).contains(byte)
                || [UInt8(ascii: "-"), UInt8(ascii: "."), UInt8(ascii: "_"), UInt8(ascii: "@")].contains(byte)
        }
        guard !value.isEmpty, value.utf8.count <= 64, permitted else {
            throw ReleaseKeyError.usage("a namespace or comment is 1 to 64 of [A-Za-z0-9._@-]")
        }
        return value
    }
}

enum ReleaseKeyTool {
    static func run(
        _ command: ReleaseKeyCommand,
        input: FileHandle = .standardInput,
        output: FileHandle = .standardOutput
    ) throws {
        switch command {
        case let .create(path):
            let descriptor = try ReleaseKeyFile.createExclusively(at: path)
            let key: SecureEnclave.P256.Signing.PrivateKey
            do {
                key = try createEnclaveKey()
            } catch {
                ReleaseKeyFile.abandon(descriptor, path: path)
                throw error
            }
            try ReleaseKeyFile.write(key.dataRepresentation, to: descriptor, path: path)
            try emit(SSHSignature.publicKeyLine(key.publicKey, comment: ReleaseKeyCommand.defaultComment), output)
        case let .publicKey(path, comment):
            let key = try loadEnclaveKey(at: path, reason: nil)
            try emit(SSHSignature.publicKeyLine(key.publicKey, comment: comment), output)
        case let .sign(path, namespace):
            let digest = try SSHSignature.digest(
                of: input,
                maximumByteCount: ReleaseKeyCommand.maximumMessageByteCount
            )
            let key = try loadEnclaveKey(at: path, reason: signingReason(namespace))
            let signature = try SSHSignature.sign(messageDigest: digest, namespace: namespace, key: key)
            try output.write(contentsOf: signature)
        }
    }

    /// macOS asks "<program> is trying to <reason>." once per signature, and a
    /// release takes two, so each says which of them the owner is approving.
    static func signingReason(_ namespace: String) -> String {
        switch namespace {
        case "remap-release": "sign the manifest of a Remap release"
        case "remap-package-v1": "sign a Remap installer package"
        default: "sign Remap release data under \(namespace)"
        }
    }

    private static func emit(_ line: String, _ output: FileHandle) throws {
        try output.write(contentsOf: Data((line + "\n").utf8))
    }

    /// Every signature needs the owner present: Touch ID, or the login password.
    private static func createEnclaveKey() throws -> SecureEnclave.P256.Signing.PrivateKey {
        guard SecureEnclave.isAvailable else {
            throw ReleaseKeyError.unavailable
        }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .userPresence],
            &error
        ) else {
            let message = error?.takeRetainedValue().localizedDescription ?? "unknown failure"
            throw ReleaseKeyError.enclave("cannot describe the key's access control: \(message)")
        }
        do {
            return try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        } catch {
            throw ReleaseKeyError.enclave("the Secure Enclave did not create a key: \(error.localizedDescription)")
        }
    }

    private static func loadEnclaveKey(
        at path: String,
        reason: String?
    ) throws -> SecureEnclave.P256.Signing.PrivateKey {
        guard SecureEnclave.isAvailable else {
            throw ReleaseKeyError.unavailable
        }
        let data = try ReleaseKeyFile.read(at: path)
        guard !data.starts(with: Data("-----BEGIN".utf8)), !data.starts(with: Data("openssh-key-v1".utf8)) else {
            throw ReleaseKeyError.keyFile("\(path) is an exportable private key, not a Secure Enclave key")
        }
        let context = LAContext()
        if let reason {
            context.localizedReason = reason
        }
        do {
            return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: data, authenticationContext: context)
        } catch {
            throw ReleaseKeyError.enclave(
                "\(path) is not a key this Mac's Secure Enclave holds: \(error.localizedDescription)"
            )
        }
    }
}
