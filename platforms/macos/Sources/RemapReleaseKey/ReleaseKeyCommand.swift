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
            "this Mac has no Secure Enclave, so it cannot hold a Remap release or rehearsal key"
        case let .keyFile(message), let .input(message), let .enclave(message):
            message
        }
    }
}

enum ReleaseKeyCommand: Equatable {
    case create(key: String, kind: ReleaseKeyKind)
    case publicKey(key: String, kind: ReleaseKeyKind, comment: String)
    case sign(key: String, kind: ReleaseKeyKind, namespace: String)

    /// The largest package is about 30 MB. This is the same bound the package verifier puts
    /// on a package, so anything the verifier would read can be signed and nothing larger.
    static let maximumMessageByteCount = 268_435_456
    static let usage = """
    usage: remap-release-key create [--kind release|rehearsal] --key <path>
           remap-release-key public-key [--kind release|rehearsal] --key <path> [--comment <comment>]
           remap-release-key sign [--kind release|rehearsal] --key <path> -n <namespace>  < message > signature

    The kind is release unless --kind says otherwise. A rehearsal key's file name contains
    "rehearsal", and a release key's never does.
    """

    static func parse(_ arguments: [String]) throws -> Self {
        guard let subcommand = arguments.first else {
            throw ReleaseKeyError.usage("a subcommand is required")
        }
        let options = try options(Array(arguments.dropFirst()))
        let allowed: Set<String> = switch subcommand {
        case "create": ["--key", "--kind"]
        case "public-key": ["--key", "--kind", "--comment"]
        case "sign": ["--key", "--kind", "-n"]
        default: throw ReleaseKeyError.usage("unknown subcommand \(subcommand)")
        }
        guard Set(options.keys).isSubset(of: allowed), let key = options["--key"] else {
            throw ReleaseKeyError.usage("\(subcommand) takes exactly \(allowed.sorted().joined(separator: ", "))")
        }
        guard isCanonicalPath(key) else {
            throw ReleaseKeyError.usage("--key must be an absolute, canonical path")
        }
        let kind = try kind(options["--kind"], key: key)
        switch subcommand {
        case "create":
            return .create(key: key, kind: kind)
        case "public-key":
            return try .publicKey(key: key, kind: kind, comment: label(options["--comment"] ?? kind.defaultComment))
        default:
            guard let namespace = options["-n"] else {
                throw ReleaseKeyError.usage("sign requires -n <namespace>")
            }
            return try .sign(key: key, kind: kind, namespace: label(namespace))
        }
    }

    /// The kind, which must agree with the blob's file name, so a release key is never created,
    /// read, or used where a rehearsal key's path was given, nor the reverse.
    private static func kind(_ value: String?, key: String) throws -> ReleaseKeyKind {
        guard let kind = ReleaseKeyKind(rawValue: value ?? ReleaseKeyKind.release.rawValue) else {
            throw ReleaseKeyError.usage("--kind is release or rehearsal")
        }
        guard kind.admits(path: key) else {
            throw ReleaseKeyError.usage(
                kind == .rehearsal
                    ? "\(key) is not a rehearsal key's path; its file name must contain \"rehearsal\""
                    : "\(key) is a rehearsal key's path; pass --kind rehearsal, or name the release key's blob"
            )
        }
        return kind
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
        output: FileHandle = .standardOutput,
        diagnostics: FileHandle = .standardError
    ) throws {
        switch command {
        case let .create(path, kind):
            let descriptor = try ReleaseKeyFile.createExclusively(at: path, kind: kind)
            let key: SecureEnclave.P256.Signing.PrivateKey
            do {
                key = try createEnclaveKey(kind: kind)
            } catch {
                ReleaseKeyFile.abandon(descriptor, path: path)
                throw error
            }
            try ReleaseKeyFile.write(
                ReleaseKeyBlob.wrap(key.dataRepresentation, kind: kind),
                to: descriptor,
                path: path
            )
            try emit(SSHSignature.publicKeyLine(key.publicKey, comment: kind.defaultComment), output)
            try emit("remap-release-key: \(kind.creationNotice); its blob is \(path)", diagnostics)
        case let .publicKey(path, kind, comment):
            let key = try loadEnclaveKey(at: path, kind: kind, reason: nil)
            try emit(SSHSignature.publicKeyLine(key.publicKey, comment: comment), output)
        case let .sign(path, kind, namespace):
            let digest = try SSHSignature.digest(
                of: input,
                maximumByteCount: ReleaseKeyCommand.maximumMessageByteCount
            )
            let key = try loadEnclaveKey(at: path, kind: kind, reason: kind.signingReason(namespace: namespace))
            let signature = try SSHSignature.sign(messageDigest: digest, namespace: namespace, key: key)
            try output.write(contentsOf: signature)
        }
    }

    private static func emit(_ line: String, _ output: FileHandle) throws {
        try output.write(contentsOf: Data((line + "\n").utf8))
    }

    /// A release key needs the owner present for every signature: Touch ID, or the login
    /// password. A rehearsal key does not, so a rehearsal builds without a person. Neither can
    /// leave the Enclave, and both are bound to this Mac while it is unlocked.
    private static func createEnclaveKey(kind: ReleaseKeyKind) throws -> SecureEnclave.P256.Signing.PrivateKey {
        guard SecureEnclave.isAvailable else {
            throw ReleaseKeyError.unavailable
        }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kind.accessControlFlags,
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
        kind: ReleaseKeyKind,
        reason: String?
    ) throws -> SecureEnclave.P256.Signing.PrivateKey {
        guard SecureEnclave.isAvailable else {
            throw ReleaseKeyError.unavailable
        }
        let data = try ReleaseKeyBlob.unwrap(ReleaseKeyFile.read(at: path), kind: kind, path: path)
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
