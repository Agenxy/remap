import Darwin
import Foundation
import RemapInstallKit
import Security

struct PortableCodeSigningIdentity: Equatable, Sendable {
    static let name = "Remap Local Codesign"
    static let systemKeychain = "/Library/Keychains/System.keychain"

    let sha1: String
    let sha256: InstallDigest
}

struct PortableCodeSigningIdentityStore: Sendable {
    private static let certificateLifetimeDays = 3650
    private let runner: PortableCommandRunner

    init(runner: PortableCommandRunner = PortableCommandRunner()) {
        self.runner = runner
    }

    func ensure() throws -> PortableCodeSigningIdentity {
        guard geteuid() == 0 else {
            throw InstallError.notRoot
        }
        if let identity = try resolve() {
            return identity
        }
        guard try certificateFingerprints().isEmpty else {
            throw InstallError.integrity(
                "Remap's local signing certificate exists without its private key"
            )
        }
        try create()
        guard let created = try resolve() else {
            throw InstallError.integrity("macOS did not make Remap's local signing key usable")
        }
        return created
    }

    func resolve() throws -> PortableCodeSigningIdentity? {
        let result = try runner.run(
            executable: "/usr/bin/security",
            arguments: [
                "find-identity",
                "-v",
                "-p",
                "codesigning",
                PortableCodeSigningIdentity.systemKeychain
            ]
        )
        guard result.exitStatus == 0 else {
            throw InstallError.operatingSystem("inspect Remap's local signing key", result.exitStatus)
        }
        let identities = try Self.identityFingerprints(
            result.utf8Output(named: "local signing-key inspection")
        )
        let certificates = try certificateFingerprints()
        guard identities.count <= 1, certificates.count <= 1 else {
            throw InstallError.integrity("multiple system signing keys are named Remap Local Codesign")
        }
        guard let identity = identities.first else {
            return nil
        }
        guard let certificate = certificates.first, identity == certificate.sha1 else {
            throw InstallError.integrity("Remap's local signing key and certificate do not match")
        }
        return try PortableCodeSigningIdentity(
            sha1: Self.canonicalFingerprint(identity, byteCount: 20),
            sha256: InstallDigest(Self.canonicalFingerprint(certificate.sha256, byteCount: 32))
        )
    }

    static func identityFingerprints(_ output: String) throws -> [String] {
        try output.split(separator: "\n").compactMap { line in
            let value = line.trimmingCharacters(in: .whitespaces)
            guard value.hasSuffix("\"\(PortableCodeSigningIdentity.name)\"") else {
                return nil
            }
            let words = value.split(whereSeparator: \ .isWhitespace)
            guard words.count >= 3 else {
                throw InstallError.integrity("macOS returned a malformed local signing identity")
            }
            return try canonicalFingerprint(String(words[1]), byteCount: 20)
        }
    }

    static func certificateFingerprints(_ output: String) throws -> [(sha1: String, sha256: String)] {
        let sha1Prefix = "SHA-1 hash: "
        let sha256Prefix = "SHA-256 hash: "
        let sha1Values = try output.split(separator: "\n").compactMap { line -> String? in
            let value = line.trimmingCharacters(in: .whitespaces)
            guard value.hasPrefix(sha1Prefix) else { return nil }
            return try canonicalFingerprint(String(value.dropFirst(sha1Prefix.count)), byteCount: 20)
        }
        let sha256Values = try output.split(separator: "\n").compactMap { line -> String? in
            let value = line.trimmingCharacters(in: .whitespaces)
            guard value.hasPrefix(sha256Prefix) else { return nil }
            return try canonicalFingerprint(String(value.dropFirst(sha256Prefix.count)), byteCount: 32)
        }
        guard sha1Values.count == sha256Values.count else {
            throw InstallError.integrity("macOS returned incomplete local signing fingerprints")
        }
        return Array(zip(sha1Values, sha256Values))
    }

    private func certificateFingerprints() throws -> [(sha1: String, sha256: String)] {
        let result = try runner.run(
            executable: "/usr/bin/security",
            arguments: [
                "find-certificate",
                "-a",
                "-Z",
                "-c",
                PortableCodeSigningIdentity.name,
                PortableCodeSigningIdentity.systemKeychain
            ]
        )
        guard result.exitStatus == 0 || result.exitStatus == 44 else {
            throw InstallError.operatingSystem(
                "inspect Remap's local signing certificate",
                result.exitStatus
            )
        }
        return try Self.certificateFingerprints(
            result.utf8Output(named: "local signing-certificate inspection")
        )
    }

    private func create() throws {
        let workspace = try PortablePrivateWorkspace.create(prefix: "remap-signing-identity")
        defer { workspace.remove() }
        let configuration = workspace.url.appendingPathComponent("codesign.cnf")
        let privateKey = workspace.url.appendingPathComponent("codesign.key.pem")
        let certificate = workspace.url.appendingPathComponent("codesign.cert.pem")
        let archive = workspace.url.appendingPathComponent("codesign.p12")
        let password = try Self.randomHex(byteCount: 32)
        try Data(Self.opensslConfiguration.utf8).write(
            to: configuration,
            options: [.withoutOverwriting]
        )
        try Self.requirePrivateFile(configuration.path, mode: 0o600, setMode: true)
        try requireSuccess(
            executable: "/usr/bin/openssl",
            arguments: [
                "req", "-x509", "-newkey", "rsa:3072", "-nodes",
                "-days", String(Self.certificateLifetimeDays),
                "-config", configuration.path,
                "-keyout", privateKey.path,
                "-out", certificate.path
            ],
            operation: "create Remap's local signing certificate"
        )
        try Self.requirePrivateFile(privateKey.path, mode: 0o600, setMode: true)
        try Self.requirePrivateFile(certificate.path, mode: 0o600, setMode: true)
        try requireSuccess(
            executable: "/usr/bin/openssl",
            arguments: [
                "pkcs12", "-export", "-descert",
                "-name", PortableCodeSigningIdentity.name,
                "-inkey", privateKey.path,
                "-in", certificate.path,
                "-out", archive.path,
                "-passout", "pass:\(password)"
            ],
            operation: "package Remap's local signing key"
        )
        try Self.requirePrivateFile(archive.path, mode: 0o600, setMode: true)
        try requireSuccess(
            executable: "/usr/bin/security",
            arguments: [
                "import", archive.path,
                "-k", PortableCodeSigningIdentity.systemKeychain,
                "-P", password,
                "-x",
                "-T", "/usr/bin/codesign",
                "-f", "pkcs12"
            ],
            operation: "store Remap's local signing key"
        )
        try requireSuccess(
            executable: "/usr/bin/security",
            arguments: [
                "add-trusted-cert", "-d", "-r", "trustRoot", "-p", "codeSign",
                "-k", PortableCodeSigningIdentity.systemKeychain,
                certificate.path
            ],
            operation: "trust Remap's local signing certificate"
        )
    }

    private func requireSuccess(
        executable: String,
        arguments: [String],
        operation: String
    ) throws {
        let result = try runner.run(
            executable: executable,
            arguments: arguments,
            timeoutSeconds: 60
        )
        guard result.exitStatus == 0 else {
            throw InstallError.operatingSystem(operation, result.exitStatus)
        }
    }

    private static func canonicalFingerprint(_ value: String, byteCount: Int) throws -> String {
        let result = value.lowercased()
        guard result.count == byteCount * 2,
              result.allSatisfy({ $0.isHexDigit && !$0.isUppercase })
        else {
            throw InstallError.integrity("macOS returned a malformed signing fingerprint")
        }
        return result
    }

    private static func randomHex(byteCount: Int) throws -> String {
        var bytes = [UInt8](repeating: 0, count: byteCount)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw InstallError.operatingSystem("generate local signing-key entropy", Int32(errSecIO))
        }
        return bytes.map { String(format: "%02x", $0) }.joined()
    }

    private static func requirePrivateFile(
        _ path: String,
        mode: mode_t,
        setMode: Bool
    ) throws {
        if setMode, chmod(path, mode) != 0 {
            throw InstallError.operatingSystem("seal local signing material", errno)
        }
        var status = stat()
        guard lstat(path, &status) == 0,
              status.st_mode & S_IFMT == S_IFREG,
              status.st_uid == 0,
              status.st_gid == 0,
              status.st_mode & 0o777 == mode,
              status.st_nlink == 1,
              status.st_size > 0,
              status.st_size <= 1_048_576,
              status.st_flags == 0
        else {
            throw InstallError.metadata("local signing material has unsafe metadata")
        }
    }

    private static let opensslConfiguration = """
    [ req ]
    default_bits = 3072
    default_md = sha256
    prompt = no
    distinguished_name = dn
    x509_extensions = codesign

    [ dn ]
    CN = Remap Local Codesign
    O = Agenxy Local
    OU = Remap Signing

    [ codesign ]
    keyUsage = critical,digitalSignature
    extendedKeyUsage = critical,codeSigning
    subjectKeyIdentifier = hash
    authorityKeyIdentifier = keyid,issuer
    basicConstraints = critical,CA:TRUE,pathlen:0
    """
}

struct PortablePrivateWorkspace: Sendable {
    let url: URL

    static func create(prefix: String) throws -> Self {
        guard geteuid() == 0,
              !prefix.isEmpty,
              prefix.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "-" })
        else {
            throw InstallError.notRoot
        }
        let url = URL(
            fileURLWithPath: "/private/var/tmp/\(prefix)-\(UUID().uuidString.lowercased())",
            isDirectory: true
        )
        try FileManager.default.createDirectory(
            at: url,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        var status = stat()
        guard lstat(url.path, &status) == 0,
              status.st_mode & S_IFMT == S_IFDIR,
              status.st_uid == 0,
              status.st_gid == 0,
              status.st_mode & 0o777 == 0o700,
              status.st_flags == 0
        else {
            throw InstallError.metadata("the portable installer workspace has unsafe metadata")
        }
        return Self(url: url)
    }

    func remove() {
        try? FileManager.default.removeItem(at: url)
    }
}
