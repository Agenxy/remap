import Foundation
import RemapInstallKit
import RemapLifecycleKit
import Security

struct PortableCodeSigner: Sendable {
    private let runner: PortableCommandRunner

    init(runner: PortableCommandRunner = PortableCommandRunner()) {
        self.runner = runner
    }

    func sign(
        path: String,
        identifier: String,
        identity: PortableCodeSigningIdentity
    ) throws -> RemapLifecycleCodeIdentity {
        try validateIdentifier(identifier)
        var status = stat()
        guard lstat(path, &status) == 0,
              status.st_mode & S_IFMT == S_IFREG || status.st_mode & S_IFMT == S_IFDIR,
              status.st_uid == 0,
              status.st_gid == 0,
              status.st_flags == 0
        else {
            throw InstallError.metadata("a portable product cannot be signed safely")
        }
        let result = try runner.run(
            executable: "/usr/bin/codesign",
            arguments: [
                "--force",
                "--sign", identity.sha1,
                "--keychain", PortableCodeSigningIdentity.systemKeychain,
                "--timestamp=none",
                "--options", "runtime",
                "--identifier", identifier,
                path
            ],
            timeoutSeconds: 60
        )
        guard result.exitStatus == 0 else {
            throw InstallError.operatingSystem("sign a portable Remap executable", result.exitStatus)
        }
        let observed = try PortableCodeIdentityChecker.identity(path: path)
        guard observed.identifier == identifier,
              observed.certificateSHA256 == identity.sha256
        else {
            throw InstallError.integrity("a portable Remap executable has the wrong local signature")
        }
        return observed
    }

    private func validateIdentifier(_ value: String) throws {
        let allowed = CharacterSet.alphanumerics.union(
            CharacterSet(charactersIn: ".-_")
        )
        guard !value.isEmpty,
              value.utf8.count <= 128,
              value.unicodeScalars.allSatisfy(allowed.contains)
        else {
            throw InstallError.integrity("a portable Remap code identifier is malformed")
        }
    }
}

enum PortableCodeIdentityChecker {
    static func identity(path: String) throws -> RemapLifecycleCodeIdentity {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code)
            == errSecSuccess,
            let code
        else {
            throw InstallError.integrity("a portable Remap executable has no code signature")
        }
        let flags = SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures)
        guard SecStaticCodeCheckValidity(code, flags, nil) == errSecSuccess else {
            throw InstallError.integrity("a portable Remap executable has an invalid code signature")
        }
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(
            code,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &information
        ) == errSecSuccess,
            let values = information as? [CFString: Any],
            let identifier = values[kSecCodeInfoIdentifier] as? String,
            let cdHash = values[kSecCodeInfoUnique] as? Data,
            let certificates = values[kSecCodeInfoCertificates] as? [SecCertificate],
            let root = certificates.last
        else {
            throw InstallError.integrity("a portable Remap executable has incomplete signing data")
        }
        return try RemapLifecycleCodeIdentity(
            identifier: identifier,
            certificateSHA256: InstallDigest.hash(SecCertificateCopyData(root) as Data),
            cdHash: cdHash.hexadecimal
        )
    }
}

private extension Data {
    var hexadecimal: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
