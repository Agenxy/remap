import Darwin
import Foundation
import Security

struct MacOSProductCodeIdentity: Equatable, Sendable {
    let identifier: String
    let signingCertificateSHA256: InstallDigest
}

struct NativeMacOSProductCodeIdentityChecker {
    func identity(fileDescriptor: Int32) throws -> MacOSProductCodeIdentity {
        let descriptorPath = URL(fileURLWithPath: "/dev/fd/\(fileDescriptor)") as CFURL
        return try identity(at: descriptorPath)
    }

    func bundleIdentity(directoryDescriptor: Int32) throws -> MacOSProductCodeIdentity {
        var descriptorStatus = stat()
        guard fstat(directoryDescriptor, &descriptorStatus) == 0,
              descriptorStatus.st_mode & S_IFMT == S_IFDIR
        else {
            throw InstallError.integrity("the native application bundle descriptor is invalid")
        }
        var pathBuffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        guard fcntl(directoryDescriptor, F_GETPATH, &pathBuffer) == 0 else {
            throw InstallError.operatingSystem("resolve native application bundle descriptor", errno)
        }
        let pathBytes = pathBuffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
        let path = String(decoding: pathBytes, as: UTF8.self)
        try requireSameDirectory(path: path, status: descriptorStatus)
        let result = try identity(
            at: URL(fileURLWithPath: path) as CFURL
        )
        try requireSameDirectory(path: path, status: descriptorStatus)
        return result
    }

    private func identity(at path: CFURL) throws -> MacOSProductCodeIdentity {
        var code: SecStaticCode?
        let creationStatus = SecStaticCodeCreateWithPath(path, [], &code)
        guard creationStatus == errSecSuccess, let code else {
            throw InstallError.integrity(
                "a native product code identity could not be opened (\(creationStatus))"
            )
        }
        let validityStatus = SecStaticCodeCheckValidity(
            code,
            SecCSFlags(rawValue: kSecCSStrictValidate),
            nil
        )
        guard validityStatus == errSecSuccess else {
            throw InstallError.integrity(
                "a native product executable has an invalid code signature (\(validityStatus))"
            )
        }
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &information)
            == errSecSuccess,
            let values = information as? [CFString: Any],
            let identifier = values[kSecCodeInfoIdentifier] as? String,
            let certificates = values[kSecCodeInfoCertificates] as? [SecCertificate],
            let rootCertificate = certificates.last
        else {
            throw InstallError.integrity("a native product executable has no certificate-backed identity")
        }
        let certificateData = SecCertificateCopyData(rootCertificate) as Data
        return MacOSProductCodeIdentity(
            identifier: identifier,
            signingCertificateSHA256: InstallDigest.hash(certificateData)
        )
    }

    private func requireSameDirectory(path: String, status expected: stat) throws {
        var observed = stat()
        guard lstat(path, &observed) == 0,
              observed.st_mode & S_IFMT == S_IFDIR,
              observed.st_dev == expected.st_dev,
              observed.st_ino == expected.st_ino
        else {
            throw InstallError.integrity("the native application bundle path changed during validation")
        }
    }
}
