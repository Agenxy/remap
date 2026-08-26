import Foundation
import Security

/// Security exposes no nondeprecated API that creates the SecKeychain reference
/// required by kSecMatchSearchList for a legacy System keychain. This one-symbol
/// ABI bridge preserves the public SecKeychainOpen signature without broadening
/// the query to another keychain. ADR-0014 records the boundary and exit plan.
@_silgen_name("SecKeychainOpen")
private func remapSecKeychainOpen(
    _ pathName: UnsafePointer<CChar>,
    _ keychain: UnsafeMutablePointer<SecKeychain?>
) -> OSStatus

enum MacOSLocalCodeSigningIdentityCleanup {
    private static let name = "Remap Local Codesign"
    private static let systemKeychainPath = "/Library/Keychains/System.keychain"
    private static let maximumMatches = 4096

    static func remove(expectedCertificateSHA256: InstallDigest) throws {
        let certificates = try matchingCertificates(expectedCertificateSHA256)
        let identities = try matchingIdentities(expectedCertificateSHA256)
        let trusted = try matchingAdministratorTrust(expectedCertificateSHA256)
        guard certificates.expected.count <= 1,
              certificates.named.count <= 1,
              identities.expected.count <= 1,
              identities.named.count <= 1,
              trusted.expected.count <= 1,
              trusted.named.count <= 1,
              certificates.named.allSatisfy({ certificateDigest($0) == expectedCertificateSHA256 }),
              try identities.named.allSatisfy({
                  try identityDigest($0) == expectedCertificateSHA256
              }),
              trusted.named.allSatisfy({ certificateDigest($0) == expectedCertificateSHA256 })
        else {
            throw InstallError.integrity(
                "the System keychain has ambiguous Remap Local Codesign state"
            )
        }
        if let identity = identities.expected.first, let certificate = certificates.expected.first {
            var identityCertificate: SecCertificate?
            let copyStatus = SecIdentityCopyCertificate(identity, &identityCertificate)
            guard copyStatus == errSecSuccess,
                  let identityCertificate,
                  CFEqual(identityCertificate, certificate)
            else {
                throw InstallError.integrity(
                    "Remap's local signing identity and certificate do not match"
                )
            }
        } else if identities.expected.isEmpty == false {
            throw InstallError.integrity(
                "Remap's local signing identity has no exact matching certificate"
            )
        }
        if let certificate = trusted.expected.first {
            let trustStatus = SecTrustSettingsRemoveTrustSettings(certificate, .admin)
            guard trustStatus == errSecSuccess || trustStatus == errSecItemNotFound else {
                throw InstallError.operatingSystem(
                    "remove Remap's local signing trust",
                    trustStatus
                )
            }
        }
        if let identity = identities.expected.first {
            try delete(value: identity, operation: "remove Remap's local signing identity")
        }
        let certificateStillExists = try matchingCertificates(expectedCertificateSHA256).expected.isEmpty == false
        if let certificate = certificates.expected.first, certificateStillExists {
            try delete(value: certificate, operation: "remove Remap's local signing certificate")
        }
        let remainingCertificates = try matchingCertificates(expectedCertificateSHA256)
        let remainingIdentities = try matchingIdentities(expectedCertificateSHA256)
        let remainingTrust = try matchingAdministratorTrust(expectedCertificateSHA256)
        guard remainingCertificates.expected.isEmpty,
              remainingCertificates.named.isEmpty,
              remainingIdentities.expected.isEmpty,
              remainingIdentities.named.isEmpty,
              remainingTrust.expected.isEmpty,
              remainingTrust.named.isEmpty
        else {
            throw InstallError.integrity(
                "Remap's local signing identity remains after cleanup"
            )
        }
    }

    private static func matchingCertificates(
        _ expectedDigest: InstallDigest
    ) throws -> (expected: [SecCertificate], named: [SecCertificate]) {
        let all: [SecCertificate] = try matches(
            itemClass: kSecClassCertificate,
            label: nil,
            operation: "inspect System-keychain certificates"
        )
        let named: [SecCertificate] = try matches(
            itemClass: kSecClassCertificate,
            label: name,
            operation: "inspect Remap's local signing certificates"
        )
        return (all.filter { certificateDigest($0) == expectedDigest }, named)
    }

    private static func matchingIdentities(
        _ expectedDigest: InstallDigest
    ) throws -> (expected: [SecIdentity], named: [SecIdentity]) {
        let all: [SecIdentity] = try matches(
            itemClass: kSecClassIdentity,
            label: nil,
            operation: "inspect System-keychain identities"
        )
        let named: [SecIdentity] = try matches(
            itemClass: kSecClassIdentity,
            label: name,
            operation: "inspect Remap's local signing identities"
        )
        return try (
            all.filter { try identityDigest($0) == expectedDigest },
            named
        )
    }

    private static func matches<T>(
        itemClass: CFString,
        label: String?,
        operation: String
    ) throws -> [T] {
        var query: [CFString: Any] = try [
            kSecClass: itemClass,
            kSecMatchLimit: kSecMatchLimitAll,
            kSecMatchSearchList: [systemKeychain()],
            kSecReturnRef: true,
            kSecUseDataProtectionKeychain: false
        ]
        if let label {
            query[kSecAttrLabel] = label
        }
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return []
        }
        guard status == errSecSuccess,
              let values = result as? [T],
              values.count <= maximumMatches
        else {
            throw InstallError.operatingSystem(operation, status)
        }
        return values
    }

    private static func certificateDigest(_ certificate: SecCertificate) -> InstallDigest {
        InstallDigest.hash(SecCertificateCopyData(certificate) as Data)
    }

    private static func identityDigest(_ identity: SecIdentity) throws -> InstallDigest {
        var certificate: SecCertificate?
        let status = SecIdentityCopyCertificate(identity, &certificate)
        guard status == errSecSuccess, let certificate else {
            throw InstallError.operatingSystem(
                "inspect Remap's local signing identity certificate",
                status
            )
        }
        return certificateDigest(certificate)
    }

    private static func matchingAdministratorTrust(
        _ expectedDigest: InstallDigest
    ) throws -> (expected: [SecCertificate], named: [SecCertificate]) {
        let all = try administratorTrustCertificates()
        return (
            all.filter { certificateDigest($0) == expectedDigest },
            all.filter { SecCertificateCopySubjectSummary($0) as String? == name }
        )
    }

    private static func administratorTrustCertificates() throws -> [SecCertificate] {
        var result: CFArray?
        let status = SecTrustSettingsCopyCertificates(.admin, &result)
        if status == errSecNoTrustSettings || status == errSecItemNotFound {
            return []
        }
        guard status == errSecSuccess,
              let values = result as? [SecCertificate],
              values.count <= maximumMatches
        else {
            throw InstallError.operatingSystem(
                "inspect administrator-domain certificate trust",
                status
            )
        }
        return values
    }

    private static func systemKeychain() throws -> SecKeychain {
        var keychain: SecKeychain?
        let status = systemKeychainPath.withCString {
            remapSecKeychainOpen($0, &keychain)
        }
        guard status == errSecSuccess, let keychain else {
            throw InstallError.operatingSystem("open the System keychain", status)
        }
        return keychain
    }

    private static func delete(value: CFTypeRef, operation: String) throws {
        let status = SecItemDelete([kSecValueRef: value] as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw InstallError.operatingSystem(operation, status)
        }
    }
}
