import Foundation
import RemapInstallKit
import Security

public struct RemapLifecycleCodeIdentity: Codable, Equatable, Sendable {
    public let identifier: String
    public let certificateSHA256: InstallDigest
    public let cdHash: String

    public init(
        identifier: String,
        certificateSHA256: InstallDigest,
        cdHash: String
    ) throws {
        guard Self.validIdentifier(identifier), Self.validCDHash(cdHash) else {
            throw InstallError.integrity("lifecycle code identity is malformed")
        }
        self.identifier = identifier
        self.certificateSHA256 = certificateSHA256
        self.cdHash = cdHash
    }

    private static func validIdentifier(_ value: String) -> Bool {
        let allowed = CharacterSet.alphanumerics.union(
            CharacterSet(charactersIn: ".-_")
        )
        return !value.isEmpty
            && value.utf8.count <= 128
            && value.unicodeScalars.allSatisfy(allowed.contains)
    }

    private static func validCDHash(_ value: String) -> Bool {
        (value.count == 40 || value.count == 64)
            && value.allSatisfy { $0.isHexDigit && !$0.isUppercase }
    }
}

public struct RemapLifecycleServiceConfiguration: Codable, Equatable, Sendable {
    public static let absolutePath = "/Library/Application Support/Agenxy/Remap/Installer/service-v1.json"
    public static let maximumByteCount = 16384

    public let schemaVersion: UInt32
    public let ownerUID: UInt32
    public let app: RemapLifecycleCodeIdentity
    public let client: RemapLifecycleCodeIdentity?
    public let bootstrap: RemapLifecycleCodeIdentity
    public let helper: RemapLifecycleCodeIdentity
    public let sourceManifestDigest: InstallDigest
    public let sourcePackageRoot: InstallAbsolutePath

    public init(
        ownerUID: UInt32,
        app: RemapLifecycleCodeIdentity,
        client: RemapLifecycleCodeIdentity? = nil,
        bootstrap: RemapLifecycleCodeIdentity,
        helper: RemapLifecycleCodeIdentity,
        sourceManifestDigest: InstallDigest,
        sourcePackageRoot: InstallAbsolutePath
    ) throws {
        let expectedSourceRoot = "/Library/Application Support/Agenxy/Remap/Installer/Sources/"
            + sourceManifestDigest.description
        guard ownerUID > 0,
              app.identifier == "org.agenxy.Remap",
              client == nil || client?.identifier == "org.agenxy.Remap.lifecycle-cli",
              bootstrap.identifier == "org.agenxy.Remap.installer-bootstrap",
              helper.identifier == "org.agenxy.Remap.installer-service",
              app.certificateSHA256 == bootstrap.certificateSHA256,
              app.certificateSHA256 == helper.certificateSHA256,
              client == nil || client?.certificateSHA256 == app.certificateSHA256,
              sourcePackageRoot.description == expectedSourceRoot
        else {
            throw InstallError.integrity("lifecycle service configuration is not product-bound")
        }
        schemaVersion = 1
        self.ownerUID = ownerUID
        self.app = app
        self.client = client
        self.bootstrap = bootstrap
        self.helper = helper
        self.sourceManifestDigest = sourceManifestDigest
        self.sourcePackageRoot = sourcePackageRoot
    }

    public static func production() throws -> Self {
        let authority = try FileSystemAuthority(systemRootPath: "/")
        let path = try InstallRelativePath(
            "Library/Application Support/Agenxy/Remap/Installer/service-v1.json"
        )
        guard let metadata = try authority.metadata(at: path),
              metadata.kind == .regularFile,
              metadata.ownerUID == 0,
              metadata.groupGID == 0,
              metadata.mode == 0o400,
              metadata.linkCount == 1,
              metadata.byteCount <= UInt64(maximumByteCount),
              !metadata.hasACL,
              metadata.flags == 0
        else {
            throw InstallError.metadata("the lifecycle service configuration has unsafe metadata")
        }
        let descriptor = try authority.openUniqueRegularFile(at: path)
        defer { close(descriptor) }
        try authority.validateNoUnexpectedExtendedMetadata(descriptor)
        let data = try authority.readUniqueFile(
            at: path,
            maximumByteCount: maximumByteCount
        )
        return try decodeCanonical(data)
    }

    public func canonicalData() throws -> Data {
        try Self.encoder.encode(self)
    }

    public static func decodeCanonical(_ data: Data) throws -> Self {
        guard data.count <= maximumByteCount else {
            throw InstallError.integrity("lifecycle service configuration exceeds its byte bound")
        }
        let configuration = try decoder.decode(Self.self, from: data)
        let reconstructed = try Self(
            ownerUID: configuration.ownerUID,
            app: configuration.app,
            client: configuration.client,
            bootstrap: configuration.bootstrap,
            helper: configuration.helper,
            sourceManifestDigest: configuration.sourceManifestDigest,
            sourcePackageRoot: configuration.sourcePackageRoot
        )
        guard configuration.schemaVersion == 1,
              configuration == reconstructed,
              try reconstructed.canonicalData() == data
        else {
            throw InstallError.integrity("lifecycle service configuration is not canonical")
        }
        return reconstructed
    }

    private static let decoder = JSONDecoder()

    private static let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return encoder
    }()
}

protocol RemapLifecycleCodeIdentityChecking: Sendable {
    func currentIdentity() throws -> RemapLifecycleCodeIdentity
    func identity(fileDescriptor: Int32) throws -> RemapLifecycleCodeIdentity
    func identity(processID: pid_t) throws -> RemapLifecycleCodeIdentity
}

struct NativeRemapLifecycleCodeIdentityChecker: RemapLifecycleCodeIdentityChecking {
    func currentIdentity() throws -> RemapLifecycleCodeIdentity {
        var code: SecCode?
        let status = SecCodeCopySelf([], &code)
        guard status == errSecSuccess, let code else {
            throw InstallError.integrity("the lifecycle service could not inspect its code identity")
        }
        return try validatedIdentity(code)
    }

    func identity(processID: pid_t) throws -> RemapLifecycleCodeIdentity {
        guard processID > 0 else {
            throw InstallError.approval("the lifecycle caller has no stable process identity")
        }
        let attributes = [kSecGuestAttributePid: NSNumber(value: processID)] as CFDictionary
        var code: SecCode?
        let status = SecCodeCopyGuestWithAttributes(nil, attributes, [], &code)
        guard status == errSecSuccess, let code else {
            throw InstallError.approval("the lifecycle caller code identity is unavailable")
        }
        return try validatedIdentity(code)
    }

    func identity(fileDescriptor: Int32) throws -> RemapLifecycleCodeIdentity {
        let path = URL(fileURLWithPath: "/dev/fd/\(fileDescriptor)") as CFURL
        var code: SecStaticCode?
        let status = SecStaticCodeCreateWithPath(path, [], &code)
        guard status == errSecSuccess, let code else {
            throw InstallError.integrity("the lifecycle helper code identity is unavailable")
        }
        return try validatedStaticIdentity(code)
    }

    private func validatedIdentity(_ code: SecCode) throws -> RemapLifecycleCodeIdentity {
        let dynamicStatus = SecCodeCheckValidity(
            code,
            SecCSFlags(rawValue: kSecCSStrictValidate),
            nil
        )
        guard dynamicStatus == errSecSuccess else {
            throw InstallError.approval("the lifecycle caller has an invalid dynamic signature")
        }
        var staticCode: SecStaticCode?
        let copyStatus = SecCodeCopyStaticCode(code, [], &staticCode)
        guard copyStatus == errSecSuccess, let staticCode else {
            throw InstallError.approval("the lifecycle caller static signature is unavailable")
        }
        let staticStatus = SecStaticCodeCheckValidity(
            staticCode,
            SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures),
            nil
        )
        guard staticStatus == errSecSuccess else {
            throw InstallError.approval("the lifecycle caller bundle signature is invalid")
        }
        return try signingIdentity(staticCode)
    }

    private func validatedStaticIdentity(
        _ staticCode: SecStaticCode
    ) throws -> RemapLifecycleCodeIdentity {
        let status = SecStaticCodeCheckValidity(
            staticCode,
            SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures),
            nil
        )
        guard status == errSecSuccess else {
            throw InstallError.integrity("the lifecycle helper has an invalid signature")
        }
        return try signingIdentity(staticCode)
    }

    private func signingIdentity(
        _ staticCode: SecStaticCode
    ) throws -> RemapLifecycleCodeIdentity {
        var information: CFDictionary?
        let informationStatus = SecCodeCopySigningInformation(
            staticCode,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &information
        )
        guard informationStatus == errSecSuccess,
              let values = information as? [CFString: Any],
              let identifier = values[kSecCodeInfoIdentifier] as? String,
              let unique = values[kSecCodeInfoUnique] as? Data,
              let certificates = values[kSecCodeInfoCertificates] as? [SecCertificate],
              let rootCertificate = certificates.last
        else {
            throw InstallError.approval("the lifecycle caller has no certificate-backed identity")
        }
        return try RemapLifecycleCodeIdentity(
            identifier: identifier,
            certificateSHA256: InstallDigest.hash(
                SecCertificateCopyData(rootCertificate) as Data
            ),
            cdHash: unique.hexadecimal
        )
    }
}

public struct RemapLifecycleCallerAuthenticator: Sendable {
    private let configuration: RemapLifecycleServiceConfiguration
    private let checker: any RemapLifecycleCodeIdentityChecking

    public init(configuration: RemapLifecycleServiceConfiguration) {
        self.init(
            configuration: configuration,
            checker: NativeRemapLifecycleCodeIdentityChecker()
        )
    }

    init(
        configuration: RemapLifecycleServiceConfiguration,
        checker: any RemapLifecycleCodeIdentityChecking
    ) {
        self.configuration = configuration
        self.checker = checker
    }

    public var ownerUID: UInt32 {
        configuration.ownerUID
    }

    public func authorizeService() throws {
        guard try checker.currentIdentity() == configuration.helper else {
            throw InstallError.approval("the lifecycle service identity does not match its root-owned configuration")
        }
    }

    public func authorizeBootstrap() throws {
        guard try checker.currentIdentity() == configuration.bootstrap else {
            throw InstallError.approval("the lifecycle bootstrap identity does not match its root-owned configuration")
        }
    }

    public func authorizeBootstrapRepair() throws {
        let identity = try checker.currentIdentity()
        guard identity.identifier == configuration.bootstrap.identifier,
              identity.certificateSHA256 == configuration.bootstrap.certificateSHA256
        else {
            throw InstallError.approval(
                "the repair bootstrap identity does not match the configured signing root"
            )
        }
    }

    public func authorizeCaller(
        effectiveUID: UInt32,
        processID: pid_t
    ) throws {
        guard effectiveUID == configuration.ownerUID else {
            throw InstallError.approval("the lifecycle caller is not the configured Remap owner")
        }
        let identity = try checker.identity(processID: processID)
        guard identity == configuration.app || identity == configuration.client else {
            throw InstallError.approval(
                "the lifecycle caller is not the configured Remap application or lifecycle client"
            )
        }
    }

    func authorizeHelper(fileDescriptor: Int32) throws {
        guard try checker.identity(fileDescriptor: fileDescriptor) == configuration.helper else {
            throw InstallError.approval("the installed lifecycle helper identity does not match its configuration")
        }
    }
}

private extension Data {
    var hexadecimal: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
