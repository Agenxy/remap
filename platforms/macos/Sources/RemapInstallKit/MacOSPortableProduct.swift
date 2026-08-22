import Foundation

/// Exact locally signed product inputs used to assemble one native source image.
public struct MacOSPortableProduct: Sendable {
    public let rootPath: String
    public let productVersion: String
    public let ownerUID: UInt32
    public let signingCertificateSHA256: InstallDigest
    public let previousGenerationID: String?

    public init(
        rootPath: String,
        productVersion: String,
        ownerUID: UInt32,
        signingCertificateSHA256: InstallDigest,
        previousGenerationID: String?
    ) throws {
        guard rootPath.hasPrefix("/"), !rootPath.contains("\0") else {
            throw InstallError.invalidPath(rootPath)
        }
        try InstallManifest.validateIdentifier(productVersion, field: "product version")
        if let previousGenerationID {
            try InstallManifest.validateIdentifier(
                previousGenerationID,
                field: "previous generation ID"
            )
        }
        guard ownerUID != 0 else {
            throw InstallError.invalidManifest("the native daemon account must not be root")
        }
        self.rootPath = rootPath
        self.productVersion = productVersion
        self.ownerUID = ownerUID
        self.signingCertificateSHA256 = signingCertificateSHA256
        self.previousGenerationID = previousGenerationID
    }
}

/// Canonical source package created from one locally signed portable product.
public struct MacOSPortableSourcePackage: Sendable {
    public let rootPath: String
    public let manifestDigest: InstallDigest
    public let generationID: String

    public init(
        rootPath: String,
        manifestDigest: InstallDigest,
        generationID: String
    ) {
        self.rootPath = rootPath
        self.manifestDigest = manifestDigest
        self.generationID = generationID
    }
}

enum MacOSPortableProductContract {
    static let generationPlaceholder = "{generationID}"
    static let productIdentifier = "org.agenxy.Remap"

    static let requiredFiles = Set([
        "bin/remap",
        "libexec/remap-install",
        "libexec/remap-lifecycle",
        "libexec/remap-resolver",
        "libexec/remap-system",
        "libexec/remapd",
        "share/completions/remap.bash",
        "share/completions/remap.fish",
        "share/completions/remap.zsh",
        "share/licenses/remap/LICENSE",
        "share/licenses/remap/NOTICE"
    ]).union(manpageNames.map { "share/man/man1/\($0)" })

    static let requiredDirectories: Set<String> = [
        "app",
        "app/Remap.app",
        "bin",
        "libexec",
        "share",
        "share/completions",
        "share/licenses",
        "share/licenses/remap",
        "share/man",
        "share/man/man1"
    ]

    static let manpageNames = [
        "remap-apply.1",
        "remap-completions.1",
        "remap-daemon.1",
        "remap-disable.1",
        "remap-doctor.1",
        "remap-enable.1",
        "remap-get.1",
        "remap-list.1",
        "remap-manpage.1",
        "remap-manpages.1",
        "remap-mcp.1",
        "remap-preview.1",
        "remap-remove.1",
        "remap-resolve.1",
        "remap-set.1",
        "remap-status.1",
        "remap-system-recover.1",
        "remap-system-status.1",
        "remap-system-uninstall.1",
        "remap-system.1",
        "remap-validate.1",
        "remap.1"
    ]
}
