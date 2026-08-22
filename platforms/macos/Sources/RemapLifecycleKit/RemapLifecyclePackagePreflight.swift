import Foundation
import RemapInstallKit

/// Rejects a bootstrap package before Apple Installer can overwrite prior authority.
public struct RemapLifecyclePackagePreflight: Sendable {
    /// Modes emitted by the two earlier local-installer topology revisions.
    /// Migration is attempted only after the complete lifecycle authority,
    /// signing root, and immutable source package have been validated.
    static let recoverableOrganisationModes: Set<UInt16> = [0o700, 0o711, 0o755]
    static let recoverableProductModes: Set<UInt16> = [0o700, 0o711]

    typealias Exists = @Sendable (InstallRelativePath) throws -> Bool
    typealias ValidateExisting = @Sendable () throws -> Void
    typealias MigrateExisting = @Sendable () throws -> Void
    typealias RecoverCleanup = @Sendable () throws -> Void

    private let exists: Exists
    private let validateExisting: ValidateExisting
    private let migrateExisting: MigrateExisting
    private let recoverCleanup: RecoverCleanup

    public static func production() throws -> Self {
        let authority = try FileSystemAuthority(systemRootPath: "/")
        let cleanup = try MacOSPortableAuthorityCleanup.production()
        return Self(
            authority: authority,
            recoverCleanup: {
                let lease = try MacOSPortableAuthorityLock.acquire()
                _ = lease
                _ = try cleanup.reconcilePendingPlan(
                    beforeRemovingHelper: MacOSInstallerServiceLaunchd.bootoutIfLoaded
                )
            },
            validateExisting: {
                let configuration = try RemapLifecycleServiceConfiguration.production()
                let authenticator = RemapLifecycleCallerAuthenticator(
                    configuration: configuration
                )
                try authenticator.authorizeBootstrapRepair()
                try RemapLifecycleBootstrapper(
                    authority: authority,
                    authenticator: authenticator
                ).validateInstalledAuthority()
                _ = try MacOSInstallSourcePackage(
                    rootPath: configuration.sourcePackageRoot.description,
                    expectedManifestDigest: configuration.sourceManifestDigest.description,
                    sourceUID: 0
                )
            },
            migrateExisting: {
                try authority.transitionExactOwnedDirectoryMode(
                    at: InstallRelativePath("Library/Application Support/Agenxy"),
                    ownerUID: 0,
                    groupGID: 0,
                    permittedModes: recoverableOrganisationModes,
                    mode: 0o755
                )
                try authority.transitionExactOwnedDirectoryMode(
                    at: InstallRelativePath("Library/Application Support/Agenxy/Remap"),
                    ownerUID: 0,
                    groupGID: 0,
                    permittedModes: recoverableProductModes,
                    mode: 0o711
                )
            }
        )
    }

    init(
        authority: FileSystemAuthority,
        recoverCleanup: @escaping RecoverCleanup = {},
        validateExisting: @escaping ValidateExisting,
        migrateExisting: @escaping MigrateExisting
    ) {
        exists = { try authority.metadata(at: $0) != nil }
        self.recoverCleanup = recoverCleanup
        self.validateExisting = validateExisting
        self.migrateExisting = migrateExisting
    }

    init(
        exists: @escaping Exists,
        recoverCleanup: @escaping RecoverCleanup = {},
        validateExisting: @escaping ValidateExisting = {
            throw InstallError.collision("existing lifecycle authority was not validated")
        },
        migrateExisting: @escaping MigrateExisting = {}
    ) {
        self.exists = exists
        self.recoverCleanup = recoverCleanup
        self.validateExisting = validateExisting
        self.migrateExisting = migrateExisting
    }

    public func validateCleanInstall() throws {
        try recoverCleanup()
        let paths = try Self.exclusivePaths
        let present = try paths.map(exists)
        guard present.contains(true) else {
            return
        }
        guard present.allSatisfy(\.self) else {
            throw InstallError.collision(
                "the native Installer found partial Remap lifecycle authority"
            )
        }
        try validateExisting()
        try migrateExisting()
    }

    private static var exclusivePaths: [InstallRelativePath] {
        get throws {
            try [
                InstallRelativePath(
                    "Library/PrivilegedHelperTools/org.agenxy.Remap.installer-service"
                ),
                InstallRelativePath(
                    "Library/LaunchDaemons/org.agenxy.Remap.installer-service.plist"
                ),
                InstallRelativePath("Library/Application Support/Agenxy/Remap")
            ]
        }
    }
}
