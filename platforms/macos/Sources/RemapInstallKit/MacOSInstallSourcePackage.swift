import Foundation

/// One canonical, descriptor-rooted source package admitted at the privileged
/// installer boundary.
public struct MacOSInstallSourcePackage: Sendable {
    private static let manifestLimit = 1_048_576

    public let manifest: InstallManifest
    public let source: FileSystemAuthority

    public init(
        rootPath: String,
        expectedManifestDigest: String,
        sourceUID: UInt32
    ) throws {
        let root = try InstallAbsolutePath(rootPath)
        let packageAuthority = try FileSystemAuthority(
            sourcePackageRootPath: root.value,
            ownerUID: sourceUID
        )
        let data = try packageAuthority.readUniqueFile(
            at: InstallRelativePath("manifest.json"),
            maximumByteCount: Self.manifestLimit
        )
        manifest = try InstallManifest.decodeCanonical(
            data,
            expectedDigest: InstallDigest(expectedManifestDigest)
        )
        source = try packageAuthority.sourceSubdirectory(
            at: InstallRelativePath("payload")
        )
    }
}
