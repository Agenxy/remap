import Foundation
import RemapInstallKit

struct RemapInstallPackage {
    let manifest: InstallManifest
    let source: FileSystemAuthority

    init(rootPath: String, expectedDigest: String, sourceUID: UInt32) throws {
        let package = try MacOSInstallSourcePackage(
            rootPath: rootPath,
            expectedManifestDigest: expectedDigest,
            sourceUID: sourceUID
        )
        manifest = package.manifest
        source = package.source
    }
}
