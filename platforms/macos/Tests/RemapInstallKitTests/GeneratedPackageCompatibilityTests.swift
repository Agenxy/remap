import Darwin
import Foundation
@testable import RemapInstallKit
import Testing

private let generatedPackageEnvironment = ProcessInfo.processInfo.environment
private let generatedPackageAvailable = generatedPackageEnvironment["REMAP_GENERATED_PACKAGE_ROOT"] != nil

@Test(.enabled(if: generatedPackageAvailable, "requires a package assembled by tools/remap_native_package.py"))
func pythonGeneratedPackageMatchesTheNativeProductionContract() throws {
    let root = try #require(generatedPackageEnvironment["REMAP_GENERATED_PACKAGE_ROOT"])
    let digestValue = try #require(generatedPackageEnvironment["REMAP_GENERATED_MANIFEST_SHA256"])
    let sourceUIDValue = try #require(generatedPackageEnvironment["REMAP_GENERATED_SOURCE_UID"])
    let sourceUID = try #require(UInt32(sourceUIDValue))
    #expect(String(sourceUID) == sourceUIDValue)

    let packageAuthority = try FileSystemAuthority(
        testingSourcePackageRootPath: root,
        ownerUID: sourceUID,
        durability: TestInstallDurability()
    )
    let manifestData = try packageAuthority.readUniqueFile(
        at: InstallRelativePath("manifest.json"),
        maximumByteCount: 1_048_576
    )
    let manifest = try InstallManifest.decodeCanonical(
        manifestData,
        expectedDigest: InstallDigest(digestValue)
    )
    let payload = try packageAuthority.sourceSubdirectory(at: InstallRelativePath("payload"))
    try manifest.entries.forEach { try payload.verifySource($0, at: $0.path) }
    let directoryPublications = manifest.publications
        .filter { $0.kind == .directory }
        .map(\.path.description)
    #expect(directoryPublications == expectedPublicDirectoryPaths)

    let tree = try TemporaryInstallTree()
    let systemRoot = try tree.directory("generated-package-system")
    let layout = try MacOSInstallLayout(
        authority: testAuthority(at: systemRoot),
        systemRootPath: systemRoot.path,
        installOwnerUID: UInt32(geteuid()),
        installGroupGID: UInt32(getegid())
    )
    _ = try MacOSGenerationImageStore(layout: layout).validateProductionSource(
        manifest,
        authority: payload
    )
    let configurationData = try payload.readUniqueFile(
        at: InstallRelativePath(MacOSInstallConfiguration.entryName),
        maximumByteCount: 65536
    )
    let configuration = try InstallCanonicalJSON.decoder.decode(
        MacOSInstallConfiguration.self,
        from: configurationData
    )
    #expect(configuration.schemaVersion == 2)
    let checker = NativeMacOSProductCodeIdentityChecker()
    let applicationBundle = URL(fileURLWithPath: root)
        .appending(path: "payload/app/Remap.app", directoryHint: .isDirectory)
    let applicationDescriptor = open(
        applicationBundle.path,
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
    )
    guard applicationDescriptor >= 0 else {
        throw InstallError.operatingSystem("open generated application identity fixture", errno)
    }
    defer { close(applicationDescriptor) }
    let applicationIdentity = try checker.bundleIdentity(directoryDescriptor: applicationDescriptor)
    #expect(applicationIdentity.identifier == "org.agenxy.Remap")
    #expect(applicationIdentity.signingCertificateSHA256 == configuration.signingCertificateSHA256)

    let tamperedBundle = tree.url.appending(path: "Tampered.app", directoryHint: .isDirectory)
    try FileManager.default.copyItem(at: applicationBundle, to: tamperedBundle)
    let tamperedExecutable = tamperedBundle.appending(path: "Contents/MacOS/Remap")
    guard chmod(tamperedExecutable.path, 0o700) == 0 else {
        throw InstallError.operatingSystem("make tampered code fixture writable", errno)
    }
    var tamperedData = try Data(contentsOf: tamperedExecutable)
    let tamperedIndex = try #require(tamperedData.indices.dropFirst(4096).first)
    tamperedData[tamperedIndex] ^= 1
    try tamperedData.write(to: tamperedExecutable)
    let tamperedDescriptor = open(
        tamperedBundle.path,
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
    )
    guard tamperedDescriptor >= 0 else {
        throw InstallError.operatingSystem("open tampered code fixture", errno)
    }
    defer { close(tamperedDescriptor) }
    #expect(throws: InstallError.self) {
        _ = try checker.bundleIdentity(directoryDescriptor: tamperedDescriptor)
    }

    let installerPath = try InstallRelativePath("libexec/remap-install")
    let installer = try #require(manifest.entries.first { $0.path == installerPath })
    #expect(installer.role == .support)
    #expect(installer.ownerUID == 0)
    #expect(installer.groupGID == 0)
    #expect(installer.mode == 0o555)
    let absoluteInstaller = URL(fileURLWithPath: root)
        .appending(path: "payload/libexec/remap-install").path
    let installerDescriptor = open(absoluteInstaller, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    guard installerDescriptor >= 0 else {
        throw InstallError.operatingSystem("open generated bootstrap identity fixture", errno)
    }
    defer { close(installerDescriptor) }
    let codeIdentity = try NativeMacOSBootstrapCodeIdentityChecker().identity(
        fileDescriptor: installerDescriptor
    )
    #expect(codeIdentity.identifier == MacOSBootstrapHelperStore.codeIdentifier)
    #expect((40 ... 64).contains(codeIdentity.cdHash.count))
}

private let expectedPublicDirectoryPaths = [
    "usr/local",
    "usr/local/bin",
    "usr/local/share",
    "usr/local/share/bash-completion",
    "usr/local/share/bash-completion/completions",
    "usr/local/share/fish",
    "usr/local/share/fish/vendor_completions.d",
    "usr/local/share/licenses",
    "usr/local/share/licenses/remap",
    "usr/local/share/man",
    "usr/local/share/man/man1",
    "usr/local/share/zsh",
    "usr/local/share/zsh/site-functions"
]
