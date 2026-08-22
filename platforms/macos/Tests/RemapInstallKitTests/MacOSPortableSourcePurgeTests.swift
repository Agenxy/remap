import Darwin
import Foundation
@testable import RemapInstallKit
import Testing

@Suite("Portable source collection")
struct MacOSPortableSourcePurgeTests {
    @Test("manifest-owned source bytes are removed without recursive deletion")
    func exactSourceIsPurged() throws {
        try withFixture { fixture in
            let purge = try fixture.purge()
            try purge.purge()
            #expect(!FileManager.default.fileExists(atPath: fixture.source.rootPath))
            try purge.purge()
        }
    }

    @Test("foreign content blocks collection and remains untouched")
    func foreignContentIsPreserved() throws {
        try withFixture { fixture in
            let foreign = URL(fileURLWithPath: fixture.source.rootPath)
                .appendingPathComponent("payload/foreign")
            try setMode(foreign.deletingLastPathComponent().path, 0o700)
            try Data("foreign".utf8).write(to: foreign)
            try setMode(foreign.path, 0o400)

            #expect(throws: InstallError.self) {
                try fixture.purge().purge()
            }
            #expect(try Data(contentsOf: foreign) == Data("foreign".utf8))
        }
    }

    @Test("a partial exact purge resumes from the retained manifest")
    func partialPurgeResumes() throws {
        try withFixture { fixture in
            let root = URL(fileURLWithPath: fixture.source.rootPath)
            let removable = root.appendingPathComponent("payload/bin/remap")
            try setMode(removable.deletingLastPathComponent().path, 0o700)
            try FileManager.default.removeItem(at: removable)

            try fixture.purge().purge()
            #expect(!FileManager.default.fileExists(atPath: fixture.source.rootPath))
        }
    }

    @Test("detached source packages are verified before removal")
    func detachedSourcesArePurged() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("remap-detached-sources-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        try setMode(root.path, 0o700)
        defer { try? FileManager.default.removeItem(at: root) }
        let product = root.appendingPathComponent("product")
        try createProduct(product)
        let first = try assembleSource(root: root, product: product, name: "first", upstream: "192.0.2.53:53")
        let second = try assembleSource(root: root, product: product, name: "second", upstream: "192.0.2.54:53")
        let sources = root.appendingPathComponent("Sources")
        try FileManager.default.createDirectory(at: sources, withIntermediateDirectories: false)
        try setMode(sources.path, 0o700)
        let retained = sources.appendingPathComponent(first.manifestDigest.description)
        let detached = sources.appendingPathComponent(second.manifestDigest.description)
        try FileManager.default.moveItem(atPath: first.rootPath, toPath: retained.path)
        try FileManager.default.moveItem(atPath: second.rootPath, toPath: detached.path)
        let authority = try FileSystemAuthority(testingRootPath: root.path)

        try MacOSPortableSourcePurge.purgeDetachedSources(
            authority: authority,
            sourcesPath: InstallRelativePath("Sources"),
            retaining: [first.manifestDigest],
            ownerUID: UInt32(geteuid()),
            groupGID: UInt32(getegid())
        )

        #expect(FileManager.default.fileExists(atPath: retained.path))
        #expect(!FileManager.default.fileExists(atPath: detached.path))
    }

    @Test("foreign source entries block every detached purge")
    func foreignDetachedSourceBlocksPurge() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("remap-foreign-source-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        try setMode(root.path, 0o700)
        defer { try? FileManager.default.removeItem(at: root) }
        let sources = root.appendingPathComponent("Sources")
        try FileManager.default.createDirectory(at: sources, withIntermediateDirectories: false)
        try setMode(sources.path, 0o700)
        let foreign = sources.appendingPathComponent("foreign")
        try FileManager.default.createDirectory(at: foreign, withIntermediateDirectories: false)
        try setMode(foreign.path, 0o700)
        let authority = try FileSystemAuthority(testingRootPath: root.path)

        #expect(throws: InstallError.self) {
            try MacOSPortableSourcePurge.purgeDetachedSources(
                authority: authority,
                sourcesPath: InstallRelativePath("Sources"),
                retaining: [],
                ownerUID: UInt32(geteuid()),
                groupGID: UInt32(getegid())
            )
        }
        #expect(FileManager.default.fileExists(atPath: foreign.path))
    }

    private func withFixture(_ body: (Fixture) throws -> Void) throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("remap-source-purge-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        try setMode(root.path, 0o700)
        defer { try? FileManager.default.removeItem(at: root) }
        let product = root.appendingPathComponent("product")
        try createProduct(product)
        let package = root.appendingPathComponent("package")
        let source = try MacOSPortableSourceAssembler.assemble(
            product: MacOSPortableProduct(
                rootPath: product.path,
                productVersion: "0.2.0",
                ownerUID: geteuid(),
                signingCertificateSHA256: InstallDigest(String(repeating: "a", count: 64)),
                previousGenerationID: nil
            ),
            upstreams: ["192.0.2.53:53"],
            destinationRootPath: package.path,
            expectedOwnerUID: geteuid(),
            expectedGroupGID: getegid()
        )
        let authority = try FileSystemAuthority(testingRootPath: root.path)
        try body(Fixture(root: root, source: source, authority: authority))
    }

    private func createProduct(_ root: URL) throws {
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        let files = MacOSPortableProductContract.requiredFiles.union([
            "app/Remap.app/Contents/Info.plist",
            "app/Remap.app/Contents/MacOS/Remap"
        ])
        for relative in files {
            let path = root.appendingPathComponent(relative)
            try FileManager.default.createDirectory(
                at: path.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            try Data(relative.utf8).write(to: path)
        }
        for path in try root.descendantsIncludingSelf().reversed() {
            let directory = try path.resourceValues(forKeys: [.isDirectoryKey]).isDirectory == true
            let relative = String(path.path.dropFirst(root.path.count + 1))
            let executable = relative == "bin/remap"
                || relative.hasPrefix("libexec/")
                || relative == "app/Remap.app/Contents/MacOS/Remap"
            try setMode(path.path, directory || executable ? 0o500 : 0o400)
        }
    }

    private func assembleSource(
        root: URL,
        product: URL,
        name: String,
        upstream: String
    ) throws -> MacOSPortableSourcePackage {
        try MacOSPortableSourceAssembler.assemble(
            product: MacOSPortableProduct(
                rootPath: product.path,
                productVersion: name == "first" ? "0.2.0" : "0.2.1",
                ownerUID: geteuid(),
                signingCertificateSHA256: InstallDigest(String(repeating: "a", count: 64)),
                previousGenerationID: nil
            ),
            upstreams: [upstream],
            destinationRootPath: root.appendingPathComponent(name).path,
            expectedOwnerUID: geteuid(),
            expectedGroupGID: getegid()
        )
    }
}

private struct Fixture {
    let root: URL
    let source: MacOSPortableSourcePackage
    let authority: FileSystemAuthority

    func purge() throws -> MacOSPortableSourcePurge {
        try MacOSPortableSourcePurge(
            authority: authority,
            packagePath: InstallRelativePath(
                String(source.rootPath.dropFirst(root.path.count + 1))
            ),
            expectedManifestDigest: source.manifestDigest,
            ownerUID: UInt32(geteuid()),
            groupGID: UInt32(getegid())
        )
    }
}

private func setMode(_ path: String, _ mode: mode_t) throws {
    guard chmod(path, mode) == 0 else {
        throw POSIXError(.init(rawValue: errno) ?? .EIO)
    }
}

private extension URL {
    func descendantsIncludingSelf() throws -> [URL] {
        guard let enumerator = FileManager.default.enumerator(
            at: self,
            includingPropertiesForKeys: [.isDirectoryKey]
        ) else {
            throw CocoaError(.fileReadUnknown)
        }
        return [self] + enumerator.compactMap { $0 as? URL }
    }
}
