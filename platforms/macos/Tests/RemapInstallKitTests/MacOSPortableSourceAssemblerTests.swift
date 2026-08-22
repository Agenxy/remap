import Darwin
import Foundation
@testable import RemapInstallKit
import Testing

@Suite("Portable macOS source assembly")
struct MacOSPortableSourceAssemblerTests {
    @Test("locally signed product bytes produce one deterministic canonical source image")
    func deterministicSourceImage() throws {
        try withTemporaryDirectory { root in
            let product = root.appendingPathComponent("product", isDirectory: true)
            try createProduct(at: product)
            let sources = root.appendingPathComponent("sources", isDirectory: true)
            try FileManager.default.createDirectory(at: sources, withIntermediateDirectories: false)
            try setMode(sources, 0o700)
            let descriptor = try MacOSPortableProduct(
                rootPath: product.path,
                productVersion: "0.2.0",
                ownerUID: geteuid(),
                signingCertificateSHA256: InstallDigest(String(repeating: "a", count: 64)),
                previousGenerationID: nil
            )
            let first = try assemble(descriptor, destination: sources.appendingPathComponent("first"))
            let second = try assemble(descriptor, destination: sources.appendingPathComponent("second"))
            #expect(first.manifestDigest == second.manifestDigest)
            #expect(first.generationID == second.generationID)
            let data = try Data(contentsOf: URL(fileURLWithPath: first.rootPath)
                .appendingPathComponent("manifest.json"))
            let manifest = try InstallManifest.decodeCanonical(data, expectedDigest: first.manifestDigest)
            #expect(manifest.generationID == first.generationID)
            #expect(manifest.entries.contains { $0.path.description == "bin/remap" && $0.role == .commandLineTool })
            #expect(manifest.entries.contains { $0.path.description == "libexec/remapd" && $0.role == .daemon })
            #expect(manifest.publications.contains { $0.path.description == "usr/local/bin/remap" })
            #expect(manifest.publications.contains { $0.path.description == "Applications/Remap.app" })
            #expect(manifest.publications.count == 45)
        }
    }

    private func assemble(
        _ product: MacOSPortableProduct,
        destination: URL
    ) throws -> MacOSPortableSourcePackage {
        try MacOSPortableSourceAssembler.assemble(
            product: product,
            upstreams: ["192.0.2.53:53"],
            destinationRootPath: destination.path,
            expectedOwnerUID: geteuid(),
            expectedGroupGID: getegid()
        )
    }

    private func createProduct(at root: URL) throws {
        let files = MacOSPortableProductContract.requiredFiles.union([
            "app/Remap.app/Contents/Info.plist",
            "app/Remap.app/Contents/MacOS/Remap"
        ])
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        for relative in files.sorted() {
            let destination = root.appendingPathComponent(relative)
            try FileManager.default.createDirectory(
                at: destination.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            try Data("portable:\(relative)".utf8).write(to: destination)
        }
        let executableFiles = files.filter {
            $0 == "bin/remap"
                || $0.hasPrefix("libexec/")
                || $0 == "app/Remap.app/Contents/MacOS/Remap"
        }
        for path in try root.descendantsIncludingSelf().reversed() {
            let isDirectory = try path.resourceValues(forKeys: [.isDirectoryKey]).isDirectory == true
            let relative = path == root ? "" : String(path.path.dropFirst(root.path.count + 1))
            try setMode(path, isDirectory || executableFiles.contains(relative) ? 0o500 : 0o400)
        }
    }

    private func setMode(_ url: URL, _ mode: mode_t) throws {
        guard chmod(url.path, mode) == 0 else {
            throw POSIXError(.init(rawValue: errno) ?? .EIO)
        }
    }

    private func withTemporaryDirectory(_ body: (URL) throws -> Void) throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("remap-portable-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        try setMode(root, 0o700)
        defer { try? FileManager.default.removeItem(at: root) }
        try body(root)
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
