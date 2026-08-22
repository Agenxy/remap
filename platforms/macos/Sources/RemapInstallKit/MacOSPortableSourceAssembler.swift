import Darwin
import Foundation

/// Builds the canonical root-owned source image used by the portable macOS installer.
public enum MacOSPortableSourceAssembler {
    public static func assemble(
        product: MacOSPortableProduct,
        upstreams: [String],
        destinationRootPath: String
    ) throws -> MacOSPortableSourcePackage {
        guard geteuid() == 0 else {
            throw InstallError.notRoot
        }
        return try assemble(
            product: product,
            upstreams: upstreams,
            destinationRootPath: destinationRootPath,
            expectedOwnerUID: 0,
            expectedGroupGID: 0
        )
    }

    static func assemble(
        product: MacOSPortableProduct,
        upstreams: [String],
        destinationRootPath: String,
        expectedOwnerUID: uid_t,
        expectedGroupGID: gid_t
    ) throws -> MacOSPortableSourcePackage {
        let destination = URL(fileURLWithPath: destinationRootPath, isDirectory: true)
        try requirePrivateParent(
            destination.deletingLastPathComponent(),
            ownerUID: expectedOwnerUID,
            groupGID: expectedGroupGID
        )
        guard !FileManager.default.fileExists(atPath: destination.path) else {
            throw InstallError.collision(destination.path)
        }
        try FileManager.default.createDirectory(
            at: destination,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        var completed = false
        defer {
            if !completed {
                try? FileManager.default.removeItem(at: destination)
            }
        }
        let payload = destination.appendingPathComponent("payload", isDirectory: true)
        try MacOSPortableFileTree.copyProduct(
            from: product.rootPath,
            to: payload.path,
            ownerUID: expectedOwnerUID,
            groupGID: expectedGroupGID
        )
        let account = try MacOSAccountLookup.account(for: product.ownerUID)
        let dataDirectory = account.homeDirectory.value
            + "/Library/Application Support/org.Agenxy.Remap"
        try writeConfiguration(
            payload: payload,
            ownerUID: product.ownerUID,
            dataDirectory: dataDirectory,
            signingCertificateSHA256: product.signingCertificateSHA256
        )
        let initialEntries = try MacOSPortableFileTree.entries(payloadPath: payload.path)
        let generationID = try MacOSPortableManifestBuilder.generationID(
            productVersion: product.productVersion,
            entries: initialEntries,
            account: account,
            ownerUID: product.ownerUID,
            dataDirectory: dataDirectory,
            upstreams: upstreams
        )
        try writeLaunchd(
            payload: payload,
            generationID: generationID,
            account: account,
            ownerUID: product.ownerUID,
            dataDirectory: dataDirectory,
            upstreams: upstreams
        )
        let entries = try MacOSPortableFileTree.entries(payloadPath: payload.path)
        let manifest = try InstallManifest(
            productIdentifier: MacOSPortableProductContract.productIdentifier,
            generationID: generationID,
            productVersion: product.productVersion,
            previousGenerationID: product.previousGenerationID,
            entries: entries,
            publications: MacOSPortableManifestBuilder.publications(
                generationID: generationID,
                entries: entries
            )
        )
        let manifestData = try manifest.canonicalData()
        let manifestURL = destination.appendingPathComponent("manifest.json")
        try manifestData.write(to: manifestURL, options: [.withoutOverwriting])
        try MacOSPortableFileTree.sealPackage(rootPath: destination.path)
        let digest = InstallDigest.hash(manifestData)
        let decoded = try InstallManifest.decodeCanonical(manifestData, expectedDigest: digest)
        guard decoded == manifest else {
            throw InstallError.integrity("the portable source manifest changed during assembly")
        }
        completed = true
        return MacOSPortableSourcePackage(
            rootPath: destination.path,
            manifestDigest: digest,
            generationID: generationID
        )
    }

    private static func writeConfiguration(
        payload: URL,
        ownerUID: UInt32,
        dataDirectory: String,
        signingCertificateSHA256: InstallDigest
    ) throws {
        let configuration = try MacOSInstallConfiguration(
            ownerUID: ownerUID,
            dataDirectory: InstallAbsolutePath(dataDirectory),
            controlSocket: InstallAbsolutePath(dataDirectory + "/control.sock"),
            signingCertificateSHA256: signingCertificateSHA256
        )
        let data = try InstallCanonicalJSON.encoder.encode(configuration)
        try data.write(
            to: payload.appendingPathComponent(MacOSInstallConfiguration.entryName),
            options: [.withoutOverwriting]
        )
    }

    private static func writeLaunchd(
        payload: URL,
        generationID: String,
        account: MacOSAccount,
        ownerUID: UInt32,
        dataDirectory: String,
        upstreams: [String]
    ) throws {
        let documents = try MacOSPortableLaunchd.documents(
            generationID: generationID,
            account: account,
            ownerUID: ownerUID,
            dataDirectory: dataDirectory,
            upstreams: upstreams
        )
        let directory = payload.appendingPathComponent("launchd", isDirectory: true)
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        for (label, document) in documents.sorted(by: { $0.key < $1.key }) {
            let data = try PropertyListSerialization.data(
                fromPropertyList: document,
                format: .xml,
                options: 0
            )
            try data.write(
                to: directory.appendingPathComponent(label + ".plist"),
                options: [.withoutOverwriting]
            )
        }
    }

    private static func requirePrivateParent(
        _ parent: URL,
        ownerUID: uid_t,
        groupGID: gid_t
    ) throws {
        var status = stat()
        guard lstat(parent.path, &status) == 0,
              status.st_mode & S_IFMT == S_IFDIR,
              status.st_uid == ownerUID,
              status.st_gid == groupGID,
              status.st_mode & 0o777 == 0o700,
              status.st_flags == 0
        else {
            throw InstallError.metadata("the portable source parent has unsafe metadata")
        }
    }
}
