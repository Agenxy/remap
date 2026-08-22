import Darwin
import Foundation
import RemapInstallKit

enum PortableReleaseNodeKind: String, Codable, Equatable, Sendable {
    case directory
    case regularFile
}

struct PortableReleaseEntry: Codable, Equatable, Sendable {
    let path: InstallRelativePath
    let kind: PortableReleaseNodeKind
    let sha256: InstallDigest?
    let byteCount: UInt64?
    let mode: UInt16

    init(
        path: InstallRelativePath,
        kind: PortableReleaseNodeKind,
        sha256: InstallDigest?,
        byteCount: UInt64?,
        mode: UInt16
    ) throws {
        let regular = kind == .regularFile && sha256 != nil && byteCount != nil
        let directory = kind == .directory && sha256 == nil && byteCount == nil
        guard regular || directory,
              kind == .directory ? mode == 0o700 : mode == 0o400 || mode == 0o500,
              byteCount.map({ $0 <= 134_217_728 }) ?? true
        else {
            throw InstallError.invalidManifest("a portable release entry is malformed")
        }
        self.path = path
        self.kind = kind
        self.sha256 = sha256
        self.byteCount = byteCount
        self.mode = mode
    }
}

struct PortableReleaseManifest: Codable, Equatable, Sendable {
    static let schemaVersion: UInt32 = 1
    static let productIdentifier = "org.agenxy.Remap"
    static let maximumByteCount = 4_194_304

    let schemaVersion: UInt32
    let productIdentifier: String
    let productVersion: String
    let architecture: String
    let minimumMacOSVersion: String
    let entries: [PortableReleaseEntry]

    init(
        productVersion: String,
        architecture: String,
        minimumMacOSVersion: String,
        entries: [PortableReleaseEntry]
    ) throws {
        let identifierCharacters = CharacterSet.alphanumerics.union(
            CharacterSet(charactersIn: ".-+_")
        )
        guard !productVersion.isEmpty,
              productVersion.utf8.count <= 128,
              productVersion.unicodeScalars.allSatisfy(identifierCharacters.contains),
              ["arm64", "x86_64"].contains(architecture),
              minimumMacOSVersion == "15.0",
              !entries.isEmpty,
              entries.count <= 4096,
              entries == entries.sorted(by: { $0.path < $1.path }),
              Set(entries.map(\.path)).count == entries.count
        else {
            throw InstallError.invalidManifest("the portable release manifest is not canonical")
        }
        schemaVersion = Self.schemaVersion
        productIdentifier = Self.productIdentifier
        self.productVersion = productVersion
        self.architecture = architecture
        self.minimumMacOSVersion = minimumMacOSVersion
        self.entries = entries
    }

    func canonicalData() throws -> Data {
        try Self.encoder.encode(self)
    }

    static func decodeCanonical(_ data: Data) throws -> Self {
        guard data.count <= maximumByteCount else {
            throw InstallError.invalidManifest("the portable release manifest exceeds its byte bound")
        }
        let decoded = try Self.decoder.decode(Self.self, from: data)
        let rebuilt = try Self(
            productVersion: decoded.productVersion,
            architecture: decoded.architecture,
            minimumMacOSVersion: decoded.minimumMacOSVersion,
            entries: decoded.entries
        )
        guard decoded.schemaVersion == schemaVersion,
              decoded.productIdentifier == productIdentifier,
              rebuilt == decoded,
              try rebuilt.canonicalData() == data
        else {
            throw InstallError.invalidManifest("the portable release manifest is not canonical")
        }
        return rebuilt
    }

    private static let decoder = JSONDecoder()

    private static let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return encoder
    }()
}

struct PortableVerifiedRelease: Sendable {
    let rootPath: String
    let manifest: PortableReleaseManifest
    let manifestDigest: InstallDigest
}

struct PortableReleaseVerifier: Sendable {
    static let releaseRoot = "/Library/Application Support/Agenxy/Remap/Portable/Staged"
    static let manifestName = "release-manifest.json"
    static let signatureName = "release-manifest.json.sig"
    static let payloadName = "payload"
    static let signingIdentity = "remap-release"
    static let signingNamespace = "remap-release"
    static let releasePublicKey = """
    ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGDuwpKP+y7P4EN1/3snVhNRVTugTbFLTRZLvtA5P5kU remap-release-v1
    """

    private let runner: PortableCommandRunner

    init(runner: PortableCommandRunner = PortableCommandRunner()) {
        self.runner = runner
    }

    func verify() throws -> PortableVerifiedRelease {
        guard geteuid() == 0 else {
            throw InstallError.notRoot
        }
        try requireProtectedAncestry()
        let authority = try FileSystemAuthority(
            sourcePackageRootPath: Self.releaseRoot,
            ownerUID: 0
        )
        let rootChildren = try authority.listRootDirectory()
        guard rootChildren == [Self.payloadName, Self.manifestName, Self.signatureName].sorted() else {
            throw InstallError.integrity("the portable Remap release root has unexpected entries")
        }
        let manifestPath = try InstallRelativePath(Self.manifestName)
        let signaturePath = try InstallRelativePath(Self.signatureName)
        let payloadPath = try InstallRelativePath(Self.payloadName)
        try requireFile(authority, path: manifestPath, mode: 0o400)
        try requireFile(authority, path: signaturePath, mode: 0o400)
        try requireDirectory(authority, path: payloadPath, mode: 0o700)
        let manifestData = try authority.readUniqueFile(
            at: manifestPath,
            maximumByteCount: PortableReleaseManifest.maximumByteCount
        )
        let signatureData = try authority.readUniqueFile(at: signaturePath, maximumByteCount: 65536)
        try verifySignature(manifestData: manifestData, signatureData: signatureData)
        let manifest = try PortableReleaseManifest.decodeCanonical(manifestData)
        try requireHostArchitecture(manifest.architecture)
        let observed = try Self.entries(authority: authority, payloadPath: payloadPath)
        guard observed == manifest.entries else {
            throw InstallError.integrity("the portable Remap payload does not match its release manifest")
        }
        return PortableVerifiedRelease(
            rootPath: Self.releaseRoot + "/" + Self.payloadName,
            manifest: manifest,
            manifestDigest: InstallDigest.hash(manifestData)
        )
    }

    static func entries(
        authority: FileSystemAuthority,
        payloadPath: InstallRelativePath,
        expectedOwnerUID: uid_t = 0
    ) throws -> [PortableReleaseEntry] {
        var values: [PortableReleaseEntry] = []
        try walk(
            authority: authority,
            directory: payloadPath,
            relative: nil,
            expectedOwnerUID: expectedOwnerUID
        ) { path, relative in
            let metadata = try requireMetadata(
                authority,
                path: path,
                expectedOwnerUID: expectedOwnerUID
            )
            switch metadata.kind {
            case .directory:
                try values.append(
                    PortableReleaseEntry(
                        path: relative,
                        kind: .directory,
                        sha256: nil,
                        byteCount: nil,
                        mode: metadata.mode
                    )
                )
            case .regularFile:
                let data = try authority.readUniqueFile(
                    at: path,
                    maximumByteCount: 134_217_728
                )
                try values.append(
                    PortableReleaseEntry(
                        path: relative,
                        kind: .regularFile,
                        sha256: InstallDigest.hash(data),
                        byteCount: UInt64(data.count),
                        mode: metadata.mode
                    )
                )
            case .symbolicLink:
                throw InstallError.metadata("the portable release contains a symbolic link")
            }
            guard values.count <= 4096 else {
                throw InstallError.invalidManifest("the portable release exceeds its entry bound")
            }
        }
        return values.sorted { $0.path < $1.path }
    }

    private func verifySignature(manifestData: Data, signatureData: Data) throws {
        let workspace = try PortablePrivateWorkspace.create(prefix: "remap-release-verification")
        defer { workspace.remove() }
        let allowedSigners = workspace.url.appendingPathComponent("allowed-signers")
        let signature = workspace.url.appendingPathComponent("manifest.sig")
        let line = Self.signingIdentity + " " + Self.releasePublicKey + "\n"
        try Data(line.utf8).write(to: allowedSigners, options: [.withoutOverwriting])
        try signatureData.write(to: signature, options: [.withoutOverwriting])
        guard chmod(allowedSigners.path, 0o400) == 0 else {
            throw InstallError.operatingSystem("seal the release verification key", errno)
        }
        guard chmod(signature.path, 0o400) == 0 else {
            throw InstallError.operatingSystem("seal the release signature", errno)
        }
        let result = try runner.run(
            executable: "/usr/bin/ssh-keygen",
            arguments: [
                "-Y", "verify",
                "-f", allowedSigners.path,
                "-I", Self.signingIdentity,
                "-n", Self.signingNamespace,
                "-s", signature.path
            ],
            input: manifestData
        )
        guard result.exitStatus == 0 else {
            throw InstallError.integrity("the portable Remap release signature is invalid")
        }
    }

    private func requireHostArchitecture(_ expected: String) throws {
        var system = utsname()
        guard uname(&system) == 0 else {
            throw InstallError.operatingSystem("inspect the target Mac architecture", errno)
        }
        let machine = withUnsafePointer(to: &system.machine) {
            $0.withMemoryRebound(to: CChar.self, capacity: Int(_SYS_NAMELEN)) {
                String(cString: $0)
            }
        }
        guard machine == expected else {
            throw InstallError.unsupported(
                "this Remap package is for \(expected), but this Mac is \(machine)"
            )
        }
    }

    private static func walk(
        authority: FileSystemAuthority,
        directory: InstallRelativePath,
        relative: InstallRelativePath?,
        expectedOwnerUID: uid_t,
        visit: (InstallRelativePath, InstallRelativePath) throws -> Void
    ) throws {
        for name in try authority.listDirectory(at: directory) {
            let child = try directory.appending(component: name)
            let childRelative = if let relative {
                try relative.appending(component: name)
            } else {
                try InstallRelativePath(name)
            }
            try visit(child, childRelative)
            if try requireMetadata(
                authority,
                path: child,
                expectedOwnerUID: expectedOwnerUID
            ).kind == .directory {
                try walk(
                    authority: authority,
                    directory: child,
                    relative: childRelative,
                    expectedOwnerUID: expectedOwnerUID,
                    visit: visit
                )
            }
        }
    }

    private func requireProtectedAncestry() throws {
        let system = try FileSystemAuthority(systemRootPath: "/")
        let path = try InstallRelativePath(
            "Library/Application Support/Agenxy/Remap/Portable/Staged"
        )
        guard try system.metadata(at: path)?.kind == .directory else {
            throw InstallError.metadata("the portable release root is not a directory")
        }
    }

    private func requireFile(
        _ authority: FileSystemAuthority,
        path: InstallRelativePath,
        mode: UInt16
    ) throws {
        let metadata = try Self.requireMetadata(authority, path: path)
        guard metadata.kind == .regularFile,
              metadata.mode == mode,
              metadata.linkCount == 1
        else {
            throw InstallError.metadata("a portable release file has unsafe metadata")
        }
    }

    private func requireDirectory(
        _ authority: FileSystemAuthority,
        path: InstallRelativePath,
        mode: UInt16
    ) throws {
        let metadata = try Self.requireMetadata(authority, path: path)
        guard metadata.kind == .directory, metadata.mode == mode else {
            throw InstallError.metadata("a portable release directory has unsafe metadata")
        }
    }

    private static func requireMetadata(
        _ authority: FileSystemAuthority,
        path: InstallRelativePath,
        expectedOwnerUID: uid_t = 0
    ) throws -> InstallNodeMetadata {
        guard let metadata = try authority.metadata(at: path),
              metadata.ownerUID == expectedOwnerUID,
              metadata.groupGID == (expectedOwnerUID == 0 ? 0 : getegid()),
              !metadata.hasACL,
              metadata.flags == 0,
              metadata.kind == .directory
              ? metadata.mode == 0o700
              : metadata.mode == 0o400 || metadata.mode == 0o500
        else {
            throw InstallError.metadata("a portable release node has an unsafe mode")
        }
        return metadata
    }
}
