import Darwin
import Foundation
import RemapInstallKit
import RemapLifecycleKit
import RemapSystemKit

struct PortablePreparedProduct: Sendable {
    let sourcePackage: MacOSPortableSourcePackage
    let bootstrapPath: String
    let bootstrapIdentity: RemapLifecycleCodeIdentity
    let servicePath: String
    let serviceIdentity: RemapLifecycleCodeIdentity
    let appIdentity: RemapLifecycleCodeIdentity
    let clientIdentity: RemapLifecycleCodeIdentity
    let ownerUID: UInt32
    let ownerHomeDirectory: String
    let workspacePath: String

    func removeWorkspace() {
        try? FileManager.default.removeItem(atPath: workspacePath)
    }
}

struct PortableProductPreparer: Sendable {
    private let signer: PortableCodeSigner

    init(signer: PortableCodeSigner = PortableCodeSigner()) {
        self.signer = signer
    }

    func prepare(
        release: PortableVerifiedRelease,
        identity: PortableCodeSigningIdentity,
        installerStatus: MacOSInstallerStatus
    ) throws -> PortablePreparedProduct {
        let account = try PortableConsoleAccount.current()
        let workspace = try PortablePrivateWorkspace.create(prefix: "remap-portable-product")
        var keepWorkspace = false
        defer {
            if !keepWorkspace {
                workspace.remove()
            }
        }
        let productSource = URL(fileURLWithPath: release.rootPath, isDirectory: true)
            .appendingPathComponent("product", isDirectory: true)
        let lifecycleSource = URL(fileURLWithPath: release.rootPath, isDirectory: true)
            .appendingPathComponent("lifecycle", isDirectory: true)
        let product = workspace.url.appendingPathComponent("product", isDirectory: true)
        let lifecycle = workspace.url.appendingPathComponent("lifecycle", isDirectory: true)
        try copyTree(productSource, to: product)
        try copyTree(lifecycleSource, to: lifecycle)
        try requireProductContract(product)
        let cli = try sign(product, "bin/remap", "org.agenxy.Remap.cli", identity)
        _ = cli
        _ = try sign(product, "libexec/remapd", "org.agenxy.Remap.daemon", identity)
        _ = try sign(
            product,
            "libexec/remap-install",
            "org.agenxy.Remap.install-bootstrap",
            identity
        )
        _ = try sign(product, "libexec/remap-resolver", "org.agenxy.Remap.resolver", identity)
        _ = try sign(product, "libexec/remap-system", "org.agenxy.Remap.system", identity)
        let clientIdentity = try sign(
            product,
            "libexec/remap-lifecycle",
            "org.agenxy.Remap.lifecycle-cli",
            identity
        )
        let appIdentity = try signer.sign(
            path: product.appendingPathComponent("app/Remap.app", isDirectory: true).path,
            identifier: "org.agenxy.Remap",
            identity: identity
        )
        let bootstrapPath = lifecycle.appendingPathComponent("remap-installer-bootstrap").path
        let servicePath = lifecycle.appendingPathComponent("remap-installer-service").path
        let bootstrapIdentity = try signer.sign(
            path: bootstrapPath,
            identifier: "org.agenxy.Remap.installer-bootstrap",
            identity: identity
        )
        let serviceIdentity = try signer.sign(
            path: servicePath,
            identifier: "org.agenxy.Remap.installer-service",
            identity: identity
        )
        try seal(product)
        try seal(lifecycle)
        try PortableInstallTopology.ensureSourceDirectory()
        let upstreams = try resolverUpstreams()
        let temporarySource = PortableInstallTopology.sourcesPath
            + "/.assembling-\(UUID().uuidString.lowercased())"
        let portable = try MacOSPortableProduct(
            rootPath: product.path,
            productVersion: release.manifest.productVersion,
            ownerUID: account.uid,
            signingCertificateSHA256: identity.sha256,
            previousGenerationID: installerStatus.activeGenerationID
        )
        let assembled = try MacOSPortableSourceAssembler.assemble(
            product: portable,
            upstreams: upstreams,
            destinationRootPath: temporarySource
        )
        let finalSource = PortableInstallTopology.sourcesPath
            + "/\(assembled.manifestDigest.description)"
        try publishSource(temporary: temporarySource, final: finalSource, package: assembled)
        keepWorkspace = true
        return PortablePreparedProduct(
            sourcePackage: MacOSPortableSourcePackage(
                rootPath: finalSource,
                manifestDigest: assembled.manifestDigest,
                generationID: assembled.generationID
            ),
            bootstrapPath: bootstrapPath,
            bootstrapIdentity: bootstrapIdentity,
            servicePath: servicePath,
            serviceIdentity: serviceIdentity,
            appIdentity: appIdentity,
            clientIdentity: clientIdentity,
            ownerUID: account.uid,
            ownerHomeDirectory: account.homeDirectory,
            workspacePath: workspace.url.path
        )
    }

    private func resolverUpstreams() throws -> [String] {
        let resolver = SystemResolver()
        let plan: DNSPlan = if let record = try resolver.activeRecord() {
            try resolver.reconciliationPlan(record: record)
        } else {
            try resolver.plan()
        }
        return try MacOSInstallerResolverPlan(
            serviceCount: plan.services.count,
            upstreamAddresses: plan.upstreams
        ).upstreams
    }

    private func sign(
        _ root: URL,
        _ relative: String,
        _ identifier: String,
        _ identity: PortableCodeSigningIdentity
    ) throws -> RemapLifecycleCodeIdentity {
        try signer.sign(
            path: root.appendingPathComponent(relative).path,
            identifier: identifier,
            identity: identity
        )
    }

    private func publishSource(
        temporary: String,
        final: String,
        package: MacOSPortableSourcePackage
    ) throws {
        if renamex_np(temporary, final, UInt32(RENAME_EXCL)) == 0 {
            return
        }
        guard errno == EEXIST else {
            throw InstallError.operatingSystem("publish the locally signed source package", errno)
        }
        _ = try MacOSInstallSourcePackage(
            rootPath: final,
            expectedManifestDigest: package.manifestDigest.description,
            sourceUID: 0
        )
        try FileManager.default.removeItem(atPath: temporary)
    }

    private func copyTree(_ source: URL, to destination: URL) throws {
        let metadata = try node(source.path)
        guard metadata.kind == .directory else {
            throw InstallError.invalidManifest("the portable release is missing one product directory")
        }
        try FileManager.default.createDirectory(
            at: destination,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        let children = try FileManager.default.contentsOfDirectory(
            at: source,
            includingPropertiesForKeys: nil
        ).sorted { $0.lastPathComponent < $1.lastPathComponent }
        for child in children {
            let observed = try node(child.path)
            let target = destination.appendingPathComponent(child.lastPathComponent)
            switch observed.kind {
            case .directory:
                try copyTree(child, to: target)
            case .regularFile:
                let data = try Data(contentsOf: child, options: [.mappedIfSafe])
                guard UInt64(data.count) == observed.byteCount else {
                    throw InstallError.integrity("a portable release file changed during preparation")
                }
                try data.write(to: target, options: [.withoutOverwriting])
                guard chmod(target.path, observed.mode & 0o111 == 0 ? 0o600 : 0o700) == 0 else {
                    throw InstallError.operatingSystem("prepare a portable product file", errno)
                }
            }
        }
    }

    private func seal(_ root: URL) throws {
        let children = try FileManager.default.contentsOfDirectory(
            at: root,
            includingPropertiesForKeys: nil
        ).sorted { $0.lastPathComponent > $1.lastPathComponent }
        for child in children {
            let observed = try node(child.path)
            if observed.kind == .directory {
                try seal(child)
                guard chmod(child.path, 0o500) == 0 else {
                    throw InstallError.operatingSystem("seal a portable product directory", errno)
                }
            } else {
                guard chmod(child.path, observed.mode & 0o111 == 0 ? 0o400 : 0o500) == 0 else {
                    throw InstallError.operatingSystem("seal a portable product file", errno)
                }
            }
        }
        guard chmod(root.path, 0o500) == 0 else {
            throw InstallError.operatingSystem("seal a portable product root", errno)
        }
    }

    private func requireProductContract(_ product: URL) throws {
        for relative in Self.requiredProductFiles {
            guard try node(product.appendingPathComponent(relative).path).kind == .regularFile else {
                throw InstallError.invalidManifest("the portable release is missing \(relative)")
            }
        }
        for relative in Self.requiredProductDirectories {
            guard try node(product.appendingPathComponent(relative).path).kind == .directory else {
                throw InstallError.invalidManifest("the portable release is missing \(relative)")
            }
        }
    }

    private func node(_ path: String) throws -> Node {
        var status = stat()
        guard lstat(path, &status) == 0,
              status.st_uid == 0,
              status.st_gid == 0,
              status.st_flags == 0,
              status.st_nlink == 1 || status.st_mode & S_IFMT == S_IFDIR
        else {
            throw InstallError.metadata("a portable release node has unsafe metadata")
        }
        let kind: NodeKind
        switch status.st_mode & S_IFMT {
        case S_IFDIR:
            kind = .directory
        case S_IFREG:
            kind = .regularFile
        default:
            throw InstallError.metadata("the portable release contains a link or special file")
        }
        guard status.st_size >= 0, status.st_size <= 134_217_728 else {
            throw InstallError.metadata("a portable release file exceeds its size bound")
        }
        return Node(
            kind: kind,
            mode: mode_t(status.st_mode & 0o777),
            byteCount: UInt64(status.st_size)
        )
    }

    private enum NodeKind {
        case directory
        case regularFile
    }

    private struct Node {
        let kind: NodeKind
        let mode: mode_t
        let byteCount: UInt64
    }

    private static let manpages = [
        "remap-apply.1", "remap-completions.1", "remap-daemon.1", "remap-disable.1",
        "remap-doctor.1", "remap-enable.1", "remap-get.1", "remap-list.1",
        "remap-manpage.1", "remap-manpages.1", "remap-mcp.1", "remap-preview.1",
        "remap-remove.1", "remap-resolve.1", "remap-set.1", "remap-status.1",
        "remap-system-recover.1", "remap-system-status.1", "remap-system-uninstall.1",
        "remap-system.1", "remap-validate.1", "remap.1"
    ]

    private static let requiredProductFiles = Set([
        "bin/remap", "libexec/remap-install", "libexec/remap-lifecycle", "libexec/remap-resolver",
        "libexec/remap-system", "libexec/remapd", "share/completions/remap.bash",
        "share/completions/remap.fish", "share/completions/remap.zsh",
        "share/licenses/remap/LICENSE", "share/licenses/remap/NOTICE"
    ]).union(manpages.map { "share/man/man1/\($0)" })

    private static let requiredProductDirectories: Set<String> = [
        "app", "app/Remap.app", "bin", "libexec", "share", "share/completions",
        "share/licenses", "share/licenses/remap", "share/man", "share/man/man1"
    ]
}

private struct PortableConsoleAccount: Sendable {
    let uid: UInt32
    let homeDirectory: String

    static func current() throws -> Self {
        var console = stat()
        guard lstat("/dev/console", &console) == 0,
              console.st_uid > 0,
              let account = getpwuid(console.st_uid),
              let name = account.pointee.pw_name,
              let home = account.pointee.pw_dir
        else {
            throw InstallError.approval("sign in to a normal Mac account before installing Remap")
        }
        let userName = String(cString: name)
        let homeDirectory = String(cString: home)
        guard !userName.isEmpty,
              !homeDirectory.isEmpty,
              homeDirectory.hasPrefix("/Users/"),
              URL(fileURLWithPath: homeDirectory).standardizedFileURL.path == homeDirectory
        else {
            throw InstallError.approval("the active Mac account is not a supported Remap owner")
        }
        return Self(uid: console.st_uid, homeDirectory: homeDirectory)
    }
}
