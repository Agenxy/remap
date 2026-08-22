import Darwin
import Foundation
import RemapControlKit
import RemapInstallKit

@main
enum RemapPortableInstallerMain {
    static func main() async {
        do {
            try await run()
        } catch {
            let message = if let installError = error as? InstallError {
                installError.description
            } else {
                String(describing: error)
            }
            report("Installation stopped safely: \(message)")
            exit(EXIT_FAILURE)
        }
    }

    private static func run() async throws {
        guard geteuid() == 0 else {
            throw InstallError.notRoot
        }
        let invocation = try PortableInstallerInvocation(
            arguments: CommandLine.arguments,
            environment: ProcessInfo.processInfo.environment
        )
        if invocation == .preinstall {
            report("The package is ready for local verification")
            return
        }
        report("Verifying the downloaded Remap release")
        let release = try PortableReleaseVerifier().verify()
        let installer = try MacOSInstaller.production()
        try await recoverInstaller(installer)
        let initialStatus = try installer.status()
        report("Preparing the local signing key")
        let identity = try PortableCodeSigningIdentityStore().ensure()
        report("Signing the verified Remap executables on this Mac")
        let prepared = try PortableProductPreparer().prepare(
            release: release,
            identity: identity,
            installerStatus: initialStatus
        )
        defer { prepared.removeWorkspace() }
        report("Updating Remap's local service authority")
        let authority = try PortableLifecycleAuthorityInstaller().install(
            prepared: prepared,
            activeGenerationID: initialStatus.activeGenerationID
        )
        do {
            let package = try await installProduct(
                installer: installer,
                prepared: prepared,
                initialStatus: initialStatus
            )
            try authority.markProductCommitted()
            try await verifyInstalledProduct(
                installer: installer,
                package: package,
                prepared: prepared,
                productVersion: release.manifest.productVersion
            )
            try authority.commit()
            try removePortableStaging()
            report("Remap \(release.manifest.productVersion) is installed and ready")
        } catch {
            let primary = error
            do {
                try authority.settleAfterFailure()
            } catch {
                throw InstallError.transaction(
                    primary: String(describing: primary),
                    recovery: String(describing: error)
                )
            }
            throw primary
        }
    }

    private static func recoverInstaller(_ installer: MacOSInstaller) async throws {
        let preview = try installer.previewRecovery(transactionID: nil)
        guard !preview.effects.isEmpty else {
            return
        }
        report("Finishing a previously interrupted Remap change")
        _ = try await installer.recoverAll(approvalToken: preview.approvalToken)
        guard try installer.previewRecovery(transactionID: nil).effects.isEmpty else {
            throw InstallError.integrity("the prior Remap change did not finish cleanly")
        }
    }

    private static func installProduct(
        installer: MacOSInstaller,
        prepared: PortablePreparedProduct,
        initialStatus: MacOSInstallerStatus
    ) async throws -> MacOSInstallSourcePackage {
        let package = try MacOSInstallSourcePackage(
            rootPath: prepared.sourcePackage.rootPath,
            expectedManifestDigest: prepared.sourcePackage.manifestDigest.description,
            sourceUID: 0
        )
        if initialStatus.activeGenerationID == package.manifest.generationID {
            report("Remap is already current; verifying the installed system")
            return package
        }
        let operation: InstallOperation = initialStatus.activeGenerationID == nil ? .install : .update
        let preview = try installer.preview(
            operation: operation,
            manifest: package.manifest,
            source: package.source
        )
        report(operation == .install ? "Installing Remap" : "Updating Remap")
        try await installer.installOrUpdate(
            operation: operation,
            transactionID: "portable-\(operation.rawValue)-\(UUID().uuidString.lowercased())",
            manifest: package.manifest,
            source: package.source,
            approvalToken: preview.approvalToken
        )
        return package
    }

    private static func verifyInstalledProduct(
        installer: MacOSInstaller,
        package: MacOSInstallSourcePackage,
        prepared: PortablePreparedProduct,
        productVersion: String
    ) async throws {
        let client = RemapControlClient(
            socketPath: prepared.ownerHomeDirectory
                + "/Library/Application Support/org.Agenxy.Remap/control.sock",
            clientVersion: productVersion
        )
        try await PortableInstalledReadinessVerifier().wait {
            let status = try installer.status()
            guard status.activeGenerationID == package.manifest.generationID,
                  status.transactions.allSatisfy({ !$0.recoveryRequired }),
                  status.services.allSatisfy(\.loaded),
                  status.dns.active,
                  status.dns.effectiveRemapServiceCount > 0
            else {
                return false
            }
            let runtime = await RemapRuntimeProbe.verify(client: client)
            return runtime.ready && runtime.daemonVersion == productVersion
        }
    }

    private static func removePortableStaging() throws {
        let path = PortableReleaseVerifier.releaseRoot
        guard FileManager.default.fileExists(atPath: path) else {
            return
        }
        try FileManager.default.removeItem(atPath: path)
        let parent = URL(fileURLWithPath: path).deletingLastPathComponent()
        if (try? FileManager.default.contentsOfDirectory(atPath: parent.path).isEmpty) == true {
            try FileManager.default.removeItem(at: parent)
        }
    }

    private static func report(_ message: String) {
        FileHandle.standardError.write(Data("Remap Installer: \(message).\n".utf8))
    }
}

private enum PortableInstallerInvocation: Equatable {
    static let packageIdentifier = "org.agenxy.Remap.PortableInstaller"

    case postinstall
    case preinstall

    init(arguments: [String], environment: [String: String]) throws {
        guard let executable = arguments.first,
              arguments.count <= 8,
              arguments.allSatisfy({ !$0.contains("\0") && $0.utf8.count <= 4096 }),
              let value = Self(rawValue: URL(fileURLWithPath: executable).lastPathComponent),
              environment["SCRIPT_NAME"] == value.rawValue,
              environment["INSTALL_PKG_SESSION_ID"] == Self.packageIdentifier,
              environment["DSTROOT"] == "/",
              environment["DSTVOLUME"] == "/",
              let packagePath = environment["PACKAGE_PATH"],
              packagePath.hasPrefix("/"),
              URL(fileURLWithPath: packagePath).standardizedFileURL.path == packagePath
        else {
            throw InstallError.integrity("the Apple Installer invocation is not exact")
        }
        self = value
    }

    private init?(rawValue: String) {
        switch rawValue {
        case "postinstall": self = .postinstall
        case "preinstall": self = .preinstall
        default: return nil
        }
    }

    private var rawValue: String {
        switch self {
        case .postinstall: "postinstall"
        case .preinstall: "preinstall"
        }
    }
}
