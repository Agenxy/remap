import Darwin
import Foundation
@testable import RemapInstallKit
import Synchronization
import Testing

@Suite("Portable authority cleanup")
struct MacOSPortableAuthorityCleanupTests {
    @Test("the exact portable authority is removed and the stable parent remains")
    func exactAuthorityIsRemoved() throws {
        try withFixture { fixture in
            let plan = try fixture.plan()
            try fixture.cleanup.prepare(plan)
            try fixture.cleanup.perform(expectedApprovalToken: plan.approvalToken)

            #expect(!FileManager.default.fileExists(atPath: fixture.remapRoot.path))
            for path in MacOSPortableAuthorityFileState.specifications.keys {
                #expect(!FileManager.default.fileExists(atPath: fixture.root.path + "/" + path))
            }
            #expect(FileManager.default.fileExists(atPath: fixture.agenxyRoot.path))
        }
    }

    @Test("unexpected installer content blocks cleanup without deleting it")
    func foreignContentIsPreserved() throws {
        try withFixture { fixture in
            let foreign = fixture.installerRoot.appendingPathComponent("foreign")
            try Data("foreign".utf8).write(to: foreign)
            try setMode(foreign.path, 0o400)

            #expect(throws: InstallError.self) {
                _ = try fixture.capture()
            }
            #expect(try Data(contentsOf: foreign) == Data("foreign".utf8))
        }
    }

    @Test("cleanup resumes after an exact authority file is already absent")
    func partialCleanupResumes() throws {
        try withFixture { fixture in
            let plan = try fixture.plan()
            try fixture.cleanup.prepare(plan)
            let helper = fixture.root.appendingPathComponent(
                "Library/PrivilegedHelperTools/org.agenxy.Remap.installer-service"
            )
            try FileManager.default.removeItem(at: helper)

            try fixture.cleanup.perform(expectedApprovalToken: plan.approvalToken)
            #expect(!FileManager.default.fileExists(atPath: fixture.remapRoot.path))
        }
    }

    @Test("a prepared plan is discarded only when the installed product is unchanged")
    func preparedPlanIsDiscardedForUnchangedProduct() throws {
        try withFixture { fixture in
            let plan = try fixture.plan()
            let unchanged = fixture.cleanup(productIsAbsent: false, productMatchesApproval: true)
            try unchanged.prepare(plan)

            #expect(try unchanged.reconcilePendingPlan() == .discarded)
            #expect(try unchanged.pendingPlan() == nil)
            #expect(FileManager.default.fileExists(atPath: fixture.sourceURL.path))
            for path in MacOSPortableAuthorityFileState.specifications.keys {
                #expect(FileManager.default.fileExists(atPath: fixture.root.path + "/" + path))
            }
        }
    }

    @Test("a prepared plan completes cleanup after the product is absent")
    func preparedPlanCompletesAfterProductRemoval() throws {
        try withFixture { fixture in
            let plan = try fixture.plan()
            let beforeRemoval = fixture.cleanup(
                productIsAbsent: false,
                productMatchesApproval: true
            )
            try beforeRemoval.prepare(plan)

            let afterRemoval = fixture.cleanup(
                productIsAbsent: true,
                productMatchesApproval: false
            )
            #expect(try afterRemoval.reconcilePendingPlan() == .completed)
            #expect(!FileManager.default.fileExists(atPath: fixture.remapRoot.path))
        }
    }

    @Test("ambiguous product state preserves the prepared plan and authority")
    func ambiguousProductStateFailsClosed() throws {
        try withFixture { fixture in
            let plan = try fixture.plan()
            try fixture.cleanup(
                productIsAbsent: false,
                productMatchesApproval: true
            ).prepare(plan)

            let ambiguous = fixture.cleanup(
                productIsAbsent: false,
                productMatchesApproval: false
            )
            #expect(throws: InstallError.self) {
                _ = try ambiguous.reconcilePendingPlan()
            }
            #expect(try ambiguous.pendingPlan() == plan)
            #expect(FileManager.default.fileExists(atPath: fixture.sourceURL.path))
        }
    }

    @Test("the recovery plan and helper remain through the bootout boundary")
    func recoveryEvidenceOutlivesBootoutBoundary() throws {
        try withFixture { fixture in
            let plan = try fixture.plan()
            try fixture.cleanup.prepare(plan)
            let helper = fixture.root.path
                + "/Library/PrivilegedHelperTools/org.agenxy.Remap.installer-service"
            let planPath = fixture.root.path + "/"
                + MacOSPortableAuthorityCleanupState.planPathString
            let observedBoth = Mutex(false)

            try fixture.cleanup.perform(expectedApprovalToken: plan.approvalToken) {
                observedBoth.withLock {
                    $0 = access(helper, F_OK) == 0 && access(planPath, F_OK) == 0
                }
            }

            #expect(observedBoth.withLock { $0 })
            #expect(access(helper, F_OK) != 0)
            #expect(access(planPath, F_OK) != 0)
        }
    }

    @Test("a failed bootout boundary retains exact recovery evidence and resumes")
    func failedBootoutBoundaryResumes() throws {
        try withFixture { fixture in
            let plan = try fixture.plan()
            try fixture.cleanup.prepare(plan)
            let helper = fixture.root.path
                + "/Library/PrivilegedHelperTools/org.agenxy.Remap.installer-service"
            let planPath = fixture.root.path + "/"
                + MacOSPortableAuthorityCleanupState.planPathString

            #expect(throws: CleanupBoundaryFailure.self) {
                try fixture.cleanup.perform(expectedApprovalToken: plan.approvalToken) {
                    throw CleanupBoundaryFailure()
                }
            }
            #expect(access(helper, F_OK) == 0)
            #expect(access(planPath, F_OK) == 0)
            #expect(try fixture.cleanup.pendingPlan() == plan)

            try fixture.cleanup.perform(expectedApprovalToken: plan.approvalToken)
            #expect(!FileManager.default.fileExists(atPath: fixture.remapRoot.path))
            #expect(access(planPath, F_OK) != 0)
        }
    }

    @Test("signing identity removal is digest-bound and remains recoverable on failure")
    func signingIdentityRemovalIsBoundAndRecoverable() throws {
        try withFixture { fixture in
            let plan = try fixture.plan()
            let observed = Mutex<InstallDigest?>(nil)
            let cleanup = fixture.cleanup(
                productIsAbsent: true,
                productMatchesApproval: true,
                removeSigningIdentity: { digest in
                    observed.withLock { $0 = digest }
                    throw CleanupBoundaryFailure()
                }
            )
            try cleanup.prepare(plan)

            #expect(throws: CleanupBoundaryFailure.self) {
                try cleanup.perform(expectedApprovalToken: plan.approvalToken)
            }
            #expect(observed.withLock { $0 } == plan.state.signingCertificateSHA256)
            #expect(try cleanup.pendingPlan() == plan)
            let helper = fixture.root.path
                + "/Library/PrivilegedHelperTools/org.agenxy.Remap.installer-service"
            #expect(access(helper, F_OK) == 0)
        }
    }

    @Test("cleanup forgets only the package receipt bound into the approval")
    func cleanupForgetsTheApprovedPackageReceipt() throws {
        try withFixture { fixture in
            let receipt = TestPackageReceipt(version: "0.2.0")
            let plan = try fixture.plan(packageReceiptVersion: "0.2.0")
            try fixture.cleanup(
                productIsAbsent: false,
                productMatchesApproval: true,
                packageReceipt: receipt
            ).prepare(plan)

            try fixture.cleanup(
                productIsAbsent: true,
                productMatchesApproval: false,
                packageReceipt: receipt
            ).perform(expectedApprovalToken: plan.approvalToken)
            #expect(try receipt.version() == nil)
        }
    }

    @Test("receipt drift blocks cleanup before authority bytes are removed")
    func receiptDriftBlocksCleanup() throws {
        try withFixture { fixture in
            let receipt = TestPackageReceipt(version: "0.2.0")
            let plan = try fixture.plan(packageReceiptVersion: "0.2.0")
            try fixture.cleanup(
                productIsAbsent: false,
                productMatchesApproval: true,
                packageReceipt: receipt
            ).prepare(plan)
            receipt.setVersion("0.2.1")

            #expect(throws: InstallError.self) {
                try fixture.cleanup(
                    productIsAbsent: true,
                    productMatchesApproval: false,
                    packageReceipt: receipt
                ).perform(expectedApprovalToken: plan.approvalToken)
            }
            #expect(FileManager.default.fileExists(atPath: fixture.sourceURL.path))
        }
    }

    private func withFixture(_ body: (CleanupFixture) throws -> Void) throws {
        let fixture = try CleanupFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        try body(fixture)
    }
}

private struct CleanupBoundaryFailure: Error {}

private struct CleanupFixture {
    let root: URL
    let agenxyRoot: URL
    let remapRoot: URL
    let installerRoot: URL
    let authority: FileSystemAuthority
    let sourceRoot: InstallAbsolutePath
    let sourceDigest: InstallDigest
    let cleanup: MacOSPortableAuthorityCleanup

    var sourceURL: URL {
        root.appendingPathComponent(sourceRoot.description)
    }

    init() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent(
            "remap-authority-cleanup-\(UUID().uuidString.lowercased())"
        )
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        try setMode(root.path, 0o700)
        agenxyRoot = root.appendingPathComponent("Library/Application Support/Agenxy")
        remapRoot = agenxyRoot.appendingPathComponent("Remap")
        installerRoot = remapRoot.appendingPathComponent("Installer")
        try FileManager.default.createDirectory(
            at: installerRoot.appendingPathComponent("Sources"),
            withIntermediateDirectories: true
        )
        try setMode(remapRoot.path, 0o711)
        try setMode(installerRoot.path, 0o700)
        try setMode(installerRoot.appendingPathComponent("Sources").path, 0o700)

        let product = root.appendingPathComponent("product")
        try createProduct(product)
        let assembled = installerRoot.appendingPathComponent("Sources/.assembling")
        let source = try MacOSPortableSourceAssembler.assemble(
            product: MacOSPortableProduct(
                rootPath: product.path,
                productVersion: "0.2.0",
                ownerUID: geteuid(),
                signingCertificateSHA256: InstallDigest(String(repeating: "a", count: 64)),
                previousGenerationID: nil
            ),
            upstreams: ["192.0.2.53:53"],
            destinationRootPath: assembled.path,
            expectedOwnerUID: geteuid(),
            expectedGroupGID: getegid()
        )
        let final = installerRoot.appendingPathComponent("Sources/\(source.manifestDigest)")
        try FileManager.default.moveItem(at: assembled, to: final)
        sourceRoot = try InstallAbsolutePath(
            "/" + MacOSPortableAuthorityCleanupState.sourcesPathString
                + "/\(source.manifestDigest)"
        )
        sourceDigest = source.manifestDigest

        for (relative, mode) in MacOSPortableAuthorityFileState.specifications {
            let path = root.appendingPathComponent(relative)
            try FileManager.default.createDirectory(
                at: path.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            try Data(relative.utf8).write(to: path)
            try setMode(path.path, mode_t(mode))
        }
        authority = try FileSystemAuthority(testingRootPath: root.path)
        cleanup = MacOSPortableAuthorityCleanup(
            authority: authority,
            expectedUID: UInt32(geteuid()),
            expectedGID: UInt32(getegid()),
            productIsAbsent: { true },
            productMatchesApproval: { _, _ in true }
        )
    }

    func capture(
        packageReceiptVersion: String? = nil
    ) throws -> MacOSPortableAuthorityCleanupState {
        try MacOSPortableAuthorityCleanupState.capture(
            authority: authority,
            sourcePackageRoot: sourceRoot,
            sourceManifestDigest: sourceDigest,
            signingCertificateSHA256: InstallDigest(String(repeating: "a", count: 64)),
            packageReceiptVersion: packageReceiptVersion,
            expectedUID: UInt32(geteuid()),
            expectedGID: UInt32(getegid())
        )
    }

    func cleanup(
        productIsAbsent: Bool,
        productMatchesApproval: Bool,
        packageReceipt: any MacOSPackageReceiptControlling = MacOSPackageReceiptStore(
            runner: MissingMacOSPackageReceiptRunner()
        ),
        removeSigningIdentity: @escaping @Sendable (InstallDigest) throws -> Void = { _ in }
    ) -> MacOSPortableAuthorityCleanup {
        MacOSPortableAuthorityCleanup(
            authority: authority,
            expectedUID: UInt32(geteuid()),
            expectedGID: UInt32(getegid()),
            productIsAbsent: { productIsAbsent },
            productMatchesApproval: { _, _ in productMatchesApproval },
            packageReceipt: packageReceipt,
            removeSigningIdentity: removeSigningIdentity
        )
    }

    func plan(
        packageReceiptVersion: String? = nil
    ) throws -> MacOSPortableAuthorityCleanupPlan {
        try MacOSPortableAuthorityCleanupPlan(
            transactionID: "uninstall-test",
            approvalToken: InstallApprovalToken(String(repeating: "b", count: 64)),
            generationID: "generation-test",
            productApprovalToken: InstallApprovalToken(String(repeating: "c", count: 64)),
            state: capture(packageReceiptVersion: packageReceiptVersion)
        )
    }
}

private final class TestPackageReceipt: MacOSPackageReceiptControlling, @unchecked Sendable {
    private let storedVersion: Mutex<String?>

    init(version: String?) {
        storedVersion = Mutex(version)
    }

    func version() throws -> String? {
        storedVersion.withLock { $0 }
    }

    func forget(expectedVersion: String?) throws {
        try storedVersion.withLock { version in
            guard version == expectedVersion || (version == nil && expectedVersion != nil) else {
                throw InstallError.collision("test package receipt")
            }
            version = nil
        }
    }

    func setVersion(_ version: String?) {
        storedVersion.withLock { $0 = version }
    }
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
