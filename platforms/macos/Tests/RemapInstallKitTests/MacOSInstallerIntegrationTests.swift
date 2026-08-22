import Darwin
import Foundation
@testable import RemapInstallKit
import Testing

@Test
func nativeEffectAdapterInstallsAndUninstallsThroughAFakeSystemRoot() async throws {
    let fixture = try MacOSInstallerFixture()
    let preview = try fixture.installer.preview(
        operation: .install,
        manifest: fixture.manifest,
        source: fixture.source
    )
    #expect(preview.verifiedSourceEntries == fixture.manifest.entries.count)
    #expect(preview.publicationChanges == fixture.manifest.publications.count - 2)
    #expect(preview.publicationChangeDetails.allSatisfy { $0.action == .create })
    #expect(!preview.publicationChangeDetails.contains {
        $0.path.description == "usr/local" || $0.path.description == "usr/local/bin"
    })
    try await fixture.installer.installOrUpdate(
        operation: .install,
        transactionID: "install-native-fixture",
        manifest: fixture.manifest,
        source: fixture.source,
        approvalToken: preview.approvalToken
    )
    let installed = try fixture.installer.status()
    #expect(installed.activeGenerationID == fixture.manifest.generationID)
    #expect(installed.generations.map(\.generationID) == [fixture.manifest.generationID])
    let everyServiceLoaded = installed.services.allSatisfy(\.loaded)
    #expect(everyServiceLoaded)
    #expect(installed.dns.active)
    #expect(installed.dns.effectiveRemapServiceCount == 1)
    #expect(installed.transactions.isEmpty)
    #expect(fixture.launchd.kickstartCount == 0)
    let uninstallPreview = try fixture.installer.previewUninstall(generationID: fixture.manifest.generationID)
    #expect(uninstallPreview.publicationChangeDetails.allSatisfy { $0.action == .remove })
    #expect(!uninstallPreview.publicationChangeDetails.contains {
        $0.path.description == "usr/local" || $0.path.description == "usr/local/bin"
    })
    #expect(uninstallPreview.effects.contains("purge the manifest-owned immutable generation"))
    try await fixture.installer.uninstall(
        transactionID: "uninstall-native-fixture",
        generationID: fixture.manifest.generationID,
        approvalToken: uninstallPreview.approvalToken
    )
    let removed = try fixture.installer.status()
    #expect(removed.activeGenerationID == nil)
    #expect(removed.generations.isEmpty)
    #expect(removed.services.allSatisfy { !$0.loaded })
    #expect(!removed.dns.active)
    #expect(removed.dns.effectiveRemapServiceCount == 0)
    #expect(!fixture.exists("Library/Application Support/Agenxy/Remap"))
    #expect(fixture.exists("Library/Application Support/Agenxy"))
    #expect(!fixture.exists("usr/local/share"))
    #expect(fixture.exists("usr/local/bin"))
}

@Test
func nativeEffectAdapterUpdatesAndCollectsOnlyItsCommittedJournal() async throws {
    let fixture = try MacOSInstallerFixture()
    try await fixture.install(transactionID: "install-before-native-update")
    let update = try fixture.updatePackage(
        generationID: "native-generation-update",
        productVersion: "1.0.1"
    )
    fixture.launchd.selectGeneration(update.manifest.generationID)
    let preview = try fixture.installer.preview(
        operation: .update,
        manifest: update.manifest,
        source: update.source
    )
    #expect(preview.effects.contains("purge previous generation \(fixture.manifest.generationID)"))
    #expect(preview.publicationChangeDetails.allSatisfy {
        $0.previousGenerationID == fixture.manifest.generationID
            && $0.nextGenerationID == update.manifest.generationID
    })

    try await fixture.installer.installOrUpdate(
        operation: .update,
        transactionID: "update-native-fixture",
        manifest: update.manifest,
        source: update.source,
        approvalToken: preview.approvalToken
    )

    let status = try fixture.installer.status()
    #expect(status.activeGenerationID == update.manifest.generationID)
    #expect(status.generations.map(\.generationID) == [update.manifest.generationID])
    let everyServiceLoaded = status.services.allSatisfy(\.loaded)
    #expect(everyServiceLoaded)
    #expect(status.dns.active)
    #expect(status.transactions.isEmpty)
    #expect(try fixture.layout.journals.completedTransactionNames().isEmpty)
}

@Test
func nativeUpdateRecoversARecordLeftAfterOrdinaryDNSWasRestored() async throws {
    let fixture = try MacOSInstallerFixture()
    try await fixture.install(transactionID: "install-before-safe-bypass-update")
    fixture.resolver.setObservation(MacOSResolverObservation(
        ownerUID: UInt32(geteuid()),
        productVersion: fixture.manifest.productVersion,
        phase: .active,
        configuredServiceIDs: ["test-service"],
        remapServiceIDs: []
    ))
    let update = try fixture.updatePackage(
        generationID: "safe-bypass-update",
        productVersion: "1.0.1"
    )
    fixture.launchd.selectGeneration(update.manifest.generationID)
    let preview = try fixture.installer.preview(
        operation: .update,
        manifest: update.manifest,
        source: update.source
    )

    try await fixture.installer.installOrUpdate(
        operation: .update,
        transactionID: "update-after-safe-bypass",
        manifest: update.manifest,
        source: update.source,
        approvalToken: preview.approvalToken
    )

    let status = try fixture.installer.status()
    #expect(status.activeGenerationID == update.manifest.generationID)
    #expect(status.dns.active)
    #expect(status.dns.effectiveRemapServiceCount == 1)
    let context = try InstallTransitionContext(
        operation: .uninstall,
        current: update.manifest,
        previous: nil
    )
    try await fixture.effects.reconcile(.dnsRestored, context: context)
    try await fixture.effects.verify(.dnsRestored, context: context)
    let observation = try fixture.resolver.observation()
    #expect(!observation.recordPresent)
    #expect(observation.remapServiceIDs.isEmpty)
}

@Test
func installerStatusExposesEffectiveResolverResidueWithoutAnActivationRecord() throws {
    let fixture = try MacOSInstallerFixture()
    fixture.resolver.setObservation(MacOSResolverObservation(
        ownerUID: nil,
        productVersion: nil,
        phase: nil,
        configuredServiceIDs: [],
        remapServiceIDs: ["stale-remap-service"]
    ))

    let status = try fixture.installer.status()

    #expect(!status.dns.active)
    #expect(status.dns.configuredServiceCount == 0)
    #expect(status.dns.effectiveRemapServiceCount == 1)
}

@Test
func nativeEffectAdapterRecoversAnExactPreparedDNSActivation() async throws {
    let fixture = try MacOSInstallerFixture()
    try fixture.prepareStorage()
    let staging = try fixture.layout.generations.stage(
        fixture.manifest,
        from: fixture.source,
        transactionID: "prepared-dns-recovery"
    )
    try fixture.layout.generations.publish(staging, manifest: fixture.manifest)
    let context = try InstallTransitionContext(
        operation: .install,
        current: fixture.manifest,
        previous: nil
    )
    fixture.resolver.setObservation(MacOSResolverObservation(
        ownerUID: UInt32(geteuid()),
        productVersion: fixture.manifest.productVersion,
        phase: .prepared,
        configuredServiceIDs: ["test-service"],
        remapServiceIDs: []
    ))

    try await fixture.effects.reconcile(.dnsRestored, context: context)
    try await fixture.effects.verify(.dnsRestored, context: context)

    let observation = try fixture.resolver.observation()
    #expect(!observation.recordPresent)
    #expect(observation.remapServiceIDs.isEmpty)
}

@Test
func nativeInstallPublishesSearchablePayloadPathsAndPrivateTransactionState() async throws {
    let fixture = try MacOSInstallerFixture()
    try await fixture.install(transactionID: "install-access-fixture")
    let productDirectories = [
        "Library/Application Support/Agenxy/Remap",
        "Library/Application Support/Agenxy/Remap/Install",
        "Library/Application Support/Agenxy/Remap/Install/Generations"
    ]
    for relative in productDirectories {
        #expect(try fixture.mode(relative) == 0o711)
    }
    for relative in MacOSInstallerFixture.publicDirectoryPaths {
        #expect(try fixture.mode(relative) == 0o755)
    }
    let generation = "\(MacOSInstallLayout.installerBase)/Generations/\(fixture.manifest.generationID)"
    #expect(try fixture.mode(generation) == GenerationStore.generationRootMode)
    #expect(try fixture.mode("\(MacOSInstallLayout.installerBase)/Journals") == 0o700)
    #expect(try fixture.mode("Library/Application Support/Agenxy") == 0o755)
    #expect(!fixture.exists("\(MacOSInstallLayout.installerBase)/transaction.lock"))
    try fixture.retargetPublicLinksIntoFakeRoot()
    let command = fixture.rootURL.appending(path: "usr/local/bin/remap").path
    let appExecutable = fixture.rootURL.appending(path: "Applications/Remap.app/Contents/MacOS/Remap").path
    let publicFiles = MacOSInstallerFixture.publicReadableFiles.map {
        fixture.rootURL.appending(path: $0).path
    }
    #expect(access(command, R_OK | X_OK) == 0)
    #expect(access(appExecutable, R_OK | X_OK) == 0)
    #expect(publicFiles.allSatisfy { access($0, R_OK) == 0 })
    #expect(try fixture.otherUserCanTraverse(
        productDirectories + MacOSInstallerFixture.publicDirectoryPaths + [generation]
    ))
    #expect(!fixture.otherUserCanRead("\(MacOSInstallLayout.installerBase)/Journals"))
}

@Test
func tamperedApprovalTokenCannotStageJournalOrInvokeSystemEffects() async throws {
    let fixture = try MacOSInstallerFixture()
    let preview = try fixture.installer.preview(
        operation: .install,
        manifest: fixture.manifest,
        source: fixture.source
    )
    let tamperedToken = try InstallApprovalToken(String(repeating: "0", count: 64))
    #expect(preview.approvalToken != tamperedToken)

    await #expect(throws: InstallError.approval(
        "the approved preview is stale or does not match this operation"
    )) {
        try await fixture.installer.installOrUpdate(
            operation: .install,
            transactionID: "tampered-approval",
            manifest: fixture.manifest,
            source: fixture.source,
            approvalToken: tamperedToken
        )
    }
    try fixture.expectNoMutation(transactionID: "tampered-approval")
}

@Test
func staleApprovalTokenCannotStageJournalOrInvokeSystemEffects() async throws {
    let fixture = try MacOSInstallerFixture()
    let preview = try fixture.installer.preview(
        operation: .install,
        manifest: fixture.manifest,
        source: fixture.source
    )
    fixture.launchd.injectForeignDaemon()

    await #expect(throws: InstallError.approval(
        "the approved preview is stale or does not match this operation"
    )) {
        try await fixture.installer.installOrUpdate(
            operation: .install,
            transactionID: "stale-approval",
            manifest: fixture.manifest,
            source: fixture.source,
            approvalToken: preview.approvalToken
        )
    }
    try fixture.expectNoMutation(transactionID: "stale-approval")
    #expect(fixture.launchd.bootoutCount == 0)
}

@Test
func completeUninstallPreservesUnexpectedProductStorage() async throws {
    let fixture = try MacOSInstallerFixture()
    try await fixture.install(transactionID: "install-unmanaged-storage")
    try await fixture.recoverAllApproved()
    let sentinel = fixture.rootURL.appending(
        path: "\(MacOSInstallLayout.installerBase)/unmanaged"
    )
    try writeTestFile(Data("preserve".utf8), to: sentinel)
    let uninstallPreview = try fixture.installer.previewUninstall(
        generationID: fixture.manifest.generationID
    )

    await #expect(throws: InstallError.collision(MacOSInstallLayout.installerBase)) {
        try await fixture.installer.uninstall(
            transactionID: "uninstall-unmanaged-storage",
            generationID: fixture.manifest.generationID,
            approvalToken: uninstallPreview.approvalToken
        )
    }
    #expect(try Data(contentsOf: sentinel) == Data("preserve".utf8))
}

@Test
func storageTopologyRejectsAPreexistingPrivateCollisionWithoutChangingIt() throws {
    let tree = try TemporaryInstallTree()
    let root = try tree.directory("topology-collision")
    try MacOSInstallerFixture.prepareStandardSystemDirectories(root)
    let organisation = root.appending(path: "Library/Application Support/Agenxy")
    try FileManager.default.createDirectory(at: organisation, withIntermediateDirectories: false)
    guard chmod(organisation.path, 0o700) == 0 else {
        throw InstallError.operatingSystem("prepare topology collision", errno)
    }
    let authority = try testAuthority(at: root)
    let layout = try MacOSInstallLayout(
        authority: authority,
        systemRootPath: root.path,
        installOwnerUID: UInt32(geteuid()),
        installGroupGID: UInt32(getegid())
    )
    #expect(throws: InstallError.collision("Library/Application Support/Agenxy")) {
        try layout.prepareStorageTopology()
    }
    let metadata = try authority.metadata(at: InstallRelativePath("Library/Application Support/Agenxy"))
    #expect(try #require(metadata).mode == 0o700)
}

@Test
func regularLaunchDaemonPublicationPreservesAnUnmanagedReplacement() throws {
    let fixture = try MacOSInstallerFixture()
    try fixture.prepareStorage()
    let publication = try #require(fixture.manifest.publications.first { $0.kind == .regularFile })
    let generation = try fixture.layout.generations.stage(
        fixture.manifest,
        from: fixture.source,
        transactionID: "regular-stage"
    )
    try fixture.layout.generations.publish(generation, manifest: fixture.manifest)
    try fixture.layout.publications.publish(publication, replacing: nil, transactionID: "regular-publish")
    #expect(try fixture.layout.publications.classify(publication) == .owned)
    try fixture.layout.authority.unlinkRegularFile(
        at: publication.path,
        expected: publication.regularFileEntry()
    )
    let replacement = fixture.rootURL.appending(path: publication.path.description)
    try FileManager.default.createDirectory(
        at: replacement.deletingLastPathComponent(),
        withIntermediateDirectories: true
    )
    try writeTestFile(Data("unmanaged".utf8), to: replacement)
    #expect(try fixture.layout.publications.classify(publication) == .unmanaged)
    #expect(throws: InstallError.collision(publication.path.description)) {
        try fixture.layout.publications.unpublish(publication)
    }
    #expect(try Data(contentsOf: replacement) == Data("unmanaged".utf8))
}

@Test
func nativeEffectAdapterRejectsLoadedJobOutsideManifestLineage() async throws {
    let fixture = try MacOSInstallerFixture()
    fixture.launchd.injectForeignDaemon()
    let context = try InstallTransitionContext(
        operation: .install,
        current: fixture.manifest,
        previous: nil
    )
    await #expect(throws: InstallError.self) {
        try await fixture.effects.reconcile(.serviceRunning, context: context)
    }
    #expect(fixture.launchd.bootoutCount == 0)
}

@Test
func nativeEffectAdapterFailsClosedAtAuthenticatedAcceptance() async throws {
    let fixture = try MacOSInstallerFixture(runtimeFailure: true)
    try fixture.prepareStorage()
    let context = try InstallTransitionContext(
        operation: .install,
        current: fixture.manifest,
        previous: nil
    )
    let staging = try fixture.layout.generations.stage(
        fixture.manifest,
        from: fixture.source,
        transactionID: "acceptance-stage"
    )
    try fixture.layout.generations.publish(staging, manifest: fixture.manifest)
    await #expect(throws: InstallError.integrity("authenticated runtime fault")) {
        try await fixture.effects.verify(.installationAccepted, context: context)
    }
}

@Test
func startupRecoveryQuarantinesOnlyExactlyOwnedOrphanStaging() async throws {
    let fixture = try MacOSInstallerFixture()
    try fixture.prepareStorage()
    _ = try fixture.layout.generations.stage(
        fixture.manifest,
        from: fixture.source,
        transactionID: "power-loss-orphan"
    )
    let preview = try fixture.installer.previewRecovery(transactionID: nil)
    let result = try await fixture.installer.recoverAll(
        approvalToken: preview.approvalToken
    )
    #expect(result.recoveredTransactions.isEmpty)
    #expect(result.quarantinedOrphans == ["power-loss-orphan"])
    #expect(try fixture.layout.generations.classifyStaging(
        fixture.manifest,
        transactionID: "power-loss-orphan"
    ) == .missing)
    #expect(try fixture.layout.generations.classifyAbandoned(
        fixture.manifest,
        transactionID: "power-loss-orphan"
    ) == .missing)
    let converged = try fixture.installer.previewRecovery(transactionID: nil)
    #expect(converged.effects.isEmpty)
    #expect(converged.transactions.isEmpty)
    #expect(converged.orphanedStagingTransactionIDs.isEmpty)
    #expect(converged.detachedGenerationNames.isEmpty)
    #expect(!fixture.exists("Library/Application Support/Agenxy/Remap"))
}

@Test
func recoveryPreservesThePackageLifecycleSiblingAndStillConverges() async throws {
    let fixture = try MacOSInstallerFixture()
    try fixture.prepareStorage()
    _ = try fixture.layout.generations.stage(
        fixture.manifest,
        from: fixture.source,
        transactionID: "package-sibling-orphan"
    )
    let lifecycle = fixture.rootURL.appending(
        path: "Library/Application Support/Agenxy/Remap/Installer"
    )
    try FileManager.default.createDirectory(at: lifecycle, withIntermediateDirectories: false)
    guard chmod(lifecycle.path, 0o700) == 0 else {
        throw InstallError.operatingSystem("prepare package lifecycle sibling", errno)
    }
    try writeTestFile(Data("lifecycle".utf8), to: lifecycle.appending(path: "service-v1.json"))

    let preview = try fixture.installer.previewRecovery(transactionID: nil)
    _ = try await fixture.installer.recoverAll(approvalToken: preview.approvalToken)

    #expect(try fixture.installer.previewRecovery(transactionID: nil).effects.isEmpty)
    #expect(fixture.exists("Library/Application Support/Agenxy/Remap/Installer/service-v1.json"))
    #expect(!fixture.exists(MacOSInstallLayout.installerBase))
}

@Test
func recoveryApprovalRejectsNewOrphanStateBeforeRecoveryEffects() async throws {
    let fixture = try MacOSInstallerFixture()
    try fixture.prepareStorage()
    _ = try fixture.layout.generations.stage(
        fixture.manifest,
        from: fixture.source,
        transactionID: "first-orphan"
    )
    let preview = try fixture.installer.previewRecovery(transactionID: nil)
    _ = try fixture.layout.generations.stage(
        fixture.manifest,
        from: fixture.source,
        transactionID: "second-orphan"
    )

    await #expect(throws: InstallError.approval(
        "the approved recovery preview is stale or does not match"
    )) {
        try await fixture.installer.recoverAll(approvalToken: preview.approvalToken)
    }
    let manifestDigest = try fixture.manifest.digest()
    #expect(try fixture.layout.generations.classifyStaging(
        fixture.manifest,
        transactionID: "first-orphan"
    ) == .owned(manifestDigest))
    #expect(try fixture.layout.generations.classifyStaging(
        fixture.manifest,
        transactionID: "second-orphan"
    ) == .owned(manifestDigest))
}

@Test
func cleanRecoveryPreviewIsAnExactNoOp() throws {
    let fixture = try MacOSInstallerFixture()
    let preview = try fixture.installer.previewRecovery(transactionID: nil)

    #expect(preview.selectedTransactionIDs.isEmpty)
    #expect(preview.transactions.isEmpty)
    #expect(preview.orphanedStagingTransactionIDs.isEmpty)
    #expect(preview.detachedGenerationNames.isEmpty)
    #expect(preview.effects.isEmpty)
}

@Test
func terminalJournalAddedAfterPreviewInvalidatesLifecycleApproval() async throws {
    let fixture = try MacOSInstallerFixture()
    try await fixture.install(transactionID: "install-before-terminal-drift")
    try await fixture.recoverAllApproved()
    let preview = try fixture.installer.previewUninstall(
        generationID: fixture.manifest.generationID
    )
    try fixture.appendTerminalInstallJournal(transactionID: "late-terminal")

    await #expect(throws: InstallError.approval(
        "recover installer state before requesting lifecycle approval"
    )) {
        try await fixture.installer.uninstall(
            transactionID: "uninstall-after-terminal-drift",
            generationID: fixture.manifest.generationID,
            approvalToken: preview.approvalToken
        )
    }
    #expect(fixture.launchd.bootoutCount == 0)
    #expect(try fixture.layout.generations.classify(fixture.manifest) != .missing)
}

@Test
func detachedGenerationAddedAfterPreviewInvalidatesLifecycleApproval() async throws {
    let fixture = try MacOSInstallerFixture()
    try await fixture.install(transactionID: "install-before-detached-drift")
    try await fixture.recoverAllApproved()
    let preview = try fixture.installer.previewUninstall(
        generationID: fixture.manifest.generationID
    )
    try fixture.createDetachedGeneration(transactionID: "late-detached")

    await #expect(throws: InstallError.approval(
        "recover installer state before requesting lifecycle approval"
    )) {
        try await fixture.installer.uninstall(
            transactionID: "uninstall-after-detached-drift",
            generationID: fixture.manifest.generationID,
            approvalToken: preview.approvalToken
        )
    }
    #expect(fixture.launchd.bootoutCount == 0)
    #expect(try fixture.layout.generations.classify(fixture.manifest) != .missing)
}

@Test
func previewRejectsManifestBoundButUnsafeNativeConfiguration() throws {
    let fixture = try MacOSInstallerFixture(malformedDaemonPlist: true)
    #expect(throws: InstallError.invalidManifest("the launchd property list is malformed")) {
        try fixture.installer.preview(
            operation: .install,
            manifest: fixture.manifest,
            source: fixture.source
        )
    }
}

@Test
func previewRejectsAValidManifestForAnotherProduct() throws {
    let fixture = try MacOSInstallerFixture()
    let foreign = try InstallManifest(
        productIdentifier: "org.example.Foreign",
        generationID: fixture.manifest.generationID,
        productVersion: fixture.manifest.productVersion,
        previousGenerationID: nil,
        entries: fixture.manifest.entries,
        publications: fixture.manifest.publications
    )
    #expect(throws: InstallError.invalidManifest("the native package has the wrong product identity")) {
        try fixture.installer.preview(operation: .install, manifest: foreign, source: fixture.source)
    }
}

final class MacOSInstallerFixture: @unchecked Sendable {
    fileprivate static let publicDirectoryPaths = [
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

    fileprivate static let publicReadableFiles = [
        "usr/local/share/bash-completion/completions/remap",
        "usr/local/share/fish/vendor_completions.d/remap.fish",
        "usr/local/share/licenses/remap/LICENSE",
        "usr/local/share/man/man1/remap.1",
        "usr/local/share/zsh/site-functions/_remap"
    ]

    let tree: TemporaryInstallTree
    let rootURL: URL
    let layout: MacOSInstallLayout
    let source: FileSystemAuthority
    let manifest: InstallManifest
    let launchd: FakeMacOSLaunchdController
    let resolver: FakeMacOSResolverController
    let effects: MacOSInstallSystemEffectAdapter
    let installer: MacOSInstaller

    init(runtimeFailure: Bool = false, malformedDaemonPlist: Bool = false) throws {
        tree = try TemporaryInstallTree()
        rootURL = try tree.directory("native-system")
        let sourceURL = try tree.directory("native-source")
        try Self.prepareStandardSystemDirectories(rootURL)
        let authority = try testAuthority(at: rootURL)
        layout = try MacOSInstallLayout(
            authority: authority,
            systemRootPath: rootURL.path,
            installOwnerUID: UInt32(geteuid()),
            installGroupGID: UInt32(getegid())
        )
        let built = try Self.buildManifest(
            rootURL: rootURL,
            sourceURL: sourceURL,
            malformedDaemonPlist: malformedDaemonPlist,
            generationID: "native-generation",
            previousGenerationID: nil,
            productVersion: "1.0.0"
        )
        manifest = built.manifest
        source = try testAuthority(at: sourceURL)
        launchd = FakeMacOSLaunchdController(systemRoot: rootURL.path, generationID: manifest.generationID)
        resolver = FakeMacOSResolverController()
        let runtime = FakeMacOSRuntimeHealthChecker(fails: runtimeFailure)
        effects = MacOSInstallSystemEffectAdapter(
            images: MacOSGenerationImageStore(layout: layout),
            launchd: launchd,
            resolver: resolver,
            runtime: runtime,
            resolverReadiness: MacOSResolverReadinessVerifier(
                timeout: .seconds(30),
                retryDelay: .zero,
                requiredConsecutiveObservations: 2
            )
        )
        installer = MacOSInstaller(
            layout: layout,
            effects: effects,
            launchd: launchd,
            resolver: resolver
        )
    }

    func install(transactionID: String) async throws {
        let preview = try installer.preview(
            operation: .install,
            manifest: manifest,
            source: source
        )
        try await installer.installOrUpdate(
            operation: .install,
            transactionID: transactionID,
            manifest: manifest,
            source: source,
            approvalToken: preview.approvalToken
        )
    }

    func updatePackage(
        generationID: String,
        productVersion: String
    ) throws -> (manifest: InstallManifest, source: FileSystemAuthority) {
        let sourceURL = try tree.directory("native-source-\(generationID)")
        let built = try Self.buildManifest(
            rootURL: rootURL,
            sourceURL: sourceURL,
            malformedDaemonPlist: false,
            generationID: generationID,
            previousGenerationID: manifest.generationID,
            productVersion: productVersion
        )
        return try (built.manifest, testAuthority(at: sourceURL))
    }

    func prepareStorage() throws {
        try layout.prepareStorageTopology()
    }

    func recoverAllApproved() async throws {
        let preview = try installer.previewRecovery(transactionID: nil)
        _ = try await installer.recoverAll(approvalToken: preview.approvalToken)
    }

    func appendTerminalInstallJournal(transactionID: String) throws {
        let context = try InstallTransitionContext(
            operation: .install,
            current: manifest,
            previous: nil
        )
        let writer = InstallJournalWriter(store: layout.journals)
        try writer.appendInitial(
            transactionID: transactionID,
            context: context,
            phase: .prepared
        )
        for phase in [
            InstallPhase.generationPublished,
            .serviceStarted,
            .dnsActive,
            .applicationPublished,
            .accepted,
            .committed
        ] {
            try writer.appendNext(transactionID: transactionID, phase: phase)
        }
    }

    func createDetachedGeneration(transactionID: String) throws {
        let staging = try layout.generations.stage(
            manifest,
            from: source,
            transactionID: transactionID
        )
        #expect(try layout.authority.metadata(at: staging) != nil)
        try layout.generations.quarantineStaging(manifest, transactionID: transactionID)
    }

    func expectNoMutation(transactionID: String) throws {
        #expect(try layout.journals.load(transactionID: transactionID).isEmpty)
        #expect(try layout.generations.classify(manifest) == .missing)
        for publication in manifest.publications where publication.kind != .directory {
            #expect(try layout.publications.classify(publication) == .missing)
        }
    }

    fileprivate static func prepareStandardSystemDirectories(_ root: URL) throws {
        let library = root.appending(path: "Library", directoryHint: .isDirectory)
        let applicationSupport = library.appending(path: "Application Support", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: applicationSupport, withIntermediateDirectories: true)
        let launchDaemons = library.appending(path: "LaunchDaemons", directoryHint: .isDirectory)
        let applications = root.appending(path: "Applications", directoryHint: .isDirectory)
        let localBin = root.appending(path: "usr/local/bin", directoryHint: .isDirectory)
        let local = localBin.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: launchDaemons, withIntermediateDirectories: false)
        try FileManager.default.createDirectory(at: applications, withIntermediateDirectories: false)
        try FileManager.default.createDirectory(at: localBin, withIntermediateDirectories: true)
        for path in [
            library.path,
            applicationSupport.path,
            launchDaemons.path,
            applications.path,
            local.path,
            localBin.path
        ] {
            guard chmod(path, 0o755) == 0 else {
                throw InstallError.operatingSystem("prepare fake standard system directory", errno)
            }
        }
    }

    func mode(_ relative: String) throws -> UInt16 {
        let metadata = try layout.authority.metadata(at: InstallRelativePath(relative))
        return try #require(metadata).mode
    }

    func exists(_ relative: String) -> Bool {
        (try? layout.authority.metadata(at: InstallRelativePath(relative))) != nil
    }

    func otherUserCanTraverse(_ paths: [String]) throws -> Bool {
        try paths.allSatisfy { try mode($0) & 0o001 == 0o001 }
    }

    func otherUserCanRead(_ relative: String) -> Bool {
        do {
            return try mode(relative) & 0o004 == 0o004
        } catch {
            return false
        }
    }

    func retargetPublicLinksIntoFakeRoot() throws {
        let current = rootURL.appending(path: "\(MacOSInstallLayout.installerBase)/current")
        let command = rootURL.appending(path: "usr/local/bin/remap")
        let application = rootURL.appending(path: "Applications/Remap.app")
        let generation = rootURL.appending(
            path: "\(MacOSInstallLayout.installerBase)/Generations/\(manifest.generationID)"
        )
        for path in [current, command, application] {
            try FileManager.default.removeItem(at: path)
        }
        try FileManager.default.createSymbolicLink(atPath: current.path, withDestinationPath: generation.path)
        try FileManager.default.createSymbolicLink(
            atPath: command.path,
            withDestinationPath: current.appending(path: "bin/remap").path
        )
        try FileManager.default.createSymbolicLink(
            atPath: application.path,
            withDestinationPath: current.appending(path: "app/Remap.app").path
        )
        let readableTargets = [
            "usr/local/share/bash-completion/completions/remap": "share/completions/remap.bash",
            "usr/local/share/fish/vendor_completions.d/remap.fish": "share/completions/remap.fish",
            "usr/local/share/licenses/remap/LICENSE": "share/licenses/remap/LICENSE",
            "usr/local/share/man/man1/remap.1": "share/man/man1/remap.1",
            "usr/local/share/zsh/site-functions/_remap": "share/completions/remap.zsh"
        ]
        for (path, target) in readableTargets {
            let publicPath = rootURL.appending(path: path)
            try FileManager.default.removeItem(at: publicPath)
            try FileManager.default.createSymbolicLink(
                atPath: publicPath.path,
                withDestinationPath: current.appending(path: target).path
            )
        }
    }

    private static func buildManifest(
        rootURL: URL,
        sourceURL: URL,
        malformedDaemonPlist: Bool,
        generationID: String,
        previousGenerationID: String?,
        productVersion: String
    ) throws -> (manifest: InstallManifest, configuration: MacOSInstallConfiguration) {
        let configuration = try configuration()
        let root = rootURL.path + "/" + MacOSInstallLayout.installerBase
            + "/Generations/\(generationID)"
        let files = try sourceFiles(
            configuration: configuration,
            generationRoot: root,
            malformedDaemonPlist: malformedDaemonPlist
        )
        try writeSource(files, at: sourceURL)
        let entries = try manifestEntries(files)
        let publications = try launchdPublications(entries: entries, generationID: generationID)
        let manifest = try InstallManifest(
            productIdentifier: "org.agenxy.Remap",
            generationID: generationID,
            productVersion: productVersion,
            previousGenerationID: previousGenerationID,
            entries: entries,
            publications: publications
        )
        return (manifest, configuration)
    }

    private static func configuration() throws -> MacOSInstallConfiguration {
        let home = try MacOSAccountLookup.account(for: UInt32(geteuid())).homeDirectory.value
        let data = home + "/Library/Application Support/org.Agenxy.Remap"
        return try MacOSInstallConfiguration(
            ownerUID: UInt32(geteuid()),
            dataDirectory: InstallAbsolutePath(data),
            controlSocket: InstallAbsolutePath(data + "/control.sock"),
            signingCertificateSHA256: InstallDigest(String(repeating: "0", count: 64))
        )
    }

    private static func sourceFiles(
        configuration: MacOSInstallConfiguration,
        generationRoot: String,
        malformedDaemonPlist: Bool
    ) throws -> [String: Data] {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try [
            "app/Remap.app/Contents/MacOS/Remap": Data("app".utf8),
            "bin/remap": Data("cli".utf8),
            MacOSInstallConfiguration.entryName: encoder.encode(configuration),
            "launchd/org.agenxy.Remap.daemon.plist": malformedDaemonPlist
                ? Data("not a property list".utf8)
                : daemonPlist(
                    configuration: configuration,
                    program: generationRoot + "/libexec/remapd"
                ),
            "launchd/org.agenxy.Remap.resolver.plist": resolverPlist(
                configuration: configuration,
                program: generationRoot + "/libexec/remap-resolver"
            ),
            "libexec/remap-install": Data("installer".utf8),
            "libexec/remap-resolver": Data("resolver".utf8),
            "libexec/remapd": Data("daemon".utf8),
            "share/completions/remap.bash": Data("bash completion".utf8),
            "share/completions/remap.fish": Data("fish completion".utf8),
            "share/completions/remap.zsh": Data("zsh completion".utf8),
            "share/licenses/remap/LICENSE": Data("license".utf8),
            "share/man/man1/remap.1": Data("manual".utf8)
        ]
    }

    private static func writeSource(_ files: [String: Data], at root: URL) throws {
        for (path, data) in files {
            let destination = root.appending(path: path)
            try FileManager.default.createDirectory(
                at: destination.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            try writeTestFile(data, to: destination)
        }
    }

    private static func manifestEntries(_ files: [String: Data]) throws -> [InstallEntry] {
        let owner = UInt32(geteuid())
        let group = UInt32(getegid())
        let directories = try [
            "app",
            "app/Remap.app",
            "app/Remap.app/Contents",
            "app/Remap.app/Contents/MacOS",
            "bin",
            "launchd",
            "libexec",
            "share",
            "share/completions",
            "share/licenses",
            "share/licenses/remap",
            "share/man",
            "share/man/man1"
        ].map { path in
            try InstallEntry(
                path: InstallRelativePath(path),
                kind: .directory,
                role: .support,
                sha256: nil,
                byteCount: nil,
                ownerUID: owner,
                groupGID: group,
                mode: 0o555
            )
        }
        let regularFiles = try files.map {
            try manifestFileEntry(path: $0.key, data: $0.value, owner: owner, group: group)
        }
        return directories + regularFiles
    }

    private static func manifestFileEntry(
        path: String,
        data: Data,
        owner: UInt32,
        group: UInt32
    ) throws -> InstallEntry {
        let role: InstallEntryRole = switch path {
        case "bin/remap":
            .commandLineTool
        case _ where path.hasPrefix("app/"):
            .application
        case "libexec/remapd", "libexec/remap-resolver":
            .daemon
        default:
            .support
        }
        return try InstallEntry(
            path: InstallRelativePath(path),
            kind: .regularFile,
            role: role,
            sha256: InstallDigest.hash(data),
            byteCount: UInt64(data.count),
            ownerUID: owner,
            groupGID: group,
            mode: path.hasPrefix("libexec/") || path == "bin/remap" || path.hasPrefix("app/") ? 0o555 : 0o444
        )
    }

    private static func launchdPublications(
        entries: [InstallEntry],
        generationID: String
    ) throws -> [InstallPublication] {
        var publications = try publicDirectoryPaths.map { path in
            try InstallPublication(
                path: InstallRelativePath(path),
                generationID: generationID,
                ownerUID: UInt32(geteuid()),
                groupGID: UInt32(getegid())
            )
        }
        publications += try MacOSLaunchdServiceKind.allCases.map { kind in
            let entry = try #require(entries.first { $0.path.description == kind.plistEntry })
            return try InstallPublication(
                path: InstallRelativePath("Library/LaunchDaemons/\(kind.label).plist"),
                source: InstallRelativePath(
                    "\(MacOSInstallLayout.installerBase)/Generations/\(generationID)/\(kind.plistEntry)"
                ),
                sha256: #require(entry.sha256),
                byteCount: #require(entry.byteCount),
                generationID: generationID,
                ownerUID: UInt32(geteuid()),
                groupGID: UInt32(getegid())
            )
        }
        try publications.append(InstallPublication(
            path: InstallRelativePath("\(MacOSInstallLayout.installerBase)/current"),
            target: InstallSymlinkTarget(
                "/\(MacOSInstallLayout.installerBase)/Generations/\(generationID)"
            ),
            generationID: generationID
        ))
        try publications.append(InstallPublication(
            path: InstallRelativePath("Applications/Remap.app"),
            target: InstallSymlinkTarget(
                "/\(MacOSInstallLayout.installerBase)/current/app/Remap.app"
            ),
            generationID: generationID
        ))
        try publications.append(InstallPublication(
            path: InstallRelativePath("usr/local/bin/remap"),
            target: InstallSymlinkTarget(
                "/\(MacOSInstallLayout.installerBase)/current/bin/remap"
            ),
            generationID: generationID
        ))
        let readableTargets = [
            "usr/local/share/bash-completion/completions/remap": "share/completions/remap.bash",
            "usr/local/share/fish/vendor_completions.d/remap.fish": "share/completions/remap.fish",
            "usr/local/share/licenses/remap/LICENSE": "share/licenses/remap/LICENSE",
            "usr/local/share/man/man1/remap.1": "share/man/man1/remap.1",
            "usr/local/share/zsh/site-functions/_remap": "share/completions/remap.zsh"
        ]
        for (path, target) in readableTargets {
            try publications.append(InstallPublication(
                path: InstallRelativePath(path),
                target: InstallSymlinkTarget(
                    "/\(MacOSInstallLayout.installerBase)/current/\(target)"
                ),
                generationID: generationID
            ))
        }
        return publications
    }
}
