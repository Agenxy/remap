import Foundation

/// High-level native installer used by the privileged source-install executable.
public struct MacOSInstaller: Sendable {
    private let layout: MacOSInstallLayout
    private let effects: any InstallSystemEffectAdapting
    private let launchd: any MacOSLaunchdControlling
    private let resolver: any MacOSResolverControlling

    public static func production() throws -> MacOSInstaller {
        let layout = try MacOSInstallLayout.production()
        let launchd = NativeMacOSLaunchdController()
        let resolver = NativeMacOSResolverController()
        let effects = MacOSInstallSystemEffectAdapter(
            images: MacOSGenerationImageStore(layout: layout),
            launchd: launchd,
            resolver: resolver,
            runtime: NativeMacOSRuntimeHealthChecker()
        )
        return MacOSInstaller(layout: layout, effects: effects, launchd: launchd, resolver: resolver)
    }

    init(
        layout: MacOSInstallLayout,
        effects: any InstallSystemEffectAdapting,
        launchd: any MacOSLaunchdControlling,
        resolver: any MacOSResolverControlling
    ) {
        self.layout = layout
        self.effects = effects
        self.launchd = launchd
        self.resolver = resolver
    }

    public func preview(
        operation: InstallOperation,
        manifest: InstallManifest,
        source: FileSystemAuthority
    ) throws -> MacOSInstallerPreview {
        guard operation != .uninstall else {
            throw InstallError.unsupported("uninstall preview uses the installed generation")
        }
        try validateSource(manifest, authority: source)
        let previous = try loadPrevious(for: operation, manifest: manifest)
        let context = try InstallTransitionContext(
            operation: operation, current: manifest, previous: previous
        )
        return try approvalPreview(for: context, verifiedSourceEntries: manifest.entries.count)
    }

    public func previewUninstall(generationID: String) throws -> MacOSInstallerPreview {
        let manifest = try layout.generations.loadManifest(for: generationID)
        let context = try InstallTransitionContext(
            operation: .uninstall, current: manifest, previous: nil
        )
        return try approvalPreview(for: context, verifiedSourceEntries: 0)
    }

    public func installOrUpdate(
        operation: InstallOperation,
        transactionID: String,
        manifest: InstallManifest,
        source: FileSystemAuthority,
        approvalToken: InstallApprovalToken
    ) async throws {
        guard operation == .install || operation == .update else {
            throw InstallError.unsupported("installOrUpdate requires install or update")
        }
        let approvedPreview = try preview(operation: operation, manifest: manifest, source: source)
        try requireApproval(approvalToken, matches: approvedPreview)
        let previous = try loadPrevious(for: operation, manifest: manifest)
        let context = try InstallTransitionContext(
            operation: operation, current: manifest, previous: previous
        )
        let request = try InstallTransactionRequest(
            transactionID: transactionID,
            context: context,
            source: source
        )
        let verifier = MacOSInstallerApprovalVerifier(
            installer: self,
            expectedToken: approvalToken,
            verifiedSourceEntries: manifest.entries.count
        )
        try await coordinator(approvalVerifier: verifier).installOrUpdate(request)
    }

    public func uninstall(
        transactionID: String,
        generationID: String,
        approvalToken: InstallApprovalToken
    ) async throws {
        let approvedPreview = try previewUninstall(generationID: generationID)
        try requireApproval(approvalToken, matches: approvedPreview)
        let manifest = try layout.generations.loadManifest(for: generationID)
        let verifier = MacOSInstallerApprovalVerifier(
            installer: self,
            expectedToken: approvalToken,
            verifiedSourceEntries: 0
        )
        try await coordinator(approvalVerifier: verifier).uninstall(
            transactionID: transactionID,
            manifest: manifest
        )
        try completeUninstallCleanup()
    }

    fileprivate func approvalPreview(
        for context: InstallTransitionContext,
        verifiedSourceEntries: Int
    ) throws -> MacOSInstallerPreview {
        let recoveryPreview = try previewRecovery(transactionID: nil)
        guard recoveryPreview.effects.isEmpty else {
            throw InstallError.approval("recover installer state before requesting lifecycle approval")
        }
        let pendingTransactions: [String] = []
        switch context.operation {
        case .install, .update:
            return try installPreview(
                context: context,
                verifiedSourceEntries: verifiedSourceEntries,
                pendingTransactions: pendingTransactions
            )
        case .uninstall:
            return try uninstallPreview(
                context: context,
                pendingTransactions: pendingTransactions
            )
        }
    }

    private func installPreview(
        context: InstallTransitionContext,
        verifiedSourceEntries: Int,
        pendingTransactions: [String]
    ) throws -> MacOSInstallerPreview {
        let manifest = context.current
        guard case .missing = try layout.generations.classify(manifest) else {
            throw InstallError.collision("generation \(manifest.generationID)")
        }
        try PublicationReconciler(store: layout.publications).requireInstallable(context)
        let changes = try MacOSInstallerPublicationChange.changes(for: context) {
            try layout.publications.classify($0)
        }
        return try MacOSInstallerPreview(
            schemaVersion: 2,
            operation: context.operation,
            generationID: manifest.generationID,
            productVersion: manifest.productVersion,
            verifiedSourceEntries: verifiedSourceEntries,
            publicationChangeDetails: changes,
            pendingRecoveryTransactions: pendingTransactions,
            effects: Self.previewEffects(previousGenerationID: context.previous?.generationID),
            approvalState: approvalState(for: context)
        )
    }

    private func uninstallPreview(
        context: InstallTransitionContext,
        pendingTransactions: [String]
    ) throws -> MacOSInstallerPreview {
        let manifest = context.current
        guard case .owned = try layout.generations.classify(manifest) else {
            throw InstallError.collision("generation \(manifest.generationID)")
        }
        var removablePublications: [InstallPublication] = []
        for publication in manifest.publications {
            let classification = try layout.publications.classify(publication)
            if classification == .owned {
                removablePublications.append(publication)
            } else if publication.kind != .directory || classification != .compatible {
                throw InstallError.collision(publication.path.description)
            }
        }
        return try MacOSInstallerPreview(
            schemaVersion: 2,
            operation: .uninstall,
            generationID: manifest.generationID,
            productVersion: manifest.productVersion,
            verifiedSourceEntries: 0,
            publicationChangeDetails: MacOSInstallerPublicationChange.removals(
                for: removablePublications
            ),
            pendingRecoveryTransactions: pendingTransactions,
            effects: [
                "restore prior DNS",
                "stop launchd services org.agenxy.Remap.daemon and org.agenxy.Remap.resolver",
                "remove manifest-owned publications",
                "purge the manifest-owned immutable generation",
                "remove empty native install storage /Library/Application Support/Agenxy/Remap/Install"
            ],
            approvalState: approvalState(for: context)
        )
    }

    public func previewRecovery(
        transactionID: String?
    ) throws -> MacOSInstallerRecoveryPreview {
        let transactionIDs = try layout.journals.transactionIDs()
        let transactions = try transactionIDs.map { identity in
            try MacOSInstallerRecoveryTransaction(
                records: layout.journals.load(transactionID: identity)
            )
        }
        let selected: [String]
        if let transactionID {
            try InstallManifest.validateIdentifier(transactionID, field: "recovery transaction ID")
            guard transactions.contains(where: { $0.transactionID == transactionID }) else {
                throw InstallError.approval("the requested recovery transaction no longer exists")
            }
            selected = [transactionID]
        } else {
            selected = transactions.filter(\.recoveryRequired).map(\.transactionID)
        }
        let known = Set(transactionIDs)
        let completed = try layout.journals.completedTransactionNames()
        let orphans = try layout.generations.orphanedStagingTransactionIDs(
            knownTransactionIDs: known
        )
        let detached = try layout.generations.detachedGenerationNames()
        let removesProductStorage =
            try layout.generations.ownedManifests().isEmpty
                && layout.hasOwnedProductStorage()
        let effects = recoveryEffects(
            requestedTransactionID: transactionID,
            selectedTransactionIDs: Set(selected),
            transactions: transactions,
            completedTransactionNames: completed,
            orphanedTransactionIDs: orphans,
            detachedGenerationNames: detached,
            removesProductStorage: removesProductStorage
        )
        return try MacOSInstallerRecoveryPreview(
            requestedTransactionID: transactionID,
            selectedTransactionIDs: selected,
            transactions: transactions,
            orphanedStagingTransactionIDs: orphans,
            detachedGenerationNames: detached,
            effects: effects
        )
    }

    public func recover(
        transactionID: String,
        approvalToken: InstallApprovalToken
    ) async throws {
        let approvedPreview = try previewRecovery(transactionID: transactionID)
        try requireApproval(approvalToken, matches: approvedPreview)
        let lock = try layout.lockConfiguration.acquire()
        defer { _ = lock }
        let lockedPreview = try previewRecovery(transactionID: transactionID)
        try requireApproval(approvalToken, matches: lockedPreview)
        try layout.prepareStorageTopology()
        try await recovery().recoverLocked(transactionID: transactionID)
        try collectTerminalGarbage()
    }

    public func recoverAll(
        approvalToken: InstallApprovalToken
    ) async throws -> MacOSInstallerRecoveryResult {
        let approvedPreview = try previewRecovery(transactionID: nil)
        try requireApproval(approvalToken, matches: approvedPreview)
        let lock = try layout.lockConfiguration.acquire()
        defer { _ = lock }
        let lockedPreview = try previewRecovery(transactionID: nil)
        try requireApproval(approvalToken, matches: lockedPreview)
        try layout.prepareStorageTopology()
        var recovered: [String] = []
        for transactionID in lockedPreview.selectedTransactionIDs {
            try await recovery().recoverLocked(transactionID: transactionID)
            recovered.append(transactionID)
        }
        let orphans = try layout.generations.quarantineOrphanedStaging(
            knownTransactionIDs: Set(lockedPreview.transactions.map(\.transactionID))
        )
        try collectTerminalGarbage()
        return MacOSInstallerRecoveryResult(
            schemaVersion: 1,
            recoveredTransactions: recovered.sorted(),
            quarantinedOrphans: orphans
        )
    }

    public func status() throws -> MacOSInstallerStatus {
        let manifests = try layout.generations.ownedManifests()
        let generations = manifests.map {
            MacOSInstallerGenerationStatus(
                generationID: $0.generationID,
                productVersion: $0.productVersion
            )
        }
        let transactions: [MacOSInstallerTransactionStatus] = try layout.journals
            .transactionIDs().compactMap { transactionID in
                let records = try layout.journals.load(transactionID: transactionID)
                guard let latest = records.last else {
                    return nil
                }
                return try MacOSInstallerTransactionStatus(
                    transactionID: transactionID,
                    operation: latest.operation,
                    phase: latest.phase,
                    recoveryRequired: InstallRecoveryStateMachine.nextAction(for: records) != .none
                )
            }
        let services = try MacOSLaunchdServiceKind.allCases.map(serviceStatus)
        let dnsState = try resolver.observation()
        let dns = MacOSInstallerDNSStatus(
            active: dnsState.activeRecord,
            productVersion: dnsState.productVersion,
            configuredServiceCount: dnsState.configuredServiceIDs.count,
            effectiveRemapServiceCount: dnsState.remapServiceIDs.count
        )
        return try MacOSInstallerStatus(
            schemaVersion: 1,
            activeGenerationID: activeGenerationID(in: manifests),
            generations: generations,
            transactions: transactions,
            services: services,
            dns: dns
        )
    }

    private func activeGenerationID(in manifests: [InstallManifest]) throws -> String? {
        let currentPath = try InstallRelativePath("\(MacOSInstallLayout.installerBase)/current")
        for manifest in manifests {
            guard let publication = manifest.publications.first(where: { $0.path == currentPath }) else {
                continue
            }
            if try layout.publications.classify(publication) == .owned {
                return manifest.generationID
            }
        }
        guard try layout.authority.metadata(at: currentPath) == nil else {
            throw InstallError.collision(currentPath.description)
        }
        return nil
    }

    private func loadPrevious(
        for operation: InstallOperation,
        manifest: InstallManifest
    ) throws -> InstallManifest? {
        switch operation {
        case .install:
            return nil
        case .update:
            guard let generationID = manifest.previousGenerationID else {
                throw InstallError.invalidManifest("an update has no previous generation identity")
            }
            let previous = try layout.generations.loadManifest(for: generationID)
            guard case .owned = try layout.generations.classify(previous) else {
                throw InstallError.collision("previous generation \(generationID)")
            }
            return previous
        case .uninstall:
            throw InstallError.unsupported("uninstall has no source manifest")
        }
    }

    private func validateSource(
        _ manifest: InstallManifest,
        authority: FileSystemAuthority
    ) throws {
        try manifest.validate()
        try manifest.entries.forEach { try authority.verifySource($0, at: $0.path) }
        _ = try MacOSGenerationImageStore(layout: layout).validateSource(manifest, authority: authority)
    }

    private func approvalState(
        for context: InstallTransitionContext
    ) throws -> MacOSInstallerApprovalState {
        let manifests = try layout.generations.ownedManifests()
        let generations = try manifests.map(MacOSInstallerApprovalGeneration.init(manifest:))
        let publicationStates = try approvalPublications(for: context).map { publication in
            try MacOSInstallerApprovalPublicationState(
                publication: publication,
                classification: layout.publications.classify(publication)
            )
        }
        let services = try MacOSLaunchdServiceKind.allCases.map(serviceStatus)
        let dnsState = try resolver.observation()
        let dns = MacOSInstallerDNSStatus(
            active: dnsState.activeRecord,
            productVersion: dnsState.productVersion,
            configuredServiceCount: dnsState.configuredServiceIDs.count,
            effectiveRemapServiceCount: dnsState.remapServiceIDs.count
        )
        return try MacOSInstallerApprovalState(
            manifestDigest: context.current.digest(),
            previousManifestDigest: context.previous?.digest(),
            activeGenerationID: activeGenerationID(in: manifests),
            installedGenerations: generations,
            publicationStates: publicationStates,
            services: services,
            dns: dns
        )
    }

    private func approvalPublications(
        for context: InstallTransitionContext
    ) -> [InstallPublication] {
        let previous = Dictionary(
            uniqueKeysWithValues: (context.previous?.publications ?? []).map {
                ($0.path, $0)
            }
        )
        let current = Dictionary(
            uniqueKeysWithValues: context.current.publications.map {
                ($0.path, $0)
            }
        )
        return Set(previous.keys).union(current.keys).sorted().compactMap { path in
            previous[path] ?? current[path]
        }
    }

    private func requireApproval(
        _ supplied: InstallApprovalToken,
        matches preview: MacOSInstallerPreview
    ) throws {
        guard supplied == preview.approvalToken else {
            throw InstallError.approval("the approved preview is stale or does not match this operation")
        }
    }

    private func requireApproval(
        _ supplied: InstallApprovalToken,
        matches preview: MacOSInstallerRecoveryPreview
    ) throws {
        guard supplied == preview.approvalToken else {
            throw InstallError.approval("the approved recovery preview is stale or does not match")
        }
    }

    private func recoveryEffects(
        requestedTransactionID: String?,
        selectedTransactionIDs: Set<String>,
        transactions: [MacOSInstallerRecoveryTransaction],
        completedTransactionNames: [String],
        orphanedTransactionIDs: [String],
        detachedGenerationNames: [String],
        removesProductStorage: Bool
    ) -> [String] {
        var effects: [String] = []
        for transaction in transactions {
            if selectedTransactionIDs.contains(transaction.transactionID) {
                effects.append(
                    "recover and collect transaction \(transaction.transactionID) from \(transaction.phase.rawValue)"
                )
            } else if !transaction.recoveryRequired {
                effects.append("collect terminal journal \(transaction.transactionID)")
            }
        }
        effects += completedTransactionNames.map { "purge completed journal \($0)" }
        if requestedTransactionID == nil {
            effects += orphanedTransactionIDs.map {
                "quarantine and purge orphan staging transaction \($0)"
            }
        }
        effects += detachedGenerationNames.map { "purge detached generation \($0)" }
        if removesProductStorage {
            effects.append(
                "remove empty native install storage /Library/Application Support/Agenxy/Remap/Install"
            )
        }
        return effects
    }

    private func serviceStatus(_ kind: MacOSLaunchdServiceKind) throws -> MacOSInstallerServiceStatus {
        switch try launchd.observation(label: kind.label) {
        case .missing:
            MacOSInstallerServiceStatus(
                label: kind.label,
                loaded: false,
                plistPath: nil,
                programPath: nil
            )
        case let .loaded(plistPath, programPath):
            MacOSInstallerServiceStatus(
                label: kind.label,
                loaded: true,
                plistPath: plistPath.value,
                programPath: programPath.value
            )
        }
    }

    private func completeUninstallCleanup() throws {
        let lock = try layout.lockConfiguration.acquire()
        defer { _ = lock }
        try collectTerminalGarbage()
    }

    private func collectTerminalGarbage() throws {
        _ = try layout.generations.purgeDetachedGenerations()
        _ = try layout.journals.collectTerminalTransactions()
        guard try layout.generations.ownedManifests().isEmpty,
              try layout.journals.transactionIDs().isEmpty
        else {
            return
        }
        try layout.removeEmptyProductStorage()
    }

    static func previewEffects(previousGenerationID: String?) -> [String] {
        var effects = [
            "publish immutable generation",
            "load launchd services org.agenxy.Remap.daemon and org.agenxy.Remap.resolver",
            "activate native system DNS",
            "publish manifest-owned paths",
            "verify authenticated runtime"
        ]
        if let previousGenerationID {
            effects.append("keep ordinary internet DNS active while replacing Remap services")
            effects.append("preload and verify the new forwarding plan before reactivating Remap DNS")
            effects.append("purge previous generation \(previousGenerationID)")
        }
        return effects
    }
}

private extension MacOSInstaller {
    func coordinator(
        approvalVerifier: any InstallApprovalVerifying
    ) -> InstallTransactionCoordinator {
        InstallTransactionCoordinator(
            lockConfiguration: layout.lockConfiguration,
            generations: layout.generations,
            publications: layout.publications,
            journal: layout.journals,
            effects: effects,
            approvalVerifier: approvalVerifier,
            prepareStorage: { try layout.prepareStorageTopology() },
            validateManifest: validateNativePublicationContract
        )
    }

    func recovery() -> InstallCrashRecoveryExecutor {
        InstallCrashRecoveryExecutor(
            lockConfiguration: layout.lockConfiguration,
            generations: layout.generations,
            publications: layout.publications,
            journal: layout.journals,
            effects: effects,
            validateManifest: validateNativePublicationContract
        )
    }

    func validateNativePublicationContract(_ manifest: InstallManifest) throws {
        guard layout.systemRootPath == "/" else { return }
        try MacOSInstallConfiguration.validatePublicationContract(
            for: manifest,
            installOwnerUID: layout.installOwnerUID,
            installGroupGID: layout.installGroupGID
        )
    }
}

private struct MacOSInstallerApprovalVerifier: InstallApprovalVerifying {
    let installer: MacOSInstaller
    let expectedToken: InstallApprovalToken
    let verifiedSourceEntries: Int

    func verify(_ context: InstallTransitionContext) throws {
        let preview: MacOSInstallerPreview
        do {
            preview = try installer.approvalPreview(
                for: context,
                verifiedSourceEntries: verifiedSourceEntries
            )
        } catch {
            throw InstallError.approval("authoritative installer state changed after preview")
        }
        guard preview.approvalToken == expectedToken else {
            throw InstallError.approval("authoritative installer state changed after preview")
        }
    }
}
