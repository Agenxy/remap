import Darwin
import Foundation
@testable import RemapInstallKit
import Testing

@Test
func freshInstallCommitsOnlyVerifiedEffects() async throws {
    let harness = try InstallTransactionHarness()
    let data = Data("current".utf8)
    let source = try harness.source(data: data, name: "source-current")
    let manifest = try harness.manifest(generationID: "current", previousGenerationID: nil, data: data)
    let context = try InstallTransitionContext(operation: .install, current: manifest, previous: nil)
    let request = try InstallTransactionRequest(
        transactionID: "install-current",
        context: context,
        source: source
    )
    let effects = TestSystemEffectAdapter()
    let journal = harness.journal()
    try await harness.coordinator(journal: journal, effects: effects).installOrUpdate(request)
    #expect(try journal.transactionIDs().isEmpty)
    #expect(try journal.completedTransactionNames().isEmpty)
    #expect(try harness.generations.classify(manifest) == .owned(manifest.digest()))
    #expect(try harness.publications.classify(manifest.publications[0]) == .owned)
    #expect(effects.calls == expectedInstallEffectCalls)
}

@Test
func rejectedApprovalAtTheTransactionLockHasNoObservableEffects() async throws {
    let harness = try InstallTransactionHarness()
    let data = Data("approval".utf8)
    let source = try harness.source(data: data, name: "approval-source")
    let manifest = try harness.manifest(
        generationID: "approval-generation",
        previousGenerationID: nil,
        data: data
    )
    let request = try InstallTransactionRequest(
        transactionID: "approval-rejected",
        context: InstallTransitionContext(operation: .install, current: manifest, previous: nil),
        source: source
    )
    let effects = TestSystemEffectAdapter()
    let journal = harness.journal()

    await #expect(throws: InstallError.approval("rejected by test")) {
        try await harness.coordinator(
            journal: journal,
            effects: effects,
            approvalVerifier: RejectingInstallApprovalVerifier()
        ).installOrUpdate(request)
    }
    #expect(try journal.load(transactionID: request.transactionID).isEmpty)
    #expect(try harness.generations.classify(manifest) == .missing)
    #expect(effects.calls.isEmpty)
}

private struct RejectingInstallApprovalVerifier: InstallApprovalVerifying {
    func verify(_: InstallTransitionContext) throws {
        throw InstallError.approval("rejected by test")
    }
}

@Test
func crashRecoveryValidatesManifestBeforeRestoringPublications() async throws {
    let harness = try InstallTransactionHarness()
    let data = Data("installed".utf8)
    let source = try harness.source(data: data, name: "recovery-validation-source")
    let manifest = try harness.manifest(
        generationID: "recovery-validation",
        previousGenerationID: nil,
        data: data
    )
    try harness.prepareInstalled(
        manifest: manifest,
        source: source,
        transactionID: "recovery-validation-setup"
    )
    let journal = harness.journal()
    let context = try InstallTransitionContext(
        operation: .uninstall,
        current: manifest,
        previous: nil
    )
    try InstallJournalWriter(store: journal).appendInitial(
        transactionID: "recovery-validation",
        context: context,
        phase: .uninstallPrepared
    )
    let effects = TestSystemEffectAdapter()
    await #expect(throws: InstallError.invalidManifest("rejected recovery manifest")) {
        try await harness.recovery(
            journal: journal,
            effects: effects,
            validateManifest: { _ in
                throw InstallError.invalidManifest("rejected recovery manifest")
            }
        ).recover(transactionID: "recovery-validation")
    }
    #expect(effects.calls.isEmpty)
    #expect(try harness.publications.classify(manifest.publications[0]) == .owned)
}

@Test
func committedPurgeRecoveryValidatesManifestBeforeRemovingGenerationBytes() async throws {
    let harness = try InstallTransactionHarness()
    let data = Data("purge-validation".utf8)
    let source = try harness.source(data: data, name: "purge-validation-source")
    let manifest = try harness.manifest(
        generationID: "purge-validation",
        previousGenerationID: nil,
        data: data
    )
    try harness.prepareInstalled(
        manifest: manifest,
        source: source,
        transactionID: "purge-validation-setup"
    )
    let transactionID = "purge-validation"
    await #expect(throws: InstallError.faultInjected("journal-append-7")) {
        try await harness.coordinator(
            journal: harness.journal(
                faultInjector: CountingCheckpointFaultInjector(failureOrdinal: 7)
            ),
            effects: TestSystemEffectAdapter()
        ).uninstall(transactionID: transactionID, manifest: manifest)
    }
    await #expect(throws: InstallError.invalidManifest("rejected purge manifest")) {
        try await harness.recovery(
            journal: harness.journal(),
            effects: TestSystemEffectAdapter(),
            validateManifest: { _ in
                throw InstallError.invalidManifest("rejected purge manifest")
            }
        ).recover(transactionID: transactionID)
    }
    #expect(
        try harness.generations.classifyRetired(manifest, transactionID: transactionID)
            == .owned(manifest.digest())
    )
}

@Test
func updateCommitsWithExactPreviousGenerationOwnership() async throws {
    let harness = try InstallTransactionHarness()
    let previousData = Data("previous".utf8)
    let previousSource = try harness.source(data: previousData, name: "source-previous")
    let previous = try harness.manifest(generationID: "previous", previousGenerationID: nil, data: previousData)
    try harness.prepareInstalled(manifest: previous, source: previousSource, transactionID: "setup-previous")
    let currentData = Data("current".utf8)
    let currentSource = try harness.source(data: currentData, name: "source-current")
    let current = try harness.manifest(
        generationID: "current",
        previousGenerationID: previous.generationID,
        data: currentData
    )
    let context = try InstallTransitionContext(operation: .update, current: current, previous: previous)
    let request = try InstallTransactionRequest(
        transactionID: "update-current",
        context: context,
        source: currentSource
    )
    let journal = harness.journal()
    try await harness.coordinator(
        journal: journal,
        effects: TestSystemEffectAdapter()
    ).installOrUpdate(request)
    #expect(try journal.transactionIDs().isEmpty)
    #expect(try journal.completedTransactionNames().isEmpty)
    #expect(try harness.generations.classify(previous) == .missing)
    #expect(try harness.generations.classifyRetired(
        previous,
        transactionID: request.transactionID
    ) == .missing)
    #expect(try harness.generations.classify(current) == .owned(current.digest()))
    #expect(try harness.publications.classify(current.publications[0]) == .owned)
}

@Test
func sequentialUpdatesRetainOnlyTheCurrentGeneration() async throws {
    let harness = try InstallTransactionHarness()
    let initialData = Data("generation-0".utf8)
    let initialSource = try harness.source(data: initialData, name: "source-generation-0")
    var previous = try harness.manifest(
        generationID: "generation-0",
        previousGenerationID: nil,
        data: initialData
    )
    try harness.prepareInstalled(
        manifest: previous,
        source: initialSource,
        transactionID: "setup-generation-0"
    )

    for index in 1 ... 40 {
        let data = Data("generation-\(index)".utf8)
        let source = try harness.source(data: data, name: "source-generation-\(index)")
        let current = try harness.manifest(
            generationID: "generation-\(index)",
            previousGenerationID: previous.generationID,
            data: data
        )
        let request = try InstallTransactionRequest(
            transactionID: "update-generation-\(index)",
            context: InstallTransitionContext(operation: .update, current: current, previous: previous),
            source: source
        )
        let journal = harness.journal()
        try await harness.coordinator(
            journal: journal,
            effects: TestSystemEffectAdapter()
        ).installOrUpdate(request)
        #expect(try journal.transactionIDs().isEmpty)
        #expect(try journal.completedTransactionNames().isEmpty)
        #expect(try harness.generations.ownedManifests().map(\.generationID) == [current.generationID])
        previous = current
    }
}

@Test
func failedUpdateImmediatelyRestoresTheExactPreviousGeneration() async throws {
    let harness = try InstallTransactionHarness()
    let previousData = Data("previous".utf8)
    let previousSource = try harness.source(data: previousData, name: "source-previous")
    let previous = try harness.manifest(generationID: "previous", previousGenerationID: nil, data: previousData)
    try harness.prepareInstalled(manifest: previous, source: previousSource, transactionID: "setup-previous")
    let currentData = Data("current".utf8)
    let currentSource = try harness.source(data: currentData, name: "source-current")
    let current = try harness.manifest(
        generationID: "current",
        previousGenerationID: previous.generationID,
        data: currentData
    )
    let context = try InstallTransitionContext(operation: .update, current: current, previous: previous)
    let request = try InstallTransactionRequest(
        transactionID: "update-interrupted",
        context: context,
        source: currentSource
    )
    let faultingJournal = harness.journal(
        faultInjector: CountingCheckpointFaultInjector(failureOrdinal: 5)
    )
    let effects = TestSystemEffectAdapter()
    await #expect(throws: InstallError.faultInjected("journal-append-5")) {
        try await harness.coordinator(
            journal: faultingJournal,
            effects: effects
        ).installOrUpdate(request)
    }
    #expect(try faultingJournal.transactionIDs().isEmpty)
    #expect(try harness.publications.classify(previous.publications[0]) == .owned)
    #expect(try harness.generations.classify(previous) == .owned(previous.digest()))
    #expect(try harness.generations.classifyRetired(current, transactionID: request.transactionID) == .missing)
    #expect(effects.calls.suffix(4) == [
        "reconcile:priorServiceRestored",
        "verify:priorServiceRestored",
        "reconcile:dnsRestored",
        "verify:dnsRestored"
    ])
}

@Test
func verificationFailureImmediatelyRollsBackWithoutFalseProgress() async throws {
    let harness = try InstallTransactionHarness()
    let data = Data("current".utf8)
    let source = try harness.source(data: data, name: "source-current")
    let manifest = try harness.manifest(generationID: "current", previousGenerationID: nil, data: data)
    let context = try InstallTransitionContext(operation: .install, current: manifest, previous: nil)
    let request = try InstallTransactionRequest(
        transactionID: "verify-failure",
        context: context,
        source: source
    )
    let effects = TestSystemEffectAdapter(
        fault: TestEffectFault(effect: .dnsActive, stage: .verify)
    )
    let journal = harness.journal()
    await #expect(throws: InstallError.faultInjected("verify-dnsActive")) {
        try await harness.coordinator(journal: journal, effects: effects).installOrUpdate(request)
    }
    #expect(try journal.transactionIDs().isEmpty)
    let recovery = harness.recovery(journal: journal, effects: TestSystemEffectAdapter())
    try await recovery.recover(transactionID: request.transactionID)
    #expect(try journal.transactionIDs().isEmpty)
    #expect(try harness.generations.classifyRetired(manifest, transactionID: request.transactionID) == .missing)
}

@Test(arguments: installEffectFaults)
func everyInstallEffectBoundaryImmediatelyRollsBackWithoutFalseProgress(
    fault: TestEffectFault
) async throws {
    let harness = try InstallTransactionHarness()
    let data = Data("effect-boundary".utf8)
    let source = try harness.source(data: data, name: "effect-boundary-source")
    let manifest = try harness.manifest(
        generationID: "effect-boundary",
        previousGenerationID: nil,
        data: data
    )
    let context = try InstallTransitionContext(operation: .install, current: manifest, previous: nil)
    let request = try InstallTransactionRequest(
        transactionID: "install-\(fault.effect.rawValue)-\(fault.stage.name)",
        context: context,
        source: source
    )
    let journal = harness.journal()
    await #expect(throws: InstallError.faultInjected(fault.diagnostic)) {
        try await harness.coordinator(
            journal: journal,
            effects: TestSystemEffectAdapter(fault: fault)
        ).installOrUpdate(request)
    }
    #expect(try journal.transactionIDs().isEmpty)
    #expect(try harness.generations.classifyRetired(manifest, transactionID: request.transactionID) == .missing)
}

@Test
func failedImmediateRollbackRemainsDurablyRecoverable() async throws {
    let harness = try InstallTransactionHarness()
    let data = Data("rollback-failure".utf8)
    let source = try harness.source(data: data, name: "rollback-failure-source")
    let manifest = try harness.manifest(
        generationID: "rollback-failure",
        previousGenerationID: nil,
        data: data
    )
    let request = try InstallTransactionRequest(
        transactionID: "rollback-failure",
        context: InstallTransitionContext(operation: .install, current: manifest, previous: nil),
        source: source
    )
    let journal = harness.journal(
        faultInjector: CountingCheckpointFaultInjector(failureOrdinal: 3)
    )
    do {
        try await harness.coordinator(
            journal: journal,
            effects: TestSystemEffectAdapter(
                fault: TestEffectFault(effect: .serviceRunning, stage: .verify)
            )
        ).installOrUpdate(request)
        Issue.record("expected the install and its immediate rollback to fail")
    } catch let error as InstallError {
        guard case .transaction = error else {
            Issue.record("expected a combined transaction failure, got \(error)")
            return
        }
    }
    #expect(try journal.load(transactionID: request.transactionID).last?.phase == .generationPublished)
    try await harness.recovery(
        journal: harness.journal(),
        effects: TestSystemEffectAdapter()
    ).recover(transactionID: request.transactionID)
    #expect(try harness.generations.classifyRetired(manifest, transactionID: request.transactionID) == .missing)
}

@Test(arguments: uninstallEffectFaults)
func everyUninstallEffectBoundaryResumesWithoutFalseProgress(fault: TestEffectFault) async throws {
    let harness = try InstallTransactionHarness()
    let data = Data("uninstall-effect-boundary".utf8)
    let source = try harness.source(data: data, name: "uninstall-effect-source")
    let manifest = try harness.manifest(
        generationID: "uninstall-effect-boundary",
        previousGenerationID: nil,
        data: data
    )
    try harness.prepareInstalled(manifest: manifest, source: source, transactionID: "effect-setup")
    let transactionID = "uninstall-\(fault.effect.rawValue)-\(fault.stage.name)"
    let journal = harness.journal()
    await #expect(throws: InstallError.faultInjected(fault.diagnostic)) {
        try await harness.coordinator(
            journal: journal,
            effects: TestSystemEffectAdapter(fault: fault)
        ).uninstall(transactionID: transactionID, manifest: manifest)
    }
    let failedPhases = try journal.load(transactionID: transactionID).map(\.phase)
    #expect(failedPhases.last == fault.lastCompletedUninstallPhase)
    let recovery = harness.recovery(journal: journal, effects: TestSystemEffectAdapter())
    try await recovery.recover(transactionID: transactionID)
    #expect(try journal.load(transactionID: transactionID).last?.phase == .generationPurged)
    #expect(try harness.publications.classify(manifest.publications[0]) == .missing)
    #expect(try harness.generations.classifyRetired(manifest, transactionID: transactionID) == .missing)
}

@Test(arguments: Array(1 ... 7))
func everyInstallJournalBoundaryImmediatelyRollsBack(failureOrdinal: Int) async throws {
    let harness = try InstallTransactionHarness()
    let data = Data("boundary-\(failureOrdinal)".utf8)
    let source = try harness.source(data: data, name: "source-\(failureOrdinal)")
    let manifest = try harness.manifest(
        generationID: "generation-\(failureOrdinal)",
        previousGenerationID: nil,
        data: data
    )
    let context = try InstallTransitionContext(operation: .install, current: manifest, previous: nil)
    let transactionID = "install-boundary-\(failureOrdinal)"
    let request = try InstallTransactionRequest(
        transactionID: transactionID,
        context: context,
        source: source
    )
    let fault = CountingCheckpointFaultInjector(failureOrdinal: failureOrdinal)
    let faultingJournal = harness.journal(faultInjector: fault)
    await #expect(throws: InstallError.faultInjected("journal-append-\(failureOrdinal)")) {
        try await harness.coordinator(
            journal: faultingJournal,
            effects: TestSystemEffectAdapter()
        ).installOrUpdate(request)
    }
    let journal = harness.journal()
    if failureOrdinal == 1 {
        #expect(try journal.load(transactionID: transactionID).isEmpty)
        #expect(try harness.generations
            .classifyAbandoned(manifest, transactionID: transactionID) == .owned(manifest.digest()))
        return
    }
    #expect(try journal.load(transactionID: transactionID).isEmpty)
    #expect(try harness.generations.classifyRetired(manifest, transactionID: transactionID) == .missing)
}

@Test(arguments: Array(2 ... 9))
func everyUninstallJournalBoundaryResumesIdempotently(failureOrdinal: Int) async throws {
    let harness = try InstallTransactionHarness()
    let data = Data("installed-\(failureOrdinal)".utf8)
    let source = try harness.source(data: data, name: "installed-source-\(failureOrdinal)")
    let manifest = try harness.manifest(
        generationID: "installed-\(failureOrdinal)",
        previousGenerationID: nil,
        data: data
    )
    try harness.prepareInstalled(manifest: manifest, source: source, transactionID: "setup-\(failureOrdinal)")
    let transactionID = "uninstall-boundary-\(failureOrdinal)"
    let faultingJournal = harness.journal(
        faultInjector: CountingCheckpointFaultInjector(failureOrdinal: failureOrdinal)
    )
    await #expect(throws: InstallError.faultInjected("journal-append-\(failureOrdinal)")) {
        try await harness.coordinator(
            journal: faultingJournal,
            effects: TestSystemEffectAdapter()
        ).uninstall(transactionID: transactionID, manifest: manifest)
    }
    let healthyJournal = harness.journal()
    let recovery = harness.recovery(journal: healthyJournal, effects: TestSystemEffectAdapter())
    try await recovery.recover(transactionID: transactionID)
    let recovered = try healthyJournal.load(transactionID: transactionID)
    #expect(recovered.last?.phase == .generationPurged)
    let recordCount = recovered.count
    try await recovery.recover(transactionID: transactionID)
    #expect(try healthyJournal.load(transactionID: transactionID).count == recordCount)
    #expect(try harness.generations.classifyRetired(manifest, transactionID: transactionID) == .missing)
    #expect(try harness.publications.classify(manifest.publications[0]) == .missing)
}

@Test
func uninstallPreservesAnUnmanagedReplacement() async throws {
    let harness = try InstallTransactionHarness()
    let data = Data("installed".utf8)
    let source = try harness.source(data: data, name: "installed-source")
    let manifest = try harness.manifest(generationID: "installed", previousGenerationID: nil, data: data)
    try harness.prepareInstalled(manifest: manifest, source: source, transactionID: "setup")
    let publicationURL = harness.root.appending(path: "Public/remap")
    try FileManager.default.removeItem(at: publicationURL)
    try FileManager.default.createDirectory(at: publicationURL, withIntermediateDirectories: false)
    let sentinel = publicationURL.appending(path: "foreign")
    try writeTestFile(Data("preserve".utf8), to: sentinel)
    let journal = harness.journal()
    await #expect(throws: InstallError.collision("Public/remap")) {
        try await harness.coordinator(
            journal: journal,
            effects: TestSystemEffectAdapter()
        ).uninstall(transactionID: "unmanaged", manifest: manifest)
    }
    #expect(FileManager.default.fileExists(atPath: sentinel.path))
    #expect(try journal.load(transactionID: "unmanaged").isEmpty)
}

@Test
func uninstallRejectsAValidLookingButMismatchedManifest() async throws {
    let harness = try InstallTransactionHarness()
    let installedData = Data("installed".utf8)
    let source = try harness.source(data: installedData, name: "installed-source")
    let installed = try harness.manifest(
        generationID: "installed",
        previousGenerationID: nil,
        data: installedData
    )
    try harness.prepareInstalled(manifest: installed, source: source, transactionID: "setup")
    let forged = try harness.manifest(
        generationID: installed.generationID,
        previousGenerationID: nil,
        data: Data("forged".utf8)
    )
    let journal = harness.journal()
    await #expect(throws: InstallError.collision("generation installed")) {
        try await harness.coordinator(
            journal: journal,
            effects: TestSystemEffectAdapter()
        ).uninstall(transactionID: "forged-uninstall", manifest: forged)
    }
    #expect(try journal.load(transactionID: "forged-uninstall").isEmpty)
    #expect(try harness.generations.classify(installed) == .owned(installed.digest()))
}

@Test
func unmanifestedGenerationContentRevokesOwnership() throws {
    let harness = try InstallTransactionHarness()
    let data = Data("installed".utf8)
    let source = try harness.source(data: data, name: "installed-source")
    let manifest = try harness.manifest(generationID: "installed", previousGenerationID: nil, data: data)
    try harness.prepareInstalled(manifest: manifest, source: source, transactionID: "setup")
    let generationURL = harness.root.appending(path: "Generations/installed")
    guard chmod(generationURL.path, 0o755) == 0 else {
        throw InstallError.operatingSystem("open test generation", errno)
    }
    try writeTestFile(Data("unmanifested".utf8), to: generationURL.appending(path: "intruder"))
    guard chmod(generationURL.path, 0o555) == 0 else {
        throw InstallError.operatingSystem("reseal test generation", errno)
    }
    #expect(try harness.generations.classify(manifest) == .unmanaged)
}

let installPhases: [InstallPhase] = [
    .prepared,
    .generationPublished,
    .serviceStarted,
    .dnsActive,
    .applicationPublished,
    .accepted,
    .committed
]

let purgePhases: [InstallPhase] = [
    .generationPurgePrepared,
    .generationContentsPurged,
    .generationPurged
]

let expectedInstallEffectCalls = [
    "reconcile:serviceRunning",
    "verify:serviceRunning",
    "reconcile:dnsActive",
    "verify:dnsActive",
    "reconcile:installationAccepted",
    "verify:installationAccepted"
]

let installEffectFaults = [
    TestEffectFault(effect: .serviceRunning, stage: .reconcile),
    TestEffectFault(effect: .serviceRunning, stage: .verify),
    TestEffectFault(effect: .dnsActive, stage: .reconcile),
    TestEffectFault(effect: .dnsActive, stage: .verify),
    TestEffectFault(effect: .installationAccepted, stage: .reconcile),
    TestEffectFault(effect: .installationAccepted, stage: .verify)
]

let uninstallEffectFaults = [
    TestEffectFault(effect: .dnsRestored, stage: .reconcile),
    TestEffectFault(effect: .dnsRestored, stage: .verify),
    TestEffectFault(effect: .serviceStopped, stage: .reconcile),
    TestEffectFault(effect: .serviceStopped, stage: .verify)
]
