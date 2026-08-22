import Darwin
import Foundation
@testable import RemapInstallKit
import Testing

@Test
func interruptedGenerationPurgeResumesFromManifestBoundSubset() throws {
    let fixture = try GenerationPurgeFixture()
    try fixture.store.retire(fixture.manifest, transactionID: fixture.transactionID)
    let faulting = try fixture.store(faultInjector: CheckpointFaultInjector(checkpoint: .beforeRemove))
    #expect(throws: InstallError.faultInjected("beforeRemove")) {
        try faulting.purgeContents(
            generationID: fixture.manifest.generationID,
            transactionID: fixture.transactionID
        )
    }
    try fixture.store.purgeContents(
        generationID: fixture.manifest.generationID,
        transactionID: fixture.transactionID
    )
    try fixture.store.finishPurge(
        generationID: fixture.manifest.generationID,
        transactionID: fixture.transactionID
    )
    #expect(try fixture.store.classifyRetired(
        fixture.manifest,
        transactionID: fixture.transactionID
    ) == .missing)
}

@Test
func generationPurgePreservesAnUnmanifestedRetiredReplacement() throws {
    let fixture = try GenerationPurgeFixture()
    try fixture.store.retire(fixture.manifest, transactionID: fixture.transactionID)
    let retiredURL = try fixture.retiredURL()
    let retired = try #require(retiredURL)
    guard chmod(retired.path, 0o700) == 0 else {
        throw InstallError.operatingSystem("open retired generation for adversarial test", errno)
    }
    let sentinel = retired.appending(path: "unmanaged")
    try writeTestFile(Data("preserve".utf8), to: sentinel)
    guard chmod(retired.path, mode_t(GenerationStore.generationRootMode)) == 0 else {
        throw InstallError.operatingSystem("reseal retired generation after adversarial test", errno)
    }
    #expect(throws: InstallError.collision(retired.path.replacingOccurrences(
        of: fixture.root.path + "/",
        with: ""
    ))) {
        try fixture.store.purgeContents(
            generationID: fixture.manifest.generationID,
            transactionID: fixture.transactionID
        )
    }
    #expect(FileManager.default.fileExists(atPath: sentinel.path))
}

@Test
func interruptedAbandonedGenerationCollectionResumesWithoutAJournal() async throws {
    let harness = try InstallTransactionHarness()
    let data = Data("abandoned".utf8)
    let source = try harness.source(data: data, name: "abandoned-source")
    let manifest = try harness.manifest(
        generationID: "abandoned-generation",
        previousGenerationID: nil,
        data: data
    )
    let transactionID = "abandoned-transaction"
    let request = try InstallTransactionRequest(
        transactionID: transactionID,
        context: InstallTransitionContext(operation: .install, current: manifest, previous: nil),
        source: source
    )
    await #expect(throws: InstallError.faultInjected("journal-append-1")) {
        try await harness.coordinator(
            journal: harness.journal(
                faultInjector: CountingCheckpointFaultInjector(failureOrdinal: 1)
            ),
            effects: TestSystemEffectAdapter()
        ).installOrUpdate(request)
    }
    let faultingAuthority = try testAuthority(
        at: harness.root,
        faultInjector: CheckpointFaultInjector(checkpoint: .beforeRemove)
    )
    let faultingStore = try GenerationStore(
        authority: faultingAuthority,
        generationsPath: InstallRelativePath("Generations"),
        ownerUID: UInt32(geteuid()),
        groupGID: UInt32(getegid())
    )
    #expect(throws: InstallError.faultInjected("beforeRemove")) {
        try faultingStore.purgeDetachedGenerations()
    }
    #expect(try harness.generations.purgeDetachedGenerations().count == 1)
    #expect(try harness.generations.classifyAbandoned(
        manifest,
        transactionID: transactionID
    ) == .missing)
}

private final class GenerationPurgeFixture: @unchecked Sendable {
    let tree: TemporaryInstallTree
    let root: URL
    let manifest: InstallManifest
    let transactionID = "purge-transaction"
    let store: GenerationStore

    init() throws {
        tree = try TemporaryInstallTree()
        root = try tree.directory("purge-root")
        let sourceURL = try tree.directory("purge-source")
        let data = Data("purge-data".utf8)
        try writeTestFile(data, to: sourceURL.appending(path: "remap"))
        manifest = try testManifest(entries: [testEntry(path: "remap", data: data)])
        store = try Self.makeStore(root: root)
        let source = try testAuthority(at: sourceURL)
        let staging = try store.stage(manifest, from: source, transactionID: "purge-setup")
        try store.publish(staging, manifest: manifest)
    }

    func store(faultInjector: any InstallFaultInjecting) throws -> GenerationStore {
        try Self.makeStore(root: root, faultInjector: faultInjector)
    }

    func retiredURL() throws -> URL? {
        let generations = root.appending(path: "Generations")
        let name = try FileManager.default.contentsOfDirectory(atPath: generations.path)
            .first { $0.hasPrefix(".retired-") }
        return name.map { generations.appending(path: $0) }
    }

    private static func makeStore(
        root: URL,
        faultInjector: any InstallFaultInjecting = NoInstallFaultInjector()
    ) throws -> GenerationStore {
        let authority = try testAuthority(at: root, faultInjector: faultInjector)
        return try GenerationStore(
            authority: authority,
            generationsPath: InstallRelativePath("Generations"),
            ownerUID: UInt32(geteuid()),
            groupGID: UInt32(getegid())
        )
    }
}
