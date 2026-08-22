import Darwin
import Foundation
@testable import RemapInstallKit
import Testing

@Test
func generationIsStagedPublishedAndClassifiedByManifest() throws {
    let tree = try TemporaryInstallTree()
    let sourceURL = try tree.directory("source")
    let destinationURL = try tree.directory("destination")
    let data = Data("immutable generation".utf8)
    try writeTestFile(data, to: sourceURL.appending(path: "remap"))
    let entry = try testEntry(path: "remap", data: data, role: .commandLineTool)
    let manifest = try testManifest(entries: [entry])
    let source = try testAuthority(at: sourceURL)
    let destination = try testAuthority(at: destinationURL)
    let generations = try GenerationStore(
        authority: destination,
        generationsPath: InstallRelativePath("Generations"),
        ownerUID: UInt32(geteuid()),
        groupGID: UInt32(getegid())
    )
    let staging = try generations.stage(manifest, from: source, transactionID: "transaction-1")
    try generations.publish(staging, manifest: manifest)
    #expect(try generations.classify(manifest) == .owned(manifest.digest()))
    #expect(try generations.loadManifest(for: manifest.generationID) == manifest)
    let generationPath = try InstallRelativePath("Generations/generation-1")
    #expect(try destination.metadata(at: generationPath)?.mode == GenerationStore.generationRootMode)
}

@Test
func generationCollisionIsNeverAdoptedWithoutTheExactManifest() throws {
    let tree = try TemporaryInstallTree()
    let root = try tree.directory("root")
    let authority = try testAuthority(at: root)
    try authority.createDirectory(
        at: InstallRelativePath("Generations/generation-1"),
        ownerUID: UInt32(geteuid()),
        groupGID: UInt32(getegid()),
        mode: 0o700
    )
    let manifest = try testManifest(entries: [])
    let store = try GenerationStore(
        authority: authority,
        generationsPath: InstallRelativePath("Generations"),
        ownerUID: UInt32(geteuid()),
        groupGID: UInt32(getegid())
    )
    #expect(try store.classify(manifest) == .unmanaged)
}

@Test
func publicationUpdateUsesExactAtomicSymlinkExchange() throws {
    let tree = try TemporaryInstallTree()
    let root = try tree.directory("root")
    let authority = try testAuthority(at: root)
    try authority.ensureOwnedDirectory(
        at: InstallRelativePath("Applications"),
        ownerUID: UInt32(geteuid()),
        groupGID: UInt32(getegid()),
        mode: 0o755
    )
    let store = PublicationStore(authority: authority)
    let previous = try testPublication(
        path: "Applications/Remap.app",
        target: "/Generations/one/Remap.app",
        generationID: "one"
    )
    let next = try testPublication(
        path: "Applications/Remap.app",
        target: "/Generations/two/Remap.app",
        generationID: "two"
    )
    try store.publish(previous, replacing: nil, transactionID: "install-one")
    try store.publish(next, replacing: previous, transactionID: "update-two")
    #expect(try store.classify(next) == .owned)
    #expect(try authority.readSymbolicLink(at: next.path) == next.target?.value)
    #expect(try authority.listDirectory(at: InstallRelativePath("Applications")) == ["Remap.app"])
}

@Test
func publicationNeverCreatesAnUndeclaredParent() throws {
    let tree = try TemporaryInstallTree()
    let root = try tree.directory("missing-publication-parent")
    let authority = try testAuthority(at: root)
    let publication = try testPublication(
        path: "Missing/remap",
        target: "/Generations/one/remap",
        generationID: "one"
    )

    #expect(throws: InstallError.self) {
        try PublicationStore(authority: authority).publish(
            publication,
            replacing: nil,
            transactionID: "missing-parent"
        )
    }
    #expect(try authority.metadata(at: InstallRelativePath("Missing")) == nil)
}

@Test
func uninstallPreservesUnmanagedApplicationDirectoriesRecursively() throws {
    let tree = try TemporaryInstallTree()
    let root = try tree.directory("root")
    let application = root.appending(path: "Applications/Remap.app", directoryHint: .isDirectory)
    try FileManager.default.createDirectory(at: application, withIntermediateDirectories: true)
    let sentinel = application.appending(path: "foreign-data")
    try writeTestFile(Data("preserve me".utf8), to: sentinel)
    let authority = try testAuthority(at: root)
    let publication = try testPublication(
        path: "Applications/Remap.app",
        target: "/Generations/one/Remap.app",
        generationID: "one"
    )
    let store = PublicationStore(authority: authority)
    #expect(throws: InstallError.collision("Applications/Remap.app")) {
        try store.unpublish(publication)
    }
    #expect(FileManager.default.fileExists(atPath: sentinel.path))
}

@Test
func directoryPublicationRemovesOnlyAProvenanceBoundDirectory() throws {
    let tree = try TemporaryInstallTree()
    let root = try tree.directory("directory-publication")
    let authority = try testAuthority(at: root)
    try authority.ensureOwnedDirectory(
        at: InstallRelativePath("Shared"),
        ownerUID: UInt32(geteuid()),
        groupGID: UInt32(getegid()),
        mode: 0o755
    )
    let publication = try InstallPublication(
        path: InstallRelativePath("Shared/Created"),
        generationID: "generation-1",
        ownerUID: UInt32(geteuid()),
        groupGID: UInt32(getegid())
    )
    let store = PublicationStore(authority: authority)

    try store.publish(publication, replacing: nil, transactionID: "directory-create")
    #expect(try store.classify(publication) == .owned)
    try store.unpublish(publication)
    #expect(try store.classify(publication) == .missing)
    #expect(try authority.listDirectory(at: InstallRelativePath("Shared")).isEmpty)
}

@Test
func directoryPublicationNeverAdoptsAPreexistingCompatibleDirectory() throws {
    let tree = try TemporaryInstallTree()
    let root = try tree.directory("compatible-directory")
    let authority = try testAuthority(at: root)
    let shared = try InstallRelativePath("Shared")
    let existing = try InstallRelativePath("Shared/Existing")
    for path in [shared, existing] {
        try authority.ensureOwnedDirectory(
            at: path,
            ownerUID: UInt32(geteuid()),
            groupGID: UInt32(getegid()),
            mode: 0o755
        )
    }
    let publication = try InstallPublication(
        path: existing,
        generationID: "generation-1",
        ownerUID: UInt32(geteuid()),
        groupGID: UInt32(getegid())
    )
    let store = PublicationStore(authority: authority)

    #expect(try store.classify(publication) == .compatible)
    try store.publish(publication, replacing: nil, transactionID: "compatible")
    try store.unpublish(publication)
    #expect(try store.classify(publication) == .compatible)
}

@Test
func stagedDirectoryRaceDoesNotAdoptAnUnrelatedExactDirectory() throws {
    let tree = try TemporaryInstallTree()
    let root = try tree.directory("directory-race")
    let healthyAuthority = try testAuthority(at: root)
    let shared = try InstallRelativePath("Shared")
    try healthyAuthority.ensureOwnedDirectory(
        at: shared,
        ownerUID: UInt32(geteuid()),
        groupGID: UInt32(getegid()),
        mode: 0o755
    )
    let publication = try InstallPublication(
        path: InstallRelativePath("Shared/Raced"),
        generationID: "generation-1",
        ownerUID: UInt32(geteuid()),
        groupGID: UInt32(getegid())
    )
    let faultingAuthority = try testAuthority(
        at: root,
        faultInjector: CheckpointFaultInjector(checkpoint: .beforeRename)
    )
    #expect(throws: InstallError.faultInjected("beforeRename")) {
        try PublicationStore(authority: faultingAuthority).publish(
            publication,
            replacing: nil,
            transactionID: "raced"
        )
    }
    try healthyAuthority.ensureOwnedDirectory(
        at: publication.path,
        ownerUID: UInt32(geteuid()),
        groupGID: UInt32(getegid()),
        mode: 0o755
    )

    let healthyStore = PublicationStore(authority: healthyAuthority)
    try healthyStore.publish(publication, replacing: nil, transactionID: "raced")
    #expect(try healthyStore.classify(publication) == .compatible)
    try healthyStore.unpublish(publication)
    #expect(try healthyStore.classify(publication) == .compatible)
}

@Test
func productBoundDirectoryProvenanceSurvivesSequentialUpdatesThenUninstalls() throws {
    let tree = try TemporaryInstallTree()
    let root = try tree.directory("directory-updates")
    let authority = try testAuthority(at: root)
    try authority.ensureOwnedDirectory(
        at: InstallRelativePath("Shared"),
        ownerUID: UInt32(geteuid()),
        groupGID: UInt32(getegid()),
        mode: 0o755
    )
    let store = PublicationStore(authority: authority)
    let reconciler = PublicationReconciler(store: store)
    var previous: InstallManifest?

    for index in 1 ... 3 {
        let generationID = "generation-\(index)"
        let publication = try InstallPublication(
            path: InstallRelativePath("Shared/Owned"),
            generationID: generationID,
            ownerUID: UInt32(geteuid()),
            groupGID: UInt32(getegid())
        )
        let manifest = try InstallManifest(
            productIdentifier: "dev.agenxy.remap",
            generationID: generationID,
            productVersion: "1.0.\(index)",
            previousGenerationID: previous?.generationID,
            entries: [],
            publications: [publication]
        )
        let operation: InstallOperation = previous == nil ? .install : .update
        let context = try InstallTransitionContext(
            operation: operation,
            current: manifest,
            previous: previous
        )
        try reconciler.install(context, transactionID: "directory-update-\(index)")
        #expect(try store.classify(publication) == .owned)
        previous = manifest
    }

    let current = try #require(previous)
    try reconciler.removeCurrent(
        InstallTransitionContext(operation: .uninstall, current: current, previous: nil)
    )
    #expect(try store.classify(current.publications[0]) == .missing)
}

@Test
func interruptedOwnedDirectoryRemovalResumesFromTheRetiredSibling() throws {
    let tree = try TemporaryInstallTree()
    let root = try tree.directory("directory-removal-recovery")
    let healthyAuthority = try testAuthority(at: root)
    try healthyAuthority.ensureOwnedDirectory(
        at: InstallRelativePath("Shared"),
        ownerUID: UInt32(geteuid()),
        groupGID: UInt32(getegid()),
        mode: 0o755
    )
    let publication = try InstallPublication(
        path: InstallRelativePath("Shared/Owned"),
        generationID: "generation-1",
        ownerUID: UInt32(geteuid()),
        groupGID: UInt32(getegid())
    )
    let healthyStore = PublicationStore(authority: healthyAuthority)
    try healthyStore.publish(publication, replacing: nil, transactionID: "install")
    let faultingAuthority = try testAuthority(
        at: root,
        faultInjector: CheckpointFaultInjector(checkpoint: .beforeRemove)
    )

    #expect(throws: InstallError.faultInjected("beforeRemove")) {
        try PublicationStore(authority: faultingAuthority).unpublish(publication)
    }
    try healthyStore.unpublish(publication)
    #expect(try healthyStore.classify(publication) == .missing)
    #expect(try healthyAuthority.listDirectory(at: InstallRelativePath("Shared")).isEmpty)
}

@Test
func interruptedDirectoryStagingResumesBeforePublication() throws {
    let tree = try TemporaryInstallTree()
    let root = try tree.directory("directory-staging-recovery")
    let healthyAuthority = try testAuthority(at: root)
    try healthyAuthority.ensureOwnedDirectory(
        at: InstallRelativePath("Shared"),
        ownerUID: UInt32(geteuid()),
        groupGID: UInt32(getegid()),
        mode: 0o755
    )
    let publication = try InstallPublication(
        path: InstallRelativePath("Shared/Owned"),
        generationID: "generation-1",
        ownerUID: UInt32(geteuid()),
        groupGID: UInt32(getegid())
    )
    let faultingAuthority = try testAuthority(
        at: root,
        faultInjector: CheckpointFaultInjector(checkpoint: .beforeCreateFile)
    )

    #expect(throws: InstallError.faultInjected("beforeCreateFile")) {
        try PublicationStore(authority: faultingAuthority).publish(
            publication,
            replacing: nil,
            transactionID: "install"
        )
    }
    let healthyStore = PublicationStore(authority: healthyAuthority)
    try healthyStore.publish(publication, replacing: nil, transactionID: "install")
    #expect(try healthyStore.classify(publication) == .owned)
}
