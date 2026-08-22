import Darwin
import Foundation
@testable import RemapInstallKit

@_silgen_name("mbr_uid_to_uuid")
func remapMbrUIDToUUID(_ userID: uid_t, _ identifier: UnsafeMutablePointer<UInt8>) -> Int32

final class TemporaryInstallTree: @unchecked Sendable {
    let url: URL

    init() throws {
        let base = FileManager.default.temporaryDirectory
        url = base.appending(path: "remap-install-tests-\(UUID().uuidString)", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false)
        guard chmod(url.path, 0o700) == 0 else {
            throw InstallError.operatingSystem("secure temporary test directory", errno)
        }
    }

    deinit {
        try? FileManager.default.removeItem(at: url)
    }

    func directory(_ name: String) throws -> URL {
        let child = url.appending(path: name, directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: child, withIntermediateDirectories: false)
        guard chmod(child.path, 0o700) == 0 else {
            throw InstallError.operatingSystem("secure temporary authority", errno)
        }
        return child
    }
}

struct TestInstallDurability: InstallDurability {
    func syncDirectory(_: Int32, operation _: String) throws {}
    func syncFile(_: Int32, operation _: String) throws {}
}

struct CheckpointFaultInjector: InstallFaultInjecting {
    let checkpoint: InstallCheckpoint

    func check(_ checkpoint: InstallCheckpoint) throws {
        if checkpoint == self.checkpoint {
            throw InstallError.faultInjected(checkpoint.rawValue)
        }
    }
}

final class CountingCheckpointFaultInjector: @unchecked Sendable, InstallFaultInjecting {
    private let lock = NSLock()
    private let failureOrdinal: Int
    private var count = 0

    init(failureOrdinal: Int) {
        self.failureOrdinal = failureOrdinal
    }

    func check(_ checkpoint: InstallCheckpoint) throws {
        guard checkpoint == .beforeJournalAppend else {
            return
        }
        lock.lock()
        count += 1
        let shouldFail = count == failureOrdinal
        lock.unlock()
        if shouldFail {
            throw InstallError.faultInjected("journal-append-\(failureOrdinal)")
        }
    }
}

enum TestEffectStage: Equatable, Sendable {
    case reconcile
    case verify

    var name: String {
        switch self {
        case .reconcile:
            "reconcile"
        case .verify:
            "verify"
        }
    }
}

struct TestEffectFault: Sendable {
    let effect: InstallSystemEffect
    let stage: TestEffectStage

    var diagnostic: String {
        "\(stage.name)-\(effect.rawValue)"
    }

    var lastCompletedUninstallPhase: InstallPhase {
        switch effect {
        case .dnsRestored:
            .uninstallPrepared
        case .serviceStopped:
            .dnsRestored
        case .dnsActive, .installationAccepted, .priorServiceRestored, .serviceRunning:
            fatalError("not an uninstall effect")
        }
    }
}

final class TestSystemEffectAdapter: @unchecked Sendable, InstallSystemEffectAdapting {
    private let lock = NSLock()
    private let fault: TestEffectFault?
    private var reconciled: Set<InstallSystemEffect> = []
    private var recordedCalls: [String] = []

    init(fault: TestEffectFault? = nil) {
        self.fault = fault
    }

    var calls: [String] {
        lock.lock()
        defer { lock.unlock() }
        return recordedCalls
    }

    func reconcile(_ effect: InstallSystemEffect, context _: InstallTransitionContext) async throws {
        try lock.withLock {
            recordedCalls.append("reconcile:\(effect.rawValue)")
            if fault?.effect == effect, fault?.stage == .reconcile {
                throw InstallError.faultInjected("reconcile-\(effect.rawValue)")
            }
            reconciled.insert(effect)
        }
    }

    func verify(_ effect: InstallSystemEffect, context _: InstallTransitionContext) async throws {
        try lock.withLock {
            recordedCalls.append("verify:\(effect.rawValue)")
            if fault?.effect == effect, fault?.stage == .verify {
                throw InstallError.faultInjected("verify-\(effect.rawValue)")
            }
            guard reconciled.contains(effect) else {
                throw InstallError.integrity("test adapter verified an unreconciled effect")
            }
        }
    }
}

final class InstallTransactionHarness: @unchecked Sendable {
    let tree: TemporaryInstallTree
    let root: URL
    let authority: FileSystemAuthority
    let generations: GenerationStore
    let publications: PublicationStore
    let lockPath: InstallRelativePath
    let journalPath: InstallRelativePath

    init() throws {
        tree = try TemporaryInstallTree()
        root = try tree.directory("system")
        authority = try testAuthority(at: root)
        try authority.ensureOwnedDirectory(
            at: InstallRelativePath("Public"),
            ownerUID: UInt32(geteuid()),
            groupGID: UInt32(getegid()),
            mode: 0o755
        )
        generations = try GenerationStore(
            authority: authority,
            generationsPath: InstallRelativePath("Generations"),
            ownerUID: UInt32(geteuid()),
            groupGID: UInt32(getegid())
        )
        publications = PublicationStore(authority: authority)
        lockPath = try InstallRelativePath("install.lock")
        journalPath = try InstallRelativePath("Journal")
    }

    func journal(
        faultInjector: any InstallFaultInjecting = NoInstallFaultInjector()
    ) -> InstallJournalStore {
        InstallJournalStore(
            authority: authority,
            journalsPath: journalPath,
            ownerUID: UInt32(geteuid()),
            groupGID: UInt32(getegid()),
            faultInjector: faultInjector
        )
    }

    func source(data: Data, name: String) throws -> FileSystemAuthority {
        let directory = try tree.directory(name)
        try writeTestFile(data, to: directory.appending(path: "remap"))
        return try testAuthority(at: directory)
    }

    func manifest(
        generationID: String,
        previousGenerationID: String?,
        data: Data
    ) throws -> InstallManifest {
        let entry = try testEntry(path: "remap", data: data, role: .commandLineTool)
        let publication = try testPublication(
            path: "Public/remap",
            target: "/Generations/\(generationID)/remap",
            generationID: generationID
        )
        return try InstallManifest(
            productIdentifier: "dev.agenxy.remap",
            generationID: generationID,
            productVersion: "1.0.\(generationID)",
            previousGenerationID: previousGenerationID,
            entries: [entry],
            publications: [publication]
        )
    }

    func prepareInstalled(
        manifest: InstallManifest,
        source: FileSystemAuthority,
        transactionID: String
    ) throws {
        let staging = try generations.stage(manifest, from: source, transactionID: transactionID)
        try generations.publish(staging, manifest: manifest)
        for publication in manifest.publications {
            try publications.publish(publication, replacing: nil, transactionID: transactionID)
        }
    }

    func coordinator(
        journal: InstallJournalStore,
        effects: any InstallSystemEffectAdapting,
        approvalVerifier: any InstallApprovalVerifying = TestInstallApprovalVerifier()
    ) -> InstallTransactionCoordinator {
        InstallTransactionCoordinator(
            lockAuthority: authority,
            lockPath: lockPath,
            generations: generations,
            publications: publications,
            journal: journal,
            effects: effects,
            approvalVerifier: approvalVerifier
        )
    }

    func recovery(
        journal: InstallJournalStore,
        effects: any InstallSystemEffectAdapting
    ) -> InstallCrashRecoveryExecutor {
        InstallCrashRecoveryExecutor(
            lockAuthority: authority,
            lockPath: lockPath,
            generations: generations,
            publications: publications,
            journal: journal,
            effects: effects
        )
    }
}

struct TestInstallApprovalVerifier: InstallApprovalVerifying {
    func verify(_: InstallTransitionContext) throws {}
}

func testAuthority(
    at url: URL,
    faultInjector: any InstallFaultInjecting = NoInstallFaultInjector()
) throws -> FileSystemAuthority {
    try FileSystemAuthority(
        testingRootPath: url.path,
        durability: TestInstallDurability(),
        faultInjector: faultInjector
    )
}

func testSourcePackageAuthority(
    at url: URL,
    ownerUID: UInt32 = UInt32(geteuid())
) throws -> FileSystemAuthority {
    try FileSystemAuthority(
        testingSourcePackageRootPath: url.path,
        ownerUID: ownerUID,
        durability: TestInstallDurability()
    )
}

func writeTestFile(_ data: Data, to url: URL) throws {
    try data.write(to: url, options: .withoutOverwriting)
    guard chmod(url.path, 0o600) == 0 else {
        throw InstallError.operatingSystem("secure test source", errno)
    }
}

func testEntry(path: String, data: Data, role: InstallEntryRole = .support) throws -> InstallEntry {
    try InstallEntry(
        path: InstallRelativePath(path),
        kind: .regularFile,
        role: role,
        sha256: InstallDigest.hash(data),
        byteCount: UInt64(data.count),
        ownerUID: UInt32(geteuid()),
        groupGID: UInt32(getegid()),
        mode: 0o444
    )
}

func testPublication(path: String, target: String, generationID: String) throws -> InstallPublication {
    try InstallPublication(
        path: InstallRelativePath(path),
        target: InstallSymlinkTarget(target),
        generationID: generationID
    )
}

func testManifest(
    generationID: String = "generation-1",
    entries: [InstallEntry],
    publications: [InstallPublication] = []
) throws -> InstallManifest {
    try InstallManifest(
        productIdentifier: "dev.agenxy.remap",
        generationID: generationID,
        productVersion: "1.0.0",
        previousGenerationID: nil,
        entries: entries,
        publications: publications
    )
}

func addExtendedACL(to url: URL) throws {
    var accessControlList = acl_init(1)
    guard accessControlList != nil else {
        throw InstallError.operatingSystem("allocate test ACL", errno)
    }
    defer {
        if let accessControlList {
            acl_free(UnsafeMutableRawPointer(accessControlList))
        }
    }
    var entry: acl_entry_t?
    guard acl_create_entry(&accessControlList, &entry) == 0, let entry else {
        throw InstallError.operatingSystem("create test ACL entry", errno)
    }
    guard acl_set_tag_type(entry, ACL_EXTENDED_DENY) == 0 else {
        throw InstallError.operatingSystem("set test ACL tag", errno)
    }
    var identifier = [UInt8](repeating: 0, count: 16)
    guard remapMbrUIDToUUID(geteuid(), &identifier) == 0 else {
        throw InstallError.operatingSystem("resolve test ACL identity", errno)
    }
    let qualifierResult = identifier.withUnsafeBytes {
        acl_set_qualifier(entry, $0.baseAddress)
    }
    guard qualifierResult == 0 else {
        throw InstallError.operatingSystem("set test ACL identity", errno)
    }
    var permissions: acl_permset_t?
    var flags: acl_flagset_t?
    guard acl_get_permset(entry, &permissions) == 0, let permissions,
          acl_clear_perms(permissions) == 0,
          acl_add_perm(permissions, ACL_WRITE_DATA) == 0,
          acl_set_permset(entry, permissions) == 0,
          acl_get_flagset_np(UnsafeMutableRawPointer(entry), &flags) == 0,
          let flags,
          acl_clear_flags_np(flags) == 0,
          acl_set_flagset_np(UnsafeMutableRawPointer(entry), flags) == 0,
          let accessControlList,
          acl_valid(accessControlList) == 0,
          acl_set_file(url.path, ACL_TYPE_EXTENDED, accessControlList) == 0
    else {
        throw InstallError.operatingSystem("apply test ACL", errno)
    }
}
