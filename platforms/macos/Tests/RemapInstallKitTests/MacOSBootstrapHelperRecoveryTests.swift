import CryptoKit
import Darwin
import Foundation
@testable import RemapInstallKit
import Testing

@Test
func bootstrapRecoveryIsAnIdempotentNoOpWithZeroResidue() throws {
    let fixture = try BootstrapRecoveryFixture()
    let preview = try fixture.recovery().preview()

    #expect(preview.candidates.isEmpty)
    #expect(preview.effects.isEmpty)
    let result = try fixture.recovery().recover(approvalToken: preview.approvalToken)
    #expect(result.removedPaths.isEmpty)
    #expect(try fixture.recovery().preview().effects.isEmpty)
}

@Test
func activeBootstrapHelperIsDisclosedAndNeverRemoved() throws {
    let fixture = try BootstrapRecoveryFixture()
    let path = try fixture.helper(suffix: String(repeating: "a", count: 32), contents: "active")
    let active = try BootstrapTestActivityLease(path: path)
    let preview = try fixture.recovery().preview()

    #expect(preview.candidates.map(\.activity) == [.active])
    #expect(preview.effects.isEmpty)
    #expect(try fixture.recovery().recover(approvalToken: preview.approvalToken).removedPaths.isEmpty)
    withExtendedLifetime(active) {}
    #expect(FileManager.default.fileExists(atPath: path.path))
}

@Test
func concurrentHelperActivityInvalidatesApprovalBeforeUnlink() throws {
    let fixture = try BootstrapRecoveryFixture()
    let path = try fixture.helper(suffix: String(repeating: "b", count: 32), contents: "concurrent")
    let preview = try fixture.recovery().preview()
    let active = try BootstrapTestActivityLease(path: path)

    #expect(throws: InstallError.approval(
        "the approved bootstrap recovery preview is stale or does not match"
    )) {
        try fixture.recovery().recover(approvalToken: preview.approvalToken)
    }
    withExtendedLifetime(active) {}
    #expect(FileManager.default.fileExists(atPath: path.path))
}

@Test
func concurrentHelperCannotBecomeActiveAfterExclusiveRevalidation() throws {
    let fixture = try BootstrapRecoveryFixture()
    let path = try fixture.helper(suffix: String(repeating: "9", count: 32), contents: "late-start")
    let start = BootstrapConcurrentStartFault(path: path)
    let recovery = fixture.recovery(faultInjector: start)
    let preview = try recovery.preview()

    _ = try recovery.recover(approvalToken: preview.approvalToken)
    #expect(!start.acquiredActivityLease)
    #expect(!FileManager.default.fileExists(atPath: path.path))
}

@Test
func currentBootstrapHelperIdentityIsNeverSelectedForRemoval() throws {
    let fixture = try BootstrapRecoveryFixture()
    let path = try fixture.helper(suffix: String(repeating: "c", count: 32), contents: "current")
    let recovery = try fixture.recovery(currentExecutableIdentity: fixture.identity(path))
    let preview = try recovery.preview()

    #expect(preview.candidates.map(\.activity) == [.current])
    #expect(preview.effects.isEmpty)
    #expect(try recovery.recover(approvalToken: preview.approvalToken).removedPaths.isEmpty)
    #expect(FileManager.default.fileExists(atPath: path.path))
}

@Test
func bootstrapPathSwapCannotDeleteTheReplacement() throws {
    let fixture = try BootstrapRecoveryFixture()
    let path = try fixture.helper(suffix: String(repeating: "d", count: 32), contents: "original")
    let fault = BootstrapPathSwapFault(path: path)
    let recovery = fixture.recovery(faultInjector: fault)
    let preview = try recovery.preview()

    let logicalPath = MacOSBootstrapHelperStore.absoluteDirectory + "/" + path.lastPathComponent
    #expect(throws: InstallError.collision(logicalPath)) {
        try recovery.recover(approvalToken: preview.approvalToken)
    }
    #expect(try Data(contentsOf: path) == Data("replacement".utf8))
    #expect(FileManager.default.fileExists(atPath: fault.moved.path))
}

@Test
func bootstrapWrongCodeIdentityIsDisclosedAndExplicitlyRecoverable() throws {
    let fixture = try BootstrapRecoveryFixture()
    let path = try fixture.helper(suffix: String(repeating: "e", count: 32), contents: "wrong-identity")
    let preview = try fixture.recovery().preview()

    let candidate = try #require(preview.candidates.first)
    #expect(candidate.codeValidity == .invalid)
    #expect(candidate.codeIdentifier == nil)
    #expect(candidate.cdHash == nil)
    #expect(candidate.sha256.count == 64)
    #expect(preview.effects == ["remove inactive orphan bootstrap helper \(candidate.path.value)"])

    let result = try fixture.recovery().recover(approvalToken: preview.approvalToken)
    #expect(result.removedPaths == [candidate.path])
    #expect(!FileManager.default.fileExists(atPath: path.path))
}

@Test
func bootstrapInvalidSignatureBytesAreNeverExecutedAndRemainRecoverable() throws {
    let fixture = try BootstrapRecoveryFixture()
    let path = try fixture.helper(suffix: String(repeating: "7", count: 32), contents: "corrupt")
    let recovery = fixture.recovery(identityChecker: BootstrapInvalidCodeIdentityChecker())
    let preview = try recovery.preview()

    let candidate = try #require(preview.candidates.first)
    #expect(candidate.codeValidity == .invalid)
    let digest = SHA256.hash(data: Data("corrupt".utf8)).map { String(format: "%02x", $0) }.joined()
    #expect(candidate.sha256 == digest)

    _ = try recovery.recover(approvalToken: preview.approvalToken)
    #expect(!FileManager.default.fileExists(atPath: path.path))
}

@Test
func bootstrapExtendedACLIsRejectedWithoutDeletion() throws {
    let fixture = try BootstrapRecoveryFixture()
    let path = try fixture.helper(suffix: String(repeating: "8", count: 32), contents: "acl")
    try addExtendedACL(to: path)

    #expect(throws: InstallError.metadata("a bootstrap helper has unsafe metadata")) {
        try fixture.recovery().preview()
    }
    #expect(FileManager.default.fileExists(atPath: path.path))
}

@Test
func bootstrapMetadataOrContentDriftRejectsTheStaleToken() throws {
    let fixture = try BootstrapRecoveryFixture()
    let path = try fixture.helper(suffix: String(repeating: "f", count: 32), contents: "first")
    let preview = try fixture.recovery().preview()
    try fixture.replaceHelper(path, contents: "second-version")

    #expect(throws: InstallError.approval(
        "the approved bootstrap recovery preview is stale or does not match"
    )) {
        try fixture.recovery().recover(approvalToken: preview.approvalToken)
    }
    #expect(try Data(contentsOf: path) == Data("second-version".utf8))
}

@Test
func bootstrapRecoveryCrashLeavesAReviewableIdempotentRemainder() throws {
    let fixture = try BootstrapRecoveryFixture()
    let first = try fixture.helper(suffix: String(repeating: "1", count: 32), contents: "first")
    let second = try fixture.helper(suffix: String(repeating: "2", count: 32), contents: "second")
    let fault = BootstrapNthRemoveFault(failureOrdinal: 2)
    let interrupted = fixture.recovery(faultInjector: fault)
    let preview = try interrupted.preview()

    #expect(throws: InstallError.faultInjected("bootstrap-remove-2")) {
        try interrupted.recover(approvalToken: preview.approvalToken)
    }
    #expect(!FileManager.default.fileExists(atPath: first.path))
    #expect(FileManager.default.fileExists(atPath: second.path))

    let remainder = try fixture.recovery().preview()
    #expect(remainder.candidates.map(\.path.value) == [
        MacOSBootstrapHelperStore.absoluteDirectory + "/" + second.lastPathComponent
    ])
    _ = try fixture.recovery().recover(approvalToken: remainder.approvalToken)
    #expect(try fixture.recovery().preview().effects.isEmpty)
}

@Test
func privateBootstrapStageIsHashBoundAndExplicitlyRecoverable() throws {
    let fixture = try BootstrapRecoveryFixture()
    let stage = try fixture.stage(
        suffix: String(repeating: "3", count: 32),
        contents: "partial-untrusted-bytes"
    )
    let preview = try fixture.recovery().preview()

    let candidate = try #require(preview.stagingCandidates.first)
    let logical = MacOSBootstrapHelperStore.absoluteDirectory + "/" + stage.lastPathComponent
    #expect(candidate.path.value == logical)
    #expect(candidate.mode == 0o700)
    #expect(candidate.stagedFile?.mode == 0o600)
    #expect(candidate.stagedFile?.sha256.count == 64)
    #expect(preview.effects == ["remove private orphan bootstrap stage \(logical)"])

    let result = try fixture.recovery().recover(approvalToken: preview.approvalToken)
    #expect(result.removedPaths == [candidate.path])
    #expect(!FileManager.default.fileExists(atPath: stage.path))
}

@Test
func publishReadyBootstrapStageIsCrashRecoverable() throws {
    let fixture = try BootstrapRecoveryFixture()
    let stage = try fixture.stage(
        suffix: String(repeating: "6", count: 32),
        contents: "verified-publish-ready",
        stageMode: 0o711,
        fileMode: 0o555
    )
    let preview = try fixture.recovery().preview()

    let candidate = try #require(preview.stagingCandidates.first)
    #expect(candidate.mode == 0o711)
    #expect(candidate.stagedFile?.mode == 0o555)
    #expect(candidate.stagedFile?.sha256.count == 64)

    _ = try fixture.recovery().recover(approvalToken: preview.approvalToken)
    #expect(!FileManager.default.fileExists(atPath: stage.path))
}

@Test
func privateBootstrapStageDriftInvalidatesItsApproval() throws {
    let fixture = try BootstrapRecoveryFixture()
    let stage = try fixture.stage(
        suffix: String(repeating: "4", count: 32),
        contents: "first"
    )
    let preview = try fixture.recovery().preview()
    let child = stage.appending(path: MacOSBootstrapStageStore.childName)
    try Data("second".utf8).write(to: child)
    guard chmod(child.path, 0o600) == 0 else {
        throw InstallError.operatingSystem("reseal private bootstrap test stage", errno)
    }

    #expect(throws: InstallError.approval(
        "the approved bootstrap recovery preview is stale or does not match"
    )) {
        try fixture.recovery().recover(approvalToken: preview.approvalToken)
    }
    #expect(FileManager.default.fileExists(atPath: stage.path))
}

private final class BootstrapRecoveryFixture: @unchecked Sendable {
    let tree: TemporaryInstallTree
    let root: URL
    let authority: FileSystemAuthority
    let layout: MacOSInstallLayout
    let helperDirectory: URL

    init() throws {
        tree = try TemporaryInstallTree()
        root = try tree.directory("bootstrap-system")
        let applicationSupport = root.appending(path: "Library/Application Support")
        helperDirectory = root.appending(path: "Library/PrivilegedHelperTools")
        try FileManager.default.createDirectory(at: applicationSupport, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: helperDirectory, withIntermediateDirectories: false)
        for path in [
            root.appending(path: "Library"),
            applicationSupport,
            helperDirectory
        ] {
            guard chmod(path.path, 0o755) == 0 else {
                throw InstallError.operatingSystem("prepare bootstrap test directory", errno)
            }
        }
        authority = try testAuthority(at: root)
        layout = try MacOSInstallLayout(
            authority: authority,
            systemRootPath: root.path,
            installOwnerUID: UInt32(geteuid()),
            installGroupGID: UInt32(getegid())
        )
    }

    func helper(suffix: String, contents: String) throws -> URL {
        let path = helperDirectory.appending(path: MacOSBootstrapHelperStore.prefix + suffix)
        try Data(contents.utf8).write(to: path, options: .withoutOverwriting)
        guard chmod(path.path, 0o555) == 0 else {
            throw InstallError.operatingSystem("seal bootstrap test helper", errno)
        }
        return path
    }

    func stage(
        suffix: String,
        contents: String?,
        stageMode: mode_t = 0o700,
        fileMode: mode_t = 0o600
    ) throws -> URL {
        let path = helperDirectory.appending(path: MacOSBootstrapStageStore.prefix + suffix)
        try FileManager.default.createDirectory(at: path, withIntermediateDirectories: false)
        guard chmod(path.path, 0o700) == 0 else {
            throw InstallError.operatingSystem("seal private bootstrap test stage", errno)
        }
        if let contents {
            let child = path.appending(path: MacOSBootstrapStageStore.childName)
            try Data(contents.utf8).write(to: child, options: .withoutOverwriting)
            guard chmod(child.path, fileMode) == 0 else {
                throw InstallError.operatingSystem("seal private bootstrap staged file", errno)
            }
        }
        guard chmod(path.path, stageMode) == 0 else {
            throw InstallError.operatingSystem("seal private bootstrap test stage mode", errno)
        }
        return path
    }

    func replaceHelper(_ path: URL, contents: String) throws {
        guard chmod(path.path, 0o755) == 0 else {
            throw InstallError.operatingSystem("open bootstrap test helper for replacement", errno)
        }
        try Data(contents.utf8).write(to: path, options: .atomic)
        guard chmod(path.path, 0o555) == 0 else {
            throw InstallError.operatingSystem("reseal bootstrap test helper", errno)
        }
    }

    func identity(_ path: URL) throws -> MacOSBootstrapFileIdentity {
        var status = stat()
        guard lstat(path.path, &status) == 0 else {
            throw InstallError.operatingSystem("inspect bootstrap test helper", errno)
        }
        return MacOSBootstrapFileIdentity(deviceID: UInt64(status.st_dev), fileID: UInt64(status.st_ino))
    }

    func recovery(
        currentExecutableIdentity: MacOSBootstrapFileIdentity? = nil,
        identityChecker: any MacOSBootstrapCodeIdentityChecking = BootstrapTestCodeIdentityChecker(),
        faultInjector: any InstallFaultInjecting = NoInstallFaultInjector()
    ) -> MacOSBootstrapHelperRecovery {
        let store = MacOSBootstrapHelperStore(
            authority: authority,
            ownerUID: UInt32(geteuid()),
            groupGID: UInt32(getegid()),
            identityChecker: identityChecker,
            currentExecutableIdentity: currentExecutableIdentity,
            durability: TestInstallDurability(),
            faultInjector: faultInjector
        )
        return MacOSBootstrapHelperRecovery(
            lockConfiguration: layout.lockConfiguration,
            store: store,
            stagingStore: MacOSBootstrapStageStore(
                authority: authority,
                ownerUID: UInt32(geteuid()),
                groupGID: UInt32(getegid()),
                durability: TestInstallDurability()
            )
        )
    }
}

private struct BootstrapTestCodeIdentityChecker: MacOSBootstrapCodeIdentityChecking {
    func identity(fileDescriptor: Int32) throws -> MacOSBootstrapCodeIdentity {
        var buffer = [UInt8](repeating: 0, count: 4096)
        let count = pread(fileDescriptor, &buffer, buffer.count, 0)
        guard count >= 0 else {
            throw InstallError.operatingSystem("read bootstrap test identity", errno)
        }
        let data = Data(buffer.prefix(count))
        let identifier = data.starts(with: Data("wrong".utf8))
            ? "org.example.Unrelated"
            : MacOSBootstrapHelperStore.codeIdentifier
        return MacOSBootstrapCodeIdentity(
            identifier: identifier,
            cdHash: SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        )
    }
}

private struct BootstrapInvalidCodeIdentityChecker: MacOSBootstrapCodeIdentityChecking {
    func identity(fileDescriptor _: Int32) throws -> MacOSBootstrapCodeIdentity {
        throw InstallError.integrity("test invalid bootstrap signature")
    }
}

private final class BootstrapTestActivityLease {
    private let descriptor: Int32

    init(path: URL) throws {
        descriptor = open(path.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0, flock(descriptor, LOCK_SH | LOCK_NB) == 0 else {
            if descriptor >= 0 {
                close(descriptor)
            }
            throw InstallError.operatingSystem("hold bootstrap test activity lease", errno)
        }
    }

    deinit {
        close(descriptor)
    }
}

private final class BootstrapPathSwapFault: @unchecked Sendable, InstallFaultInjecting {
    let moved: URL
    private let path: URL
    private var fired = false

    init(path: URL) {
        self.path = path
        moved = path.appendingPathExtension("moved")
    }

    func check(_ checkpoint: InstallCheckpoint) throws {
        guard checkpoint == .beforeRemove, !fired else { return }
        fired = true
        try FileManager.default.moveItem(at: path, to: moved)
        try Data("replacement".utf8).write(to: path, options: .withoutOverwriting)
        guard chmod(path.path, 0o555) == 0 else {
            throw InstallError.operatingSystem("seal bootstrap replacement", errno)
        }
    }
}

private final class BootstrapNthRemoveFault: @unchecked Sendable, InstallFaultInjecting {
    private let failureOrdinal: Int
    private var count = 0

    init(failureOrdinal: Int) {
        self.failureOrdinal = failureOrdinal
    }

    func check(_ checkpoint: InstallCheckpoint) throws {
        guard checkpoint == .beforeRemove else { return }
        count += 1
        if count == failureOrdinal {
            throw InstallError.faultInjected("bootstrap-remove-\(failureOrdinal)")
        }
    }
}

private final class BootstrapConcurrentStartFault: @unchecked Sendable, InstallFaultInjecting {
    private let path: URL
    private(set) var acquiredActivityLease = false

    init(path: URL) {
        self.path = path
    }

    func check(_ checkpoint: InstallCheckpoint) throws {
        guard checkpoint == .beforeRemove else { return }
        let descriptor = open(path.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else {
            throw InstallError.operatingSystem("open concurrent bootstrap helper", errno)
        }
        defer { close(descriptor) }
        acquiredActivityLease = flock(descriptor, LOCK_SH | LOCK_NB) == 0
    }
}
