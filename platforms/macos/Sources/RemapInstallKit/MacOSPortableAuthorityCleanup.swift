import Darwin
import Foundation

public struct MacOSPortableAuthorityFileState: Codable, Equatable, Sendable {
    public let path: InstallRelativePath
    public let sha256: InstallDigest
    public let byteCount: UInt64
    public let mode: UInt16

    public init(
        path: InstallRelativePath,
        sha256: InstallDigest,
        byteCount: UInt64,
        mode: UInt16
    ) throws {
        guard Self.specifications[path.description] == mode,
              byteCount > 0,
              byteCount <= 134_217_728
        else {
            throw InstallError.integrity("portable authority file state is malformed")
        }
        self.path = path
        self.sha256 = sha256
        self.byteCount = byteCount
        self.mode = mode
    }

    static let specifications: [String: UInt16] = [
        "Library/PrivilegedHelperTools/org.agenxy.Remap.installer-service": 0o555,
        "Library/Application Support/Agenxy/Remap/Installer/service-v1.json": 0o400,
        "Library/LaunchDaemons/org.agenxy.Remap.installer-service.plist": 0o644
    ]
}

public struct MacOSPortableAuthorityCleanupState: Codable, Equatable, Sendable {
    public static let installerPathString = "Library/Application Support/Agenxy/Remap/Installer"
    public static let sourcesPathString = installerPathString + "/Sources"
    public static let planPathString =
        "Library/Application Support/Agenxy/.remap-portable-uninstall-v2.json"
    public static let stableLockPathString =
        "Library/Application Support/Agenxy/.remap-lifecycle-authority.lock"

    public let schemaVersion: UInt32
    public let sourcePackageRoot: InstallAbsolutePath
    public let sourceManifestDigest: InstallDigest
    public let packageReceiptVersion: String?
    public let files: [MacOSPortableAuthorityFileState]

    public init(
        sourcePackageRoot: InstallAbsolutePath,
        sourceManifestDigest: InstallDigest,
        packageReceiptVersion: String? = nil,
        files: [MacOSPortableAuthorityFileState]
    ) throws {
        let expectedRoot = "/" + Self.sourcesPathString
            + "/\(sourceManifestDigest.description)"
        let ordered = try files.map {
            try MacOSPortableAuthorityFileState(
                path: $0.path,
                sha256: $0.sha256,
                byteCount: $0.byteCount,
                mode: $0.mode
            )
        }.sorted { $0.path < $1.path }
        guard sourcePackageRoot.description == expectedRoot,
              packageReceiptVersion == nil
              || MacOSPackageReceiptStore.validVersion(packageReceiptVersion ?? ""),
              ordered.map(\.path.description)
              == MacOSPortableAuthorityFileState.specifications.keys.sorted(),
              Set(ordered.map(\.path)).count == ordered.count
        else {
            throw InstallError.integrity("portable authority cleanup state is incomplete")
        }
        schemaVersion = 1
        self.sourcePackageRoot = sourcePackageRoot
        self.sourceManifestDigest = sourceManifestDigest
        self.packageReceiptVersion = packageReceiptVersion
        self.files = ordered
    }

    public static func capture(
        sourcePackageRoot: InstallAbsolutePath,
        sourceManifestDigest: InstallDigest
    ) throws -> Self {
        try capture(
            authority: FileSystemAuthority(systemRootPath: "/"),
            sourcePackageRoot: sourcePackageRoot,
            sourceManifestDigest: sourceManifestDigest,
            packageReceiptVersion: MacOSPackageReceiptStore.production().version(),
            expectedUID: 0,
            expectedGID: 0
        )
    }

    static func capture(
        authority: FileSystemAuthority,
        sourcePackageRoot: InstallAbsolutePath,
        sourceManifestDigest: InstallDigest,
        packageReceiptVersion: String? = nil,
        expectedUID: UInt32,
        expectedGID: UInt32
    ) throws -> Self {
        let state = try Self(
            sourcePackageRoot: sourcePackageRoot,
            sourceManifestDigest: sourceManifestDigest,
            packageReceiptVersion: packageReceiptVersion,
            files: MacOSPortableAuthorityFileState.specifications
                .map { pathString, mode in
                    let path = try InstallRelativePath(pathString)
                    guard let metadata = try authority.metadata(at: path),
                          metadata.kind == .regularFile,
                          metadata.ownerUID == expectedUID,
                          metadata.groupGID == expectedGID,
                          metadata.mode == mode,
                          metadata.linkCount == 1,
                          metadata.byteCount > 0,
                          metadata.byteCount <= 134_217_728,
                          !metadata.hasACL,
                          metadata.flags == 0
                    else {
                        throw InstallError.metadata("portable authority file metadata is unsafe")
                    }
                    let data = try authority.readUniqueFile(
                        at: path,
                        maximumByteCount: Int(metadata.byteCount)
                    )
                    return try MacOSPortableAuthorityFileState(
                        path: path,
                        sha256: InstallDigest.hash(data),
                        byteCount: UInt64(data.count),
                        mode: mode
                    )
                }
        )
        try state.validateComplete(
            authority: authority,
            permitsPlan: false,
            expectedUID: expectedUID,
            expectedGID: expectedGID
        )
        return state
    }

    func validateComplete(
        authority: FileSystemAuthority,
        permitsPlan: Bool,
        expectedUID: UInt32 = 0,
        expectedGID: UInt32 = 0
    ) throws {
        try validateDirectories(
            authority: authority,
            permitsPlan: permitsPlan,
            expectedUID: expectedUID,
            expectedGID: expectedGID
        )
        for file in files {
            try authority.verifyAuthorityFile(
                at: file.path,
                expectedDigest: file.sha256,
                expectedByteCount: file.byteCount,
                ownerUID: expectedUID,
                groupGID: expectedGID,
                mode: file.mode
            )
        }
        let sourcePath = try sourceRelativePath()
        let purge = try MacOSPortableSourcePurge(
            authority: authority,
            packagePath: sourcePath,
            expectedManifestDigest: sourceManifestDigest,
            ownerUID: expectedUID,
            groupGID: expectedGID
        )
        try purge.validate()
    }

    func validateRemaining(
        authority: FileSystemAuthority,
        expectedUID: UInt32 = 0,
        expectedGID: UInt32 = 0
    ) throws {
        try validateDirectories(
            authority: authority,
            permitsPlan: true,
            expectedUID: expectedUID,
            expectedGID: expectedGID
        )
        for file in files where try authority.metadata(at: file.path) != nil {
            try authority.verifyAuthorityFile(
                at: file.path,
                expectedDigest: file.sha256,
                expectedByteCount: file.byteCount,
                ownerUID: expectedUID,
                groupGID: expectedGID,
                mode: file.mode
            )
        }
        let sourcePath = try sourceRelativePath()
        if try authority.metadata(at: sourcePath) != nil {
            let purge = try MacOSPortableSourcePurge(
                authority: authority,
                packagePath: sourcePath,
                expectedManifestDigest: sourceManifestDigest,
                ownerUID: expectedUID,
                groupGID: expectedGID
            )
            try purge.validate()
        }
    }

    private func validateDirectories(
        authority: FileSystemAuthority,
        permitsPlan _: Bool,
        expectedUID: UInt32,
        expectedGID: UInt32
    ) throws {
        let installerPath = try InstallRelativePath(Self.installerPathString)
        let sourcesPath = try InstallRelativePath(Self.sourcesPathString)
        if try authority.metadata(at: installerPath) != nil {
            try authority.verifyOwnedDirectory(
                at: installerPath,
                ownerUID: expectedUID,
                groupGID: expectedGID,
                permittedModes: [0o700]
            )
            let permitted = Set(["Sources", "service-v1.json"])
            guard try Set(authority.listDirectory(at: installerPath)).isSubset(of: permitted) else {
                throw InstallError.collision(installerPath.description)
            }
        }
        if try authority.metadata(at: sourcesPath) != nil {
            try authority.verifyOwnedDirectory(
                at: sourcesPath,
                ownerUID: expectedUID,
                groupGID: expectedGID,
                permittedModes: [0o700]
            )
            guard try Set(authority.listDirectory(at: sourcesPath))
                .isSubset(of: [sourceManifestDigest.description])
            else {
                throw InstallError.collision(sourcesPath.description)
            }
        }
    }

    func sourceRelativePath() throws -> InstallRelativePath {
        try InstallRelativePath(Self.sourcesPathString)
            .appending(InstallRelativePath(sourceManifestDigest.description))
    }
}

public struct MacOSPortableAuthorityCleanupPlan: Codable, Equatable, Sendable {
    public let schemaVersion: UInt32
    public let transactionID: String
    public let approvalToken: InstallApprovalToken
    public let generationID: String
    public let productApprovalToken: InstallApprovalToken
    public let state: MacOSPortableAuthorityCleanupState

    public init(
        transactionID: String,
        approvalToken: InstallApprovalToken,
        generationID: String,
        productApprovalToken: InstallApprovalToken,
        state: MacOSPortableAuthorityCleanupState
    ) throws {
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: ".-_"))
        guard !transactionID.isEmpty,
              transactionID.utf8.count <= 128,
              transactionID.unicodeScalars.allSatisfy(allowed.contains)
        else {
            throw InstallError.integrity("portable authority cleanup transaction is malformed")
        }
        try InstallManifest.validateIdentifier(generationID, field: "portable cleanup generation ID")
        schemaVersion = 2
        self.transactionID = transactionID
        self.approvalToken = approvalToken
        self.generationID = generationID
        self.productApprovalToken = productApprovalToken
        let validatedState = try MacOSPortableAuthorityCleanupState(
            sourcePackageRoot: state.sourcePackageRoot,
            sourceManifestDigest: state.sourceManifestDigest,
            packageReceiptVersion: state.packageReceiptVersion,
            files: state.files
        )
        guard state.schemaVersion == 1, state == validatedState else {
            throw InstallError.integrity("portable authority cleanup state is not canonical")
        }
        self.state = validatedState
    }

    public func canonicalData() throws -> Data {
        try Self.encoder.encode(self)
    }

    public static func decodeCanonical(_ data: Data) throws -> Self {
        guard data.count <= 65536 else {
            throw InstallError.integrity("portable authority cleanup plan exceeds its byte bound")
        }
        let decoded = try Self.decoder.decode(Self.self, from: data)
        let rebuilt = try Self(
            transactionID: decoded.transactionID,
            approvalToken: decoded.approvalToken,
            generationID: decoded.generationID,
            productApprovalToken: decoded.productApprovalToken,
            state: decoded.state
        )
        guard decoded.schemaVersion == 2,
              decoded == rebuilt,
              try rebuilt.canonicalData() == data
        else {
            throw InstallError.integrity("portable authority cleanup plan is not canonical")
        }
        return rebuilt
    }

    private static let decoder = JSONDecoder()
    private static let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return encoder
    }()
}

public enum MacOSPortableAuthorityCleanupRecovery: String, Equatable, Sendable {
    case none
    case completed
    case discarded
}

public final class MacOSPortableAuthorityLock: @unchecked Sendable {
    private let descriptor: Int32

    public static func acquire() throws -> MacOSPortableAuthorityLock {
        let authority = try FileSystemAuthority(systemRootPath: "/")
        let lockPath = try InstallRelativePath(
            MacOSPortableAuthorityCleanupState.stableLockPathString
        )
        guard let metadata = try authority.metadata(at: lockPath),
              metadata.kind == .regularFile,
              metadata.ownerUID == 0,
              metadata.groupGID == 0,
              metadata.mode == 0o600,
              metadata.linkCount == 1,
              metadata.byteCount == 0,
              !metadata.hasACL,
              metadata.flags == 0
        else {
            throw InstallError.metadata("the portable lifecycle lock has unsafe metadata")
        }
        let descriptor = try authority.openUniqueRegularFile(
            at: lockPath
        )
        try authority.validateNoUnexpectedExtendedMetadata(descriptor)
        guard flock(descriptor, LOCK_EX | LOCK_NB) == 0 else {
            let failure = errno
            close(descriptor)
            if failure == EWOULDBLOCK {
                throw InstallError.alreadyLocked
            }
            throw InstallError.operatingSystem("lock the portable lifecycle authority", failure)
        }
        return MacOSPortableAuthorityLock(descriptor: descriptor)
    }

    init(descriptor: Int32) {
        self.descriptor = descriptor
    }

    deinit {
        if descriptor >= 0 {
            flock(descriptor, LOCK_UN)
            close(descriptor)
        }
    }
}

public struct MacOSPortableAuthorityCleanup: Sendable {
    private let authority: FileSystemAuthority
    private let expectedUID: UInt32
    private let expectedGID: UInt32
    private let productIsAbsent: @Sendable () throws -> Bool
    private let productMatchesApproval: @Sendable (String, InstallApprovalToken) throws -> Bool
    private let packageReceipt: any MacOSPackageReceiptControlling

    public static func production() throws -> Self {
        try Self(
            authority: FileSystemAuthority(systemRootPath: "/"),
            expectedUID: 0,
            expectedGID: 0,
            productIsAbsent: {
                let status = try MacOSInstaller.production().status()
                return status.activeGenerationID == nil
                    && status.generations.isEmpty
                    && status.transactions.isEmpty
                    && !status.dns.active
                    && status.dns.effectiveRemapServiceCount == 0
            },
            productMatchesApproval: { generationID, approvalToken in
                try MacOSInstaller.production()
                    .previewUninstall(generationID: generationID).approvalToken == approvalToken
            },
            packageReceipt: MacOSPackageReceiptStore.production()
        )
    }

    init(
        authority: FileSystemAuthority,
        expectedUID: UInt32,
        expectedGID: UInt32,
        productIsAbsent: @escaping @Sendable () throws -> Bool,
        productMatchesApproval: @escaping @Sendable (
            String,
            InstallApprovalToken
        ) throws -> Bool = { _, _ in false },
        packageReceipt: any MacOSPackageReceiptControlling = MacOSPackageReceiptStore(
            runner: MissingMacOSPackageReceiptRunner()
        )
    ) {
        self.authority = authority
        self.expectedUID = expectedUID
        self.expectedGID = expectedGID
        self.productIsAbsent = productIsAbsent
        self.productMatchesApproval = productMatchesApproval
        self.packageReceipt = packageReceipt
    }

    public func prepare(_ plan: MacOSPortableAuthorityCleanupPlan) throws {
        let planPath = try InstallRelativePath(MacOSPortableAuthorityCleanupState.planPathString)
        try plan.state.validateComplete(
            authority: authority,
            permitsPlan: false,
            expectedUID: expectedUID,
            expectedGID: expectedGID
        )
        guard try authority.metadata(at: planPath) == nil else {
            throw InstallError.collision(planPath.description)
        }
        guard try productMatchesApproval(plan.generationID, plan.productApprovalToken) else {
            throw InstallError.approval("the installed Remap state changed before uninstall")
        }
        guard try packageReceipt.version() == plan.state.packageReceiptVersion else {
            throw InstallError.approval("the Remap package receipt changed before uninstall")
        }
        try authority.writeFile(
            plan.canonicalData(),
            at: planPath,
            ownerUID: expectedUID,
            groupGID: expectedGID,
            mode: 0o400
        )
    }

    public func pendingPlan() throws -> MacOSPortableAuthorityCleanupPlan? {
        let planPath = try InstallRelativePath(MacOSPortableAuthorityCleanupState.planPathString)
        guard try authority.metadata(at: planPath) != nil else { return nil }
        return try MacOSPortableAuthorityCleanupPlan.decodeCanonical(
            readPlanData(at: planPath)
        )
    }

    public func validatePendingPlan(
        expectedApprovalToken: InstallApprovalToken
    ) throws -> MacOSPortableAuthorityCleanupPlan {
        try validatedPendingPlan(expectedApprovalToken: expectedApprovalToken).plan
    }

    @discardableResult
    public func reconcilePendingPlan(
        beforeRemovingHelper: @Sendable () throws -> Void = {}
    ) throws -> MacOSPortableAuthorityCleanupRecovery {
        guard let plan = try pendingPlan() else {
            return .none
        }
        if try productIsAbsent() {
            try perform(
                expectedApprovalToken: plan.approvalToken,
                beforeRemovingHelper: beforeRemovingHelper
            )
            return .completed
        }
        guard try productMatchesApproval(plan.generationID, plan.productApprovalToken) else {
            throw InstallError.integrity(
                "Remap has an interrupted uninstall that must be recovered before continuing"
            )
        }
        try discard(plan)
        return .discarded
    }

    public func perform(
        expectedApprovalToken: InstallApprovalToken,
        beforeRemovingHelper: @Sendable () throws -> Void = {}
    ) throws {
        let planPath = try InstallRelativePath(MacOSPortableAuthorityCleanupState.planPathString)
        let validated = try validatedPendingPlan(expectedApprovalToken: expectedApprovalToken)
        let plan = validated.plan
        let data = validated.data
        let sourcePath = try plan.state.sourceRelativePath()
        if try authority.metadata(at: sourcePath) != nil {
            try MacOSPortableSourcePurge(
                authority: authority,
                packagePath: sourcePath,
                expectedManifestDigest: plan.state.sourceManifestDigest,
                ownerUID: expectedUID,
                groupGID: expectedGID
            ).purge()
        }
        let helperPath = try InstallRelativePath(
            "Library/PrivilegedHelperTools/org.agenxy.Remap.installer-service"
        )
        let removableFiles = try plan.state.files.filter {
            try $0.path != helperPath && (authority.metadata(at: $0.path) != nil)
        }
        for file in removableFiles {
            try authority.unlinkAuthorityFile(
                at: file.path,
                expectedDigest: file.sha256,
                expectedByteCount: file.byteCount,
                ownerUID: expectedUID,
                groupGID: expectedGID,
                mode: file.mode
            )
        }
        let sourcesPath = try InstallRelativePath(MacOSPortableAuthorityCleanupState.sourcesPathString)
        if try authority.metadata(at: sourcesPath) != nil {
            try authority.removeEmptyDirectory(at: sourcesPath)
        }
        try beforeRemovingHelper()
        let helper = plan.state.files.first(where: { $0.path == helperPath })
        let helperIsPresent = try authority.metadata(at: helperPath) != nil
        if let helper, helperIsPresent {
            try authority.unlinkAuthorityFile(
                at: helperPath,
                expectedDigest: helper.sha256,
                expectedByteCount: helper.byteCount,
                ownerUID: expectedUID,
                groupGID: expectedGID,
                mode: helper.mode
            )
        }
        try authority.removeEmptyDirectory(
            at: InstallRelativePath(MacOSPortableAuthorityCleanupState.installerPathString)
        )
        let remapRoot = try InstallRelativePath("Library/Application Support/Agenxy/Remap")
        let remapRootIsPresent = try authority.metadata(at: remapRoot) != nil
        let remapRootIsEmpty = try !remapRootIsPresent || authority.listDirectory(at: remapRoot).isEmpty
        if remapRootIsPresent, remapRootIsEmpty {
            try authority.verifyOwnedDirectory(
                at: remapRoot,
                ownerUID: expectedUID,
                groupGID: expectedGID,
                permittedModes: [0o711]
            )
            try authority.removeEmptyDirectory(at: remapRoot)
        }
        try packageReceipt.forget(expectedVersion: plan.state.packageReceiptVersion)
        try authority.unlinkAuthorityFile(
            at: planPath,
            expectedDigest: InstallDigest.hash(data),
            expectedByteCount: UInt64(data.count),
            ownerUID: expectedUID,
            groupGID: expectedGID,
            mode: 0o400
        )
    }

    private func readPlanData(at path: InstallRelativePath) throws -> Data {
        guard let metadata = try authority.metadata(at: path),
              metadata.kind == .regularFile,
              metadata.ownerUID == expectedUID,
              metadata.groupGID == expectedGID,
              metadata.mode == 0o400,
              metadata.linkCount == 1,
              metadata.byteCount > 0,
              metadata.byteCount <= 65536,
              !metadata.hasACL,
              metadata.flags == 0
        else {
            throw InstallError.metadata("portable authority cleanup plan metadata is unsafe")
        }
        let descriptor = try authority.openUniqueRegularFile(at: path)
        defer { close(descriptor) }
        try authority.validateNoUnexpectedExtendedMetadata(descriptor)
        var opened = stat()
        guard fstat(descriptor, &opened) == 0,
              opened.st_mode & S_IFMT == S_IFREG,
              opened.st_uid == expectedUID,
              opened.st_gid == expectedGID,
              UInt16(opened.st_mode & 0o777) == 0o400,
              opened.st_nlink == 1,
              opened.st_flags == 0,
              UInt64(opened.st_size) == metadata.byteCount
        else {
            throw InstallError.metadata("portable authority cleanup plan changed before read")
        }
        var data = Data()
        data.reserveCapacity(Int(metadata.byteCount))
        var buffer = [UInt8](repeating: 0, count: 16384)
        while true {
            let count = read(descriptor, &buffer, buffer.count)
            guard count >= 0 else {
                if errno == EINTR {
                    continue
                }
                throw InstallError.operatingSystem("read portable cleanup plan", errno)
            }
            if count == 0 {
                break
            }
            guard data.count <= Int(metadata.byteCount) - count else {
                throw InstallError.integrity("portable authority cleanup plan changed size")
            }
            data.append(buffer, count: count)
        }
        var settled = stat()
        guard fstat(descriptor, &settled) == 0,
              settled.st_dev == opened.st_dev,
              settled.st_ino == opened.st_ino,
              settled.st_size == opened.st_size,
              settled.st_mtimespec.tv_sec == opened.st_mtimespec.tv_sec,
              settled.st_mtimespec.tv_nsec == opened.st_mtimespec.tv_nsec,
              settled.st_ctimespec.tv_sec == opened.st_ctimespec.tv_sec,
              settled.st_ctimespec.tv_nsec == opened.st_ctimespec.tv_nsec
        else {
            throw InstallError.integrity("portable authority cleanup plan changed while read")
        }
        return data
    }

    private func validatedPendingPlan(
        expectedApprovalToken: InstallApprovalToken
    ) throws -> (plan: MacOSPortableAuthorityCleanupPlan, data: Data) {
        let planPath = try InstallRelativePath(MacOSPortableAuthorityCleanupState.planPathString)
        guard try authority.metadata(at: planPath) != nil else {
            throw InstallError.integrity("the portable cleanup plan is missing")
        }
        let data = try readPlanData(at: planPath)
        let plan = try MacOSPortableAuthorityCleanupPlan.decodeCanonical(data)
        guard plan.approvalToken == expectedApprovalToken else {
            throw InstallError.approval("the portable cleanup approval changed")
        }
        try plan.state.validateRemaining(
            authority: authority,
            expectedUID: expectedUID,
            expectedGID: expectedGID
        )
        guard try productIsAbsent() else {
            throw InstallError.integrity("Remap product state remains installed")
        }
        let observedReceipt = try packageReceipt.version()
        guard observedReceipt == plan.state.packageReceiptVersion
            || (observedReceipt == nil && plan.state.packageReceiptVersion != nil)
        else {
            throw InstallError.integrity("the Remap package receipt changed during cleanup")
        }
        return (plan, data)
    }

    private func discard(_ plan: MacOSPortableAuthorityCleanupPlan) throws {
        let planPath = try InstallRelativePath(MacOSPortableAuthorityCleanupState.planPathString)
        let data = try readPlanData(at: planPath)
        guard try MacOSPortableAuthorityCleanupPlan.decodeCanonical(data) == plan else {
            throw InstallError.approval("the portable cleanup plan changed")
        }
        try plan.state.validateComplete(
            authority: authority,
            permitsPlan: true,
            expectedUID: expectedUID,
            expectedGID: expectedGID
        )
        guard try productMatchesApproval(plan.generationID, plan.productApprovalToken) else {
            throw InstallError.integrity("the installed Remap state changed during cleanup recovery")
        }
        guard try packageReceipt.version() == plan.state.packageReceiptVersion else {
            throw InstallError.integrity("the Remap package receipt changed during cleanup recovery")
        }
        try authority.unlinkAuthorityFile(
            at: planPath,
            expectedDigest: InstallDigest.hash(data),
            expectedByteCount: UInt64(data.count),
            ownerUID: expectedUID,
            groupGID: expectedGID,
            mode: 0o400
        )
    }
}
