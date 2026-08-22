import Darwin
import Foundation
import RemapInstallKit
import RemapLifecycleKit

enum PortableLifecyclePaths {
    static let helper = MacOSInstallerServiceLaunchd.programPath
    static let configuration = RemapLifecycleServiceConfiguration.absolutePath
    static let plist = MacOSInstallerServiceLaunchd.plistPath
    static let journal = PortableInstallTopology.installerPath
        + "/portable-authority-transaction-v1.jsonl"
    /// This inode deliberately survives product uninstall. Deleting a contended
    /// lock path would let a second process serialize on a different inode.
    static let lock = "/Library/Application Support/Agenxy/.remap-lifecycle-authority.lock"

    static let orderedPublications: [(path: String, mode: UInt16)] = [
        (helper, 0o555),
        (configuration, 0o400),
        (plist, 0o644)
    ]
}

enum PortableAuthorityPhase: Int, Codable, Comparable, Sendable {
    case prepared
    case staged
    case helperPublished
    case configurationPublished
    case plistPublished
    case serviceLoaded
    case productCommitted

    static func < (left: Self, right: Self) -> Bool {
        left.rawValue < right.rawValue
    }
}

struct PortableAuthorityJournalPublication: Codable, Equatable, Sendable {
    let finalPath: String
    let stagedPath: String
    let hadPrevious: Bool
    let newDigest: InstallDigest
    let newByteCount: Int
    let previousDigest: InstallDigest?
    let previousByteCount: Int?
    let mode: UInt16

    init(
        finalPath: String,
        stagedPath: String,
        hadPrevious: Bool,
        newDigest: InstallDigest,
        newByteCount: Int,
        previousDigest: InstallDigest?,
        previousByteCount: Int?,
        mode: UInt16
    ) throws {
        guard finalPath.hasPrefix("/"),
              URL(fileURLWithPath: finalPath).standardizedFileURL.path == finalPath,
              stagedPath.hasPrefix("/"),
              URL(fileURLWithPath: stagedPath).standardizedFileURL.path == stagedPath,
              URL(fileURLWithPath: stagedPath).deletingLastPathComponent()
              == URL(fileURLWithPath: finalPath).deletingLastPathComponent(),
              URL(fileURLWithPath: stagedPath).lastPathComponent
              .hasPrefix(".remap-portable-"),
              stagedPath != finalPath,
              newByteCount > 0,
              newByteCount <= PortableAuthorityFiles.maximumByteCount,
              hadPrevious == (previousDigest != nil),
              hadPrevious == (previousByteCount != nil),
              previousByteCount.map({ $0 > 0 && $0 <= PortableAuthorityFiles.maximumByteCount }) ?? true
        else {
            throw InstallError.integrity("a lifecycle authority journal publication is malformed")
        }
        self.finalPath = finalPath
        self.stagedPath = stagedPath
        self.hadPrevious = hadPrevious
        self.newDigest = newDigest
        self.newByteCount = newByteCount
        self.previousDigest = previousDigest
        self.previousByteCount = previousByteCount
        self.mode = mode
    }
}

struct PortableAuthorityJournal: Codable, Equatable, Sendable {
    static let schemaVersion: UInt32 = 1

    let schemaVersion: UInt32
    let transactionID: String
    let phase: PortableAuthorityPhase
    let generationID: String
    let previousServiceWasLoaded: Bool
    let previousSourceRoot: String?
    let previousSourceManifestDigest: InstallDigest?
    let publications: [PortableAuthorityJournalPublication]

    init(
        transactionID: String,
        phase: PortableAuthorityPhase,
        generationID: String,
        previousServiceWasLoaded: Bool,
        previousSourceRoot: String? = nil,
        previousSourceManifestDigest: InstallDigest? = nil,
        publications: [PortableAuthorityJournalPublication]
    ) throws {
        let characters = CharacterSet.alphanumerics.union(
            CharacterSet(charactersIn: ".-_")
        )
        let expected = PortableLifecyclePaths.orderedPublications
        guard !transactionID.isEmpty,
              transactionID.utf8.count <= 128,
              transactionID.unicodeScalars.allSatisfy(characters.contains),
              !generationID.isEmpty,
              generationID.utf8.count <= 128,
              generationID.unicodeScalars.allSatisfy(characters.contains),
              publications.map(\.finalPath) == expected.map(\.path),
              publications.map(\.mode) == expected.map(\.mode),
              Set(publications.map(\.stagedPath)).count == expected.count,
              (previousSourceRoot == nil) == (previousSourceManifestDigest == nil),
              publications.allSatisfy({ publication in
                  URL(fileURLWithPath: publication.stagedPath).lastPathComponent
                      .hasPrefix(".remap-portable-\(transactionID)-")
              })
        else {
            throw InstallError.integrity("the lifecycle authority journal is malformed")
        }
        if let previousSourceRoot {
            let path = try InstallAbsolutePath(previousSourceRoot)
            guard path.description == PortableInstallTopology.sourcesPath
                + "/\(previousSourceManifestDigest?.description ?? "")"
            else {
                throw InstallError.integrity("the prior portable source identity is malformed")
            }
        }
        schemaVersion = Self.schemaVersion
        self.transactionID = transactionID
        self.phase = phase
        self.generationID = generationID
        self.previousServiceWasLoaded = previousServiceWasLoaded
        self.previousSourceRoot = previousSourceRoot
        self.previousSourceManifestDigest = previousSourceManifestDigest
        self.publications = publications
    }

    func withPhase(_ value: PortableAuthorityPhase) throws -> Self {
        guard value >= phase else {
            throw InstallError.integrity("the lifecycle authority journal moved backward")
        }
        return try Self(
            transactionID: transactionID,
            phase: value,
            generationID: generationID,
            previousServiceWasLoaded: previousServiceWasLoaded,
            previousSourceRoot: previousSourceRoot,
            previousSourceManifestDigest: previousSourceManifestDigest,
            publications: publications
        )
    }

    func canonicalData() throws -> Data {
        try Self.encoder.encode(self)
    }

    static func decodeCanonical(_ data: Data) throws -> Self {
        let decoded = try decoder.decode(Self.self, from: data)
        let rebuilt = try Self(
            transactionID: decoded.transactionID,
            phase: decoded.phase,
            generationID: decoded.generationID,
            previousServiceWasLoaded: decoded.previousServiceWasLoaded,
            previousSourceRoot: decoded.previousSourceRoot,
            previousSourceManifestDigest: decoded.previousSourceManifestDigest,
            publications: decoded.publications
        )
        guard decoded.schemaVersion == schemaVersion,
              decoded == rebuilt,
              try rebuilt.canonicalData() == data
        else {
            throw InstallError.integrity("the lifecycle authority journal is not canonical")
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

private struct PortableAuthorityJournalFrame: Codable, Equatable {
    static let schemaVersion: UInt32 = 1

    let schemaVersion: UInt32
    let sequence: UInt32
    let previousFrameDigest: InstallDigest?
    let journal: PortableAuthorityJournal

    init(
        sequence: UInt32,
        previousFrameDigest: InstallDigest?,
        journal: PortableAuthorityJournal
    ) throws {
        guard (sequence == 0) == (previousFrameDigest == nil) else {
            throw InstallError.journal("the portable authority journal chain is incomplete")
        }
        schemaVersion = Self.schemaVersion
        self.sequence = sequence
        self.previousFrameDigest = previousFrameDigest
        self.journal = journal
    }

    func canonicalData() throws -> Data {
        try Self.encoder.encode(self)
    }

    static func decodeCanonical(_ data: Data) throws -> Self {
        let decoded = try decoder.decode(Self.self, from: data)
        let validatedJournal = try PortableAuthorityJournal.decodeCanonical(
            decoded.journal.canonicalData()
        )
        let rebuilt = try Self(
            sequence: decoded.sequence,
            previousFrameDigest: decoded.previousFrameDigest,
            journal: validatedJournal
        )
        guard decoded.schemaVersion == schemaVersion,
              decoded == rebuilt,
              try rebuilt.canonicalData() == data
        else {
            throw InstallError.journal("a portable authority journal frame is not canonical")
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

struct PortableLifecycleJournalStore: Sendable {
    static let maximumByteCount = 65536
    static let maximumFrameCount = 16

    private let files: PortableAuthorityFiles

    init(files: PortableAuthorityFiles = .production()) {
        self.files = files
    }

    func load() throws -> PortableAuthorityJournal? {
        guard files.exists(PortableLifecyclePaths.journal) else {
            return nil
        }
        let data = try files.readRepairingTrailingFrame(
            PortableLifecyclePaths.journal,
            expectedMode: 0o600,
            maximumByteCount: Self.maximumByteCount
        )
        guard !data.isEmpty else {
            try files.removeIfPresent(PortableLifecyclePaths.journal, expectedMode: 0o600)
            return nil
        }
        return try decodeFrames(data).last?.journal
    }

    func save(_ journal: PortableAuthorityJournal) throws {
        let frames: [PortableAuthorityJournalFrame]
        if files.exists(PortableLifecyclePaths.journal) {
            let data = try files.readRepairingTrailingFrame(
                PortableLifecyclePaths.journal,
                expectedMode: 0o600,
                maximumByteCount: Self.maximumByteCount
            )
            frames = data.isEmpty ? [] : try decodeFrames(data)
            guard let last = frames.last,
                  sameTransaction(last.journal, journal),
                  journal.phase >= last.journal.phase
            else {
                throw InstallError.journal("the portable authority journal changed transaction")
            }
            guard journal.phase != last.journal.phase else {
                guard journal == last.journal else {
                    throw InstallError.journal("the portable authority journal changed without advancing")
                }
                return
            }
        } else {
            guard journal.phase == .prepared else {
                throw InstallError.journal("the portable authority journal did not begin prepared")
            }
            frames = []
        }
        guard frames.count < Self.maximumFrameCount else {
            throw InstallError.journal("the portable authority journal exceeds its frame bound")
        }
        let priorData = try frames.last?.canonicalData()
        let frame = try PortableAuthorityJournalFrame(
            sequence: UInt32(frames.count),
            previousFrameDigest: priorData.map(InstallDigest.hash),
            journal: journal
        )
        var framed = try frame.canonicalData()
        framed.append(0x0A)
        try files.append(
            framed,
            to: PortableLifecyclePaths.journal,
            mode: 0o600,
            maximumByteCount: Self.maximumByteCount
        )
    }

    func remove() throws {
        try files.removeIfPresent(PortableLifecyclePaths.journal, expectedMode: 0o600)
    }

    private func decodeFrames(_ data: Data) throws -> [PortableAuthorityJournalFrame] {
        guard !data.isEmpty, data.last == 0x0A else {
            throw InstallError.journal("the portable authority journal has no complete frame")
        }
        let lines = data.dropLast().split(separator: 0x0A, omittingEmptySubsequences: false)
        guard !lines.isEmpty, lines.count <= Self.maximumFrameCount,
              lines.allSatisfy({ !$0.isEmpty })
        else {
            throw InstallError.journal("the portable authority journal exceeds its frame bound")
        }
        var frames: [PortableAuthorityJournalFrame] = []
        for (index, line) in lines.enumerated() {
            let frame = try PortableAuthorityJournalFrame.decodeCanonical(Data(line))
            let previous = try frames.last?.canonicalData()
            guard frame.sequence == index,
                  frame.previousFrameDigest == previous.map(InstallDigest.hash),
                  frames.last.map({ sameTransaction($0.journal, frame.journal) }) ?? true,
                  frames.last.map({ frame.journal.phase > $0.journal.phase }) ?? true
            else {
                throw InstallError.journal("the portable authority journal chain is invalid")
            }
            frames.append(frame)
        }
        return frames
    }

    private func sameTransaction(
        _ left: PortableAuthorityJournal,
        _ right: PortableAuthorityJournal
    ) -> Bool {
        left.transactionID == right.transactionID
            && left.generationID == right.generationID
            && left.previousServiceWasLoaded == right.previousServiceWasLoaded
            && left.previousSourceRoot == right.previousSourceRoot
            && left.previousSourceManifestDigest == right.previousSourceManifestDigest
            && left.publications == right.publications
    }
}

final class PortableAuthorityLock: @unchecked Sendable {
    private let descriptor: Int32

    private init(descriptor: Int32) {
        self.descriptor = descriptor
    }

    deinit {
        flock(descriptor, LOCK_UN)
        close(descriptor)
    }

    static func acquire(files: PortableAuthorityFiles = .production()) throws -> Self {
        let descriptor = try files.openLock(PortableLifecyclePaths.lock, mode: 0o600)
        guard flock(descriptor, LOCK_EX | LOCK_NB) == 0 else {
            let failure = errno
            close(descriptor)
            if failure == EWOULDBLOCK {
                throw InstallError.alreadyLocked
            }
            throw InstallError.operatingSystem("lock the portable lifecycle authority", failure)
        }
        return Self(descriptor: descriptor)
    }
}

struct PortableAuthorityFileSnapshot: Equatable, Sendable {
    let digest: InstallDigest
    let byteCount: Int
    let mode: UInt16
    let deviceID: UInt64
    let fileID: UInt64
}

struct PortableAuthorityFiles: Sendable {
    static let maximumByteCount = 134_217_728

    let rootPrefix: String
    let expectedUID: uid_t
    let expectedGID: gid_t

    static func production() -> Self {
        Self(rootPrefix: "", expectedUID: 0, expectedGID: 0)
    }

    func resolve(_ logicalPath: String) throws -> String {
        guard logicalPath.hasPrefix("/"),
              URL(fileURLWithPath: logicalPath).standardizedFileURL.path == logicalPath,
              rootPrefix.isEmpty || (
                  rootPrefix.hasPrefix("/")
                      && URL(fileURLWithPath: rootPrefix).standardizedFileURL.path == rootPrefix
              )
        else {
            throw InstallError.invalidPath(logicalPath)
        }
        return rootPrefix + logicalPath
    }

    func exists(_ logicalPath: String) -> Bool {
        guard let path = try? resolve(logicalPath) else { return false }
        return FileManager.default.fileExists(atPath: path)
    }

    func inspect(
        _ logicalPath: String,
        expectedMode: UInt16,
        maximumByteCount: Int = Self.maximumByteCount
    ) throws -> PortableAuthorityFileSnapshot? {
        try inspect(
            logicalPath,
            allowedModes: [expectedMode],
            maximumByteCount: maximumByteCount
        )
    }

    func inspect(
        _ logicalPath: String,
        allowedModes: Set<UInt16>,
        maximumByteCount: Int = Self.maximumByteCount
    ) throws -> PortableAuthorityFileSnapshot? {
        let path = try resolve(logicalPath)
        let descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else {
            if errno == ENOENT {
                return nil
            }
            throw InstallError.operatingSystem("open lifecycle authority data", errno)
        }
        defer { close(descriptor) }
        return try snapshot(
            descriptor,
            allowedModes: allowedModes,
            maximumByteCount: maximumByteCount
        )
    }

    func append(
        _ data: Data,
        to logicalPath: String,
        mode: UInt16,
        maximumByteCount: Int
    ) throws {
        guard !data.isEmpty, data.count <= maximumByteCount else {
            throw InstallError.integrity("lifecycle authority data exceeds its byte bound")
        }
        let path = try resolve(logicalPath)
        var created = false
        var descriptor = open(
            path,
            O_WRONLY | O_APPEND | O_NOFOLLOW | O_CLOEXEC
        )
        if descriptor < 0, errno == ENOENT {
            descriptor = open(
                path,
                O_WRONLY | O_APPEND | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                mode_t(mode)
            )
            created = descriptor >= 0
        }
        guard descriptor >= 0 else {
            throw InstallError.operatingSystem("open the lifecycle authority journal", errno)
        }
        defer { close(descriptor) }
        if created {
            try sealCreated(descriptor, expectedMode: mode)
            try fsyncParent(of: logicalPath)
        } else {
            _ = try validateMetadata(descriptor, allowedModes: [mode])
        }
        var status = stat()
        guard fstat(descriptor, &status) == 0,
              status.st_size >= 0,
              Int(status.st_size) <= maximumByteCount - data.count
        else {
            throw InstallError.journal("the portable authority journal exceeds its byte bound")
        }
        try writeAll(descriptor, data)
        guard fsync(descriptor) == 0 else {
            throw InstallError.durability("the portable authority journal", errno)
        }
        try fsyncParent(of: logicalPath)
    }

    func readRepairingTrailingFrame(
        _ logicalPath: String,
        expectedMode: UInt16,
        maximumByteCount: Int
    ) throws -> Data {
        let path = try resolve(logicalPath)
        let descriptor = open(path, O_RDWR | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else {
            throw InstallError.operatingSystem("open the lifecycle authority journal", errno)
        }
        defer { close(descriptor) }
        let data = try readValidated(
            descriptor,
            expectedMode: expectedMode,
            maximumByteCount: maximumByteCount
        )
        guard !data.isEmpty else { return data }
        guard let lastNewline = data.lastIndex(of: 0x0A) else {
            guard ftruncate(descriptor, 0) == 0,
                  fsync(descriptor) == 0
            else {
                throw InstallError.durability("a partial portable authority journal frame", errno)
            }
            try fsyncParent(of: logicalPath)
            return Data()
        }
        let completeEnd = data.index(after: lastNewline)
        guard completeEnd != data.endIndex else { return data }
        guard ftruncate(descriptor, off_t(completeEnd)) == 0,
              fsync(descriptor) == 0
        else {
            throw InstallError.durability("a partial portable authority journal frame", errno)
        }
        try fsyncParent(of: logicalPath)
        return Data(data[..<completeEnd])
    }

    func openLock(_ logicalPath: String, mode: UInt16) throws -> Int32 {
        let path = try resolve(logicalPath)
        var created = false
        var descriptor = open(
            path,
            O_RDWR | O_NOFOLLOW | O_CLOEXEC
        )
        if descriptor < 0, errno == ENOENT {
            descriptor = open(
                path,
                O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                mode_t(mode)
            )
            created = descriptor >= 0
        }
        guard descriptor >= 0 else {
            throw InstallError.operatingSystem("open the portable authority lock", errno)
        }
        do {
            if created {
                try sealCreated(descriptor, expectedMode: mode)
                try fsyncParent(of: logicalPath)
            } else {
                _ = try validateMetadata(descriptor, allowedModes: [mode])
            }
            return descriptor
        } catch {
            close(descriptor)
            throw error
        }
    }

    func writeNew(_ data: Data, to logicalPath: String, finalMode: UInt16) throws {
        guard !data.isEmpty, data.count <= Self.maximumByteCount else {
            throw InstallError.integrity("lifecycle authority data exceeds its byte bound")
        }
        let path = try resolve(logicalPath)
        let descriptor = open(
            path,
            O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
            0o600
        )
        guard descriptor >= 0 else {
            throw InstallError.operatingSystem("stage lifecycle authority data", errno)
        }
        defer { close(descriptor) }
        guard fchown(descriptor, expectedUID, expectedGID) == 0 else {
            throw InstallError.operatingSystem("own staged lifecycle authority data", errno)
        }
        try writeAll(descriptor, data)
        guard fchmod(descriptor, mode_t(finalMode)) == 0,
              fsync(descriptor) == 0
        else {
            throw InstallError.operatingSystem("seal staged lifecycle authority data", errno)
        }
        let observed = try snapshot(
            descriptor,
            allowedModes: [finalMode],
            maximumByteCount: data.count
        )
        guard observed.digest == InstallDigest.hash(data),
              observed.byteCount == data.count
        else {
            throw InstallError.integrity("staged lifecycle authority data changed")
        }
        try fsyncParent(of: logicalPath)
    }

    func exchange(
        _ left: String,
        expectedLeft: PortableAuthorityFileSnapshot,
        with right: String,
        expectedRight: PortableAuthorityFileSnapshot
    ) throws {
        guard try inspect(left, allowedModes: [expectedLeft.mode]) == expectedLeft,
              try inspect(right, allowedModes: [expectedRight.mode]) == expectedRight
        else {
            throw InstallError.collision("lifecycle authority publication identity changed")
        }
        let leftPath = try resolve(left)
        let rightPath = try resolve(right)
        guard renamex_np(leftPath, rightPath, UInt32(RENAME_SWAP)) == 0 else {
            throw InstallError.operatingSystem("exchange lifecycle authority data", errno)
        }
        try fsyncParent(of: right)
    }

    func moveNoReplace(
        _ source: String,
        expectedSource: PortableAuthorityFileSnapshot,
        to destination: String
    ) throws {
        guard try inspect(source, allowedModes: [expectedSource.mode]) == expectedSource,
              !exists(destination)
        else {
            throw InstallError.collision("lifecycle authority publication identity changed")
        }
        let sourcePath = try resolve(source)
        let destinationPath = try resolve(destination)
        guard renamex_np(sourcePath, destinationPath, UInt32(RENAME_EXCL)) == 0 else {
            throw InstallError.operatingSystem("publish lifecycle authority data", errno)
        }
        try fsyncParent(of: destination)
    }

    func removeExact(
        _ logicalPath: String,
        expected: PortableAuthorityFileSnapshot
    ) throws {
        guard try inspect(logicalPath, allowedModes: [expected.mode]) == expected else {
            throw InstallError.collision("lifecycle authority removal identity changed")
        }
        let path = try resolve(logicalPath)
        var status = stat()
        guard lstat(path, &status) == 0 else {
            throw InstallError.operatingSystem("remove lifecycle authority data", errno)
        }
        guard UInt64(status.st_dev) == expected.deviceID,
              UInt64(status.st_ino) == expected.fileID
        else {
            throw InstallError.collision("lifecycle authority removal identity changed")
        }
        guard unlink(path) == 0 else {
            throw InstallError.operatingSystem("remove lifecycle authority data", errno)
        }
        try fsyncParent(of: logicalPath)
    }

    func removeIfPresent(_ logicalPath: String, expectedMode: UInt16) throws {
        guard let expected = try inspect(logicalPath, expectedMode: expectedMode) else { return }
        try removeExact(logicalPath, expected: expected)
    }

    func fsyncParent(of logicalPath: String) throws {
        let path = try resolve(logicalPath)
        let parent = URL(fileURLWithPath: path).deletingLastPathComponent().path
        let descriptor = open(parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else {
            throw InstallError.operatingSystem("open a lifecycle authority directory", errno)
        }
        defer { close(descriptor) }
        guard fsync(descriptor) == 0 else {
            throw InstallError.durability("the lifecycle authority directory", errno)
        }
    }

    private func readValidated(
        _ descriptor: Int32,
        expectedMode: UInt16,
        maximumByteCount: Int
    ) throws -> Data {
        var status = try validateMetadata(descriptor, allowedModes: [expectedMode])
        guard status.st_size >= 0, status.st_size <= maximumByteCount else {
            throw InstallError.integrity("lifecycle authority data exceeds its byte bound")
        }
        var data = Data()
        var offset: off_t = 0
        var buffer = [UInt8](repeating: 0, count: 65536)
        while offset < status.st_size {
            let count = pread(
                descriptor,
                &buffer,
                min(buffer.count, Int(status.st_size - offset)),
                offset
            )
            guard count > 0 else {
                throw InstallError.integrity("lifecycle authority data changed while it was read")
            }
            data.append(contentsOf: buffer.prefix(count))
            offset += off_t(count)
        }
        var finalByte: UInt8 = 0
        guard pread(descriptor, &finalByte, 1, offset) == 0,
              fstat(descriptor, &status) == 0,
              status.st_size == offset
        else {
            throw InstallError.integrity("lifecycle authority data changed while it was read")
        }
        return data
    }

    private func snapshot(
        _ descriptor: Int32,
        allowedModes: Set<UInt16>,
        maximumByteCount: Int
    ) throws -> PortableAuthorityFileSnapshot {
        let before = try validateMetadata(descriptor, allowedModes: allowedModes)
        guard before.st_size >= 0, before.st_size <= maximumByteCount else {
            throw InstallError.integrity("lifecycle authority data exceeds its byte bound")
        }
        let data = try readValidated(
            descriptor,
            expectedMode: UInt16(before.st_mode & 0o777),
            maximumByteCount: maximumByteCount
        )
        let after = try validateMetadata(descriptor, allowedModes: allowedModes)
        guard before.st_dev == after.st_dev,
              before.st_ino == after.st_ino,
              before.st_size == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec,
              before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec
        else {
            throw InstallError.integrity("lifecycle authority data changed while it was inspected")
        }
        return PortableAuthorityFileSnapshot(
            digest: InstallDigest.hash(data),
            byteCount: data.count,
            mode: UInt16(after.st_mode & 0o777),
            deviceID: UInt64(after.st_dev),
            fileID: UInt64(after.st_ino)
        )
    }

    private func validateMetadata(
        _ descriptor: Int32,
        allowedModes: Set<UInt16>
    ) throws -> stat {
        var status = stat()
        guard fstat(descriptor, &status) == 0,
              status.st_mode & S_IFMT == S_IFREG,
              status.st_uid == expectedUID,
              status.st_gid == expectedGID,
              allowedModes.contains(UInt16(status.st_mode & 0o777)),
              status.st_nlink == 1,
              status.st_flags == 0,
              try Set(attributeNames(descriptor)).isSubset(of: ["com.apple.provenance"]),
              try !hasACL(descriptor)
        else {
            throw InstallError.metadata("lifecycle authority data has unsafe metadata")
        }
        return status
    }

    private func sealCreated(_ descriptor: Int32, expectedMode: UInt16) throws {
        guard fchown(descriptor, expectedUID, expectedGID) == 0,
              fchmod(descriptor, mode_t(expectedMode)) == 0
        else {
            throw InstallError.operatingSystem("seal lifecycle authority data", errno)
        }
        _ = try validateMetadata(descriptor, allowedModes: [expectedMode])
    }

    private func writeAll(_ descriptor: Int32, _ data: Data) throws {
        try data.withUnsafeBytes { bytes in
            guard let base = bytes.baseAddress else { return }
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.write(
                    descriptor,
                    base.advanced(by: offset),
                    bytes.count - offset
                )
                if count > 0 {
                    offset += count
                } else if errno != EINTR {
                    throw InstallError.operatingSystem("write lifecycle authority data", errno)
                }
            }
        }
    }

    private func attributeNames(_ descriptor: Int32) throws -> [String] {
        let size = flistxattr(descriptor, nil, 0, 0)
        guard size >= 0 else {
            throw InstallError.operatingSystem("inspect lifecycle authority attributes", errno)
        }
        guard size > 0 else { return [] }
        var bytes = [CChar](repeating: 0, count: size)
        guard flistxattr(descriptor, &bytes, size, 0) == size else {
            throw InstallError.operatingSystem("read lifecycle authority attributes", errno)
        }
        return bytes.split(separator: 0).map {
            String(decoding: $0.map(UInt8.init(bitPattern:)), as: UTF8.self)
        }.sorted()
    }

    private func hasACL(_ descriptor: Int32) throws -> Bool {
        guard let list = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else {
            if errno == ENOENT {
                return false
            }
            throw InstallError.operatingSystem("inspect lifecycle authority ACL", errno)
        }
        defer { acl_free(UnsafeMutableRawPointer(list)) }
        var entry: acl_entry_t?
        let result = acl_get_entry(list, Int32(ACL_FIRST_ENTRY.rawValue), &entry)
        guard result >= 0 else {
            throw InstallError.operatingSystem("read lifecycle authority ACL", errno)
        }
        return result == 0
    }
}
