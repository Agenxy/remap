import Foundation

/// Collision-safe privileged directories whose modes separate public payload traversal
/// from private transaction state.
struct MacOSInstallTopology: Sendable {
    private static let organisationMode: UInt16 = 0o755
    private static let publicTraversalMode: UInt16 = 0o711

    private let authority: FileSystemAuthority
    private let ownerUID: UInt32
    private let groupGID: UInt32
    private let organisationPath: InstallRelativePath
    private let productPath: InstallRelativePath
    private let installPath: InstallRelativePath
    private let generationsPath: InstallRelativePath
    private let journalsPath: InstallRelativePath
    private let legacyLockPath: InstallRelativePath

    init(
        authority: FileSystemAuthority,
        ownerUID: UInt32,
        groupGID: UInt32
    ) throws {
        self.authority = authority
        self.ownerUID = ownerUID
        self.groupGID = groupGID
        organisationPath = try InstallRelativePath("Library/Application Support/Agenxy")
        productPath = try organisationPath.appending(component: "Remap")
        installPath = try productPath.appending(component: "Install")
        generationsPath = try installPath.appending(component: "Generations")
        journalsPath = try installPath.appending(component: "Journals")
        legacyLockPath = try installPath.appending(component: "transaction.lock")
    }

    func prepare() throws {
        try ensure(organisationPath, mode: Self.organisationMode)
        try ensure(productPath, mode: Self.publicTraversalMode)
        try ensure(installPath, mode: Self.publicTraversalMode)
        try ensure(generationsPath, mode: Self.publicTraversalMode)
    }

    /// Removes only the exact empty native-install topology after an uninstall.
    /// The shared Agenxy directory remains as the stable cross-process lock
    /// authority, and a sibling native-package lifecycle directory keeps the
    /// product parent in place.
    func removeEmptyProductStorage() throws {
        try removeLegacyLockIfPresent()
        try removeEmptyOwnedDirectory(journalsPath, mode: 0o700)
        try removeEmptyOwnedDirectory(generationsPath, mode: Self.publicTraversalMode)
        try removeEmptyOwnedDirectory(installPath, mode: Self.publicTraversalMode)
        try removeProductParentIfEmpty()
    }

    /// Reports whether the exact Remap native-install root exists. A package's
    /// separate `Installer` lifecycle sibling does not itself require recovery.
    func hasOwnedProductStorage() throws -> Bool {
        guard try authority.metadata(at: installPath) != nil else {
            return false
        }
        try authority.verifyOwnedDirectory(
            at: installPath,
            ownerUID: ownerUID,
            groupGID: groupGID,
            permittedModes: [Self.publicTraversalMode]
        )
        return true
    }

    private func ensure(_ path: InstallRelativePath, mode: UInt16) throws {
        try authority.ensureOwnedDirectory(
            at: path,
            ownerUID: ownerUID,
            groupGID: groupGID,
            mode: mode
        )
    }

    private func removeLegacyLockIfPresent() throws {
        guard try authority.metadata(at: legacyLockPath) != nil else {
            return
        }
        let entry = try InstallEntry(
            path: InstallRelativePath("transaction.lock"),
            kind: .regularFile,
            role: .support,
            sha256: InstallDigest.hash(Data()),
            byteCount: 0,
            ownerUID: ownerUID,
            groupGID: groupGID,
            mode: 0o600
        )
        try authority.unlinkRegularFile(at: legacyLockPath, expected: entry)
    }

    private func removeEmptyOwnedDirectory(_ path: InstallRelativePath, mode: UInt16) throws {
        guard try authority.metadata(at: path) != nil else {
            return
        }
        try authority.verifyOwnedDirectory(
            at: path,
            ownerUID: ownerUID,
            groupGID: groupGID,
            permittedModes: [mode]
        )
        guard try authority.listDirectory(at: path).isEmpty else {
            throw InstallError.collision(path.description)
        }
        try authority.removeEmptyDirectory(at: path)
    }

    private func removeProductParentIfEmpty() throws {
        guard try authority.metadata(at: productPath) != nil else {
            return
        }
        try authority.verifyOwnedDirectory(
            at: productPath,
            ownerUID: ownerUID,
            groupGID: groupGID,
            permittedModes: [Self.publicTraversalMode]
        )
        guard try authority.listDirectory(at: productPath).isEmpty else {
            return
        }
        try authority.removeEmptyDirectory(at: productPath)
    }
}
