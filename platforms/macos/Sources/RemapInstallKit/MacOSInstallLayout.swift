import Foundation

/// Fixed privileged storage layout for the native macOS source installer.
public struct MacOSInstallLayout: Sendable {
    public static let installerBase = "Library/Application Support/Agenxy/Remap/Install"

    public let authority: FileSystemAuthority
    public let generations: GenerationStore
    public let publications: PublicationStore
    public let journals: InstallJournalStore
    public let lockPath: InstallRelativePath

    private let topology: MacOSInstallTopology
    let lockConfiguration: InstallLockConfiguration
    let systemRootPath: String
    let generationsPath: InstallRelativePath
    let installOwnerUID: UInt32
    let installGroupGID: UInt32

    public static func production() throws -> MacOSInstallLayout {
        let authority = try FileSystemAuthority(systemRootPath: "/")
        return try MacOSInstallLayout(
            authority: authority,
            systemRootPath: "/",
            installOwnerUID: 0,
            installGroupGID: 0
        )
    }

    init(
        authority: FileSystemAuthority,
        systemRootPath: String,
        installOwnerUID: UInt32,
        installGroupGID: UInt32
    ) throws {
        let base = try InstallRelativePath(Self.installerBase)
        let organisation = try InstallRelativePath("Library/Application Support/Agenxy")
        let generationsPath = try base.appending(component: "Generations")
        let journalsPath = try base.appending(component: "Journals")
        self.authority = authority
        self.systemRootPath = systemRootPath
        self.generationsPath = generationsPath
        self.installOwnerUID = installOwnerUID
        self.installGroupGID = installGroupGID
        topology = try MacOSInstallTopology(
            authority: authority,
            ownerUID: installOwnerUID,
            groupGID: installGroupGID
        )
        generations = GenerationStore(
            authority: authority,
            generationsPath: generationsPath,
            ownerUID: installOwnerUID,
            groupGID: installGroupGID
        )
        publications = PublicationStore(authority: authority)
        journals = InstallJournalStore(
            authority: authority,
            journalsPath: journalsPath,
            ownerUID: installOwnerUID,
            groupGID: installGroupGID
        )
        lockPath = organisation
        lockConfiguration = InstallLockConfiguration(
            authority: authority,
            path: organisation,
            kind: .ownedDirectory(
                ownerUID: installOwnerUID,
                groupGID: installGroupGID,
                mode: 0o755
            )
        )
    }

    func prepareStorageTopology() throws {
        try topology.prepare()
    }

    func removeEmptyProductStorage() throws {
        try topology.removeEmptyProductStorage()
    }

    func hasOwnedProductStorage() throws -> Bool {
        try topology.hasOwnedProductStorage()
    }

    func generationPath(_ generationID: String) throws -> InstallRelativePath {
        try InstallManifest.validateIdentifier(generationID, field: "generation ID")
        return try generationsPath.appending(component: generationID)
    }

    func absoluteGenerationPath(_ generationID: String) throws -> InstallAbsolutePath {
        let relative = try generationPath(generationID)
        let root = URL(fileURLWithPath: systemRootPath, isDirectory: true)
        return try InstallAbsolutePath(root.appending(path: relative.description).path)
    }
}
