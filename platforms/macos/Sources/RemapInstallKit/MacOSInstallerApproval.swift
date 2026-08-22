import Foundation

public enum MacOSInstallerApprovalPublicationClassification: String, Codable, Equatable, Sendable {
    case compatible
    case missing
    case owned
}

public struct MacOSInstallerApprovalGeneration: Codable, Equatable, Sendable {
    public let generationID: String
    public let manifestDigest: InstallDigest

    init(manifest: InstallManifest) throws {
        generationID = manifest.generationID
        manifestDigest = try manifest.digest()
    }
}

public struct MacOSInstallerApprovalPublicationState: Codable, Equatable, Sendable {
    public let path: InstallRelativePath
    public let kind: InstallPublicationKind
    public let generationID: String
    public let classification: MacOSInstallerApprovalPublicationClassification

    init(
        publication: InstallPublication,
        classification: PublicationClassification
    ) throws {
        let approvalClassification: MacOSInstallerApprovalPublicationClassification = switch classification {
        case .compatible:
            .compatible
        case .missing:
            .missing
        case .owned:
            .owned
        case .unmanaged:
            throw InstallError.collision(publication.path.description)
        }
        path = publication.path
        kind = publication.kind
        generationID = publication.generationID
        self.classification = approvalClassification
    }
}

public struct MacOSInstallerApprovalState: Codable, Equatable, Sendable {
    public static let maximumGenerations = 64
    public static let maximumPublications = 256
    public static let maximumServices = 16

    public let schemaVersion: UInt32
    public let manifestDigest: InstallDigest
    public let previousManifestDigest: InstallDigest?
    public let activeGenerationID: String?
    public let installedGenerations: [MacOSInstallerApprovalGeneration]
    public let publicationStates: [MacOSInstallerApprovalPublicationState]
    public let services: [MacOSInstallerServiceStatus]
    public let dns: MacOSInstallerDNSStatus

    init(
        manifestDigest: InstallDigest,
        previousManifestDigest: InstallDigest?,
        activeGenerationID: String?,
        installedGenerations: [MacOSInstallerApprovalGeneration],
        publicationStates: [MacOSInstallerApprovalPublicationState],
        services: [MacOSInstallerServiceStatus],
        dns: MacOSInstallerDNSStatus
    ) throws {
        let generations = installedGenerations.sorted { $0.generationID < $1.generationID }
        let publications = publicationStates.sorted { $0.path < $1.path }
        let orderedServices = services.sorted { $0.label < $1.label }
        guard generations.count <= Self.maximumGenerations,
              publications.count <= Self.maximumPublications,
              orderedServices.count <= Self.maximumServices,
              Set(generations.map(\.generationID)).count == generations.count,
              Set(publications.map(\.path)).count == publications.count,
              Set(orderedServices.map(\.label)).count == orderedServices.count,
              activeGenerationID == nil || generations.contains(where: { $0.generationID == activeGenerationID })
        else {
            throw InstallError.integrity("installer approval state exceeds its deterministic bounds")
        }
        schemaVersion = 1
        self.manifestDigest = manifestDigest
        self.previousManifestDigest = previousManifestDigest
        self.activeGenerationID = activeGenerationID
        self.installedGenerations = generations
        self.publicationStates = publications
        self.services = orderedServices
        self.dns = dns
    }
}

struct MacOSInstallerApprovalPayload: Encodable {
    let schemaVersion: UInt32
    let operation: InstallOperation
    let generationID: String
    let productVersion: String
    let verifiedSourceEntries: Int
    let publicationChangeDetails: [MacOSInstallerPublicationChange]
    let pendingRecoveryTransactions: [String]
    let effects: [String]
    let approvalState: MacOSInstallerApprovalState
}

public protocol InstallApprovalVerifying: Sendable {
    func verify(_ context: InstallTransitionContext) throws
}
