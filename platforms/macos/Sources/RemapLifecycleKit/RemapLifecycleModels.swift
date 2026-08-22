import Foundation
import RemapInstallKit

public enum RemapLifecycleAction: String, Codable, Equatable, Sendable {
    case install
    case previewInstall = "preview-install"
    case previewRecover = "preview-recover"
    case previewRecoverBootstrapHelpers = "preview-recover-bootstrap-helpers"
    case previewUninstall = "preview-uninstall"
    case previewUpdate = "preview-update"
    case recover
    case recoverBootstrapHelpers = "recover-bootstrap-helpers"
    case status
    case uninstall
    case update
}

public struct RemapLifecycleRequest: Codable, Equatable, Sendable {
    public let schemaVersion: UInt32
    public let action: RemapLifecycleAction
    public let packageRoot: String?
    public let manifestDigest: InstallDigest?
    public let generationID: String?
    public let transactionID: String?
    public let approvalToken: InstallApprovalToken?

    public init(
        action: RemapLifecycleAction,
        packageRoot: String? = nil,
        manifestDigest: InstallDigest? = nil,
        generationID: String? = nil,
        transactionID: String? = nil,
        approvalToken: InstallApprovalToken? = nil
    ) throws {
        schemaVersion = 1
        self.action = action
        self.packageRoot = packageRoot
        self.manifestDigest = manifestDigest
        self.generationID = generationID
        self.transactionID = transactionID
        self.approvalToken = approvalToken
        try validate()
    }

    public func validate() throws {
        guard schemaVersion == 1 else {
            throw InstallError.unsupported("lifecycle request schema")
        }
        if let packageRoot {
            _ = try InstallAbsolutePath(packageRoot)
        }
        if let generationID {
            try validateIdentifier(generationID, field: "generation ID")
        }
        if let transactionID {
            try validateIdentifier(transactionID, field: "transaction ID")
        }
        let valid = switch action {
        case .status, .previewRecover, .previewRecoverBootstrapHelpers:
            packageRoot == nil && manifestDigest == nil && generationID == nil
                && transactionID == nil && approvalToken == nil
        case .previewInstall, .previewUpdate:
            (packageRoot == nil) == (manifestDigest == nil) && generationID == nil
                && transactionID == nil && approvalToken == nil
        case .install, .update:
            (packageRoot == nil) == (manifestDigest == nil) && generationID == nil
                && approvalToken != nil
        case .previewUninstall:
            packageRoot == nil && manifestDigest == nil && generationID != nil
                && transactionID == nil && approvalToken == nil
        case .uninstall:
            packageRoot == nil && manifestDigest == nil && generationID != nil
                && approvalToken != nil
        case .recover:
            packageRoot == nil && manifestDigest == nil && generationID == nil
                && approvalToken != nil
        case .recoverBootstrapHelpers:
            packageRoot == nil && manifestDigest == nil && generationID == nil
                && transactionID == nil && approvalToken != nil
        }
        guard valid else {
            throw InstallError.integrity("lifecycle request fields do not match its action")
        }
    }

    private func validateIdentifier(_ value: String, field: String) throws {
        let allowed = CharacterSet.alphanumerics.union(
            CharacterSet(charactersIn: ".-_+")
        )
        guard !value.isEmpty,
              value.utf8.count <= 128,
              !value.contains("\0"),
              value.unicodeScalars.allSatisfy(allowed.contains)
        else {
            throw InstallError.integrity("lifecycle (field) is malformed")
        }
    }
}

public enum RemapLifecycleOutcome: String, Codable, Equatable, Sendable {
    case failure
    case success
}

public enum RemapLifecycleDiagnosticCategory: String, Codable, Equatable, Sendable {
    case approval
    case authority
    case busy
    case conflict
    case integrity
    case internalFailure = "internal"
    case unsupported
}

public struct RemapLifecycleDiagnostic: Codable, Equatable, Sendable {
    public let category: RemapLifecycleDiagnosticCategory
    public let message: String
    public let hint: String
    public let retryable: Bool

    public init(
        category: RemapLifecycleDiagnosticCategory,
        message: String,
        hint: String,
        retryable: Bool
    ) {
        self.category = category
        self.message = message
        self.hint = hint
        self.retryable = retryable
    }
}

public struct RemapLifecycleMutationResult: Codable, Equatable, Sendable {
    public let generationID: String
    public let transactionID: String
    public let authorityCleanupPending: Bool?

    public init(
        generationID: String,
        transactionID: String,
        authorityCleanupPending: Bool? = nil
    ) {
        self.generationID = generationID
        self.transactionID = transactionID
        self.authorityCleanupPending = authorityCleanupPending
    }
}

public struct RemapLifecycleResponse: Codable, Equatable, Sendable {
    public let schemaVersion: UInt32
    public let action: RemapLifecycleAction
    public let outcome: RemapLifecycleOutcome
    public let status: MacOSInstallerStatus?
    public let preview: MacOSInstallerPreview?
    public let uninstallPreview: RemapLifecycleUninstallPreview?
    public let recoveryPreview: MacOSInstallerRecoveryPreview?
    public let bootstrapRecoveryPreview: MacOSBootstrapHelperRecoveryPreview?
    public let mutation: RemapLifecycleMutationResult?
    public let recovery: MacOSInstallerRecoveryResult?
    public let bootstrapRecovery: MacOSBootstrapHelperRecoveryResult?
    public let diagnostic: RemapLifecycleDiagnostic?

    public static func success(
        action: RemapLifecycleAction,
        status: MacOSInstallerStatus? = nil,
        preview: MacOSInstallerPreview? = nil,
        uninstallPreview: RemapLifecycleUninstallPreview? = nil,
        recoveryPreview: MacOSInstallerRecoveryPreview? = nil,
        bootstrapRecoveryPreview: MacOSBootstrapHelperRecoveryPreview? = nil,
        mutation: RemapLifecycleMutationResult? = nil,
        recovery: MacOSInstallerRecoveryResult? = nil,
        bootstrapRecovery: MacOSBootstrapHelperRecoveryResult? = nil
    ) throws -> Self {
        try Self(
            action: action,
            outcome: .success,
            status: status,
            preview: preview,
            uninstallPreview: uninstallPreview,
            recoveryPreview: recoveryPreview,
            bootstrapRecoveryPreview: bootstrapRecoveryPreview,
            mutation: mutation,
            recovery: recovery,
            bootstrapRecovery: bootstrapRecovery,
            diagnostic: nil
        )
    }

    public static func failure(
        action: RemapLifecycleAction,
        diagnostic: RemapLifecycleDiagnostic
    ) -> Self {
        Self(action: action, diagnostic: diagnostic)
    }

    public func validate() throws {
        guard schemaVersion == 1 else {
            throw InstallError.unsupported("lifecycle response schema")
        }
        let payloadCount = [
            status != nil,
            preview != nil,
            uninstallPreview != nil,
            recoveryPreview != nil,
            bootstrapRecoveryPreview != nil,
            mutation != nil,
            recovery != nil,
            bootstrapRecovery != nil,
            diagnostic != nil
        ].count(where: { $0 })
        guard payloadCount == 1,
              (outcome == .success) == (diagnostic == nil),
              payloadMatchesAction
        else {
            throw InstallError.integrity("lifecycle response payload is ambiguous")
        }
        try uninstallPreview?.validate()
    }

    private var payloadMatchesAction: Bool {
        if outcome == .failure {
            return diagnostic != nil
        }
        return switch action {
        case .status: status != nil
        case .previewInstall, .previewUpdate: preview != nil
        case .previewUninstall: preview != nil || uninstallPreview != nil
        case .previewRecover: recoveryPreview != nil
        case .previewRecoverBootstrapHelpers: bootstrapRecoveryPreview != nil
        case .install, .uninstall, .update: mutation != nil
        case .recover: recovery != nil
        case .recoverBootstrapHelpers: bootstrapRecovery != nil
        }
    }

    private init(
        action: RemapLifecycleAction,
        outcome: RemapLifecycleOutcome,
        status: MacOSInstallerStatus?,
        preview: MacOSInstallerPreview?,
        uninstallPreview: RemapLifecycleUninstallPreview?,
        recoveryPreview: MacOSInstallerRecoveryPreview?,
        bootstrapRecoveryPreview: MacOSBootstrapHelperRecoveryPreview?,
        mutation: RemapLifecycleMutationResult?,
        recovery: MacOSInstallerRecoveryResult?,
        bootstrapRecovery: MacOSBootstrapHelperRecoveryResult?,
        diagnostic: RemapLifecycleDiagnostic?
    ) throws {
        schemaVersion = 1
        self.action = action
        self.outcome = outcome
        self.status = status
        self.preview = preview
        self.uninstallPreview = uninstallPreview
        self.recoveryPreview = recoveryPreview
        self.bootstrapRecoveryPreview = bootstrapRecoveryPreview
        self.mutation = mutation
        self.recovery = recovery
        self.bootstrapRecovery = bootstrapRecovery
        self.diagnostic = diagnostic
        try validate()
    }

    private init(
        action: RemapLifecycleAction,
        diagnostic: RemapLifecycleDiagnostic
    ) {
        schemaVersion = 1
        self.action = action
        outcome = .failure
        status = nil
        preview = nil
        uninstallPreview = nil
        recoveryPreview = nil
        bootstrapRecoveryPreview = nil
        mutation = nil
        recovery = nil
        bootstrapRecovery = nil
        self.diagnostic = diagnostic
    }
}

public enum RemapLifecycleCoding {
    public static func decodeRequest(_ data: Data) throws -> RemapLifecycleRequest {
        guard data.count <= RemapLifecycleXPC.maximumRequestByteCount else {
            throw InstallError.integrity("lifecycle request exceeds its byte bound")
        }
        let request = try decoder.decode(RemapLifecycleRequest.self, from: data)
        try request.validate()
        return request
    }

    public static func encodeRequest(_ request: RemapLifecycleRequest) throws -> Data {
        try request.validate()
        let data = try encoder.encode(request)
        guard data.count <= RemapLifecycleXPC.maximumRequestByteCount else {
            throw InstallError.integrity("lifecycle request exceeds its byte bound")
        }
        return data
    }

    public static func decodeResponse(_ data: Data) throws -> RemapLifecycleResponse {
        guard data.count <= RemapLifecycleXPC.maximumResponseByteCount else {
            throw InstallError.integrity("lifecycle response exceeds its byte bound")
        }
        let response = try decoder.decode(RemapLifecycleResponse.self, from: data)
        try response.validate()
        return response
    }

    public static func encodeResponse(_ response: RemapLifecycleResponse) throws -> Data {
        try response.validate()
        let data = try encoder.encode(response)
        guard data.count <= RemapLifecycleXPC.maximumResponseByteCount else {
            throw InstallError.integrity("lifecycle response exceeds its byte bound")
        }
        return data
    }

    private static let decoder = JSONDecoder()

    private static let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return encoder
    }()
}
