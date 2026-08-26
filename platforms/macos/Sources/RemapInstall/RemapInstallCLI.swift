import Darwin
import Foundation
import RemapInstallKit
import RemapSystemKit

enum RemapInstallCLI {
    static func run(arguments: [String]) async -> Int32 {
        do {
            let invocation = try RemapInstallArguments.parse(arguments)
            try await execute(invocation)
            return 0
        } catch {
            RemapInstallOutput.failure(error, json: arguments.contains("--json"))
            return RemapInstallOutput.exitStatus(for: error)
        }
    }

    private static func execute(_ invocation: RemapInstallInvocation) async throws {
        switch invocation.command {
        case .help:
            print(help)
        case .version:
            print("remap-install \(RemapProduct.version)")
        case .status:
            let value = try MacOSInstaller.production().status()
            try RemapInstallOutput.success(
                command: "status",
                value: value,
                json: invocation.json,
                human: statusSummary(value)
            )
        case .resolverPlan:
            let value = try resolverPlan()
            let serviceLabel = value.serviceCount == 1 ? "service" : "services"
            let upstreamLabel = value.upstreams.count == 1 ? "upstream" : "upstreams"
            try RemapInstallOutput.success(
                command: "resolver-plan",
                value: value,
                json: invocation.json,
                human: "Resolver plan: \(value.serviceCount) \(serviceLabel), "
                    + "\(value.upstreams.count) \(upstreamLabel)."
            )
        case let .recoverAll(approvalToken):
            let result = try await executeRecoverAll(approvalToken)
            let summary = "Recovery complete. Transactions: \(result.recoveredTransactions.count); "
                + "orphans: \(result.quarantinedOrphans.count)."
            try RemapInstallOutput.success(
                command: "recover",
                value: result,
                json: invocation.json,
                human: summary
            )
        case let .recoverBootstrapHelpers(approvalToken):
            let result = try await executeBootstrapRecovery(approvalToken)
            try RemapInstallOutput.success(
                command: "recover-bootstrap-helpers",
                value: result,
                json: invocation.json,
                human: "Removed \(result.removedPaths.count) verified orphan bootstrap helper(s)."
            )
        case let .recover(transactionID, approvalToken):
            try await executeRecovery(transactionID: transactionID, approvalToken: approvalToken)
            try RemapInstallOutput.success(
                command: "recover",
                value: ["transactionID": transactionID],
                json: invocation.json,
                human: "Recovered transaction \(transactionID)."
            )
        case let .previewInstall(packageRoot, digest, sourceUID):
            try preview(
                .install,
                packageRoot: packageRoot,
                digest: digest,
                sourceUID: sourceUID,
                json: invocation.json
            )
        case let .previewUpdate(packageRoot, digest, sourceUID):
            try preview(
                .update,
                packageRoot: packageRoot,
                digest: digest,
                sourceUID: sourceUID,
                json: invocation.json
            )
        case let .previewUninstall(generationID):
            let value = try MacOSInstaller.production().previewUninstall(generationID: generationID)
            try outputPreview(value, json: invocation.json)
        case .previewRecoverAll:
            let value = try MacOSInstaller.production().previewRecovery(transactionID: nil)
            try outputRecoveryPreview(value, json: invocation.json)
        case .previewRecoverBootstrapHelpers:
            let value = try MacOSBootstrapHelperRecovery.production().preview()
            try outputBootstrapRecoveryPreview(value, json: invocation.json)
        case let .previewRecover(transactionID):
            let value = try MacOSInstaller.production().previewRecovery(transactionID: transactionID)
            try outputRecoveryPreview(value, json: invocation.json)
        case let .install(packageRoot, digest, sourceUID, approvalToken, transactionID):
            try await mutate(
                .install,
                packageRoot: packageRoot,
                digest: digest,
                sourceUID: sourceUID,
                approvalToken: approvalToken,
                transactionID: transactionID,
                json: invocation.json
            )
        case let .update(packageRoot, digest, sourceUID, approvalToken, transactionID):
            try await mutate(
                .update,
                packageRoot: packageRoot,
                digest: digest,
                sourceUID: sourceUID,
                approvalToken: approvalToken,
                transactionID: transactionID,
                json: invocation.json
            )
        case let .uninstall(generationID, approvalToken, transactionID):
            let identity = transactionID ?? generatedTransactionID(prefix: "uninstall")
            try await executeUninstall(
                transactionID: identity,
                generationID: generationID,
                approvalToken: approvalToken
            )
            try RemapInstallOutput.success(
                command: "uninstall",
                value: ["generationID": generationID, "transactionID": identity],
                json: invocation.json,
                human: "Uninstalled generation \(generationID)."
            )
        }
    }

    private static func preview(
        _ operation: InstallOperation,
        packageRoot: String,
        digest: String,
        sourceUID: UInt32,
        json: Bool
    ) throws {
        let package = try RemapInstallPackage(
            rootPath: packageRoot,
            expectedDigest: digest,
            sourceUID: sourceUID
        )
        let value = try MacOSInstaller.production().preview(
            operation: operation,
            manifest: package.manifest,
            source: package.source
        )
        try outputPreview(value, json: json)
    }

    private static func mutate(
        _ operation: InstallOperation,
        packageRoot: String,
        digest: String,
        sourceUID: UInt32,
        approvalToken: InstallApprovalToken,
        transactionID: String?,
        json: Bool
    ) async throws {
        let package = try RemapInstallPackage(
            rootPath: packageRoot,
            expectedDigest: digest,
            sourceUID: sourceUID
        )
        let installer = try MacOSInstaller.production()
        let preview = try installer.preview(
            operation: operation,
            manifest: package.manifest,
            source: package.source
        )
        try await RemapInstallUserPresence.authorize(
            reviewedToken: approvalToken,
            expectedToken: preview.approvalToken
        )
        let identity = transactionID ?? generatedTransactionID(prefix: operation.rawValue)
        try await installer.installOrUpdate(
            operation: operation,
            transactionID: identity,
            manifest: package.manifest,
            source: package.source,
            approvalToken: approvalToken
        )
        let result = ["generationID": package.manifest.generationID, "transactionID": identity]
        try RemapInstallOutput.success(
            command: operation.rawValue,
            value: result,
            json: json,
            human: "\(operation.rawValue.capitalized) committed generation \(package.manifest.generationID)."
        )
    }

    private static func outputPreview(_ value: MacOSInstallerPreview, json: Bool) throws {
        let summary = "Preview: \(value.operation.rawValue) \(value.generationID); "
            + "\(value.publicationChanges) publication change(s), "
            + "\(value.pendingRecoveryTransactions.count) pending recovery transaction(s)."
        let changes = value.publicationChangeDetails.map { change in
            "  \(change.action.rawValue): /\(change.path.description) "
                + "(\(change.previousGenerationID ?? "none") -> \(change.nextGenerationID ?? "none"))"
        }
        let human = ([summary, "Publication scope:"] + changes).joined(separator: "\n")
        let approval = human + "\nApproval token: \(value.approvalToken)"
        try RemapInstallOutput.success(command: "preview", value: value, json: json, human: approval)
    }

    private static func outputRecoveryPreview(
        _ value: MacOSInstallerRecoveryPreview,
        json: Bool
    ) throws {
        let summary = "Recovery preview: \(value.selectedTransactionIDs.count) selected transaction(s); "
            + "\(value.orphanedStagingTransactionIDs.count) orphan(s); "
            + "\(value.detachedGenerationNames.count) detached generation(s)."
        let human = ([summary, "Effect scope:"] + value.effects.map { "  \($0)" }
            + ["Approval token: \(value.approvalToken)"]).joined(separator: "\n")
        try RemapInstallOutput.success(
            command: "preview-recovery",
            value: value,
            json: json,
            human: human
        )
    }

    private static func outputBootstrapRecoveryPreview(
        _ value: MacOSBootstrapHelperRecoveryPreview,
        json: Bool
    ) throws {
        let candidates = value.candidates.map { candidate in
            let mode = String(candidate.mode, radix: 8)
            let code = candidate.codeValidity == .verified
                ? "verified CDHash \(candidate.cdHash ?? "unavailable")"
                : "invalid code identity"
            return "  \(candidate.activity.rawValue): \(candidate.path.value) "
                + "(\(code), SHA-256 \(candidate.sha256), uid \(candidate.ownerUID), "
                + "gid \(candidate.groupGID), mode \(mode), \(candidate.byteCount) bytes)"
        }
        let stages = value.stagingCandidates.map { candidate in
            let mode = String(candidate.mode, radix: 8)
            let staged = candidate.stagedFile.map {
                "candidate \($0.byteCount) bytes SHA-256 \($0.sha256)"
            } ?? "empty"
            return "  staged: \(candidate.path.value) (mode \(mode), \(staged))"
        }
        let human = ([
            "Bootstrap recovery preview: \(value.candidates.count) direct candidate(s), "
                + "\(value.stagingCandidates.count) staging candidate(s); "
                + "\(value.effects.count) removable orphan(s).",
            "Candidate scope:"
        ] + candidates + stages + ["Approval token: \(value.approvalToken)"]).joined(separator: "\n")
        try RemapInstallOutput.success(
            command: "preview-bootstrap-recovery",
            value: value,
            json: json,
            human: human
        )
    }

    private static func generatedTransactionID(prefix: String) -> String {
        "\(prefix)-\(UUID().uuidString.lowercased())"
    }

    private static func resolverPlan() throws -> MacOSInstallerResolverPlan {
        guard geteuid() == 0 else {
            throw InstallError.notRoot
        }
        let resolver = SystemResolver()
        let plan: DNSPlan = if let active = try resolver.activeRecord() {
            try resolver.reconciliationPlan(record: active)
        } else {
            try resolver.plan()
        }
        return try MacOSInstallerResolverPlan(
            serviceCount: plan.services.count,
            upstreamAddresses: plan.upstreams
        )
    }

    private static func statusSummary(_ value: MacOSInstallerStatus) -> String {
        let loaded = value.services.filter(\.loaded).count
        let recovery = value.transactions.filter(\.recoveryRequired).count
        return "Active generation: \(value.activeGenerationID ?? "none"). "
            + "Installed generations: \(value.generations.count). "
            + "Loaded services: \(loaded)/\(value.services.count). "
            + "DNS active: \(value.dns.active ? "yes" : "no"). "
            + "Pending recovery: \(recovery)."
    }

    private static let help = """
    remap-install: transactional native macOS source installer

    USAGE
      remap-install preview install --package-root PATH --manifest-sha256 SHA256 --source-uid UID [--json]
      remap-install install --package-root PATH --manifest-sha256 SHA256
        --source-uid UID --approval-token SHA256 [--transaction ID] [--json]
      remap-install preview update --package-root PATH --manifest-sha256 SHA256 --source-uid UID [--json]
      remap-install update --package-root PATH --manifest-sha256 SHA256
        --source-uid UID --approval-token SHA256 [--transaction ID] [--json]
      remap-install preview uninstall --generation ID [--json]
      remap-install uninstall --generation ID --approval-token SHA256 [--transaction ID] [--json]
      remap-install preview recover --transaction ID [--json]
      remap-install preview recover --all [--json]
      remap-install status [--json]
      remap-install resolver-plan [--json]
      remap-install recover --transaction ID --approval-token SHA256 [--json]
      remap-install recover --all --approval-token SHA256 [--json]
      remap-install preview recover-bootstrap-helpers [--json]
      remap-install recover-bootstrap-helpers --approval-token SHA256 [--json]

    PACKAGE
      PATH must be an absolute, private directory owned by UID and contain canonical
      manifest.json plus payload. Remap requires the expected manifest digest and
      verifies every byte, owner, mode, link count, ACL, extended attribute, and
      publication before effects. The source authority is strictly read-only.

    SAFETY
      Preview is read-only and returns an approval token bound to its package,
      classified path effects, active generation, services, DNS, and recovery state.
      Every mutation requires that exact token, recomputes its preview, and requires
      macOS device-owner authentication before staging, journaling, or system effects.
      Recover unfinished work, then preview again.
      Bootstrap-helper recovery is separately previewed and approved. Active and
      currently executing helpers are disclosed but never selected for removal.

    AUTOMATION
      Agents and noninteractive tools must request preview --json, independently
      retain its exact approvalToken, then pass it with --approval-token while a local
      user approves the macOS authentication prompt. There is no implicit,
      environment-based, cached-sudo, or unattended approval bypass.

    PRIVACY
      resolver-plan is root-only and read-only. Human output reports counts only.
      Its JSON output includes locally sensitive resolver addresses for exact package assembly.
      The command fails closed above four upstreams, matching remapd's data-plane limit.
    """
}
