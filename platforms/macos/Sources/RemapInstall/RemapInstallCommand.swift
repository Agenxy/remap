import Foundation
import RemapInstallKit

enum RemapInstallCommand: Equatable {
    case help
    case install(
        packageRoot: String,
        digest: String,
        sourceUID: UInt32,
        approvalToken: InstallApprovalToken,
        transactionID: String?
    )
    case previewInstall(packageRoot: String, digest: String, sourceUID: UInt32)
    case previewRecoverBootstrapHelpers
    case previewRecoverAll
    case previewRecover(transactionID: String)
    case previewUninstall(generationID: String)
    case previewUpdate(packageRoot: String, digest: String, sourceUID: UInt32)
    case recoverAll(approvalToken: InstallApprovalToken)
    case recoverBootstrapHelpers(approvalToken: InstallApprovalToken)
    case recover(transactionID: String, approvalToken: InstallApprovalToken)
    case resolverPlan
    case status
    case uninstall(
        generationID: String,
        approvalToken: InstallApprovalToken,
        transactionID: String?
    )
    case update(
        packageRoot: String,
        digest: String,
        sourceUID: UInt32,
        approvalToken: InstallApprovalToken,
        transactionID: String?
    )
    case version
}

struct RemapInstallInvocation: Equatable {
    let command: RemapInstallCommand
    let json: Bool
}

enum RemapInstallArguments {
    static func parse(_ arguments: [String]) throws -> RemapInstallInvocation {
        let json = arguments.contains("--json")
        let values = arguments.filter { $0 != "--json" }
        guard let command = values.first else {
            return RemapInstallInvocation(command: .help, json: json)
        }
        let tail = Array(values.dropFirst())
        switch command {
        case "help", "--help", "-h":
            guard tail.isEmpty else { throw usage("help accepts no arguments") }
            return RemapInstallInvocation(command: .help, json: json)
        case "--version", "version":
            guard tail.isEmpty else { throw usage("version accepts no arguments") }
            return RemapInstallInvocation(command: .version, json: json)
        case "status":
            guard tail.isEmpty else { throw usage("status accepts only --json") }
            return RemapInstallInvocation(command: .status, json: json)
        case "resolver-plan":
            guard tail.isEmpty else { throw usage("resolver-plan accepts only --json") }
            return RemapInstallInvocation(command: .resolverPlan, json: json)
        case "recover":
            return try parseRecover(tail, json: json)
        case "recover-bootstrap-helpers":
            let options = try options(tail, allowed: ["--approval-token"])
            return try RemapInstallInvocation(
                command: .recoverBootstrapHelpers(
                    approvalToken: approvalToken(options, command: "recover-bootstrap-helpers")
                ),
                json: json
            )
        case "preview":
            return try parsePreview(tail, json: json)
        case "install", "update":
            return try parseMutation(command, arguments: tail, json: json)
        case "uninstall":
            return try parseUninstall(tail, json: json)
        default:
            throw usage("unknown command \(command)")
        }
    }

    private static func parseMutation(
        _ command: String,
        arguments: [String],
        json: Bool
    ) throws -> RemapInstallInvocation {
        let options = try options(
            arguments,
            allowed: [
                "--approval-token",
                "--manifest-sha256",
                "--package-root",
                "--source-uid",
                "--transaction"
            ]
        )
        guard let root = options["--package-root"] else {
            throw usage("\(command) requires --package-root")
        }
        guard let digest = options["--manifest-sha256"] else {
            throw usage("\(command) requires --manifest-sha256")
        }
        let sourceUID = try sourceUID(options, command: command)
        let approvalToken = try approvalToken(options, command: command)
        let transactionID = options["--transaction"]
        let parsed: RemapInstallCommand = command == "install"
            ? .install(
                packageRoot: root,
                digest: digest,
                sourceUID: sourceUID,
                approvalToken: approvalToken,
                transactionID: transactionID
            )
            : .update(
                packageRoot: root,
                digest: digest,
                sourceUID: sourceUID,
                approvalToken: approvalToken,
                transactionID: transactionID
            )
        return RemapInstallInvocation(command: parsed, json: json)
    }

    private static func parseUninstall(
        _ arguments: [String],
        json: Bool
    ) throws -> RemapInstallInvocation {
        let options = try options(
            arguments,
            allowed: ["--approval-token", "--generation", "--transaction"]
        )
        guard let generationID = options["--generation"] else {
            throw usage("uninstall requires --generation")
        }
        return try RemapInstallInvocation(
            command: .uninstall(
                generationID: generationID,
                approvalToken: approvalToken(options, command: "uninstall"),
                transactionID: options["--transaction"]
            ),
            json: json
        )
    }

    private static func parsePreview(
        _ arguments: [String],
        json: Bool
    ) throws -> RemapInstallInvocation {
        guard let operation = arguments.first else {
            throw usage("preview requires install, update, uninstall, or recover")
        }
        let tail = Array(arguments.dropFirst())
        if operation == "recover-bootstrap-helpers" {
            guard tail.isEmpty else {
                throw usage("preview recover-bootstrap-helpers accepts only --json")
            }
            return RemapInstallInvocation(command: .previewRecoverBootstrapHelpers, json: json)
        }
        if operation == "recover" {
            if tail == ["--all"] {
                return RemapInstallInvocation(command: .previewRecoverAll, json: json)
            }
            let options = try options(tail, allowed: ["--transaction"])
            guard let transactionID = options["--transaction"] else {
                throw usage("preview recover requires --all or --transaction")
            }
            return RemapInstallInvocation(
                command: .previewRecover(transactionID: transactionID),
                json: json
            )
        }
        if operation == "uninstall" {
            let options = try options(tail, allowed: ["--generation"])
            guard let generationID = options["--generation"] else {
                throw usage("preview uninstall requires --generation")
            }
            return RemapInstallInvocation(command: .previewUninstall(generationID: generationID), json: json)
        }
        guard operation == "install" || operation == "update" else {
            throw usage("preview requires install, update, uninstall, recover, or recover-bootstrap-helpers")
        }
        let options = try options(tail, allowed: ["--manifest-sha256", "--package-root", "--source-uid"])
        guard let root = options["--package-root"] else {
            throw usage("preview \(operation) requires --package-root")
        }
        guard let digest = options["--manifest-sha256"] else {
            throw usage("preview \(operation) requires --manifest-sha256")
        }
        let sourceUID = try sourceUID(options, command: "preview \(operation)")
        let command: RemapInstallCommand = operation == "install"
            ? .previewInstall(packageRoot: root, digest: digest, sourceUID: sourceUID)
            : .previewUpdate(packageRoot: root, digest: digest, sourceUID: sourceUID)
        return RemapInstallInvocation(command: command, json: json)
    }

    private static func parseRecover(
        _ arguments: [String],
        json: Bool
    ) throws -> RemapInstallInvocation {
        let options = try options(
            arguments,
            allowed: ["--all", "--approval-token", "--transaction"],
            valueless: ["--all"]
        )
        let approvalToken = try approvalToken(options, command: "recover")
        if options["--all"] != nil {
            guard options["--transaction"] == nil else {
                throw usage("recover accepts either --all or --transaction")
            }
            return RemapInstallInvocation(command: .recoverAll(approvalToken: approvalToken), json: json)
        }
        guard let transactionID = options["--transaction"] else {
            throw usage("recover requires --all or --transaction")
        }
        return RemapInstallInvocation(
            command: .recover(transactionID: transactionID, approvalToken: approvalToken),
            json: json
        )
    }

    private static func options(
        _ arguments: [String],
        allowed: Set<String>,
        valueless: Set<String> = []
    ) throws -> [String: String] {
        var parsed: [String: String] = [:]
        var index = 0
        while index < arguments.count {
            let name = arguments[index]
            guard allowed.contains(name), parsed[name] == nil else {
                throw usage("unsupported, repeated, or missing option \(name)")
            }
            if valueless.contains(name) {
                parsed[name] = "true"
                index += 1
                continue
            }
            guard index + 1 < arguments.count else {
                throw usage("every option requires exactly one value")
            }
            let value = arguments[index + 1]
            guard !value.hasPrefix("--") else {
                throw usage("unsupported, repeated, or missing option \(name)")
            }
            parsed[name] = value
            index += 2
        }
        return parsed
    }

    private static func sourceUID(_ options: [String: String], command: String) throws -> UInt32 {
        guard let value = options["--source-uid"],
              let sourceUID = UInt32(value),
              String(sourceUID) == value
        else {
            throw usage("\(command) requires a canonical decimal --source-uid")
        }
        return sourceUID
    }

    private static func approvalToken(
        _ options: [String: String],
        command: String
    ) throws -> InstallApprovalToken {
        guard let value = options["--approval-token"] else {
            throw usage("\(command) requires --approval-token from its exact preview")
        }
        do {
            return try InstallApprovalToken(value)
        } catch {
            throw usage("\(command) requires a canonical lowercase SHA-256 --approval-token")
        }
    }

    private static func usage(_ message: String) -> InstallError {
        .unsupported(message)
    }
}
