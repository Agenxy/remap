import Foundation
import RemapInstallKit
import RemapSystemKit

struct RemapInstallSuccess<Value: Encodable>: Encodable {
    let schemaVersion = 1
    let ok = true
    let command: String
    let data: Value
}

struct RemapInstallFailure: Encodable {
    let schemaVersion = 1
    let ok = false
    let error: RemapInstallFailureDetail
}

struct RemapInstallFailureDetail: Encodable {
    let category: String
    let message: String
    let hint: String?
}

enum RemapInstallOutput {
    static func success(
        command: String,
        value: some Encodable,
        json: Bool,
        human: String
    ) throws {
        if json {
            try writeJSON(RemapInstallSuccess(command: command, data: value), to: .standardOutput)
        } else {
            write(human + "\n", to: .standardOutput)
        }
    }

    static func failure(_ error: Error, json: Bool) {
        let detail = failureDetail(error)
        if json {
            try? writeJSON(RemapInstallFailure(error: detail), to: .standardError)
        } else {
            var message = "remap-install: \(detail.message)"
            if let hint = detail.hint {
                message += "\nNext: \(hint)"
            }
            write(message + "\n", to: .standardError)
        }
    }

    static func exitStatus(for error: Error) -> Int32 {
        if let resolverError = error as? ResolverError {
            return resolverExitStatus(resolverError)
        }
        guard let installError = error as? InstallError else {
            return 1
        }
        switch installError {
        case .notRoot:
            return 77
        case .collision, .alreadyLocked:
            return 73
        case .approval, .invalidManifest, .invalidPath, .integrity, .journal, .metadata:
            return 65
        case .unsupported:
            return 64
        default:
            return 1
        }
    }

    private static func failureDetail(_ error: Error) -> RemapInstallFailureDetail {
        if let resolverError = error as? ResolverError {
            return RemapInstallFailureDetail(
                category: "resolver",
                message: resolverError.description,
                hint: "Inspect the active network service and Remap's root-owned DNS activation record."
            )
        }
        guard let installError = error as? InstallError else {
            return RemapInstallFailureDetail(
                category: "internal",
                message: "The native installer failed without a stable diagnostic.",
                hint: "Run remap-install status --json and preserve the local output for inspection."
            )
        }
        let policy = failurePolicy(installError)
        return RemapInstallFailureDetail(
            category: policy.category,
            message: installError.description,
            hint: policy.hint
        )
    }

    private static func resolverExitStatus(_ error: ResolverError) -> Int32 {
        switch error {
        case .notRoot:
            77
        case .configurationConflict:
            73
        case .noEnabledDNSService, .noUsableUpstream, .unsupportedResolverScope:
            69
        case .activationRecordIntegrity, .invalidActivationRecord, .secureStorage:
            65
        default:
            1
        }
    }

    private static func failurePolicy(_ error: InstallError) -> (category: String, hint: String?) {
        switch error {
        case .notRoot:
            ("authority", "Run the reviewed source installer through its administrator authorization step.")
        case .alreadyLocked:
            ("busy", "Wait for the active transaction, then run remap-install recover --all.")
        case .approval:
            ("approval", "Request a fresh exact preview, approve it, and pass its approval token unchanged.")
        case .collision:
            ("collision", "Inspect the named path. Remap will not overwrite or remove an unmanaged object.")
        case .unsupported:
            ("usage", "Run remap-install help for the exact command shape.")
        case .invalidManifest, .invalidPath, .integrity, .journal, .metadata:
            ("integrity", "Stop and inspect the package, installed generation, and transaction journal.")
        default:
            ("system", "Run remap-install status --json, correct the reported system condition, then recover.")
        }
    }

    private static func writeJSON(_ value: some Encodable, to handle: FileHandle) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        var data = try encoder.encode(value)
        data.append(0x0A)
        handle.write(data)
    }

    private static func write(_ value: String, to handle: FileHandle) {
        handle.write(Data(value.utf8))
    }
}
