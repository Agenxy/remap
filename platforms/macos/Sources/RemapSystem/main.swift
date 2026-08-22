import Darwin
import Foundation
import RemapSystemKit

private struct SuccessEnvelope<Value: Encodable>: Encodable {
    let ok = true
    let command: String
    let data: Value
}

private struct ErrorEnvelope: Encodable {
    let ok = false
    let code: String
    let message: String
    let hint: String
}

@main
enum RemapSystemCommand {
    static func main() async {
        do {
            try await run(arguments: Array(CommandLine.arguments.dropFirst()))
        } catch {
            renderError(error)
            exit(1)
        }
    }

    private static func run(arguments: [String]) async throws {
        let json = arguments.contains("--json")
        let values = arguments.filter { $0 != "--json" }
        guard let command = values.first else {
            renderHelp()
            return
        }
        let resolver = SystemResolver()
        switch command {
        case "plan":
            let plan = try resolver.plan()
            try render(command: command, value: plan, json: json)
        case "status":
            let record = try resolver.activeRecord()
            try render(command: command, value: record, json: json)
        case "activate":
            let ownerUID = try requiredUInt32(values, flag: "--owner-uid")
            let version = try requiredValue(values, flag: "--product-version")
            let socketPath = try requiredValue(values, flag: "--system-socket")
            let record = try await resolver.activate(
                ownerUID: ownerUID,
                productVersion: version,
                systemSocketPath: socketPath
            )
            try render(command: command, value: record, json: json)
        case "deactivate":
            try resolver.deactivate()
            try render(command: command, value: ["active": false], json: json)
        case "help", "--help", "-h":
            renderHelp()
        case "--version", "version":
            print("remap-system \(RemapProduct.version)")
        default:
            throw CommandError("Unknown command '\(command)'.")
        }
    }

    private static func render(
        command: String,
        value: some Encodable,
        json: Bool
    ) throws {
        if json {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
            let data = try encoder.encode(SuccessEnvelope(command: command, data: value))
            guard let text = String(data: data, encoding: .utf8) else {
                throw CommandError("The JSON result could not be encoded as UTF-8.")
            }
            print(text)
            return
        }
        switch command {
        case "plan":
            guard let plan = value as? DNSPlan else {
                throw CommandError("The native plan result has the wrong type.")
            }
            print("Native DNS plan")
            print("  Active services  \(plan.services.count)")
            print("  Upstream servers \(plan.upstreams.joined(separator: ", "))")
        case "status":
            if let record = value as? ActivationRecord {
                print("Native DNS is \(record.payload.phase == .active ? "active" : "recoverable")")
                print("  Services \(record.payload.services.count)")
                print("  Version  \(record.payload.productVersion)")
            } else {
                print("Native DNS is inactive")
            }
        case "activate":
            print("Native DNS activated. Unmapped names still use the captured upstream resolvers.")
        case "deactivate":
            print("Native DNS deactivated and the prior configuration was restored.")
        default:
            throw CommandError("The command has no human renderer.")
        }
    }

    private static func renderError(_ error: Error) {
        let message = String(describing: error)
        let envelope = ErrorEnvelope(
            code: errorCode(error),
            message: message,
            hint: "Run 'remap-system help' for recovery and supported operations."
        )
        if CommandLine.arguments.contains("--json") {
            let encoded = try? JSONEncoder().encode(envelope)
            if let encoded, let text = String(data: encoded, encoding: .utf8) {
                FileHandle.standardError.write(Data((text + "\n").utf8))
                return
            }
        }
        FileHandle.standardError.write(Data("error[\(envelope.code)]: \(message)\n".utf8))
        FileHandle.standardError.write(Data("hint: \(envelope.hint)\n".utf8))
    }

    private static func renderHelp() {
        print(
            """
            remap-system: native macOS resolver lifecycle

            Usage:
              remap-system plan [--json]
              remap-system status [--json]
              remap-system activate --owner-uid UID --product-version VERSION \
                --system-socket ABSOLUTE_PATH [--json]
              remap-system deactivate [--json]

            plan is read-only. activate and deactivate are invoked by Remap's native
            privileged installer and restore DNS transactionally on failure.
            """
        )
    }

    private static func requiredValue(_ arguments: [String], flag: String) throws -> String {
        guard let index = arguments.firstIndex(of: flag), arguments.indices.contains(index + 1) else {
            throw CommandError("Missing required option \(flag).")
        }
        return arguments[index + 1]
    }

    private static func requiredUInt32(_ arguments: [String], flag: String) throws -> UInt32 {
        let value = try requiredValue(arguments, flag: flag)
        guard let parsed = UInt32(value), parsed != 0 else {
            throw CommandError("\(flag) must be a non-root numeric user ID.")
        }
        return parsed
    }

    private static func errorCode(_ error: Error) -> String {
        switch error {
        case is ResolverError:
            "E_SYSTEM_RESOLVER"
        case is CommandError:
            "E_USAGE"
        default:
            "E_SYSTEM_INTERNAL"
        }
    }
}

private struct CommandError: Error, CustomStringConvertible {
    let description: String

    init(_ description: String) {
        self.description = description
    }
}
