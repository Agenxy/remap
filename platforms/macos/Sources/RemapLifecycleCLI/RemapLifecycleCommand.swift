import Darwin
import Foundation
import RemapInstallKit
import RemapLifecycleKit

enum RemapLifecycleCLICommand: Equatable {
    case help
    case recover(json: Bool)
    case status(json: Bool)
    case uninstall(json: Bool)

    static func parse(_ arguments: [String]) throws -> Self {
        guard arguments.count <= 3,
              arguments.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 128 && !$0.contains("\0") })
        else {
            throw RemapLifecycleCLIError.usage("too many or invalid arguments")
        }
        let values = Array(arguments.dropFirst())
        let json = values.contains("--json")
        guard values.count(where: { $0 == "--json" }) <= 1 else {
            throw RemapLifecycleCLIError.usage("--json may be used only once")
        }
        let commands = values.filter { $0 != "--json" }
        guard commands.count == 1 else {
            throw RemapLifecycleCLIError.usage("choose status, recover, or uninstall")
        }
        switch commands[0] {
        case "help", "--help", "-h":
            guard !json else {
                throw RemapLifecycleCLIError.usage("help does not use --json")
            }
            return .help
        case "recover": return .recover(json: json)
        case "status": return .status(json: json)
        case "uninstall": return .uninstall(json: json)
        default:
            throw RemapLifecycleCLIError.usage("unknown command: \(plain(commands[0]))")
        }
    }
}

enum RemapLifecycleCLIError: Error, Equatable {
    case approval(String)
    case integrity(String)
    case usage(String)
}

enum RemapLifecycleCLIApproval {
    static func prompt(for token: InstallApprovalToken, interactive: Bool) -> String {
        if interactive {
            return "Type approve \(token.description.prefix(12)) to continue: "
        }
        return "Send the complete approval token on standard input to continue.\n"
    }

    static func validate(
        _ input: String?,
        token: InstallApprovalToken,
        interactive: Bool
    ) throws {
        let expected = interactive
            ? "approve \(token.description.prefix(12))"
            : token.description
        guard input == expected else {
            throw RemapLifecycleCLIError.approval("approval did not match the reviewed changes")
        }
    }
}

enum RemapLifecycleCLIOutput {
    static let help = """
    Manage the installed Remap service.

    Usage:
      remap system status [--json]
      remap system recover [--json]
      remap system uninstall [--json]

    Commands:
      status      Show the installed generation, services, and DNS state.
      recover     Review and repair an interrupted Remap lifecycle operation.
      uninstall   Review and remove the installed Remap product.

    Mutating commands show every planned change and require an exact approval.
    Piped use requires the complete approval token on standard input.
    """

    static func status(_ status: MacOSInstallerStatus) -> String {
        let installation = status.activeGenerationID.map { "installed (\($0))" } ?? "not installed"
        let loaded = status.services.count(where: \ .loaded)
        let recovery = status.transactions.count(where: \ .recoveryRequired)
        return """
        Remap is \(installation).
        Generations: \(status.generations.count)
        Services: \(loaded) of \(status.services.count) loaded
        DNS: \(status.dns.active ? "active" : "inactive") (\(status.dns
            .effectiveRemapServiceCount) effective service(s))
        Recovery needed: \(recovery == 0 ? "no" : "yes (\(recovery))")
        """
    }

    static func preview(title: String, effects: [String]) -> String {
        let lines = effects.map { "  - \(plain($0))" }.joined(separator: "\n")
        return effects.isEmpty ? "\(title): no changes are needed." : "\(title):\n\(lines)"
    }
}

struct RemapLifecycleCLIErrorDocument: Encodable {
    let schemaVersion: UInt32 = 1
    let ok = false
    let error: RemapLifecycleDiagnostic

    static func data(for value: any Error) throws -> Data {
        let diagnostic: RemapLifecycleDiagnostic
        if let remote = value as? RemapLifecycleRemoteError {
            diagnostic = remote.diagnostic
        } else if let local = value as? RemapLifecycleCLIError {
            let category: RemapLifecycleDiagnosticCategory
            let message: String
            let hint: String
            switch local {
            case let .approval(detail):
                category = .approval
                message = detail
                hint = "Request a fresh preview and approve the exact token."
            case let .integrity(detail):
                category = .integrity
                message = detail
                hint = "Run remap system status, then retry or recover."
            case let .usage(detail):
                category = .unsupported
                message = detail
                hint = "Run remap system --help."
            }
            diagnostic = RemapLifecycleDiagnostic(
                category: category,
                message: message,
                hint: hint,
                retryable: false
            )
        } else {
            diagnostic = RemapLifecycleDiagnostic(
                category: .internalFailure,
                message: String(describing: value),
                hint: "Run remap system status, then retry or recover.",
                retryable: false
            )
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        var data = try encoder.encode(Self(error: diagnostic))
        data.append(0x0A)
        return data
    }
}

func plain(_ value: String) -> String {
    String(value.unicodeScalars.map { scalar in
        if CharacterSet.controlCharacters.contains(scalar) {
            return "?"
        }
        return Character(scalar)
    })
}
