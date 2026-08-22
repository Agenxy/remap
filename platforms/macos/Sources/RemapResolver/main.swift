import Darwin
import Foundation
import OSLog
import RemapSystemKit

@main
enum RemapResolverCommand {
    private static let logger = Logger(
        subsystem: "org.agenxy.Remap",
        category: "resolver-supervisor"
    )

    static func main() async {
        do {
            guard geteuid() == 0 else { throw SupervisorCommandError.notRoot }
            let invocation = try parse(Array(CommandLine.arguments.dropFirst()))
            switch invocation {
            case .help:
                print(help)
            case .version:
                print("remap-resolver \(RemapProduct.version)")
            case let .run(ownerUID, socketPath):
                let channel = ResolverSystemChannel(
                    socketPath: socketPath,
                    expectedPeerUID: ownerUID
                )
                let supervisor = ResolverSupervisor(
                    reconciler: ResolverReconciler(
                        channel: channel,
                        reactivatePreparedDNS: true
                    ),
                    monitor: ResolverChangeMonitor(watchedSocketPath: socketPath),
                    observe: logState
                )
                await supervisor.run()
            }
        } catch {
            logger.error("resolver supervisor stopped: \(errorCode(error), privacy: .public)")
            exit(EXIT_FAILURE)
        }
    }

    private static func parse(_ arguments: [String]) throws -> SupervisorInvocation {
        if arguments.isEmpty || arguments == ["help"] || arguments == ["--help"] {
            return .help
        }
        if arguments == ["--version"] || arguments == ["version"] {
            return .version
        }
        guard arguments.count == 5,
              arguments[0] == "run",
              arguments[1] == "--owner-uid",
              let ownerUID = uid_t(arguments[2]),
              ownerUID != 0,
              arguments[3] == "--system-socket",
              arguments[4].hasPrefix("/")
        else {
            throw SupervisorCommandError.usage
        }
        return .run(ownerUID: ownerUID, socketPath: arguments[4])
    }

    private static func logState(_ state: ResolverSupervisorState) {
        switch state {
        case let .bypassed(code):
            logger.fault("resolver supervisor restored ordinary DNS: \(code, privacy: .public)")
        case .ready:
            logger.notice("resolver supervisor ready")
        case let .degraded(code):
            logger.error("resolver supervisor degraded: \(code, privacy: .public)")
        }
    }

    private static func errorCode(_ error: Error) -> String {
        switch error {
        case SupervisorCommandError.notRoot:
            "E_RESOLVER_NOT_ROOT"
        case is SupervisorCommandError:
            "E_RESOLVER_USAGE"
        default:
            "E_RESOLVER_RUNTIME"
        }
    }

    private static let help = """
    remap-resolver: native resolver reconciliation service

    USAGE
      remap-resolver run --owner-uid UID --system-socket ABSOLUTE_PATH

    This root service observes native network changes and publishes only bounded
    resolver generations to the selected user's non-root Remap authority.
    """
}

private enum SupervisorInvocation {
    case help
    case run(ownerUID: uid_t, socketPath: String)
    case version
}

private enum SupervisorCommandError: Error {
    case notRoot
    case usage
}
