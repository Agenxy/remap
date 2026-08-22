import Foundation
import RemapLifecycleKit

@main
enum RemapInstallerServiceMain {
    static func main() throws {
        guard geteuid() == 0 else {
            throw RemapInstallerServiceFailure.rootAuthorityRequired
        }
        let isCleanupFinisher = CommandLine.arguments.count == 3
            && CommandLine.arguments[1] == RemapPortableCleanupFinisher.argument
        if isCleanupFinisher {
            try RemapPortableCleanupFinisher.finish(
                approvalTokenString: CommandLine.arguments[2]
            )
            return
        }
        guard CommandLine.arguments.count == 1 else {
            throw RemapInstallerServiceFailure.unsupportedArguments
        }
        let delegate = try RemapInstallerServiceDelegate.production()
        let listener = NSXPCListener(
            machServiceName: RemapLifecycleXPC.machServiceName
        )
        listener.delegate = delegate
        listener.resume()
        withExtendedLifetime((delegate, listener)) {
            RunLoop.current.run()
        }
    }
}

private enum RemapInstallerServiceFailure: Error {
    case rootAuthorityRequired
    case unsupportedArguments
}

private final class RemapInstallerServiceDelegate: NSObject, NSXPCListenerDelegate {
    private let authenticator: RemapLifecycleCallerAuthenticator
    private let executor: RemapLifecycleExecutor
    private let cleanupScheduler: RemapPortableAuthorityCleanupScheduler

    static func production() throws -> RemapInstallerServiceDelegate {
        let configuration = try RemapLifecycleServiceConfiguration.production()
        let authenticator = RemapLifecycleCallerAuthenticator(
            configuration: configuration
        )
        try authenticator.authorizeService()
        return try RemapInstallerServiceDelegate(
            authenticator: authenticator,
            executor: RemapLifecycleExecutor.production(configuration: configuration),
            cleanupScheduler: RemapPortableAuthorityCleanupScheduler()
        )
    }

    private init(
        authenticator: RemapLifecycleCallerAuthenticator,
        executor: RemapLifecycleExecutor,
        cleanupScheduler: RemapPortableAuthorityCleanupScheduler
    ) {
        self.authenticator = authenticator
        self.executor = executor
        self.cleanupScheduler = cleanupScheduler
        super.init()
    }

    func listener(
        _: NSXPCListener,
        shouldAcceptNewConnection connection: NSXPCConnection
    ) -> Bool {
        let sourceUID = UInt32(connection.effectiveUserIdentifier)
        do {
            try authenticator.authorizeCaller(
                effectiveUID: sourceUID,
                processID: connection.processIdentifier
            )
        } catch {
            return false
        }
        connection.exportedInterface = NSXPCInterface(
            with: RemapLifecycleXPCServiceProtocol.self
        )
        connection.exportedObject = RemapInstallerServiceSession(
            authenticator: authenticator,
            connection: connection,
            executor: executor,
            sourceUID: sourceUID,
            cleanupScheduler: cleanupScheduler
        )
        connection.resume()
        return true
    }
}

private final class RemapInstallerServiceSession: NSObject, RemapLifecycleXPCServiceProtocol {
    private let authenticator: RemapLifecycleCallerAuthenticator
    private weak var connection: NSXPCConnection?
    private let executor: RemapLifecycleExecutor
    private let sourceUID: UInt32
    private let cleanupScheduler: RemapPortableAuthorityCleanupScheduler

    init(
        authenticator: RemapLifecycleCallerAuthenticator,
        connection: NSXPCConnection,
        executor: RemapLifecycleExecutor,
        sourceUID: UInt32,
        cleanupScheduler: RemapPortableAuthorityCleanupScheduler
    ) {
        self.authenticator = authenticator
        self.connection = connection
        self.executor = executor
        self.sourceUID = sourceUID
        self.cleanupScheduler = cleanupScheduler
    }

    func perform(
        _ requestData: Data,
        withReply reply: @escaping (Data) -> Void
    ) {
        guard let connection else {
            reply(authorityFailure())
            return
        }
        let connectionBox = RemapInstallerConnection(connection)
        let effectiveUID = UInt32(connectionBox.value.effectiveUserIdentifier)
        let processID = connectionBox.value.processIdentifier
        let authenticator = authenticator
        let executor = executor
        let sourceUID = sourceUID
        let cleanupScheduler = cleanupScheduler
        let reply = RemapInstallerReply(reply)
        Task {
            let response: RemapLifecycleResponse
            do {
                try authenticator.authorizeCaller(
                    effectiveUID: effectiveUID,
                    processID: processID
                )
                let request = try RemapLifecycleCoding.decodeRequest(requestData)
                response = await executor.execute(request, sourceUID: sourceUID)
                let cleanupPending = response.mutation?.authorityCleanupPending == true
                if cleanupPending, let approvalToken = request.approvalToken {
                    connectionBox.value.invalidationHandler = {
                        cleanupScheduler.schedule(approvalToken: approvalToken)
                    }
                }
            } catch {
                let diagnostic = RemapLifecycleDiagnostic(
                    category: .integrity,
                    message: "The lifecycle request is malformed.",
                    hint: "Update or repair the Remap application before retrying.",
                    retryable: false
                )
                response = .failure(action: .status, diagnostic: diagnostic)
            }
            reply.send(Self.encoded(response))
        }
    }

    private func authorityFailure() -> Data {
        let diagnostic = RemapLifecycleDiagnostic(
            category: .authority,
            message: "The lifecycle caller connection is no longer authoritative.",
            hint: "Reopen Remap before retrying.",
            retryable: true
        )
        let response = RemapLifecycleResponse.failure(
            action: .status,
            diagnostic: diagnostic
        )
        return Self.encoded(response)
    }

    private static func encoded(_ response: RemapLifecycleResponse) -> Data {
        do {
            return try RemapLifecycleCoding.encodeResponse(response)
        } catch {
            return fallbackFailure
        }
    }

    private static let fallbackFailure = Data(
        #"""
        {
          "action": "status",
          "diagnostic": {
            "category": "internal",
            "hint": "Repair Remap before retrying.",
            "message": "The lifecycle service could not encode its reply.",
            "retryable": false
          },
          "outcome": "failure",
          "schemaVersion": 1
        }
        """#.utf8
    )
}

private final class RemapInstallerConnection: @unchecked Sendable {
    let value: NSXPCConnection

    init(_ value: NSXPCConnection) {
        self.value = value
    }
}

private final class RemapInstallerReply: @unchecked Sendable {
    private let reply: (Data) -> Void

    init(_ reply: @escaping (Data) -> Void) {
        self.reply = reply
    }

    func send(_ data: Data) {
        reply(data)
    }
}
