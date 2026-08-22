@preconcurrency import Foundation
import RemapInstallKit
import Synchronization

public struct RemapLifecycleRemoteError: Error, Equatable, Sendable {
    public let diagnostic: RemapLifecycleDiagnostic

    public init(diagnostic: RemapLifecycleDiagnostic) {
        self.diagnostic = diagnostic
    }
}

public struct RemapLifecycleClient: Sendable {
    typealias Exchange = @Sendable (Data) async throws -> Data

    private let exchange: Exchange

    public init() {
        exchange = { data in
            try await RemapLifecycleXPCExchange().perform(request: data)
        }
    }

    init(exchange: @escaping Exchange) {
        self.exchange = exchange
    }

    public func execute(
        _ request: RemapLifecycleRequest
    ) async throws -> RemapLifecycleResponse {
        let data = try RemapLifecycleCoding.encodeRequest(request)
        let responseData = try await withThrowingTaskGroup(of: Data.self) { group in
            group.addTask { try await exchange(data) }
            group.addTask {
                try await Task.sleep(for: deadline(for: request.action))
                throw InstallError.integrity(
                    "the lifecycle service exceeded its bounded response time"
                )
            }
            guard let result = try await group.next() else {
                throw InstallError.integrity(
                    "the lifecycle service returned no response"
                )
            }
            group.cancelAll()
            return result
        }
        let response = try RemapLifecycleCoding.decodeResponse(responseData)
        guard response.action == request.action else {
            throw InstallError.integrity(
                "the lifecycle response does not match its request"
            )
        }
        if let diagnostic = response.diagnostic {
            throw RemapLifecycleRemoteError(diagnostic: diagnostic)
        }
        return response
    }

    private func deadline(for action: RemapLifecycleAction) -> Duration {
        switch action {
        case .status,
             .previewInstall,
             .previewRecover,
             .previewRecoverBootstrapHelpers,
             .previewUninstall,
             .previewUpdate:
            .seconds(5)
        case .install,
             .recover,
             .recoverBootstrapHelpers,
             .uninstall,
             .update:
            .seconds(120)
        }
    }
}

private final class RemapLifecycleXPCExchange: @unchecked Sendable {
    private let state = Mutex(RemapLifecycleXPCExchangeState.idle)

    func perform(request: Data) async throws -> Data {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let connection = NSXPCConnection(
                    machServiceName: RemapLifecycleXPC.machServiceName,
                    options: .privileged
                )
                connection.remoteObjectInterface = NSXPCInterface(
                    with: RemapLifecycleXPCServiceProtocol.self
                )
                connection.interruptionHandler = {
                    self.complete(
                        .failure(InstallError.integrity(
                            "the lifecycle service connection was interrupted"
                        ))
                    )
                }
                connection.invalidationHandler = {
                    self.complete(
                        .failure(InstallError.integrity(
                            "the lifecycle service connection was invalidated"
                        ))
                    )
                }
                guard register(continuation, connection: connection) else {
                    connection.invalidate()
                    continuation.resume(throwing: CancellationError())
                    return
                }
                connection.resume()
                let proxy = connection.remoteObjectProxyWithErrorHandler { _ in
                    self.complete(
                        .failure(InstallError.integrity(
                            "the lifecycle service rejected the authenticated request"
                        ))
                    )
                }
                guard let service = proxy as? any RemapLifecycleXPCServiceProtocol else {
                    complete(
                        .failure(InstallError.integrity(
                            "the lifecycle service exported the wrong protocol"
                        ))
                    )
                    return
                }
                service.perform(request) { response in
                    self.complete(.success(response))
                }
            }
        } onCancel: {
            self.complete(.failure(CancellationError()))
        }
    }

    private func register(
        _ continuation: CheckedContinuation<Data, any Error>,
        connection: NSXPCConnection
    ) -> Bool {
        let connection = RemapLifecycleXPCConnection(connection)
        return state.withLock { value in
            guard case .idle = value else { return false }
            value = .waiting(continuation, connection)
            return true
        }
    }

    private func complete(_ result: Result<Data, any Error>) {
        let values = state.withLock { value -> (
            CheckedContinuation<Data, any Error>,
            RemapLifecycleXPCConnection
        )? in
            switch value {
            case .idle:
                value = .finished
                return nil
            case let .waiting(continuation, connection):
                value = .finished
                return (continuation, connection)
            case .finished:
                return nil
            }
        }
        guard let (continuation, connectionBox) = values else { return }
        let connection = connectionBox.value
        connection.interruptionHandler = nil
        connection.invalidationHandler = nil
        connection.invalidate()
        continuation.resume(with: result)
    }
}

private enum RemapLifecycleXPCExchangeState {
    case finished
    case idle
    case waiting(
        CheckedContinuation<Data, any Error>,
        RemapLifecycleXPCConnection
    )
}

private final class RemapLifecycleXPCConnection: @unchecked Sendable {
    let value: NSXPCConnection

    init(_ value: NSXPCConnection) {
        self.value = value
    }
}
