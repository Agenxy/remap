import Foundation
import Observation
import RemapControlKit
import RemapSystemKit

@MainActor
@Observable
final class RemapStore {
    typealias CommandExecutor = @Sendable (RemapControlCommand) async throws -> RemapCommandResult

    enum AuthorityState: Equatable {
        case connecting
        case ready
        case unavailable
    }

    enum ResolverState: Equatable {
        case checking
        case active(ResolverObservation)
        case inactive(ResolverObservation)
        case unavailable
    }

    enum ListenerState: Equatable {
        case checking
        case authenticated
        case unavailable
    }

    private static let pageSize: UInt16 = 128
    private static let maximumSnapshotAttempts = 3

    var authorityState = AuthorityState.connecting
    var status: RemapRegistryStatus?
    var mappings: [RemapMapping] = []
    var resolverState = ResolverState.checking
    var dnsState = ListenerState.checking
    var gatewayState = ListenerState.checking
    var runtimeHealth: RemapRuntimeHealth?
    var diagnostic: RemapDiagnostic?
    var isRefreshing = false
    var selectedPattern: String?

    private let executeCommand: CommandExecutor?
    private let observeNativeResolver: @Sendable () throws -> ResolverObservation
    private let verifyRuntime: @Sendable () async -> RemapRuntimeHealth

    init() {
        let client = try? RemapControlClient.discovered(clientVersion: AppIdentity.version)
        if let client {
            executeCommand = { command in try await client.execute(command) }
        } else {
            executeCommand = nil
        }
        observeNativeResolver = { try SystemResolver().observe() }
        verifyRuntime = {
            guard let client else { return .unavailable }
            return await RemapRuntimeProbe.verify(client: client)
        }
    }

    init(
        executeCommand: CommandExecutor?,
        observeResolver: @escaping @Sendable () throws -> ResolverObservation,
        verifyRuntime: @escaping @Sendable () async -> RemapRuntimeHealth
    ) {
        self.executeCommand = executeCommand
        observeNativeResolver = observeResolver
        self.verifyRuntime = verifyRuntime
    }

    var selectedMapping: RemapMapping? {
        mappings.first { $0.pattern == selectedPattern }
    }

    var canMutateMappings: Bool {
        authorityState == .ready && status?.maintenance == nil
    }

    var isSystemReady: Bool {
        guard authorityState == .ready,
              runtimeHealth?.ready == true,
              status?.maintenance == nil,
              case .active = resolverState
        else {
            return false
        }
        return true
    }

    func observeUntilCancelled() async {
        while !Task.isCancelled {
            await refresh()
            let revision = status?.revision
            guard let executeCommand, let revision else {
                try? await Task.sleep(for: .seconds(2))
                continue
            }
            do {
                let result = try await executeCommand(
                    .waitForRevision(after: revision, timeoutMilliseconds: 5000)
                )
                guard case let .revision(notice) = result else {
                    throw protocolDiagnostic("the Remap service returned the wrong revision result")
                }
                if !notice.changed {
                    continue
                }
            } catch is CancellationError {
                return
            } catch {
                set(error)
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }

    func refresh() async {
        guard !isRefreshing else { return }
        isRefreshing = true
        defer { isRefreshing = false }
        resolverState = observeResolver()
        dnsState = .checking
        gatewayState = .checking
        runtimeHealth = nil
        guard let executeCommand else {
            authorityState = .unavailable
            dnsState = .unavailable
            gatewayState = .unavailable
            diagnostic = transportDiagnostic()
            return
        }
        let runtimeTask = Task { await verifyRuntime() }
        do {
            let snapshot = try await coherentSnapshot(executeCommand: executeCommand)
            let runtime = await runtimeTask.value
            status = snapshot.status
            mappings = snapshot.mappings
            authorityState = .ready
            apply(runtime)
            diagnostic = snapshot.status.maintenance
            preserveSelection()
        } catch is CancellationError {
            runtimeTask.cancel()
            return
        } catch {
            authorityState = .unavailable
            await apply(runtimeTask.value)
            set(error)
        }
    }

    func preview(_ change: RemapChange) async throws -> RemapPreview {
        let executeCommand = try requireExecutor()
        let result = try await executeCommand(.preview(changes: [change]))
        guard case let .preview(preview) = result else {
            throw protocolDiagnostic("the Remap service returned the wrong preview result")
        }
        return preview
    }

    func apply(_ change: RemapChange, expectedRevision: UInt64) async throws -> RemapApplyReceipt {
        let executeCommand = try requireExecutor()
        let operationID = UUID().uuidString.lowercased()
        let result = try await executeCommand(
            .apply(
                expectedRevision: expectedRevision,
                operationID: operationID,
                changes: [change]
            )
        )
        guard case let .apply(receipt) = result else {
            throw protocolDiagnostic("the Remap service returned the wrong mutation result")
        }
        await refresh()
        return receipt
    }

    func dismissDiagnostic() {
        diagnostic = status?.maintenance
    }

    private func coherentSnapshot(
        executeCommand: CommandExecutor
    ) async throws -> (status: RemapRegistryStatus, mappings: [RemapMapping]) {
        for _ in 0 ..< Self.maximumSnapshotAttempts {
            let firstStatus = try await readStatus(executeCommand)
            let page = try await readAllMappings(executeCommand, expectedRevision: firstStatus.revision)
            let finalStatus = try await readStatus(executeCommand)
            let isCoherent = firstStatus.revision == finalStatus.revision
                && page.revision == finalStatus.revision
                && UInt64(page.mappings.count) == finalStatus.mappingCount
            if isCoherent {
                return (finalStatus, page.mappings)
            }
        }
        throw RemapDiagnostic(
            code: "E_SNAPSHOT_CHANGED",
            message: "the registry kept changing while the app refreshed",
            hint: "Wait a moment, then refresh again.",
            retryable: true
        )
    }

    private func readStatus(_ executeCommand: CommandExecutor) async throws -> RemapRegistryStatus {
        let result = try await executeCommand(.status)
        guard case let .status(status) = result else {
            throw protocolDiagnostic("the Remap service returned the wrong status result")
        }
        return status
    }

    private func readAllMappings(
        _ executeCommand: CommandExecutor,
        expectedRevision: UInt64
    ) async throws -> (revision: UInt64, mappings: [RemapMapping]) {
        var cursor: String?
        var all: [RemapMapping] = []
        repeat {
            let result = try await executeCommand(
                .list(after: cursor, limit: Self.pageSize, includeDisabled: true)
            )
            guard case let .list(page) = result, page.revision == expectedRevision else {
                throw protocolDiagnostic("the registry changed between mapping pages")
            }
            all.append(contentsOf: page.mappings)
            cursor = page.nextCursor
        } while cursor != nil
        return (expectedRevision, all)
    }

    private func requireExecutor() throws -> CommandExecutor {
        guard let executeCommand else { throw transportDiagnostic() }
        return executeCommand
    }

    private func observeResolver() -> ResolverState {
        do {
            let observation = try observeNativeResolver()
            return observation.isRemapActive ? .active(observation) : .inactive(observation)
        } catch {
            return .unavailable
        }
    }

    private func preserveSelection() {
        if selectedMapping != nil {
            return
        }
        selectedPattern = mappings.first?.pattern
    }

    private func apply(_ health: RemapRuntimeHealth) {
        runtimeHealth = health
        dnsState = health.dns ? .authenticated : .unavailable
        gatewayState = health.http ? .authenticated : .unavailable
    }

    private func set(_ error: any Error) {
        if let diagnostic = error as? RemapDiagnostic {
            self.diagnostic = diagnostic
        } else {
            diagnostic = RemapDiagnostic(
                code: "E_NATIVE_APP",
                message: "the app could not complete the operation",
                hint: "Refresh the app. If the problem remains, run remap doctor.",
                retryable: true
            )
        }
    }
}

private func protocolDiagnostic(_ message: String) -> RemapDiagnostic {
    RemapDiagnostic(
        code: "E_CONTROL_PROTOCOL",
        message: message,
        hint: "Update the Remap app and service together, then retry.",
        retryable: false
    )
}

private func transportDiagnostic() -> RemapDiagnostic {
    RemapDiagnostic(
        code: "E_DAEMON_UNAVAILABLE",
        message: "the Remap background service is not responding",
        hint: "Install or repair the Remap service, then refresh.",
        retryable: true
    )
}
